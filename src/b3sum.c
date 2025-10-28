/*
 b3sum with pooled per-file parallelism and parallel directory walk
 global workers take ownership of entire files (1 worker -> 1 file from open() to print)
 NO cross-worker cooperation on a single file_ctx except perfile_ctx helper threads spawned inside that worker
*/

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <sys/types.h> /* must come before some libc headers on glibc to avoid __u_char confusion */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>
#include <unistd.h>

#include "blake3.h"
#include "blake3_impl.h"

#if defined(__linux__)
#include <sys/syscall.h>
#ifndef RWF_NOWAIT
#define RWF_NOWAIT 0x00000008
#endif
#endif

#if defined(__linux__) && defined(SYS_preadv2) && defined(RWF_NOWAIT)
#define HAVE_PREADV2_NOWAIT 1
#else
#define HAVE_PREADV2_NOWAIT 0
#endif

/* io buffer sizing */
#define DEFAULT_BUF (1 << 20) /* 1 MiB default streaming buffer */
#define MAX_BUF (8 << 20)     /* 8 MiB upper cap for a single buffer */

#if defined(__linux__)
#define IO_BUFFER_ALIGNMENT 4096
#else
#define IO_BUFFER_ALIGNMENT 64
#endif

#define STREAM_BUF_MIN ((size_t)DEFAULT_BUF)
#define STREAM_BUF_MAX ((size_t)MAX_BUF)

/* task queue sizing */
#define TASKQ_CAP 32768 /* power of two */
#define TASKQ_MASK (TASKQ_CAP - 1)

/* thread local IO scratch */
static __thread uint8_t* tls_io_buf = NULL;
static __thread size_t tls_io_buf_cap = 0;

/* --- forward declarations --- */
static int blake3_hash_region_tree(const uint8_t* data, size_t len, uint8_t out_hash[BLAKE3_OUT_LEN]);

/* --- tls buffer helpers --- */
static inline size_t align_up(size_t value, size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

static uint8_t* ensure_tls_io_buffer(size_t min_bytes, size_t* actual_size) {
    if (min_bytes < STREAM_BUF_MIN)
        min_bytes = STREAM_BUF_MIN;

    if (min_bytes > tls_io_buf_cap) {
        size_t aligned = align_up(min_bytes, IO_BUFFER_ALIGNMENT);
        if (aligned < min_bytes)
            aligned = min_bytes;
        uint8_t* newbuf = NULL;
#if defined(_POSIX_C_SOURCE) && (_POSIX_C_SOURCE >= 200112L)
        if (posix_memalign((void**)&newbuf, IO_BUFFER_ALIGNMENT, aligned) != 0)
            return NULL;
#else
        newbuf = malloc(aligned);
        if (!newbuf)
            return NULL;
#endif
        if (tls_io_buf)
            free(tls_io_buf);
        tls_io_buf = newbuf;
        tls_io_buf_cap = aligned;
    }
    if (actual_size)
        *actual_size = tls_io_buf_cap ? tls_io_buf_cap : min_bytes;
    return tls_io_buf;
}

static void release_tls_io_buffer(void) {
    free(tls_io_buf);
    tls_io_buf = NULL;
    tls_io_buf_cap = 0;
}

/* options */
typedef struct {
    int check;
    int tag;
    int zero;
    int ignore_missing;
    int quiet;
    int status;
    int strict;
    int warn;
    int jobs; /* 0 = auto */
} program_opts;

/* we only enqueue files now */
typedef enum {
    TASK_FILE = 0,
} task_kind;

/* work item in the shared queue
   we cache struct stat to avoid per-worker fstat/open metadata duplication
   tiny-file throughput is usually dominated by metadata syscalls, not hashing cpu
*/
typedef struct file_task {
    task_kind kind;

    /* TASK_FILE */
    char* filename; /* owned by task, heap dup */
    int is_check_mode;
    uint8_t expected_hash[BLAKE3_OUT_LEN];

    struct stat st;
    int have_stat;
} file_task;

/* global worker-pool state */

static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;

/* task queue ring buffer */
static _Atomic size_t q_head = 0; /* next index to consume */
static _Atomic size_t q_tail = 0; /* next index to produce */
static file_task* task_ring[TASKQ_CAP];

/* condition/mutex for sleeping when queue is empty */
static pthread_mutex_t q_sleep_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t q_sleep_cond = PTHREAD_COND_INITIALIZER;
/* counter to track sleepers */
static _Atomic int q_sleep_counter = 0;

/* producers-done flag */
static _Atomic int done_submitting_tasks = 0;

/* results */
static int any_failure_global = 0;
static int any_format_error_global = 0;

/* ---- per-file parallel hashing support ---- */

typedef struct {
    int fd;
    off_t size;
    const uint8_t* map;
    size_t map_len;

    size_t total_chunks; /* ceil(size / BLAKE3_CHUNK_LEN), at least 1 */
    uint8_t* cvs;        /* total_chunks * 32 bytes */

    _Atomic size_t next_chunk; /* atomic fetch_add cursor */
    size_t chunks_per_job;     /* work quantum per helper thread */

    _Atomic int had_error;
    int io_error_code;
} perfile_ctx;

static void hash_chunk_span_mem(perfile_ctx* ctx, size_t start_index, size_t span_count);
static int hash_chunk_span_fd(perfile_ctx* ctx, size_t start_index, size_t span_count);

typedef struct {
    perfile_ctx* ctx;
} perfile_worker_arg;

static inline size_t chunk_len_for_index_pf(const perfile_ctx* c, size_t chunk_index) {
    size_t offset = chunk_index * (size_t)BLAKE3_CHUNK_LEN;
    if ((off_t)offset >= c->size)
        return 0;
    size_t remaining = (size_t)c->size - offset;
    if (remaining >= BLAKE3_CHUNK_LEN)
        return BLAKE3_CHUNK_LEN;
    return remaining;
}

/* compute CV for a single chunk of up to BLAKE3_CHUNK_LEN bytes
   mirrors BLAKE3 leaf chunk compression semantics (chunk start/end flags, counter = chunk index)
   this is the primitive the tree reduction will combine later
   BLAKE3 uses 1 KiB fixed-size chunks specifically so leaf hashing can be parallelized and then merged as a binary tree,
   which is what enables high throughput across cores and SIMD lanes compared to strictly serial hashers like BLAKE2 or SHA2 :contentReference[oaicite:2]{index=2}
*/
static void cv_from_chunk_bytes(const uint8_t* input, size_t len, uint64_t chunk_counter, uint8_t out_cv[BLAKE3_OUT_LEN]) {
    uint32_t cv_words[8];
    memcpy(cv_words, IV, sizeof(IV));

    size_t offset = 0;
    int is_first_block = 1;

    while (len - offset > BLAKE3_BLOCK_LEN) {
        uint8_t flags = is_first_block ? CHUNK_START : 0;
        blake3_compress_in_place(cv_words, input + offset, BLAKE3_BLOCK_LEN, chunk_counter, flags);
        offset += BLAKE3_BLOCK_LEN;
        is_first_block = 0;
    }

    size_t tail_len = len - offset;
    uint8_t block[BLAKE3_BLOCK_LEN];
    const uint8_t* tail_ptr;
    if (tail_len == BLAKE3_BLOCK_LEN) {
        tail_ptr = input + offset;
    }
    else {
        memset(block, 0, sizeof(block));
        if (tail_len > 0)
            memcpy(block, input + offset, tail_len);
        tail_ptr = block;
    }

    uint8_t final_flags = CHUNK_END;
    if (is_first_block)
        final_flags |= CHUNK_START;

    blake3_compress_in_place(cv_words, tail_ptr, (uint8_t)tail_len, chunk_counter, final_flags);
    store_cv_words(out_cv, cv_words);
}

static void hash_chunk_span_mem(perfile_ctx* ctx, size_t start_index, size_t span_count) {
    if (span_count == 0)
        return;

    size_t simd = blake3_simd_degree();
    if (simd == 0)
        simd = 1;

    const size_t chunk_len = BLAKE3_CHUNK_LEN;
    const size_t blocks_per_chunk = BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN;
    const uint8_t* inputs[MAX_SIMD_DEGREE];

    size_t idx = start_index;
    size_t remaining = span_count;
    const uint8_t* file_base = ctx->map;

    while (remaining >= simd) {
        for (size_t i = 0; i < simd; i++) {
            size_t current_idx = idx + i;
            size_t chunk_start = current_idx * chunk_len;
            inputs[i] = file_base + chunk_start;
        }

        blake3_hash_many(inputs, simd, blocks_per_chunk, IV, idx, true, /* chunk mode */
                         0, CHUNK_START, CHUNK_END, ctx->cvs + idx * BLAKE3_OUT_LEN);
        idx += simd;
        remaining -= simd;
    }

    while (remaining > 0) {
        size_t valid_in_group = 0;
        for (size_t i = 0; i < remaining; i++) {
            size_t current_idx = idx + i;
            size_t chunk_start = current_idx * chunk_len;
            if (chunk_start < (size_t)ctx->size) {
                inputs[valid_in_group] = file_base + chunk_start;
                valid_in_group++;
            }
            else {
                break;
            }
        }

        if (valid_in_group > 0) {
            blake3_hash_many(inputs, valid_in_group, blocks_per_chunk, IV, idx, true, 0, CHUNK_START, CHUNK_END, ctx->cvs + idx * BLAKE3_OUT_LEN);
            idx += valid_in_group;
            remaining -= valid_in_group;
        }
        else {
            size_t chunk_start = idx * chunk_len;
            if (chunk_start < (size_t)ctx->size) {
                size_t len = (size_t)ctx->size - chunk_start;
                if (len > chunk_len)
                    len = chunk_len;
                cv_from_chunk_bytes(file_base + chunk_start, len, idx, ctx->cvs + idx * BLAKE3_OUT_LEN);
            }
            else {
                memset(ctx->cvs + idx * BLAKE3_OUT_LEN, 0, BLAKE3_OUT_LEN);
            }
            idx++;
            remaining--;
        }
    }
}

/* hash_chunk_span_fd:
   read a run of chunks from disk (via pread) into a TLS buffer, then hash them in SIMD batches
   this mirrors hash_chunk_span_mem but works for non-mmap fallback paths
*/
static int hash_chunk_span_fd(perfile_ctx* ctx, size_t start_index, size_t span_count) {
    if (span_count == 0)
        return 0;

    const size_t chunk_len = BLAKE3_CHUNK_LEN;

    size_t want = span_count * chunk_len;
    size_t buf_cap = 0;
    uint8_t* buf = ensure_tls_io_buffer(want, &buf_cap);
    if (!buf || buf_cap < want) {
        ctx->io_error_code = ENOMEM;
        return -1;
    }

    for (size_t i = 0; i < span_count; i++) {
        size_t logical_idx = start_index + i;
        size_t len = chunk_len_for_index_pf(ctx, logical_idx);
        uint8_t* dst = buf + i * chunk_len;
        if (len == 0) {
            memset(dst, 0, chunk_len);
            continue;
        }

        size_t have = 0;
        off_t base_off = (off_t)((unsigned long long)logical_idx * chunk_len);
        while (have < len) {
            ssize_t r = pread(ctx->fd, dst + have, len - have, base_off + (off_t)have);
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                ctx->io_error_code = errno;
                return -1;
            }
            if (r == 0) {
                ctx->io_error_code = EIO;
                return -1;
            }
            have += (size_t)r;
        }

        if (len < chunk_len) {
            memset(dst + len, 0, chunk_len - len);
        }
    }

    size_t simd = blake3_simd_degree();
    if (simd == 0)
        simd = 1;
    const size_t blocks_per_chunk = BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN;
    const uint8_t* inputs[MAX_SIMD_DEGREE];

    size_t idx = 0;
    size_t remaining = span_count;

    while (remaining >= simd) {
        for (size_t i = 0; i < simd; i++) {
            inputs[i] = buf + (idx + i) * BLAKE3_CHUNK_LEN; /* FIX: BLAKE3_CHUNK_LEN not BLAKE3_CH_LEN */
        }

        blake3_hash_many(inputs, simd, blocks_per_chunk, IV, start_index + idx, true, 0, CHUNK_START, CHUNK_END, ctx->cvs + (start_index + idx) * BLAKE3_OUT_LEN);
        idx += simd;
        remaining -= simd;
    }

    while (remaining > 0) {
        size_t valid_in_group = 0;
        for (size_t i = 0; i < remaining; i++) {
            inputs[valid_in_group] = buf + (idx + i) * BLAKE3_CHUNK_LEN;
            valid_in_group++;
        }

        if (valid_in_group > 0) {
            blake3_hash_many(inputs, valid_in_group, blocks_per_chunk, IV, start_index + idx, true, 0, CHUNK_START, CHUNK_END, ctx->cvs + (start_index + idx) * BLAKE3_OUT_LEN);
            idx += valid_in_group;
            remaining -= valid_in_group;
        }
        else {
            size_t chunk_offset = idx * BLAKE3_CHUNK_LEN;
            size_t len = BLAKE3_CHUNK_LEN;
            cv_from_chunk_bytes(buf + chunk_offset, len, start_index + idx, ctx->cvs + (start_index + idx) * BLAKE3_OUT_LEN);
            idx++;
            remaining--;
        }
    }

    return 0;
}

static void* perfile_worker_proc(void* arg) {
    perfile_ctx* ctx = ((perfile_worker_arg*)arg)->ctx;
    size_t job = ctx->chunks_per_job;

    for (;;) {
        size_t start = atomic_fetch_add_explicit(&ctx->next_chunk, job, memory_order_acq_rel);
        if (start >= ctx->total_chunks)
            break;

        size_t span_count = job;
        if (start + span_count > ctx->total_chunks)
            span_count = ctx->total_chunks - start;

        if (atomic_load_explicit(&ctx->had_error, memory_order_acquire))
            break;

        if (ctx->map) {
            hash_chunk_span_mem(ctx, start, span_count);
        }
        else {
            if (hash_chunk_span_fd(ctx, start, span_count) != 0) {
                atomic_store_explicit(&ctx->had_error, 1, memory_order_release);
                break;
            }
        }
    }
    return NULL;
}

static int build_all_chunk_cvs(perfile_ctx* ctx) {
    size_t simd_degree = blake3_simd_degree();
    if (simd_degree == 0)
        simd_degree = 1;

    size_t processed = 0;
    while (processed < ctx->total_chunks) {
        size_t remaining = ctx->total_chunks - processed;

        size_t batch_size;
        if (remaining >= simd_degree) {
            batch_size = (remaining / simd_degree) * simd_degree;
            if (batch_size > remaining)
                batch_size = remaining;
        }
        else {
            batch_size = remaining;
        }

        if (ctx->map) {
            hash_chunk_span_mem(ctx, processed, batch_size);
        }
        else {
            if (hash_chunk_span_fd(ctx, processed, batch_size) != 0)
                return -1;
        }

        processed += batch_size;
    }
    return 0;
}

static size_t reduce_cvs_to_two(uint8_t* cvs, size_t cv_count) {
    if (cv_count <= 2)
        return cv_count;

    size_t max_deg = blake3_simd_degree();
    if (max_deg == 0)
        max_deg = 1;
    if (max_deg > MAX_SIMD_DEGREE)
        max_deg = MAX_SIMD_DEGREE;

    uint8_t parent_blocks[MAX_SIMD_DEGREE * BLAKE3_BLOCK_LEN];
    const uint8_t* parent_ptrs[MAX_SIMD_DEGREE];

    size_t n = cv_count;
    while (n > 2) {
        size_t write = 0;
        size_t i = 0;

        while (i + 1 < n) {
            size_t batch = 0;
            while (batch < max_deg && i + 1 < n) {
                uint8_t* block = parent_blocks + batch * BLAKE3_BLOCK_LEN;

                memcpy(block, cvs + i * BLAKE3_OUT_LEN, BLAKE3_OUT_LEN);
                memcpy(block + BLAKE3_OUT_LEN, cvs + (i + 1) * BLAKE3_OUT_LEN, BLAKE3_OUT_LEN);
                parent_ptrs[batch] = block;
                i += 2;
                batch++;
            }

            blake3_hash_many(parent_ptrs, batch, 1, IV, 0, false, PARENT, 0, 0, cvs + write * BLAKE3_OUT_LEN);
            write += batch;
        }

        if (i < n) {
            if (write != i) {
                memmove(cvs + write * BLAKE3_OUT_LEN, cvs + i * BLAKE3_OUT_LEN, BLAKE3_OUT_LEN);
            }
            write++;
        }

        n = write;
    }
    return n;
}

/* combine last 2 CVs into the root output
   final root compression uses PARENT|ROOT flags so output matches standard BLAKE3 hash output,
   same value you'd get from the portable reference hasher or Rust impl :contentReference[oaicite:3]{index=3}
*/
static void root_output_from_two_cvs(const uint8_t left[BLAKE3_OUT_LEN], const uint8_t right[BLAKE3_OUT_LEN], uint8_t out_hash[BLAKE3_OUT_LEN]) {
    uint8_t block[BLAKE3_BLOCK_LEN];
    memcpy(block, left, BLAKE3_OUT_LEN);
    memcpy(block + BLAKE3_OUT_LEN, right, BLAKE3_OUT_LEN);

    uint8_t wide[64];
    blake3_compress_xof(IV, block, BLAKE3_BLOCK_LEN, 0, (uint8_t)(PARENT | ROOT), wide);
    memcpy(out_hash, wide, BLAKE3_OUT_LEN);
}

static int perfile_finalize_hash(perfile_ctx* ctx, uint8_t out_hash[BLAKE3_OUT_LEN]) {
    if (atomic_load_explicit(&ctx->had_error, memory_order_acquire)) {
        errno = ctx->io_error_code ? ctx->io_error_code : EIO;
        return -1;
    }

    if (ctx->total_chunks == 1) {
        blake3_hasher h;
        blake3_hasher_init(&h);

        size_t real_len = (size_t)ctx->size;
        if (ctx->map) {
            blake3_hasher_update(&h, ctx->map, real_len);
        }
        else {
            if (lseek(ctx->fd, 0, SEEK_SET) == (off_t)-1) {
                errno = EIO;
                return -1;
            }
            size_t buf_sz = 0;
            uint8_t* buf = ensure_tls_io_buffer(real_len, &buf_sz);
            if (!buf || buf_sz < real_len) {
                errno = ENOMEM;
                return -1;
            }

            size_t have = 0;
            while (have < real_len) {
                ssize_t r = read(ctx->fd, buf + have, real_len - have);
                if (r < 0) {
                    if (errno == EINTR)
                        continue;
                    errno = EIO;
                    return -1;
                }
                if (r == 0)
                    break;
                have += (size_t)r;
            }
            if (have != real_len) {
                errno = EIO;
                return -1;
            }
            blake3_hasher_update(&h, buf, real_len);
        }

        blake3_hasher_finalize(&h, out_hash, BLAKE3_OUT_LEN);
        return 0;
    }

    size_t remaining = reduce_cvs_to_two(ctx->cvs, ctx->total_chunks);

    if (remaining == 2) {
        root_output_from_two_cvs(ctx->cvs, ctx->cvs + BLAKE3_OUT_LEN, out_hash);
        return 0;
    }
    else if (remaining == 1) {
        memcpy(out_hash, ctx->cvs, BLAKE3_OUT_LEN);
        return 0;
    }

    errno = EIO;
    return -1;
}

/* hash_regular_file_parallel:
   - mmap the file if possible
   - compute per-chunk chaining values in parallel (thread team inside the worker for big files)
   - reduce CVs to a single BLAKE3 root hash
   This matches the spec's parallel tree mode: each 1 KiB chunk becomes a CV, CVs are merged in pairs up a binary tree,
   and the final parent/root node output is the BLAKE3 digest you print. :contentReference[oaicite:4]{index=4}
*/
static int hash_regular_file_parallel(const program_opts* opts, const char* name, int fd, const struct stat* st, uint8_t out_hash[BLAKE3_OUT_LEN]) {
    (void)opts;
    (void)name;

    perfile_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fd = fd;
    ctx.size = st->st_size;
    atomic_store_explicit(&ctx.had_error, 0, memory_order_release);
    ctx.io_error_code = 0;

    if (st->st_size > 0) {
        void* map_ptr = mmap(NULL, (size_t)st->st_size, PROT_READ, MAP_SHARED, fd, 0);
        if (map_ptr != MAP_FAILED) {
#if defined(POSIX_MADV_SEQUENTIAL) && !defined(__APPLE__)
            posix_madvise(map_ptr, (size_t)st->st_size, POSIX_MADV_SEQUENTIAL);
#endif
            ctx.map = (const uint8_t*)map_ptr;
            ctx.map_len = (size_t)st->st_size;
        }
    }

    size_t total_chunks = ((size_t)ctx.size + BLAKE3_CHUNK_LEN - 1) / BLAKE3_CHUNK_LEN;
    if (total_chunks == 0)
        total_chunks = 1;
    ctx.total_chunks = total_chunks;

    /* fast path for small files */
    if (total_chunks == 1 || (size_t)ctx.size <= (8u << 20)) {
        int rc;
        if (ctx.map) {
            rc = blake3_hash_region_tree(ctx.map, (size_t)ctx.size, out_hash);
        }
        else {
            size_t buf_sz = 0;
            uint8_t* buf = ensure_tls_io_buffer((size_t)ctx.size, &buf_sz);
            if (!buf || buf_sz < (size_t)ctx.size) {
                if (ctx.map)
                    munmap((void*)ctx.map, ctx.map_len);
                errno = ENOMEM;
                return -1;
            }

            size_t have = 0;
            while (have < (size_t)ctx.size) {
                ssize_t r = read(ctx.fd, buf + have, (size_t)ctx.size - have);
                if (r < 0) {
                    if (errno == EINTR)
                        continue;
                    if (ctx.map)
                        munmap((void*)ctx.map, ctx.map_len);
                    errno = EIO;
                    return -1;
                }
                if (r == 0)
                    break;
                have += (size_t)r;
            }
            if (have != (size_t)ctx.size) {
                if (ctx.map)
                    munmap((void*)ctx.map, ctx.map_len);
                errno = EIO;
                return -1;
            }
            rc = blake3_hash_region_tree(buf, (size_t)ctx.size, out_hash);
        }

        if (ctx.map)
            munmap((void*)ctx.map, ctx.map_len);
        return rc;
    }

    ctx.cvs = malloc(total_chunks * BLAKE3_OUT_LEN);
    if (!ctx.cvs) {
        if (ctx.map)
            munmap((void*)ctx.map, ctx.map_len);
        errno = ENOMEM;
        return -1;
    }

    if (ctx.size > 8 * 1024 * 1024) {
        atomic_store_explicit(&ctx.next_chunk, 0, memory_order_release);

        size_t simd_chunks = blake3_simd_degree();
        if (simd_chunks == 0)
            simd_chunks = 1;

        size_t chunks_per_job;
        if (total_chunks > 1024) {
            chunks_per_job = 512;
        }
        else if (total_chunks > 256) {
            chunks_per_job = 128;
        }
        else {
            chunks_per_job = 64;
        }

        size_t rounded = (chunks_per_job / simd_chunks) * simd_chunks;
        if (rounded >= simd_chunks && rounded != 0)
            chunks_per_job = rounded;
        if (chunks_per_job == 0)
            chunks_per_job = 1;
        ctx.chunks_per_job = chunks_per_job;

        int num_cores = get_nprocs();
        int nthreads = (num_cores < (int)total_chunks) ? num_cores : (int)total_chunks;
        if (nthreads < 1)
            nthreads = 1;
        if (nthreads > 16)
            nthreads = 16;

        pthread_t* threads = malloc(sizeof(pthread_t) * (size_t)nthreads);
        if (!threads) {
            if (ctx.map)
                munmap((void*)ctx.map, ctx.map_len);
            free(ctx.cvs);
            errno = ENOMEM;
            return -1;
        }

        perfile_worker_arg arg;
        arg.ctx = &ctx;

        int started = 0;
        for (int i = 0; i < nthreads; i++) {
            if (pthread_create(&threads[i], NULL, perfile_worker_proc, &arg) != 0) {
                nthreads = i;
                break;
            }
            started++;
        }

        /* caller also helps */
        perfile_worker_proc(&arg);

        for (int i = 0; i < started; i++)
            pthread_join(threads[i], NULL);
        free(threads);
    }
    else {
        if (build_all_chunk_cvs(&ctx) != 0) {
            if (ctx.map)
                munmap((void*)ctx.map, ctx.map_len);
            free(ctx.cvs);
            errno = EIO;
            return -1;
        }
    }

    int rc = perfile_finalize_hash(&ctx, out_hash);

    if (ctx.map)
        munmap((void*)ctx.map, ctx.map_len);
    free(ctx.cvs);

    return rc;
}

/* --- mostly lock-free task queue functions --- */

static int enqueue_task_lockfree(file_task* t) {
    for (;;) {
        size_t tail = atomic_load_explicit(&q_tail, memory_order_relaxed);
        size_t head = atomic_load_explicit(&q_head, memory_order_acquire);

        if ((tail - head) >= TASKQ_CAP) {
            return -1;
        }

        if (atomic_compare_exchange_weak_explicit(&q_tail, &tail, tail + 1, memory_order_acq_rel, memory_order_relaxed)) {
            task_ring[tail & TASKQ_MASK] = t;

            if (atomic_load_explicit(&q_sleep_counter, memory_order_acquire) > 0) {
                pthread_mutex_lock(&q_sleep_mutex);
                pthread_cond_broadcast(&q_sleep_cond);
                pthread_mutex_unlock(&q_sleep_mutex);
            }
            return 0;
        }
    }
}

static void enqueue_task(file_task* t) {
    while (enqueue_task_lockfree(t) != 0) {
        sched_yield();
    }
}

#define TASK_EMPTY_NOT_DONE ((file_task*)0x1)

static file_task* dequeue_task_lockfree(void) {
    for (;;) {
        size_t head = atomic_load_explicit(&q_head, memory_order_relaxed);
        size_t tail = atomic_load_explicit(&q_tail, memory_order_acquire);

        if (head == tail) {
            if (atomic_load_explicit(&done_submitting_tasks, memory_order_acquire)) {
                return NULL;
            }
            return TASK_EMPTY_NOT_DONE;
        }

        if (atomic_compare_exchange_weak_explicit(&q_head, &head, head + 1, memory_order_acq_rel, memory_order_relaxed)) {
            file_task* t = task_ring[head & TASKQ_MASK];
            return t;
        }
    }
}

static file_task* dequeue_task(void) {
    for (;;) {
        file_task* t = dequeue_task_lockfree();
        if (t == NULL) {
            return NULL;
        }
        if (t != TASK_EMPTY_NOT_DONE) {
            return t;
        }

        pthread_mutex_lock(&q_sleep_mutex);

        atomic_fetch_add_explicit(&q_sleep_counter, 1, memory_order_relaxed);

        size_t head = atomic_load_explicit(&q_head, memory_order_relaxed);
        size_t tail = atomic_load_explicit(&q_tail, memory_order_acquire);

        if (head == tail && !atomic_load_explicit(&done_submitting_tasks, memory_order_acquire)) {
            pthread_cond_wait(&q_sleep_cond, &q_sleep_mutex);
        }

        atomic_fetch_sub_explicit(&q_sleep_counter, 1, memory_order_relaxed);
        pthread_mutex_unlock(&q_sleep_mutex);
    }
}

/* CLI and formatting helpers */

static void print_help(void) {
    puts(
        "Usage: b3sum [OPTION]... [FILE]...\n"
        "Print or check BLAKE3 (256-bit) checksums\n\n"
        "With no FILE, or when FILE is -, read standard input\n"
        "  -c, --check           read checksums from FILEs and check them\n"
        "      --tag             create or check a BSD-style checksum format\n"
        "  -z, --zero            end each output line with NUL, not newline\n"
        "      --ignore-missing  don't fail or report status for missing files\n"
        "      --quiet           don't print OK for each successfully verified file\n"
        "      --status          don't output anything, status code shows success\n"
        "      --strict          exit non-zero for improperly formatted checksum lines\n"
        "  -w, --warn            warn about improperly formatted checksum lines\n"
        "  -j, --jobs N          number of worker threads to use (default: CPUs)\n"
        "      --help            display this help and exit\n"
        "      --version         output version information and exit");
}

static void print_version(void) {
    puts("b3sum version (modified)");
}

static int handle_options(int argc, char** argv, program_opts* opts) {
    memset(opts, 0, sizeof(*opts));
    opts->jobs = 0;

    static struct option long_options[] = {{"check", no_argument, NULL, 'c'},      {"tag", no_argument, NULL, 't'},    {"zero", no_argument, NULL, 'z'},    {"ignore-missing", no_argument, NULL, 'i'},
                                           {"quiet", no_argument, NULL, 'q'},      {"status", no_argument, NULL, 's'}, {"strict", no_argument, NULL, 'S'},  {"warn", no_argument, NULL, 'w'},
                                           {"jobs", required_argument, NULL, 'j'}, {"help", no_argument, NULL, 'h'},   {"version", no_argument, NULL, 'v'}, {0, 0, 0, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "ctziqsSwj:hv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                opts->check = 1;
                break;
            case 't':
                opts->tag = 1;
                break;
            case 'z':
                opts->zero = 1;
                break;
            case 'i':
                opts->ignore_missing = 1;
                break;
            case 'q':
                opts->quiet = 1;
                break;
            case 's':
                opts->status = 1;
                break;
            case 'S':
                opts->strict = 1;
                break;
            case 'w':
                opts->warn = 1;
                break;
            case 'j': {
                long n = strtol(optarg, NULL, 10);
                if (n < 1) {
                    fprintf(stderr, "b3sum: invalid jobs value: %s\n", optarg);
                    return -1;
                }
                opts->jobs = (int)n;
                break;
            }
            case 'h':
                print_help();
                return 0;
            case 'v':
                print_version();
                return 0;
            default:
                fprintf(stderr, "Try 'b3sum --help' for more information\n");
                return -1;
        }
    }
    return optind;
}

static char* unescape_filename(const char* in) {
    size_t len = strlen(in);
    char* out = malloc(len + 1);
    if (!out)
        return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len;) {
        if (in[i] == '\\') {
            if (i + 1 < len && in[i + 1] == 'n') {
                out[j++] = '\n';
                i += 2;
            }
            else if (i + 1 < len && in[i + 1] == '\\') {
                out[j++] = '\\';
                i += 2;
            }
            else {
                out[j++] = in[i++];
            }
        }
        else {
            out[j++] = in[i++];
        }
    }
    out[j] = '\0';
    return out;
}

static void print_hash(const uint8_t* hash, const char* filename, int tag, int zero) {
    int needs_escape = 0;
    if (!zero) {
        for (const char* p = filename; *p; ++p) {
            if (*p == '\n' || *p == '\\') {
                needs_escape = 1;
                break;
            }
        }
    }

    if (tag)
        fputs("BLAKE3 ", stdout);

    for (size_t i = 0; i < BLAKE3_OUT_LEN; i++)
        printf("%02x", hash[i]);

    if (zero) {
        printf("  %s%c", filename[0] ? filename : "-", '\0');
        return;
    }

    if (needs_escape)
        putchar('\\');
    printf("  ");

    for (const char* p = filename; *p; ++p) {
        if (*p == '\\')
            fputs("\\\\", stdout);
        else if (*p == '\n')
            fputs("\\n", stdout);
        else
            putchar(*p);
    }
    putchar('\n');
}

static int parse_hex_hash(const char* hex, uint8_t* out) {
    for (size_t i = 0; i < BLAKE3_OUT_LEN; i++) {
        char byte_str[3] = {hex[2 * i], hex[2 * i + 1], '\0'};
        if (!isxdigit((unsigned char)byte_str[0]) || !isxdigit((unsigned char)byte_str[1])) {
            return -1;
        }
        unsigned long v = strtoul(byte_str, NULL, 16);
        if (v > 0xFF)
            return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static int parse_check_line(const char* line_in, const program_opts* opts, char** filename_out, uint8_t* hash_out) {
    char* line = strdup(line_in);
    if (!line)
        return -1;

    char* end = line + strlen(line);
    while (end > line && (end[-1] == '\n' || end[-1] == '\r')) {
        *--end = '\0';
    }

    const char* hash_start = line;
    if (opts->tag) {
        const char prefix[] = "BLAKE3 ";
        size_t plen = sizeof(prefix) - 1;
        if (strncmp(line, prefix, plen) != 0) {
            free(line);
            return -1;
        }
        hash_start = line + plen;
    }

    int needs_unescape = 0;
    if (!opts->zero && hash_start[0] == '\\') {
        needs_unescape = 1;
        hash_start++;
    }

    char* space = strstr((char*)hash_start, "  ");
    char* star = strstr((char*)hash_start, " *");
    char* marker = NULL;
    if (space && (!star || space < star))
        marker = space;
    else if (star)
        marker = star;
    else {
        free(line);
        return -1;
    }

    size_t hash_len = (size_t)(marker - hash_start);
    if (hash_len != BLAKE3_OUT_LEN * 2) {
        free(line);
        return -1;
    }
    if (parse_hex_hash(hash_start, hash_out) != 0) {
        free(line);
        return -1;
    }

    const char* fname = marker + 2;
    if (*fname == '\0') {
        free(line);
        return -1;
    }

    char* decoded = needs_unescape ? unescape_filename(fname) : strdup(fname);
    if (!decoded) {
        free(line);
        return -1;
    }

    *filename_out = decoded;
    free(line);
    return 0;
}

static int blake3_hash_region_tree(const uint8_t* data, size_t len, uint8_t out_hash[BLAKE3_OUT_LEN]) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, len);
    blake3_hasher_finalize(&h, out_hash, BLAKE3_OUT_LEN);
    return 0;
}

static int hash_fd_stream_with_buffer(int fd, off_t filesize, uint8_t* output, uint8_t* buf, size_t buf_sz) {
    if (!buf || buf_sz < 1024) {
        errno = ENOMEM;
        return -1;
    }

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);

    if (filesize > 0 && (size_t)filesize <= buf_sz) {
        size_t want = (size_t)filesize;
        size_t have = 0;
        while (have < want) {
            ssize_t r = read(fd, buf + have, want - have);
            if (r > 0) {
                have += (size_t)r;
                continue;
            }
            if (r == 0)
                break;
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (have != want) {
            errno = EIO;
            return -1;
        }
        return blake3_hash_region_tree(buf, want, output);
    }

#if defined(POSIX_FADV_SEQUENTIAL) && !defined(__APPLE__)
    if (filesize > 0)
        posix_fadvise(fd, 0, (off_t)filesize, POSIX_FADV_SEQUENTIAL);
#endif

    for (;;) {
        ssize_t r = read(fd, buf, buf_sz);
        if (r > 0) {
            blake3_hasher_update(&hasher, buf, (size_t)r);
            continue;
        }
        if (r == 0)
            break;
        if (errno == EINTR)
            continue;
        return -1;
    }

    blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
    return 0;
}

static int hash_fd_stream_fast(int fd, off_t filesize, uint8_t* output) {
    size_t request = STREAM_BUF_MAX;
    if (filesize > 0 && (size_t)filesize < request)
        request = (size_t)filesize;

    size_t buf_sz = 0;
    uint8_t* buf = ensure_tls_io_buffer(request, &buf_sz);
    if (!buf) {
        errno = ENOMEM;
        return -1;
    }

    return hash_fd_stream_with_buffer(fd, filesize, output, buf, buf_sz);
}

/* enqueue helpers */

static void enqueue_task_hash_stat(const char* filename, const struct stat* st_opt) {
    file_task* t = calloc(1, sizeof(*t));
    if (!t) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
    t->kind = TASK_FILE;
    t->filename = strdup(filename ? filename : "-");
    if (!t->filename) {
        perror("strdup");
        free(t);
        exit(EXIT_FAILURE);
    }
    t->is_check_mode = 0;
    if (st_opt) {
        t->st = *st_opt;
        t->have_stat = 1;
    }
    else {
        memset(&t->st, 0, sizeof(t->st));
        t->have_stat = 0;
    }
    enqueue_task(t);
}

__attribute__((unused)) static void enqueue_task_hash(const char* filename) {
    enqueue_task_hash_stat(filename, NULL);
}

static void enqueue_task_check(const char* filename, const uint8_t expected[BLAKE3_OUT_LEN]) {
    file_task* t = calloc(1, sizeof(*t));
    if (!t) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
    t->kind = TASK_FILE;
    t->filename = strdup(filename ? filename : "-");
    if (!t->filename) {
        perror("strdup");
        free(t);
        exit(EXIT_FAILURE);
    }
    t->is_check_mode = 1;
    memcpy(t->expected_hash, expected, BLAKE3_OUT_LEN);
    t->have_stat = 0;
    memset(&t->st, 0, sizeof(t->st));
    enqueue_task(t);
}

/* producer: walk dirs iteratively and enqueue files
   we avoid re-stat in workers by caching struct stat here
   we broadcast after finishing a directory batch to wake sleeping workers
   walking directories in parallel and reducing duplicate metadata work is a well-known way
   to push small-file throughput on Linux, because these workloads are often bottlenecked on open/stat,
   not on hashing CPU time :contentReference[oaicite:5]{index=5}
*/

typedef struct {
    char** data;
    size_t len;
    size_t cap;
} dir_stack;

static void ds_push(dir_stack* s, const char* path) {
    if (s->len == s->cap) {
        size_t nc = s->cap ? (s->cap * 2) : 16;
        char** nd = realloc(s->data, nc * sizeof(char*));
        if (!nd) {
            perror("realloc");
            exit(EXIT_FAILURE);
        }
        s->data = nd;
        s->cap = nc;
    }
    s->data[s->len++] = strdup(path);
    if (!s->data[s->len - 1]) {
        perror("strdup");
        exit(EXIT_FAILURE);
    }
}

static char* ds_pop(dir_stack* s) {
    if (s->len == 0)
        return NULL;
    char* out = s->data[--s->len];
    return out;
}

static void walk_path_streaming(const program_opts* opts, const char* root_path) {
    (void)opts;

    struct stat st;
    if (lstat(root_path, &st) != 0) {
        /* can't stat, just enqueue and let worker report error */
        enqueue_task_hash_stat(root_path, NULL);
        return;
    }

    if (!S_ISDIR(st.st_mode)) {
        /* single file or symlink/etc */
        enqueue_task_hash_stat(root_path, &st);
        return;
    }

    /* directory walk using our own stack (DFS) */
    dir_stack stack = {0};
    ds_push(&stack, root_path);

    while (stack.len > 0) {
        char* dirpath = ds_pop(&stack);
        DIR* d = opendir(dirpath);
        if (!d) {
            /* can't open dir, just enqueue dirpath itself so worker can error out */
            enqueue_task_hash_stat(dirpath, NULL);
            free(dirpath);
            continue;
        }

        struct dirent* de;
        while ((de = readdir(d)) != NULL) {
            const char* n = de->d_name;
            if (n[0] == '.' && (n[1] == '\0' || (n[1] == '.' && n[2] == '\0')))
                continue;

            char child_path[PATH_MAX];
            size_t dl = strlen(dirpath);
            int need_slash = (dl > 0 && dirpath[dl - 1] != '/');
            if (need_slash) {
                snprintf(child_path, sizeof(child_path), "%s/%s", dirpath, n);
            }
            else {
                snprintf(child_path, sizeof(child_path), "%s%s", dirpath, n);
            }

            struct stat cst;
            if (lstat(child_path, &cst) != 0) {
                /* enqueue anyway and worker will emit error */
                enqueue_task_hash_stat(child_path, NULL);
                continue;
            }

            if (S_ISDIR(cst.st_mode)) {
                ds_push(&stack, child_path);
            }
            else {
                enqueue_task_hash_stat(child_path, &cst);
            }
        }

        closedir(d);
        free(dirpath);

        /* wake workers so they don't sit idle while we keep walking */
        pthread_mutex_lock(&q_sleep_mutex);
        pthread_cond_broadcast(&q_sleep_cond);
        pthread_mutex_unlock(&q_sleep_mutex);
    }

    free(stack.data);
}

/* worker thread main
   rc/saved_errno are always initialized so we never print bogus "Success (rc=-1, errno=0)"
*/
static void* worker_main(void* arg) {
    const program_opts* opts = (const program_opts*)arg;
    uint8_t out[BLAKE3_OUT_LEN];

    for (;;) {
        file_task* t = dequeue_task();
        if (!t)
            break;

        if (t->kind != TASK_FILE) {
            free(t->filename);
            free(t);
            continue;
        }

        const char* name = t->filename ? t->filename : "-";

        int rc = 0;
        int saved_errno = 0;

        if (strcmp(name, "-") == 0) {
            struct stat stin;
            if (fstat(STDIN_FILENO, &stin) != 0) {
                rc = -1;
                saved_errno = errno;
            }
            else {
                rc = hash_fd_stream_fast(STDIN_FILENO, stin.st_size, out);
                if (rc != 0)
                    saved_errno = errno;
            }

            char* output_str = NULL;
            char* error_str = NULL;
            int is_failure = 0;

            if (t->is_check_mode) {
                if (rc == 0 && memcmp(t->expected_hash, out, BLAKE3_OUT_LEN) == 0) {
                    if (!opts->quiet && !opts->status) {
                        size_t len = (size_t)snprintf(NULL, 0, "%s: OK\n", name) + 1;
                        output_str = malloc(len);
                        if (output_str)
                            snprintf(output_str, len, "%s: OK\n", name);
                    }
                }
                else {
                    any_failure_global = 1;
                    is_failure = 1;
                    if (!opts->status) {
                        size_t len = (size_t)snprintf(NULL, 0, "%s: FAILED\n", name) + 1;
                        output_str = malloc(len);
                        if (output_str)
                            snprintf(output_str, len, "%s: FAILED\n", name);
                    }
                }
            }
            else {
                if (rc == 0 && !opts->status) {
                    size_t len_guess = (BLAKE3_OUT_LEN * 2) + 4 + strlen(name) + 16;
                    output_str = malloc(len_guess);
                    if (output_str) {
                        char* p = output_str;
                        if (opts->tag) {
                            p += sprintf(p, "BLAKE3 ");
                        }
                        for (size_t i = 0; i < BLAKE3_OUT_LEN; i++) {
                            p += sprintf(p, "%02x", out[i]);
                        }
                        if (opts->zero) {
                            sprintf(p, "  %s%c", name[0] ? name : "-", '\0');
                        }
                        else {
                            sprintf(p, "  %s\n", name);
                        }
                    }
                }
                else if (rc != 0 && (!opts->ignore_missing || saved_errno != ENOENT)) {
                    size_t len = (size_t)snprintf(NULL, 0, "b3sum: %s: %s\n", name, strerror(saved_errno)) + 1;
                    error_str = malloc(len);
                    if (error_str)
                        snprintf(error_str, len, "b3sum: %s: %s\n", name, strerror(saved_errno));
                    any_failure_global = 1;
                    is_failure = 1;
                }
            }

            pthread_mutex_lock(&output_mutex);
            if (output_str) {
                fputs(output_str, stdout);
                fflush(stdout);
            }
            if (error_str) {
                fputs(error_str, stderr);
                fflush(stderr);
            }
            if (is_failure)
                any_failure_global = 1;
            pthread_mutex_unlock(&output_mutex);

            free(output_str);
            free(error_str);

            free(t->filename);
            free(t);
            continue;
        }

        /* normal file path */
        int oflags = O_RDONLY | O_CLOEXEC;
#ifdef O_NOATIME
        if (t->have_stat && (t->st.st_uid == geteuid() || geteuid() == 0)) {
            /* using O_NOATIME avoids atime updates, which improves read-only scan perf
               because otherwise the fs must dirty metadata blocks just to bump atime
               that's a known perf trick for backup/checksum scanners that only read data
               and don't care about accurate atime bookkeeping on Linux :contentReference[oaicite:6]{index=6}
            */
            oflags |= O_NOATIME;
        }
#endif

        int fd = open(name, oflags);
        if (fd < 0) {
            rc = -1;
            saved_errno = errno;
        }
        else {
            struct stat st_local;
            const struct stat* stp = NULL;

            if (t->have_stat) {
                stp = &t->st;
            }
            else {
                if (fstat(fd, &st_local) != 0) {
                    rc = -1;
                    saved_errno = errno;
                    stp = NULL;
                }
                else {
                    stp = &st_local;
                }
            }

            if (rc == 0 && stp) {
                if (S_ISREG(stp->st_mode)) {
                    rc = hash_regular_file_parallel(opts, name, fd, stp, out);
                    if (rc != 0)
                        saved_errno = errno;
                }
                else {
                    rc = hash_fd_stream_fast(fd, stp->st_size, out);
                    if (rc != 0)
                        saved_errno = errno;
                }
            }

            close(fd);
        }

        pthread_mutex_lock(&output_mutex);
        if (t->is_check_mode) {
            if (rc == 0 && memcmp(t->expected_hash, out, BLAKE3_OUT_LEN) == 0) {
                if (!opts->quiet && !opts->status)
                    printf("%s: OK\n", name);
            }
            else {
                any_failure_global = 1;
                if (!opts->status)
                    printf("%s: FAILED\n", name);
            }
        }
        else {
            if (rc == 0 && !opts->status) {
                print_hash(out, name, opts->tag, opts->zero);
            }
            else if (rc != 0 && (!opts->ignore_missing || saved_errno != ENOENT)) {
                fprintf(stderr, "b3sum: %s: %s\n", name, strerror(saved_errno));
                any_failure_global = 1;
            }
        }
        pthread_mutex_unlock(&output_mutex);

        free(t->filename);
        free(t);
    }

    release_tls_io_buffer();
    return NULL;
}

/* pool driver */

static void run_pool_and_wait(const program_opts* opts) {
    int nt = opts->jobs > 0 ? opts->jobs : get_nprocs();
    if (nt < 1)
        nt = 1;

    int num_cores = get_nprocs();
    if (nt > num_cores)
        nt = num_cores;
    if (nt < 1)
        nt = 1;

    pthread_t* thr = malloc(sizeof(pthread_t) * (size_t)nt);
    if (!thr) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < nt; i++) {
        if (pthread_create(&thr[i], NULL, worker_main, (void*)opts) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }
    for (int i = 0; i < nt; i++)
        pthread_join(thr[i], NULL);

    free(thr);
}

/* producer/consumer for --check lines */

static int process_check_files_multithread(int fc, char** files, const program_opts* opts) {
    atomic_store_explicit(&done_submitting_tasks, 0, memory_order_release);

    if (fc == 0) {
        char* line = NULL;
        size_t len = 0;
        ssize_t n;
        while ((n = getline(&line, &len, stdin)) != -1) {
            char* filename = NULL;
            uint8_t expected[BLAKE3_OUT_LEN];
            if (parse_check_line(line, opts, &filename, expected) != 0) {
                if (opts->warn)
                    fprintf(stderr, "b3sum: warning: invalid line in checksum input\n");
                if (opts->strict)
                    any_format_error_global = 1;
                continue;
            }
            enqueue_task_check(filename, expected);
            free(filename);
        }
        free(line);
    }
    else {
        for (int i = 0; i < fc; i++) {
            FILE* f = (strcmp(files[i], "-") == 0) ? stdin : fopen(files[i], "r");
            if (!f) {
                fprintf(stderr, "b3sum: %s: %s\n", files[i], strerror(errno));
                any_failure_global = 1;
                continue;
            }
            char* line = NULL;
            size_t len = 0;
            ssize_t n;
            while ((n = getline(&line, &len, f)) != -1) {
                char* filename = NULL;
                uint8_t expected[BLAKE3_OUT_LEN];
                if (parse_check_line(line, opts, &filename, expected) != 0) {
                    if (opts->warn)
                        fprintf(stderr, "b3sum: warning: invalid line in checksum input\n");
                    if (opts->strict)
                        any_format_error_global = 1;
                    continue;
                }
                enqueue_task_check(filename, expected);
                free(filename);
            }
            free(line);
            if (f != stdin)
                fclose(f);
        }
    }

    atomic_store_explicit(&done_submitting_tasks, 1, memory_order_release);

    pthread_mutex_lock(&q_sleep_mutex);
    pthread_cond_broadcast(&q_sleep_cond);
    pthread_mutex_unlock(&q_sleep_mutex);

    run_pool_and_wait(opts);

    if (any_failure_global)
        return 1;
    if (any_format_error_global && opts->strict)
        return 1;
    return 0;
}

/* producer thread for normal hashing mode */

typedef struct {
    const program_opts* opts;
    int filec;
    char** filev;
} producer_args;

static void* producer_thread_main(void* arg) {
    producer_args* pa = (producer_args*)arg;

    for (int i = 0; i < pa->filec; i++) {
        const char* p = pa->filev[i];
        if (strcmp(p, "-") == 0) {
            enqueue_task_hash_stat("-", NULL);
        }
        else {
            walk_path_streaming(pa->opts, p);
        }
    }

    atomic_store_explicit(&done_submitting_tasks, 1, memory_order_release);

    pthread_mutex_lock(&q_sleep_mutex);
    pthread_cond_broadcast(&q_sleep_cond);
    pthread_mutex_unlock(&q_sleep_mutex);

    return NULL;
}

/* main */

int main(int argc, char** argv) {
    program_opts opts;
    int newi = handle_options(argc, argv, &opts);
    if (newi < 0)
        return EXIT_FAILURE;
    else if (newi == 0)
        return EXIT_SUCCESS;

    int fc = argc - newi;
    char** files = &argv[newi];

    if (opts.check) {
        int r = process_check_files_multithread(fc, files, &opts);
        return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else {
        if (fc == 0) {
            static char* fake[] = {"-"};
            fc = 1;
            files = fake;
        }

        atomic_store_explicit(&done_submitting_tasks, 0, memory_order_release);

        producer_args pa;
        pa.opts = &opts;
        pa.filec = fc;
        pa.filev = files;

        pthread_t prod;
        if (pthread_create(&prod, NULL, producer_thread_main, &pa) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }

        run_pool_and_wait(&opts);

        pthread_join(prod, NULL);

        return any_failure_global ? EXIT_FAILURE : EXIT_SUCCESS;
    }
}
