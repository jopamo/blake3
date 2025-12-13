/*
b3sum:
*/

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <sys/types.h>
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

/* thread local output batching */
#define OUTPUT_BATCH_BUF_SIZE (64 * 1024)  /* 64KB per thread */
static __thread char* tls_out_buf = NULL;
static __thread size_t tls_out_buf_pos = 0;
static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;  // serialize stdout

/* --- forward declarations --- */
static int blake3_hash_region_tree(const uint8_t* data, size_t len, uint8_t out_hash[BLAKE3_OUT_LEN]);

/* --- tls buffer helpers --- */
static inline size_t align_up(size_t value, size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

// ensure_tls_io_buffer
// ensures the thread-local I/O buffer is at least min_bytes large
// grows and reallocates with proper alignment if needed
// returns pointer to buffer or NULL on allocation failure
// sets *actual_size to the buffer capacity if provided

static uint8_t* ensure_tls_io_buffer(size_t min_bytes, size_t* actual_size) {
    if (min_bytes < STREAM_BUF_MIN)
        min_bytes = STREAM_BUF_MIN;

    // fast path if already large enough
    if (min_bytes <= tls_io_buf_cap) {
        if (actual_size)
            *actual_size = tls_io_buf_cap;
        return tls_io_buf;
    }

    // round up to alignment boundary
    size_t aligned = (min_bytes + (IO_BUFFER_ALIGNMENT - 1)) & ~(IO_BUFFER_ALIGNMENT - 1);

    uint8_t* newbuf;
#if defined(_POSIX_C_SOURCE) && (_POSIX_C_SOURCE >= 200112L)
    if (posix_memalign((void**)&newbuf, IO_BUFFER_ALIGNMENT, aligned))
        return NULL;
#else
    newbuf = malloc(aligned);
    if (!newbuf)
        return NULL;
#endif

    free(tls_io_buf);
    tls_io_buf = newbuf;
    tls_io_buf_cap = aligned;

    if (actual_size)
        *actual_size = aligned;

    return tls_io_buf;
}

// release_tls_io_buffer
// frees the thread-local I/O buffer and resets tracking fields
// safe to call multiple times
static void release_tls_io_buffer(void) {
    free(tls_io_buf);
    tls_io_buf = NULL;
    tls_io_buf_cap = 0;
}

// ensure_tls_out_buffer
// ensures the thread-local output buffer is allocated
// returns pointer to buffer or NULL on allocation failure
static char* ensure_tls_out_buffer(void) {
    if (!tls_out_buf) {
        tls_out_buf = malloc(OUTPUT_BATCH_BUF_SIZE);
        if (!tls_out_buf)
            return NULL;
        tls_out_buf_pos = 0;
    }
    return tls_out_buf;
}

// flush_tls_out_buffer
// writes buffered output to stdout under output mutex
static void flush_tls_out_buffer(void) {
    if (tls_out_buf && tls_out_buf_pos > 0) {
        pthread_mutex_lock(&output_mutex);
        fwrite(tls_out_buf, 1, tls_out_buf_pos, stdout);
        pthread_mutex_unlock(&output_mutex);
        tls_out_buf_pos = 0;
    }
}

// release_tls_out_buffer
// frees the thread-local output buffer
static void release_tls_out_buffer(void) {
    flush_tls_out_buffer();
    free(tls_out_buf);
    tls_out_buf = NULL;
    tls_out_buf_pos = 0;
}

/* ──────────────── program options ────────────────
   holds parsed CLI flags and operational modes
   all fields are ints for easy zero-init via memset
*/
typedef struct {
    int check;           // verify hashes instead of printing
    int tag;             // include BLAKE3 tag header
    int zero;            // use null byte terminator
    int ignore_missing;  // skip missing files silently
    int quiet;           // suppress normal output
    int status;          // exit nonzero if mismatch
    int strict;          // reject malformed inputs
    int warn;            // print warnings on parse errors
    int jobs;            // number of worker threads (0 = auto)
} program_opts;

/* ──────────────── task types ────────────────
   currently we only enqueue file hashing tasks
*/
typedef enum { TASK_FILE = 0 } task_kind;

/* ──────────────── work queue item ────────────────
   represents one file hashing job; includes cached metadata
   metadata caching saves syscalls on many small files
*/
typedef struct file_task {
    task_kind kind;
    char* filename;     // owned by task
    int is_check_mode;  // true if comparing to expected hash
    uint8_t expected_hash[BLAKE3_OUT_LEN];
    struct stat st;  // cached stat(2) data
    int have_stat;   // nonzero if st is valid
} file_task;

/* ──────────────── global worker-pool state ──────────────── */


// task queue implemented as a fixed-size ring buffer
static _Atomic size_t q_head = 0;  // next task to consume
static _Atomic size_t q_tail = 0;  // next task to produce
static file_task* task_ring[TASKQ_CAP];

// sleeping coordination for idle consumers
static pthread_mutex_t q_sleep_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t q_sleep_cond = PTHREAD_COND_INITIALIZER;
static _Atomic int q_sleep_counter = 0;

// indicates no more tasks will be enqueued
static _Atomic int done_submitting_tasks = 0;

// result flags aggregated across workers
static int any_failure_global = 0;
static int any_format_error_global = 0;

/* ──────────────── per-file parallel hashing ────────────────
   manages helper threads hashing different chunk ranges of a file
   avoids redundant mmap/fstat overhead between threads
*/
typedef struct {
    int fd;                     // open file descriptor
    off_t size;                 // total file size
    const uint8_t* map;         // memory-mapped region (if used)
    size_t map_len;             // length of mapped region
    size_t total_chunks;        // ceil(size / BLAKE3_CHUNK_LEN)
    uint8_t* cvs;               // per-chunk chaining values
    _Atomic size_t next_chunk;  // atomic cursor for work stealing
    size_t chunks_per_job;      // chunk batch size per helper
    _Atomic int had_error;      // nonzero if any I/O or hash error
    int io_error_code;          // saved errno if had_error != 0
} perfile_ctx;

// forward declarations for file and memory chunk hashing
static void hash_chunk_span_mem(perfile_ctx* ctx, size_t start_index, size_t span_count);
static int hash_chunk_span_fd(perfile_ctx* ctx, size_t start_index, size_t span_count);

// per-thread helper argument structure
typedef struct {
    perfile_ctx* ctx;
} perfile_worker_arg;

/* ──────────────── chunk_len_for_index_pf ────────────────
   returns number of bytes in a given chunk index within a file
   last chunk may be partial
*/
static inline size_t chunk_len_for_index_pf(const perfile_ctx* c, size_t chunk_index) {
    size_t offset = chunk_index * (size_t)BLAKE3_CHUNK_LEN;
    if ((off_t)offset >= c->size)
        return 0;
    size_t remaining = (size_t)c->size - offset;
    return remaining < BLAKE3_CHUNK_LEN ? remaining : BLAKE3_CHUNK_LEN;
}

// cv_from_chunk_bytes
// computes the 32-byte chaining value (CV) for a single BLAKE3 chunk
// mirrors leaf hashing logic: processes input in 64-byte blocks
// applies CHUNK_START/CHUNK_END flags and chunk index as counter
// output CV is used later by the tree hasher
static void cv_from_chunk_bytes(const uint8_t* input, size_t len, uint64_t chunk_counter, uint8_t out_cv[BLAKE3_OUT_LEN]) {
    uint32_t cv[8];
    memcpy(cv, IV, sizeof(IV));

    size_t offset = 0;
    int first = 1;

    // process all full 64-byte blocks except the last
    while (len - offset > BLAKE3_BLOCK_LEN) {
        blake3_compress_in_place(cv, input + offset, BLAKE3_BLOCK_LEN, chunk_counter, first ? CHUNK_START : 0);
        first = 0;
        offset += BLAKE3_BLOCK_LEN;
    }

    // prepare last block (possibly partial)
    size_t tail_len = len - offset;
    uint8_t block[BLAKE3_BLOCK_LEN];
    const uint8_t* tail = input + offset;

    if (tail_len != BLAKE3_BLOCK_LEN) {
        memcpy(block, tail, tail_len);
        if (tail_len < BLAKE3_BLOCK_LEN)
            memset(block + tail_len, 0, BLAKE3_BLOCK_LEN - tail_len);
        tail = block;
    }

    uint8_t flags = CHUNK_END | (first ? CHUNK_START : 0);
    blake3_compress_in_place(cv, tail, (uint8_t)tail_len, chunk_counter, flags);

    store_cv_words(out_cv, cv);
}

// hash_chunk_span_mem
// hashes a contiguous span of chunks directly from mapped file memory
// uses SIMD-parallel blake3_hash_many for full-width groups,
// falling back to scalar cv_from_chunk_bytes for any trailing partial chunks
// stores each 32-byte chaining value (CV) sequentially into ctx->cvs
static void hash_chunk_span_mem(perfile_ctx* ctx, size_t start_index, size_t span_count) {
    if (span_count == 0)
        return;

    const size_t simd = blake3_simd_degree() ?: 1;
    const size_t chunk_len = BLAKE3_CHUNK_LEN;
    const size_t blocks_per_chunk = chunk_len / BLAKE3_BLOCK_LEN;
    const uint8_t* base = ctx->map;
    const size_t total_size = (size_t)ctx->size;

    const uint8_t* inputs[MAX_SIMD_DEGREE];
    size_t idx = start_index;
    size_t remain = span_count;

    // process full SIMD-width groups
    while (remain >= simd) {
        for (size_t i = 0; i < simd; i++)
            inputs[i] = base + (idx + i) * chunk_len;

        blake3_hash_many(inputs, simd, blocks_per_chunk, IV, idx, true, 0, CHUNK_START, CHUNK_END, ctx->cvs + idx * BLAKE3_OUT_LEN);

        idx += simd;
        remain -= simd;
    }

    // handle tail chunks (not a full SIMD group)
    while (remain--) {
        size_t off = idx * chunk_len;
        if (off >= total_size) {
            memset(ctx->cvs + idx * BLAKE3_OUT_LEN, 0, BLAKE3_OUT_LEN);
            idx++;
            continue;
        }

        size_t len = total_size - off;
        if (len >= chunk_len) {
            inputs[0] = base + off;
            blake3_hash_many(inputs, 1, blocks_per_chunk, IV, idx, true, 0, CHUNK_START, CHUNK_END, ctx->cvs + idx * BLAKE3_OUT_LEN);
        }
        else {
            cv_from_chunk_bytes(base + off, len, idx, ctx->cvs + idx * BLAKE3_OUT_LEN);
        }
        idx++;
    }
}

// hash_chunk_span_fd
// reads and hashes a range of chunks directly from file descriptor ctx->fd
// falls back to pread() for each chunk when mmap is unavailable
// uses a TLS-aligned buffer and SIMD hashing for throughput
// returns 0 on success or -1 on I/O/memory error (errno stored in ctx->io_error_code)
static int hash_chunk_span_fd(perfile_ctx* ctx, size_t start_index, size_t span_count) {
    if (span_count == 0)
        return 0;

    const size_t chunk_len = BLAKE3_CHUNK_LEN;
    const size_t total_bytes = span_count * chunk_len;

    size_t buf_cap = 0;
    uint8_t* buf = ensure_tls_io_buffer(total_bytes, &buf_cap);
    if (!buf || buf_cap < total_bytes) {
        ctx->io_error_code = ENOMEM;
        return -1;
    }

    // read each chunk fully into TLS buffer
    for (size_t i = 0; i < span_count; i++) {
        size_t chunk_idx = start_index + i;
        size_t len = chunk_len_for_index_pf(ctx, chunk_idx);
        uint8_t* dst = buf + i * chunk_len;

        if (len == 0) {
            memset(dst, 0, chunk_len);
            continue;
        }

        off_t off = (off_t)((uint64_t)chunk_idx * chunk_len);
        size_t done = 0;
        while (done < len) {
            ssize_t r = pread(ctx->fd, dst + done, len - done, off + (off_t)done);
            if (r > 0) {
                done += (size_t)r;
                continue;
            }
            if (r == 0) {  // unexpected EOF
                ctx->io_error_code = EIO;
                return -1;
            }
            if (errno == EINTR)
                continue;
            ctx->io_error_code = errno;
            return -1;
        }

        if (len < chunk_len)
            memset(dst + len, 0, chunk_len - len);
    }

    const size_t simd = blake3_simd_degree() ?: 1;
    const size_t blocks_per_chunk = chunk_len / BLAKE3_BLOCK_LEN;
    const uint8_t* inputs[MAX_SIMD_DEGREE];

    size_t idx = 0;
    size_t remain = span_count;

    // process full SIMD-width groups
    while (remain >= simd) {
        for (size_t i = 0; i < simd; i++)
            inputs[i] = buf + (idx + i) * chunk_len;

        blake3_hash_many(inputs, simd, blocks_per_chunk, IV, start_index + idx, true, 0, CHUNK_START, CHUNK_END, ctx->cvs + (start_index + idx) * BLAKE3_OUT_LEN);

        idx += simd;
        remain -= simd;
    }

    // handle any tail chunks
    while (remain--) {
        inputs[0] = buf + idx * chunk_len;
        cv_from_chunk_bytes(inputs[0], chunk_len, start_index + idx, ctx->cvs + (start_index + idx) * BLAKE3_OUT_LEN);
        idx++;
    }

    return 0;
}

// perfile_worker_proc
// worker thread entry for hashing assigned chunk ranges of one file
// repeatedly claims chunk batches atomically from ctx->next_chunk
// exits when all chunks are done or an error occurs in any thread
static void* perfile_worker_proc(void* arg) {
    perfile_ctx* ctx = ((perfile_worker_arg*)arg)->ctx;
    const size_t job = ctx->chunks_per_job;

    for (;;) {
        // atomically claim a span of chunks
        size_t start = atomic_fetch_add_explicit(&ctx->next_chunk, job, memory_order_acq_rel);
        if (start >= ctx->total_chunks)
            break;

        size_t span = ctx->total_chunks - start;
        if (span > job)
            span = job;

        // early exit if another worker reported failure
        if (atomic_load_explicit(&ctx->had_error, memory_order_acquire))
            break;

        // choose optimal source (mmap or direct fd)
        int err = 0;
        if (ctx->map)
            hash_chunk_span_mem(ctx, start, span);
        else if ((err = hash_chunk_span_fd(ctx, start, span)) != 0)
            atomic_store_explicit(&ctx->had_error, 1, memory_order_release);

        if (err)
            break;
    }

    return NULL;
}

// build_all_chunk_cvs
// hashes all chunks in the file (mapped or read from fd) and fills ctx->cvs
// batches work in SIMD-width groups for maximum parallelism
// returns 0 on success or -1 on I/O/memory error
static int build_all_chunk_cvs(perfile_ctx* ctx) {
    const size_t simd = blake3_simd_degree() ?: 1;
    size_t done = 0;
    const size_t total = ctx->total_chunks;

    while (done < total) {
        size_t remain = total - done;
        size_t batch = remain >= simd ? simd * (remain / simd) : remain;

        int err = 0;
        if (ctx->map)
            hash_chunk_span_mem(ctx, done, batch);
        else if ((err = hash_chunk_span_fd(ctx, done, batch)) != 0)
            return -1;

        done += batch;
    }

    return 0;
}

// reduce_cvs_to_two
// reduces an array of per-chunk chaining values (CVs) into ≤2 parents
// performs binary tree compression in SIMD batches using blake3_hash_many
// returns the new CV count (1 or 2)
static size_t reduce_cvs_to_two(uint8_t* cvs, size_t cv_count) {
    if (cv_count <= 2)
        return cv_count;

    const size_t simd = blake3_simd_degree() ?: 1;
    const size_t max_deg = simd > MAX_SIMD_DEGREE ? MAX_SIMD_DEGREE : simd;

    uint8_t blocks[MAX_SIMD_DEGREE * BLAKE3_BLOCK_LEN];
    const uint8_t* ptrs[MAX_SIMD_DEGREE];

    size_t n = cv_count;

    while (n > 2) {
        size_t out = 0, i = 0;

        // combine pairs of CVs into parents
        while (i + 1 < n) {
            size_t batch = 0;
            for (; batch < max_deg && i + 1 < n; batch++, i += 2) {
                uint8_t* blk = blocks + batch * BLAKE3_BLOCK_LEN;
                memcpy(blk, cvs + i * BLAKE3_OUT_LEN, BLAKE3_OUT_LEN);
                memcpy(blk + BLAKE3_OUT_LEN, cvs + (i + 1) * BLAKE3_OUT_LEN, BLAKE3_OUT_LEN);
                ptrs[batch] = blk;
            }

            blake3_hash_many(ptrs, batch, 1, IV, 0, false, PARENT, 0, 0, cvs + out * BLAKE3_OUT_LEN);
            out += batch;
        }

        // handle odd leftover CV
        if (i < n) {
            if (out != i)
                memmove(cvs + out * BLAKE3_OUT_LEN, cvs + i * BLAKE3_OUT_LEN, BLAKE3_OUT_LEN);
            out++;
        }

        n = out;
    }

    return n;
}

// root_output_from_two_cvs
// combines two child CVs into the root hash output
// uses PARENT|ROOT flags for final compression, matching official BLAKE3 output
static void root_output_from_two_cvs(const uint8_t left[BLAKE3_OUT_LEN], const uint8_t right[BLAKE3_OUT_LEN], uint8_t out_hash[BLAKE3_OUT_LEN]) {
    uint8_t block[BLAKE3_BLOCK_LEN];
    memcpy(block, left, BLAKE3_OUT_LEN);
    memcpy(block + BLAKE3_OUT_LEN, right, BLAKE3_OUT_LEN);

    uint8_t wide[64];
    blake3_compress_xof(IV, block, BLAKE3_BLOCK_LEN, 0, (uint8_t)(PARENT | ROOT), wide);

    memcpy(out_hash, wide, BLAKE3_OUT_LEN);
}

// perfile_finalize_hash
// final reduction and output stage for a single file hash
// combines per-chunk CVs into a single digest identical to standard BLAKE3
// returns 0 on success or -1 on error (errno set)
static int perfile_finalize_hash(perfile_ctx* ctx, uint8_t out_hash[BLAKE3_OUT_LEN]) {
    if (atomic_load_explicit(&ctx->had_error, memory_order_acquire)) {
        errno = ctx->io_error_code ? ctx->io_error_code : EIO;
        return -1;
    }

    // special case: single small chunk (fast path)
    if (ctx->total_chunks == 1) {
        blake3_hasher h;
        blake3_hasher_init(&h);

        size_t len = (size_t)ctx->size;
        const uint8_t* data = NULL;
        size_t buf_sz = 0;

        if (ctx->map) {
            data = ctx->map;
        }
        else {
            if (lseek(ctx->fd, 0, SEEK_SET) == (off_t)-1) {
                errno = EIO;
                return -1;
            }
            data = ensure_tls_io_buffer(len, &buf_sz);
            if (!data || buf_sz < len) {
                errno = ENOMEM;
                return -1;
            }

            size_t have = 0;
            while (have < len) {
                ssize_t r = read(ctx->fd, (uint8_t*)data + have, len - have);
                if (r > 0) {
                    have += (size_t)r;
                    continue;
                }
                if (r == 0) {
                    errno = EIO;
                    return -1;
                }
                if (errno != EINTR) {
                    errno = EIO;
                    return -1;
                }
            }
        }

        blake3_hasher_update(&h, data, len);
        blake3_hasher_finalize(&h, out_hash, BLAKE3_OUT_LEN);
        return 0;
    }

    // reduce to 1 or 2 CVs, then finalize
    size_t remain = reduce_cvs_to_two(ctx->cvs, ctx->total_chunks);

    if (remain == 2) {
        root_output_from_two_cvs(ctx->cvs, ctx->cvs + BLAKE3_OUT_LEN, out_hash);
        return 0;
    }

    if (remain == 1) {
        memcpy(out_hash, ctx->cvs, BLAKE3_OUT_LEN);
        return 0;
    }

    errno = EIO;
    return -1;
}

// hash_regular_file_parallel
// hashes a regular file using BLAKE3 tree mode
// - mmaps file when possible
// - processes chunks in parallel via a local worker team
// - reduces all chaining values to a single root digest
// returns 0 on success, -1 on error (errno set)
static int hash_regular_file_parallel(const program_opts* opts, const char* name, int fd, const struct stat* st, uint8_t out_hash[BLAKE3_OUT_LEN]) {
    (void)opts;
    (void)name;

    perfile_ctx ctx = {0};
    ctx.fd = fd;
    ctx.size = st->st_size;
    atomic_store_explicit(&ctx.had_error, 0, memory_order_release);
    ctx.io_error_code = 0;

    // try mmap for read-mostly workloads
    if (ctx.size > 0) {
        void* m = mmap(NULL, (size_t)ctx.size, PROT_READ, MAP_SHARED, fd, 0);
        if (m != MAP_FAILED) {
#if defined(POSIX_MADV_SEQUENTIAL) && !defined(__APPLE__)
            posix_madvise(m, (size_t)ctx.size, POSIX_MADV_SEQUENTIAL);
#endif
            ctx.map = (const uint8_t*)m;
            ctx.map_len = (size_t)ctx.size;
        }
    }

    // total chunk count
    ctx.total_chunks = (ctx.size + BLAKE3_CHUNK_LEN - 1) / BLAKE3_CHUNK_LEN;
    if (ctx.total_chunks == 0)
        ctx.total_chunks = 1;

    // fast path for small files (≤8 MiB)
    if (ctx.total_chunks == 1 || ctx.size <= (8u << 20)) {
        int rc;
        if (ctx.map)
            rc = blake3_hash_region_tree(ctx.map, (size_t)ctx.size, out_hash);
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
                ssize_t r = read(fd, buf + have, (size_t)ctx.size - have);
                if (r > 0) {
                    have += (size_t)r;
                    continue;
                }
                if (r == 0) {
                    errno = EIO;
                    break;
                }
                if (errno != EINTR) {
                    errno = EIO;
                    break;
                }
            }
            if (have != (size_t)ctx.size) {
                if (ctx.map)
                    munmap((void*)ctx.map, ctx.map_len);
                return -1;
            }
            rc = blake3_hash_region_tree(buf, (size_t)ctx.size, out_hash);
        }

        if (ctx.map)
            munmap((void*)ctx.map, ctx.map_len);
        return rc;
    }

    // allocate per-chunk CV array
    ctx.cvs = malloc(ctx.total_chunks * BLAKE3_OUT_LEN);
    if (!ctx.cvs) {
        if (ctx.map)
            munmap((void*)ctx.map, ctx.map_len);
        errno = ENOMEM;
        return -1;
    }

    // large file path: multi-threaded chunk hashing
    if (ctx.size > (8u << 20)) {
        atomic_store_explicit(&ctx.next_chunk, 0, memory_order_release);

        size_t simd = blake3_simd_degree() ?: 1;
        size_t chunks_per_job = (ctx.total_chunks > 1024) ? 512 : (ctx.total_chunks > 256) ? 128 : 64;
        size_t rounded = (chunks_per_job / simd) * simd;
        ctx.chunks_per_job = rounded ? rounded : 1;

        int cores = get_nprocs();
        int threads = cores < (int)ctx.total_chunks ? cores : (int)ctx.total_chunks;
        if (threads < 1)
            threads = 1;
        if (threads > 16)
            threads = 16;

        pthread_t* pool = malloc(sizeof(pthread_t) * (size_t)threads);
        if (!pool) {
            if (ctx.map)
                munmap((void*)ctx.map, ctx.map_len);
            free(ctx.cvs);
            errno = ENOMEM;
            return -1;
        }

        perfile_worker_arg arg = {.ctx = &ctx};
        int started = 0;

        for (int i = 0; i < threads; i++) {
            if (pthread_create(&pool[i], NULL, perfile_worker_proc, &arg) != 0)
                break;
            started++;
        }

        // main thread assists
        perfile_worker_proc(&arg);

        for (int i = 0; i < started; i++)
            pthread_join(pool[i], NULL);

        free(pool);
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

    // reduce and finalize
    int rc = perfile_finalize_hash(&ctx, out_hash);

    if (ctx.map)
        munmap((void*)ctx.map, ctx.map_len);
    free(ctx.cvs);
    return rc;
}

/* ─── spin-wait hint ────────────────────────────────────────────────
   cpu_relax() gives the processor a short pause hint inside spin loops
   prevents excessive pipeline stalls and power waste during contention
   maps to the correct intrinsic per architecture
*/

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#define cpu_relax() _mm_pause()
#elif defined(__aarch64__) || defined(__arm__)
#define cpu_relax() __asm__ __volatile__("yield" ::: "memory")
#else
#define cpu_relax() ((void)0)
#endif

/* ─── queue sentinel ────────────────────────────────────────────────
   special non-null marker for “no task yet, but not done”
   must differ from NULL so workers can sleep safely without consuming end flag
*/
#ifndef TASK_EMPTY_NOT_DONE
#define TASK_EMPTY_NOT_DONE ((file_task*)0x1)
#endif

// enqueue_task_lockfree
// pushes one task pointer into the global ring buffer
// returns 0 on success, -1 if queue is full
// lock-free for the fast path; only locks for condition wake-up when consumers sleep
static int enqueue_task_lockfree(file_task* t) {
    for (;;) {
        size_t tail = atomic_load_explicit(&q_tail, memory_order_relaxed);
        size_t head = atomic_load_explicit(&q_head, memory_order_acquire);

        // ring full: (tail - head) == TASKQ_CAP
        if ((tail - head) >= TASKQ_CAP)
            return -1;

        // claim a slot
        if (atomic_compare_exchange_weak_explicit(&q_tail, &tail, tail + 1, memory_order_acq_rel, memory_order_relaxed)) {
            task_ring[tail & TASKQ_MASK] = t;

            // only wake if a sleeper exists
            if (atomic_load_explicit(&q_sleep_counter, memory_order_relaxed) > 0) {
                pthread_mutex_lock(&q_sleep_mutex);
                pthread_cond_broadcast(&q_sleep_cond);
                pthread_mutex_unlock(&q_sleep_mutex);
            }
            return 0;
        }
        // CAS failed: another producer raced; retry
        cpu_relax();  // optional spin hint
    }
}

// enqueue_task
// retries until the task is successfully pushed
static void enqueue_task(file_task* t) {
    while (enqueue_task_lockfree(t) != 0)
        sched_yield();
}

// dequeue_task_lockfree
// pops a task pointer from the global ring buffer
// returns:
//   - valid task pointer if available
//   - TASK_EMPTY_NOT_DONE if queue empty but producers may add more
//   - NULL if queue empty and producers are finished
static file_task* dequeue_task_lockfree(void) {
    for (;;) {
        size_t head = atomic_load_explicit(&q_head, memory_order_relaxed);
        size_t tail = atomic_load_explicit(&q_tail, memory_order_acquire);

        if (head == tail) {
            if (atomic_load_explicit(&done_submitting_tasks, memory_order_acquire))
                return NULL;
            return TASK_EMPTY_NOT_DONE;
        }

        // claim next task
        if (atomic_compare_exchange_weak_explicit(&q_head, &head, head + 1, memory_order_acq_rel, memory_order_relaxed)) {
            return task_ring[head & TASKQ_MASK];
        }
        cpu_relax();  // optional spin hint
    }
}

// dequeue_task
// blocking consumer side of the task queue
// waits via condition variable when queue is empty but producers still active
// returns:
//   - valid file_task* when available
//   - NULL when producers are done and queue fully drained
static file_task* dequeue_task(void) {
    for (;;) {
        file_task* t = dequeue_task_lockfree();
        if (t == NULL)
            return NULL;  // all done
        if (t != TASK_EMPTY_NOT_DONE)
            return t;  // got a task

        // sleep until producer signals new work
        pthread_mutex_lock(&q_sleep_mutex);
        atomic_fetch_add_explicit(&q_sleep_counter, 1, memory_order_relaxed);

        size_t head = atomic_load_explicit(&q_head, memory_order_relaxed);
        size_t tail = atomic_load_explicit(&q_tail, memory_order_acquire);

        // only sleep if queue still empty and not finished
        if (head == tail && !atomic_load_explicit(&done_submitting_tasks, memory_order_acquire))
            pthread_cond_wait(&q_sleep_cond, &q_sleep_mutex);

        atomic_fetch_sub_explicit(&q_sleep_counter, 1, memory_order_relaxed);
        pthread_mutex_unlock(&q_sleep_mutex);
    }
}

/* ──────────────── CLI and formatting helpers ──────────────── */

static void print_help(void) {
    puts(
        "Usage: b3sum [OPTION]... [FILE]...\n"
        "Compute or verify BLAKE3 (256-bit) checksums\n\n"
        "Options:\n"
        "  -c, --check           read checksums from FILEs and verify\n"
        "      --tag             use BSD-style output format\n"
        "  -z, --zero            end lines with NUL, not newline\n"
        "      --ignore-missing  skip missing files without error\n"
        "      --quiet           suppress OK status output\n"
        "      --status          exit code only, no output\n"
        "      --strict          fail on malformed input lines\n"
        "  -w, --warn            warn on malformed input lines\n"
        "  -j, --jobs N          number of worker threads (default: CPUs)\n"
        "      --help            show this help and exit\n"
        "      --version         show version and exit\n");
}

static void print_version(void) {
    puts("b3sum (optimized build)");
}

// handle_options
// parses command-line flags into opts
// returns index of first non-option argument or 0 on --help/--version, -1 on error
static int handle_options(int argc, char** argv, program_opts* opts) {
    memset(opts, 0, sizeof(*opts));
    opts->jobs = 0;  // auto

    static const struct option long_opts[] = {{"check", no_argument, NULL, 'c'},          {"tag", no_argument, NULL, 't'},     {"zero", no_argument, NULL, 'z'},
                                              {"ignore-missing", no_argument, NULL, 'i'}, {"quiet", no_argument, NULL, 'q'},   {"status", no_argument, NULL, 's'},
                                              {"strict", no_argument, NULL, 'S'},         {"warn", no_argument, NULL, 'w'},    {"jobs", required_argument, NULL, 'j'},
                                              {"help", no_argument, NULL, 'h'},           {"version", no_argument, NULL, 'v'}, {0, 0, 0, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "ctziqsSwj:hv", long_opts, NULL)) != -1) {
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
                fputs("Try 'b3sum --help' for more information\n", stderr);
                return -1;
        }
    }
    return optind;
}

// unescape_filename
// converts "\n" → newline and "\\" → '\' in place
// returns heap-allocated decoded string or NULL on OOM
static char* unescape_filename(const char* in) {
    size_t len = strlen(in);
    char* out = malloc(len + 1);
    if (!out)
        return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len;) {
        if (in[i] == '\\' && i + 1 < len) {
            char next = in[i + 1];
            if (next == 'n') {
                out[j++] = '\n';
                i += 2;
                continue;
            }
            else if (next == '\\') {
                out[j++] = '\\';
                i += 2;
                continue;
            }
        }
        out[j++] = in[i++];
    }
    out[j] = '\0';
    return out;
}

// print_hash
// prints a formatted BLAKE3 hash and filename with optional escaping/tag/null terminator
static void print_hash(const uint8_t* hash, const char* filename, int tag, int zero) {
    if (tag)
        fputs("BLAKE3 ", stdout);

    for (size_t i = 0; i < BLAKE3_OUT_LEN; i++)
        printf("%02x", hash[i]);

    if (zero) {
        printf("  %s%c", *filename ? filename : "-", '\0');
        return;
    }

    int needs_escape = 0;
    for (const char* p = filename; *p; ++p)
        if (*p == '\n' || *p == '\\') {
            needs_escape = 1;
            break;
        }

    if (needs_escape)
        putchar('\\');
    fputs("  ", stdout);

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

// parse_hex_hash
// decodes a 64-char hex string into 32-byte hash
// returns 0 on success, -1 on invalid input
static int parse_hex_hash(const char* hex, uint8_t* out) {
    for (size_t i = 0; i < BLAKE3_OUT_LEN; i++) {
        unsigned char a = hex[2 * i], b = hex[2 * i + 1];
        if (!isxdigit(a) || !isxdigit(b))
            return -1;
        char tmp[3] = {a, b, 0};
        unsigned long v = strtoul(tmp, NULL, 16);
        if (v > 0xFF)
            return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

// parse_check_line
// parses one checksum line (hex + "  filename") and outputs hash + decoded filename
// supports BSD-style "BLAKE3 " prefix and escaped filenames
// returns 0 on success, -1 on format/alloc error
static int parse_check_line(const char* line_in, const program_opts* opts, char** filename_out, uint8_t* hash_out) {
    char* line = strdup(line_in);
    if (!line)
        return -1;

    // strip trailing newline/CR
    char* end = line + strlen(line);
    while (end > line && (end[-1] == '\n' || end[-1] == '\r'))
        *--end = '\0';

    const char* p = line;
    if (opts->tag) {
        static const char prefix[] = "BLAKE3 ";
        size_t plen = sizeof(prefix) - 1;
        if (strncmp(p, prefix, plen) != 0) {
            free(line);
            return -1;
        }
        p += plen;
    }

    int needs_unescape = (!opts->zero && *p == '\\');
    if (needs_unescape)
        p++;

    char* sep = strstr((char*)p, "  ");
    if (!sep)
        sep = strstr((char*)p, " *");
    if (!sep) {
        free(line);
        return -1;
    }

    size_t hex_len = (size_t)(sep - p);
    if (hex_len != BLAKE3_OUT_LEN * 2 || parse_hex_hash(p, hash_out) != 0) {
        free(line);
        return -1;
    }

    const char* fname = sep + 2;
    if (!*fname) {
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

// blake3_hash_region_tree
// hashes a contiguous memory region using standard BLAKE3 tree mode
// returns 0 on success
static int blake3_hash_region_tree(const uint8_t* data, size_t len, uint8_t out_hash[BLAKE3_OUT_LEN]) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, len);
    blake3_hasher_finalize(&h, out_hash, BLAKE3_OUT_LEN);
    return 0;
}

// hash_fd_stream_with_buffer
// hashes an open file descriptor using a user-supplied buffer
// uses sequential reads and supports full-buffer fast path for small files
// returns 0 on success, -1 on error (errno set)
static int hash_fd_stream_with_buffer(int fd, off_t filesize, uint8_t* output, uint8_t* buf, size_t buf_sz) {
    if (!buf || buf_sz < 1024) {
        errno = ENOMEM;
        return -1;
    }

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);

    // fast path: entire file fits in buffer
    if (filesize > 0 && (size_t)filesize <= buf_sz) {
        size_t want = (size_t)filesize;
        size_t have = 0;
        while (have < want) {
            ssize_t r = read(fd, buf + have, want - have);
            if (r > 0) {
                have += (size_t)r;
                continue;
            }
            if (r == 0) {
                errno = EIO;
                return -1;
            }
            if (errno == EINTR)
                continue;
            return -1;
        }
        return blake3_hash_region_tree(buf, want, output);
    }

#if defined(POSIX_FADV_SEQUENTIAL) && !defined(__APPLE__)
    if (filesize > 0)
        posix_fadvise(fd, 0, filesize, POSIX_FADV_SEQUENTIAL);
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

// hash_fd_stream_fast
// fast wrapper around hash_fd_stream_with_buffer()
// chooses optimal TLS buffer size and delegates streaming
// returns 0 on success or -1 on error (errno set)
static int hash_fd_stream_fast(int fd, off_t filesize, uint8_t* output) {
    size_t request = STREAM_BUF_MAX;

    // shrink buffer if file smaller than STREAM_BUF_MAX
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

/* ──────────────── enqueue helpers ──────────────── */

// enqueue_task_hash_stat
// enqueues a file hash task with optional pre-fetched stat(2) metadata
// ensures allocation failures exit immediately
static void enqueue_task_hash_stat(const char* filename, const struct stat* st_opt) {
    file_task* t = calloc(1, sizeof(*t));
    if (!t) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    const char* src = filename ? filename : "-";
    t->filename = strdup(src);
    if (!t->filename) {
        perror("strdup");
        free(t);
        exit(EXIT_FAILURE);
    }

    t->kind = TASK_FILE;
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

// enqueue_task_hash
// convenience wrapper: enqueue a hash task without stat info
__attribute__((unused)) static void enqueue_task_hash(const char* filename) {
    enqueue_task_hash_stat(filename, NULL);
}

// enqueue_task_check
// enqueues a checksum verification task with expected digest
// exits on allocation failure for consistent robustness
static void enqueue_task_check(const char* filename, const uint8_t expected[BLAKE3_OUT_LEN]) {
    file_task* t = calloc(1, sizeof(*t));
    if (!t) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    const char* src = filename ? filename : "-";
    t->filename = strdup(src);
    if (!t->filename) {
        perror("strdup");
        free(t);
        exit(EXIT_FAILURE);
    }

    t->kind = TASK_FILE;
    t->is_check_mode = 1;
    memcpy(t->expected_hash, expected, BLAKE3_OUT_LEN);
    memset(&t->st, 0, sizeof(t->st));
    t->have_stat = 0;

    enqueue_task(t);
}

// dir_stack
// simple dynamic stack for directory paths (DFS)
typedef struct {
    char** data;
    size_t len;
    size_t cap;
} dir_stack;

// ds_push
// pushes a copy of path onto the stack, growing if needed
static void ds_push(dir_stack* s, const char* path) {
    if (s->len == s->cap) {
        size_t new_cap = s->cap ? s->cap * 2 : 16;
        char** new_data = realloc(s->data, new_cap * sizeof(char*));
        if (!new_data) {
            perror("realloc");
            exit(EXIT_FAILURE);
        }
        s->data = new_data;
        s->cap = new_cap;
    }

    char* copy = strdup(path);
    if (!copy) {
        perror("strdup");
        exit(EXIT_FAILURE);
    }
    s->data[s->len++] = copy;
}

// ds_pop
// pops a path pointer from the stack (caller must free)
static char* ds_pop(dir_stack* s) {
    return (s->len == 0) ? NULL : s->data[--s->len];
}

// walk_path_streaming
// performs a non-recursive DFS over root_path
// enqueues regular files for hashing, recurses into subdirectories
// errors (e.g., unreadable dirs or files) are still enqueued for worker reporting
static void walk_path_streaming(const program_opts* opts, const char* root_path) {
    (void)opts;

    struct stat st;
    if (lstat(root_path, &st) != 0) {
        enqueue_task_hash_stat(root_path, NULL);
        return;
    }

    // handle single file or symlink
    if (!S_ISDIR(st.st_mode)) {
        enqueue_task_hash_stat(root_path, &st);
        return;
    }

    // initialize stack with the starting directory
    dir_stack stack = {0};
    ds_push(&stack, root_path);

    while (stack.len > 0) {
        char* dirpath = ds_pop(&stack);
        DIR* d = opendir(dirpath);
        if (!d) {
            enqueue_task_hash_stat(dirpath, NULL);
            free(dirpath);
            continue;
        }

        struct dirent* de;
        while ((de = readdir(d)) != NULL) {
            const char* n = de->d_name;

            // skip "." and ".."
            if (n[0] == '.' && (n[1] == '\0' || (n[1] == '.' && n[2] == '\0')))
                continue;

            char child_path[PATH_MAX];
            size_t dl = strlen(dirpath);
            int slash = (dl && dirpath[dl - 1] != '/');
            int written = snprintf(child_path, sizeof(child_path), slash ? "%s/%s" : "%s%s", dirpath, n);
            if (written < 0 || (size_t)written >= sizeof(child_path)) {
                // skip paths too long
                fprintf(stderr, "warning: path too long, skipped: %s/%s\n", dirpath, n);
                continue;
            }

            struct stat cst;
            if (lstat(child_path, &cst) != 0) {
                enqueue_task_hash_stat(child_path, NULL);
                continue;
            }

            if (S_ISDIR(cst.st_mode))
                ds_push(&stack, child_path);
            else
                enqueue_task_hash_stat(child_path, &cst);
        }

        closedir(d);
        free(dirpath);

        // wake sleeping workers periodically so they can drain the queue
        pthread_mutex_lock(&q_sleep_mutex);
        pthread_cond_broadcast(&q_sleep_cond);
        pthread_mutex_unlock(&q_sleep_mutex);
    }

    free(stack.data);
}

// worker_main
// worker thread entry point
// consumes tasks from global queue, hashes files or stdin, and prints output
// exits when no tasks remain
static void* worker_main(void* arg) {
    const program_opts* opts = (const program_opts*)arg;
    uint8_t out[BLAKE3_OUT_LEN];

    for (;;) {
        file_task* t = dequeue_task();
        if (!t)
            break;  // no more tasks

        if (t->kind != TASK_FILE) {
            free(t->filename);
            free(t);
            continue;
        }

        const char* name = t->filename ? t->filename : "-";
        int rc = 0;
        int saved_errno = 0;

        // ───── handle STDIN path ─────
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
                if (rc == 0 && !opts->status)
                    print_hash(out, name, opts->tag, opts->zero);
                else if (rc != 0 && (!opts->ignore_missing || saved_errno != ENOENT)) {
                    fprintf(stderr, "b3sum: %s: %s\n", name, strerror(saved_errno));
                    any_failure_global = 1;
                }
            }
            pthread_mutex_unlock(&output_mutex);
            free(t->filename);
            free(t);
            continue;
        }

        // ───── handle regular file path ─────
        int oflags = O_RDONLY | O_CLOEXEC;
#ifdef O_NOATIME
        // skip atime updates for local files or root-owned access
        if (t->have_stat && (t->st.st_uid == geteuid() || geteuid() == 0))
            oflags |= O_NOATIME;
#endif

        int fd = open(name, oflags);
        if (fd < 0) {
            rc = -1;
            saved_errno = errno;
        }
        else {
            struct stat st_local;
            const struct stat* stp = t->have_stat ? &t->st : NULL;

            if (!stp) {
                if (fstat(fd, &st_local) == 0)
                    stp = &st_local;
                else {
                    rc = -1;
                    saved_errno = errno;
                }
            }

            if (rc == 0 && stp) {
                if (S_ISREG(stp->st_mode)) {
                    rc = hash_regular_file_parallel(opts, name, fd, stp, out);
                }
                else {
                    rc = hash_fd_stream_fast(fd, stp->st_size, out);
                }
                if (rc != 0)
                    saved_errno = errno;
            }

            close(fd);
        }

        pthread_mutex_lock(&output_mutex);
        if (t->is_check_mode) {
            int ok = (rc == 0 && memcmp(t->expected_hash, out, BLAKE3_OUT_LEN) == 0);
            if (ok) {
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
            if (rc == 0 && !opts->status)
                print_hash(out, name, opts->tag, opts->zero);
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

// run_pool_and_wait
// spawns a worker pool, waits for completion, and joins all threads
static void run_pool_and_wait(const program_opts* opts) {
    int nthreads = opts->jobs > 0 ? opts->jobs : get_nprocs();
    if (nthreads < 1)
        nthreads = 1;

    int cores = get_nprocs();
    if (nthreads > cores)
        nthreads = cores;

    pthread_t* threads = malloc(sizeof(pthread_t) * (size_t)nthreads);
    if (!threads) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < nthreads; i++) {
        if (pthread_create(&threads[i], NULL, worker_main, (void*)opts) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    free(threads);
}

/* ──────────────── checksum verification (–-check mode) ──────────────── */

static int process_check_files_multithread(int fc, char** files, const program_opts* opts) {
    atomic_store_explicit(&done_submitting_tasks, 0, memory_order_release);

    char* line = NULL;
    size_t len = 0;

    if (fc == 0) {
        // read from stdin
        while (getline(&line, &len, stdin) != -1) {
            char* fname = NULL;
            uint8_t expected[BLAKE3_OUT_LEN];
            if (parse_check_line(line, opts, &fname, expected) != 0) {
                if (opts->warn)
                    fputs("b3sum: warning: invalid line in checksum input\n", stderr);
                if (opts->strict)
                    any_format_error_global = 1;
                continue;
            }
            enqueue_task_check(fname, expected);
            free(fname);
        }
    }
    else {
        for (int i = 0; i < fc; i++) {
            FILE* f = (strcmp(files[i], "-") == 0) ? stdin : fopen(files[i], "r");
            if (!f) {
                fprintf(stderr, "b3sum: %s: %s\n", files[i], strerror(errno));
                any_failure_global = 1;
                continue;
            }

            while (getline(&line, &len, f) != -1) {
                char* fname = NULL;
                uint8_t expected[BLAKE3_OUT_LEN];
                if (parse_check_line(line, opts, &fname, expected) != 0) {
                    if (opts->warn)
                        fputs("b3sum: warning: invalid line in checksum input\n", stderr);
                    if (opts->strict)
                        any_format_error_global = 1;
                    continue;
                }
                enqueue_task_check(fname, expected);
                free(fname);
            }

            if (f != stdin)
                fclose(f);
        }
    }

    free(line);

    atomic_store_explicit(&done_submitting_tasks, 1, memory_order_release);
    pthread_mutex_lock(&q_sleep_mutex);
    pthread_cond_broadcast(&q_sleep_cond);
    pthread_mutex_unlock(&q_sleep_mutex);

    run_pool_and_wait(opts);

    return (any_failure_global || (any_format_error_global && opts->strict)) ? 1 : 0;
}

/* ──────────────── file hashing producer ──────────────── */

typedef struct {
    const program_opts* opts;
    int filec;
    char** filev;
} producer_args;

static void* producer_thread_main(void* arg) {
    producer_args* pa = (producer_args*)arg;

    for (int i = 0; i < pa->filec; i++) {
        const char* path = pa->filev[i];
        if (strcmp(path, "-") == 0)
            enqueue_task_hash_stat("-", NULL);
        else
            walk_path_streaming(pa->opts, path);
    }

    atomic_store_explicit(&done_submitting_tasks, 1, memory_order_release);
    pthread_mutex_lock(&q_sleep_mutex);
    pthread_cond_broadcast(&q_sleep_cond);
    pthread_mutex_unlock(&q_sleep_mutex);
    return NULL;
}

/* ──────────────── main ──────────────── */

int main(int argc, char** argv) {
    program_opts opts;
    int argi = handle_options(argc, argv, &opts);
    if (argi < 0)
        return EXIT_FAILURE;
    if (argi == 0)
        return EXIT_SUCCESS;

    int fc = argc - argi;
    char** files = &argv[argi];

    if (opts.check) {
        int r = process_check_files_multithread(fc, files, &opts);
        return r ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    // default: hash mode
    if (fc == 0) {
        static char* stdin_only[] = {"-"};
        files = stdin_only;
        fc = 1;
    }

    atomic_store_explicit(&done_submitting_tasks, 0, memory_order_release);

    producer_args pa = {.opts = &opts, .filec = fc, .filev = files};

    pthread_t prod;
    if (pthread_create(&prod, NULL, producer_thread_main, &pa) != 0) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
    }

    run_pool_and_wait(&opts);
    pthread_join(prod, NULL);

    return any_failure_global ? EXIT_FAILURE : EXIT_SUCCESS;
}
