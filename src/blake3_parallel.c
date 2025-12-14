#define _GNU_SOURCE

#include "blake3_parallel.h"
#include "blake3_impl.h"

/* Keep these local to avoid pulling extra headers into the hot path */
typedef struct {
    uint8_t bytes[32];
} b3_cv_bytes_t;

typedef struct {
    uint32_t key[8];
    uint8_t flags;
} b3_keyed_flags_t;

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <alloca.h>
#include <stdio.h>

#define DEBUG_PARALLEL 0

/* Thread-local CV scratch
   Avoids per-task malloc and avoids alloca in deep or repeated calls
   Buffer is grown amortized and reused for the lifetime of the worker thread */
static __thread b3_cv_bytes_t* g_tls_cv_buf = NULL;
static __thread size_t g_tls_cv_cap = 0;

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

static b3_cv_bytes_t* ensure_tls_cv_buffer(size_t count) {
    // Fast-path: a request for 0 elements doesn't require growth
    if (count == 0) {
        return g_tls_cv_buf;
    }

    // Maximum number of elements we can allocate without size_t overflow
    const size_t max_elems = SIZE_MAX / sizeof(b3_cv_bytes_t);

    // Reject impossible requests that would overflow the allocation size
    if (count > max_elems) {
        errno = ENOMEM;
        return NULL;
    }

    // Grow only when the requested element count exceeds current capacity
    if (count > g_tls_cv_cap) {
        // Start with an initial capacity if we don't have one yet
        size_t new_cap = g_tls_cv_cap ? g_tls_cv_cap : (size_t)1024;

        // Clamp the starting capacity to the absolute maximum representable element count
        if (new_cap > max_elems) {
            new_cap = max_elems;
        }

        // Exponentially grow capacity until it satisfies count, avoiding overflow
        while (new_cap < count) {
            // If doubling would overflow or exceed the maximum, jump directly to count
            if (new_cap > max_elems / 2) {
                new_cap = count;
                break;
            }
            new_cap *= 2;
        }

        // Final sanity check before computing the byte size
        if (new_cap > max_elems) {
            errno = ENOMEM;
            return NULL;
        }

        // Compute the allocation size in bytes with overflow already excluded above
        size_t bytes = new_cap * sizeof(b3_cv_bytes_t);

        // Reallocate, preserving the original buffer on failure
        b3_cv_bytes_t* new_buf = realloc(g_tls_cv_buf, bytes);
        if (!new_buf) {
            return NULL;
        }

        // Commit the new buffer and capacity only after realloc succeeds
        g_tls_cv_buf = new_buf;
        g_tls_cv_cap = new_cap;
    }

    // Return the TLS buffer pointer, grown as needed
    return g_tls_cv_buf;
}

void b3p_free_tls_resources(void) {
    if (g_tls_cv_buf) {
        free(g_tls_cv_buf);
        g_tls_cv_buf = NULL;
        g_tls_cv_cap = 0;
    }
}

/* Worker pool structures
   Simple bounded queue plus taskgroup counter
   Intended to keep scheduling overhead negligible relative to hashing work */
typedef void (*b3p_task_fn)(void* arg);

typedef struct {
    atomic_uint pending;
    pthread_mutex_t mu;
    pthread_cond_t cv;
} b3p_taskgroup_t;

typedef struct {
    b3p_task_fn fn;
    void* arg;
    b3p_taskgroup_t* group;
} b3p_task_t;

typedef struct {
    b3p_task_t* buf;
    size_t cap;
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t mu;
    pthread_cond_t cv_push;
    pthread_cond_t cv_pop;
    int stop;
} b3p_taskq_t;

typedef struct {
    pthread_t* threads;
    size_t nthreads;
    b3p_taskq_t q;
} b3p_pool_t;

/* Parallel hashing context
   Stores the keyed flags and the current input range for one-shot hashing
   Scratch CV storage is kept on the context for amortized reuse across calls */
typedef b3_keyed_flags_t b3p_keyed_flags_t;

struct b3p_ctx {
    b3p_keyed_flags_t kf;

    const uint8_t* input;
    size_t input_len;
    size_t num_chunks;

    b3_cv_bytes_t* scratch_cvs;
    size_t scratch_cvs_cap;

    b3p_pool_t pool;
    b3p_config_t cfg;
};

/* Internal forward declarations */
static int b3p_pool_init(b3p_pool_t* p, size_t nthreads, size_t qcap);
static void b3p_pool_destroy(b3p_pool_t* p);
static void b3p_taskgroup_init(b3p_taskgroup_t* g);
static void b3p_taskgroup_destroy(b3p_taskgroup_t* g);
static int b3p_pool_submit(b3p_pool_t* p, b3p_taskgroup_t* g, b3p_task_fn fn, void* arg);
static void b3p_taskgroup_wait(b3p_taskgroup_t* g);
static void* b3p_worker_main(void* arg);

static int b3p_ensure_scratch(struct b3p_ctx* ctx, size_t want_cvs);

static b3p_method_t b3p_pick_heuristic(struct b3p_ctx* ctx);

static int b3p_run_method_a_chunks(struct b3p_ctx* ctx, b3_cv_bytes_t* out_root, b3_cv_bytes_t* out_split_children);
static int b3p_run_method_b_subtrees(struct b3p_ctx* ctx, b3_cv_bytes_t* out_root, b3_cv_bytes_t* out_split_children);
static void b3p_reduce_stack(struct b3p_ctx* ctx, b3_cv_bytes_t* cvs, size_t n, size_t subtree_chunks, b3_cv_bytes_t* out_root, int is_final, b3_cv_bytes_t* out_split_children);

static int b3p_compute_root(struct b3p_ctx* ctx, b3p_method_t method, b3_cv_bytes_t* out_root, b3_cv_bytes_t* out_split_children, uint64_t* out_ns);

/* Public API */

b3p_config_t b3p_config_default(void) {
    b3p_config_t c = {0};

    c.nthreads = 0;
    c.min_parallel_bytes = 64 * 1024;
    c.method_a_min_chunks = 16;
    c.method_b_min_chunks_per_thread = 64;
    c.subtree_chunks = B3P_DEFAULT_SUBTREE_CHUNKS;

    c.autotune_enable = 1;
    c.autotune_sample_mask = 63;

    return c;
}

b3p_ctx_t* b3p_create(const b3p_config_t* cfg) {
    struct b3p_ctx* ctx = (struct b3p_ctx*)calloc(1, sizeof(struct b3p_ctx));
    if (!ctx)
        return NULL;

    ctx->cfg = *cfg;
    size_t nthreads = cfg->nthreads;
    if (nthreads == 0) {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 1)
            ncpu = 1;
        nthreads = (size_t)ncpu;
    }

    /* If only one thread is requested, skip pool creation entirely
       This avoids mutex/cond overhead and keeps serial one-shot fast */
    if (nthreads > 1) {
        size_t qcap = nthreads * 2;
        if (qcap < 2)
            qcap = 2;
        if (b3p_pool_init(&ctx->pool, nthreads, qcap) != 0) {
            free(ctx);
            return NULL;
        }
    }
    else {
        ctx->pool.nthreads = 0;
    }

    ctx->scratch_cvs = NULL;
    ctx->scratch_cvs_cap = 0;

    return (b3p_ctx_t*)ctx;
}

void b3p_destroy(b3p_ctx_t* vctx) {
    struct b3p_ctx* ctx = (struct b3p_ctx*)vctx;
    if (!ctx)
        return;
    b3p_pool_destroy(&ctx->pool);
    free(ctx->scratch_cvs);
    free(ctx);
}

int b3p_hash_one_shot(b3p_ctx_t* ctx, const uint8_t* input, size_t input_len, const uint8_t key[BLAKE3_KEY_LEN], uint8_t flags, b3p_method_t method, uint8_t* out, size_t out_len) {
    return b3p_hash_one_shot_seek(ctx, input, input_len, key, flags, method, 0, out, out_len);
}

int b3p_hash_one_shot_seek(b3p_ctx_t* vctx,
                           const uint8_t* input,
                           size_t input_len,
                           const uint8_t key[BLAKE3_KEY_LEN],
                           uint8_t flags,
                           b3p_method_t method,
                           uint64_t seek,
                           uint8_t* out,
                           size_t out_len) {
    struct b3p_ctx* ctx = (struct b3p_ctx*)vctx;
    if (!ctx || !input || !out)
        return -1;
    if (out_len == 0)
        return 0;

    ctx->input = input;
    ctx->input_len = input_len;
    ctx->num_chunks = (input_len + (size_t)BLAKE3_CHUNK_LEN - 1) / (size_t)BLAKE3_CHUNK_LEN;
    if (ctx->num_chunks == 0)
        ctx->num_chunks = 1;

    /* Convert key bytes to little-endian words once per call
       The hashing core consumes key as u32 words */
    for (size_t i = 0; i < 8; i++) {
        uint32_t w = 0;
        w |= (uint32_t)key[i * 4 + 0] << 0;
        w |= (uint32_t)key[i * 4 + 1] << 8;
        w |= (uint32_t)key[i * 4 + 2] << 16;
        w |= (uint32_t)key[i * 4 + 3] << 24;
        ctx->kf.key[i] = w;
    }
    ctx->kf.flags = flags;

#if DEBUG_PARALLEL
    fprintf(stderr, "[parallel] flags: %02x input_len=%zu num_chunks=%zu\n", flags, input_len, ctx->num_chunks);
#endif

    b3p_method_t chosen = method;
    if (method == B3P_METHOD_AUTO) {
        chosen = b3p_pick_heuristic(ctx);
    }

    /* For single chunk inputs, compute directly to support XOF/Seek on the root block */
    if (ctx->num_chunks == 1) {
        blake3_chunk_state state;
        chunk_state_init(&state, ctx->kf.key, ctx->kf.flags);
        state.chunk_counter = 0;
        chunk_state_update(&state, ctx->input, ctx->input_len);
        output_t output = chunk_state_output(&state);
        /* Use internal impl for output_root_bytes to avoid including blake3.c content */
        b3_output_root_impl(output.input_cv, output.flags, output.block, output.block_len, output.counter, seek, out, out_len);
        return 0;
    }

    b3_cv_bytes_t root = {0};
    b3_cv_bytes_t split_children[2];
    uint64_t ns = 0;
    int rc = b3p_compute_root(ctx, chosen, &root, split_children, &ns);
    if (rc != 0)
        return rc;

    /* For multi-chunk inputs, the root is a PARENT node formed by split_children */
    /* Reconstruct the root parent block to support XOF */
    uint8_t root_block[BLAKE3_BLOCK_LEN];
    memcpy(root_block, split_children[0].bytes, 32);
    memcpy(root_block + 32, split_children[1].bytes, 32);

    b3_output_root_impl(ctx->kf.key, ctx->kf.flags | PARENT, root_block, BLAKE3_BLOCK_LEN, 0, seek, out, out_len);
    return 0;
}

/* Worker pool implementation */

static int b3p_pool_init(b3p_pool_t* p, size_t nthreads, size_t qcap) {
    if (qcap == 0) {
        qcap = 256;
    }
    if (nthreads == 0) {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 1)
            ncpu = 1;
        nthreads = (size_t)ncpu;
    }

    p->q.buf = (b3p_task_t*)calloc(qcap, sizeof(b3p_task_t));
    if (p->q.buf == NULL)
        return -1;
    p->q.cap = qcap;
    p->q.head = 0;
    p->q.tail = 0;
    p->q.count = 0;
    p->q.stop = 0;

    int err = 0;
    err |= pthread_mutex_init(&p->q.mu, NULL);
    err |= pthread_cond_init(&p->q.cv_push, NULL);
    err |= pthread_cond_init(&p->q.cv_pop, NULL);
    if (err != 0) {
        free(p->q.buf);
        return -1;
    }

    p->threads = (pthread_t*)calloc(nthreads, sizeof(pthread_t));
    if (p->threads == NULL) {
        pthread_mutex_destroy(&p->q.mu);
        pthread_cond_destroy(&p->q.cv_push);
        pthread_cond_destroy(&p->q.cv_pop);
        free(p->q.buf);
        return -1;
    }
    p->nthreads = nthreads;

    for (size_t i = 0; i < nthreads; i++) {
        if (pthread_create(&p->threads[i], NULL, b3p_worker_main, p) != 0) {
            p->nthreads = i;
            p->q.stop = 1;
            pthread_cond_broadcast(&p->q.cv_pop);
            for (size_t j = 0; j < i; j++) {
                pthread_join(p->threads[j], NULL);
            }
            free(p->threads);
            pthread_mutex_destroy(&p->q.mu);
            pthread_cond_destroy(&p->q.cv_push);
            pthread_cond_destroy(&p->q.cv_pop);
            free(p->q.buf);
            return -1;
        }
    }

    return 0;
}

static void b3p_pool_destroy(b3p_pool_t* p) {
    if (p->q.buf == NULL)
        return;

    pthread_mutex_lock(&p->q.mu);
    p->q.stop = 1;
    pthread_cond_broadcast(&p->q.cv_pop);
    pthread_mutex_unlock(&p->q.mu);

    for (size_t i = 0; i < p->nthreads; i++) {
        pthread_join(p->threads[i], NULL);
    }

    free(p->threads);
    pthread_mutex_destroy(&p->q.mu);
    pthread_cond_destroy(&p->q.cv_push);
    pthread_cond_destroy(&p->q.cv_pop);
    free(p->q.buf);
    p->q.buf = NULL;
}

static void b3p_taskgroup_init(b3p_taskgroup_t* g) {
    atomic_init(&g->pending, 0);
    pthread_mutex_init(&g->mu, NULL);
    pthread_cond_init(&g->cv, NULL);
}

static void b3p_taskgroup_destroy(b3p_taskgroup_t* g) {
    pthread_mutex_destroy(&g->mu);
    pthread_cond_destroy(&g->cv);
}

/* Submitting tasks increments the pending counter
   Workers decrement it and signal completion when it reaches zero */
static int b3p_pool_submit(b3p_pool_t* p, b3p_taskgroup_t* g, b3p_task_fn fn, void* arg) {
    pthread_mutex_lock(&p->q.mu);
    while (p->q.count == p->q.cap && !p->q.stop) {
        pthread_cond_wait(&p->q.cv_push, &p->q.mu);
    }
    if (p->q.stop) {
        pthread_mutex_unlock(&p->q.mu);
        return -1;
    }

    b3p_task_t* t = &p->q.buf[p->q.tail];
    t->fn = fn;
    t->arg = arg;
    t->group = g;
    p->q.tail = (p->q.tail + 1) % p->q.cap;
    p->q.count++;
    pthread_cond_signal(&p->q.cv_pop);
    pthread_mutex_unlock(&p->q.mu);

    if (g) {
        atomic_fetch_add_explicit(&g->pending, 1, memory_order_relaxed);
    }
    return 0;
}

static void b3p_taskgroup_wait(b3p_taskgroup_t* g) {
    pthread_mutex_lock(&g->mu);
    while (atomic_load_explicit(&g->pending, memory_order_relaxed) > 0) {
        pthread_cond_wait(&g->cv, &g->mu);
    }
    pthread_mutex_unlock(&g->mu);
}

/* Worker thread main loop
   Pops tasks, runs them, and updates the taskgroup pending counter */
static void* b3p_worker_main(void* arg) {
    b3p_pool_t* p = (b3p_pool_t*)arg;

    for (;;) {
        b3p_task_t t = {0};

        pthread_mutex_lock(&p->q.mu);
        while (p->q.count == 0 && !p->q.stop)
            pthread_cond_wait(&p->q.cv_pop, &p->q.mu);

        if (p->q.stop && p->q.count == 0) {
            pthread_mutex_unlock(&p->q.mu);
            break;
        }

        t = p->q.buf[p->q.head];
        p->q.head = (p->q.head + 1) % p->q.cap;
        p->q.count--;
        pthread_cond_signal(&p->q.cv_push);
        pthread_mutex_unlock(&p->q.mu);

        t.fn(t.arg);

        if (t.group) {
            pthread_mutex_lock(&t.group->mu);
            unsigned prev = atomic_fetch_sub_explicit(&t.group->pending, 1, memory_order_relaxed);
            if (prev == 1) {
                pthread_cond_broadcast(&t.group->cv);
            }
            pthread_mutex_unlock(&t.group->mu);
        }
    }

    /* Worker exit cleanup
       TLS scratch is owned by the thread, so it can be freed here */
    if (g_tls_cv_buf) {
        free(g_tls_cv_buf);
        g_tls_cv_buf = NULL;
        g_tls_cv_cap = 0;
    }

    return NULL;
}

/* Scratch management */

static int b3p_ensure_scratch(struct b3p_ctx* ctx, size_t want_cvs) {
    if (want_cvs <= ctx->scratch_cvs_cap)
        return 0;

    size_t new_cap = ctx->scratch_cvs_cap ? ctx->scratch_cvs_cap : 1024;
    while (new_cap < want_cvs)
        new_cap *= 2;

    void* p = realloc(ctx->scratch_cvs, new_cap * sizeof(b3_cv_bytes_t));
    if (!p)
        return -1;

    ctx->scratch_cvs = p;
    ctx->scratch_cvs_cap = new_cap;
    return 0;
}

/* Selection logic
   Heuristic chooses between chunk-level and subtree-level parallelism
   Prefer subtrees only when there is enough work per thread */
static inline size_t b3_min_sz(size_t a, size_t b) {
    return a < b ? a : b;
}

static inline size_t b3_full_chunks(size_t input_len) {
    return input_len / (size_t)BLAKE3_CHUNK_LEN;
}

static b3p_method_t b3p_pick_heuristic(struct b3p_ctx* ctx) {
    if (ctx->pool.nthreads < 2)
        return B3P_METHOD_A_CHUNKS;

    if (ctx->input_len < ctx->cfg.min_parallel_bytes)
        return B3P_METHOD_A_CHUNKS;

    size_t chunks = b3_full_chunks(ctx->input_len);
    if (chunks < ctx->cfg.method_a_min_chunks)
        return B3P_METHOD_A_CHUNKS;

    size_t simd = blake3_simd_degree();
    size_t effective_lane = b3_min_sz(simd, (size_t)MAX_SIMD_DEGREE);

    size_t chunks_per_thread_floor = ctx->cfg.method_b_min_chunks_per_thread * effective_lane;
    if (chunks >= ctx->pool.nthreads * chunks_per_thread_floor)
        return B3P_METHOD_B_SUBTREES;

    return B3P_METHOD_A_CHUNKS;
}

/* Method implementations */

static inline void
b3p_hash_range_to_root(struct b3p_ctx* ctx, size_t chunk_start, size_t chunk_end, b3_cv_bytes_t* restrict tmp, b3_cv_bytes_t* restrict out_root, int is_root, b3_cv_bytes_t* out_split_children);

typedef struct {
    struct b3p_ctx* ctx;
    atomic_size_t next_chunk;
    size_t end_chunk;
    size_t batch_step;
    b3_cv_bytes_t* out_cvs;
    b3_cv_bytes_t* out_split_children;
} b3p_chunks_job_t;

typedef struct {
    struct b3p_ctx* ctx;
    size_t subtree_chunks;
    atomic_size_t next_subtree;
    size_t num_subtrees;
    b3_cv_bytes_t* out_subtree_cvs;
    b3_cv_bytes_t* out_split_children;
} b3p_subtrees_job_t;

/* Chunk mode
   Each worker grabs a batch of chunks, hashes them, reduces to a batch root CV
   This amortizes scheduling overhead and reduces the size of the final reduction */
static void b3p_task_hash_chunks(void* arg) {
    b3p_chunks_job_t* job = arg;
    struct b3p_ctx* ctx = job->ctx;

    /* Local buffer sized for the maximum batch
       Keeps per-batch CVs on the stack, avoiding heap traffic */
    b3_cv_bytes_t local_buf[1024];

    for (;;) {
        size_t batch_start = atomic_fetch_add_explicit(&job->next_chunk, job->batch_step, memory_order_relaxed);
        if (batch_start >= job->end_chunk)
            break;

        size_t batch_limit = batch_start + job->batch_step;
        if (batch_limit > job->end_chunk)
            batch_limit = job->end_chunk;

        size_t batch_idx = batch_start / job->batch_step;

        /* This batch is the entire input only in the single-batch case
           Passing is_root through ensures correct ROOT handling for tiny inputs */
        int is_root = (batch_start == 0 && batch_limit == ctx->num_chunks);

        b3p_hash_range_to_root(ctx, batch_start, batch_limit, local_buf, &job->out_cvs[batch_idx], is_root, (is_root ? job->out_split_children : NULL));
    }
}

/* Hash and reduce a contiguous chunk range
   Hashes full chunks via blake3_hash_many for batching, then handles one partial tail if present
   Reduction is done with the stack merge to preserve correct tree shape for non-powers-of-two */
static inline void
b3p_hash_range_to_root(struct b3p_ctx* ctx, size_t chunk_start, size_t chunk_end, b3_cv_bytes_t* restrict tmp, b3_cv_bytes_t* restrict out_root, int is_root, b3_cv_bytes_t* out_split_children) {
    size_t n = chunk_end - chunk_start;

#if DEBUG_PARALLEL
    fprintf(stderr, "[parallel] hash_range_to_root: chunk_start=%zu chunk_end=%zu n=%zu\n", chunk_start, chunk_end, n);
#endif

    size_t simd_degree = blake3_simd_degree();
    if (simd_degree > MAX_SIMD_DEGREE)
        simd_degree = MAX_SIMD_DEGREE;

    const uint8_t* input_ptr = ctx->input + chunk_start * (size_t)BLAKE3_CHUNK_LEN;

    size_t i = 0;
    while (i < n) {
        size_t count = simd_degree;
        if (i + count > n)
            count = n - i;

        /* Determine how many of the next 'count' chunks are full
           If the very last chunk is partial, hash it with the chunk primitive */
        size_t full_count = count;
        if (chunk_start + i + count == ctx->num_chunks) {
            size_t off = (ctx->num_chunks - 1) * (size_t)BLAKE3_CHUNK_LEN;
            if (ctx->input_len - off < (size_t)BLAKE3_CHUNK_LEN) {
                full_count--;
            }
        }

        if (full_count > 0) {
            const uint8_t* inputs[MAX_SIMD_DEGREE];
            for (size_t j = 0; j < full_count; j++) {
                inputs[j] = input_ptr + j * (size_t)BLAKE3_CHUNK_LEN;
            }

            uint8_t flags_end = CHUNK_END;
            if (is_root && n == 1 && full_count == 1) {
                flags_end |= ROOT;
            }

            blake3_hash_many(inputs, full_count, BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, ctx->kf.key, (uint64_t)(chunk_start + i), true, ctx->kf.flags, CHUNK_START, flags_end, tmp[i].bytes);
        }

        if (full_count < count) {
            size_t j = full_count;
            size_t chunk_i = chunk_start + i + j;
            const uint8_t* partial_chunk_ptr = input_ptr + j * (size_t)BLAKE3_CHUNK_LEN;

            size_t off = chunk_i * (size_t)BLAKE3_CHUNK_LEN;
            size_t remain = ctx->input_len - off;
            size_t clen = remain < (size_t)BLAKE3_CHUNK_LEN ? remain : (size_t)BLAKE3_CHUNK_LEN;

            int chunk_is_root = (is_root && n == 1);

            /* Partial chunk uses the chunk CV primitive
               This avoids padding logic in the hash_many fast path */
            b3_hash_chunk_cv_impl(ctx->kf.key, ctx->kf.flags, partial_chunk_ptr, clen, (uint64_t)chunk_i, chunk_is_root, tmp[i + j].bytes);
        }

        i += count;
        input_ptr += count * (size_t)BLAKE3_CHUNK_LEN;
    }

    b3p_reduce_stack(ctx, tmp, n, 1, out_root, is_root, out_split_children);
}

/* Subtree mode
   Each worker hashes an entire subtree range and reduces it to a subtree root CV
   The final merge combines subtree roots using the stack merge */
static void b3p_task_hash_subtrees(void* arg) {
    b3p_subtrees_job_t* job = arg;
    struct b3p_ctx* ctx = job->ctx;

    size_t max_tmp = job->subtree_chunks;

    b3_cv_bytes_t* tmp = ensure_tls_cv_buffer(max_tmp);
    if (!tmp)
        return;

    for (;;) {
        size_t s = atomic_fetch_add_explicit(&job->next_subtree, 1, memory_order_relaxed);
        if (s >= job->num_subtrees)
            break;

        size_t chunk_start = s * job->subtree_chunks;
        size_t chunk_end = chunk_start + job->subtree_chunks;
        if (chunk_end > ctx->num_chunks)
            chunk_end = ctx->num_chunks;

        b3_cv_bytes_t root = {0};
        int is_root = (job->num_subtrees == 1);
        b3p_hash_range_to_root(ctx, chunk_start, chunk_end, tmp, &root, is_root, (is_root ? job->out_split_children : NULL));
        job->out_subtree_cvs[s] = root;
    }
}

/* Merge two child CVs into a parent CV
   ROOT is applied only at the final merge step */
static inline void b3p_merge_nodes(const uint32_t key[8], uint8_t base_flags, const b3_cv_bytes_t* left, const b3_cv_bytes_t* restrict right, b3_cv_bytes_t* out, int is_root) {
    uint8_t flags = (uint8_t)(base_flags | PARENT);
    if (is_root)
        flags |= ROOT;
    b3_hash_parent_cv_impl(key, flags, left->bytes, right->bytes, out->bytes);
}

/* Stack reduction for CVs
   Implements the BLAKE3 lazy-merge shape via counts
   This preserves correctness for non-power-of-two counts and avoids extra passes */
static void b3p_reduce_stack(struct b3p_ctx* ctx, b3_cv_bytes_t* restrict cvs, size_t n, size_t subtree_chunks, b3_cv_bytes_t* restrict out_root, int is_final, b3_cv_bytes_t* out_split_children) {
    size_t stack_counts[64];
    size_t top = 0;

    size_t total_count = 0;
    for (size_t i = 0; i < n; i++) {
        size_t count = subtree_chunks;
        if (subtree_chunks > 1 && i == n - 1) {
            size_t remainder = ctx->num_chunks % subtree_chunks;
            if (remainder != 0)
                count = remainder;
        }
        total_count += count;
    }

    for (size_t i = 0; i < n; i++) {
        size_t count = subtree_chunks;
        if (subtree_chunks > 1 && i == n - 1) {
            size_t remainder = ctx->num_chunks % subtree_chunks;
            if (remainder != 0)
                count = remainder;
        }

        if (top != i) {
            cvs[top] = cvs[i];
        }
        stack_counts[top] = count;
        top++;

        while (top >= 2) {
            if (stack_counts[top - 1] == stack_counts[top - 2]) {
                size_t right_idx = top - 1;
                size_t left_idx = top - 2;

                size_t new_count = stack_counts[left_idx] + stack_counts[right_idx];
                int is_root = (is_final && new_count == total_count);

                if (is_root && out_split_children) {
                    out_split_children[0] = cvs[left_idx];
                    out_split_children[1] = cvs[right_idx];
                    return;
                }

                b3p_merge_nodes(ctx->kf.key, ctx->kf.flags, &cvs[left_idx], &cvs[right_idx], &cvs[left_idx], is_root);

                stack_counts[left_idx] = new_count;
                top--;
            }
            else {
                break;
            }
        }
    }

    while (top > 1) {
        size_t right_idx = top - 1;
        size_t left_idx = top - 2;

        size_t new_count = stack_counts[left_idx] + stack_counts[right_idx];
        int is_root = (is_final && new_count == total_count);

        if (is_root && out_split_children) {
            out_split_children[0] = cvs[left_idx];
            out_split_children[1] = cvs[right_idx];
            return;
        }

        b3p_merge_nodes(ctx->kf.key, ctx->kf.flags, &cvs[left_idx], &cvs[right_idx], &cvs[left_idx], is_root);

        stack_counts[left_idx] = new_count;
        top--;
    }

    *out_root = cvs[0];
}

/* Method A
   Chunk batching hashes contiguous ranges and reduces each batch into a CV
   Final merge reduces the batch roots into the tree root */
static int b3p_run_method_a_chunks(struct b3p_ctx* ctx, b3_cv_bytes_t* out_root, b3_cv_bytes_t* out_split_children) {
    size_t simd_degree = blake3_simd_degree();
    if (simd_degree > MAX_SIMD_DEGREE)
        simd_degree = MAX_SIMD_DEGREE;

    /* Batch size is chosen to amortize scheduling and reduction overhead
       Larger batches reduce queue pressure, but increase per-task latency */
    size_t batch_step = simd_degree * 64;

    size_t num_batches = (ctx->num_chunks + batch_step - 1) / batch_step;

    if (b3p_ensure_scratch(ctx, num_batches) != 0)
        return -1;

    b3p_chunks_job_t job = {.ctx = ctx, .next_chunk = 0, .end_chunk = ctx->num_chunks, .batch_step = batch_step, .out_cvs = ctx->scratch_cvs, .out_split_children = out_split_children};

    b3p_taskgroup_t g;
    b3p_taskgroup_init(&g);

    size_t tasks = ctx->cfg.nthreads ? ctx->cfg.nthreads : 1;
    /* Optimization: if only 1 batch, run on main thread to ensure split children are written to stack */
    if (num_batches == 1) {
        b3p_task_hash_chunks(&job);
    }
    else {
        for (size_t t = 0; t < tasks; t++)
            b3p_pool_submit(&ctx->pool, &g, b3p_task_hash_chunks, &job);

        b3p_taskgroup_wait(&g);
    }
    b3p_taskgroup_destroy(&g);

    b3p_reduce_stack(ctx, ctx->scratch_cvs, num_batches, batch_step, out_root, 1, out_split_children);
    return 0;
}

/* Method B
   Subtree batching hashes fixed-size subtrees per task
   Final merge reduces subtree roots into the tree root */
static int b3p_run_method_b_subtrees(struct b3p_ctx* ctx, b3_cv_bytes_t* out_root, b3_cv_bytes_t* out_split_children) {
    size_t subtree_chunks = ctx->cfg.subtree_chunks;
    if (subtree_chunks == 0) {
        subtree_chunks = B3P_DEFAULT_SUBTREE_CHUNKS;
    }

    /* Power-of-two subtree sizes minimize merge irregularity */
    subtree_chunks = round_down_to_power_of_2(subtree_chunks);

    size_t num_subtrees = (ctx->num_chunks + subtree_chunks - 1) / subtree_chunks;

    if (b3p_ensure_scratch(ctx, num_subtrees) != 0)
        return -1;

    b3p_subtrees_job_t job = {
        .ctx = ctx, .subtree_chunks = subtree_chunks, .next_subtree = 0, .num_subtrees = num_subtrees, .out_subtree_cvs = ctx->scratch_cvs, .out_split_children = out_split_children};

    b3p_taskgroup_t g;
    b3p_taskgroup_init(&g);

    size_t tasks = ctx->cfg.nthreads ? ctx->cfg.nthreads : 1;
    if (num_subtrees == 1) {
        b3p_task_hash_subtrees(&job);
    }
    else {
        for (size_t t = 0; t < tasks; t++)
            b3p_pool_submit(&ctx->pool, &g, b3p_task_hash_subtrees, &job);

        b3p_taskgroup_wait(&g);
    }

    b3p_reduce_stack(ctx, ctx->scratch_cvs, num_subtrees, subtree_chunks, out_root, 1, out_split_children);
    return 0;
}

/* Serial fallback for contexts created with nthreads <= 1
   Uses the same subtree partitioning logic without starting a worker pool */
static int b3p_run_serial(struct b3p_ctx* ctx, b3_cv_bytes_t* out_root, b3_cv_bytes_t* out_split_children) {
    size_t subtree_chunks = ctx->cfg.subtree_chunks;
    if (subtree_chunks == 0) {
        subtree_chunks = B3P_DEFAULT_SUBTREE_CHUNKS;
    }
    subtree_chunks = round_down_to_power_of_2(subtree_chunks);

    size_t num_subtrees = (ctx->num_chunks + subtree_chunks - 1) / subtree_chunks;

    if (b3p_ensure_scratch(ctx, num_subtrees) != 0)
        return -1;

    b3_cv_bytes_t* tmp = ensure_tls_cv_buffer(subtree_chunks);
    if (!tmp)
        return -1;

    int is_root = (num_subtrees == 1);

    for (size_t s = 0; s < num_subtrees; s++) {
        size_t chunk_start = s * subtree_chunks;
        size_t chunk_end = chunk_start + subtree_chunks;
        if (chunk_end > ctx->num_chunks)
            chunk_end = ctx->num_chunks;

        b3_cv_bytes_t root = {0};
        b3p_hash_range_to_root(ctx, chunk_start, chunk_end, tmp, &root, is_root, (is_root ? out_split_children : NULL));
        ctx->scratch_cvs[s] = root;
    }

    b3p_reduce_stack(ctx, ctx->scratch_cvs, num_subtrees, subtree_chunks, out_root, 1, out_split_children);
    return 0;
}

/* Root computation dispatch
   Uses serial path if no pool exists, otherwise selects the requested method */
static int b3p_compute_root(struct b3p_ctx* ctx, b3p_method_t method, b3_cv_bytes_t* out_root, b3_cv_bytes_t* out_split_children, uint64_t* out_ns) {
    if (ctx->pool.nthreads == 0) {
        *out_ns = 0;
        return b3p_run_serial(ctx, out_root, out_split_children);
    }

    int rc = 0;
    if (method == B3P_METHOD_A_CHUNKS)
        rc = b3p_run_method_a_chunks(ctx, out_root, out_split_children);
    else if (method == B3P_METHOD_B_SUBTREES)
        rc = b3p_run_method_b_subtrees(ctx, out_root, out_split_children);
    else
        rc = -1;

    *out_ns = 0;
    return rc;
}

/* Serial one-shot helper
   This is intended for small buffers where parallel setup would dominate */
int b3p_hash_buffer_serial(const uint8_t* input, size_t input_len, const uint8_t key[BLAKE3_KEY_LEN], uint8_t flags, uint8_t* out, size_t out_len) {
    if (!input || !out)
        return -1;
    if (out_len == 0)
        return 0;

    struct b3p_ctx ctx = {0};
    ctx.input = input;
    ctx.input_len = input_len;
    ctx.num_chunks = (input_len + (size_t)BLAKE3_CHUNK_LEN - 1) / (size_t)BLAKE3_CHUNK_LEN;
    if (ctx.num_chunks == 0)
        ctx.num_chunks = 1;

    for (size_t i = 0; i < 8; i++) {
        uint32_t w = 0;
        w |= (uint32_t)key[i * 4 + 0] << 0;
        w |= (uint32_t)key[i * 4 + 1] << 8;
        w |= (uint32_t)key[i * 4 + 2] << 16;
        w |= (uint32_t)key[i * 4 + 3] << 24;
        ctx.kf.key[i] = w;
    }
    ctx.kf.flags = flags;

    if (ctx.num_chunks == 1) {
        blake3_chunk_state state;
        chunk_state_init(&state, ctx.kf.key, ctx.kf.flags);
        state.chunk_counter = 0;
        chunk_state_update(&state, ctx.input, ctx.input_len);
        output_t output = chunk_state_output(&state);
        b3_output_root_impl(output.input_cv, output.flags, output.block, output.block_len, output.counter, 0, out, out_len);
        return 0;
    }

    b3_cv_bytes_t* tmp = ensure_tls_cv_buffer(ctx.num_chunks);
    if (!tmp)
        return -1;

    b3_cv_bytes_t root = {0};
    b3_cv_bytes_t split_children[2];
    b3p_hash_range_to_root(&ctx, 0, ctx.num_chunks, tmp, &root, 1, split_children);

    uint8_t root_block[BLAKE3_BLOCK_LEN];
    memcpy(root_block, split_children[0].bytes, 32);
    memcpy(root_block + 32, split_children[1].bytes, 32);

    b3_output_root_impl(ctx.kf.key, ctx.kf.flags | PARENT, root_block, BLAKE3_BLOCK_LEN, 0, 0, out, out_len);
    return 0;
}
