/* src/blake3_parallel.c
 * Parallel hashing implementation using threads
 */

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

typedef struct {
    b3_cv_bytes_t* buf;
    size_t cap;
} tls_cv_buf_t;

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <alloca.h>
#include <stdio.h>
static __thread b3_cv_bytes_t* g_tls_cv_buf = NULL;
static __thread size_t g_tls_cv_cap = 0;

static pthread_once_t g_tls_cv_key_once = PTHREAD_ONCE_INIT;
static pthread_key_t g_tls_cv_key;

static void g_tls_cv_key_destructor(void* ptr) {
    tls_cv_buf_t* tls = (tls_cv_buf_t*)ptr;
    if (tls) {
        free(tls->buf);
        free(tls);
    }
}

static void g_tls_cv_key_create(void) {
    pthread_key_create(&g_tls_cv_key, g_tls_cv_key_destructor);
}

#define DEBUG_PARALLEL 0
#define CACHE_LINE_SIZE 64

/* Try to use C11 alignment, fallback for older compilers */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#include <stdalign.h>
#else
#define alignas(x) __attribute__((aligned(x)))
#endif

static inline size_t next_power_of_2(size_t x) {
    if (x == 0)
        return 1;
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    if (sizeof(size_t) > 4)
        x |= x >> 32;
    return x + 1;
}

/* Thread-local CV scratch
   Avoids per-task malloc and avoids alloca in deep or repeated calls
   Buffer is grown amortized and reused for the lifetime of the worker thread */

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
    pthread_once(&g_tls_cv_key_once, g_tls_cv_key_create);
    tls_cv_buf_t* tls = pthread_getspecific(g_tls_cv_key);
    if (tls) {
        free(tls->buf);
        free(tls);
        pthread_setspecific(g_tls_cv_key, NULL);
    }
    // Free thread-local buffer if allocated
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

typedef struct {
    struct b3p_ctx* ctx;
    /* CACHE LINE PADDING START */
    alignas(CACHE_LINE_SIZE) atomic_size_t next_chunk;
    /* CACHE LINE PADDING END */
    size_t end_chunk;
    size_t batch_step;
    b3_cv_bytes_t* out_cvs;
    b3_cv_bytes_t* out_split_children;
} b3p_chunks_job_t;

typedef struct {
    struct b3p_ctx* ctx;
    size_t subtree_chunks;
    /* CACHE LINE PADDING START */
    alignas(CACHE_LINE_SIZE) atomic_size_t next_subtree;
    /* CACHE LINE PADDING END */
    size_t num_subtrees;
    b3_cv_bytes_t* out_subtree_cvs;
    b3_cv_bytes_t* out_split_children;
} b3p_subtrees_job_t;

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

static inline void
b3p_hash_range_to_root(struct b3p_ctx* ctx, size_t chunk_start, size_t chunk_end, b3_cv_bytes_t* restrict tmp, b3_cv_bytes_t* restrict out_root, int is_root, b3_cv_bytes_t* out_split_children);

static b3p_method_t b3p_pick_heuristic(struct b3p_ctx* ctx);

static int b3p_run_method_a_chunks(struct b3p_ctx* ctx, b3_cv_bytes_t* out_root, b3_cv_bytes_t* out_split_children);
static int b3p_run_method_b_subtrees(struct b3p_ctx* ctx, b3_cv_bytes_t* out_root, b3_cv_bytes_t* out_split_children);
static void b3p_reduce_stack(struct b3p_ctx* ctx, b3_cv_bytes_t* cvs, size_t n, size_t subtree_chunks, size_t total_chunks, b3_cv_bytes_t* out_root, int is_final, b3_cv_bytes_t* out_split_children);

static int b3p_compute_root(struct b3p_ctx* ctx, b3p_method_t method, b3_cv_bytes_t* out_root, b3_cv_bytes_t* out_split_children, uint64_t* out_ns);

/* Public API */

b3p_config_t b3p_config_default(void) {
    // Return a fully initialized config with sane defaults for typical workloads
    return (b3p_config_t){
        // 0 means "auto" in the rest of the codebase
        .nthreads = 0,

        // Avoid parallel overhead on small inputs
        .min_parallel_bytes = 16u * 1024u,

        // Method A: require enough chunks to amortize scheduling
        .method_a_min_chunks = 4u,

        // Method B: require enough per-thread work to keep workers busy
        .method_b_min_chunks_per_thread = 16u,

        // Subtree size used for reducing intermediate CVs
        .subtree_chunks = B3P_DEFAULT_SUBTREE_CHUNKS,

        // Enable autotuning by default
        .autotune_enable = 1u,

        // Sample roughly 1 out of 64 calls by default
        .autotune_sample_mask = 63u,
    };
}

b3p_ctx_t* b3p_create(const b3p_config_t* cfg) {
    // Reject a NULL config pointer early
    if (!cfg) {
        return NULL;
    }

    // Allocate and zero-init the context so cleanup paths are simple
    struct b3p_ctx* ctx = (struct b3p_ctx*)calloc(1, sizeof(*ctx));
    if (!ctx) {
        return NULL;
    }

    // Copy config by value so the caller can free/mutate their copy safely
    ctx->cfg = *cfg;

    // Determine worker count, treating 0 as "auto"
    size_t nthreads = ctx->cfg.nthreads;
    if (nthreads == 0) {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 1) {
            ncpu = 1;
        }

        // Clamp to a sensible lower bound and cast safely
        nthreads = (size_t)ncpu;
        if (nthreads < 1) {
            nthreads = 1;
        }
    }

    // If only one thread is requested, skip pool creation entirely
    // This avoids mutex/cond overhead and keeps serial one-shot fast
    if (nthreads > 1) {
        // Keep the queue small to reduce memory while allowing slight burstiness
        // Enforce a power of 2 for queue efficiency
        size_t qcap = nthreads * 2;

        // Guard against size_t overflow on multiplication
        if (qcap < nthreads) {
            qcap = nthreads;
        }

        // Force queue capacity to next power of 2 for fast bitwise indexing
        qcap = next_power_of_2(qcap);
        if (qcap < 2)
            qcap = 2;

        // Initialize the pool, freeing the context if it fails
        if (b3p_pool_init(&ctx->pool, nthreads, qcap) != 0) {
            free(ctx);
            return NULL;
        }
    }
    else {
        // Mark pool as disabled, the rest of the code should treat nthreads==0 as serial mode
        ctx->pool.nthreads = 0;
    }

    // Scratch storage starts empty and grows on demand
    ctx->scratch_cvs = NULL;
    ctx->scratch_cvs_cap = 0;

    return (b3p_ctx_t*)ctx;
}

void b3p_destroy(b3p_ctx_t* vctx) {
    // Allow callers to destroy a NULL context safely
    if (!vctx) {
        return;
    }

    struct b3p_ctx* ctx = (struct b3p_ctx*)vctx;

    // Tear down the worker pool first so no thread can touch ctx-owned memory afterward
    b3p_pool_destroy(&ctx->pool);

    // Free scratch CV storage used to amortize allocations across calls
    free(ctx->scratch_cvs);
    ctx->scratch_cvs = NULL;
    ctx->scratch_cvs_cap = 0;

    // Free the context itself
    free(ctx);
}

int b3p_hash_one_shot(b3p_ctx_t* ctx, const uint8_t* input, size_t input_len, const uint8_t key[BLAKE3_KEY_LEN], uint8_t flags, b3p_method_t method, uint8_t* out, size_t out_len) {
    // Preserve behavior by delegating to the seekable implementation at offset 0
    // This keeps a single implementation for all one-shot hashing paths
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
    // Validate required pointers for any non-trivial work
    struct b3p_ctx* ctx = (struct b3p_ctx*)vctx;
    if (!ctx || !input || !out || !key) {
        return -1;
    }

    // A zero-length output request is always a no-op success
    if (out_len == 0) {
        return 0;
    }

    // Stash the input range on the context for downstream helpers
    ctx->input = input;
    ctx->input_len = input_len;

    // Compute number of BLAKE3 chunks using overflow-safe ceiling division
    const size_t chunk_len = (size_t)BLAKE3_CHUNK_LEN;
    size_t num_chunks = 1;

    // For non-empty input, compute ceil(input_len / chunk_len) safely
    if (input_len != 0) {
        // Guard the "+ (chunk_len - 1)" round-up term against size_t overflow
        if (input_len > SIZE_MAX - (chunk_len - 1)) {
            return -1;
        }
        num_chunks = (input_len + (chunk_len - 1)) / chunk_len;

        // Defensive: ensure we never end up with 0 for non-empty input
        if (num_chunks == 0) {
            num_chunks = 1;
        }
    }

    ctx->num_chunks = num_chunks;

    // Convert key bytes to little-endian u32 words once per call
    // The hashing core consumes the key as 8 u32 words
    for (size_t i = 0; i < 8; i++) {
        uint32_t w = 0;
        w |= (uint32_t)key[i * 4 + 0] << 0;
        w |= (uint32_t)key[i * 4 + 1] << 8;
        w |= (uint32_t)key[i * 4 + 2] << 16;
        w |= (uint32_t)key[i * 4 + 3] << 24;
        ctx->kf.key[i] = w;
    }

    // Store flags for this call
    ctx->kf.flags = flags;

#if DEBUG_PARALLEL
    // Debug trace for selecting parallel strategies
    fprintf(stderr, "[parallel] flags: %02x input_len=%zu num_chunks=%zu\n", flags, input_len, ctx->num_chunks);
#endif

    // Resolve AUTO into a concrete method based on current input/cfg
    b3p_method_t chosen = method;
    if (chosen == B3P_METHOD_AUTO) {
        chosen = b3p_pick_heuristic(ctx);
    }

    // Fast path: a single chunk can be hashed directly and supports seekable XOF output
    if (ctx->num_chunks == 1) {
        blake3_chunk_state state;

        // Initialize the chunk state with the keyed words and flags
        chunk_state_init(&state, ctx->kf.key, ctx->kf.flags);

        // One-shot root always starts at chunk counter 0
        state.chunk_counter = 0;

        // Feed the chunk (possibly empty) into the state
        chunk_state_update(&state, ctx->input, ctx->input_len);

        // Produce the output descriptor for the root
        output_t output = chunk_state_output(&state);

        // Emit XOF bytes at the requested seek offset without pulling in blake3.c
        b3_output_root_impl(output.input_cv, output.flags, output.block, output.block_len, output.counter, seek, out, out_len);
        return 0;
    }

    // Multi-chunk path: compute split children and reconstruct the root parent block for XOF
    b3_cv_bytes_t root = (b3_cv_bytes_t){0};
    b3_cv_bytes_t split_children[2] = {0};
    uint64_t ns = 0;

    // Compute the Merkle root and the two child CVs of the final split
    int rc = b3p_compute_root(ctx, chosen, &root, split_children, &ns);
    if (rc != 0) {
        return rc;
    }

    // The root for multi-chunk inputs is a PARENT node built from the two child CVs
    uint8_t root_block[BLAKE3_BLOCK_LEN];

    // Root block is left child CV || right child CV
    memcpy(root_block, split_children[0].bytes, 32);
    memcpy(root_block + 32, split_children[1].bytes, 32);

    // Emit XOF bytes for the root parent at the requested seek offset
    b3_output_root_impl(ctx->kf.key, (uint8_t)(ctx->kf.flags | PARENT), root_block, BLAKE3_BLOCK_LEN, 0, seek, out, out_len);
    return 0;
}

static int b3p_pool_init(b3p_pool_t* p, size_t nthreads, size_t qcap) {
    // Validate pointer early
    if (!p) {
        return -1;
    }

    // Choose a default queue capacity when none is provided
    if (qcap == 0) {
        qcap = 256;
    }

    // Force queue capacity to next power of 2 for fast bitwise indexing
    qcap = next_power_of_2(qcap);
    if (qcap < 2)
        qcap = 2;

    // Treat 0 threads as "auto"
    if (nthreads == 0) {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 1) {
            ncpu = 1;
        }
        nthreads = (size_t)ncpu;
        if (nthreads < 1) {
            nthreads = 1;
        }
    }

    // Clear observable state up front so destroy can be called safely on failure paths
    p->threads = NULL;
    p->nthreads = 0;
    p->q.buf = NULL;
    p->q.cap = 0;
    p->q.head = 0;
    p->q.tail = 0;
    p->q.count = 0;
    p->q.stop = 0;

    // Allocate the bounded task queue buffer
    p->q.buf = (b3p_task_t*)calloc(qcap, sizeof(b3p_task_t));
    if (!p->q.buf) {
        return -1;
    }
    p->q.cap = qcap;

    // Initialize queue synchronization primitives
    int err = 0;
    err |= pthread_mutex_init(&p->q.mu, NULL);
    err |= pthread_cond_init(&p->q.cv_push, NULL);
    err |= pthread_cond_init(&p->q.cv_pop, NULL);
    if (err != 0) {
        // Best-effort cleanup of any partial init
        pthread_cond_destroy(&p->q.cv_pop);
        pthread_cond_destroy(&p->q.cv_push);
        pthread_mutex_destroy(&p->q.mu);
        free(p->q.buf);
        p->q.buf = NULL;
        p->q.cap = 0;
        return -1;
    }

    // Allocate the worker thread handles
    p->threads = (pthread_t*)calloc(nthreads, sizeof(pthread_t));
    if (!p->threads) {
        pthread_mutex_destroy(&p->q.mu);
        pthread_cond_destroy(&p->q.cv_push);
        pthread_cond_destroy(&p->q.cv_pop);
        free(p->q.buf);
        p->q.buf = NULL;
        p->q.cap = 0;
        return -1;
    }
    p->nthreads = nthreads;

    // Spawn workers, rolling back cleanly if any thread creation fails
    for (size_t i = 0; i < nthreads; i++) {
        if (pthread_create(&p->threads[i], NULL, b3p_worker_main, p) != 0) {
            // Only join the threads that actually started
            p->nthreads = i;

            // Stop flag is protected by the queue mutex
            pthread_mutex_lock(&p->q.mu);
            p->q.stop = 1;
            pthread_cond_broadcast(&p->q.cv_pop);
            pthread_cond_broadcast(&p->q.cv_push);
            pthread_mutex_unlock(&p->q.mu);

            for (size_t j = 0; j < i; j++) {
                pthread_join(p->threads[j], NULL);
            }

            free(p->threads);
            p->threads = NULL;

            pthread_mutex_destroy(&p->q.mu);
            pthread_cond_destroy(&p->q.cv_push);
            pthread_cond_destroy(&p->q.cv_pop);

            free(p->q.buf);
            p->q.buf = NULL;
            p->q.cap = 0;
            return -1;
        }
    }

    return 0;
}

static void b3p_pool_destroy(b3p_pool_t* p) {
    // Allow destroy on NULL to be harmless
    if (!p) {
        return;
    }

    // If the queue buffer was never allocated, the pool was never initialized
    if (!p->q.buf) {
        return;
    }

    // Request stop under lock and wake sleepers on both condvars
    pthread_mutex_lock(&p->q.mu);
    p->q.stop = 1;
    pthread_cond_broadcast(&p->q.cv_pop);
    pthread_cond_broadcast(&p->q.cv_push);
    pthread_mutex_unlock(&p->q.mu);

    // Join workers before freeing shared structures they might access
    for (size_t i = 0; i < p->nthreads; i++) {
        pthread_join(p->threads[i], NULL);
    }

    // Release worker handle storage
    free(p->threads);
    p->threads = NULL;
    p->nthreads = 0;

    // Tear down synchronization primitives after all workers are gone
    pthread_mutex_destroy(&p->q.mu);
    pthread_cond_destroy(&p->q.cv_push);
    pthread_cond_destroy(&p->q.cv_pop);

    // Free queue storage and reset fields so double-destroy is safe
    free(p->q.buf);
    p->q.buf = NULL;
    p->q.cap = 0;
    p->q.head = 0;
    p->q.tail = 0;
    p->q.count = 0;
    p->q.stop = 0;
}

static void b3p_taskgroup_init(b3p_taskgroup_t* g) {
    // Initialize a taskgroup in the "no pending work" state
    atomic_init(&g->pending, 0);

    // Mutex/cond pair used to wait until pending reaches zero
    pthread_mutex_init(&g->mu, NULL);
    pthread_cond_init(&g->cv, NULL);
}

static void b3p_taskgroup_destroy(b3p_taskgroup_t* g) {
    // Destroy synchronization primitives associated with the taskgroup
    pthread_mutex_destroy(&g->mu);
    pthread_cond_destroy(&g->cv);
}

static int b3p_pool_submit(b3p_pool_t* p, b3p_taskgroup_t* g, b3p_task_fn fn, void* arg) {
    // Reject invalid pool or task function pointers
    if (!p || !fn) {
        return -1;
    }

    // Count the task as pending before it can possibly complete
    if (g) {
        atomic_fetch_add_explicit(&g->pending, 1, memory_order_relaxed);
    }

    // Push the task into the bounded queue
    pthread_mutex_lock(&p->q.mu);

    // Wait while the queue is full, unless a stop was requested
    while (p->q.count == p->q.cap && !p->q.stop) {
        pthread_cond_wait(&p->q.cv_push, &p->q.mu);
    }

    // If stopping, roll back the pending count and fail
    if (p->q.stop) {
        pthread_mutex_unlock(&p->q.mu);

        if (g) {
            unsigned prev = atomic_fetch_sub_explicit(&g->pending, 1, memory_order_relaxed);
            (void)prev;
            pthread_mutex_lock(&g->mu);
            if (atomic_load_explicit(&g->pending, memory_order_relaxed) == 0) {
                pthread_cond_broadcast(&g->cv);
            }
            pthread_mutex_unlock(&g->mu);
        }

        return -1;
    }

    // Fill the next slot in the ring buffer
    b3p_task_t* t = &p->q.buf[p->q.tail];
    t->fn = fn;
    t->arg = arg;
    t->group = g;

    // Advance tail and increase count
    p->q.tail = (p->q.tail + 1) & (p->q.cap - 1);
    p->q.count++;

    // Wake one worker waiting for a task
    pthread_cond_signal(&p->q.cv_pop);
    pthread_mutex_unlock(&p->q.mu);

    return 0;
}

static void b3p_taskgroup_wait(b3p_taskgroup_t* g) {
    // Waiting on a NULL taskgroup is a no-op
    if (!g) {
        return;
    }

    // Wait until pending reaches zero, using the condvar for sleep/wake
    pthread_mutex_lock(&g->mu);
    while (atomic_load_explicit(&g->pending, memory_order_relaxed) != 0) {
        pthread_cond_wait(&g->cv, &g->mu);
    }
    pthread_mutex_unlock(&g->mu);
}

static void* b3p_worker_main(void* arg) {
    // Each worker services the shared pool queue
    b3p_pool_t* p = (b3p_pool_t*)arg;

    // Mask for queue wrapping (cap is power of 2)
    const size_t wrap_mask = p->q.cap - 1;

    for (;;) {
        // Local copy so we can run the task outside the queue lock
        b3p_task_t t = (b3p_task_t){0};

        // Pop one task from the queue, blocking if empty
        pthread_mutex_lock(&p->q.mu);
        while (p->q.count == 0 && !p->q.stop) {
            pthread_cond_wait(&p->q.cv_pop, &p->q.mu);
        }

        // Exit once stop is requested and all queued work is drained
        if (p->q.stop && p->q.count == 0) {
            pthread_mutex_unlock(&p->q.mu);
            break;
        }

        // Remove the task from the head of the ring buffer
        t = p->q.buf[p->q.head];
        p->q.head = (p->q.head + 1) & wrap_mask;
        p->q.count--;

        // Wake a producer waiting for space
        pthread_cond_signal(&p->q.cv_push);
        pthread_mutex_unlock(&p->q.mu);

        // Execute the task outside the queue lock
        t.fn(t.arg);

        // Mark completion on the associated taskgroup, if any
        if (t.group) {
            unsigned prev = atomic_fetch_sub_explicit(&t.group->pending, 1, memory_order_relaxed);

            // If we just dropped to zero, wake any waiters
            if (prev == 1) {
                pthread_mutex_lock(&t.group->mu);
                pthread_cond_broadcast(&t.group->cv);
                pthread_mutex_unlock(&t.group->mu);
            }
        }
    }

    // Worker exit cleanup
    // TLS scratch is owned by the thread, so it can be freed here safely
    if (g_tls_cv_buf) {
        free(g_tls_cv_buf);
        g_tls_cv_buf = NULL;
    }
    g_tls_cv_cap = 0;

    return NULL;
}

static int b3p_ensure_scratch(struct b3p_ctx* ctx, size_t want_cvs) {
    // Validate context pointer
    if (!ctx) {
        return -1;
    }

    // Nothing to do if we already have enough capacity
    if (want_cvs <= ctx->scratch_cvs_cap) {
        return 0;
    }

    // Reject requests that would overflow allocation sizing
    const size_t max_elems = SIZE_MAX / sizeof(b3_cv_bytes_t);
    if (want_cvs > max_elems) {
        return -1;
    }

    // Start with a baseline capacity to reduce realloc churn
    size_t new_cap = ctx->scratch_cvs_cap ? ctx->scratch_cvs_cap : (size_t)1024;

    // Clamp baseline to the representable maximum
    if (new_cap > max_elems) {
        new_cap = max_elems;
    }

    // Grow exponentially until reaching want_cvs, avoiding overflow
    while (new_cap < want_cvs) {
        // If doubling would overflow, jump directly to want_cvs
        if (new_cap > max_elems / 2) {
            new_cap = want_cvs;
            break;
        }
        new_cap *= 2;
    }

    // Final sanity check before computing bytes
    if (new_cap > max_elems) {
        return -1;
    }

    // Compute allocation size in bytes with overflow excluded by max_elems checks
    size_t bytes = new_cap * sizeof(b3_cv_bytes_t);

    // Reallocate and preserve old buffer on failure
    void* p = realloc(ctx->scratch_cvs, bytes);
    if (!p) {
        return -1;
    }

    // Commit only after realloc succeeds
    ctx->scratch_cvs = (b3_cv_bytes_t*)p;
    ctx->scratch_cvs_cap = new_cap;
    return 0;
}

static inline size_t b3_min_sz(size_t a, size_t b) {
    // Return the smaller of two size_t values
    return a < b ? a : b;
}

static inline size_t b3_full_chunks(size_t input_len) {
    // Number of complete BLAKE3 chunks in the input, excluding any partial tail
    return input_len / (size_t)BLAKE3_CHUNK_LEN;
}

static b3p_method_t b3p_pick_heuristic(struct b3p_ctx* ctx) {
    // If the pool is disabled or single-threaded, chunk scheduling is the simplest path
    if (!ctx || ctx->pool.nthreads < 2) {
        return B3P_METHOD_A_CHUNKS;
    }

    // Avoid parallel overhead for small inputs
    if (ctx->input_len < ctx->cfg.min_parallel_bytes) {
        return B3P_METHOD_A_CHUNKS;
    }

    // Use only full chunks for the parallelism decision to avoid tail effects
    size_t chunks = b3_full_chunks(ctx->input_len);

    // If there aren't enough chunks overall, prefer chunk-level scheduling
    if (chunks < ctx->cfg.method_a_min_chunks) {
        return B3P_METHOD_A_CHUNKS;
    }

    // Determine how many SIMD lanes we can effectively use, clamped to the implementation maximum
    size_t simd = blake3_simd_degree();
    size_t effective_lane = b3_min_sz(simd, (size_t)MAX_SIMD_DEGREE);

    // Require enough work per thread to amortize subtree setup and reduction costs
    size_t chunks_per_thread_floor = ctx->cfg.method_b_min_chunks_per_thread * effective_lane;

    // Guard multiplication overflow in the threshold computation
    size_t threshold = 0;
    if (chunks_per_thread_floor != 0 && ctx->pool.nthreads > SIZE_MAX / chunks_per_thread_floor) {
        // If the threshold would overflow, it is effectively "too large", so choose chunks
        return B3P_METHOD_A_CHUNKS;
    }
    threshold = ctx->pool.nthreads * chunks_per_thread_floor;

    // Prefer subtree-level parallelism only when there is enough work per worker
    if (chunks >= threshold) {
        return B3P_METHOD_B_SUBTREES;
    }

    // Default to chunk-level parallelism for everything else
    return B3P_METHOD_A_CHUNKS;
}

static void b3p_task_hash_chunks(void* arg) {
    // Validate the job pointer and required fields
    b3p_chunks_job_t* job = (b3p_chunks_job_t*)arg;
    if (!job || !job->ctx || !job->out_cvs) {
        return;
    }

    struct b3p_ctx* ctx = job->ctx;

    // A zero batch_step would deadlock progress due to fetch_add(0)
    if (job->batch_step == 0) {
        return;
    }

    // Local buffer sized for the common-case maximum batch
    // Keeps per-batch CVs on the stack, avoiding heap traffic
    b3_cv_bytes_t local_buf[64];

    for (;;) {
        // Claim the next batch range atomically
        size_t batch_start = atomic_fetch_add_explicit(&job->next_chunk, job->batch_step, memory_order_relaxed);

        // Stop when all chunks have been claimed
        if (batch_start >= job->end_chunk) {
            break;
        }

        // Compute the exclusive end of this batch, clamped to end_chunk
        size_t batch_limit = batch_start + job->batch_step;
        if (batch_limit < batch_start) {
            // Overflow in addition means the request is nonsensical, bail out safely
            break;
        }
        if (batch_limit > job->end_chunk) {
            batch_limit = job->end_chunk;
        }

        // Compute a stable batch index for where this batch root CV is written
        size_t batch_idx = batch_start / job->batch_step;

        // This batch is the entire input only in the single-batch case
        // Passing is_root through ensures correct ROOT handling for tiny inputs
        int is_root = (batch_start == 0 && batch_limit == ctx->num_chunks);

        // Determine how many chunk CVs this batch will produce in the temporary buffer
        size_t want_tmp = batch_limit - batch_start;
        if (want_tmp == 0) {
            // Nothing to do for an empty range
            continue;
        }

        // Use stack storage when it fits, otherwise fall back to per-thread TLS scratch
        b3_cv_bytes_t* tmp = local_buf;
        if (want_tmp > (sizeof(local_buf) / sizeof(local_buf[0]))) {
            tmp = ensure_tls_cv_buffer(want_tmp);
            if (!tmp) {
                // Allocation failure for scratch means this worker can't make progress
                break;
            }
        }

        // Hash the claimed range and reduce it to the batch root CV
        // Only the true root batch writes out_split_children for XOF root reconstruction
        b3p_hash_range_to_root(ctx, batch_start, batch_limit, tmp, &job->out_cvs[batch_idx], is_root, is_root ? job->out_split_children : NULL);
    }
}

static inline void
b3p_hash_range_to_root(struct b3p_ctx* ctx, size_t chunk_start, size_t chunk_end, b3_cv_bytes_t* restrict tmp, b3_cv_bytes_t* restrict out_root, int is_root, b3_cv_bytes_t* out_split_children) {
    // Validate required pointers and basic range sanity
    if (!ctx || !tmp || !out_root) {
        return;
    }
    if (chunk_end < chunk_start) {
        return;
    }

    // Number of chunks in this range
    size_t n = chunk_end - chunk_start;
    if (n == 0) {
        return;
    }

#if DEBUG_PARALLEL
    // Debug trace for chunk range hashing
    fprintf(stderr, "[parallel] hash_range_to_root: chunk_start=%zu chunk_end=%zu n=%zu\n", chunk_start, chunk_end, n);
#endif

    // Clamp SIMD degree to the compile-time maximum used by the inputs[] stack array
    size_t simd_degree = blake3_simd_degree();
    if (simd_degree > (size_t)MAX_SIMD_DEGREE) {
        simd_degree = (size_t)MAX_SIMD_DEGREE;
    }
    if (simd_degree == 0) {
        simd_degree = 1;
    }

    // Compute the starting input pointer for the first chunk in the range
    // chunk_start * CHUNK_LEN cannot overflow in valid callers, but guard anyway
    if (chunk_start > SIZE_MAX / (size_t)BLAKE3_CHUNK_LEN) {
        return;
    }
    size_t start_off = chunk_start * (size_t)BLAKE3_CHUNK_LEN;
    if (start_off > ctx->input_len) {
        return;
    }

    const uint8_t* input_ptr = ctx->input + start_off;

    // Hash chunks in SIMD-sized batches
    size_t i = 0;
    while (i < n) {
        // Choose up to simd_degree chunks for this batch
        size_t count = simd_degree;
        if (i + count > n) {
            count = n - i;
        }

        // Determine how many of the next 'count' chunks are full
        // If the very last chunk is partial, hash it with the chunk primitive
        size_t full_count = count;
        if (chunk_start + i + count == ctx->num_chunks) {
            // Compute offset of final chunk start and check if tail is partial
            size_t last_off = (ctx->num_chunks - 1) * (size_t)BLAKE3_CHUNK_LEN;
            if (last_off <= ctx->input_len) {
                size_t tail = ctx->input_len - last_off;
                if (tail < (size_t)BLAKE3_CHUNK_LEN) {
                    // Leave the last chunk to the slow path
                    full_count--;
                }
            }
        }

        // Hash the full chunks of this batch with the batched fast path
        if (full_count > 0) {
            // Gather chunk pointers for the batch
            const uint8_t* inputs[MAX_SIMD_DEGREE];
            for (size_t j = 0; j < full_count; j++) {
                inputs[j] = input_ptr + j * (size_t)BLAKE3_CHUNK_LEN;
            }

            // Select chunk end flags, adding ROOT only for the true single-chunk root case
            uint8_t flags_end = CHUNK_END;
            if (is_root && n == 1 && full_count == 1) {
                flags_end |= ROOT;
            }

            // Hash 'full_count' full chunks starting at chunk counter (chunk_start + i)
            // Each output CV is written contiguously starting at tmp[i].bytes
            blake3_hash_many(inputs, full_count, BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, ctx->kf.key, (uint64_t)(chunk_start + i), true, ctx->kf.flags, CHUNK_START, flags_end, tmp[i].bytes);
        }

        // If the batch includes the final partial chunk, hash it with the chunk primitive
        if (full_count < count) {
            size_t j = full_count;

            // Global chunk index for this partial chunk
            size_t chunk_i = chunk_start + i + j;

            // Pointer to the start of this chunk
            const uint8_t* partial_chunk_ptr = input_ptr + j * (size_t)BLAKE3_CHUNK_LEN;

            // Compute the remaining bytes in the input starting at this chunk
            if (chunk_i > SIZE_MAX / (size_t)BLAKE3_CHUNK_LEN) {
                return;
            }
            size_t off = chunk_i * (size_t)BLAKE3_CHUNK_LEN;
            if (off > ctx->input_len) {
                return;
            }

            size_t remain = ctx->input_len - off;
            size_t clen = remain < (size_t)BLAKE3_CHUNK_LEN ? remain : (size_t)BLAKE3_CHUNK_LEN;

            // Root flag in the chunk primitive is only valid for the overall single-chunk case
            int chunk_is_root = (is_root && n == 1);

            // Partial chunk uses the chunk CV primitive
            // This avoids padding logic in the hash_many fast path
            b3_hash_chunk_cv_impl(ctx->kf.key, ctx->kf.flags, partial_chunk_ptr, clen, (uint64_t)chunk_i, chunk_is_root, tmp[i + j].bytes);
        }

        // Advance to the next SIMD batch
        i += count;

        // Move input_ptr forward by count chunks, guarding overflow defensively
        if (count > SIZE_MAX / (size_t)BLAKE3_CHUNK_LEN) {
            return;
        }
        input_ptr += count * (size_t)BLAKE3_CHUNK_LEN;
    }

    // Reduce the per-chunk CVs to a single root CV using stack merge to preserve tree shape
    b3p_reduce_stack(ctx, tmp, n, 1, n, out_root, is_root, out_split_children);
}

static void b3p_task_hash_subtrees(void* arg) {
    // Validate the job pointer and required fields
    b3p_subtrees_job_t* job = (b3p_subtrees_job_t*)arg;
    if (!job || !job->ctx || !job->out_subtree_cvs) {
        return;
    }

    struct b3p_ctx* ctx = job->ctx;

    // A subtree size of 0 would cause an infinite loop or division-by-zero patterns elsewhere
    if (job->subtree_chunks == 0) {
        return;
    }

    // Allocate per-thread temporary CV storage from TLS
    // This avoids heap churn and is reused across tasks within the same worker
    size_t max_tmp = job->subtree_chunks;
    b3_cv_bytes_t* tmp = ensure_tls_cv_buffer(max_tmp);
    if (!tmp) {
        return;
    }

    for (;;) {
        // Claim the next subtree index
        size_t s = atomic_fetch_add_explicit(&job->next_subtree, 1, memory_order_relaxed);

        // Stop when all subtrees are claimed
        if (s >= job->num_subtrees) {
            break;
        }

        // Compute the chunk range covered by this subtree
        // chunk_start = s * subtree_chunks, with overflow guarded
        if (s > SIZE_MAX / job->subtree_chunks) {
            break;
        }
        size_t chunk_start = s * job->subtree_chunks;

        // Compute exclusive end and clamp to the total chunk count
        size_t chunk_end = chunk_start + job->subtree_chunks;
        if (chunk_end < chunk_start) {
            break;
        }
        if (chunk_end > ctx->num_chunks) {
            chunk_end = ctx->num_chunks;
        }

        // Hash and reduce the subtree range to a subtree root CV
        b3_cv_bytes_t root = (b3_cv_bytes_t){0};

        // Only the single-subtree case represents the overall root input
        int is_root = (job->num_subtrees == 1);

        // In the root case, propagate split children for later XOF root reconstruction
        b3p_hash_range_to_root(ctx, chunk_start, chunk_end, tmp, &root, is_root, is_root ? job->out_split_children : NULL);

        // Store the computed subtree root at its assigned index
        job->out_subtree_cvs[s] = root;
    }
}

/* Merge two child CVs into a parent CV
   ROOT is applied only at the final merge step */
static inline void b3p_merge_nodes(const uint32_t key[8], uint8_t base_flags, const b3_cv_bytes_t* left, const b3_cv_bytes_t* restrict right, b3_cv_bytes_t* out, int is_root) {
    // Validate pointers to avoid UB in leaf callers
    if (!key || !left || !right || !out) {
        return;
    }

    // Parent nodes always include PARENT, and ROOT is applied only at the final merge step
    uint8_t flags = (uint8_t)(base_flags | PARENT);
    if (is_root) {
        flags |= ROOT;
    }

    // Compute parent chaining value from two child CVs
    b3_hash_parent_cv_impl(key, flags, left->bytes, right->bytes, out->bytes);
}

static void b3p_reduce_stack(struct b3p_ctx* ctx,
                             b3_cv_bytes_t* restrict cvs,
                             size_t n,
                             size_t subtree_chunks,
                             size_t total_chunks,
                             b3_cv_bytes_t* restrict out_root,
                             int is_final,
                             b3_cv_bytes_t* out_split_children) {
    // Validate required pointers and basic preconditions
    if (!ctx || !cvs || !out_root) {
        return;
    }

    // A reduction over zero CVs is undefined in this implementation
    if (n == 0) {
        return;
    }

    // subtree_chunks should be at least 1 to make progress
    if (subtree_chunks == 0) {
        return;
    }

    // The lazy-merge stack depth is bounded by log2(total chunks)
    // 64 is enough for any realistic input sizes, but keep a guard anyway
    size_t stack_counts[64];
    size_t top = 0;

    // Compute total_count across all CVs, accounting for a shorter last subtree
    size_t total_count = 0;
    for (size_t i = 0; i < n; i++) {
        // Default chunk count represented by each CV
        size_t count = subtree_chunks;

        // If reducing subtree roots, the last subtree may be partial
        if (subtree_chunks > 1 && i == n - 1) {
            size_t remainder = total_chunks % subtree_chunks;
            if (remainder != 0) {
                count = remainder;
            }
        }

        // Guard against size_t overflow in total_count accumulation
        if (count > SIZE_MAX - total_count) {
            return;
        }
        total_count += count;
    }

    // Push each CV with its corresponding count and merge lazily when counts match
    for (size_t i = 0; i < n; i++) {
        // Determine the count represented by this CV
        size_t count = subtree_chunks;
        if (subtree_chunks > 1 && i == n - 1) {
            size_t remainder = total_chunks % subtree_chunks;
            if (remainder != 0) {
                count = remainder;
            }
        }

        // Compact CVs in-place so the merge results are always in the lower indices
        if (top != i) {
            cvs[top] = cvs[i];
        }

        // Push count for this CV
        if (top >= (sizeof(stack_counts) / sizeof(stack_counts[0]))) {
            // Stack would overflow, which implies an unexpected tree shape for this bound
            return;
        }
        stack_counts[top] = count;
        top++;

        // Merge while the top two stack entries have the same subtree size
        while (top >= 2) {
            if (stack_counts[top - 1] != stack_counts[top - 2]) {
                break;
            }

            size_t right_idx = top - 1;
            size_t left_idx = top - 2;

            // Combine counts, guarding overflow
            if (stack_counts[left_idx] > SIZE_MAX - stack_counts[right_idx]) {
                return;
            }
            size_t new_count = stack_counts[left_idx] + stack_counts[right_idx];

            // This merge is the root only if it's the final reduction and spans the whole input
            int is_root = (is_final && new_count == total_count);

            // If the caller wants split children, capture them at the root merge boundary
            if (is_root && out_split_children) {
                out_split_children[0] = cvs[left_idx];
                out_split_children[1] = cvs[right_idx];
                return;
            }

            // Merge child CVs into the parent CV in-place at left_idx
            b3p_merge_nodes(ctx->kf.key, ctx->kf.flags, &cvs[left_idx], &cvs[right_idx], &cvs[left_idx], is_root);

            // Replace the left count with the combined count and pop the right entry
            stack_counts[left_idx] = new_count;
            top--;
        }
    }

    // Merge any remaining uneven stack entries from right to left
    while (top > 1) {
        size_t right_idx = top - 1;
        size_t left_idx = top - 2;

        // Combine counts, guarding overflow
        if (stack_counts[left_idx] > SIZE_MAX - stack_counts[right_idx]) {
            return;
        }
        size_t new_count = stack_counts[left_idx] + stack_counts[right_idx];

        // Root detection matches the lazy-merge logic above
        int is_root = (is_final && new_count == total_count);

        // Optionally expose the two children that form the final root parent
        if (is_root && out_split_children) {
            out_split_children[0] = cvs[left_idx];
            out_split_children[1] = cvs[right_idx];
            return;
        }

        // Merge into the left slot
        b3p_merge_nodes(ctx->kf.key, ctx->kf.flags, &cvs[left_idx], &cvs[right_idx], &cvs[left_idx], is_root);

        // Update count and pop
        stack_counts[left_idx] = new_count;
        top--;
    }

    // The final root CV is at the bottom of the stack
    *out_root = cvs[0];
}

static int b3p_run_method_a_chunks(struct b3p_ctx* ctx, b3_cv_bytes_t* out_root, b3_cv_bytes_t* out_split_children) {
    // Validate required pointers
    if (!ctx || !out_root) {
        return -1;
    }

    // Determine SIMD degree used by the underlying implementation and clamp it
    size_t simd_degree = blake3_simd_degree();
    if (simd_degree > (size_t)MAX_SIMD_DEGREE) {
        simd_degree = (size_t)MAX_SIMD_DEGREE;
    }
    if (simd_degree == 0) {
        simd_degree = 1;
    }

    // Batch size amortizes scheduling and reduction overhead
    // Larger batches reduce queue pressure, but increase per-task latency
    size_t batch_step = simd_degree * 8;

    // Guard multiplication overflow, fall back to a conservative batch size
    if (batch_step / 8 != simd_degree) {
        batch_step = 64;
    }
    if (batch_step == 0) {
        batch_step = 64;
    }

    // Compute the number of batches using overflow-safe ceiling division
    size_t num_batches = 1;
    if (ctx->num_chunks != 0) {
        if (ctx->num_chunks > SIZE_MAX - (batch_step - 1)) {
            return -1;
        }
        num_batches = (ctx->num_chunks + (batch_step - 1)) / batch_step;
        if (num_batches == 0) {
            num_batches = 1;
        }
    }

    // Ensure scratch storage is large enough to hold per-batch CVs
    if (b3p_ensure_scratch(ctx, num_batches) != 0) {
        return -1;
    }

    // Prepare the shared job descriptor used by all workers
    b3p_chunks_job_t job = {
        .ctx = ctx,
        .next_chunk = 0,
        .end_chunk = ctx->num_chunks,
        .batch_step = batch_step,
        .out_cvs = ctx->scratch_cvs,
        .out_split_children = out_split_children,
    };

    // Initialize a taskgroup to wait for worker completion
    b3p_taskgroup_t g;
    b3p_taskgroup_init(&g);

    // Decide how many worker tasks to enqueue
    // In serial mode (no pool), run exactly one worker on the calling thread
    size_t tasks = 1;
    if (ctx->pool.nthreads > 0) {
        tasks = ctx->pool.nthreads;
    }

    // Optimization: if only one batch, run on the calling thread
    // This guarantees any split-children write happens on this stack frame when desired
    if (num_batches == 1 || tasks == 1) {
        b3p_task_hash_chunks(&job);
    }
    else {
        // Submit tasks to the pool, leaving one for the calling thread
        for (size_t t = 0; t < tasks - 1; t++) {
            if (b3p_pool_submit(&ctx->pool, &g, b3p_task_hash_chunks, &job) != 0) {
                // If submission fails, wait for any already-submitted work to drain
                b3p_taskgroup_wait(&g);
                b3p_taskgroup_destroy(&g);
                return -1;
            }
        }

        // Calling thread participates in the work
        b3p_task_hash_chunks(&job);

        // Wait until all submitted worker tasks report completion
        b3p_taskgroup_wait(&g);
    }

    // Destroy taskgroup resources
    b3p_taskgroup_destroy(&g);

    // Reduce batch-root CVs into the final tree root
    b3p_reduce_stack(ctx, ctx->scratch_cvs, num_batches, batch_step, ctx->num_chunks, out_root, 1, out_split_children);
    return 0;
}

/* Method B
   Subtree batching hashes fixed-size subtrees per task
   Final merge reduces subtree roots into the tree root */
static int b3p_run_method_b_subtrees(struct b3p_ctx* ctx, b3_cv_bytes_t* out_root, b3_cv_bytes_t* out_split_children) {
    // Validate required pointers
    if (!ctx || !out_root) {
        return -1;
    }

    // Choose subtree size from config or default
    size_t subtree_chunks = ctx->cfg.subtree_chunks;
    if (subtree_chunks == 0) {
        subtree_chunks = B3P_DEFAULT_SUBTREE_CHUNKS;
    }

    // Power-of-two subtree sizes minimize merge irregularity
    subtree_chunks = round_down_to_power_of_2(subtree_chunks);

    // Ensure subtree_chunks is non-zero after rounding
    if (subtree_chunks == 0) {
        subtree_chunks = 1;
    }

    // Compute number of subtrees with overflow-safe ceiling division
    size_t num_subtrees = 1;
    if (ctx->num_chunks != 0) {
        if (ctx->num_chunks > SIZE_MAX - (subtree_chunks - 1)) {
            return -1;
        }
        num_subtrees = (ctx->num_chunks + (subtree_chunks - 1)) / subtree_chunks;
        if (num_subtrees == 0) {
            num_subtrees = 1;
        }
    }

    // Ensure scratch storage is large enough for subtree roots
    if (b3p_ensure_scratch(ctx, num_subtrees) != 0) {
        return -1;
    }

    // Prepare the shared job descriptor used by all workers
    b3p_subtrees_job_t job = {
        .ctx = ctx,
        .subtree_chunks = subtree_chunks,
        .next_subtree = 0,
        .num_subtrees = num_subtrees,
        .out_subtree_cvs = ctx->scratch_cvs,
        .out_split_children = out_split_children,
    };

    // Initialize a taskgroup to wait for worker completion
    b3p_taskgroup_t g;
    b3p_taskgroup_init(&g);

    // Decide how many worker tasks to enqueue
    // In serial mode (no pool), run exactly one worker on the calling thread
    size_t tasks = 1;
    if (ctx->pool.nthreads > 0) {
        tasks = ctx->pool.nthreads;
    }

    // If only one subtree (or serial mode), run on the calling thread
    if (num_subtrees == 1 || tasks == 1) {
        b3p_task_hash_subtrees(&job);
    }
    else {
        // Submit tasks to the pool, leaving one for the calling thread
        for (size_t t = 0; t < tasks - 1; t++) {
            if (b3p_pool_submit(&ctx->pool, &g, b3p_task_hash_subtrees, &job) != 0) {
                // If submission fails, wait for any already-submitted work to drain
                b3p_taskgroup_wait(&g);
                b3p_taskgroup_destroy(&g);
                return -1;
            }
        }

        // Calling thread participates in the work
        b3p_task_hash_subtrees(&job);

        // Wait until all subtrees have been processed
        b3p_taskgroup_wait(&g);
    }

    // Destroy taskgroup resources
    b3p_taskgroup_destroy(&g);

    // Reduce subtree roots into the final tree root
    b3p_reduce_stack(ctx, ctx->scratch_cvs, num_subtrees, subtree_chunks, ctx->num_chunks, out_root, 1, out_split_children);
    return 0;
}

/* Serial fallback for contexts created with nthreads <= 1
   Uses the same subtree partitioning logic without starting a worker pool */
static int b3p_run_serial(struct b3p_ctx* ctx, b3_cv_bytes_t* out_root, b3_cv_bytes_t* out_split_children) {
    // Validate required pointers
    if (!ctx || !out_root) {
        return -1;
    }

    // Choose subtree size from config or default
    size_t subtree_chunks = ctx->cfg.subtree_chunks;
    if (subtree_chunks == 0) {
        subtree_chunks = B3P_DEFAULT_SUBTREE_CHUNKS;
    }

    // Power-of-two subtree sizes minimize merge irregularity
    subtree_chunks = round_down_to_power_of_2(subtree_chunks);

    // Ensure subtree_chunks is non-zero after rounding
    if (subtree_chunks == 0) {
        subtree_chunks = 1;
    }

    // Compute number of subtrees with overflow-safe ceiling division
    size_t num_subtrees = 1;
    if (ctx->num_chunks != 0) {
        if (ctx->num_chunks > SIZE_MAX - (subtree_chunks - 1)) {
            return -1;
        }
        num_subtrees = (ctx->num_chunks + (subtree_chunks - 1)) / subtree_chunks;
        if (num_subtrees == 0) {
            num_subtrees = 1;
        }
    }

    // Ensure scratch storage is large enough for subtree roots
    if (b3p_ensure_scratch(ctx, num_subtrees) != 0) {
        return -1;
    }

    // Allocate per-thread temporary CV storage from TLS
    // In serial mode this is still useful because it can grow for large subtrees
    b3_cv_bytes_t* tmp = ensure_tls_cv_buffer(subtree_chunks);
    if (!tmp) {
        return -1;
    }

    // Only a single subtree represents the overall root input
    int is_root = (num_subtrees == 1);

    // Hash each subtree sequentially and store its root CV
    for (size_t s = 0; s < num_subtrees; s++) {
        // Compute the chunk range for this subtree, guarding overflow
        if (s > SIZE_MAX / subtree_chunks) {
            return -1;
        }
        size_t chunk_start = s * subtree_chunks;

        // Compute exclusive end and clamp to total chunk count
        size_t chunk_end = chunk_start + subtree_chunks;
        if (chunk_end < chunk_start) {
            return -1;
        }
        if (chunk_end > ctx->num_chunks) {
            chunk_end = ctx->num_chunks;
        }

        // Hash and reduce the subtree to a root CV
        b3_cv_bytes_t root = (b3_cv_bytes_t){0};

        // In the root case, propagate split children for later XOF root reconstruction
        b3p_hash_range_to_root(ctx, chunk_start, chunk_end, tmp, &root, is_root, is_root ? out_split_children : NULL);

        // Store subtree root into scratch for the final reduction
        ctx->scratch_cvs[s] = root;
    }

    // Reduce subtree roots into the final tree root
    b3p_reduce_stack(ctx, ctx->scratch_cvs, num_subtrees, subtree_chunks, ctx->num_chunks, out_root, 1, out_split_children);
    return 0;
}

/* Root computation dispatch
   Uses serial path if no pool exists, otherwise selects the requested method */
static int b3p_compute_root(struct b3p_ctx* ctx, b3p_method_t method, b3_cv_bytes_t* out_root, b3_cv_bytes_t* out_split_children, uint64_t* out_ns) {
    // Validate required pointers
    if (!ctx || !out_root || !out_ns) {
        return -1;
    }

    // Default timing output to 0 for builds without profiling
    *out_ns = 0;

    // If the pool is disabled, always run serial regardless of requested method
    if (ctx->pool.nthreads == 0) {
        return b3p_run_serial(ctx, out_root, out_split_children);
    }

    // Dispatch to the selected method, rejecting unsupported values
    int rc = -1;
    switch (method) {
        case B3P_METHOD_A_CHUNKS:
            rc = b3p_run_method_a_chunks(ctx, out_root, out_split_children);
            break;

        case B3P_METHOD_B_SUBTREES:
            rc = b3p_run_method_b_subtrees(ctx, out_root, out_split_children);
            break;

        default:
            // Unknown method value
            rc = -1;
            break;
    }

    // Keep timing at 0 unless a timing backend is wired up
    return rc;
}

/* Serial one-shot helper
   This is intended for small buffers where parallel setup would dominate */
int b3p_hash_buffer_serial(const uint8_t* input, size_t input_len, const uint8_t key[BLAKE3_KEY_LEN], uint8_t flags, uint8_t* out, size_t out_len) {
    // Validate required pointers for any non-trivial work
    if (!input || !out || !key) {
        return -1;
    }

    // A zero-length output request is always a no-op success
    if (out_len == 0) {
        return 0;
    }

    // Use a stack context so the caller doesn't need to allocate a b3p_ctx_t
    struct b3p_ctx ctx = (struct b3p_ctx){0};
    ctx.input = input;
    ctx.input_len = input_len;

    // Compute number of chunks using overflow-safe ceiling division
    const size_t chunk_len = (size_t)BLAKE3_CHUNK_LEN;
    size_t num_chunks = 1;

    if (input_len != 0) {
        // Guard the "+ (chunk_len - 1)" round-up term against size_t overflow
        if (input_len > SIZE_MAX - (chunk_len - 1)) {
            return -1;
        }
        num_chunks = (input_len + (chunk_len - 1)) / chunk_len;

        // Defensive: never allow 0
        if (num_chunks == 0) {
            num_chunks = 1;
        }
    }

    ctx.num_chunks = num_chunks;

    // Convert key bytes to little-endian u32 words once per call
    for (size_t i = 0; i < 8; i++) {
        uint32_t w = 0;
        w |= (uint32_t)key[i * 4 + 0] << 0;
        w |= (uint32_t)key[i * 4 + 1] << 8;
        w |= (uint32_t)key[i * 4 + 2] << 16;
        w |= (uint32_t)key[i * 4 + 3] << 24;
        ctx.kf.key[i] = w;
    }

    // Store flags for this call
    ctx.kf.flags = flags;

    // Fast path: a single chunk can be hashed directly and supports XOF output
    if (ctx.num_chunks == 1) {
        blake3_chunk_state state;

        // Initialize the chunk state with the keyed words and flags
        chunk_state_init(&state, ctx.kf.key, ctx.kf.flags);

        // One-shot root always starts at chunk counter 0
        state.chunk_counter = 0;

        // Feed the chunk (possibly empty) into the state
        chunk_state_update(&state, ctx.input, ctx.input_len);

        // Produce the output descriptor for the root
        output_t output = chunk_state_output(&state);

        // Emit output bytes at seek 0
        b3_output_root_impl(output.input_cv, output.flags, output.block, output.block_len, output.counter, 0, out, out_len);
        return 0;
    }

    // Allocate temporary CV storage from TLS for per-chunk outputs
    b3_cv_bytes_t* tmp = ensure_tls_cv_buffer(ctx.num_chunks);
    if (!tmp) {
        return -1;
    }

    // Hash the entire input range and reduce to the root, capturing split children for XOF
    b3_cv_bytes_t root = (b3_cv_bytes_t){0};
    b3_cv_bytes_t split_children[2] = {0};

    b3p_hash_range_to_root(&ctx, 0, ctx.num_chunks, tmp, &root, 1, split_children);

    // Reconstruct the root parent block as left child CV || right child CV
    uint8_t root_block[BLAKE3_BLOCK_LEN];
    memcpy(root_block, split_children[0].bytes, 32);
    memcpy(root_block + 32, split_children[1].bytes, 32);

    // Emit XOF output for the root parent at seek 0
    b3_output_root_impl(ctx.kf.key, (uint8_t)(ctx.kf.flags | PARENT), root_block, BLAKE3_BLOCK_LEN, 0, 0, out, out_len);
    return 0;
}
