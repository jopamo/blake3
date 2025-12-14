#define _GNU_SOURCE
#include "blake3_parallel.h"
#include "blake3_impl.h"

/* Types previously defined in blake3_internal.h */
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

// Thread-local scratch space for CVs (avoiding per-task malloc/alloca)
static __thread b3_cv_bytes_t *g_tls_cv_buf = NULL;
static __thread size_t g_tls_cv_cap = 0;

static b3_cv_bytes_t* ensure_tls_cv_buffer(size_t count) {
    if (count > g_tls_cv_cap) {
        size_t new_cap = g_tls_cv_cap ? g_tls_cv_cap : 1024;
        while (new_cap < count) new_cap *= 2;
        
        b3_cv_bytes_t *new_buf = realloc(g_tls_cv_buf, new_cap * sizeof(b3_cv_bytes_t));
        if (!new_buf) return NULL;
        
        g_tls_cv_buf = new_buf;
        g_tls_cv_cap = new_cap;
    }
    return g_tls_cv_buf;
}

/* ============================================================================
 * Worker pool data structures
 * ===========================================================================*/

typedef void (*b3p_task_fn)(void *arg);

typedef struct {
  atomic_uint pending;
  pthread_mutex_t mu;
  pthread_cond_t cv;
} b3p_taskgroup_t;

typedef struct {
  b3p_task_fn fn;
  void *arg;
  b3p_taskgroup_t *group;
} b3p_task_t;

typedef struct {
  b3p_task_t *buf;
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
  pthread_t *threads;
  size_t nthreads;
  b3p_taskq_t q;
} b3p_pool_t;





/* ============================================================================
 * Context object tying it all together
 * ===========================================================================*/

typedef b3_keyed_flags_t b3p_keyed_flags_t;

struct b3p_ctx {
  b3p_keyed_flags_t kf;

  const uint8_t *input;
  size_t input_len;
  size_t num_chunks;

  b3_cv_bytes_t *scratch_cvs;
  size_t scratch_cvs_cap;

  b3p_pool_t pool;
  b3p_config_t cfg;
};

/* ============================================================================
 * Forward declarations of internal functions
 * ===========================================================================*/

static int b3p_pool_init(b3p_pool_t *p, size_t nthreads, size_t qcap);
static void b3p_pool_destroy(b3p_pool_t *p);
static void b3p_taskgroup_init(b3p_taskgroup_t *g);
static void b3p_taskgroup_destroy(b3p_taskgroup_t *g);
static int b3p_pool_submit(b3p_pool_t *p, b3p_taskgroup_t *g, b3p_task_fn fn, void *arg);
static void b3p_taskgroup_wait(b3p_taskgroup_t *g);
static void *b3p_worker_main(void *arg);


static int b3p_ensure_scratch(struct b3p_ctx *ctx, size_t want_cvs);

static b3p_method_t b3p_pick_heuristic(struct b3p_ctx *ctx);

static int b3p_run_method_a_chunks(struct b3p_ctx *ctx, b3_cv_bytes_t *out_root);
static int b3p_run_method_b_subtrees(struct b3p_ctx *ctx, b3_cv_bytes_t *out_root);
static void b3p_reduce_in_place(struct b3p_ctx *ctx, b3_cv_bytes_t *cvs, size_t n, b3_cv_bytes_t *out_root, int is_final);

static int b3p_compute_root(
  struct b3p_ctx *ctx,
  b3p_method_t method,
  b3_cv_bytes_t *out_root,
  uint64_t *out_ns
);

/* ============================================================================
 * Public API implementation
 * ===========================================================================*/

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

b3p_ctx_t *b3p_create(const b3p_config_t *cfg) {
  struct b3p_ctx *ctx = (struct b3p_ctx *)calloc(1, sizeof(struct b3p_ctx));
  if (!ctx) return NULL;

  ctx->cfg = *cfg;
  size_t nthreads = cfg->nthreads;
  if (nthreads == 0) {
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1) ncpu = 1;
    nthreads = (size_t)ncpu;
  }

  if (nthreads > 1) {
      if (b3p_pool_init(&ctx->pool, nthreads, nthreads * 2 < 2 ? 2 : nthreads * 2) != 0) {
        free(ctx);
        return NULL;
      }
  } else {
      ctx->pool.nthreads = 0;
  }

  ctx->scratch_cvs = NULL;
  ctx->scratch_cvs_cap = 0;

  return (b3p_ctx_t *)ctx;
}

void b3p_destroy(b3p_ctx_t *vctx) {
  struct b3p_ctx *ctx = (struct b3p_ctx *)vctx;
  if (!ctx) return;
  b3p_pool_destroy(&ctx->pool);
  free(ctx->scratch_cvs);
  free(ctx);
}

int b3p_hash_one_shot(
  b3p_ctx_t *ctx,
  const uint8_t *input,
  size_t input_len,
  const uint8_t key[BLAKE3_KEY_LEN],
  uint8_t flags,
  b3p_method_t method,
  uint8_t *out,
  size_t out_len
) {
  return b3p_hash_one_shot_seek(ctx, input, input_len, key, flags, method, 0, out, out_len);
}

int b3p_hash_one_shot_seek(
  b3p_ctx_t *vctx,
  const uint8_t *input,
  size_t input_len,
  const uint8_t key[BLAKE3_KEY_LEN],
  uint8_t flags,
  b3p_method_t method,
  uint64_t seek,
  uint8_t *out,
  size_t out_len
) {
  struct b3p_ctx *ctx = (struct b3p_ctx *)vctx;
  if (!ctx || !input || !out) return -1;
  if (out_len == 0) return 0;

  ctx->input = input;
  ctx->input_len = input_len;
  ctx->num_chunks = (input_len + (size_t)BLAKE3_CHUNK_LEN - 1) / (size_t)BLAKE3_CHUNK_LEN;
  if (ctx->num_chunks == 0) ctx->num_chunks = 1;

  // Convert key bytes to words
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
  fprintf(stderr, "[parallel] key bytes: ");
  for (int i = 0; i < BLAKE3_KEY_LEN; i++) {
    fprintf(stderr, "%02x", key[i]);
  }
  fprintf(stderr, "\n[parallel] key words: ");
  for (int i = 0; i < 8; i++) {
    fprintf(stderr, "%08x ", ctx->kf.key[i]);
  }
  fprintf(stderr, "\n[parallel] flags: %02x\n", flags);
#endif

  b3p_method_t chosen = method;
  if (method == B3P_METHOD_AUTO) {
    chosen = b3p_pick_heuristic(ctx);
  }

  b3_cv_bytes_t root = {0};
  uint64_t ns = 0;
  int rc = b3p_compute_root(ctx, chosen, &root, &ns);
  if (rc != 0)
    return rc;


  b3_output_root_impl(ctx->kf.key, ctx->kf.flags, root.bytes, seek, out, out_len);
  return 0;
}

/* ============================================================================
 * Worker pool implementation
 * ===========================================================================*/

static int b3p_pool_init(b3p_pool_t *p, size_t nthreads, size_t qcap) {
  if (qcap == 0) {
    qcap = 256;
  }
  if (nthreads == 0) {
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1) ncpu = 1;
    nthreads = (size_t)ncpu;
  }

  p->q.buf = (b3p_task_t*)calloc(qcap, sizeof(b3p_task_t));
  if (p->q.buf == NULL) return -1;
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
      /* Failed to create thread; stop already created threads */
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

static void b3p_pool_destroy(b3p_pool_t *p) {
  if (p->q.buf == NULL) return;

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

static void b3p_taskgroup_init(b3p_taskgroup_t *g) {
  atomic_init(&g->pending, 0);
  pthread_mutex_init(&g->mu, NULL);
  pthread_cond_init(&g->cv, NULL);
}

static void b3p_taskgroup_destroy(b3p_taskgroup_t *g) {
  pthread_mutex_destroy(&g->mu);
  pthread_cond_destroy(&g->cv);
}

static int b3p_pool_submit(b3p_pool_t *p, b3p_taskgroup_t *g, b3p_task_fn fn, void *arg) {
  pthread_mutex_lock(&p->q.mu);
  while (p->q.count == p->q.cap && !p->q.stop) {
    pthread_cond_wait(&p->q.cv_push, &p->q.mu);
  }
  if (p->q.stop) {
    pthread_mutex_unlock(&p->q.mu);
    return -1;
  }

  b3p_task_t *t = &p->q.buf[p->q.tail];
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

static void b3p_taskgroup_wait(b3p_taskgroup_t *g) {
  pthread_mutex_lock(&g->mu);
  while (atomic_load_explicit(&g->pending, memory_order_relaxed) > 0) {
    pthread_cond_wait(&g->cv, &g->mu);
  }
  pthread_mutex_unlock(&g->mu);
}

static void *b3p_worker_main(void *arg) {
  b3p_pool_t *p = (b3p_pool_t *)arg;

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

  if (g_tls_cv_buf) {
      free(g_tls_cv_buf);
      g_tls_cv_buf = NULL;
      g_tls_cv_cap = 0;
  }

  return NULL;
}









/* ============================================================================
 * Scratch management
 * ===========================================================================*/

static int b3p_ensure_scratch(struct b3p_ctx *ctx, size_t want_cvs) {
  if (want_cvs <= ctx->scratch_cvs_cap)
    return 0;

  size_t new_cap = ctx->scratch_cvs_cap ? ctx->scratch_cvs_cap : 1024;
  while (new_cap < want_cvs)
    new_cap *= 2;

  void *p = realloc(ctx->scratch_cvs, new_cap * sizeof(b3_cv_bytes_t));
  if (!p)
    return -1;

  ctx->scratch_cvs = p;
  ctx->scratch_cvs_cap = new_cap;
  return 0;
}

/* ============================================================================
 * Selection logic
 * ===========================================================================*/

static inline size_t b3_min_sz(size_t a, size_t b) { return a < b ? a : b; }

static inline size_t b3_full_chunks(size_t input_len) {
  return input_len / (size_t)BLAKE3_CHUNK_LEN;
}

static b3p_method_t b3p_pick_heuristic(struct b3p_ctx *ctx) {
  if (ctx->pool.nthreads < 2) return B3P_METHOD_A_CHUNKS;

  if (ctx->input_len < ctx->cfg.min_parallel_bytes) return B3P_METHOD_A_CHUNKS;

  size_t chunks = b3_full_chunks(ctx->input_len);
  if (chunks < ctx->cfg.method_a_min_chunks) return B3P_METHOD_A_CHUNKS;

  size_t simd = blake3_simd_degree();
  size_t effective_lane = b3_min_sz(simd, (size_t)MAX_SIMD_DEGREE);

  size_t chunks_per_thread_floor = 128 * effective_lane;
  if (chunks >= ctx->pool.nthreads * chunks_per_thread_floor) return B3P_METHOD_B_SUBTREES;

  return B3P_METHOD_A_CHUNKS;
}


/* ============================================================================
 * Method implementations
 * ===========================================================================*/

typedef struct {
  struct b3p_ctx *ctx;
  atomic_size_t next_chunk;
  size_t end_chunk;
  b3_cv_bytes_t *out_cvs;
} b3p_chunks_job_t;

typedef struct {
  struct b3p_ctx *ctx;
  size_t subtree_chunks;
  atomic_size_t next_subtree;
  size_t num_subtrees;
  b3_cv_bytes_t *out_subtree_cvs;
} b3p_subtrees_job_t;

static void b3p_task_hash_chunks(void *arg) {
  b3p_chunks_job_t *job = arg;
  struct b3p_ctx *ctx = job->ctx;

  size_t simd_degree = blake3_simd_degree();
  if (simd_degree > MAX_SIMD_DEGREE) simd_degree = MAX_SIMD_DEGREE;

  // Process larger batches to reduce atomic contention
  size_t batch_step = simd_degree * 64; 

  for (;;) {
    size_t batch_start = atomic_fetch_add_explicit(&job->next_chunk, batch_step, memory_order_relaxed);
    if (batch_start >= job->end_chunk)
      break;

    size_t batch_limit = batch_start + batch_step;
    if (batch_limit > job->end_chunk) batch_limit = job->end_chunk;

    size_t i = batch_start;
    const uint8_t *input_ptr = ctx->input + i * (size_t)BLAKE3_CHUNK_LEN;

    while (i < batch_limit) {
        size_t count = simd_degree;
        if (i + count > batch_limit)
          count = batch_limit - i;

        size_t full_count = count;
        // Only the very last chunk of the entire input might be partial.
        if (i + count == ctx->num_chunks) {
          size_t off = (ctx->num_chunks - 1) * (size_t)BLAKE3_CHUNK_LEN;
          if (ctx->input_len - off < (size_t)BLAKE3_CHUNK_LEN) {
            full_count--;
          }
        }

        if (full_count > 0) {
          const uint8_t *inputs[MAX_SIMD_DEGREE];
          for (size_t j = 0; j < full_count; j++) {
            inputs[j] = input_ptr + j * (size_t)BLAKE3_CHUNK_LEN;
          }
          uint8_t flags_common = ctx->kf.flags;
          uint8_t flags_end = CHUNK_END;
          if (ctx->num_chunks == 1) {
             flags_end |= ROOT;
          }
          
          blake3_hash_many(inputs, full_count, BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN,
                           ctx->kf.key, (uint64_t)i, true, flags_common, CHUNK_START, flags_end,
                           job->out_cvs[i].bytes);
        }

        if (full_count < count) {
          size_t j = full_count;
          size_t idx = i + j;
          const uint8_t *partial_ptr = input_ptr + j * (size_t)BLAKE3_CHUNK_LEN;
          size_t off = idx * (size_t)BLAKE3_CHUNK_LEN;
          size_t remain = ctx->input_len - off;
          size_t clen = remain < (size_t)BLAKE3_CHUNK_LEN ? remain : (size_t)BLAKE3_CHUNK_LEN;
          b3_hash_chunk_cv_impl(ctx->kf.key, ctx->kf.flags, partial_ptr, clen, (uint64_t)idx, (ctx->num_chunks == 1), job->out_cvs[idx].bytes);
        }
        
        i += count;
        input_ptr += count * (size_t)BLAKE3_CHUNK_LEN;
    }
  }
}

static void b3p_hash_range_to_root(
  struct b3p_ctx *ctx,
  size_t chunk_start,
  size_t chunk_end,
  b3_cv_bytes_t *tmp,
  b3_cv_bytes_t *out_root,
  int is_root
) {
  size_t n = chunk_end - chunk_start;
  // fprintf(stderr, "DEBUG: b3p_hash_range_to_root start=%zu end=%zu n=%zu\n", chunk_start, chunk_end, n);
#if DEBUG_PARALLEL
  fprintf(stderr, "[parallel] hash_range_to_root: chunk_start=%zu chunk_end=%zu n=%zu\n", chunk_start, chunk_end, n);
#endif

  size_t simd_degree = blake3_simd_degree();
  if (simd_degree > MAX_SIMD_DEGREE) simd_degree = MAX_SIMD_DEGREE;

  const uint8_t *input_ptr = ctx->input + chunk_start * (size_t)BLAKE3_CHUNK_LEN;

  size_t i = 0;
  while (i < n) {
      size_t count = simd_degree;
      if (i + count > n) count = n - i;

      size_t full_count = count;
      if (chunk_start + i + count == ctx->num_chunks) {
        size_t off = (ctx->num_chunks - 1) * (size_t)BLAKE3_CHUNK_LEN;
        if (ctx->input_len - off < (size_t)BLAKE3_CHUNK_LEN) {
             full_count--;
        }
      }

      if (full_count > 0) {
          const uint8_t *inputs[MAX_SIMD_DEGREE];
          for (size_t j = 0; j < full_count; j++) {
              inputs[j] = input_ptr + j * (size_t)BLAKE3_CHUNK_LEN;
          }
          uint8_t flags_end = CHUNK_END;
          // If this batch covers the single root chunk (n=1 implies we are processing the only chunk in this range)
          // If is_root is true, and n=1, then this chunk is the root of the tree.
          if (is_root && n == 1 && full_count == 1) {
             flags_end |= ROOT;
          }

          blake3_hash_many(inputs, full_count, BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN,
                           ctx->kf.key, (uint64_t)(chunk_start + i), true, ctx->kf.flags, CHUNK_START, flags_end,
                           tmp[i].bytes);
      }

      if (full_count < count) {
          size_t j = full_count;
          size_t chunk_i = chunk_start + i + j;
          const uint8_t *partial_chunk_ptr = input_ptr + j * (size_t)BLAKE3_CHUNK_LEN;
          
          size_t off = chunk_i * (size_t)BLAKE3_CHUNK_LEN;
          size_t remain = ctx->input_len - off;
          size_t clen = remain < (size_t)BLAKE3_CHUNK_LEN ? remain : (size_t)BLAKE3_CHUNK_LEN;
          
          bool chunk_is_root = (is_root && n == 1);
          b3_hash_chunk_cv_impl(ctx->kf.key, ctx->kf.flags, partial_chunk_ptr, clen, (uint64_t)chunk_i, chunk_is_root, tmp[i + j].bytes);
      }
      i += count;
      input_ptr += count * (size_t)BLAKE3_CHUNK_LEN;
  }

  b3p_reduce_in_place(ctx, tmp, n, out_root, is_root);
}

static void b3p_task_hash_subtrees(void *arg) {
#if DEBUG_PARALLEL
  fprintf(stderr, "[parallel] task_hash_subtrees start\n");
#endif
  b3p_subtrees_job_t *job = arg;
  struct b3p_ctx *ctx = job->ctx;

  size_t max_tmp = job->subtree_chunks;
#if DEBUG_PARALLEL
  fprintf(stderr, "[parallel] max_tmp=%zu\n", max_tmp);
#endif
  b3_cv_bytes_t *tmp = ensure_tls_cv_buffer(max_tmp);
  if (!tmp) return; // Should handle error better? but void return

  for (;;) {
    size_t s = atomic_fetch_add_explicit(&job->next_subtree, 1, memory_order_relaxed);
    if (s >= job->num_subtrees)
      break;
#if DEBUG_PARALLEL
    fprintf(stderr, "[parallel] subtree s=%zu\n", s);
#endif
    size_t chunk_start = s * job->subtree_chunks;
    size_t chunk_end = chunk_start + job->subtree_chunks;
    if (chunk_end > ctx->num_chunks)
      chunk_end = ctx->num_chunks;
#if DEBUG_PARALLEL
    fprintf(stderr, "[parallel] chunk_start=%zu chunk_end=%zu\n", chunk_start, chunk_end);
#endif
    b3_cv_bytes_t root = {0};
    int is_root = (job->num_subtrees == 1);
    b3p_hash_range_to_root(ctx, chunk_start, chunk_end, tmp, &root, is_root);
    job->out_subtree_cvs[s] = root;
  }
}

static void b3p_reduce_in_place(struct b3p_ctx *ctx, b3_cv_bytes_t *cvs, size_t n, b3_cv_bytes_t *out_root, int is_final) {
  while (n > 1) {
    size_t parents = 0;
    size_t i = 0;

    size_t simd_degree = blake3_simd_degree();
    if (simd_degree > MAX_SIMD_DEGREE) simd_degree = MAX_SIMD_DEGREE;

    while (i + 2 * simd_degree <= n) {
        const uint8_t *inputs[MAX_SIMD_DEGREE];

        for (size_t j = 0; j < simd_degree; j++) {
            // The left and right CVs are contiguous in memory.
            // cvs[k] is 32 bytes. cvs[k+1] is the next 32 bytes.
            // So &cvs[i + 2*j] points to the start of the 64-byte parent block.
            inputs[j] = cvs[i + 2 * j].bytes;
        }

        uint8_t flags = ctx->kf.flags | PARENT;
        if (is_final && n == 2) flags |= ROOT;

        blake3_hash_many(inputs, simd_degree, 1, ctx->kf.key, 0, false, flags, 0, 0,
                         cvs[parents].bytes);
        
        i += 2 * simd_degree;
        parents += simd_degree;
    }

    for (; i + 1 < n; i += 2) {
      uint8_t flags = ctx->kf.flags | PARENT;
      if (is_final && n == 2) {
          flags |= ROOT;
      }
      b3_hash_parent_cv_impl(ctx->kf.key, flags, cvs[i].bytes, cvs[i + 1].bytes, cvs[parents].bytes);
      parents++;
    }

    if (i < n) {
      cvs[parents] = cvs[i];
      parents++;
    }

    n = parents;
  }

  *out_root = cvs[0];
}

static int b3p_run_method_a_chunks(struct b3p_ctx *ctx, b3_cv_bytes_t *out_root) {
  if (b3p_ensure_scratch(ctx, ctx->num_chunks) != 0)
    return -1;

  b3p_chunks_job_t job = {
    .ctx = ctx,
    .next_chunk = 0,
    .end_chunk = ctx->num_chunks,
    .out_cvs = ctx->scratch_cvs
  };

  b3p_taskgroup_t g;
  b3p_taskgroup_init(&g);

  size_t tasks = ctx->cfg.nthreads ? ctx->cfg.nthreads : 1;
  for (size_t t = 0; t < tasks; t++)
    b3p_pool_submit(&ctx->pool, &g, b3p_task_hash_chunks, &job);

  b3p_taskgroup_wait(&g);
  b3p_taskgroup_destroy(&g);

  b3p_reduce_in_place(ctx, ctx->scratch_cvs, ctx->num_chunks, out_root, 1);
  return 0;
}

static int b3p_run_method_b_subtrees(struct b3p_ctx *ctx, b3_cv_bytes_t *out_root) {
#if DEBUG_PARALLEL
  fprintf(stderr, "[parallel] method B: input_len=%zu num_chunks=%zu nthreads=%zu\n", ctx->input_len, ctx->num_chunks, ctx->pool.nthreads);
#endif
  size_t subtree_chunks = ctx->cfg.subtree_chunks ? ctx->cfg.subtree_chunks : B3P_DEFAULT_SUBTREE_CHUNKS;
  size_t num_subtrees = (ctx->num_chunks + subtree_chunks - 1) / subtree_chunks;
#if DEBUG_PARALLEL
  fprintf(stderr, "[parallel] subtree_chunks=%zu num_subtrees=%zu\n", subtree_chunks, num_subtrees);
#endif

  if (b3p_ensure_scratch(ctx, num_subtrees) != 0)
    return -1;

  b3p_subtrees_job_t job = {
    .ctx = ctx,
    .subtree_chunks = subtree_chunks,
    .next_subtree = 0,
    .num_subtrees = num_subtrees,
    .out_subtree_cvs = ctx->scratch_cvs
  };

  b3p_taskgroup_t g;
  b3p_taskgroup_init(&g);

  size_t tasks = ctx->cfg.nthreads ? ctx->cfg.nthreads : 1;
  for (size_t t = 0; t < tasks; t++)
    b3p_pool_submit(&ctx->pool, &g, b3p_task_hash_subtrees, &job);

  b3p_taskgroup_wait(&g);
  b3p_taskgroup_destroy(&g);

  b3p_reduce_in_place(ctx, ctx->scratch_cvs, num_subtrees, out_root, 1);
  return 0;
}

static int b3p_run_serial(struct b3p_ctx *ctx, b3_cv_bytes_t *out_root) {
  size_t subtree_chunks = ctx->cfg.subtree_chunks ? ctx->cfg.subtree_chunks : B3P_DEFAULT_SUBTREE_CHUNKS;
  size_t num_subtrees = (ctx->num_chunks + subtree_chunks - 1) / subtree_chunks;

  if (b3p_ensure_scratch(ctx, num_subtrees) != 0)
    return -1;

  size_t max_tmp = subtree_chunks;
  b3_cv_bytes_t *tmp = ensure_tls_cv_buffer(max_tmp);
  if (!tmp) return -1;

  int is_root = (num_subtrees == 1);

  for (size_t s = 0; s < num_subtrees; s++) {
    size_t chunk_start = s * subtree_chunks;
    size_t chunk_end = chunk_start + subtree_chunks;
    if (chunk_end > ctx->num_chunks)
      chunk_end = ctx->num_chunks;

    b3_cv_bytes_t root = {0};
    b3p_hash_range_to_root(ctx, chunk_start, chunk_end, tmp, &root, is_root);
    ctx->scratch_cvs[s] = root;
  }
  
  // free(tmp) removed because tmp is TLS

  b3p_reduce_in_place(ctx, ctx->scratch_cvs, num_subtrees, out_root, 1);
  return 0;
}

/* ============================================================================
 * Root computation
 * ===========================================================================*/

static int b3p_compute_root(
  struct b3p_ctx *ctx,
  b3p_method_t method,
  b3_cv_bytes_t *out_root,
  uint64_t *out_ns
) {
  if (ctx->pool.nthreads == 0) {
      *out_ns = 0;
      return b3p_run_serial(ctx, out_root);
  }

  int rc = 0;
  if (method == B3P_METHOD_A_CHUNKS)
    rc = b3p_run_method_a_chunks(ctx, out_root);
  else if (method == B3P_METHOD_B_SUBTREES)
    rc = b3p_run_method_b_subtrees(ctx, out_root);
  else
    rc = -1;

  *out_ns = 0;
  return rc;
}

int b3p_hash_buffer_serial(
  const uint8_t *input,
  size_t input_len,
  const uint8_t key[BLAKE3_KEY_LEN],
  uint8_t flags,
  uint8_t *out,
  size_t out_len
) {
  if (!input || !out) return -1;
  if (out_len == 0) return 0;

  struct b3p_ctx ctx = {0};
  ctx.input = input;
  ctx.input_len = input_len;
  ctx.num_chunks = (input_len + (size_t)BLAKE3_CHUNK_LEN - 1) / (size_t)BLAKE3_CHUNK_LEN;
  if (ctx.num_chunks == 0) ctx.num_chunks = 1;

  for (size_t i = 0; i < 8; i++) {
    uint32_t w = 0;
    w |= (uint32_t)key[i * 4 + 0] << 0;
    w |= (uint32_t)key[i * 4 + 1] << 8;
    w |= (uint32_t)key[i * 4 + 2] << 16;
    w |= (uint32_t)key[i * 4 + 3] << 24;
    ctx.kf.key[i] = w;
  }
  ctx.kf.flags = flags;

  // For small inputs, allocate on stack to avoid malloc overhead
  // 1MB input -> 1024 chunks -> 32KB CVs. Safe.
  // 4MB input -> 4096 chunks -> 128KB CVs. Safe.
  // Above that, use malloc.
  size_t needed_cvs = ctx.num_chunks;
  
  b3_cv_bytes_t *tmp = ensure_tls_cv_buffer(needed_cvs);
  if (!tmp) return -1;

  b3_cv_bytes_t root = {0};
  // We process the entire buffer as one range. Since this function is for serial execution
  // of contiguous buffers, we treat the whole input as one "subtree" (or rather the whole tree).
  // b3p_hash_range_to_root will handle reduction and ROOT flag (since is_root=1).
  b3p_hash_range_to_root(&ctx, 0, ctx.num_chunks, tmp, &root, 1);

  // if (heap_tmp) free(heap_tmp); removed

  b3_output_root_impl(ctx.kf.key, ctx.kf.flags, root.bytes, 0, out, out_len);
  return 0;
}