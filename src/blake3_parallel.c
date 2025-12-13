#define _GNU_SOURCE
#include "blake3_parallel.h"
#include "blake3_internal.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <alloca.h>
#include <stdio.h>

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
 * Adaptive selection state (EWMA buckets)
 * ===========================================================================*/

typedef struct {
  atomic_uint have_a;
  atomic_uint have_b;
  atomic_uint_fast64_t ewma_a_q32;
  atomic_uint_fast64_t ewma_b_q32;
} b3p_tune_bucket_t;

#define B3P_TUNE_BUCKETS 32

typedef struct {
  int enable;
  uint32_t sample_mask;
  atomic_uint_fast32_t rng;
  b3p_tune_bucket_t buckets[B3P_TUNE_BUCKETS];
} b3p_tuner_t;

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
  b3p_tuner_t tuner;

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

static uint32_t b3p_bucket_for_chunks(size_t num_chunks);
static uint64_t b3p_q32_from_ratio(double x);
static uint64_t b3p_ewma_update_q32(uint64_t old_q32, uint64_t sample_q32);
static uint32_t b3p_rng_next(atomic_uint_fast32_t *s);
static int b3p_should_sample(struct b3p_ctx *ctx);
static uint64_t b3p_now_ns(void);
static void b3p_tuner_update(struct b3p_ctx *ctx, b3p_method_t m, uint64_t ns, size_t bytes);

static int b3p_ensure_scratch(struct b3p_ctx *ctx, size_t want_cvs);

static b3p_method_t b3p_pick_heuristic(struct b3p_ctx *ctx);
static b3p_method_t b3p_pick_with_tuner(struct b3p_ctx *ctx, b3p_method_t fallback);

static int b3p_run_method_a(struct b3p_ctx *ctx, b3_cv_bytes_t *out_root);
static int b3p_run_method_b(struct b3p_ctx *ctx, b3_cv_bytes_t *out_root);
static void b3p_reduce_in_place(struct b3p_ctx *ctx, b3_cv_bytes_t *cvs, size_t n, b3_cv_bytes_t *out_root);

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
  // Initialize tuner
  ctx->tuner.enable = cfg->autotune_enable;
  ctx->tuner.sample_mask = cfg->autotune_sample_mask;
  ctx->tuner.rng = (uint32_t)b3p_now_ns();
  // buckets are zero-initialized by calloc

  // Initialize worker pool
  size_t nthreads = cfg->nthreads;
  size_t qcap = 256; // default queue capacity
  if (b3p_pool_init(&ctx->pool, nthreads, qcap) != 0) {
    free(ctx);
    return NULL;
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

  b3p_method_t chosen = method;
  if (method == B3P_METHOD_AUTO) {
    b3p_method_t h = b3p_pick_heuristic(ctx);
    chosen = b3p_pick_with_tuner(ctx, h);
  }

  b3_cv_bytes_t root = {0};
  uint64_t ns = 0;
  int rc = b3p_compute_root(ctx, chosen, &root, &ns);
  if (rc != 0)
    return rc;

  if (ns)
    b3p_tuner_update(ctx, chosen, ns, input_len);

  b3_output_root(&ctx->kf, &root, seek, out, out_len);
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

  return NULL;
}

/* ============================================================================
 * Tuner implementation
 * ===========================================================================*/

static uint32_t b3p_bucket_for_chunks(size_t num_chunks) {
  uint32_t b = 0;
  size_t v = num_chunks;
  while (v > 1 && b + 1 < B3P_TUNE_BUCKETS) {
    v >>= 1;
    b++;
  }
  return b;
}

static uint64_t b3p_q32_from_ratio(double x) {
  return (uint64_t)(x * (double)(1ULL << 32));
}

static uint64_t b3p_ewma_update_q32(uint64_t old_q32, uint64_t sample_q32) {
  uint64_t alpha_num = 1;
  uint64_t alpha_den = 8;
  uint64_t keep = (alpha_den - alpha_num);
  return (old_q32 * keep + sample_q32 * alpha_num) / alpha_den;
}

static uint32_t b3p_rng_next(atomic_uint_fast32_t *s) {
  uint32_t x = atomic_load_explicit(s, memory_order_relaxed);
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  atomic_store_explicit(s, x, memory_order_relaxed);
  return x;
}

static int b3p_should_sample(struct b3p_ctx *ctx) {
  if (!ctx->tuner.enable)
    return 0;
  uint32_t r = b3p_rng_next(&ctx->tuner.rng);
  return (r & ctx->tuner.sample_mask) == 0;
}

static uint64_t b3p_now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void b3p_tuner_update(struct b3p_ctx *ctx, b3p_method_t m, uint64_t ns, size_t bytes) {
  if (!ctx->tuner.enable || bytes == 0)
    return;

  uint32_t bi = b3p_bucket_for_chunks(ctx->num_chunks);
  b3p_tune_bucket_t *bk = &ctx->tuner.buckets[bi];

  double ns_per_byte = (double)ns / (double)bytes;
  uint64_t sample = b3p_q32_from_ratio(ns_per_byte);

  if (m == B3P_METHOD_A_CHUNKS) {
    uint64_t old = atomic_load_explicit(&bk->ewma_a_q32, memory_order_relaxed);
    uint64_t neu = old ? b3p_ewma_update_q32(old, sample) : sample;
    atomic_store_explicit(&bk->ewma_a_q32, neu, memory_order_relaxed);
    atomic_store_explicit(&bk->have_a, 1, memory_order_relaxed);
  } else if (m == B3P_METHOD_B_SUBTREES) {
    uint64_t old = atomic_load_explicit(&bk->ewma_b_q32, memory_order_relaxed);
    uint64_t neu = old ? b3p_ewma_update_q32(old, sample) : sample;
    atomic_store_explicit(&bk->ewma_b_q32, neu, memory_order_relaxed);
    atomic_store_explicit(&bk->have_b, 1, memory_order_relaxed);
  }
}

/* ============================================================================
 * Scratch management
 * ===========================================================================*/

static int b3p_ensure_scratch(struct b3p_ctx *ctx, size_t want_cvs) {
  fprintf(stderr, "ensure_scratch: want=%zu cap=%zu\n", want_cvs, ctx->scratch_cvs_cap);
  if (want_cvs <= ctx->scratch_cvs_cap)
    return 0;

  size_t new_cap = ctx->scratch_cvs_cap ? ctx->scratch_cvs_cap : 1024;
  while (new_cap < want_cvs)
    new_cap *= 2;
  fprintf(stderr, "  new_cap=%zu alloc=%zu\n", new_cap, new_cap * sizeof(b3_cv_bytes_t));

  void *p = realloc(ctx->scratch_cvs, new_cap * sizeof(b3_cv_bytes_t));
  if (!p)
    return -1;

  ctx->scratch_cvs = p;
  ctx->scratch_cvs_cap = new_cap;
  fprintf(stderr, "  allocated\n");
  return 0;
}

/* ============================================================================
 * Selection logic
 * ===========================================================================*/

static b3p_method_t b3p_pick_heuristic(struct b3p_ctx *ctx) {
  size_t eff_threads = ctx->cfg.nthreads ? ctx->cfg.nthreads : 1;
  if (eff_threads <= 1)
    return B3P_METHOD_A_CHUNKS;

  if (ctx->input_len < ctx->cfg.min_parallel_bytes)
    return B3P_METHOD_A_CHUNKS;

  if (ctx->num_chunks < ctx->cfg.method_a_min_chunks)
    return B3P_METHOD_A_CHUNKS;

  size_t need = ctx->cfg.method_b_min_chunks_per_thread * eff_threads;
  if (ctx->num_chunks >= need)
    return B3P_METHOD_B_SUBTREES;

  return B3P_METHOD_A_CHUNKS;
}

static b3p_method_t b3p_pick_with_tuner(struct b3p_ctx *ctx, b3p_method_t fallback) {
  if (!ctx->tuner.enable)
    return fallback;

  uint32_t b = b3p_bucket_for_chunks(ctx->num_chunks);
  b3p_tune_bucket_t *bk = &ctx->tuner.buckets[b];

  unsigned ha = atomic_load_explicit(&bk->have_a, memory_order_relaxed);
  unsigned hb = atomic_load_explicit(&bk->have_b, memory_order_relaxed);

  if (!ha || !hb)
    return fallback;

  uint64_t a = atomic_load_explicit(&bk->ewma_a_q32, memory_order_relaxed);
  uint64_t bq = atomic_load_explicit(&bk->ewma_b_q32, memory_order_relaxed);

  return (bq < a) ? B3P_METHOD_B_SUBTREES : B3P_METHOD_A_CHUNKS;
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

  for (;;) {
    size_t i = atomic_fetch_add_explicit(&job->next_chunk, 1, memory_order_relaxed);
    if (i >= job->end_chunk)
      break;

    size_t off = i * (size_t)BLAKE3_CHUNK_LEN;
    size_t remain = ctx->input_len - off;
    size_t clen = remain < (size_t)BLAKE3_CHUNK_LEN ? remain : (size_t)BLAKE3_CHUNK_LEN;

    b3_hash_chunk_cv(&ctx->kf, ctx->input + off, clen, (uint64_t)i, &job->out_cvs[i]);
  }
}

static void b3p_hash_range_to_root(
  struct b3p_ctx *ctx,
  size_t chunk_start,
  size_t chunk_end,
  b3_cv_bytes_t *tmp,
  b3_cv_bytes_t *out_root
) {
  size_t n = chunk_end - chunk_start;

  for (size_t i = 0; i < n; i++) {
    size_t chunk_i = chunk_start + i;
    size_t off = chunk_i * (size_t)BLAKE3_CHUNK_LEN;
    size_t remain = ctx->input_len - off;
    size_t clen = remain < (size_t)BLAKE3_CHUNK_LEN ? remain : (size_t)BLAKE3_CHUNK_LEN;

    b3_hash_chunk_cv(&ctx->kf, ctx->input + off, clen, (uint64_t)chunk_i, &tmp[i]);
  }

  b3p_reduce_in_place(ctx, tmp, n, out_root);
}

static void b3p_task_hash_subtrees(void *arg) {
  b3p_subtrees_job_t *job = arg;
  struct b3p_ctx *ctx = job->ctx;

  size_t max_tmp = job->subtree_chunks;
  b3_cv_bytes_t *tmp = (b3_cv_bytes_t*)alloca(max_tmp * sizeof(b3_cv_bytes_t));

  for (;;) {
    size_t s = atomic_fetch_add_explicit(&job->next_subtree, 1, memory_order_relaxed);
    if (s >= job->num_subtrees)
      break;

    size_t chunk_start = s * job->subtree_chunks;
    size_t chunk_end = chunk_start + job->subtree_chunks;
    if (chunk_end > ctx->num_chunks)
      chunk_end = ctx->num_chunks;

    b3_cv_bytes_t root = {0};
    b3p_hash_range_to_root(ctx, chunk_start, chunk_end, tmp, &root);
    job->out_subtree_cvs[s] = root;
  }
}

static void b3p_reduce_in_place(struct b3p_ctx *ctx, b3_cv_bytes_t *cvs, size_t n, b3_cv_bytes_t *out_root) {
  while (n > 1) {
    size_t parents = 0;
    size_t i = 0;

    for (; i + 1 < n; i += 2) {
      b3_hash_parent_cv(&ctx->kf, &cvs[i], &cvs[i + 1], &cvs[parents]);
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

static int b3p_run_method_a(struct b3p_ctx *ctx, b3_cv_bytes_t *out_root) {
  fprintf(stderr, "run_method_a: num_chunks=%zu\n", ctx->num_chunks);
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

  b3p_reduce_in_place(ctx, ctx->scratch_cvs, ctx->num_chunks, out_root);
  return 0;
}

static int b3p_run_method_b(struct b3p_ctx *ctx, b3_cv_bytes_t *out_root) {
  size_t subtree_chunks = ctx->cfg.subtree_chunks ? ctx->cfg.subtree_chunks : B3P_DEFAULT_SUBTREE_CHUNKS;
  size_t num_subtrees = (ctx->num_chunks + subtree_chunks - 1) / subtree_chunks;

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

  b3p_reduce_in_place(ctx, ctx->scratch_cvs, num_subtrees, out_root);
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
  int sample = b3p_should_sample(ctx);
  uint64_t t0 = sample ? b3p_now_ns() : 0;

  int rc = 0;
  if (method == B3P_METHOD_A_CHUNKS)
    rc = b3p_run_method_a(ctx, out_root);
  else if (method == B3P_METHOD_B_SUBTREES)
    rc = b3p_run_method_b(ctx, out_root);
  else
    rc = -1;

  if (sample) {
    uint64_t t1 = b3p_now_ns();
    *out_ns = (rc == 0) ? (t1 - t0) : 0;
  } else {
    *out_ns = 0;
  }

  return rc;
}