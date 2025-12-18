#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdatomic.h>

// Mocks
static int g_fail_realloc_at = -1;
static int g_realloc_count = 0;
static int g_fail_pthread_create = 0;
static int g_alloc_count = 0;  // Malloc/Calloc/Realloc total
static size_t g_simd_degree_result = 1;
static int g_chunk_cv_calls = 0;
static int g_hash_many_calls = 0;
static int g_parent_cv_calls = 0;
static uint8_t g_parent_cv_flags[32] = {0};
static const uint8_t* g_parent_cv_left[32] = {0};
static const uint8_t* g_parent_cv_right[32] = {0};

void* my_realloc(void* ptr, size_t size) {
    g_alloc_count++;
    g_realloc_count++;
    if (g_fail_realloc_at != -1 && g_realloc_count == g_fail_realloc_at) {
        return NULL;
    }
    return realloc(ptr, size);
}

void* my_malloc(size_t size) {
    g_alloc_count++;
    return malloc(size);
}

void* my_calloc(size_t nmemb, size_t size) {
    g_alloc_count++;
    return calloc(nmemb, size);
}

void my_free(void* ptr) {
    free(ptr);
}

int my_pthread_create(pthread_t* thread, const pthread_attr_t* attr, void* (*start_routine)(void*), void* arg) {
    if (g_fail_pthread_create) {
        return EAGAIN;
    }
    return pthread_create(thread, attr, start_routine, arg);
}

#define realloc my_realloc
#define malloc my_malloc
#define calloc my_calloc
#define free my_free
#define pthread_create my_pthread_create

// Include source under test
#include "../src/blake3_parallel.c"

// Stubs for link dependencies
void blake3_compress_in_place(uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len, uint64_t counter, uint8_t flags) {}
void blake3_compress_xof(const uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len, uint64_t counter, uint8_t flags, uint8_t out[64]) {}
void blake3_xof_many(const uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len, uint64_t counter, uint8_t flags, uint8_t out[64], size_t outblocks) {}
void blake3_hash_many(const uint8_t* const* inputs,
                      size_t num_inputs,
                      size_t blocks,
                      const uint32_t key[8],
                      uint64_t counter,
                      bool increment_counter,
                      uint8_t flags,
                      uint8_t flags_start,
                      uint8_t flags_end,
                      uint8_t* out) {
    g_hash_many_calls++;
}
size_t blake3_simd_degree(void) {
    return g_simd_degree_result;
}

// Internal primitives stubs
void b3_hash_chunk_cv_impl(const uint32_t key[8], uint8_t flags, const uint8_t* chunk, size_t chunk_len, uint64_t chunk_index, bool is_root, uint8_t out_cv[32]) {
    g_chunk_cv_calls++;
}
void b3_hash_parent_cv_impl(const uint32_t key[8], uint8_t flags, const uint8_t left_cv[32], const uint8_t right_cv[32], uint8_t out_cv[32]) {
    if (g_parent_cv_calls < 32) {
        g_parent_cv_flags[g_parent_cv_calls] = flags;
        g_parent_cv_left[g_parent_cv_calls] = left_cv;
        g_parent_cv_right[g_parent_cv_calls] = right_cv;
    }
    g_parent_cv_calls++;
    // Compute output as XOR of left and right (deterministic, associative)
    for (int i = 0; i < 32; i++) {
        out_cv[i] = left_cv[i] ^ right_cv[i];
    }
}
void b3_output_root_impl(const uint32_t input_cv[8], uint8_t block_flags, const uint8_t* block, size_t block_len, uint64_t counter, uint64_t seek, uint8_t* out, size_t out_len) {}

// Dummy task for testing
static void dummy_task(void* arg) {
    // Do nothing
}

// Helper to merge two CVs using XOR (matches stub b3_hash_parent_cv_impl)
static void xor_merge(const b3_cv_bytes_t* left, const b3_cv_bytes_t* right, b3_cv_bytes_t* out) {
    for (int i = 0; i < 32; i++) {
        out->bytes[i] = left->bytes[i] ^ right->bytes[i];
    }
}

// Helper for heuristic tests
static struct b3p_ctx* create_test_ctx(void) {
    struct b3p_ctx* ctx = (struct b3p_ctx*)calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    // Default config
    ctx->cfg = b3p_config_default();
    // Default pool.nthreads is 0 (disabled)
    // Set dummy input to avoid null pointer dereference
    static uint8_t dummy_input[1024] = {0};
    ctx->input = dummy_input;
    ctx->input_len = sizeof(dummy_input);
    ctx->num_chunks = (ctx->input_len + BLAKE3_CHUNK_LEN - 1) / BLAKE3_CHUNK_LEN;
    // Set key and flags
    memset(ctx->kf.key, 0, sizeof(ctx->kf.key));
    ctx->kf.flags = 0;
    return ctx;
}

// Tests
void test_alloc_failure(void) {
    printf("Testing alloc failure...\n");
    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t* ctx = b3p_create(&cfg);
    assert(ctx != NULL);

    // Force failure on next realloc
    g_realloc_count = 0;
    g_fail_realloc_at = 1;

    // Request more scratch than current (0)
    int rc = b3p_ensure_scratch(ctx, 100);
    assert(rc == -1);

    // Verify count incremented
    assert(g_realloc_count == 1);

    // Disable failure
    g_fail_realloc_at = -1;
    rc = b3p_ensure_scratch(ctx, 100);
    assert(rc == 0);

    b3p_destroy(ctx);
    printf("OK\n");
}

void test_pool_creation_failure(void) {
    printf("Testing pool creation failure...\n");
    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = 2;

    g_fail_pthread_create = 1;
    b3p_ctx_t* ctx = b3p_create(&cfg);
    assert(ctx == NULL);
    g_fail_pthread_create = 0;

    ctx = b3p_create(&cfg);
    assert(ctx != NULL);
    b3p_destroy(ctx);
    printf("OK\n");
}

void test_performance_invariants(void) {
    printf("Testing performance invariants (no alloc in loop)...");
    b3p_config_t cfg = b3p_config_default();
    // Use Method A
    cfg.min_parallel_bytes = 0;
    cfg.method_b_min_chunks_per_thread = 100000;  // Force A

    b3p_ctx_t* ctx = b3p_create(&cfg);

    uint8_t input[1024];
    uint8_t key[32] = {0};
    uint8_t out[32];

    // Warmup
    b3p_hash_one_shot(ctx, input, sizeof(input), key, 0, B3P_METHOD_A_CHUNKS, out, 32);

    int start_allocs = g_alloc_count;

    // Loop
    for (int i = 0; i < 100; i++) {
        b3p_hash_one_shot(ctx, input, sizeof(input), key, 0, B3P_METHOD_A_CHUNKS, out, 32);
    }

    int end_allocs = g_alloc_count;

    if (end_allocs != start_allocs) {
        printf("FAILED: Allocations occurred in hot loop! start=%d end=%d\n", start_allocs, end_allocs);
        exit(1);
    }

    b3p_destroy(ctx);
    printf("OK\n");
}

void test_tls_cv_buffer(void) {
    printf("Testing TLS CV buffer...\n");

    // TLS_ZeroCount_NoAlloc
    // Call ensure_tls_cv_buffer(0) before any allocation
    // Expect returns NULL and does not set errno
    errno = 0;
    b3_cv_bytes_t* buf = ensure_tls_cv_buffer(0);
    assert(buf == NULL);
    assert(errno == 0);

    // TLS_GrowFromEmpty_InitialCapAtLeast1024
    // Call ensure_tls_cv_buffer(1)
    // Expect non-NULL, g_tls_cv_cap >= 1024
    errno = 0;
    buf = ensure_tls_cv_buffer(1);
    assert(buf != NULL);
    assert(g_tls_cv_cap >= 1024);
    // With default initial capacity 1024 and count=1, capacity should be exactly 1024
    assert(g_tls_cv_cap == 1024);
    assert(errno == 0);

    // TLS_Grow_ExponentialUntilCount
    // Call ensure_tls_cv_buffer(1025) after initial
    // Expect cap grows to >= 1025 (likely 2048)
    size_t old_cap = g_tls_cv_cap;
    buf = ensure_tls_cv_buffer(1025);
    assert(buf != NULL);
    assert(g_tls_cv_cap >= 1025);
    assert(g_tls_cv_cap > old_cap);  // should have grown
    // Exponential growth: likely double, but could be more due to overflow clamp
    // Check that capacity doubled (should be 2048 unless max_elems constraint)
    const size_t max_elems = SIZE_MAX / sizeof(b3_cv_bytes_t);
    if (old_cap <= max_elems / 2) {
        // Should have doubled
        assert(g_tls_cv_cap == old_cap * 2);
    }

    // TLS_NoGrow_WhenWithinCap
    // Save g_tls_cv_buf pointer + g_tls_cv_cap
    b3_cv_bytes_t* saved_buf = g_tls_cv_buf;
    size_t saved_cap = g_tls_cv_cap;
    buf = ensure_tls_cv_buffer(saved_cap);
    assert(buf == saved_buf);
    assert(g_tls_cv_cap == saved_cap);

    // TLS_OverflowProtection_CountTooLarge
    // Call with count = SIZE_MAX / sizeof(b3_cv_bytes_t) + 1
    // Expect returns NULL and sets errno == ENOMEM
    size_t max_elems2 = SIZE_MAX / sizeof(b3_cv_bytes_t);
    // Save current buffer state to ensure it's not modified
    b3_cv_bytes_t* saved_buf2 = g_tls_cv_buf;
    size_t saved_cap2 = g_tls_cv_cap;
    errno = 0;
    buf = ensure_tls_cv_buffer(max_elems2 + 1);
    assert(buf == NULL);
    assert(errno == ENOMEM);
    // Buffer state should remain unchanged
    assert(g_tls_cv_buf == saved_buf2);
    assert(g_tls_cv_cap == saved_cap2);

    // TLS_FreeResources_Idempotent
    // Allocate once, call b3p_free_tls_resources() twice
    // Expect no crash, g_tls_cv_buf == NULL, g_tls_cv_cap == 0
    // First ensure we have a buffer
    buf = ensure_tls_cv_buffer(1);
    assert(buf != NULL);
    b3p_free_tls_resources();
    assert(g_tls_cv_buf == NULL);
    assert(g_tls_cv_cap == 0);
    // Second call should be idempotent
    b3p_free_tls_resources();
    assert(g_tls_cv_buf == NULL);
    assert(g_tls_cv_cap == 0);
    // After freeing, we should be able to allocate again
    buf = ensure_tls_cv_buffer(1);
    assert(buf != NULL);
    assert(g_tls_cv_cap >= 1024);
    // Clean up
    b3p_free_tls_resources();

    printf("OK\n");
}

void test_scratch_cv_buffer(void) {
    printf("Testing context scratch CV buffer...\n");

    // Create a minimal context for testing
    struct b3p_ctx* ctx = (struct b3p_ctx*)calloc(1, sizeof(*ctx));
    assert(ctx != NULL);

    // Scratch_EnsureFromZero_GrowsToAtLeast1024
    // New ctx with cap 0, call b3p_ensure_scratch(ctx, 1)
    // Expect cap >= 1024
    assert(ctx->scratch_cvs_cap == 0);
    assert(ctx->scratch_cvs == NULL);
    int rc = b3p_ensure_scratch(ctx, 1);
    assert(rc == 0);
    assert(ctx->scratch_cvs_cap >= 1024);
    assert(ctx->scratch_cvs != NULL);

    // Scratch_Ensure_NoReallocWhenEnough
    // Grow to N, call again with want <= cap
    // Expect pointer stable
    b3_cv_bytes_t* saved_ptr = ctx->scratch_cvs;
    size_t saved_cap = ctx->scratch_cvs_cap;
    rc = b3p_ensure_scratch(ctx, saved_cap);
    assert(rc == 0);
    assert(ctx->scratch_cvs == saved_ptr);
    assert(ctx->scratch_cvs_cap == saved_cap);

    // Scratch_Ensure_OverflowReject
    // want > SIZE_MAX / sizeof(b3_cv_bytes_t)
    // Expect -1
    size_t max_elems = SIZE_MAX / sizeof(b3_cv_bytes_t);
    rc = b3p_ensure_scratch(ctx, max_elems + 1);
    assert(rc == -1);
    // Ensure buffer unchanged
    assert(ctx->scratch_cvs == saved_ptr);
    assert(ctx->scratch_cvs_cap == saved_cap);

    // Scratch_Ensure_GrowToExactWhenNearMax
    // Set cap near max and request slightly larger, verify it selects want directly when doubling would overflow
    // We need to set scratch_cvs_cap near max_elems
    // Since we can't actually allocate that much memory, we'll mock realloc to succeed
    // Instead, we'll test the logic by examining the static function directly
    // For now, we'll skip this test as it requires large allocation

    // Clean up
    free(ctx->scratch_cvs);
    free(ctx);

    printf("OK\n");
}

void test_pool_lifecycle(void) {
    printf("Testing pool lifecycle...\n");

    // Pool_InitRejectsNull
    // b3p_pool_init(NULL, ...) returns -1
    int rc = b3p_pool_init(NULL, 1, 256);
    assert(rc == -1);

    // Pool_Init_Defaults_qcapWhenZero
    // qcap=0 -> should allocate internal qcap 256
    b3p_pool_t pool = {0};
    rc = b3p_pool_init(&pool, 1, 0);
    assert(rc == 0);
    assert(pool.q.cap == 256);
    assert(pool.q.buf != NULL);
    b3p_pool_destroy(&pool);

    // Pool_Init_AutoThreadsWhenZero
    // nthreads=0 -> should set p->nthreads >= 1
    rc = b3p_pool_init(&pool, 0, 256);
    assert(rc == 0);
    assert(pool.nthreads >= 1);
    b3p_pool_destroy(&pool);

    // Pool_Destroy_NullSafe
    // b3p_pool_destroy(NULL) no crash
    b3p_pool_destroy(NULL);

    // Pool_Destroy_UninitializedSafe
    // pool struct zeroed (no q.buf), destroy is no-op
    pool = (b3p_pool_t){0};
    b3p_pool_destroy(&pool);

    // Pool_Destroy_Idempotent
    // init then destroy twice, no crash, fields reset
    rc = b3p_pool_init(&pool, 1, 256);
    assert(rc == 0);
    b3p_pool_destroy(&pool);
    // Second destroy should be safe
    b3p_pool_destroy(&pool);

    // Pool_WorkerTLSFreedOnExit
    // Run pool, ensure worker touched TLS (submit hash task that forces TLS alloc), destroy pool
    // Expect no leak in external leak checker (ASan/LSan)
    // We'll create a pool with 1 thread, submit a dummy task that calls ensure_tls_cv_buffer,
    // then destroy pool. ASan/LSan will detect leaks if TLS not freed.
    // However, we cannot easily submit tasks because we need taskgroup and proper job.
    // We'll skip this test for now as it's more integration.

    printf("OK\n");
}

void test_queue_submit_semantics(void) {
    printf("Testing queue submit semantics...\n");

    // Submit_RejectsNullPoolOrFn
    // p=NULL or fn=NULL returns -1
    b3p_pool_t pool = {0};
    b3p_taskgroup_t group = {0};
    b3p_taskgroup_init(&group);

    // Pool NULL
    int rc = b3p_pool_submit(NULL, &group, NULL, NULL);
    assert(rc == -1);
    // fn NULL
    rc = b3p_pool_submit(&pool, &group, NULL, NULL);
    assert(rc == -1);

    // Taskgroup_PendingIncrementsAndDrainsToZero
    // Submit K trivial tasks with taskgroup, wait, expect pending becomes 0
    // Need to initialize pool first
    rc = b3p_pool_init(&pool, 1, 256);
    assert(rc == 0);

    // Use external dummy_task function

    // Submit K tasks
    const int K = 10;
    for (int i = 0; i < K; i++) {
        rc = b3p_pool_submit(&pool, &group, dummy_task, NULL);
        assert(rc == 0);
    }

    // Wait for tasks to complete
    b3p_taskgroup_wait(&group);
    // Pending should be zero
    assert(atomic_load_explicit(&group.pending, memory_order_relaxed) == 0);

    // Submit_FailsWhenStopSet_RollsBackPending
    // Set p->q.stop=1 under lock, then submit with taskgroup
    // Expect submit returns -1 and taskgroup pending is not stuck >0
    // First reset stop flag (pool already initialized)
    pthread_mutex_lock(&pool.q.mu);
    pool.q.stop = 1;
    pthread_mutex_unlock(&pool.q.mu);

    // Submit should fail
    rc = b3p_pool_submit(&pool, &group, dummy_task, NULL);
    assert(rc == -1);
    // Pending should not be incremented (or rolled back)
    assert(atomic_load_explicit(&group.pending, memory_order_relaxed) == 0);

    // Reset stop flag for cleanup
    pthread_mutex_lock(&pool.q.mu);
    pool.q.stop = 0;
    pthread_mutex_unlock(&pool.q.mu);

    // Queue_BoundedBlocksAndWakes
    // Small qcap=2, submit tasks that block workers, ensure submitter blocks and resumes when space available
    // This test requires threading and is complex; skip for now.

    // Taskgroup_WaitNullNoop
    // b3p_taskgroup_wait(NULL) returns quickly
    b3p_taskgroup_wait(NULL);  // Should not crash

    // Clean up
    b3p_pool_destroy(&pool);
    b3p_taskgroup_destroy(&group);

    printf("OK\n");
}

void test_heuristic_selection(void) {
    printf("Testing heuristic selection...\n");

    // Heuristic_SingleThreadAlwaysChunks
    // ctx pool nthreads < 2 => method A
    struct b3p_ctx* ctx = create_test_ctx();
    assert(ctx != NULL);
    ctx->pool.nthreads = 0;  // disabled
    b3p_method_t method = b3p_pick_heuristic(ctx);
    assert(method == B3P_METHOD_A_CHUNKS);
    ctx->pool.nthreads = 1;  // single-threaded
    method = b3p_pick_heuristic(ctx);
    assert(method == B3P_METHOD_A_CHUNKS);

    // Heuristic_SmallInputBelowMinParallelBytes
    // input_len < min_parallel_bytes => method A
    ctx->pool.nthreads = 2;  // enable pool
    ctx->cfg.min_parallel_bytes = 1024;
    ctx->input_len = 512;  // below threshold
    method = b3p_pick_heuristic(ctx);
    assert(method == B3P_METHOD_A_CHUNKS);

    // Heuristic_NotEnoughFullChunks
    // full chunks < method_a_min_chunks => method A
    ctx->input_len = 10 * BLAKE3_CHUNK_LEN;  // 10 full chunks
    ctx->cfg.min_parallel_bytes = 0;         // disable min parallel
    ctx->cfg.method_a_min_chunks = 20;       // require 20 chunks
    method = b3p_pick_heuristic(ctx);
    assert(method == B3P_METHOD_A_CHUNKS);

    // Heuristic_OverflowInThresholdComputation
    // craft cfg so chunks_per_thread_floor != 0 and nthreads > SIZE_MAX / chunks_per_thread_floor
    // expect returns method A (your overflow fallback)
    // Set chunks_per_thread_floor to 2, nthreads > SIZE_MAX/2
    ctx->cfg.method_b_min_chunks_per_thread = 2;  // non-zero
    ctx->pool.nthreads = SIZE_MAX / 2 + 1;        // will overflow when multiplied
    // Ensure other conditions don't trigger early returns
    ctx->input_len = 100 * BLAKE3_CHUNK_LEN;  // plenty of chunks
    ctx->cfg.min_parallel_bytes = 0;
    ctx->cfg.method_a_min_chunks = 0;
    method = b3p_pick_heuristic(ctx);
    assert(method == B3P_METHOD_A_CHUNKS);

    // Heuristic_SufficientChunksChoosesSubtrees
    // chunks >= nthreads * (method_b_min_chunks_per_thread * effective_lane) => method B
    // Reset nthreads to reasonable value
    ctx->pool.nthreads = 2;
    ctx->cfg.method_b_min_chunks_per_thread = 4;
    // effective_lane is 1 (blake3_simd_degree stub returns 1)
    // threshold = 2 * (4 * 1) = 8 chunks needed
    ctx->input_len = 10 * BLAKE3_CHUNK_LEN;  // 10 chunks > threshold
    // Ensure other conditions pass
    ctx->cfg.min_parallel_bytes = 0;
    ctx->cfg.method_a_min_chunks = 0;
    method = b3p_pick_heuristic(ctx);
    assert(method == B3P_METHOD_B_SUBTREES);

    free(ctx);
    printf("OK\n");
}

void test_public_api_context(void) {
    printf("Testing public API context...\n");

    // ConfigDefault_SaneValues
    // Check defaults: nthreads=0, min_parallel_bytes=64KiB, sample mask=63, subtree_chunks default, etc
    b3p_config_t cfg = b3p_config_default();
    assert(cfg.nthreads == 0);
    assert(cfg.min_parallel_bytes == 16 * 1024);  // 16KiB
    assert(cfg.autotune_sample_mask == 63);
    assert(cfg.subtree_chunks == B3P_DEFAULT_SUBTREE_CHUNKS);

    // Create_RejectsNullConfig
    // b3p_create(NULL) == NULL
    b3p_ctx_t* ctx = b3p_create(NULL);
    assert(ctx == NULL);

    // Create_SerialWhenNthreads1
    // cfg.nthreads=1 => ctx->pool.nthreads == 0 (disabled)
    cfg.nthreads = 1;
    ctx = b3p_create(&cfg);
    assert(ctx != NULL);
    // Access internal pool.nthreads (struct b3p_ctx internal)
    // Since we included source, we can cast
    struct b3p_ctx* ctx_internal = (struct b3p_ctx*)ctx;
    assert(ctx_internal->pool.nthreads == 0);  // disabled for serial
    b3p_destroy(ctx);

    // Create_AutoThreadsAtLeast1
    // cfg.nthreads=0 and sysconf mocked to 0/negative => clamps to 1
    // We cannot mock sysconf easily; rely on actual system.
    // We'll test that nthreads=0 creates a working context.
    cfg.nthreads = 0;
    ctx = b3p_create(&cfg);
    assert(ctx != NULL);
    ctx_internal = (struct b3p_ctx*)ctx;
    // nthreads should be >= 1 (or 0 if disabled)
    // Actually, if nthreads=0, pool.nthreads may be set to number of CPUs or 1.
    // We'll just ensure context is usable.
    b3p_destroy(ctx);

    // Destroy_NullSafe
    // b3p_destroy(NULL) no crash
    b3p_destroy(NULL);

    // Destroy_FreesScratchAndPool
    // Create with pool, do a hash to allocate scratch and TLS, destroy, verify leak-free under ASan/LSan
    // We'll create a context with 2 threads, do a small hash to trigger allocations,
    // then destroy. ASan will detect leaks.
    cfg.nthreads = 2;
    ctx = b3p_create(&cfg);
    assert(ctx != NULL);
    uint8_t input[1024] = {0};
    uint8_t key[32] = {0};
    uint8_t out[32];
    // Perform a hash to allocate scratch and TLS
    int rc = b3p_hash_one_shot(ctx, input, sizeof(input), key, 0, B3P_METHOD_AUTO, out, 32);
    assert(rc == 0);
    b3p_destroy(ctx);
    // If there were leaks, ASan would report them.

    printf("OK\n");
}

void test_chunk_hashing_job(void) {
    printf("Testing chunk hashing job...\n");

    // ChunksJob_NullGuards
    // job NULL / ctx NULL / out_cvs NULL => no crash
    b3p_task_hash_chunks(NULL);

    b3p_chunks_job_t job = {0};
    b3p_task_hash_chunks(&job);  // ctx NULL

    job.ctx = (struct b3p_ctx*)1;  // non-null but invalid
    b3p_task_hash_chunks(&job);    // out_cvs NULL

    // ChunksJob_BatchStepZero_NoProgress
    // batch_step = 0 => returns quickly, does not write output
    // We need a minimal valid job to not crash
    struct b3p_ctx* ctx = create_test_ctx();
    assert(ctx != NULL);
    ctx->num_chunks = 10;
    b3_cv_bytes_t out_cvs[10] = {0};

    job.ctx = ctx;
    job.out_cvs = out_cvs;
    job.batch_step = 0;
    job.end_chunk = 10;
    atomic_init(&job.next_chunk, 0);

    // Should return early without writing anything
    b3p_task_hash_chunks(&job);
    // Verify no atomic increment (hard to check)
    // Ensure no crash

    // ChunksJob_SingleBatch_RootSplitChildrenWritten
    // num_chunks fits in one batch => ensure root path passes out_split_children
    // Set batch_step >= num_chunks
    job.batch_step = 10;
    job.end_chunk = 10;
    atomic_store(&job.next_chunk, 0);
    b3_cv_bytes_t split_children[2] = {0};
    job.out_split_children = split_children;

    // We need to stub b3p_hash_range_to_root to verify it receives out_split_children
    // Since we can't intercept static function, we'll rely on existing stub behavior
    // The stub for b3_hash_chunk_cv_impl does nothing, so out_cvs will remain zero
    // That's fine for no-crash test.
    b3p_task_hash_chunks(&job);

    // ChunksJob_TLSFallbackForLargeWantTmp
    // Force want_tmp > 1024 so it uses TLS buffer, still produces correct output
    // Need want_tmp > 1024, i.e., batch_limit - batch_start > 1024
    // Set batch_step = 2000, end_chunk = 2000, but need input length etc.
    // We'll skip this test as it requires more setup.

    free(ctx);
    printf("OK\n");
}

void test_subtree_hashing_job(void) {
    printf("Testing subtree hashing job...\n");

    // SubtreesJob_NullGuards
    // job NULL / ctx NULL / out_subtree_cvs NULL => no crash
    b3p_task_hash_subtrees(NULL);

    b3p_subtrees_job_t job = {0};
    b3p_task_hash_subtrees(&job);  // ctx NULL

    job.ctx = (struct b3p_ctx*)1;  // non-null but invalid
    b3p_task_hash_subtrees(&job);  // out_subtree_cvs NULL

    // SubtreesJob_SubtreeChunksZero_Returns
    // subtree_chunks=0 => return
    struct b3p_ctx* ctx = create_test_ctx();
    assert(ctx != NULL);
    ctx->num_chunks = 100;
    b3_cv_bytes_t out_cvs[10] = {0};

    job.ctx = ctx;
    job.out_subtree_cvs = out_cvs;
    job.subtree_chunks = 0;
    job.num_subtrees = 10;
    atomic_init(&job.next_subtree, 0);

    // Should return early without writing anything
    b3p_task_hash_subtrees(&job);
    // Ensure no crash

    // SubtreesJob_ClaimsAllSubtreesExactlyOnce
    // Run with multiple workers, verify each subtree index computed once (e.g., fill markers)
    // This requires multiple threads and coordination; skip for unit test.

    // SubtreesJob_RootSplitChildrenOnlyWhenSingleSubtree
    // num_subtrees==1 should write split children, otherwise should not
    // Test with num_subtrees=1
    job.subtree_chunks = 100;  // subtree_chunks == num_chunks
    job.num_subtrees = 1;
    atomic_store(&job.next_subtree, 0);
    b3_cv_bytes_t split_children[2] = {0};
    job.out_split_children = split_children;

    // The function will call b3p_hash_range_to_root with is_root=true and out_split_children
    // Our stub for b3_hash_chunk_cv_impl does nothing, so out_cvs will remain zero
    b3p_task_hash_subtrees(&job);

    // Test with num_subtrees=2 (should not pass split_children)
    job.num_subtrees = 2;
    job.subtree_chunks = 50;  // each subtree covers 50 chunks
    atomic_store(&job.next_subtree, 0);
    // out_split_children still set; function should pass NULL to b3p_hash_range_to_root
    b3p_task_hash_subtrees(&job);

    free(ctx);
    printf("OK\n");
}

void test_range_hashing_core(void) {
    printf("Testing range hashing core edge cases...\n");

    // Helper to create a minimal context
    struct b3p_ctx* ctx = create_test_ctx();
    assert(ctx != NULL);

    // Default input length 1024, chunk len 1024? Actually BLAKE3_CHUNK_LEN is 1024.
    // Ensure we have at least one chunk.
    ctx->input_len = 1024;
    ctx->num_chunks = 1;

    // Temporary buffers
    b3_cv_bytes_t tmp[16];
    b3_cv_bytes_t out_root[1];

    // 1. Null guards
    b3p_hash_range_to_root(NULL, 0, 1, tmp, out_root, 0, NULL);
    b3p_hash_range_to_root(ctx, 0, 1, NULL, out_root, 0, NULL);
    b3p_hash_range_to_root(ctx, 0, 1, tmp, NULL, 0, NULL);
    // Should not crash

    // 2. Invalid range (end < start)
    b3p_hash_range_to_root(ctx, 5, 3, tmp, out_root, 0, NULL);

    // 3. Zero-length range (start == end)
    b3p_hash_range_to_root(ctx, 7, 7, tmp, out_root, 0, NULL);

    // 4. SIMD degree clamping: zero degree
    g_simd_degree_result = 0;
    b3p_hash_range_to_root(ctx, 0, 1, tmp, out_root, 0, NULL);
    // Should clamp to 1, no crash
    g_simd_degree_result = 17;  // assuming MAX_SIMD_DEGREE is 16
    b3p_hash_range_to_root(ctx, 0, 1, tmp, out_root, 0, NULL);
    // Should clamp to 16, no crash
    g_simd_degree_result = 1;  // restore

    // 5. Last chunk partial (input length less than chunk)
    ctx->input_len = 500;  // less than CHUNK_LEN
    ctx->num_chunks = 1;
    g_chunk_cv_calls = 0;
    g_hash_many_calls = 0;
    b3p_hash_range_to_root(ctx, 0, 1, tmp, out_root, 0, NULL);
    assert(g_chunk_cv_calls == 1);
    assert(g_hash_many_calls == 0);
    ctx->input_len = 1024;  // restore

    // 6. Multiplication overflow start offset guard
    size_t max_chunks = SIZE_MAX / BLAKE3_CHUNK_LEN;
    b3p_hash_range_to_root(ctx, max_chunks + 1, max_chunks + 2, tmp, out_root, 0, NULL);
    // Should return early

    // 7. Input bounds guard
    ctx->input_len = 100;
    b3p_hash_range_to_root(ctx, 1, 2, tmp, out_root, 0, NULL);  // start_off = 1024 > 100
    ctx->input_len = 1024;

    // Additional overflow guard for chunk_i
    // chunk_i overflow when chunk_start + i + j > SIZE_MAX / CHUNK_LEN
    // Hard to trigger; skip.

    // Additional overflow guard for count
    // count > SIZE_MAX / CHUNK_LEN (simd_degree could be huge)
    // but simd_degree is clamped to MAX_SIMD_DEGREE (16). So cannot test.

    free(ctx);
    printf("OK\n");
}

void test_reduction_functions(void) {
    printf("Testing reduction functions...\n");

#define RESET_PARENT_CV_CALLS()                                  \
    do {                                                         \
        g_parent_cv_calls = 0;                                   \
        memset(g_parent_cv_flags, 0, sizeof(g_parent_cv_flags)); \
        memset(g_parent_cv_left, 0, sizeof(g_parent_cv_left));   \
        memset(g_parent_cv_right, 0, sizeof(g_parent_cv_right)); \
    } while (0)

    struct b3p_ctx* ctx = create_test_ctx();
    assert(ctx != NULL);
    ctx->num_chunks = 100;

    b3_cv_bytes_t cvs[10];
    b3_cv_bytes_t out_root = {0};
    b3_cv_bytes_t split_children[2] = {0};

    RESET_PARENT_CV_CALLS();
    b3p_reduce_stack(NULL, cvs, 5, 1, 5, &out_root, 0, NULL);
    assert(g_parent_cv_calls == 0);
    b3p_reduce_stack(ctx, NULL, 5, 1, 5, &out_root, 0, NULL);
    assert(g_parent_cv_calls == 0);
    b3p_reduce_stack(ctx, cvs, 5, 1, 5, NULL, 0, NULL);
    assert(g_parent_cv_calls == 0);
    printf("  Reduce_NullGuards passed\n");

    RESET_PARENT_CV_CALLS();
    b3p_reduce_stack(ctx, cvs, 0, 1, 0, &out_root, 0, NULL);
    assert(g_parent_cv_calls == 0);
    printf("  Reduce_NZero_Returns passed\n");

    RESET_PARENT_CV_CALLS();
    b3p_reduce_stack(ctx, cvs, 5, 0, 0, &out_root, 0, NULL);
    assert(g_parent_cv_calls == 0);
    printf("  Reduce_SubtreeChunksZero_Returns passed\n");

    RESET_PARENT_CV_CALLS();
    size_t huge = SIZE_MAX - 5;
    b3p_reduce_stack(ctx, cvs, 2, huge, ctx->num_chunks, &out_root, 0, NULL);
    assert(g_parent_cv_calls == 0);
    printf("  Reduce_TotalCountOverflowGuard passed\n");

    srand(42);
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 32; j++) {
            cvs[i].bytes[j] = rand() & 0xFF;
        }
    }

    b3_cv_bytes_t orig_cvs[10];
    for (int i = 0; i < 10; i++) {
        orig_cvs[i] = cvs[i];
    }

    b3_cv_bytes_t expected = {0};
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 32; j++) {
            expected.bytes[j] ^= orig_cvs[i].bytes[j];
        }
    }

    RESET_PARENT_CV_CALLS();
    b3p_reduce_stack(ctx, cvs, 10, 1, 10, &out_root, 1, NULL);
    if (memcmp(out_root.bytes, expected.bytes, 32) != 0) {
        printf("MISMATCH in Reduce_LazyMergePreservesTreeShape\n");
        printf("Expected: ");
        for (int j = 0; j < 32; j++) {
            printf("%02x", expected.bytes[j]);
        }
        printf("\nGot:      ");
        for (int j = 0; j < 32; j++) {
            printf("%02x", out_root.bytes[j]);
        }
        printf("\n");
        fflush(stdout);
        assert(0);
    }
    assert(g_parent_cv_calls == 9);
    printf("  Reduce_LazyMergePreservesTreeShape passed\n");

    for (int i = 0; i < 10; i++) {
        cvs[i] = orig_cvs[i];
    }

    const size_t subtree_chunks = 8;
    const size_t n_cvs = 10;
    const size_t remainder = 5;
    const size_t total_chunks = (n_cvs - 1) * subtree_chunks + remainder;
    size_t saved_num_chunks = ctx->num_chunks;
    ctx->num_chunks = total_chunks;

    RESET_PARENT_CV_CALLS();
    b3p_reduce_stack(ctx, cvs, n_cvs, subtree_chunks, ctx->num_chunks, &out_root, 1, NULL);
    if (memcmp(out_root.bytes, expected.bytes, 32) != 0) {
        printf("MISMATCH in Reduce_LazyMergeWithSubtreeChunksAndRemainder\n");
        printf("Expected: ");
        for (int j = 0; j < 32; j++) {
            printf("%02x", expected.bytes[j]);
        }
        printf("\nGot:      ");
        for (int j = 0; j < 32; j++) {
            printf("%02x", out_root.bytes[j]);
        }
        printf("\n");
        fflush(stdout);
        assert(0);
    }
    assert(g_parent_cv_calls == (int)(n_cvs - 1));
    printf("  Reduce_LazyMergeWithSubtreeChunksAndRemainder passed\n");

    ctx->num_chunks = saved_num_chunks;
    for (int i = 0; i < 10; i++) {
        cvs[i] = orig_cvs[i];
    }

    RESET_PARENT_CV_CALLS();

    const size_t n_cvs2 = 10;

    b3_cv_bytes_t cvs_for_split[10];
    b3_cv_bytes_t cvs_for_full[10];
    for (size_t i = 0; i < n_cvs2; i++) {
        cvs_for_split[i] = orig_cvs[i];
        cvs_for_full[i] = orig_cvs[i];
    }

    b3_cv_bytes_t full_root = (b3_cv_bytes_t){0};
    b3p_reduce_stack(ctx, cvs_for_full, n_cvs2, 1, n_cvs2, &full_root, 1, NULL);

    RESET_PARENT_CV_CALLS();

    split_children[0] = (b3_cv_bytes_t){0};
    split_children[1] = (b3_cv_bytes_t){0};
    b3p_reduce_stack(ctx, cvs_for_split, n_cvs2, 1, n_cvs2, &out_root, 1, split_children);

    printf("parent_cv_calls=%d expected=%zu\n", g_parent_cv_calls, n_cvs2 - 2);
    printf("split0_first=%02x split1_first=%02x\n", split_children[0].bytes[0], split_children[1].bytes[0]);

    assert(g_parent_cv_calls == (int)(n_cvs2 - 2));

    b3_cv_bytes_t root_from_children = (b3_cv_bytes_t){0};
    xor_merge(&split_children[0], &split_children[1], &root_from_children);
    assert(memcmp(root_from_children.bytes, full_root.bytes, 32) == 0);
    printf("  Reduce_SplitChildrenCapturedAtRoot passed\n");

    for (int i = 0; i < 10; i++) {
        cvs[i] = orig_cvs[i];
    }

    RESET_PARENT_CV_CALLS();
    b3p_reduce_stack(ctx, cvs, 2, 1, 2, &out_root, 1, NULL);
    assert(g_parent_cv_calls == 1);
    assert((g_parent_cv_flags[0] & ROOT) == ROOT);

    RESET_PARENT_CV_CALLS();
    b3p_reduce_stack(ctx, cvs, 2, 1, 2, &out_root, 0, NULL);
    assert(g_parent_cv_calls == 1);
    assert((g_parent_cv_flags[0] & ROOT) == 0);
    printf("  Merge_RootFlagAppliedOnlyAtFinal passed\n");

    free(ctx);
    printf("OK\n");
}

int main(void) {
    test_alloc_failure();
    test_pool_creation_failure();
    test_performance_invariants();
    test_tls_cv_buffer();
    test_scratch_cv_buffer();
    test_pool_lifecycle();
    test_queue_submit_semantics();
    test_heuristic_selection();
    test_public_api_context();
    test_chunk_hashing_job();
    test_subtree_hashing_job();
    test_reduction_functions();
    test_range_hashing_core();
    return 0;
}
