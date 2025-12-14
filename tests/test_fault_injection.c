#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

// Mocks
static int g_fail_realloc_at = -1;
static int g_realloc_count = 0;
static int g_fail_pthread_create = 0;
static int g_alloc_count = 0; // Malloc/Calloc/Realloc total

void *my_realloc(void *ptr, size_t size) {
    g_alloc_count++;
    g_realloc_count++;
    if (g_fail_realloc_at != -1 && g_realloc_count == g_fail_realloc_at) {
        return NULL;
    }
    return realloc(ptr, size);
}

void *my_malloc(size_t size) {
    g_alloc_count++;
    return malloc(size);
}

void *my_calloc(size_t nmemb, size_t size) {
    g_alloc_count++;
    return calloc(nmemb, size);
}

void my_free(void *ptr) {
    free(ptr);
}

int my_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                      void *(*start_routine) (void *), void *arg) {
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
void blake3_hash_many(const uint8_t* const* inputs, size_t num_inputs, size_t blocks, const uint32_t key[8], uint64_t counter, bool increment_counter, uint8_t flags, uint8_t flags_start, uint8_t flags_end, uint8_t* out) {}
size_t blake3_simd_degree(void) { return 1; }

// Internal primitives stubs
void b3_hash_chunk_cv_impl(const uint32_t key[8], uint8_t flags, const uint8_t *chunk, size_t chunk_len, uint64_t chunk_index, bool is_root, uint8_t out_cv[32]) {}
void b3_hash_parent_cv_impl(const uint32_t key[8], uint8_t flags, const uint8_t left_cv[32], const uint8_t right_cv[32], uint8_t out_cv[32]) {}
void b3_output_root_impl(const uint32_t input_cv[8], uint8_t block_flags, const uint8_t *block, size_t block_len, uint64_t counter, uint64_t seek, uint8_t *out, size_t out_len) {}

// Tests
void test_alloc_failure(void) {
    printf("Testing alloc failure...\n");
    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t *ctx = b3p_create(&cfg);
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
    b3p_ctx_t *ctx = b3p_create(&cfg);
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
    cfg.method_b_min_chunks_per_thread = 100000; // Force A
    
    b3p_ctx_t *ctx = b3p_create(&cfg);
    
    uint8_t input[1024];
    uint8_t key[32] = {0};
    uint8_t out[32];

    // Warmup
    b3p_hash_one_shot(ctx, input, sizeof(input), key, 0, B3P_METHOD_A_CHUNKS, out, 32);

    int start_allocs = g_alloc_count;
    
    // Loop
    for (int i=0; i<100; i++) {
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

int main(void) {
    test_alloc_failure();
    test_pool_creation_failure();
    test_performance_invariants();
    return 0;
}
