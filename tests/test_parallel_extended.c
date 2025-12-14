#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include "../src/blake3.h"
#include "../src/blake3_parallel.h"
#include "../src/blake3_impl.h"

// Helper for random data
void generate_random_data(uint8_t *buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)rand();
    }
}

// Reference implementation using standard BLAKE3 APIs
void reference_blake3(const uint8_t *input, size_t input_len, const uint8_t *key, int is_keyed, uint8_t flags, uint8_t *out, size_t out_len, uint64_t seek_offset) {
    blake3_hasher hasher;
    if (is_keyed) {
        blake3_hasher_init_keyed(&hasher, key);
    } else {
        blake3_hasher_init(&hasher);
    }
    // Note: Standard API doesn't allow setting arbitrary flags easily for update/finalize.
    // For verification against b3p with custom flags, we rely on b3p_hash_buffer_serial as reference in other tests.
    // Here we focus on standard correctness (flags=0 or KEYED_HASH).
    blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize_seek(&hasher, seek_offset, out, out_len);
}

// Helper to compare b3p result with reference
void verify_correctness(b3p_ctx_t *ctx, const uint8_t *input, size_t len, b3p_method_t method, const char *desc) {
    uint8_t key[BLAKE3_KEY_LEN] = {0}; // Dummy key
    uint8_t out_ref[BLAKE3_OUT_LEN];
    uint8_t out_test[BLAKE3_OUT_LEN];

    // Reference (Standard BLAKE3, keyed to match b3p explicit zero key)
    reference_blake3(input, len, key, 1, KEYED_HASH, out_ref, BLAKE3_OUT_LEN, 0);

    // Test
    int rc = b3p_hash_one_shot(ctx, input, len, key, KEYED_HASH, method, out_test, BLAKE3_OUT_LEN);
    assert(rc == 0);

    if (memcmp(out_ref, out_test, BLAKE3_OUT_LEN) != 0) {
        fprintf(stderr, "FAILED: %s (len=%zu)\n", desc, len);
        exit(1);
    }
}

void test_methods_and_heuristics(void) {
    printf("Testing methods and heuristics...\n");
    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = 4;
    b3p_ctx_t *ctx = b3p_create(&cfg);
    assert(ctx != NULL);

    size_t lengths[] = {0, 1, 1024, 2048, 1024*1024, 16*1024*1024};
    for (size_t i = 0; i < sizeof(lengths)/sizeof(size_t); i++) {
        size_t len = lengths[i];
        uint8_t *input = malloc(len);
        if (len > 0) generate_random_data(input, len);

        verify_correctness(ctx, input, len, B3P_METHOD_A_CHUNKS, "Force A");
        verify_correctness(ctx, input, len, B3P_METHOD_B_SUBTREES, "Force B");
        verify_correctness(ctx, input, len, B3P_METHOD_AUTO, "Auto");

        // Verify Auto matches Forced (implicitly verified since all match reference)
        
        free(input);
    }
    b3p_destroy(ctx);
    printf("OK\n");
}

void test_threading_behaviors(void) {
    printf("Testing threading behaviors...\n");
    size_t len = 1024 * 1024; // 1MB
    uint8_t *input = malloc(len);
    generate_random_data(input, len);

    int threads[] = {1, 2, 3, 4, 8};
    for (size_t i = 0; i < sizeof(threads)/sizeof(int); i++) {
        int n = threads[i];
        b3p_config_t cfg = b3p_config_default();
        cfg.nthreads = n;
        b3p_ctx_t *ctx = b3p_create(&cfg);
        
        verify_correctness(ctx, input, len, B3P_METHOD_AUTO, "Thread count variation");
        
        // Reuse context
        for (int j = 0; j < 10; j++) {
             verify_correctness(ctx, input, len / (j+1), B3P_METHOD_AUTO, "Ctx reuse");
        }

        b3p_destroy(ctx);
    }
    
    // nthreads > work items (tiny input)
    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = 16;
    b3p_ctx_t *ctx = b3p_create(&cfg);
    verify_correctness(ctx, input, 1, B3P_METHOD_AUTO, "Tiny input many threads");
    b3p_destroy(ctx);

    free(input);
    printf("OK\n");
}

void test_seek_xof_semantics(void) {
    printf("Testing Seek/XOF semantics...\n");
    size_t len = 64 * 1024;
    uint8_t *input = malloc(len);
    generate_random_data(input, len);
    uint8_t key[BLAKE3_KEY_LEN] = {0};

    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t *ctx = b3p_create(&cfg);

    // 1. output(seek=0, out_len=L) equals first L bytes of output(seek=0, out_len=L+K)
    {
        size_t L = 100;
        size_t K = 50;
        uint8_t out1[150];
        uint8_t out2[150];
        
        b3p_hash_one_shot_seek(ctx, input, len, key, KEYED_HASH, B3P_METHOD_AUTO, 0, out1, L);
        b3p_hash_one_shot_seek(ctx, input, len, key, KEYED_HASH, B3P_METHOD_AUTO, 0, out2, L+K);
        
        if (memcmp(out1, out2, L) != 0) {
            fprintf(stderr, "FAILED: XOF prefix check\n");
            exit(1);
        }
    }

    // 2. output(seek=S, out_len=L) equals slice [S:S+L) of output(seek=0, out_len=S+L)
    {
        uint64_t S = 64;
        size_t L = 64;
        uint8_t out_full[200];
        uint8_t out_part[200];

        b3p_hash_one_shot_seek(ctx, input, len, key, KEYED_HASH, B3P_METHOD_AUTO, 0, out_full, S+L);
        b3p_hash_one_shot_seek(ctx, input, len, key, KEYED_HASH, B3P_METHOD_AUTO, S, out_part, L);

        if (memcmp(out_full + S, out_part, L) != 0) {
            fprintf(stderr, "FAILED: XOF seek check\n");
            exit(1);
        }
    }

    // 3. Boundary seeks
    uint64_t seeks[] = {63, 64, 65, 1023, 1024, 1025, 1ULL<<20, (1ULL<<32)+5};
    for (size_t i = 0; i < sizeof(seeks)/sizeof(uint64_t); i++) {
        uint64_t s = seeks[i];
        uint8_t out_ref[10];
        uint8_t out_test[10];
        size_t out_len = 10;

        reference_blake3(input, len, key, 1, KEYED_HASH, out_ref, out_len, s);
        b3p_hash_one_shot_seek(ctx, input, len, key, KEYED_HASH, B3P_METHOD_AUTO, s, out_test, out_len);

        if (memcmp(out_ref, out_test, out_len) != 0) {
            fprintf(stderr, "FAILED: Boundary seek %lu\n", s);
            exit(1);
        }
    }

    b3p_destroy(ctx);
    free(input);
    printf("OK\n");
}

void test_alignment(void) {
    printf("Testing alignment...\n");
    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t *ctx = b3p_create(&cfg);
    
    size_t len = 1024;
    // Allocate buffer larger than len + offset
    uint8_t *buffer = malloc(len + 64);
    
    for (int offset = 0; offset < 64; offset++) {
        uint8_t *input = buffer + offset;
        generate_random_data(input, len);
        verify_correctness(ctx, input, len, B3P_METHOD_AUTO, "Alignment");
    }

    free(buffer);
    b3p_destroy(ctx);
    printf("OK\n");
}

typedef struct {
    int id;
} stress_thread_arg_t;

void *stress_worker(void *arg) {
    (void)arg;
    // Each thread creates its own context
    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = 2; // Mixed parallelism
    b3p_ctx_t *ctx = b3p_create(&cfg);
    assert(ctx != NULL);

    uint8_t key[BLAKE3_KEY_LEN] = {0};
    size_t max_len = 8 * 1024 * 1024;
    uint8_t *input = malloc(max_len);
    
    // Hash random sizes
    for (int i = 0; i < 20; i++) {
        size_t len = rand() % max_len;
        generate_random_data(input, len);
        
        uint8_t out_ref[BLAKE3_OUT_LEN];
        uint8_t out_test[BLAKE3_OUT_LEN];

        reference_blake3(input, len, key, 1, KEYED_HASH, out_ref, BLAKE3_OUT_LEN, 0);
        b3p_hash_one_shot(ctx, input, len, key, KEYED_HASH, B3P_METHOD_AUTO, out_test, BLAKE3_OUT_LEN);
        
        assert(memcmp(out_ref, out_test, BLAKE3_OUT_LEN) == 0);
    }

    free(input);
    b3p_destroy(ctx);
    b3p_free_tls_resources();
    return NULL;
}
void test_stress_concurrency(void) {
    printf("Testing stress concurrency...\n");
    int nthreads = 4;
    pthread_t threads[nthreads];
    
    for (int i = 0; i < nthreads; i++) {
        pthread_create(&threads[i], NULL, stress_worker, NULL);
    }

    for (int i = 0; i < nthreads; i++) {
        pthread_join(threads[i], NULL);
    }
    printf("OK\n");
}

int main(void) {
    srand(999);
    test_methods_and_heuristics();
    test_threading_behaviors();
    test_seek_xof_semantics();
    test_alignment();
    test_stress_concurrency();
    b3p_free_tls_resources();
    printf("All extended tests passed.\n");
    return 0;
}
