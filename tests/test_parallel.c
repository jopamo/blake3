#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/blake3.h"
#include "../src/blake3_parallel.h"
#include "../src/blake3_impl.h"

// Helper for random data
void generate_random_data(uint8_t *buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)rand();
    }
}

// Generalized BLAKE3 implementation for reference verification, supporting XOF, keyed, and flags
void reference_blake3(const uint8_t *input, size_t input_len, const uint8_t *key, int is_keyed, uint8_t flags, uint8_t *out, size_t out_len, uint64_t seek_offset) {
    blake3_hasher hasher;
    if (is_keyed) {
        blake3_hasher_init_keyed(&hasher, key);
    } else {
        blake3_hasher_init(&hasher);
    }
    blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize_seek(&hasher, seek_offset, out, out_len);
}


void test_oneshot(size_t len, int nthreads, size_t out_len) {
    printf("Testing len=%zu threads=%d out_len=%zu... ", len, nthreads, out_len);
    
    uint8_t *input = malloc(len);
    if (len > 0) {
        // Deterministic pattern
        for (size_t i = 0; i < len; i++) {
            input[i] = (uint8_t)(i % 251);
        }
    }

    uint8_t *expected = malloc(out_len);
    uint8_t dummy_key[BLAKE3_KEY_LEN] = {0}; // For non-keyed hash, key is not used
    uint8_t dummy_flags = KEYED_HASH; // For regular hash
    reference_blake3(input, len, dummy_key, 1, dummy_flags, expected, out_len, 0);

    uint8_t *actual = malloc(out_len);
    
    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = nthreads;
    b3p_ctx_t *b3p = b3p_create(&cfg);
    assert(b3p != NULL);

    int rc = b3p_hash_one_shot(b3p, input, len, dummy_key, dummy_flags, B3P_METHOD_AUTO, actual, out_len);
    assert(rc == 0); // Assert rc is 0

    b3p_destroy(b3p);
    free(input);

    if (memcmp(expected, actual, out_len) != 0) {
        printf("FAILED\n");
        printf("Expected: ");
        for(size_t i=0;i<out_len;i++) printf("%02x", expected[i]);
        printf("\nActual:   ");
        for(size_t i=0;i<out_len;i++) printf("%02x", actual[i]);
        printf("\n");
        exit(1);
    }
    printf("OK\n");
    free(expected);
    free(actual);
}


void test_api_smoke(void) {
    printf("Testing API smoke... ");

    // b3p_create(default cfg) returns non-NULL
    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t *b3p = b3p_create(&cfg);
    assert(b3p != NULL);

    // b3p_destroy(NULL) is safe
    b3p_destroy(NULL); // Should not crash

    // b3p_hash_one_shot with out_len=0 returns 0 and does not touch output buffer
    uint8_t input_dummy[] = {0x01, 0x02, 0x03};
    uint8_t out_buffer[BLAKE3_OUT_LEN];
    memset(out_buffer, 0xFF, BLAKE3_OUT_LEN); // Fill with known pattern
    
    // Dummy key and flags for b3p_hash_one_shot
    uint8_t dummy_key[BLAKE3_KEY_LEN] = {0}; 
    uint8_t dummy_flags = 0;

    int rc_zero_out = b3p_hash_one_shot(b3p, input_dummy, sizeof(input_dummy), dummy_key, dummy_flags, B3P_METHOD_AUTO, out_buffer, 0);
    assert(rc_zero_out == 0); // Expect success
    // Verify output buffer is untouched
    for (size_t i = 0; i < BLAKE3_OUT_LEN; i++) {
        assert(out_buffer[i] == 0xFF);
    }

    // b3p_hash_one_shot_seek with NULL ctx/input/out returns -1
    int rc_null_ctx = b3p_hash_one_shot_seek(NULL, input_dummy, sizeof(input_dummy), dummy_key, dummy_flags, B3P_METHOD_AUTO, 0, out_buffer, BLAKE3_OUT_LEN);
    assert(rc_null_ctx == -1);

    int rc_null_input = b3p_hash_one_shot_seek(b3p, NULL, sizeof(input_dummy), dummy_key, dummy_flags, B3P_METHOD_AUTO, 0, out_buffer, BLAKE3_OUT_LEN);
    assert(rc_null_input == -1);

    int rc_null_out = b3p_hash_one_shot_seek(b3p, input_dummy, sizeof(input_dummy), dummy_key, dummy_flags, B3P_METHOD_AUTO, 0, NULL, BLAKE3_OUT_LEN);
    assert(rc_null_out == -1);

    b3p_destroy(b3p);
    printf("OK\n");
}


uint8_t* get_b3p_hash(b3p_ctx_t *ctx, const uint8_t *input, size_t input_len, int nthreads) {
    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = nthreads;
    if (!ctx) { // Create context if not provided
        ctx = b3p_create(&cfg);
        assert(ctx != NULL);
    }
    
    uint8_t *out = malloc(BLAKE3_OUT_LEN);
    assert(out != NULL);

    uint8_t dummy_key[BLAKE3_KEY_LEN] = {0}; 
    uint8_t dummy_flags = 0;

    int rc = b3p_hash_one_shot(ctx, input, input_len, dummy_key, dummy_flags, B3P_METHOD_AUTO, out, BLAKE3_OUT_LEN);
    assert(rc == 0);
    
    if (!ctx) { // Destroy context if created within this function
        b3p_destroy(ctx);
    }
    return out;
}

void test_determinism_multiple_runs(void) {
    printf("Testing determinism across multiple runs... ");
    size_t len = 1024 * 1024; // 1MB
    uint8_t *input = malloc(len);
    for (size_t i = 0; i < len; i++) {
        input[i] = (uint8_t)(i % 251);
    }

    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t *b3p = b3p_create(&cfg);
    assert(b3p != NULL);

    uint8_t *first_hash = get_b3p_hash(b3p, input, len, 0); // nthreads not used when ctx is provided

    for (int i = 0; i < 1000; i++) {
        uint8_t *current_hash = get_b3p_hash(b3p, input, len, 0);
        assert(memcmp(first_hash, current_hash, BLAKE3_OUT_LEN) == 0);
        free(current_hash);
    }

    free(first_hash);
    b3p_destroy(b3p);
    free(input);
    printf("OK\n");
}

void test_determinism_create_destroy(void) {
    printf("Testing determinism across create/destroy cycles... ");
    size_t len = 1024 * 1024; // 1MB
    uint8_t *input = malloc(len);
    for (size_t i = 0; i < len; i++) {
        input[i] = (uint8_t)(i % 251);
    }

    uint8_t *first_hash = NULL;
    for (int i = 0; i < 100; i++) {
        b3p_config_t cfg = b3p_config_default();
        b3p_ctx_t *b3p = b3p_create(&cfg);
        assert(b3p != NULL);
        
        uint8_t *current_hash = get_b3p_hash(b3p, input, len, 0); // nthreads not used when ctx is provided
        b3p_destroy(b3p);

        if (first_hash == NULL) {
            first_hash = current_hash;
        } else {
            assert(memcmp(first_hash, current_hash, BLAKE3_OUT_LEN) == 0);
            free(current_hash);
        }
    }
    
    free(first_hash);
    free(input);
    printf("OK\n");
}

#define NCPU 32

void test_determinism_thread_counts(void) {
    printf("Testing determinism across different thread counts... ");
    size_t len = 10 * 1024 * 1024; // 10MB
    uint8_t *input = malloc(len);
    for (size_t i = 0; i < len; i++) {
        input[i] = (uint8_t)(i % 251);
    }

    uint8_t *first_hash = get_b3p_hash(NULL, input, len, 1);

    uint8_t *hash_2_threads = get_b3p_hash(NULL, input, len, 2);
    assert(memcmp(first_hash, hash_2_threads, BLAKE3_OUT_LEN) == 0);
    free(hash_2_threads);

    uint8_t *hash_ncpu_threads = get_b3p_hash(NULL, input, len, NCPU);
    assert(memcmp(first_hash, hash_ncpu_threads, BLAKE3_OUT_LEN) == 0);
    free(hash_ncpu_threads);

    free(first_hash);
    free(input);
    printf("OK\n");
}

void test_correctness_vs_reference_one_shot(void) {
    printf("Testing correctness vs reference (one-shot)... ");

    size_t out_lens[] = {1, 2, 31, 32, 33, 63, 64, 65, 1024, 4096};
    size_t input_lens[] = {0, 1, 100, 1024, 2048, 4096, 16384, 1024 * 1024}; // Various input sizes

    uint8_t dummy_key[BLAKE3_KEY_LEN] = {0}; 
    uint8_t dummy_flags = KEYED_HASH;

    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t *b3p = b3p_create(&cfg);
    assert(b3p != NULL);

    for (size_t i = 0; i < sizeof(input_lens) / sizeof(input_lens[0]); i++) {
        size_t input_len = input_lens[i];
        uint8_t *input = malloc(input_len);
        if (input_len > 0) {
            generate_random_data(input, input_len);
        }

        for (size_t j = 0; j < sizeof(out_lens) / sizeof(out_lens[0]); j++) {
            size_t out_len = out_lens[j];

            uint8_t *expected = malloc(out_len);
            reference_blake3(input, input_len, dummy_key, 1, dummy_flags, expected, out_len, 0);

            uint8_t *actual = malloc(out_len);
            int rc = b3p_hash_one_shot(b3p, input, input_len, dummy_key, dummy_flags, B3P_METHOD_AUTO, actual, out_len);
            assert(rc == 0);

            if (memcmp(expected, actual, out_len) != 0) {
                printf("FAILED at input_len=%zu, out_len=%zu\n", input_len, out_len);
                printf("Expected: ");
                for(size_t k=0; k<out_len; k++) printf("%02x", expected[k]);
                printf("\nActual:   ");
                for(size_t k=0; k<out_len; k++) printf("%02x", actual[k]);
                printf("\n");
                assert(0); // Force a crash to stop execution and see the output
            }
            free(expected);
            free(actual);
        }
        free(input);
    }
    b3p_destroy(b3p);
    printf("OK\n");
}

void test_correctness_vs_reference_seek(void) {
    printf("Testing correctness vs reference (seek)... ");

    size_t out_lens[] = {1, 2, 31, 32, 33, 63, 64, 65, 1024, 4096};
    uint64_t seeks[] = {0, 1, 63, 64, 65, 1024, (1ULL << 20), (1ULL << 32) + 5};
    size_t input_len = 1024 * 1024; // 1MB random input
    uint8_t *input = malloc(input_len);
    generate_random_data(input, input_len);

    uint8_t dummy_key[BLAKE3_KEY_LEN] = {0}; 
    uint8_t dummy_flags = KEYED_HASH;

    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t *b3p = b3p_create(&cfg);
    assert(b3p != NULL);

    for (size_t i = 0; i < sizeof(out_lens) / sizeof(out_lens[0]); i++) {
        size_t out_len = out_lens[i];
        for (size_t j = 0; j < sizeof(seeks) / sizeof(seeks[0]); j++) {
            uint64_t seek = seeks[j];

            uint8_t *expected = malloc(out_len);
            reference_blake3(input, input_len, dummy_key, 1, dummy_flags, expected, out_len, seek);

            uint8_t *actual = malloc(out_len);
            int rc = b3p_hash_one_shot_seek(b3p, input, input_len, dummy_key, dummy_flags, B3P_METHOD_AUTO, seek, actual, out_len);
            assert(rc == 0);

            assert(memcmp(expected, actual, out_len) == 0);
            free(expected);
            free(actual);
        }
    }
    b3p_destroy(b3p);
    free(input);
    printf("OK\n");
}

void test_empty_input_hash_difference(void) {
    printf("Testing empty input hash difference between finalize and finalize_seek... ");
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, NULL, 0); // Empty input

    uint8_t out1[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, out1, BLAKE3_OUT_LEN);
    printf("Finalize hash (empty input): ");
    for(size_t k=0; k<BLAKE3_OUT_LEN; k++) printf("%02x", out1[k]);
    printf("\n");

    uint8_t out2[BLAKE3_OUT_LEN];
    blake3_hasher_finalize_seek(&hasher, 0, out2, BLAKE3_OUT_LEN);

    if (memcmp(out1, out2, BLAKE3_OUT_LEN) != 0) {
        printf("FAILED\n");
        printf("Finalize:       ");
        for(size_t k=0; k<BLAKE3_OUT_LEN; k++) printf("%02x", out1[k]);
        printf("\nFinalize_seek:  ");
        for(size_t k=0; k<BLAKE3_OUT_LEN; k++) printf("%02x", out2[k]);
        printf("\n");
        assert(0);
    }
    printf("OK\n");
}

int main(void) {
    srand(0); // Seed random number generator for reproducible tests
    test_api_smoke();
    test_determinism_multiple_runs();
    test_determinism_create_destroy();
    test_determinism_thread_counts();

    test_correctness_vs_reference_one_shot();
    test_correctness_vs_reference_seek();
    
    // Test small files (serial path)
    test_oneshot(0, 1, BLAKE3_OUT_LEN);
    test_oneshot(1, 1, BLAKE3_OUT_LEN);
    test_oneshot(1024, 1, BLAKE3_OUT_LEN);
    test_oneshot(2000, 1, BLAKE3_OUT_LEN);
    
    // Test medium files (boundary of chunking)
    test_oneshot(8192, 1, BLAKE3_OUT_LEN); // 8KB
    test_oneshot(8192 * 1024, 1, BLAKE3_OUT_LEN); // 8MB (4 subtrees with 2MB chunks)

    // Test large files
    test_oneshot(16 * 1024 * 1024, 1, BLAKE3_OUT_LEN); // 16MB serial
    test_oneshot(16 * 1024 * 1024, 4, BLAKE3_OUT_LEN); // 16MB parallel (should use 8 subtrees -> 4 threads ok)

    // Test parallel
    test_oneshot(1024 * 1024, 2, BLAKE3_OUT_LEN);
    test_oneshot(10 * 1024 * 1024, 4, BLAKE3_OUT_LEN);
    test_oneshot(100 * 1024 * 1024, 8, BLAKE3_OUT_LEN);

    return 0;
}
