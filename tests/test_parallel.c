#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/blake3.h"
#include "../src/blake3_parallel.h"
#include "../src/blake3_impl.h"

// Helper for random data
void generate_random_data(uint8_t* buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)rand();
    }
}

// Generalized BLAKE3 implementation for reference verification, supporting XOF, keyed, and flags
void reference_blake3(const uint8_t* input, size_t input_len, const uint8_t* key, int is_keyed, uint8_t flags, uint8_t* out, size_t out_len, uint64_t seek_offset) {
    blake3_hasher hasher;
    if (is_keyed) {
        blake3_hasher_init_keyed(&hasher, key);
    }
    else {
        blake3_hasher_init(&hasher);
    }
    blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize_seek(&hasher, seek_offset, out, out_len);
}

void test_oneshot(size_t len, int nthreads, size_t out_len) {
    printf("Testing len=%zu threads=%d out_len=%zu... ", len, nthreads, out_len);

    uint8_t* input = malloc(len);
    if (len > 0) {
        // Deterministic pattern
        for (size_t i = 0; i < len; i++) {
            input[i] = (uint8_t)(i % 251);
        }
    }

    uint8_t* expected = malloc(out_len);
    uint8_t dummy_key[BLAKE3_KEY_LEN] = {0};  // For non-keyed hash, key is not used
    uint8_t dummy_flags = KEYED_HASH;         // For regular hash
    reference_blake3(input, len, dummy_key, 1, dummy_flags, expected, out_len, 0);

    uint8_t* actual = malloc(out_len);

    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = nthreads;
    b3p_ctx_t* b3p = b3p_create(&cfg);
    assert(b3p != NULL);

    int rc = b3p_hash_one_shot(b3p, input, len, dummy_key, dummy_flags, B3P_METHOD_AUTO, actual, out_len);
    assert(rc == 0);  // Assert rc is 0

    b3p_destroy(b3p);
    free(input);

    if (memcmp(expected, actual, out_len) != 0) {
        printf("FAILED\n");
        printf("Expected: ");
        for (size_t i = 0; i < out_len; i++)
            printf("%02x", expected[i]);
        printf("\nActual:   ");
        for (size_t i = 0; i < out_len; i++)
            printf("%02x", actual[i]);
        printf("\n");
        exit(1);
    }
    printf("OK\n");
    free(expected);
    free(actual);
}

void verify_vector(b3p_ctx_t* b3p, size_t len) {
    uint8_t* input = malloc(len);
    if (len > 0) {
        for (size_t i = 0; i < len; i++) {
            input[i] = (uint8_t)(i % 251);
        }
    }

    uint8_t dummy_key[BLAKE3_KEY_LEN] = {0};
    uint8_t dummy_flags = KEYED_HASH;

    // 1. Base correctness: one_shot out_len=32
    {
        size_t out_len = 32;
        uint8_t* expected = malloc(out_len);
        reference_blake3(input, len, dummy_key, 1, dummy_flags, expected, out_len, 0);
        uint8_t* actual = malloc(out_len);
        int rc = b3p_hash_one_shot(b3p, input, len, dummy_key, dummy_flags, B3P_METHOD_AUTO, actual, out_len);
        assert(rc == 0);
        if (memcmp(expected, actual, out_len) != 0) {
            printf("FAILED one_shot at len=%zu\n", len);
            exit(1);
        }
        free(expected);
        free(actual);
    }

    // 2. Seek correctness: seek=0, out_len=32
    {
        size_t out_len = 32;
        uint8_t* expected = malloc(out_len);
        reference_blake3(input, len, dummy_key, 1, dummy_flags, expected, out_len, 0);
        uint8_t* actual = malloc(out_len);
        int rc = b3p_hash_one_shot_seek(b3p, input, len, dummy_key, dummy_flags, B3P_METHOD_AUTO, 0, actual, out_len);
        assert(rc == 0);
        if (memcmp(expected, actual, out_len) != 0) {
            printf("FAILED one_shot_seek(0) at len=%zu\n", len);
            exit(1);
        }
        free(expected);
        free(actual);
    }

    // 3. XOF variations
    size_t out_lens[] = {1, 2, 31, 32, 33, 63, 64, 65, 1024, 4096};
    uint64_t seeks[] = {0, 1, 63, 64, 65, 1024, 1ULL << 20};

    for (size_t i = 0; i < sizeof(out_lens) / sizeof(size_t); i++) {
        for (size_t j = 0; j < sizeof(seeks) / sizeof(uint64_t); j++) {
            size_t out_len = out_lens[i];
            uint64_t seek = seeks[j];

            uint8_t* expected = malloc(out_len);
            reference_blake3(input, len, dummy_key, 1, dummy_flags, expected, out_len, seek);

            uint8_t* actual = malloc(out_len);
            int rc = b3p_hash_one_shot_seek(b3p, input, len, dummy_key, dummy_flags, B3P_METHOD_AUTO, seek, actual, out_len);
            assert(rc == 0);

            if (memcmp(expected, actual, out_len) != 0) {
                printf("FAILED XOF at len=%zu, seek=%lu, out_len=%zu\n", len, seek, out_len);
                exit(1);
            }
            free(expected);
            free(actual);
        }
    }

    free(input);
}

void test_api_smoke(void) {
    printf("Testing API smoke... ");

    // b3p_create(default cfg) returns non-NULL
    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t* b3p = b3p_create(&cfg);
    assert(b3p != NULL);

    // b3p_create(NULL) uses default config
    b3p_ctx_t* b3p_default = b3p_create(NULL);
    assert(b3p_default != NULL);
    b3p_destroy(b3p_default);

    // b3p_destroy(NULL) is safe
    b3p_destroy(NULL);  // Should not crash

    // b3p_hash_one_shot with out_len=0 returns 0 and does not touch output buffer
    uint8_t input_dummy[] = {0x01, 0x02, 0x03};
    uint8_t out_buffer[BLAKE3_OUT_LEN];
    memset(out_buffer, 0xFF, BLAKE3_OUT_LEN);  // Fill with known pattern

    // Dummy key and flags for b3p_hash_one_shot
    uint8_t dummy_key[BLAKE3_KEY_LEN] = {0};
    b3p_flags_t dummy_flags = 0;

    int rc_zero_out = b3p_hash_one_shot(b3p, input_dummy, sizeof(input_dummy), dummy_key, dummy_flags, B3P_METHOD_AUTO, out_buffer, 0);
    assert(rc_zero_out == 0);  // Expect success

    int rc_zero_out_null = b3p_hash_one_shot(b3p, input_dummy, sizeof(input_dummy), dummy_key, dummy_flags, B3P_METHOD_AUTO, NULL, 0);
    assert(rc_zero_out_null == 0);

    // Verify output buffer is untouched
    for (size_t i = 0; i < BLAKE3_OUT_LEN; i++) {
        assert(out_buffer[i] == 0xFF);
    }

    // NULL input is allowed when input_len == 0.
    uint8_t empty_parallel[BLAKE3_OUT_LEN];
    int rc_null_empty = b3p_hash_unkeyed(b3p, NULL, 0, B3P_METHOD_AUTO, empty_parallel, BLAKE3_OUT_LEN);
    assert(rc_null_empty == 0);
    blake3_hasher empty_hasher;
    blake3_hasher_init(&empty_hasher);
    uint8_t empty_serial[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&empty_hasher, empty_serial, BLAKE3_OUT_LEN);
    assert(memcmp(empty_parallel, empty_serial, BLAKE3_OUT_LEN) == 0);

    // b3p_hash_one_shot_seek with NULL ctx/input/out returns -1 for non-empty input/output.
    int rc_null_ctx = b3p_hash_one_shot_seek(NULL, input_dummy, sizeof(input_dummy), dummy_key, dummy_flags, B3P_METHOD_AUTO, 0, out_buffer, BLAKE3_OUT_LEN);
    assert(rc_null_ctx == -1);

    int rc_null_input = b3p_hash_one_shot_seek(b3p, NULL, sizeof(input_dummy), dummy_key, dummy_flags, B3P_METHOD_AUTO, 0, out_buffer, BLAKE3_OUT_LEN);
    assert(rc_null_input == -1);

    int rc_null_out = b3p_hash_one_shot_seek(b3p, input_dummy, sizeof(input_dummy), dummy_key, dummy_flags, B3P_METHOD_AUTO, 0, NULL, BLAKE3_OUT_LEN);
    assert(rc_null_out == -1);

    b3p_destroy(b3p);
    printf("OK\n");
}

uint8_t* get_b3p_hash(b3p_ctx_t* ctx, const uint8_t* input, size_t input_len, int nthreads) {
    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = nthreads;
    int created_locally = 0;
    if (!ctx) {  // Create context if not provided
        ctx = b3p_create(&cfg);
        assert(ctx != NULL);
        created_locally = 1;
    }

    uint8_t* out = malloc(BLAKE3_OUT_LEN);
    assert(out != NULL);

    uint8_t dummy_key[BLAKE3_KEY_LEN] = {0};
    uint8_t dummy_flags = 0;

    int rc = b3p_hash_one_shot(ctx, input, input_len, dummy_key, dummy_flags, B3P_METHOD_AUTO, out, BLAKE3_OUT_LEN);
    assert(rc == 0);

    if (created_locally) {  // Destroy context if created within this function
        b3p_destroy(ctx);
    }
    return out;
}

void test_determinism_multiple_runs(void) {
    printf("Testing determinism across multiple runs... ");
    size_t len = 1024 * 1024;  // 1MB
    uint8_t* input = malloc(len);
    for (size_t i = 0; i < len; i++) {
        input[i] = (uint8_t)(i % 251);
    }

    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t* b3p = b3p_create(&cfg);
    assert(b3p != NULL);

    uint8_t* first_hash = get_b3p_hash(b3p, input, len, 0);  // nthreads not used when ctx is provided

    for (int i = 0; i < 1000; i++) {
        uint8_t* current_hash = get_b3p_hash(b3p, input, len, 0);
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
    size_t len = 1024 * 1024;  // 1MB
    uint8_t* input = malloc(len);
    for (size_t i = 0; i < len; i++) {
        input[i] = (uint8_t)(i % 251);
    }

    uint8_t* first_hash = NULL;
    for (int i = 0; i < 100; i++) {
        b3p_config_t cfg = b3p_config_default();
        b3p_ctx_t* b3p = b3p_create(&cfg);
        assert(b3p != NULL);

        uint8_t* current_hash = get_b3p_hash(b3p, input, len, 0);  // nthreads not used when ctx is provided
        b3p_destroy(b3p);

        if (first_hash == NULL) {
            first_hash = current_hash;
        }
        else {
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
    size_t len = 10 * 1024 * 1024;  // 10MB
    uint8_t* input = malloc(len);
    for (size_t i = 0; i < len; i++) {
        input[i] = (uint8_t)(i % 251);
    }

    uint8_t* first_hash = get_b3p_hash(NULL, input, len, 1);

    uint8_t* hash_2_threads = get_b3p_hash(NULL, input, len, 2);
    assert(memcmp(first_hash, hash_2_threads, BLAKE3_OUT_LEN) == 0);
    free(hash_2_threads);

    uint8_t* hash_ncpu_threads = get_b3p_hash(NULL, input, len, NCPU);
    assert(memcmp(first_hash, hash_ncpu_threads, BLAKE3_OUT_LEN) == 0);
    free(hash_ncpu_threads);

    free(first_hash);
    free(input);
    printf("OK\n");
}

void test_correctness_vs_reference_one_shot(void) {
    printf("Testing correctness vs reference (one-shot)... ");

    size_t out_lens[] = {1, 2, 31, 32, 33, 63, 64, 65, 1024, 4096};
    size_t input_lens[] = {0, 1, 100, 1024, 2048, 4096, 16384, 1024 * 1024};  // Various input sizes

    uint8_t dummy_key[BLAKE3_KEY_LEN] = {0};
    uint8_t dummy_flags = KEYED_HASH;

    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t* b3p = b3p_create(&cfg);
    assert(b3p != NULL);

    for (size_t i = 0; i < sizeof(input_lens) / sizeof(input_lens[0]); i++) {
        size_t input_len = input_lens[i];
        uint8_t* input = malloc(input_len);
        if (input_len > 0) {
            generate_random_data(input, input_len);
        }

        for (size_t j = 0; j < sizeof(out_lens) / sizeof(out_lens[0]); j++) {
            size_t out_len = out_lens[j];

            uint8_t* expected = malloc(out_len);
            reference_blake3(input, input_len, dummy_key, 1, dummy_flags, expected, out_len, 0);

            uint8_t* actual = malloc(out_len);
            int rc = b3p_hash_one_shot(b3p, input, input_len, dummy_key, dummy_flags, B3P_METHOD_AUTO, actual, out_len);
            assert(rc == 0);

            if (memcmp(expected, actual, out_len) != 0) {
                printf("FAILED at input_len=%zu, out_len=%zu\n", input_len, out_len);
                printf("Expected: ");
                for (size_t k = 0; k < out_len; k++)
                    printf("%02x", expected[k]);
                printf("\nActual:   ");
                for (size_t k = 0; k < out_len; k++)
                    printf("%02x", actual[k]);
                printf("\n");
                assert(0);  // Force a crash to stop execution and see the output
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
    size_t input_len = 1024 * 1024;  // 1MB random input
    uint8_t* input = malloc(input_len);
    generate_random_data(input, input_len);

    uint8_t dummy_key[BLAKE3_KEY_LEN] = {0};
    uint8_t dummy_flags = KEYED_HASH;

    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t* b3p = b3p_create(&cfg);
    assert(b3p != NULL);

    for (size_t i = 0; i < sizeof(out_lens) / sizeof(out_lens[0]); i++) {
        size_t out_len = out_lens[i];
        for (size_t j = 0; j < sizeof(seeks) / sizeof(seeks[0]); j++) {
            uint64_t seek = seeks[j];

            uint8_t* expected = malloc(out_len);
            reference_blake3(input, input_len, dummy_key, 1, dummy_flags, expected, out_len, seek);

            uint8_t* actual = malloc(out_len);
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
    blake3_hasher_update(&hasher, NULL, 0);  // Empty input

    uint8_t out1[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, out1, BLAKE3_OUT_LEN);
    printf("Finalize hash (empty input): ");
    for (size_t k = 0; k < BLAKE3_OUT_LEN; k++)
        printf("%02x", out1[k]);
    printf("\n");

    uint8_t out2[BLAKE3_OUT_LEN];
    blake3_hasher_finalize_seek(&hasher, 0, out2, BLAKE3_OUT_LEN);

    if (memcmp(out1, out2, BLAKE3_OUT_LEN) != 0) {
        printf("FAILED\n");
        printf("Finalize:       ");
        for (size_t k = 0; k < BLAKE3_OUT_LEN; k++)
            printf("%02x", out1[k]);
        printf("\nFinalize_seek:  ");
        for (size_t k = 0; k < BLAKE3_OUT_LEN; k++)
            printf("%02x", out2[k]);
        printf("\n");
        assert(0);
    }
    printf("OK\n");
}

void add_len(size_t** lens, size_t* count, size_t* cap, size_t l) {
    if (*count == *cap) {
        *cap = *cap ? *cap * 2 : 256;
        *lens = realloc(*lens, *cap * sizeof(size_t));
    }
    (*lens)[(*count)++] = l;
}

void test_edge_cases(void) {
    printf("Testing edge cases...\n");
    size_t* lens = NULL;
    size_t count = 0;
    size_t cap = 0;

    // 1. Basic small cases
    add_len(&lens, &count, &cap, 0);
    add_len(&lens, &count, &cap, 1);

    // 2. Block boundaries
    add_len(&lens, &count, &cap, 63);
    add_len(&lens, &count, &cap, 64);
    add_len(&lens, &count, &cap, 65);

    // 3. Chunk boundaries
    add_len(&lens, &count, &cap, 1023);
    add_len(&lens, &count, &cap, 1024);
    add_len(&lens, &count, &cap, 1025);

    // 4. Two chunks
    add_len(&lens, &count, &cap, 2047);
    add_len(&lens, &count, &cap, 2048);
    add_len(&lens, &count, &cap, 2049);

    // 5. Multiples of chunks
    size_t n_values[] = {2, 3, 31, 32, 33, 63, 64, 65};
    for (size_t i = 0; i < sizeof(n_values) / sizeof(size_t); i++) {
        size_t n = n_values[i];
        size_t base = n * 1024;
        add_len(&lens, &count, &cap, base - 1);
        add_len(&lens, &count, &cap, base);
        add_len(&lens, &count, &cap, base + 1);
    }

    // 6. Batch step boundaries (Method A)
    size_t simd_degree = blake3_simd_degree();
    if (simd_degree > MAX_SIMD_DEGREE)
        simd_degree = MAX_SIMD_DEGREE;
    size_t batch_step_chunks = simd_degree * 64;
    size_t batch_step_bytes = batch_step_chunks * 1024;

    add_len(&lens, &count, &cap, batch_step_bytes - 1);
    add_len(&lens, &count, &cap, batch_step_bytes);
    add_len(&lens, &count, &cap, batch_step_bytes + 1);

    // Also test around num_chunks = multiple of batch_step.
    // Let's test 1x and 2x batch_step
    add_len(&lens, &count, &cap, (2 * batch_step_bytes) - 1);
    add_len(&lens, &count, &cap, (2 * batch_step_bytes));
    add_len(&lens, &count, &cap, (2 * batch_step_bytes) + 1);

    // 7. Subtree boundaries (Method B)
    size_t subtree_chunks = B3P_DEFAULT_SUBTREE_CHUNKS;
    size_t subtree_bytes = subtree_chunks * 1024;

    add_len(&lens, &count, &cap, subtree_bytes - 1);
    add_len(&lens, &count, &cap, subtree_bytes);
    add_len(&lens, &count, &cap, subtree_bytes + 1);

    add_len(&lens, &count, &cap, (2 * subtree_bytes) - 1);
    add_len(&lens, &count, &cap, (2 * subtree_bytes));
    add_len(&lens, &count, &cap, (2 * subtree_bytes) + 1);

    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = 4;
    b3p_ctx_t* b3p = b3p_create(&cfg);
    assert(b3p != NULL);

    for (size_t i = 0; i < count; i++) {
        verify_vector(b3p, lens[i]);
    }

    b3p_destroy(b3p);
    free(lens);
    printf("Edge cases OK\n");
}

int main(void) {
    srand(0);  // Seed random number generator for reproducible tests
    test_api_smoke();
    test_edge_cases();
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
    test_oneshot(8192, 1, BLAKE3_OUT_LEN);         // 8KB
    test_oneshot(8192 * 1024, 1, BLAKE3_OUT_LEN);  // 8MB (4 subtrees with 2MB chunks)

    // Test large files
    test_oneshot(16 * 1024 * 1024, 1, BLAKE3_OUT_LEN);  // 16MB serial
    test_oneshot(16 * 1024 * 1024, 4, BLAKE3_OUT_LEN);  // 16MB parallel (should use 8 subtrees -> 4 threads ok)

    // Test parallel
    test_oneshot(1024 * 1024, 2, BLAKE3_OUT_LEN);
    test_oneshot(10 * 1024 * 1024, 4, BLAKE3_OUT_LEN);
    test_oneshot(100 * 1024 * 1024, 8, BLAKE3_OUT_LEN);

    b3p_free_tls_resources();
    return 0;
}
