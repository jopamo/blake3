#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "../src/blake3.h"
#include "../src/blake3_parallel.h"
#include "../src/blake3_impl.h"

void generate_random_data(uint8_t *buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)rand();
    }
}

void reference_blake3(const uint8_t *input, size_t input_len, const uint8_t *key, int is_keyed, uint8_t flags, uint8_t *out, size_t out_len) {
    blake3_hasher hasher;
    if (is_keyed) {
        blake3_hasher_init_keyed(&hasher, key);
    } else {
        blake3_hasher_init(&hasher);
    }
    blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize(&hasher, out, out_len);
}

void verify_correctness(b3p_ctx_t *ctx, const uint8_t *input, size_t len, const char *desc) {
    uint8_t key[BLAKE3_KEY_LEN] = {0};
    uint8_t out_ref[BLAKE3_OUT_LEN];
    uint8_t out_test[BLAKE3_OUT_LEN];

    // Use keyed mode to ensure consistent key usage (Zero Key)
    reference_blake3(input, len, key, 1, KEYED_HASH, out_ref, BLAKE3_OUT_LEN);
    int rc = b3p_hash_one_shot(ctx, input, len, key, KEYED_HASH, B3P_METHOD_AUTO, out_test, BLAKE3_OUT_LEN);
    assert(rc == 0);

    if (memcmp(out_ref, out_test, BLAKE3_OUT_LEN) != 0) {
        fprintf(stderr, "FAILED: %s (len=%zu)\n", desc, len);
        exit(1);
    }
}

void test_regression_vectors(void) {
    printf("Testing regression vectors...\n");
    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = 4;
    b3p_ctx_t *ctx = b3p_create(&cfg);
    assert(ctx != NULL);

    size_t chunk = BLAKE3_CHUNK_LEN; // 1024
    size_t subtree_chunks = B3P_DEFAULT_SUBTREE_CHUNKS; // 2048
    
    // 16 MiB = 16 * 1024 * 1024
    size_t len_16mib = 16 * 1024 * 1024;
    size_t max_test_len = len_16mib + 2 * 1024 * 1024; // enough buffer
    uint8_t *input = malloc(max_test_len);
    generate_random_data(input, max_test_len);

    // 1. 16 MiB exact
    verify_correctness(ctx, input, len_16mib, "16 MiB exact");

    // 2. 16 MiB ± 1 KiB
    verify_correctness(ctx, input, len_16mib - 1024, "16 MiB - 1 KiB");
    verify_correctness(ctx, input, len_16mib + 1024, "16 MiB + 1 KiB");

    // 3. 16 MiB ± 32 KiB
    verify_correctness(ctx, input, len_16mib - 32*1024, "16 MiB - 32 KiB");
    verify_correctness(ctx, input, len_16mib + 32*1024, "16 MiB + 32 KiB");

    // 4. 16 MiB ± subtree (2 MiB)
    size_t subtree_bytes = subtree_chunks * chunk;
    verify_correctness(ctx, input, len_16mib - subtree_bytes, "16 MiB - subtree");
    verify_correctness(ctx, input, len_16mib + subtree_bytes, "16 MiB + subtree");

    b3p_destroy(ctx);
    free(input);
    printf("OK\n");
}

int main(void) {
    srand(42);
    test_regression_vectors();
    return 0;
}
