#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/blake3.h"
#include "../src/blake3_parallel.h"

// Standard IV for BLAKE3
static const uint32_t IV[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};

void get_std_key(uint8_t* key) {
    for (int k = 0; k < 8; k++) {
        uint32_t w = IV[k];
        key[k * 4 + 0] = (uint8_t)(w >> 0);
        key[k * 4 + 1] = (uint8_t)(w >> 8);
        key[k * 4 + 2] = (uint8_t)(w >> 16);
        key[k * 4 + 3] = (uint8_t)(w >> 24);
    }
}

// Reference implementation
void reference_blake3(const uint8_t* input, size_t len, uint8_t* out) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, len);
    blake3_hasher_finalize(&hasher, out, BLAKE3_OUT_LEN);
}

void check_hash(const char* label, const uint8_t* input, size_t len, int threads, b3p_method_t method) {
    uint8_t key[32];
    get_std_key(key);

    uint8_t expected[BLAKE3_OUT_LEN];
    reference_blake3(input, len, expected);

    uint8_t actual[BLAKE3_OUT_LEN];
    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = threads;
    // Force parallel even for small inputs if we want to test logic
    cfg.min_parallel_bytes = 0;

    b3p_ctx_t* ctx = b3p_create(&cfg);
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        exit(1);
    }

    int rc = b3p_hash_one_shot(ctx, input, len, key, 0, method, actual, BLAKE3_OUT_LEN);
    b3p_destroy(ctx);

    if (rc != 0) {
        fprintf(stderr, "b3p_hash_one_shot failed\n");
        exit(1);
    }

    if (memcmp(expected, actual, BLAKE3_OUT_LEN) != 0) {
        fprintf(stderr, "FAIL: %s\n", label);
        fprintf(stderr, "Expected: ");
        for (int i = 0; i < 32; i++)
            fprintf(stderr, "%02x", expected[i]);
        fprintf(stderr, "\nActual:   ");
        for (int i = 0; i < 32; i++)
            fprintf(stderr, "%02x", actual[i]);
        fprintf(stderr, "\n");
        exit(1);
    }
    printf("PASS: %s\n", label);
}

int main(void) {
    printf("Running parallel edge case tests...\n");

    // 1. The 4MB Mixed Zero/Random Case
    // 2MB Zeros, 1MB Random, 1MB Zeros
    size_t size = 4 * 1024 * 1024;
    uint8_t* buf = calloc(1, size);  // calloc initializes to 0
    if (!buf) {
        perror("calloc");
        return 1;
    }

    // Fill 2MB-3MB with "random" data (deterministic pattern)
    for (size_t i = 2 * 1024 * 1024; i < 3 * 1024 * 1024; i++) {
        buf[i] = (uint8_t)((i * 12345 + 6789) & 0xFF);
    }

    // Check with Auto method (likely Subtrees for 4MB)
    check_hash("4MB Mixed (Auto, 4 threads)", buf, size, 4, B3P_METHOD_AUTO);

    // Check with explicitly Method B (Subtrees)
    check_hash("4MB Mixed (Subtrees, 4 threads)", buf, size, 4, B3P_METHOD_B_SUBTREES);

    // Check with Method A (Chunks)
    check_hash("4MB Mixed (Chunks, 4 threads)", buf, size, 4, B3P_METHOD_A_CHUNKS);

    // Check single threaded
    check_hash("4MB Mixed (1 thread)", buf, size, 1, B3P_METHOD_AUTO);

    // 2. Exact Chunk Boundary Transitions
    // Create a transition from 0 to random exactly at a subtree boundary (assuming 2048 chunks = 2MB)
    memset(buf, 0, size);
    // Fill exactly starting at 2MB
    for (size_t i = 2 * 1024 * 1024; i < size; i++) {
        buf[i] = 0xAA;
    }
    check_hash("4MB Half-Zero/Half-AA (Subtrees, 2 threads)", buf, size, 2, B3P_METHOD_B_SUBTREES);

    // 3. Sparse Holes
    // 1MB Data, 2MB Zero, 1MB Data
    memset(buf, 0xBB, size);
    memset(buf + 1024 * 1024, 0, 2 * 1024 * 1024);
    check_hash("4MB Hole (Subtrees, 4 threads)", buf, size, 4, B3P_METHOD_B_SUBTREES);

    free(buf);
    printf("All edge case tests passed.\n");
    return 0;
}
