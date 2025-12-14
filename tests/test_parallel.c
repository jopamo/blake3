#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/blake3.h"
#include "../src/blake3_parallel.h"

// Simple portable BLAKE3 implementation for reference verification
void reference_blake3(const uint8_t *input, size_t input_len, uint8_t *out) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize(&hasher, out, BLAKE3_OUT_LEN);
}

void test_oneshot(size_t len, int nthreads) {
    printf("Testing len=%zu threads=%d... ", len, nthreads);
    
    uint8_t *input = malloc(len);
    if (len > 0) {
        // Deterministic pattern
        for (size_t i = 0; i < len; i++) {
            input[i] = (uint8_t)(i % 251);
        }
    }

    uint8_t expected[BLAKE3_OUT_LEN];
    reference_blake3(input, len, expected);

    uint8_t actual[BLAKE3_OUT_LEN];
    
    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = nthreads;
    b3p_ctx_t *b3p = b3p_create(&cfg);
    assert(b3p != NULL);

    // Using IV for standard hash
    uint32_t IV[8] = {0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL, 0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL};
    uint8_t iv_bytes[BLAKE3_KEY_LEN];
    for (size_t i = 0; i < 8; i++) {
        iv_bytes[i * 4 + 0] = (uint8_t)(IV[i] >> 0);
        iv_bytes[i * 4 + 1] = (uint8_t)(IV[i] >> 8);
        iv_bytes[i * 4 + 2] = (uint8_t)(IV[i] >> 16);
        iv_bytes[i * 4 + 3] = (uint8_t)(IV[i] >> 24);
    }

    int rc = b3p_hash_one_shot(b3p, input, len, iv_bytes, 0, B3P_METHOD_AUTO, actual, BLAKE3_OUT_LEN);
    assert(rc == 0);

    b3p_destroy(b3p);
    free(input);

    if (memcmp(expected, actual, BLAKE3_OUT_LEN) != 0) {
        printf("FAILED\n");
        printf("Expected: ");
        for(int i=0;i<BLAKE3_OUT_LEN;i++) printf("%02x", expected[i]);
        printf("\nActual:   ");
        for(int i=0;i<BLAKE3_OUT_LEN;i++) printf("%02x", actual[i]);
        printf("\n");
        exit(1);
    }
    printf("OK\n");
}

int main(void) {
    // Test small files (serial path)
    test_oneshot(0, 1);
    test_oneshot(1, 1);
    test_oneshot(1024, 1);
    test_oneshot(2000, 1);
    
    // Test medium files (boundary of chunking)
    test_oneshot(8192, 1); // 8KB
    test_oneshot(8192 * 1024, 1); // 8MB (4 subtrees with 2MB chunks)

    // Test large files
    test_oneshot(16 * 1024 * 1024, 1); // 16MB serial
    test_oneshot(16 * 1024 * 1024, 4); // 16MB parallel (should use 8 subtrees -> 4 threads ok)

    // Test parallel
    test_oneshot(1024 * 1024, 2);
    test_oneshot(10 * 1024 * 1024, 4);
    test_oneshot(100 * 1024 * 1024, 8);

    return 0;
}
