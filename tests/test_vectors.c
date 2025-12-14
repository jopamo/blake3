#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/blake3.h"

// Helper to convert hex string to bytes
void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

void check_vector(const void *input, size_t input_len, const char *expected_hex) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, input_len);
    
    uint8_t output[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);

    uint8_t expected[BLAKE3_OUT_LEN];
    hex_to_bytes(expected_hex, expected, BLAKE3_OUT_LEN);

    if (memcmp(output, expected, BLAKE3_OUT_LEN) != 0) {
        fprintf(stderr, "Vector test failed!\n");
        fprintf(stderr, "Input len: %zu\n", input_len);
        fprintf(stderr, "Expected: %s\n", expected_hex);
        fprintf(stderr, "Got:      ");
        for (int i = 0; i < BLAKE3_OUT_LEN; i++) fprintf(stderr, "%02x", output[i]);
        fprintf(stderr, "\n");
        exit(1);
    }
}

int main(void) {
    // Empty string
    check_vector("", 0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");

    // "abc"
    check_vector("abc", 3, "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");

    // "The quick brown fox jumps over the lazy dog"
    check_vector("The quick brown fox jumps over the lazy dog", 43, "2f1514181aadccd913abd94cfa592701a5686ab23f8df1dff1b74710febc6d4a");

    printf("Vector tests passed.\n");
    return 0;
}
