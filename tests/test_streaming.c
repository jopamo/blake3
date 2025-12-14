#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/blake3.h"

void test_streaming_consistency(size_t len) {
    // Generate random input
    uint8_t *input = malloc(len);
    for (size_t i = 0; i < len; i++) {
        input[i] = (uint8_t)(rand() % 256);
    }

    // Compute hash in one go
    blake3_hasher hasher_oneshot;
    blake3_hasher_init(&hasher_oneshot);
    blake3_hasher_update(&hasher_oneshot, input, len);
    uint8_t out_oneshot[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher_oneshot, out_oneshot, BLAKE3_OUT_LEN);

    // Compute hash in byte-sized chunks
    blake3_hasher hasher_byte;
    blake3_hasher_init(&hasher_byte);
    for (size_t i = 0; i < len; i++) {
        blake3_hasher_update(&hasher_byte, &input[i], 1);
    }
    uint8_t out_byte[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher_byte, out_byte, BLAKE3_OUT_LEN);

    assert(memcmp(out_oneshot, out_byte, BLAKE3_OUT_LEN) == 0);

    // Compute hash in random chunks
    blake3_hasher hasher_chunks;
    blake3_hasher_init(&hasher_chunks);
    size_t processed = 0;
    while (processed < len) {
        size_t remaining = len - processed;
        size_t chunk_size = (rand() % (remaining + 1)); // 0 to remaining
        if (chunk_size == 0 && remaining > 0) chunk_size = 1;
        
        blake3_hasher_update(&hasher_chunks, &input[processed], chunk_size);
        processed += chunk_size;
    }
    uint8_t out_chunks[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher_chunks, out_chunks, BLAKE3_OUT_LEN);

    assert(memcmp(out_oneshot, out_chunks, BLAKE3_OUT_LEN) == 0);

    free(input);
}

void test_seek_consistency(size_t len) {
     uint8_t *input = malloc(len);
    for (size_t i = 0; i < len; i++) {
        input[i] = (uint8_t)(rand() % 256);
    }

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, len);
    
    // Normal finalize gives first 32 bytes
    uint8_t out_normal[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, out_normal, BLAKE3_OUT_LEN);

    // Seek 0 should be same as normal
    uint8_t out_seek0[BLAKE3_OUT_LEN];
    blake3_hasher_finalize_seek(&hasher, 0, out_seek0, BLAKE3_OUT_LEN);

    assert(memcmp(out_normal, out_seek0, BLAKE3_OUT_LEN) == 0);

    // Test extended output
    uint8_t out_extended[64];
    blake3_hasher_finalize(&hasher, out_extended, 64);

    uint8_t out_seek_part2[32];
    blake3_hasher_finalize_seek(&hasher, 32, out_seek_part2, 32);

    assert(memcmp(out_extended + 32, out_seek_part2, 32) == 0);

    free(input);
}

int main(void) {
    srand(42);

    printf("Testing streaming consistency...\n");
    test_streaming_consistency(10);
    test_streaming_consistency(100);
    test_streaming_consistency(1024); // 1 block
    test_streaming_consistency(1025);
    test_streaming_consistency(2048);
    test_streaming_consistency(8192); // typical buffer size
    test_streaming_consistency(100000);

    printf("Testing seek consistency...\n");
    test_seek_consistency(100);

    printf("Streaming tests passed.\n");
    return 0;
}
