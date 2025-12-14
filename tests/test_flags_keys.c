#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/blake3.h"
#include "../src/blake3_parallel.h"
#include "../src/blake3_impl.h"

void generate_random_data(uint8_t *buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)rand();
    }
}

// Compare parallel implementation against serial implementation (b3p_hash_buffer_serial)
// ensuring consistency regardless of flags or keys.
void verify_match(const uint8_t *input, size_t len, const uint8_t *key, uint8_t flags, const char *desc) {
    uint8_t out_serial[BLAKE3_OUT_LEN];
    uint8_t out_parallel[BLAKE3_OUT_LEN];
    
    // Serial (our reference for arbitrary flags)
    int rc1 = b3p_hash_buffer_serial(input, len, key, flags, out_serial, BLAKE3_OUT_LEN);
    assert(rc1 == 0);

    // Parallel
    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t *ctx = b3p_create(&cfg);
    assert(ctx != NULL);
    int rc2 = b3p_hash_one_shot(ctx, input, len, key, flags, B3P_METHOD_AUTO, out_parallel, BLAKE3_OUT_LEN);
    assert(rc2 == 0);
    b3p_destroy(ctx);

    if (memcmp(out_serial, out_parallel, BLAKE3_OUT_LEN) != 0) {
        printf("FAILED %s len=%zu\n", desc, len);
        exit(1);
    }
}

void test_chunk_shapes(void) {
    printf("Testing chunk shapes...\n");
    size_t lens[] = {1024, 1, 1023, 2048, 2047, 2049, (100*1024)+17};
    uint8_t key[BLAKE3_KEY_LEN] = {0};
    uint8_t *buf = malloc(200*1024); // Enough for largest
    
    for (size_t i=0; i<sizeof(lens)/sizeof(size_t); i++) {
        size_t l = lens[i];
        generate_random_data(buf, l);
        verify_match(buf, l, key, KEYED_HASH, "chunk_shape");
    }
    free(buf);
}

void test_flags(void) {
    printf("Testing flags...\n");
    size_t len = 1024 * 16;
    uint8_t *input = malloc(len);
    generate_random_data(input, len);
    uint8_t key[BLAKE3_KEY_LEN];
    generate_random_data(key, BLAKE3_KEY_LEN);

    // 1. flags=0
    verify_match(input, len, key, 0, "flags=0");

    // 2. flags=KEYED_HASH
    verify_match(input, len, key, KEYED_HASH, "flags=KEYED_HASH");

    // 3. flags=DERIVE_KEY_CONTEXT
    verify_match(input, len, key, DERIVE_KEY_CONTEXT, "flags=DERIVE_KEY_CONTEXT");

    // 4. flags=DERIVE_KEY_MATERIAL
    verify_match(input, len, key, DERIVE_KEY_MATERIAL, "flags=DERIVE_KEY_MATERIAL");

    // 5. Fuzz
    for (int i=0; i<50; i++) {
        uint8_t f = (uint8_t)rand();
        verify_match(input, len, key, f, "flags_fuzz");
    }
    free(input);
}

void test_keys(void) {
    printf("Testing keys...\n");
    size_t len = 1024 * 4;
    uint8_t *input = malloc(len);
    generate_random_data(input, len);
    uint8_t key[BLAKE3_KEY_LEN];

    // 1. All zero
    memset(key, 0, BLAKE3_KEY_LEN);
    verify_match(input, len, key, KEYED_HASH, "key_zero");

    // 2. All 0xFF
    memset(key, 0xFF, BLAKE3_KEY_LEN);
    verify_match(input, len, key, KEYED_HASH, "key_ff");

    // 3. Incremental
    for(int i=0; i<BLAKE3_KEY_LEN; i++) key[i] = (uint8_t)i;
    verify_match(input, len, key, KEYED_HASH, "key_incr");

    // 4. 100 random keys
    for(int i=0; i<100; i++) {
        generate_random_data(key, BLAKE3_KEY_LEN);
        verify_match(input, len, key, KEYED_HASH, "key_random");
    }
    free(input);
}

int main(void) {
    srand(12345);
    test_chunk_shapes();
    test_flags();
    test_keys();
    printf("All flags/keys tests passed\n");
    return 0;
}
