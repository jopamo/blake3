#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../src/blake3.h"

int main(void) {
    uint8_t key[BLAKE3_KEY_LEN];
    for (int i=0; i<BLAKE3_KEY_LEN; i++) key[i] = (uint8_t)i;

    uint8_t input[] = "hello world";
    
    // Test 1: Keyed hashing determinism
    blake3_hasher h1, h2;
    uint8_t out1[BLAKE3_OUT_LEN], out2[BLAKE3_OUT_LEN];

    blake3_hasher_init_keyed(&h1, key);
    blake3_hasher_update(&h1, input, sizeof(input));
    blake3_hasher_finalize(&h1, out1, BLAKE3_OUT_LEN);

    blake3_hasher_init_keyed(&h2, key);
    blake3_hasher_update(&h2, input, sizeof(input));
    blake3_hasher_finalize(&h2, out2, BLAKE3_OUT_LEN);

    assert(memcmp(out1, out2, BLAKE3_OUT_LEN) == 0);

    // Test 2: Different keys -> Different output
    uint8_t key_mod[BLAKE3_KEY_LEN];
    memcpy(key_mod, key, BLAKE3_KEY_LEN);
    key_mod[0] ^= 1;

    blake3_hasher h3;
    uint8_t out3[BLAKE3_OUT_LEN];
    blake3_hasher_init_keyed(&h3, key_mod);
    blake3_hasher_update(&h3, input, sizeof(input));
    blake3_hasher_finalize(&h3, out3, BLAKE3_OUT_LEN);

    assert(memcmp(out1, out3, BLAKE3_OUT_LEN) != 0);

    // Test 3: Key derivation determinism
    const char *ctx = "test context";
    blake3_hasher hd1, hd2;
    uint8_t outd1[BLAKE3_OUT_LEN], outd2[BLAKE3_OUT_LEN];

    blake3_hasher_init_derive_key(&hd1, ctx);
    blake3_hasher_update(&hd1, input, sizeof(input));
    blake3_hasher_finalize(&hd1, outd1, BLAKE3_OUT_LEN);

    blake3_hasher_init_derive_key(&hd2, ctx);
    blake3_hasher_update(&hd2, input, sizeof(input));
    blake3_hasher_finalize(&hd2, outd2, BLAKE3_OUT_LEN);

    assert(memcmp(outd1, outd2, BLAKE3_OUT_LEN) == 0);

    // Test 4: Different context -> Different output
    blake3_hasher hd3;
    uint8_t outd3[BLAKE3_OUT_LEN];
    blake3_hasher_init_derive_key(&hd3, "different context");
    blake3_hasher_update(&hd3, input, sizeof(input));
    blake3_hasher_finalize(&hd3, outd3, BLAKE3_OUT_LEN);

    assert(memcmp(outd1, outd3, BLAKE3_OUT_LEN) != 0);

    // Test 5: init_derive_key vs init_derive_key_raw
    blake3_hasher hd_raw;
    uint8_t out_raw[BLAKE3_OUT_LEN];
    blake3_hasher_init_derive_key_raw(&hd_raw, ctx, strlen(ctx));
    blake3_hasher_update(&hd_raw, input, sizeof(input));
    blake3_hasher_finalize(&hd_raw, out_raw, BLAKE3_OUT_LEN);

    assert(memcmp(outd1, out_raw, BLAKE3_OUT_LEN) == 0);

    // Test 6: Reset
    blake3_hasher_reset(&h1);
    // After reset, it should behave like standard init (no key)
    // Wait, documentation says: "Reset the hasher to its initial state."
    // Does that mean "initial state OF THIS INSTANCE" (retaining key) or "default state" (unkeyed)?
    // Usually it means "reset to state after init". 
    // Let's verify this assumption. If it's wrong, we'll fix the test.
    // Actually, looking at blake3.c would verify this.
    // But logically, reset should clear accumulated data but keep configuration (key/iv). 
    
    // Let's re-hash the same input with h1 (keyed)
    blake3_hasher_update(&h1, input, sizeof(input));
    uint8_t out1_reset[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&h1, out1_reset, BLAKE3_OUT_LEN);

    assert(memcmp(out1, out1_reset, BLAKE3_OUT_LEN) == 0);

    printf("Keyed/Derive tests passed.\n");
    return 0;
}
