#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/blake3.h"
#include "../src/blake3_impl.h"
#include "../src/blake3_parallel.h"

static void fill_pattern(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)((i * 131u + 17u) & 0xFFu);
    }
}

static void fill_key(uint8_t key[BLAKE3_KEY_LEN]) {
    for (size_t i = 0; i < BLAKE3_KEY_LEN; i++) {
        key[i] = (uint8_t)(0xA0u + i);
    }
}

static void fill_iv_bytes(uint8_t out[BLAKE3_KEY_LEN]) {
    for (size_t i = 0; i < 8; i++) {
        store32(out + (i * 4), IV[i]);
    }
}

static void expect_equal(const uint8_t* a, const uint8_t* b, size_t len, const char* label) {
    if (memcmp(a, b, len) != 0) {
        fprintf(stderr, "Mismatch: %s\n", label);
        exit(1);
    }
}

static void ref_unkeyed_seek(const uint8_t* input, size_t input_len, uint64_t seek, uint8_t* out, size_t out_len) {
    blake3_hasher hasher;
    const uint8_t* in = input_len ? input : (const uint8_t*)"";
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, in, input_len);
    blake3_hasher_finalize_seek(&hasher, seek, out, out_len);
}

static void ref_keyed_seek(const uint8_t* input, size_t input_len, const uint8_t key[BLAKE3_KEY_LEN], uint64_t seek, uint8_t* out, size_t out_len) {
    blake3_hasher hasher;
    const uint8_t* in = input_len ? input : (const uint8_t*)"";
    blake3_hasher_init_keyed(&hasher, key);
    blake3_hasher_update(&hasher, in, input_len);
    blake3_hasher_finalize_seek(&hasher, seek, out, out_len);
}

static void ref_derive_seek(const uint8_t* input, size_t input_len, const void* context, size_t context_len, uint64_t seek, uint8_t* out, size_t out_len) {
    blake3_hasher hasher;
    const uint8_t* in = input_len ? input : (const uint8_t*)"";
    const void* ctx = context_len ? context : "";
    blake3_hasher_init_derive_key_raw(&hasher, ctx, context_len);
    blake3_hasher_update(&hasher, in, input_len);
    blake3_hasher_finalize_seek(&hasher, seek, out, out_len);
}

static void test_null_zero_contracts(void) {
    uint8_t key[BLAKE3_KEY_LEN];
    uint8_t iv[BLAKE3_KEY_LEN];
    b3p_ctx_t* ctx = b3p_create(NULL);
    assert(ctx != NULL);

    fill_key(key);
    fill_iv_bytes(iv);

    assert(b3p_hash_unkeyed(ctx, NULL, 0, B3P_METHOD_AUTO, NULL, 0) == 0);
    assert(b3p_hash_unkeyed_seek(ctx, NULL, 0, B3P_METHOD_AUTO, 7, NULL, 0) == 0);
    assert(b3p_hash_keyed(ctx, NULL, 0, key, B3P_METHOD_AUTO, NULL, 0) == 0);
    assert(b3p_hash_keyed_seek(ctx, NULL, 0, key, B3P_METHOD_AUTO, 11, NULL, 0) == 0);
    assert(b3p_hash_derive(ctx, NULL, 0, NULL, 0, B3P_METHOD_AUTO, NULL, 0) == 0);
    assert(b3p_hash_derive_seek(ctx, NULL, 0, NULL, 0, B3P_METHOD_AUTO, 3, NULL, 0) == 0);

    assert(b3p_hash_unkeyed_buffer_serial(NULL, 0, NULL, 0) == 0);
    assert(b3p_hash_keyed_buffer_serial(NULL, 0, key, NULL, 0) == 0);
    assert(b3p_hash_derive_buffer_serial(NULL, 0, NULL, 0, NULL, 0) == 0);

    assert(b3p_hash_raw_cv_one_shot(ctx, NULL, 0, iv, 0, B3P_METHOD_AUTO, NULL, 0) == 0);
    assert(b3p_hash_raw_cv_one_shot_seek(ctx, NULL, 0, iv, 0, B3P_METHOD_AUTO, 5, NULL, 0) == 0);
    assert(b3p_hash_raw_cv_buffer_serial(NULL, 0, iv, 0, NULL, 0) == 0);

    assert(b3p_init_derive(NULL, 0, key) == 0);
    assert(b3p_init_derive(NULL, 1, key) == -1);

    assert(b3p_hash_unkeyed(ctx, NULL, 1, B3P_METHOD_AUTO, key, BLAKE3_OUT_LEN) == -1);
    assert(b3p_hash_keyed(ctx, NULL, 1, key, B3P_METHOD_AUTO, key, BLAKE3_OUT_LEN) == -1);
    assert(b3p_hash_derive(ctx, NULL, 1, NULL, 0, B3P_METHOD_AUTO, key, BLAKE3_OUT_LEN) == -1);
    assert(b3p_hash_raw_cv_one_shot(ctx, NULL, 1, iv, 0, B3P_METHOD_AUTO, key, BLAKE3_OUT_LEN) == -1);

    b3p_destroy(ctx);
}

static void test_unkeyed_and_keyed_equivalence(void) {
    const size_t lens[] = {0, 1, 63, 64, 65, 1024, 4097};
    const uint64_t seeks[] = {0, 1, 64, 1024};
    const size_t out_lens[] = {32, 96};
    uint8_t key[BLAKE3_KEY_LEN];

    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = 4;
    cfg.min_parallel_bytes = 0;
    b3p_ctx_t* ctx = b3p_create(&cfg);
    assert(ctx != NULL);

    fill_key(key);

    for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        const size_t len = lens[i];
        uint8_t* input = (uint8_t*)malloc(len ? len : 1);
        assert(input != NULL);
        fill_pattern(input, len);
        const uint8_t* in_ptr = len ? input : NULL;

        for (size_t j = 0; j < sizeof(seeks) / sizeof(seeks[0]); j++) {
            for (size_t k = 0; k < sizeof(out_lens) / sizeof(out_lens[0]); k++) {
                uint8_t expected[96];
                uint8_t got[96];
                const uint64_t seek = seeks[j];
                const size_t out_len = out_lens[k];

                ref_unkeyed_seek(in_ptr, len, seek, expected, out_len);
                assert(b3p_hash_unkeyed_seek(ctx, in_ptr, len, B3P_METHOD_AUTO, seek, got, out_len) == 0);
                expect_equal(expected, got, out_len, "b3p_hash_unkeyed_seek vs blake3_hasher");

                ref_keyed_seek(in_ptr, len, key, seek, expected, out_len);
                assert(b3p_hash_keyed_seek(ctx, in_ptr, len, key, B3P_METHOD_AUTO, seek, got, out_len) == 0);
                expect_equal(expected, got, out_len, "b3p_hash_keyed_seek vs blake3_hasher");
            }
        }

        {
            uint8_t expected[32];
            uint8_t got[32];

            ref_unkeyed_seek(in_ptr, len, 0, expected, sizeof(expected));
            assert(b3p_hash_unkeyed(ctx, in_ptr, len, B3P_METHOD_AUTO, got, sizeof(got)) == 0);
            expect_equal(expected, got, sizeof(got), "b3p_hash_unkeyed vs blake3_hasher");

            assert(b3p_hash_unkeyed_buffer_serial(in_ptr, len, got, sizeof(got)) == 0);
            expect_equal(expected, got, sizeof(got), "b3p_hash_unkeyed_buffer_serial vs blake3_hasher");

            ref_keyed_seek(in_ptr, len, key, 0, expected, sizeof(expected));
            assert(b3p_hash_keyed(ctx, in_ptr, len, key, B3P_METHOD_AUTO, got, sizeof(got)) == 0);
            expect_equal(expected, got, sizeof(got), "b3p_hash_keyed vs blake3_hasher");

            assert(b3p_hash_keyed_buffer_serial(in_ptr, len, key, got, sizeof(got)) == 0);
            expect_equal(expected, got, sizeof(got), "b3p_hash_keyed_buffer_serial vs blake3_hasher");
        }

        free(input);
    }

    b3p_destroy(ctx);
}

static void test_raw_safe_mapping_equivalence(void) {
    const size_t lens[] = {0, 17, 1024, 1025, 65537};
    const uint64_t seeks[] = {0, 1, 63, 4096};
    const size_t out_lens[] = {32, 64};
    const b3p_method_t methods[] = {B3P_METHOD_AUTO, B3P_METHOD_A_CHUNKS, B3P_METHOD_B_SUBTREES};
    uint8_t key[BLAKE3_KEY_LEN];
    uint8_t iv[BLAKE3_KEY_LEN];

    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = 4;
    cfg.min_parallel_bytes = 0;
    b3p_ctx_t* ctx = b3p_create(&cfg);
    assert(ctx != NULL);

    fill_key(key);
    fill_iv_bytes(iv);

    for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        const size_t len = lens[i];
        uint8_t* input = (uint8_t*)malloc(len ? len : 1);
        assert(input != NULL);
        fill_pattern(input, len);
        const uint8_t* in_ptr = len ? input : NULL;

        for (size_t m = 0; m < sizeof(methods) / sizeof(methods[0]); m++) {
            for (size_t j = 0; j < sizeof(seeks) / sizeof(seeks[0]); j++) {
                for (size_t k = 0; k < sizeof(out_lens) / sizeof(out_lens[0]); k++) {
                    uint8_t safe[64];
                    uint8_t raw[64];
                    const uint64_t seek = seeks[j];
                    const size_t out_len = out_lens[k];
                    const b3p_method_t method = methods[m];

                    assert(b3p_hash_unkeyed_seek(ctx, in_ptr, len, method, seek, safe, out_len) == 0);
                    assert(b3p_hash_raw_cv_one_shot_seek(ctx, in_ptr, len, iv, 0, method, seek, raw, out_len) == 0);
                    expect_equal(safe, raw, out_len, "unkeyed safe/raw mapping");

                    assert(b3p_hash_keyed_seek(ctx, in_ptr, len, key, method, seek, safe, out_len) == 0);
                    assert(b3p_hash_raw_cv_one_shot_seek(ctx, in_ptr, len, key, B3P_FLAG_KEYED_HASH, method, seek, raw, out_len) == 0);
                    expect_equal(safe, raw, out_len, "keyed safe/raw mapping");
                }
            }
        }

        {
            uint8_t safe[32];
            uint8_t raw[32];

            assert(b3p_hash_unkeyed_buffer_serial(in_ptr, len, safe, sizeof(safe)) == 0);
            assert(b3p_hash_raw_cv_buffer_serial(in_ptr, len, iv, 0, raw, sizeof(raw)) == 0);
            expect_equal(safe, raw, sizeof(safe), "unkeyed serial safe/raw mapping");

            assert(b3p_hash_keyed_buffer_serial(in_ptr, len, key, safe, sizeof(safe)) == 0);
            assert(b3p_hash_raw_cv_buffer_serial(in_ptr, len, key, B3P_FLAG_KEYED_HASH, raw, sizeof(raw)) == 0);
            expect_equal(safe, raw, sizeof(safe), "keyed serial safe/raw mapping");
        }

        free(input);
    }

    b3p_destroy(ctx);
}

static void test_derive_mode_contracts(void) {
    const size_t lens[] = {0, 1, 65, 1024, 8193};
    const uint64_t seeks[] = {0, 1, 64, 512};
    const size_t out_lens[] = {32, 96};
    const uint8_t context[] = {0x62, 0x33, 0x70, 0x00, 0x63, 0x74, 0x78};
    uint8_t context_key[BLAKE3_KEY_LEN];

    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = 4;
    cfg.min_parallel_bytes = 0;
    b3p_ctx_t* ctx = b3p_create(&cfg);
    assert(ctx != NULL);

    assert(b3p_init_derive(context, sizeof(context), context_key) == 0);

    for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        const size_t len = lens[i];
        uint8_t* input = (uint8_t*)malloc(len ? len : 1);
        assert(input != NULL);
        fill_pattern(input, len);
        const uint8_t* in_ptr = len ? input : NULL;

        for (size_t j = 0; j < sizeof(seeks) / sizeof(seeks[0]); j++) {
            for (size_t k = 0; k < sizeof(out_lens) / sizeof(out_lens[0]); k++) {
                uint8_t expected[96];
                uint8_t safe[96];
                uint8_t raw[96];
                const uint64_t seek = seeks[j];
                const size_t out_len = out_lens[k];

                ref_derive_seek(in_ptr, len, context, sizeof(context), seek, expected, out_len);
                assert(b3p_hash_derive_seek(ctx, in_ptr, len, context, sizeof(context), B3P_METHOD_AUTO, seek, safe, out_len) == 0);
                expect_equal(expected, safe, out_len, "b3p_hash_derive_seek vs blake3_hasher");

                assert(b3p_hash_raw_cv_one_shot_seek(ctx, in_ptr, len, context_key, B3P_FLAG_DERIVE_KEY_MATERIAL, B3P_METHOD_AUTO, seek, raw, out_len) == 0);
                expect_equal(safe, raw, out_len, "derive safe/raw mapping");
            }
        }

        {
            uint8_t expected[32];
            uint8_t safe[32];
            uint8_t raw[32];

            ref_derive_seek(in_ptr, len, context, sizeof(context), 0, expected, sizeof(expected));

            assert(b3p_hash_derive(ctx, in_ptr, len, context, sizeof(context), B3P_METHOD_AUTO, safe, sizeof(safe)) == 0);
            expect_equal(expected, safe, sizeof(safe), "b3p_hash_derive vs blake3_hasher");

            assert(b3p_hash_derive_buffer_serial(in_ptr, len, context, sizeof(context), safe, sizeof(safe)) == 0);
            expect_equal(expected, safe, sizeof(safe), "b3p_hash_derive_buffer_serial vs blake3_hasher");

            assert(b3p_hash_raw_cv_buffer_serial(in_ptr, len, context_key, B3P_FLAG_DERIVE_KEY_MATERIAL, raw, sizeof(raw)) == 0);
            expect_equal(expected, raw, sizeof(raw), "derive serial safe/raw mapping");
        }

        free(input);
    }

    b3p_destroy(ctx);
}

int main(void) {
    test_null_zero_contracts();
    test_unkeyed_and_keyed_equivalence();
    test_raw_safe_mapping_equivalence();
    test_derive_mode_contracts();
    printf("All parallel safe contract tests passed\n");
    return 0;
}
