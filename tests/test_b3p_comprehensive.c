#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include "../src/blake3.h"
#include "../src/blake3_parallel.h"
#include "../src/blake3_impl.h"

#define ASSERT_EQ(a, b) assert((a) == (b))
#define ASSERT_NE(a, b) assert((a) != (b))

// --- Helpers ---

void get_std_key(uint8_t* key) {
    for (int k = 0; k < 8; k++)
        store32(key + k * 4, IV[k]);
}

void generate_random_data(uint8_t* buffer, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)rand();
    }
}

// Reference implementation wrapper
void reference_blake3(const uint8_t* input,
                      size_t input_len,
                      const uint8_t* key,
                      int mode,  // 0=hash, 1=keyed, 2=derive_key
                      const char* context,
                      uint8_t* out,
                      size_t out_len,
                      uint64_t seek) {
    blake3_hasher hasher;
    if (mode == 1) {
        blake3_hasher_init_keyed(&hasher, key);
    }
    else if (mode == 2) {
        blake3_hasher_init_derive_key(&hasher, context);
    }
    else {
        blake3_hasher_init(&hasher);
    }
    blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize_seek(&hasher, seek, out, out_len);
}

// Compare b3p output with reference
void check_vs_reference(const uint8_t* input, size_t input_len, const uint8_t* key, uint8_t flags, b3p_method_t method, int nthreads, uint64_t seek, size_t out_len, const char* test_name) {
    // Determine mode/key for reference based on flags
    int mode = 0;

    // Note: This mapping assumes flags passed to b3p match the intent.
    // If flags has KEYED_HASH, we use keyed mode.
    if (flags & KEYED_HASH) {
        mode = 1;
    }

    uint8_t* expected = malloc(out_len);
    uint8_t* actual = malloc(out_len);

    if ((flags & KEYED_HASH) || flags == 0) {
        reference_blake3(input, input_len, key, mode, NULL, expected, out_len, seek);
    }
    else {
        // Fallback: compare against serial b3p for non-standard flags
        b3p_hash_buffer_serial(input, input_len, key, flags, expected, out_len);  // This doesn't support seek...
        // If seek != 0 and exotic flags, we might skip reference check or implement a serial seeker.
        if (seek != 0) {
            // For now, skip exotic flags + seek reference check unless we build a full reference model.
            free(expected);
            free(actual);
            return;
        }
    }

    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = nthreads;
    b3p_ctx_t* ctx = b3p_create(&cfg);
    assert(ctx);

    if (seek == 0 && out_len == 32 && method == B3P_METHOD_AUTO) {
        // Use hash_one_shot for common case
        b3p_hash_one_shot(ctx, input, input_len, key, flags, method, actual, out_len);
    }
    else {
        b3p_hash_one_shot_seek(ctx, input, input_len, key, flags, method, seek, actual, out_len);
    }

    if (memcmp(expected, actual, out_len) != 0) {
        fprintf(stderr, "FAIL: %s (len=%zu, seek=%lu, out_len=%zu)\n", test_name, input_len, seek, out_len);
        exit(1);
    }

    b3p_destroy(ctx);
    free(expected);
    free(actual);
}

// --- Test Categories ---

void test_api_smoke(void) {
    printf("Test: API Smoke... ");

    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t* ctx = b3p_create(&cfg);
    ASSERT_NE(ctx, NULL);

    b3p_destroy(NULL);  // Safe

    uint8_t in[10] = {0};
    uint8_t out[32];
    memset(out, 0xAA, 32);
    uint8_t key[32] = {0};

    // out_len=0
    int rc = b3p_hash_one_shot(ctx, in, 10, key, 0, B3P_METHOD_AUTO, out, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(out[0], 0xAA);  // Untouched

    // NULL checks
    ASSERT_EQ(b3p_hash_one_shot_seek(NULL, in, 10, key, 0, 0, 0, out, 32), -1);
    ASSERT_EQ(b3p_hash_one_shot_seek(ctx, NULL, 10, key, 0, 0, 0, out, 32), -1);
    ASSERT_EQ(b3p_hash_one_shot_seek(ctx, in, 10, key, 0, 0, 0, NULL, 32), -1);

    b3p_destroy(ctx);
    printf("OK\n");
}

void test_determinism(void) {
    printf("Test: Determinism... ");
    size_t len = 1024 * 1024;
    uint8_t* input = malloc(len);
    generate_random_data(input, len);
    uint8_t key[32];
    generate_random_data(key, 32);

    uint8_t out1[32], out2[32];
    b3p_config_t cfg = b3p_config_default();

    // 1000 runs
    b3p_ctx_t* ctx = b3p_create(&cfg);
    b3p_hash_one_shot(ctx, input, len, key, KEYED_HASH, B3P_METHOD_AUTO, out1, 32);
    for (int i = 0; i < 1000; i++) {
        b3p_hash_one_shot(ctx, input, len, key, KEYED_HASH, B3P_METHOD_AUTO, out2, 32);
        ASSERT_EQ(memcmp(out1, out2, 32), 0);
    }

    // Thread counts
    size_t threads[] = {1, 2, 4, 8};
    for (int i = 0; i < 4; i++) {
        cfg.nthreads = threads[i];
        b3p_ctx_t* ctx2 = b3p_create(&cfg);
        b3p_hash_one_shot(ctx2, input, len, key, KEYED_HASH, B3P_METHOD_AUTO, out2, 32);
        ASSERT_EQ(memcmp(out1, out2, 32), 0);
        b3p_destroy(ctx2);
    }

    // Repeated create/destroy
    for (int i = 0; i < 50; i++) {
        b3p_ctx_t* ctx3 = b3p_create(&cfg);
        b3p_hash_one_shot(ctx3, input, len, key, KEYED_HASH, B3P_METHOD_AUTO, out2, 32);
        ASSERT_EQ(memcmp(out1, out2, 32), 0);
        b3p_destroy(ctx3);
    }

    b3p_destroy(ctx);
    free(input);
    printf("OK\n");
}

void test_correctness_vectors(void) {
    printf("Test: Correctness vs Reference... ");
    // Vectors implied by "input length edge cases"
    size_t lens[] = {0, 1, 63, 64, 65, 1023, 1024, 1025, 2047, 2048, 2049, (2 * 1024) - 1, 2 * 1024, (2 * 1024) + 1, (31 * 1024) - 1, 31 * 1024, (31 * 1024) + 1, (32 * 1024) - 1, 32 * 1024,
                     (32 * 1024) + 1, (33 * 1024) - 1, 33 * 1024, (33 * 1024) + 1, (64 * 1024) - 1, 64 * 1024, (64 * 1024) + 1,  // Batch boundaries
                     // Subtree boundaries (assuming 2048 chunks default)
                     (2048 * 1024) - 1, 2048 * 1024, (2048 * 1024) + 1};

    uint8_t key[32];
    generate_random_data(key, 32);

    uint8_t std_key[32];
    for (int k = 0; k < 8; k++)
        store32(std_key + k * 4, IV[k]);

    for (size_t i = 0; i < sizeof(lens) / sizeof(size_t); i++) {
        size_t l = lens[i];
        uint8_t* in = malloc(l ? l : 1);
        if (l)
            generate_random_data(in, l);

        // Hash one shot (Standard Hash uses IV)
        check_vs_reference(in, l, std_key, 0, B3P_METHOD_AUTO, 4, 0, 32, "Correctness Hash");

        // Keyed
        check_vs_reference(in, l, key, KEYED_HASH, B3P_METHOD_AUTO, 4, 0, 32, "Correctness Keyed");

        // Seek 0
        check_vs_reference(in, l, std_key, 0, B3P_METHOD_AUTO, 4, 0, 32, "Correctness Seek 0");

        // XOF / Seek variants
        size_t out_lens[] = {1, 32, 65, 1024};
        uint64_t seeks[] = {1, 63, 64, 1024};

        for (size_t j = 0; j < 4; j++) {
            for (size_t k = 0; k < 4; k++) {
                check_vs_reference(in, l, key, KEYED_HASH, B3P_METHOD_AUTO, 2, seeks[k], out_lens[j], "Correctness XOF");
            }
        }

        free(in);
    }
    printf("OK\n");
}

void test_flag_coverage(void) {
    printf("Test: Flag Coverage... ");
    size_t len = 4096;
    uint8_t* in = malloc(len);
    generate_random_data(in, len);
    uint8_t key[32];
    generate_random_data(key, 32);

    uint8_t std_key[32];
    get_std_key(std_key);

    // Flags=0
    check_vs_reference(in, len, std_key, 0, B3P_METHOD_AUTO, 2, 0, 32, "Flags=0");

    // Flags=KEYED_HASH
    check_vs_reference(in, len, key, KEYED_HASH, B3P_METHOD_AUTO, 2, 0, 32, "Flags=KEYED");

    // Random flags fuzz
    // We compare b3p parallel vs b3p serial for consistency on weird flags
    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = 4;
    b3p_ctx_t* ctx = b3p_create(&cfg);

    for (int i = 0; i < 20; i++) {
        uint8_t flags = (uint8_t)rand();
        uint8_t out_s[32], out_p[32];
        b3p_hash_buffer_serial(in, len, key, flags, out_s, 32);
        b3p_hash_one_shot(ctx, in, len, key, flags, B3P_METHOD_AUTO, out_p, 32);
        ASSERT_EQ(memcmp(out_s, out_p, 32), 0);
    }

    b3p_destroy(ctx);
    free(in);
    printf("OK\n");
}

void test_key_handling(void) {
    printf("Test: Key Handling... ");
    size_t len = 1024;
    uint8_t* in = malloc(len);
    generate_random_data(in, len);

    uint8_t keys[4][32];
    // All zero
    memset(keys[0], 0, 32);
    // All ones
    memset(keys[1], 0xFF, 32);
    // Incremental
    for (int i = 0; i < 32; i++)
        keys[2][i] = i;
    // Random
    generate_random_data(keys[3], 32);

    for (int i = 0; i < 4; i++) {
        check_vs_reference(in, len, keys[i], KEYED_HASH, B3P_METHOD_AUTO, 2, 0, 32, "Key Variant");
    }
    free(in);
    printf("OK\n");
}

void test_methods(void) {
    printf("Test: Methods... ");
    size_t len = 16 * 1024 * 1024;  // 16MB
    uint8_t* in = malloc(len);
    generate_random_data(in, len);
    uint8_t key[32];
    get_std_key(key);

    // Force A
    check_vs_reference(in, len, key, 0, B3P_METHOD_A_CHUNKS, 4, 0, 32, "Method A");

    // Force B
    check_vs_reference(in, len, key, 0, B3P_METHOD_B_SUBTREES, 4, 0, 32, "Method B");

    // Auto
    check_vs_reference(in, len, key, 0, B3P_METHOD_AUTO, 4, 0, 32, "Method Auto");

    // Check Auto matches Forced
    uint8_t out_a[32], out_b[32], out_auto[32];
    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = 4;
    b3p_ctx_t* ctx = b3p_create(&cfg);

    b3p_hash_one_shot(ctx, in, len, key, 0, B3P_METHOD_A_CHUNKS, out_a, 32);
    b3p_hash_one_shot(ctx, in, len, key, 0, B3P_METHOD_B_SUBTREES, out_b, 32);
    b3p_hash_one_shot(ctx, in, len, key, 0, B3P_METHOD_AUTO, out_auto, 32);

    ASSERT_EQ(memcmp(out_a, out_b, 32), 0);
    ASSERT_EQ(memcmp(out_a, out_auto, 32), 0);

    b3p_destroy(ctx);
    free(in);
    printf("OK\n");
}

void test_threading(void) {
    printf("Test: Threading Behaviors... ");
    size_t len = 2 * 1024 * 1024;
    uint8_t* in = malloc(len);
    generate_random_data(in, len);
    uint8_t key[32];
    get_std_key(key);

    size_t threads[] = {1, 2, 3, 4, 16};
    for (int i = 0; i < 5; i++) {
        check_vs_reference(in, len, key, 0, B3P_METHOD_AUTO, threads[i], 0, 32, "Threading");
    }

    // Threads > work items (tiny input)
    check_vs_reference(in, 10, key, 0, B3P_METHOD_AUTO, 32, 0, 32, "Oversubscribed");

    free(in);
    printf("OK\n");
}

void test_seek_xof(void) {
    printf("Test: Seek/XOF Semantics... ");
    size_t len = 1024;
    uint8_t* in = malloc(len);
    generate_random_data(in, len);
    uint8_t key[32];
    get_std_key(key);

    // 1. output(seek=0, out_len=L) == first L of output(seek=0, out_len=L+K)
    b3p_config_t cfg = b3p_config_default();
    b3p_ctx_t* ctx = b3p_create(&cfg);
    uint8_t out_short[32];
    uint8_t out_long[64];

    b3p_hash_one_shot_seek(ctx, in, len, key, 0, B3P_METHOD_AUTO, 0, out_short, 32);
    b3p_hash_one_shot_seek(ctx, in, len, key, 0, B3P_METHOD_AUTO, 0, out_long, 64);

    ASSERT_EQ(memcmp(out_short, out_long, 32), 0);

    // 2. output(seek=S, out_len=L) == slice [S:S+L) of output(seek=0, out_len=S+L)
    uint64_t S = 10;
    size_t L = 20;
    uint8_t out_seek[20];
    b3p_hash_one_shot_seek(ctx, in, len, key, 0, B3P_METHOD_AUTO, S, out_seek, L);
    ASSERT_EQ(memcmp(out_seek, out_long + S, L), 0);

    // Boundary seeks
    uint64_t seeks[] = {63, 64, 65, 1023, 1024, 1025, (1ULL << 20)};
    for (int i = 0; i < 7; i++) {
        check_vs_reference(in, len, key, 0, B3P_METHOD_AUTO, 2, seeks[i], 32, "Seek Boundary");
    }

    b3p_destroy(ctx);
    free(in);
    printf("OK\n");
}

void test_alignment(void) {
    printf("Test: Alignment... ");
    size_t alloc_len = 1024 + 64;
    uint8_t* buf = malloc(alloc_len);
    generate_random_data(buf, alloc_len);
    uint8_t key[32];
    get_std_key(key);

    // Try offsets 0..63
    for (int offset = 0; offset < 64; offset++) {
        check_vs_reference(buf + offset, 1024, key, 0, B3P_METHOD_AUTO, 2, 0, 32, "Aligned");
    }

    free(buf);
    printf("OK\n");
}

typedef struct {
    b3p_ctx_t* ctx;
    int id;
} stress_arg_t;

void* stress_thread(void* arg) {
    stress_arg_t* a = (stress_arg_t*)arg;
    unsigned int seed = (unsigned int)a->id;
    uint8_t key[32] = {0};
    uint8_t out[32];
    // Hash random sizes 0..1MB
    for (int i = 0; i < 50; i++) {
        size_t len = (size_t)rand_r(&seed) % (1024 * 1024);
        uint8_t* in = malloc(len ? len : 1);
        b3p_hash_one_shot(a->ctx, in, len, key, 0, B3P_METHOD_AUTO, out, 32);
        free(in);
    }
    b3p_free_tls_resources();
    return NULL;
}

void test_stress(void) {
    printf("Test: Stress/Concurrency... ");
    b3p_config_t cfg = b3p_config_default();
    cfg.nthreads = 4;

    // Run multiple application threads, each with OWN ctx
    const int APP_THREADS = 8;
    pthread_t th[APP_THREADS];
    stress_arg_t args[APP_THREADS];

    for (int i = 0; i < APP_THREADS; i++) {
        args[i].id = i;
        args[i].ctx = b3p_create(&cfg);
        pthread_create(&th[i], NULL, stress_thread, &args[i]);
    }

    for (int i = 0; i < APP_THREADS; i++) {
        pthread_join(th[i], NULL);
        b3p_destroy(args[i].ctx);
    }

    printf("OK\n");
}

int main(void) {
    srand(12345);
    test_api_smoke();
    test_determinism();
    test_correctness_vectors();
    test_flag_coverage();
    test_key_handling();
    test_methods();
    test_threading();
    test_seek_xof();
    test_alignment();
    test_stress();

    printf("ALL TESTS PASSED\n");
    return 0;
}
