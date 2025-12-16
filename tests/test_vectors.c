#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/blake3.h"

// Official BLAKE3 Test Vectors parameters
static const uint8_t KEY[BLAKE3_KEY_LEN] = "whats the Elvish word for friend";
static const char* CONTEXT = "BLAKE3 2019-12-27 16:29:52 test vectors context";

typedef struct {
    size_t input_len;
    const char* hash;
    const char* keyed_hash;
    const char* derive_key;
} test_case;

static const test_case CASES[] = {{0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
                                   "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"},
                                  {1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213", "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
                                   "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"},
                                  {2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63", "5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a9",
                                   "1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6"},
                                  {3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f", "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9",
                                   "440aba35cb006b61fc17c0529255de438efc06a8c9ebf3f2ddac3b5a86705797"},
                                  {4, "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32", "7671dde590c95d5ac9616651ff5aa0a27bee5913a348e053b8aa9108917fe070",
                                   "f46085c8190d69022369ce1a18880e9b369c135eb93f3c63550d3e7630e91060"},
                                  {64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98", "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6",
                                   "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e9"},
                                  {1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11", "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e",
                                   "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea59"}};

void hex_to_bytes(const char* hex, uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int v;
        sscanf(hex + 2 * i, "%2x", &v);
        bytes[i] = (uint8_t)v;
    }
}

void fill_input(uint8_t* input, size_t len) {
    for (size_t i = 0; i < len; i++) {
        input[i] = (uint8_t)(i % 251);
    }
}

void check_mode(const char* mode_name,
                const uint8_t* input,
                size_t len,
                const char* expected_hex,
                void (*init_fn)(blake3_hasher*),
                void (*init_keyed_fn)(blake3_hasher*, const uint8_t*),
                void (*init_derive_fn)(blake3_hasher*, const char*)) {
    blake3_hasher hasher;
    if (init_fn) {
        init_fn(&hasher);
    }
    else if (init_keyed_fn) {
        init_keyed_fn(&hasher, KEY);
    }
    else if (init_derive_fn) {
        init_derive_fn(&hasher, CONTEXT);
    }

    blake3_hasher_update(&hasher, input, len);
    uint8_t output[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);

    uint8_t expected[BLAKE3_OUT_LEN];
    hex_to_bytes(expected_hex, expected, BLAKE3_OUT_LEN);

    if (memcmp(output, expected, BLAKE3_OUT_LEN) != 0) {
        fprintf(stderr, "FAILED: %s (len=%zu)\n", mode_name, len);
        fprintf(stderr, "Expected: %s\n", expected_hex);
        fprintf(stderr, "Got:      ");
        for (int i = 0; i < BLAKE3_OUT_LEN; i++)
            fprintf(stderr, "%02x", output[i]);
        fprintf(stderr, "\n");
        exit(1);
    }
}

int main(void) {
    printf("Running official BLAKE3 test vectors...\n");

    for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++) {
        size_t len = CASES[i].input_len;
        uint8_t* input = malloc(len ? len : 1);  // Avoid malloc(0)
        fill_input(input, len);

        // Standard Hash
        check_mode("Hash", input, len, CASES[i].hash, blake3_hasher_init, NULL, NULL);

        // Keyed Hash
        check_mode("Keyed", input, len, CASES[i].keyed_hash, NULL, blake3_hasher_init_keyed, NULL);

        // Derive Key
        check_mode("Derive", input, len, CASES[i].derive_key, NULL, NULL, blake3_hasher_init_derive_key);

        free(input);
    }

    printf("All official vectors passed.\n");
    return 0;
}