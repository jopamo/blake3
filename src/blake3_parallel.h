/* src/blake3_parallel.h
 * Internal header for parallel hashing
 */

#ifndef BLAKE3_PARALLEL_H
#define BLAKE3_PARALLEL_H

#include "blake3.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define B3P_DEFAULT_SUBTREE_CHUNKS 512

typedef enum { B3P_METHOD_AUTO = 0, B3P_METHOD_A_CHUNKS = 1, B3P_METHOD_B_SUBTREES = 2 } b3p_method_t;

typedef struct b3p_ctx b3p_ctx_t;

typedef struct {
    size_t nthreads;
    size_t min_parallel_bytes;
    size_t method_a_min_chunks;
    size_t method_b_min_chunks_per_thread;
    size_t subtree_chunks;
    int autotune_enable;
    uint32_t autotune_sample_mask;
} b3p_config_t;

BLAKE3_API b3p_config_t b3p_config_default(void);

BLAKE3_API b3p_ctx_t* b3p_create(const b3p_config_t* cfg);
BLAKE3_API void b3p_destroy(b3p_ctx_t* ctx);

BLAKE3_API int b3p_hash_one_shot(b3p_ctx_t* ctx, const uint8_t* input, size_t input_len, const uint8_t key[BLAKE3_KEY_LEN], uint8_t flags, b3p_method_t method, uint8_t* out, size_t out_len);

BLAKE3_API int
b3p_hash_one_shot_seek(b3p_ctx_t* ctx, const uint8_t* input, size_t input_len, const uint8_t key[BLAKE3_KEY_LEN], uint8_t flags, b3p_method_t method, uint64_t seek, uint8_t* out, size_t out_len);

BLAKE3_API int b3p_hash_buffer_serial(const uint8_t* input, size_t input_len, const uint8_t key[BLAKE3_KEY_LEN], uint8_t flags, uint8_t* out, size_t out_len);

BLAKE3_API void b3p_free_tls_resources(void);

#ifdef __cplusplus
}
#endif

#endif /* BLAKE3_PARALLEL_H */