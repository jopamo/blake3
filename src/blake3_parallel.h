/* src/blake3_parallel.h
 * Public header for parallel hashing APIs
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

/* Public raw flag type for expert APIs. */
typedef uint32_t b3p_flags_t;

enum b3p_flag_bits {
    B3P_FLAG_CHUNK_START = 1u << 0,
    B3P_FLAG_CHUNK_END = 1u << 1,
    B3P_FLAG_PARENT = 1u << 2,
    B3P_FLAG_ROOT = 1u << 3,
    B3P_FLAG_KEYED_HASH = 1u << 4,
    B3P_FLAG_DERIVE_KEY_CONTEXT = 1u << 5,
    B3P_FLAG_DERIVE_KEY_MATERIAL = 1u << 6,
};

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

/* Safe public one-shot APIs (recommended). */
/* Standard BLAKE3 hash mode. */
BLAKE3_API int b3p_hash_unkeyed(b3p_ctx_t* ctx, const uint8_t* input, size_t input_len, b3p_method_t method, uint8_t* out, size_t out_len);
BLAKE3_API int b3p_hash_unkeyed_seek(b3p_ctx_t* ctx, const uint8_t* input, size_t input_len, b3p_method_t method, uint64_t seek, uint8_t* out, size_t out_len);

/* BLAKE3 keyed hash mode. */
BLAKE3_API int b3p_hash_keyed(b3p_ctx_t* ctx, const uint8_t* input, size_t input_len, const uint8_t key[BLAKE3_KEY_LEN], b3p_method_t method, uint8_t* out, size_t out_len);
BLAKE3_API int b3p_hash_keyed_seek(b3p_ctx_t* ctx, const uint8_t* input, size_t input_len, const uint8_t key[BLAKE3_KEY_LEN], b3p_method_t method, uint64_t seek, uint8_t* out, size_t out_len);

/* BLAKE3 derive-key mode.
 * b3p_init_derive computes the context key from (context, context_len).
 * b3p_hash_derive* then hashes input as DERIVE_KEY_MATERIAL.
 */
BLAKE3_API int b3p_init_derive(const void* context, size_t context_len, uint8_t out_context_key[BLAKE3_KEY_LEN]);
BLAKE3_API int b3p_hash_derive(b3p_ctx_t* ctx, const uint8_t* input, size_t input_len, const void* context, size_t context_len, b3p_method_t method, uint8_t* out, size_t out_len);
BLAKE3_API int b3p_hash_derive_seek(b3p_ctx_t* ctx, const uint8_t* input, size_t input_len, const void* context, size_t context_len, b3p_method_t method, uint64_t seek, uint8_t* out, size_t out_len);

/* Safe public serial helpers. */
BLAKE3_API int b3p_hash_unkeyed_buffer_serial(const uint8_t* input, size_t input_len, uint8_t* out, size_t out_len);
BLAKE3_API int b3p_hash_keyed_buffer_serial(const uint8_t* input, size_t input_len, const uint8_t key[BLAKE3_KEY_LEN], uint8_t* out, size_t out_len);
BLAKE3_API int b3p_hash_derive_buffer_serial(const uint8_t* input, size_t input_len, const void* context, size_t context_len, uint8_t* out, size_t out_len);

/* Expert raw APIs.
 * `cv` is the initial chaining value encoded as 32 little-endian bytes.
 * `flags` are B3P_FLAG_* bits.
 */
BLAKE3_API int b3p_hash_raw_cv_one_shot(b3p_ctx_t* ctx, const uint8_t* input, size_t input_len, const uint8_t cv[BLAKE3_KEY_LEN], b3p_flags_t flags, b3p_method_t method, uint8_t* out, size_t out_len);
BLAKE3_API int b3p_hash_raw_cv_one_shot_seek(b3p_ctx_t* ctx,
                                             const uint8_t* input,
                                             size_t input_len,
                                             const uint8_t cv[BLAKE3_KEY_LEN],
                                             b3p_flags_t flags,
                                             b3p_method_t method,
                                             uint64_t seek,
                                             uint8_t* out,
                                             size_t out_len);
BLAKE3_API int b3p_hash_raw_cv_buffer_serial(const uint8_t* input, size_t input_len, const uint8_t cv[BLAKE3_KEY_LEN], b3p_flags_t flags, uint8_t* out, size_t out_len);

/* Legacy APIs kept for compatibility.
 * These are raw-CV entry points and equivalent to b3p_hash_raw_cv_*.
 */
BLAKE3_API int b3p_hash_one_shot(b3p_ctx_t* ctx, const uint8_t* input, size_t input_len, const uint8_t cv[BLAKE3_KEY_LEN], b3p_flags_t flags, b3p_method_t method, uint8_t* out, size_t out_len);
BLAKE3_API int
b3p_hash_one_shot_seek(b3p_ctx_t* ctx, const uint8_t* input, size_t input_len, const uint8_t cv[BLAKE3_KEY_LEN], b3p_flags_t flags, b3p_method_t method, uint64_t seek, uint8_t* out, size_t out_len);
BLAKE3_API int b3p_hash_buffer_serial(const uint8_t* input, size_t input_len, const uint8_t cv[BLAKE3_KEY_LEN], b3p_flags_t flags, uint8_t* out, size_t out_len);

BLAKE3_API void b3p_free_tls_resources(void);

#ifdef __cplusplus
}
#endif

#endif /* BLAKE3_PARALLEL_H */
