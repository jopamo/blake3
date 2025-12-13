#include "blake3_internal.h"
#include "blake3.h"
#include "blake3_impl.h"
#include <string.h>

/*
 * Alternative implementation of parallel hashing primitives.
 * This file provides standalone versions of b3_hash_chunk_cv, b3_hash_parent_cv,
 * and b3_output_root that use lower-level BLAKE3 functions.
 * Note: The primary implementations are in blake3.c (b3_hash_chunk_cv_impl etc.)
 * This file is not compiled by default in the Meson build system.
 */

/* Produces a 32-byte CV for one chunk index */
void b3_hash_chunk_cv(
  const b3_keyed_flags_t *kf,
  const uint8_t *chunk,
  size_t chunk_len,
  uint64_t chunk_index,
  b3_cv_bytes_t *out_cv
) {
    /* For full chunks, use blake3_hash_many for optimal SIMD */
    if (chunk_len == BLAKE3_CHUNK_LEN) {
        const uint8_t* inputs[1] = {chunk};
        blake3_hash_many(inputs, 1, BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN,
                        kf->key, chunk_index, true,
                        kf->flags, CHUNK_START, CHUNK_END,
                        out_cv->bytes);
        return;
    }

    /* Partial chunk: use chunk state */
    blake3_chunk_state state;
    memcpy(state.cv, kf->key, BLAKE3_KEY_LEN);
    state.chunk_counter = chunk_index;
    memset(state.buf, 0, BLAKE3_BLOCK_LEN);
    state.buf_len = 0;
    state.blocks_compressed = 0;
    state.flags = kf->flags;

    size_t offset = 0;
    while (offset < chunk_len) {
        size_t take = BLAKE3_BLOCK_LEN - (size_t)state.buf_len;
        if (take > chunk_len - offset) {
            take = chunk_len - offset;
        }

        uint8_t* dest = state.buf + (size_t)state.buf_len;
        memcpy(dest, chunk + offset, take);
        state.buf_len += (uint8_t)take;
        offset += take;

        if (state.buf_len == BLAKE3_BLOCK_LEN) {
            uint8_t block_flags = state.flags;
            if (state.blocks_compressed == 0) {
                block_flags |= CHUNK_START;
            }
            blake3_compress_in_place(state.cv, state.buf, BLAKE3_BLOCK_LEN,
                                     state.chunk_counter, block_flags);
            state.blocks_compressed += 1;
            state.buf_len = 0;
        }
    }

    /* Finalize chunk */
    uint8_t block_flags = state.flags;
    if (state.blocks_compressed == 0) {
        block_flags |= CHUNK_START;
    }
    block_flags |= CHUNK_END;

    /* Create output and extract chaining value */
    uint32_t input_cv[8];
    memcpy(input_cv, state.cv, 32);
    blake3_compress_in_place(input_cv, state.buf, state.buf_len,
                             state.chunk_counter, block_flags);

    /* Store as bytes */
    for (size_t i = 0; i < 8; i++) {
        uint32_t w = input_cv[i];
        out_cv->bytes[i * 4 + 0] = (uint8_t)(w >> 0);
        out_cv->bytes[i * 4 + 1] = (uint8_t)(w >> 8);
        out_cv->bytes[i * 4 + 2] = (uint8_t)(w >> 16);
        out_cv->bytes[i * 4 + 3] = (uint8_t)(w >> 24);
    }
}

/* Produces a 32-byte parent CV from two child CVs */
void b3_hash_parent_cv(
  const b3_keyed_flags_t *kf,
  const b3_cv_bytes_t *left,
  const b3_cv_bytes_t *right,
  b3_cv_bytes_t *out_cv
) {
    /* Parent block is concatenation of two child CVs */
    uint8_t block[BLAKE3_BLOCK_LEN];
    memcpy(block, left->bytes, BLAKE3_OUT_LEN);
    memcpy(block + BLAKE3_OUT_LEN, right->bytes, BLAKE3_OUT_LEN);

    /* Use blake3_hash_many with parent flags */
    const uint8_t* inputs[1] = {block};
    blake3_hash_many(inputs, 1, 1,
                    kf->key, 0, false,
                    kf->flags, PARENT, 0,
                    out_cv->bytes);
}

/* Converts root CV into arbitrary out_len bytes (XOF) */
void b3_output_root(
  const b3_keyed_flags_t *kf,
  const b3_cv_bytes_t *root_cv,
  uint64_t seek,
  uint8_t *out,
  size_t out_len
) {
    /* Convert root CV bytes to words */
    uint32_t cv_words[8];
    for (size_t i = 0; i < 8; i++) {
        cv_words[i] = (uint32_t)root_cv->bytes[i * 4 + 0] << 0
                    | (uint32_t)root_cv->bytes[i * 4 + 1] << 8
                    | (uint32_t)root_cv->bytes[i * 4 + 2] << 16
                    | (uint32_t)root_cv->bytes[i * 4 + 3] << 24;
    }

    /* Output root bytes using compress_xof */
    size_t offset = 0;
    uint64_t counter = seek / BLAKE3_BLOCK_LEN;

    while (offset < out_len) {
        uint8_t block[BLAKE3_BLOCK_LEN];
        uint8_t block_len = (out_len - offset) < BLAKE3_BLOCK_LEN
                          ? (uint8_t)(out_len - offset)
                          : BLAKE3_BLOCK_LEN;

        blake3_compress_xof(cv_words, block, block_len, counter,
                           kf->flags | ROOT, out + offset);
        offset += block_len;
        counter++;
    }
}