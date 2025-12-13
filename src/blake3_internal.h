#ifndef BLAKE3_INTERNAL_H
#define BLAKE3_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include "blake3_impl.h"

#define B3_CV_WORDS 8
#define B3_CV_BYTES 32

typedef struct {
  uint32_t cv[B3_CV_WORDS];
} b3_cv_words_t;

typedef struct {
  uint8_t bytes[B3_CV_BYTES];
} b3_cv_bytes_t;

typedef struct {
  uint32_t key[B3_CV_WORDS];
  uint8_t flags;
} b3_keyed_flags_t;

/* Produces a 32-byte CV for one chunk index */
static inline void b3_hash_chunk_cv(
  const b3_keyed_flags_t *kf,
  const uint8_t *chunk,
  size_t chunk_len,
  uint64_t chunk_index,
  b3_cv_bytes_t *out_cv
) {
  b3_hash_chunk_cv_impl(kf->key, kf->flags, chunk, chunk_len, chunk_index, out_cv->bytes);
}

/* Produces a 32-byte parent CV from two child CVs */
static inline void b3_hash_parent_cv(
  const b3_keyed_flags_t *kf,
  const b3_cv_bytes_t *left,
  const b3_cv_bytes_t *right,
  b3_cv_bytes_t *out_cv
) {
  b3_hash_parent_cv_impl(kf->key, kf->flags, left->bytes, right->bytes, out_cv->bytes);
}

/* Converts root CV into arbitrary out_len bytes (XOF) */
static inline void b3_output_root(
  const b3_keyed_flags_t *kf,
  const b3_cv_bytes_t *root_cv,
  uint64_t seek,
  uint8_t *out,
  size_t out_len
) {
  b3_output_root_impl(kf->key, kf->flags, root_cv->bytes, seek, out, out_len);
}

#endif /* BLAKE3_INTERNAL_H */