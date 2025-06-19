#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "blake3.h"
#include "blake3_impl.h"

const char* blake3_version(void) {
  return BLAKE3_VERSION_STRING;
}

INLINE void chunk_state_init(blake3_chunk_state* self, const uint32_t key[8], uint8_t flags) {
  memcpy(self->cv, key, BLAKE3_KEY_LEN);
  self->chunk_counter = 0;
  memset(self->buf, 0, BLAKE3_BLOCK_LEN);
  self->buf_len = 0;
  self->blocks_compressed = 0;
  self->flags = flags;
}

INLINE void chunk_state_reset(blake3_chunk_state* self, const uint32_t key[8], uint64_t chunk_counter) {
  memcpy(self->cv, key, BLAKE3_KEY_LEN);
  self->chunk_counter = chunk_counter;
  self->blocks_compressed = 0;
  memset(self->buf, 0, BLAKE3_BLOCK_LEN);
  self->buf_len = 0;
}

INLINE size_t chunk_state_len(const blake3_chunk_state* self) {
  return (BLAKE3_BLOCK_LEN * (size_t)self->blocks_compressed) + ((size_t)self->buf_len);
}

INLINE size_t chunk_state_fill_buf(blake3_chunk_state* self, const uint8_t* input, size_t input_len) {
  size_t take = BLAKE3_BLOCK_LEN - self->buf_len;
  take = (take > input_len) ? input_len : take;
  memcpy(self->buf + self->buf_len, input, take);
  self->buf_len += take;
  return take;
}

INLINE uint8_t chunk_state_maybe_start_flag(const blake3_chunk_state* self) {
  if (self->blocks_compressed == 0) {
    return CHUNK_START;
  }
  else {
    return 0;
  }
}

typedef struct {
  uint32_t input_cv[8];
  uint64_t counter;
  uint8_t block[BLAKE3_BLOCK_LEN];
  uint8_t block_len;
  uint8_t flags;
} output_t;

INLINE output_t make_output(const uint32_t input_cv[8],
                            const uint8_t block[BLAKE3_BLOCK_LEN],
                            uint8_t block_len,
                            uint64_t counter,
                            uint8_t flags) {
  output_t ret;
  memcpy(ret.input_cv, input_cv, 32);
  memcpy(ret.block, block, BLAKE3_BLOCK_LEN);
  ret.block_len = block_len;
  ret.counter = counter;
  ret.flags = flags;
  return ret;
}

// Chaining values within a given chunk (specifically the compress_in_place
// interface) are represented as words. This avoids unnecessary bytes<->words
// conversion overhead in the portable implementation. However, the hash_many
// interface handles both user input and parent node blocks, so it accepts
// bytes. For that reason, chaining values in the CV stack are represented as
// bytes.
INLINE void output_chaining_value(const output_t* self, uint8_t cv[32]) {
  uint32_t cv_words[8];
  memcpy(cv_words, self->input_cv, 32);
  blake3_compress_in_place(cv_words, self->block, self->block_len, self->counter, self->flags);
  store_cv_words(cv, cv_words);
}

INLINE void output_root_bytes(const output_t* self, uint64_t seek, uint8_t* out, size_t out_len) {
  if (out_len == 0) {
    return;
  }
  uint64_t output_block_counter = seek / 64;
  size_t offset_within_block = seek % 64;
  uint8_t wide_buf[64];
  if (offset_within_block) {
    blake3_compress_xof(self->input_cv, self->block, self->block_len, output_block_counter, self->flags | ROOT,
                        wide_buf);
    const size_t available_bytes = 64 - offset_within_block;
    const size_t bytes = out_len > available_bytes ? available_bytes : out_len;
    memcpy(out, wide_buf + offset_within_block, bytes);
    out += bytes;
    out_len -= bytes;
    output_block_counter += 1;
  }
  if (out_len / 64) {
    blake3_xof_many(self->input_cv, self->block, self->block_len, output_block_counter, self->flags | ROOT, out,
                    out_len / 64);
  }
  output_block_counter += out_len / 64;
  out += out_len & -64;
  out_len -= out_len & -64;
  if (out_len) {
    blake3_compress_xof(self->input_cv, self->block, self->block_len, output_block_counter, self->flags | ROOT,
                        wide_buf);
    memcpy(out, wide_buf, out_len);
  }
}

INLINE void chunk_state_update(blake3_chunk_state* self, const uint8_t* input, size_t input_len) {
  if (self->buf_len > 0) {
    size_t take = chunk_state_fill_buf(self, input, input_len);
    input += take;
    input_len -= take;
    if (input_len > 0) {
      blake3_compress_in_place(self->cv, self->buf, BLAKE3_BLOCK_LEN, self->chunk_counter,
                               self->flags | chunk_state_maybe_start_flag(self));
      self->blocks_compressed += 1;
      self->buf_len = 0;
      memset(self->buf, 0, BLAKE3_BLOCK_LEN);
    }
  }

  while (input_len > BLAKE3_BLOCK_LEN) {
    blake3_compress_in_place(self->cv, input, BLAKE3_BLOCK_LEN, self->chunk_counter,
                             self->flags | chunk_state_maybe_start_flag(self));
    self->blocks_compressed += 1;
    input += BLAKE3_BLOCK_LEN;
    input_len -= BLAKE3_BLOCK_LEN;
  }

  chunk_state_fill_buf(self, input, input_len);
}

INLINE output_t chunk_state_output(const blake3_chunk_state* self) {
  uint8_t block_flags = self->flags | chunk_state_maybe_start_flag(self) | CHUNK_END;
  return make_output(self->cv, self->buf, self->buf_len, self->chunk_counter, block_flags);
}

INLINE output_t parent_output(const uint8_t block[BLAKE3_BLOCK_LEN], const uint32_t key[8], uint8_t flags) {
  return make_output(key, block, BLAKE3_BLOCK_LEN, 0, flags | PARENT);
}

// Given some input larger than one chunk, return the number of bytes that
// should go in the left subtree. This is the largest power-of-2 number of
// chunks that leaves at least 1 byte for the right subtree.
INLINE size_t left_len(size_t content_len) {
  // Subtract 1 to reserve at least one byte for the right side. content_len
  // should always be greater than BLAKE3_CHUNK_LEN.
  size_t full_chunks = (content_len - 1) / BLAKE3_CHUNK_LEN;
  return round_down_to_power_of_2(full_chunks) * BLAKE3_CHUNK_LEN;
}

// Hash a subtree using SIMD parallelism for chunks. It hashes up to MAX_SIMD_DEGREE chunks at the same time
// and writes out the chunk chaining values. It returns the number of chunks hashed.
INLINE size_t compress_chunks_parallel(const uint8_t* input,
                                       size_t input_len,
                                       const uint32_t key[8],
                                       uint64_t chunk_counter,
                                       uint8_t flags,
                                       uint8_t* out) {
#if defined(BLAKE3_TESTING)
  assert(input_len > 0);
  assert(input_len <= MAX_SIMD_DEGREE * BLAKE3_CHUNK_LEN);
#endif

  size_t input_position = 0;
  size_t chunks_array_len = 0;
  const uint8_t* chunks_array[MAX_SIMD_DEGREE];

  // Read input into chunks_array
  while (input_len - input_position >= BLAKE3_CHUNK_LEN) {
    chunks_array[chunks_array_len++] = &input[input_position];
    input_position += BLAKE3_CHUNK_LEN;
  }

  // Process chunks in parallel
  blake3_hash_many(chunks_array, chunks_array_len, BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, key, chunk_counter, true, flags,
                   CHUNK_START, CHUNK_END, out);

  // Handle remaining partial chunk
  if (input_len > input_position) {
    uint64_t counter = chunk_counter + (uint64_t)chunks_array_len;
    blake3_chunk_state chunk_state;
    chunk_state_init(&chunk_state, key, flags);
    chunk_state.chunk_counter = counter;
    chunk_state_update(&chunk_state, &input[input_position], input_len - input_position);
    output_t output = chunk_state_output(&chunk_state);
    output_chaining_value(&output, &out[chunks_array_len * BLAKE3_OUT_LEN]);
    return chunks_array_len + 1;
  }
  return chunks_array_len;
}

// Use SIMD parallelism to hash up to MAX_SIMD_DEGREE parents at the same time
// and writes out the parent chaining values. It returns the number of parents hashed.
INLINE size_t compress_parents_parallel(const uint8_t* child_chaining_values,
                                        size_t num_chaining_values,
                                        const uint32_t key[8],
                                        uint8_t flags,
                                        uint8_t* out) {
#if defined(BLAKE3_TESTING)
  assert(2 <= num_chaining_values && num_chaining_values <= 2 * MAX_SIMD_DEGREE_OR_2);
#endif

  // If there are fewer than two chaining values, there's nothing to process
  if (num_chaining_values < 2) {
    return 0;
  }

  const uint8_t* parents_array[MAX_SIMD_DEGREE_OR_2];
  size_t parents_array_len = 0;

  // Group child chaining values into pairs, ensuring we don't exceed the array size
  for (size_t i = 0; i + 1 < num_chaining_values && parents_array_len < MAX_SIMD_DEGREE_OR_2; i += 2) {
    parents_array[parents_array_len++] = &child_chaining_values[i * BLAKE3_OUT_LEN];
  }

  // Process parent chunks in parallel
  blake3_hash_many(parents_array, parents_array_len, 1, key, 0, false, flags | PARENT, 0, 0, out);

  // If there's an odd chaining value left, append it to the result
  if (num_chaining_values > 2 * parents_array_len) {
    memcpy(&out[parents_array_len * BLAKE3_OUT_LEN], &child_chaining_values[2 * parents_array_len * BLAKE3_OUT_LEN],
           BLAKE3_OUT_LEN);
    return parents_array_len + 1;
  }

  return parents_array_len;
}

// Main function for compressing a subtree, utilizing SIMD parallelism to hash multiple chunks
// and parents. It processes subtrees and condenses the chaining values down to a single parent node.
static size_t blake3_compress_subtree_wide(const uint8_t* input,
                                           size_t input_len,
                                           const uint32_t key[8],
                                           uint64_t chunk_counter,
                                           uint8_t flags,
                                           uint8_t* out) {
  // If the input is small, directly compress it using SIMD if possible.
  if (input_len <= blake3_simd_degree() * BLAKE3_CHUNK_LEN) {
    return compress_chunks_parallel(input, input_len, key, chunk_counter, flags, out);
  }

  // Calculate left and right subtree lengths
  size_t left_input_len = left_len(input_len);
  size_t right_input_len = input_len - left_input_len;
  const uint8_t* right_input = &input[left_input_len];
  uint64_t right_chunk_counter = chunk_counter + (left_input_len / BLAKE3_CHUNK_LEN);

  // Prepare output buffer for child nodes' chaining values
  uint8_t cv_array[2 * MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN];

  // Decide degree based on chunk length and SIMD degree
  size_t degree = blake3_simd_degree();
  if (degree == 1 && left_input_len > BLAKE3_CHUNK_LEN) {
    degree = 2;  // Ensure at least two outputs are generated for degree=1 case
  }
  uint8_t* right_cvs = &cv_array[degree * BLAKE3_OUT_LEN];

  // Recursively process the left and right subtrees
  size_t left_n = blake3_compress_subtree_wide(input, left_input_len, key, chunk_counter, flags, cv_array);
  size_t right_n =
      blake3_compress_subtree_wide(right_input, right_input_len, key, right_chunk_counter, flags, right_cvs);

  // Special case for SIMD degree=1: ensure at least two outputs are returned
  if (left_n == 1) {
    memcpy(out, cv_array, 2 * BLAKE3_OUT_LEN);
    return 2;
  }

  // Combine left and right subtrees and compress parents
  size_t num_chaining_values = left_n + right_n;
  return compress_parents_parallel(cv_array, num_chaining_values, key, flags, out);
}

// Optimized version of compress_subtree_to_parent_node function
INLINE void compress_subtree_to_parent_node(const uint8_t* input,
                                            size_t input_len,
                                            const uint32_t key[8],
                                            uint64_t chunk_counter,
                                            uint8_t flags,
                                            uint8_t out[2 * BLAKE3_OUT_LEN]) {
#if defined(BLAKE3_TESTING)
  assert(input_len > BLAKE3_CHUNK_LEN);
#endif

  uint8_t cv_array[MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN];

  // Compute the chaining values for the entire subtree
  size_t num_cvs = blake3_compress_subtree_wide(input, input_len, key, chunk_counter, flags, cv_array);
  assert(num_cvs <= MAX_SIMD_DEGREE_OR_2);

  // If num_cvs is greater than 2, reduce them to 2 chaining values.
  // This is only necessary if MAX_SIMD_DEGREE_OR_2 > 2.
#if MAX_SIMD_DEGREE_OR_2 > 2
  if (num_cvs > 2) {
    uint8_t out_array[MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN / 2];

    // Perform parent compression to reduce chaining values
    while (num_cvs > 2) {
      num_cvs = compress_parents_parallel(cv_array, num_cvs, key, flags, out_array);
      memcpy(cv_array, out_array, num_cvs * BLAKE3_OUT_LEN);
    }
  }
#endif

  // Copy the result to the output, guaranteeing two chaining values.
  memcpy(out, cv_array, 2 * BLAKE3_OUT_LEN);
}

INLINE void hasher_init_base(blake3_hasher* self, const uint32_t key[8], uint8_t flags) {
  memcpy(self->key, key, BLAKE3_KEY_LEN);
  chunk_state_init(&self->chunk, key, flags);
  self->cv_stack_len = 0;
}

void blake3_hasher_init(blake3_hasher* self) {
  hasher_init_base(self, IV, 0);
}

void blake3_hasher_init_keyed(blake3_hasher* self, const uint8_t key[BLAKE3_KEY_LEN]) {
  uint32_t key_words[8];
  load_key_words(key, key_words);
  hasher_init_base(self, key_words, KEYED_HASH);
}

void blake3_hasher_init_derive_key_raw(blake3_hasher* self, const void* context, size_t context_len) {
  blake3_hasher context_hasher;
  hasher_init_base(&context_hasher, IV, DERIVE_KEY_CONTEXT);
  blake3_hasher_update(&context_hasher, context, context_len);
  uint8_t context_key[BLAKE3_KEY_LEN];
  blake3_hasher_finalize(&context_hasher, context_key, BLAKE3_KEY_LEN);
  uint32_t context_key_words[8];
  load_key_words(context_key, context_key_words);
  hasher_init_base(self, context_key_words, DERIVE_KEY_MATERIAL);
}

void blake3_hasher_init_derive_key(blake3_hasher* self, const char* context) {
  blake3_hasher_init_derive_key_raw(self, context, strlen(context));
}

// Merge the CV stack by counting the number of chunks and performing lazy merging
// This reduces unnecessary stack adjustments and avoids redundant memory operations.
INLINE void hasher_merge_cv_stack(blake3_hasher* self, uint64_t total_len) {
  // Calculate the number of items remaining in the stack after merging
  size_t post_merge_stack_len = (size_t)popcnt(total_len);

  // Perform lazy merging by checking if the stack is longer than necessary
  while (self->cv_stack_len > post_merge_stack_len) {
    // Merge the top two CVs into a parent node
    uint8_t* parent_node = &self->cv_stack[(self->cv_stack_len - 2) * BLAKE3_OUT_LEN];
    output_t output = parent_output(parent_node, self->key, self->chunk.flags);
    output_chaining_value(&output, parent_node);

    // Decrease the stack length as we have merged the top two CVs
    self->cv_stack_len -= 1;
  }
}

// Push a new CV onto the stack, performing lazy merging with the previous CV
// The merging is done just before pushing the new CV to the stack, ensuring optimal memory usage.
INLINE void hasher_push_cv(blake3_hasher* self, uint8_t new_cv[BLAKE3_OUT_LEN], uint64_t chunk_counter) {
  // Merge the CV stack before adding the new CV
  hasher_merge_cv_stack(self, chunk_counter);

  // Add the new CV to the top of the stack
  memcpy(&self->cv_stack[self->cv_stack_len * BLAKE3_OUT_LEN], new_cv, BLAKE3_OUT_LEN);
  self->cv_stack_len += 1;
}

// This function now efficiently hashes chunks while considering subtrees,
// and deals with the edge case of incomplete subtrees in a more streamlined way.
void blake3_hasher_update(blake3_hasher* self, const void* input, size_t input_len) {
  if (input_len == 0) {
    return;  // No input to process, exit early
  }

  const uint8_t* input_bytes = (const uint8_t*)input;

  // Handle remaining partial chunk data from previous updates
  if (chunk_state_len(&self->chunk) > 0) {
    size_t remaining_in_chunk = BLAKE3_CHUNK_LEN - chunk_state_len(&self->chunk);
    size_t chunk_part_len = (remaining_in_chunk > input_len) ? input_len : remaining_in_chunk;
    chunk_state_update(&self->chunk, input_bytes, chunk_part_len);

    input_bytes += chunk_part_len;
    input_len -= chunk_part_len;

    // If the chunk is now full and more data remains, finalize and push the chunk
    if (input_len > 0) {
      output_t output = chunk_state_output(&self->chunk);
      uint8_t chunk_cv[32];
      output_chaining_value(&output, chunk_cv);
      hasher_push_cv(self, chunk_cv, self->chunk.chunk_counter);
      chunk_state_reset(&self->chunk, self->key, self->chunk.chunk_counter + 1);
    }
    else {
      return;  // No further processing required for this chunk
    }
  }

  // Process remaining input chunks
  while (input_len > BLAKE3_CHUNK_LEN) {
    size_t subtree_len = round_down_to_power_of_2(input_len);
    uint64_t count_so_far = self->chunk.chunk_counter * BLAKE3_CHUNK_LEN;

    // Adjust the subtree length to ensure it divides evenly with the total chunks processed
    while (((subtree_len - 1) & count_so_far) != 0) {
      subtree_len /= 2;
    }

    uint64_t subtree_chunks = subtree_len / BLAKE3_CHUNK_LEN;

    if (subtree_len <= BLAKE3_CHUNK_LEN) {
      // If only one chunk is left, process it individually
      blake3_chunk_state chunk_state;
      chunk_state_init(&chunk_state, self->key, self->chunk.flags);
      chunk_state.chunk_counter = self->chunk.chunk_counter;
      chunk_state_update(&chunk_state, input_bytes, subtree_len);
      output_t output = chunk_state_output(&chunk_state);
      uint8_t cv[BLAKE3_OUT_LEN];
      output_chaining_value(&output, cv);
      hasher_push_cv(self, cv, chunk_state.chunk_counter);
    }
    else {
      // Process the subtree efficiently with two CVs
      uint8_t cv_pair[2 * BLAKE3_OUT_LEN];
      compress_subtree_to_parent_node(input_bytes, subtree_len, self->key, self->chunk.chunk_counter, self->chunk.flags,
                                      cv_pair);
      hasher_push_cv(self, cv_pair, self->chunk.chunk_counter);
      hasher_push_cv(self, &cv_pair[BLAKE3_OUT_LEN], self->chunk.chunk_counter + (subtree_chunks / 2));
    }

    // Update chunk counter and adjust the input and length accordingly
    self->chunk.chunk_counter += subtree_chunks;
    input_bytes += subtree_len;
    input_len -= subtree_len;
  }

  // If there's any remaining data that is less than a full chunk, process it
  if (input_len > 0) {
    chunk_state_update(&self->chunk, input_bytes, input_len);
    hasher_merge_cv_stack(self, self->chunk.chunk_counter);  // Ensure the stack is consistent
  }
}

void blake3_hasher_finalize(const blake3_hasher* self, uint8_t* out, size_t out_len) {
  blake3_hasher_finalize_seek(self, 0, out, out_len);
}

void blake3_hasher_finalize_seek(const blake3_hasher* self, uint64_t seek, uint8_t* out, size_t out_len) {
  if (out_len == 0) {
    return;  // No output required
  }

  // If the stack is empty, directly compute the root from the current chunk
  if (self->cv_stack_len == 0) {
    output_t output = chunk_state_output(&self->chunk);
    output_root_bytes(&output, seek, out, out_len);
    return;
  }

  output_t output;
  size_t cvs_remaining;

  // If there's remaining data in the chunk state, finalize it first
  if (chunk_state_len(&self->chunk) > 0) {
    cvs_remaining = self->cv_stack_len;
    output = chunk_state_output(&self->chunk);
  }
  else {
    // Otherwise, use the top of the stack
    cvs_remaining = self->cv_stack_len - 2;
    output = parent_output(&self->cv_stack[cvs_remaining * 32], self->key, self->chunk.flags);
  }

  // Merge the remaining CVs into the root
  while (cvs_remaining > 0) {
    cvs_remaining -= 1;
    uint8_t parent_block[BLAKE3_BLOCK_LEN];
    memcpy(parent_block, &self->cv_stack[cvs_remaining * 32], 32);
    output_chaining_value(&output, &parent_block[32]);
    output = parent_output(parent_block, self->key, self->chunk.flags);
  }

  // Output the final root
  output_root_bytes(&output, seek, out, out_len);
}

void blake3_hasher_reset(blake3_hasher* self) {
  chunk_state_reset(&self->chunk, self->key, 0);
  self->cv_stack_len = 0;
}
