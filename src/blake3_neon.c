/* src/blake3_neon.c
 * ARM NEON implementation of the compression function
 */

#include "blake3_impl.h"

#include <arm_neon.h>

#ifdef __ARM_BIG_ENDIAN
#error "This implementation only supports little-endian ARM."
// It might be that all we need for big-endian support here is to get the loads
// and stores right, but step zero would be finding a way to test it in CI.
#endif

INLINE uint32x4_t loadu_128(const uint8_t src[16]) {
    // vld1q_u32 has alignment requirements. Don't use it.
    return vreinterpretq_u32_u8(vld1q_u8(src));
}

INLINE void storeu_128(uint32x4_t src, uint8_t dest[16]) {
    // vst1q_u32 has alignment requirements. Don't use it.
    vst1q_u8(dest, vreinterpretq_u8_u32(src));
}

INLINE uint32x4_t add_128(uint32x4_t a, uint32x4_t b) {
    return vaddq_u32(a, b);
}

INLINE uint32x4_t xor_128(uint32x4_t a, uint32x4_t b) {
    return veorq_u32(a, b);
}

INLINE uint32x4_t set1_128(uint32_t x) {
    return vld1q_dup_u32(&x);
}

INLINE uint32x4_t set4(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    uint32_t array[4] = {a, b, c, d};
    return vld1q_u32(array);
}

INLINE uint32x4_t rot16_128(uint32x4_t x) {
    // The straightforward implementation would be two shifts and an or, but that's
    // slower on microarchitectures we've tested. See
    // https://github.com/BLAKE3-team/BLAKE3/pull/319.
    // return vorrq_u32(vshrq_n_u32(x, 16), vshlq_n_u32(x, 32 - 16));
    return vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)));
}

INLINE uint32x4_t rot12_128(uint32x4_t x) {
    // See comment in rot16_128.
    // return vorrq_u32(vshrq_n_u32(x, 12), vshlq_n_u32(x, 32 - 12));
    return vsriq_n_u32(vshlq_n_u32(x, 32 - 12), x, 12);
}

INLINE uint32x4_t rot8_128(uint32x4_t x) {
    // See comment in rot16_128.
    // return vorrq_u32(vshrq_n_u32(x, 8), vshlq_n_u32(x, 32 - 8));
    return vsriq_n_u32(vshlq_n_u32(x, 32 - 8), x, 8);
}

INLINE uint32x4_t rot7_128(uint32x4_t x) {
    // See comment in rot16_128.
    // return vorrq_u32(vshrq_n_u32(x, 7), vshlq_n_u32(x, 32 - 7));
    return vsriq_n_u32(vshlq_n_u32(x, 32 - 7), x, 7);
}

INLINE uint32x4_t rot_l_1(uint32x4_t x) {
    return vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(x), vreinterpretq_u8_u32(x), 4));
}
INLINE uint32x4_t rot_l_2(uint32x4_t x) {
    return vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(x), vreinterpretq_u8_u32(x), 8));
}
INLINE uint32x4_t rot_l_3(uint32x4_t x) {
    return vreinterpretq_u32_u8(vextq_u8(vreinterpretq_u8_u32(x), vreinterpretq_u8_u32(x), 12));
}
INLINE uint32x4_t rot_r_1(uint32x4_t x) {
    return rot_l_3(x);
}
INLINE uint32x4_t rot_r_2(uint32x4_t x) {
    return rot_l_2(x);
}
INLINE uint32x4_t rot_r_3(uint32x4_t x) {
    return rot_l_1(x);
}

INLINE void g1_neon(uint32x4_t* row0, uint32x4_t* row1, uint32x4_t* row2, uint32x4_t* row3, uint32x4_t m) {
    *row0 = add_128(add_128(*row0, m), *row1);
    *row3 = xor_128(*row3, *row0);
    *row3 = rot16_128(*row3);
    *row2 = add_128(*row2, *row3);
    *row1 = xor_128(*row1, *row2);
    *row1 = rot12_128(*row1);
}

INLINE void g2_neon(uint32x4_t* row0, uint32x4_t* row1, uint32x4_t* row2, uint32x4_t* row3, uint32x4_t m) {
    *row0 = add_128(add_128(*row0, m), *row1);
    *row3 = xor_128(*row3, *row0);
    *row3 = rot8_128(*row3);
    *row2 = add_128(*row2, *row3);
    *row1 = xor_128(*row1, *row2);
    *row1 = rot7_128(*row1);
}

INLINE void diagonalize_neon(uint32x4_t* row0, uint32x4_t* row2, uint32x4_t* row3) {
    *row0 = rot_r_1(*row0);
    *row3 = rot_r_2(*row3);
    *row2 = rot_r_3(*row2);
}

INLINE void undiagonalize_neon(uint32x4_t* row0, uint32x4_t* row2, uint32x4_t* row3) {
    *row0 = rot_l_1(*row0);
    *row3 = rot_l_2(*row3);
    *row2 = rot_l_3(*row2);
}

#if defined(__aarch64__)
void blake3_compress_in_place_neon(uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len, uint64_t counter, uint8_t flags);
#endif

// TODO: compress_neon

// TODO: hash2_neon

/*
 * ----------------------------------------------------------------------------
 * hash4_neon
 * ----------------------------------------------------------------------------
 */

INLINE void round_fn4(uint32x4_t v[16], uint32x4_t m[16], size_t r) {
    v[0] = add_128(v[0], m[(size_t)MSG_SCHEDULE[r][0]]);
    v[1] = add_128(v[1], m[(size_t)MSG_SCHEDULE[r][2]]);
    v[2] = add_128(v[2], m[(size_t)MSG_SCHEDULE[r][4]]);
    v[3] = add_128(v[3], m[(size_t)MSG_SCHEDULE[r][6]]);
    v[0] = add_128(v[0], v[4]);
    v[1] = add_128(v[1], v[5]);
    v[2] = add_128(v[2], v[6]);
    v[3] = add_128(v[3], v[7]);
    v[12] = xor_128(v[12], v[0]);
    v[13] = xor_128(v[13], v[1]);
    v[14] = xor_128(v[14], v[2]);
    v[15] = xor_128(v[15], v[3]);
    v[12] = rot16_128(v[12]);
    v[13] = rot16_128(v[13]);
    v[14] = rot16_128(v[14]);
    v[15] = rot16_128(v[15]);
    v[8] = add_128(v[8], v[12]);
    v[9] = add_128(v[9], v[13]);
    v[10] = add_128(v[10], v[14]);
    v[11] = add_128(v[11], v[15]);
    v[4] = xor_128(v[4], v[8]);
    v[5] = xor_128(v[5], v[9]);
    v[6] = xor_128(v[6], v[10]);
    v[7] = xor_128(v[7], v[11]);
    v[4] = rot12_128(v[4]);
    v[5] = rot12_128(v[5]);
    v[6] = rot12_128(v[6]);
    v[7] = rot12_128(v[7]);
    v[0] = add_128(v[0], m[(size_t)MSG_SCHEDULE[r][1]]);
    v[1] = add_128(v[1], m[(size_t)MSG_SCHEDULE[r][3]]);
    v[2] = add_128(v[2], m[(size_t)MSG_SCHEDULE[r][5]]);
    v[3] = add_128(v[3], m[(size_t)MSG_SCHEDULE[r][7]]);
    v[0] = add_128(v[0], v[4]);
    v[1] = add_128(v[1], v[5]);
    v[2] = add_128(v[2], v[6]);
    v[3] = add_128(v[3], v[7]);
    v[12] = xor_128(v[12], v[0]);
    v[13] = xor_128(v[13], v[1]);
    v[14] = xor_128(v[14], v[2]);
    v[15] = xor_128(v[15], v[3]);
    v[12] = rot8_128(v[12]);
    v[13] = rot8_128(v[13]);
    v[14] = rot8_128(v[14]);
    v[15] = rot8_128(v[15]);
    v[8] = add_128(v[8], v[12]);
    v[9] = add_128(v[9], v[13]);
    v[10] = add_128(v[10], v[14]);
    v[11] = add_128(v[11], v[15]);
    v[4] = xor_128(v[4], v[8]);
    v[5] = xor_128(v[5], v[9]);
    v[6] = xor_128(v[6], v[10]);
    v[7] = xor_128(v[7], v[11]);
    v[4] = rot7_128(v[4]);
    v[5] = rot7_128(v[5]);
    v[6] = rot7_128(v[6]);
    v[7] = rot7_128(v[7]);

    v[0] = add_128(v[0], m[(size_t)MSG_SCHEDULE[r][8]]);
    v[1] = add_128(v[1], m[(size_t)MSG_SCHEDULE[r][10]]);
    v[2] = add_128(v[2], m[(size_t)MSG_SCHEDULE[r][12]]);
    v[3] = add_128(v[3], m[(size_t)MSG_SCHEDULE[r][14]]);
    v[0] = add_128(v[0], v[5]);
    v[1] = add_128(v[1], v[6]);
    v[2] = add_128(v[2], v[7]);
    v[3] = add_128(v[3], v[4]);
    v[15] = xor_128(v[15], v[0]);
    v[12] = xor_128(v[12], v[1]);
    v[13] = xor_128(v[13], v[2]);
    v[14] = xor_128(v[14], v[3]);
    v[15] = rot16_128(v[15]);
    v[12] = rot16_128(v[12]);
    v[13] = rot16_128(v[13]);
    v[14] = rot16_128(v[14]);
    v[10] = add_128(v[10], v[15]);
    v[11] = add_128(v[11], v[12]);
    v[8] = add_128(v[8], v[13]);
    v[9] = add_128(v[9], v[14]);
    v[5] = xor_128(v[5], v[10]);
    v[6] = xor_128(v[6], v[11]);
    v[7] = xor_128(v[7], v[8]);
    v[4] = xor_128(v[4], v[9]);
    v[5] = rot12_128(v[5]);
    v[6] = rot12_128(v[6]);
    v[7] = rot12_128(v[7]);
    v[4] = rot12_128(v[4]);
    v[0] = add_128(v[0], m[(size_t)MSG_SCHEDULE[r][9]]);
    v[1] = add_128(v[1], m[(size_t)MSG_SCHEDULE[r][11]]);
    v[2] = add_128(v[2], m[(size_t)MSG_SCHEDULE[r][13]]);
    v[3] = add_128(v[3], m[(size_t)MSG_SCHEDULE[r][15]]);
    v[0] = add_128(v[0], v[5]);
    v[1] = add_128(v[1], v[6]);
    v[2] = add_128(v[2], v[7]);
    v[3] = add_128(v[3], v[4]);
    v[15] = xor_128(v[15], v[0]);
    v[12] = xor_128(v[12], v[1]);
    v[13] = xor_128(v[13], v[2]);
    v[14] = xor_128(v[14], v[3]);
    v[15] = rot8_128(v[15]);
    v[12] = rot8_128(v[12]);
    v[13] = rot8_128(v[13]);
    v[14] = rot8_128(v[14]);
    v[10] = add_128(v[10], v[15]);
    v[11] = add_128(v[11], v[12]);
    v[8] = add_128(v[8], v[13]);
    v[9] = add_128(v[9], v[14]);
    v[5] = xor_128(v[5], v[10]);
    v[6] = xor_128(v[6], v[11]);
    v[7] = xor_128(v[7], v[8]);
    v[4] = xor_128(v[4], v[9]);
    v[5] = rot7_128(v[5]);
    v[6] = rot7_128(v[6]);
    v[7] = rot7_128(v[7]);
    v[4] = rot7_128(v[4]);
}

INLINE void transpose_vecs_128(uint32x4_t vecs[4]) {
    // Individually transpose the four 2x2 sub-matrices in each corner.
    uint32x4x2_t rows01 = vtrnq_u32(vecs[0], vecs[1]);
    uint32x4x2_t rows23 = vtrnq_u32(vecs[2], vecs[3]);

    // Swap the top-right and bottom-left 2x2s (which just got transposed).
    vecs[0] = vcombine_u32(vget_low_u32(rows01.val[0]), vget_low_u32(rows23.val[0]));
    vecs[1] = vcombine_u32(vget_low_u32(rows01.val[1]), vget_low_u32(rows23.val[1]));
    vecs[2] = vcombine_u32(vget_high_u32(rows01.val[0]), vget_high_u32(rows23.val[0]));
    vecs[3] = vcombine_u32(vget_high_u32(rows01.val[1]), vget_high_u32(rows23.val[1]));
}

INLINE void transpose_msg_vecs4(const uint8_t* const* inputs, size_t block_offset, uint32x4_t out[16]) {
    out[0] = loadu_128(&inputs[0][block_offset + 0 * sizeof(uint32x4_t)]);
    out[1] = loadu_128(&inputs[1][block_offset + 0 * sizeof(uint32x4_t)]);
    out[2] = loadu_128(&inputs[2][block_offset + 0 * sizeof(uint32x4_t)]);
    out[3] = loadu_128(&inputs[3][block_offset + 0 * sizeof(uint32x4_t)]);
    out[4] = loadu_128(&inputs[0][block_offset + 1 * sizeof(uint32x4_t)]);
    out[5] = loadu_128(&inputs[1][block_offset + 1 * sizeof(uint32x4_t)]);
    out[6] = loadu_128(&inputs[2][block_offset + 1 * sizeof(uint32x4_t)]);
    out[7] = loadu_128(&inputs[3][block_offset + 1 * sizeof(uint32x4_t)]);
    out[8] = loadu_128(&inputs[0][block_offset + 2 * sizeof(uint32x4_t)]);
    out[9] = loadu_128(&inputs[1][block_offset + 2 * sizeof(uint32x4_t)]);
    out[10] = loadu_128(&inputs[2][block_offset + 2 * sizeof(uint32x4_t)]);
    out[11] = loadu_128(&inputs[3][block_offset + 2 * sizeof(uint32x4_t)]);
    out[12] = loadu_128(&inputs[0][block_offset + 3 * sizeof(uint32x4_t)]);
    out[13] = loadu_128(&inputs[1][block_offset + 3 * sizeof(uint32x4_t)]);
    out[14] = loadu_128(&inputs[2][block_offset + 3 * sizeof(uint32x4_t)]);
    out[15] = loadu_128(&inputs[3][block_offset + 3 * sizeof(uint32x4_t)]);
#if defined(__GNUC__) || defined(__clang__)
    for (size_t i = 0; i < 4; ++i) {
        __builtin_prefetch(&inputs[i][block_offset + 256]);
    }
#endif
    transpose_vecs_128(&out[0]);
    transpose_vecs_128(&out[4]);
    transpose_vecs_128(&out[8]);
    transpose_vecs_128(&out[12]);
}

INLINE void load_counters4(uint64_t counter, bool increment_counter, uint32x4_t* out_low, uint32x4_t* out_high) {
    uint64_t mask = (increment_counter ? ~0 : 0);
    *out_low = set4(counter_low(counter + (mask & 0)), counter_low(counter + (mask & 1)), counter_low(counter + (mask & 2)), counter_low(counter + (mask & 3)));
    *out_high = set4(counter_high(counter + (mask & 0)), counter_high(counter + (mask & 1)), counter_high(counter + (mask & 2)), counter_high(counter + (mask & 3)));
}

static void
blake3_hash4_neon(const uint8_t* const* inputs, size_t blocks, const uint32_t key[8], uint64_t counter, bool increment_counter, uint8_t flags, uint8_t flags_start, uint8_t flags_end, uint8_t* out) {
    uint32x4_t h_vecs[8] = {
        set1_128(key[0]), set1_128(key[1]), set1_128(key[2]), set1_128(key[3]), set1_128(key[4]), set1_128(key[5]), set1_128(key[6]), set1_128(key[7]),
    };
    uint32x4_t counter_low_vec, counter_high_vec;
    load_counters4(counter, increment_counter, &counter_low_vec, &counter_high_vec);
    uint8_t block_flags = flags | flags_start;

    for (size_t block = 0; block < blocks; block++) {
        if (block + 1 == blocks) {
            block_flags |= flags_end;
        }
        uint32x4_t block_len_vec = set1_128(BLAKE3_BLOCK_LEN);
        uint32x4_t block_flags_vec = set1_128(block_flags);
        uint32x4_t msg_vecs[16];
        transpose_msg_vecs4(inputs, block * BLAKE3_BLOCK_LEN, msg_vecs);

        uint32x4_t v[16] = {
            h_vecs[0],       h_vecs[1],       h_vecs[2],       h_vecs[3],       h_vecs[4],       h_vecs[5],        h_vecs[6],     h_vecs[7],
            set1_128(IV[0]), set1_128(IV[1]), set1_128(IV[2]), set1_128(IV[3]), counter_low_vec, counter_high_vec, block_len_vec, block_flags_vec,
        };
        round_fn4(v, msg_vecs, 0);
        round_fn4(v, msg_vecs, 1);
        round_fn4(v, msg_vecs, 2);
        round_fn4(v, msg_vecs, 3);
        round_fn4(v, msg_vecs, 4);
        round_fn4(v, msg_vecs, 5);
        round_fn4(v, msg_vecs, 6);
        h_vecs[0] = xor_128(v[0], v[8]);
        h_vecs[1] = xor_128(v[1], v[9]);
        h_vecs[2] = xor_128(v[2], v[10]);
        h_vecs[3] = xor_128(v[3], v[11]);
        h_vecs[4] = xor_128(v[4], v[12]);
        h_vecs[5] = xor_128(v[5], v[13]);
        h_vecs[6] = xor_128(v[6], v[14]);
        h_vecs[7] = xor_128(v[7], v[15]);
        block_flags = flags;
    }

    transpose_vecs_128(&h_vecs[0]);
    transpose_vecs_128(&h_vecs[4]);
    // The first four vecs now contain the first half of each output, and the
    // second four vecs contain the second half of each output.
    storeu_128(h_vecs[0], &out[0 * sizeof(uint32x4_t)]);
    storeu_128(h_vecs[4], &out[1 * sizeof(uint32x4_t)]);
    storeu_128(h_vecs[1], &out[2 * sizeof(uint32x4_t)]);
    storeu_128(h_vecs[5], &out[3 * sizeof(uint32x4_t)]);
    storeu_128(h_vecs[2], &out[4 * sizeof(uint32x4_t)]);
    storeu_128(h_vecs[6], &out[5 * sizeof(uint32x4_t)]);
    storeu_128(h_vecs[3], &out[6 * sizeof(uint32x4_t)]);
    storeu_128(h_vecs[7], &out[7 * sizeof(uint32x4_t)]);
}

/*
 * ----------------------------------------------------------------------------
 * hash_many_neon
 * ----------------------------------------------------------------------------
 */

void blake3_compress_in_place_portable(uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len, uint64_t counter, uint8_t flags);

INLINE void broadcast_msg_vecs4(const uint8_t* block, uint32x4_t out[16]) {
    for (size_t i = 0; i < 16; ++i) {
        out[i] = set1_128(load32(block + 4 * i));
    }
}

void blake3_xof_many_neon(const uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len, uint64_t counter, uint8_t flags, uint8_t out[64], size_t outblocks) {
    uint32x4_t key_vecs[8] = {
        set1_128(cv[0]), set1_128(cv[1]), set1_128(cv[2]), set1_128(cv[3]), set1_128(cv[4]), set1_128(cv[5]), set1_128(cv[6]), set1_128(cv[7]),
    };
    uint32x4_t block_len_vec = set1_128(block_len);
    uint32x4_t block_flags_vec = set1_128(flags | CHUNK_END | ROOT | CHUNK_START);

    uint32x4_t msg_vecs[16];
    broadcast_msg_vecs4(block, msg_vecs);

    while (outblocks >= 4) {
        uint32x4_t counter_low_vec, counter_high_vec;
        load_counters4(counter, true, &counter_low_vec, &counter_high_vec);

        uint32x4_t v[16] = {
            key_vecs[0],     key_vecs[1],     key_vecs[2],     key_vecs[3],     key_vecs[4],     key_vecs[5],      key_vecs[6],   key_vecs[7],
            set1_128(IV[0]), set1_128(IV[1]), set1_128(IV[2]), set1_128(IV[3]), counter_low_vec, counter_high_vec, block_len_vec, block_flags_vec,
        };
        round_fn4(v, msg_vecs, 0);
        round_fn4(v, msg_vecs, 1);
        round_fn4(v, msg_vecs, 2);
        round_fn4(v, msg_vecs, 3);
        round_fn4(v, msg_vecs, 4);
        round_fn4(v, msg_vecs, 5);
        round_fn4(v, msg_vecs, 6);

        uint32x4_t out_low[8];
        uint32x4_t out_high[8];

        out_low[0] = xor_128(v[0], v[8]);
        out_low[1] = xor_128(v[1], v[9]);
        out_low[2] = xor_128(v[2], v[10]);
        out_low[3] = xor_128(v[3], v[11]);
        out_low[4] = xor_128(v[4], v[12]);
        out_low[5] = xor_128(v[5], v[13]);
        out_low[6] = xor_128(v[6], v[14]);
        out_low[7] = xor_128(v[7], v[15]);

        out_high[0] = xor_128(v[8], key_vecs[0]);
        out_high[1] = xor_128(v[9], key_vecs[1]);
        out_high[2] = xor_128(v[10], key_vecs[2]);
        out_high[3] = xor_128(v[11], key_vecs[3]);
        out_high[4] = xor_128(v[12], key_vecs[4]);
        out_high[5] = xor_128(v[13], key_vecs[5]);
        out_high[6] = xor_128(v[14], key_vecs[6]);
        out_high[7] = xor_128(v[15], key_vecs[7]);

        transpose_vecs_128(&out_low[0]);
        transpose_vecs_128(&out_low[4]);
        transpose_vecs_128(&out_high[0]);
        transpose_vecs_128(&out_high[4]);

        // Interleave output: low0, low4, high0, high4, low1, low5, high1, high5...
        // But we want continuous 64 bytes per lane.
        // out_low[0] is first 16 bytes of lane 0, 1, 2, 3.
        // Wait, transpose_vecs_128 transposes 4x4 matrix of 32-bit elements.
        // Input:
        // out_low[0]: L0_w0, L1_w0, L2_w0, L3_w0
        // ...
        // out_low[3]: L0_w3, L1_w3, L2_w3, L3_w3
        // After transpose:
        // out_low[0]: L0_w0, L0_w1, L0_w2, L0_w3 (First 16 bytes of Lane 0)
        // out_low[1]: L1_w0 ...

        // We need to write 64 bytes for Lane 0:
        // out_low[0], out_low[4], out_high[0], out_high[4]

        storeu_128(out_low[0], out + 0 * 64 + 0);
        storeu_128(out_low[4], out + 0 * 64 + 16);
        storeu_128(out_high[0], out + 0 * 64 + 32);
        storeu_128(out_high[4], out + 0 * 64 + 48);

        storeu_128(out_low[1], out + 1 * 64 + 0);
        storeu_128(out_low[5], out + 1 * 64 + 16);
        storeu_128(out_high[1], out + 1 * 64 + 32);
        storeu_128(out_high[5], out + 1 * 64 + 48);

        storeu_128(out_low[2], out + 2 * 64 + 0);
        storeu_128(out_low[6], out + 2 * 64 + 16);
        storeu_128(out_high[2], out + 2 * 64 + 32);
        storeu_128(out_high[6], out + 2 * 64 + 48);

        storeu_128(out_low[3], out + 3 * 64 + 0);
        storeu_128(out_low[7], out + 3 * 64 + 16);
        storeu_128(out_high[3], out + 3 * 64 + 32);
        storeu_128(out_high[7], out + 3 * 64 + 48);

        counter += 4;
        outblocks -= 4;
        out += 4 * 64;
    }

    while (outblocks > 0) {
#if defined(__aarch64__)
        blake3_compress_xof_neon(cv, block, block_len, counter, flags, out);
#else
        blake3_compress_xof_portable(cv, block, block_len, counter, flags, out);
#endif
        counter += 1;
        outblocks -= 1;
        out += 64;
    }
}

INLINE void hash_one_neon(const uint8_t* input, size_t blocks, const uint32_t key[8], uint64_t counter, uint8_t flags, uint8_t flags_start, uint8_t flags_end, uint8_t out[BLAKE3_OUT_LEN]) {
    uint32_t cv[8];
    memcpy(cv, key, BLAKE3_KEY_LEN);
    uint8_t block_flags = flags | flags_start;
    while (blocks > 0) {
        if (blocks == 1) {
            block_flags |= flags_end;
        }
#if defined(__aarch64__) && BLAKE3_USE_NEON == 1
        blake3_compress_in_place_neon(cv, input, BLAKE3_BLOCK_LEN, counter, block_flags);
#else
        // TODO: Implement compress_neon. However note that according to
        // https://github.com/BLAKE2/BLAKE2/commit/7965d3e6e1b4193438b8d3a656787587d2579227,
        // compress_neon might not be any faster than compress_portable.
        blake3_compress_in_place_portable(cv, input, BLAKE3_BLOCK_LEN, counter, block_flags);
#endif
        input = &input[BLAKE3_BLOCK_LEN];
        blocks -= 1;
        block_flags = flags;
    }
    memcpy(out, cv, BLAKE3_OUT_LEN);
}

static void
blake3_hash2_neon(const uint8_t* const* inputs, size_t blocks, const uint32_t key[8], uint64_t counter, bool increment_counter, uint8_t flags, uint8_t flags_start, uint8_t flags_end, uint8_t* out) {
    const uint8_t* const in4[4] = {inputs[0], inputs[1], inputs[0], inputs[0]};
    uint8_t tmp[4 * BLAKE3_OUT_LEN];
    blake3_hash4_neon(in4, blocks, key, counter, increment_counter, flags, flags_start, flags_end, tmp);
    memcpy(out + 0 * BLAKE3_OUT_LEN, tmp + 0 * BLAKE3_OUT_LEN, BLAKE3_OUT_LEN);
    memcpy(out + 1 * BLAKE3_OUT_LEN, tmp + 1 * BLAKE3_OUT_LEN, BLAKE3_OUT_LEN);
}

static void
blake3_hash3_neon(const uint8_t* const* inputs, size_t blocks, const uint32_t key[8], uint64_t counter, bool increment_counter, uint8_t flags, uint8_t flags_start, uint8_t flags_end, uint8_t* out) {
    const uint8_t* const in4[4] = {inputs[0], inputs[1], inputs[2], inputs[0]};
    uint8_t tmp[4 * BLAKE3_OUT_LEN];
    blake3_hash4_neon(in4, blocks, key, counter, increment_counter, flags, flags_start, flags_end, tmp);
    memcpy(out + 0 * BLAKE3_OUT_LEN, tmp + 0 * BLAKE3_OUT_LEN, BLAKE3_OUT_LEN);
    memcpy(out + 1 * BLAKE3_OUT_LEN, tmp + 1 * BLAKE3_OUT_LEN, BLAKE3_OUT_LEN);
    memcpy(out + 2 * BLAKE3_OUT_LEN, tmp + 2 * BLAKE3_OUT_LEN, BLAKE3_OUT_LEN);
}

void blake3_hash_many_neon(const uint8_t* const* inputs,
                           size_t num_inputs,
                           size_t blocks,
                           const uint32_t key[8],
                           uint64_t counter,
                           bool increment_counter,
                           uint8_t flags,
                           uint8_t flags_start,
                           uint8_t flags_end,
                           uint8_t* out) {
    while (num_inputs >= 4) {
        blake3_hash4_neon(inputs, blocks, key, counter, increment_counter, flags, flags_start, flags_end, out);
        if (increment_counter) {
            counter += 4;
        }
        inputs += 4;
        num_inputs -= 4;
        out = &out[4 * BLAKE3_OUT_LEN];
    }

    if (num_inputs == 3) {
        blake3_hash3_neon(inputs, blocks, key, counter, increment_counter, flags, flags_start, flags_end, out);
        return;
    }

    if (num_inputs == 2) {
        blake3_hash2_neon(inputs, blocks, key, counter, increment_counter, flags, flags_start, flags_end, out);
        return;
    }

    if (num_inputs == 1) {
        hash_one_neon(inputs[0], blocks, key, counter, flags, flags_start, flags_end, out);
        return;
    }
}
