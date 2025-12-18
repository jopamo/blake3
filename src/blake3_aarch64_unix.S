// src/blake3_aarch64_unix.S
// AArch64 scalar compress for blake3_compress_in_place_neon

#if defined(__aarch64__)

.text
.p2align 4
.global blake3_compress_in_place_neon
.type blake3_compress_in_place_neon, %function

// void blake3_compress_in_place_neon(
//     uint32_t cv[8],          // x0
//     const uint8_t block[64], // x1
//     uint8_t block_len,       // w2
//     uint64_t counter,        // x3
//     uint8_t flags            // w4
// )

.macro G a, b, c, d, m0, m1
    add     \a, \a, \b
    add     \a, \a, \m0
    eor     \d, \d, \a
    ror     \d, \d, #16
    add     \c, \c, \d
    eor     \b, \b, \c
    ror     \b, \b, #12
    add     \a, \a, \b
    add     \a, \a, \m1
    eor     \d, \d, \a
    ror     \d, \d, #8
    add     \c, \c, \d
    eor     \b, \b, \c
    ror     \b, \b, #7
.endm

.macro round_seq m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15
    // Column step
    ldr w16, [x20, #(\m0 * 4)];  ldr w17, [x20, #(\m1 * 4)];  G w0, w4, w8,  w12, w16, w17
    ldr w16, [x20, #(\m2 * 4)];  ldr w17, [x20, #(\m3 * 4)];  G w1, w5, w9,  w13, w16, w17
    ldr w16, [x20, #(\m4 * 4)];  ldr w17, [x20, #(\m5 * 4)];  G w2, w6, w10, w14, w16, w17
    ldr w16, [x20, #(\m6 * 4)];  ldr w17, [x20, #(\m7 * 4)];  G w3, w7, w11, w15, w16, w17
    // Diagonal step
    ldr w16, [x20, #(\m8 * 4)];  ldr w17, [x20, #(\m9 * 4)];  G w0, w5, w10, w15, w16, w17
    ldr w16, [x20, #(\m10 * 4)]; ldr w17, [x20, #(\m11 * 4)]; G w1, w6, w11, w12, w16, w17
    ldr w16, [x20, #(\m12 * 4)]; ldr w17, [x20, #(\m13 * 4)]; G w2, w7, w8,  w13, w16, w17
    ldr w16, [x20, #(\m14 * 4)]; ldr w17, [x20, #(\m15 * 4)]; G w3, w4, w9,  w14, w16, w17
.endm

blake3_compress_in_place_neon:
    // Save callee-saved regs
    stp     x19, x20, [sp, #-16]!

    // Capture arguments in scratch registers immediately
    // x0 = cv (ptr) -> moved to x19
    // x1 = block (ptr) -> moved to x20
    // w2 = block_len -> saved to w10
    // x3 = counter -> saved to x9
    // w4 = flags -> saved to w11
    
    mov     x19, x0
    mov     x20, x1
    mov     w10, w2
    mov     x9, x3
    mov     w11, w4

    // Initialize state[12..15] from saved arguments
    // state[12] = counter_low
    mov     w12, w9
    // state[13] = counter_high
    lsr     x9, x9, #32
    mov     w13, w9
    // state[14] = block_len
    uxtb    w14, w10
    // state[15] = flags
    uxtb    w15, w11

    // Initialize state[0..7] = cv[0..7] from x19
    ldp     w0, w1, [x19, #0]
    ldp     w2, w3, [x19, #8]
    ldp     w4, w5, [x19, #16]
    ldp     w6, w7, [x19, #24]

    // Initialize state[8..11] = IV[0..3]
    movz    w8,  #0xE667
    movk    w8,  #0x6A09, lsl #16
    movz    w9,  #0xAE85
    movk    w9,  #0xBB67, lsl #16
    movz    w10, #0xF372
    movk    w10, #0x3C6E, lsl #16
    movz    w11, #0xF53A
    movk    w11, #0xA54F, lsl #16

    // Round 0
    // 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    round_seq 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15

    // Round 1
    // 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
    round_seq 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8

    // Round 2
    // 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1
    round_seq 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1

    // Round 3
    // 10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6
    round_seq 10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6

    // Round 4
    // 12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4
    round_seq 12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4

    // Round 5
    // 9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7
    round_seq 9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7

    // Round 6
    // 11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13
    round_seq 11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13

    // Finalize: new_cv[i] = v[i] ^ v[i+8]
    eor     w16, w0, w8
    eor     w17, w1, w9
    stp     w16, w17, [x19, #0]

    eor     w16, w2, w10
    eor     w17, w3, w11
    stp     w16, w17, [x19, #8]

    eor     w16, w4, w12
    eor     w17, w5, w13
    stp     w16, w17, [x19, #16]

    eor     w16, w6, w14
    eor     w17, w7, w15
    stp     w16, w17, [x19, #24]

    // Restore callee-saved regs
    ldp     x19, x20, [sp], #16
    ret

.size blake3_compress_in_place_neon, .-blake3_compress_in_place_neon

#endif