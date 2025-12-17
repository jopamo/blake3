#if defined(__aarch64__)

.text
.align 4
.global blake3_compress_in_place_neon
.type blake3_compress_in_place_neon, %function

// void blake3_compress_in_place_neon(
//     uint32_t cv[8],         // x0
//     const uint8_t block[64],// x1
//     uint8_t block_len,      // w2
//     uint64_t counter,       // x3
//     uint8_t flags           // w4
// )

blake3_compress_in_place_neon:
    // Save callee-saved registers x19, x20
    stp     x19, x20, [sp, #-16]!

    // Keep pointers in x19 (cv) and x20 (block)
    mov     x19, x0
    mov     x20, x1

    // Load state w0-w7 from cv (x19)
    ldp     w0, w1, [x19, #0]
    ldp     w2, w3, [x19, #8]
    ldp     w4, w5, [x19, #16]
    ldp     w6, w7, [x19, #24]

    // Load IV into w8-w11
    // IV[0] = 0x6A09E667
    mov     w8, #0xE667
    movk    w8, #0x6A09, lsl #16
    // IV[1] = 0xBB67AE85
    mov     w9, #0xAE85
    movk    w9, #0xBB67, lsl #16
    // IV[2] = 0x3C6EF372
    mov     w10, #0xF372
    movk    w10, #0x3C6E, lsl #16
    // IV[3] = 0xA54FF53A
    mov     w11, #0xF53A
    movk    w11, #0xA54F, lsl #16

    // Load counter into w12, w13
    mov     w12, w3             // Low 32 bits of counter
    lsr     x9, x3, #32         // Use x9 (scratch) for high bits shift
    mov     w13, w9             // High 32 bits of counter

    // Load block_len and flags into w14, w15
    uxtb    w14, w2
    uxtb    w15, w4

    // Define G macro
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

    // Round 0
    // Schedule: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    ldr     w16, [x20, #0]      // m0
    ldr     w17, [x20, #4]      // m1
    G       w0, w4, w8, w12, w16, w17

    ldr     w16, [x20, #8]      // m2
    ldr     w17, [x20, #12]     // m3
    G       w1, w5, w9, w13, w16, w17

    ldr     w16, [x20, #16]     // m4
    ldr     w17, [x20, #20]     // m5
    G       w2, w6, w10, w14, w16, w17

    ldr     w16, [x20, #24]     // m6
    ldr     w17, [x20, #28]     // m7
    G       w3, w7, w11, w15, w16, w17

    // Diagonals R0
    ldr     w16, [x20, #32]     // m8
    ldr     w17, [x20, #36]     // m9
    G       w0, w5, w10, w15, w16, w17

    ldr     w16, [x20, #40]     // m10
    ldr     w17, [x20, #44]     // m11
    G       w1, w6, w11, w12, w16, w17

    ldr     w16, [x20, #48]     // m12
    ldr     w17, [x20, #52]     // m13
    G       w2, w7, w8, w13, w16, w17

    ldr     w16, [x20, #56]     // m14
    ldr     w17, [x20, #60]     // m15
    G       w3, w4, w9, w14, w16, w17

    // Round 1
    // Schedule: 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
    ldr     w16, [x20, #8]      // m2
    ldr     w17, [x20, #24]     // m6
    G       w0, w4, w8, w12, w16, w17

    ldr     w16, [x20, #12]     // m3
    ldr     w17, [x20, #40]     // m10
    G       w1, w5, w9, w13, w16, w17

    ldr     w16, [x20, #28]     // m7
    ldr     w17, [x20, #0]      // m0
    G       w2, w6, w10, w14, w16, w17

    ldr     w16, [x20, #16]     // m4
    ldr     w17, [x20, #52]     // m13
    G       w3, w7, w11, w15, w16, w17

    // Diagonals R1
    ldr     w16, [x20, #4]      // m1
    ldr     w17, [x20, #44]     // m11
    G       w0, w5, w10, w15, w16, w17

    ldr     w16, [x20, #48]     // m12
    ldr     w17, [x20, #20]     // m5
    G       w1, w6, w11, w12, w16, w17

    ldr     w16, [x20, #36]     // m9
    ldr     w17, [x20, #56]     // m14
    G       w2, w7, w8, w13, w16, w17

    ldr     w16, [x20, #60]     // m15
    ldr     w17, [x20, #32]     // m8
    G       w3, w4, w9, w14, w16, w17

    // Round 2
    // Schedule: 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1
    ldr     w16, [x20, #12]     // m3
    ldr     w17, [x20, #16]     // m4
    G       w0, w4, w8, w12, w16, w17

    ldr     w16, [x20, #40]     // m10
    ldr     w17, [x20, #48]     // m12
    G       w1, w5, w9, w13, w16, w17

    ldr     w16, [x20, #52]     // m13
    ldr     w17, [x20, #8]      // m2
    G       w2, w6, w10, w14, w16, w17

    ldr     w16, [x20, #28]     // m7
    ldr     w17, [x20, #56]     // m14
    G       w3, w7, w11, w15, w16, w17

    // Diagonals R2
    ldr     w16, [x20, #24]     // m6
    ldr     w17, [x20, #20]     // m5
    G       w0, w5, w10, w15, w16, w17

    ldr     w16, [x20, #36]     // m9
    ldr     w17, [x20, #0]      // m0
    G       w1, w6, w11, w12, w16, w17

    ldr     w16, [x20, #44]     // m11
    ldr     w17, [x20, #60]     // m15
    G       w2, w7, w8, w13, w16, w17

    ldr     w16, [x20, #32]     // m8
    ldr     w17, [x20, #4]      // m1
    G       w3, w4, w9, w14, w16, w17

    // Round 3
    // Schedule: 10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6
    ldr     w16, [x20, #40]     // m10
    ldr     w17, [x20, #28]     // m7
    G       w0, w4, w8, w12, w16, w17

    ldr     w16, [x20, #48]     // m12
    ldr     w17, [x20, #36]     // m9
    G       w1, w5, w9, w13, w16, w17

    ldr     w16, [x20, #56]     // m14
    ldr     w17, [x20, #12]     // m3
    G       w2, w6, w10, w14, w16, w17

    ldr     w16, [x20, #52]     // m13
    ldr     w17, [x20, #60]     // m15
    G       w3, w7, w11, w15, w16, w17

    // Diagonals R3
    ldr     w16, [x20, #16]     // m4
    ldr     w17, [x20, #0]      // m0
    G       w0, w5, w10, w15, w16, w17

    ldr     w16, [x20, #44]     // m11
    ldr     w17, [x20, #8]      // m2
    G       w1, w6, w11, w12, w16, w17

    ldr     w16, [x20, #20]     // m5
    ldr     w17, [x20, #32]     // m8
    G       w2, w7, w8, w13, w16, w17

    ldr     w16, [x20, #4]      // m1
    ldr     w17, [x20, #24]     // m6
    G       w3, w4, w9, w14, w16, w17

    // Round 4
    // Schedule: 12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4
    ldr     w16, [x20, #48]     // m12
    ldr     w17, [x20, #52]     // m13
    G       w0, w4, w8, w12, w16, w17

    ldr     w16, [x20, #36]     // m9
    ldr     w17, [x20, #44]     // m11
    G       w1, w5, w9, w13, w16, w17

    ldr     w16, [x20, #60]     // m15
    ldr     w17, [x20, #40]     // m10
    G       w2, w6, w10, w14, w16, w17

    ldr     w16, [x20, #56]     // m14
    ldr     w17, [x20, #32]     // m8
    G       w3, w7, w11, w15, w16, w17

    // Diagonals R4
    ldr     w16, [x20, #28]     // m7
    ldr     w17, [x20, #8]      // m2
    G       w0, w5, w10, w15, w16, w17

    ldr     w16, [x20, #20]     // m5
    ldr     w17, [x20, #12]     // m3
    G       w1, w6, w11, w12, w16, w17

    ldr     w16, [x20, #0]      // m0
    ldr     w17, [x20, #4]      // m1
    G       w2, w7, w8, w13, w16, w17

    ldr     w16, [x20, #24]     // m6
    ldr     w17, [x20, #16]     // m4
    G       w3, w4, w9, w14, w16, w17

    // Round 5
    // Schedule: 9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7
    ldr     w16, [x20, #36]     // m9
    ldr     w17, [x20, #56]     // m14
    G       w0, w4, w8, w12, w16, w17

    ldr     w16, [x20, #44]     // m11
    ldr     w17, [x20, #20]     // m5
    G       w1, w5, w9, w13, w16, w17

    ldr     w16, [x20, #32]     // m8
    ldr     w17, [x20, #48]     // m12
    G       w2, w6, w10, w14, w16, w17

    ldr     w16, [x20, #60]     // m15
    ldr     w17, [x20, #4]      // m1
    G       w3, w7, w11, w15, w16, w17

    // Diagonals R5
    ldr     w16, [x20, #52]     // m13
    ldr     w17, [x20, #12]     // m3
    G       w0, w5, w10, w15, w16, w17

    ldr     w16, [x20, #0]      // m0
    ldr     w17, [x20, #40]     // m10
    G       w1, w6, w11, w12, w16, w17

    ldr     w16, [x20, #8]      // m2
    ldr     w17, [x20, #24]     // m6
    G       w2, w7, w8, w13, w16, w17

    ldr     w16, [x20, #16]     // m4
    ldr     w17, [x20, #28]     // m7
    G       w3, w4, w9, w14, w16, w17

    // Round 6
    // Schedule: 11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13
    ldr     w16, [x20, #44]     // m11
    ldr     w17, [x20, #60]     // m15
    G       w0, w4, w8, w12, w16, w17

    ldr     w16, [x20, #20]     // m5
    ldr     w17, [x20, #0]      // m0
    G       w1, w5, w9, w13, w16, w17

    ldr     w16, [x20, #4]      // m1
    ldr     w17, [x20, #36]     // m9
    G       w2, w6, w10, w14, w16, w17

    ldr     w16, [x20, #32]     // m8
    ldr     w17, [x20, #24]     // m6
    G       w3, w7, w11, w15, w16, w17

    // Diagonals R6
    ldr     w16, [x20, #56]     // m14
    ldr     w17, [x20, #40]     // m10
    G       w0, w5, w10, w15, w16, w17

    ldr     w16, [x20, #8]      // m2
    ldr     w17, [x20, #48]     // m12
    G       w1, w6, w11, w12, w16, w17

    ldr     w16, [x20, #12]     // m3
    ldr     w17, [x20, #16]     // m4
    G       w2, w7, w8, w13, w16, w17

    ldr     w16, [x20, #28]     // m7
    ldr     w17, [x20, #52]     // m13
    G       w3, w4, w9, w14, w16, w17

    // Finalize
    // cv[i] = cv[i] ^ cv[i+8]
    eor     w0, w0, w8
    eor     w1, w1, w9
    stp     w0, w1, [x19, #0]

    eor     w2, w2, w10
    eor     w3, w3, w11
    stp     w2, w3, [x19, #8]

    eor     w4, w4, w12
    eor     w5, w5, w13
    stp     w4, w5, [x19, #16]

    eor     w6, w6, w14
    eor     w7, w7, w15
    stp     w6, w7, [x19, #24]

    // Restore callee-saved registers
    ldp     x19, x20, [sp], #16
    ret

.size blake3_compress_in_place_neon, .-blake3_compress_in_place_neon

#endif