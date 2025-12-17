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

blake3_compress_in_place_neon:
    // Save callee-saved regs
    stp     x19, x20, [sp, #-16]!

    mov     x19, x0 // cv pointer
    mov     x20, x1 // block pointer

    // state[12..15] = counter_low, counter_high, block_len, flags
    mov     w12, w3
    lsr     x9, x3, #32
    mov     w13, w9
    uxtb    w14, w2
    uxtb    w15, w4

    // state[0..7] = cv[0..7]
    ldp     w0, w1, [x19, #0]
    ldp     w2, w3, [x19, #8]
    ldp     w4, w5, [x19, #16]
    ldp     w6, w7, [x19, #24]

    // state[8..11] = IV[0..3]
    movz    w8,  #0xE667
    movk    w8,  #0x6A09, lsl #16
    movz    w9,  #0xAE85
    movk    w9,  #0xBB67, lsl #16
    movz    w10, #0xF372
    movk    w10, #0x3C6E, lsl #16
    movz    w11, #0xF53A
    movk    w11, #0xA54F, lsl #16

    // Rounds
    .irp r, 0, 1, 2, 3, 4, 5, 6
        // Round \r
        // Column step
        .if \r == 0
            ldr w16, [x20, #0];  ldr w17, [x20, #4];  G w0, w4, w8,  w12, w16, w17
            ldr w16, [x20, #8];  ldr w17, [x20, #12]; G w1, w5, w9,  w13, w16, w17
            ldr w16, [x20, #16]; ldr w17, [x20, #20]; G w2, w6, w10, w14, w16, w17
            ldr w16, [x20, #24]; ldr w17, [x20, #28]; G w3, w7, w11, w15, w16, w17
        .elif \r == 1
            ldr w16, [x20, #8];  ldr w17, [x20, #24]; G w0, w4, w8,  w12, w16, w17
            ldr w16, [x20, #12]; ldr w17, [x20, #40]; G w1, w5, w9,  w13, w16, w17
            ldr w16, [x20, #28]; ldr w17, [x20, #0];  G w2, w6, w10, w14, w16, w17
            ldr w16, [x20, #16]; ldr w17, [x20, #52]; G w3, w7, w11, w15, w16, w17
        .elif \r == 2
            ldr w16, [x20, #12]; ldr w17, [x20, #16]; G w0, w4, w8,  w12, w16, w17
            ldr w16, [x20, #40]; ldr w17, [x20, #48]; G w1, w5, w9,  w13, w16, w17
            ldr w16, [x20, #52]; ldr w17, [x20, #8];  G w2, w6, w10, w14, w16, w17
            ldr w16, [x20, #28]; ldr w17, [x20, #56]; G w3, w7, w11, w15, w16, w17
        .elif \r == 3
            ldr w16, [x20, #40]; ldr w17, [x20, #28]; G w0, w4, w8,  w12, w16, w17
            ldr w16, [x20, #48]; ldr w17, [x20, #36]; G w1, w5, w9,  w13, w16, w17
            ldr w16, [x20, #56]; ldr w17, [x20, #12]; G w2, w6, w10, w14, w16, w17
            ldr w16, [x20, #52]; ldr w17, [x20, #60]; G w3, w7, w11, w15, w16, w17
        .elif \r == 4
            ldr w16, [x20, #48]; ldr w17, [x20, #52]; G w0, w4, w8,  w12, w16, w17
            ldr w16, [x20, #36]; ldr w17, [x20, #44]; G w1, w5, w9,  w13, w16, w17
            ldr w16, [x20, #60]; ldr w17, [x20, #40]; G w2, w6, w10, w14, w16, w17
            ldr w16, [x20, #56]; ldr w17, [x20, #32]; G w3, w7, w11, w15, w16, w17
        .elif \r == 5
            ldr w16, [x20, #36]; ldr w17, [x20, #56]; G w0, w4, w8,  w12, w16, w17
            ldr w16, [x20, #44]; ldr w17, [x20, #20]; G w1, w5, w9,  w13, w16, w17
            ldr w16, [x20, #32]; ldr w17, [x20, #48]; G w2, w6, w10, w14, w16, w17
            ldr w16, [x20, #60]; ldr w17, [x20, #4];  G w3, w7, w11, w15, w16, w17
        .elif \r == 6
            ldr w16, [x20, #44]; ldr w17, [x20, #60]; G w0, w4, w8,  w12, w16, w17
            ldr w16, [x20, #20]; ldr w17, [x20, #0];  G w1, w5, w9,  w13, w16, w17
            ldr w16, [x20, #4];  ldr w17, [x20, #36]; G w2, w6, w10, w14, w16, w17
            ldr w16, [x20, #32]; ldr w17, [x20, #24]; G w3, w7, w11, w15, w16, w17
        .endif

        // Diagonal step
        .if \r == 0
            ldr w16, [x20, #32]; ldr w17, [x20, #36]; G w0, w5, w10, w15, w16, w17
            ldr w16, [x20, #40]; ldr w17, [x20, #44]; G w1, w6, w11, w12, w16, w17
            ldr w16, [x20, #48]; ldr w17, [x20, #52]; G w2, w7, w8,  w13, w16, w17
            ldr w16, [x20, #56]; ldr w17, [x20, #60]; G w3, w4, w9,  w14, w16, w17
        .elif \r == 1
            ldr w16, [x20, #4];  ldr w17, [x20, #44]; G w0, w5, w10, w15, w16, w17
            ldr w16, [x20, #48]; ldr w17, [x20, #20]; G w1, w6, w11, w12, w16, w17
            ldr w16, [x20, #36]; ldr w17, [x20, #56]; G w2, w7, w8,  w13, w16, w17
            ldr w16, [x20, #60]; ldr w17, [x20, #32]; G w3, w4, w9,  w14, w16, w17
        .elif \r == 2
            ldr w16, [x20, #24]; ldr w17, [x20, #20]; G w0, w5, w10, w15, w16, w17
            ldr w16, [x20, #36]; ldr w17, [x20, #0];  G w1, w6, w11, w12, w16, w17
            ldr w16, [x20, #44]; ldr w17, [x20, #60]; G w2, w7, w8,  w13, w16, w17
            ldr w16, [x20, #32]; ldr w17, [x20, #4];  G w3, w4, w9,  w14, w16, w17
        .elif \r == 3
            ldr w16, [x20, #16]; ldr w17, [x20, #0];  G w0, w5, w10, w15, w16, w17
            ldr w16, [x20, #44]; ldr w17, [x20, #8];  G w1, w6, w11, w12, w16, w17
            ldr w16, [x20, #20]; ldr w17, [x20, #32]; G w2, w7, w8,  w13, w16, w17
            ldr w16, [x20, #4];  ldr w17, [x20, #24]; G w3, w4, w9,  w14, w16, w17
        .elif \r == 4
            ldr w16, [x20, #28]; ldr w17, [x20, #8];  G w0, w5, w10, w15, w16, w17
            ldr w16, [x20, #20]; ldr w17, [x20, #12]; G w1, w6, w11, w12, w16, w17
            ldr w16, [x20, #0];  ldr w17, [x20, #4];  G w2, w7, w8,  w13, w16, w17
            ldr w16, [x20, #24]; ldr w17, [x20, #16]; G w3, w4, w9,  w14, w16, w17
        .elif \r == 5
            ldr w16, [x20, #52]; ldr w17, [x20, #12]; G w0, w5, w10, w15, w16, w17
            ldr w16, [x20, #0];  ldr w17, [x20, #40]; G w1, w6, w11, w12, w16, w17
            ldr w16, [x20, #8];  ldr w17, [x20, #24]; G w2, w7, w8,  w13, w16, w17
            ldr w16, [x20, #16]; ldr w17, [x20, #28]; G w3, w4, w9,  w14, w16, w17
        .elif \r == 6
            ldr w16, [x20, #56]; ldr w17, [x20, #40]; G w0, w5, w10, w15, w16, w17
            ldr w16, [x20, #8];  ldr w17, [x20, #12]; G w1, w6, w11, w12, w16, w17
            ldr w16, [x20, #12]; ldr w17, [x20, #16]; G w2, w7, w8,  w13, w16, w17
            ldr w16, [x20, #28]; ldr w17, [x20, #52]; G w3, w4, w9,  w14, w16, w17
        .endif
    .endr

    // Finalize: new_cv[i] = old_cv[i] ^ v[i] ^ v[i+8]
    // Load old CV values
    ldp     w16, w17, [x19, #0]
    eor     w16, w16, w0
    eor     w16, w16, w8
    eor     w17, w17, w1
    eor     w17, w17, w9
    stp     w16, w17, [x19, #0]

    ldp     w16, w17, [x19, #8]
    eor     w16, w16, w2
    eor     w16, w16, w10
    eor     w17, w17, w3
    eor     w17, w17, w11
    stp     w16, w17, [x19, #8]

    ldp     w16, w17, [x19, #16]
    eor     w16, w16, w4
    eor     w16, w16, w12
    eor     w17, w17, w5
    eor     w17, w17, w13
    stp     w16, w17, [x19, #16]

    ldp     w16, w17, [x19, #24]
    eor     w16, w16, w6
    eor     w16, w16, w14
    eor     w17, w17, w7
    eor     w17, w17, w15
    stp     w16, w17, [x19, #24]

    // Restore callee-saved regs
    ldp     x19, x20, [sp], #16
    ret

.size blake3_compress_in_place_neon, .-blake3_compress_in_place_neon

#endif