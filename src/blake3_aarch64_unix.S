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

.macro G a, b, c, d, mx, my
    add     \a, \a, \b
    add     \a, \a, \mx
    eor     \d, \d, \a
    ror     \d, \d, #16
    add     \c, \c, \d
    eor     \b, \b, \c
    ror     \b, \b, #12

    add     \a, \a, \b
    add     \a, \a, \my
    eor     \d, \d, \a
    ror     \d, \d, #8
    add     \c, \c, \d
    eor     \b, \b, \c
    ror     \b, \b, #7
.endm

// One round macro, pass the 16 message indices for this round
.macro ROUND m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15
    // column step
    ldr w16, [x1, #(\m0*4)]
    ldr w17, [x1, #(\m1*4)]
    G w0, w4, w8,  w12, w16, w17

    ldr w16, [x1, #(\m2*4)]
    ldr w17, [x1, #(\m3*4)]
    G w1, w5, w9,  w13, w16, w17

    ldr w16, [x1, #(\m4*4)]
    ldr w17, [x1, #(\m5*4)]
    G w2, w6, w10, w14, w16, w17

    ldr w16, [x1, #(\m6*4)]
    ldr w17, [x1, #(\m7*4)]
    G w3, w7, w11, w15, w16, w17

    // diagonal step
    ldr w16, [x1, #(\m8*4)]
    ldr w17, [x1, #(\m9*4)]
    G w0, w5, w10, w15, w16, w17

    ldr w16, [x1, #(\m10*4)]
    ldr w17, [x1, #(\m11*4)]
    G w1, w6, w11, w12, w16, w17

    ldr w16, [x1, #(\m12*4)]
    ldr w17, [x1, #(\m13*4)]
    G w2, w7, w8,  w13, w16, w17

    ldr w16, [x1, #(\m14*4)]
    ldr w17, [x1, #(\m15*4)]
    G w3, w4, w9,  w14, w16, w17
.endm

blake3_compress_in_place_neon:
    // preserve callee-saved regs if you use them
    stp x19, x20, [sp, #-16]!
    mov x19, x0

    // load cv into w0..w7
    ldp w0, w1, [x19, #0]
    ldp w2, w3, [x19, #8]
    ldp w4, w5, [x19, #16]
    ldp w6, w7, [x19, #24]

    // IV into w8..w11
    // IV = 6A09E667 BB67AE85 3C6EF372 A54FF53A
    movz w8,  #0xE667
    movk w8,  #0x6A09, lsl #16
    movz w9,  #0xAE85
    movk w9,  #0xBB67, lsl #16
    movz w10, #0xF372
    movk w10, #0x3C6E, lsl #16
    movz w11, #0xF53A
    movk w11, #0xA54F, lsl #16

    // counter, block_len, flags into w12..w15
    // Adjusted mapping for:
    // x0=cv, x1=block, w2=block_len, x3=counter, w4=flags
    
    // w12 = counter_low (from x3)
    mov  w12, w3
    
    // w13 = counter_high (from x3 >> 32)
    lsr  x20, x3, #32
    mov  w13, w20
    
    // w14 = block_len (from w2)
    mov  w14, w2
    
    // w15 = flags (from w4)
    mov  w15, w4

    // 7 rounds
    ROUND  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15
    ROUND  2, 6, 3,10, 7, 0, 4,13, 1,11,12, 5, 9,14,15, 8
    ROUND  3, 4,10,12,13, 2, 7,14, 6, 5, 9, 0,11,15, 8, 1
    ROUND 10, 7,12, 9,14, 3,13,15, 4, 0,11, 2, 5, 8, 1, 6
    ROUND 12,13, 9,11,15,10,14, 8, 7, 2, 5, 3, 0, 1, 6, 4
    ROUND  9,14,11, 5, 8,12,15, 1,13, 3, 0,10, 2, 6, 4, 7
    ROUND 11,15, 5, 0, 1, 9, 8, 6,14,10, 2,12, 3, 4, 7,13

    // finalize cv[i] = cv[i] ^ v[i] ^ v[i+8]
    ldp w16, w17, [x19, #0]
    eor w16, w16, w0
    eor w16, w16, w8
    eor w17, w17, w1
    eor w17, w17, w9
    stp w16, w17, [x19, #0]

    ldp w16, w17, [x19, #8]
    eor w16, w16, w2
    eor w16, w16, w10
    eor w17, w17, w3
    eor w17, w17, w11
    stp w16, w17, [x19, #8]

    ldp w16, w17, [x19, #16]
    eor w16, w16, w4
    eor w16, w16, w12
    eor w17, w17, w5
    eor w17, w17, w13
    stp w16, w17, [x19, #16]

    ldp w16, w17, [x19, #24]
    eor w16, w16, w6
    eor w16, w16, w14
    eor w17, w17, w7
    eor w17, w17, w15
    stp w16, w17, [x19, #24]

    ldp x19, x20, [sp], #16
    ret

.size blake3_compress_in_place_neon, .-blake3_compress_in_place_neon

#endif
