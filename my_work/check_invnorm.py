#!/usr/bin/env python3
"""
Check if sm4_invnorm(x) == low 4 bits of inverse_affine(sbox(x))
"""

SM4_POLY = 0xF5

def bf8m(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= (SM4_POLY | 0x100)
            a &= 0xFF
        else:
            a &= 0xFF
        b >>= 1
    return r

def bf8s(a): return bf8m(a, a)

SM4_SBOX = [
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x79,0xee,0xef,0x00,0x00,0x00,0x00,0x00,0x00
]

def sm4_sbox(x): return SM4_SBOX[x]

def rotl8(v, n): return ((v << n) | (v >> (8 - n))) & 0xFF

def inverse_affine(sbox_out):
    y = sbox_out ^ 0xD6
    return rotl8(y, 7) ^ rotl8(y, 5) ^ rotl8(y, 1)

def inv238(x):
    y = bf8s(x)     # x^2
    x = bf8s(y)     # x^4
    y = bf8m(x, y)  # x^6
    x = bf8s(x)     # x^8
    y = bf8m(x, y)  # x^14
    x = bf8s(x)     # x^16
    x = bf8s(x)     # x^32
    y = bf8m(x, y)  # x^46
    x = bf8s(x)     # x^64
    y = bf8m(x, y)  # x^110
    x = bf8s(x)     # x^128
    x = bf8m(x, y)  # x^238
    return x

def invnorm(x):
    # Extract bits at positions (0, 2, 4, 5) -> output bits (0, 1, 2, 3)
    v = inv238(x)
    return ((v >> 0) & 1) | (((v >> 2) & 1) << 1) | (((v >> 4) & 1) << 2) | (((v >> 5) & 1) << 3)

# GF(256) inverse
def gf_inv(x):
    if x == 0: return 0
    for y in range(256):
        if bf8m(x, y) == 1:
            return y
    return 0

print("=== Comparing sm4_invnorm(x) vs inverse_affine(sbox(x)) low 4 bits ===")
mismatches = 0
for x in range(256):
    norm = invnorm(x)
    ia = inverse_affine(sm4_sbox(x))
    ia4 = ia & 0xF
    if norm != ia4:
        mismatches += 1
        if mismatches <= 10:
            print(f"  x={x:#04x}: invnorm={norm:#06b}({norm}), ia_low4={ia4:#06b}({ia4}), full_ia={ia:#04x}")

if mismatches == 0:
    print("ALL 256 values: invnorm(x) == inverse_affine(sbox(x)) & 0xF  ✓")
else:
    print(f"MISMATCHES: {mismatches}/256")

print()
print("=== Checking inverse_affine(sbox(x)) == GF_inv(x) ===")
ia_inv_match = 0
for x in range(256):
    ia = inverse_affine(sm4_sbox(x))
    gi = gf_inv(x)
    if ia == gi:
        ia_inv_match += 1

print(f"inverse_affine(sbox(x)) == GF_inv(x): {ia_inv_match}/256 match")
print()

# Now check what the even-round prover actually does:
# sbox_out -> inverse_affine -> take bits [0,1,2,3]
# compare with invnorm(sbox_input)
print("=== Even-round: inverse_affine(sbox_out) bits 0..3  vs  invnorm(sbox_input) ===")
print("(prover derives sbox_out from state, then takes inverse_affine, then bits 0..3)")
even_mismatches = 0
for x in range(256):
    sout = sm4_sbox(x)
    ia_of_sout = inverse_affine(sout)  # This is what even-round prover computes
    ia4 = ia_of_sout & 0xF            # proto takes bits 0..3
    norm = invnorm(x)                  # This is odd-round witness value
    if ia4 != norm:
        even_mismatches += 1
        if even_mismatches <= 5:
            print(f"  x={x:#04x}: ia(sout)&0xF={ia4:#06b}, invnorm={norm:#06b}")

if even_mismatches == 0:
    print("ALL: inverse_affine(sbox(x)) & 0xF == invnorm(x)  ✓")
else:
    print(f"MISMATCHES: {even_mismatches}/256")

print()
# What does inv_norm_to_conjugates use? It uses x_val bits 0,1,2,3
# For odd round: x_val = invnorm = bits from inv238(sbox_input)
# For even round: x_val = inverse_affine(sbox_out) = full 8-bit inverse
print("=== Key question: are bits 0,1,2,3 of inverse_affine(sbox(x)) == invnorm(x)? ===")
# invnorm takes bits 0,2,4,5 of inv238(x) as bits 0,1,2,3
# inverse_affine(sbox(x)) takes bits 0,1,2,3 naturally
# These would match only if bits (0,2,4,5) of inv238(x) == bits (0,1,2,3) of inverse_affine(sbox(x))
q1_mismatches = 0
for x in range(1, 256):
    norm = invnorm(x)  # bits(0,2,4,5) of x^238 -> remapped to (0,1,2,3)
    ia = inverse_affine(sm4_sbox(x))  # full 8-bit, take bits 0..3
    ia4 = ia & 0xF
    if norm != ia4:
        q1_mismatches += 1
        if q1_mismatches <= 5:
            raw = inv238(x)
            print(f"  x={x:#04x}: inv238={raw:#04x}, norm4={norm}, ia_bits0-3={ia4}, "
                  f"ia={ia:#04x}")

if q1_mismatches == 0:
    print("MATCH: invnorm(x) == low4(inverse_affine(sbox(x))) for all nonzero x  ✓")
else:
    print(f"MISMATCH: {q1_mismatches}/255 differ")
