#!/usr/bin/env python3
# GF(2^128) 验证：v0 + delta*v1 + delta^2*v2 == verifier_term

def int_from_le_hex(h):
    """Parse little-endian hex string to integer"""
    b = bytes.fromhex(h)
    return int.from_bytes(b, 'little')

# GF(2^128) polynomial: x^128 + x^7 + x^2 + x + 1
MODULUS = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1

def gf128_mul(a, b):
    r = 0
    for _ in range(128):
        if b & 1:
            r ^= a
        a <<= 1
        if a >> 128:
            a ^= MODULUS
        b >>= 1
    return r

def gf128_add(a, b):
    return a ^ b

# From the debug output (single run)
v0_hex = "12e0fc7b47313871e455e4b26caa1a28"
v1_hex = "5d93f12075a788db59ef4da857728ca5"
v2_hex = "7c40597eaf3c6f40158d27c48fe03d8b"
delta_hex = "c3a4f9ec9c67f3e6edb50926765e8a00"
term_hex = "39b4cedb6d7ed7465ed39eb6ff7d9c30"

v0 = int_from_le_hex(v0_hex)
v1 = int_from_le_hex(v1_hex)
v2 = int_from_le_hex(v2_hex)
delta = int_from_le_hex(delta_hex)
term = int_from_le_hex(term_hex)

delta_sq = gf128_mul(delta, delta)

# v0 + delta*v1 + delta^2*v2
computed = gf128_add(gf128_add(v0, gf128_mul(delta, v1)), gf128_mul(delta_sq, v2))

print(f"v0          = {hex(v0)}")
print(f"delta       = {hex(delta)}")
print(f"delta^2     = {hex(delta_sq)}")
print(f"computed    = {hex(computed)}")
print(f"term        = {hex(term)}")
print(f"v0+d*v1+d2*v2 == term: {computed == term}")
print()
# Also check if term == v0 alone (maybe verifier uses different combination)
print(f"v0 == term: {v0 == term}")
# Check if verifier uses term = v0 + delta*v1 (no v2)
computed2 = gf128_add(v0, gf128_mul(delta, v1))
print(f"v0 + delta*v1 == term: {computed2 == term}")
