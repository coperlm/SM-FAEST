#!/usr/bin/env python3
# Verify polynomial relationship: v0 + delta*v1 + delta^2*v2 == verifier_x
# Data from debug log (step=0 of keyexp round=0 pos=0)

v0    = bytes.fromhex("21d1ea0da68677a722257d8e27706c00")
v1    = bytes.fromhex("2296cb30d256a8aad0fedcb969a0cb73")
v2    = bytes.fromhex("c8ba8f2b83b318fdf0438b09d33310af")
x_ver = bytes.fromhex("266f695cf61694c1f99703d457ea9394")
delta = bytes.fromhex("1945b266a5bcdd7839606d3be5280f00")

def gf128_mul(a_bytes, b_bytes):
    """GF(2^128) multiplication, reduction by x^128 + x^7 + x^2 + x + 1"""
    a = int.from_bytes(a_bytes, 'little')
    b = int.from_bytes(b_bytes, 'little')
    result = 0
    for i in range(128):
        if (b >> i) & 1:
            result ^= (a << i)
    # Reduce modulo x^128 + x^7 + x^2 + x + 1
    for i in range(255, 127, -1):
        if (result >> i) & 1:
            # XOR with polynomial shifted
            # x^128 + x^7 + x^2 + x + 1
            result ^= (1 << (i-128)) ^ (1 << (i-121)) ^ (1 << (i-126)) ^ (1 << (i-127))
    result &= (1 << 128) - 1
    return result.to_bytes(16, 'little')

def xor16(a, b):
    return bytes(x^y for x,y in zip(a,b))

delta_sq = gf128_mul(delta, delta)
d_v1     = gf128_mul(delta, v1)
d2_v2    = gf128_mul(delta_sq, v2)
expected = xor16(xor16(v0, d_v1), d2_v2)

print(f"delta:    {delta.hex()}")
print(f"delta^2:  {delta_sq.hex()}")
print(f"v0:       {v0.hex()}")
print(f"delta*v1: {d_v1.hex()}")
print(f"d^2*v2:   {d2_v2.hex()}")
print(f"expected: {expected.hex()}")
print(f"verif x:  {x_ver.hex()}")
print(f"match:    {expected == x_ver}")
