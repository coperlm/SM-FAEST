#!/usr/bin/env python3
# Verify: term == deg3 + delta*deg2 + delta^2*deg1 ?
# Values from debug log (keyexp round=0 pos=0)

deg3  = bytes.fromhex("8e30f0e1603b46f9ce0ebaa4bf77291b")
deg2  = bytes.fromhex("484d6872 55a28a449fa01a2c0678178b".replace(" ",""))
deg1  = bytes.fromhex("24b6c43337acdf1cd938252b94b169b9")
term  = bytes.fromhex("cbb34790e7b584a9f1f123ce157d1d00")
delta = bytes.fromhex("bc3e748a75f9ed2c24fa74ba8be6d601")

def gf128_mul(a_bytes, b_bytes):
    """GF(2^128) multiplication, reduction by x^128 + x^7 + x^2 + x + 1"""
    a = int.from_bytes(a_bytes, 'little')
    b = int.from_bytes(b_bytes, 'little')
    result = 0
    for i in range(128):
        if (b >> i) & 1:
            result ^= (a << i)
    # Reduce modulo x^128 + x^7 + x^2 + x + 1
    # poly = x^128 + x^7 + x^2 + x + 1
    for i in range(255, 127, -1):
        if (result >> i) & 1:
            result ^= (1 << i) ^ (1 << (i-128+7)) ^ (1 << (i-128+2)) ^ (1 << (i-128+1)) ^ (1 << (i-128))
    result &= (1 << 128) - 1
    return result.to_bytes(16, 'little')

def xor16(a, b):
    return bytes(x^y for x,y in zip(a,b))

delta_sq = gf128_mul(delta, delta)
d_deg2   = gf128_mul(delta, deg2)
d2_deg1  = gf128_mul(delta_sq, deg1)
expected = xor16(xor16(deg3, d_deg2), d2_deg1)

print(f"delta:    {delta.hex()}")
print(f"delta^2:  {delta_sq.hex()}")
print(f"deg3:     {deg3.hex()}")
print(f"deg2:     {deg2.hex()}")
print(f"deg1:     {deg1.hex()}")
print(f"d*deg2:   {d_deg2.hex()}")
print(f"d^2*deg1: {d2_deg1.hex()}")
print(f"expected: {expected.hex()}")
print(f"term:     {term.hex()}")
print(f"match:    {expected == term}")
