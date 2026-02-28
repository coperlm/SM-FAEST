#!/usr/bin/env python3
import re
import subprocess
import sys

def int_from_le_hex(h):
    b = bytes.fromhex(h.strip())
    return int.from_bytes(b, 'little')

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

# Run test and capture output
result = subprocess.run(
    ['/home/coper/桌面/FAEST/build/faest_sm4_128s/faest_sm4_128s_api_test'],
    capture_output=True, text=True
)
lines = result.stderr.split('\n')

# Extract delta
delta_val = None
for line in lines:
    m = re.search(r'verifier delta: ([0-9a-f]+)', line)
    if m:
        delta_val = int_from_le_hex(m.group(1))
        break

if delta_val is None:
    print("ERROR: no delta found")
    sys.exit(1)

delta_sq = gf128_mul(delta_val, delta_val)
print(f"delta = {hex(delta_val)}")

# Extract prover h0 states (h0, h1, h2)
prover_h = {}  # step -> (h0, h1, h2)
for line in lines:
    m = re.search(r'zk128_3 update h0 step=(\d+) h0=([0-9a-f]+) h1=([0-9a-f]+) h2=([0-9a-f]+)', line)
    if m:
        step = int(m.group(1))
        h0 = int_from_le_hex(m.group(2))
        h1 = int_from_le_hex(m.group(3))
        h2 = int_from_le_hex(m.group(4))
        prover_h[step] = (h0, h1, h2)

# Extract verifier h0 states
verifier_h = {}  # step -> h0
for line in lines:
    m = re.search(r'zk128 update step=(\d+) h0=([0-9a-f]+) h1=([0-9a-f]+)', line)
    if m:
        step = int(m.group(1))
        h0 = int_from_le_hex(m.group(2))
        h1 = int_from_le_hex(m.group(3))
        verifier_h[step] = (h0, h1)

print(f"prover steps: {len(prover_h)}, verifier steps: {len(verifier_h)}")

# Check consistency: verifier_H0[step] == prover_H0[0][step] + delta * prover_H0[1][step] + delta^2 * prover_H0[2][step]
first_bad = None
for step in sorted(prover_h.keys()):
    if step not in verifier_h:
        continue
    ph0, ph1, ph2 = prover_h[step]
    vh0, vh1 = verifier_h[step]
    
    expected_vh0 = gf128_add(gf128_add(ph0, gf128_mul(delta_val, ph1)), gf128_mul(delta_sq, ph2))
    
    if expected_vh0 != vh0:
        if first_bad is None:
            first_bad = step
            print(f"FIRST MISMATCH at step {step}:")
            print(f"  prover H0[0] = {hex(ph0)}")
            print(f"  prover H0[1] = {hex(ph1)}")
            print(f"  prover H0[2] = {hex(ph2)}")
            print(f"  expected verifier H0 = {hex(expected_vh0)}")
            print(f"  actual verifier H0   = {hex(vh0)}")

if first_bad is None:
    print("All steps consistent! (hashes match)")
else:
    print(f"\nTotal: first mismatch at step {first_bad}")
