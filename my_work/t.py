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

def bf8s(a):
    return bf8m(a, a)

def inv238(x):
    # 238 = 0b11101110
    y = bf8s(x)         # x^2
    x = bf8s(y)         # x^4
    y = bf8m(x, y)      # x^6
    x = bf8s(x)         # x^8
    y = bf8m(x, y)      # x^14
    x = bf8s(x)         # x^16
    x = bf8s(x)         # x^32
    y = bf8m(x, y)      # x^46
    x = bf8s(x)         # x^64
    y = bf8m(x, y)      # x^110
    x = bf8s(x)         # x^128
    x = bf8m(x, y)      # x^238
    return x

def invnorm(x):
    v = inv238(x)
    return ((v >> 0) & 1) | (((v >> 2) & 1) << 1) | (((v >> 4) & 1) << 2) | (((v >> 5) & 1) << 3)

print("invnorm(0x81) =", hex(invnorm(0x81)))
print("inv238(0x81) =", hex(inv238(0x81)))
