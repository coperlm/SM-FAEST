#!/usr/bin/env python3
"""SM4 Galois helper prototype checks.

验证目标：
1) c * a^2 * a^16 == a（c = Norm(a)^-1）
2) trace 的基本性质（线性 + trace(x^2)=trace(x)）
"""

from __future__ import annotations

SM4_MOD = 0xF5


def gf_mul(a: int, b: int) -> int:
    a &= 0xFF
    b &= 0xFF
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= SM4_MOD
        b >>= 1
    return out


def gf_sq(a: int) -> int:
    return gf_mul(a, a)


def gf_pow(a: int, e: int) -> int:
    r = 1
    x = a & 0xFF
    while e:
        if e & 1:
            r = gf_mul(r, x)
        x = gf_sq(x)
        e >>= 1
    return r


def field_trace(x: int) -> int:
    t = x & 0xFF
    p = x & 0xFF
    for _ in range(7):
        p = gf_sq(p)
        t ^= p
    return bin(t).count("1") & 1


def conjugates(x: int) -> tuple[int, int, int, int]:
    x2 = gf_sq(x)
    x4 = gf_sq(x2)
    x8 = gf_sq(x4)
    x16 = gf_sq(x8)
    return x2, x4, x8, x16


def field_norm(x: int) -> int:
    x2, x4, x8, x16 = conjugates(x)
    _ = (x2, x4, x8)
    return gf_mul(x, x16)


def check_identity() -> None:
    for a in range(1, 256):
        a2, _, _, a16 = conjugates(a)
        c = gf_pow(field_norm(a), 14)
        lhs = gf_mul(gf_mul(c, a2), a16)
        assert lhs == a, f"identity failed at a={a:#04x}, lhs={lhs:#04x}"


def check_trace() -> None:
    for x in range(256):
        assert field_trace(gf_sq(x)) == field_trace(x), f"trace frobenius failed at {x:#04x}"
    for x in range(256):
        for y in range(256):
            assert field_trace(x ^ y) == (field_trace(x) ^ field_trace(y)), (
                f"trace linear failed at {x:#04x},{y:#04x}"
            )


def main() -> None:
    check_identity()
    check_trace()
    print("ok: c*a^2*a^16==a and trace checks passed for all 256 elements")


if __name__ == "__main__":
    main()
