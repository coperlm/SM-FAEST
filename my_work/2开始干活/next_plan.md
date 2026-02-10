Context for Copilot:We are implementing SM4 constraints for FAEST. The current implementation of sm4_invnorm is failing tests (1/255 passing). We have identified two critical root causes that must be fixed simultaneously:Affine Constant/Matrix: The constant should be 0xD6 (derived from Sbox[0]), and the inverse linear transform matrix needs to be exact.Field Incompatibility (CRITICAL): SM4 uses polynomial 0x1F5 ($x^8+x^7+x^6+x^5+x^4+x^2+1$), but the FAEST backend (bfSSS_mul) is hardcoded for AES polynomial 0x11B. We cannot verify $x \cdot z = 1$ unless we map the SM4 values into the AES field before multiplication.Action Required:Please create a Python script to generate the correct C header files, and then update faest_sm4.c.Step 1: Create/Run Generator Script (gen_sm4_constants.py)Create a Python script to calculate two matrices:SM4_INV_AFFINE: Solves $z = L^{-1}(y \oplus 0xD6)$.SM4_TO_AES_ISO: A linear isomorphism matrix $T$ that maps elements from $GF(2^8)_{SM4}$ to $GF(2^8)_{AES}$. This is required so that $T(a) \cdot_{AES} T(b) = T(a \cdot_{SM4} b)$.Use this logic for the script:

import galois # pip install galois
import numpy as np

# 1. Setup Fields
GF_SM4 = galois.GF(2**8, irreducible_poly=0x1F5)
GF_AES = galois.GF(2**8, irreducible_poly=0x11B)

# 2. Solve Isomorphism (Naive brute force or standard basis change)
# We need T such that T(x) is the representation of x in AES field.
# Since both are GF(2^8), they are isomorphic. We map the generator x (0x02) to a root of 0x1F5 in GF_AES.
# Find root of SM4 poly in AES field:
poly_sm4 = galois.Poly([1, 1, 1, 1, 1, 0, 1, 0, 1], field=GF_AES) # 0x1F5 coefficients
roots = poly_sm4.roots()
if len(roots) == 0: raise ValueError("No isomorphism found")
primitive_element = roots[0] # This element in AES field behaves like 'x' in SM4 field

# Build Transform Matrix M (8x8)
# Column j is the vector representation of (primitive_element^j) in AES field
M_iso = np.zeros((8, 8), dtype=int)
for j in range(8):
    val = primitive_element ** j
    # vector representation (LSB at index 0 or 7 depends on endianness, usually LSB=bit0)
    # FAEST usually assumes little-endian bits in byte
    vec = val.vector() # galois returns MSB->LSB usually
    M_iso[:, j] = vec[::-1] # Check endianness with FAEST conventions

# 3. Solve Inverse Affine (as discussed previously)
# Target: z = Matrix * (y + 0xD6)
# ... (Use the logic from previous turn to solve this matrix)

Step 2: Update faest_sm4.c
Refactor the constraints prover to use this pipeline:

// 1. Get S-box output from ciphertext
bf8_t y = ...; 

// 2. Inverse Affine (SM4 Domain)
// z_sm4 = L_inv(y ^ 0xD6)
bf8_t z_sm4 = apply_matrix(SM4_INV_AFFINE, bf8_add(y, 0xD6));

// 3. Basis Change (SM4 -> AES Domain)
// Map both input x and calculated inverse z to AES field
bf8_t x_aes = apply_matrix(SM4_TO_AES_ISO, x_input);
bf8_t z_aes = apply_matrix(SM4_TO_AES_ISO, z_sm4);

// 4. Constraint (AES Domain)
// Now we can use FAEST's native multiplier
// Constraint: x_aes * z_aes == 1 (in AES field)
bf8_t product = bf8_mul(x_aes, z_aes);
// Assert product == 1 (or add to ZK trace)

Immediate Request: Write the full gen_sm4_constants.py to generate these matrices as C arrays, and then show me the modified sm4_sbox_constraints function that applies the Isomorphism before the multiplication constraint.