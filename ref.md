AES and SM4 https://gemini.google.com/app/a10b1f7cfaa924a6

其他参考
https://sxyz.blog/aes-from-scratch/
https://www.cnblogs.com/vegetableDD/p/11866251.html

把 AES 改成 SM4 需要重点改的代码点 🔧
S‑box 表达与 degree‑split：aes_SSS_sbox_affine_*、aes_SSS_inverse_affine_* → 用 SM4 S‑box + 等效分解。
线性层：删除/替换 ShiftRows + MixColumns 的约束，改为 SM4 的 L 变换（轮函数中的线性变换）。
轮函数管线：aes_SSS_enc_constraints_*（把 AES 每轮约束改为 SM4 每轮约束）。
密钥调度：aes_SSS_keyexp_* 与 aes_SSS_expkey_constraints_* → 替为 SM4 的 key schedule 与相应约束。
参数与实例：在 instances.c/h 与参数模板中添加 SM4 对应的 lambda/Nst/Ske 等。
测试与向量：修改/添加单元测试以覆盖 SM4 case（tests）。
