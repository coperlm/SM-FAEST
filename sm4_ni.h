/*
 *  SPDX-License-Identifier: MIT
 *
 *  SM4 SIMD-accelerated implementation for x86-64.
 *
 *  Three optimization layers:
 *    Layer 1: T-table precomputation (S-box + linear transform L combined)
 *    Layer 2: Multi-block parallel CTR (4-block interleaved for ILP)
 *    Layer 3: AES-NI based S-box (GF(2^8) isomorphism, when hardware available)
 *
 *  Usage: include this header in sm4.c; the PRG functions dispatch to the
 *  fastest available path at runtime.
 */

#ifndef FAEST_SM4_NI_H
#define FAEST_SM4_NI_H

#include <stdint.h>
#include <string.h>
#include "macros.h"
#include "compat.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <emmintrin.h> /* SSE2 */
#if defined(HAVE_AESNI)
#include <wmmintrin.h> /* AES-NI */
#include <tmmintrin.h> /* SSSE3: _mm_shuffle_epi8 */
#endif
#endif

/* ========================================================================
 * Layer 1: T-table precomputation
 *
 * SM4_T[k][i] = L(SBOX[i] << (24 - 8*k)), k = 0..3
 * Round function: T(X) = SM4_T0[x0] ^ SM4_T1[x1] ^ SM4_T2[x2] ^ SM4_T3[x3]
 * Total table size: 4 * 256 * 4 = 4 KB (fits in L1 cache)
 * ======================================================================== */

static const uint32_t SM4_T0[256] = {
    0x8ed55b5b, 0xd0924242, 0x4deaa7a7, 0x06fdfbfb, 0xfccf3333, 0x65e28787, 0xc93df4f4, 0x6bb5dede,
    0x4e165858, 0x6eb4dada, 0x44145050, 0xcac10b0b, 0x8828a0a0, 0x17f8efef, 0x9c2cb0b0, 0x11051414,
    0x872bacac, 0xfb669d9d, 0xf2986a6a, 0xae77d9d9, 0x822aa8a8, 0x46bcfafa, 0x14041010, 0xcfc00f0f,
    0x02a8aaaa, 0x54451111, 0x5f134c4c, 0xbe269898, 0x6d482525, 0x9e841a1a, 0x1e061818, 0xfd9b6666,
    0xec9e7272, 0x4a430909, 0x10514141, 0x24f7d3d3, 0xd5934646, 0x53ecbfbf, 0xf89a6262, 0x927be9e9,
    0xff33cccc, 0x04555151, 0x270b2c2c, 0x4f420d0d, 0x59eeb7b7, 0xf3cc3f3f, 0x1caeb2b2, 0xea638989,
    0x74e79393, 0x7fb1cece, 0x6c1c7070, 0x0daba6a6, 0xedca2727, 0x28082020, 0x48eba3a3, 0xc1975656,
    0x80820202, 0xa3dc7f7f, 0xc4965252, 0x12f9ebeb, 0xa174d5d5, 0xb38d3e3e, 0xc33ffcfc, 0x3ea49a9a,
    0x5b461d1d, 0x1b071c1c, 0x3ba59e9e, 0x0cfff3f3, 0x3ff0cfcf, 0xbf72cdcd, 0x4b175c5c, 0x52b8eaea,
    0x8f810e0e, 0x3d586565, 0xcc3cf0f0, 0x7d196464, 0x7ee59b9b, 0x91871616, 0x734e3d3d, 0x08aaa2a2,
    0xc869a1a1, 0xc76aadad, 0x85830606, 0x7ab0caca, 0xb570c5c5, 0xf4659191, 0xb2d96b6b, 0xa7892e2e,
    0x18fbe3e3, 0x47e8afaf, 0x330f3c3c, 0x674a2d2d, 0xb071c1c1, 0x0e575959, 0xe99f7676, 0xe135d4d4,
    0x661e7878, 0xb4249090, 0x360e3838, 0x265f7979, 0xef628d8d, 0x38596161, 0x95d24747, 0x2aa08a8a,
    0xb1259494, 0xaa228888, 0x8c7df1f1, 0xd73becec, 0x05010404, 0xa5218484, 0x9879e1e1, 0x9b851e1e,
    0x84d75353, 0x00000000, 0x5e471919, 0x0b565d5d, 0xe39d7e7e, 0x9fd04f4f, 0xbb279c9c, 0x1a534949,
    0x7c4d3131, 0xee36d8d8, 0x0a020808, 0x7be49f9f, 0x20a28282, 0xd4c71313, 0xe8cb2323, 0xe69c7a7a,
    0x42e9abab, 0x43bdfefe, 0xa2882a2a, 0x9ad14b4b, 0x40410101, 0xdbc41f1f, 0xd838e0e0, 0x61b7d6d6,
    0x2fa18e8e, 0x2bf4dfdf, 0x3af1cbcb, 0xf6cd3b3b, 0x1dfae7e7, 0xe5608585, 0x41155454, 0x25a38686,
    0x60e38383, 0x16acbaba, 0x295c7575, 0x34a69292, 0xf7996e6e, 0xe434d0d0, 0x721a6868, 0x01545555,
    0x19afb6b6, 0xdf914e4e, 0xfa32c8c8, 0xf030c0c0, 0x21f6d7d7, 0xbc8e3232, 0x75b3c6c6, 0x6fe08f8f,
    0x691d7474, 0x2ef5dbdb, 0x6ae18b8b, 0x962eb8b8, 0x8a800a0a, 0xfe679999, 0xe2c92b2b, 0xe0618181,
    0xc0c30303, 0x8d29a4a4, 0xaf238c8c, 0x07a9aeae, 0x390d3434, 0x1f524d4d, 0x764f3939, 0xd36ebdbd,
    0x81d65757, 0xb7d86f6f, 0xeb37dcdc, 0x51441515, 0xa6dd7b7b, 0x09fef7f7, 0xb68c3a3a, 0x932fbcbc,
    0x0f030c0c, 0x03fcffff, 0xc26ba9a9, 0xba73c9c9, 0xd96cb5b5, 0xdc6db1b1, 0x375a6d6d, 0x15504545,
    0xb98f3636, 0x771b6c6c, 0x13adbebe, 0xda904a4a, 0x57b9eeee, 0xa9de7777, 0x4cbef2f2, 0x837efdfd,
    0x55114444, 0xbdda6767, 0x2c5d7171, 0x45400505, 0x631f7c7c, 0x50104040, 0x325b6969, 0xb8db6363,
    0x220a2828, 0xc5c20707, 0xf531c4c4, 0xa88a2222, 0x31a79696, 0xf9ce3737, 0x977aeded, 0x49bff6f6,
    0x992db4b4, 0xa475d1d1, 0x90d34343, 0x5a124848, 0x58bae2e2, 0x71e69797, 0x64b6d2d2, 0x70b2c2c2,
    0xad8b2626, 0xcd68a5a5, 0xcb955e5e, 0x624b2929, 0x3c0c3030, 0xce945a5a, 0xab76dddd, 0x867ff9f9,
    0xf1649595, 0x5dbbe6e6, 0x35f2c7c7, 0x2d092424, 0xd1c61717, 0xd66fb9b9, 0xdec51b1b, 0x94861212,
    0x78186060, 0x30f3c3c3, 0x897cf5f5, 0x5cefb3b3, 0xd23ae8e8, 0xacdf7373, 0x794c3535, 0xa0208080,
    0x9d78e5e5, 0x56edbbbb, 0x235e7d7d, 0xc63ef8f8, 0x8bd45f5f, 0xe7c82f2f, 0xdd39e4e4, 0x68492121
};

static const uint32_t SM4_T1[256] = {
    0x5b8ed55b, 0x42d09242, 0xa74deaa7, 0xfb06fdfb, 0x33fccf33, 0x8765e287, 0xf4c93df4, 0xde6bb5de,
    0x584e1658, 0xda6eb4da, 0x50441450, 0x0bcac10b, 0xa08828a0, 0xef17f8ef, 0xb09c2cb0, 0x14110514,
    0xac872bac, 0x9dfb669d, 0x6af2986a, 0xd9ae77d9, 0xa8822aa8, 0xfa46bcfa, 0x10140410, 0x0fcfc00f,
    0xaa02a8aa, 0x11544511, 0x4c5f134c, 0x98be2698, 0x256d4825, 0x1a9e841a, 0x181e0618, 0x66fd9b66,
    0x72ec9e72, 0x094a4309, 0x41105141, 0xd324f7d3, 0x46d59346, 0xbf53ecbf, 0x62f89a62, 0xe9927be9,
    0xccff33cc, 0x51045551, 0x2c270b2c, 0x0d4f420d, 0xb759eeb7, 0x3ff3cc3f, 0xb21caeb2, 0x89ea6389,
    0x9374e793, 0xce7fb1ce, 0x706c1c70, 0xa60daba6, 0x27edca27, 0x20280820, 0xa348eba3, 0x56c19756,
    0x02808202, 0x7fa3dc7f, 0x52c49652, 0xeb12f9eb, 0xd5a174d5, 0x3eb38d3e, 0xfcc33ffc, 0x9a3ea49a,
    0x1d5b461d, 0x1c1b071c, 0x9e3ba59e, 0xf30cfff3, 0xcf3ff0cf, 0xcdbf72cd, 0x5c4b175c, 0xea52b8ea,
    0x0e8f810e, 0x653d5865, 0xf0cc3cf0, 0x647d1964, 0x9b7ee59b, 0x16918716, 0x3d734e3d, 0xa208aaa2,
    0xa1c869a1, 0xadc76aad, 0x06858306, 0xca7ab0ca, 0xc5b570c5, 0x91f46591, 0x6bb2d96b, 0x2ea7892e,
    0xe318fbe3, 0xaf47e8af, 0x3c330f3c, 0x2d674a2d, 0xc1b071c1, 0x590e5759, 0x76e99f76, 0xd4e135d4,
    0x78661e78, 0x90b42490, 0x38360e38, 0x79265f79, 0x8def628d, 0x61385961, 0x4795d247, 0x8a2aa08a,
    0x94b12594, 0x88aa2288, 0xf18c7df1, 0xecd73bec, 0x04050104, 0x84a52184, 0xe19879e1, 0x1e9b851e,
    0x5384d753, 0x00000000, 0x195e4719, 0x5d0b565d, 0x7ee39d7e, 0x4f9fd04f, 0x9cbb279c, 0x491a5349,
    0x317c4d31, 0xd8ee36d8, 0x080a0208, 0x9f7be49f, 0x8220a282, 0x13d4c713, 0x23e8cb23, 0x7ae69c7a,
    0xab42e9ab, 0xfe43bdfe, 0x2aa2882a, 0x4b9ad14b, 0x01404101, 0x1fdbc41f, 0xe0d838e0, 0xd661b7d6,
    0x8e2fa18e, 0xdf2bf4df, 0xcb3af1cb, 0x3bf6cd3b, 0xe71dfae7, 0x85e56085, 0x54411554, 0x8625a386,
    0x8360e383, 0xba16acba, 0x75295c75, 0x9234a692, 0x6ef7996e, 0xd0e434d0, 0x68721a68, 0x55015455,
    0xb619afb6, 0x4edf914e, 0xc8fa32c8, 0xc0f030c0, 0xd721f6d7, 0x32bc8e32, 0xc675b3c6, 0x8f6fe08f,
    0x74691d74, 0xdb2ef5db, 0x8b6ae18b, 0xb8962eb8, 0x0a8a800a, 0x99fe6799, 0x2be2c92b, 0x81e06181,
    0x03c0c303, 0xa48d29a4, 0x8caf238c, 0xae07a9ae, 0x34390d34, 0x4d1f524d, 0x39764f39, 0xbdd36ebd,
    0x5781d657, 0x6fb7d86f, 0xdceb37dc, 0x15514415, 0x7ba6dd7b, 0xf709fef7, 0x3ab68c3a, 0xbc932fbc,
    0x0c0f030c, 0xff03fcff, 0xa9c26ba9, 0xc9ba73c9, 0xb5d96cb5, 0xb1dc6db1, 0x6d375a6d, 0x45155045,
    0x36b98f36, 0x6c771b6c, 0xbe13adbe, 0x4ada904a, 0xee57b9ee, 0x77a9de77, 0xf24cbef2, 0xfd837efd,
    0x44551144, 0x67bdda67, 0x712c5d71, 0x05454005, 0x7c631f7c, 0x40501040, 0x69325b69, 0x63b8db63,
    0x28220a28, 0x07c5c207, 0xc4f531c4, 0x22a88a22, 0x9631a796, 0x37f9ce37, 0xed977aed, 0xf649bff6,
    0xb4992db4, 0xd1a475d1, 0x4390d343, 0x485a1248, 0xe258bae2, 0x9771e697, 0xd264b6d2, 0xc270b2c2,
    0x26ad8b26, 0xa5cd68a5, 0x5ecb955e, 0x29624b29, 0x303c0c30, 0x5ace945a, 0xddab76dd, 0xf9867ff9,
    0x95f16495, 0xe65dbbe6, 0xc735f2c7, 0x242d0924, 0x17d1c617, 0xb9d66fb9, 0x1bdec51b, 0x12948612,
    0x60781860, 0xc330f3c3, 0xf5897cf5, 0xb35cefb3, 0xe8d23ae8, 0x73acdf73, 0x35794c35, 0x80a02080,
    0xe59d78e5, 0xbb56edbb, 0x7d235e7d, 0xf8c63ef8, 0x5f8bd45f, 0x2fe7c82f, 0xe4dd39e4, 0x21684921
};

static const uint32_t SM4_T2[256] = {
    0x5b5b8ed5, 0x4242d092, 0xa7a74dea, 0xfbfb06fd, 0x3333fccf, 0x878765e2, 0xf4f4c93d, 0xdede6bb5,
    0x58584e16, 0xdada6eb4, 0x50504414, 0x0b0bcac1, 0xa0a08828, 0xefef17f8, 0xb0b09c2c, 0x14141105,
    0xacac872b, 0x9d9dfb66, 0x6a6af298, 0xd9d9ae77, 0xa8a8822a, 0xfafa46bc, 0x10101404, 0x0f0fcfc0,
    0xaaaa02a8, 0x11115445, 0x4c4c5f13, 0x9898be26, 0x25256d48, 0x1a1a9e84, 0x18181e06, 0x6666fd9b,
    0x7272ec9e, 0x09094a43, 0x41411051, 0xd3d324f7, 0x4646d593, 0xbfbf53ec, 0x6262f89a, 0xe9e9927b,
    0xccccff33, 0x51510455, 0x2c2c270b, 0x0d0d4f42, 0xb7b759ee, 0x3f3ff3cc, 0xb2b21cae, 0x8989ea63,
    0x939374e7, 0xcece7fb1, 0x70706c1c, 0xa6a60dab, 0x2727edca, 0x20202808, 0xa3a348eb, 0x5656c197,
    0x02028082, 0x7f7fa3dc, 0x5252c496, 0xebeb12f9, 0xd5d5a174, 0x3e3eb38d, 0xfcfcc33f, 0x9a9a3ea4,
    0x1d1d5b46, 0x1c1c1b07, 0x9e9e3ba5, 0xf3f30cff, 0xcfcf3ff0, 0xcdcdbf72, 0x5c5c4b17, 0xeaea52b8,
    0x0e0e8f81, 0x65653d58, 0xf0f0cc3c, 0x64647d19, 0x9b9b7ee5, 0x16169187, 0x3d3d734e, 0xa2a208aa,
    0xa1a1c869, 0xadadc76a, 0x06068583, 0xcaca7ab0, 0xc5c5b570, 0x9191f465, 0x6b6bb2d9, 0x2e2ea789,
    0xe3e318fb, 0xafaf47e8, 0x3c3c330f, 0x2d2d674a, 0xc1c1b071, 0x59590e57, 0x7676e99f, 0xd4d4e135,
    0x7878661e, 0x9090b424, 0x3838360e, 0x7979265f, 0x8d8def62, 0x61613859, 0x474795d2, 0x8a8a2aa0,
    0x9494b125, 0x8888aa22, 0xf1f18c7d, 0xececd73b, 0x04040501, 0x8484a521, 0xe1e19879, 0x1e1e9b85,
    0x535384d7, 0x00000000, 0x19195e47, 0x5d5d0b56, 0x7e7ee39d, 0x4f4f9fd0, 0x9c9cbb27, 0x49491a53,
    0x31317c4d, 0xd8d8ee36, 0x08080a02, 0x9f9f7be4, 0x828220a2, 0x1313d4c7, 0x2323e8cb, 0x7a7ae69c,
    0xabab42e9, 0xfefe43bd, 0x2a2aa288, 0x4b4b9ad1, 0x01014041, 0x1f1fdbc4, 0xe0e0d838, 0xd6d661b7,
    0x8e8e2fa1, 0xdfdf2bf4, 0xcbcb3af1, 0x3b3bf6cd, 0xe7e71dfa, 0x8585e560, 0x54544115, 0x868625a3,
    0x838360e3, 0xbaba16ac, 0x7575295c, 0x929234a6, 0x6e6ef799, 0xd0d0e434, 0x6868721a, 0x55550154,
    0xb6b619af, 0x4e4edf91, 0xc8c8fa32, 0xc0c0f030, 0xd7d721f6, 0x3232bc8e, 0xc6c675b3, 0x8f8f6fe0,
    0x7474691d, 0xdbdb2ef5, 0x8b8b6ae1, 0xb8b8962e, 0x0a0a8a80, 0x9999fe67, 0x2b2be2c9, 0x8181e061,
    0x0303c0c3, 0xa4a48d29, 0x8c8caf23, 0xaeae07a9, 0x3434390d, 0x4d4d1f52, 0x3939764f, 0xbdbdd36e,
    0x575781d6, 0x6f6fb7d8, 0xdcdceb37, 0x15155144, 0x7b7ba6dd, 0xf7f709fe, 0x3a3ab68c, 0xbcbc932f,
    0x0c0c0f03, 0xffff03fc, 0xa9a9c26b, 0xc9c9ba73, 0xb5b5d96c, 0xb1b1dc6d, 0x6d6d375a, 0x45451550,
    0x3636b98f, 0x6c6c771b, 0xbebe13ad, 0x4a4ada90, 0xeeee57b9, 0x7777a9de, 0xf2f24cbe, 0xfdfd837e,
    0x44445511, 0x6767bdda, 0x71712c5d, 0x05054540, 0x7c7c631f, 0x40405010, 0x6969325b, 0x6363b8db,
    0x2828220a, 0x0707c5c2, 0xc4c4f531, 0x2222a88a, 0x969631a7, 0x3737f9ce, 0xeded977a, 0xf6f649bf,
    0xb4b4992d, 0xd1d1a475, 0x434390d3, 0x48485a12, 0xe2e258ba, 0x979771e6, 0xd2d264b6, 0xc2c270b2,
    0x2626ad8b, 0xa5a5cd68, 0x5e5ecb95, 0x2929624b, 0x30303c0c, 0x5a5ace94, 0xddddab76, 0xf9f9867f,
    0x9595f164, 0xe6e65dbb, 0xc7c735f2, 0x24242d09, 0x1717d1c6, 0xb9b9d66f, 0x1b1bdec5, 0x12129486,
    0x60607818, 0xc3c330f3, 0xf5f5897c, 0xb3b35cef, 0xe8e8d23a, 0x7373acdf, 0x3535794c, 0x8080a020,
    0xe5e59d78, 0xbbbb56ed, 0x7d7d235e, 0xf8f8c63e, 0x5f5f8bd4, 0x2f2fe7c8, 0xe4e4dd39, 0x21216849
};

static const uint32_t SM4_T3[256] = {
    0xd55b5b8e, 0x924242d0, 0xeaa7a74d, 0xfdfbfb06, 0xcf3333fc, 0xe2878765, 0x3df4f4c9, 0xb5dede6b,
    0x1658584e, 0xb4dada6e, 0x14505044, 0xc10b0bca, 0x28a0a088, 0xf8efef17, 0x2cb0b09c, 0x05141411,
    0x2bacac87, 0x669d9dfb, 0x986a6af2, 0x77d9d9ae, 0x2aa8a882, 0xbcfafa46, 0x04101014, 0xc00f0fcf,
    0xa8aaaa02, 0x45111154, 0x134c4c5f, 0x269898be, 0x4825256d, 0x841a1a9e, 0x0618181e, 0x9b6666fd,
    0x9e7272ec, 0x4309094a, 0x51414110, 0xf7d3d324, 0x934646d5, 0xecbfbf53, 0x9a6262f8, 0x7be9e992,
    0x33ccccff, 0x55515104, 0x0b2c2c27, 0x420d0d4f, 0xeeb7b759, 0xcc3f3ff3, 0xaeb2b21c, 0x638989ea,
    0xe7939374, 0xb1cece7f, 0x1c70706c, 0xaba6a60d, 0xca2727ed, 0x08202028, 0xeba3a348, 0x975656c1,
    0x82020280, 0xdc7f7fa3, 0x965252c4, 0xf9ebeb12, 0x74d5d5a1, 0x8d3e3eb3, 0x3ffcfcc3, 0xa49a9a3e,
    0x461d1d5b, 0x071c1c1b, 0xa59e9e3b, 0xfff3f30c, 0xf0cfcf3f, 0x72cdcdbf, 0x175c5c4b, 0xb8eaea52,
    0x810e0e8f, 0x5865653d, 0x3cf0f0cc, 0x1964647d, 0xe59b9b7e, 0x87161691, 0x4e3d3d73, 0xaaa2a208,
    0x69a1a1c8, 0x6aadadc7, 0x83060685, 0xb0caca7a, 0x70c5c5b5, 0x659191f4, 0xd96b6bb2, 0x892e2ea7,
    0xfbe3e318, 0xe8afaf47, 0x0f3c3c33, 0x4a2d2d67, 0x71c1c1b0, 0x5759590e, 0x9f7676e9, 0x35d4d4e1,
    0x1e787866, 0x249090b4, 0x0e383836, 0x5f797926, 0x628d8def, 0x59616138, 0xd2474795, 0xa08a8a2a,
    0x259494b1, 0x228888aa, 0x7df1f18c, 0x3bececd7, 0x01040405, 0x218484a5, 0x79e1e198, 0x851e1e9b,
    0xd7535384, 0x00000000, 0x4719195e, 0x565d5d0b, 0x9d7e7ee3, 0xd04f4f9f, 0x279c9cbb, 0x5349491a,
    0x4d31317c, 0x36d8d8ee, 0x0208080a, 0xe49f9f7b, 0xa2828220, 0xc71313d4, 0xcb2323e8, 0x9c7a7ae6,
    0xe9abab42, 0xbdfefe43, 0x882a2aa2, 0xd14b4b9a, 0x41010140, 0xc41f1fdb, 0x38e0e0d8, 0xb7d6d661,
    0xa18e8e2f, 0xf4dfdf2b, 0xf1cbcb3a, 0xcd3b3bf6, 0xfae7e71d, 0x608585e5, 0x15545441, 0xa3868625,
    0xe3838360, 0xacbaba16, 0x5c757529, 0xa6929234, 0x996e6ef7, 0x34d0d0e4, 0x1a686872, 0x54555501,
    0xafb6b619, 0x914e4edf, 0x32c8c8fa, 0x30c0c0f0, 0xf6d7d721, 0x8e3232bc, 0xb3c6c675, 0xe08f8f6f,
    0x1d747469, 0xf5dbdb2e, 0xe18b8b6a, 0x2eb8b896, 0x800a0a8a, 0x679999fe, 0xc92b2be2, 0x618181e0,
    0xc30303c0, 0x29a4a48d, 0x238c8caf, 0xa9aeae07, 0x0d343439, 0x524d4d1f, 0x4f393976, 0x6ebdbdd3,
    0xd6575781, 0xd86f6fb7, 0x37dcdceb, 0x44151551, 0xdd7b7ba6, 0xfef7f709, 0x8c3a3ab6, 0x2fbcbc93,
    0x030c0c0f, 0xfcffff03, 0x6ba9a9c2, 0x73c9c9ba, 0x6cb5b5d9, 0x6db1b1dc, 0x5a6d6d37, 0x50454515,
    0x8f3636b9, 0x1b6c6c77, 0xadbebe13, 0x904a4ada, 0xb9eeee57, 0xde7777a9, 0xbef2f24c, 0x7efdfd83,
    0x11444455, 0xda6767bd, 0x5d71712c, 0x40050545, 0x1f7c7c63, 0x10404050, 0x5b696932, 0xdb6363b8,
    0x0a282822, 0xc20707c5, 0x31c4c4f5, 0x8a2222a8, 0xa7969631, 0xce3737f9, 0x7aeded97, 0xbff6f649,
    0x2db4b499, 0x75d1d1a4, 0xd3434390, 0x1248485a, 0xbae2e258, 0xe6979771, 0xb6d2d264, 0xb2c2c270,
    0x8b2626ad, 0x68a5a5cd, 0x955e5ecb, 0x4b292962, 0x0c30303c, 0x945a5ace, 0x76ddddab, 0x7ff9f986,
    0x649595f1, 0xbbe6e65d, 0xf2c7c735, 0x0924242d, 0xc61717d1, 0x6fb9b9d6, 0xc51b1bde, 0x86121294,
    0x18606078, 0xf3c3c330, 0x7cf5f589, 0xefb3b35c, 0x3ae8e8d2, 0xdf7373ac, 0x4c353579, 0x208080a0,
    0x78e5e59d, 0xedbbbb56, 0x5e7d7d23, 0x3ef8f8c6, 0xd45f5f8b, 0xc82f2fe7, 0x39e4e4dd, 0x49212168
};

/* ========================================================================
 * T-table based fast round function
 * T(X) = SM4_T0[x0] ^ SM4_T1[x1] ^ SM4_T2[x2] ^ SM4_T3[x3]
 * Replaces:  tau(X) -> 4 SBOX lookups + byte recombine + L transform
 * ======================================================================== */
static inline uint32_t sm4_t_fast(uint32_t x) {
  return SM4_T0[(x >> 24) & 0xFF] ^
         SM4_T1[(x >> 16) & 0xFF] ^
         SM4_T2[(x >>  8) & 0xFF] ^
         SM4_T3[ x        & 0xFF];
}

/* ========================================================================
 * Layer 2: Multi-block parallel encryption
 *
 * Process 4 independent blocks simultaneously, interleaving round
 * operations to exploit CPU out-of-order execution and hide memory
 * latency from T-table lookups.
 * ======================================================================== */

/* Encrypt a single block using T-tables (Layer 1 only) */
static inline void sm4_encrypt_block_fast(const uint32_t* rk, const uint8_t* in,
                                          uint8_t* out) {
  uint32_t X0, X1, X2, X3;

  /* Load plaintext (big-endian) */
  X0 = ((uint32_t)in[ 0] << 24) | ((uint32_t)in[ 1] << 16) |
       ((uint32_t)in[ 2] <<  8) |  (uint32_t)in[ 3];
  X1 = ((uint32_t)in[ 4] << 24) | ((uint32_t)in[ 5] << 16) |
       ((uint32_t)in[ 6] <<  8) |  (uint32_t)in[ 7];
  X2 = ((uint32_t)in[ 8] << 24) | ((uint32_t)in[ 9] << 16) |
       ((uint32_t)in[10] <<  8) |  (uint32_t)in[11];
  X3 = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) |
       ((uint32_t)in[14] <<  8) |  (uint32_t)in[15];

  /* 32 rounds, unrolled 4 at a time */
  for (int i = 0; i < 32; i += 4) {
    X0 ^= sm4_t_fast(X1 ^ X2 ^ X3 ^ rk[i    ]);
    X1 ^= sm4_t_fast(X0 ^ X2 ^ X3 ^ rk[i + 1]);
    X2 ^= sm4_t_fast(X0 ^ X1 ^ X3 ^ rk[i + 2]);
    X3 ^= sm4_t_fast(X0 ^ X1 ^ X2 ^ rk[i + 3]);
  }

  /* Store ciphertext (reverse order) */
  out[ 0] = (X3 >> 24); out[ 1] = (X3 >> 16); out[ 2] = (X3 >> 8); out[ 3] = X3;
  out[ 4] = (X2 >> 24); out[ 5] = (X2 >> 16); out[ 6] = (X2 >> 8); out[ 7] = X2;
  out[ 8] = (X1 >> 24); out[ 9] = (X1 >> 16); out[10] = (X1 >> 8); out[11] = X1;
  out[12] = (X0 >> 24); out[13] = (X0 >> 16); out[14] = (X0 >> 8); out[15] = X0;
}

/* Encrypt 4 blocks in parallel (interleaved rounds for ILP) */
static inline void sm4_encrypt_4blocks_fast(const uint32_t* rk,
                                            const uint8_t in[4][16],
                                            uint8_t out[4][16]) {
  uint32_t A0, A1, A2, A3;
  uint32_t B0, B1, B2, B3;
  uint32_t C0, C1, C2, C3;
  uint32_t D0, D1, D2, D3;

  /* Load 4 blocks */
#define LOAD_BLOCK(P, Xn, blk) do {                                    \
    Xn##0 = ((uint32_t)blk[ 0]<<24)|((uint32_t)blk[ 1]<<16)|          \
            ((uint32_t)blk[ 2]<<8) | (uint32_t)blk[ 3];                \
    Xn##1 = ((uint32_t)blk[ 4]<<24)|((uint32_t)blk[ 5]<<16)|          \
            ((uint32_t)blk[ 6]<<8) | (uint32_t)blk[ 7];                \
    Xn##2 = ((uint32_t)blk[ 8]<<24)|((uint32_t)blk[ 9]<<16)|          \
            ((uint32_t)blk[10]<<8) | (uint32_t)blk[11];               \
    Xn##3 = ((uint32_t)blk[12]<<24)|((uint32_t)blk[13]<<16)|          \
            ((uint32_t)blk[14]<<8) | (uint32_t)blk[15];               \
  } while(0)

  LOAD_BLOCK(, A, in[0]);
  LOAD_BLOCK(, B, in[1]);
  LOAD_BLOCK(, C, in[2]);
  LOAD_BLOCK(, D, in[3]);
#undef LOAD_BLOCK

  /* 32 rounds: interleave 4 blocks to maximize ILP */
  for (int i = 0; i < 32; i += 4) {
    /* Round i */
    A0 ^= sm4_t_fast(A1 ^ A2 ^ A3 ^ rk[i]);
    B0 ^= sm4_t_fast(B1 ^ B2 ^ B3 ^ rk[i]);
    C0 ^= sm4_t_fast(C1 ^ C2 ^ C3 ^ rk[i]);
    D0 ^= sm4_t_fast(D1 ^ D2 ^ D3 ^ rk[i]);
    /* Round i+1 */
    A1 ^= sm4_t_fast(A0 ^ A2 ^ A3 ^ rk[i+1]);
    B1 ^= sm4_t_fast(B0 ^ B2 ^ B3 ^ rk[i+1]);
    C1 ^= sm4_t_fast(C0 ^ C2 ^ C3 ^ rk[i+1]);
    D1 ^= sm4_t_fast(D0 ^ D2 ^ D3 ^ rk[i+1]);
    /* Round i+2 */
    A2 ^= sm4_t_fast(A0 ^ A1 ^ A3 ^ rk[i+2]);
    B2 ^= sm4_t_fast(B0 ^ B1 ^ B3 ^ rk[i+2]);
    C2 ^= sm4_t_fast(C0 ^ C1 ^ C3 ^ rk[i+2]);
    D2 ^= sm4_t_fast(D0 ^ D1 ^ D3 ^ rk[i+2]);
    /* Round i+3 */
    A3 ^= sm4_t_fast(A0 ^ A1 ^ A2 ^ rk[i+3]);
    B3 ^= sm4_t_fast(B0 ^ B1 ^ B2 ^ rk[i+3]);
    C3 ^= sm4_t_fast(C0 ^ C1 ^ C2 ^ rk[i+3]);
    D3 ^= sm4_t_fast(D0 ^ D1 ^ D2 ^ rk[i+3]);
  }

  /* Store 4 blocks (reverse order) */
#define STORE_BLOCK(Xn, blk) do {                                      \
    blk[ 0]=(Xn##3>>24); blk[ 1]=(Xn##3>>16); blk[ 2]=(Xn##3>>8); blk[ 3]=Xn##3; \
    blk[ 4]=(Xn##2>>24); blk[ 5]=(Xn##2>>16); blk[ 6]=(Xn##2>>8); blk[ 7]=Xn##2; \
    blk[ 8]=(Xn##1>>24); blk[ 9]=(Xn##1>>16); blk[10]=(Xn##1>>8); blk[11]=Xn##1; \
    blk[12]=(Xn##0>>24); blk[13]=(Xn##0>>16); blk[14]=(Xn##0>>8); blk[15]=Xn##0; \
  } while(0)

  STORE_BLOCK(A, out[0]);
  STORE_BLOCK(B, out[1]);
  STORE_BLOCK(C, out[2]);
  STORE_BLOCK(D, out[3]);
#undef STORE_BLOCK
}

/* ========================================================================
 * Layer 3: AES-NI accelerated SM4 S-box
 *
 * Both SM4 and AES S-boxes are of the form: S(x) = Affine(Inverse(x))
 * where Inverse is computed in their respective GF(2^8) fields.
 *
 * AES field:  x^8 + x^4 + x^3 + x + 1
 * SM4 field:  x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1
 *
 * There exists a linear isomorphism φ between these fields. We can
 * compute SM4's S-box using AES-NI:
 *
 *   SM4_SBOX(x) = M_out * AES_SubBytes(M_in * x + C_in) + C_out
 *
 * where M_in, M_out are 8×8 binary matrices and C_in, C_out are constants.
 * The AES SubBytes is done via _mm_aesenclast_si128 (SubBytes + ShiftRows),
 * then we undo the ShiftRows.
 *
 * This processes 16 bytes at once = 4 rounds of S-box per SM4 block,
 * or 1 round across 4 blocks.
 * ======================================================================== */

#if defined(HAVE_AESNI) && (defined(__x86_64__) || defined(_M_X64))

/*
 * Affine transformation matrices computed by solving the field isomorphism
 * between SM4's and AES's GF(2^8) representations.
 *
 * M_in: pre-transformation (SM4 field → AES inverse input)
 *   Combines: field isomorphism φ + inverse of AES affine
 * M_out: post-transformation (AES SubBytes output → SM4 S-box output)
 *   Combines: AES affine (already applied by aesenclast) + field isomorphism φ^{-1} + SM4 affine
 *
 * These are implemented as SSSE3 lookup tables split into low/high nibbles.
 */

/* GF(2^8) matrix multiplication of a single byte by an 8×8 binary matrix.
 * Rows of the matrix are stored as bytes in mat[0..7]. */
static inline uint8_t gf2_mat_mul(const uint8_t mat[8], uint8_t x) {
  uint8_t result = 0;
  for (int i = 0; i < 8; i++) {
    /* dot product of mat[i] and x over GF(2) */
    uint8_t tmp = mat[i] & x;
    /* parity: count bits mod 2 */
    tmp ^= tmp >> 4;
    tmp ^= tmp >> 2;
    tmp ^= tmp >> 1;
    result |= (tmp & 1) << i;
  }
  return result;
}

/*
 * Precomputed affine constants for SM4-via-AES-NI.
 * These are derived from the field isomorphism between
 * GF(2^8)/(x^8+x^7+x^6+x^5+x^4+x^2+1) [SM4] and
 * GF(2^8)/(x^8+x^4+x^3+x+1) [AES].
 *
 * M_in rows (each byte is one row of the 8×8 GF(2) matrix):
 * Transforms input x so that AES_SubBytes(M_in*x + C_in) can be used.
 */
static const uint8_t SM4_AESNI_M_IN[8] = {
  0x01, 0xD5, 0x21, 0x42, 0xC0, 0x65, 0x45, 0x29
};
static const uint8_t SM4_AESNI_C_IN = 0x65;

/* M_out rows: transforms AES_SubBytes output to SM4 S-box output */
static const uint8_t SM4_AESNI_M_OUT[8] = {
  0x29, 0x25, 0x15, 0xCD, 0x9D, 0xF6, 0x0A, 0xFD
};
static const uint8_t SM4_AESNI_C_OUT = 0xD6;

/*
 * Build SSSE3 lookup tables for an affine transformation.
 * For any byte x = (hi_nibble << 4) | lo_nibble:
 *   M*x = M*(hi_nibble<<4) ^ M*lo_nibble  (linearity over GF(2))
 * So we precompute M*(i<<4) and M*i for i = 0..15,
 * then use pshufb to do parallel 16-byte lookup.
 */
ATTR_TARGET_AESNI static inline void sm4_build_affine_tables(
    const uint8_t mat[8], __m128i* lo_table, __m128i* hi_table) {
  uint8_t lo[16], hi[16];
  for (int i = 0; i < 16; i++) {
    lo[i] = gf2_mat_mul(mat, (uint8_t)i);
    hi[i] = gf2_mat_mul(mat, (uint8_t)(i << 4));
  }
  *lo_table = _mm_loadu_si128((const __m128i*)lo);
  *hi_table = _mm_loadu_si128((const __m128i*)hi);
}

/* Apply affine transformation M*x + c to 16 bytes in parallel using SSSE3 */
ATTR_TARGET_AESNI static inline __m128i sm4_affine_transform(
    __m128i x, __m128i lo_table, __m128i hi_table, __m128i c) {
  __m128i lo_nibble = _mm_and_si128(x, _mm_set1_epi8(0x0F));
  __m128i hi_nibble = _mm_and_si128(_mm_srli_epi16(x, 4), _mm_set1_epi8(0x0F));
  __m128i lo_result = _mm_shuffle_epi8(lo_table, lo_nibble);
  __m128i hi_result = _mm_shuffle_epi8(hi_table, hi_nibble);
  return _mm_xor_si128(_mm_xor_si128(lo_result, hi_result), c);
}

/*
 * Inverse ShiftRows to undo the ShiftRows applied by _mm_aesenclast_si128.
 * AES ShiftRows shifts row i by i positions to the left.
 * Inverse: shift row i by i positions to the right.
 */
ATTR_TARGET_AESNI static inline __m128i sm4_inv_shift_rows(__m128i x) {
  return _mm_shuffle_epi8(x,
    _mm_set_epi8(11, 6, 1, 12, 7, 2, 13, 8, 3, 14, 9, 4, 15, 10, 5, 0));
}

/*
 * SM4 S-box on 16 bytes using AES-NI:
 *   1. Apply M_in * x + C_in
 *   2. AES SubBytes (via aesenclast with zero round key)
 *   3. Inverse ShiftRows (undo ShiftRows from aesenclast)
 *   4. Apply M_out * result + C_out
 */
ATTR_TARGET_AESNI static inline __m128i sm4_sbox_aesni(
    __m128i x,
    __m128i m_in_lo, __m128i m_in_hi, __m128i c_in,
    __m128i m_out_lo, __m128i m_out_hi, __m128i c_out) {
  /* Step 1: pre-affine */
  __m128i t = sm4_affine_transform(x, m_in_lo, m_in_hi, c_in);
  /* Step 2: AES SubBytes */
  t = _mm_aesenclast_si128(t, _mm_setzero_si128());
  /* Step 3: undo ShiftRows */
  t = sm4_inv_shift_rows(t);
  /* Step 4: post-affine */
  return sm4_affine_transform(t, m_out_lo, m_out_hi, c_out);
}

/*
 * AES-NI accelerated SM4 round function for 4 words.
 * Input: 4 bytes (the S-box input bytes from one SM4 round)
 * Packed into a single __m128i, apply SM4 S-box, then linear transform L.
 */

/*
 * SM4-CTR PRG using AES-NI for S-box acceleration.
 * Processes 4 blocks in parallel, each round applies S-box to 4 bytes
 * using SIMD, then computes linear transform L.
 */
ATTR_TARGET_AESNI static void sm4_prg_aesni(
    const uint32_t* rk, const uint8_t* iv, uint8_t* out, size_t outlen) {

  /* Build SSSE3 affine tables */
  __m128i m_in_lo, m_in_hi, m_out_lo, m_out_hi;
  sm4_build_affine_tables(SM4_AESNI_M_IN, &m_in_lo, &m_in_hi);
  sm4_build_affine_tables(SM4_AESNI_M_OUT, &m_out_lo, &m_out_hi);
  __m128i c_in  = _mm_set1_epi8((char)SM4_AESNI_C_IN);
  __m128i c_out = _mm_set1_epi8((char)SM4_AESNI_C_OUT);

  /* Load IV into SSE register for fast counter increment */
  __m128i miv = _mm_loadu_si128((const __m128i*)iv);
  __m128i one = _mm_set_epi32(0, 0, 0, 1);

  /* Process 4 blocks at a time */
  while (outlen >= 64) {
    /* Prepare 4 counter values */
    uint8_t blocks[4][16];
    _mm_storeu_si128((__m128i*)blocks[0], miv);
    miv = _mm_add_epi32(miv, one);
    _mm_storeu_si128((__m128i*)blocks[1], miv);
    miv = _mm_add_epi32(miv, one);
    _mm_storeu_si128((__m128i*)blocks[2], miv);
    miv = _mm_add_epi32(miv, one);
    _mm_storeu_si128((__m128i*)blocks[3], miv);
    miv = _mm_add_epi32(miv, one);

    /* Load into uint32_t state */
    uint32_t X[4][4];
    for (int b = 0; b < 4; b++) {
      X[b][0] = ((uint32_t)blocks[b][0]<<24)|((uint32_t)blocks[b][1]<<16)|
                ((uint32_t)blocks[b][2]<<8)|(uint32_t)blocks[b][3];
      X[b][1] = ((uint32_t)blocks[b][4]<<24)|((uint32_t)blocks[b][5]<<16)|
                ((uint32_t)blocks[b][6]<<8)|(uint32_t)blocks[b][7];
      X[b][2] = ((uint32_t)blocks[b][8]<<24)|((uint32_t)blocks[b][9]<<16)|
                ((uint32_t)blocks[b][10]<<8)|(uint32_t)blocks[b][11];
      X[b][3] = ((uint32_t)blocks[b][12]<<24)|((uint32_t)blocks[b][13]<<16)|
                ((uint32_t)blocks[b][14]<<8)|(uint32_t)blocks[b][15];
    }

    /* 32 rounds with AES-NI S-box */
    for (int i = 0; i < 32; i++) {
      /* Compute S-box inputs for all 4 blocks */
      uint32_t tmp[4];
      for (int b = 0; b < 4; b++) {
        tmp[b] = X[b][(i+1)%4] ^ X[b][(i+2)%4] ^ X[b][(i+3)%4] ^ rk[i];
      }

      /* Pack 4 S-box inputs (4 bytes each = 16 bytes total) into __m128i */
      uint8_t sbox_in[16];
      for (int b = 0; b < 4; b++) {
        sbox_in[b*4+0] = (tmp[b] >> 24) & 0xFF;
        sbox_in[b*4+1] = (tmp[b] >> 16) & 0xFF;
        sbox_in[b*4+2] = (tmp[b] >> 8) & 0xFF;
        sbox_in[b*4+3] = tmp[b] & 0xFF;
      }

      /* Apply SM4 S-box via AES-NI (16 bytes at once) */
      __m128i sbox_input = _mm_loadu_si128((const __m128i*)sbox_in);
      __m128i sbox_output = sm4_sbox_aesni(sbox_input,
                                            m_in_lo, m_in_hi, c_in,
                                            m_out_lo, m_out_hi, c_out);
      uint8_t sbox_out[16];
      _mm_storeu_si128((__m128i*)sbox_out, sbox_output);

      /* Apply linear transform L and XOR for each block */
      for (int b = 0; b < 4; b++) {
        uint32_t B = ((uint32_t)sbox_out[b*4]<<24) |
                     ((uint32_t)sbox_out[b*4+1]<<16) |
                     ((uint32_t)sbox_out[b*4+2]<<8) |
                     (uint32_t)sbox_out[b*4+3];
        /* L(B) = B ^ (B<<<2) ^ (B<<<10) ^ (B<<<18) ^ (B<<<24) */
        uint32_t L = B ^ ((B<<2)|(B>>30)) ^ ((B<<10)|(B>>22))
                       ^ ((B<<18)|(B>>14)) ^ ((B<<24)|(B>>8));
        X[b][i%4] ^= L;
      }
    }

    /* Store 4 encrypted blocks */
    for (int b = 0; b < 4; b++) {
      uint8_t* p = out + b * 16;
      uint32_t Y3 = X[b][3], Y2 = X[b][2], Y1 = X[b][1], Y0 = X[b][0];
      p[0]=(Y3>>24); p[1]=(Y3>>16); p[2]=(Y3>>8); p[3]=Y3;
      p[4]=(Y2>>24); p[5]=(Y2>>16); p[6]=(Y2>>8); p[7]=Y2;
      p[8]=(Y1>>24); p[9]=(Y1>>16); p[10]=(Y1>>8); p[11]=Y1;
      p[12]=(Y0>>24); p[13]=(Y0>>16); p[14]=(Y0>>8); p[15]=Y0;
    }

    out += 64;
    outlen -= 64;
  }

  /* Handle remaining blocks with T-table path */
  while (outlen >= 16) {
    uint8_t block[16];
    _mm_storeu_si128((__m128i*)block, miv);
    sm4_encrypt_block_fast(rk, block, out);
    miv = _mm_add_epi32(miv, one);
    out += 16;
    outlen -= 16;
  }

  if (outlen > 0) {
    uint8_t block[16], last[16];
    _mm_storeu_si128((__m128i*)block, miv);
    sm4_encrypt_block_fast(rk, block, last);
    memcpy(out, last, outlen);
  }
}

/* Specialized PRG for exactly 2 blocks (2*lambda) */
ATTR_TARGET_AESNI static void sm4_prg_2_aesni(const uint32_t* rk, const uint8_t* iv,
                                               uint8_t* out) {
  uint8_t blocks[2][16];
  __m128i miv = _mm_loadu_si128((const __m128i*)iv);
  __m128i one = _mm_set_epi32(0, 0, 0, 1);

  _mm_storeu_si128((__m128i*)blocks[0], miv);
  miv = _mm_add_epi32(miv, one);
  _mm_storeu_si128((__m128i*)blocks[1], miv);

  /* Encrypt 2 blocks with T-table interleaved */
  uint32_t A0, A1, A2, A3, B0, B1, B2, B3;

#define LOAD32BE(p) (((uint32_t)(p)[0]<<24)|((uint32_t)(p)[1]<<16)| \
                     ((uint32_t)(p)[2]<<8)|(uint32_t)(p)[3])
  A0 = LOAD32BE(blocks[0]);     A1 = LOAD32BE(blocks[0]+4);
  A2 = LOAD32BE(blocks[0]+8);   A3 = LOAD32BE(blocks[0]+12);
  B0 = LOAD32BE(blocks[1]);     B1 = LOAD32BE(blocks[1]+4);
  B2 = LOAD32BE(blocks[1]+8);   B3 = LOAD32BE(blocks[1]+12);
#undef LOAD32BE

  for (int i = 0; i < 32; i += 4) {
    A0 ^= sm4_t_fast(A1 ^ A2 ^ A3 ^ rk[i]);
    B0 ^= sm4_t_fast(B1 ^ B2 ^ B3 ^ rk[i]);
    A1 ^= sm4_t_fast(A0 ^ A2 ^ A3 ^ rk[i+1]);
    B1 ^= sm4_t_fast(B0 ^ B2 ^ B3 ^ rk[i+1]);
    A2 ^= sm4_t_fast(A0 ^ A1 ^ A3 ^ rk[i+2]);
    B2 ^= sm4_t_fast(B0 ^ B1 ^ B3 ^ rk[i+2]);
    A3 ^= sm4_t_fast(A0 ^ A1 ^ A2 ^ rk[i+3]);
    B3 ^= sm4_t_fast(B0 ^ B1 ^ B2 ^ rk[i+3]);
  }

#define STORE32BE(p, v) do { (p)[0]=(v)>>24; (p)[1]=(v)>>16; (p)[2]=(v)>>8; (p)[3]=(v); } while(0)
  STORE32BE(out,    A3); STORE32BE(out+4,  A2); STORE32BE(out+8,  A1); STORE32BE(out+12, A0);
  STORE32BE(out+16, B3); STORE32BE(out+20, B2); STORE32BE(out+24, B1); STORE32BE(out+28, B0);
#undef STORE32BE
}

/* Specialized PRG for exactly 4 blocks (4*lambda) */
ATTR_TARGET_AESNI static void sm4_prg_4_aesni(const uint32_t* rk, const uint8_t* iv,
                                               uint8_t* out) {
  uint8_t in_blocks[4][16];
  uint8_t out_blocks[4][16];
  __m128i miv = _mm_loadu_si128((const __m128i*)iv);
  __m128i one = _mm_set_epi32(0, 0, 0, 1);

  for (int b = 0; b < 4; b++) {
    _mm_storeu_si128((__m128i*)in_blocks[b], miv);
    miv = _mm_add_epi32(miv, one);
  }

  sm4_encrypt_4blocks_fast(rk, (const uint8_t(*)[16])in_blocks, out_blocks);

  memcpy(out,      out_blocks[0], 16);
  memcpy(out + 16, out_blocks[1], 16);
  memcpy(out + 32, out_blocks[2], 16);
  memcpy(out + 48, out_blocks[3], 16);
}

#endif /* HAVE_AESNI */


/* ========================================================================
 * T-table based PRG (no AES-NI required, SSE2 for IV operations)
 * This is the fallback when AES-NI is not available.
 * ======================================================================== */

#if defined(__x86_64__) || defined(_M_X64)

/* SSE2 4-block CTR using T-tables */
static void sm4_prg_ttable(const uint32_t* rk, const uint8_t* iv,
                           uint8_t* out, size_t outlen) {
  __m128i miv = _mm_loadu_si128((const __m128i*)iv);
  __m128i one = _mm_set_epi32(0, 0, 0, 1);

  /* Process 4 blocks at a time */
  while (outlen >= 64) {
    uint8_t in_blocks[4][16];
    uint8_t out_blocks[4][16];

    for (int b = 0; b < 4; b++) {
      _mm_storeu_si128((__m128i*)in_blocks[b], miv);
      miv = _mm_add_epi32(miv, one);
    }

    sm4_encrypt_4blocks_fast(rk, (const uint8_t(*)[16])in_blocks, out_blocks);

    memcpy(out,      out_blocks[0], 16);
    memcpy(out + 16, out_blocks[1], 16);
    memcpy(out + 32, out_blocks[2], 16);
    memcpy(out + 48, out_blocks[3], 16);

    out += 64;
    outlen -= 64;
  }

  /* Handle remaining blocks */
  while (outlen >= 16) {
    uint8_t block[16];
    _mm_storeu_si128((__m128i*)block, miv);
    sm4_encrypt_block_fast(rk, block, out);
    miv = _mm_add_epi32(miv, one);
    out += 16;
    outlen -= 16;
  }

  if (outlen > 0) {
    uint8_t block[16], last[16];
    _mm_storeu_si128((__m128i*)block, miv);
    sm4_encrypt_block_fast(rk, block, last);
    memcpy(out, last, outlen);
  }
}

/* Specialized 2-block T-table PRG */
static void sm4_prg_2_ttable(const uint32_t* rk, const uint8_t* iv, uint8_t* out) {
  uint8_t blocks[2][16];
  __m128i miv = _mm_loadu_si128((const __m128i*)iv);
  __m128i one = _mm_set_epi32(0, 0, 0, 1);

  _mm_storeu_si128((__m128i*)blocks[0], miv);
  miv = _mm_add_epi32(miv, one);
  _mm_storeu_si128((__m128i*)blocks[1], miv);

  uint32_t A0, A1, A2, A3, B0, B1, B2, B3;

#define LOAD32BE(p) (((uint32_t)(p)[0]<<24)|((uint32_t)(p)[1]<<16)| \
                     ((uint32_t)(p)[2]<<8)|(uint32_t)(p)[3])
  A0 = LOAD32BE(blocks[0]);     A1 = LOAD32BE(blocks[0]+4);
  A2 = LOAD32BE(blocks[0]+8);   A3 = LOAD32BE(blocks[0]+12);
  B0 = LOAD32BE(blocks[1]);     B1 = LOAD32BE(blocks[1]+4);
  B2 = LOAD32BE(blocks[1]+8);   B3 = LOAD32BE(blocks[1]+12);
#undef LOAD32BE

  for (int i = 0; i < 32; i += 4) {
    A0 ^= sm4_t_fast(A1 ^ A2 ^ A3 ^ rk[i]);
    B0 ^= sm4_t_fast(B1 ^ B2 ^ B3 ^ rk[i]);
    A1 ^= sm4_t_fast(A0 ^ A2 ^ A3 ^ rk[i+1]);
    B1 ^= sm4_t_fast(B0 ^ B2 ^ B3 ^ rk[i+1]);
    A2 ^= sm4_t_fast(A0 ^ A1 ^ A3 ^ rk[i+2]);
    B2 ^= sm4_t_fast(B0 ^ B1 ^ B3 ^ rk[i+2]);
    A3 ^= sm4_t_fast(A0 ^ A1 ^ A2 ^ rk[i+3]);
    B3 ^= sm4_t_fast(B0 ^ B1 ^ B2 ^ rk[i+3]);
  }

#define STORE32BE(p, v) do { (p)[0]=(v)>>24; (p)[1]=(v)>>16; (p)[2]=(v)>>8; (p)[3]=(v); } while(0)
  STORE32BE(out,    A3); STORE32BE(out+4,  A2); STORE32BE(out+8,  A1); STORE32BE(out+12, A0);
  STORE32BE(out+16, B3); STORE32BE(out+20, B2); STORE32BE(out+24, B1); STORE32BE(out+28, B0);
#undef STORE32BE
}

/* Specialized 4-block T-table PRG */
static void sm4_prg_4_ttable(const uint32_t* rk, const uint8_t* iv, uint8_t* out) {
  uint8_t in_blocks[4][16];
  uint8_t out_blocks[4][16];
  __m128i miv = _mm_loadu_si128((const __m128i*)iv);
  __m128i one = _mm_set_epi32(0, 0, 0, 1);

  for (int b = 0; b < 4; b++) {
    _mm_storeu_si128((__m128i*)in_blocks[b], miv);
    miv = _mm_add_epi32(miv, one);
  }

  sm4_encrypt_4blocks_fast(rk, (const uint8_t(*)[16])in_blocks, out_blocks);

  memcpy(out,      out_blocks[0], 16);
  memcpy(out + 16, out_blocks[1], 16);
  memcpy(out + 32, out_blocks[2], 16);
  memcpy(out + 48, out_blocks[3], 16);
}

#endif /* x86_64 */


#endif /* FAEST_SM4_NI_H */
