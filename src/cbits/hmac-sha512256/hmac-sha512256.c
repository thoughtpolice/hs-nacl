#include <stdint.h>
#include "hmac-sha512256.h"

#define VERIFY_F(i) differentbits |= x[i] ^ y[i];

static inline
int crypto_verify_32(const unsigned char *x,const unsigned char *y)
{
  unsigned int differentbits = 0;
  VERIFY_F(0)
  VERIFY_F(1)
  VERIFY_F(2)
  VERIFY_F(3)
  VERIFY_F(4)
  VERIFY_F(5)
  VERIFY_F(6)
  VERIFY_F(7)
  VERIFY_F(8)
  VERIFY_F(9)
  VERIFY_F(10)
  VERIFY_F(11)
  VERIFY_F(12)
  VERIFY_F(13)
  VERIFY_F(14)
  VERIFY_F(15)
  VERIFY_F(16)
  VERIFY_F(17)
  VERIFY_F(18)
  VERIFY_F(19)
  VERIFY_F(20)
  VERIFY_F(21)
  VERIFY_F(22)
  VERIFY_F(23)
  VERIFY_F(24)
  VERIFY_F(25)
  VERIFY_F(26)
  VERIFY_F(27)
  VERIFY_F(28)
  VERIFY_F(29)
  VERIFY_F(30)
  VERIFY_F(31)
  return (1 & ((differentbits - 1) >> 8)) - 1;
}

#undef VERIFY_F

static inline uint64_t load_bigendian(const unsigned char *x)
{
  return
      (uint64_t) (x[7]) \
  | (((uint64_t) (x[6])) << 8) \
  | (((uint64_t) (x[5])) << 16) \
  | (((uint64_t) (x[4])) << 24) \
  | (((uint64_t) (x[3])) << 32) \
  | (((uint64_t) (x[2])) << 40) \
  | (((uint64_t) (x[1])) << 48) \
  | (((uint64_t) (x[0])) << 56)
  ;
}

static inline void store_bigendian(unsigned char *x,uint64_t u)
{
  x[7] = u; u >>= 8;
  x[6] = u; u >>= 8;
  x[5] = u; u >>= 8;
  x[4] = u; u >>= 8;
  x[3] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[0] = u;
}

#define SHR(x,c) ((x) >> (c))
#define ROTR(x,c) (((x) >> (c)) | ((x) << (64 - (c))))

#define Ch(x,y,z) ((x & y) ^ (~x & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define Sigma1(x) (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))
#define sigma0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x,7))
#define sigma1(x) (ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6))

#define M(w0,w14,w9,w1) w0 = sigma1(w14) + w9 + sigma0(w1) + w0;

#define EXPAND \
  M(w0 ,w14,w9 ,w1 ) \
  M(w1 ,w15,w10,w2 ) \
  M(w2 ,w0 ,w11,w3 ) \
  M(w3 ,w1 ,w12,w4 ) \
  M(w4 ,w2 ,w13,w5 ) \
  M(w5 ,w3 ,w14,w6 ) \
  M(w6 ,w4 ,w15,w7 ) \
  M(w7 ,w5 ,w0 ,w8 ) \
  M(w8 ,w6 ,w1 ,w9 ) \
  M(w9 ,w7 ,w2 ,w10) \
  M(w10,w8 ,w3 ,w11) \
  M(w11,w9 ,w4 ,w12) \
  M(w12,w10,w5 ,w13) \
  M(w13,w11,w6 ,w14) \
  M(w14,w12,w7 ,w15) \
  M(w15,w13,w8 ,w0 )

#define F(r0,r1,r2,r3,r4,r5,r6,r7,w,k) \
  r7 += Sigma1(r4) + Ch(r4,r5,r6) + k + w; \
  r3 += r7; \
  r7 += Sigma0(r0) + Maj(r0,r1,r2);

#define G(r0,r1,r2,r3,r4,r5,r6,r7,i) \
  F(r0,r1,r2,r3,r4,r5,r6,r7,w0 ,round[i + 0]) \
  F(r7,r0,r1,r2,r3,r4,r5,r6,w1 ,round[i + 1]) \
  F(r6,r7,r0,r1,r2,r3,r4,r5,w2 ,round[i + 2]) \
  F(r5,r6,r7,r0,r1,r2,r3,r4,w3 ,round[i + 3]) \
  F(r4,r5,r6,r7,r0,r1,r2,r3,w4 ,round[i + 4]) \
  F(r3,r4,r5,r6,r7,r0,r1,r2,w5 ,round[i + 5]) \
  F(r2,r3,r4,r5,r6,r7,r0,r1,w6 ,round[i + 6]) \
  F(r1,r2,r3,r4,r5,r6,r7,r0,w7 ,round[i + 7]) \
  F(r0,r1,r2,r3,r4,r5,r6,r7,w8 ,round[i + 8]) \
  F(r7,r0,r1,r2,r3,r4,r5,r6,w9 ,round[i + 9]) \
  F(r6,r7,r0,r1,r2,r3,r4,r5,w10,round[i + 10]) \
  F(r5,r6,r7,r0,r1,r2,r3,r4,w11,round[i + 11]) \
  F(r4,r5,r6,r7,r0,r1,r2,r3,w12,round[i + 12]) \
  F(r3,r4,r5,r6,r7,r0,r1,r2,w13,round[i + 13]) \
  F(r2,r3,r4,r5,r6,r7,r0,r1,w14,round[i + 14]) \
  F(r1,r2,r3,r4,r5,r6,r7,r0,w15,round[i + 15])

static const uint64_t round[80] = {
  0x428a2f98d728ae22ULL
, 0x7137449123ef65cdULL
, 0xb5c0fbcfec4d3b2fULL
, 0xe9b5dba58189dbbcULL
, 0x3956c25bf348b538ULL
, 0x59f111f1b605d019ULL
, 0x923f82a4af194f9bULL
, 0xab1c5ed5da6d8118ULL
, 0xd807aa98a3030242ULL
, 0x12835b0145706fbeULL
, 0x243185be4ee4b28cULL
, 0x550c7dc3d5ffb4e2ULL
, 0x72be5d74f27b896fULL
, 0x80deb1fe3b1696b1ULL
, 0x9bdc06a725c71235ULL
, 0xc19bf174cf692694ULL
, 0xe49b69c19ef14ad2ULL
, 0xefbe4786384f25e3ULL
, 0x0fc19dc68b8cd5b5ULL
, 0x240ca1cc77ac9c65ULL
, 0x2de92c6f592b0275ULL
, 0x4a7484aa6ea6e483ULL
, 0x5cb0a9dcbd41fbd4ULL
, 0x76f988da831153b5ULL
, 0x983e5152ee66dfabULL
, 0xa831c66d2db43210ULL
, 0xb00327c898fb213fULL
, 0xbf597fc7beef0ee4ULL
, 0xc6e00bf33da88fc2ULL
, 0xd5a79147930aa725ULL
, 0x06ca6351e003826fULL
, 0x142929670a0e6e70ULL
, 0x27b70a8546d22ffcULL
, 0x2e1b21385c26c926ULL
, 0x4d2c6dfc5ac42aedULL
, 0x53380d139d95b3dfULL
, 0x650a73548baf63deULL
, 0x766a0abb3c77b2a8ULL
, 0x81c2c92e47edaee6ULL
, 0x92722c851482353bULL
, 0xa2bfe8a14cf10364ULL
, 0xa81a664bbc423001ULL
, 0xc24b8b70d0f89791ULL
, 0xc76c51a30654be30ULL
, 0xd192e819d6ef5218ULL
, 0xd69906245565a910ULL
, 0xf40e35855771202aULL
, 0x106aa07032bbd1b8ULL
, 0x19a4c116b8d2d0c8ULL
, 0x1e376c085141ab53ULL
, 0x2748774cdf8eeb99ULL
, 0x34b0bcb5e19b48a8ULL
, 0x391c0cb3c5c95a63ULL
, 0x4ed8aa4ae3418acbULL
, 0x5b9cca4f7763e373ULL
, 0x682e6ff3d6b2b8a3ULL
, 0x748f82ee5defb2fcULL
, 0x78a5636f43172f60ULL
, 0x84c87814a1f0ab72ULL
, 0x8cc702081a6439ecULL
, 0x90befffa23631e28ULL
, 0xa4506cebde82bde9ULL
, 0xbef9a3f7b2c67915ULL
, 0xc67178f2e372532bULL
, 0xca273eceea26619cULL
, 0xd186b8c721c0c207ULL
, 0xeada7dd6cde0eb1eULL
, 0xf57d4f7fee6ed178ULL
, 0x06f067aa72176fbaULL
, 0x0a637dc5a2c898a6ULL
, 0x113f9804bef90daeULL
, 0x1b710b35131c471bULL
, 0x28db77f523047d84ULL
, 0x32caab7b40c72493ULL
, 0x3c9ebe0a15c9bebcULL
, 0x431d67c49c100d4cULL
, 0x4cc5d4becb3e42b6ULL
, 0x597f299cfc657e2aULL
, 0x5fcb6fab3ad6faecULL
, 0x6c44198c4a475817ULL
};

static inline int crypto_hashblocks(unsigned char *statebytes,const unsigned char *in,unsigned long long inlen)
{
  uint64_t state[8];
  uint64_t r0;
  uint64_t r1;
  uint64_t r2;
  uint64_t r3;
  uint64_t r4;
  uint64_t r5;
  uint64_t r6;
  uint64_t r7;

  r0 = load_bigendian(statebytes +  0); state[0] = r0;
  r1 = load_bigendian(statebytes +  8); state[1] = r1;
  r2 = load_bigendian(statebytes + 16); state[2] = r2;
  r3 = load_bigendian(statebytes + 24); state[3] = r3;
  r4 = load_bigendian(statebytes + 32); state[4] = r4;
  r5 = load_bigendian(statebytes + 40); state[5] = r5;
  r6 = load_bigendian(statebytes + 48); state[6] = r6;
  r7 = load_bigendian(statebytes + 56); state[7] = r7;

  while (inlen >= 128) {
    uint64_t w0  = load_bigendian(in +   0);
    uint64_t w1  = load_bigendian(in +   8);
    uint64_t w2  = load_bigendian(in +  16);
    uint64_t w3  = load_bigendian(in +  24);
    uint64_t w4  = load_bigendian(in +  32);
    uint64_t w5  = load_bigendian(in +  40);
    uint64_t w6  = load_bigendian(in +  48);
    uint64_t w7  = load_bigendian(in +  56);
    uint64_t w8  = load_bigendian(in +  64);
    uint64_t w9  = load_bigendian(in +  72);
    uint64_t w10 = load_bigendian(in +  80);
    uint64_t w11 = load_bigendian(in +  88);
    uint64_t w12 = load_bigendian(in +  96);
    uint64_t w13 = load_bigendian(in + 104);
    uint64_t w14 = load_bigendian(in + 112);
    uint64_t w15 = load_bigendian(in + 120);

    G(r0,r1,r2,r3,r4,r5,r6,r7,0)

    EXPAND

    G(r0,r1,r2,r3,r4,r5,r6,r7,16)

    EXPAND

    G(r0,r1,r2,r3,r4,r5,r6,r7,32)

    EXPAND

    G(r0,r1,r2,r3,r4,r5,r6,r7,48)

    EXPAND

    G(r0,r1,r2,r3,r4,r5,r6,r7,64)

    r0 += state[0];
    r1 += state[1];
    r2 += state[2];
    r3 += state[3];
    r4 += state[4];
    r5 += state[5];
    r6 += state[6];
    r7 += state[7];

    state[0] = r0;
    state[1] = r1;
    state[2] = r2;
    state[3] = r3;
    state[4] = r4;
    state[5] = r5;
    state[6] = r6;
    state[7] = r7;

    in += 128;
    inlen -= 128;
  }

  store_bigendian(statebytes +  0,state[0]);
  store_bigendian(statebytes +  8,state[1]);
  store_bigendian(statebytes + 16,state[2]);
  store_bigendian(statebytes + 24,state[3]);
  store_bigendian(statebytes + 32,state[4]);
  store_bigendian(statebytes + 40,state[5]);
  store_bigendian(statebytes + 48,state[6]);
  store_bigendian(statebytes + 56,state[7]);

  return inlen;
}

#define blocks crypto_hashblocks

static const unsigned char iv[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
} ;

int sha512256_hmac(unsigned char *out,const unsigned char *in,unsigned long long inlen,const unsigned char *k)
{
  unsigned char h[64];
  unsigned char padded[256];
  int i;
  unsigned long long bytes = 128 + inlen;

  for (i = 0;i < 64;++i) h[i] = iv[i];

  for (i = 0;i < 32;++i) padded[i] = k[i] ^ 0x36;
  for (i = 32;i < 128;++i) padded[i] = 0x36;

  blocks(h,padded,128);
  blocks(h,in,inlen);
  in += inlen;
  inlen &= 127;
  in -= inlen;

  for (i = 0;i < inlen;++i) padded[i] = in[i];
  padded[inlen] = 0x80;

  if (inlen < 112) {
    for (i = inlen + 1;i < 119;++i) padded[i] = 0;
    padded[119] = bytes >> 61;
    padded[120] = bytes >> 53;
    padded[121] = bytes >> 45;
    padded[122] = bytes >> 37;
    padded[123] = bytes >> 29;
    padded[124] = bytes >> 21;
    padded[125] = bytes >> 13;
    padded[126] = bytes >> 5;
    padded[127] = bytes << 3;
    blocks(h,padded,128);
  } else {
    for (i = inlen + 1;i < 247;++i) padded[i] = 0;
    padded[247] = bytes >> 61;
    padded[248] = bytes >> 53;
    padded[249] = bytes >> 45;
    padded[250] = bytes >> 37;
    padded[251] = bytes >> 29;
    padded[252] = bytes >> 21;
    padded[253] = bytes >> 13;
    padded[254] = bytes >> 5;
    padded[255] = bytes << 3;
    blocks(h,padded,256);
  }

  for (i = 0;i < 32;++i) padded[i] = k[i] ^ 0x5c;
  for (i = 32;i < 128;++i) padded[i] = 0x5c;

  for (i = 0;i < 64;++i) padded[128 + i] = h[i];
  for (i = 0;i < 64;++i) h[i] = iv[i];

  for (i = 64;i < 128;++i) padded[128 + i] = 0;
  padded[128 + 64] = 0x80;
  padded[128 + 126] = 6;

  blocks(h,padded,256);
  for (i = 0;i < 32;++i) out[i] = h[i];

  return 0;
}

int sha512256_hmac_verify(const unsigned char *h,const unsigned char *in,unsigned long long inlen,const unsigned char *k)
{
  unsigned char correct[32];
  sha512256_hmac(correct,in,inlen,k);
  return crypto_verify_32(h,correct);
}
