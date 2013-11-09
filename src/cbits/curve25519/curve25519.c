#include "curve25519.h"
#include "randombytes.h"

static inline void curve25519_add(unsigned int out[32],
                                  const unsigned int a[32],
                                  const unsigned int b[32])
{
  unsigned int j;
  unsigned int u;
  u = 0;
  for (j = 0;j < 31;++j) { u += a[j] + b[j]; out[j] = u & 255; u >>= 8; }
  u += a[31] + b[31]; out[31] = u;
}

static inline void curve25519_sub(unsigned int out[32],
                                  const unsigned int a[32],
                                  const unsigned int b[32])
{
  unsigned int j;
  unsigned int u;
  u = 218;
  for (j = 0;j < 31;++j) {
    u += a[j] + 65280 - b[j];
    out[j] = u & 255;
    u >>= 8;
  }
  u += a[31] - b[31];
  out[31] = u;
}

static inline void curve25519_squeeze(unsigned int a[32])
{
  unsigned int j;
  unsigned int u;
  u = 0;
  for (j = 0;j < 31;++j) { u += a[j]; a[j] = u & 255; u >>= 8; }
  u += a[31]; a[31] = u & 127;
  u = 19 * (u >> 7);
  for (j = 0;j < 31;++j) { u += a[j]; a[j] = u & 255; u >>= 8; }
  u += a[31]; a[31] = u;
}

static const unsigned int curve25519_minusp[32] = {
 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128
} ;

static inline void curve25519_freeze(unsigned int a[32])
{
  unsigned int aorig[32];
  unsigned int j;
  unsigned int negative;

  for (j = 0;j < 32;++j) aorig[j] = a[j];
  curve25519_add(a,a,curve25519_minusp);
  negative = -((a[31] >> 7) & 1);
  for (j = 0;j < 32;++j) a[j] ^= negative & (aorig[j] ^ a[j]);
}

static inline void curve25519_mult(unsigned int out[32],
                                   const unsigned int a[32],
                                   const unsigned int b[32])
{
  unsigned int i;
  unsigned int j;
  unsigned int u;

  for (i = 0;i < 32;++i) {
    u = 0;
    for (j = 0;j <= i;++j) u += a[j] * b[i - j];
    for (j = i + 1;j < 32;++j) u += 38 * a[j] * b[i + 32 - j];
    out[i] = u;
  }
  curve25519_squeeze(out);
}

static inline void curve25519_mult121665(unsigned int out[32],
                                         const unsigned int a[32])
{
  unsigned int j;
  unsigned int u;

  u = 0;
  for (j = 0;j < 31;++j) { u += 121665 * a[j]; out[j] = u & 255; u >>= 8; }
  u += 121665 * a[31]; out[31] = u & 127;
  u = 19 * (u >> 7);
  for (j = 0;j < 31;++j) { u += out[j]; out[j] = u & 255; u >>= 8; }
  u += out[j]; out[j] = u;
}

static inline void curve25519_square(unsigned int out[32],
                                     const unsigned int a[32])
{
  unsigned int i;
  unsigned int j;
  unsigned int u;

  for (i = 0;i < 32;++i) {
    u = 0;
    for (j = 0;j < i - j;++j) u += a[j] * a[i - j];
    for (j = i + 1;j < i + 32 - j;++j) u += 38 * a[j] * a[i + 32 - j];
    u *= 2;
    if ((i & 1) == 0) {
      u += a[i / 2] * a[i / 2];
      u += 38 * a[i / 2 + 16] * a[i / 2 + 16];
    }
    out[i] = u;
  }
  curve25519_squeeze(out);
}

static inline void curve25519_select(unsigned int p[64],
                                     unsigned int q[64],
                                     const unsigned int r[64],
                                     const unsigned int s[64],
                                     unsigned int b)
{
  unsigned int j;
  unsigned int t;
  unsigned int bminus1;

  bminus1 = b - 1;
  for (j = 0;j < 64;++j) {
    t = bminus1 & (r[j] ^ s[j]);
    p[j] = s[j] ^ t;
    q[j] = r[j] ^ t;
  }
}

static void curve25519_mainloop(unsigned int work[64],const unsigned char e[32])
{
  unsigned int xzm1[64];
  unsigned int xzm[64];
  unsigned int xzmb[64];
  unsigned int xzm1b[64];
  unsigned int xznb[64];
  unsigned int xzn1b[64];
  unsigned int a0[64];
  unsigned int a1[64];
  unsigned int b0[64];
  unsigned int b1[64];
  unsigned int c1[64];
  unsigned int r[32];
  unsigned int s[32];
  unsigned int t[32];
  unsigned int u[32];
  unsigned int i;
  unsigned int j;
  unsigned int b;
  int pos;

  for (j = 0;j < 32;++j) xzm1[j] = work[j];
  xzm1[32] = 1;
  for (j = 33;j < 64;++j) xzm1[j] = 0;

  xzm[0] = 1;
  for (j = 1;j < 64;++j) xzm[j] = 0;

  for (pos = 254;pos >= 0;--pos) {
    b = e[pos / 8] >> (pos & 7);
    b &= 1;
    curve25519_select(xzmb,xzm1b,xzm,xzm1,b);
    curve25519_add(a0,xzmb,xzmb + 32);
    curve25519_sub(a0 + 32,xzmb,xzmb + 32);
    curve25519_add(a1,xzm1b,xzm1b + 32);
    curve25519_sub(a1 + 32,xzm1b,xzm1b + 32);
    curve25519_square(b0,a0);
    curve25519_square(b0 + 32,a0 + 32);
    curve25519_mult(b1,a1,a0 + 32);
    curve25519_mult(b1 + 32,a1 + 32,a0);
    curve25519_add(c1,b1,b1 + 32);
    curve25519_sub(c1 + 32,b1,b1 + 32);
    curve25519_square(r,c1 + 32);
    curve25519_sub(s,b0,b0 + 32);
    curve25519_mult121665(t,s);
    curve25519_add(u,t,b0);
    curve25519_mult(xznb,b0,b0 + 32);
    curve25519_mult(xznb + 32,s,u);
    curve25519_square(xzn1b,c1);
    curve25519_mult(xzn1b + 32,r,work);
    curve25519_select(xzm,xzm1,xznb,xzn1b,b);
  }

  for (j = 0;j < 64;++j) work[j] = xzm[j];
}

static inline void curve25519_recip(unsigned int out[32],
                                    const unsigned int z[32])
{
  unsigned int z2[32];
  unsigned int z9[32];
  unsigned int z11[32];
  unsigned int z2_5_0[32];
  unsigned int z2_10_0[32];
  unsigned int z2_20_0[32];
  unsigned int z2_50_0[32];
  unsigned int z2_100_0[32];
  unsigned int t0[32];
  unsigned int t1[32];
  int i;

  /* 2 */ curve25519_square(z2,z);
  /* 4 */ curve25519_square(t1,z2);
  /* 8 */ curve25519_square(t0,t1);
  /* 9 */ curve25519_mult(z9,t0,z);
  /* 11 */ curve25519_mult(z11,z9,z2);
  /* 22 */ curve25519_square(t0,z11);
  /* 2^5 - 2^0 = 31 */ curve25519_mult(z2_5_0,t0,z9);

  /* 2^6 - 2^1 */ curve25519_square(t0,z2_5_0);
  /* 2^7 - 2^2 */ curve25519_square(t1,t0);
  /* 2^8 - 2^3 */ curve25519_square(t0,t1);
  /* 2^9 - 2^4 */ curve25519_square(t1,t0);
  /* 2^10 - 2^5 */ curve25519_square(t0,t1);
  /* 2^10 - 2^0 */ curve25519_mult(z2_10_0,t0,z2_5_0);

  /* 2^11 - 2^1 */ curve25519_square(t0,z2_10_0);
  /* 2^12 - 2^2 */ curve25519_square(t1,t0);
  /* 2^20 - 2^10 */ for (i = 2;i < 10;i += 2) { curve25519_square(t0,t1); curve25519_square(t1,t0); }
  /* 2^20 - 2^0 */ curve25519_mult(z2_20_0,t1,z2_10_0);

  /* 2^21 - 2^1 */ curve25519_square(t0,z2_20_0);
  /* 2^22 - 2^2 */ curve25519_square(t1,t0);
  /* 2^40 - 2^20 */ for (i = 2;i < 20;i += 2) { curve25519_square(t0,t1); curve25519_square(t1,t0); }
  /* 2^40 - 2^0 */ curve25519_mult(t0,t1,z2_20_0);

  /* 2^41 - 2^1 */ curve25519_square(t1,t0);
  /* 2^42 - 2^2 */ curve25519_square(t0,t1);
  /* 2^50 - 2^10 */ for (i = 2;i < 10;i += 2) { curve25519_square(t1,t0); curve25519_square(t0,t1); }
  /* 2^50 - 2^0 */ curve25519_mult(z2_50_0,t0,z2_10_0);

  /* 2^51 - 2^1 */ curve25519_square(t0,z2_50_0);
  /* 2^52 - 2^2 */ curve25519_square(t1,t0);
  /* 2^100 - 2^50 */ for (i = 2;i < 50;i += 2) { curve25519_square(t0,t1); curve25519_square(t1,t0); }
  /* 2^100 - 2^0 */ curve25519_mult(z2_100_0,t1,z2_50_0);

  /* 2^101 - 2^1 */ curve25519_square(t1,z2_100_0);
  /* 2^102 - 2^2 */ curve25519_square(t0,t1);
  /* 2^200 - 2^100 */ for (i = 2;i < 100;i += 2) { curve25519_square(t1,t0); curve25519_square(t0,t1); }
  /* 2^200 - 2^0 */ curve25519_mult(t1,t0,z2_100_0);

  /* 2^201 - 2^1 */ curve25519_square(t0,t1);
  /* 2^202 - 2^2 */ curve25519_square(t1,t0);
  /* 2^250 - 2^50 */ for (i = 2;i < 50;i += 2) { curve25519_square(t0,t1); curve25519_square(t1,t0); }
  /* 2^250 - 2^0 */ curve25519_mult(t0,t1,z2_50_0);

  /* 2^251 - 2^1 */ curve25519_square(t1,t0);
  /* 2^252 - 2^2 */ curve25519_square(t0,t1);
  /* 2^253 - 2^3 */ curve25519_square(t1,t0);
  /* 2^254 - 2^4 */ curve25519_square(t0,t1);
  /* 2^255 - 2^5 */ curve25519_square(t1,t0);
  /* 2^255 - 21 */ curve25519_mult(out,t1,z11);
}

static inline int curve25519_crypto_scalarmult(unsigned char *q,
                                               const unsigned char *n,
                                               const unsigned char *p)
{
  unsigned int work[96];
  unsigned char e[32];
  unsigned int i;
  for (i = 0;i < 32;++i) e[i] = n[i];
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;
  for (i = 0;i < 32;++i) work[i] = p[i];
  curve25519_mainloop(work,e);
  curve25519_recip(work + 32,work + 32);
  curve25519_mult(work + 64,work,work + 32);
  curve25519_freeze(work + 64);
  for (i = 0;i < 32;++i) q[i] = work[64 + i];
  return 0;
}

static const unsigned char basepoint[32] = {9};
static inline int curve25519_crypto_scalarmult_base(unsigned char *q,
                                                    const unsigned char *n)
{
  return curve25519_crypto_scalarmult(q,n,basepoint);
}

#ifdef PRIVATE_API
static
#endif
int curve25519_dh_keypair(unsigned char *pk,unsigned char *sk)
{
  randombytes(sk,32);
  curve25519_crypto_scalarmult_base(pk,sk);
  return 0;
}

#ifdef PRIVATE_API
static
#endif
int curve25519_dh(unsigned char *s,const unsigned char *pk,const unsigned char *sk)
{
  curve25519_crypto_scalarmult(s,sk,pk);
  return 0;
}
