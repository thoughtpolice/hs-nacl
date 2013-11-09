#include "poly1305.h"

#define VERIFY_F(i) differentbits |= x[i] ^ y[i];
static inline
int crypto_verify_16(const unsigned char *x,const unsigned char *y)
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
  return (1 & ((differentbits - 1) >> 8)) - 1;
}
#undef VERIFY_F

static inline void poly1305_add(unsigned int h[17],const unsigned int c[17])
{
  unsigned int j;
  unsigned int u;
  u = 0;
  for (j = 0;j < 17;++j) { u += h[j] + c[j]; h[j] = u & 255; u >>= 8; }
}

static inline void poly1305_squeeze(unsigned int h[17])
{
  unsigned int j;
  unsigned int u;
  u = 0;
  for (j = 0;j < 16;++j) { u += h[j]; h[j] = u & 255; u >>= 8; }
  u += h[16]; h[16] = u & 3;
  u = 5 * (u >> 2);
  for (j = 0;j < 16;++j) { u += h[j]; h[j] = u & 255; u >>= 8; }
  u += h[16]; h[16] = u;
}

static const unsigned int poly1305_minusp[17] = {
  5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
} ;

static inline void poly1305_freeze(unsigned int h[17])
{
  unsigned int horig[17];
  unsigned int j;
  unsigned int negative;
  for (j = 0;j < 17;++j) horig[j] = h[j];
  poly1305_add(h,poly1305_minusp);
  negative = -(h[16] >> 7);
  for (j = 0;j < 17;++j) h[j] ^= negative & (horig[j] ^ h[j]);
}

static inline void poly1305_mulmod(unsigned int h[17],const unsigned int r[17])
{
  unsigned int hr[17];
  unsigned int i;
  unsigned int j;
  unsigned int u;

  for (i = 0;i < 17;++i) {
    u = 0;
    for (j = 0;j <= i;++j) u += h[j] * r[i - j];
    for (j = i + 1;j < 17;++j) u += 320 * h[j] * r[i + 17 - j];
    hr[i] = u;
  }
  for (i = 0;i < 17;++i) h[i] = hr[i];
  poly1305_squeeze(h);
}

#ifdef PRIVATE_API
static
#endif
int poly1305_mac(unsigned char *out,const unsigned char *in,
                 unsigned long long inlen,const unsigned char *k)
{
  unsigned int j;
  unsigned int r[17];
  unsigned int h[17];
  unsigned int c[17];

  r[0] = k[0];
  r[1] = k[1];
  r[2] = k[2];
  r[3] = k[3] & 15;
  r[4] = k[4] & 252;
  r[5] = k[5];
  r[6] = k[6];
  r[7] = k[7] & 15;
  r[8] = k[8] & 252;
  r[9] = k[9];
  r[10] = k[10];
  r[11] = k[11] & 15;
  r[12] = k[12] & 252;
  r[13] = k[13];
  r[14] = k[14];
  r[15] = k[15] & 15;
  r[16] = 0;

  for (j = 0;j < 17;++j) h[j] = 0;

  while (inlen > 0) {
    for (j = 0;j < 17;++j) c[j] = 0;
    for (j = 0;(j < 16) && (j < inlen);++j) c[j] = in[j];
    c[j] = 1;
    in += j; inlen -= j;
    poly1305_add(h,c);
    poly1305_mulmod(h,r);
  }

  poly1305_freeze(h);

  for (j = 0;j < 16;++j) c[j] = k[j + 16];
  c[16] = 0;
  poly1305_add(h,c);
  for (j = 0;j < 16;++j) out[j] = h[j];
  return 0;
}

#ifdef PRIVATE_API
static
#endif
int poly1305_mac_verify(const unsigned char *h,const unsigned char *in,
                        unsigned long long inlen,const unsigned char *k)
{
  unsigned char correct[16];
  poly1305_mac(correct,in,inlen,k);
  return crypto_verify_16(h,correct);
}
