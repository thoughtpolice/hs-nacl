#include <stdint.h>
#include <stdlib.h>
#include "siphash2448.h"

typedef  uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

#define VERIFY_F(i) differentbits |= x[i] ^ y[i];
static inline
int crypto_verify_8(const unsigned char *x,const unsigned char *y)
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
  return (1 & ((differentbits - 1) >> 8)) - 1;
}
#undef VERIFY_F


#define rotl64(x, c) ( ((x) << (c)) ^ ((x) >> (64-(c))) )

static inline
u64 siphash(const u8 key[16], const unsigned char *m, const u64 n,
            const size_t rounds, const size_t finalrounds)
{
	u64 v0, v1, v2, v3;
	u64 k0, k1;
	u64 mi, mask, len;
	size_t i, k;

	k0 = *((u64*)(key + 0));
	k1 = *((u64*)(key + 8));

	v0 = k0 ^ 0x736f6d6570736575ULL;
	v1 = k1 ^ 0x646f72616e646f6dULL;
	v2 = k0 ^ 0x6c7967656e657261ULL;
	v3 = k1 ^ 0x7465646279746573ULL;

#define HALF_ROUND(a,b,c,d,s,t) \
	do \
	{ \
		a += b;  c += d; \
		b = rotl64(b, s); d = rotl64(d, t); \
		b ^= a;  d ^= c; \
	} while(0)

#define COMPRESS(v0,v1,v2,v3) \
	do \
	{ \
		HALF_ROUND(v0,v1,v2,v3,13,16); \
		v0 = rotl64(v0,32); \
		HALF_ROUND(v2,v1,v0,v3,17,21); \
		v2 = rotl64(v2, 32); \
	} while(0)

	for(i = 0; i < (n-n%8); i += 8)
	{
		mi = *((u64*)(m + i));
		v3 ^= mi;
		for(k = 0; k < rounds; ++k) COMPRESS(v0,v1,v2,v3);
		v0 ^= mi;
	}

	mi = *((u64*)(m + i));
	len = (n&0xff) << 56;
	mask = n%8 == 0 ? 0 : 0xffffffffffffffffULL >> (8*(8-n%8));
	mi = (mi&mask) ^ len;

	v3 ^= mi;
	for(k = 0; k < rounds; ++k) COMPRESS(v0,v1,v2,v3);
	v0 ^= mi;

	v2 ^= 0xff;
	for(k = 0; k < finalrounds; ++k) COMPRESS(v0,v1,v2,v3);

#undef COMPRESS
#undef HALF_ROUND
	return (v0 ^ v1) ^ (v2 ^ v3);
}

int siphash24_mac(unsigned char *out,const unsigned char *in,
                  unsigned long long inlen,const unsigned char *k)
{
  int i;
  union
  {
    u8  bytes[8];
    u64 gpr;
  } hash;
  hash.gpr = siphash(k, in, inlen, 2, 4);
  for(i=0; i < 8; ++i) out[i] = hash.bytes[i];
  return 0;
}


int siphash24_mac_verify(const unsigned char *h,const unsigned char *in,
                         unsigned long long inlen,const unsigned char *k)
{
  u8 correct[8];
  siphash24_mac(correct,in,inlen,k);
  return crypto_verify_8(h,correct);
}

int siphash48_mac(unsigned char *out,const unsigned char *in,
                  unsigned long long inlen,const unsigned char *k)
{
  int i;
  union
  {
    u8  bytes[8];
    u64 gpr;
  } hash;
  hash.gpr = siphash(k, in, inlen, 4, 8);
  for(i=0; i < 8; ++i) out[i] = hash.bytes[i];
  return 0;
}

int siphash48_mac_verify(const unsigned char *h,const unsigned char *in,
                         unsigned long long inlen,const unsigned char *k)
{
  u8 correct[8];
  siphash48_mac(correct,in,inlen,k);
  return crypto_verify_8(h,correct);
}
