#include "curve25519xsalsa20poly1305.h"
#include "randombytes.h"

#define PRIVATE_API
#include "../curve25519-donna/curve25519.c"
#include "../xsalsa20poly1305/xsalsa20poly1305.c"
#undef PRIVATE_API

int curve25519xsalsa20poly1305_box_keypair(
  unsigned char *pk,
  unsigned char *sk
)
{
  curve25519_donna_keypair(pk, sk);
  return 0;
}

static const unsigned char curve25519xsalsa20poly1305_n[16] = {0};

int curve25519xsalsa20poly1305_box_beforenm(
  unsigned char *k,
  const unsigned char *pk,
  const unsigned char *sk
)
{
  unsigned char s[32];
  curve25519_donna(s,sk,pk);
  return crypto_core_hsalsa20(k,curve25519xsalsa20poly1305_n,s,sigma);
}

int curve25519xsalsa20poly1305_box_afternm(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k
)
{
  return xsalsa20poly1305_secretbox(c,m,mlen,n,k);
}

int curve25519xsalsa20poly1305_box_open_afternm(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *k
)
{
  return xsalsa20poly1305_secretbox_open(m,c,clen,n,k);
}

int curve25519xsalsa20poly1305_box(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *pk,
  const unsigned char *sk
)
{
  unsigned char k[32];
  curve25519xsalsa20poly1305_box_beforenm(k,pk,sk);
  return curve25519xsalsa20poly1305_box_afternm(c,m,mlen,n,k);
}

int curve25519xsalsa20poly1305_box_open(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *pk,
  const unsigned char *sk
)
{
  unsigned char k[32];
  curve25519xsalsa20poly1305_box_beforenm(k,pk,sk);
  return curve25519xsalsa20poly1305_box_open_afternm(m,c,clen,n,k);
}
