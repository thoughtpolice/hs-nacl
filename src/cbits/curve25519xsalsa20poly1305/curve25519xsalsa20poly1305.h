#ifndef _CURVE25519XSALSA20POLY1305_H_
#define _CURVE25519XSALSA20POLY1305_H_

int curve25519xsalsa20poly1305_box_keypair(
  unsigned char *pk,
  unsigned char *sk);

int curve25519xsalsa20poly1305_box(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *pk,
  const unsigned char *sk);

int curve25519xsalsa20poly1305_box_open(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *pk,
  const unsigned char *sk);

int curve25519xsalsa20poly1305_box_beforenm(
  unsigned char *k,
  const unsigned char *pk,
  const unsigned char *sk);

int curve25519xsalsa20poly1305_box_afternm(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k);

int curve25519xsalsa20poly1305_box_open_afternm(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *k);

#endif /* _CURVE25519XSALSA20POLY1305_H_ */
