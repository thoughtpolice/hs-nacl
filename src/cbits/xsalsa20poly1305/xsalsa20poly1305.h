#ifndef _XSALSA20POLY1305_H_
#define _XSALSA20POLY1305_H_

#ifdef PRIVATE_API
static
#endif
int xsalsa20poly1305_secretbox(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k);

#ifdef PRIVATE_API
static
#endif
int xsalsa20poly1305_secretbox_open(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *k);

#endif /* _XSALSA20POLY1305_H_ */
