#ifndef _CURVE25519_H_
#define _CURVE25519_H_

#ifdef PRIVATE_API
static
#endif
int curve25519_dh_keypair(unsigned char *pk,unsigned char *sk);

#ifdef PRIVATE_API
static
#endif
int curve25519_dh(unsigned char *s,const unsigned char *pk,const unsigned char *sk);

#endif /* _CURVE25519_H_ */
