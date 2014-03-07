#ifndef CURVE25519_H
#define CURVE25519_H

typedef unsigned char curve25519_key[32];

#ifdef PRIVATE_API
static
#endif
void curve25519_donna(curve25519_key mypublic, const curve25519_key secret, const curve25519_key basepoint);

#ifdef PRIVATE_API
static
#endif
void curve25519_donna_basepoint(curve25519_key mypublic, const curve25519_key secret);

#ifdef PRIVATE_API
static
#endif
void curve25519_donna_keypair(curve25519_key mypublic, curve25519_key mysecret);

#endif /* CURVE25519_H */

