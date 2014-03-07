#ifndef POLY1305_DONNA_H
#define POLY1305_DONNA_H

#include <stddef.h>

typedef struct poly1305_context {
	size_t aligner;
	unsigned char opaque[136];
} poly1305_context;

#ifdef PRIVATE_API
static
#endif
void poly1305_init(poly1305_context *ctx, const unsigned char key[32]);

#ifdef PRIVATE_API
static
#endif
void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes);

#ifdef PRIVATE_API
static
#endif
void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]);

#ifdef PRIVATE_API
static
#endif
void poly1305_auth(unsigned char mac[16], const unsigned char *m, size_t bytes, const unsigned char key[32]);

#ifdef PRIVATE_API
static
#endif
int poly1305_auth_verify(const unsigned char mac[16], const unsigned char *m, size_t bytes, const unsigned char key[32]);

#ifdef PRIVATE_API
static
#endif
int poly1305_verify(const unsigned char mac1[16], const unsigned char mac2[16]);

#ifdef PRIVATE_API
static
#endif
int poly1305_power_on_self_test(void);

#endif /* POLY1305_DONNA_H */

