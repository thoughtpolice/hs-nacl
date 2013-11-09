#ifndef _HMAC_SHA512256_H_
#define _HMAC_SHA512256_H_

int hmacsha512256_hmac(unsigned char *out,const unsigned char *in,
                       unsigned long long inlen,const unsigned char *k);
int hmacsha512256_hmac_verify(const unsigned char *h,const unsigned char *in,
                              unsigned long long inlen,const unsigned char *k);

#endif /* _HMAC_SHA512256_H_ */
