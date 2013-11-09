#ifndef _SIPHASH2448_H_
#define _SIPHASH2448_H_

int siphash24_mac(unsigned char *out,const unsigned char *in,
                  unsigned long long inlen,const unsigned char *k);
int siphash24_mac_verify(const unsigned char *h,const unsigned char *in,
                         unsigned long long inlen,const unsigned char *k);

int siphash48_mac(unsigned char *out,const unsigned char *in,
                  unsigned long long inlen,const unsigned char *k);
int siphash48_mac_verify(const unsigned char *h,const unsigned char *in,
                         unsigned long long inlen,const unsigned char *k);

#endif /* _SIPHASH2448_H_ */
