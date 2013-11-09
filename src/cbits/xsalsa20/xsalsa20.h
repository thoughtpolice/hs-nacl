#ifndef _XSALSA20_H_
#define _XSALSA20_H_

int xsalsa20_stream_xor(unsigned char *c,
                        const unsigned char *m,unsigned long long mlen,
                        const unsigned char *n,
                        const unsigned char *k);

int xsalsa20_stream(unsigned char *c,unsigned long long clen,
                    const unsigned char *n,
                    const unsigned char *k);

#endif /* _XSALSA20_H_ */
