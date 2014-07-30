/* chacha20-portable.c - a portable ChaCha20/8 implementation
    NaCl compatible interface: http://nacl.cr.yp.to/stream.html

   Written in 2014 by Austin Seipp <aseipp@pobox.com>

   To the extent possible under law, the author(s) have dedicated all
   copyright and related and neighboring rights to this software to
   the public domain worldwide. This software is distributed without
   any warranty.

   You should have received a copy of the CC0 Public Domain Dedication
   along with this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
*/
#ifndef _CHACHA20_H_
#define _CHACHA20_H_

#define crypto_stream_chacha20_KEYBYTES   32
#define crypto_stream_chacha20_NONCEBYTES 8

int crypto_stream_chacha20_xor(unsigned char* c,
                               const unsigned char* m, unsigned long long mlen,
                               const unsigned char* n,
                               const unsigned char* k);

int crypto_stream_chacha20(unsigned char* c, unsigned long long clen,
                           const unsigned char* n,
                           const unsigned char* k);

#endif /* _CHACHA20_H_ */
