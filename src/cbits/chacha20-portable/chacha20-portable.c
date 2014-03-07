/* chacha20-portable.c - a portable ChaCha20/8 implementation, based on:
     http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-01#section-3

    partially inspired by TweetNaCl: http://tweetnacl.cr.yp.to
    acheives 6.41/cpb with GCC 4.8.1 on an i7-4770 @ 3.40GHz

   Written in 2014 by Austin Seipp <aseipp@pobox.com>

   To the extent possible under law, the author(s) have dedicated all
   copyright and related and neighboring rights to this software to
   the public domain worldwide. This software is distributed without
   any warranty.

   You should have received a copy of the CC0 Public Domain Dedication
   along with this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#define FOR(i,n) for (i = 0; i < n; ++i)

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

/* See: http://blog.regehr.org/archives/1063 */
static u32 L32(u32 x,u32 n) { return (x<<n) | (x>>(-n&31)); }

static u32 ld32(const u8* x)
{
  u32 u = x[3];
  u = (u<<8)|x[2];
  u = (u<<8)|x[1];
  return (u<<8)|x[0];
}

static void st32(u8 *x,u32 u)
{
  int i;
  FOR(i,4) { x[i] = u; u >>= 8; }
}

static void
QR(u32* x, u32 a, u32 b, u32 c, u32 d)
{
  x[a] = x[a]+x[b]; x[d] = L32(x[d]^x[a],16);
  x[c] = x[c]+x[d]; x[b] = L32(x[b]^x[c],12);
  x[a] = x[a]+x[b]; x[d] = L32(x[d]^x[a], 8);
  x[c] = x[c]+x[d]; x[b] = L32(x[b]^x[c], 7);
}

static void
core(u8 o[64], const u32 in[16])
{
  u32 x[16];
  int i;

  FOR(i, 16) { x[i] = in[i]; }
  FOR(i, 10) {
    /* Column round */
    QR(x, 0, 4, 8,  12);
    QR(x, 1, 5, 9,  13);
    QR(x, 2, 6, 10, 14);
    QR(x, 3, 7, 11, 15);
    /* Diagonal round */
    QR(x, 0, 5, 10, 15);
    QR(x, 1, 6, 11, 12);
    QR(x, 2, 7, 8,  13);
    QR(x, 3, 4, 9,  14);
  }

  FOR(i, 16) { x[i] = x[i] + in[i]; } /* Add input */
  FOR(i, 16) { st32(o+(4*i), x[i]); } /* Output */
}

int
crypto_stream_chacha20_xor(u8* c, const u8* m, u64 b, const u8* n, const u8* k)
{
  u64 i;
  u32 st[16];
  u8  blk[64];

  /* Constants */
  st[0]  = 0x61707865;
  st[1]  = 0x3320646e;
  st[2]  = 0x79622d32;
  st[3]  = 0x6b206574;
  /* 4-11: key bytes */
  st[4]  = ld32(k);
  st[5]  = ld32(k+4);
  st[6]  = ld32(k+8);
  st[7]  = ld32(k+12);
  st[8]  = ld32(k+16);
  st[9]  = ld32(k+20);
  st[10] = ld32(k+24);
  st[11] = ld32(k+28);
  /* Counter + Nonce */
  st[12] = 0;
  st[13] = 0;
  st[14] = ld32(n);
  st[15] = ld32(n+4);

  for(;;) {
    /* Advance state */
    core(blk, st);
    st[12] = st[12]+1;
    if (st[12] == 0) { st[13] = st[13]+1; }
    /* Fast path */
    if (b <= 64) { FOR(i,b) { c[i] = m[i] ^ blk[i]; } return 0; }
    /* Normal path */
    FOR(i, 64) { c[i] = m[i] ^ blk[i]; }
    b -= 64;
    m += 64;
    c += 64;
  }
  return 0;
}

int
crypto_stream_chacha20(u8* o, u64 ol, const u8* n, const u8* k)
{
  int i;
  FOR(i, ol) { o[i] = 0; }
  return crypto_stream_chacha20_xor(o,o,ol,n,k);
}
