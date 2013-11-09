#include <stdlib.h>
#include "nonce.h"

void
nacl_incnonce(unsigned char*p, size_t len)
{
  int i=len;
  for(; --i >= 0;) {
    if(++p[i] != 0) break;
  }
}
