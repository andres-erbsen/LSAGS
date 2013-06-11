// Written by Andres Erbsen, distributed under GPLv3 with the OpenSSL exception

#include <assert.h>
#include "lsags.h"

#define N 10
unsigned char sks[N*LSAGS_SK_SIZE];
unsigned char pks[N*LSAGS_PK_SIZE];

int main () {
  unsigned char *sig = calloc(LSAGS_sig_size(N),1);
  if (sig == NULL) goto err;

  int i;
  for (i=0; i<N; ++i) {
    if (!LSAGS_keygen(sks+i*LSAGS_SK_SIZE, pks+i*LSAGS_PK_SIZE)) goto err;
  }

  for (i=0; i<N; ++i) {
    if(!LSAGS_sign(pks, sizeof(pks), sks+i*LSAGS_SK_SIZE, "ABCD1234", 8, "FISH", 4, sig, NULL)) goto err;
    if(!LSAGS_verify(pks, sizeof(pks), "ABCD1234", 8, "FISH", 4, sig, NULL)) assert(0);
  }
  exit(0);
err:
  exit(1);
}
