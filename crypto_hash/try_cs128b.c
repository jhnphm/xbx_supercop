/*
 * crypto_hash/try.c version 20090118
 * D. J. Bernstein
 * Jens Graef (128b-modifications)
 * Public domain.
 */

#include <stdlib.h>
#include <stdio.h>
#include "crypto_hash.h"

extern unsigned char *alignedcalloc(unsigned long long);

const char *primitiveimplementation = crypto_hash_IMPLEMENTATION;

#define MAXTEST_BYTES (10000 + crypto_hash_BYTES)
#define CHECKSUM_BYTES 128
#define CHECKSUM_PAD_BYTES 2048 
#define TUNE_BYTES 1536

static unsigned char *h;
static unsigned char *h2;
static unsigned char *m;
static unsigned char *m2;

void fail(const char *why)
{
  printf("%s\n",why);
  exit(111);
}

void limits()
{
#ifdef RLIM_INFINITY
  struct rlimit r;
  r.rlim_cur = 0;
  r.rlim_max = 0;
#ifdef RLIMIT_NOFILE
  setrlimit(RLIMIT_NOFILE,&r);
#endif
#ifdef RLIMIT_NPROC
  setrlimit(RLIMIT_NPROC,&r);
#endif
#ifdef RLIMIT_CORE
  setrlimit(RLIMIT_CORE,&r);
#endif
#endif
}


unsigned char *alignedcalloc(unsigned long long len)
{
  unsigned char *x = (unsigned char *) calloc(1,len + 256);
  long long i;
  if (!x) fail("out of memory");
  /* will never deallocate so shifting is ok */
  for (i = 0;i < len + 256;++i) x[i] = random();
  x += 64;
  x += 63 & (-(unsigned long) x);
  for (i = 0;i < len;++i) x[i] = 0;
  return x;
}

void preallocate(void)
{
}

void allocate(void)
{
  h = alignedcalloc(crypto_hash_BYTES);
  h2 = alignedcalloc(crypto_hash_BYTES);
  m = alignedcalloc(MAXTEST_BYTES);
  m2 = alignedcalloc(MAXTEST_BYTES);
}

void predoit(void)
{
}

void doit(void)
{
  crypto_hash(h,m,TUNE_BYTES);
}

char checksum_v[crypto_hash_BYTES * 2 + 1];

void calc_checksum(void)
{
  long long i;
  long long j;

  for (i = 0;i < CHECKSUM_BYTES;++i) {
    long long hlen = crypto_hash_BYTES;
    long long mlen = i;

    /* fill area before start und end with random */
    for (j = -16;j < 0;++j) h[j] = random();
    for (j = hlen;j < hlen + 16;++j) h[j] = random();
    /* copy to h2 */
    for (j = -16;j < hlen + 16;++j) h2[j] = h[j];
    /* fill area before start und end with random */
    for (j = -16;j < 0;++j) m[j] = random();
    for (j = mlen;j < mlen + 16;++j) m[j] = random();
    /* copy to h1 */
    for (j = -16;j < mlen + 16;++j) m2[j] = m[j];


    if (crypto_hash(h,m,mlen) != 0) fail( "crypto_hash returns nonzero");
    /* check original message */
    for (j = -16;j < mlen + 16;++j) if (m2[j] != m[j]) fail( "crypto_hash writes to input");
    /* check area before start and end */
    for (j = -16;j < 0;++j) if (h2[j] != h[j]) fail( "crypto_hash writes before output");
    for (j = hlen;j < hlen + 16;++j) if (h2[j] != h[j]) fail( "crypto_hash writes after output");
    /* crypt into itself */
    if (crypto_hash(m2,m2,mlen) != 0) fail( "crypto_hash returns nonzero");
    /* compare */
    for (j = 0;j < hlen;++j) if (m2[j] != h[j]) fail( "crypto_hash does not handle overlap");


    /* xor the message with the hash */
    for (j = 0;j < mlen;++j) m[j] ^= h[j % hlen];
    /* take the first byte of the hast as new next byte for message */
    m[mlen] = h[0];
  }
  
  /* padding */
  for(i=CHECKSUM_BYTES; i<CHECKSUM_PAD_BYTES;i++)
  {
    j=i-CHECKSUM_BYTES;

    /** convert to bcd */
    unsigned char high=(j%100)/10;
    unsigned char low=j%10;
    m[i]=high*16+low;
  } 

  /* hash it */
  if (crypto_hash(h,m,CHECKSUM_PAD_BYTES) != 0) fail( "crypto_hash returns nonzero");

  for (i = 0;i < crypto_hash_BYTES;++i) {
    checksum_v[2 * i] = "0123456789ABCDEF"[15 & (h[i] >> 4)];
    checksum_v[2 * i + 1] = "0123456789ABCDEF"[15 & h[i]];
  }
  checksum_v[2 * i] = 0;
}
int main(void){
  preallocate();
  limits();
  allocate();
  srandom(getpid());

    calc_checksum();
    puts(checksum_v);
    return 0;
}

