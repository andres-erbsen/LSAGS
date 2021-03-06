// Written by Andres Erbsen, distributed under GPLv3 with the OpenSSL exception

#include "lsags.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include "keccak/KeccakSponge.h"

#include <stdio.h>
#include <assert.h>


/* deterministic random number r:  0 <= r < range */
int BN_keccak_range(BIGNUM* r, const BIGNUM *range, const spongeState *hash_ctx) {
  int ret = 0, bytes = 0;
  unsigned char *buf = NULL;
  if (range->neg || BN_is_zero(range)) goto err;
  if (!BN_one(r)) goto err;
  if (!BN_sub(r,range,r)) goto err; // r = rand-1
  int bits = BN_num_bits(r);
  if (bits == 0) { // range = 1; r = 0
    return 1;
  }
	bytes = (bits+7)/8;
	unsigned char mask = ~(0xff<<((bits-1)%8 + 1));

  buf = OPENSSL_malloc(bytes);
  if (buf == NULL) goto err;
  
  unsigned char i = 0;
  do {
    if (i == 100) goto err;
    spongeState hash_ctx_try = *hash_ctx;
    Absorb(&hash_ctx_try, &i, 8*sizeof(unsigned char));
    Squeeze(&hash_ctx_try, buf, 8*bytes); // only sqeuuezing only `bits` could work
    buf[0] &= mask;
    if (!BN_bin2bn(buf, bytes, r)) goto err;
  } while (++i, BN_ucmp(r,range) >= 0);

  ret = 1;
err:
  OPENSSL_cleanse(buf, bytes);
  OPENSSL_free(buf);
  return ret;
}


int EC_POINT_keccak(const EC_GROUP *group, EC_POINT *point, const spongeState *hash_ctx, BN_CTX* ctx) {
  int ret = 0, bytes = 0;
  unsigned char *buf = NULL;
  BIGNUM *range=NULL, *a=NULL, *b=NULL;
  BN_CTX_start(ctx);
  range = BN_CTX_get(ctx);
  a = BN_CTX_get(ctx);
  b = BN_CTX_get(ctx);
  if (b == NULL) goto err;
  if (!EC_GROUP_get_curve_GFp(group, range, a, b, ctx)) goto err;

  // a and b are useless. reuse a for range-1
  if (range->neg || BN_is_zero(range)) goto err;
  if (!BN_one(a)) goto err;
  if (!BN_sub(a,range,a)) goto err; // r = rand-1
  int bits = BN_num_bits(a);
	bytes = (bits+7)/8 + 1; // +1 for encoding / y sign byte
	unsigned char mask = ~(0xff<<((bits-1)%8 + 1));
  
  buf = OPENSSL_malloc(bytes);
  if (buf == NULL) goto err;

  unsigned char i = 0;
  do {
    if (i == 200) goto err;
    spongeState hash_ctx_try = *hash_ctx;
    Absorb(&hash_ctx_try, &i, 8);
    Squeeze(&hash_ctx_try, buf, 8*bytes);
    buf[0] &= 1; // y sign bit
    buf[0] |= POINT_CONVERSION_COMPRESSED;
    buf[1] &= mask;
  } while (++i, !EC_POINT_oct2point(group, point, buf, bytes, ctx));

  ret = 1;
err:
  BN_CTX_end(ctx);
  OPENSSL_cleanse(buf, bytes);
  OPENSSL_free(buf);
  return ret;
}


int BN_bn2bin_be(const BIGNUM *a, unsigned char *to, int len) {
  int offset = len - BN_num_bytes(a);
  while (offset--) *to++ = '\0';
  BN_bn2bin(a, to);
  return len;
}


int LSAGS_keygen(unsigned char* sk, unsigned char* pk) {
  int ret = 0;
  EC_KEY* eckey = EC_KEY_new_by_curve_name(LSAGS_CURVE_NID);
  if (eckey == NULL) goto err;
  if (!EC_KEY_generate_key(eckey)) goto err;
  if (!EC_POINT_point2oct(
          EC_KEY_get0_group(eckey), 
          EC_KEY_get0_public_key(eckey),
          POINT_CONVERSION_COMPRESSED,
          pk,
          LSAGS_PK_SIZE,
          NULL)) goto err;
  if (!BN_bn2bin_be(EC_KEY_get0_private_key(eckey), sk, LSAGS_SK_SIZE)) goto err;

  ret = 1;
err:
  EC_KEY_free(eckey);
  return ret;
}


// hLym = hash(( pks, y_tilde, m ))
int LSAGS_hLym(unsigned char* hLym, const int n, const unsigned char* pks,
               const size_t pks_size, const unsigned char* y_tilde_raw,
               const unsigned char* msg, const size_t msg_size) {
  spongeState hash_ctx;
  InitSponge(&hash_ctx, LSAGS_KECCAK_r, LSAGS_KECCAK_c);
  unsigned char n_le[4]; // little-endian # of pks, make the encoding reversible
  n_le[0]=n&0xff; n_le[1]=(n>>8)&0xff; n_le[2]=(n>>16)&0xff; n_le[3]=(n>>24)&0xff;
  Absorb(&hash_ctx, n_le, 8*4);
  Absorb(&hash_ctx, pks, 8*pks_size);
  Absorb(&hash_ctx, y_tilde_raw, 8*LSAGS_PK_SIZE);
  Absorb(&hash_ctx, msg, 8*msg_size);
  Squeeze(&hash_ctx, hLym, 8*LSAGS_HASH_SIZE);
  return 1;
}


// h = group.hash((tag, pks), G)
#define LSAGS_h_MACRO do {\
  spongeState hash_ctx;\
  InitSponge(&hash_ctx, LSAGS_KECCAK_r, LSAGS_KECCAK_c);\
  Absorb(&hash_ctx, "G", 8); /* different from other hashes here*/ \
  unsigned char ts_le[4]; /*little-endian tag size*/\
  ts_le[0]=tag_size&0xff; ts_le[1]=(tag_size>>8)&0xff;\
  ts_le[2]=(tag_size>>16)&0xff; ts_le[3]=(tag_size>>24)&0xff;\
  Absorb(&hash_ctx, ts_le, 32);\
  Absorb(&hash_ctx, tag, 8*tag_size);\
  Absorb(&hash_ctx, pks, 8*pks_size);\
  if(!EC_POINT_keccak(group, h, &hash_ctx, ctx)) goto err;\
} while (0)


// c = group.hash(( hLym, z, zz ))
#define LSAGS_c_combine_MACRO do {\
  unsigned char z_raw[LSAGS_PK_SIZE], zz_raw[LSAGS_PK_SIZE];\
  if (!EC_POINT_point2oct(group, z, POINT_CONVERSION_COMPRESSED,\
        z_raw, LSAGS_PK_SIZE, ctx)) goto err;\
  if (!EC_POINT_point2oct(group, zz, POINT_CONVERSION_COMPRESSED,\
        zz_raw, LSAGS_PK_SIZE, ctx)) goto err;\
  spongeState hash_ctx;\
  InitSponge(&hash_ctx, LSAGS_KECCAK_r, LSAGS_KECCAK_c);\
  Absorb(&hash_ctx, hLym, 8*LSAGS_HASH_SIZE);\
  Absorb(&hash_ctx, z_raw, 8*LSAGS_PK_SIZE);\
  Absorb(&hash_ctx, zz_raw, 8*LSAGS_PK_SIZE);\
  if(!BN_keccak_range(c, q, &hash_ctx)) goto err;\
} while (0)


// c = group.hash((  hLym,    g**s * pk_i**c,   h**s * y_tilde**c  ))
#define LSAGS_c_round_MACRO do {\
  if(!EC_POINT_oct2point(group, pk, pks + i*LSAGS_PK_SIZE, LSAGS_PK_SIZE, ctx)) goto err;\
  if(!EC_POINT_mul(group, z, s, pk, c, ctx)) goto err;\
  if(!EC_POINT_mul(group, t, NULL, h, s, ctx)) goto err;\
  if(!EC_POINT_mul(group, zz, NULL, y_tilde, c, ctx)) goto err;\
  if(!EC_POINT_add(group, zz, zz, t, ctx)) goto err;\
  LSAGS_c_combine_MACRO;\
} while (0)


size_t LSAGS_sig_size(const int n) {
  return LSAGS_PK_SIZE + LSAGS_SK_SIZE * (1+n);
}

int LSAGS_verify(const unsigned char* pks, const size_t pks_size, const unsigned char* msg, const size_t msg_size, const unsigned char* tag, const size_t tag_size, const unsigned char* sig, const size_t sig_size, BN_CTX* ctx) {
  EC_POINT *y_tilde=NULL, *h=NULL, *t=NULL, *z=NULL, *zz=NULL, *pk=NULL;
  BIGNUM *c=NULL, *q=NULL, *s=NULL;
  EC_GROUP* group=NULL;
  int ret = 0, ctx_is_new = 0;
  if (pks_size % LSAGS_PK_SIZE) return 0;
  int n = pks_size / LSAGS_PK_SIZE;
  if (LSAGS_sig_size(n) != sig_size) return 0;

  if (ctx == NULL) {
    ctx = BN_CTX_new();
    ctx_is_new = 1;
  }
  if (ctx == NULL) goto err;
  BN_CTX_start(ctx);
  c = BN_CTX_get(ctx);
  q = BN_CTX_get(ctx);
  s = BN_CTX_get(ctx);
  if (s == NULL) goto err;

  if ((group = EC_GROUP_new_by_curve_name(LSAGS_CURVE_NID)) == NULL) goto err;
  if (!EC_GROUP_get_order(group, q, ctx)) goto err;
  y_tilde = EC_POINT_new(group); if (y_tilde == NULL) goto err;
  h = EC_POINT_new(group); if (h == NULL) goto err;
  t = EC_POINT_new(group); if (t == NULL) goto err;
  z = EC_POINT_new(group); if (z == NULL) goto err;
  zz = EC_POINT_new(group); if (zz == NULL) goto err;
  pk = EC_POINT_new(group); if (pk == NULL) goto err;

  LSAGS_h_MACRO;
  if (!EC_POINT_oct2point(group, y_tilde, sig, LSAGS_PK_SIZE, ctx)) goto err;
  BN_bin2bn(sig + LSAGS_PK_SIZE, LSAGS_SK_SIZE, c);

  unsigned char hLym[LSAGS_HASH_SIZE];
  if (!LSAGS_hLym(hLym, n, pks, pks_size, sig, msg, msg_size)) goto err;

  int i; for (i=0; i<n; ++i) {
    BN_bin2bn(sig + LSAGS_PK_SIZE + (1+i)*LSAGS_SK_SIZE, LSAGS_SK_SIZE, s); 
    LSAGS_c_round_MACRO;
  }

  unsigned char computed_c_raw[LSAGS_SK_SIZE];
  if (!BN_bn2bin_be(c, computed_c_raw, LSAGS_SK_SIZE)) goto err;

  ret = 1;
  for (i=0; i<LSAGS_SK_SIZE; ++i)
    ret &= (computed_c_raw[i] == sig[LSAGS_PK_SIZE+i]);

err:
  EC_POINT_free(pk);
  EC_POINT_free(zz);
  EC_POINT_free(z);
  EC_POINT_free(t);
  EC_POINT_free(h);
  EC_POINT_free(y_tilde);
  EC_GROUP_free(group);
  if (ctx) BN_CTX_end(ctx);
  if (ctx_is_new) BN_CTX_free(ctx);
  return ret;
}


int LSAGS_sign(unsigned char* pks, size_t pks_size, unsigned char* sk, unsigned char* msg, size_t msg_size, unsigned char* tag, const size_t tag_size, unsigned char* sig_out, BN_CTX* ctx) {
  BIGNUM *x_pi=NULL, *u=NULL, *q=NULL, *c=NULL, *s=NULL;
  EC_POINT *y_tilde=NULL, *h=NULL, *z=NULL, *zz=NULL, *pk=NULL, *t=NULL;
  EC_GROUP* group=NULL;
  int ret = 0, ctx_is_new = 0;
  if (pks_size % LSAGS_PK_SIZE) return 0;
  int n = pks_size / LSAGS_PK_SIZE;

  if (ctx == NULL) {
    ctx_is_new = 1;
    ctx = BN_CTX_new();
  }
  if (ctx == NULL) goto err;
  BN_CTX_start(ctx);
  x_pi = BN_CTX_get(ctx);
  u = BN_CTX_get(ctx);
  q = BN_CTX_get(ctx);
  c = BN_CTX_get(ctx);
  s = BN_CTX_get(ctx);
  if (s == NULL) goto err;

  if ((group = EC_GROUP_new_by_curve_name(LSAGS_CURVE_NID)) == NULL) goto err;
  if (!EC_GROUP_precompute_mult(group, ctx)) goto err;
  if (!EC_GROUP_get_order(group, q, ctx)) goto err;

  y_tilde = EC_POINT_new(group); if (y_tilde == NULL) goto err;
  h = EC_POINT_new(group); if (h == NULL) goto err;
  t = EC_POINT_new(group); if (t == NULL) goto err;
  z = EC_POINT_new(group); if (z == NULL) goto err;
  zz = EC_POINT_new(group); if (zz == NULL) goto err;
  pk = EC_POINT_new(group); if (pk == NULL) goto err;

  BN_bin2bn(sk, LSAGS_SK_SIZE, x_pi);
  if (!EC_POINT_mul(group, pk, x_pi, NULL, NULL, ctx)) goto err;
  char our_pk_raw[LSAGS_PK_SIZE];
  if (!EC_POINT_point2oct(group, pk, POINT_CONVERSION_COMPRESSED,
        our_pk_raw, LSAGS_PK_SIZE, ctx)) goto err;
  int pi = -1;
  int j; for (j=0; j<n; ++j) {
    if (!memcmp(our_pk_raw, pks+j*LSAGS_PK_SIZE, LSAGS_PK_SIZE)) {
      pi = j;
      break;
    }
  }
  if (pi < 0) goto err;
  if (pi >= n) goto err;


  LSAGS_h_MACRO;

  // y_tilde = h**x_pi
  if(!EC_POINT_mul(group, y_tilde, NULL, h, x_pi, ctx)) goto err;
  if (!EC_POINT_point2oct(group, y_tilde, POINT_CONVERSION_COMPRESSED,
        sig_out, LSAGS_PK_SIZE, ctx)) goto err;

  unsigned char hLym[LSAGS_HASH_SIZE];
  if (!LSAGS_hLym(hLym, n, pks, pks_size, sig_out, msg, msg_size)) goto err;

  if (!BN_rand_range(u, q)) goto err;


  if (!EC_POINTs_mul(group, z, u, 0, NULL, NULL, ctx)) goto err; // z = g**u
  if(!EC_POINT_mul(group, zz, NULL, h, u, ctx)) goto err; // zz = h**u
  LSAGS_c_combine_MACRO;
  if (pi == n-1) if (!BN_bn2bin_be(c, sig_out + LSAGS_PK_SIZE, LSAGS_SK_SIZE)) goto err;

  int i = pi;
  while ((i = (i+1)%n) != pi) {
    assert(0 <= i);
    assert(i < n);
    if (!BN_rand_range(s, q)) goto err;
    if (!BN_bn2bin_be(s, sig_out + LSAGS_PK_SIZE + (1+i)*LSAGS_SK_SIZE, LSAGS_SK_SIZE)) goto err;
    LSAGS_c_round_MACRO;
    if (i == n-1) if (!BN_bn2bin_be(c, sig_out + LSAGS_PK_SIZE, LSAGS_SK_SIZE)) goto err;
  }

  // s = (u - x_pi*c) % q
  if (!BN_mod_mul(s, x_pi, c, q, ctx)) goto err;
  if (!BN_mod_sub_quick(s, u, s, q)) goto err;
  if (!BN_bn2bin_be(s, sig_out + LSAGS_PK_SIZE + (1+pi)*LSAGS_SK_SIZE, LSAGS_SK_SIZE)) goto err;

  ret = 1;
err:
  if (ctx) BN_CTX_end(ctx);
  if (ctx_is_new) BN_CTX_free(ctx);
  EC_POINT_free(y_tilde);
  EC_POINT_free(pk);
  EC_POINT_free(z);
  EC_POINT_free(h);
  EC_POINT_free(t);
  EC_POINT_free(zz);
  EC_GROUP_free(group);
  return ret;
}

