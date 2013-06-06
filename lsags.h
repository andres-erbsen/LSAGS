// Written by Andres Erbsen, distributed under GPLv3 with the OpenSSL exception

#include <openssl/bn.h>

#define LSAGS_SK_SIZE 28
#define LSAGS_PK_SIZE 29
#define LSAGS_HASH_SIZE 32

// keccak parameters: the default, more conservative than the 256-bit proposal
#define LSAGS_KECCAK_r 1024
#define LSAGS_KECCAK_c (1600-LSAGS_KECCAK_r)

#define LSAGS_CURVE_NID NID_secp224r1


int LSAGS_keygen(unsigned char* sk, unsigned char* pk);

int LSAGS_verify(const unsigned char* pks, const size_t pks_size, const unsigned char* msg, const size_t msg_size, const unsigned char* tag, const unsigned char tag_size, const unsigned char* sig, BN_CTX* ctx);

int LSAGS_sign(unsigned char* pks, size_t pks_size, unsigned char* sk, int pi, unsigned char* msg, size_t msg_size, unsigned char* tag, const unsigned char tag_size, unsigned char* sig_out, BN_CTX* ctx);
