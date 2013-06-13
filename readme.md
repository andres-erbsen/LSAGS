Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups
================================================================

An implementation of the linkable anonymous group signature scheme by Joseph K.
Liu, Victor K. Wei and Duncan S. Wong described in
<http://eprint.iacr.org/2004/027.pdf>.

The primitives used go as follows:

- $G$ is the NIST P-224 elliptic curve
- $H_1$ and $H_2$ are implemented using `Keccak[]`. $H(x)$ is the $H(x||i)$ with
  the least byte $i$ for which the result represents some element of the
  required group
- Private keys and other scalars are encoded as 28-byte big-endian integers
- Public keys and other elliptic curve points are encoded as a byte in
  {`0x02`,`0x03`} representing the sign of the $y$ coordinate followed by the
  $x$ coordinate.


Dependencies
------------
- `openssl`
- `keccak` (included)

Building
--------
    gcc -c -O3 keccak/KeccakF-1600-opt32.c -o keccak/KeccakF-1600-opt32.o
    gcc -c -O3 keccak/KeccakSponge.c -o keccak/KeccakSponge.o
    gcc -c -O3 lsags.c -o lsags.o
    gcc -O3 -o lsags-test lsags-test.c lsags.o keccak/KeccakSponge.o keccak/KeccakF-1600-opt32.o -lcrypto


Performance
-----------
Signing or verifying a message in a group with 1000 members takes about 2
seconds on Intel Core 2 Duo L9400 @ 1.86GHz.

License
-------
GPLv3 with the exception that allows linking to OpenSSL. If you are a non-GPL
open source project and would like to use the code, contact me about it.
