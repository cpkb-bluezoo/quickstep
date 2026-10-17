/* Copyright (C) 2026 Chris Burdess <dog@gnu.org>

   This file is part of quickstep.

   quickstep is free software: you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   quickstep is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public
   License along with this program.  If not, see
   <https://www.gnu.org/licenses/>.  */

/* ML-DSA (FIPS 204) through libgcrypt, for sign.c.  Internal: nothing here
   is exported.

   GnuTLS does ML-DSA only through the leancrypto backend, which most builds
   lack, but libgcrypt has had its own since 1.12.0.  This module drives
   that, and does the two jobs GnuTLS cannot do without its backend: it
   reads the private key forms of RFC 9881 (PKCS#8), and takes the raw
   public key out of the SubjectPublicKeyInfo of a certificate (GnuTLS can
   parse such a certificate and validate it under a classical CA, but gives
   no access to the key).  Nothing here uses GnuTLS.

   The schemes are the TLS SignatureScheme code points (GQ_SIG_MLDSA44,
   GQ_SIG_MLDSA65, GQ_SIG_MLDSA87).  Results are GQ_OK;
   GQ_ERR_UNSUPPORTED when what was given is not ML-DSA (or libgcrypt cannot
   do it), so that a caller may try something else; GQ_ERR_CERT for a key or
   certificate that is ML-DSA but malformed or inconsistent; GQ_ERR_CRYPTO
   for a signature that does not verify or an operation libgcrypt refused;
   GQ_ERR_BUFSIZE, GQ_ERR_RANGE and GQ_ERR_INVAL for the usual.  */

#ifndef QUICKSTEP_MLDSA_H
#define QUICKSTEP_MLDSA_H

#include <stddef.h>
#include <stdint.h>

#define GQI_MLDSA_SEED_LEN 32
#define GQI_MLDSA_PK_MAX 2592	/* ML-DSA-87.  */
#define GQI_MLDSA_SK_MAX 4896
#define GQI_MLDSA_SIG_MAX 4627
#define GQI_MLDSA_CTX_MAX 255	/* FIPS 204 algorithm 2.  */

/* A private key as read, expanded: the form that signs.  PK is set when the
   key came with a seed, which is the only way to know it.  Wipe it with
   gq_wipe when done.  */
struct gqi_mldsa_key
{
  unsigned scheme;
  uint8_t sk[GQI_MLDSA_SK_MAX];
  size_t sk_len;
  uint8_t pk[GQI_MLDSA_PK_MAX];
  size_t pk_len;			/* 0 if not known.  */
};

/* Sizes of the public key, expanded private key and signature of SCHEME,
   or 0 if it is not an ML-DSA scheme.  */
size_t gqi_mldsa_pk_len (unsigned scheme);
size_t gqi_mldsa_sk_len (unsigned scheme);
size_t gqi_mldsa_sig_len (unsigned scheme);

/* Can libgcrypt do ML-DSA here?  gqi_mldsa_enable (0) makes this say no
   until gqi_mldsa_enable (1), which tests use to reach what a caller does
   instead.  */
int gqi_mldsa_usable (void);
void gqi_mldsa_enable (int on);

/* ML-DSA.KeyGen_internal (FIPS 204 algorithm 6): the public key (PK_MAX
   bytes at most) and expanded private key from SEED.  */
int gqi_mldsa_keygen (unsigned scheme, const uint8_t seed[GQI_MLDSA_SEED_LEN],
                      uint8_t *pk, uint8_t *sk);

/* ML-DSA.Sign (algorithm 2, the pure form) of MSG with the context string
   CTX (CTX_LEN up to 255; NULL and 0 for the empty one that TLS uses).
   RND is the 32 bytes of randomness, or NULL for fresh ones (the hedged
   signature; all zero is the deterministic one).  The signature goes to SIG
   (CAP bytes) and its size to *SIG_LEN.  */
int gqi_mldsa_sign (unsigned scheme, const uint8_t *sk, const uint8_t *ctx,
                    size_t ctx_len, const uint8_t *msg, size_t len,
                    const uint8_t *rnd, uint8_t *sig, size_t cap,
                    size_t *sig_len);

/* ML-DSA.Sign_internal (algorithm 7): MSG is M' as the caller formed it,
   with no context prefix added.  */
int gqi_mldsa_sign_internal (unsigned scheme, const uint8_t *sk,
                             const uint8_t *msg, size_t len,
                             const uint8_t *rnd, uint8_t *sig, size_t cap,
                             size_t *sig_len);

/* ML-DSA.Verify (algorithm 3) and Verify_internal (algorithm 8).  GQ_OK if
   the signature is valid, GQ_ERR_CRYPTO if it is not (including one of the
   wrong length, or a key of the wrong size).  */
int gqi_mldsa_verify (unsigned scheme, const uint8_t *pk, size_t pk_len,
                      const uint8_t *ctx, size_t ctx_len,
                      const uint8_t *msg, size_t len,
                      const uint8_t *sig, size_t sig_len);
int gqi_mldsa_verify_internal (unsigned scheme, const uint8_t *pk,
                               size_t pk_len, const uint8_t *msg, size_t len,
                               const uint8_t *sig, size_t sig_len);

/* A private key in the PKCS#8 PrivateKeyInfo (OneAsymmetricKey) of RFC 9881
   section 6, DER: the seed, the expanded key, or both (which must agree,
   section 8.2).  The algorithm identifier must be one of the three OIDs
   with the parameters absent.  GQ_ERR_UNSUPPORTED if it is some other
   algorithm.  */
int gqi_mldsa_key_from_pkcs8 (const uint8_t *der, size_t len,
                              struct gqi_mldsa_key *key);

/* The same from PEM text with a "PRIVATE KEY" block (RFC 7468).
   GQ_ERR_UNSUPPORTED if there is none, or it is another algorithm.  */
int gqi_mldsa_key_from_pem (const void *pem, size_t len,
                            struct gqi_mldsa_key *key);

/* The public key in the SubjectPublicKeyInfo of the certificate CERT (DER):
   its scheme, and the raw key in PK (PK_MAX bytes) with its size in
   *PK_LEN.  GQ_ERR_UNSUPPORTED if the certificate's key is not ML-DSA,
   or it cannot be walked (the caller then lets the real parser say why).  */
int gqi_mldsa_pk_from_cert (const uint8_t *cert, size_t len, unsigned *scheme,
                            uint8_t *pk, size_t *pk_len);

#endif /* QUICKSTEP_MLDSA_H */
