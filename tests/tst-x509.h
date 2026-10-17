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

/* Run-time X.509 fixture generation for tests, using GnuTLS directly.
   Generating certificates when the test runs means nothing expires.  */

#ifndef GQ_TST_X509_H
#define GQ_TST_X509_H

#include <time.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

/* Does the GnuTLS we build against name ML-DSA at all?  (Whether it can do
   it is another matter: gq_sigscheme_available.)  */
#define TST_HAVE_MLDSA (HAVE_DECL_GNUTLS_PK_MLDSA65 && HAVE_DECL_GNUTLS_SIGN_MLDSA65)

/* Can the GnuTLS in use make ML-DSA keys, that is, has it a backend for
   them (leancrypto)?  That is a different matter from whether the library can
   do ML-DSA, which libgcrypt gives it anyway.  The tests that need GnuTLS
   itself to make or validate ML-DSA (its own keys, chains signed with
   ML-DSA) ask this, and with GQ_EXPECT_MLDSA set they fail where it says
   no.  */
static inline int
tst_gnutls_mldsa (void)
{
#if TST_HAVE_MLDSA
  static int probed = -1;

  if (probed < 0)
    {
      gnutls_x509_privkey_t k;

      probed = 0;
      if (gnutls_x509_privkey_init (&k) >= 0)
        {
          probed = gnutls_x509_privkey_generate (k, GNUTLS_PK_MLDSA65, 0, 0) >= 0;
          gnutls_x509_privkey_deinit (k);
        }
    }
  return probed;
#else
  return 0;
#endif
}

enum tst_key
{
  TST_ECDSA256, TST_ECDSA384, TST_ED25519, TST_RSA2048, TST_RSA1024,
  TST_MLDSA44, TST_MLDSA65, TST_MLDSA87
};

struct tst_cert
{
  gnutls_x509_privkey_t key;
  gnutls_x509_crt_t crt;
};

/* Create a certificate for a fresh KIND key.  SAN NULL makes a CA.
   ISSUER NULL self-signs.  NOT_BEFORE/NOT_AFTER are seconds relative to
   now.  Returns 0 on success or a GnuTLS error.  */
static inline int
tst_make_cert_eku (struct tst_cert *out, enum tst_key kind, const char *cn,
                   const char *san, const struct tst_cert *issuer,
                   long not_before, long not_after,
                   gnutls_digest_algorithm_t dig, const char *eku)
{
  time_t now = time (NULL);
  unsigned char serial[4] = { 1, 2, 3, 4 };
  gnutls_pk_algorithm_t pk = GNUTLS_PK_ECDSA;
  unsigned bits = 256;
  int r;

  switch (kind)
    {
    case TST_ECDSA256: bits = GNUTLS_CURVE_TO_BITS (GNUTLS_ECC_CURVE_SECP256R1); break;
    case TST_ECDSA384: bits = GNUTLS_CURVE_TO_BITS (GNUTLS_ECC_CURVE_SECP384R1); break;
    case TST_ED25519: pk = GNUTLS_PK_EDDSA_ED25519;
      bits = gnutls_sec_param_to_pk_bits (pk, GNUTLS_SEC_PARAM_MEDIUM);
      dig = GNUTLS_DIG_UNKNOWN;		/* EdDSA hashes internally.  */
      break;
    case TST_RSA2048: pk = GNUTLS_PK_RSA; bits = 2048; break;
    case TST_RSA1024: pk = GNUTLS_PK_RSA; bits = 1024; break;
#if TST_HAVE_MLDSA
    case TST_MLDSA44: pk = GNUTLS_PK_MLDSA44; bits = 0; dig = GNUTLS_DIG_UNKNOWN;
      break;
    case TST_MLDSA65: pk = GNUTLS_PK_MLDSA65; bits = 0; dig = GNUTLS_DIG_UNKNOWN;
      break;
    case TST_MLDSA87: pk = GNUTLS_PK_MLDSA87; bits = 0; dig = GNUTLS_DIG_UNKNOWN;
      break;
#else
    case TST_MLDSA44: case TST_MLDSA65: case TST_MLDSA87:
      return GNUTLS_E_UNIMPLEMENTED_FEATURE;
#endif
    }

  gnutls_x509_privkey_init (&out->key);
  r = gnutls_x509_privkey_generate (out->key, pk, bits, 0);
  if (r < 0)
    return r;
  gnutls_x509_crt_init (&out->crt);
  gnutls_x509_crt_set_version (out->crt, 3);
  gnutls_x509_crt_set_key (out->crt, out->key);
  gnutls_x509_crt_set_serial (out->crt, serial, sizeof serial);
  gnutls_x509_crt_set_activation_time (out->crt, now + not_before);
  gnutls_x509_crt_set_expiration_time (out->crt, now + not_after);
  gnutls_x509_crt_set_dn_by_oid (out->crt, GNUTLS_OID_X520_COMMON_NAME, 0, cn,
                                 (unsigned) strlen (cn));
  if (san == NULL)
    {
      gnutls_x509_crt_set_basic_constraints (out->crt, 1, -1);
      gnutls_x509_crt_set_key_usage (out->crt, GNUTLS_KEY_KEY_CERT_SIGN);
    }
  else
    {
      gnutls_x509_crt_set_subject_alt_name (out->crt, GNUTLS_SAN_DNSNAME, san,
                                            (unsigned) strlen (san),
                                            GNUTLS_FSAN_SET);
      gnutls_x509_crt_set_key_purpose_oid (out->crt, eku, 0);
    }
  if (issuer == NULL)
    return gnutls_x509_crt_sign2 (out->crt, out->crt, out->key, dig, 0);
  return gnutls_x509_crt_sign2 (out->crt, issuer->crt, issuer->key, dig, 0);
}

/* Server certificate (serverAuth).  */
static inline int
tst_make_cert (struct tst_cert *out, enum tst_key kind, const char *cn,
               const char *san, const struct tst_cert *issuer,
               long not_before, long not_after, gnutls_digest_algorithm_t dig)
{
  return tst_make_cert_eku (out, kind, cn, san, issuer, not_before, not_after,
                            dig, GNUTLS_KP_TLS_WWW_SERVER);
}

static inline void
tst_free_cert (struct tst_cert *c)
{
  gnutls_x509_crt_deinit (c->crt);
  gnutls_x509_privkey_deinit (c->key);
}

#endif
