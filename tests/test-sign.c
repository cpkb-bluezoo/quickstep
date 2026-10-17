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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <quickstep/status.h>
#include <quickstep/policy.h>
#include <quickstep/sign.h>

#include "../src/mldsa.h"
#include "tst-util.h"
#include "vectors-mldsa.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  gq_privkey *k;

  CHECK_EQ (gq_privkey_from_pem (&k, "x", 1), GQ_ERR_UNAVAILABLE);
  TST_DONE ();
}

#else

#include "tst-x509.h"

static const unsigned all_schemes[] = {
  GQ_SIG_ECDSA_SECP256R1_SHA256, GQ_SIG_ECDSA_SECP384R1_SHA384,
  GQ_SIG_RSA_PSS_RSAE_SHA256, GQ_SIG_RSA_PSS_RSAE_SHA384,
  GQ_SIG_RSA_PSS_RSAE_SHA512, GQ_SIG_ED25519,
  GQ_SIG_RSA_PKCS1_SHA256, GQ_SIG_RSA_PKCS1_SHA384, GQ_SIG_RSA_PKCS1_SHA512,
  GQ_SIG_MLDSA44, GQ_SIG_MLDSA65, GQ_SIG_MLDSA87
};

static const unsigned schemes3[] = { GQ_SIG_MLDSA44, GQ_SIG_MLDSA65,
                                     GQ_SIG_MLDSA87 };

static const char message[] = "TLS 1.3, server CertificateVerify";

/* Load KIND's key and certificate through our own API.  */
static void
load (enum tst_key kind, struct tst_cert *c, gq_privkey **priv,
      gq_pubkey **pub)
{
  gnutls_datum_t pem, der;
  int r = tst_make_cert (c, kind, "example.test", "example.test", NULL,
                         -3600, 86400, GNUTLS_DIG_SHA256);

  *priv = NULL;
  *pub = NULL;
  CHECK_EQ (r, 0);
  if (r != 0)
    return;
  CHECK_EQ (gnutls_x509_privkey_export2_pkcs8 (c->key, GNUTLS_X509_FMT_PEM, NULL,
                                            GNUTLS_PKCS_PLAIN, &pem), 0);
  CHECK_EQ (gnutls_x509_crt_export2 (c->crt, GNUTLS_X509_FMT_DER, &der), 0);
  CHECK_EQ (gq_privkey_from_pem (priv, pem.data, pem.size), GQ_OK);
  CHECK_EQ (gq_pubkey_from_cert (pub, der.data, der.size), GQ_OK);
  gnutls_free (pem.data);
  gnutls_free (der.data);
}

static void
test_key (enum tst_key kind, const unsigned *fit, size_t nfit)
{
  struct tst_cert c;
  gq_privkey *priv;
  gq_pubkey *pub;
  uint8_t sig[GQ_SIGNATURE_MAX], bad[GQ_SIGNATURE_MAX];
  size_t n, i, j;

  load (kind, &c, &priv, &pub);
  if (priv == NULL || pub == NULL)
    return;

  for (j = 0; j < sizeof all_schemes / sizeof all_schemes[0]; j++)
    {
      unsigned s = all_schemes[j];
      int fits = 0;

      for (i = 0; i < nfit; i++)
        fits |= fit[i] == s;
      CHECK_EQ (gq_privkey_supports (priv, s), fits);

      if (!fits)
        {
          /* A scheme that does not fit the key is refused on both sides.  */
          CHECK_EQ (gq_privkey_sign (priv, s, message, sizeof message, sig,
                                     sizeof sig, &n), GQ_ERR_CRYPTO);
          CHECK_EQ (gq_pubkey_verify (pub, s, message, sizeof message, sig, 64),
                    GQ_ERR_CRYPTO);
          continue;
        }

      CHECK_EQ (gq_privkey_sign (priv, s, message, sizeof message, sig,
                                 sizeof sig, &n), GQ_OK);
      CHECK (n > 0 && n <= GQ_SIGNATURE_MAX);
      CHECK_EQ (gq_pubkey_verify (pub, s, message, sizeof message, sig, n),
                GQ_OK);

      /* Any change to message or signature, or truncation, is refused.  */
      CHECK_EQ (gq_pubkey_verify (pub, s, message, sizeof message - 1, sig, n),
                GQ_ERR_CRYPTO);
      memcpy (bad, sig, n);
      bad[n / 2] ^= 1;
      CHECK_EQ (gq_pubkey_verify (pub, s, message, sizeof message, bad, n),
                GQ_ERR_CRYPTO);
      CHECK_EQ (gq_pubkey_verify (pub, s, message, sizeof message, sig, n - 1),
                GQ_ERR_CRYPTO);

      /* Output buffer too small.  */
      CHECK_EQ (gq_privkey_sign (priv, s, message, sizeof message, sig, 8, &n),
                GQ_ERR_BUFSIZE);
    }

  /* A signature made under one RSA-PSS hash does not verify as another.  */
  if (kind == TST_RSA2048)
    {
      CHECK_EQ (gq_privkey_sign (priv, GQ_SIG_RSA_PKCS1_SHA256, message,
                                 sizeof message, sig, sizeof sig, &n), GQ_OK);
      CHECK_EQ (gq_pubkey_verify (pub, GQ_SIG_RSA_PKCS1_SHA384, message,
                                  sizeof message, sig, n), GQ_ERR_CRYPTO);
      CHECK_EQ (gq_privkey_sign (priv, GQ_SIG_RSA_PSS_RSAE_SHA256, message,
                                 sizeof message, sig, sizeof sig, &n), GQ_OK);
      CHECK_EQ (gq_pubkey_verify (pub, GQ_SIG_RSA_PSS_RSAE_SHA384, message,
                                  sizeof message, sig, n), GQ_ERR_CRYPTO);
    }

  gq_privkey_free (priv);
  gq_pubkey_free (pub);
  tst_free_cert (&c);
}

static void
test_policy_and_errors (void)
{
  struct tst_cert c;
  gq_privkey *priv, *k;
  gq_pubkey *pub, *p;
  uint8_t sig[GQ_SIGNATURE_MAX];
  size_t n;

  load (TST_ECDSA256, &c, &priv, &pub);
  if (priv == NULL || pub == NULL)
    return;

  /* Schemes outside the policy.  */
  CHECK_EQ (gq_privkey_sign (priv, 0x0201, message, 4, sig, sizeof sig, &n),
            GQ_ERR_UNSUPPORTED);		/* RSA PKCS#1 SHA-1 */
  CHECK_EQ (gq_privkey_sign (priv, 0x0203, message, 4, sig, sizeof sig, &n),
            GQ_ERR_UNSUPPORTED);		/* ECDSA SHA-1 */
  CHECK_EQ (gq_pubkey_verify (pub, 0x0201, message, 4, sig, 64),
            GQ_ERR_UNSUPPORTED);
  CHECK (!gq_privkey_supports (priv, 0x0203));

  /* An ML-DSA scheme cannot be used with a classical key.  */
  CHECK_EQ (gq_privkey_sign (priv, GQ_SIG_MLDSA65, message, 4, sig,
                             sizeof sig, &n), GQ_ERR_CRYPTO);

  /* Garbage input.  */
  CHECK_EQ (gq_privkey_from_pem (&k, "not a key", 9), GQ_ERR_CERT);
  CHECK_EQ (gq_pubkey_from_cert (&p, (const uint8_t *) "junk", 4),
            GQ_ERR_CERT);

  gq_privkey_free (priv);
  gq_pubkey_free (pub);
  tst_free_cert (&c);
}

static void
test_weak_rsa (void)
{
  struct tst_cert c;
  gnutls_datum_t pem, der;
  gq_privkey *k;
  gq_pubkey *p;

  if (tst_make_cert (&c, TST_RSA1024, "example.test", "example.test", NULL,
                     -3600, 86400, GNUTLS_DIG_SHA256) != 0)
    {
      fprintf (stderr, "note: cannot generate RSA-1024 here; skipped\n");
      return;
    }
  CHECK_EQ (gnutls_x509_privkey_export2_pkcs8 (c.key, GNUTLS_X509_FMT_PEM, NULL,
                                            GNUTLS_PKCS_PLAIN, &pem), 0);
  CHECK_EQ (gnutls_x509_crt_export2 (c.crt, GNUTLS_X509_FMT_DER, &der), 0);
  CHECK_EQ (gq_privkey_from_pem (&k, pem.data, pem.size), GQ_ERR_CERT);
  CHECK_EQ (gq_pubkey_from_cert (&p, der.data, der.size), GQ_ERR_CERT);
  gnutls_free (pem.data);
  gnutls_free (der.data);
  tst_free_cert (&c);
}

#if TST_HAVE_MLDSA

static const struct
{
  enum tst_key kind;
  unsigned scheme;
  size_t size;			/* The signature, FIPS 204 table 2.  */
} mldsa_kinds[] = {
  { TST_MLDSA44, GQ_SIG_MLDSA44, 2420 },
  { TST_MLDSA65, GQ_SIG_MLDSA65, 3309 },
  { TST_MLDSA87, GQ_SIG_MLDSA87, 4627 }
};

static gnutls_sign_algorithm_t
gnutls_algo (unsigned scheme)
{
  return scheme == GQ_SIG_MLDSA44 ? GNUTLS_SIGN_MLDSA44
    : scheme == GQ_SIG_MLDSA65 ? GNUTLS_SIGN_MLDSA65 : GNUTLS_SIGN_MLDSA87;
}

/* One ML-DSA parameter set, with a key that GnuTLS made.  LIBGCRYPT says
   which implementation of ours loads it: libgcrypt's (the choice when it
   can) or, with that turned off, GnuTLS's own.  The checks every key gets (a
   signature checks, any change or truncation of it or of the message does
   not, the other schemes are refused), the size of the signature, a private
   key in each of the encodings RFC 9881 gives it (the seed, the expanded
   key, or both), and with libgcrypt, signatures made by one implementation
   checked by the other.  */
static void
test_mldsa_key (enum tst_key kind, unsigned scheme, size_t size,
                int libgcrypt)
{
  static const unsigned flags[] = {
    0,				/* GnuTLS's default: both, if it has the seed.  */
#if HAVE_DECL_GNUTLS_PKCS_MLDSA_SEED && HAVE_DECL_GNUTLS_PKCS_MLDSA_EXPANDED
    GNUTLS_PKCS_MLDSA_SEED, GNUTLS_PKCS_MLDSA_EXPANDED,
    GNUTLS_PKCS_MLDSA_SEED | GNUTLS_PKCS_MLDSA_EXPANDED
#endif
  };
  unsigned fit[1];
  struct tst_cert c;
  gq_privkey *priv, *k;
  gq_pubkey *pub;
  uint8_t sig[GQ_SIGNATURE_MAX];
  size_t n, i;

  gqi_mldsa_enable (libgcrypt);
  fit[0] = scheme;
  CHECK (gq_sigscheme_available (scheme));
  test_key (kind, fit, 1);

  load (kind, &c, &priv, &pub);
  if (priv == NULL || pub == NULL)
    return;
  CHECK_EQ (gq_privkey_sign (priv, scheme, message, sizeof message, sig,
                             sizeof sig, &n), GQ_OK);
  CHECK_EQ (n, size);

  for (i = 0; i < sizeof flags / sizeof flags[0]; i++)
    {
      gnutls_datum_t pem;

      CHECK_EQ (gnutls_x509_privkey_export2_pkcs8 (c.key,
                                                   GNUTLS_X509_FMT_PEM, NULL,
                                                   flags[i], &pem), 0);
      if (gq_privkey_from_pem (&k, pem.data, pem.size) != GQ_OK)
        {
          fprintf (stderr, "private key encoding 0x%x not loaded\n", flags[i]);
          tst_failures++;
        }
      else
        {
          CHECK (gq_privkey_supports (k, scheme));
          CHECK_EQ (gq_privkey_sign (k, scheme, message, sizeof message, sig,
                                     sizeof sig, &n), GQ_OK);
          CHECK_EQ (n, size);
          CHECK_EQ (gq_pubkey_verify (pub, scheme, message, sizeof message,
                                      sig, n), GQ_OK);
          gq_privkey_free (k);
        }
      gnutls_free (pem.data);
    }

  /* Our signature checks with GnuTLS, and GnuTLS's with ours: two
     implementations (libgcrypt's and leancrypto's) of FIPS 204 and of the
     way TLS uses it, agreeing on the empty context.  */
  if (libgcrypt)
    {
      gnutls_privkey_t gk;
      gnutls_pubkey_t gp;
      gnutls_datum_t d = { (unsigned char *) (uintptr_t) message,
                           sizeof message }, gs = { NULL, 0 }, ours;

      CHECK_EQ (gq_privkey_sign (priv, scheme, message, sizeof message, sig,
                                 sizeof sig, &n), GQ_OK);
      ours.data = sig;
      ours.size = (unsigned) n;
      CHECK_EQ (gnutls_pubkey_init (&gp), 0);
      CHECK_EQ (gnutls_pubkey_import_x509 (gp, c.crt, 0), 0);
      CHECK (gnutls_pubkey_verify_data2 (gp, gnutls_algo (scheme), 0, &d,
                                         &ours) >= 0);
      CHECK (gnutls_pubkey_verify_data2 (gp, gnutls_algo (scheme), 0, &d,
                                         &ours) >= 0);
      CHECK_EQ (gnutls_privkey_init (&gk), 0);
      CHECK_EQ (gnutls_privkey_import_x509 (gk, c.key, 0), 0);
      CHECK (gnutls_privkey_sign_data2 (gk, gnutls_algo (scheme), 0, &d, &gs)
             >= 0);
      if (gs.data)
        {
          CHECK_EQ (gq_pubkey_verify (pub, scheme, message, sizeof message,
                                      gs.data, gs.size), GQ_OK);
          gnutls_free (gs.data);
        }
      gnutls_privkey_deinit (gk);
      gnutls_pubkey_deinit (gp);
    }

  gq_privkey_free (priv);
  gq_pubkey_free (pub);
  tst_free_cert (&c);
  gqi_mldsa_enable (1);
}

#endif /* TST_HAVE_MLDSA */

/* ML-DSA with GnuTLS's own backend, if it has one: keys it makes, loaded
   by libgcrypt's code and, with that turned off, by its own.  Where the
   build says it has such a GnuTLS (GQ_EXPECT_MLDSA), its absence fails the
   test.  */
static void
test_mldsa_size (void)
{
  /* GQ_SIGNATURE_MAX is documented as always enough; ML-DSA signatures are
     several kilobytes (FIPS 204: 2420, 3309 and 4627 octets), and the
     engines sign into buffers of that size.  */
  CHECK (GQ_SIGNATURE_MAX >= 4627);
}

static void
test_mldsa_gnutls (void)
{
#if !TST_HAVE_MLDSA
  tst_mldsa_ready (0, "the ML-DSA tests with GnuTLS keys");
#else
  size_t i;

  if (!tst_mldsa_ready (tst_gnutls_mldsa (), "the ML-DSA tests with GnuTLS keys"))
    return;
  for (i = 0; i < sizeof mldsa_kinds / sizeof mldsa_kinds[0]; i++)
    {
      test_mldsa_key (mldsa_kinds[i].kind, mldsa_kinds[i].scheme,
                      mldsa_kinds[i].size, 1);
      test_mldsa_key (mldsa_kinds[i].kind, mldsa_kinds[i].scheme,
                      mldsa_kinds[i].size, 0);
    }
#endif
}

/* ML-DSA through libgcrypt, which needs nothing of GnuTLS but its parser:
   the private keys and certificates of RFC 9881 appendix C, in the default
   environment.  */
static void
test_mldsa_libgcrypt (void)
{
  static const struct
  {
    unsigned scheme;
    size_t size;
  } sets[] = {
    { GQ_SIG_MLDSA44, 2420 }, { GQ_SIG_MLDSA65, 3309 },
    { GQ_SIG_MLDSA87, 4627 }
  };
  const char *const *seed_pem[3] = {
    (const char *const[]) { RFC9881_MLDSA44_SEED_PEM },
    (const char *const[]) { RFC9881_MLDSA65_SEED_PEM },
    (const char *const[]) { RFC9881_MLDSA87_SEED_PEM }
  };
  const char *const *exp_pem[3] = {
    (const char *const[]) { RFC9881_MLDSA44_EXPANDED_PEM },
    (const char *const[]) { RFC9881_MLDSA65_EXPANDED_PEM },
    (const char *const[]) { RFC9881_MLDSA87_EXPANDED_PEM }
  };
  const char *const *both_pem[3] = {
    (const char *const[]) { RFC9881_MLDSA44_BOTH_PEM },
    (const char *const[]) { RFC9881_MLDSA65_BOTH_PEM },
    (const char *const[]) { RFC9881_MLDSA87_BOTH_PEM }
  };
  const char *const *cert_pem[3] = {
    (const char *const[]) { RFC9881_MLDSA44_CERT_PEM },
    (const char *const[]) { RFC9881_MLDSA65_CERT_PEM },
    (const char *const[]) { RFC9881_MLDSA87_CERT_PEM }
  };
  static char pem[16384];
  static uint8_t der[16384], sig[GQ_SIGNATURE_MAX], bad[GQ_SIGNATURE_MAX];
  size_t i, j, k_, n, dl;

  CHECK (gqi_mldsa_usable ());
  for (i = 0; i < 3; i++)
    {
      CHECK (gq_sigscheme_available (sets[i].scheme));
      CHECK_EQ (gq_sigscheme_available (sets[i].scheme), 1);
    }

  for (i = 0; i < 3; i++)
    {
      unsigned sc = sets[i].scheme;
      const char *const *forms[3] = { seed_pem[i], exp_pem[i], both_pem[i] };
      gq_pubkey *pub = NULL;

      tst_cat_parts (cert_pem[i], pem, sizeof pem);
      dl = tst_pem_der (pem, der, sizeof der);
      CHECK_EQ (gq_pubkey_from_cert (&pub, der, dl), GQ_OK);
      if (pub == NULL)
        continue;

      for (j = 0; j < 3; j++)		/* seed, expanded, both.  */
        {
          gq_privkey *priv = NULL;

          tst_cat_parts (forms[j], pem, sizeof pem);
          CHECK_EQ (gq_privkey_from_pem (&priv, pem, strlen (pem)), GQ_OK);
          if (priv == NULL)
            continue;
          for (k_ = 0; k_ < 3; k_++)
            CHECK_EQ (gq_privkey_supports (priv, schemes3[k_]),
                      schemes3[k_] == sc);
          CHECK (!gq_privkey_supports (priv, GQ_SIG_ED25519));
          CHECK (!gq_privkey_supports (priv, GQ_SIG_ECDSA_SECP256R1_SHA256));

          CHECK_EQ (gq_privkey_sign (priv, sc, message, sizeof message, sig,
                                     sizeof sig, &n), GQ_OK);
          CHECK_EQ (n, sets[i].size);
          /* The key in the certificate is the one of the private key.  */
          CHECK_EQ (gq_pubkey_verify (pub, sc, message, sizeof message, sig, n),
                    GQ_OK);

          /* Changes of the message and the signature, a short or long one.  */
          CHECK_EQ (gq_pubkey_verify (pub, sc, message, sizeof message - 1, sig,
                                      n), GQ_ERR_CRYPTO);
          memcpy (bad, sig, n);
          bad[n / 3] ^= 0x10;
          CHECK_EQ (gq_pubkey_verify (pub, sc, message, sizeof message, bad, n),
                    GQ_ERR_CRYPTO);
          CHECK_EQ (gq_pubkey_verify (pub, sc, message, sizeof message, sig,
                                      n - 1), GQ_ERR_CRYPTO);
          CHECK_EQ (gq_pubkey_verify (pub, sc, message, sizeof message, sig,
                                      n + 1), GQ_ERR_CRYPTO);

          /* Other schemes are refused by key and by signature (a key of
             one set does not verify under the scheme of another).  */
          for (k_ = 0; k_ < 3; k_++)
            if (schemes3[k_] != sc)
              {
                CHECK_EQ (gq_privkey_sign (priv, schemes3[k_], message,
                                           sizeof message, bad, sizeof bad,
                                           &n), GQ_ERR_CRYPTO);
                CHECK_EQ (gq_pubkey_verify (pub, schemes3[k_], message,
                                            sizeof message, sig,
                                            sets[i].size), GQ_ERR_CRYPTO);
              }
          CHECK_EQ (gq_privkey_sign (priv, GQ_SIG_ED25519, message,
                                     sizeof message, bad, sizeof bad, &n),
                    GQ_ERR_CRYPTO);

          /* A buffer too small for it.  */
          CHECK_EQ (gq_privkey_sign (priv, sc, message, sizeof message, bad,
                                     sets[i].size - 1, &n), GQ_ERR_BUFSIZE);
          gq_privkey_free (priv);
        }

      /* A classical scheme cannot be verified with this key either.  */
      CHECK_EQ (gq_pubkey_verify (pub, GQ_SIG_ED25519, message, sizeof message,
                                  sig, 64), GQ_ERR_CRYPTO);
      gq_pubkey_free (pub);
    }

  /* A key whose seed does not make its expanded key is refused (RFC 9881
     section 8.2), and so is damage to one that is ML-DSA.  */
  {
    gq_privkey *priv = NULL;

    tst_cat_parts ((const char *const[]) { RFC9881_MLDSA44_INCONSISTENT_BOTH_PEM },
                   pem, sizeof pem);
    CHECK_EQ (gq_privkey_from_pem (&priv, pem, strlen (pem)), GQ_ERR_CERT);
    CHECK (priv == NULL);
    tst_cat_parts ((const char *const[]) { RFC9881_MLDSA65_SEED_PEM }, pem,
                   sizeof pem);
    pem[100] = (pem[100] == 'A') ? 'B' : 'A';
    /* (whatever that does to it, it is not a key that loads and signs
       as the original does)  */
    if (gq_privkey_from_pem (&priv, pem, strlen (pem)) == GQ_OK)
      {
        gq_pubkey *pub = NULL;

        tst_cat_parts ((const char *const[]) { RFC9881_MLDSA65_CERT_PEM }, pem,
                       sizeof pem);
        dl = tst_pem_der (pem, der, sizeof der);
        CHECK_EQ (gq_pubkey_from_cert (&pub, der, dl), GQ_OK);
        CHECK_EQ (gq_privkey_sign (priv, GQ_SIG_MLDSA65, message,
                                   sizeof message, sig, sizeof sig, &n),
                  GQ_OK);
        CHECK_EQ (gq_pubkey_verify (pub, GQ_SIG_MLDSA65, message,
                                    sizeof message, sig, n), GQ_ERR_CRYPTO);
        gq_pubkey_free (pub);
        gq_privkey_free (priv);
      }
  }

  /* With libgcrypt turned off, a certificate of ML-DSA is still read (and
     is still the same key) but a key cannot be loaded or used without a
     GnuTLS backend.  */
  gqi_mldsa_enable (0);
  CHECK_EQ (gq_sigscheme_available (GQ_SIG_MLDSA65), tst_gnutls_mldsa ());
  {
    gq_privkey *priv = NULL;

    tst_cat_parts ((const char *const[]) { RFC9881_MLDSA65_SEED_PEM }, pem,
                   sizeof pem);
    if (!tst_gnutls_mldsa ())
      CHECK_EQ (gq_privkey_from_pem (&priv, pem, strlen (pem)), GQ_ERR_CERT);
  }
  gqi_mldsa_enable (1);
}

int
main (void)
{
  static const unsigned p256[] = { GQ_SIG_ECDSA_SECP256R1_SHA256 };
  static const unsigned p384[] = { GQ_SIG_ECDSA_SECP384R1_SHA384 };
  static const unsigned ed[] = { GQ_SIG_ED25519 };
  static const unsigned rsa[] = { GQ_SIG_RSA_PSS_RSAE_SHA256,
                                  GQ_SIG_RSA_PSS_RSAE_SHA384,
                                  GQ_SIG_RSA_PSS_RSAE_SHA512,
                                  GQ_SIG_RSA_PKCS1_SHA256,
                                  GQ_SIG_RSA_PKCS1_SHA384,
                                  GQ_SIG_RSA_PKCS1_SHA512 };

  test_key (TST_ECDSA256, p256, 1);
  test_key (TST_ECDSA384, p384, 1);
  test_key (TST_ED25519, ed, 1);
  test_key (TST_RSA2048, rsa, 6);
  test_policy_and_errors ();
  test_weak_rsa ();
  test_mldsa_size ();
  test_mldsa_gnutls ();
  test_mldsa_libgcrypt ();
  TST_DONE ();
}

#endif
