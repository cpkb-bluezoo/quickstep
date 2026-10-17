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
#include <quickstep/trust.h>

#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  gq_trust *t;

  CHECK_EQ (gq_trust_new (&t), GQ_ERR_UNAVAILABLE);
  TST_DONE ();
}

#else

#include "tst-x509.h"

static int
make_cert (struct tst_cert *out, const char *cn, const char *san,
           const struct tst_cert *issuer, long nb, long na,
           gnutls_digest_algorithm_t dig)
{
  return tst_make_cert (out, TST_ECDSA256, cn, san, issuer, nb, na, dig);
}

static gq_slice
der (const struct tst_cert *c, gnutls_datum_t *d)
{
  gq_slice s;

  gnutls_x509_crt_export2 (c->crt, GNUTLS_X509_FMT_DER, d);
  s.data = d->data;
  s.len = d->size;
  return s;
}

static gq_trust *
trust_for (const struct tst_cert *ca)
{
  gnutls_datum_t pem;
  gq_trust *t = NULL;

  CHECK_EQ (gq_trust_new (&t), GQ_OK);
  if (ca)
    {
      gnutls_x509_crt_export2 (ca->crt, GNUTLS_X509_FMT_PEM, &pem);
      CHECK_EQ (gq_trust_add_pem (t, pem.data, pem.size), GQ_OK);
      gnutls_free (pem.data);
    }
  return t;
}

static int
verify (gq_trust *t, const struct tst_cert *leaf, const char *host,
        enum gq_cert_error *why)
{
  gnutls_datum_t d;
  gq_slice s = der (leaf, &d);
  int r = gq_trust_verify_chain (t, &s, 1, host, why);

  gnutls_free (d.data);
  return r;
}

#if TST_HAVE_MLDSA

/* Verify the chain of CERTS (leaf first) against T for example.test.  */
static int
verify_chain (gq_trust *t, const struct tst_cert *const *certs, size_t n,
              const char *host, enum gq_cert_error *why)
{
  gnutls_datum_t d[4];
  gq_slice s[4];
  size_t i;
  int r;

  for (i = 0; i < n; i++)
    s[i] = der (certs[i], &d[i]);
  r = gq_trust_verify_chain (t, s, n, host, why);
  for (i = 0; i < n; i++)
    gnutls_free (d[i].data);
  return r;
}

/* Chains made of ML-DSA keys (FIPS 204, certificates as in
   draft-ietf-lamps-dilithium-certificates), checked under the same MEDIUM
   profile as any other: a root, an intermediate and a leaf of three
   different parameter sets; a classical CA over an ML-DSA leaf and the
   other way round; and the ways such a chain must fail.  Needs a GnuTLS
   with an ML-DSA backend to make the keys (GQ_EXPECT_MLDSA makes its
   absence a failure).  */
static void
test_mldsa_chains (void)
{
  struct tst_cert root, mid, leaf, other, ec_ca, hy_leaf, ec_leaf, expired;
  const struct tst_cert *chain[2];
  enum gq_cert_error why;
  gq_trust *t, *t_other, *t_ec;
  gnutls_datum_t d;
  gq_slice s;

  if (!tst_mldsa_ready (gq_sigscheme_available (GQ_SIG_MLDSA65),
                        "the ML-DSA chain tests"))
    return;

  CHECK_EQ (tst_make_cert (&root, TST_MLDSA65, "ML-DSA root", NULL, NULL,
                           -3600, 86400, GNUTLS_DIG_UNKNOWN), 0);
  CHECK_EQ (tst_make_cert (&mid, TST_MLDSA87, "ML-DSA intermediate", NULL,
                           &root, -3600, 86400, GNUTLS_DIG_UNKNOWN), 0);
  CHECK_EQ (tst_make_cert (&leaf, TST_MLDSA44, "example.test", "example.test",
                           &mid, -3600, 86400, GNUTLS_DIG_UNKNOWN), 0);
  CHECK_EQ (tst_make_cert (&other, TST_MLDSA65, "Other ML-DSA root", NULL,
                           NULL, -3600, 86400, GNUTLS_DIG_UNKNOWN), 0);
  CHECK_EQ (make_cert (&ec_ca, "EC CA", NULL, NULL, -3600, 86400,
                       GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&hy_leaf, TST_MLDSA65, "example.test",
                           "example.test", &ec_ca, -3600, 86400,
                           GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&ec_leaf, TST_ECDSA256, "example.test",
                           "example.test", &root, -3600, 86400,
                           GNUTLS_DIG_UNKNOWN), 0);
  CHECK_EQ (tst_make_cert (&expired, TST_MLDSA44, "example.test",
                           "example.test", &mid, -7200, -3600,
                           GNUTLS_DIG_UNKNOWN), 0);

  t = trust_for (&root);
  t_other = trust_for (&other);
  t_ec = trust_for (&ec_ca);

  /* Root, intermediate, leaf: all ML-DSA, all accepted by the profile.  */
  chain[0] = &leaf;
  chain[1] = &mid;
  CHECK_EQ (verify_chain (t, chain, 2, "example.test", &why), GQ_OK);
  CHECK_EQ (why, GQ_CERT_OK);
  CHECK_EQ (verify_chain (t, chain, 2, NULL, &why), GQ_OK);
  CHECK_EQ (verify_chain (t, chain, 2, "other.test", &why), GQ_ERR_CERT);
  CHECK_EQ (why, GQ_CERT_HOSTNAME);

  /* No intermediate, so no path; another root, so no anchor.  */
  CHECK_EQ (verify_chain (t, chain, 1, "example.test", &why), GQ_ERR_CERT);
  CHECK_EQ (why, GQ_CERT_UNTRUSTED);
  CHECK_EQ (verify_chain (t_other, chain, 2, "example.test", &why),
            GQ_ERR_CERT);
  CHECK_EQ (why, GQ_CERT_UNTRUSTED);

  /* The time checks apply as to any chain.  */
  chain[0] = &expired;
  CHECK_EQ (verify_chain (t, chain, 2, "example.test", &why), GQ_ERR_CERT);
  CHECK_EQ (why, GQ_CERT_EXPIRED);

  /* A signature with one bit changed does not verify: the last byte of
     the certificate is the last byte of the issuer's signature.  */
  s = der (&leaf, &d);
  {
    uint8_t *bad = malloc (s.len);
    gnutls_datum_t dm;
    gq_slice cs[2];

    memcpy (bad, s.data, s.len);
    bad[s.len - 1] ^= 1;
    cs[0] = (gq_slice) { bad, s.len };
    cs[1] = der (&mid, &dm);
    CHECK_EQ (gq_trust_verify_chain (t, cs, 2, "example.test", &why),
              GQ_ERR_CERT);
    CHECK (why != GQ_CERT_OK);
    gnutls_free (dm.data);
    free (bad);
  }
  gnutls_free (d.data);

  /* A classical CA over an ML-DSA leaf, and an ML-DSA root over a
     classical leaf.  */
  chain[0] = &hy_leaf;
  CHECK_EQ (verify_chain (t_ec, chain, 1, "example.test", &why), GQ_OK);
  CHECK_EQ (verify_chain (t, chain, 1, "example.test", &why), GQ_ERR_CERT);
  chain[0] = &ec_leaf;
  CHECK_EQ (verify_chain (t, chain, 1, "example.test", &why), GQ_OK);
  CHECK_EQ (verify_chain (t_ec, chain, 1, "example.test", &why), GQ_ERR_CERT);

  gq_trust_free (t);
  gq_trust_free (t_other);
  gq_trust_free (t_ec);
  tst_free_cert (&root);
  tst_free_cert (&mid);
  tst_free_cert (&leaf);
  tst_free_cert (&other);
  tst_free_cert (&ec_ca);
  tst_free_cert (&hy_leaf);
  tst_free_cert (&ec_leaf);
  tst_free_cert (&expired);
}

#else

static void
test_mldsa_chains (void)
{
  tst_mldsa_ready (0, "the ML-DSA chain tests");
}

#endif

int
main (void)
{
  struct tst_cert ca, leaf, expired, sha1leaf;
  gq_trust *t, *empty;
  enum gq_cert_error why;
  gq_slice junk = { (const uint8_t *) "not a certificate", 17 };
  int r;

  CHECK_EQ (make_cert (&ca, "Test CA", NULL, NULL, -3600, 86400,
                       GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (make_cert (&leaf, "example.test", "example.test", &ca, -3600,
                       86400, GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (make_cert (&expired, "example.test", "example.test", &ca, -7200,
                       -3600, GNUTLS_DIG_SHA256), 0);

  t = trust_for (&ca);
  empty = trust_for (NULL);

  CHECK_EQ (verify (t, &leaf, "example.test", &why), GQ_OK);
  CHECK_EQ (why, GQ_CERT_OK);
  CHECK_EQ (verify (t, &leaf, NULL, &why), GQ_OK);

  CHECK_EQ (verify (t, &leaf, "other.test", &why), GQ_ERR_CERT);
  CHECK_EQ (why, GQ_CERT_HOSTNAME);

  CHECK_EQ (verify (empty, &leaf, "example.test", &why), GQ_ERR_CERT);
  CHECK_EQ (why, GQ_CERT_UNTRUSTED);

  CHECK_EQ (verify (t, &expired, "example.test", &why), GQ_ERR_CERT);
  CHECK_EQ (why, GQ_CERT_EXPIRED);

  CHECK_EQ (gq_trust_verify_chain (t, &junk, 1, NULL, &why), GQ_ERR_CERT);
  CHECK_EQ (why, GQ_CERT_MALFORMED);

  CHECK_EQ (gq_trust_verify_chain (t, NULL, 0, NULL, &why), GQ_ERR_INVAL);

  /* SHA-1 signatures must be refused.  Some GnuTLS builds refuse to even
     create one; then there is nothing to test.  */
  r = make_cert (&sha1leaf, "example.test", "example.test", &ca, -3600,
                 86400, GNUTLS_DIG_SHA1);
  if (r == 0)
    {
      CHECK_EQ (verify (t, &sha1leaf, "example.test", &why), GQ_ERR_CERT);
      CHECK_EQ (why, GQ_CERT_WEAK_ALGORITHM);
      tst_free_cert (&sha1leaf);
    }
  else
    fprintf (stderr, "note: cannot sign with SHA-1 here; skipped\n");

  /* RSA below 2048 bits is refused even with a modern signature hash.  */
  {
    struct tst_cert weak;

    if (tst_make_cert (&weak, TST_RSA1024, "example.test", "example.test",
                       &ca, -3600, 86400, GNUTLS_DIG_SHA256) == 0)
      {
        CHECK_EQ (verify (t, &weak, "example.test", &why), GQ_ERR_CERT);
        CHECK_EQ (why, GQ_CERT_WEAK_ALGORITHM);
        tst_free_cert (&weak);
      }
    else
      fprintf (stderr, "note: cannot generate RSA-1024 here; skipped\n");
  }

  test_mldsa_chains ();

  gq_trust_free (t);
  gq_trust_free (empty);
  tst_free_cert (&ca);
  tst_free_cert (&leaf);
  tst_free_cert (&expired);
  TST_DONE ();
}

#endif
