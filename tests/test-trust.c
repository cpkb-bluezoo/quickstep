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
#include "tst-mldsa-cert.h"

static int
make_cert (struct tst_cert *out, const char *cn, const char *san,
           const struct tst_cert *issuer, long nb, long na,
           gnutls_digest_algorithm_t dig)
{
  return tst_make_cert (out, TST_ECDSA256, cn, san, issuer, nb, na, dig);
}

/* Leaf with an explicit keyUsage (serverAuth EKU still present).  */
static int
make_server_leaf_ku (struct tst_cert *out, const char *san,
                     const struct tst_cert *issuer, unsigned ku_bits)
{
  time_t now = time (NULL);
  unsigned char serial[4] = { 7, 7, 7, 7 };
  int r;

  gnutls_x509_privkey_init (&out->key);
  r = gnutls_x509_privkey_generate (out->key, GNUTLS_PK_ECDSA,
                                    GNUTLS_CURVE_TO_BITS
                                    (GNUTLS_ECC_CURVE_SECP256R1), 0);
  if (r < 0)
    return r;
  gnutls_x509_crt_init (&out->crt);
  gnutls_x509_crt_set_version (out->crt, 3);
  gnutls_x509_crt_set_key (out->crt, out->key);
  gnutls_x509_crt_set_serial (out->crt, serial, sizeof serial);
  gnutls_x509_crt_set_activation_time (out->crt, now - 3600);
  gnutls_x509_crt_set_expiration_time (out->crt, now + 86400);
  gnutls_x509_crt_set_dn_by_oid (out->crt, GNUTLS_OID_X520_COMMON_NAME, 0, san,
                                 (unsigned) strlen (san));
  gnutls_x509_crt_set_subject_alt_name (out->crt, GNUTLS_SAN_DNSNAME, san,
                                        (unsigned) strlen (san),
                                        GNUTLS_FSAN_SET);
  gnutls_x509_crt_set_key_purpose_oid (out->crt, GNUTLS_KP_TLS_WWW_SERVER, 0);
  r = gnutls_x509_crt_set_key_usage (out->crt, ku_bits);
  if (r < 0)
    return r;
  return gnutls_x509_crt_sign2 (out->crt, issuer->crt, issuer->key,
                                GNUTLS_DIG_SHA256, 0);
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


/* A classical CA over an ML-DSA leaf is a chain a GnuTLS that knows the key
   algorithm validates whatever backend it has (it checks the CA's signature,
   and has no need of the leaf's key): the one an application is likely to
   meet first.  An older GnuTLS (Ubuntu 24.04's) refuses it as a weak
   algorithm, and the test skips there.  The leaves are made without GnuTLS's
   help (tst-mldsa-cert.h).  */
static void
test_mldsa_hybrid_chains (void)
{
  static const unsigned schemes[] = { GQ_SIG_MLDSA44, GQ_SIG_MLDSA65,
                                      GQ_SIG_MLDSA87 };
  struct tst_cert ca, other_ca;
  static struct tst_mlident leaf, expired, client;
  gq_trust *t, *t_other, *empty;
  enum gq_cert_error why;
  size_t i;

  if (!tst_mldsa_ready (tst_gnutls_validates_mldsa (),
                        "the ML-DSA hybrid chain tests"))
    return;
  CHECK_EQ (make_cert (&ca, "Test CA", NULL, NULL, -3600, 86400,
                       GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (make_cert (&other_ca, "Other CA", NULL, NULL, -3600, 86400,
                       GNUTLS_DIG_SHA256), 0);
  t = trust_for (&ca);
  t_other = trust_for (&other_ca);
  empty = trust_for (NULL);

  for (i = 0; i < 3; i++)
    {
      gq_slice c[1];
      uint8_t bad[8192];

      CHECK_EQ (tst_make_mldsa_cert (&leaf, schemes[i], "example.test",
                                     "example.test", 0, &ca, -3600, 86400), 0);
      CHECK_EQ (tst_make_mldsa_cert (&expired, schemes[i], "example.test",
                                     "example.test", 0, &ca, -7200, -3600), 0);
      CHECK_EQ (tst_make_mldsa_cert (&client, schemes[i], "client.test",
                                     "client.test", 1, &ca, -3600, 86400), 0);
      c[0] = leaf.chain[0];

      /* Accepted, with and without a host name, under the MEDIUM profile.  */
      CHECK_EQ (gq_trust_verify_chain (t, c, 1, "example.test", &why), GQ_OK);
      CHECK_EQ (why, GQ_CERT_OK);
      CHECK_EQ (gq_trust_verify_chain (t, c, 1, NULL, &why), GQ_OK);

      /* ...and refused as any chain is.  */
      CHECK_EQ (gq_trust_verify_chain (t, c, 1, "other.test", &why),
                GQ_ERR_CERT);
      CHECK_EQ (why, GQ_CERT_HOSTNAME);
      CHECK_EQ (gq_trust_verify_chain (t_other, c, 1, "example.test", &why),
                GQ_ERR_CERT);
      CHECK_EQ (why, GQ_CERT_UNTRUSTED);
      CHECK_EQ (gq_trust_verify_chain (empty, c, 1, "example.test", &why),
                GQ_ERR_CERT);
      CHECK_EQ (why, GQ_CERT_UNTRUSTED);
      c[0] = expired.chain[0];
      CHECK_EQ (gq_trust_verify_chain (t, c, 1, "example.test", &why),
                GQ_ERR_CERT);
      CHECK_EQ (why, GQ_CERT_EXPIRED);

      /* The certificate's own signature (the CA's), changed in one bit.  */
      memcpy (bad, leaf.cert, leaf.cert_len);
      bad[leaf.cert_len - 1] ^= 1;
      c[0] = (gq_slice) { bad, leaf.cert_len };
      CHECK_EQ (gq_trust_verify_chain (t, c, 1, "example.test", &why),
                GQ_ERR_CERT);
      CHECK (why != GQ_CERT_OK);

      /* The purpose: a client certificate serves a client, and a server
         certificate a server.  */
      c[0] = client.chain[0];
      CHECK_EQ (gq_trust_verify_chain_for (t, c, 1, NULL, GQ_PURPOSE_CLIENT,
                                           &why), GQ_OK);
      CHECK_EQ (gq_trust_verify_chain_for (t, c, 1, "client.test",
                                           GQ_PURPOSE_SERVER, &why),
                GQ_ERR_CERT);

      tst_free_mldsa_cert (&leaf);
      tst_free_mldsa_cert (&expired);
      tst_free_mldsa_cert (&client);
    }

  gq_trust_free (t);
  gq_trust_free (t_other);
  gq_trust_free (empty);
  tst_free_cert (&ca);
  tst_free_cert (&other_ca);
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

/* Chains made of ML-DSA keys (FIPS 204, certificates as in RFC 9881),
   checked under the same MEDIUM profile as any other: a root, an intermediate and a leaf of three
   different parameter sets; a classical CA over an ML-DSA leaf and the
   other way round; and the ways such a chain must fail.  Needs a GnuTLS
   with an ML-DSA backend, to make the keys and to check the signatures of
   ML-DSA (GQ_EXPECT_MLDSA makes its absence a failure).  */
static void
test_mldsa_chains (void)
{
  struct tst_cert root, mid, leaf, other, ec_ca, hy_leaf, ec_leaf, expired;
  const struct tst_cert *chain[2];
  enum gq_cert_error why;
  gq_trust *t, *t_other, *t_ec;
  gnutls_datum_t d;
  gq_slice s;

  if (!tst_mldsa_ready (tst_gnutls_mldsa (), "the ML-DSA chain tests"))
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

/* A leaf with a subject common name and no subjectAltName at all.  */
static int
make_cn_only (struct tst_cert *out, const char *cn, const struct tst_cert *ca)
{
  unsigned char serial[4] = { 9, 8, 7, 6 };
  time_t now = time (NULL);

  gnutls_x509_privkey_init (&out->key);
  if (gnutls_x509_privkey_generate (out->key, GNUTLS_PK_ECDSA,
                                    GNUTLS_CURVE_TO_BITS
                                    (GNUTLS_ECC_CURVE_SECP256R1), 0) < 0)
    return -1;
  gnutls_x509_crt_init (&out->crt);
  gnutls_x509_crt_set_version (out->crt, 3);
  gnutls_x509_crt_set_key (out->crt, out->key);
  gnutls_x509_crt_set_serial (out->crt, serial, sizeof serial);
  gnutls_x509_crt_set_activation_time (out->crt, now - 3600);
  gnutls_x509_crt_set_expiration_time (out->crt, now + 86400);
  gnutls_x509_crt_set_dn_by_oid (out->crt, GNUTLS_OID_X520_COMMON_NAME, 0, cn,
                                 (unsigned) strlen (cn));
  gnutls_x509_crt_set_key_purpose_oid (out->crt, GNUTLS_KP_TLS_WWW_SERVER, 0);
  return gnutls_x509_crt_sign2 (out->crt, ca->crt, ca->key, GNUTLS_DIG_SHA256,
                                0);
}

/* Which names a certificate stands for, and which certificates may stand
   between it and the anchor.  */
static void
test_names_and_paths (void)
{
  struct tst_cert ca, wild, plain, cnonly, midok, midbad, under_ok, under_bad;
  gq_trust *t;
  enum gq_cert_error why;
  gnutls_datum_t d[3];
  gq_slice chain[3];

  CHECK_EQ (make_cert (&ca, "Test CA", NULL, NULL, -3600, 86400,
                       GNUTLS_DIG_SHA256), 0);
  t = trust_for (&ca);

  /* A wildcard covers one label, and not the domain itself.  */
  CHECK_EQ (make_cert (&wild, "w", "*.example.test", &ca, -3600, 86400,
                       GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (verify (t, &wild, "a.example.test", &why), GQ_OK);
  CHECK_EQ (verify (t, &wild, "a.b.example.test", &why), GQ_ERR_CERT);
  CHECK_EQ (why, GQ_CERT_HOSTNAME);
  CHECK_EQ (verify (t, &wild, "example.test", &why), GQ_ERR_CERT);
  CHECK_EQ (verify (t, &wild, "a.example.other", &why), GQ_ERR_CERT);
  CHECK_EQ (verify (t, &wild, "", &why) == GQ_OK, 0);

  /* A DNS name is not an address, and an address is not a DNS name.  */
  CHECK_EQ (make_cert (&plain, "p", "example.test", &ca, -3600, 86400,
                       GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (verify (t, &plain, "192.0.2.1", &why), GQ_ERR_CERT);
  CHECK_EQ (verify (t, &plain, "example.test.evil.test", &why), GQ_ERR_CERT);
  CHECK_EQ (verify (t, &plain, "xexample.test", &why), GQ_ERR_CERT);

  /* No subjectAltName: GnuTLS falls back to the common name, which RFC 9525
     does not do.  trust.h says so; this pins what is said.  */
  CHECK_EQ (make_cn_only (&cnonly, "cn-only.test", &ca), 0);
  CHECK_EQ (verify (t, &cnonly, "cn-only.test", &why), GQ_OK);
  CHECK_EQ (verify (t, &cnonly, "other.test", &why), GQ_ERR_CERT);

  /* An intermediate must be a CA: a CA one passes, an end-entity
     certificate that signed another does not.  */
  CHECK_EQ (make_cert (&midok, "mid-ca", NULL, &ca, -3600, 86400,
                       GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (make_cert (&midbad, "mid-leaf", "mid.test", &ca, -3600, 86400,
                       GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (make_cert (&under_ok, "u1", "under.test", &midok, -3600, 86400,
                       GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (make_cert (&under_bad, "u2", "under.test", &midbad, -3600, 86400,
                       GNUTLS_DIG_SHA256), 0);
  chain[0] = der (&under_ok, &d[0]);
  chain[1] = der (&midok, &d[1]);
  CHECK_EQ (gq_trust_verify_chain (t, chain, 2, "under.test", &why), GQ_OK);
  gnutls_free (d[0].data);
  gnutls_free (d[1].data);
  chain[0] = der (&under_bad, &d[0]);
  chain[1] = der (&midbad, &d[1]);
  CHECK_EQ (gq_trust_verify_chain (t, chain, 2, "under.test", &why),
            GQ_ERR_CERT);
  gnutls_free (d[0].data);
  gnutls_free (d[1].data);
  tst_free_cert (&midok);
  tst_free_cert (&midbad);
  tst_free_cert (&under_ok);
  tst_free_cert (&under_bad);
  tst_free_cert (&wild);
  tst_free_cert (&plain);
  tst_free_cert (&cnonly);

  /* A chain of 40 is refused, however well formed, without anything
     running out.  */
  {
    enum { N = 40 };
    static struct tst_cert c[N + 1];
    static gnutls_datum_t dd[N + 1];
    static gq_slice ch[N + 1];
    int i;

    for (i = 0; i <= N; i++)
      CHECK_EQ (make_cert (&c[i], "link", i < N ? NULL : "deep.test",
                           i ? &c[i - 1] : &ca, -3600, 86400,
                           GNUTLS_DIG_SHA256), 0);
    /* Leaf first.  */
    for (i = 0; i <= N; i++)
      ch[i] = der (&c[N - i], &dd[i]);
    CHECK (gq_trust_verify_chain (t, ch, N + 1, "deep.test", &why) != GQ_OK);
    CHECK (gq_trust_verify_chain (t, ch, 3, "deep.test", &why) != GQ_OK);
    for (i = 0; i <= N; i++)
      {
        gnutls_free (dd[i].data);
        tst_free_cert (&c[i]);
      }
  }
  gq_trust_free (t);
  tst_free_cert (&ca);
}

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

  {
    struct tst_cert ku_leaf;

    CHECK_EQ (make_server_leaf_ku (&ku_leaf, "example.test", &ca,
                                  GNUTLS_KEY_KEY_CERT_SIGN), 0);
    CHECK_EQ (verify (t, &ku_leaf, "example.test", &why), GQ_ERR_CERT);
    CHECK_EQ (why, GQ_CERT_OTHER);
    tst_free_cert (&ku_leaf);
  }

  test_mldsa_hybrid_chains ();
  test_mldsa_chains ();
  test_names_and_paths ();

  gq_trust_free (t);
  gq_trust_free (empty);
  tst_free_cert (&ca);
  tst_free_cert (&leaf);
  tst_free_cert (&expired);
  TST_DONE ();
}

#endif
