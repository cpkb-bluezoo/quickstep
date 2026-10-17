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

/* ML-DSA server and client certificates for the tests, made without a GnuTLS
   that can do ML-DSA (most cannot): the key comes from libgcrypt through the
   library's own ML-DSA module, and the certificate is assembled here as DER
   (RFC 9881 SubjectPublicKeyInfo, RFC 5280 TBSCertificate) and signed by a
   classical CA that GnuTLS does handle.  A chain of that kind, a classical CA
   over an ML-DSA leaf, is what GnuTLS validates whatever backend it has.

   The tests that include this are linked with the library's internals
   (tests/Makefile.am), for src/mldsa.h.  */

#ifndef GQ_TST_MLDSA_CERT_H
#define GQ_TST_MLDSA_CERT_H

#include <time.h>

#include <quickstep/crypto.h>
#include <quickstep/sign.h>
#include <quickstep/tls.h>
#include <quickstep/trust.h>

#include "../src/mldsa.h"
#include "tst-x509.h"

struct tst_mlident
{
  unsigned scheme;
  uint8_t cert[8192];		/* ML-DSA-87's key alone is 2592 bytes.  */
  size_t cert_len;
  gq_slice chain[1];
  gq_privkey *key;
  uint8_t seed[GQI_MLDSA_SEED_LEN];
};

/* A growing DER buffer.  */
struct tst_der
{
  uint8_t b[8192];
  size_t n;
};

static inline void
tst_der_put (struct tst_der *d, const void *p, size_t n)
{
  memcpy (d->b + d->n, p, n);
  d->n += n;
}

/* Header of a TLV of LEN contents bytes.  */
static inline void
tst_der_hdr (struct tst_der *d, unsigned tag, size_t len)
{
  d->b[d->n++] = (uint8_t) tag;
  if (len < 0x80)
    d->b[d->n++] = (uint8_t) len;
  else if (len < 0x100)
    {
      d->b[d->n++] = 0x81;
      d->b[d->n++] = (uint8_t) len;
    }
  else
    {
      d->b[d->n++] = 0x82;
      d->b[d->n++] = (uint8_t) (len >> 8);
      d->b[d->n++] = (uint8_t) len;
    }
}

/* Append TAG with the contents of INNER.  */
static inline void
tst_der_wrap (struct tst_der *d, unsigned tag, const struct tst_der *inner)
{
  tst_der_hdr (d, tag, inner->n);
  tst_der_put (d, inner->b, inner->n);
}

static inline void
tst_der_utctime (struct tst_der *d, time_t t)
{
  char s[32];
  struct tm tm;

  gmtime_r (&t, &tm);
  snprintf (s, sizeof s, "%02d%02d%02d%02d%02d%02dZ", (tm.tm_year + 1900) % 100,
            tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
  tst_der_hdr (d, 0x17, 13);
  tst_der_put (d, s, 13);
}

/* Base64 with the line breaks of a PEM body.  */
static inline void
tst_b64 (const uint8_t *in, size_t n, char *out)
{
  static const char tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i, o = 0, col = 0;

  for (i = 0; i < n; i += 3)
    {
      uint32_t v = (uint32_t) in[i] << 16;
      int k = 2;

      if (i + 1 < n)
        v |= (uint32_t) in[i + 1] << 8, k++;
      if (i + 2 < n)
        v |= in[i + 2], k++;
      out[o++] = tab[(v >> 18) & 63];
      out[o++] = tab[(v >> 12) & 63];
      out[o++] = k > 2 ? tab[(v >> 6) & 63] : '=';
      out[o++] = k > 3 ? tab[v & 63] : '=';
      col += 4;
      if (col == 64)
        {
          out[o++] = '\n';
          col = 0;
        }
    }
  if (col)
    out[o++] = '\n';
  out[o] = 0;
}

/* The PKCS#8 PEM of an ML-DSA seed key (RFC 9881: the seed form).  */
static inline void
tst_mldsa_seed_pem (unsigned scheme, const uint8_t seed[GQI_MLDSA_SEED_LEN],
                    char *pem, size_t cap)
{
  uint8_t der[64] = {
    0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x03, 0x00, 0x04, 0x22, 0x80, 0x20
  };
  char body[128];

  der[17] = (uint8_t) (scheme == GQ_SIG_MLDSA44 ? 17
                       : scheme == GQ_SIG_MLDSA65 ? 18 : 19);
  memcpy (der + 22, seed, GQI_MLDSA_SEED_LEN);
  tst_b64 (der, 22 + GQI_MLDSA_SEED_LEN, body);
  snprintf (pem, cap, "-----BEGIN PRIVATE KEY-----\n%s-----END PRIVATE KEY-----\n",
            body);
}

/* A certificate for a new ML-DSA key of SCHEME, with the name CN and the
   subjectAltName SAN (a server certificate, or for a client if CLIENT),
   issued by the classical (ECDSA) CA, valid from NOT_BEFORE to NOT_AFTER
   seconds from now.  Returns 0, or a nonzero value on failure.  */
static inline int
tst_make_mldsa_cert (struct tst_mlident *id, unsigned scheme, const char *cn,
                     const char *san, int client, const struct tst_cert *ca,
                     long not_before, long not_after)
{
  static const uint8_t ecdsa_sha256[] = {
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
  };
  static const uint8_t oid_ml[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                                    0x03, 0x04, 0x03 };
  static const uint8_t cn_oid[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
  static const uint8_t eku_server[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
                                        0x05, 0x07, 0x03, 0x01 };
  static const uint8_t eku_client[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
                                        0x05, 0x07, 0x03, 0x02 };
  struct tst_der tbs, t1, t2, t3, spki, ext, cert;
  uint8_t pk[GQI_MLDSA_PK_MAX], sk[GQI_MLDSA_SK_MAX], serial[4], sig[160];
  gnutls_datum_t dn, data;
  size_t siglen = sizeof sig;
  time_t now = time (NULL);
  char pem[256];
  size_t pklen = gqi_mldsa_pk_len (scheme);
  int r;

  memset (id, 0, sizeof *id);
  id->scheme = scheme;
  if (pklen == 0)
    return -1;
  gq_random (id->seed, sizeof id->seed);
  if (gqi_mldsa_keygen (scheme, id->seed, pk, sk) != GQ_OK)
    return -1;
  gq_random (serial, sizeof serial);
  serial[0] = (uint8_t) ((serial[0] & 0x3f) | 0x01);

  /* subjectPublicKeyInfo: { { OID }, BIT STRING { 0, key } }.  */
  t1.n = 0;
  tst_der_put (&t1, oid_ml, sizeof oid_ml);
  t1.b[t1.n++] = (uint8_t) (scheme == GQ_SIG_MLDSA44 ? 17
                            : scheme == GQ_SIG_MLDSA65 ? 18 : 19);
  t2.n = 0;
  tst_der_wrap (&t2, 0x30, &t1);		/* AlgorithmIdentifier.  */
  t3.n = 0;
  t3.b[t3.n++] = 0x00;				/* No unused bits.  */
  tst_der_put (&t3, pk, pklen);
  tst_der_wrap (&t2, 0x03, &t3);
  spki.n = 0;
  tst_der_wrap (&spki, 0x30, &t2);

  /* extensions: subjectAltName, keyUsage (digitalSignature), extKeyUsage.  */
  ext.n = 0;
  {
    struct tst_der e, v, s;
    static const uint8_t san_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x11 };
    static const uint8_t ku_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x0f };
    static const uint8_t eku_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x25 };
    static const uint8_t critical[] = { 0x01, 0x01, 0xff };
    static const uint8_t ku[] = { 0x03, 0x02, 0x07, 0x80 };

    if (san)
      {
        s.n = 0;
        tst_der_hdr (&s, 0x82, strlen (san));		/* dNSName.  */
        tst_der_put (&s, san, strlen (san));
        v.n = 0;
        tst_der_wrap (&v, 0x30, &s);			/* GeneralNames.  */
        e.n = 0;
        tst_der_put (&e, san_oid, sizeof san_oid);
        tst_der_hdr (&e, 0x04, v.n);
        tst_der_put (&e, v.b, v.n);
        tst_der_wrap (&ext, 0x30, &e);
      }
    e.n = 0;
    tst_der_put (&e, ku_oid, sizeof ku_oid);
    tst_der_put (&e, critical, sizeof critical);
    tst_der_hdr (&e, 0x04, sizeof ku);
    tst_der_put (&e, ku, sizeof ku);
    tst_der_wrap (&ext, 0x30, &e);
    s.n = 0;
    if (client)
      tst_der_put (&s, eku_client, sizeof eku_client);
    else
      tst_der_put (&s, eku_server, sizeof eku_server);
    v.n = 0;
    tst_der_wrap (&v, 0x30, &s);
    e.n = 0;
    tst_der_put (&e, eku_oid, sizeof eku_oid);
    tst_der_hdr (&e, 0x04, v.n);
    tst_der_put (&e, v.b, v.n);
    tst_der_wrap (&ext, 0x30, &e);
  }

  /* TBSCertificate.  */
  tbs.n = 0;
  tst_der_put (&tbs, (uint8_t[]) { 0xa0, 0x03, 0x02, 0x01, 0x02 }, 5);
  tst_der_hdr (&tbs, 0x02, sizeof serial);
  tst_der_put (&tbs, serial, sizeof serial);
  tst_der_put (&tbs, ecdsa_sha256, sizeof ecdsa_sha256);
  /* The issuer is the CA's subject.  */
  if (gnutls_x509_crt_get_raw_dn (ca->crt, &dn) < 0)
    return -1;
  tst_der_put (&tbs, dn.data, dn.size);
  gnutls_free (dn.data);
  t1.n = 0;
  tst_der_utctime (&t1, now + not_before);
  tst_der_utctime (&t1, now + not_after);
  tst_der_wrap (&tbs, 0x30, &t1);
  /* subject: the common name.  */
  t1.n = 0;
  tst_der_put (&t1, cn_oid, sizeof cn_oid);
  tst_der_hdr (&t1, 0x0c, strlen (cn));
  tst_der_put (&t1, cn, strlen (cn));
  t2.n = 0;
  tst_der_wrap (&t2, 0x30, &t1);
  t3.n = 0;
  tst_der_wrap (&t3, 0x31, &t2);
  t1.n = 0;
  tst_der_wrap (&t1, 0x30, &t3);
  tst_der_put (&tbs, t1.b, t1.n);
  tst_der_put (&tbs, spki.b, spki.n);
  t1.n = 0;
  tst_der_wrap (&t1, 0x30, &ext);
  tst_der_hdr (&tbs, 0xa3, t1.n);
  tst_der_put (&tbs, t1.b, t1.n);

  /* The CA signs it (the whole TBSCertificate, with its header).  */
  t1.n = 0;
  tst_der_wrap (&t1, 0x30, &tbs);
  data.data = t1.b;
  data.size = (unsigned) t1.n;
  r = gnutls_x509_privkey_sign_data (ca->key, GNUTLS_DIG_SHA256, 0, &data, sig,
                                     &siglen);
  if (r < 0)
    return -1;

  cert.n = 0;
  tst_der_put (&cert, t1.b, t1.n);
  tst_der_put (&cert, ecdsa_sha256, sizeof ecdsa_sha256);
  tst_der_hdr (&cert, 0x03, siglen + 1);
  cert.b[cert.n++] = 0;
  tst_der_put (&cert, sig, siglen);
  t2.n = 0;
  tst_der_wrap (&t2, 0x30, &cert);
  if (t2.n > sizeof id->cert)
    return -1;
  memcpy (id->cert, t2.b, t2.n);
  id->cert_len = t2.n;
  id->chain[0] = (gq_slice) { id->cert, id->cert_len };

  tst_mldsa_seed_pem (scheme, id->seed, pem, sizeof pem);
  if (gq_privkey_from_pem (&id->key, pem, strlen (pem)) != GQ_OK)
    return -1;
  return 0;
}

static inline void
tst_free_mldsa_cert (struct tst_mlident *id)
{
  gq_privkey_free (id->key);
  gq_wipe (id->seed, sizeof id->seed);
  id->key = NULL;
}

/* Does the GnuTLS in use validate a classical CA's certificate for an ML-DSA
   key?  Those that know the key algorithm do, with or without a backend
   (3.8.13 does); an older one (Ubuntu 24.04's 3.8.3) calls it a weak
   algorithm and refuses, so no chain with an ML-DSA key can be validated
   there, whatever the library does.  The tests of that skip, and with
   GQ_EXPECT_MLDSA they fail (tst_mldsa_ready).  */
static inline int
tst_gnutls_validates_mldsa (void)
{
  static int probed = -1;

  if (probed < 0)
    {
      struct tst_cert ca;
      static struct tst_mlident id;
      gnutls_datum_t pem;
      gq_trust *t = NULL;
      gq_slice c[1];

      probed = 0;
      if (tst_make_cert (&ca, TST_ECDSA256, "Probe CA", NULL, NULL, -3600,
                         86400, GNUTLS_DIG_SHA256) == 0)
        {
          if (tst_make_mldsa_cert (&id, GQ_SIG_MLDSA65, "probe", "probe.test",
                                   0, &ca, -3600, 86400) == 0
              && gq_trust_new (&t) == GQ_OK
              && gnutls_x509_crt_export2 (ca.crt, GNUTLS_X509_FMT_PEM,
                                          &pem) >= 0)
            {
              c[0] = id.chain[0];
              if (gq_trust_add_pem (t, pem.data, pem.size) == GQ_OK)
                probed = gq_trust_verify_chain (t, c, 1, "probe.test", NULL)
                  == GQ_OK;
              gnutls_free (pem.data);
            }
          gq_trust_free (t);
          tst_free_mldsa_cert (&id);
          tst_free_cert (&ca);
        }
    }
  return probed;
}

#endif
