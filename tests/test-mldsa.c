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

/* ML-DSA through libgcrypt (src/mldsa.c): the NIST ACVP vectors for key
   generation, signing (with the randomness given, so the signatures are
   compared byte for byte) and verification, the private keys and
   certificates of RFC 9881 appendix C, and what must be refused.  It needs
   no GnuTLS.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <quickstep/status.h>
#include <quickstep/policy.h>
#include <quickstep/crypto.h>
#include <quickstep/sign.h>

#include "mldsa.h"
#include "tst-util.h"
#include "vectors-mldsa.h"

#define P(...) ((const char *const[]) { __VA_ARGS__ })

/* Big enough for the biggest message of a vector (16 KiB) and signature.  */
static uint8_t msg[16384 + 512], ctx[512], sig[GQI_MLDSA_SIG_MAX + 8],
  want_sig[GQI_MLDSA_SIG_MAX + 8], pk[GQI_MLDSA_PK_MAX + 8],
  sk[GQI_MLDSA_SK_MAX + 8], want_pk[GQI_MLDSA_PK_MAX + 8],
  want_sk[GQI_MLDSA_SK_MAX + 8], rnd[32], seed[32];
static char pem[16384];

static const unsigned schemes[] = { GQ_SIG_MLDSA44, GQ_SIG_MLDSA65,
                                    GQ_SIG_MLDSA87 };

static void
test_sizes (void)
{
  CHECK_EQ (gqi_mldsa_pk_len (GQ_SIG_MLDSA44), 1312);
  CHECK_EQ (gqi_mldsa_pk_len (GQ_SIG_MLDSA65), 1952);
  CHECK_EQ (gqi_mldsa_pk_len (GQ_SIG_MLDSA87), 2592);
  CHECK_EQ (gqi_mldsa_sk_len (GQ_SIG_MLDSA44), 2560);
  CHECK_EQ (gqi_mldsa_sk_len (GQ_SIG_MLDSA65), 4032);
  CHECK_EQ (gqi_mldsa_sk_len (GQ_SIG_MLDSA87), 4896);
  CHECK_EQ (gqi_mldsa_sig_len (GQ_SIG_MLDSA44), 2420);
  CHECK_EQ (gqi_mldsa_sig_len (GQ_SIG_MLDSA65), 3309);
  CHECK_EQ (gqi_mldsa_sig_len (GQ_SIG_MLDSA87), 4627);
  CHECK_EQ (gqi_mldsa_pk_len (GQ_SIG_ED25519), 0);
  CHECK_EQ (gqi_mldsa_sig_len (0), 0);
  CHECK (GQI_MLDSA_SIG_MAX <= GQ_SIGNATURE_MAX);
}

/* ---- Known answers ---- */

/* Key generation from the seed gives the vector's keys.  */
static void
kat_keygen (unsigned scheme, const char *const *seed_hex,
            const char *const *pk_hex, const char *const *sk_hex)
{
  CHECK_EQ (tst_unhex_parts (seed_hex, seed, sizeof seed), 32);
  CHECK_EQ (tst_unhex_parts (pk_hex, want_pk, sizeof want_pk),
            gqi_mldsa_pk_len (scheme));
  CHECK_EQ (tst_unhex_parts (sk_hex, want_sk, sizeof want_sk),
            gqi_mldsa_sk_len (scheme));
  CHECK_EQ (gqi_mldsa_keygen (scheme, seed, pk, sk), GQ_OK);
  CHECK (memcmp (pk, want_pk, gqi_mldsa_pk_len (scheme)) == 0);
  CHECK (memcmp (sk, want_sk, gqi_mldsa_sk_len (scheme)) == 0);
}

#define KEYGEN(tag, scheme) \
  kat_keygen (scheme, P (MLDSA##tag##_KEYGEN_SEED), \
              P (MLDSA##tag##_KEYGEN_PK), P (MLDSA##tag##_KEYGEN_SK))

/* Signing with the randomness given gives the vector's signature, byte for
   byte.  EXTERNAL: with the context (FIPS 204 algorithm 2), else the
   message is M' (algorithm 7).  RND_HEX NULL is 32 zero bytes.  */
static void
kat_siggen (unsigned scheme, int external, const char *const *sk_hex,
            const char *const *msg_hex, const char *const *ctx_hex,
            const char *const *rnd_hex, const char *const *sig_hex)
{
  size_t n, mlen, clen = 0, slen;

  CHECK_EQ (tst_unhex_parts (sk_hex, sk, sizeof sk),
            gqi_mldsa_sk_len (scheme));
  mlen = tst_unhex_parts (msg_hex, msg, sizeof msg);
  if (ctx_hex)
    clen = tst_unhex_parts (ctx_hex, ctx, sizeof ctx);
  memset (rnd, 0, sizeof rnd);
  if (rnd_hex)
    CHECK_EQ (tst_unhex_parts (rnd_hex, rnd, sizeof rnd), 32);
  slen = tst_unhex_parts (sig_hex, want_sig, sizeof want_sig);
  CHECK_EQ (slen, gqi_mldsa_sig_len (scheme));
  if (external)
    CHECK_EQ (gqi_mldsa_sign (scheme, sk, ctx, clen, msg, mlen, rnd, sig,
                              sizeof sig, &n), GQ_OK);
  else
    CHECK_EQ (gqi_mldsa_sign_internal (scheme, sk, msg, mlen, rnd, sig,
                                       sizeof sig, &n), GQ_OK);
  CHECK_EQ (n, slen);
  CHECK (n == slen && memcmp (sig, want_sig, n) == 0);
}

#define SIGGEN_DET(tag, scheme) \
  kat_siggen (scheme, 1, P (MLDSA##tag##_SIGGEN_DET_SK), \
              P (MLDSA##tag##_SIGGEN_DET_MESSAGE), \
              P (MLDSA##tag##_SIGGEN_DET_CONTEXT), NULL, \
              P (MLDSA##tag##_SIGGEN_DET_SIGNATURE))
#define SIGGEN_RND(tag, scheme) \
  kat_siggen (scheme, 1, P (MLDSA##tag##_SIGGEN_RND_SK), \
              P (MLDSA##tag##_SIGGEN_RND_MESSAGE), \
              P (MLDSA##tag##_SIGGEN_RND_CONTEXT), \
              P (MLDSA##tag##_SIGGEN_RND_RND), \
              P (MLDSA##tag##_SIGGEN_RND_SIGNATURE))
#define SIGGEN_INT(tag, scheme) \
  kat_siggen (scheme, 0, P (MLDSA##tag##_SIGGEN_INT_SK), \
              P (MLDSA##tag##_SIGGEN_INT_MESSAGE), NULL, NULL, \
              P (MLDSA##tag##_SIGGEN_INT_SIGNATURE))

/* A vector of the verification tests: it verifies, or does not.  */
static void
kat_sigver (unsigned scheme, int passes, const char *const *pk_hex,
            const char *const *msg_hex, const char *const *ctx_hex,
            const char *const *sig_hex)
{
  size_t mlen, clen, plen, slen;

  plen = tst_unhex_parts (pk_hex, pk, sizeof pk);
  mlen = tst_unhex_parts (msg_hex, msg, sizeof msg);
  clen = tst_unhex_parts (ctx_hex, ctx, sizeof ctx);
  slen = tst_unhex_parts (sig_hex, sig, sizeof sig);
  CHECK_EQ (plen, gqi_mldsa_pk_len (scheme));
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, ctx, clen, msg, mlen, sig,
                              slen), passes ? GQ_OK : GQ_ERR_CRYPTO);
}

#define SIGVER_BAD(tag, scheme) \
  kat_sigver (scheme, 0, P (MLDSA##tag##_SIGVER_BAD_PK), \
              P (MLDSA##tag##_SIGVER_BAD_MESSAGE), \
              P (MLDSA##tag##_SIGVER_BAD_CONTEXT), \
              P (MLDSA##tag##_SIGVER_BAD_SIGNATURE))

#define SIGVER_OK(tag, scheme) \
  kat_sigver (scheme, 1, P (MLDSA##tag##_SIGVER_OK_PK), \
              P (MLDSA##tag##_SIGVER_OK_MESSAGE), \
              P (MLDSA##tag##_SIGVER_OK_CONTEXT), \
              P (MLDSA##tag##_SIGVER_OK_SIGNATURE))

static void
test_nist_vectors (void)
{
  KEYGEN (44, GQ_SIG_MLDSA44);
  KEYGEN (65, GQ_SIG_MLDSA65);
  KEYGEN (87, GQ_SIG_MLDSA87);
  SIGGEN_DET (44, GQ_SIG_MLDSA44);
  SIGGEN_DET (65, GQ_SIG_MLDSA65);
  SIGGEN_DET (87, GQ_SIG_MLDSA87);
  SIGGEN_RND (44, GQ_SIG_MLDSA44);
  SIGGEN_RND (65, GQ_SIG_MLDSA65);
  SIGGEN_RND (87, GQ_SIG_MLDSA87);
  SIGGEN_INT (44, GQ_SIG_MLDSA44);
  SIGGEN_INT (65, GQ_SIG_MLDSA65);
  SIGGEN_INT (87, GQ_SIG_MLDSA87);
  SIGVER_OK (44, GQ_SIG_MLDSA44);
  SIGVER_OK (65, GQ_SIG_MLDSA65);
  SIGVER_OK (87, GQ_SIG_MLDSA87);
  SIGVER_BAD (44, GQ_SIG_MLDSA44);
  SIGVER_BAD (65, GQ_SIG_MLDSA65);
  SIGVER_BAD (87, GQ_SIG_MLDSA87);
}

/* ---- Round trips and what must fail ---- */

static void
roundtrip (unsigned scheme)
{
  uint8_t a[GQI_MLDSA_SIG_MAX], b[GQI_MLDSA_SIG_MAX], bad[GQI_MLDSA_SIG_MAX];
  const uint8_t m[] = "TLS 1.3, server CertificateVerify";
  const uint8_t c[] = "a context";
  size_t na, nb, plen = gqi_mldsa_pk_len (scheme), i;
  unsigned other;

  memset (seed, 0x5a, sizeof seed);
  CHECK_EQ (gqi_mldsa_keygen (scheme, seed, pk, sk), GQ_OK);

  /* The empty context, as TLS uses; two hedged signatures differ.  */
  CHECK_EQ (gqi_mldsa_sign (scheme, sk, NULL, 0, m, sizeof m, NULL, a,
                            sizeof a, &na), GQ_OK);
  CHECK_EQ (na, gqi_mldsa_sig_len (scheme));
  CHECK_EQ (gqi_mldsa_sign (scheme, sk, NULL, 0, m, sizeof m, NULL, b,
                            sizeof b, &nb), GQ_OK);
  CHECK (na == nb && memcmp (a, b, na) != 0);
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, NULL, 0, m, sizeof m, a, na),
            GQ_OK);
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, NULL, 0, m, sizeof m, b, nb),
            GQ_OK);

  /* The empty context is the context of length 0, and not another one.  */
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, c, 0, m, sizeof m, a, na),
            GQ_OK);
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, c, sizeof c, m, sizeof m, a,
                              na), GQ_ERR_CRYPTO);

  /* A context, up to 255 bytes, no more.  */
  CHECK_EQ (gqi_mldsa_sign (scheme, sk, c, sizeof c, m, sizeof m, NULL, a,
                            sizeof a, &na), GQ_OK);
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, c, sizeof c, m, sizeof m, a,
                              na), GQ_OK);
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, NULL, 0, m, sizeof m, a, na),
            GQ_ERR_CRYPTO);
  memset (ctx, 'c', sizeof ctx);
  CHECK_EQ (gqi_mldsa_sign (scheme, sk, ctx, 255, m, sizeof m, NULL, a,
                            sizeof a, &na), GQ_OK);
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, ctx, 255, m, sizeof m, a, na),
            GQ_OK);
  CHECK_EQ (gqi_mldsa_sign (scheme, sk, ctx, 256, m, sizeof m, NULL, a,
                            sizeof a, &na), GQ_ERR_RANGE);
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, ctx, 256, m, sizeof m, a, na),
            GQ_ERR_RANGE);

  /* An empty message is a message.  */
  CHECK_EQ (gqi_mldsa_sign (scheme, sk, NULL, 0, NULL, 0, NULL, a, sizeof a,
                            &na), GQ_OK);
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, NULL, 0, NULL, 0, a, na),
            GQ_OK);

  /* Randomness: the same gives the same signature.  */
  memset (rnd, 7, sizeof rnd);
  CHECK_EQ (gqi_mldsa_sign (scheme, sk, NULL, 0, m, sizeof m, rnd, a,
                            sizeof a, &na), GQ_OK);
  CHECK_EQ (gqi_mldsa_sign (scheme, sk, NULL, 0, m, sizeof m, rnd, b,
                            sizeof b, &nb), GQ_OK);
  CHECK (na == nb && memcmp (a, b, na) == 0);

  /* A changed message, signature or key does not verify.  */
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, NULL, 0, m, sizeof m - 1, a,
                              na), GQ_ERR_CRYPTO);
  for (i = 0; i < na; i += 211)
    {
      memcpy (bad, a, na);
      bad[i] ^= 1;
      CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, NULL, 0, m, sizeof m,
                                  bad, na), GQ_ERR_CRYPTO);
    }
  memcpy (bad, pk, plen);
  bad[plen / 2] ^= 1;
  CHECK_EQ (gqi_mldsa_verify (scheme, bad, plen, NULL, 0, m, sizeof m, a, na),
            GQ_ERR_CRYPTO);

  /* A signature or key of the wrong length (one short, one long, none).  */
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, NULL, 0, m, sizeof m, a,
                              na - 1), GQ_ERR_CRYPTO);
  memcpy (bad, a, na);
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, NULL, 0, m, sizeof m, bad,
                              na + 1), GQ_ERR_CRYPTO);
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen, NULL, 0, m, sizeof m, a, 0),
            GQ_ERR_CRYPTO);
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen - 1, NULL, 0, m, sizeof m, a,
                              na), GQ_ERR_CRYPTO);
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, plen + 1, NULL, 0, m, sizeof m, a,
                              na), GQ_ERR_CRYPTO);
  CHECK_EQ (gqi_mldsa_verify (scheme, pk, 0, NULL, 0, m, sizeof m, a, na),
            GQ_ERR_CRYPTO);

  /* A key of another parameter set, whatever its length is taken for.  */
  for (i = 0; i < 3; i++)
    {
      uint8_t opk[GQI_MLDSA_PK_MAX], osk[GQI_MLDSA_SK_MAX];

      other = schemes[i];
      if (other == scheme)
        continue;
      CHECK_EQ (gqi_mldsa_keygen (other, seed, opk, osk), GQ_OK);
      CHECK_EQ (gqi_mldsa_verify (scheme, opk, gqi_mldsa_pk_len (other),
                                  NULL, 0, m, sizeof m, a, na), GQ_ERR_CRYPTO);
      CHECK_EQ (gqi_mldsa_verify (other, opk, gqi_mldsa_pk_len (other), NULL,
                                  0, m, sizeof m, a, na), GQ_ERR_CRYPTO);
      /* ...nor a signature of a key of one set under the scheme of another. */
      CHECK_EQ (gqi_mldsa_verify (other, pk, plen, NULL, 0, m, sizeof m, a,
                                  na), GQ_ERR_CRYPTO);
    }

  /* Room for the signature.  */
  CHECK_EQ (gqi_mldsa_sign (scheme, sk, NULL, 0, m, sizeof m, NULL, a, na - 1,
                            &nb), GQ_ERR_BUFSIZE);
  CHECK_EQ (gqi_mldsa_sign (scheme, sk, NULL, 0, m, sizeof m, NULL, a, 0, &nb),
            GQ_ERR_BUFSIZE);

  /* A scheme that is not ML-DSA.  */
  CHECK_EQ (gqi_mldsa_sign (GQ_SIG_ED25519, sk, NULL, 0, m, sizeof m, NULL, a,
                            sizeof a, &na), GQ_ERR_UNSUPPORTED);
  CHECK_EQ (gqi_mldsa_verify (GQ_SIG_ED25519, pk, plen, NULL, 0, m, sizeof m,
                              a, 64), GQ_ERR_UNSUPPORTED);
  CHECK_EQ (gqi_mldsa_keygen (GQ_SIG_ED25519, seed, pk, sk),
            GQ_ERR_UNSUPPORTED);
}

static void
test_roundtrips (void)
{
  size_t i;

  for (i = 0; i < 3; i++)
    roundtrip (schemes[i]);
}

/* ---- RFC 9881 ---- */

/* The DER of the PEM vectors is decoded by the tests' own base64 (tst-util.h),
   so that it can be mutated without leaning on the code under test.  */
#define pem_der tst_pem_der

static uint8_t der[16384], mut[16384];

/* The key of RFC 9881 for SCHEME, in the form of the PEM pieces.  */
static void
rfc_key (unsigned scheme, const char *const *pieces, int has_pk,
         const uint8_t *seed_pk, const uint8_t *seed_sk)
{
  struct gqi_mldsa_key k;
  size_t n, dl;

  tst_cat_parts (pieces, pem, sizeof pem);
  memset (&k, 0xaa, sizeof k);
  CHECK_EQ (gqi_mldsa_key_from_pem (pem, strlen (pem), &k), GQ_OK);
  CHECK_EQ (k.scheme, scheme);
  CHECK_EQ (k.sk_len, gqi_mldsa_sk_len (scheme));
  CHECK (memcmp (k.sk, seed_sk, k.sk_len) == 0);
  /* The public key is known if there was a seed to make it from.  */
  if (has_pk)
    {
      CHECK_EQ (k.pk_len, gqi_mldsa_pk_len (scheme));
      CHECK (memcmp (k.pk, seed_pk, k.pk_len) == 0);
    }
  else
    CHECK_EQ (k.pk_len, 0);

  /* The same from the DER, and signing with the key it gave.  */
  dl = pem_der (pem, der, sizeof der);
  CHECK (dl > 30);
  memset (&k, 0xaa, sizeof k);
  CHECK_EQ (gqi_mldsa_key_from_pkcs8 (der, dl, &k), GQ_OK);
  CHECK_EQ (gqi_mldsa_sign (scheme, k.sk, NULL, 0, (const uint8_t *) "x", 1,
                            NULL, sig, sizeof sig, &n), GQ_OK);
  CHECK_EQ (gqi_mldsa_verify (scheme, seed_pk, gqi_mldsa_pk_len (scheme),
                              NULL, 0, (const uint8_t *) "x", 1, sig, n),
            GQ_OK);
}

static void
test_rfc9881_keys (void)
{
  const struct
  {
    unsigned scheme;
    const char *const *seed_pem, *const *expanded_pem, *const *both_pem,
      *const *cert_pem;
  } sets[] = {
    { GQ_SIG_MLDSA44, P (RFC9881_MLDSA44_SEED_PEM),
      P (RFC9881_MLDSA44_EXPANDED_PEM), P (RFC9881_MLDSA44_BOTH_PEM),
      P (RFC9881_MLDSA44_CERT_PEM) },
    { GQ_SIG_MLDSA65, P (RFC9881_MLDSA65_SEED_PEM),
      P (RFC9881_MLDSA65_EXPANDED_PEM), P (RFC9881_MLDSA65_BOTH_PEM),
      P (RFC9881_MLDSA65_CERT_PEM) },
    { GQ_SIG_MLDSA87, P (RFC9881_MLDSA87_SEED_PEM),
      P (RFC9881_MLDSA87_EXPANDED_PEM), P (RFC9881_MLDSA87_BOTH_PEM),
      P (RFC9881_MLDSA87_CERT_PEM) }
  };
  size_t i;
  static uint8_t kpk[GQI_MLDSA_PK_MAX], ksk[GQI_MLDSA_SK_MAX];

  CHECK_EQ (tst_unhex_parts (P (RFC9881_SEED), seed, sizeof seed), 32);
  for (i = 0; i < 3; i++)
    {
      unsigned sc = sets[i].scheme;

      /* What the seed gives, which all the forms must agree with.  */
      CHECK_EQ (gqi_mldsa_keygen (sc, seed, kpk, ksk), GQ_OK);
      rfc_key (sc, sets[i].seed_pem, 1, kpk, ksk);
      rfc_key (sc, sets[i].expanded_pem, 0, kpk, ksk);
      rfc_key (sc, sets[i].both_pem, 1, kpk, ksk);
    }
}

static void
test_rfc9881_certificates (void)
{
  const struct
  {
    unsigned scheme;
    const char *const *cert_pem;
  } sets[] = {
    { GQ_SIG_MLDSA44, P (RFC9881_MLDSA44_CERT_PEM) },
    { GQ_SIG_MLDSA65, P (RFC9881_MLDSA65_CERT_PEM) },
    { GQ_SIG_MLDSA87, P (RFC9881_MLDSA87_CERT_PEM) }
  };
  size_t i, dl, n, cut;
  unsigned sc;
  static uint8_t kpk[GQI_MLDSA_PK_MAX], ksk[GQI_MLDSA_SK_MAX], cpk[GQI_MLDSA_PK_MAX];

  CHECK_EQ (tst_unhex_parts (P (RFC9881_SEED), seed, sizeof seed), 32);
  for (i = 0; i < 3; i++)
    {
      tst_cat_parts (sets[i].cert_pem, pem, sizeof pem);
      dl = pem_der (pem, der, sizeof der);
      CHECK (dl > 1000);
      CHECK_EQ (gqi_mldsa_keygen (sets[i].scheme, seed, kpk, ksk), GQ_OK);

      /* The certificate is for the key the seed makes.  */
      sc = 0;
      n = 0;
      CHECK_EQ (gqi_mldsa_pk_from_cert (der, dl, &sc, cpk, &n), GQ_OK);
      CHECK_EQ (sc, sets[i].scheme);
      CHECK_EQ (n, gqi_mldsa_pk_len (sets[i].scheme));
      CHECK (memcmp (cpk, kpk, n) == 0);

      /* Cut anywhere in the front of it and it is not a certificate (the
         real parser says why), nor does a key that is cut off in the
         middle count.  */
      for (cut = 0; cut < 200; cut += 7)
        {
          unsigned sc2;
          size_t n2;

          CHECK_EQ (gqi_mldsa_pk_from_cert (der, cut, &sc2, cpk, &n2),
                    GQ_ERR_UNSUPPORTED);
        }
    }
}

/* ---- Refusals ---- */

/* DER of the PKCS#8 of RFC 9881 for ML-DSA-44, seed form, built by hand:
   SEQUENCE { INTEGER 0, SEQUENCE { OID }, OCTET STRING { [0] seed } }.  */
static size_t
seed_pkcs8 (uint8_t *out, unsigned oid_last, const uint8_t *seed32)
{
  static const uint8_t head[] = {
    0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x03, 0x00 /* the last arc */, 0x04, 0x22, 0x80,
    0x20
  };

  memcpy (out, head, sizeof head);
  out[17] = (uint8_t) oid_last;
  memcpy (out + sizeof head, seed32, 32);
  return sizeof head + 32;
}

static void
test_pkcs8_refusals (void)
{
  struct gqi_mldsa_key k;
  uint8_t s[32], d[200], pk44[GQI_MLDSA_PK_MAX], sk44[GQI_MLDSA_SK_MAX];
  size_t n, dl, i;

  memcpy (s, "0123456789abcdef0123456789abcdef", 32);

  /* The hand-built one is good, and all that follows differs from it.  */
  n = seed_pkcs8 (d, 17, s);
  CHECK_EQ (gqi_mldsa_key_from_pkcs8 (d, n, &k), GQ_OK);
  CHECK_EQ (k.scheme, GQ_SIG_MLDSA44);
  CHECK_EQ (gqi_mldsa_keygen (GQ_SIG_MLDSA44, s, pk44, sk44), GQ_OK);
  CHECK (k.sk_len == 2560 && memcmp (k.sk, sk44, 2560) == 0);
  CHECK (k.pk_len == 1312 && memcmp (k.pk, pk44, 1312) == 0);
  /* The other two OIDs are the other two sets.  */
  n = seed_pkcs8 (d, 18, s);
  CHECK_EQ (gqi_mldsa_key_from_pkcs8 (d, n, &k), GQ_OK);
  CHECK_EQ (k.scheme, GQ_SIG_MLDSA65);
  n = seed_pkcs8 (d, 19, s);
  CHECK_EQ (gqi_mldsa_key_from_pkcs8 (d, n, &k), GQ_OK);
  CHECK_EQ (k.scheme, GQ_SIG_MLDSA87);

  /* Another algorithm (the arc after the last ML-DSA, or before) is not
     ours, which the caller needs to know apart from a damaged key.  */
  for (i = 0; i < 2; i++)
    {
      n = seed_pkcs8 (d, i ? 16 : 20, s);
      CHECK_EQ (gqi_mldsa_key_from_pkcs8 (d, n, &k), GQ_ERR_UNSUPPORTED);
    }

  /* Cut short at every length, or with a byte too many: not a key.  */
  n = seed_pkcs8 (d, 17, s);
  for (dl = 0; dl < n; dl++)
    CHECK (gqi_mldsa_key_from_pkcs8 (d, dl, &k) != GQ_OK);
  d[n] = 0;
  CHECK (gqi_mldsa_key_from_pkcs8 (d, n + 1, &k) != GQ_OK);

  /* A version other than 0 and 1.  */
  n = seed_pkcs8 (d, 17, s);
  d[4] = 2;
  CHECK_EQ (gqi_mldsa_key_from_pkcs8 (d, n, &k), GQ_ERR_CERT);

  /* The seed of 31 bytes, or 33: lengths made consistent all the way up.  */
  {
    uint8_t e[200];

    n = seed_pkcs8 (e, 17, s);
    memcpy (d, e, n);
    d[1] = 0x33; d[19] = 0x21; d[21] = 0x1f;
    CHECK_EQ (gqi_mldsa_key_from_pkcs8 (d, n - 1, &k), GQ_ERR_CERT);
    memcpy (d, e, n);
    d[n] = 0;
    d[1] = 0x35; d[19] = 0x23; d[21] = 0x21;
    CHECK_EQ (gqi_mldsa_key_from_pkcs8 (d, n + 1, &k), GQ_ERR_CERT);
  }

  /* Parameters present in the algorithm identifier (NULL), which the RFC
     forbids.  */
  {
    static const uint8_t with_null[] = {
      0x30, 0x36, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x03, 0x11, 0x05, 0x00, 0x04, 0x22, 0x80, 0x20
    };

    memcpy (d, with_null, sizeof with_null);
    memcpy (d + sizeof with_null, s, 32);
    CHECK_EQ (gqi_mldsa_key_from_pkcs8 (d, sizeof with_null + 32, &k),
              GQ_ERR_CERT);
  }

  /* The wrong tag for the key: an OCTET STRING of 32 bytes is an expanded
     key of the wrong size, and not a seed.  */
  n = seed_pkcs8 (d, 17, s);
  d[20] = 0x04;
  CHECK_EQ (gqi_mldsa_key_from_pkcs8 (d, n, &k), GQ_ERR_CERT);
  /* And the choice is by tag, not by length.  */
  n = seed_pkcs8 (d, 17, s);
  d[20] = 0x81;
  CHECK_EQ (gqi_mldsa_key_from_pkcs8 (d, n, &k), GQ_ERR_CERT);
  CHECK_EQ (gqi_mldsa_key_from_pkcs8 (NULL, 0, &k), GQ_ERR_UNSUPPORTED);
}

/* A mutated copy of the DER of PEM text, as a key.  */
static int
mutated (const char *const *pieces, size_t at, unsigned xor_with,
         size_t new_len)
{
  struct gqi_mldsa_key k;
  size_t dl;

  tst_cat_parts (pieces, pem, sizeof pem);
  dl = pem_der (pem, der, sizeof der);
  memcpy (mut, der, dl);
  if (at < dl)
    mut[at] ^= xor_with;
  return gqi_mldsa_key_from_pkcs8 (mut, new_len ? new_len : dl, &k);
}

static void
test_rfc9881_refusals (void)
{
  struct gqi_mldsa_key k;
  size_t dl, i;

  /* C.4: a seed that does not make the expanded key it comes with.  */
  tst_cat_parts (P (RFC9881_MLDSA44_INCONSISTENT_BOTH_PEM), pem, sizeof pem);
  CHECK_EQ (gqi_mldsa_key_from_pem (pem, strlen (pem), &k), GQ_ERR_CERT);

  /* The two that only have the expanded key are consistent as far as can be
     told from it: the public key is not there to compare with (checking
     them takes more than libgcrypt gives), so they load.  */
  tst_cat_parts (P (RFC9881_MLDSA44_INCONSISTENT_EXPANDED_TR_PEM), pem,
                 sizeof pem);
  CHECK_EQ (gqi_mldsa_key_from_pem (pem, strlen (pem), &k), GQ_OK);
  tst_cat_parts (P (RFC9881_MLDSA44_INCONSISTENT_EXPANDED_T0_PEM), pem,
                 sizeof pem);
  CHECK_EQ (gqi_mldsa_key_from_pem (pem, strlen (pem), &k), GQ_OK);

  /* The seed-and-expanded key with one bit of the expanded part changed
     (the consistency check, as the RFC requires, finds it) and with one bit
     of the seed changed.  */
  tst_cat_parts (P (RFC9881_MLDSA44_BOTH_PEM), pem, sizeof pem);
  dl = pem_der (pem, der, sizeof der);
  CHECK (dl > 2600);
  CHECK_EQ (mutated (P (RFC9881_MLDSA44_BOTH_PEM), dl - 1, 1, 0), GQ_ERR_CERT);
  CHECK_EQ (mutated (P (RFC9881_MLDSA44_BOTH_PEM), dl - 2000, 1, 0),
            GQ_ERR_CERT);
  CHECK_EQ (mutated (P (RFC9881_MLDSA44_BOTH_PEM), 40, 1, 0), GQ_ERR_CERT);

  /* A length that does not add up, at each of the levels of the DER: the
     outer SEQUENCE, the OCTET STRING, and the inner SEQUENCE.  */
  for (i = 0; i < 16; i++)
    CHECK (mutated (P (RFC9881_MLDSA44_BOTH_PEM), i, 0x7f, 0) != GQ_OK);

  /* The expanded key a byte short or long (everything else consistent) is
     not one.  */
  {
    uint8_t good[16384];

    tst_cat_parts (P (RFC9881_MLDSA44_EXPANDED_PEM), pem, sizeof pem);
    dl = pem_der (pem, good, sizeof good);
    CHECK (gqi_mldsa_key_from_pkcs8 (good, dl - 1, &k) != GQ_OK);
    memcpy (mut, good, dl);
    mut[dl] = 0;
    CHECK (gqi_mldsa_key_from_pkcs8 (mut, dl + 1, &k) != GQ_OK);
  }

  /* The OID of another set on the 44 key: the expanded key is the wrong
     size for it.  */
  tst_cat_parts (P (RFC9881_MLDSA44_EXPANDED_PEM), pem, sizeof pem);
  dl = pem_der (pem, der, sizeof der);
  memcpy (mut, der, dl);
  {
    static const uint8_t arcs[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                                    0x03 };
    size_t at = 0;

    for (i = 0; i + sizeof arcs < 40; i++)
      if (memcmp (der + i, arcs, sizeof arcs) == 0)
        at = i + sizeof arcs;
    CHECK (at > 0);
    CHECK_EQ (mut[at], 0x11);		/* The last arc, 17.  */
    mut[at] = 0x12;
  }
  CHECK_EQ (gqi_mldsa_key_from_pkcs8 (mut, dl, &k), GQ_ERR_CERT);

  /* Not PEM, or PEM of something else, or armor around nothing, or around
     what is not base64 or has no end: not ML-DSA keys, whatever else they
     are, and for the real parser to say.  */
  CHECK_EQ (gqi_mldsa_key_from_pem ("", 0, &k), GQ_ERR_UNSUPPORTED);
  CHECK_EQ (gqi_mldsa_key_from_pem ("hello", 5, &k), GQ_ERR_UNSUPPORTED);
  {
    static const char other[] =
      "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    static const char enc[] =
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n"
      "-----END ENCRYPTED PRIVATE KEY-----\n";
    static const char empty[] =
      "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n";
    static const char junk[] =
      "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n";
    static const char open[] =
      "-----BEGIN PRIVATE KEY-----\nAAAA\n";

    CHECK_EQ (gqi_mldsa_key_from_pem (other, sizeof other - 1, &k),
              GQ_ERR_UNSUPPORTED);
    CHECK_EQ (gqi_mldsa_key_from_pem (enc, sizeof enc - 1, &k),
              GQ_ERR_UNSUPPORTED);
    CHECK_EQ (gqi_mldsa_key_from_pem (empty, sizeof empty - 1, &k),
              GQ_ERR_UNSUPPORTED);
    CHECK_EQ (gqi_mldsa_key_from_pem (junk, sizeof junk - 1, &k),
              GQ_ERR_UNSUPPORTED);
    CHECK_EQ (gqi_mldsa_key_from_pem (open, sizeof open - 1, &k),
              GQ_ERR_UNSUPPORTED);
  }

  /* A key block among others in one file is found.  */
  {
    static char two[16384];
    size_t l;

    strcpy (two, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    l = strlen (two);
    tst_cat_parts (P (RFC9881_MLDSA65_SEED_PEM), two + l, sizeof two - l);
    CHECK_EQ (gqi_mldsa_key_from_pem (two, strlen (two), &k), GQ_OK);
    CHECK_EQ (k.scheme, GQ_SIG_MLDSA65);
  }
}

static void
test_cert_refusals (void)
{
  size_t dl, i, n, plen;
  unsigned sc;
  uint8_t cpk[GQI_MLDSA_PK_MAX];
  const uint8_t oid44[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                            0x04, 0x03, 0x11 };
  size_t at = 0;

  tst_cat_parts (P (RFC9881_MLDSA44_CERT_PEM), pem, sizeof pem);
  dl = pem_der (pem, der, sizeof der);
  CHECK (dl > 1500);

  /* The OID of the key (the second one in the certificate: the first is the
     signature algorithm).  */
  for (i = 0; i + sizeof oid44 < dl; i++)
    if (memcmp (der + i, oid44, sizeof oid44) == 0)
      {
        if (at)
          {
            at = i;
            break;
          }
        at = i;
      }
  CHECK (at > 0);
  /* The last arc after the one of the signature is the one of the key.  */
  n = 0;
  CHECK_EQ (gqi_mldsa_pk_from_cert (der, dl, &sc, cpk, &n), GQ_OK);
  plen = n;
  CHECK_EQ (plen, 1312);

  /* The key's OID turned into that of ML-DSA-65, whose key is bigger: the
     bit string is the wrong size.  */
  memcpy (mut, der, dl);
  mut[at + sizeof oid44 - 1] = 0x12;
  n = 0;
  CHECK_EQ (gqi_mldsa_pk_from_cert (mut, dl, &sc, cpk, &n), GQ_ERR_CERT);

  /* ...into another algorithm: not ML-DSA, which is not an error here.  */
  memcpy (mut, der, dl);
  mut[at + sizeof oid44 - 1] = 0x14;
  CHECK_EQ (gqi_mldsa_pk_from_cert (mut, dl, &sc, cpk, &n),
            GQ_ERR_UNSUPPORTED);

  /* Junk, nothing, and a prefix of a certificate.  */
  CHECK_EQ (gqi_mldsa_pk_from_cert ((const uint8_t *) "junk", 4, &sc, cpk, &n),
            GQ_ERR_UNSUPPORTED);
  CHECK_EQ (gqi_mldsa_pk_from_cert (der, 0, &sc, cpk, &n),
            GQ_ERR_UNSUPPORTED);
  CHECK (gqi_mldsa_pk_from_cert (der, at + 10, &sc, cpk, &n) != GQ_OK);
}

/* ---- Not available ---- */

static void
test_disabled (void)
{
  struct gqi_mldsa_key k;
  size_t n;

  CHECK (gqi_mldsa_usable ());
  gqi_mldsa_enable (0);
  CHECK (!gqi_mldsa_usable ());
  CHECK_EQ (gqi_mldsa_keygen (GQ_SIG_MLDSA65, seed, pk, sk),
            GQ_ERR_UNSUPPORTED);
  CHECK_EQ (gqi_mldsa_sign (GQ_SIG_MLDSA65, sk, NULL, 0, NULL, 0, NULL, sig,
                            sizeof sig, &n), GQ_ERR_UNSUPPORTED);
  tst_cat_parts (P (RFC9881_MLDSA65_SEED_PEM), pem, sizeof pem);
  CHECK_EQ (gqi_mldsa_key_from_pem (pem, strlen (pem), &k),
            GQ_ERR_UNSUPPORTED);
  gqi_mldsa_enable (1);
  CHECK (gqi_mldsa_usable ());
  CHECK_EQ (gqi_mldsa_key_from_pem (pem, strlen (pem), &k), GQ_OK);
}

int
main (void)
{
  CHECK_EQ (gq_crypto_init (), GQ_OK);
  test_sizes ();
  /* A libgcrypt without ML-DSA is a build we cannot test; it is not one the
     floor of 1.12.0 allows.  */
  CHECK (gqi_mldsa_usable ());
  test_nist_vectors ();
  test_roundtrips ();
  test_rfc9881_keys ();
  test_rfc9881_certificates ();
  test_pkcs8_refusals ();
  test_rfc9881_refusals ();
  test_cert_refusals ();
  test_disabled ();
  TST_DONE ();
}
