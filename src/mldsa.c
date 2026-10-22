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

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

#include <quickstep/status.h>
#include <quickstep/policy.h>
#include <quickstep/crypto.h>

#include "mldsa.h"

/* How libgcrypt is driven (libgcrypt 1.12, cipher/pubkey-dilithium.c):

   Algorithm names are "dilithium2", "dilithium3" and "dilithium5" for
   ML-DSA-44, -65 and -87.

   Key generation: (genkey (NAME (S <seed>))) gives
   (key-data (public-key (NAME (p <pk>)))
             (private-key (NAME (p <pk>) (s <sk>) (S <seed>)))), the
   deterministic KeyGen_internal of FIPS 204; without the S item it draws a
   seed of its own.

   Signing: (data (raw) (flags no-prefix) (value <M'>) [(random-override
   <rnd>)]) with (private-key (NAME (s <sk>))) is ML-DSA.Sign_internal, the
   hedged one unless rnd is given.  Without the no-prefix flag libgcrypt
   forms M' itself from a (label <ctx>), but an empty label is refused (a
   zero-length atom reads back as absent, and an absent one is an error), and
   the empty context is the one TLS uses.  So M' = 0 || |ctx| || ctx || M of
   algorithm 2 is formed here, for every context, and always signed with
   no-prefix: one path, and the same bytes as libgcrypt makes with a label
   (the tests check the signatures against NIST's).

   Verifying: (sig-val (NAME (s <sig>))) and (public-key (NAME (p <pk>)))
   with the same data.  Sizes are checked here first, since libgcrypt says
   only "bad signature" or "bad key".  */

static int mldsa_enabled = 1;

static const struct
{
  unsigned scheme;
  const char *name;
  uint8_t oid_last;		/* The last arc of 2.16.840.1.101.3.4.3.n.  */
} algos[] = {
  { GQ_SIG_MLDSA44, "dilithium2", 17 },
  { GQ_SIG_MLDSA65, "dilithium3", 18 },
  { GQ_SIG_MLDSA87, "dilithium5", 19 }
};

#define N_ALGOS (sizeof algos / sizeof algos[0])

static const char *
name_of (unsigned scheme)
{
  size_t i;

  for (i = 0; i < N_ALGOS; i++)
    if (algos[i].scheme == scheme)
      return algos[i].name;
  return NULL;
}

size_t
gqi_mldsa_pk_len (unsigned scheme)
{
  switch (scheme)
    {
    case GQ_SIG_MLDSA44: return 1312;
    case GQ_SIG_MLDSA65: return 1952;
    case GQ_SIG_MLDSA87: return 2592;
    default: return 0;
    }
}

size_t
gqi_mldsa_sk_len (unsigned scheme)
{
  switch (scheme)
    {
    case GQ_SIG_MLDSA44: return 2560;
    case GQ_SIG_MLDSA65: return 4032;
    case GQ_SIG_MLDSA87: return 4896;
    default: return 0;
    }
}

size_t
gqi_mldsa_sig_len (unsigned scheme)
{
  switch (scheme)
    {
    case GQ_SIG_MLDSA44: return 2420;
    case GQ_SIG_MLDSA65: return 3309;
    case GQ_SIG_MLDSA87: return 4627;
    default: return 0;
    }
}

int
gqi_mldsa_usable (void)
{
  if (!mldsa_enabled || gq_crypto_init () != GQ_OK)
    return 0;
  return gcry_pk_test_algo (GCRY_PK_MLDSA) == 0;
}

void
gqi_mldsa_enable (int on)
{
  mldsa_enabled = on != 0;
}

/* The bytes of the item TOKEN ("p", "s" or "S", all of one size) of the
   list NAME-list of KEY, copied to OUT.  */
static int
item_bytes (gcry_sexp_t list, const char *token, uint8_t *out, size_t want)
{
  gcry_mpi_t m = NULL;
  const void *d;
  unsigned int nbits = 0;
  int r = GQ_ERR_CRYPTO;

  if (gcry_sexp_extract_param (list, NULL, token, &m, NULL) != 0 || m == NULL)
    return GQ_ERR_CRYPTO;
  d = gcry_mpi_get_opaque (m, &nbits);
  if (d != NULL && (nbits + 7) / 8 == want)
    {
      memcpy (out, d, want);
      r = GQ_OK;
    }
  gcry_mpi_release (m);
  return r;
}

int
gqi_mldsa_keygen (unsigned scheme, const uint8_t seed[GQI_MLDSA_SEED_LEN],
                  uint8_t *pk, uint8_t *sk)
{
  const char *name = name_of (scheme);
  gcry_sexp_t param = NULL, key = NULL, priv = NULL, body = NULL;
  int r;

  if (name == NULL)
    return GQ_ERR_UNSUPPORTED;
  if (seed == NULL || pk == NULL || sk == NULL)
    return GQ_ERR_INVAL;
  if (!gqi_mldsa_usable ())
    return GQ_ERR_UNSUPPORTED;
  if (gcry_sexp_build (&param, NULL, "(genkey(%s(S%b)))", name,
                       (int) GQI_MLDSA_SEED_LEN, seed) != 0)
    return GQ_ERR_NOMEM;
  r = gcry_pk_genkey (&key, param) == 0 ? GQ_OK : GQ_ERR_CRYPTO;
  if (r == GQ_OK)
    {
      priv = gcry_sexp_find_token (key, "private-key", 0);
      body = priv ? gcry_sexp_nth (priv, 1) : NULL;
      if (body == NULL)
        r = GQ_ERR_CRYPTO;
    }
  if (r == GQ_OK)
    r = item_bytes (body, "/p", pk, gqi_mldsa_pk_len (scheme));
  if (r == GQ_OK)
    r = item_bytes (body, "/s", sk, gqi_mldsa_sk_len (scheme));
  gcry_sexp_release (body);
  gcry_sexp_release (priv);
  gcry_sexp_release (key);
  gcry_sexp_release (param);
  return r;
}

int
gqi_mldsa_sign_internal (unsigned scheme, const uint8_t *sk,
                         const uint8_t *msg, size_t len, const uint8_t *rnd,
                         uint8_t *sig, size_t cap, size_t *sig_len)
{
  const char *name = name_of (scheme);
  gcry_sexp_t skey = NULL, data = NULL, res = NULL, body = NULL;
  size_t want = gqi_mldsa_sig_len (scheme);
  int r;

  if (name == NULL)
    return GQ_ERR_UNSUPPORTED;
  if (sk == NULL || (msg == NULL && len > 0) || sig == NULL
      || sig_len == NULL || len > (size_t) INT_MAX)
    return GQ_ERR_INVAL;
  if (cap < want)
    return GQ_ERR_BUFSIZE;
  if (!gqi_mldsa_usable ())
    return GQ_ERR_UNSUPPORTED;
  if (gcry_sexp_build (&skey, NULL, "(private-key(%s(s%b)))", name,
                       (int) gqi_mldsa_sk_len (scheme), sk) != 0)
    return GQ_ERR_NOMEM;
  if ((rnd != NULL
       ? gcry_sexp_build (&data, NULL,
                          "(data(raw)(flags no-prefix)(value%b)"
                          "(random-override%b))", (int) len,
                          msg ? (const void *) msg : (const void *) "", 32, rnd)
       : gcry_sexp_build (&data, NULL,
                          "(data(raw)(flags no-prefix)(value%b))", (int) len,
                          msg ? (const void *) msg : (const void *) "")) != 0)
    {
      gcry_sexp_release (skey);
      return GQ_ERR_NOMEM;
    }
  r = gcry_pk_sign (&res, data, skey) == 0 ? GQ_OK : GQ_ERR_CRYPTO;
  if (r == GQ_OK)
    {
      body = gcry_sexp_nth (res, 1);
      r = body ? item_bytes (body, "/s", sig, want) : GQ_ERR_CRYPTO;
      if (r == GQ_OK)
        *sig_len = want;
    }
  gcry_sexp_release (body);
  gcry_sexp_release (res);
  gcry_sexp_release (data);
  gcry_sexp_release (skey);
  return r;
}

/* M' = 0 || |ctx| || ctx || M (FIPS 204 algorithm 2 line 10).  */
static uint8_t *
form_mprime (const uint8_t *ctx, size_t ctx_len, const uint8_t *msg,
             size_t len, size_t *out_len)
{
  uint8_t *m;

  if (len > (size_t) INT_MAX - 2 - GQI_MLDSA_CTX_MAX)
    return NULL;
  m = malloc (2 + ctx_len + len);
  if (m == NULL)
    return NULL;
  m[0] = 0;
  m[1] = (uint8_t) ctx_len;
  if (ctx_len)
    memcpy (m + 2, ctx, ctx_len);
  if (len)
    memcpy (m + 2 + ctx_len, msg, len);
  *out_len = 2 + ctx_len + len;
  return m;
}

int
gqi_mldsa_sign (unsigned scheme, const uint8_t *sk, const uint8_t *ctx,
                size_t ctx_len, const uint8_t *msg, size_t len,
                const uint8_t *rnd, uint8_t *sig, size_t cap, size_t *sig_len)
{
  uint8_t *m;
  size_t ml;
  int r;

  if (name_of (scheme) == NULL)
    return GQ_ERR_UNSUPPORTED;
  if ((ctx == NULL && ctx_len > 0) || (msg == NULL && len > 0))
    return GQ_ERR_INVAL;
  if (ctx_len > GQI_MLDSA_CTX_MAX)
    return GQ_ERR_RANGE;
  m = form_mprime (ctx, ctx_len, msg, len, &ml);
  if (m == NULL)
    return GQ_ERR_NOMEM;
  r = gqi_mldsa_sign_internal (scheme, sk, m, ml, rnd, sig, cap, sig_len);
  free (m);
  return r;
}

int
gqi_mldsa_verify_internal (unsigned scheme, const uint8_t *pk, size_t pk_len,
                           const uint8_t *msg, size_t len, const uint8_t *sig,
                           size_t sig_len)
{
  const char *name = name_of (scheme);
  gcry_sexp_t pkey = NULL, data = NULL, sv = NULL;
  int r;

  if (name == NULL)
    return GQ_ERR_UNSUPPORTED;
  if (pk == NULL || (msg == NULL && len > 0) || sig == NULL
      || len > (size_t) INT_MAX)
    return GQ_ERR_INVAL;
  if (pk_len != gqi_mldsa_pk_len (scheme)
      || sig_len != gqi_mldsa_sig_len (scheme))
    return GQ_ERR_CRYPTO;
  if (!gqi_mldsa_usable ())
    return GQ_ERR_UNSUPPORTED;
  if (gcry_sexp_build (&pkey, NULL, "(public-key(%s(p%b)))", name,
                       (int) pk_len, pk) != 0)
    return GQ_ERR_NOMEM;
  if (gcry_sexp_build (&data, NULL, "(data(raw)(flags no-prefix)(value%b))",
                       (int) len, msg ? (const void *) msg : (const void *) "")
      != 0)
    {
      gcry_sexp_release (pkey);
      return GQ_ERR_NOMEM;
    }
  if (gcry_sexp_build (&sv, NULL, "(sig-val(%s(s%b)))", name, (int) sig_len,
                       sig) != 0)
    {
      gcry_sexp_release (data);
      gcry_sexp_release (pkey);
      return GQ_ERR_NOMEM;
    }
  r = gcry_pk_verify (sv, data, pkey) == 0 ? GQ_OK : GQ_ERR_CRYPTO;
  gcry_sexp_release (sv);
  gcry_sexp_release (data);
  gcry_sexp_release (pkey);
  return r;
}

int
gqi_mldsa_verify (unsigned scheme, const uint8_t *pk, size_t pk_len,
                  const uint8_t *ctx, size_t ctx_len, const uint8_t *msg,
                  size_t len, const uint8_t *sig, size_t sig_len)
{
  uint8_t *m;
  size_t ml;
  int r;

  if (name_of (scheme) == NULL)
    return GQ_ERR_UNSUPPORTED;
  if ((ctx == NULL && ctx_len > 0) || (msg == NULL && len > 0))
    return GQ_ERR_INVAL;
  if (ctx_len > GQI_MLDSA_CTX_MAX)
    return GQ_ERR_RANGE;
  m = form_mprime (ctx, ctx_len, msg, len, &ml);
  if (m == NULL)
    return GQ_ERR_NOMEM;
  r = gqi_mldsa_verify_internal (scheme, pk, pk_len, m, ml, sig, sig_len);
  free (m);
  return r;
}

/* ------------------------------------------------------------------ */
/* DER                                                                */
/* ------------------------------------------------------------------ */

/* Read one tag-length-value from [*PP, END): definite, minimally encoded
   length, a single-byte tag.  Moves *PP past it.  */
static int
tlv (const uint8_t **pp, const uint8_t *end, unsigned *tag,
     const uint8_t **val, size_t *len)
{
  const uint8_t *p = *pp;
  size_t l, i, nb;

  if (end - p < 2 || (p[0] & 0x1f) == 0x1f)
    return 0;
  *tag = p[0];
  if (p[1] < 0x80)
    {
      l = p[1];
      p += 2;
    }
  else
    {
      nb = p[1] & 0x7fu;
      if (nb == 0 || nb > 3 || (size_t) (end - p) < 2 + nb)
        return 0;
      l = 0;
      for (i = 0; i < nb; i++)
        l = (l << 8) | p[2 + i];
      if (l < 0x80 || (nb > 1 && p[2] == 0))	/* Not minimal.  */
        return 0;
      p += 2 + nb;
    }
  if (l > (size_t) (end - p))
    return 0;
  *val = p;
  *len = l;
  *pp = p + l;
  return 1;
}

/* The OID 2.16.840.1.101.3.4.3.N with N = 17, 18 or 19: the scheme, or 0.  */
static unsigned
scheme_of_oid (const uint8_t *v, size_t n)
{
  static const uint8_t prefix[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                                    0x03 };
  size_t i;

  if (n != sizeof prefix + 1 || memcmp (v, prefix, sizeof prefix) != 0)
    return 0;
  for (i = 0; i < N_ALGOS; i++)
    if (algos[i].oid_last == v[sizeof prefix])
      return algos[i].scheme;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Private keys                                                       */
/* ------------------------------------------------------------------ */

int
gqi_mldsa_key_from_pkcs8 (const uint8_t *der, size_t len,
                          struct gqi_mldsa_key *key)
{
  const uint8_t *p, *end, *v, *a, *aend, *pe, *q, *qend;
  unsigned tag;
  size_t n, an, pn;
  unsigned scheme;
  uint8_t kseed[GQI_MLDSA_SEED_LEN], ksk[GQI_MLDSA_SK_MAX],
    kpk[GQI_MLDSA_PK_MAX];
  int have_seed = 0, have_sk = 0, r = GQ_ERR_CERT;
  unsigned version;
  const uint8_t *exp = NULL, *pubkey = NULL;
  size_t exp_len = 0, pubkey_len = 0;

  if (key == NULL)
    return GQ_ERR_INVAL;
  memset (key, 0, sizeof *key);
  if (der == NULL)
    return GQ_ERR_UNSUPPORTED;

  /* PrivateKeyInfo ::= SEQUENCE { version, algorithm, privateKey, ... }.
     Until the algorithm is known to be ML-DSA this is not our key to judge:
     anything wrong with it is "not ours", so that a key GnuTLS reads that
     this strict reader does not (a BER length, say) is not refused.  */
  p = der;
  end = der + len;
  if (!tlv (&p, end, &tag, &v, &n) || tag != 0x30 || p != end)
    return GQ_ERR_UNSUPPORTED;
  p = v;
  end = v + n;
  if (!tlv (&p, end, &tag, &v, &n) || tag != 0x02 || n != 1)
    return GQ_ERR_UNSUPPORTED;
  version = v[0];

  /* AlgorithmIdentifier: the OID first.  */
  if (!tlv (&p, end, &tag, &a, &an) || tag != 0x30)
    return GQ_ERR_UNSUPPORTED;
  aend = a + an;
  q = a;
  if (!tlv (&q, aend, &tag, &v, &n) || tag != 0x06)
    return GQ_ERR_UNSUPPORTED;
  scheme = scheme_of_oid (v, n);
  if (scheme == 0)
    return GQ_ERR_UNSUPPORTED;
  if (!gqi_mldsa_usable ())
    return GQ_ERR_UNSUPPORTED;

  /* It is ML-DSA: from here a flaw is the key's.  */
  if (version > 1 || q != aend)		/* Parameters must be absent.  */
    return GQ_ERR_CERT;

  /* privateKey: an OCTET STRING holding the CHOICE.  */
  if (!tlv (&p, end, &tag, &pe, &pn) || tag != 0x04)
    return GQ_ERR_CERT;
  q = pe;
  qend = pe + pn;
  if (!tlv (&q, qend, &tag, &v, &n) || q != qend)
    return GQ_ERR_CERT;
  if (tag == 0x80)			/* seed [0] IMPLICIT OCTET STRING.  */
    {
      if (n != GQI_MLDSA_SEED_LEN)
        return GQ_ERR_CERT;
      memcpy (kseed, v, n);
      have_seed = 1;
    }
  else if (tag == 0x04)			/* expandedKey.  */
    {
      if (n != gqi_mldsa_sk_len (scheme))
        return GQ_ERR_CERT;
      exp = v;
      exp_len = n;
    }
  else if (tag == 0x30)			/* both.  */
    {
      const uint8_t *b = v, *bend = v + n, *bv;
      size_t bn;

      if (!tlv (&b, bend, &tag, &bv, &bn) || tag != 0x04
          || bn != GQI_MLDSA_SEED_LEN)
        return GQ_ERR_CERT;
      memcpy (kseed, bv, bn);
      have_seed = 1;
      if (!tlv (&b, bend, &tag, &bv, &bn) || tag != 0x04
          || bn != gqi_mldsa_sk_len (scheme) || b != bend)
        return GQ_ERR_CERT;
      exp = bv;
      exp_len = bn;
    }
  else
    return GQ_ERR_CERT;

  /* attributes [0], publicKey [1], in that order, and nothing after.  */
  if (p != end)
    {
      if (!tlv (&p, end, &tag, &v, &n))
        return GQ_ERR_CERT;
      if (tag == 0xa0 && p != end && !tlv (&p, end, &tag, &v, &n))
        return GQ_ERR_CERT;
      if (tag == 0x81)
        {
          if (n != 1 + gqi_mldsa_pk_len (scheme) || v[0] != 0)
            return GQ_ERR_CERT;
          pubkey = v + 1;
          pubkey_len = n - 1;
        }
      else if (tag != 0xa0)
        return GQ_ERR_CERT;
      if (p != end)
        return GQ_ERR_CERT;
    }

  /* The expanded key and the public key, from the seed if there is one;
     where there is also an expanded key, they must agree (RFC 9881
     section 8.2).  */
  if (have_seed)
    {
      if (gqi_mldsa_keygen (scheme, kseed, kpk, ksk) != GQ_OK)
        {
          r = GQ_ERR_CRYPTO;
          goto out;
        }
      have_sk = 1;
      if (exp != NULL && !gq_ct_equal (ksk, exp, exp_len))
        goto out;
      if (pubkey != NULL && !gq_ct_equal (kpk, pubkey, pubkey_len))
        goto out;
      memcpy (key->pk, kpk, gqi_mldsa_pk_len (scheme));
      key->pk_len = gqi_mldsa_pk_len (scheme);
    }
  else
    {
      memcpy (ksk, exp, exp_len);
      have_sk = 1;
    }
  /* A public key given with only the expanded key can be checked by using
     the two together.  */
  if (!have_seed && pubkey != NULL)
    {
      static const uint8_t probe[] = "quickstep ML-DSA key check";
      uint8_t sg[GQI_MLDSA_SIG_MAX];
      size_t sl;

      if (gqi_mldsa_sign (scheme, ksk, NULL, 0, probe, sizeof probe, NULL, sg,
                          sizeof sg, &sl) != GQ_OK
          || gqi_mldsa_verify (scheme, pubkey, pubkey_len, NULL, 0, probe,
                               sizeof probe, sg, sl) != GQ_OK)
        goto out;
      memcpy (key->pk, pubkey, pubkey_len);
      key->pk_len = pubkey_len;
    }
  key->scheme = scheme;
  key->sk_len = gqi_mldsa_sk_len (scheme);
  memcpy (key->sk, ksk, key->sk_len);
  r = GQ_OK;

out:
  if (r != GQ_OK)
    gq_wipe (key, sizeof *key);
  gq_wipe (kseed, sizeof kseed);
  if (have_sk)
    gq_wipe (ksk, sizeof ksk);
  return r;
}

/* Strict base64 (RFC 4648 section 4) with white space allowed between the
   characters, as in the body of a PEM block.  */
static int
b64_decode (const char *s, size_t n, uint8_t *out, size_t cap, size_t *outlen)
{
  uint32_t acc = 0;
  int bits = 0, pad = 0;
  size_t o = 0, i;

  for (i = 0; i < n; i++)
    {
      int v;
      char c = s[i];

      if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
        continue;
      if (c == '=')
        {
          pad++;
          continue;
        }
      if (pad)			/* Data after padding.  */
        return 0;
      if (c >= 'A' && c <= 'Z') v = c - 'A';
      else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
      else if (c >= '0' && c <= '9') v = c - '0' + 52;
      else if (c == '+') v = 62;
      else if (c == '/') v = 63;
      else return 0;
      acc = (acc << 6) | (uint32_t) v;
      bits += 6;
      if (bits >= 8)
        {
          bits -= 8;
          if (o == cap)
            return 0;
          out[o++] = (uint8_t) (acc >> bits);
          acc &= (1u << bits) - 1;
        }
    }
  /* The leftover bits are zero, and the padding is what completes a group
     of four.  */
  if (acc != 0 || pad > 2)
    return 0;
  *outlen = o;
  return 1;
}

int
gqi_mldsa_key_from_pem (const void *pem, size_t len, struct gqi_mldsa_key *key)
{
  static const char begin[] = "-----BEGIN PRIVATE KEY-----";
  static const char endm[] = "-----END PRIVATE KEY-----";
  const char *text = pem, *b = NULL, *e = NULL, *t;
  uint8_t *der;
  size_t dl = 0, i;
  int r;

  if (key == NULL)
    return GQ_ERR_INVAL;
  memset (key, 0, sizeof *key);
  if (text == NULL)
    return GQ_ERR_UNSUPPORTED;
  for (i = 0; i + sizeof begin - 1 <= len; i++)
    if (memcmp (text + i, begin, sizeof begin - 1) == 0)
      {
        b = text + i + sizeof begin - 1;
        break;
      }
  if (b == NULL)
    return GQ_ERR_UNSUPPORTED;
  for (t = b; (size_t) (text + len - t) >= sizeof endm - 1; t++)
    if (memcmp (t, endm, sizeof endm - 1) == 0)
      {
        e = t;
        break;
      }
  if (e == NULL)
    return GQ_ERR_UNSUPPORTED;
  der = malloc ((size_t) (e - b) / 4 * 3 + 3);
  if (der == NULL)
    return GQ_ERR_NOMEM;
  if (!b64_decode (b, (size_t) (e - b), der, (size_t) (e - b) / 4 * 3 + 3, &dl))
    {
      /* Some of the key may have been decoded before it failed.  */
      gq_wipe (der, (size_t) (e - b) / 4 * 3 + 3);
      free (der);
      return GQ_ERR_UNSUPPORTED;
    }
  r = gqi_mldsa_key_from_pkcs8 (der, dl, key);
  gq_wipe (der, dl);
  free (der);
  return r;
}

/* ------------------------------------------------------------------ */
/* Certificates                                                       */
/* ------------------------------------------------------------------ */

int
gqi_mldsa_pk_from_cert (const uint8_t *cert, size_t len, unsigned *scheme,
                        uint8_t *pk, size_t *pk_len)
{
  const uint8_t *p, *end, *v, *spki, *se, *alg, *ae, *bs;
  unsigned tag, sc;
  size_t n, sn, an, bn, i;

  if (cert == NULL || scheme == NULL || pk == NULL || pk_len == NULL)
    return GQ_ERR_INVAL;

  /* Certificate ::= SEQUENCE { tbsCertificate, ... }; the TBS is
     [0] version OPTIONAL, serialNumber, signature, issuer, validity,
     subject, subjectPublicKeyInfo.  This walks that far and no further:
     what is being asked is where the key is, not whether the certificate
     is any good, which is the job of the code that validates it.  */
  p = cert;
  end = cert + len;
  if (!tlv (&p, end, &tag, &v, &n) || tag != 0x30 || p != end)
    return GQ_ERR_UNSUPPORTED;
  p = v;
  end = v + n;
  if (!tlv (&p, end, &tag, &v, &n) || tag != 0x30)
    return GQ_ERR_UNSUPPORTED;
  p = v;
  end = v + n;
  if (end - p > 0 && p[0] == 0xa0 && !tlv (&p, end, &tag, &v, &n))
    return GQ_ERR_UNSUPPORTED;
  if (!tlv (&p, end, &tag, &v, &n) || tag != 0x02)	/* serialNumber.  */
    return GQ_ERR_UNSUPPORTED;
  for (i = 0; i < 4; i++)	/* signature, issuer, validity, subject.  */
    if (!tlv (&p, end, &tag, &v, &n) || tag != 0x30)
      return GQ_ERR_UNSUPPORTED;
  if (!tlv (&p, end, &tag, &spki, &sn) || tag != 0x30)
    return GQ_ERR_UNSUPPORTED;

  /* SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }.  */
  se = spki + sn;
  p = spki;
  if (!tlv (&p, se, &tag, &alg, &an) || tag != 0x30)
    return GQ_ERR_UNSUPPORTED;
  ae = alg + an;
  {
    const uint8_t *q = alg;

    if (!tlv (&q, ae, &tag, &v, &n) || tag != 0x06)
      return GQ_ERR_UNSUPPORTED;
    sc = scheme_of_oid (v, n);
    if (sc == 0)
      return GQ_ERR_UNSUPPORTED;
    if (q != ae)			/* Parameters must be absent.  */
      return GQ_ERR_CERT;
  }
  if (!tlv (&p, se, &tag, &bs, &bn) || tag != 0x03 || p != se)
    return GQ_ERR_CERT;
  if (bn != 1 + gqi_mldsa_pk_len (sc) || bs[0] != 0)
    return GQ_ERR_CERT;
  memcpy (pk, bs + 1, bn - 1);
  *pk_len = bn - 1;
  *scheme = sc;
  return GQ_OK;
}
