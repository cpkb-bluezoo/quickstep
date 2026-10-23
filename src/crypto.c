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

#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

#include <quickstep/status.h>
#include <quickstep/crypto.h>

#include "crypto_int.h"
#include "gettext.h"

#define GQ_MIN_GCRYPT "1.12.0"

void
gq_wipe (void *secret, size_t len)
{
  volatile uint8_t *p = secret;

  while (len--)
    *p++ = 0;
}

int
gq_ct_equal (const void *a, const void *b, size_t n)
{
  const uint8_t *x = a, *y = b;
  uint8_t diff = 0;
  size_t i;

  for (i = 0; i < n; i++)
    diff |= x[i] ^ y[i];
  return diff == 0;
}

int
gq_crypto_init (void)
{
  gqi_i18n_init ();
  if (gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
    return GQ_OK;
  if (!gcry_check_version (GQ_MIN_GCRYPT))
    return GQ_ERR_CRYPTO;
  /* Try for a secure-memory pool before secrets are allocated.  If the
     platform cannot provide one, libgcrypt falls back to ordinary memory;
     an application that needs stronger guarantees initialises libgcrypt
     itself before the first call here.  */
  (void) gcry_control (GCRYCTL_INIT_SECMEM, 32768, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  return GQ_OK;
}

int
gq_random (void *buf, size_t len)
{
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  gcry_randomize (buf, len, GCRY_STRONG_RANDOM);
  return GQ_OK;
}

/* ------------------------------------------------------------------ */
/* Hashes and HMAC                                                    */
/* ------------------------------------------------------------------ */

size_t
gq_hash_size (enum gq_hash alg)
{
  switch (alg)
    {
    case GQ_HASH_SHA256: return 32;
    case GQ_HASH_SHA384: return 48;
    default:             return 0;
    }
}

static int
hash_algo (enum gq_hash alg)
{
  return alg == GQ_HASH_SHA256 ? GCRY_MD_SHA256
       : alg == GQ_HASH_SHA384 ? GCRY_MD_SHA384 : 0;
}

int
gq_hash_compute (enum gq_hash alg, const void *data, size_t len,
                 uint8_t *out, size_t outlen)
{
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  if (gq_hash_size (alg) == 0)
    return GQ_ERR_UNSUPPORTED;
  if (outlen != gq_hash_size (alg) || (data == NULL && len > 0))
    return GQ_ERR_INVAL;
  gcry_md_hash_buffer (hash_algo (alg), out, data, len);
  return GQ_OK;
}

/* HMAC is done in one call, from a list of buffers of which the first is the
   key, and not with a MAC context of our own.  libgcrypt opens the context it
   uses inside that call without polling for entropy, which a context opened
   through its MAC interface does: with libgcrypt's own random number
   generator the poll cost a few microseconds, a handshake did dozens of
   HMACs (every HKDF step is one or more), and the polls came to two fifths
   of its CPU time.  Nothing is kept between calls, so there is no state to
   share between threads and no key left behind.  */
static const uint8_t no_bytes[1];

static void
iov_set (gcry_buffer_t *b, const void *data, size_t len)
{
  memset (b, 0, sizeof *b);
  /* The field is not const, though libgcrypt only reads it.  An empty
     buffer still gets a real pointer: libgcrypt adds an offset to it.  */
  b->data = (void *) (uintptr_t) (len ? data : (const void *) no_bytes);
  b->len = len;
}

static int
hmac_iov (enum gq_hash alg, const gcry_buffer_t *iov, int n, uint8_t *out)
{
  return gcry_md_hash_buffers (hash_algo (alg), GCRY_MD_FLAG_HMAC, out, iov,
                               n) ? GQ_ERR_CRYPTO : GQ_OK;
}

int
gq_hmac (enum gq_hash alg, const void *key, size_t keylen,
         const void *data, size_t len, uint8_t *out, size_t outlen)
{
  gcry_buffer_t iov[2];
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  if (gq_hash_size (alg) == 0)
    return GQ_ERR_UNSUPPORTED;
  if (outlen != gq_hash_size (alg) || (data == NULL && len > 0))
    return GQ_ERR_INVAL;

  iov_set (&iov[0], key, keylen);
  iov_set (&iov[1], data, len);
  return hmac_iov (alg, iov, 2, out);
}

/* ------------------------------------------------------------------ */
/* HKDF                                                               */
/* ------------------------------------------------------------------ */

int
gq_hkdf_extract (enum gq_hash alg, const void *salt, size_t saltlen,
                 const void *ikm, size_t ikmlen,
                 uint8_t *prk, size_t prklen)
{
  uint8_t zeros[64];
  size_t hl = gq_hash_size (alg);

  if (hl == 0)
    return GQ_ERR_UNSUPPORTED;
  if (saltlen == 0)
    {
      memset (zeros, 0, hl);
      salt = zeros;
      saltlen = hl;
    }
  return gq_hmac (alg, salt, saltlen, ikm, ikmlen, prk, prklen);
}

int
gq_hkdf_expand (enum gq_hash alg, const void *prk, size_t prklen,
                const void *info, size_t infolen,
                uint8_t *out, size_t outlen)
{
  uint8_t t[64];
  size_t hl = gq_hash_size (alg);
  size_t done = 0;
  uint8_t counter = 1;
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  if (hl == 0)
    return GQ_ERR_UNSUPPORTED;
  if (prklen < hl || (info == NULL && infolen > 0)
      || outlen > 255 * hl || (out == NULL && outlen > 0))
    return GQ_ERR_INVAL;

  /* T(n) = HMAC (PRK, T(n-1) | info | n).  */
  while (done < outlen && r == GQ_OK)
    {
      gcry_buffer_t iov[4];
      int n = 0;
      size_t take = outlen - done < hl ? outlen - done : hl;

      iov_set (&iov[n++], prk, prklen);
      if (done > 0)
        iov_set (&iov[n++], t, hl);
      if (infolen > 0)
        iov_set (&iov[n++], info, infolen);
      iov_set (&iov[n++], &counter, 1);
      r = hmac_iov (alg, iov, n, t);
      if (r == GQ_OK)
        {
          memcpy (out + done, t, take);
          done += take;
          counter++;
        }
    }
  gq_wipe (t, sizeof t);
  return r;
}

int
gq_hkdf_expand_label_v (enum gq_hash alg, int dtls, const void *secret,
                        size_t secretlen, const char *label,
                        const void *context, size_t contextlen, uint8_t *out,
                        size_t outlen)
{
  /* struct { uint16 length; opaque label<7..255>; opaque context<0..255>; } */
  uint8_t info[2 + 1 + 255 + 1 + 255];
  static const char tls_prefix[] = "tls13 ", dtls_prefix[] = "dtls13";
  const char *prefix = dtls ? dtls_prefix : tls_prefix;
  size_t plen = dtls ? sizeof dtls_prefix - 1 : sizeof tls_prefix - 1;
  size_t llen, off = 0;

  if (label == NULL || outlen > 0xffff || contextlen > 255
      || (context == NULL && contextlen > 0))
    return GQ_ERR_INVAL;
  llen = strlen (label);
  if (plen + llen > 255)
    return GQ_ERR_INVAL;

  info[off++] = (uint8_t) (outlen >> 8);
  info[off++] = (uint8_t) outlen;
  info[off++] = (uint8_t) (plen + llen);
  memcpy (info + off, prefix, plen);
  off += plen;
  memcpy (info + off, label, llen);
  off += llen;
  info[off++] = (uint8_t) contextlen;
  if (contextlen)
    memcpy (info + off, context, contextlen);
  off += contextlen;

  return gq_hkdf_expand (alg, secret, secretlen, info, off, out, outlen);
}

int
gq_hkdf_expand_label (enum gq_hash alg, const void *secret, size_t secretlen,
                      const char *label, const void *context,
                      size_t contextlen, uint8_t *out, size_t outlen)
{
  return gq_hkdf_expand_label_v (alg, 0, secret, secretlen, label, context,
                                 contextlen, out, outlen);
}

/* ------------------------------------------------------------------ */
/* AEAD and header protection                                         */
/* ------------------------------------------------------------------ */

size_t
gq_aead_key_size (enum gq_aead alg)
{
  switch (alg)
    {
    case GQ_AEAD_AES_128_GCM:		return 16;
    case GQ_AEAD_AES_256_GCM:		return 32;
    case GQ_AEAD_CHACHA20_POLY1305:	return 32;
    default:				return 0;
    }
}

enum gq_hash
gq_aead_hash (enum gq_aead alg)
{
  return alg == GQ_AEAD_AES_256_GCM ? GQ_HASH_SHA384 : GQ_HASH_SHA256;
}

static int
aead_open_handle (enum gq_aead alg, gcry_cipher_hd_t *h)
{
  int algo, mode;

  switch (alg)
    {
    case GQ_AEAD_AES_128_GCM:
      algo = GCRY_CIPHER_AES128;
      mode = GCRY_CIPHER_MODE_GCM;
      break;
    case GQ_AEAD_AES_256_GCM:
      algo = GCRY_CIPHER_AES256;
      mode = GCRY_CIPHER_MODE_GCM;
      break;
    case GQ_AEAD_CHACHA20_POLY1305:
      algo = GCRY_CIPHER_CHACHA20;
      mode = GCRY_CIPHER_MODE_POLY1305;
      break;
    default:
      return GQ_ERR_UNSUPPORTED;
    }
  return gcry_cipher_open (h, algo, mode, 0) ? GQ_ERR_CRYPTO : GQ_OK;
}

static int
aead_setup (enum gq_aead alg, gcry_cipher_hd_t *h, const uint8_t *key,
            size_t keylen, const uint8_t *nonce, const void *aad,
            size_t aadlen)
{
  int r = aead_open_handle (alg, h);

  if (r != GQ_OK)
    return r;
  if (gcry_cipher_setkey (*h, key, keylen)
      || gcry_cipher_setiv (*h, nonce, GQ_AEAD_NONCE_LEN)
      || (aadlen > 0 && gcry_cipher_authenticate (*h, aad, aadlen)))
    {
      gcry_cipher_close (*h);
      return GQ_ERR_CRYPTO;
    }
  return GQ_OK;
}

int
gq_aead_seal (enum gq_aead alg, const uint8_t *key, size_t keylen,
              const uint8_t *nonce, const void *aad, size_t aadlen,
              const void *pt, size_t ptlen, uint8_t *out, size_t outlen)
{
  gcry_cipher_hd_t h;
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  if (gq_aead_key_size (alg) == 0)
    return GQ_ERR_UNSUPPORTED;
  if (keylen != gq_aead_key_size (alg) || key == NULL || nonce == NULL
      || (aad == NULL && aadlen > 0) || (pt == NULL && ptlen > 0)
      || outlen != ptlen + GQ_AEAD_TAG_LEN)
    return GQ_ERR_INVAL;

  r = aead_setup (alg, &h, key, keylen, nonce, aad, aadlen);
  if (r != GQ_OK)
    return r;
  if (ptlen > 0 && gcry_cipher_encrypt (h, out, ptlen, pt, ptlen))
    r = GQ_ERR_CRYPTO;
  else if (gcry_cipher_gettag (h, out + ptlen, GQ_AEAD_TAG_LEN))
    r = GQ_ERR_CRYPTO;
  gcry_cipher_close (h);
  return r;
}

int
gq_aead_open (enum gq_aead alg, const uint8_t *key, size_t keylen,
              const uint8_t *nonce, const void *aad, size_t aadlen,
              const void *ct, size_t ctlen, uint8_t *out, size_t outlen)
{
  gcry_cipher_hd_t h;
  size_t ptlen;
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  if (gq_aead_key_size (alg) == 0)
    return GQ_ERR_UNSUPPORTED;
  if (ctlen < GQ_AEAD_TAG_LEN)
    return GQ_ERR_CRYPTO;
  ptlen = ctlen - GQ_AEAD_TAG_LEN;
  if (keylen != gq_aead_key_size (alg) || key == NULL || nonce == NULL
      || (aad == NULL && aadlen > 0) || ct == NULL || outlen != ptlen)
    return GQ_ERR_INVAL;

  r = aead_setup (alg, &h, key, keylen, nonce, aad, aadlen);
  if (r != GQ_OK)
    return r;
  if (ptlen > 0 && gcry_cipher_decrypt (h, out, ptlen, ct, ptlen))
    r = GQ_ERR_CRYPTO;
  else if (gcry_cipher_checktag (h, (const uint8_t *) ct + ptlen,
                                 GQ_AEAD_TAG_LEN))
    r = GQ_ERR_CRYPTO;
  gcry_cipher_close (h);
  if (r != GQ_OK && ptlen > 0)
    gq_wipe (out, ptlen);
  return r;
}

/* A handle for the header protection mask of ALG: the ChaCha20 block
   function, or AES in ECB mode for one block.  */
static int
hp_open_handle (enum gq_aead alg, gcry_cipher_hd_t *h)
{
  if (alg == GQ_AEAD_CHACHA20_POLY1305)
    return gcry_cipher_open (h, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM,
                             0) ? GQ_ERR_CRYPTO : GQ_OK;
  return gcry_cipher_open (h, alg == GQ_AEAD_AES_128_GCM
                              ? GCRY_CIPHER_AES128 : GCRY_CIPHER_AES256,
                           GCRY_CIPHER_MODE_ECB, 0) ? GQ_ERR_CRYPTO : GQ_OK;
}

/* The mask, from a handle whose key is set.  */
static int
hp_mask_with (gcry_cipher_hd_t h, enum gq_aead alg,
              const uint8_t sample[GQ_HP_SAMPLE_LEN],
              uint8_t mask[GQ_HP_MASK_LEN])
{
  uint8_t block[GQ_HP_SAMPLE_LEN];

  if (alg == GQ_AEAD_CHACHA20_POLY1305)
    {
      /* Counter is the first four sample bytes (little endian) and the
         nonce the remaining twelve; libgcrypt's ChaCha20 accepts exactly
         that 16-byte layout through setiv.  Encrypting zeros yields the
         keystream.  */
      static const uint8_t zeros[GQ_HP_MASK_LEN];

      if (gcry_cipher_setiv (h, sample, GQ_HP_SAMPLE_LEN)
          || gcry_cipher_encrypt (h, mask, GQ_HP_MASK_LEN, zeros,
                                  GQ_HP_MASK_LEN))
        return GQ_ERR_CRYPTO;
      return GQ_OK;
    }
  if (gcry_cipher_encrypt (h, block, sizeof block, sample, GQ_HP_SAMPLE_LEN))
    return GQ_ERR_CRYPTO;
  memcpy (mask, block, GQ_HP_MASK_LEN);
  gq_wipe (block, sizeof block);
  return GQ_OK;
}

int
gq_hp_mask (enum gq_aead alg, const uint8_t *hp_key, size_t keylen,
            const uint8_t sample[GQ_HP_SAMPLE_LEN],
            uint8_t mask[GQ_HP_MASK_LEN])
{
  gcry_cipher_hd_t h;
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  if (gq_aead_key_size (alg) == 0)
    return GQ_ERR_UNSUPPORTED;
  if (keylen != gq_aead_key_size (alg) || hp_key == NULL)
    return GQ_ERR_INVAL;

  if (hp_open_handle (alg, &h) != GQ_OK)
    return GQ_ERR_CRYPTO;
  if (gcry_cipher_setkey (h, hp_key, keylen))
    r = GQ_ERR_CRYPTO;
  else
    r = hp_mask_with (h, alg, sample, mask);
  gcry_cipher_close (h);
  return r;
}

/* ------------------------------------------------------------------ */
/* Contexts kept for the life of a key                                */
/* ------------------------------------------------------------------ */

struct gqi_cipher
{
  unsigned refs;
  enum gq_aead alg;
  int hp;			/* Header protection, not the AEAD.  */
  size_t keylen;
  uint8_t key[32];		/* What the handle's key was set from.  */
  gcry_cipher_hd_t h;
};

static gqi_cipher *
cipher_new (enum gq_aead alg, int hp, const uint8_t *key, size_t keylen)
{
  gqi_cipher *c;
  int r;

  if (gq_crypto_init () != GQ_OK || key == NULL
      || gq_aead_key_size (alg) == 0 || keylen != gq_aead_key_size (alg)
      || keylen > sizeof c->key)
    return NULL;
  c = calloc (1, sizeof *c);
  if (c == NULL)
    return NULL;
  r = hp ? hp_open_handle (alg, &c->h) : aead_open_handle (alg, &c->h);
  if (r != GQ_OK)
    {
      free (c);
      return NULL;
    }
  if (gcry_cipher_setkey (c->h, key, keylen))
    {
      gcry_cipher_close (c->h);
      free (c);
      return NULL;
    }
  c->refs = 1;
  c->alg = alg;
  c->hp = hp;
  c->keylen = keylen;
  memcpy (c->key, key, keylen);
  return c;
}

gqi_cipher *
gqi_aead_new (enum gq_aead alg, const uint8_t *key, size_t keylen)
{
  return cipher_new (alg, 0, key, keylen);
}

gqi_cipher *
gqi_hp_new (enum gq_aead alg, const uint8_t *hp_key, size_t keylen)
{
  return cipher_new (alg, 1, hp_key, keylen);
}

gqi_cipher *
gqi_cipher_ref (gqi_cipher *c)
{
  if (c)
    c->refs++;
  return c;
}

void
gqi_cipher_unref (gqi_cipher *c)
{
  if (c == NULL || --c->refs > 0)
    return;
  gcry_cipher_close (c->h);
  gq_wipe (c, sizeof *c);
  free (c);
}

int
gqi_cipher_is (const gqi_cipher *c, enum gq_aead alg, const uint8_t *key,
               size_t keylen)
{
  return c != NULL && c->alg == alg && c->keylen == keylen && key != NULL
         && gq_ct_equal (c->key, key, keylen);
}

int
gqi_aead_seal (gqi_cipher *c, const uint8_t *nonce, const void *aad,
               size_t aadlen, const void *pt, size_t ptlen, uint8_t *out,
               size_t outlen)
{
  if (c == NULL || c->hp || nonce == NULL || (aad == NULL && aadlen > 0)
      || (pt == NULL && ptlen > 0) || outlen != ptlen + GQ_AEAD_TAG_LEN)
    return GQ_ERR_INVAL;
  if (gcry_cipher_reset (c->h)
      || gcry_cipher_setiv (c->h, nonce, GQ_AEAD_NONCE_LEN)
      || (aadlen > 0 && gcry_cipher_authenticate (c->h, aad, aadlen))
      || (ptlen > 0 && gcry_cipher_encrypt (c->h, out, ptlen, pt, ptlen))
      || gcry_cipher_gettag (c->h, out + ptlen, GQ_AEAD_TAG_LEN))
    return GQ_ERR_CRYPTO;
  return GQ_OK;
}

int
gqi_aead_open (gqi_cipher *c, const uint8_t *nonce, const void *aad,
               size_t aadlen, const void *ct, size_t ctlen, uint8_t *out,
               size_t outlen)
{
  size_t ptlen;
  int r = GQ_OK;

  if (c == NULL || c->hp)
    return GQ_ERR_INVAL;
  if (ctlen < GQ_AEAD_TAG_LEN)
    return GQ_ERR_CRYPTO;
  ptlen = ctlen - GQ_AEAD_TAG_LEN;
  if (nonce == NULL || (aad == NULL && aadlen > 0) || ct == NULL
      || outlen != ptlen)
    return GQ_ERR_INVAL;
  if (gcry_cipher_reset (c->h)
      || gcry_cipher_setiv (c->h, nonce, GQ_AEAD_NONCE_LEN)
      || (aadlen > 0 && gcry_cipher_authenticate (c->h, aad, aadlen)))
    return GQ_ERR_CRYPTO;
  if (ptlen > 0 && gcry_cipher_decrypt (c->h, out, ptlen, ct, ptlen))
    r = GQ_ERR_CRYPTO;
  else if (gcry_cipher_checktag (c->h, (const uint8_t *) ct + ptlen,
                                 GQ_AEAD_TAG_LEN))
    r = GQ_ERR_CRYPTO;
  if (r != GQ_OK && ptlen > 0)
    gq_wipe (out, ptlen);
  return r;
}

int
gqi_hp_mask (gqi_cipher *c, const uint8_t sample[GQ_HP_SAMPLE_LEN],
             uint8_t mask[GQ_HP_MASK_LEN])
{
  if (c == NULL || !c->hp)
    return GQ_ERR_INVAL;
  return hp_mask_with (c->h, c->alg, sample, mask);
}

int
gqi_seal (gqi_cipher *ctx, enum gq_aead alg, const uint8_t *key,
          size_t keylen, const uint8_t *nonce, const void *aad, size_t aadlen,
          const void *pt, size_t ptlen, uint8_t *out, size_t outlen)
{
  if (ctx != NULL && !ctx->hp && gqi_cipher_is (ctx, alg, key, keylen))
    return gqi_aead_seal (ctx, nonce, aad, aadlen, pt, ptlen, out, outlen);
  return gq_aead_seal (alg, key, keylen, nonce, aad, aadlen, pt, ptlen, out,
                       outlen);
}

int
gqi_open (gqi_cipher *ctx, enum gq_aead alg, const uint8_t *key,
          size_t keylen, const uint8_t *nonce, const void *aad, size_t aadlen,
          const void *ct, size_t ctlen, uint8_t *out, size_t outlen)
{
  if (ctx != NULL && !ctx->hp && gqi_cipher_is (ctx, alg, key, keylen))
    return gqi_aead_open (ctx, nonce, aad, aadlen, ct, ctlen, out, outlen);
  return gq_aead_open (alg, key, keylen, nonce, aad, aadlen, ct, ctlen, out,
                       outlen);
}

int
gqi_mask (gqi_cipher *ctx, enum gq_aead alg, const uint8_t *hp_key,
          size_t keylen, const uint8_t sample[GQ_HP_SAMPLE_LEN],
          uint8_t mask[GQ_HP_MASK_LEN])
{
  if (ctx != NULL && ctx->hp && gqi_cipher_is (ctx, alg, hp_key, keylen))
    return gqi_hp_mask (ctx, sample, mask);
  return gq_hp_mask (alg, hp_key, keylen, sample, mask);
}

static int
aes128_ecb (const uint8_t key[16], const uint8_t block[16], uint8_t out[16],
           int decrypt)
{
  gcry_cipher_hd_t h;
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  if (key == NULL || block == NULL || out == NULL)
    return GQ_ERR_INVAL;
  if (gcry_cipher_open (&h, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0))
    return GQ_ERR_CRYPTO;
  r = GQ_OK;
  if (gcry_cipher_setkey (h, key, 16)
      || (decrypt ? gcry_cipher_decrypt (h, out, 16, block, 16)
                 : gcry_cipher_encrypt (h, out, 16, block, 16)))
    r = GQ_ERR_CRYPTO;
  gcry_cipher_close (h);
  return r;
}

int
gq_aes128_ecb_encrypt (const uint8_t key[16], const uint8_t block[16],
                       uint8_t out[16])
{
  return aes128_ecb (key, block, out, 0);
}

int
gq_aes128_ecb_decrypt (const uint8_t key[16], const uint8_t block[16],
                       uint8_t out[16])
{
  return aes128_ecb (key, block, out, 1);
}

int
gq_random_key (void *buf, size_t len)
{
  int r = gq_crypto_init ();

  if (r != GQ_OK)
    return r;
  gcry_randomize (buf, len, GCRY_VERY_STRONG_RANDOM);
  return GQ_OK;
}
