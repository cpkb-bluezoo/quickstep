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

/* Cipher contexts kept open for the life of a key.

   gq_aead_seal, gq_aead_open and gq_hp_mask open a libgcrypt context, set
   the key and close it again on every call.  That is the right shape for
   something done once, and several times the cost of the encryption for
   something done to every packet or record: an allocation, a key schedule
   (and for GCM the hash table), and with libgcrypt's own random number
   generator an entropy poll in every open.  A context made once for a key
   does the same work with a reset and a new IV.

   A context remembers the key it was made for, and refuses to be used with
   another (gqi_cipher_is): the caller checks, and falls back to the
   one-off calls, so a key struct that was changed behind its context's back
   is slower, never wrong.

   Contexts are counted, not owned: a key struct that moves from one place
   to another takes its contexts with it, and the one that is derived from
   it by a key update shares the header protection context, whose key does
   not change.  They are not thread safe; a connection is used by one
   thread at a time.  Internal: not exported.  */

#ifndef QUICKSTEP_CRYPTO_INT_H
#define QUICKSTEP_CRYPTO_INT_H

#include <stddef.h>
#include <stdint.h>

#include <quickstep/crypto.h>

typedef struct gqi_cipher gqi_cipher;

/* A context for ALG's AEAD under KEY, or for its header protection mask
   under HP_KEY.  Reference count 1.  NULL if it cannot be made; callers go
   on without.  */
gqi_cipher *gqi_aead_new (enum gq_aead alg, const uint8_t *key,
                          size_t keylen);
gqi_cipher *gqi_hp_new (enum gq_aead alg, const uint8_t *hp_key,
                        size_t keylen);

/* Another holder of C (NULL is fine); and let go of one (NULL is fine).
   The last to let go closes the context and wipes its copy of the key.  */
gqi_cipher *gqi_cipher_ref (gqi_cipher *c);
void gqi_cipher_unref (gqi_cipher *c);

/* Is C a context for ALG and KEY?  */
int gqi_cipher_is (const gqi_cipher *c, enum gq_aead alg, const uint8_t *key,
                   size_t keylen);

/* As gq_aead_seal, gq_aead_open and gq_hp_mask, with the key already set.  */
int gqi_aead_seal (gqi_cipher *c, const uint8_t *nonce, const void *aad,
                   size_t aadlen, const void *pt, size_t ptlen, uint8_t *out,
                   size_t outlen);
int gqi_aead_open (gqi_cipher *c, const uint8_t *nonce, const void *aad,
                   size_t aadlen, const void *ct, size_t ctlen, uint8_t *out,
                   size_t outlen);
int gqi_hp_mask (gqi_cipher *c, const uint8_t sample[GQ_HP_SAMPLE_LEN],
                 uint8_t mask[GQ_HP_MASK_LEN]);

/* What the holder of a key calls: gq_aead_seal, gq_aead_open and gq_hp_mask
   with the same arguments, and in front of them CTX, the holder's context
   for the key (NULL if it has none).  If CTX is for ALG and KEY it is used;
   otherwise (none, or the key was changed behind its back) a context is set
   up for the call.  */
int gqi_seal (gqi_cipher *ctx, enum gq_aead alg, const uint8_t *key,
              size_t keylen, const uint8_t *nonce, const void *aad,
              size_t aadlen, const void *pt, size_t ptlen, uint8_t *out,
              size_t outlen);
int gqi_open (gqi_cipher *ctx, enum gq_aead alg, const uint8_t *key,
              size_t keylen, const uint8_t *nonce, const void *aad,
              size_t aadlen, const void *ct, size_t ctlen, uint8_t *out,
              size_t outlen);
int gqi_mask (gqi_cipher *ctx, enum gq_aead alg, const uint8_t *hp_key,
              size_t keylen, const uint8_t sample[GQ_HP_SAMPLE_LEN],
              uint8_t mask[GQ_HP_MASK_LEN]);

#endif /* QUICKSTEP_CRYPTO_INT_H */
