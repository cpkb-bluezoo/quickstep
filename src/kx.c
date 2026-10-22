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

#include <string.h>

#include <gcrypt.h>

#include <quickstep/status.h>
#include <quickstep/crypto.h>
#include <quickstep/kx.h>

#define TRY(expr) do { int r_ = (expr); if (r_ != GQ_OK) return r_; } while (0)

/* Description of a group as its classical and post-quantum halves.  The
   pure ML-KEM groups have no classical half: ec_algo is 0 and its sizes
   are 0, which makes join and split below copy it as an empty part.  */
struct group
{
  uint16_t id;
  int ec_algo;			/* gcry_kem algo, 0 if none.  */
  const char *curve;		/* libgcrypt curve name of a NIST curve.  */
  size_t ec_pub, ec_sec;	/* Point (or X25519 key) and scalar sizes.  */
  size_t ec_raw, ec_out;	/* Raw KEM shared size, and bytes we keep.  */
  int is_x25519;
  int kem_algo;			/* ML-KEM algo, 0 if none.  */
  size_t kem_pub, kem_sec, kem_ct;
  int pq_first;			/* Wire and secret order (RFC 10024).  */
};

#define MLKEM_SS 32

static const struct group groups[] = {
  { GQ_GROUP_X25519, GCRY_KEM_RAW_X25519, NULL, 32, 32, 32, 32, 1,
    0, 0, 0, 0, 0 },
  { GQ_GROUP_SECP256R1, GCRY_KEM_RAW_P256R1, "NIST P-256", 65, 32, 65, 32, 0,
    0, 0, 0, 0, 0 },
  { GQ_GROUP_SECP384R1, GCRY_KEM_RAW_P384R1, "NIST P-384", 97, 48, 97, 48, 0,
    0, 0, 0, 0, 0 },
  { GQ_GROUP_X25519_MLKEM768, GCRY_KEM_RAW_X25519, NULL, 32, 32, 32, 32, 1,
    GCRY_KEM_MLKEM768, GCRY_KEM_MLKEM768_PUBKEY_LEN,
    GCRY_KEM_MLKEM768_SECKEY_LEN, GCRY_KEM_MLKEM768_CIPHER_LEN, 1 },
  { GQ_GROUP_SECP256R1_MLKEM768, GCRY_KEM_RAW_P256R1, "NIST P-256", 65, 32, 65, 32, 0,
    GCRY_KEM_MLKEM768, GCRY_KEM_MLKEM768_PUBKEY_LEN,
    GCRY_KEM_MLKEM768_SECKEY_LEN, GCRY_KEM_MLKEM768_CIPHER_LEN, 0 },
  { GQ_GROUP_SECP384R1_MLKEM1024, GCRY_KEM_RAW_P384R1, "NIST P-384", 97, 48, 97, 48, 0,
    GCRY_KEM_MLKEM1024, GCRY_KEM_MLKEM1024_PUBKEY_LEN,
    GCRY_KEM_MLKEM1024_SECKEY_LEN, GCRY_KEM_MLKEM1024_CIPHER_LEN, 0 },
  { GQ_GROUP_MLKEM512, 0, NULL, 0, 0, 0, 0, 0,
    GCRY_KEM_MLKEM512, GCRY_KEM_MLKEM512_PUBKEY_LEN,
    GCRY_KEM_MLKEM512_SECKEY_LEN, GCRY_KEM_MLKEM512_CIPHER_LEN, 0 },
  { GQ_GROUP_MLKEM768, 0, NULL, 0, 0, 0, 0, 0,
    GCRY_KEM_MLKEM768, GCRY_KEM_MLKEM768_PUBKEY_LEN,
    GCRY_KEM_MLKEM768_SECKEY_LEN, GCRY_KEM_MLKEM768_CIPHER_LEN, 0 },
  { GQ_GROUP_MLKEM1024, 0, NULL, 0, 0, 0, 0, 0,
    GCRY_KEM_MLKEM1024, GCRY_KEM_MLKEM1024_PUBKEY_LEN,
    GCRY_KEM_MLKEM1024_SECKEY_LEN, GCRY_KEM_MLKEM1024_CIPHER_LEN, 0 }
};

static const struct group *
find_group (unsigned id)
{
  size_t i;

  if (!gq_policy_allows_group (id))
    return NULL;
  for (i = 0; i < sizeof groups / sizeof groups[0]; i++)
    if (groups[i].id == id)
      return &groups[i];
  return NULL;
}

size_t
gq_kx_client_share_len (unsigned group)
{
  const struct group *g = find_group (group);

  return g ? g->ec_pub + g->kem_pub : 0;
}

size_t
gq_kx_server_share_len (unsigned group)
{
  const struct group *g = find_group (group);

  return g ? g->ec_pub + g->kem_ct : 0;
}

size_t
gq_kx_shared_len (unsigned group)
{
  const struct group *g = find_group (group);

  return g ? g->ec_out + (g->kem_algo ? MLKEM_SS : 0) : 0;
}

void
gq_kx_key_wipe (gq_kx_key *key)
{
  gq_wipe (key, sizeof *key);
}

static int
all_zero (const uint8_t *p, size_t n)
{
  uint8_t acc = 0;

  while (n--)
    acc |= *p++;
  return acc == 0;
}

/* The peer's point on a NIST curve must be a point of that curve, in the
   uncompressed form with both coordinates reduced (RFC 8446 section
   4.2.8.2).  libgcrypt's ECDH takes whatever it is given before 1.12.4 and
   an unchecked point is an invalid-curve attack, so it is checked here
   whatever the version.  X25519 accepts every 32 bytes and its low-order
   results are caught after the fact (ec_extract).  */
static int
ec_peer_ok (const struct group *g, const uint8_t *q)
{
  gcry_ctx_t ctx = NULL;
  gcry_mpi_t x = NULL, y = NULL, p = NULL;
  gcry_mpi_point_t pt = NULL;
  size_t c = (g->ec_pub - 1) / 2;
  int ok = 0;

  if (g->curve == NULL)
    return 1;
  if (q[0] != 0x04 || gcry_mpi_ec_new (&ctx, NULL, g->curve))
    return 0;
  if (gcry_mpi_scan (&x, GCRYMPI_FMT_USG, q + 1, c, NULL) == 0
      && gcry_mpi_scan (&y, GCRYMPI_FMT_USG, q + 1 + c, c, NULL) == 0)
    {
      p = gcry_mpi_ec_get_mpi ("p", ctx, 1);
      pt = gcry_mpi_point_new (0);
    }
  if (p != NULL && pt != NULL && gcry_mpi_cmp (x, p) < 0
      && gcry_mpi_cmp (y, p) < 0)
    {
      gcry_mpi_point_set (pt, x, y, GCRYMPI_CONST_ONE);
      ok = gcry_mpi_ec_curve_point (pt, ctx);
    }
  gcry_mpi_point_release (pt);
  gcry_mpi_release (x);
  gcry_mpi_release (y);
  gcry_mpi_release (p);
  gcry_ctx_release (ctx);
  return ok;
}

/* ECDH half: the classical shared secret from KEM raw output.  For the
   NIST curves libgcrypt returns the whole point (0x04 x y); TLS wants x
   alone (RFC 8446 section 7.4.2).  X25519 outputs are checked for the
   all-zero result produced by low-order points.  */
static int
ec_extract (const struct group *g, const uint8_t *raw, uint8_t *out)
{
  if (g->is_x25519)
    {
      if (all_zero (raw, 32))
        return GQ_ERR_CRYPTO;
      memcpy (out, raw, 32);
    }
  else
    {
      if (raw[0] != 0x04)
        return GQ_ERR_CRYPTO;
      memcpy (out, raw + 1, g->ec_out);
    }
  return GQ_OK;
}

/* Assemble two halves in the group's order.  */
static void
join (const struct group *g, uint8_t *dst, const uint8_t *ec, size_t ec_len,
      const uint8_t *pq, size_t pq_len)
{
  if (g->pq_first)
    {
      memcpy (dst, pq, pq_len);
      memcpy (dst + pq_len, ec, ec_len);
    }
  else
    {
      memcpy (dst, ec, ec_len);
      memcpy (dst + ec_len, pq, pq_len);
    }
}

/* Split a wire value into its halves, given the two sizes.  */
static void
split (const struct group *g, const uint8_t *src, size_t ec_len,
       size_t pq_len, const uint8_t **ec, const uint8_t **pq)
{
  if (g->pq_first)
    {
      *pq = src;
      *ec = src + pq_len;
    }
  else
    {
      *ec = src;
      *pq = src + ec_len;
    }
}

int
gq_kx_generate (unsigned group, gq_kx_key *key)
{
  const struct group *g = find_group (group);

  if (key == NULL)
    return GQ_ERR_INVAL;
  if (g == NULL)
    return GQ_ERR_UNSUPPORTED;
  TRY (gq_crypto_init ());

  {
    uint8_t ec_pub[97], pq_pub[GCRY_KEM_MLKEM1024_PUBKEY_LEN];

    memset (key, 0, sizeof *key);
    key->group = g->id;
    if (g->ec_algo
        && gcry_kem_keypair (g->ec_algo, ec_pub, g->ec_pub, key->secret,
                             g->ec_sec))
      return GQ_ERR_CRYPTO;
    if (g->kem_algo)
      {
        /* The coins of FIPS 203 (d and z).  Left to itself libgcrypt draws
           them at its strongest level, for a key that may be long lived,
           which makes it gather jitter entropy on every call: 2.4
           milliseconds, more than the rest of a handshake.  This key lasts
           one handshake, like the elliptic curve key above, which libgcrypt
           makes at the ordinary strong level, so draw them at that.  */
        uint8_t coins[2 * GCRY_KEM_MLKEM_RANDOM_LEN];
        int failed = gq_random (coins, sizeof coins) != GQ_OK
                     || gcry_kem_genkey (g->kem_algo, pq_pub, g->kem_pub,
                                         key->secret + g->ec_sec, g->kem_sec,
                                         coins, sizeof coins);

        gq_wipe (coins, sizeof coins);
        if (failed)
          {
            gq_kx_key_wipe (key);
            return GQ_ERR_CRYPTO;
          }
        join (g, key->share, ec_pub, g->ec_pub, pq_pub, g->kem_pub);
      }
    else
      memcpy (key->share, ec_pub, g->ec_pub);
    key->share_len = g->ec_pub + g->kem_pub;
  }
  return GQ_OK;
}

int
gq_kx_respond (unsigned group, const uint8_t *client_share,
               size_t client_len, uint8_t *server_share, size_t cap,
               size_t *server_len, uint8_t *shared, size_t shared_cap,
               size_t *shared_len)
{
  const struct group *g = find_group (group);
  uint8_t ec_ct[97], ec_raw[97], ec_ss[48];
  uint8_t pq_ct[GCRY_KEM_MLKEM1024_CIPHER_LEN], pq_ss[MLKEM_SS];
  const uint8_t *ec_peer, *pq_peer = NULL;
  int r = GQ_OK;

  if (g == NULL)
    return GQ_ERR_UNSUPPORTED;
  if (client_share == NULL || server_share == NULL || shared == NULL
      || server_len == NULL || shared_len == NULL)
    return GQ_ERR_INVAL;
  if (client_len != g->ec_pub + g->kem_pub)
    return GQ_ERR_ENCODING;
  if (cap < g->ec_pub + g->kem_ct
      || shared_cap < g->ec_out + (g->kem_algo ? MLKEM_SS : 0))
    return GQ_ERR_BUFSIZE;
  TRY (gq_crypto_init ());

  split (g, client_share, g->ec_pub, g->kem_pub, &ec_peer, &pq_peer);
  if (g->ec_algo)
    {
      if (!ec_peer_ok (g, ec_peer))
        return GQ_ERR_CRYPTO;		/* Not a valid point.  */
      if (gcry_kem_encap (g->ec_algo, ec_peer, g->ec_pub, ec_ct, g->ec_pub,
                          ec_raw, g->ec_raw, NULL, 0))
        return GQ_ERR_CRYPTO;		/* Not a valid point.  */
      TRY (ec_extract (g, ec_raw, ec_ss));
    }

  if (g->kem_algo)
    {
      if (gcry_kem_encap (g->kem_algo, pq_peer, g->kem_pub, pq_ct,
                          g->kem_ct, pq_ss, MLKEM_SS, NULL, 0))
        r = GQ_ERR_CRYPTO;
      else
        {
          join (g, server_share, ec_ct, g->ec_pub, pq_ct, g->kem_ct);
          join (g, shared, ec_ss, g->ec_out, pq_ss, MLKEM_SS);
        }
    }
  else
    {
      memcpy (server_share, ec_ct, g->ec_pub);
      memcpy (shared, ec_ss, g->ec_out);
    }
  if (r == GQ_OK)
    {
      *server_len = g->ec_pub + g->kem_ct;
      *shared_len = g->ec_out + (g->kem_algo ? MLKEM_SS : 0);
    }
  gq_wipe (ec_raw, sizeof ec_raw);
  gq_wipe (ec_ss, sizeof ec_ss);
  gq_wipe (pq_ss, sizeof pq_ss);
  return r;
}

int
gq_kx_complete (const gq_kx_key *key, const uint8_t *server_share,
                size_t server_len, uint8_t *shared, size_t shared_cap,
                size_t *shared_len)
{
  const struct group *g;
  uint8_t ec_raw[97], ec_ss[48], pq_ss[MLKEM_SS];
  const uint8_t *ec_peer, *pq_peer = NULL;
  int r = GQ_OK;

  if (key == NULL || server_share == NULL || shared == NULL
      || shared_len == NULL)
    return GQ_ERR_INVAL;
  g = find_group (key->group);
  if (g == NULL)
    return GQ_ERR_UNSUPPORTED;
  if (server_len != g->ec_pub + g->kem_ct)
    return GQ_ERR_ENCODING;
  if (shared_cap < g->ec_out + (g->kem_algo ? MLKEM_SS : 0))
    return GQ_ERR_BUFSIZE;
  TRY (gq_crypto_init ());

  split (g, server_share, g->ec_pub, g->kem_ct, &ec_peer, &pq_peer);
  if (g->ec_algo)
    {
      if (!ec_peer_ok (g, ec_peer))
        return GQ_ERR_CRYPTO;		/* Not a valid point.  */
      if (gcry_kem_decap (g->ec_algo, key->secret, g->ec_sec, ec_peer,
                          g->ec_pub, ec_raw, g->ec_raw, NULL, 0))
        return GQ_ERR_CRYPTO;
      TRY (ec_extract (g, ec_raw, ec_ss));
    }

  if (g->kem_algo)
    {
      /* ML-KEM decapsulation never fails on a well-sized ciphertext:
         a forged one yields an unrelated secret (implicit rejection),
         which then fails the Finished check.  */
      if (gcry_kem_decap (g->kem_algo, key->secret + g->ec_sec, g->kem_sec,
                          pq_peer, g->kem_ct, pq_ss, MLKEM_SS, NULL, 0))
        r = GQ_ERR_CRYPTO;
      else
        join (g, shared, ec_ss, g->ec_out, pq_ss, MLKEM_SS);
    }
  else
    memcpy (shared, ec_ss, g->ec_out);
  if (r == GQ_OK)
    *shared_len = g->ec_out + (g->kem_algo ? MLKEM_SS : 0);
  gq_wipe (ec_raw, sizeof ec_raw);
  gq_wipe (ec_ss, sizeof ec_ss);
  gq_wipe (pq_ss, sizeof pq_ss);
  return r;
}
