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

#include <quickstep/status.h>
#include <quickstep/crypto.h>
#include <quickstep/policy.h>
#include <quickstep/kx.h>

#include "tst-util.h"
#include "tst-rndstats.h"
#include "vectors-mlkem.h"

static const unsigned all_groups[] = {
  GQ_GROUP_X25519, GQ_GROUP_SECP256R1, GQ_GROUP_SECP384R1,
  GQ_GROUP_X25519_MLKEM768, GQ_GROUP_SECP256R1_MLKEM768,
  GQ_GROUP_SECP384R1_MLKEM1024,
  GQ_GROUP_MLKEM512, GQ_GROUP_MLKEM768, GQ_GROUP_MLKEM1024
};

/* Expected: client share, server share, shared secret sizes.  The pure
   groups carry the ML-KEM encapsulation key and ciphertext alone.  */
static const size_t sizes[][3] = {
  { 32, 32, 32 }, { 65, 65, 32 }, { 97, 97, 48 },
  { 1184 + 32, 1088 + 32, 64 }, { 65 + 1184, 65 + 1088, 64 },
  { 97 + 1568, 97 + 1568, 48 + 32 },
  { 800, 768, 32 }, { 1184, 1088, 32 }, { 1568, 1568, 32 }
};

static void
test_roundtrip (void)
{
  size_t i;

  for (i = 0; i < sizeof all_groups / sizeof all_groups[0]; i++)
    {
      unsigned g = all_groups[i];
      static gq_kx_key key, key2;
      uint8_t server[GQ_KX_SHARE_MAX], ss[GQ_KX_SHARED_MAX], cs[GQ_KX_SHARED_MAX];
      size_t slen, sslen, cslen;

      CHECK_EQ (gq_kx_client_share_len (g), sizes[i][0]);
      CHECK_EQ (gq_kx_server_share_len (g), sizes[i][1]);
      CHECK_EQ (gq_kx_shared_len (g), sizes[i][2]);

      CHECK_EQ (gq_kx_generate (g, &key), GQ_OK);
      CHECK_EQ (key.share_len, sizes[i][0]);
      CHECK_EQ (gq_kx_respond (g, key.share, key.share_len, server,
                               sizeof server, &slen, ss, sizeof ss, &sslen),
                GQ_OK);
      CHECK_EQ (slen, sizes[i][1]);
      CHECK_EQ (sslen, sizes[i][2]);
      CHECK_EQ (gq_kx_complete (&key, server, slen, cs, sizeof cs, &cslen),
                GQ_OK);
      CHECK_EQ (cslen, sslen);
      CHECK (memcmp (cs, ss, sslen) == 0);

      /* Fresh keys and fresh responses differ.  */
      CHECK_EQ (gq_kx_generate (g, &key2), GQ_OK);
      CHECK (memcmp (key.share, key2.share, key.share_len) != 0);

      /* A response to someone else's share yields a different secret.  */
      {
        uint8_t other[GQ_KX_SHARE_MAX], os[GQ_KX_SHARED_MAX];
        size_t olen, osl, cl2;

        CHECK_EQ (gq_kx_respond (g, key2.share, key2.share_len, other,
                                 sizeof other, &olen, os, sizeof os, &osl),
                  GQ_OK);
        if (gq_kx_complete (&key, other, olen, cs, sizeof cs, &cl2) == GQ_OK)
          CHECK (memcmp (cs, os, osl) != 0 && memcmp (cs, ss, sslen) != 0);
      }
      gq_kx_key_wipe (&key);
      CHECK (key.share_len == 0 && key.secret[0] == 0);
    }
}

/* RFC 7748 section 6.1 test vectors, fed through the client path.  */
static void
test_x25519_kat (void)
{
  static gq_kx_key key;
  uint8_t peer[32], out[GQ_KX_SHARED_MAX];
  size_t n;

  memset (&key, 0, sizeof key);
  key.group = GQ_GROUP_X25519;
  tst_unhex ("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
             key.secret, 32);
  tst_unhex ("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
             peer, 32);
  CHECK_EQ (gq_kx_complete (&key, peer, 32, out, sizeof out, &n), GQ_OK);
  CHECK (tst_eq_hex (out, n,
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));

  tst_unhex ("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
             key.secret, 32);
  tst_unhex ("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
             peer, 32);
  CHECK_EQ (gq_kx_complete (&key, peer, 32, out, sizeof out, &n), GQ_OK);
  CHECK (tst_eq_hex (out, n,
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
}

/* Verify the RFC 10024 ordering of the hybrid halves by recomputing the
   classical half with the plain curve group.  */
static void
check_hybrid_order (unsigned hybrid, unsigned classical, size_t ec_pub,
                    size_t ec_ss, size_t pq_ct, int pq_first)
{
  static gq_kx_key key, plain;
  uint8_t server[GQ_KX_SHARE_MAX], ss[GQ_KX_SHARED_MAX], want[GQ_KX_SHARED_MAX];
  size_t slen, sslen, wlen;
  const uint8_t *ec_share = pq_first ? server + pq_ct : server;
  const uint8_t *ec_part = pq_first ? ss + 32 : ss;

  CHECK_EQ (gq_kx_generate (hybrid, &key), GQ_OK);
  CHECK_EQ (gq_kx_respond (hybrid, key.share, key.share_len, server,
                           sizeof server, &slen, ss, sizeof ss, &sslen),
            GQ_OK);

  /* The classical scalar sits first in the secret buffer.  */
  memset (&plain, 0, sizeof plain);
  plain.group = (uint16_t) classical;
  memcpy (plain.secret, key.secret, 48);
  CHECK_EQ (gq_kx_complete (&plain, ec_share, ec_pub, want, sizeof want,
                            &wlen), GQ_OK);
  CHECK_EQ (wlen, ec_ss);
  CHECK (memcmp (ec_part, want, ec_ss) == 0);

  /* And the classical public value is at the documented end of the share.  */
  CHECK_EQ (slen, ec_pub + pq_ct);
}

static void
test_hybrid_order (void)
{
  check_hybrid_order (GQ_GROUP_X25519_MLKEM768, GQ_GROUP_X25519, 32, 32,
                      1088, 1);
  check_hybrid_order (GQ_GROUP_SECP256R1_MLKEM768, GQ_GROUP_SECP256R1, 65,
                      32, 1088, 0);
  check_hybrid_order (GQ_GROUP_SECP384R1_MLKEM1024, GQ_GROUP_SECP384R1, 97,
                      48, 1568, 0);
}

/* Known-answer test of a hybrid group on the client side, the only
   direction whose inputs the caller fixes: gq_kx_generate and
   gq_kx_respond draw their own randomness, which the interface does not
   let a test replace.  The client key is the classical private key
   followed by the ML-KEM decapsulation key (the layout kx.h documents),
   the server share and the expected shared secret are literal values
   from vectors-mlkem.h with the halves in the order RFC 10024 gives the
   group.  A swap of either order, or a wrong length for a half, changes
   the result.  */
static void
check_hybrid_kat (unsigned group, const char *const *scalar,
                  const char *const *dk, const char *const *server_share,
                  const char *const *shared)
{
  static gq_kx_key key;
  uint8_t share[GQ_KX_SHARE_MAX], want[GQ_KX_SHARED_MAX];
  uint8_t out[GQ_KX_SHARED_MAX];
  size_t scalar_len, dk_len, share_len, want_len, n;

  memset (&key, 0, sizeof key);
  key.group = (uint16_t) group;
  scalar_len = tst_unhex_parts (scalar, key.secret, sizeof key.secret);
  dk_len = tst_unhex_parts (dk, key.secret + scalar_len,
                            sizeof key.secret - scalar_len);
  CHECK (scalar_len + dk_len <= sizeof key.secret);
  share_len = tst_unhex_parts (server_share, share, sizeof share);
  want_len = tst_unhex_parts (shared, want, sizeof want);

  CHECK_EQ (share_len, gq_kx_server_share_len (group));
  CHECK_EQ (want_len, gq_kx_shared_len (group));
  CHECK_EQ (gq_kx_complete (&key, share, share_len, out, sizeof out, &n),
            GQ_OK);
  CHECK_EQ (n, want_len);
  CHECK (n == want_len && memcmp (out, want, n) == 0);
}

#define HYBRID_KAT(group, scalar, dk, name) \
  check_hybrid_kat (group, \
                    (const char *const[]) { scalar }, \
                    (const char *const[]) { dk }, \
                    (const char *const[]) { HYBRID_##name##_SERVER_SHARE }, \
                    (const char *const[]) { HYBRID_##name##_SHARED })

static void
test_hybrid_kat (void)
{
  HYBRID_KAT (GQ_GROUP_X25519_MLKEM768, HYBRID_X25519_SCALAR,
              MLKEM768_DECAP1_DK, X25519_MLKEM768);
  HYBRID_KAT (GQ_GROUP_SECP256R1_MLKEM768, HYBRID_P256_SCALAR,
              MLKEM768_DECAP1_DK, SECP256R1_MLKEM768);
  HYBRID_KAT (GQ_GROUP_SECP384R1_MLKEM1024, HYBRID_P384_SCALAR,
              MLKEM1024_DECAP1_DK, SECP384R1_MLKEM1024);
}

/* Known-answer test of a pure ML-KEM group on the client side (see
   check_hybrid_kat for why only that side): the key is the decapsulation
   key from the vectors, the server share the vector's ciphertext, and the
   shared secret is the vector's, with nothing added or reordered.  For a
   modified ciphertext it is the implicit-rejection secret, which
   gq_kx_complete must return as a success: the failure shows up at the
   Finished check.  */
static void
check_pure_kat (unsigned group, const char *const *dk, const char *const *c,
                const char *const *k)
{
  static gq_kx_key key;
  uint8_t share[GQ_KX_SHARE_MAX], want[GQ_KX_SHARED_MAX];
  uint8_t out[GQ_KX_SHARED_MAX];
  size_t dk_len, share_len, want_len, n;

  memset (&key, 0, sizeof key);
  key.group = (uint16_t) group;
  dk_len = tst_unhex_parts (dk, key.secret, sizeof key.secret);
  CHECK (dk_len > 0 && dk_len < sizeof key.secret);
  share_len = tst_unhex_parts (c, share, sizeof share);
  want_len = tst_unhex_parts (k, want, sizeof want);

  CHECK_EQ (share_len, gq_kx_server_share_len (group));
  CHECK_EQ (want_len, 32);
  CHECK_EQ (gq_kx_complete (&key, share, share_len, out, sizeof out, &n),
            GQ_OK);
  CHECK_EQ (n, want_len);
  CHECK (n == want_len && memcmp (out, want, n) == 0);
}

#define PURE_KAT(group, tag, n) \
  check_pure_kat (group, \
                  (const char *const[]) { MLKEM##tag##_DECAP##n##_DK }, \
                  (const char *const[]) { MLKEM##tag##_DECAP##n##_C }, \
                  (const char *const[]) { MLKEM##tag##_DECAP##n##_K })

static void
test_pure_kat (void)
{
  PURE_KAT (GQ_GROUP_MLKEM512, 512, 1);
  PURE_KAT (GQ_GROUP_MLKEM512, 512, 2);		/* Modified ciphertext.  */
  PURE_KAT (GQ_GROUP_MLKEM768, 768, 1);
  PURE_KAT (GQ_GROUP_MLKEM768, 768, 2);
  PURE_KAT (GQ_GROUP_MLKEM1024, 1024, 1);
  PURE_KAT (GQ_GROUP_MLKEM1024, 1024, 2);
}

/* A pure group's share is exactly the key (client) or the ciphertext
   (server): one byte more or fewer is refused on both ends, as is a
   share that is empty or that belongs to a larger parameter set.  */
static void
test_pure_lengths (void)
{
  static const unsigned pure[] = {
    GQ_GROUP_MLKEM512, GQ_GROUP_MLKEM768, GQ_GROUP_MLKEM1024
  };
  size_t i;

  for (i = 0; i < sizeof pure / sizeof pure[0]; i++)
    {
      unsigned g = pure[i];
      static gq_kx_key key;
      static uint8_t share[GQ_KX_SHARE_MAX + 1], server[GQ_KX_SHARE_MAX];
      uint8_t ss[GQ_KX_SHARED_MAX];
      size_t cl = gq_kx_client_share_len (g), sl = gq_kx_server_share_len (g);
      size_t n, m, other;

      CHECK_EQ (gq_kx_generate (g, &key), GQ_OK);
      CHECK_EQ (key.share_len, cl);
      memset (share, 0, sizeof share);
      memcpy (share, key.share, cl);

      CHECK_EQ (gq_kx_respond (g, share, cl, server, sizeof server, &n, ss,
                               sizeof ss, &m), GQ_OK);
      CHECK_EQ (n, sl);
      CHECK_EQ (gq_kx_respond (g, share, cl - 1, server, sizeof server, &n,
                               ss, sizeof ss, &m), GQ_ERR_ENCODING);
      CHECK_EQ (gq_kx_respond (g, share, cl + 1, server, sizeof server, &n,
                               ss, sizeof ss, &m), GQ_ERR_ENCODING);
      CHECK_EQ (gq_kx_respond (g, share, 0, server, sizeof server, &n, ss,
                               sizeof ss, &m), GQ_ERR_ENCODING);
      /* The key of another parameter set (the three sizes all differ).  */
      for (other = 0; other < sizeof pure / sizeof pure[0]; other++)
        if (pure[other] != g)
          CHECK_EQ (gq_kx_respond (g, share,
                                   gq_kx_client_share_len (pure[other]),
                                   server, sizeof server, &n, ss, sizeof ss,
                                   &m), GQ_ERR_ENCODING);
      /* A hybrid-sized share is not a pure one either.  */
      CHECK_EQ (gq_kx_respond (g, share, cl + 32, server, sizeof server, &n,
                               ss, sizeof ss, &m), GQ_ERR_ENCODING);

      /* The client checks the ciphertext it is given in the same way.  */
      CHECK_EQ (gq_kx_respond (g, share, cl, server, sizeof server, &n, ss,
                               sizeof ss, &m), GQ_OK);
      CHECK_EQ (gq_kx_complete (&key, server, sl, ss, sizeof ss, &m), GQ_OK);
      CHECK_EQ (gq_kx_complete (&key, server, sl - 1, ss, sizeof ss, &m),
                GQ_ERR_ENCODING);
      CHECK_EQ (gq_kx_complete (&key, server, sl + 1, ss, sizeof ss, &m),
                GQ_ERR_ENCODING);
      CHECK_EQ (gq_kx_complete (&key, server, 0, ss, sizeof ss, &m),
                GQ_ERR_ENCODING);

      /* A wrong-sized output buffer is reported, not overrun.  */
      CHECK_EQ (gq_kx_respond (g, share, cl, server, sl - 1, &n, ss,
                               sizeof ss, &m), GQ_ERR_BUFSIZE);
      CHECK_EQ (gq_kx_respond (g, share, cl, server, sizeof server, &n, ss,
                               31, &m), GQ_ERR_BUFSIZE);
      CHECK_EQ (gq_kx_complete (&key, server, sl, ss, 31, &m),
                GQ_ERR_BUFSIZE);
    }
}

/* The peer's elliptic curve point must be on the curve (RFC 8446 section
   4.2.8.2): libgcrypt's ECDH takes any point, and an unchecked one is an
   invalid-curve attack.  For each group with a NIST curve, a share whose
   point is (0, 0), is off the curve (a valid point with its last byte
   changed) or is in compressed form is refused, both by the server that
   receives it from a client and by the client that receives it from a
   server.  The curve is first in the share of all these groups.  */
static void
test_invalid_points (void)
{
  static const struct
  {
    unsigned group;
    size_t point;
  } v[] = {
    { GQ_GROUP_SECP256R1, 65 }, { GQ_GROUP_SECP384R1, 97 },
    { GQ_GROUP_SECP256R1_MLKEM768, 65 }, { GQ_GROUP_SECP384R1_MLKEM1024, 97 }
  };
  size_t i, bad;

  for (i = 0; i < sizeof v / sizeof v[0]; i++)
    {
      static gq_kx_key key;
      static uint8_t good[GQ_KX_SHARE_MAX], share[GQ_KX_SHARE_MAX];
      static uint8_t server[GQ_KX_SHARE_MAX], goodserver[GQ_KX_SHARE_MAX];
      uint8_t ss[GQ_KX_SHARED_MAX];
      unsigned g = v[i].group;
      size_t pt = v[i].point, cl, sl = 0, n, m;

      CHECK_EQ (gq_kx_generate (g, &key), GQ_OK);
      cl = key.share_len;
      memcpy (good, key.share, cl);
      CHECK_EQ (gq_kx_respond (g, good, cl, goodserver, sizeof goodserver,
                               &sl, ss, sizeof ss, &m), GQ_OK);

      for (bad = 0; bad < 3; bad++)
        {
          /* Client share to the server.  */
          memcpy (share, good, cl);
          if (bad == 0)
            {
              memset (share + 1, 0, pt - 1);	/* (0, 0).  */
            }
          else if (bad == 1)
            share[pt - 1] ^= 0x55;		/* Off the curve.  */
          else
            share[0] = 0x02;			/* Compressed form.  */
          CHECK (gq_kx_respond (g, share, cl, server, sizeof server, &n, ss,
                                sizeof ss, &m) != GQ_OK);

          /* Server share to the client.  */
          memcpy (share, goodserver, sl);
          if (bad == 0)
            memset (share + 1, 0, pt - 1);
          else if (bad == 1)
            share[pt - 1] ^= 0x55;
          else
            share[0] = 0x02;
          CHECK (gq_kx_complete (&key, share, sl, ss, sizeof ss, &m)
                 != GQ_OK);
        }
      /* And the untouched ones still work.  */
      CHECK_EQ (gq_kx_complete (&key, goodserver, sl, ss, sizeof ss, &m),
                GQ_OK);
    }
}

/* A coordinate is a number below the field's prime, written once (RFC 8446
   section 4.2.8.2, SEC 1 section 2.3.4): a share whose x is the right number
   plus p is not that point.  The points are real ones (x = 5 on P-256, x = 2
   on P-384, found with a square root), so what separates them from the
   accepted share is only that one coordinate is not reduced.  */
static void
test_noncanonical_points (void)
{
  static const char p256_good[] =
    "04" "0000000000000000000000000000000000000000000000000000000000000005"
    "459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc";
  static const char p256_bigx[] =
    "04" "ffffffff00000001000000000000000000000001000000000000000000000004"
    "459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc";
  static const char p384_good[] =
    "04" "0000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000002"
    "8cdeadbbd04911a3c1931e26df3fa6439dca9c7eb286fbd46fc319f0e2bb7802"
    "32baf57825fc0c1912ada2fefe84024c";
  static const char p384_bigx[] =
    "04" "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
    "ffffffff000000000000000100000001"
    "8cdeadbbd04911a3c1931e26df3fa6439dca9c7eb286fbd46fc319f0e2bb7802"
    "32baf57825fc0c1912ada2fefe84024c";
  static const struct
  {
    unsigned group;
    size_t point;
    const char *good, *bigx;
  } v[] = {
    { GQ_GROUP_SECP256R1, 65, p256_good, p256_bigx },
    { GQ_GROUP_SECP384R1, 97, p384_good, p384_bigx },
    { GQ_GROUP_SECP256R1_MLKEM768, 65, p256_good, p256_bigx },
    { GQ_GROUP_SECP384R1_MLKEM1024, 97, p384_good, p384_bigx }
  };
  size_t i;

  for (i = 0; i < sizeof v / sizeof v[0]; i++)
    {
      static gq_kx_key key;
      static uint8_t share[GQ_KX_SHARE_MAX], server[GQ_KX_SHARE_MAX];
      uint8_t ss[GQ_KX_SHARED_MAX];
      size_t cl = v[i].point, n, m;

      /* The hybrids carry the rest of a real share after the point.  */
      if (v[i].group == GQ_GROUP_SECP256R1_MLKEM768
          || v[i].group == GQ_GROUP_SECP384R1_MLKEM1024)
        {
          CHECK_EQ (gq_kx_generate (v[i].group, &key), GQ_OK);
          cl = key.share_len;
          memcpy (share, key.share, cl);
        }
      CHECK_EQ (tst_unhex (v[i].good, share, v[i].point), v[i].point);
      CHECK_EQ (gq_kx_respond (v[i].group, share, cl, server, sizeof server,
                               &n, ss, sizeof ss, &m), GQ_OK);
      CHECK_EQ (tst_unhex (v[i].bigx, share, v[i].point), v[i].point);
      CHECK (gq_kx_respond (v[i].group, share, cl, server, sizeof server, &n,
                            ss, sizeof ss, &m) != GQ_OK);
    }
}

/* X25519 points of small order (RFC 7748 section 6.1, RFC 8446 section
   7.4.2): they make the shared secret zero whatever our key, so the share
   is refused.  The list is the eight values below the prime that give
   it, and the three above the prime that reduce to them.  */
static void
test_small_order_points (void)
{
  static const char *const bad[] = {
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    /* The same with the top bit set, which X25519 ignores.  */
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
    "0000000000000000000000000000000000000000000000000000000000000080"
  };
  size_t i;

  for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
    {
      uint8_t share[32], server[GQ_KX_SHARE_MAX], ss[GQ_KX_SHARED_MAX];
      size_t n, m;
      int r;

      CHECK_EQ (tst_unhex (bad[i], share, 32), 32);
      r = gq_kx_respond (GQ_GROUP_X25519, share, 32, server, sizeof server,
                         &n, ss, sizeof ss, &m);
      CHECK (r != GQ_OK);
    }
}

static void
test_errors (void)
{
  static gq_kx_key key;
  uint8_t share[GQ_KX_SHARE_MAX], server[GQ_KX_SHARE_MAX], ss[GQ_KX_SHARED_MAX];
  size_t n, m;

  /* Groups outside the policy list.  */
  CHECK_EQ (gq_kx_generate (0x0019, &key), GQ_ERR_UNSUPPORTED);	/* secp521r1 */
  CHECK_EQ (gq_kx_generate (0x0100, &key), GQ_ERR_UNSUPPORTED);	/* ffdhe2048 */
  CHECK_EQ (gq_kx_client_share_len (0x0100), 0);

  /* Wrong share sizes.  */
  memset (share, 1, sizeof share);
  CHECK_EQ (gq_kx_respond (GQ_GROUP_X25519, share, 31, server, sizeof server,
                           &n, ss, sizeof ss, &m), GQ_ERR_ENCODING);
  CHECK_EQ (gq_kx_respond (GQ_GROUP_X25519_MLKEM768, share, 32, server,
                           sizeof server, &n, ss, sizeof ss, &m),
            GQ_ERR_ENCODING);

  /* Low-order X25519 points produce an all-zero secret: refused.  */
  memset (share, 0, 32);
  CHECK_EQ (gq_kx_respond (GQ_GROUP_X25519, share, 32, server, sizeof server,
                           &n, ss, sizeof ss, &m), GQ_ERR_CRYPTO);

  /* Off-curve NIST points are refused.  */
  memset (share, 0, 65);
  share[0] = 4;
  CHECK_EQ (gq_kx_respond (GQ_GROUP_SECP256R1, share, 65, server,
                           sizeof server, &n, ss, sizeof ss, &m),
            GQ_ERR_CRYPTO);
  memset (share, 0, 97);
  share[0] = 4;
  CHECK_EQ (gq_kx_respond (GQ_GROUP_SECP384R1, share, 97, server,
                           sizeof server, &n, ss, sizeof ss, &m),
            GQ_ERR_CRYPTO);

  /* Client side: same checks on the server share, and buffer sizes.  */
  CHECK_EQ (gq_kx_generate (GQ_GROUP_SECP256R1, &key), GQ_OK);
  CHECK_EQ (gq_kx_complete (&key, share, 64, ss, sizeof ss, &m),
            GQ_ERR_ENCODING);
  memset (share, 0, 65);
  share[0] = 4;
  CHECK_EQ (gq_kx_complete (&key, share, 65, ss, sizeof ss, &m),
            GQ_ERR_CRYPTO);
  CHECK_EQ (gq_kx_respond (GQ_GROUP_SECP256R1, key.share, 65, server, 64,
                           &n, ss, sizeof ss, &m), GQ_ERR_BUFSIZE);
  CHECK_EQ (gq_kx_respond (GQ_GROUP_SECP256R1, key.share, 65, server,
                           sizeof server, &n, ss, 31, &m), GQ_ERR_BUFSIZE);
}

/* A key share is ephemeral: made for one handshake and gone.  Asking
   libgcrypt's strongest level for the ML-KEM part, as its key generation
   does by default, makes it gather jitter entropy on every call, which took
   2.4 milliseconds of a handshake that otherwise took two.  The ordinary
   strong level is what libgcrypt itself uses for the other ephemeral keys
   and for encapsulation.  So the groups are made without a request for the
   strongest level, and each key is different.  */
static void
test_ephemeral_keys_not_strongest (void)
{
  static const unsigned groups[] = {
    GQ_GROUP_X25519_MLKEM768, GQ_GROUP_SECP256R1_MLKEM768,
    GQ_GROUP_SECP384R1_MLKEM1024, GQ_GROUP_MLKEM512, GQ_GROUP_MLKEM768,
    GQ_GROUP_MLKEM1024, GQ_GROUP_X25519, GQ_GROUP_SECP256R1
  };
  size_t i;
  unsigned long before, after;

  tst_catch_gcrypt_log ();
  CHECK_EQ (gq_crypto_init (), GQ_OK);
  if (!tst_rnd_stat ("getlvl2=", 0, &before))
    {
      fprintf (stderr, "note: libgcrypt does not keep random statistics "
               "here (FIPS mode or another generator); skipped\n");
      return;
    }
  for (i = 0; i < sizeof groups / sizeof groups[0]; i++)
    {
      gq_kx_key a, b;

      CHECK_EQ (gq_kx_generate (groups[i], &a), GQ_OK);
      CHECK_EQ (gq_kx_generate (groups[i], &b), GQ_OK);
      CHECK_EQ (a.share_len, b.share_len);
      CHECK (memcmp (a.share, b.share, a.share_len) != 0);
      CHECK (memcmp (a.secret, b.secret, 32) != 0);
      gq_kx_key_wipe (&a);
      gq_kx_key_wipe (&b);
    }
  CHECK (tst_rnd_stat ("getlvl2=", 0, &after));
  CHECK_EQ (after, before);
}

int
main (void)
{
  test_roundtrip ();
  test_x25519_kat ();
  test_hybrid_order ();
  test_hybrid_kat ();
  test_pure_kat ();
  test_pure_lengths ();
  test_errors ();
  test_invalid_points ();
  test_noncanonical_points ();
  test_small_order_points ();
  test_ephemeral_keys_not_strongest ();
  TST_DONE ();
}
