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
#include <quickstep/packet.h>
#include <quickstep/protect.h>

#include "tst-util.h"
#include "tst-alloc.h"
#include "vectors.h"

static const char *DCID_HEX = "8394c8f03e515708";

static void
check_keys (const gq_packet_keys *k, const char *key, const char *iv,
            const char *hp)
{
  size_t kl = gq_aead_key_size (k->aead);

  CHECK (tst_eq_hex (k->key, kl, key));
  CHECK (tst_eq_hex (k->iv, GQ_AEAD_NONCE_LEN, iv));
  CHECK (tst_eq_hex (k->hp, kl, hp));
}

/* RFC 9001 appendix A.1 and RFC 9369 appendix A.1.  */
static void
test_initial_keys (void)
{
  uint8_t dcid[8], cs[32], ss[32];
  gq_packet_keys c, s;

  tst_unhex (DCID_HEX, dcid, sizeof dcid);

  CHECK_EQ (gq_initial_secrets (GQ_VERSION_1, dcid, 8, cs, ss), GQ_OK);
  CHECK (tst_eq_hex (cs, 32,
    "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"));
  CHECK (tst_eq_hex (ss, 32,
    "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"));
  CHECK_EQ (gq_packet_keys_initial (GQ_VERSION_1, dcid, 8, &c, &s), GQ_OK);
  check_keys (&c, "1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c",
              "9f50449e04a0e810283a1e9933adedd2");
  check_keys (&s, "cf3a5331653c364c88f0f379b6067e37", "0ac1493ca1905853b0bba03e",
              "c206b8d9b9f0f37644430b490eeaa314");

  CHECK_EQ (gq_initial_secrets (GQ_VERSION_2, dcid, 8, cs, ss), GQ_OK);
  CHECK (tst_eq_hex (cs, 32,
    "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b"));
  CHECK (tst_eq_hex (ss, 32,
    "0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1"));
  CHECK_EQ (gq_packet_keys_initial (GQ_VERSION_2, dcid, 8, &c, &s), GQ_OK);
  check_keys (&c, "8b1a0bc121284290a29e0971b5cd045d", "91f73e2351d8fa91660e909f",
              "45b95e15235d6f45a6b19cbcb0294ba9");
  check_keys (&s, "82db637861d55e1d011f19ea71d5d2a7", "dd13c276499c0249d3310652",
              "edf6d05c83121201b436e16877593c3a");

  CHECK_EQ (gq_packet_keys_initial (0x1a2a3a4a, dcid, 8, &c, &s),
            GQ_ERR_UNSUPPORTED);
}

/* RFC 9001 appendix A.2: the protected client Initial, byte for byte,
   including the header we build ourselves.  */
static void
test_client_initial (void)
{
  uint8_t dcid[8], hdr_expect[64], want[1300], pkt[1300], plain[1162];
  uint8_t crypto[300];
  size_t hdr, hdr_expect_len, cn, want_len, out, off, plen;
  uint64_t pn;
  gq_packet_keys c;

  tst_unhex (DCID_HEX, dcid, sizeof dcid);
  CHECK_EQ (gq_packet_keys_initial (GQ_VERSION_1, dcid, 8, &c, NULL), GQ_OK);

  cn = tst_unhex (V_CLIENT_CRYPTO_FRAME, crypto, sizeof crypto);
  memset (plain, 0, sizeof plain);
  memcpy (plain, crypto, cn);		/* Remainder is PADDING.  */
  hdr_expect_len = tst_unhex (V_CLIENT_UNPROTECTED_HEADER, hdr_expect,
                              sizeof hdr_expect);
  want_len = tst_unhex (V_CLIENT_PROTECTED_PACKET, want, sizeof want);
  CHECK_EQ (want_len, 1200);

  CHECK_EQ (gq_long_header_build (GQ_PKT_INITIAL, GQ_VERSION_1, dcid, 8, NULL,
                                  0, NULL, 0, 2, 4, sizeof plain, pkt,
                                  sizeof pkt, &hdr), GQ_OK);
  CHECK_EQ (hdr, hdr_expect_len);
  CHECK (memcmp (pkt, hdr_expect, hdr) == 0);

  memcpy (pkt + hdr, plain, sizeof plain);
  CHECK_EQ (gq_packet_seal (&c, 2, pkt, hdr - 4, 4, sizeof plain,
                            sizeof pkt, &out), GQ_OK);
  CHECK_EQ (out, want_len);
  CHECK (memcmp (pkt, want, want_len) == 0);

  /* Receive it back.  */
  memcpy (pkt, want, want_len);
  CHECK_EQ (gq_packet_open (&c, 0, 0, pkt, want_len, hdr - 4, &pn, &off,
                            &plen), GQ_OK);
  CHECK (pn == 2);
  CHECK_EQ (off, hdr);
  CHECK_EQ (plen, sizeof plain);
  CHECK (memcmp (pkt + off, plain, plen) == 0);
  CHECK (memcmp (pkt, hdr_expect, hdr) == 0);	/* Header unmasked.  */

  /* Tampering: any changed byte fails authentication.  */
  memcpy (pkt, want, want_len);
  pkt[700] ^= 1;
  CHECK_EQ (gq_packet_open (&c, 0, 0, pkt, want_len, hdr - 4, &pn, &off,
                            &plen), GQ_ERR_CRYPTO);
  memcpy (pkt, want, want_len);
  pkt[10] ^= 1;			/* Inside the DCID: covered by the AAD.  */
  CHECK_EQ (gq_packet_open (&c, 0, 0, pkt, want_len, hdr - 4, &pn, &off,
                            &plen), GQ_ERR_CRYPTO);
  memcpy (pkt, want, want_len);
  CHECK_EQ (gq_packet_open (&c, 0, 0, pkt, want_len - 1, hdr - 4, &pn, &off,
                            &plen), GQ_ERR_CRYPTO);

  /* Wrong key.  */
  {
    gq_packet_keys s;

    CHECK_EQ (gq_packet_keys_initial (GQ_VERSION_1, dcid, 8, NULL, &s), GQ_OK);
    memcpy (pkt, want, want_len);
    CHECK_EQ (gq_packet_open (&s, 0, 0, pkt, want_len, hdr - 4, &pn, &off,
                              &plen), GQ_ERR_CRYPTO);
  }
}

/* RFC 9001 appendix A.3: the server Initial.  */
static void
test_server_initial (void)
{
  uint8_t dcid[8], scid[8], want[256], pkt[256], plain[256], hdr_expect[64];
  size_t hdr, want_len, pn = 0, out, off, plen, pl, hl;
  uint64_t got_pn;
  gq_packet_keys s;

  tst_unhex (DCID_HEX, dcid, sizeof dcid);
  tst_unhex ("f067a5502a4262b5", scid, sizeof scid);
  CHECK_EQ (gq_packet_keys_initial (GQ_VERSION_1, dcid, 8, NULL, &s), GQ_OK);

  pl = tst_unhex (V_SERVER_PAYLOAD_PLAINTEXT, plain, sizeof plain);
  hl = tst_unhex (V_SERVER_UNPROTECTED_HEADER, hdr_expect, sizeof hdr_expect);
  want_len = tst_unhex (V_SERVER_PROTECTED_PACKET, want, sizeof want);

  CHECK_EQ (gq_long_header_build (GQ_PKT_INITIAL, GQ_VERSION_1, NULL, 0, scid,
                                  8, NULL, 0, 1, 2, pl, pkt, sizeof pkt,
                                  &hdr), GQ_OK);
  CHECK_EQ (hdr, hl);
  CHECK (memcmp (pkt, hdr_expect, hdr) == 0);
  memcpy (pkt + hdr, plain, pl);
  pn = hdr - 2;
  CHECK_EQ (gq_packet_seal (&s, 1, pkt, pn, 2, pl, sizeof pkt, &out), GQ_OK);
  CHECK_EQ (out, want_len);
  CHECK (memcmp (pkt, want, want_len) == 0);

  memcpy (pkt, want, want_len);
  CHECK_EQ (gq_packet_open (&s, 0, 0, pkt, want_len, pn, &got_pn, &off, &plen),
            GQ_OK);
  CHECK (got_pn == 1);
  CHECK_EQ (plen, pl);
  CHECK (memcmp (pkt + off, plain, pl) == 0);
}

/* RFC 9001 appendix A.5: ChaCha20-Poly1305 short header packet.  */
static void
test_chacha_short (void)
{
  uint8_t secret[32], pkt[64], want[64], hdr_want[8];
  size_t hdr, out, want_len, off, plen;
  uint64_t pn;
  gq_packet_keys k;
  const uint64_t full = 654360564;

  tst_unhex ("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b",
             secret, sizeof secret);
  CHECK_EQ (gq_packet_keys_derive (GQ_VERSION_1, GQ_AEAD_CHACHA20_POLY1305,
                                   secret, 32, &k), GQ_OK);
  want_len = tst_unhex ("4cfe4189655e5cd55c41f69080575d7999c25a5bfb", want,
                        sizeof want);
  tst_unhex ("4200bff4", hdr_want, sizeof hdr_want);

  CHECK_EQ (gq_short_header_build (NULL, 0, 0, 0, full, 3, pkt, sizeof pkt,
                                   &hdr), GQ_OK);
  CHECK_EQ (hdr, 4);
  CHECK (memcmp (pkt, hdr_want, 4) == 0);
  pkt[hdr] = 0x01;		/* A single PING frame.  */
  CHECK_EQ (gq_packet_seal (&k, full, pkt, 1, 3, 1, sizeof pkt, &out), GQ_OK);
  CHECK_EQ (out, want_len);
  CHECK (memcmp (pkt, want, want_len) == 0);

  memcpy (pkt, want, want_len);
  CHECK_EQ (gq_packet_open (&k, 1, full - 1, pkt, want_len, 1, &pn, &off,
                            &plen), GQ_OK);
  CHECK (pn == full);
  CHECK_EQ (plen, 1);
  CHECK_EQ (pkt[off], 0x01);
}

static void
test_seal_errors_and_reserved (void)
{
  static const uint8_t secret[32] = { 1 };
  uint8_t pkt[100];
  size_t hdr, out, off, plen;
  uint64_t pn;
  gq_packet_keys k;

  CHECK_EQ (gq_packet_keys_derive (GQ_VERSION_1, GQ_AEAD_AES_128_GCM, secret,
                                   32, &k), GQ_OK);
  CHECK_EQ (gq_short_header_build (NULL, 0, 0, 0, 7, 1, pkt, sizeof pkt,
                                   &hdr), GQ_OK);
  /* One-byte packet number needs at least 3 payload bytes to sample.  */
  CHECK_EQ (gq_packet_seal (&k, 7, pkt, 1, 1, 2, sizeof pkt, &out),
            GQ_ERR_RANGE);
  CHECK_EQ (gq_packet_seal (&k, 7, pkt, 1, 1, 3, 1 + 1 + 3 + 15, &out),
            GQ_ERR_BUFSIZE);
  CHECK_EQ (gq_packet_seal (&k, 7, pkt, 1, 1, 3, 1 + 1 + 3 + 16, &out),
            GQ_OK);
  CHECK_EQ (out, 21);

  /* Too short to sample on receipt.  This is not a malformed packet the
     connection should react to, only one that cannot be unprotected, so it
     must not look like the reserved-bits error below (RFC 9001 section
     5.4: such packets are discarded).  */
  CHECK_EQ (gq_packet_open (&k, 0, 0, pkt, 20, 1, &pn, &off, &plen),
            GQ_ERR_RANGE);

  /* Reserved bits set in the plaintext header: authentic, but illegal.  */
  gq_short_header_build (NULL, 0, 0, 0, 7, 1, pkt, sizeof pkt, &hdr);
  pkt[0] |= 0x08;
  memset (pkt + hdr, 0, 3);
  CHECK_EQ (gq_packet_seal (&k, 7, pkt, 1, 1, 3, sizeof pkt, &out), GQ_OK);
  CHECK_EQ (gq_packet_open (&k, 0, 0, pkt, out, 1, &pn, &off, &plen),
            GQ_ERR_ENCODING);
}

static void
test_key_update (void)
{
  static const uint8_t secret[32] = { 7 };
  uint8_t next[32], next2[32], pkt[64], copy[64];
  size_t out, off, plen;
  uint64_t pn;
  gq_packet_keys k0, k1, k1v2, k2;

  CHECK_EQ (gq_packet_keys_derive (GQ_VERSION_1, GQ_AEAD_AES_128_GCM, secret,
                                   32, &k0), GQ_OK);
  CHECK_EQ (gq_packet_keys_update (GQ_VERSION_1, &k0, secret, 32, next, &k1),
            GQ_OK);
  CHECK_EQ (gq_packet_keys_update (GQ_VERSION_2, &k0, secret, 32, next2, &k1v2),
            GQ_OK);
  CHECK (memcmp (k0.key, k1.key, 16) != 0);
  CHECK (memcmp (k0.iv, k1.iv, 12) != 0);
  CHECK (memcmp (k0.hp, k1.hp, 16) == 0);	/* HP key survives updates.  */
  CHECK (memcmp (k1.key, k1v2.key, 16) != 0);	/* Version-specific label.  */
  CHECK (memcmp (next, next2, 32) != 0);
  CHECK_EQ (gq_packet_keys_update (GQ_VERSION_1, &k1, next, 32, next2, &k2),
            GQ_OK);
  CHECK (memcmp (k1.key, k2.key, 16) != 0);

  /* A packet sealed after the update opens only with the new keys.  */
  memset (pkt, 0, sizeof pkt);
  pkt[0] = 0x40 | 0x04;		/* Key phase 1, one-byte packet number.  */
  pkt[1] = 9;
  CHECK_EQ (gq_packet_seal (&k1, 9, pkt, 1, 1, 10, sizeof pkt, &out), GQ_OK);
  memcpy (copy, pkt, out);
  CHECK_EQ (gq_packet_open (&k1, 0, 0, pkt, out, 1, &pn, &off, &plen), GQ_OK);
  memcpy (pkt, copy, out);
  CHECK_EQ (gq_packet_open (&k0, 0, 0, pkt, out, 1, &pn, &off, &plen),
            GQ_ERR_CRYPTO);

  gq_packet_keys_wipe (&k0);
  CHECK (tst_eq_hex (k0.key, 4, "00000000"));
}

/* Seal and open N packets of PAYLOAD bytes under K, each with its own packet
   number, and check that each comes back as it went.  */
static void
churn (const gq_packet_keys *k, int n, size_t payload)
{
  uint8_t pkt[200];
  uint8_t plain[200];
  int i;

  for (i = 0; i < n; i++)
    {
      size_t hdr, out, off, plen, j;
      uint64_t pn;

      CHECK_EQ (gq_short_header_build (NULL, 0, 0, 0, (uint64_t) i, 2, pkt,
                                       sizeof pkt, &hdr), GQ_OK);
      for (j = 0; j < payload; j++)
        pkt[hdr + j] = plain[j] = (uint8_t) (i + 3 * j);
      CHECK_EQ (gq_packet_seal (k, (uint64_t) i, pkt, 1, 2, payload,
                                sizeof pkt, &out), GQ_OK);
      CHECK_EQ (gq_packet_open (k, i > 0, (uint64_t) (i ? i - 1 : 0), pkt, out,
                                1, &pn, &off, &plen), GQ_OK);
      CHECK_EQ (pn, (uint64_t) i);
      CHECK_EQ (plen, payload);
      CHECK (memcmp (pkt + off, plain, payload) == 0);
    }
}

/* Protecting a packet must not set up a cipher: that is a context
   allocation, a key schedule and, with libgcrypt's own random number
   generator, an entropy poll, per packet and for the header mask as well as
   the AEAD, and at 1200 bytes it cost ten times the encryption itself.  The
   contexts are made when the keys are, and used for every packet after.  */
static void
test_no_setup_per_packet (void)
{
  static const uint8_t secret[48] = { 5 };
  static const enum gq_aead algs[3] = { GQ_AEAD_AES_128_GCM,
                                        GQ_AEAD_AES_256_GCM,
                                        GQ_AEAD_CHACHA20_POLY1305 };
  int a;

  for (a = 0; a < 3; a++)
    {
      gq_packet_keys k, k2;
      uint8_t next[48];
      size_t secret_len = gq_hash_size (gq_aead_hash (algs[a]));
      unsigned long before;

      CHECK_EQ (gq_packet_keys_derive (GQ_VERSION_1, algs[a], secret,
                                       secret_len, &k), GQ_OK);
      CHECK_EQ (gq_packet_keys_prepare (&k), GQ_OK);
      churn (&k, 1, 40);		/* Anything lazy is made by now.  */
      before = tst_allocs;
      churn (&k, 300, 40);
      CHECK_EQ (tst_allocs, before);
      /* Keys after a key update, which share the header protection key.  */
      CHECK_EQ (gq_packet_keys_update (GQ_VERSION_1, &k, secret, secret_len,
                                       next, &k2), GQ_OK);
      churn (&k2, 1, 40);
      before = tst_allocs;
      churn (&k2, 300, 40);
      churn (&k, 50, 40);
      CHECK_EQ (tst_allocs, before);
      gq_packet_keys_wipe (&k);
      gq_packet_keys_wipe (&k2);
    }
}

/* Keys with contexts and keys without are the same keys: a packet sealed by
   one opens with the other, in both directions, whatever the cipher.  */
static void
test_prepared_and_plain_agree (void)
{
  static const uint8_t secret[48] = { 9 };
  static const enum gq_aead algs[3] = { GQ_AEAD_AES_128_GCM,
                                        GQ_AEAD_AES_256_GCM,
                                        GQ_AEAD_CHACHA20_POLY1305 };
  int a;

  for (a = 0; a < 3; a++)
    {
      gq_packet_keys plain, fast;
      size_t secret_len = gq_hash_size (gq_aead_hash (algs[a]));
      uint8_t p1[100], p2[100];
      size_t hdr, o1, o2, off, plen;
      uint64_t pn;

      CHECK_EQ (gq_packet_keys_derive (GQ_VERSION_1, algs[a], secret,
                                       secret_len, &plain), GQ_OK);
      fast = plain;		/* No contexts yet: a plain copy.  */
      CHECK_EQ (gq_packet_keys_prepare (&fast), GQ_OK);
      CHECK (fast.aead_ctx != NULL && fast.hp_ctx != NULL);
      CHECK (plain.aead_ctx == NULL && plain.hp_ctx == NULL);
      gq_short_header_build (NULL, 0, 0, 1, 77, 2, p1, sizeof p1, &hdr);
      memset (p1 + hdr, 0x5a, 50);
      memcpy (p2, p1, hdr + 50);
      CHECK_EQ (gq_packet_seal (&plain, 77, p1, 1, 2, 50, sizeof p1, &o1),
                GQ_OK);
      CHECK_EQ (gq_packet_seal (&fast, 77, p2, 1, 2, 50, sizeof p2, &o2),
                GQ_OK);
      CHECK_EQ (o1, o2);
      CHECK (memcmp (p1, p2, o1) == 0);
      CHECK_EQ (gq_packet_open (&fast, 0, 0, p1, o1, 1, &pn, &off, &plen),
                GQ_OK);
      CHECK_EQ (plen, 50);
      CHECK_EQ (gq_packet_open (&plain, 0, 0, p2, o2, 1, &pn, &off, &plen),
                GQ_OK);
      CHECK_EQ (plen, 50);
      /* A packet that was changed does not open, and leaves the context
         usable for the next.  */
      gq_short_header_build (NULL, 0, 0, 1, 78, 2, p1, sizeof p1, &hdr);
      memset (p1 + hdr, 0x5a, 50);
      CHECK_EQ (gq_packet_seal (&fast, 78, p1, 1, 2, 50, sizeof p1, &o1),
                GQ_OK);
      memcpy (p2, p1, o1);		/* Opening works on the packet in place.  */
      p1[o1 - 3] ^= 1;
      CHECK_EQ (gq_packet_open (&fast, 0, 0, p1, o1, 1, &pn, &off, &plen),
                GQ_ERR_CRYPTO);
      CHECK_EQ (gq_packet_open (&fast, 0, 0, p2, o1, 1, &pn, &off, &plen),
                GQ_OK);
      CHECK_EQ (pn, 78);
      gq_packet_keys_wipe (&fast);
      CHECK (fast.aead_ctx == NULL && fast.hp_ctx == NULL);
      gq_packet_keys_wipe (&plain);
    }
}

/* A context made for one key is not used for another.  Keys are plain
   data; if the bytes are changed after the contexts were made, the packets
   are protected by the bytes, not by the contexts' memory of the old ones.  */
static void
test_stale_context_not_used (void)
{
  static const uint8_t secret[32] = { 3 };
  gq_packet_keys plain, fast;
  uint8_t p1[100], p2[100];
  size_t hdr, o1, o2;

  CHECK_EQ (gq_packet_keys_derive (GQ_VERSION_1, GQ_AEAD_AES_128_GCM, secret,
                                   32, &plain), GQ_OK);
  fast = plain;
  CHECK_EQ (gq_packet_keys_prepare (&fast), GQ_OK);
  /* New bytes in both the key and the header protection key.  */
  plain.key[0] ^= 0x80;
  plain.hp[5] ^= 0x01;
  fast.key[0] ^= 0x80;
  fast.hp[5] ^= 0x01;
  gq_short_header_build (NULL, 0, 0, 0, 5, 2, p1, sizeof p1, &hdr);
  memset (p1 + hdr, 0x33, 40);
  memcpy (p2, p1, hdr + 40);
  CHECK_EQ (gq_packet_seal (&plain, 5, p1, 1, 2, 40, sizeof p1, &o1), GQ_OK);
  CHECK_EQ (gq_packet_seal (&fast, 5, p2, 1, 2, 40, sizeof p2, &o2), GQ_OK);
  CHECK_EQ (o1, o2);
  CHECK (memcmp (p1, p2, o1) == 0);
  gq_packet_keys_wipe (&fast);
}

/* Moving keys: the destination has them and the source has nothing; what
   the destination held is let go; moving to oneself is no move.  Key update
   in place, and from keys that have contexts to keys that have their own.  */
static void
test_move_and_update (void)
{
  static const uint8_t secret[32] = { 11 };
  gq_packet_keys a, b, ref, upd, upd2;
  uint8_t next[32], next2[32];
  unsigned long before;
  static const uint8_t zero[sizeof (gq_packet_keys)];

  CHECK_EQ (gq_packet_keys_derive (GQ_VERSION_1, GQ_AEAD_AES_128_GCM, secret,
                                   32, &a), GQ_OK);
  ref = a;				/* Plain copy, for comparison.  */
  CHECK_EQ (gq_packet_keys_prepare (&a), GQ_OK);
  memset (&b, 0, sizeof b);
  gq_packet_keys_move (&b, &a);
  CHECK (memcmp (&a, zero, sizeof a) == 0);
  CHECK (b.aead_ctx != NULL && b.hp_ctx != NULL);
  CHECK (memcmp (b.key, ref.key, 16) == 0);
  gq_packet_keys_move (&b, &b);		/* Nothing happens.  */
  CHECK (b.aead_ctx != NULL);
  churn (&b, 5, 40);

  /* Onto keys that have contexts of their own: they are let go (checked
     for leaks by the sanitizers in CI), and the new ones work.  */
  CHECK_EQ (gq_packet_keys_derive (GQ_VERSION_1, GQ_AEAD_AES_128_GCM, secret,
                                   32, &a), GQ_OK);
  CHECK_EQ (gq_packet_keys_prepare (&a), GQ_OK);
  gq_packet_keys_move (&b, &a);
  churn (&b, 5, 40);

  /* An update from prepared keys is prepared, and the same keys as from
     plain ones.  */
  CHECK_EQ (gq_packet_keys_update (GQ_VERSION_1, &b, secret, 32, next, &upd),
            GQ_OK);
  CHECK_EQ (gq_packet_keys_update (GQ_VERSION_1, &ref, secret, 32, next2,
                                   &upd2), GQ_OK);
  CHECK (upd.aead_ctx != NULL && upd.hp_ctx == b.hp_ctx);
  CHECK (upd2.aead_ctx == NULL && upd2.hp_ctx == NULL);
  CHECK (memcmp (upd.key, upd2.key, 16) == 0);
  CHECK (memcmp (upd.iv, upd2.iv, 12) == 0);
  CHECK (memcmp (upd.hp, upd2.hp, 16) == 0);
  CHECK (memcmp (next, next2, 32) == 0);
  before = tst_allocs;
  churn (&upd, 20, 40);
  CHECK_EQ (tst_allocs, before);
  /* The old keys' header protection context outlives them: it is shared.  */
  gq_packet_keys_wipe (&b);
  churn (&upd, 5, 40);
  /* In place.  */
  CHECK_EQ (gq_packet_keys_update (GQ_VERSION_1, &upd, next, 32, next2, &upd),
            GQ_OK);
  CHECK (upd.aead_ctx != NULL && upd.hp_ctx != NULL);
  churn (&upd, 5, 40);
  gq_packet_keys_wipe (&upd);
}

int
main (void)
{
  tst_count_allocs ();
  test_initial_keys ();
  test_client_initial ();
  test_server_initial ();
  test_chacha_short ();
  test_seal_errors_and_reserved ();
  test_key_update ();
  test_no_setup_per_packet ();
  test_prepared_and_plain_agree ();
  test_stale_context_not_used ();
  test_move_and_update ();
  TST_DONE ();
}
