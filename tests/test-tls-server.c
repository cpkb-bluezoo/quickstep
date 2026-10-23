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
#include <quickstep/tls.h>
#include <quickstep/tlsmsg.h>

#ifdef __GLIBC__
# include <malloc.h>		/* mallinfo2.  */
#endif
#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "tst-x509.h"
#include "tst-mldsa-cert.h"

/* ------------------------------------------------------------------ */
/* Fixtures                                                           */
/* ------------------------------------------------------------------ */

static struct tst_cert ca, ca2, ec, rsa, ed_srv, cli_ok, cli_bad_ca, cli_wrong_eku;
static gq_privkey *ec_key, *rsa_key, *ed_key, *cli_ok_key, *cli_bad_key,
  *cli_eku_key;
static uint8_t ec_der[2048], rsa_der[2048], ed_der[2048], cli_der[2048],
  clibad_der[2048], clieku_der[2048];
static gq_slice ec_chain[1], rsa_chain[1], ed_chain[1], cli_chain[1],
  clibad_chain[1], clieku_chain[1];
static gq_trust *client_trust;	/* Clients trust ca.  */
static gq_trust *server_trust;	/* Servers trust ca for client certs.  */
static gq_tls_credentials ec_creds, rsa_creds, ed_creds;

static size_t
der_of (const struct tst_cert *c, uint8_t *out)
{
  gnutls_datum_t d;
  size_t n;

  gnutls_x509_crt_export2 (c->crt, GNUTLS_X509_FMT_DER, &d);
  n = d.size;
  memcpy (out, d.data, n);
  gnutls_free (d.data);
  return n;
}

static gq_privkey *
key_of (const struct tst_cert *c)
{
  gnutls_datum_t pem;
  gq_privkey *k = NULL;

  gnutls_x509_privkey_export2_pkcs8 (c->key, GNUTLS_X509_FMT_PEM, NULL,
                                     GNUTLS_PKCS_PLAIN, &pem);
  CHECK_EQ (gq_privkey_from_pem (&k, pem.data, pem.size), GQ_OK);
  gnutls_free (pem.data);
  return k;
}

static gq_trust *
trust_of (const struct tst_cert *anchor)
{
  gnutls_datum_t pem;
  gq_trust *t;

  CHECK_EQ (gq_trust_new (&t), GQ_OK);
  gnutls_x509_crt_export2 (anchor->crt, GNUTLS_X509_FMT_PEM, &pem);
  CHECK_EQ (gq_trust_add_pem (t, pem.data, pem.size), GQ_OK);
  gnutls_free (pem.data);
  return t;
}

static void
setup_fixtures (void)
{
  const long nb = -3600, na = 86400;

  CHECK_EQ (tst_make_cert (&ca, TST_ECDSA256, "CA", NULL, NULL, nb, na,
                           GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&ca2, TST_ECDSA256, "CA2", NULL, NULL, nb, na,
                           GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&ec, TST_ECDSA256, "ec", "example.test", &ca, nb,
                           na, GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&rsa, TST_RSA2048, "rsa", "other.test", &ca, nb,
                           na, GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&ed_srv, TST_ED25519, "ed", "ed.test", &ca, nb, na,
                           GNUTLS_DIG_UNKNOWN), 0);
  CHECK_EQ (tst_make_cert_eku (&cli_ok, TST_ED25519, "client", "client.test",
                               &ca, nb, na, GNUTLS_DIG_UNKNOWN,
                               GNUTLS_KP_TLS_WWW_CLIENT), 0);
  CHECK_EQ (tst_make_cert_eku (&cli_bad_ca, TST_ECDSA256, "client2",
                               "client.test", &ca2, nb, na,
                               GNUTLS_DIG_SHA256, GNUTLS_KP_TLS_WWW_CLIENT), 0);
  CHECK_EQ (tst_make_cert_eku (&cli_wrong_eku, TST_ECDSA256, "client3",
                               "client.test", &ca, nb, na, GNUTLS_DIG_SHA256,
                               GNUTLS_KP_TLS_WWW_SERVER), 0);
  ec_chain[0] = (gq_slice) { ec_der, der_of (&ec, ec_der) };
  rsa_chain[0] = (gq_slice) { rsa_der, der_of (&rsa, rsa_der) };
  ed_chain[0] = (gq_slice) { ed_der, der_of (&ed_srv, ed_der) };
  cli_chain[0] = (gq_slice) { cli_der, der_of (&cli_ok, cli_der) };
  clibad_chain[0] = (gq_slice) { clibad_der, der_of (&cli_bad_ca, clibad_der) };
  clieku_chain[0] = (gq_slice) { clieku_der, der_of (&cli_wrong_eku, clieku_der) };
  ec_key = key_of (&ec);
  rsa_key = key_of (&rsa);
  ed_key = key_of (&ed_srv);
  cli_ok_key = key_of (&cli_ok);
  cli_bad_key = key_of (&cli_bad_ca);
  cli_eku_key = key_of (&cli_wrong_eku);
  client_trust = trust_of (&ca);
  server_trust = trust_of (&ca);
  ec_creds = (gq_tls_credentials) { ec_chain, 1, ec_key };
  rsa_creds = (gq_tls_credentials) { rsa_chain, 1, rsa_key };
  ed_creds = (gq_tls_credentials) { ed_chain, 1, ed_key };
}

/* ------------------------------------------------------------------ */
/* One endpoint's recorded events                                     */
/* ------------------------------------------------------------------ */

struct end
{
  gq_tls *tls;
  uint8_t sent[4][16384];
  size_t sent_len[4];
  gq_tls_secret secrets[32];
  int n_secrets;
  int complete;
  gq_tls_info info;
  int alert;
  uint8_t peer_tp[64];
  size_t peer_tp_len;
  gq_tls_session session;		/* Last ticket received.  */
  const char *const *dialled;	/* Name a client connected to (if a client): a
				   stored session is bound to it.  */
  int n_tickets;
  unsigned hs_seq[8];		/* Handshake-level message types sent.  */
  int n_hs;
  unsigned ini_seq[8], app_seq[8];	/* ...and at the Initial and 1-RTT levels.  */
  int n_ini, n_app;
};

static int
e_send (void *u, enum gq_level l, const uint8_t *d, size_t n)
{
  struct end *e = u;

  if (l == GQ_LEVEL_HANDSHAKE && n > 0 && e->n_hs < 8)
    e->hs_seq[e->n_hs++] = d[0];
  if (l == GQ_LEVEL_INITIAL && n > 0 && e->n_ini < 8)
    e->ini_seq[e->n_ini++] = d[0];
  if (l == GQ_LEVEL_APPLICATION && n > 0 && e->n_app < 8)
    e->app_seq[e->n_app++] = d[0];
  memcpy (e->sent[l] + e->sent_len[l], d, n);
  e->sent_len[l] += n;
  return 0;
}

static int
e_secret (void *u, const gq_tls_secret *s)
{
  struct end *e = u;

  e->secrets[e->n_secrets++] = *s;
  return 0;
}

static int
e_params (void *u, const uint8_t *d, size_t n)
{
  struct end *e = u;

  memcpy (e->peer_tp, d, n);
  e->peer_tp_len = n;
  return 0;
}

static int
e_complete (void *u, const gq_tls_info *i)
{
  struct end *e = u;

  e->complete = 1;
  e->info = *i;
  return 0;
}

static int
e_ticket (void *u, const gq_tls_ticket *t)
{
  struct end *e = u;

  e->n_tickets++;
  if (gq_tls_session_store (&e->session, t) != GQ_OK)
    return 1;
  return gq_tls_session_bind_server_name (&e->session,
                                          e->dialled ? *e->dialled : NULL)
    == GQ_OK ? 0 : 1;
}

static int
e_alert (void *u, unsigned code)
{
  ((struct end *) u)->alert = (int) code;
  return 0;
}

static gq_tls_sink
sink_for (struct end *e)
{
  gq_tls_sink s;

  memset (&s, 0, sizeof s);
  s.user = e;
  s.send = e_send;
  s.secret = e_secret;
  s.peer_params = e_params;
  s.complete = e_complete;
  s.ticket = e_ticket;
  s.alert = e_alert;
  return s;
}

/* A pair under test: config templates the tests adjust.  */
struct pair
{
  struct end c, s;
  gq_tls_config cc;
  gq_tls_server_config sc;
  gq_tls_sink csink, ssink;
  gq_slice calpn[2], salpn[2];
  uint8_t ctp[4], stp[4];
  gq_slice cchain[1];
  uint64_t cnow, snow;		/* Fake clocks, milliseconds.  */
};

static uint64_t
clock_of (void *u)
{
  return *(uint64_t *) u;
}

static struct pair *
pair_new (void)
{
  struct pair *p = calloc (1, sizeof *p);

  p->c.alert = p->s.alert = -1;
  p->cnow = p->snow = UINT64_C (1700000000000);
  p->cc.hooks.now_ms = clock_of;
  p->cc.hooks.user = &p->cnow;
  p->sc.hooks.now_ms = clock_of;
  p->sc.hooks.user = &p->snow;
  p->cc.server_name = "example.test";
  p->c.dialled = &p->cc.server_name;
  p->cc.trust = client_trust;
  p->sc.credentials = ec_creds;
  p->csink = sink_for (&p->c);
  p->ssink = sink_for (&p->s);
  memset (p->ctp, 0xc1, sizeof p->ctp);
  memset (p->stp, 0x5e, sizeof p->stp);
  return p;
}

static void
pair_create (struct pair *p)
{
  CHECK_EQ (gq_tls_client_new (&p->c.tls, &p->cc, &p->csink), GQ_OK);
  CHECK_EQ (gq_tls_server_new (&p->s.tls, &p->sc, &p->ssink), GQ_OK);
}

static void
pair_free (struct pair *p)
{
  gq_tls_free (p->c.tls);
  gq_tls_free (p->s.tls);
  free (p);
}

static int
feed_end (struct end *dst, enum gq_level level, const uint8_t *d, size_t n,
          size_t chunk)
{
  int r = GQ_OK;

  if (chunk == 0)
    chunk = n;
  while (n > 0 && r == GQ_OK)
    {
      size_t k = n < chunk ? n : chunk;
      const uint8_t *p = d;
      size_t l = k;

      r = gq_tls_feed (dst->tls, level, &p, &l);
      d += k;
      n -= k;
    }
  return r;
}

/* Move every pending byte between the two engines until quiet.  Stops at
   the first failure and returns its status (client feed first).  */
static int
pump (struct pair *p, size_t chunk)
{
  int moved = 1, r = GQ_OK, lv;

  while (moved && r == GQ_OK)
    {
      moved = 0;
      for (lv = 0; lv < 4 && r == GQ_OK; lv++)
        {
          size_t n = p->c.sent_len[lv];

          if (n)
            {
              uint8_t buf[16384];

              memcpy (buf, p->c.sent[lv], n);
              p->c.sent_len[lv] = 0;
              r = feed_end (&p->s, (enum gq_level) lv, buf, n, chunk);
              moved = 1;
            }
        }
      for (lv = 0; lv < 4 && r == GQ_OK; lv++)
        {
          size_t n = p->s.sent_len[lv];

          if (n)
            {
              uint8_t buf[16384];

              memcpy (buf, p->s.sent[lv], n);
              p->s.sent_len[lv] = 0;
              r = feed_end (&p->c, (enum gq_level) lv, buf, n, chunk);
              moved = 1;
            }
        }
    }
  return r;
}

static const gq_tls_secret *
find (const struct end *e, enum gq_level lv, enum gq_dir d)
{
  int i;

  for (i = e->n_secrets - 1; i >= 0; i--)
    if (e->secrets[i].level == lv && e->secrets[i].dir == d)
      return &e->secrets[i];
  return NULL;
}

static int
same_secret (const gq_tls_secret *a, const gq_tls_secret *b)
{
  return a && b && a->len == b->len && a->aead == b->aead
    && memcmp (a->secret, b->secret, a->len) == 0;
}

/* The two ends must hold mirror-image keys at every level.  */
static void
check_mirror (const struct pair *p)
{
  CHECK (same_secret (find (&p->c, GQ_LEVEL_HANDSHAKE, GQ_DIR_READ),
                      find (&p->s, GQ_LEVEL_HANDSHAKE, GQ_DIR_WRITE)));
  CHECK (same_secret (find (&p->c, GQ_LEVEL_HANDSHAKE, GQ_DIR_WRITE),
                      find (&p->s, GQ_LEVEL_HANDSHAKE, GQ_DIR_READ)));
  CHECK (same_secret (find (&p->c, GQ_LEVEL_APPLICATION, GQ_DIR_READ),
                      find (&p->s, GQ_LEVEL_APPLICATION, GQ_DIR_WRITE)));
  CHECK (same_secret (find (&p->c, GQ_LEVEL_APPLICATION, GQ_DIR_WRITE),
                      find (&p->s, GQ_LEVEL_APPLICATION, GQ_DIR_READ)));
}

static void
check_exporters (const struct pair *p)
{
  uint8_t a[32], b[32];

  CHECK_EQ (gq_tls_export (p->c.tls, "EXPORTER-test", (const uint8_t *) "ctx",
                           3, a, 32), GQ_OK);
  CHECK_EQ (gq_tls_export (p->s.tls, "EXPORTER-test", (const uint8_t *) "ctx",
                           3, b, 32), GQ_OK);
  CHECK (memcmp (a, b, 32) == 0);
}

static void
check_success (const struct pair *p)
{
  CHECK (p->c.complete && p->s.complete);
  CHECK (gq_tls_is_complete (p->c.tls) && gq_tls_is_complete (p->s.tls));
  check_mirror (p);
  check_exporters (p);
  CHECK_EQ (p->c.info.cipher_suite, p->s.info.cipher_suite);
  CHECK_EQ (p->c.info.group, p->s.info.group);
  CHECK_EQ (p->c.info.hello_retry, p->s.info.hello_retry);
  CHECK_EQ (p->c.info.alpn_len, p->s.info.alpn_len);
}

/* ------------------------------------------------------------------ */
/* Tests                                                              */
/* ------------------------------------------------------------------ */

static void
test_basic (size_t chunk)
{
  struct pair *p = pair_new ();

  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, chunk), GQ_OK);
  check_success (p);
  /* Server preference is the policy order; the hybrid group leads.  */
  CHECK_EQ (p->s.info.group, GQ_GROUP_X25519_MLKEM768);
  CHECK_EQ (p->s.info.cipher_suite, GQ_TLS_AES_256_GCM_SHA384);
  /* What signed the handshake is reported by both ends; no client did.  */
  CHECK_EQ (p->s.info.sig_scheme, GQ_SIG_ECDSA_SECP256R1_SHA256);
  CHECK_EQ (p->c.info.sig_scheme, GQ_SIG_ECDSA_SECP256R1_SHA256);
  CHECK_EQ (p->s.info.client_sig_scheme, 0);
  CHECK_EQ (p->c.info.client_sig_scheme, 0);
  CHECK (p->s.info.server_name_len == 12
         && strcmp (p->s.info.server_name, "example.test") == 0);
  CHECK_EQ (p->c.info.client_auth_requested, 0);
  /* Servers do not start; clients cannot be fed before starting.  */
  CHECK_EQ (gq_tls_start (p->s.tls), GQ_ERR_INVAL);
  pair_free (p);
}

/* ---- Key log ---- */

struct keylog
{
  char line[8][512];
  int n;
};

static void
keylog_line (void *u, const char *line)
{
  struct keylog *k = u;

  if (k->n < 8)
    snprintf (k->line[k->n], sizeof k->line[0], "%s", line);
  k->n++;
}

/* The secret of the line with this label, checked against what the engine
   handed its sink; the ClientHello random is returned for comparison.  */
static int
keylog_has (const struct keylog *k, const char *label, const gq_tls_secret *s,
            char random[65])
{
  int i;
  size_t l = strlen (label);

  for (i = 0; i < k->n && i < 8; i++)
    if (strncmp (k->line[i], label, l) == 0 && k->line[i][l] == ' ')
      {
        const char *r = k->line[i] + l + 1, *sec = strchr (r, ' ');

        if (sec == NULL || sec - r != 64)
          return 0;
        memcpy (random, r, 64);
        random[64] = 0;
        return tst_eq_hex (s->secret, s->len, sec + 1);
      }
  return 0;
}

static void
test_keylog (int hrr)
{
  struct pair *p = pair_new ();
  struct keylog ck, sk;
  static const uint16_t only_p384[] = { GQ_GROUP_SECP384R1 };
  char cr[65], sr[65];
  int i, n;

  memset (&ck, 0, sizeof ck);
  memset (&sk, 0, sizeof sk);
  p->cc.keylog = keylog_line;
  p->cc.keylog_user = &ck;
  p->sc.keylog = keylog_line;
  p->sc.keylog_user = &sk;
  if (hrr)
    {
      p->sc.groups = only_p384;
      p->sc.n_groups = 1;
    }
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);

  /* Four secrets each, the same four lines at both ends.  */
  CHECK_EQ (ck.n, 4);
  CHECK_EQ (sk.n, 4);
  for (i = 0; i < ck.n; i++)
    {
      int j, found = 0;

      for (j = 0; j < sk.n; j++)
        found |= strcmp (ck.line[i], sk.line[j]) == 0;
      CHECK (found);
    }
  CHECK (keylog_has (&ck, "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                     find (&p->c, GQ_LEVEL_HANDSHAKE, GQ_DIR_WRITE), cr));
  CHECK (keylog_has (&ck, "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                     find (&p->c, GQ_LEVEL_HANDSHAKE, GQ_DIR_READ), cr));
  CHECK (keylog_has (&ck, "CLIENT_TRAFFIC_SECRET_0",
                     find (&p->c, GQ_LEVEL_APPLICATION, GQ_DIR_WRITE), cr));
  CHECK (keylog_has (&ck, "SERVER_TRAFFIC_SECRET_0",
                     find (&p->c, GQ_LEVEL_APPLICATION, GQ_DIR_READ), cr));
  CHECK (keylog_has (&sk, "CLIENT_TRAFFIC_SECRET_0",
                     find (&p->s, GQ_LEVEL_APPLICATION, GQ_DIR_READ), sr));
  CHECK (strcmp (cr, sr) == 0);

  /* The random is the one in the ClientHello, which the server saw: it
     is not the server's own.  */
  CHECK (memcmp (cr, "0000000000000000", 16) != 0);

  /* A key update changes the secrets but adds no lines.  */
  n = ck.n;
  CHECK_EQ (gq_tls_key_update (p->c.tls, 1), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  CHECK_EQ (ck.n, n);
  CHECK_EQ (sk.n, n);
  pair_free (p);
}

static void
test_hrr (int cookie)
{
  struct pair *p = pair_new ();
  static const uint16_t only_p384[] = { GQ_GROUP_SECP384R1 };

  p->sc.groups = only_p384;
  p->sc.n_groups = 1;
  p->sc.hello_retry_cookie = cookie;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.hello_retry, 1);
  CHECK_EQ (p->s.info.group, GQ_GROUP_SECP384R1);
  /* RFC 9001 section 4.1.3: everything of the exchange of hellos, the retry
     included, goes at the Initial level, on both sides, and nothing of it at
     the Handshake level.  */
  CHECK_EQ (p->s.n_ini, 2);
  CHECK (p->s.ini_seq[0] == GQ_HS_SERVER_HELLO
         && p->s.ini_seq[1] == GQ_HS_SERVER_HELLO);
  CHECK_EQ (p->c.n_ini, 2);
  CHECK (p->c.ini_seq[0] == GQ_HS_CLIENT_HELLO
         && p->c.ini_seq[1] == GQ_HS_CLIENT_HELLO);
  CHECK (p->s.hs_seq[0] == GQ_HS_ENCRYPTED_EXTENSIONS);
  pair_free (p);
}

static void
test_preferences (void)
{
  struct pair *p = pair_new ();
  static const uint16_t suites[] = { GQ_TLS_CHACHA20_POLY1305_SHA256,
                                     GQ_TLS_AES_128_GCM_SHA256 };
  static const uint16_t groups[] = { GQ_GROUP_SECP256R1, GQ_GROUP_X25519 };

  /* Server order wins: ChaCha20, and P-256 although the client also sent
     an X25519 share (it sent hybrid and X25519 shares only, so the server
     falls back to a retry for its preferred group).  */
  p->sc.suites = suites;
  p->sc.n_suites = 2;
  p->sc.groups = groups;
  p->sc.n_groups = 2;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.cipher_suite, GQ_TLS_CHACHA20_POLY1305_SHA256);
  /* The client had shares for hybrid and X25519; the server, preferring
     P-256 but having an acceptable share (X25519), avoids the retry.  */
  CHECK_EQ (p->s.info.group, GQ_GROUP_X25519);
  CHECK_EQ (p->s.info.hello_retry, 0);
  pair_free (p);
}

/* ---- Pure ML-KEM groups (draft-ietf-tls-mlkem) ---- */

static const unsigned pure_groups[] = {
  GQ_GROUP_MLKEM512, GQ_GROUP_MLKEM768, GQ_GROUP_MLKEM1024
};

/* A key generation hook that adds DELTA bytes to the client share of GROUP,
   so that its length is wrong while its content is a real key's.  The
   hooks share one user pointer, so the clock (read by clock_of) comes
   first.  */
struct bad_share
{
  uint64_t now;
  unsigned group;
  long delta;
};

static int
bad_share_gen (void *u, unsigned group, gq_kx_key *key)
{
  const struct bad_share *b = u;

  if (gq_kx_generate (group, key) != GQ_OK)
    return 1;
  if (group == b->group)
    key->share_len = (size_t) ((long) key->share_len + b->delta);
  return 0;
}

static void
test_pure_groups (void)
{
  size_t i, chunk;

  for (i = 0; i < sizeof pure_groups / sizeof pure_groups[0]; i++)
    for (chunk = 0; chunk < 2; chunk++)
      {
        unsigned g = pure_groups[i];
        uint16_t only[1], retry[2];
        struct pair *p = pair_new ();

        /* The group alone on both ends: its own share, no retry.  */
        only[0] = (uint16_t) g;
        p->cc.groups = p->sc.groups = only;
        p->cc.n_groups = p->sc.n_groups = 1;
        pair_create (p);
        CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
        CHECK_EQ (pump (p, chunk), GQ_OK);
        check_success (p);
        CHECK_EQ (p->s.info.group, g);
        CHECK_EQ (p->s.info.hello_retry, 0);
        pair_free (p);

        /* The client's first share is for X25519, which the server does
           not offer: the server retries for the pure group.  */
        p = pair_new ();
        retry[0] = GQ_GROUP_X25519;
        retry[1] = (uint16_t) g;
        p->cc.groups = retry;
        p->cc.n_groups = 2;
        p->sc.groups = only;
        p->sc.n_groups = 1;
        pair_create (p);
        CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
        CHECK_EQ (pump (p, chunk), GQ_OK);
        check_success (p);
        CHECK_EQ (p->s.info.group, g);
        CHECK_EQ (p->s.info.hello_retry, 1);
        CHECK_EQ (p->c.info.hello_retry, 1);
        pair_free (p);
      }
}

/* A pure group is only used when the application lists it: the defaults
   on either end do not include it.  */
static void
test_pure_groups_opt_in (void)
{
  size_t i;

  for (i = 0; i < sizeof pure_groups / sizeof pure_groups[0]; i++)
    {
      uint16_t only[1] = { (uint16_t) pure_groups[i] };
      struct pair *p = pair_new ();

      /* A client that lists it, a server on the default groups.  */
      p->cc.groups = only;
      p->cc.n_groups = 1;
      pair_create (p);
      CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
      CHECK_EQ (pump (p, 0), GQ_ERR_UNSUPPORTED);
      CHECK_EQ (p->s.alert, GQ_ALERT_HANDSHAKE_FAILURE);
      pair_free (p);

      /* A server that lists it, a client on the default groups.  */
      p = pair_new ();
      p->sc.groups = only;
      p->sc.n_groups = 1;
      pair_create (p);
      CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
      CHECK_EQ (pump (p, 0), GQ_ERR_UNSUPPORTED);
      CHECK_EQ (p->s.alert, GQ_ALERT_HANDSHAKE_FAILURE);
      pair_free (p);
    }
}

/* A server given a hybrid and a pure group takes the order it is given.  */
static void
test_pure_groups_order (void)
{
  static const uint16_t c_pure_first[] = { GQ_GROUP_MLKEM768,
                                           GQ_GROUP_X25519_MLKEM768 };
  static const uint16_t c_pure_x25519[] = { GQ_GROUP_MLKEM768,
                                            GQ_GROUP_X25519 };
  static const uint16_t s_x25519[] = { GQ_GROUP_X25519 };
  static const uint16_t c_x25519_first[] = { GQ_GROUP_X25519,
                                             GQ_GROUP_MLKEM768,
                                             GQ_GROUP_X25519_MLKEM768 };
  static const uint16_t s_hybrid_first[] = { GQ_GROUP_X25519_MLKEM768,
                                             GQ_GROUP_MLKEM768 };
  static const uint16_t s_pure_first[] = { GQ_GROUP_MLKEM768,
                                           GQ_GROUP_X25519_MLKEM768 };
  struct pair *p;

  /* A client that lists a plain-curve group after the pure one also sends
     a share for it, so a server without the pure group needs no retry.  */
  p = pair_new ();
  p->cc.groups = c_pure_x25519;
  p->cc.n_groups = 2;
  p->sc.groups = s_x25519;
  p->sc.n_groups = 1;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.group, GQ_GROUP_X25519);
  CHECK_EQ (p->s.info.hello_retry, 0);
  pair_free (p);

  /* The client sent a share for the pure group only; the server prefers
     the hybrid but has no share for it, so a retry is avoided.  */
  p = pair_new ();
  p->cc.groups = c_pure_first;
  p->cc.n_groups = 2;
  p->sc.groups = s_hybrid_first;
  p->sc.n_groups = 2;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.group, GQ_GROUP_MLKEM768);
  CHECK_EQ (p->s.info.hello_retry, 0);
  pair_free (p);

  /* Only an X25519 share was sent: the server's first choice decides the
     retry, whichever kind it is.  */
  p = pair_new ();
  p->cc.groups = c_x25519_first;
  p->cc.n_groups = 3;
  p->sc.groups = s_hybrid_first;
  p->sc.n_groups = 2;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.group, GQ_GROUP_X25519_MLKEM768);
  CHECK_EQ (p->s.info.hello_retry, 1);
  pair_free (p);

  p = pair_new ();
  p->cc.groups = c_x25519_first;
  p->cc.n_groups = 3;
  p->sc.groups = s_pure_first;
  p->sc.n_groups = 2;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.group, GQ_GROUP_MLKEM768);
  CHECK_EQ (p->s.info.hello_retry, 1);
  pair_free (p);
}

/* A server refuses a client share of the wrong length for a pure group
   with illegal_parameter (a missing byte, an extra one), in a first
   ClientHello and in the one that answers a retry.  */
static void
test_pure_groups_wrong_length (void)
{
  static const long deltas[] = { -1, 1 };
  size_t i, d, retry;

  for (i = 0; i < sizeof pure_groups / sizeof pure_groups[0]; i++)
    for (d = 0; d < 2; d++)
      for (retry = 0; retry < 2; retry++)
        {
          unsigned g = pure_groups[i];
          uint16_t only[1] = { (uint16_t) g };
          uint16_t after_x[2] = { GQ_GROUP_X25519, (uint16_t) g };
          struct bad_share b = { UINT64_C (1700000000000), g, deltas[d] };
          struct pair *p = pair_new ();

          p->cc.groups = retry ? after_x : only;
          p->cc.n_groups = retry ? 2 : 1;
          p->sc.groups = only;
          p->sc.n_groups = 1;
          p->cc.hooks.kx_generate = bad_share_gen;
          p->cc.hooks.user = &b;
          pair_create (p);
          CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
          CHECK_EQ (pump (p, 0), GQ_ERR_PROTOCOL);
          CHECK_EQ (p->s.alert, GQ_ALERT_ILLEGAL_PARAMETER);
          CHECK (gq_tls_is_failed (p->s.tls));
          CHECK (!p->s.complete);
          pair_free (p);
        }
}

static const gq_tls_credentials *
by_name (void *u, const char *name)
{
  int *calls = u;

  (*calls)++;
  if (name == NULL || strcmp (name, "example.test") == 0)
    return &ec_creds;
  if (strcmp (name, "other.test") == 0)
    return &rsa_creds;
  return NULL;
}

static void
test_nameless_ticket_not_rebound (void)
{
  gq_ticket_keys *keys;
  gq_tls_session sess;
  struct pair *p;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->cc.server_name = NULL;
  p->cc.trust = client_trust;
  p->cc.no_name_check = 1;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.server_name_len, 0);
  sess = p->c.session;
  pair_free (p);

  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->cc.server_name = "example.test";
  p->cc.resume = &sess;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 0);
  CHECK_EQ (p->s.info.resumed, 0);
  pair_free (p);
  gq_ticket_keys_free (keys);
}

static void
test_sni_credentials (void)
{
  struct pair *p;
  int calls = 0;

  p = pair_new ();
  p->sc.select_credentials = by_name;
  p->sc.select_user = &calls;
  p->cc.server_name = "other.test";
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (calls, 1);
  CHECK (strcmp (p->s.info.server_name, "other.test") == 0);
  pair_free (p);

  /* An unknown name is refused with unrecognized_name.  */
  p = pair_new ();
  p->sc.select_credentials = by_name;
  p->sc.select_user = &calls;
  p->cc.server_name = "nowhere.test";
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_PROTOCOL);
  CHECK_EQ (p->s.alert, 112);
  pair_free (p);

  /* No SNI: the callback sees NULL and can pick a default.  */
  p = pair_new ();
  p->sc.select_credentials = by_name;
  p->sc.select_user = &calls;
  p->cc.server_name = NULL;
  p->cc.trust = NULL;
  p->csink.verify_peer = NULL;
  {
    /* Without a name the client cannot check host names; trust the CA, and
       say so (it is refused otherwise).  */
    p->cc.trust = client_trust;
    p->cc.no_name_check = 1;
  }
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.server_name_len, 0);
  pair_free (p);

  /* The certificate type follows the client's signature algorithms: an
     Ed25519 server certificate needs a client that lists Ed25519.  */
  p = pair_new ();
  p->sc.credentials = ed_creds;
  p->cc.server_name = "ed.test";
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  pair_free (p);

  p = pair_new ();
  {
    static const uint16_t ecdsa_only[] = { GQ_SIG_ECDSA_SECP256R1_SHA256 };

    p->sc.credentials = ed_creds;
    p->cc.server_name = "ed.test";
    p->cc.sigschemes = ecdsa_only;
    p->cc.n_sigschemes = 1;
  }
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_UNSUPPORTED);
  CHECK_EQ (p->s.alert, GQ_ALERT_HANDSHAKE_FAILURE);
  pair_free (p);
}

static void
test_alpn_and_quic (void)
{
  struct pair *p;

  /* Server preference decides.  */
  p = pair_new ();
  p->calpn[0] = (gq_slice) { (const uint8_t *) "http/1.1", 8 };
  p->calpn[1] = (gq_slice) { (const uint8_t *) "h2", 2 };
  p->salpn[0] = (gq_slice) { (const uint8_t *) "h2", 2 };
  p->salpn[1] = (gq_slice) { (const uint8_t *) "http/1.1", 8 };
  p->cc.alpn = p->calpn;
  p->cc.n_alpn = 2;
  p->sc.alpn = p->salpn;
  p->sc.n_alpn = 2;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK (p->s.info.alpn_len == 2 && memcmp (p->s.info.alpn, "h2", 2) == 0);
  CHECK (p->c.info.alpn_len == 2 && memcmp (p->c.info.alpn, "h2", 2) == 0);
  pair_free (p);

  /* No overlap: no_application_protocol.  */
  p = pair_new ();
  p->calpn[0] = (gq_slice) { (const uint8_t *) "foo", 3 };
  p->salpn[0] = (gq_slice) { (const uint8_t *) "h2", 2 };
  p->cc.alpn = p->calpn;
  p->cc.n_alpn = 1;
  p->sc.alpn = p->salpn;
  p->sc.n_alpn = 1;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_PROTOCOL);
  CHECK_EQ (p->s.alert, GQ_ALERT_NO_APPLICATION_PROTOCOL);
  pair_free (p);

  /* A server with ALPN configured and a client that sends none: fine
     over TLS, selects nothing.  */
  p = pair_new ();
  p->salpn[0] = (gq_slice) { (const uint8_t *) "h2", 2 };
  p->sc.alpn = p->salpn;
  p->sc.n_alpn = 1;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.alpn_len, 0);
  pair_free (p);

  /* QUIC: transport parameters both ways, ALPN mandatory, no KeyUpdate.  */
  p = pair_new ();
  p->calpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
  p->salpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
  p->cc.alpn = p->calpn;
  p->cc.n_alpn = 1;
  p->cc.transport_params = p->ctp;
  p->cc.transport_params_len = sizeof p->ctp;
  p->cc.quic = 1;
  p->sc.alpn = p->salpn;
  p->sc.n_alpn = 1;
  p->sc.transport_params = p->stp;
  p->sc.transport_params_len = sizeof p->stp;
  p->sc.quic = 1;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK (p->s.peer_tp_len == 4 && memcmp (p->s.peer_tp, p->ctp, 4) == 0);
  CHECK (p->c.peer_tp_len == 4 && memcmp (p->c.peer_tp, p->stp, 4) == 0);
  CHECK_EQ (gq_tls_key_update (p->s.tls, 0), GQ_ERR_INVAL);
  pair_free (p);

  /* A QUIC server needs the client's transport parameters.  */
  p = pair_new ();
  p->calpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
  p->salpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
  p->cc.alpn = p->calpn;
  p->cc.n_alpn = 1;
  p->sc.alpn = p->salpn;
  p->sc.n_alpn = 1;
  p->sc.transport_params = p->stp;
  p->sc.transport_params_len = sizeof p->stp;
  p->sc.quic = 1;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_PROTOCOL);
  CHECK_EQ (p->s.alert, GQ_ALERT_MISSING_EXTENSION);
  pair_free (p);
}

static void
client_cert (struct pair *p, const gq_slice *chain, gq_privkey *key)
{
  p->cchain[0] = chain[0];
  p->cc.client_chain = p->cchain;
  p->cc.n_client_chain = 1;
  p->cc.client_key = key;
}

static void
test_client_auth (void)
{
  struct pair *p;

  /* Required, valid Ed25519 client certificate.  */
  p = pair_new ();
  p->sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
  p->sc.client_trust = server_trust;
  client_cert (p, cli_chain, cli_ok_key);
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.client_auth_requested, 1);
  CHECK_EQ (p->c.info.client_auth_sent, 1);
  CHECK_EQ (p->s.info.client_auth_requested, 1);
  CHECK_EQ (p->s.info.client_auth_sent, 1);	/* Verified.  */
  CHECK_EQ (p->s.info.client_sig_scheme, GQ_SIG_ED25519);
  CHECK_EQ (p->c.info.client_sig_scheme, GQ_SIG_ED25519);
  pair_free (p);

  /* Optional and absent: the handshake completes unauthenticated.  */
  p = pair_new ();
  p->sc.client_auth = GQ_CLIENT_AUTH_OPTIONAL;
  p->sc.client_trust = server_trust;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->s.info.client_auth_requested, 1);
  CHECK_EQ (p->s.info.client_auth_sent, 0);
  pair_free (p);

  /* Required and absent: certificate_required.  */
  p = pair_new ();
  p->sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
  p->sc.client_trust = server_trust;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_CERT);
  CHECK_EQ (p->s.alert, 116);
  pair_free (p);

  /* Certificate from an untrusted CA: unknown_ca.  */
  p = pair_new ();
  p->sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
  p->sc.client_trust = server_trust;
  client_cert (p, clibad_chain, cli_bad_key);
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_CERT);
  CHECK_EQ (p->s.alert, GQ_ALERT_UNKNOWN_CA);
  pair_free (p);

  /* A serverAuth-only certificate cannot authenticate a client.  */
  p = pair_new ();
  p->sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
  p->sc.client_trust = server_trust;
  client_cert (p, clieku_chain, cli_eku_key);
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_CERT);
  CHECK_EQ (p->s.alert, GQ_ALERT_BAD_CERTIFICATE);
  pair_free (p);

  /* Asking for certificates with no way to verify them is refused when
     the engine is created.  */
  {
    gq_tls *t;
    gq_tls_server_config sc;
    struct end e;
    gq_tls_sink sk = sink_for (&e);

    memset (&sc, 0, sizeof sc);
    sc.credentials = ec_creds;
    sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
    CHECK_EQ (gq_tls_server_new (&t, &sc, &sk), GQ_ERR_INVAL);
    sc.client_auth = GQ_CLIENT_AUTH_NONE;
    sc.credentials.key = NULL;
    CHECK_EQ (gq_tls_server_new (&t, &sc, &sk), GQ_ERR_INVAL);
  }
}

/* Accept any chain: the validation of a chain with an ML-DSA key in it is
   GnuTLS's, and an older one cannot (tst_gnutls_validates_mldsa), but the
   handshake's signatures are not its concern.  */
static int
accept_chain (void *u, const gq_slice *chain, size_t n, const char *name)
{
  (void) u; (void) chain; (void) n; (void) name;
  return 0;
}

/* A handshake with an ML-DSA key (FIPS 204; scheme codes of
   draft-ietf-tls-mldsa) signing the server's CertificateVerify, and a
   client's.  The signature is 2420 to 4627 bytes, so the flight is far
   larger than with any classical key; it is fed whole and a byte at a
   time.  The certificates are made without GnuTLS's help (a classical CA
   over an ML-DSA key, tst-mldsa-cert.h), so this runs wherever the library
   does.  VALIDATE says whether the chains are validated (by GnuTLS, which
   only some can do for an ML-DSA key) or accepted by a callback.  */
static void
mldsa_handshakes (int validate)
{
  static const uint16_t schemes[] = { GQ_SIG_MLDSA44, GQ_SIG_MLDSA65,
                                      GQ_SIG_MLDSA87 };
  static struct tst_mlident srv, cli;
  size_t i, chunk;
  struct pair *p;

#define NEW_PAIR() \
  do { \
    p = pair_new (); \
    if (!validate) \
      p->csink.verify_peer = p->ssink.verify_peer = accept_chain; \
  } while (0)

  CHECK (gq_sigscheme_available (GQ_SIG_MLDSA65));
  for (i = 0; i < 3; i++)
    {
      uint16_t only[1] = { schemes[i] };

      CHECK_EQ (tst_make_mldsa_cert (&srv, schemes[i], "ML-DSA", "example.test",
                                     0, &ca, -3600, 86400), 0);
      for (chunk = 0; chunk < 2; chunk++)
        {
          /* Offering only that scheme: nothing else could have signed.  */
          NEW_PAIR ();
          p->sc.credentials = (gq_tls_credentials) { srv.chain, 1, srv.key };
          p->cc.sigschemes = p->sc.sigschemes = only;
          p->cc.n_sigschemes = p->sc.n_sigschemes = 1;
          pair_create (p);
          CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
          CHECK_EQ (pump (p, chunk), GQ_OK);
          check_success (p);
          CHECK_EQ (p->s.info.sig_scheme, schemes[i]);
          CHECK_EQ (p->c.info.sig_scheme, schemes[i]);
          pair_free (p);

          /* With the default lists: the key decides.  */
          NEW_PAIR ();
          p->sc.credentials = (gq_tls_credentials) { srv.chain, 1, srv.key };
          pair_create (p);
          CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
          CHECK_EQ (pump (p, chunk), GQ_OK);
          check_success (p);
          CHECK_EQ (p->s.info.sig_scheme, schemes[i]);
          CHECK_EQ (p->c.info.sig_scheme, schemes[i]);
          pair_free (p);
        }

      /* A client that offers another parameter set only cannot be signed
         for.  */
      NEW_PAIR ();
      {
        uint16_t other[1] = { schemes[(i + 1) % 3] };

        p->sc.credentials = (gq_tls_credentials) { srv.chain, 1, srv.key };
        p->cc.sigschemes = other;
        p->cc.n_sigschemes = 1;
        pair_create (p);
        CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
        CHECK (pump (p, 0) != GQ_OK);
        CHECK_EQ (p->s.alert, GQ_ALERT_HANDSHAKE_FAILURE);
        CHECK (!p->c.complete && !p->s.complete);
        pair_free (p);
      }

      /* A client that offers no ML-DSA at all, with a server whose only key
         is one.  */
      NEW_PAIR ();
      {
        uint16_t classical[2] = { GQ_SIG_ED25519,
                                  GQ_SIG_ECDSA_SECP256R1_SHA256 };

        p->sc.credentials = (gq_tls_credentials) { srv.chain, 1, srv.key };
        p->cc.sigschemes = classical;
        p->cc.n_sigschemes = 2;
        pair_create (p);
        CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
        CHECK (pump (p, 0) != GQ_OK);
        CHECK (!p->c.complete && !p->s.complete);
        pair_free (p);
      }
      tst_free_mldsa_cert (&srv);
    }

  /* A client certificate with an ML-DSA key.  */
  CHECK_EQ (tst_make_mldsa_cert (&cli, GQ_SIG_MLDSA65, "client", "client.test",
                                 1, &ca, -3600, 86400), 0);
  for (chunk = 0; chunk < 2; chunk++)
    {
      NEW_PAIR ();
      p->sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
      p->sc.client_trust = server_trust;
      client_cert (p, cli.chain, cli.key);
      pair_create (p);
      CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
      CHECK_EQ (pump (p, chunk), GQ_OK);
      check_success (p);
      CHECK_EQ (p->s.info.client_auth_requested, 1);
      CHECK_EQ (p->c.info.client_auth_sent, 1);
      CHECK_EQ (p->s.info.client_auth_sent, 1);	/* Verified.  */
      CHECK_EQ (p->s.info.client_sig_scheme, GQ_SIG_MLDSA65);
      CHECK_EQ (p->c.info.client_sig_scheme, GQ_SIG_MLDSA65);
      pair_free (p);
    }
  tst_free_mldsa_cert (&cli);
#undef NEW_PAIR
}

static void
test_mldsa_handshake (void)
{
  mldsa_handshakes (0);
  if (tst_mldsa_ready (tst_gnutls_validates_mldsa (),
                       "the ML-DSA handshakes with validated chains"))
    mldsa_handshakes (1);
}

#if TST_HAVE_MLDSA

struct mldsa_ident
{
  struct tst_cert c;
  uint8_t der[16384];		/* A chain signed by ML-DSA is big.  */
  gq_slice chain[1];
  gq_privkey *key;
};

static void
mldsa_ident (struct mldsa_ident *id, enum tst_key kind,
             const struct tst_cert *issuer, const char *san, const char *eku)
{
  CHECK_EQ (tst_make_cert_eku (&id->c, kind, "ML-DSA", san, issuer, -3600,
                               86400, GNUTLS_DIG_SHA256, eku), 0);
  id->chain[0] = (gq_slice) { id->der, der_of (&id->c, id->der) };
  id->key = key_of (&id->c);
}

static void
mldsa_ident_free (struct mldsa_ident *id)
{
  gq_privkey_free (id->key);
  tst_free_cert (&id->c);
}

#endif

/* Both ends' certificates under an ML-DSA root: every signature in the chain
   and in the handshake is post-quantum.  Validating the chain is GnuTLS's
   work (trust.c), and checking an ML-DSA signature on a certificate needs the
   ML-DSA backend of GnuTLS, so this runs only where it has one
   (GQ_EXPECT_MLDSA makes its absence a failure).  */
static void
test_mldsa_handshake_pq_root (void)
{
#if !TST_HAVE_MLDSA
  tst_mldsa_ready (0, "the ML-DSA root handshake test");
#else
  static struct mldsa_ident leaf;
  static struct tst_cert root;
  struct pair *p;
  gq_trust *pq_trust;

  if (!tst_mldsa_ready (tst_gnutls_mldsa (), "the ML-DSA root handshake test"))
    return;
  CHECK_EQ (tst_make_cert (&root, TST_MLDSA87, "ML-DSA root", NULL, NULL,
                           -3600, 86400, GNUTLS_DIG_UNKNOWN), 0);
  mldsa_ident (&leaf, TST_MLDSA44, &root, "example.test",
               GNUTLS_KP_TLS_WWW_SERVER);
  pq_trust = trust_of (&root);

  p = pair_new ();
  p->cc.trust = pq_trust;
  p->sc.credentials = (gq_tls_credentials) { leaf.chain, 1, leaf.key };
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  pair_free (p);

  /* The classical trust anchor does not vouch for it.  */
  p = pair_new ();
  p->sc.credentials = (gq_tls_credentials) { leaf.chain, 1, leaf.key };
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_CERT);
  CHECK_EQ (p->c.alert, GQ_ALERT_UNKNOWN_CA);
  pair_free (p);

  gq_trust_free (pq_trust);
  mldsa_ident_free (&leaf);
  tst_free_cert (&root);
#endif
}

static void
test_key_update (void)
{
  struct pair *p = pair_new ();
  int before_c, before_s;
  uint8_t next[48];
  const gq_tls_secret *cw, *sw;

  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);

  /* Client asks; the server rekeys its read side, answers and rekeys its
     write side; the client follows.  */
  before_c = p->c.n_secrets;
  before_s = p->s.n_secrets;
  CHECK_EQ (gq_tls_key_update (p->c.tls, 1), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  CHECK_EQ (p->c.n_secrets, before_c + 2);	/* Write, then read.  */
  CHECK_EQ (p->s.n_secrets, before_s + 2);	/* Read, then write.  */
  check_mirror (p);
  cw = find (&p->c, GQ_LEVEL_APPLICATION, GQ_DIR_WRITE);
  sw = find (&p->s, GQ_LEVEL_APPLICATION, GQ_DIR_WRITE);
  CHECK (cw != sw && memcmp (cw->secret, sw->secret, cw->len) != 0);
  (void) next;

  /* Server-initiated, not asking for a reply.  */
  before_c = p->c.n_secrets;
  CHECK_EQ (gq_tls_key_update (p->s.tls, 0), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  CHECK_EQ (p->c.n_secrets, before_c + 1);
  check_mirror (p);
  pair_free (p);
}

/* ---- ClientHello failures, by crafting or mutating ---- */

/* Client hello bytes produced by a fresh client.  */
static size_t
client_hello (struct pair *p, uint8_t *out)
{
  size_t n;

  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  n = p->c.sent_len[GQ_LEVEL_INITIAL];
  memcpy (out, p->c.sent[GQ_LEVEL_INITIAL], n);
  p->c.sent_len[GQ_LEVEL_INITIAL] = 0;
  return n;
}

/* Remove extension TYPE from a ClientHello by renaming it to an unknown
   type (keeps all lengths intact).  */
static int
rename_ext (uint8_t *ch, size_t n, unsigned type, unsigned to)
{
  gq_slice exts, v, rest;
  gq_client_hello c;
  unsigned t;

  if (gq_client_hello_parse ((gq_slice) { ch + 4, n - 4 }, &c) != GQ_OK)
    return 0;
  exts = c.extensions;
  rest = exts;
  while (gq_ext_next (&rest, &t, &v) == 1)
    if (t == type)
      {
        uint8_t *p = ch + (v.data - ch) - 4;

        p[0] = (uint8_t) (to >> 8);
        p[1] = (uint8_t) to;
        return 1;
      }
  return 0;
}

static void
expect_server_fail (struct pair *p, const uint8_t *ch, size_t n, int status,
                    int alert)
{
  int r = feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0);

  CHECK_EQ (r, status);
  CHECK_EQ (p->s.alert, alert);
  CHECK (gq_tls_is_failed (p->s.tls));
  /* A failed engine refuses more input.  */
  {
    const uint8_t b[4] = { 0 };
    const uint8_t *q = b;
    size_t l = 4;

    CHECK_EQ (gq_tls_feed (p->s.tls, GQ_LEVEL_INITIAL, &q, &l), GQ_ERR_INVAL);
  }
}

static void
test_client_hello_failures (void)
{
  struct pair *p;
  uint8_t ch[8192];
  size_t n;

  /* Missing mandatory extensions.  */
  p = pair_new ();
  pair_create (p);
  n = client_hello (p, ch);
  CHECK (rename_ext (ch, n, GQ_EXT_SIGNATURE_ALGORITHMS, 0x0fff));
  expect_server_fail (p, ch, n, GQ_ERR_PROTOCOL, GQ_ALERT_MISSING_EXTENSION);
  pair_free (p);

  p = pair_new ();
  pair_create (p);
  n = client_hello (p, ch);
  CHECK (rename_ext (ch, n, GQ_EXT_KEY_SHARE, 0x0fff));
  expect_server_fail (p, ch, n, GQ_ERR_PROTOCOL, GQ_ALERT_MISSING_EXTENSION);
  pair_free (p);

  p = pair_new ();
  pair_create (p);
  n = client_hello (p, ch);
  CHECK (rename_ext (ch, n, GQ_EXT_SUPPORTED_GROUPS, 0x0fff));
  expect_server_fail (p, ch, n, GQ_ERR_PROTOCOL, GQ_ALERT_MISSING_EXTENSION);
  pair_free (p);

  /* No supported_versions: a TLS 1.2 client.  */
  p = pair_new ();
  pair_create (p);
  n = client_hello (p, ch);
  CHECK (rename_ext (ch, n, GQ_EXT_SUPPORTED_VERSIONS, 0x0fff));
  expect_server_fail (p, ch, n, GQ_ERR_PROTOCOL, GQ_ALERT_PROTOCOL_VERSION);
  pair_free (p);

  /* Old legacy_version.  */
  p = pair_new ();
  pair_create (p);
  n = client_hello (p, ch);
  ch[4] = 3; ch[5] = 1;
  expect_server_fail (p, ch, n, GQ_ERR_PROTOCOL, GQ_ALERT_PROTOCOL_VERSION);
  pair_free (p);

  /* No suite in common.  */
  p = pair_new ();
  {
    static const uint16_t s_only[] = { GQ_TLS_CHACHA20_POLY1305_SHA256 };
    static const uint16_t c_only[] = { GQ_TLS_AES_128_GCM_SHA256 };

    p->sc.suites = s_only;
    p->sc.n_suites = 1;
    p->cc.suites = c_only;
    p->cc.n_suites = 1;
  }
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_UNSUPPORTED);
  CHECK_EQ (p->s.alert, GQ_ALERT_HANDSHAKE_FAILURE);
  pair_free (p);

  /* No group in common.  */
  p = pair_new ();
  {
    static const uint16_t s_only[] = { GQ_GROUP_SECP384R1 };
    static const uint16_t c_only[] = { GQ_GROUP_X25519 };

    p->sc.groups = s_only;
    p->sc.n_groups = 1;
    p->cc.groups = c_only;
    p->cc.n_groups = 1;
  }
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_ERR_UNSUPPORTED);
  CHECK_EQ (p->s.alert, GQ_ALERT_HANDSHAKE_FAILURE);
  pair_free (p);

  /* Wrong first message: Finished where a ClientHello belongs; and a
     ClientHello at the wrong level.  */
  p = pair_new ();
  pair_create (p);
  {
    uint8_t fin[36] = { GQ_HS_FINISHED, 0, 0, 32 };

    expect_server_fail (p, fin, sizeof fin, GQ_ERR_PROTOCOL,
                        GQ_ALERT_UNEXPECTED_MESSAGE);
  }
  pair_free (p);
  p = pair_new ();
  pair_create (p);
  n = client_hello (p, ch);
  CHECK_EQ (feed_end (&p->s, GQ_LEVEL_HANDSHAKE, ch, n, 0), GQ_ERR_PROTOCOL);
  CHECK_EQ (p->s.alert, GQ_ALERT_UNEXPECTED_MESSAGE);
  pair_free (p);

  /* Absurd declared length.  */
  p = pair_new ();
  pair_create (p);
  {
    uint8_t hdr[4] = { GQ_HS_CLIENT_HELLO, 0x10, 0, 0 };

    expect_server_fail (p, hdr, 4, GQ_ERR_PROTOCOL, GQ_ALERT_ILLEGAL_PARAMETER);
  }
  pair_free (p);

  /* A second ClientHello after the handshake started, or after it ended.  */
  p = pair_new ();
  pair_create (p);
  n = client_hello (p, ch);
  CHECK_EQ (feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0), GQ_OK);
  CHECK_EQ (feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0), GQ_ERR_PROTOCOL);
  CHECK_EQ (p->s.alert, GQ_ALERT_UNEXPECTED_MESSAGE);
  pair_free (p);
}

static void
test_hrr_client_hello_failures (void)
{
  int variant;

  /* After a HelloRetryRequest, ClientHello2 must repeat ClientHello1.  */
  for (variant = 0; variant < 5; variant++)
    {
      struct pair *p = pair_new ();
      static const uint16_t only_p384[] = { GQ_GROUP_SECP384R1 };
      uint8_t ch1[8192], ch2[8192];
      size_t n1, n2;
      uint8_t *body;
      int r, want_alert;

      p->sc.groups = only_p384;
      p->sc.n_groups = 1;
      p->sc.hello_retry_cookie = (variant == 3 || variant == 4);
      pair_create (p);
      n1 = client_hello (p, ch1);
      CHECK_EQ (feed_end (&p->s, GQ_LEVEL_INITIAL, ch1, n1, 0), GQ_OK);
      /* The server answered with a HelloRetryRequest; the client replies.  */
      {
        uint8_t hrr[8192];
        size_t hn = p->s.sent_len[GQ_LEVEL_INITIAL];

        memcpy (hrr, p->s.sent[GQ_LEVEL_INITIAL], hn);
        p->s.sent_len[GQ_LEVEL_INITIAL] = 0;
        CHECK_EQ (feed_end (&p->c, GQ_LEVEL_INITIAL, hrr, hn, 0), GQ_OK);
      }
      n2 = p->c.sent_len[GQ_LEVEL_INITIAL];
      memcpy (ch2, p->c.sent[GQ_LEVEL_INITIAL], n2);
      p->c.sent_len[GQ_LEVEL_INITIAL] = 0;
      body = ch2 + 4;

      switch (variant)
        {
        case 0:			/* Different random.  */
          body[2] ^= 1;
          want_alert = GQ_ALERT_ILLEGAL_PARAMETER;
          break;
        case 1:			/* Different session ID.  */
          body[2 + 32 + 1] ^= 1;
          want_alert = GQ_ALERT_ILLEGAL_PARAMETER;
          break;
        case 2:			/* Cipher suites changed.  */
          body[2 + 32 + 1 + 32 + 2 + 1] ^= 0x04;
          want_alert = GQ_ALERT_ILLEGAL_PARAMETER;
          break;
        case 3:			/* Cookie not echoed.  */
          CHECK (rename_ext (ch2, n2, GQ_EXT_COOKIE, 0x0fff));
          want_alert = GQ_ALERT_MISSING_EXTENSION;
          break;
        default:		/* Wrong cookie.  */
          {
            gq_client_hello c;
            gq_slice v;

            CHECK_EQ (gq_client_hello_parse ((gq_slice) { ch2 + 4, n2 - 4 },
                                             &c), GQ_OK);
            CHECK (gq_ext_find (c.extensions, GQ_EXT_COOKIE, &v));
            ch2[(size_t) (v.data - ch2) + 5] ^= 1;
          }
          want_alert = GQ_ALERT_ILLEGAL_PARAMETER;
          break;
        }
      r = feed_end (&p->s, GQ_LEVEL_INITIAL, ch2, n2, 0);
      CHECK_EQ (r, GQ_ERR_PROTOCOL);
      CHECK_EQ (p->s.alert, want_alert);
      pair_free (p);
    }
}

static void
test_finished_failures (void)
{
  struct pair *p = pair_new ();
  uint8_t out[16384];
  size_t n;
  int lv;

  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  /* Run until the client's Finished is pending, then corrupt it.  */
  for (lv = 0; lv < 4; lv++)
    {
      n = p->c.sent_len[lv];
      if (n)
        {
          memcpy (out, p->c.sent[lv], n);
          p->c.sent_len[lv] = 0;
          CHECK_EQ (feed_end (&p->s, (enum gq_level) lv, out, n, 0), GQ_OK);
        }
    }
  for (lv = 0; lv < 4; lv++)
    {
      n = p->s.sent_len[lv];
      if (n)
        {
          memcpy (out, p->s.sent[lv], n);
          p->s.sent_len[lv] = 0;
          CHECK_EQ (feed_end (&p->c, (enum gq_level) lv, out, n, 0), GQ_OK);
        }
    }
  n = p->c.sent_len[GQ_LEVEL_HANDSHAKE];
  CHECK_EQ (n, 4 + 48);		/* Finished under SHA-384.  */
  memcpy (out, p->c.sent[GQ_LEVEL_HANDSHAKE], n);
  out[n - 1] ^= 1;
  CHECK_EQ (feed_end (&p->s, GQ_LEVEL_HANDSHAKE, out, n, 0), GQ_ERR_CRYPTO);
  CHECK_EQ (p->s.alert, GQ_ALERT_DECRYPT_ERROR);
  CHECK (!p->s.complete);
  pair_free (p);
}

/* Corrupt the client's messages every way and check that the server never
   crashes and only completes with matching keys.  */
static unsigned long long rng = 0x2545f4914f6cdd1dULL;

static unsigned
rnd_below (unsigned n)
{
  rng ^= rng << 13;
  rng ^= rng >> 7;
  rng ^= rng << 17;
  return (unsigned) (rng % n);
}

static void
test_mutations (int iterations)
{
  int it, completed = 0, failed = 0;

  for (it = 0; it < iterations; it++)
    {
      struct pair *p = pair_new ();
      uint8_t ch[8192];
      size_t n, i, chunk;
      int r, nmut = (int) rnd_below (4);

      if (rnd_below (4) == 0)
        {
          static const uint16_t g[] = { GQ_GROUP_SECP256R1 };

          p->sc.groups = g;
          p->sc.n_groups = 1;
        }
      if (rnd_below (3) == 0)
        {
          p->sc.client_auth = GQ_CLIENT_AUTH_OPTIONAL;
          p->sc.client_trust = server_trust;
          client_cert (p, cli_chain, cli_ok_key);
        }
      pair_create (p);
      n = client_hello (p, ch);
      for (i = 0; i < (size_t) nmut; i++)
        ch[rnd_below ((unsigned) n)] ^= (uint8_t) (1u << rnd_below (8));
      if (rnd_below (8) == 0)
        n = rnd_below ((unsigned) n + 1);
      chunk = rnd_below (3) == 0 ? 1 + rnd_below (300) : 0;

      r = feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, chunk);
      if (r == GQ_OK)
        r = pump (p, chunk);
      if (r != GQ_OK)
        {
          failed++;
          CHECK (gq_tls_is_failed (p->s.tls) || gq_tls_is_failed (p->c.tls));
        }
      if (p->s.complete)
        {
          completed++;
          CHECK (p->c.complete);
          check_mirror (p);
        }
      pair_free (p);
    }
  CHECK (failed > 0);
  fprintf (stderr, "server mutations: %d completed, %d failed of %d\n",
           completed, failed, iterations);
}


/* ------------------------------------------------------------------ */
/* Resumption                                                         */
/* ------------------------------------------------------------------ */

/* Full handshake with tickets enabled; leaves the client's last session
   in SESSION.  */
static void
first_connection (gq_ticket_keys *keys, gq_tls_session *session,
                  const struct pair *tmpl_unused)
{
  struct pair *p = pair_new ();

  (void) tmpl_unused;
  p->sc.ticket_keys = keys;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 0);
  CHECK_EQ (p->c.n_tickets, 2);
  CHECK (p->s.n_hs == 4 && p->s.hs_seq[1] == GQ_HS_CERTIFICATE);
  /* RFC 9001 section 4.1.3: tickets follow in 1-RTT, not after Finished at
     the Handshake level.  */
  CHECK_EQ (p->s.n_app, 2);
  CHECK (p->s.app_seq[0] == GQ_HS_NEW_SESSION_TICKET
         && p->s.app_seq[1] == GQ_HS_NEW_SESSION_TICKET);
  *session = p->c.session;
  pair_free (p);
}

static void
test_resumption_basic (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess, restored;
  struct pair *p;
  uint8_t blob[GQ_TICKET_MAX + 128];
  size_t n;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  first_connection (keys, &sess, NULL);

  /* Resume, including from a session that went through storage.  */
  CHECK_EQ (gq_tls_session_serialize (&sess, blob, sizeof blob, &n), GQ_OK);
  CHECK_EQ (gq_tls_session_deserialize (&restored, blob, n), GQ_OK);
  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->cc.resume = &restored;
  p->cnow = p->snow += 5000;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 1);
  CHECK_EQ (p->s.info.resumed, 1);
  /* No certificate exchange: EncryptedExtensions and Finished only.  */
  CHECK (p->s.n_hs == 2 && p->s.hs_seq[0] == GQ_HS_ENCRYPTED_EXTENSIONS
         && p->s.hs_seq[1] == GQ_HS_FINISHED);
  /* The resumed session issues fresh tickets, usable in turn.  */
  CHECK_EQ (p->c.n_tickets, 2);
  CHECK (memcmp (p->c.session.ticket, sess.ticket, 16) == 0);	/* Same key.  */
  CHECK (memcmp (p->c.session.psk, sess.psk, sess.psk_len) != 0);
  sess = p->c.session;
  pair_free (p);

  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->cc.resume = &sess;
  p->cnow = p->snow += 10000;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 1);
  pair_free (p);

  /* Chunked delivery and a different key derivation still agree.  */
  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->cc.resume = &restored;
  p->cnow = p->snow += 5000;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 1), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 1);
  pair_free (p);
  gq_ticket_keys_free (keys);
}

/* RFC 9001 section 8.4: a client does not ask for the middlebox
   compatibility mode over QUIC, and a server treats a ClientHello with a
   session ID as an error rather than echoing it.  */
static void
test_quic_server_refuses_session_id (void)
{
  struct pair *p;
  uint8_t ch[8192];
  size_t n, k;
  int r;

  for (k = 0; k < 2; k++)
    {
      p = pair_new ();
      p->calpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
      p->salpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
      p->cc.alpn = p->calpn;
      p->cc.n_alpn = 1;
      p->cc.transport_params = p->ctp;
      p->cc.transport_params_len = sizeof p->ctp;
      p->cc.quic = 1;
      p->sc.alpn = p->salpn;
      p->sc.n_alpn = 1;
      p->sc.transport_params = p->stp;
      p->sc.transport_params_len = sizeof p->stp;
      p->sc.quic = 1;
      pair_create (p);
      n = client_hello (p, ch);
      CHECK (n > 4 + 2 + 32 + 1 && ch[4 + 2 + 32] == 0);
      if (k && n > 4 + 2 + 32 + 1 && n + 32 <= sizeof ch)
        {
          /* A session ID of 32 bytes put in.  */
          memmove (ch + 4 + 2 + 32 + 1 + 32, ch + 4 + 2 + 32 + 1,
                   n - (4 + 2 + 32 + 1));
          ch[4 + 2 + 32] = 32;
          memset (ch + 4 + 2 + 32 + 1, 0x99, 32);
          n += 32;
          ch[1] = (uint8_t) ((n - 4) >> 16);
          ch[2] = (uint8_t) ((n - 4) >> 8);
          ch[3] = (uint8_t) (n - 4);
        }
      r = feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0);
      if (k)
        {
          CHECK_EQ (r, GQ_ERR_PROTOCOL);
          CHECK_EQ (p->s.alert, GQ_ALERT_ILLEGAL_PARAMETER);
        }
      else
        CHECK_EQ (r, GQ_OK);		/* Control: as the client made it.  */
      pair_free (p);
    }
}

/* RFC 8446 section 4.1.3: a HelloRetryRequest is a ServerHello and its
   legacy_version is 0x0303 as well.  */
static void
test_hrr_legacy_version (void)
{
  int variant;

  for (variant = 0; variant < 2; variant++)
    {
      struct pair *p = pair_new ();
      static const uint16_t only_p384[] = { GQ_GROUP_SECP384R1 };
      uint8_t ch[8192], hrr[8192];
      size_t n, hn;
      int r;

      p->sc.groups = only_p384;
      p->sc.n_groups = 1;
      pair_create (p);
      n = client_hello (p, ch);
      CHECK_EQ (feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0), GQ_OK);
      hn = p->s.sent_len[GQ_LEVEL_INITIAL];
      memcpy (hrr, p->s.sent[GQ_LEVEL_INITIAL], hn);
      p->s.sent_len[GQ_LEVEL_INITIAL] = 0;
      CHECK (hrr[0] == GQ_HS_SERVER_HELLO && hrr[4] == 3 && hrr[5] == 3);
      if (variant)
        hrr[5] = 4;			/* 0x0304.  */
      r = feed_end (&p->c, GQ_LEVEL_INITIAL, hrr, hn, 0);
      if (variant)
        {
          CHECK_EQ (r, GQ_ERR_PROTOCOL);
          CHECK_EQ (p->c.alert, GQ_ALERT_ILLEGAL_PARAMETER);
        }
      else
        CHECK_EQ (r, GQ_OK);
      pair_free (p);
    }
}

/* Servers behind one address share ticket keys and their clocks differ a
   little: a ticket another one issued a few seconds "in the future" is
   good, one far in the future is not.  */
static void
test_ticket_from_a_clock_slightly_ahead (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess;
  static const int64_t behind_ms[] = { 30000, 120000 };
  size_t i;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  first_connection (keys, &sess, NULL);
  for (i = 0; i < 2; i++)
    {
      struct pair *p = pair_new ();

      p->sc.ticket_keys = keys;
      p->cc.resume = &sess;
      p->cnow += 5000;			/* The client's clock goes on.  */
      p->snow -= (uint64_t) behind_ms[i];	/* This server's is behind.  */
      pair_create (p);
      CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
      CHECK_EQ (pump (p, 0), GQ_OK);
      check_success (p);
      CHECK_EQ (p->s.info.resumed, (int) (i == 0));
      pair_free (p);
    }
  gq_ticket_keys_free (keys);
}

static int g_lookups;

static int
counting_lookup (void *u, const uint8_t *id, size_t n, gq_session_state *st)
{
  (void) u;
  (void) id;
  (void) n;
  (void) st;
  g_lookups++;
  return 1;			/* Not one of ours.  */
}

/* A ClientHello is up to 64 KB, which holds more than a thousand PSK
   identities.  Each is looked up (the ticket opened or the application's
   callback, often a database) before anything about the client has been
   shown to be true, so a bounded number are tried.  Rewrites the
   pre_shared_key extension of the hello in CH (LEN bytes, a handshake
   message) to carry N bogus identities and their binders; returns the new
   length.  */
static size_t
many_identities (uint8_t *ch, size_t len, size_t cap, unsigned n,
                 unsigned n_bind)
{
  size_t pos = 4 + 2 + 32, ext_off, ext_end, psk_off = 0, i;
  unsigned k;
  size_t ids_len = n * (2 + 16 + 4), bind_len = n_bind * (1 + 32), ext_len;

  pos += 1 + ch[pos];				/* Session ID.  */
  pos += 2 + (((size_t) ch[pos] << 8) | ch[pos + 1]);	/* Suites.  */
  pos += 1 + ch[pos];				/* Compression.  */
  ext_off = pos;
  ext_end = pos + 2 + (((size_t) ch[pos] << 8) | ch[pos + 1]);
  CHECK_EQ (ext_end, len);
  for (i = ext_off + 2; i < ext_end;)
    {
      size_t l = ((size_t) ch[i + 2] << 8) | ch[i + 3];

      if (ch[i] == 0x00 && ch[i + 1] == 0x29)
        psk_off = i;
      i += 4 + l;
    }
  CHECK (psk_off != 0);
  ext_len = 2 + ids_len + 2 + bind_len;
  CHECK (psk_off + 4 + ext_len <= cap);
  ch[psk_off + 2] = (uint8_t) (ext_len >> 8);
  ch[psk_off + 3] = (uint8_t) ext_len;
  i = psk_off + 4;
  ch[i++] = (uint8_t) (ids_len >> 8);
  ch[i++] = (uint8_t) ids_len;
  for (k = 0; k < n; k++)
    {
      ch[i++] = 0;
      ch[i++] = 16;
      memset (ch + i, (int) (0x10 + k), 16);
      i += 16;
      memset (ch + i, 0, 4);		/* Obfuscated age.  */
      i += 4;
    }
  ch[i++] = (uint8_t) (bind_len >> 8);
  ch[i++] = (uint8_t) bind_len;
  for (k = 0; k < n_bind; k++)
    {
      ch[i++] = 32;
      memset (ch + i, 0x77, 32);
      i += 32;
    }
  /* Extensions block and handshake message lengths.  */
  ch[ext_off] = (uint8_t) ((i - ext_off - 2) >> 8);
  ch[ext_off + 1] = (uint8_t) (i - ext_off - 2);
  ch[1] = (uint8_t) ((i - 4) >> 16);
  ch[2] = (uint8_t) ((i - 4) >> 8);
  ch[3] = (uint8_t) (i - 4);
  return i;
}

/* The pre_shared_key extension is held to its rules (RFC 8446 section
   4.2.11): last in the hello, one binder for each identity, and only with
   psk_key_exchange_modes; with psk_ke alone (which is not supported) the
   ticket is not looked at and the handshake is a full one.  */
static void
test_psk_extension_rules (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess;
  int variant;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  first_connection (keys, &sess, NULL);
  for (variant = 0; variant < 5; variant++)
    {
      struct pair *p = pair_new ();
      uint8_t ch[16384];
      size_t n;
      int r;

      p->cc.resume = &sess;
      p->sc.psk_lookup = counting_lookup;
      p->cnow = p->snow += 5000;
      pair_create (p);
      CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
      n = p->c.sent_len[GQ_LEVEL_INITIAL];
      memcpy (ch, p->c.sent[GQ_LEVEL_INITIAL], n);
      switch (variant)
        {
        case 1:			/* Another extension after it.  */
          CHECK (n + 4 <= sizeof ch);
          {
            size_t ext_off = 4 + 2 + 32, e;

            ext_off += 1 + ch[ext_off];
            ext_off += 2 + (((size_t) ch[ext_off] << 8) | ch[ext_off + 1]);
            ext_off += 1 + ch[ext_off];
            e = ((size_t) ch[ext_off] << 8 | ch[ext_off + 1]) + 4;
            ch[ext_off] = (uint8_t) (e >> 8);
            ch[ext_off + 1] = (uint8_t) e;
            ch[n] = 0x0a;		/* A GREASE extension, empty.  */
            ch[n + 1] = 0x0a;
            ch[n + 2] = 0;
            ch[n + 3] = 0;
            n += 4;
            ch[1] = (uint8_t) ((n - 4) >> 16);
            ch[2] = (uint8_t) ((n - 4) >> 8);
            ch[3] = (uint8_t) (n - 4);
          }
          break;
        case 2:			/* Two identities, one binder.  */
          n = many_identities (ch, n, sizeof ch, 2, 1);
          break;
        case 3:			/* No psk_key_exchange_modes.  */
          CHECK (rename_ext (ch, n, GQ_EXT_PSK_KEY_EXCHANGE_MODES, 0x0fff));
          break;
        case 4:			/* psk_ke only.  */
          {
            gq_client_hello c;
            gq_slice v;

            CHECK_EQ (gq_client_hello_parse ((gq_slice) { ch + 4, n - 4 }, &c),
                      GQ_OK);
            CHECK (gq_ext_find (c.extensions, GQ_EXT_PSK_KEY_EXCHANGE_MODES,
                                &v));
            CHECK (v.len == 2 && v.data[0] == 1);
            ch[(size_t) (v.data - ch) + 1] = 0;
          }
          break;
        default:
          break;
        }
      g_lookups = 0;
      r = feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0);
      if (variant == 0 || variant == 4)
        {
          CHECK_EQ (r, GQ_OK);
          /* The control looks the ticket up; without psk_dhe_ke it is not
             used at all.  */
          CHECK_EQ (g_lookups, variant == 0 ? 1 : 0);
          CHECK_EQ (p->s.alert, -1);
        }
      else
        {
          CHECK (r != GQ_OK);
          CHECK (p->s.alert == GQ_ALERT_ILLEGAL_PARAMETER
                 || p->s.alert == GQ_ALERT_MISSING_EXTENSION
                 || p->s.alert == GQ_ALERT_DECODE_ERROR);
          CHECK_EQ (g_lookups, 0);
        }
      pair_free (p);
    }
  gq_ticket_keys_free (keys);
}

static void
test_psk_identities_are_capped (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess;
  struct pair *p;
  uint8_t ch[16384];
  size_t n;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  first_connection (keys, &sess, NULL);
  p = pair_new ();
  p->cc.resume = &sess;
  p->sc.psk_lookup = counting_lookup;
  p->cnow = p->snow += 5000;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  n = p->c.sent_len[GQ_LEVEL_INITIAL];
  CHECK (n > 4 && n < sizeof ch);
  memcpy (ch, p->c.sent[GQ_LEVEL_INITIAL], n);
  /* Control: the hello as the client made it is looked up once.  */
  g_lookups = 0;
  CHECK_EQ (feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0), GQ_OK);
  CHECK_EQ (g_lookups, 1);
  pair_free (p);

  p = pair_new ();
  p->cc.resume = &sess;
  p->sc.psk_lookup = counting_lookup;
  p->cnow = p->snow += 5000;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  n = p->c.sent_len[GQ_LEVEL_INITIAL];
  memcpy (ch, p->c.sent[GQ_LEVEL_INITIAL], n);
  n = many_identities (ch, n, sizeof ch, 150, 150);
  g_lookups = 0;
  feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0);
  CHECK (g_lookups >= 1 && g_lookups <= 8);
  pair_free (p);
  gq_ticket_keys_free (keys);
}

static int
always_fresh (void *u, const uint8_t id[32], uint64_t expires_ms,
              uint64_t now_ms)
{
  (void) u;
  (void) id;
  (void) expires_ms;
  (void) now_ms;
  return 1;
}

/* RFC 8446 section 4.2.10: a client that sent early data and is told it was
   accepted must abort if the server chose another ALPN protocol than the
   one the ticket came with: what went early was meant for that protocol.
   The server never does this itself; it is checked against one that does.  */
static void
test_client_checks_early_data_acceptance (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess;
  struct pair *p;
  int mutate;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);

  /* A session whose connection used h2, from a server allowing early data.  */
  p = pair_new ();
  p->calpn[0] = (gq_slice) { (const uint8_t *) "h2", 2 };
  p->cc.alpn = p->calpn;
  p->cc.n_alpn = 1;
  p->salpn[0] = (gq_slice) { (const uint8_t *) "h2", 2 };
  p->salpn[1] = (gq_slice) { (const uint8_t *) "h3", 2 };
  p->sc.alpn = p->salpn;
  p->sc.n_alpn = 2;
  p->sc.ticket_keys = keys;
  p->sc.max_early_data = 16384;
  p->sc.replay_check = always_fresh;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK (p->c.session.max_early_data > 0);
  sess = p->c.session;
  pair_free (p);

  for (mutate = 0; mutate < 2; mutate++)
    {
      size_t i, n;
      int r;

      p = pair_new ();
      p->calpn[0] = (gq_slice) { (const uint8_t *) "h2", 2 };
      p->calpn[1] = (gq_slice) { (const uint8_t *) "h3", 2 };
      p->cc.alpn = p->calpn;
      p->cc.n_alpn = 2;
      p->cc.resume = &sess;
      p->cc.early_data = 1;
      p->salpn[0] = (gq_slice) { (const uint8_t *) "h2", 2 };
      p->salpn[1] = (gq_slice) { (const uint8_t *) "h3", 2 };
      p->sc.alpn = p->salpn;
      p->sc.n_alpn = 2;
      p->sc.ticket_keys = keys;
      p->sc.max_early_data = 16384;
      p->sc.replay_check = always_fresh;
      p->cnow = p->snow += 5000;
      pair_create (p);
      CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
      if (!mutate)
        {
          /* Control: honestly accepted.  */
          CHECK_EQ (pump (p, 0), GQ_OK);
          check_success (p);
          CHECK_EQ (p->c.info.early_data_accepted, 1);
          pair_free (p);
          continue;
        }
      /* The server's first flight, with the protocol it names changed to
         another the client offered.  */
      CHECK_EQ (feed_end (&p->s, GQ_LEVEL_INITIAL,
                          p->c.sent[GQ_LEVEL_INITIAL],
                          p->c.sent_len[GQ_LEVEL_INITIAL], 0), GQ_OK);
      p->c.sent_len[GQ_LEVEL_INITIAL] = 0;
      CHECK_EQ (feed_end (&p->c, GQ_LEVEL_INITIAL,
                          p->s.sent[GQ_LEVEL_INITIAL],
                          p->s.sent_len[GQ_LEVEL_INITIAL], 0), GQ_OK);
      p->s.sent_len[GQ_LEVEL_INITIAL] = 0;
      n = p->s.sent_len[GQ_LEVEL_HANDSHAKE];
      for (i = 0; i + 3 < n; i++)
        if (p->s.sent[GQ_LEVEL_HANDSHAKE][i] == 2
            && p->s.sent[GQ_LEVEL_HANDSHAKE][i + 1] == 'h'
            && p->s.sent[GQ_LEVEL_HANDSHAKE][i + 2] == '2')
          {
            p->s.sent[GQ_LEVEL_HANDSHAKE][i + 2] = '3';
            break;
          }
      CHECK (i + 3 < n);
      r = feed_end (&p->c, GQ_LEVEL_HANDSHAKE, p->s.sent[GQ_LEVEL_HANDSHAKE],
                    n, 0);
      CHECK (r != GQ_OK);
      /* Refused for what it is, not for the transcript that no longer
         matches (decrypt_error, 51, at Finished).  */
      CHECK_EQ (p->c.alert, GQ_ALERT_ILLEGAL_PARAMETER);
      pair_free (p);
    }
  gq_ticket_keys_free (keys);
}

/* Whatever makes the server (or client) decline the ticket, the
   handshake still succeeds as a full one.  */
static void
fallback_case (const char *what, gq_ticket_keys *server_keys,
               const gq_tls_session *sess, uint64_t client_dt,
               uint64_t server_dt, int mutate_ticket)
{
  struct pair *p = pair_new ();
  static gq_tls_session s2;

  s2 = *sess;
  if (mutate_ticket)
    s2.ticket[40] ^= 1;
  p->sc.ticket_keys = server_keys;
  p->cc.resume = &s2;
  p->cnow += client_dt;
  p->snow += server_dt;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  if (pump (p, 0) != GQ_OK)
    fprintf (stderr, "fallback case failed: %s\n", what);
  CHECK (p->c.complete && p->s.complete);
  check_mirror (p);
  CHECK_EQ (p->c.info.resumed, 0);
  CHECK_EQ (p->s.info.resumed, 0);
  CHECK (p->s.n_hs >= 4 && p->s.hs_seq[1] == GQ_HS_CERTIFICATE);
  pair_free (p);
}

static void
test_resumption_fallbacks (void)
{
  gq_ticket_keys *keys, *other;
  static gq_tls_session sess;
  const uint64_t day = 86400000;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  CHECK_EQ (gq_ticket_keys_new (&other), GQ_OK);
  first_connection (keys, &sess, NULL);

  fallback_case ("server has other keys", other, &sess, 1000, 1000, 0);
  fallback_case ("ticket tampered", keys, &sess, 1000, 1000, 1);
  fallback_case ("server thinks it expired", keys, &sess, 1000, 2 * day, 0);
  fallback_case ("client knows it expired", keys, &sess, 2 * day, 2 * day, 0);
  /* Session says lifetime 0: never offered.  */
  {
    static gq_tls_session dead;

    dead = sess;
    dead.lifetime = 0;
    fallback_case ("zero lifetime", keys, &dead, 1000, 1000, 0);
  }
  /* A server with tickets switched off ignores the offer.  */
  fallback_case ("server has no ticket keys", NULL, &sess, 1000, 1000, 0);
  gq_ticket_keys_free (keys);
  gq_ticket_keys_free (other);
}

static void
test_resumption_policy (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess;
  struct pair *p;
  int calls = 0;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  first_connection (keys, &sess, NULL);

  /* Bound to the server name: another name gets a full handshake, with
     the other certificate.  */
  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->sc.select_credentials = by_name;
  p->sc.select_user = &calls;
  p->cc.resume = &sess;
  p->cc.server_name = "other.test";
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 0);
  pair_free (p);

  /* The suite of the ticket must still be allowed.  */
  {
    static const uint16_t chacha[] = { GQ_TLS_CHACHA20_POLY1305_SHA256 };

    p = pair_new ();
    p->sc.ticket_keys = keys;
    p->sc.suites = chacha;
    p->sc.n_suites = 1;
    p->cc.resume = &sess;
    pair_create (p);
    CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
    CHECK_EQ (pump (p, 0), GQ_OK);
    check_success (p);
    CHECK_EQ (p->c.info.resumed, 0);
    CHECK_EQ (p->s.info.cipher_suite, GQ_TLS_CHACHA20_POLY1305_SHA256);
    pair_free (p);
  }

  /* A client offering a suite it does not allow does not offer the PSK.  */
  {
    static const uint16_t chacha[] = { GQ_TLS_CHACHA20_POLY1305_SHA256 };

    p = pair_new ();
    p->sc.ticket_keys = keys;
    p->cc.suites = chacha;
    p->cc.n_suites = 1;
    p->cc.resume = &sess;
    pair_create (p);
    CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
    CHECK_EQ (pump (p, 0), GQ_OK);
    check_success (p);
    CHECK_EQ (p->c.info.resumed, 0);
    pair_free (p);
  }
  gq_ticket_keys_free (keys);
}

static void
test_resumption_client_auth (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session anon, authed;
  struct pair *p;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);

  /* A session from an unauthenticated connection cannot skip client
     authentication on a server that now requires it.  */
  first_connection (keys, &anon, NULL);
  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
  p->sc.client_trust = server_trust;
  client_cert (p, cli_chain, cli_ok_key);
  p->cc.resume = &anon;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 0);
  CHECK_EQ (p->s.info.client_auth_sent, 1);	/* Verified this time.  */
  authed = p->c.session;
  pair_free (p);

  /* A session from an authenticated connection may resume, and the
     server remembers that the client was authenticated.  */
  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->sc.client_auth = GQ_CLIENT_AUTH_REQUIRED;
  p->sc.client_trust = server_trust;
  p->cc.resume = &authed;
  pair_create (p);
  CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
  CHECK_EQ (pump (p, 0), GQ_OK);
  check_success (p);
  CHECK_EQ (p->c.info.resumed, 1);
  CHECK_EQ (p->s.info.client_auth_sent, 1);
  pair_free (p);
  gq_ticket_keys_free (keys);
}

static void
test_resumption_hrr (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess;
  struct pair *p;
  static const uint16_t p384[] = { GQ_GROUP_SECP384R1 };
  int cookie;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  first_connection (keys, &sess, NULL);

  /* After a HelloRetryRequest the binder covers the message_hash
     transcript; with and without a cookie.  */
  for (cookie = 0; cookie < 2; cookie++)
    {
      p = pair_new ();
      p->sc.ticket_keys = keys;
      p->sc.groups = p384;
      p->sc.n_groups = 1;
      p->sc.hello_retry_cookie = cookie;
      p->cc.resume = &sess;
      pair_create (p);
      CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
      CHECK_EQ (pump (p, 0), GQ_OK);
      check_success (p);
      CHECK_EQ (p->c.info.resumed, 1);
      CHECK_EQ (p->c.info.hello_retry, 1);
      CHECK_EQ (p->s.info.group, GQ_GROUP_SECP384R1);
      pair_free (p);
    }
  gq_ticket_keys_free (keys);
}

static void
test_resumption_quic (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess;
  int pass;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  for (pass = 0; pass < 2; pass++)
    {
      struct pair *p = pair_new ();

      p->calpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
      p->salpn[0] = (gq_slice) { (const uint8_t *) "h3", 2 };
      p->cc.alpn = p->calpn;
      p->cc.n_alpn = 1;
      p->cc.transport_params = p->ctp;
      p->cc.transport_params_len = sizeof p->ctp;
      p->cc.quic = 1;
      p->sc.alpn = p->salpn;
      p->sc.n_alpn = 1;
      p->sc.transport_params = p->stp;
      p->sc.transport_params_len = sizeof p->stp;
      p->sc.quic = 1;
      p->sc.ticket_keys = keys;
      if (pass)
        p->cc.resume = &sess;
      pair_create (p);
      CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
      CHECK_EQ (pump (p, 0), GQ_OK);
      check_success (p);
      CHECK_EQ (p->c.info.resumed, pass);
      /* Transport parameters still travel in a resumed handshake.  */
      CHECK (p->s.peer_tp_len == 4 && p->c.peer_tp_len == 4);
      if (!pass)
        sess = p->c.session;
      pair_free (p);
    }
  gq_ticket_keys_free (keys);
}

/* A wrong binder is fatal, not a fallback.  */
static void
test_resumption_binder_failure (void)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess;
  struct pair *p;
  uint8_t ch[8192];
  size_t n;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  first_connection (keys, &sess, NULL);
  p = pair_new ();
  p->sc.ticket_keys = keys;
  p->cc.resume = &sess;
  pair_create (p);
  n = client_hello (p, ch);
  ch[n - 1] ^= 1;
  CHECK_EQ (feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0), GQ_ERR_CRYPTO);
  CHECK_EQ (p->s.alert, GQ_ALERT_DECRYPT_ERROR);
  pair_free (p);
  gq_ticket_keys_free (keys);
}

static void
test_resumption_mutations (int iterations)
{
  gq_ticket_keys *keys;
  static gq_tls_session sess;
  int it, completed = 0, resumed = 0;

  CHECK_EQ (gq_ticket_keys_new (&keys), GQ_OK);
  first_connection (keys, &sess, NULL);
  for (it = 0; it < iterations; it++)
    {
      struct pair *p = pair_new ();
      uint8_t ch[8192];
      size_t n, i;
      int r, nmut = (int) rnd_below (4);

      p->sc.ticket_keys = keys;
      p->cc.resume = &sess;
      if (rnd_below (3) == 0)
        {
          static const uint16_t g[] = { GQ_GROUP_SECP256R1 };

          p->sc.groups = g;
          p->sc.n_groups = 1;
        }
      pair_create (p);
      n = client_hello (p, ch);
      for (i = 0; i < (size_t) nmut; i++)
        ch[rnd_below ((unsigned) n)] ^= (uint8_t) (1u << rnd_below (8));
      if (rnd_below (8) == 0)
        n = rnd_below ((unsigned) n + 1);
      r = feed_end (&p->s, GQ_LEVEL_INITIAL, ch, n, 0);
      if (r == GQ_OK)
        r = pump (p, 0);
      if (p->s.complete)
        {
          completed++;
          resumed += p->s.info.resumed;
          CHECK (p->c.complete);
          check_mirror (p);
        }
      pair_free (p);
    }
  fprintf (stderr, "resumption mutations: %d completed (%d resumed) of %d\n",
           completed, resumed, iterations);
  gq_ticket_keys_free (keys);
}

#ifdef __GLIBC__
/* Bytes of heap in use now.  */
static size_t
heap_in_use (void)
{
  return mallinfo2 ().uordblks;
}

/* Everything an engine allocates is released by gq_tls_free: a server that
   leaked a little for every ClientHello, before it had authenticated
   anything, could be run out of memory by anyone.  Heap use must not grow
   with the number of handshakes, whether they finish or are abandoned once
   the server has seen the ClientHello.  */
static void
test_no_leak_per_handshake (void)
{
  enum { WARM = 5, RUNS = 100 };
  size_t before = 0, after;
  int i;

  for (i = 0; i < WARM + RUNS; i++)
    {
      struct pair *p = pair_new ();

      if (i == WARM)
        before = heap_in_use ();
      pair_create (p);
      CHECK_EQ (gq_tls_start (p->c.tls), GQ_OK);
      if (i % 2)
        CHECK_EQ (pump (p, 0), GQ_OK);
      else
        {
          /* Abandoned: the server sees the ClientHello and no more.  */
          CHECK_EQ (feed_end (&p->s, GQ_LEVEL_INITIAL,
                              p->c.sent[GQ_LEVEL_INITIAL],
                              p->c.sent_len[GQ_LEVEL_INITIAL], 0), GQ_OK);
        }
      pair_free (p);
    }
  after = heap_in_use ();
  /* A leaked transcript alone is over 100 bytes a handshake.  Allow for
     allocator and library caches settling.  */
  CHECK (after < before + 4096);
}
#endif

int
main (void)
{
  setup_fixtures ();
#ifdef __GLIBC__
  test_no_leak_per_handshake ();
#endif
  test_basic (0);
  test_basic (1);
  test_basic (17);
  test_hrr (0);
  test_hrr (1);
  test_keylog (0);
  test_keylog (1);
  test_preferences ();
  test_pure_groups ();
  test_pure_groups_opt_in ();
  test_pure_groups_order ();
  test_pure_groups_wrong_length ();
  test_nameless_ticket_not_rebound ();
  test_sni_credentials ();
  test_alpn_and_quic ();
  test_client_auth ();
  test_mldsa_handshake ();
  test_mldsa_handshake_pq_root ();
  test_key_update ();
  test_client_hello_failures ();
  test_hrr_client_hello_failures ();
  test_finished_failures ();
  test_mutations (1200);
  test_resumption_basic ();
  test_client_checks_early_data_acceptance ();
  test_ticket_from_a_clock_slightly_ahead ();
  test_psk_extension_rules ();
  test_psk_identities_are_capped ();
  test_quic_server_refuses_session_id ();
  test_hrr_legacy_version ();
  test_resumption_fallbacks ();
  test_resumption_policy ();
  test_resumption_client_auth ();
  test_resumption_hrr ();
  test_resumption_quic ();
  test_resumption_binder_failure ();
  test_resumption_mutations (800);
  TST_DONE ();
}

#endif
