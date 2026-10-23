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

/* The negotiating front (tlsauto.h): a server that serves TLS 1.2 and 1.3
   from one listener, and a client that offers both, joined back to back over
   real records.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <pthread.h>
#include <stdio.h>

#include <quickstep/status.h>
#include <quickstep/tlsauto.h>
#include <quickstep/tls12conn.h>


#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "tst-fix12.h"

struct bytes
{
  uint8_t *p;
  size_t n, cap;
};

static void
bytes_add (struct bytes *b, const uint8_t *d, size_t n)
{
  if (b->n + n > b->cap)
    {
      b->cap = (b->n + n) * 2 + 64;
      b->p = realloc (b->p, b->cap);
    }
  memcpy (b->p + b->n, d, n);
  b->n += n;
}

enum kind { K13, K12, KAUTO };

struct peer
{
  enum kind kind;
  gq_tlsconn *c13;
  gq_tls12conn *c12;
  gq_tlsauto *ca;
  gq_tlsconn_events ev;
  struct bytes out, app;
  int connected, closed, error;
  int vcalls, vresult, vok;	/* verify_peer: calls, answer, args as expected.  */
  size_t vn;
};

static int
ev_write (void *u, const uint8_t *d, size_t n)
{
  bytes_add (&((struct peer *) u)->out, d, n);
  return 0;
}

static int
ev_data (void *u, const uint8_t *d, size_t n)
{
  bytes_add (&((struct peer *) u)->app, d, n);
  return 0;
}

static int
ev_connected (void *u, const gq_tls_info *i)
{
  (void) i;
  ((struct peer *) u)->connected = 1;
  return 0;
}

static void
ev_closed (void *u, int error, int alert)
{
  struct peer *p = u;

  (void) alert;
  p->closed = 1;
  p->error = error;
}

static void
peer_init (struct peer *p, enum kind k)
{
  memset (p, 0, sizeof *p);
  p->kind = k;
  p->ev.user = p;
  p->ev.write = ev_write;
  p->ev.data = ev_data;
  p->ev.connected = ev_connected;
  p->ev.closed = ev_closed;
}

/* The engines' wall clock, and the time the session below was received:
   fixed, so that nothing depends on the date.  */
#define TEST_NOW_MS UINT64_C (1700000000000)

static uint64_t
test_now_ms (void *user)
{
  (void) user;
  return TEST_NOW_MS;
}

static gq_tls_config
client_cfg (void)
{
  gq_tls_config c;

  memset (&c, 0, sizeof c);
  c.server_name = "example.test";
  c.trust = fx_trust;
  c.hooks.now_ms = test_now_ms;
  return c;
}

static gq_tls_server_config
server_cfg (void)
{
  gq_tls_server_config c;

  memset (&c, 0, sizeof c);
  c.credentials.chain = fx_ec.chain;
  c.credentials.n_chain = 1;
  c.credentials.key = fx_ec.key;
  c.hooks.now_ms = test_now_ms;
  return c;
}

static void
peer_free (struct peer *p)
{
  gq_tlsconn_free (p->c13);
  gq_tls12conn_free (p->c12);
  gq_tlsauto_free (p->ca);
  free (p->out.p);
  free (p->app.p);
}

static int
peer_recv (struct peer *p, const uint8_t *d, size_t n)
{
  switch (p->kind)
    {
    case K13: return gq_tlsconn_receive (p->c13, d, n);
    case K12: return gq_tls12conn_receive (p->c12, d, n);
    default: return gq_tlsauto_receive (p->ca, d, n);
    }
}

static int
peer_send (struct peer *p, const uint8_t *d, size_t n)
{
  switch (p->kind)
    {
    case K13: return gq_tlsconn_send (p->c13, d, n);
    case K12: return gq_tls12conn_send (p->c12, d, n);
    default: return gq_tlsauto_send (p->ca, d, n);
    }
}

/* Move everything each side wrote to the other, in CHUNK byte pieces.  */
static void
pump (struct peer *a, struct peer *b, size_t chunk)
{
  int rounds;

  for (rounds = 0; rounds < 200; rounds++)
    {
      struct peer *from[2] = { a, b }, *to[2] = { b, a };
      int i, moved = 0;

      for (i = 0; i < 2; i++)
        {
          struct bytes t = from[i]->out;
          size_t off = 0;

          from[i]->out.p = NULL;
          from[i]->out.n = from[i]->out.cap = 0;
          while (off < t.n)
            {
              size_t k = t.n - off < chunk ? t.n - off : chunk;

              if (!to[i]->closed)
                peer_recv (to[i], t.p + off, k);
              off += k;
              moved = 1;
            }
          free (t.p);
        }
      if (!moved)
        break;
    }
}

static void
make_client (struct peer *p, enum kind k, unsigned auto_versions)
{
  gq_tls_config cfg = client_cfg ();

  peer_init (p, k);
  switch (k)
    {
    case K13:
      CHECK_EQ (gq_tlsconn_client_new (&p->c13, &cfg, &p->ev), GQ_OK);
      CHECK_EQ (gq_tlsconn_start (p->c13), GQ_OK);
      break;
    case K12:
      CHECK_EQ (gq_tls12conn_client_new (&p->c12, &cfg, &p->ev), GQ_OK);
      CHECK_EQ (gq_tls12conn_start (p->c12), GQ_OK);
      break;
    default:
      CHECK_EQ (gq_tlsauto_client_new (&p->ca, &cfg, &p->ev, auto_versions),
                GQ_OK);
      CHECK_EQ (gq_tlsauto_start (p->ca), GQ_OK);
      break;
    }
}

static void
make_auto_server (struct peer *p, unsigned versions)
{
  gq_tls_server_config cfg = server_cfg ();

  peer_init (p, KAUTO);
  CHECK_EQ (gq_tlsauto_server_new (&p->ca, &cfg, &p->ev, versions), GQ_OK);
}

/* The ServerHello random, from the first record a server wrote.  */
static int
sentinel_in (const struct bytes *out)
{
  static const uint8_t s[8] = { 'D', 'O', 'W', 'N', 'G', 'R', 'D', 1 };

  /* Record header 5, handshake header 4, version 2, then the random.  */
  return out->n >= 11 + 32 && out->p[0] == 22 && out->p[5] == 2
         && memcmp (out->p + 11 + 24, s, 8) == 0;
}

static void
one_run (enum kind client, unsigned client_versions, unsigned server_versions,
         size_t chunk, unsigned want_version)
{
  struct peer c, s;
  static const uint8_t hello[] = "hello, server";
  struct bytes first_server = { NULL, 0, 0 };

  make_client (&c, client, client_versions);
  make_auto_server (&s, server_versions);
  /* Feed the first flight by hand so the ServerHello can be inspected.  */
  {
    struct bytes t = c.out;
    size_t off = 0;

    c.out.p = NULL;
    c.out.n = c.out.cap = 0;
    while (off < t.n)
      {
        size_t k = t.n - off < chunk ? t.n - off : chunk;

        peer_recv (&s, t.p + off, k);
        off += k;
      }
    free (t.p);
    if (s.out.n)
      bytes_add (&first_server, s.out.p, s.out.n);
  }
  pump (&c, &s, chunk);
  if (want_version == 0)
    {
      CHECK (c.closed && s.closed);
      CHECK (!c.connected && !s.connected);
    }
  else
    {
      static const uint8_t reply[] = "hello, client";

      CHECK (c.connected && s.connected);
      CHECK_EQ (gq_tlsauto_version (s.ca), want_version);
      CHECK_EQ (peer_send (&c, hello, sizeof hello), GQ_OK);
      CHECK_EQ (peer_send (&s, reply, sizeof reply), GQ_OK);
      pump (&c, &s, chunk);
      CHECK (s.app.n == sizeof hello && !memcmp (s.app.p, hello, sizeof hello));
      CHECK (c.app.n == sizeof reply && !memcmp (c.app.p, reply, sizeof reply));
      /* The sentinel is there exactly when a TLS 1.2 client was served by
         an endpoint that also speaks TLS 1.3.  */
      CHECK_EQ (sentinel_in (&first_server),
                want_version == 0x0303 && (server_versions == 0
                                           || (server_versions & 2)));
    }
  free (first_server.p);
  peer_free (&c);
  peer_free (&s);
}

enum srvkind { S_AUTO, S_AUTO12, S_AUTO13, S_BARE13, S_BARE12, S_BARE12_SENTINEL };

static void
make_server (struct peer *p, enum srvkind k)
{
  gq_tls_server_config cfg = server_cfg ();

  switch (k)
    {
    case S_AUTO: make_auto_server (p, 0); break;
    case S_AUTO12: make_auto_server (p, GQ_TLSAUTO_TLS12); break;
    case S_AUTO13: make_auto_server (p, GQ_TLSAUTO_TLS13); break;
    case S_BARE13:
      peer_init (p, K13);
      CHECK_EQ (gq_tlsconn_server_new (&p->c13, &cfg, &p->ev), GQ_OK);
      break;
    default:
      peer_init (p, K12);
      cfg.tls13_sentinel = k == S_BARE12_SENTINEL;
      CHECK_EQ (gq_tls12conn_server_new (&p->c12, &cfg, &p->ev), GQ_OK);
      break;
    }
}

/* A negotiating client (offering CLIENT_VERSIONS) against each kind of
   server: WANT is the version it should end up with, 0 for a refusal.  */
static void
client_run (unsigned client_versions, enum srvkind sk, size_t chunk,
            unsigned want)
{
  struct peer c, s;
  static const uint8_t hello[] = "hello, server";

  make_client (&c, KAUTO, client_versions);
  make_server (&s, sk);
  pump (&c, &s, chunk);
  if (want == 0)
    {
      CHECK (!c.connected && !s.connected);
      CHECK (c.closed || s.closed);
    }
  else
    {
      CHECK (c.connected && s.connected);
      CHECK_EQ (gq_tlsauto_version (c.ca), want);
      CHECK_EQ (peer_send (&c, hello, sizeof hello), GQ_OK);
      pump (&c, &s, chunk);
      CHECK (s.app.n == sizeof hello && !memcmp (s.app.p, hello, sizeof hello));
    }
  peer_free (&c);
  peer_free (&s);
}

static void
test_client (void)
{
  size_t chunks[] = { 1, 5, 100, 100000 };
  size_t i;

  for (i = 0; i < sizeof chunks / sizeof chunks[0]; i++)
    {
      size_t k = chunks[i];

      /* Both offered: whatever the server speaks.  */
      client_run (0, S_AUTO, k, 0x0304);
      client_run (0, S_AUTO13, k, 0x0304);
      client_run (0, S_BARE13, k, 0x0304);
      client_run (0, S_AUTO12, k, 0x0303);
      client_run (0, S_BARE12, k, 0x0303);
      /* Pinned clients get their version or nothing.  */
      client_run (GQ_TLSAUTO_TLS13, S_AUTO, k, 0x0304);
      client_run (GQ_TLSAUTO_TLS12, S_AUTO, k, 0x0303);
      client_run (GQ_TLSAUTO_TLS13, S_BARE12, k, 0);
      client_run (GQ_TLSAUTO_TLS12, S_BARE13, k, 0);
      /* A server that could speak TLS 1.3 but answers in 1.2 to a client that
         offered 1.3 has been pushed down: the client walks away.  */
      client_run (0, S_BARE12_SENTINEL, k, 0);
      /* ...but a client that never offered TLS 1.3 does not look.  */
      client_run (GQ_TLSAUTO_TLS12, S_BARE12_SENTINEL, k, 0x0303);
    }
}

/* A resuming client's hello carries a ticket of up to GQ_TICKET_MAX bytes
   as well as a hybrid key share and a long ALPN list, and is well over 4 KB
   then.  It has to survive being kept for a TLS 1.2 server that answers
   instead.  */
static void
test_big_hello_fallback (void)
{
  static gq_tls_session sess;
  static const uint16_t groups[] = { GQ_GROUP_SECP384R1_MLKEM1024,
                                     GQ_GROUP_X25519 };
  static char names[12][41];
  static gq_slice alpn[12];
  gq_tls_config cfg = client_cfg ();
  struct peer c, s;
  static const uint8_t hello[] = "hello, server";
  size_t i, k;

  memset (&sess, 0, sizeof sess);
  for (i = 0; i < GQ_TICKET_MAX; i++)
    sess.ticket[i] = (uint8_t) (i * 7 + 3);
  sess.ticket_len = GQ_TICKET_MAX;
  sess.cipher_suite = GQ_TLS_AES_128_GCM_SHA256;
  sess.hash = GQ_HASH_SHA256;
  sess.psk_len = 32;
  sess.lifetime = 7200;
  sess.received_ms = TEST_NOW_MS;
  CHECK_EQ (gq_tls_session_bind_server_name (&sess, cfg.server_name), GQ_OK);
  for (i = 0; i < 12; i++)
    {
      memset (names[i], 'a' + (int) i, 40);
      alpn[i].data = (const uint8_t *) names[i];
      alpn[i].len = 40;
    }
  cfg.resume = &sess;
  cfg.groups = groups;
  cfg.n_groups = 2;
  cfg.alpn = alpn;
  cfg.n_alpn = 12;
  for (k = 0; k < 2; k++)
    {
      peer_init (&c, KAUTO);
      make_server (&s, k ? S_BARE12 : S_AUTO12);
      CHECK_EQ (gq_tlsauto_client_new (&c.ca, &cfg, &c.ev, 0), GQ_OK);
      CHECK_EQ (gq_tlsauto_start (c.ca), GQ_OK);
      CHECK (c.out.n > 4096 + 5);
      pump (&c, &s, 100000);
      CHECK (c.connected && s.connected);
      CHECK_EQ (gq_tlsauto_version (c.ca), 0x0303);
      CHECK_EQ (peer_send (&c, hello, sizeof hello), GQ_OK);
      pump (&c, &s, 100000);
      CHECK (s.app.n == sizeof hello && !memcmp (s.app.p, hello, sizeof hello));
      peer_free (&c);
      peer_free (&s);
    }
}

static void
test_versions (void)
{
  size_t chunks[] = { 1, 3, 7, 100, 100000 };
  size_t i;

  for (i = 0; i < sizeof chunks / sizeof chunks[0]; i++)
    {
      /* Both served from one listener.  */
      one_run (K13, 0, 0, chunks[i], 0x0304);
      one_run (K12, 0, 0, chunks[i], 0x0303);
      /* Restricted listeners serve their own and refuse the other.  */
      one_run (K13, 0, GQ_TLSAUTO_TLS13, chunks[i], 0x0304);
      one_run (K12, 0, GQ_TLSAUTO_TLS12, chunks[i], 0x0303);
      one_run (K12, 0, GQ_TLSAUTO_TLS13, chunks[i], 0);
      one_run (K13, 0, GQ_TLSAUTO_TLS12, chunks[i], 0);
    }
}

/* A ClientHello cut into several records, at every point.  */
static void
test_fragmented_hello (void)
{
  struct peer c;
  size_t cut;

  make_client (&c, K13, 0);
  {
    /* The first record: 5 byte header and the handshake message.  */
    size_t len = (size_t) (c.out.p[3] << 8 | c.out.p[4]);
    uint8_t *hs = malloc (len);

    memcpy (hs, c.out.p + 5, len);
    for (cut = 1; cut < len; cut += 97)
      {
        struct peer s;
        uint8_t rec[2][70000];
        size_t l0 = cut, l1 = len - cut;

        rec[0][0] = 22; rec[0][1] = 3; rec[0][2] = 1;
        rec[0][3] = (uint8_t) (l0 >> 8); rec[0][4] = (uint8_t) l0;
        memcpy (rec[0] + 5, hs, l0);
        rec[1][0] = 22; rec[1][1] = 3; rec[1][2] = 3;
        rec[1][3] = (uint8_t) (l1 >> 8); rec[1][4] = (uint8_t) l1;
        memcpy (rec[1] + 5, hs + l0, l1);
        make_auto_server (&s, 0);
        peer_recv (&s, rec[0], 5 + l0);
        CHECK (s.out.n == 0);			/* Waiting for the rest.  */
        peer_recv (&s, rec[1], 5 + l1);
        CHECK (s.out.n > 0);			/* Answered.  */
        CHECK_EQ (gq_tlsauto_version (s.ca), 0x0304);
        peer_free (&s);
      }
    free (hs);
  }
  peer_free (&c);
}

/* Junk of every kind is refused without harm, and a first flight that never
   completes is bounded.  */
static void
test_garbage (void)
{
  struct peer s;
  uint8_t junk[80000];
  size_t i, n;

  for (n = 0; n < 40; n++)
    {
      make_auto_server (&s, 0);
      for (i = 0; i < sizeof junk; i++)
        junk[i] = (uint8_t) (i * 31 + n);
      junk[0] = n & 1 ? 22 : (uint8_t) n;
      junk[1] = 3;
      if (n % 4 == 0)
        {
          junk[3] = 0x10;			/* A long record, never done.  */
          junk[4] = 0;
        }
      peer_recv (&s, junk, n < 20 ? 200 + n : sizeof junk);
      peer_recv (&s, junk, 5);
      peer_free (&s);
    }
  /* A record of type 22 that starts a huge handshake message.  */
  make_auto_server (&s, 0);
  {
    static const uint8_t big[] = { 22, 3, 3, 0, 8, 1, 0xff, 0xff, 0xff, 0, 0, 0,
                                   0 };

    peer_recv (&s, big, sizeof big);
    CHECK (gq_tlsauto_version (s.ca) != 0);
  }
  peer_free (&s);
}

/* End of file without close_notify is truncation, in whichever protocol the
   connection turned out to speak, or before it did.  */
static void
test_transport_eof (void)
{
  struct peer c, s;

  make_client (&c, KAUTO, 0);
  make_auto_server (&s, 0);
  pump (&c, &s, 100000);
  CHECK (c.connected && s.connected);
  CHECK_EQ (gq_tlsauto_eof (c.ca), GQ_ERR_PROTOCOL);
  CHECK_EQ (c.closed, 1);
  CHECK_EQ (c.error, GQ_ERR_PROTOCOL);
  CHECK_EQ (gq_tlsauto_eof (c.ca), GQ_ERR_PROTOCOL);
  peer_free (&c);
  peer_free (&s);

  /* A server that has not yet decided which protocol the client speaks.  */
  make_auto_server (&s, 0);
  CHECK_EQ (gq_tlsauto_eof (s.ca), GQ_ERR_PROTOCOL);
  CHECK_EQ (s.closed, 1);
  CHECK_EQ (s.error, GQ_ERR_PROTOCOL);
  CHECK_EQ (gq_tlsauto_eof (s.ca), GQ_ERR_PROTOCOL);
  CHECK_EQ (s.closed, 1);
  peer_free (&s);
}

/* The largest hello the engine will make is 16 KB, which one record holds
   (the engine refuses to make more).  The TLS 1.2 engine that continues from
   it needs all of it; check one close to the limit.  */
static void
test_hello_over_one_record (void)
{
  static char names[70][201];
  static gq_slice alpn[70];
  gq_tls_config cfg = client_cfg ();
  struct peer c, s;
  size_t i, k;

  for (i = 0; i < 70; i++)
    {
      memset (names[i], 'a' + (int) (i % 26), 200);
      names[i][0] = (char) ('A' + (int) (i % 26));
      names[i][1] = (char) ('0' + (int) (i / 10 % 10));
      names[i][2] = (char) ('0' + (int) (i % 10));
      alpn[i].data = (const uint8_t *) names[i];
      alpn[i].len = 200;
    }
  cfg.alpn = alpn;
  cfg.n_alpn = 70;
  for (k = 0; k < 2; k++)
    {
      peer_init (&c, KAUTO);
      make_server (&s, k ? S_BARE12 : S_AUTO12);
      CHECK_EQ (gq_tlsauto_client_new (&c.ca, &cfg, &c.ev, 0), GQ_OK);
      CHECK_EQ (gq_tlsauto_start (c.ca), GQ_OK);
      CHECK (c.out.n > 12000);
      pump (&c, &s, 100000);
      CHECK (c.connected && s.connected);
      CHECK_EQ (gq_tlsauto_version (c.ca), 0x0303);
      peer_free (&c);
      peer_free (&s);
    }
}

/* The code that decides which protocol a peer speaks looks at the first
   flight before there is an engine, and it must not need a big stack to do
   so: a thread of a program may have 64 KB.  */
struct small_stack
{
  int kind;			/* 0 server, 1 client.  */
  int done;
};

static void *
small_stack_run (void *arg)
{
  struct small_stack *w = arg;
  struct peer p;
  /* The start of a hello, then of a server hello: the record is declared
     bigger than what has arrived, so the decision waits for more.  */
  static const uint8_t partial[] = { 22, 3, 1, 0x20, 0, 1, 0, 0x1f, 0xf0,
                                     3, 3, 0, 0, 0, 0, 0, 0 };

  if (w->kind == 0)
    make_auto_server (&p, 0);
  else
    make_client (&p, KAUTO, 0);
  peer_recv (&p, partial, sizeof partial);
  peer_free (&p);
  w->done = 1;
  return NULL;
}

static void
test_small_stack (void)
{
  int kind;

  for (kind = 0; kind < 2; kind++)
    {
      pthread_t th;
      pthread_attr_t at;
      struct small_stack w;

      w.kind = kind;
      w.done = 0;
      pthread_attr_init (&at);
      pthread_attr_setstacksize (&at, 64 * 1024);
      CHECK_EQ (pthread_create (&th, &at, small_stack_run, &w), 0);
      pthread_join (th, NULL);
      pthread_attr_destroy (&at);
      CHECK_EQ (w.done, 1);
    }
}

/* ---- verify_peer replaces the trust store ---- */

static int
ev_verify (void *u, const gq_slice *chain, size_t n, const char *name)
{
  struct peer *p = u;

  p->vcalls++;
  p->vn = n;
  p->vok = n == 1 && chain[0].len == fx_ec.der_len
           && memcmp (chain[0].data, fx_ec.der, fx_ec.der_len) == 0
           && name != NULL && strcmp (name, "example.test") == 0;
  return p->vresult;
}

/* A client whose trust store is EMPTY, or absent when a callback is given
   (VERIFY: 0 none, 1 accepts, 2 refuses).  */
static void
make_vp_client (struct peer *p, enum kind k, unsigned auto_versions,
                int verify, gq_trust *empty)
{
  gq_tls_config cfg = client_cfg ();

  cfg.trust = verify == 1 ? NULL : empty;
  peer_init (p, k);
  if (verify)
    {
      p->ev.verify_peer = ev_verify;
      p->vresult = verify == 2;
    }
  switch (k)
    {
    case K13:
      CHECK_EQ (gq_tlsconn_client_new (&p->c13, &cfg, &p->ev), GQ_OK);
      CHECK_EQ (gq_tlsconn_start (p->c13), GQ_OK);
      break;
    case K12:
      CHECK_EQ (gq_tls12conn_client_new (&p->c12, &cfg, &p->ev), GQ_OK);
      CHECK_EQ (gq_tls12conn_start (p->c12), GQ_OK);
      break;
    default:
      CHECK_EQ (gq_tlsauto_client_new (&p->ca, &cfg, &p->ev, auto_versions),
                GQ_OK);
      CHECK_EQ (gq_tlsauto_start (p->ca), GQ_OK);
      break;
    }
}

static void
verify_run (enum kind ck, unsigned versions, enum srvkind sk, unsigned want,
            gq_trust *empty)
{
  int verify;

  for (verify = 0; verify <= 2; verify++)
    {
      struct peer c, s;
      static const uint8_t hello[] = "hello, server";

      make_vp_client (&c, ck, versions, verify, empty);
      make_server (&s, sk);
      pump (&c, &s, 100000);
      if (verify == 1)
        {
          CHECK (c.connected && s.connected);
          CHECK_EQ (c.vcalls, 1);
          CHECK_EQ (c.vn, 1);
          CHECK (c.vok);
          if (ck == KAUTO)
            CHECK_EQ (gq_tlsauto_version (c.ca), want);
          CHECK_EQ (peer_send (&c, hello, sizeof hello), GQ_OK);
          pump (&c, &s, 100000);
          CHECK (s.app.n == sizeof hello);
        }
      else
        {
          /* Refused by the callback, or by the empty store.  */
          CHECK (!c.connected && !s.connected);
          CHECK (c.closed);
          CHECK_EQ (c.error, GQ_ERR_CERT);
          CHECK_EQ (c.vcalls, verify == 2 ? 1 : 0);
        }
      peer_free (&c);
      peer_free (&s);
    }
}

static void
test_verify_peer (void)
{
  gq_trust *empty;

  CHECK_EQ (gq_trust_new (&empty), GQ_OK);
  verify_run (K13, 0, S_BARE13, 0x0304, empty);
  verify_run (K12, 0, S_BARE12, 0x0303, empty);
  verify_run (KAUTO, 0, S_AUTO, 0x0304, empty);
  verify_run (KAUTO, 0, S_AUTO13, 0x0304, empty);
  /* A server that selects TLS 1.2 is verified the same way.  */
  verify_run (KAUTO, 0, S_AUTO12, 0x0303, empty);
  verify_run (KAUTO, 0, S_BARE12, 0x0303, empty);
  verify_run (KAUTO, GQ_TLSAUTO_TLS12, S_AUTO, 0x0303, empty);
  verify_run (KAUTO, GQ_TLSAUTO_TLS13, S_AUTO, 0x0304, empty);
  gq_trust_free (empty);
}

int
main (void)
{
  gq_crypto_init ();
  fx_setup ();
  test_big_hello_fallback ();
  test_versions ();
  test_client ();
  test_fragmented_hello ();
  test_garbage ();
  test_transport_eof ();
  test_hello_over_one_record ();
  test_small_stack ();
  test_verify_peer ();
  TST_DONE ();
}

#endif
