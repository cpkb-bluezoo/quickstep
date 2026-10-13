/* Copyright (C) 2026 Chris Burdess <dog@gnu.org>

   This file is part of quickstep.

   quickstep is free software: you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   quickstep is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program.  If not, see
   <https://www.gnu.org/licenses/>.  */

/* Version negotiation over DTLS (dtlsauto.h): every pairing of a client
   and a server that offer both or one version, with the stateless front
   door and without, over a simulated network with loss.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <quickstep/status.h>
#include <quickstep/dtlsauto.h>
#include <quickstep/dtlsrec.h>
#include <quickstep/dtlshs.h>

#include <time.h>

#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "tst-fix12.h"

#define MAXQ 256
#define BOTH 0

struct net;

struct side
{
  gq_dtlsauto *a;
  gq_dtls12 *raw;		/* Instead of A: a bare DTLS 1.2 engine.  */
  struct net *net;
  int idx;
  int connected, closed, close_err;
  int n_app;
  char app[16][32];
};

struct pkt
{
  int to;
  uint64_t at;
  size_t len;
  uint8_t data[1500];
};

struct net
{
  struct side s[2];
  struct pkt q[MAXQ];
  int nq;
  uint64_t now;
  int total;
  int lose_every;		/* Drop every Nth datagram (0: none).  */
  gq_dtls_cookies *ck;		/* The front door, if not NULL.  */
  gq_tls_server_config sc;
  gq_dtls_events sev;
  unsigned sver;
  int replies, accepts, drops;
};

static int
ev_send (void *u, const uint8_t *d, size_t n)
{
  struct side *s = u;
  struct net *net = s->net;
  int index = net->total++;
  struct pkt *p;

  if (net->lose_every && index % net->lose_every == 1)
    return 0;
  CHECK (net->nq < MAXQ);
  p = &net->q[net->nq++];
  p->to = 1 - s->idx;
  p->at = net->now + 10;
  p->len = n;
  memcpy (p->data, d, n);
  return 0;
}

static int
ev_data (void *u, const uint8_t *d, size_t n)
{
  struct side *s = u;

  if (s->n_app < 16 && n < 32)
    {
      memcpy (s->app[s->n_app], d, n);
      s->app[s->n_app][n] = 0;
    }
  s->n_app++;
  return 0;
}

static int
ev_connected (void *u, const gq_tls_info *i)
{
  struct side *s = u;

  (void) i;
  s->connected = 1;
  return 0;
}

static void
ev_closed (void *u, int error, int alert)
{
  struct side *s = u;

  (void) alert;
  s->closed++;
  s->close_err = error;
}

/* A session the clients of net_new offer, if set.  */
static const gq_tls_session *g_resume;

/* CLIENT and SERVER are the version flags each end is allowed.  */
static struct net *
net_new (unsigned client, unsigned server, int front)
{
  struct net *n = calloc (1, sizeof *n);
  gq_dtls_events ev;
  gq_tls_config cc;
  static gq_tls_credentials creds;

  n->now = 1000;
  n->s[0].net = n;
  n->s[1].net = n;
  n->s[1].idx = 1;
  memset (&ev, 0, sizeof ev);
  ev.send = ev_send;
  ev.data = ev_data;
  ev.connected = ev_connected;
  ev.closed = ev_closed;

  memset (&cc, 0, sizeof cc);
  cc.server_name = "example.test";
  cc.trust = fx_trust;
  cc.resume = g_resume;
  ev.user = &n->s[0];
  CHECK_EQ (gq_dtlsauto_client_new (&n->s[0].a, &cc, &ev, NULL, client),
            GQ_OK);

  memset (&creds, 0, sizeof creds);
  creds.chain = fx_ec.chain;
  creds.n_chain = 1;
  creds.key = fx_ec.key;
  memset (&n->sc, 0, sizeof n->sc);
  n->sc.credentials = creds;
  ev.user = &n->s[1];
  n->sev = ev;
  n->sver = server;
  if (front)
    CHECK_EQ (gq_dtls_cookies_new (&n->ck), GQ_OK);
  else
    CHECK_EQ (gq_dtlsauto_server_new (&n->s[1].a, &n->sc, &ev, NULL, server,
                                      NULL), GQ_OK);
  return n;
}

static void
net_free (struct net *n)
{
  gq_dtlsauto_free (n->s[0].a);
  gq_dtlsauto_free (n->s[1].a);
  gq_dtls12_free (n->s[1].raw);
  gq_dtls_cookies_free (n->ck);
  free (n);
}

static void
front_door (struct net *n, const uint8_t *d, size_t len)
{
  static const uint8_t binding[] = "192.0.2.1:4433";
  uint8_t reply[GQ_DTLS_LISTEN_REPLY_MAX];
  size_t rl;
  gq_dtlsauto_prime prime;
  int r = gq_dtlsauto_listen (n->ck, &n->sc, n->sver, binding,
                              sizeof binding - 1, d, len, reply,
                              sizeof reply, &rl, &prime);

  if (r == GQ_DTLS_LISTEN_REPLY)
    {
      struct pkt *p;

      n->replies++;
      CHECK (rl < len);
      p = &n->q[n->nq++];
      p->to = 0;
      p->at = n->now + 10;
      p->len = rl;
      memcpy (p->data, reply, rl);
      n->total++;
    }
  else if (r == GQ_DTLS_LISTEN_ACCEPT)
    {
      n->accepts++;
      CHECK_EQ (gq_dtlsauto_server_new (&n->s[1].a, &n->sc, &n->sev, NULL,
                                        n->sver, &prime), GQ_OK);
      gq_dtlsauto_receive (n->s[1].a, d, len, n->now);
    }
  else
    {
      CHECK (r == GQ_DTLS_LISTEN_DROP);
      n->drops++;
    }
}

static void
run (struct net *n, uint64_t limit)
{
  uint64_t start = n->now;
  int guard = 0;

  for (;;)
    {
      uint64_t best = 0;
      int bi = -1, kind = 0, i;

      if (++guard > 100000)
        {
          CHECK (!"simulation did not settle");
          break;
        }
      for (i = 0; i < n->nq; i++)
        if (bi < 0 || n->q[i].at < n->q[bi].at)
          bi = i;
      if (bi >= 0)
        {
          best = n->q[bi].at;
          kind = 1;
        }
      for (i = 0; i < 2; i++)
        {
          uint64_t d = n->s[i].raw ? gq_dtls12_deadline (n->s[i].raw)
                       : n->s[i].a ? gq_dtlsauto_deadline (n->s[i].a) : 0;

          if (d && (kind == 0 || d < best))
            {
              best = d;
              kind = 2 + i;
            }
        }
      if (kind == 0 || best - start > limit)
        break;
      if (best > n->now)
        n->now = best;
      if (kind == 1)
        {
          struct pkt p = n->q[bi];

          memmove (&n->q[bi], &n->q[bi + 1],
                   (size_t) (n->nq - bi - 1) * sizeof n->q[0]);
          n->nq--;
          if (n->s[p.to].raw)
            gq_dtls12_receive (n->s[p.to].raw, p.data, p.len, n->now);
          else if (n->s[p.to].a)
            gq_dtlsauto_receive (n->s[p.to].a, p.data, p.len, n->now);
          else if (p.to == 1 && n->ck)
            front_door (n, p.data, p.len);
        }
      else if (n->s[kind - 2].raw)
        gq_dtls12_timeout (n->s[kind - 2].raw, n->now);
      else
        gq_dtlsauto_timeout (n->s[kind - 2].a, n->now);
    }
}

/* Expect a completed association of VERSION, and data both ways.  */
static void
check_connected (struct net *n, unsigned version)
{
  n->lose_every = 0;		/* Application data is not retransmitted.  */
  static const uint8_t m1[] = "hello", m2[] = "world";
  uint8_t a[16], b[16];

  CHECK (n->s[0].connected && n->s[1].connected);
  CHECK_EQ (n->s[0].closed + n->s[1].closed, 0);
  CHECK_EQ (gq_dtlsauto_version (n->s[0].a), version);
  CHECK_EQ (gq_dtlsauto_version (n->s[1].a), version);
  CHECK_EQ (gq_dtlsauto_send (n->s[0].a, m1, 5), GQ_OK);
  CHECK_EQ (gq_dtlsauto_send (n->s[1].a, m2, 5), GQ_OK);
  run (n, 5000);
  CHECK_EQ (n->s[1].n_app, 1);
  CHECK_EQ (n->s[0].n_app, 1);
  CHECK (strcmp (n->s[1].app[0], "hello") == 0);
  CHECK (strcmp (n->s[0].app[0], "world") == 0);
  CHECK_EQ (gq_dtlsauto_export (n->s[0].a, "EXPORTER-test", NULL, 0, a, 16),
            GQ_OK);
  CHECK_EQ (gq_dtlsauto_export (n->s[1].a, "EXPORTER-test", NULL, 0, b, 16),
            GQ_OK);
  CHECK (memcmp (a, b, 16) == 0);
}

static void
one (unsigned client, unsigned server, int front, int lose, unsigned want)
{
  struct net *n = net_new (client, server, front);

  n->lose_every = lose;
  CHECK_EQ (gq_dtlsauto_start (n->s[0].a, n->now), GQ_OK);
  run (n, 120000);
  if (want)
    {
      check_connected (n, want);
      if (front)
        CHECK_EQ (n->accepts, 1);
    }
  else
    {
      CHECK (!(n->s[0].connected && n->s[1].connected));
      CHECK (gq_dtlsauto_is_closed (n->s[0].a) || n->s[0].closed
             || !n->s[1].a || !gq_dtlsauto_is_connected (n->s[0].a));
    }
  net_free (n);
}

/* An attacker who downgrades: a DTLS 1.2 server that carries the sentinel
   of a server that also does 1.3 meets a client that offered both.  */
static void
sentinel (unsigned client, int expect_refused)
{
  struct net *n = net_new (client, BOTH, 0);
  gq_dtls_events ev = n->sev;

  gq_dtlsauto_free (n->s[1].a);
  n->s[1].a = NULL;
  n->sc.tls13_sentinel = 1;
  CHECK_EQ (gq_dtls12_server_new (&n->s[1].raw, &n->sc, &ev, NULL, NULL),
            GQ_OK);
  CHECK_EQ (gq_dtlsauto_start (n->s[0].a, n->now), GQ_OK);
  run (n, 60000);
  if (expect_refused)
    {
      CHECK (!n->s[0].connected);
      CHECK (n->s[0].closed);
    }
  else
    CHECK (n->s[0].connected && n->s[1].connected);
  net_free (n);
}

#define D12 GQ_DTLSAUTO_DTLS12
#define D13 GQ_DTLSAUTO_DTLS13

/* A ClientHello whose extensions start with a big one that means nothing,
   so that supported_versions lies in a later fragment.  Take the hello
   CLIENT produced (one datagram), pad it by PAD bytes, and cut it into
   datagrams of PIECE bytes of message each.  Returns how many.  */
static int
padded_hello (struct net *n, size_t pad, size_t piece, uint8_t out[][1500],
              size_t *outlen)
{
  uint8_t msg[8192];
  const uint8_t *b;
  size_t mlen, p, k, sl, i, extlen, total, off;
  int count = 0;
  gq_wbuf w, f;

  CHECK (n->nq >= 1);
  /* Record header 13, fragment header 12, then the hello body.  */
  b = n->q[0].data;
  CHECK (b[0] == 22 && n->q[0].len > 25);
  mlen = ((size_t) b[14] << 16) | ((size_t) b[15] << 8) | b[16];
  CHECK (n->q[0].len == 13 + 12 + mlen);
  b += 25;
  p = 2 + 32;
  p += 1 + b[p];			/* session_id */
  p += 1 + b[p];			/* legacy_cookie */
  sl = ((size_t) b[p] << 8) | b[p + 1];
  p += 2 + sl;
  p += 1 + b[p];			/* compression */
  extlen = ((size_t) b[p] << 8) | b[p + 1];
  CHECK (p + 2 + extlen == mlen);
  /* body up to the extension length, the new length, the big extension,
     the old extensions.  */
  memcpy (msg, b, p);
  k = p;
  extlen += 4 + pad;
  msg[k++] = (uint8_t) (extlen >> 8);
  msg[k++] = (uint8_t) extlen;
  msg[k++] = 0x0a; msg[k++] = 0x0a;		/* A reserved type.  */
  msg[k++] = (uint8_t) (pad >> 8);
  msg[k++] = (uint8_t) pad;
  memset (msg + k, 0, pad);
  k += pad;
  memcpy (msg + k, b + p + 2, mlen - p - 2);
  total = k + mlen - p - 2;
  CHECK (total < sizeof msg);
  for (off = 0, i = 0; off < total; off += piece, i++)
    {
      uint8_t frag[1500];
      size_t take = total - off < piece ? total - off : piece;

      gq_wbuf_init (&f, frag, sizeof frag);
      gq_dtls_put_hs_frag (&f, 1, (uint32_t) total, 0, (uint32_t) off,
                           msg + off, take);
      gq_wbuf_init (&w, out[count], 1500);
      gq_dtls_put_plain (&w, 22, i, frag, f.len);
      CHECK_EQ (gq_wbuf_status (&w), GQ_OK);
      outlen[count++] = w.len;
    }
  return count;
}

/* The version of a ClientHello cannot be told from its first fragment if
   supported_versions comes later: the server waits for the rest rather
   than guessing DTLS 1.2.  */
static void
fragmented_classify (unsigned client, unsigned want)
{
  uint8_t d[8][1500];
  size_t l[8];
  struct net *n = net_new (client, BOTH, 0);
  int i, count;

  CHECK_EQ (gq_dtlsauto_start (n->s[0].a, n->now), GQ_OK);
  count = padded_hello (n, 1500, 600, d, l);
  CHECK (count >= 3 && count <= 8);
  for (i = 0; i < count; i++)
    {
      gq_dtlsauto_receive (n->s[1].a, d[i], l[i], n->now);
      /* Undecided, however many fragments are in, until the last.  */
      if (i + 1 < count)
        CHECK_EQ (gq_dtlsauto_version (n->s[1].a), 0);
    }
  CHECK_EQ (gq_dtlsauto_version (n->s[1].a), want);
  net_free (n);
}

/* A resuming client's hello carries a ticket (up to GQ_TICKET_MAX bytes)
   and does not fit a datagram: it goes out in fragments, and has to be
   kept whole for a DTLS 1.2 server that answers instead.  A DTLS 1.2
   listener in front (stateless cookies) copes with the fragments too.  */
static void
big_ticket (int front, int lose)
{
  static gq_tls_session sess;
  size_t i;

  memset (&sess, 0, sizeof sess);
  for (i = 0; i < GQ_TICKET_MAX; i++)
    sess.ticket[i] = (uint8_t) (i * 7 + 3);
  sess.ticket_len = GQ_TICKET_MAX;
  sess.cipher_suite = GQ_TLS_AES_128_GCM_SHA256;
  sess.hash = GQ_HASH_SHA256;
  sess.psk_len = 32;
  sess.lifetime = 7200;
  sess.received_ms = (uint64_t) time (NULL) * 1000;
  g_resume = &sess;
  one (BOTH, D12, front, lose, 0xfefd);
  /* A listener answering statelessly for DTLS 1.3 cannot take a ClientHello1
     spread over several datagrams (its cookie holds the hash of the whole
     message): that, and only that, is not served.  */
  if (!front)
    one (BOTH, BOTH, front, lose, 0xfefc);
  g_resume = NULL;
}

int
main (void)
{
  int front, lose;

  gq_crypto_init ();
  fx_setup ();
  for (front = 0; front <= 1; front++)
    for (lose = 0; lose <= 3; lose += 3)
      {
        /* Negotiation: both prefer 1.3.  */
        one (BOTH, BOTH, front, lose, 0xfefc);
        /* A server with only 1.2 (or a client with only 1.2).  */
        one (BOTH, D12, front, lose, 0xfefd);
        one (D12, BOTH, front, lose, 0xfefd);
        one (D12, D12, front, lose, 0xfefd);
        /* And only 1.3.  */
        one (BOTH, D13, front, lose, 0xfefc);
        one (D13, BOTH, front, lose, 0xfefc);
        one (D13, D13, front, lose, 0xfefc);
        /* Pinned to different versions: no association.  */
        one (D13, D12, front, lose, 0);
        one (D12, D13, front, lose, 0);
      }
  big_ticket (0, 0);
  big_ticket (0, 3);
  big_ticket (1, 0);
  big_ticket (1, 3);
  fragmented_classify (BOTH, 0xfefc);
  fragmented_classify (D12, 0xfefd);
  sentinel (BOTH, 1);
  sentinel (D12, 0);
  TST_DONE ();
}

#endif
