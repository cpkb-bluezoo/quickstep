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

/* QUIC connections against each other over a simulated network: virtual
   clock (microseconds), latency, and loss, reordering and corruption
   chosen per test.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#if defined __GLIBC__
# include <malloc.h>		/* M_PERTURB.  */
#endif

#include <quickstep/status.h>
#include <quickstep/conn.h>
#include <quickstep/listen.h>
#include <quickstep/packet.h>
#include <quickstep/quiclb.h>

#include "tst-util.h"
#include "tst-qkv.h"
#include "tst-qlogcheck.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "tst-fix12.h"
#include "tst-mldsa-cert.h"

#define MAXQ 8192
#define MAXS 64

struct net;

struct sbuf
{
  int used;
  uint64_t id;
  size_t n;			/* Bytes received (pattern verified).  */
  int fin, reset, stopped;
  uint64_t err;
  size_t out_total, out_done;	/* What we are sending on it.  */
  int out_fin;
  int closed;
};

struct app
{
  gq_conn *c;
  struct net *net;
  int idx;			/* 0 client, 1 server.  */
  struct sbuf sb[MAXS];
  int connected, closed, bad;
  gq_conn_close_info ci;
  int cids, retired, opened;
  size_t respond;		/* Server: bytes to answer each request with.  */
  size_t total_in;
  gq_tls_info info;
  uint8_t token[512];
  size_t token_len;
  int tokens;
  gq_tls_session sess;
  int have_sess;
  uint32_t sess_version;
  int pv, pf, mig;		/* Path events.  */
  int pref_events, pref_take;	/* Preferred address offers; take up.  */
  gq_preferred_address pref;
  int early_bytes, early_result, early_dg;
  uint8_t params[512];
  size_t params_len;
  int dg_recv, dg_bad, dg_acked, dg_lost;
  uint8_t dg_seen[1024];	/* By the id in the payload.  */
  uint8_t dg_fate[1024];
  gq_path last_mig;
};

struct pkt
{
  int to;
  uint64_t at;
  size_t len;
  uint8_t d[2048];
  gq_path from;
  int has_from;
  int ecn;			/* gq_ecn the datagram arrives with.  */
};

struct net
{
  struct pkt q[MAXQ];
  int nq;
  uint64_t now, latency;
  unsigned loss_pct;
  unsigned burst;		/* Loss comes in runs of this many (0: alone).  */
  unsigned burst_left;
  int reorder, corrupt;
  int total;
  uint32_t rng;
  struct app *app[2];
  int dropped;
  int drop_index;		/* Drop this datagram only (or -1).  */
  int c2s_allow;		/* If not 0: only this many of the client's
				   datagrams get through, then none.  */
  int c2s_passed;
  /* Path simulation: the server S, the client's local addresses L[i], and
     the external addresses a NAT presents for them.  The client's outgoing
     datagrams appear from m[out_map[i]].ext; a datagram to the client is
     delivered only if it is addressed to an external address that is alive
     for incoming traffic.  */
  int paths;
  gq_addr S, S2, L[3];	/* Server, and its preferred address.  */
  int s2_dead;			/* Nothing reaches the server by S2.  */
  uint64_t s2_to, s2_from, s1_to;	/* Bytes by S2 each way, and to S.  */
  struct
  {
    gq_addr ext;
    int local, alive_in;
    uint64_t to_bytes, from_bytes;	/* Seen at the server side.  */
    size_t mtu;			/* This path's own limit (0: none).  */
  } m[6];
  int out_map[3];
  /* Called for every datagram a connection sends, with the path it is for
     (NULL without path simulation), before the network sees it.  */
  void (*tap) (struct net *, int from, const gq_path *to, void *user);
  void *tap_user;
  /* Called with the bytes of every datagram a connection sends, as an
     observer on the path would see them.  */
  void (*snoop) (struct net *, int from, const uint8_t *d, size_t len,
                 int ecn, void *user);
  void *snoop_user;
  /* What the path does to the ECN field of what each app sends: MARK, if
     not zero, sets it, BLEACH clears it, DROP_ECT drops datagrams that have
     one, and CE_EVERY turns every that many of the ones marked ECT(0) into
     CE (a bottleneck that signals congestion).  NO_ECN: the apps use the
     calls that know nothing of ECN.  */
  int mark[2], bleach[2], drop_ect[2], no_ecn;
  /* The path MTU: datagrams longer than MTU are dropped (0: no limit), and
     from MTU_CHANGE_AT (0: never) on, longer than MTU_THEN.  */
  size_t mtu, mtu_then;
  uint64_t mtu_change_at;
  unsigned mtu_drops;
  unsigned ce_every[2], ce_count[2];
  int hold;			/* Stash datagrams to EXT-0 instead of sending.  */
  struct pkt *held[8];
  int n_held;
  /* Server admission (NULL keys: the server exists from the start).  */
  gq_token_keys *keys;
  gq_admit_config admit;
  uint8_t addr[6];
  int replies, accepts;
  int (*make_srv) (struct net *, const gq_conn_accept *);
  /* Congestion controller observations, sender side of stream 0.  */
  int64_t max_over;
  uint64_t max_cwnd, min_cwnd, events;
};

static uint32_t
rnd (struct net *n)
{
  n->rng = n->rng * 1664525u + 1013904223u;
  return n->rng >> 8;
}

static uint8_t
pat (uint64_t id, uint64_t off)
{
  return (uint8_t) (id * 31 + off * 7 + (off >> 8));
}

static struct sbuf *
sb_get (struct app *a, uint64_t id)
{
  int i;

  for (i = 0; i < MAXS; i++)
    if (a->sb[i].used && a->sb[i].id == id)
      return &a->sb[i];
  for (i = 0; i < MAXS; i++)
    if (!a->sb[i].used)
      {
        a->sb[i].used = 1;
        a->sb[i].id = id;
        return &a->sb[i];
      }
  CHECK (0);
  return &a->sb[0];
}

/* ---- Events ---- */

static void
ev_connected (void *u, const gq_tls_info *i)
{
  struct app *a = u;

  a->connected = 1;
  a->info = *i;
}

static void
ev_opened (void *u, uint64_t id)
{
  struct app *a = u;

  a->opened++;
  sb_get (a, id);
}

static int
ev_data (void *u, uint64_t id, const uint8_t *d, size_t n, int fin)
{
  struct app *a = u;
  struct sbuf *s = sb_get (a, id);
  size_t i;

  for (i = 0; i < n; i++)
    if (d[i] != pat (id, s->n + i))
      {
        a->bad++;
        break;
      }
  s->n += n;
  a->total_in += n;
  if (a->c && gq_conn_early_data_active (a->c))
    a->early_bytes += (int) n;
  CHECK (!s->fin);
  if (fin)
    {
      s->fin = 1;
      /* Server: a complete request on a bidirectional stream is answered.  */
      if (a->idx == 1 && !(id & 2) && a->respond)
        {
          s->out_total = a->respond;
          s->out_fin = 1;
        }
    }
  return 0;
}

static void
ev_reset (void *u, uint64_t id, uint64_t err)
{
  struct sbuf *s = sb_get (u, id);

  s->reset = 1;
  s->err = err;
}

static void
ev_stopped (void *u, uint64_t id, uint64_t err)
{
  struct sbuf *s = sb_get (u, id);

  s->stopped = 1;
  s->err = err;
}

static void
ev_stream_closed (void *u, uint64_t id)
{
  sb_get (u, id)->closed = 1;
}

static void
ev_new_token (void *u, const uint8_t *t, size_t n)
{
  struct app *a = u;

  CHECK (n <= sizeof a->token);
  memcpy (a->token, t, n);
  a->token_len = n;
  a->tokens++;
}

/* Set by the resumption and 0-RTT tests.  */
static gq_ticket_keys *g_ring;
static const gq_tls_session *g_resume;
static gq_replay_cache *g_replay;
static int g_early_server, g_early_client;
static const uint8_t *g_resume_params;
static size_t g_resume_params_len;

static void
ev_ticket (void *u, const gq_tls_ticket *t, uint32_t version)
{
  struct app *a = u;

  if (a->have_sess)
    return;
  CHECK_EQ (gq_tls_session_store (&a->sess, t), GQ_OK);
  a->have_sess = 1;
  a->sess_version = version;
  CHECK_EQ (gq_conn_get_peer_params (a->c, a->params, sizeof a->params,
                                     &a->params_len), GQ_OK);
}

static void
ev_path_validated (void *u, const gq_path *p)
{
  (void) p;
  ((struct app *) u)->pv++;
}

static void
ev_path_failed (void *u, const gq_path *p)
{
  (void) p;
  ((struct app *) u)->pf++;
}

static void
ev_migrated (void *u, const gq_path *p)
{
  struct app *a = u;

  a->mig++;
  a->last_mig = *p;
}

static void
ev_preferred (void *u, const gq_preferred_address *pa)
{
  struct app *a = u;

  a->pref_events++;
  a->pref = *pa;
  if (a->pref_take && a->net->S2.len)
    {
      gq_path np;

      np.local = a->net->L[0];
      np.remote = a->net->S2;
      a->pref_take = gq_conn_migrate_preferred (a->c, a->net->now, &np) == GQ_OK
                     ? 0 : -1;
    }
}

static void
ev_datagram (void *u, const uint8_t *d, size_t n)
{
  struct app *a = u;
  size_t i;

  /* Payload: id (2 bytes), then a pattern.  */
  if (n < 2)
    {
      a->dg_bad++;
      return;
    }
  i = (size_t) (d[0] << 8 | d[1]);
  for (size_t k = 2; k < n; k++)
    if (d[k] != (uint8_t) (i * 5 + k))
      {
        a->dg_bad++;
        return;
      }
  if (i < sizeof a->dg_seen)
    a->dg_seen[i]++;
  a->dg_recv++;
  if (a->c && gq_conn_early_data_active (a->c))
    a->early_dg++;
}

static void
ev_dg_acked (void *u, uint64_t id)
{
  struct app *a = u;

  a->dg_acked++;
  if (id < sizeof a->dg_fate)
    a->dg_fate[id]++;
}

static void
ev_dg_lost (void *u, uint64_t id)
{
  struct app *a = u;

  a->dg_lost++;
  if (id < sizeof a->dg_fate)
    a->dg_fate[id]++;
}

static void
ev_early_result (void *u, int accepted)
{
  ((struct app *) u)->early_result = accepted ? 1 : -1;
}

static void
ev_closed (void *u, const gq_conn_close_info *i)
{
  struct app *a = u;

  a->closed++;
  if (getenv ("QDBG"))
    fprintf (stderr, "%s closed: src=%d app=%d err=%llx reason=%.*s\n", a->idx ? "srv" : "cli", i->source, i->application, (unsigned long long) i->error, (int) i->reason_len, i->reason ? (const char *) i->reason : "");
  a->ci = *i;
  a->ci.reason = NULL;
}

static void
ev_cid (void *u, const uint8_t *cid, size_t len, const uint8_t *tok)
{
  (void) cid;
  (void) len;
  (void) tok;
  ((struct app *) u)->cids++;
}

static void
ev_cid_retired (void *u, const uint8_t *cid, size_t len)
{
  (void) cid;
  (void) len;
  ((struct app *) u)->retired++;
}

/* Write whatever each stream still owes.  */
static void
pump (struct app *a)
{
  int i;

  if (a->c == NULL || a->closed || gq_conn_state (a->c) >= GQ_CONN_CLOSING)
    return;
  for (i = 0; i < MAXS; i++)
    {
      struct sbuf *s = &a->sb[i];

      while (s->used && s->out_done < s->out_total)
        {
          uint8_t buf[3000];
          size_t n = s->out_total - s->out_done, k;
          long w;

          if (n > sizeof buf)
            n = sizeof buf;
          for (k = 0; k < n; k++)
            buf[k] = pat (s->id, s->out_done + k);
          w = gq_conn_stream_write (a->c, s->id, buf, n);
          CHECK (w >= 0);
          if (w <= 0)
            break;
          s->out_done += (size_t) w;
        }
      if (s->used && s->out_fin && s->out_done == s->out_total
)
        {
          gq_conn_stream_finish (a->c, s->id);
          s->out_fin = 0;
        }
    }
}

/* ---- The network ---- */

static gq_addr
mkaddr (const char *s)
{
  gq_addr a;

  memset (&a, 0, sizeof a);
  a.len = (uint8_t) strlen (s);
  memcpy (a.data, s, a.len);
  return a;
}

static int
addr_same (const gq_addr *a, const gq_addr *b)
{
  return a->len == b->len && memcmp (a->data, b->data, a->len) == 0;
}

/* Does the network lose this datagram?  With BURST, losses come in runs of
   that many, at the same overall rate (the simulator of the interop runner
   drops 30% of packets in bursts of 3).  */
static int
lossy (struct net *n)
{
  if (n->loss_pct == 0)
    return 0;
  if (n->burst_left)
    {
      n->burst_left--;
      return 1;
    }
  if (n->burst > 1)
    {
      if (rnd (n) % 100 < n->loss_pct / n->burst)
        {
          n->burst_left = n->burst - 1;
          return 1;
        }
      return 0;
    }
  return rnd (n) % 100 < n->loss_pct;
}

static void
enqueue (struct net *n, int from, const uint8_t *d, size_t len,
         const gq_path *to, int ecn)
{
  struct pkt *p;
  int index = n->total++;
  gq_path src;
  int has_from = 0;
  size_t lim = n->mtu;

  memset (&src, 0, sizeof src);
  if (n->tap)
    n->tap (n, from, n->paths ? to : NULL, n->tap_user);
  if (n->snoop)
    n->snoop (n, from, d, len, ecn, n->snoop_user);
  if (n->mark[from])
    ecn = n->mark[from];
  if (n->bleach[from])
    ecn = GQ_ECN_NOT_ECT;
  if (ecn != GQ_ECN_NOT_ECT && n->drop_ect[from])
    {
      n->dropped++;
      return;
    }
  if (ecn == GQ_ECN_ECT0 && n->ce_every[from]
      && ++n->ce_count[from] % n->ce_every[from] == 0)
    ecn = GQ_ECN_CE;
  if (n->paths && to)
    {
      int i, j;

      if (from == 0)
        {
          /* Through the NAT to the server.  */
          i = 0;
          while (i < 3 && !addr_same (&n->L[i], &to->local))
            i++;
          if (i == 3)
            i = 0;
          j = n->out_map[i];
          if (n->m[j].mtu && (lim == 0 || n->m[j].mtu < lim))
            lim = n->m[j].mtu;
          src.local = n->S;
          if (n->S2.len && addr_same (&n->S2, &to->remote))
            {
              if (n->s2_dead)
                {
                  n->dropped++;
                  return;
                }
              src.local = n->S2;
              n->s2_to += len;
            }
          else
            n->s1_to += len;
          src.remote = n->m[j].ext;
          n->m[j].from_bytes += len;
          has_from = 1;
        }
      else
        {
          for (j = 0; j < 6; j++)
            if (n->m[j].ext.len && addr_same (&n->m[j].ext, &to->remote))
              break;
          if (j == 6)
            {
              n->dropped++;
              return;
            }
          if (n->m[j].mtu && (lim == 0 || n->m[j].mtu < lim))
            lim = n->m[j].mtu;
          n->m[j].to_bytes += len;
          if (n->hold && j == 0 && n->n_held < 8 && n->m[0].alive_in)
            {
              struct pkt *h = calloc (1, sizeof *h);

              h->len = len;
              memcpy (h->d, d, len);
              h->from.local = n->L[n->m[j].local];
              h->from.remote = n->S;
              h->has_from = 1;
              n->held[n->n_held++] = h;
              return;
            }
          if (!n->m[j].alive_in)
            {
              n->dropped++;
              return;
            }
          src.local = n->L[n->m[j].local];
          src.remote = n->S;
          if (n->S2.len && addr_same (&n->S2, &to->local))
            {
              if (n->s2_dead)
                {
                  n->dropped++;
                  return;
                }
              src.remote = n->S2;
              n->s2_from += len;
            }
          has_from = 1;
        }
    }

  if (n->mtu_change_at && n->now >= n->mtu_change_at)
    lim = n->mtu_then;
  if (lim && len > lim)
    {
      n->dropped++;
      n->mtu_drops++;
      return;
    }
  if (index == n->drop_index || lossy (n)
      || (from == 0 && n->c2s_allow && n->c2s_passed++ >= n->c2s_allow))
    {
      n->dropped++;
      return;
    }
  if (getenv ("QDBG"))
    fprintf (stderr, "%llu: %s sends %zu bytes first=%02x%s\n",
             (unsigned long long) n->now, from ? "srv" : "cli", len, d[0],
             n->drop_index == index ? " DROPPED" : "");
  CHECK (n->nq < MAXQ);
  if (n->nq >= MAXQ)
    return;
  p = &n->q[n->nq++];
  p->to = 1 - from;
  p->at = n->now + n->latency + (n->reorder && rnd (n) % 4 == 0 ? 7000 : 0);
  p->len = len;
  p->from = src;
  p->has_from = has_from;
  p->ecn = ecn;
  memcpy (p->d, d, len);
  if (n->corrupt && index % n->corrupt == 0)
    p->d[rnd (n) % len] ^= 0x20;
}

static void
flush (struct net *n)
{
  int s;

  for (s = 0; s < 2; s++)
    {
      struct app *a = n->app[s];
      uint8_t buf[2048];
      size_t len;
      int guard = 0;

      if (a == NULL || a->c == NULL)
        continue;
      {
        gq_conn_stats st;

        gq_conn_get_stats (a->c, &st);
        if ((int64_t) st.bytes_in_flight - (int64_t) st.cwnd > n->max_over)
          n->max_over = (int64_t) st.bytes_in_flight - (int64_t) st.cwnd;
        if (st.cwnd > n->max_cwnd)
          n->max_cwnd = st.cwnd;
        if (st.cwnd < n->min_cwnd || n->min_cwnd == 0)
          n->min_cwnd = st.cwnd;
        if (st.congestion_events > n->events)
          n->events = st.congestion_events;
      }
      while (guard++ < 200)
        {
          gq_path to;
          int ecn = GQ_ECN_NOT_ECT;

          memset (&to, 0, sizeof to);
          if (n->no_ecn)
            CHECK_EQ (gq_conn_send_path (a->c, n->now, buf, sizeof buf, &len,
                                         &to), GQ_OK);
          else
            CHECK_EQ (gq_conn_send_ecn (a->c, n->now, buf, sizeof buf, &len,
                                        &to, &ecn), GQ_OK);
          if (len == 0)
            break;
          CHECK (len <= sizeof buf);
          enqueue (n, s, buf, len, n->paths ? &to : NULL, ecn);
        }
    }
}

/* Run until DONE says so or the time budget is spent.  */
static int
run (struct net *n, int (*done) (struct net *), uint64_t budget_us)
{
  uint64_t end = n->now + budget_us;
  int steps = 0;

  while (n->now < end && steps++ < 2000000)
    {
      uint64_t t = 0;
      int i, best = -1, s;

      pump (n->app[0]);
      pump (n->app[1]);
      flush (n);
      if (done && done (n))
        return 1;
      for (i = 0; i < n->nq; i++)
        if (best < 0 || n->q[i].at < n->q[best].at)
          best = i;
      if (best >= 0)
        t = n->q[best].at;
      for (s = 0; s < 2; s++)
        if (n->app[s]->c)
          {
            uint64_t tt = gq_conn_timeout (n->app[s]->c);

            if (tt && (t == 0 || tt < t))
              t = tt;
          }
      if (t == 0 || t > end)
        {
          if (t > end)
            n->now = end;
          return done ? done (n) : 1;
        }
      if (t > n->now)
        n->now = t;
      if (best >= 0 && n->q[best].at <= n->now)
        {
          struct pkt p = n->q[best];

          memmove (&n->q[best], &n->q[best + 1],
                   (size_t) (n->nq - best - 1) * sizeof n->q[0]);
          n->nq--;
          if (p.to == 1 && n->app[1]->c == NULL && n->keys)
            {
              uint8_t reply[1500];
              size_t rl = 0;
              gq_conn_accept acc;
              int act = gq_quic_admit (n->keys, &n->admit, n->addr,
                                       sizeof n->addr, p.d, p.len,
                                       n->now / 1000000, reply, sizeof reply,
                                       &rl, &acc);

              if (act == GQ_ADMIT_REPLY)
                {
                  n->replies++;
                  enqueue (n, 1, reply, rl, NULL, GQ_ECN_NOT_ECT);
                }
              else if (act == GQ_ADMIT_ACCEPT)
                {
                  n->accepts++;
                  CHECK_EQ (n->make_srv (n, &acc), GQ_OK);
                  gq_conn_recv (n->app[1]->c, n->now, p.d, p.len);
                }
              continue;
            }
          if (n->app[p.to]->c)
            gq_conn_recv_ecn (n->app[p.to]->c, n->now,
                              p.has_from ? &p.from : NULL, p.ecn, p.d,
                              p.len);
          continue;
        }
      for (s = 0; s < 2; s++)
        if (n->app[s]->c)
          {
            uint64_t tt = gq_conn_timeout (n->app[s]->c);

            if (tt && tt <= n->now)
              gq_conn_on_timeout (n->app[s]->c, n->now);
          }
    }
  return done ? done (n) : 0;
}

/* ---- Setup ---- */

static const uint8_t alpn_hq[2] = { 'h', 'q' };
static gq_slice alpn_list[1] = { { alpn_hq, 2 } };

/* ---- qlog ---- */

/* Everything one end of a connection logs.  */
struct qsink
{
  struct qev
  {
    uint64_t t;
    char name[64];
    char *fields;
  } *e;
  size_t n, cap;
  uint64_t last_t;
  int bad_order, bad_line, bad_event, bad_first;
  size_t total;
  int keep;			/* Keep the events, to look at them.  */
  int dump;
  const char *who;
};

/* How many events the test run put through the checks, and of each kind.  */
static unsigned long g_qlog_events;
static unsigned long g_qlog_seen[64];

static void
qlog_note_seen (const char *name)
{
  size_t i;

  for (i = 0; qc_events[i]; i++)
    if (strncmp (name, "quic:", 5) == 0 && !strcmp (name + 5, qc_events[i]))
      g_qlog_seen[i]++;
}

static void
qsink_cb (void *user, const gq_conn *conn, uint64_t t, const char *name,
          const char *fields, size_t len)
{
  struct qsink *k = user;
  qline q;

  (void) conn;
  char where[200];
  const char *err;

  g_qlog_events++;
  qlog_note_seen (name);
  if (t < k->last_t)
    {
      fprintf (stderr, "qlog time went back: %s %llu after %llu: %s\n", name,
               (unsigned long long) t, (unsigned long long) k->last_t, fields);
      k->bad_order++;
    }
  k->last_t = t;
  /* The log of a connection begins with its connection_started.  */
  if (k->total++ == 0 && strcmp (name, "quic:connection_started") != 0)
    {
      fprintf (stderr, "qlog starts with %s\n", name);
      k->bad_first++;
    }
  if (!qline_parse (fields, len, &q))
    {
      fprintf (stderr, "malformed qlog line: %s %s\n", name, fields);
      k->bad_line++;
    }
  else
    qline_free (&q);
  err = qc_check (name, fields, len, where, sizeof where);
  if (err)
    {
      fprintf (stderr, "qlog event not as the draft says (%s: %s): %s %s\n",
               err, where, name, fields);
      k->bad_event++;
    }
  if (k->dump)
    fprintf (stderr, "QLOG %s %llu %s %s\n", k->who, (unsigned long long) t,
             name, fields);
  if (!k->keep)
    return;
  if (k->n == k->cap)
    {
      k->cap = k->cap ? k->cap * 2 : 256;
      k->e = realloc (k->e, k->cap * sizeof *k->e);
    }
  k->e[k->n].t = t;
  snprintf (k->e[k->n].name, sizeof k->e[k->n].name, "%s", name);
  k->e[k->n].fields = strdup (fields);
  k->n++;
}

static void
qsink_free (struct qsink *k)
{
  size_t i;

  for (i = 0; i < k->n; i++)
    free (k->e[i].fields);
  free (k->e);
  memset (k, 0, sizeof *k);
}

/* The number of events called NAME.  */
static size_t
qsink_count (const struct qsink *k, const char *name)
{
  size_t i, c = 0;

  for (i = 0; i < k->n; i++)
    if (!strcmp (k->e[i].name, name))
      c++;
  return c;
}

/* The I'th event called NAME, parsed into Q; 1, or 0 if there is no such.  */
static int
qsink_nth (const struct qsink *k, const char *name, size_t i, qline *q)
{
  size_t j;

  for (j = 0; j < k->n; j++)
    if (!strcmp (k->e[j].name, name) && i-- == 0)
      return qline_parse (k->e[j].fields, strlen (k->e[j].fields), q);
  return 0;
}

/* Add up VALUE-KEY over the frames of FRAME-TYPE in every PACKET event.  */
static uint64_t
qsink_frame_sum (const struct qsink *k, const char *packet_event,
                 const char *frame_type, const char *value_key)
{
  size_t i, f;
  uint64_t sum = 0;

  for (i = 0; i < k->n; i++)
    {
      qline q;

      if (strcmp (k->e[i].name, packet_event))
        continue;
      if (!qline_parse (k->e[i].fields, strlen (k->e[i].fields), &q))
        continue;
      for (f = 0; f < q.n; f++)
        {
          char key[96];
          const char *dot;

          if (strncmp (q.key[f], "frames.", 7) != 0
              || strcmp (q.val[f], frame_type))
            continue;
          dot = strchr (q.key[f] + 7, '.');
          if (!dot || strcmp (dot, ".frame_type"))
            continue;
          snprintf (key, sizeof key, "%.*s.%s", (int) (dot - q.key[f]),
                    q.key[f], value_key);
          if (qline_get (&q, key))
            sum += strtoull (qline_get (&q, key), NULL, 10);
        }
      qline_free (&q);
    }
  return sum;
}

struct pair
{
  struct net net;
  struct app cli, srv;
  gq_tls_config ccfg;
  gq_tls_server_config scfg;
  gq_conn_events cev, sev;
  gq_conn_config scfg_conn;
  gq_token_keys keys;
  struct qsink qlog_sink[2];	/* What each end logged (unless a test did).  */
};

static void
fill_events (gq_conn_events *e, struct app *a)
{
  memset (e, 0, sizeof *e);
  e->user = a;
  e->connected = ev_connected;
  e->stream_opened = ev_opened;
  e->stream_data = ev_data;
  e->stream_reset = ev_reset;
  e->stream_stopped = ev_stopped;
  e->stream_closed = ev_stream_closed;
  e->closed = ev_closed;
  e->cid_issued = ev_cid;
  e->cid_retired = ev_cid_retired;
  e->new_token = ev_new_token;
  e->ticket = ev_ticket;
  e->early_data_result = ev_early_result;
  e->datagram = ev_datagram;
  e->datagram_acked = ev_dg_acked;
  e->datagram_lost = ev_dg_lost;
  e->path_validated = ev_path_validated;
  e->path_failed = ev_path_failed;
  e->migrated = ev_migrated;
  e->preferred_address = ev_preferred;
}

/* Groups the client offers (NULL: the policy's).  */
static const uint16_t *g_cgroups;
static size_t g_n_cgroups;
static const struct ident *g_server_ident;	/* NULL: fx_ec.  */
static const gq_slice *g_server_chain;	/* With it: a longer chain.  */
static size_t g_server_n_chain;

/* The ceiling on datagram size the connections get when the test does not
   say: 1200, so that the tests that do not concern path MTU discovery see
   the datagram size they always did.  Those that do, set it.  */
static size_t g_ceiling = 1200;

static struct pair *
pair_new (const gq_conn_config *ccfg, const gq_conn_config *scfg,
          unsigned loss_pct, uint32_t seed)
{
  struct pair *p = calloc (1, sizeof *p);

  p->net.now = 1000000;
  p->net.latency = 10000;
  p->net.loss_pct = loss_pct;
  p->net.rng = seed;
  p->net.drop_index = -1;
  p->net.app[0] = &p->cli;
  p->net.app[1] = &p->srv;
  p->cli.net = p->srv.net = &p->net;
  p->cli.idx = 0;
  p->srv.idx = 1;
  p->ccfg.server_name = "example.test";
  p->ccfg.trust = fx_trust;
  p->ccfg.alpn = alpn_list;
  p->ccfg.n_alpn = 1;
  p->scfg.credentials.chain = g_server_chain
    ? g_server_chain : (g_server_ident ? g_server_ident : &fx_ec)->chain;
  p->scfg.credentials.n_chain = g_server_chain ? g_server_n_chain : 1;
  p->scfg.credentials.key = (g_server_ident ? g_server_ident : &fx_ec)->key;
  p->scfg.alpn = alpn_list;
  p->scfg.n_alpn = 1;
  p->scfg.ticket_keys = g_ring;
  p->ccfg.resume = g_resume;
  p->ccfg.groups = g_cgroups;
  p->ccfg.n_groups = g_n_cgroups;
  p->ccfg.early_data = g_early_client;
  if (g_early_server)
    {
      p->scfg.max_early_data = 0xffffffffU;
      p->scfg.replay_check = gq_replay_cache_check;
      p->scfg.replay_user = g_replay;
    }
  fill_events (&p->cev, &p->cli);
  fill_events (&p->sev, &p->srv);
  {
    gq_conn_config cc = ccfg ? *ccfg : (gq_conn_config) { 0 };

    cc.resume_params = g_resume_params;
    cc.resume_params_len = g_resume_params_len;
    if (cc.max_udp_payload == 0)
      cc.max_udp_payload = g_ceiling;
    if (cc.qlog == NULL)
      {
        cc.qlog = qsink_cb;
        cc.qlog_user = &p->qlog_sink[0];
        p->qlog_sink[0].who = "cli";
      }
    CHECK_EQ (gq_conn_client_new (&p->cli.c, &cc, &p->ccfg, &p->cev,
                                  p->net.now), GQ_OK);
  }
  {
    gq_conn_config sc = scfg ? *scfg : (gq_conn_config) { 0 };

    if (sc.max_udp_payload == 0)
      sc.max_udp_payload = g_ceiling;
    if (sc.qlog == NULL)
      {
        sc.qlog = qsink_cb;
        sc.qlog_user = &p->qlog_sink[1];
        p->qlog_sink[1].who = "srv";
      }
    CHECK_EQ (gq_conn_server_new (&p->srv.c, &sc, &p->scfg, &p->sev,
                                  p->net.now), GQ_OK);
  }
  return p;
}

static uint64_t
sim_wall (void *u)
{
  return ((struct net *) u)->now / 1000000;
}

static int
make_srv (struct net *n, const gq_conn_accept *acc)
{
  struct pair *p = (struct pair *) n;

  return gq_conn_server_accept (&p->srv.c, &p->scfg_conn, &p->scfg, &p->sev,
                                n->now, acc);
}

/* A pair whose server exists only once the admission step accepts.  */
static struct pair *
pair_new_admit (const gq_conn_config *ccfg, unsigned loss, uint32_t seed,
                int require_retry, const uint8_t *token, size_t token_len)
{
  struct pair *p = calloc (1, sizeof *p);
  gq_conn_config cc;

  p->net.now = 1000000;
  p->net.latency = 10000;
  p->net.loss_pct = loss;
  p->net.rng = seed;
  p->net.drop_index = -1;
  p->net.app[0] = &p->cli;
  p->net.app[1] = &p->srv;
  p->cli.net = p->srv.net = &p->net;
  p->srv.idx = 1;
  p->ccfg.server_name = "example.test";
  p->ccfg.trust = fx_trust;
  p->ccfg.alpn = alpn_list;
  p->ccfg.n_alpn = 1;
  p->scfg.credentials.chain = fx_ec.chain;
  p->scfg.credentials.n_chain = 1;
  p->scfg.credentials.key = fx_ec.key;
  p->scfg.alpn = alpn_list;
  p->scfg.n_alpn = 1;
  p->scfg.ticket_keys = g_ring;
  p->ccfg.resume = g_resume;
  fill_events (&p->cev, &p->cli);
  fill_events (&p->sev, &p->srv);
  CHECK_EQ (gq_token_keys_init (&p->keys), GQ_OK);
  p->net.keys = &p->keys;
  p->net.admit.require_retry = require_retry;
  p->net.make_srv = make_srv;
  memcpy (p->net.addr, "\x7f\0\0\1\x11\x5c", 6);
  memset (&p->scfg_conn, 0, sizeof p->scfg_conn);
  p->scfg_conn.wall_seconds = sim_wall;
  p->scfg_conn.wall_user = &p->net;
  p->scfg_conn.qlog = qsink_cb;
  p->scfg_conn.qlog_user = &p->qlog_sink[1];
  p->qlog_sink[0].who = "cli";
  p->qlog_sink[1].who = "srv";
  cc = ccfg ? *ccfg : p->scfg_conn;
  if (cc.max_udp_payload == 0)
    cc.max_udp_payload = g_ceiling;
  if (p->scfg_conn.max_udp_payload == 0)
    p->scfg_conn.max_udp_payload = g_ceiling;
  if (ccfg == NULL || cc.qlog == NULL)
    {
      cc.qlog = qsink_cb;
      cc.qlog_user = &p->qlog_sink[0];
    }
  cc.token = token;
  cc.token_len = token_len;
  CHECK_EQ (gq_conn_client_new (&p->cli.c, &cc, &p->ccfg, &p->cev,
                                p->net.now), GQ_OK);
  return p;
}

static void
pair_free (struct pair *p)
{
  int i;

  gq_conn_free (p->cli.c);
  gq_conn_free (p->srv.c);
  /* What each end logged was well-formed, as the draft says, in time order
     and starting with the connection.  */
  for (i = 0; i < 2; i++)
    {
      struct qsink *k = &p->qlog_sink[i];

      CHECK_EQ (k->bad_line, 0);
      CHECK_EQ (k->bad_event, 0);
      CHECK_EQ (k->bad_order, 0);
      CHECK_EQ (k->bad_first, 0);
      qsink_free (k);
    }
  free (p);
}

static int
both_connected (struct net *n)
{
  return n->app[0]->connected && n->app[1]->connected;
}

/* ---- Tests ---- */

static void
test_handshake (uint32_t version, unsigned loss, uint32_t seed)
{
  struct pair *p;
  gq_conn_config cfg;
  gq_conn_stats st;

  memset (&cfg, 0, sizeof cfg);
  cfg.version = version;
  p = pair_new (&cfg, &cfg, loss, seed);
  CHECK (run (&p->net, both_connected, 30000000));
  CHECK (p->cli.connected && p->srv.connected);
  CHECK_EQ (p->cli.info.alpn_len, 2);
  CHECK (gq_conn_is_established (p->cli.c));
  CHECK (gq_conn_is_established (p->srv.c));
  CHECK_EQ (gq_conn_version (p->cli.c), version ? version : GQ_VERSION_2);
  /* Let the handshake finish being confirmed and CIDs be exchanged.  */
  run (&p->net, NULL, 2000000);
  CHECK (p->cli.cids >= 2 && p->srv.cids >= 2);
  gq_conn_get_stats (p->cli.c, &st);
  CHECK (st.packets_sent > 0 && st.srtt_us > 0);
  if (!loss)
    CHECK (st.srtt_us < 100000 && st.srtt_us > 10000);
  pair_free (p);
}

/* glibc can fill every allocation with a fixed pattern before it is handed
   out, so that memory used before it was written is never the zeros that a
   fresh heap tends to hold (M_PERTURB; other C libraries have nothing like
   it, and then this does nothing).  The packets of a datagram are assembled
   in storage that is allocated for each send, and one field of it was never
   cleared: whether a packet was taken for a path MTU probe depended on what
   the heap held, which went unnoticed on a fresh heap.  */
static void
perturb_allocations (void)
{
#ifdef M_PERTURB
  mallopt (M_PERTURB, 165);
#endif
}

/* A datagram of the server's first flights is lost, whichever it is in
   turn, and the data in it has to be sent again: the handshake completes.
   The server's certificate is a big one (RSA), so the flight is several
   packets.  A lost packet that was taken for a path MTU probe is not sent
   again (its loss says nothing of congestion or of the data, RFC 9000
   section 14.4), so a stale probe mark on an ordinary packet stalls the
   handshake for good.  */
static void
test_lost_handshake_datagram (void)
{
  unsigned drop;

  for (drop = 2; drop <= 8; drop++)	/* The datagrams of the handshake.  */
    {
      struct pair *p;
      gq_conn_config cfg;

      memset (&cfg, 0, sizeof cfg);
      g_server_ident = &fx_rsa;
      p = pair_new (&cfg, &cfg, 0, 1);
      g_server_ident = NULL;
      p->net.drop_index = (int) drop;
      run (&p->net, both_connected, 30000000);
      if (!both_connected (&p->net))
        fprintf (stderr, "datagram %u lost: handshake did not complete\n",
                 drop);
      CHECK (p->cli.connected && p->srv.connected);
      CHECK_EQ (p->net.dropped, 1);
      pair_free (p);
    }
}

/* A QUIC handshake with an ML-DSA server certificate: its chain and the
   CertificateVerify signature (2420 to 4627 bytes) make the server's
   handshake flight several kilobytes, which has to be split over packets,
   held back by the amplification limit until the client's address is
   validated, and recovered if some are lost.  The certificate is made
   without GnuTLS's help (tst-mldsa-cert.h), so this runs wherever the
   library does.  */
static void
test_mldsa_handshake (void)
{
  static const unsigned schemes[] = { GQ_SIG_MLDSA44, GQ_SIG_MLDSA65,
                                      GQ_SIG_MLDSA87 };
  static const uint32_t versions[] = { GQ_VERSION_1, GQ_VERSION_2 };
  size_t i, v;
  unsigned loss;

  /* The client validates the chain, which a GnuTLS that does not know the
     key algorithm cannot (and a QUIC connection has no hook to replace it;
     the TLS engines' own tests do that).  */
  if (!tst_mldsa_ready (tst_gnutls_validates_mldsa (),
                        "the QUIC ML-DSA handshake tests"))
    return;
  for (i = 0; i < 3; i++)
    {
      static struct tst_mlident ml;
      static struct ident id;

      CHECK_EQ (tst_make_mldsa_cert (&ml, schemes[i], "mldsa", "example.test",
                                     0, &fx_ca, -3600, 86400), 0);
      memset (&id, 0, sizeof id);
      id.key = ml.key;
      id.chain[0] = ml.chain[0];
      for (v = 0; v < 2; v++)
        for (loss = 0; loss <= 10; loss += 10)
          {
            struct pair *p;
            gq_conn_config cfg;

            memset (&cfg, 0, sizeof cfg);
            cfg.version = versions[v];
            g_server_ident = &id;
            p = pair_new (&cfg, &cfg, loss, (uint32_t) (7 + i * 3 + v));
            g_server_ident = NULL;
            CHECK (run (&p->net, both_connected, 60000000));
            CHECK (p->cli.connected && p->srv.connected);
            CHECK (gq_conn_is_established (p->cli.c));
            CHECK (gq_conn_is_established (p->srv.c));
            CHECK_EQ (gq_conn_version (p->cli.c), versions[v]);
            pair_free (p);
          }
      tst_free_mldsa_cert (&ml);
    }
}


/* ---- Large flights: ML-DSA's sizes ---- */

/* A handshake of the chain CHAIN (N_CHAIN certificates, signed with KEY of
   ID, or the default server identity) is run until both ends are connected
   or BUDGET microseconds have passed; the latency is 10 ms each way, so the
   round trip is 20 ms.  Fills *CLIENT_RTT and *SERVER_RTT with the times at
   which each end connected, in round trips (0: it never did).  The pair is
   returned.  */
static struct pair *
run_flight (const struct ident *id, const gq_slice *chain, size_t n_chain,
            const gq_conn_config *cfg, unsigned loss, int reorder,
            uint32_t seed, uint64_t budget, double *client_rtt,
            double *server_rtt)
{
  struct pair *p;
  uint64_t t0, tc = 0, ts = 0, end;

  g_server_ident = id;
  g_server_chain = chain;
  g_server_n_chain = n_chain;
  p = pair_new (cfg, cfg, loss, seed);
  g_server_ident = NULL;
  g_server_chain = NULL;
  p->net.reorder = reorder;
  t0 = p->net.now;
  end = t0 + budget;
  while (p->net.now < end && !(p->cli.connected && p->srv.connected))
    {
      run (&p->net, NULL, 1000);
      if (p->cli.connected && !tc)
        tc = p->net.now;
      if (p->srv.connected && !ts)
        ts = p->net.now;
    }
  *client_rtt = tc ? (double) (tc - t0) / 20000 : 0;
  *server_rtt = ts ? (double) (ts - t0) / 20000 : 0;
  return p;
}

/* What a big flight costs.  The server may send only three times what it
   has received until the client's address is validated (RFC 9000 section
   8.1), and the client's first flight is one or two Initial datagrams, so
   whatever is beyond 3.6 or 7.2 KB of server flight waits for the client's
   reply: one round trip more.  The classical flights fit; the ML-DSA ones
   of a leaf and an intermediate, 8 to 15 KB of chain, do not, and take 2
   round trips, not 1 (a client sees the server's Finished at 1 round trip
   when everything fits).  Not more: once the address is validated the
   window (12000 bytes) takes the rest in one go.  */
static void
test_flight_cost (int mode)
{
  static const unsigned schemes[] = { GQ_SIG_MLDSA44, GQ_SIG_MLDSA65,
                                      GQ_SIG_MLDSA87 };
  static const uint32_t versions[] = { GQ_VERSION_1, GQ_VERSION_2 };
  static struct tst_mlchain ch;
  static struct ident id;
  double c, s;
  size_t i, v;
  struct pair *p;
  gq_conn_config cfg;

  for (v = 0; v < 2; v++)
    {
      memset (&cfg, 0, sizeof cfg);
      cfg.version = versions[v];

      /* The flights that fit, for comparison.  */
      p = run_flight (&fx_ec, NULL, 1, &cfg, 0, 0, 1, 2000000, &c, &s);
      CHECK (c > 0.9 && c <= 1.1);
      CHECK (s > 1.4 && s <= 1.6);
      pair_free (p);
      p = run_flight (&fx_rsa, NULL, 1, &cfg, 0, 0, 1, 2000000, &c, &s);
      CHECK (c > 0.9 && c <= 1.1);
      pair_free (p);

      for (i = 0; i < 3; i++)
        {
          CHECK_EQ (tst_make_mldsa_chain (&ch, schemes[i], &fx_ca,
                                          "example.test", mode), 0);
          memset (&id, 0, sizeof id);
          id.key = ch.key;
          id.chain[0] = ch.chain[0];
          /* The bigger the parameter set, the bigger the flight: ML-DSA-44's
             chain is 7.9 KB, ML-DSA-87's 14.9 KB, and with the
             CertificateVerify folded into the leaf (a classical leaf has no
             room for it otherwise) 11 to 21 KB.  */
          CHECK (ch.total > 7000 && ch.total < 26000);
          p = run_flight (&id, ch.chain, 2, &cfg, 0, 0, 1, 2000000, &c, &s);
          CHECK (c >= 1.9 && c <= 2.1);	/* One more than the classical.  */
          CHECK (s >= 2.4 && s <= 2.6);
          CHECK (p->cli.connected && p->srv.connected);
          pair_free (p);
          tst_free_mldsa_chain (&ch);
        }
    }
}

/* The limit itself.  The client's datagrams stop arriving after the first
   (ALLOW of them); the server keeps retransmitting its flight on its timer
   and must never send more than three times what it received.  */
static void
test_flight_amplification (int mode)
{
  static const unsigned schemes[] = { GQ_SIG_MLDSA44, GQ_SIG_MLDSA65,
                                      GQ_SIG_MLDSA87 };
  static struct tst_mlchain ch;
  static struct ident id;
  size_t i;
  int allow;

  for (allow = 1; allow <= 2; allow++)
    for (i = 0; i < 4; i++)
      {
        struct pair *p;
        gq_conn_config cfg;
        gq_conn_stats st;
        const struct ident *use = &fx_ec;
        const gq_slice *chain = NULL;
        size_t n = 1;

        memset (&cfg, 0, sizeof cfg);
        if (i < 3)
          {
            CHECK_EQ (tst_make_mldsa_chain (&ch, schemes[i], &fx_ca,
                                            "example.test", mode), 0);
            memset (&id, 0, sizeof id);
            id.key = ch.key;
            id.chain[0] = ch.chain[0];
            use = &id;
            chain = ch.chain;
            n = 2;
          }
        g_server_ident = use;
        g_server_chain = chain;
        g_server_n_chain = n;
        p = pair_new (&cfg, &cfg, 0, 3);
        g_server_ident = NULL;
        g_server_chain = NULL;
        p->net.c2s_allow = allow;
        run (&p->net, NULL, 5000000);	/* Five seconds: many timeouts.  */
        gq_conn_get_stats (p->srv.c, &st);
        CHECK (st.bytes_received > 0 && st.bytes_sent > 0);
        CHECK (st.bytes_sent <= 3 * st.bytes_received);
        if (i < 3)
          {
            /* The flight is far bigger than the allowance, so the handshake
               cannot have completed.  */
            CHECK (!p->cli.connected && !p->srv.connected);
          }
        pair_free (p);
        if (i < 3)
          tst_free_mldsa_chain (&ch);
      }
}


/* Each of the first datagrams of a big flight lost in turn.  The server's
   packets after the lost one are all ones the client cannot read when it is
   the head of the ServerHello that is gone (it has no Handshake keys), so
   they fill the server's congestion window without ever being acknowledged;
   the lost part of the ServerHello still has to be sent again, by a probe,
   and the handshake complete.  */
static void
test_flight_lost_datagram (int mode)
{
  static struct tst_mlchain ch;
  static struct ident id;
  unsigned drop;

  CHECK_EQ (tst_make_mldsa_chain (&ch, GQ_SIG_MLDSA87, &fx_ca, "example.test",
                                  mode), 0);
  memset (&id, 0, sizeof id);
  id.key = ch.key;
  id.chain[0] = ch.chain[0];
  for (drop = 2; drop <= 14; drop++)
    {
      struct pair *p;
      gq_conn_config cfg;
      double c, s;

      memset (&cfg, 0, sizeof cfg);
      g_server_ident = &id;
      g_server_chain = ch.chain;
      g_server_n_chain = 2;
      p = pair_new (&cfg, &cfg, 0, 1);
      g_server_ident = NULL;
      g_server_chain = NULL;
      p->net.drop_index = (int) drop;
      (void) c; (void) s;
      run (&p->net, both_connected, 30000000);
      if (!(p->cli.connected && p->srv.connected))
        fprintf (stderr, "flight: datagram %u lost: handshake did not "
                 "complete\n", drop);
      CHECK (p->cli.connected && p->srv.connected);
      pair_free (p);
    }
  tst_free_mldsa_chain (&ch);
}

/* Whole handshakes with such flights, with the loss, burst loss and
   reordering a path may have, on both QUIC versions: all complete.  */
static void
test_flight_loss (int mode)
{
  static const unsigned schemes[] = { GQ_SIG_MLDSA44, GQ_SIG_MLDSA65,
                                      GQ_SIG_MLDSA87 };
  static const uint32_t versions[] = { GQ_VERSION_1, GQ_VERSION_2 };
  static const unsigned losses[] = { 0, 3, 8 };
  static struct tst_mlchain ch;
  static struct ident id;
  size_t i, v, l;
  uint32_t seed;

  for (i = 0; i < 3; i++)
    {
      CHECK_EQ (tst_make_mldsa_chain (&ch, schemes[i], &fx_ca, "example.test",
                                      mode), 0);
      memset (&id, 0, sizeof id);
      id.key = ch.key;
      id.chain[0] = ch.chain[0];
      for (v = 0; v < 2; v++)
        for (l = 0; l < 3; l++)
          for (seed = 1; seed <= 4; seed++)
            {
              struct pair *p;
              gq_conn_config cfg;
              double c, s;

              memset (&cfg, 0, sizeof cfg);
              cfg.version = versions[v];
              p = run_flight (&id, ch.chain, 2, &cfg, losses[l], seed & 1,
                              seed * 7 + (uint32_t) (i * 3 + v), 60000000, &c,
                              &s);
              if (!(p->cli.connected && p->srv.connected))
                fprintf (stderr, "flight: set %zu v%zu loss %u%% seed %u did "
                         "not complete\n", i, v + 1, losses[l], seed);
              CHECK (p->cli.connected && p->srv.connected);
              CHECK (gq_conn_is_established (p->cli.c));
              CHECK (gq_conn_is_established (p->srv.c));
              pair_free (p);
            }
      tst_free_mldsa_chain (&ch);
    }
}




/* A ClientHello that takes more than one Initial datagram: three post-quantum
   groups, the first with a 1665 byte share, and X25519's share as well.
   The server reads it from CRYPTO frames in two Initial packets, whichever
   of the datagrams is lost, and answers with a big flight.  */
struct hello_obs
{
  int client_big;		/* Datagrams of 1200 bytes or more from the
				   client before the server's first.  */
  int server_seen;
};

static void
hello_snoop (struct net *n, int from, const uint8_t *d, size_t len, int ecn,
             void *user)
{
  struct hello_obs *o = user;

  (void) n; (void) d; (void) ecn;
  if (from == 1)
    o->server_seen = 1;
  else if (!o->server_seen && len >= 1200)
    o->client_big++;
}

static void
test_big_client_hello (int mode)
{
  static const uint16_t groups[] = { GQ_GROUP_SECP384R1_MLKEM1024,
                                     GQ_GROUP_X25519_MLKEM768,
                                     GQ_GROUP_X25519 };
  static struct tst_mlchain ch;
  static struct ident id;
  int drop;
  uint32_t seed;

  CHECK_EQ (tst_make_mldsa_chain (&ch, GQ_SIG_MLDSA65, &fx_ca, "example.test",
                                  mode), 0);
  memset (&id, 0, sizeof id);
  id.key = ch.key;
  id.chain[0] = ch.chain[0];
  g_cgroups = groups;
  g_n_cgroups = 3;
  for (drop = -1; drop <= 7; drop++)
    for (seed = 1; seed <= (drop < 0 ? 6u : 1u); seed++)
      {
        struct pair *p;
        gq_conn_config cfg;
        struct hello_obs obs = { 0, 0 };

        memset (&cfg, 0, sizeof cfg);
        g_server_ident = &id;
        g_server_chain = ch.chain;
        g_server_n_chain = 2;
        p = pair_new (&cfg, &cfg, drop < 0 ? 5 : 0, seed);
        g_server_ident = NULL;
        g_server_chain = NULL;
        p->net.snoop = hello_snoop;
        p->net.snoop_user = &obs;
        p->net.drop_index = drop;
        run (&p->net, both_connected, 60000000);
        if (!(p->cli.connected && p->srv.connected))
          fprintf (stderr, "hello: datagram %d lost, seed %u: handshake did "
                   "not complete\n", drop, seed);
        CHECK (p->cli.connected && p->srv.connected);
        CHECK (obs.client_big >= 2);	/* It did not fit one.  */
        pair_free (p);
      }
  g_cgroups = NULL;
  g_n_cgroups = 0;
  tst_free_mldsa_chain (&ch);
}

/* All of the above for both kinds of chain: the one with a classical leaf
   padded to the ML-DSA sizes, which any GnuTLS validates, and, where this
   one validates ML-DSA keys, the one with a real ML-DSA key in the leaf.  */
static void
test_flights (void)
{
  int real = tst_mldsa_ready (tst_gnutls_validates_mldsa (),
                              "the large flights with real ML-DSA keys");
  int mode;

  for (mode = TST_CHAIN_ML; mode <= TST_CHAIN_CLASSIC; mode++)
    {
      if (mode == TST_CHAIN_ML && !real)
        continue;
      test_flight_cost (mode);
      test_flight_amplification (mode);
      test_flight_lost_datagram (mode);
      test_flight_loss (mode);
      test_big_client_hello (mode);
    }
}

/* NREQ requests of REQ bytes, each answered with RESP bytes.  */
static void
test_requests (unsigned loss, uint32_t seed, int nreq, size_t req,
               size_t resp, const gq_conn_config *ccfg,
               const gq_conn_config *scfg, int reorder)
{
  struct pair *p = pair_new (ccfg, scfg, loss, seed);
  int i, opened = 0;
  uint64_t deadline;

  p->net.reorder = reorder;
  p->srv.respond = resp;
  CHECK (run (&p->net, both_connected, 30000000));
  deadline = p->net.now + 600000000;
  while (opened < nreq && p->net.now < deadline)
    {
      uint64_t id;
      int r = gq_conn_stream_open (p->cli.c, 1, &id);

      if (r == GQ_OK)
        {
          struct sbuf *s = sb_get (&p->cli, id);

          s->out_total = req;
          s->out_fin = 1;
          opened++;
        }
      else
        run (&p->net, NULL, 100000);
    }
  CHECK_EQ (opened, nreq);
  {
    int ok = 0;

    while (p->net.now < deadline)
      {
        run (&p->net, NULL, 200000);
        ok = 1;
        for (i = 0; i < MAXS; i++)
          if (p->cli.sb[i].used && (p->cli.sb[i].id & 3) == 0
              && !(p->cli.sb[i].fin && p->cli.sb[i].n == resp))
            ok = 0;
        if (ok && opened == nreq)
          break;
      }
    CHECK (ok);
  }
  CHECK_EQ (p->cli.bad, 0);
  CHECK_EQ (p->srv.bad, 0);
  for (i = 0; i < MAXS; i++)
    if (p->cli.sb[i].used)
      CHECK_EQ (p->cli.sb[i].n, resp);
  /* Everything is acknowledged in the end and streams are released.  */
  run (&p->net, NULL, 5000000);
  for (i = 0; i < MAXS; i++)
    if (p->cli.sb[i].used && p->cli.sb[i].id < 4 * (uint64_t) nreq)
      CHECK (p->cli.sb[i].closed);
  CHECK_EQ (p->cli.closed, 0);
  CHECK_EQ (p->srv.closed, 0);
  pair_free (p);
}

/* The server sends SIZE bytes; LOSS_PCT random loss, and optionally a
   blackout of BLACKOUT_US starting once BLACKOUT_AT bytes have arrived.  ALGO
   is the server's congestion controller.  */
static void
test_congestion (int algo, size_t size, unsigned loss, uint64_t blackout_at,
                 uint64_t blackout_us, int expect_events, int expect_min)
{
  gq_conn_config cfg;
  struct pair *p;
  uint64_t id, until = 0, deadline;
  struct sbuf *s;
  int done = 0;

  if (getenv ("QDBG"))
    fprintf (stderr, "--- congestion algo=%d size=%zu loss=%u\n", algo, size,
             loss);
  memset (&cfg, 0, sizeof cfg);
  cfg.initial_max_data = 100u << 20;
  cfg.initial_max_stream_data = 100u << 20;
  cfg.congestion_control = algo;
  p = pair_new (&cfg, &cfg, 0, 21);
  p->srv.respond = size;
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 500000);
  p->net.min_cwnd = 0;
  p->net.max_cwnd = 0;
  p->net.loss_pct = loss;
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  s = sb_get (&p->cli, id);
  s->out_total = 10;
  s->out_fin = 1;
  deadline = p->net.now + 300000000;
  while (p->net.now < deadline && !done)
    {
      run (&p->net, NULL, 20000);
      if (blackout_us && !until && s->n >= blackout_at)
        {
          until = p->net.now + blackout_us;
          p->net.loss_pct = 100;
        }
      if (until && p->net.now >= until)
        {
          p->net.loss_pct = loss;
          until = 0;
          blackout_us = 0;
        }
      done = s->fin && s->n == size;
    }
  CHECK (done);
  CHECK_EQ (p->cli.bad, 0);
  /* The window starts at ten datagrams, grows, and never lets more than one
     datagram beyond it into flight.  After a congestion event the window
     can sit below what is already in flight (a reduction does not recall
     packets), so that holds only while there has been none.  */
  CHECK (p->net.max_cwnd > 12000);
  if (!expect_events)
    CHECK (p->net.max_over < 1200);
  if (expect_events)
    CHECK (p->net.events > 0);
  else
    CHECK_EQ (p->net.events, 0);
  if (expect_min)
    CHECK_EQ (p->net.min_cwnd, 2400);
  else
    CHECK (p->net.min_cwnd > 2400);
  pair_free (p);
}

/* What the server's datagrams look like to the network: how many leave at
   the same instant.  */
struct pace_obs
{
  int armed;
  uint64_t at;
  unsigned run, max_run, over;
  uint64_t max_allowed_rate;
};

static void
pace_tap (struct net *n, int from, const gq_path *to, void *user)
{
  struct pace_obs *o = user;
  gq_conn_stats st;
  unsigned allowed;

  (void) to;
  if (!o->armed || from != 1)
    return;
  if (n->now == o->at)
    o->run++;
  else
    {
      o->at = n->now;
      o->run = 1;
    }
  if (o->run > o->max_run)
    o->max_run = o->run;
  /* The initial window may leave at once from idle, and a millisecond's
     worth of credit at the pacing rate (a timer is no finer): a few more
     datagrams for the one that arrives with an acknowledgement.  */
  gq_conn_get_stats (n->app[1]->c, &st);
  allowed = (unsigned) (st.pacing_rate_bps / 8000 / 1200) + 1;
  if (allowed < 10)
    allowed = 10;
  allowed += 2;
  if (o->run > allowed)
    o->over++;
}

/* Run until stream S has delivered SIZE bytes and its end, or BUDGET_US
   passes.  */
static int
wait_for_stream (struct pair *p, struct sbuf *s, size_t size,
                 uint64_t budget_us)
{
  uint64_t deadline = p->net.now + budget_us;
  int guard = 0;

  while (!(s->fin && s->n == size) && p->net.now < deadline
         && guard++ < 100000)
    run (&p->net, NULL, 20000);
  return s->fin && s->n == size;
}

/* The log of a plain handshake and transfer: every line is well-formed, the
   events are what the draft names and come in time order, and what the log
   says adds up to what the connection counted itself.  */
static void
test_qlog_handshake (void)
{
  gq_conn_config cfg;
  struct qsink ck, sk;
  struct pair *p;
  gq_conn_stats cst, sst;
  struct sbuf *b;
  const size_t size = 300000;
  uint64_t id;
  qline q;
  size_t i;

  memset (&ck, 0, sizeof ck);
  memset (&sk, 0, sizeof sk);
  ck.who = "cli";
  sk.who = "srv";
  ck.keep = sk.keep = 1;
  ck.dump = sk.dump = getenv ("QLOG_DUMP") != NULL;
  memset (&cfg, 0, sizeof cfg);
  cfg.initial_max_data = 100u << 20;
  cfg.initial_max_stream_data = 100u << 20;
  cfg.qlog = qsink_cb;
  cfg.qlog_user = &ck;
  {
    gq_conn_config scfg = cfg;

    scfg.qlog_user = &sk;
    p = pair_new (&cfg, &scfg, 0, 41);
  }
  p->srv.respond = size;
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 500000);
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  b = sb_get (&p->cli, id);
  b->out_total = 10;
  b->out_fin = 1;
  CHECK (wait_for_stream (p, b, size, 60000000));
  run (&p->net, NULL, 1000000);
  gq_conn_get_stats (p->cli.c, &cst);
  gq_conn_get_stats (p->srv.c, &sst);

  CHECK_EQ (ck.bad_order, 0);
  CHECK_EQ (sk.bad_order, 0);
  CHECK_EQ (ck.bad_line, 0);
  CHECK_EQ (sk.bad_line, 0);
  CHECK (ck.n > 20 && sk.n > 20);

  /* Every event is one the draft defines, in its namespace.  */
  for (i = 0; i < ck.n; i++)
    CHECK (strncmp (ck.e[i].name, "quic:", 5) == 0);

  /* The connection starts the log.  */
  CHECK_EQ (strcmp (ck.e[0].name, "quic:connection_started"), 0);
  CHECK_EQ (strcmp (sk.e[0].name, "quic:connection_started"), 0);
  CHECK_EQ (qsink_count (&ck, "quic:connection_started"), 1);
  CHECK_EQ (qsink_count (&sk, "quic:connection_started"), 1);

  /* States go attempted, handshake_started, handshake_complete in turn, each
     naming the one before.  */
  CHECK (qsink_nth (&ck, "quic:connection_state_updated", 0, &q));
  CHECK (qline_is (&q, "new", "attempted"));
  CHECK (qline_get (&q, "old") == NULL);
  qline_free (&q);
  CHECK (qsink_nth (&ck, "quic:connection_state_updated", 1, &q));
  CHECK (qline_is (&q, "old", "attempted"));
  CHECK (qline_is (&q, "new", "handshake_started"));
  qline_free (&q);
  CHECK (qsink_nth (&ck, "quic:connection_state_updated", 2, &q));
  CHECK (qline_is (&q, "old", "handshake_started"));
  CHECK (qline_is (&q, "new", "handshake_complete"));
  qline_free (&q);

  /* Versions and ALPN: what was offered, and what was chosen.  */
  CHECK (qsink_nth (&ck, "quic:version_information", 0, &q));
  CHECK (qline_get (&q, "client_versions") != NULL);
  CHECK (qline_get (&q, "chosen_version") != NULL);
  qline_free (&q);
  CHECK (qsink_nth (&sk, "quic:version_information", 0, &q));
  CHECK (qline_get (&q, "server_versions") != NULL);
  qline_free (&q);
  CHECK (qsink_count (&ck, "quic:alpn_information") >= 2);
  CHECK (qsink_nth (&ck, "quic:alpn_information", 1, &q));
  CHECK (qline_get (&q, "chosen_alpn.string_value") != NULL);
  qline_free (&q);

  /* Both ends' parameters, as each side sees them.  */
  CHECK (qsink_nth (&ck, "quic:parameters_set", 0, &q));
  CHECK (qline_is (&q, "initiator", "local"));
  CHECK (qline_is_u (&q, "initial_max_data", 100u << 20));
  qline_free (&q);
  CHECK (qsink_nth (&ck, "quic:parameters_set", 1, &q));
  CHECK (qline_is (&q, "initiator", "remote"));
  CHECK (qline_get (&q, "original_destination_connection_id") != NULL);
  qline_free (&q);
  CHECK_EQ (qsink_count (&ck, "quic:recovery_parameters_set"), 1);

  /* Packets and datagrams add up to what the connection counted.  */
  CHECK_EQ (qsink_count (&ck, "quic:packet_sent"), cst.packets_sent);
  CHECK_EQ (qsink_count (&sk, "quic:packet_sent"), sst.packets_sent);
  CHECK_EQ (qsink_count (&ck, "quic:packet_received"), cst.packets_received);
  CHECK_EQ (qsink_count (&sk, "quic:packet_received"), sst.packets_received);
  CHECK_EQ (qsink_count (&sk, "quic:packet_dropped"), 0);
  CHECK_EQ (qsink_count (&ck, "quic:packet_dropped"), 0);
  CHECK (qsink_count (&sk, "quic:udp_datagrams_sent") > 0);
  CHECK (qsink_count (&sk, "quic:udp_datagrams_sent")
         <= qsink_count (&sk, "quic:packet_sent"));
  CHECK_EQ (qsink_count (&ck, "quic:udp_datagrams_received"),
            qsink_count (&sk, "quic:udp_datagrams_sent"));

  /* The response, as the frames of the packets say it.  */
  CHECK_EQ (qsink_frame_sum (&sk, "quic:packet_sent", "stream", "raw.length"),
            size);
  CHECK_EQ (qsink_frame_sum (&ck, "quic:packet_received", "stream",
                             "raw.length"), size);

  /* A packet event has its header and sizes.  */
  CHECK (qsink_nth (&sk, "quic:packet_sent", 0, &q));
  CHECK (qline_is (&q, "header.packet_type", "initial"));
  CHECK (qline_is_u (&q, "header.packet_number", 0));
  CHECK (qline_get (&q, "header.dcid") != NULL);
  CHECK (qline_get (&q, "header.scid") != NULL);
  CHECK (qline_get (&q, "raw.length") != NULL);
  CHECK (qline_get (&q, "datagram_id") != NULL);
  qline_free (&q);

  /* The keys are reported by name, never by value.  */
  CHECK (qsink_count (&ck, "quic:key_updated") >= 6);
  for (i = 0; i < ck.n; i++)
    if (!strcmp (ck.e[i].name, "quic:key_updated"))
      {
        CHECK (strstr (ck.e[i].fields, "key_type=") != NULL);
        CHECK (strstr (ck.e[i].fields, "old=") == NULL);
        CHECK (strstr (ck.e[i].fields, "new=") == NULL);
      }
  CHECK (qsink_count (&ck, "quic:key_discarded") >= 1);

  qsink_free (&ck);
  qsink_free (&sk);
  pair_free (p);
}

/* The latest value of KEY in the events called NAME (and whether there was
   one), as a number.  */
static int
qsink_last (const struct qsink *k, const char *name, const char *key,
            uint64_t *out)
{
  size_t i;
  int found = 0;

  for (i = 0; i < k->n; i++)
    {
      qline q;

      if (strcmp (k->e[i].name, name))
        continue;
      if (qline_parse (k->e[i].fields, strlen (k->e[i].fields), &q))
        {
          const char *v = qline_get (&q, key);

          if (v)
            {
              *out = strtoull (v, NULL, 10);
              found = 1;
            }
          qline_free (&q);
        }
    }
  return found;
}

/* What loss looks like in the log: each packet the connection counted lost
   is an event, its data is marked to be sent again, the congestion state
   goes into recovery, and the last metrics reported are the ones the
   connection has.  */
static void
test_qlog_loss (void)
{
  gq_conn_config cfg;
  struct qsink ck, sk;
  struct pair *p;
  gq_conn_stats sst;
  struct sbuf *b;
  const size_t size = 1000000;
  uint64_t id, v;
  qline q;
  size_t i, recovery = 0;

  memset (&ck, 0, sizeof ck);
  memset (&sk, 0, sizeof sk);
  ck.who = "cli";
  sk.who = "srv";
  ck.keep = sk.keep = 1;
  ck.dump = sk.dump = getenv ("QLOG_DUMP_LOSS") != NULL;
  memset (&cfg, 0, sizeof cfg);
  cfg.initial_max_data = 100u << 20;
  cfg.initial_max_stream_data = 100u << 20;
  cfg.qlog = qsink_cb;
  cfg.qlog_user = &ck;
  {
    gq_conn_config scfg = cfg;

    scfg.qlog_user = &sk;
    p = pair_new (&cfg, &scfg, 0, 43);
  }
  p->srv.respond = size;
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 500000);
  p->net.loss_pct = 4;
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  b = sb_get (&p->cli, id);
  b->out_total = 10;
  b->out_fin = 1;
  CHECK (wait_for_stream (p, b, size, 120000000));
  p->net.loss_pct = 0;
  run (&p->net, NULL, 3000000);
  gq_conn_get_stats (p->srv.c, &sst);
  CHECK (sst.packets_lost > 0);

  CHECK_EQ (sk.bad_order, 0);
  CHECK_EQ (sk.bad_line, 0);
  CHECK_EQ (ck.bad_line, 0);
  CHECK_EQ (qsink_count (&sk, "quic:packet_lost"), sst.packets_lost);
  CHECK (qsink_count (&sk, "quic:marked_for_retransmit") > 0);
  CHECK (qsink_count (&sk, "quic:packets_acked") > 0);
  CHECK (qsink_count (&sk, "quic:timer_updated") > 0);

  /* A lost packet says which it was and why.  */
  CHECK (qsink_nth (&sk, "quic:packet_lost", 0, &q));
  CHECK (qline_is (&q, "header.packet_type", "1RTT"));
  CHECK (qline_get (&q, "header.packet_number") != NULL);
  CHECK (qline_is (&q, "trigger", "reordering_threshold")
         || qline_is (&q, "trigger", "time_threshold"));
  qline_free (&q);

  /* The window went into recovery on a loss, and came out of it.  */
  for (i = 0; i < sk.n; i++)
    if (!strcmp (sk.e[i].name, "quic:congestion_state_updated")
        && strstr (sk.e[i].fields, "new=recovery"))
      {
        recovery++;
        CHECK (strstr (sk.e[i].fields, "trigger=packet_loss") != NULL);
      }
  CHECK (recovery > 0);
  {
    int exited = 0;

    for (i = 0; i < sk.n; i++)
      if (!strcmp (sk.e[i].name, "quic:congestion_state_updated")
          && strstr (sk.e[i].fields, "old=recovery"))
        {
          exited++;
          CHECK (strstr (sk.e[i].fields, "trigger=recovery_exit") != NULL);
        }
    CHECK (exited > 0);
  }

  /* The last metrics reported are the connection's own.  */
  CHECK (qsink_last (&sk, "quic:recovery_metrics_updated", "congestion_window",
                     &v));
  CHECK_EQ (v, sst.cwnd);
  CHECK (qsink_last (&sk, "quic:recovery_metrics_updated", "bytes_in_flight",
                     &v));
  CHECK_EQ (v, sst.bytes_in_flight);
  CHECK (qsink_last (&sk, "quic:recovery_metrics_updated", "ssthresh", &v));
  CHECK_EQ (v, sst.ssthresh);
  CHECK (qsink_last (&sk, "quic:recovery_metrics_updated", "pto_count", &v));
  CHECK_EQ (v, sst.pto_count);
  CHECK (qsink_last (&sk, "quic:recovery_metrics_updated", "smoothed_rtt", &v));
  CHECK_EQ (v, sst.srtt_us / 1000);
  /* Not every update repeats what did not change.  */
  CHECK (qsink_nth (&sk, "quic:recovery_metrics_updated", 5, &q));
  CHECK (q.n < 9);
  qline_free (&q);

  qsink_free (&ck);
  qsink_free (&sk);
  pair_free (p);
}

/* RFC 9002 section 7.7: after a transfer has grown the window, a second one
   from idle does not put the whole window on the wire at once, but spreads
   it over the round trip, with the timer the pacer asks for waking the
   connection.  Without pacing the second response, up to the send buffer
   (256 KiB), would leave in a single burst.  */
static void
test_pacing (int algo)
{
  gq_conn_config cfg;
  struct pair *p;
  struct pace_obs obs;
  gq_conn_stats st;
  uint64_t id;
  struct sbuf *s;
  const size_t size = 1000000;

  memset (&cfg, 0, sizeof cfg);
  cfg.initial_max_data = 100u << 20;
  cfg.initial_max_stream_data = 100u << 20;
  cfg.congestion_control = algo;
  p = pair_new (&cfg, &cfg, 0, 31);
  p->net.latency = 50000;		/* A 100 ms round trip.  */
  p->srv.respond = size;
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 500000);
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  s = sb_get (&p->cli, id);
  s->out_total = 10;
  s->out_fin = 1;
  CHECK (wait_for_stream (p, s, size, 120000000));
  gq_conn_get_stats (p->srv.c, &st);
  CHECK (st.pacing_rate_bps > 0);
  /* The first transfer opened the window well beyond a burst's worth.  */
  CHECK (st.cwnd > 100000);

  /* Idle for a while, then ask again.  */
  run (&p->net, NULL, 2000000);
  gq_conn_get_stats (p->srv.c, &st);
  CHECK_EQ (st.bytes_in_flight, 0);
  memset (&obs, 0, sizeof obs);
  obs.armed = 1;
  p->net.tap = pace_tap;
  p->net.tap_user = &obs;
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  s = sb_get (&p->cli, id);
  s->out_total = 10;
  s->out_fin = 1;
  CHECK (wait_for_stream (p, s, size, 120000000));
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  CHECK_EQ (obs.over, 0);
  CHECK (obs.max_run >= 2);
  pair_free (p);
}

static int
one_stream_done (struct net *n)
{
  return n->app[0]->sb[0].used && n->app[0]->sb[0].fin;
}

/* A request over a connection made through the admission step.  */
static void
exchange (struct pair *p)
{
  uint64_t id;
  struct sbuf *s;

  p->srv.respond = 5000;
  CHECK (run (&p->net, both_connected, 30000000));
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  s = sb_get (&p->cli, id);
  s->out_total = 20;
  s->out_fin = 1;
  CHECK (run (&p->net, one_stream_done, 30000000));
  CHECK_EQ (s->n, 5000);
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
}

static void
test_retry (uint32_t version, unsigned loss, uint32_t seed)
{
  struct pair *p;
  gq_conn_config cfg;

  memset (&cfg, 0, sizeof cfg);
  cfg.version = version;
  cfg.wall_seconds = sim_wall;
  p = pair_new_admit (&cfg, loss, seed, 1, NULL, 0);
  cfg.wall_seconds = sim_wall;
  p->scfg_conn.version = version;
  p->net.admit.retry_lifetime_s = 30;
  exchange (p);
  /* Exactly one Retry (with loss, retransmitted Initials may draw more),
     and the server connection only exists after the token came back.  */
  if (!loss)
    /* The client's first flight is two datagrams, so two Retries go out; it
     obeys the first and ignores the second.  */
  CHECK (p->net.replies >= 1 && p->net.accepts == 1);
  /* NEW_TOKEN arrived.  */
  run (&p->net, NULL, 1000000);
  CHECK_EQ (p->cli.tokens, 1);
  pair_free (p);
}

static void
test_tokens (void)
{
  struct pair *p, *q;
  uint8_t token[512];
  size_t tl;
  gq_token_keys saved;
  gq_conn_config cfg;

  memset (&cfg, 0, sizeof cfg);
  cfg.wall_seconds = sim_wall;
  /* No Retry needed when not required: unvalidated at first, token issued.  */
  p = pair_new_admit (&cfg, 0, 30, 0, NULL, 0);
  exchange (p);
  CHECK_EQ (p->net.replies, 0);
  run (&p->net, NULL, 1000000);
  CHECK_EQ (p->cli.tokens, 1);
  memcpy (token, p->cli.token, p->cli.token_len);
  tl = p->cli.token_len;
  saved = p->keys;
  pair_free (p);
  /* With Retry required, a NEW_TOKEN from before skips the Retry.  */
  q = pair_new_admit (&cfg, 0, 31, 1, token, tl);
  q->keys = saved;
  exchange (q);
  CHECK_EQ (q->net.replies, 0);
  pair_free (q);
  /* From another address it is worthless: the client gets a Retry.  */
  q = pair_new_admit (&cfg, 0, 32, 1, token, tl);
  q->keys = saved;
  q->net.addr[3] = 9;
  exchange (q);
  CHECK (q->net.replies >= 1);
  pair_free (q);
  /* Garbage as a token is treated as no token.  */
  {
    uint8_t junk[60];

    memset (junk, 0x5a, sizeof junk);
    q = pair_new_admit (&cfg, 0, 33, 1, junk, sizeof junk);
  q->keys = saved;
    exchange (q);
    CHECK (q->net.replies >= 1);
    pair_free (q);
  }
  /* An expired token (a day and more later) is refused too.  */
  q = pair_new_admit (&cfg, 0, 34, 1, token, tl);
  q->keys = saved;
  q->net.now += (uint64_t) 90000 * 1000000;
  exchange (q);
  CHECK (q->net.replies >= 1);
  pair_free (q);
}

/* Tokens from other implementations are longer than ours: quic-go's Retry
   token is about 110 bytes, and a client must put whatever it is given (up
   to 512 bytes) in its Initial packets.  The server takes an unknown token
   for none and asks for a Retry, and the handshake then completes.  */
static void
test_long_token (void)
{
  static const size_t lens[] = { 100, 101, 117, 200, 400, 512 };
  gq_conn_config cfg;
  size_t i;

  memset (&cfg, 0, sizeof cfg);
  cfg.wall_seconds = sim_wall;
  for (i = 0; i < sizeof lens / sizeof lens[0]; i++)
    {
      uint8_t junk[512];
      struct pair *q;

      memset (junk, 0x5a, sizeof junk);
      q = pair_new_admit (&cfg, 0, 60 + (uint32_t) i, 1, junk, lens[i]);
      CHECK (gq_conn_state (q->cli.c) == GQ_CONN_HANDSHAKE);
      exchange (q);
      CHECK (q->net.replies >= 1);
      pair_free (q);
    }
}

/* How long after its first flight a client waits before probing: the
   probe timeout of RFC 9002 section 6.2.1 from the round trip time assumed
   before a sample (333 ms unless configured), srtt + 4 * rttvar, so a
   second less a millisecond with the default.  */
static uint64_t
first_probe_delay (uint64_t initial_rtt_us)
{
  gq_conn_config cc, sc;
  struct pair *p;
  uint8_t buf[2048];
  size_t len = 1;
  uint64_t t, now;
  int guard = 0;

  memset (&cc, 0, sizeof cc);
  memset (&sc, 0, sizeof sc);
  cc.initial_rtt_us = initial_rtt_us;
  p = pair_new (&cc, &sc, 0, 5);
  now = p->net.now;
  while (len && guard++ < 10)
    CHECK_EQ (gq_conn_send (p->cli.c, now, buf, sizeof buf, &len), GQ_OK);
  t = gq_conn_timeout (p->cli.c);
  pair_free (p);
  CHECK (t > now);
  return t - now;
}

static void
test_initial_rtt (void)
{
  /* The default is the RFC's 333 ms, so a probe after 999 ms; a client that
     knows better, or must finish a handshake in a peer's few seconds under
     heavy loss, can have it sooner and the backoff starts from there.  */
  CHECK_EQ (first_probe_delay (0), 999000);
  CHECK_EQ (first_probe_delay (333000), 999000);
  CHECK_EQ (first_probe_delay (100000), 300000);
  CHECK_EQ (first_probe_delay (50000), 150000);
}

/* Handshakes under the interop runner's handshake loss: 30% of datagrams,
   in runs of 3, with 15 ms each way.  Both ends assume 100 ms until they
   measure a round trip, and the client's ClientHello fits in one datagram
   (X25519 only), as the runner's endpoint does.  Nearly all of them must be
   done within 5 seconds, which is how long some servers keep a half-open
   handshake before a late retransmission starts another.  The seeds are
   fixed, so the counts are the same on every run.  */
static void
test_handshake_under_bursty_loss (void)
{
  static const uint16_t x25519_only[] = { GQ_GROUP_X25519 };
  int i, done = 0, quick = 0;

  g_cgroups = x25519_only;
  g_n_cgroups = 1;
  for (i = 0; i < 100; i++)
    {
      gq_conn_config cc, sc;
      struct pair *p;
      uint64_t start;

      memset (&cc, 0, sizeof cc);
      memset (&sc, 0, sizeof sc);
      cc.initial_rtt_us = sc.initial_rtt_us = 100000;
      p = pair_new (&cc, &sc, 0, 2000 + (uint32_t) i);
      p->net.latency = 15000;
      p->net.loss_pct = 30;
      p->net.burst = 3;
      p->net.rng = 104729u * ((uint32_t) i + 1);
      start = p->net.now;
      if (run (&p->net, both_connected, 60000000))
        {
          done++;
          if (p->net.now - start <= 5000000)
            quick++;
        }
      pair_free (p);
    }
  g_cgroups = NULL;
  g_n_cgroups = 0;
  CHECK (done >= 99);
  CHECK (quick >= 96);
}

/* A client that advertises no stateless reset token (ours and most others
   do not) has none recorded, and a datagram that ends in zeros is not a
   stateless reset from it.  Some clients (neqo, quic-go, ngtcp2) pad their
   Initial datagrams with raw zero bytes after the packet; when such a
   datagram is retransmitted to a connection that is already established,
   the padding reads as a short header packet that cannot be decrypted, and
   its all-zero tail used to match the all-zero token of a peer that sent
   none, ending the connection.  */
static void
test_zero_tail_is_not_a_reset (void)
{
  gq_conn_config cfg;
  struct pair *p;
  gq_cid ids[8];
  uint8_t dg[200];
  size_t n, len;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new (&cfg, &cfg, 0, 90);
  exchange (p);
  n = gq_conn_local_cids (p->srv.c, ids, 8);
  CHECK (n >= 1);
  /* A short header packet for the server's connection, nothing it can
     decrypt, and a tail of zeros as long as any padding.  */
  memset (dg, 0, sizeof dg);
  dg[0] = 0x40;
  memcpy (dg + 1, ids[0].data, ids[0].len);
  len = 1 + ids[0].len + 60;
  CHECK_EQ (gq_conn_recv (p->srv.c, p->net.now, dg, len), GQ_OK);
  CHECK (gq_conn_state (p->srv.c) == GQ_CONN_ESTABLISHED);
  CHECK_EQ (p->srv.closed, 0);
  /* And it carries on: another request is answered.  */
  {
    uint64_t id;
    struct sbuf *s;

    CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
    s = sb_get (&p->cli, id);
    s->out_total = 20;
    s->out_fin = 1;
    p->srv.respond = 3000;
    run (&p->net, NULL, 2000000);
    CHECK_EQ (s->n, 3000);
  }
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  pair_free (p);
}

/* Anything that is not a first Initial is dropped without an answer, and
   unknown versions get Version Negotiation.  */
static void
test_admit_input (void)
{
  gq_token_keys keys;
  gq_admit_config ac;
  gq_conn_accept acc;
  uint8_t dg[1300], out[1500], addr[4] = { 1, 2, 3, 4 };
  size_t rl, hl;
  int act;

  memset (&ac, 0, sizeof ac);
  gq_token_keys_init (&keys);
  memset (dg, 0, sizeof dg);
  /* A real-looking Initial: build a header with room for 1200 bytes.  */
  {
    uint8_t dcid[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, scid[4] = { 9, 9, 9, 9 };

    CHECK_EQ (gq_long_header_build (GQ_PKT_INITIAL, GQ_VERSION_1, dcid, 8,
                                    scid, 4, NULL, 0, 0, 1, 1100, dg,
                                    sizeof dg, &hl), GQ_OK);
  }
  act = gq_quic_admit (&keys, &ac, addr, 4, dg, 1200, 5, out, sizeof out, &rl,
                       &acc);
  CHECK_EQ (act, GQ_ADMIT_ACCEPT);
  CHECK (!acc.validated && acc.token_keys == &keys && acc.addr_len == 4);
  ac.require_retry = 1;
  act = gq_quic_admit (&keys, &ac, addr, 4, dg, 1200, 5, out, sizeof out, &rl,
                       &acc);
  CHECK_EQ (act, GQ_ADMIT_REPLY);
  CHECK (rl > 30 && rl < 200 && (out[0] & 0x80));
  /* Too short a datagram, a short-header packet, junk: dropped.  */
  CHECK_EQ (gq_quic_admit (&keys, &ac, addr, 4, dg, 1199, 5, out, sizeof out,
                           &rl, &acc), GQ_ADMIT_DROP);
  dg[0] &= 0x7f;
  CHECK_EQ (gq_quic_admit (&keys, &ac, addr, 4, dg, 1200, 5, out, sizeof out,
                           &rl, &acc), GQ_ADMIT_DROP);
  dg[0] |= 0x80;
  /* An unknown version draws Version Negotiation listing 1 and 2, but a
     Version Negotiation packet itself does not.  */
  dg[1] = 0x1a; dg[2] = 0x2a; dg[3] = 0x3a; dg[4] = 0x4a;
  act = gq_quic_admit (&keys, &ac, addr, 4, dg, 1200, 5, out, sizeof out, &rl,
                       &acc);
  CHECK_EQ (act, GQ_ADMIT_REPLY);
  {
    gq_long_header h;

    CHECK_EQ (gq_long_header_parse (out, rl, &h), GQ_OK);
    CHECK (h.type == GQ_PKT_VERSION_NEGOTIATION && gq_vn_count (&h) == 2);
    CHECK (gq_vn_get (&h, 0) == GQ_VERSION_1 && gq_vn_get (&h, 1)
           == GQ_VERSION_2);
  }
  dg[1] = dg[2] = dg[3] = dg[4] = 0;
  CHECK_EQ (gq_quic_admit (&keys, &ac, addr, 4, dg, 1200, 5, out, sizeof out,
                           &rl, &acc), GQ_ADMIT_DROP);
  gq_token_keys_wipe (&keys);
}

/* A Retry with a bad integrity tag changes nothing; a good one restarts the
   Initial flight with the token, and the server sees the original ID.  */
static void
test_retry_tamper (void)
{
  struct pair *p = pair_new_admit (NULL, 0, 50, 1, NULL, 0);
  uint8_t d1[1500], d2[1500], retry[1500], bad[1500], again[1500];
  size_t l1, l2, lr = 0, la;
  gq_conn_accept acc;
  const uint8_t *odcid;
  size_t odlen;

  odcid = gq_conn_initial_dcid (p->cli.c, &odlen);
  CHECK_EQ (gq_conn_send (p->cli.c, p->net.now, d1, sizeof d1, &l1), GQ_OK);
  CHECK_EQ (gq_conn_send (p->cli.c, p->net.now, d2, sizeof d2, &l2), GQ_OK);
  CHECK (l1 == 1200 && l2 > 0);
  CHECK_EQ (gq_quic_admit (&p->keys, &p->net.admit, p->net.addr, 6, d1, l1,
                           1, retry, sizeof retry, &lr, &acc), GQ_ADMIT_REPLY);
  memcpy (bad, retry, lr);
  bad[lr - 1] ^= 1;
  gq_conn_recv (p->cli.c, p->net.now, bad, lr);
  CHECK_EQ (gq_conn_send (p->cli.c, p->net.now, again, sizeof again, &la),
            GQ_OK);
  CHECK_EQ (la, 0);
  {
    uint8_t odsave[GQ_MAX_CID_LEN];

    memcpy (odsave, odcid, odlen);
    gq_conn_recv (p->cli.c, p->net.now, retry, lr);
    CHECK_EQ (gq_conn_send (p->cli.c, p->net.now, again, sizeof again, &la),
              GQ_OK);
    CHECK_EQ (la, 1200);
    CHECK_EQ (gq_quic_admit (&p->keys, &p->net.admit, p->net.addr, 6, again,
                             la, 1, retry, sizeof retry, &lr, &acc),
              GQ_ADMIT_ACCEPT);
    CHECK (acc.validated && acc.odcid.len == odlen
           && !memcmp (acc.odcid.data, odsave, odlen));
    /* The same token from another address is not accepted.  */
    p->net.addr[0] ^= 1;
    CHECK_EQ (gq_quic_admit (&p->keys, &p->net.admit, p->net.addr, 6, again,
                             la, 1, retry, sizeof retry, &lr, &acc),
              GQ_ADMIT_REPLY);
  }
  pair_free (p);
}

/* Compatible version negotiation (RFC 9368): the version both ends end up
   with.  CV is the client's first flight, CLIST its preference order, SLIST
   the server's versions; the server follows the client's order.  */
static void
compat_run (uint32_t cv, const uint32_t *clist, size_t nc,
            const uint32_t *slist, size_t ns, unsigned loss, uint32_t seed,
            uint32_t expect)
{
  gq_conn_config cc, sc;
  struct pair *p;

  memset (&cc, 0, sizeof cc);
  memset (&sc, 0, sizeof sc);
  cc.version = cv;
  memcpy (cc.versions, clist, nc * sizeof *clist);
  cc.n_versions = nc;
  memcpy (sc.versions, slist, ns * sizeof *slist);
  sc.n_versions = ns;
  p = pair_new (&cc, &sc, loss, seed);
  exchange (p);
  CHECK_EQ (gq_conn_version (p->cli.c), expect);
  CHECK_EQ (gq_conn_version (p->srv.c), expect);
  pair_free (p);
}

static void
test_compat (void)
{
  static const uint32_t v12[2] = { GQ_VERSION_1, GQ_VERSION_2 };
  static const uint32_t v21[2] = { GQ_VERSION_2, GQ_VERSION_1 };
  static const uint32_t v1[1] = { GQ_VERSION_1 };
  static const uint32_t v2[1] = { GQ_VERSION_2 };

  /* The client starts in v1 but prefers v2: it is moved up, whatever the
     server's own order.  */
  compat_run (GQ_VERSION_1, v21, 2, v12, 2, 0, 60, GQ_VERSION_2);
  compat_run (GQ_VERSION_1, v21, 2, v21, 2, 0, 61, GQ_VERSION_2);
  /* ...and one that prefers v1 stays there even if the server likes v2.  */
  compat_run (GQ_VERSION_1, v12, 2, v21, 2, 0, 62, GQ_VERSION_1);
  compat_run (GQ_VERSION_2, v12, 2, v21, 2, 0, 63, GQ_VERSION_1);
  compat_run (GQ_VERSION_2, v21, 2, v12, 2, 0, 64, GQ_VERSION_2);
  /* A server that speaks only one keeps it.  */
  compat_run (GQ_VERSION_1, v21, 2, v1, 1, 0, 65, GQ_VERSION_1);
  compat_run (GQ_VERSION_2, v12, 2, v2, 1, 0, 66, GQ_VERSION_2);
  /* A pinned client gets what it asked for.  */
  compat_run (GQ_VERSION_1, v1, 1, v21, 2, 0, 67, GQ_VERSION_1);
  compat_run (GQ_VERSION_2, v2, 1, v21, 2, 0, 68, GQ_VERSION_2);
  /* Under loss the switch still completes.  */
  compat_run (GQ_VERSION_1, v21, 2, v12, 2, 20, 69, GQ_VERSION_2);
  compat_run (GQ_VERSION_2, v12, 2, v21, 2, 20, 70, GQ_VERSION_1);
  /* With nothing configured a client starts in v1 and both end in v2.  */
  {
    gq_conn_config none;
    struct pair *p;

    memset (&none, 0, sizeof none);
    p = pair_new (&none, &none, 0, 71);
    exchange (p);
    CHECK_EQ (gq_conn_version (p->cli.c), GQ_VERSION_2);
    CHECK_EQ (gq_conn_version (p->srv.c), GQ_VERSION_2);
    pair_free (p);
  }
}

/* An incompatible mismatch: Version Negotiation and a restart.  */
static void
test_version_negotiation (void)
{
  gq_conn_config cc;
  struct pair *p;
  static const uint32_t v1[1] = { GQ_VERSION_1 };

  memset (&cc, 0, sizeof cc);
  cc.version = GQ_VERSION_2;
  cc.versions[0] = GQ_VERSION_2;
  cc.versions[1] = GQ_VERSION_1;
  cc.n_versions = 2;
  cc.wall_seconds = sim_wall;
  p = pair_new_admit (&cc, 0, 70, 0, NULL, 0);
  memcpy (p->net.admit.versions, v1, sizeof v1);
  p->net.admit.n_versions = 1;
  p->scfg_conn.versions[0] = GQ_VERSION_1;
  p->scfg_conn.n_versions = 1;
  p->scfg_conn.version = GQ_VERSION_1;
  exchange (p);
  CHECK_EQ (gq_conn_version (p->cli.c), GQ_VERSION_1);
  CHECK_EQ (gq_conn_version (p->srv.c), GQ_VERSION_1);
  CHECK (p->net.replies >= 1);
  pair_free (p);

  /* No version in common: the client gives up.  */
  cc.versions[1] = GQ_VERSION_2;
  cc.n_versions = 1;
  p = pair_new_admit (&cc, 0, 71, 0, NULL, 0);
  memcpy (p->net.admit.versions, v1, sizeof v1);
  p->net.admit.n_versions = 1;
  run (&p->net, NULL, 2000000);
  CHECK_EQ (p->cli.closed, 1);
  CHECK (p->cli.ci.error == GQ_QERR_VERSION_NEGOTIATION
         && !p->cli.connected);
  CHECK_EQ (gq_conn_state (p->cli.c), GQ_CONN_DONE);
  pair_free (p);
}

/* A forged Version Negotiation packet cannot downgrade the connection: the
   restarted handshake lets the server move it back to the version the
   client prefers (RFC 9368 sections 2 and 4).  */
static void
test_downgrade (void)
{
  gq_conn_config cc;
  struct pair *p;
  uint8_t d1[1500], vn[200], junk[1500];
  size_t l1, vl, jl;
  gq_long_header h;
  static const uint32_t only1[1] = { GQ_VERSION_1 };
  static const uint32_t only2[1] = { GQ_VERSION_2 };

  memset (&cc, 0, sizeof cc);
  cc.version = GQ_VERSION_2;
  cc.versions[0] = GQ_VERSION_2;
  cc.versions[1] = GQ_VERSION_1;
  cc.n_versions = 2;
  cc.wall_seconds = sim_wall;
  p = pair_new_admit (&cc, 0, 72, 0, NULL, 0);
  p->scfg_conn.versions[0] = GQ_VERSION_1;
  p->scfg_conn.versions[1] = GQ_VERSION_2;
  p->scfg_conn.n_versions = 2;
  CHECK_EQ (gq_conn_send (p->cli.c, p->net.now, d1, sizeof d1, &l1), GQ_OK);
  CHECK_EQ (gq_long_header_parse (d1, l1, &h), GQ_OK);
  while (gq_conn_send (p->cli.c, p->net.now, junk, sizeof junk, &jl) == GQ_OK
         && jl)
    ;
  /* One that lists the version in use is not a real one; nor one that does
     not echo our IDs.  */
  CHECK_EQ (gq_vn_build (h.scid.data, h.scid.len, h.dcid.data, h.dcid.len,
                         only2, 1, 0, vn, sizeof vn, &vl), GQ_OK);
  gq_conn_recv (p->cli.c, p->net.now, vn, vl);
  CHECK_EQ (gq_vn_build (h.dcid.data, h.dcid.len, h.scid.data, h.scid.len,
                         only1, 1, 0, vn, sizeof vn, &vl), GQ_OK);
  gq_conn_recv (p->cli.c, p->net.now, vn, vl);
  CHECK_EQ (gq_conn_send (p->cli.c, p->net.now, junk, sizeof junk, &jl),
            GQ_OK);
  CHECK_EQ (jl, 0);
  CHECK_EQ (gq_conn_version (p->cli.c), GQ_VERSION_2);
  /* A well-formed forgery that hides v2 from the client.  */
  CHECK_EQ (gq_vn_build (h.scid.data, h.scid.len, h.dcid.data, h.dcid.len,
                         only1, 1, 0, vn, sizeof vn, &vl), GQ_OK);
  gq_conn_recv (p->cli.c, p->net.now, vn, vl);
  CHECK_EQ (gq_conn_version (p->cli.c), GQ_VERSION_1);
  /* The server, seeing a client that started in v1 and prefers v2, moves
     the connection to v2 by compatible negotiation: the forgery achieves
     nothing.  */
  run (&p->net, NULL, 3000000);
  CHECK (p->cli.connected && p->srv.connected);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  CHECK_EQ (gq_conn_version (p->cli.c), GQ_VERSION_2);
  CHECK_EQ (gq_conn_version (p->srv.c), GQ_VERSION_2);
  pair_free (p);
}

/* Tickets are bound to the QUIC version (RFC 9369 section 5): a session
   resumes on a connection of the version that issued it, and on no other.  */
static void
resume_case (uint32_t first, uint32_t second, int expect_resumed)
{
  gq_conn_config c1, c2;
  struct pair *p;
  gq_tls_session sess;
  uint32_t ver;
  static const uint32_t v21[2] = { GQ_VERSION_2, GQ_VERSION_1 };

  memset (&c1, 0, sizeof c1);
  c1.version = first;
  p = pair_new (&c1, &c1, 0, 90);
  exchange (p);
  run (&p->net, NULL, 1000000);
  CHECK (p->cli.have_sess);
  CHECK_EQ (p->cli.sess_version, first);
  CHECK (!p->cli.info.resumed);
  sess = p->cli.sess;
  ver = p->cli.sess_version;
  pair_free (p);

  memset (&c2, 0, sizeof c2);
  if (second)
    c2.version = second;
  else
    {
      /* Starts in v1, prefers v2: the connection ends up in v2.  */
      c2.version = GQ_VERSION_1;
      memcpy (c2.versions, v21, sizeof v21);
      c2.n_versions = 2;
    }
  g_resume = &sess;
  p = pair_new (&c2, &c2, 0, 91);
  g_resume = NULL;
  exchange (p);
  CHECK_EQ (p->cli.info.resumed, expect_resumed);
  CHECK_EQ (p->srv.info.resumed, expect_resumed);
  (void) ver;
  pair_free (p);
}

static void
test_resumption (void)
{
  CHECK_EQ (gq_ticket_keys_new (&g_ring), GQ_OK);
  resume_case (GQ_VERSION_1, GQ_VERSION_1, 1);
  resume_case (GQ_VERSION_2, GQ_VERSION_2, 1);
  resume_case (GQ_VERSION_1, GQ_VERSION_2, 0);
  resume_case (GQ_VERSION_2, GQ_VERSION_1, 0);
  /* Offered in v1, but the server moves the connection to v2.  */
  resume_case (GQ_VERSION_1, 0, 0);
  gq_ticket_keys_free (g_ring);
  g_ring = NULL;
}

/* ---- DATAGRAM ---- */

static int transfer_done (struct net *n);
static struct sbuf *start_transfer (struct pair *p, size_t resp);

/* Send N datagrams of SIZE bytes (or up to it) from side FROM.  */
static int
send_datagrams (struct pair *p, struct app *from, int base, int n,
                size_t size)
{
  int i, ok = 0;

  for (i = 0; i < n; i++)
    {
      uint8_t buf[1300];
      int nn = base + i;
      size_t len = size ? size : 2 + (size_t) (nn * 37) % 900, k;
      uint64_t id;

      if (len < 2)
        len = 2;
      buf[0] = (uint8_t) (nn >> 8);
      buf[1] = (uint8_t) nn;
      for (k = 2; k < len; k++)
        buf[k] = (uint8_t) ((size_t) nn * 5 + k);
      if (gq_conn_datagram_send (from->c, buf, len, &id) == GQ_OK)
        ok++;
      run (&p->net, NULL, 2000);
    }
  return ok;
}

static void
test_datagrams (void)
{
  gq_conn_config on, off;
  struct pair *p;
  uint8_t buf[2000];
  uint64_t id;
  size_t max;
  int sent, i, seen = 0;

  memset (&on, 0, sizeof on);
  memset (&off, 0, sizeof off);
  on.max_datagram_frame_size = 1200;
  /* Off by default: nothing can be sent, either way.  */
  p = pair_new (&off, &off, 0, 110);
  CHECK (run (&p->net, both_connected, 30000000));
  CHECK_EQ (gq_conn_datagram_send (p->cli.c, buf, 10, &id), GQ_ERR_UNAVAILABLE);
  CHECK_EQ (gq_conn_datagram_max (p->cli.c), 0);
  pair_free (p);
  /* Only the server takes them: the client may send, the server may not.  */
  p = pair_new (&off, &on, 0, 111);
  CHECK (run (&p->net, both_connected, 30000000));
  CHECK_EQ (gq_conn_datagram_send (p->srv.c, buf, 10, &id), GQ_ERR_UNAVAILABLE);
  max = gq_conn_datagram_max (p->cli.c);
  CHECK (max > 1000 && max < 1200);
  CHECK_EQ (gq_conn_datagram_send (p->cli.c, buf, max + 1, &id), GQ_ERR_RANGE);
  sent = send_datagrams (p, &p->cli, 0, 40, 0);
  run (&p->net, NULL, 500000);
  CHECK_EQ (sent, 40);
  CHECK (p->srv.dg_recv == 40 && p->srv.dg_bad == 0);
  CHECK (p->cli.dg_acked == 40 && p->cli.dg_lost == 0);
  /* The biggest that fits, exactly.  */
  memset (buf, 0, sizeof buf);
  buf[0] = 0;
  buf[1] = 50;
  for (i = 2; i < (int) max; i++)
    buf[i] = (uint8_t) (50 * 5 + i);
  CHECK_EQ (gq_conn_datagram_send (p->cli.c, buf, max, &id), GQ_OK);
  run (&p->net, NULL, 500000);
  CHECK_EQ (p->srv.dg_recv, 41);
  CHECK_EQ (p->srv.dg_bad, 0);
  pair_free (p);

  /* Both ways, alongside a stream transfer, with loss: every datagram is
     reported acknowledged or lost exactly once, and none arrives twice or
     damaged.  */
  on.send_buffer = 100000;
  p = pair_new (&on, &on, 10, 112);
  CHECK (run (&p->net, both_connected, 60000000));
  {
    struct sbuf *s = start_transfer (p, 200000);
    int a = 0, b = 0;

    for (i = 0; i < 100; i++)
      {
        a += send_datagrams (p, &p->cli, i, 1, 0);
        b += send_datagrams (p, &p->srv, i, 1, 300);
      }
    CHECK (run (&p->net, transfer_done, 120000000));
    CHECK_EQ (s->n, 200000);
    run (&p->net, NULL, 3000000);
    CHECK (a == 100 && b == 100);
    CHECK_EQ (p->cli.dg_acked + p->cli.dg_lost, a);
    CHECK_EQ (p->srv.dg_acked + p->srv.dg_lost, b);
    for (i = 0; i < 100; i++)
      {
        CHECK_EQ (p->cli.dg_fate[i], 1);
        CHECK_EQ (p->srv.dg_fate[i], 1);
        CHECK (p->srv.dg_seen[i] <= 1 && p->cli.dg_seen[i] <= 1);
        seen += p->srv.dg_seen[i];
      }
    CHECK (seen > 60 && seen <= 100);		/* Loss, but not total.  */
    CHECK (p->srv.dg_recv <= 100 && p->cli.dg_recv <= 100);
    CHECK_EQ (p->srv.dg_bad + p->cli.dg_bad, 0);
  }
  pair_free (p);

  /* A full queue refuses.  */
  on.datagram_queue = 3000;
  p = pair_new (&on, &on, 0, 113);
  CHECK (run (&p->net, both_connected, 30000000));
  for (i = 0; i < 20; i++)
    if (gq_conn_datagram_send (p->cli.c, buf, 1000, &id) == GQ_ERR_BUFSIZE)
      break;
  CHECK (i >= 3 && i < 20);
  pair_free (p);
}

/* ---- Path validation and migration ---- */

static struct pair *
pair_new_paths (gq_conn_config *ccfg, const gq_conn_config *scfg, uint32_t seed)
{
  struct pair *p;
  gq_conn_config sc = *scfg;
  int i;

  /* The client is told its path; the server learns it from the first
     datagram.  */
  memset (&sc.path, 0, sizeof sc.path);
  ccfg->path.local = mkaddr ("CLI-L0");
  ccfg->path.remote = mkaddr ("SRV:443");
  p = pair_new (ccfg, &sc, 0, seed);
  p->net.paths = 1;
  p->net.S = mkaddr ("SRV:443");
  p->net.L[0] = mkaddr ("CLI-L0");
  p->net.L[1] = mkaddr ("CLI-L1");
  p->net.L[2] = mkaddr ("CLI-L2");
  for (i = 0; i < 3; i++)
    {
      char nm[16];

      snprintf (nm, sizeof nm, "EXT-%d", i);
      p->net.m[i].ext = mkaddr (nm);
      p->net.m[i].local = i;
      p->net.m[i].alive_in = 1;
      p->net.out_map[i] = i;
    }
  p->net.S2 = mkaddr ("SRV2:443");
  p->net.m[3].ext = mkaddr ("EXT-0b");	/* Local 0 after a NAT rebinding.  */
  p->net.m[3].local = 0;
  return p;
}

static int
transfer_done (struct net *n)
{
  struct sbuf *s = &n->app[0]->sb[0];

  return s->used && s->fin;
}

/* Request RESP bytes on the first stream.  */
static struct sbuf *
start_transfer (struct pair *p, size_t resp)
{
  uint64_t id;
  struct sbuf *s;

  p->srv.respond = resp;
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  s = sb_get (&p->cli, id);
  s->out_total = 20;
  s->out_fin = 1;
  return s;
}

static void
settle (struct pair *p)
{
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 1000000);
  CHECK (p->cli.mig == 0 && p->srv.mig == 0);
}

static void
test_nat_rebinding (void)
{
  gq_conn_config cfg;
  struct pair *p;
  struct sbuf *s;
  gq_conn_stats st;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new_paths (&cfg, &cfg, 100);
  settle (p);
  s = start_transfer (p, 400000);
  run (&p->net, NULL, 60000);
  CHECK (!s->fin && s->n > 0);
  /* The NAT gives the client a new external address; the old one is gone.  */
  p->net.out_map[0] = 3;
  p->net.m[3].alive_in = 1;
  p->net.m[0].alive_in = 0;
  CHECK (run (&p->net, transfer_done, 60000000));
  CHECK_EQ (s->n, 400000);
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  /* The server noticed, moved, validated the new address; the client never
     saw a thing.  */
  run (&p->net, NULL, 500000);
  gq_conn_get_stats (p->srv.c, &st);
  CHECK (st.migrations == 1 && st.path_validations >= 1 && st.path_failures == 0);
  CHECK (p->srv.mig == 1 && p->srv.pv >= 1 && p->cli.mig == 0);
  CHECK (addr_same (&p->srv.last_mig.remote, &p->net.m[3].ext));
  pair_free (p);
}

static void
test_active_migration (void)
{
  gq_conn_config cfg;
  struct pair *p;
  struct sbuf *s;
  gq_path np, cur;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new_paths (&cfg, &cfg, 101);
  settle (p);
  s = start_transfer (p, 400000);
  run (&p->net, NULL, 40000);
  np.local = p->net.L[1];
  np.remote = p->net.S;
  CHECK_EQ (gq_conn_migrate (p->cli.c, p->net.now, &np), GQ_OK);
  CHECK (run (&p->net, NULL, 200000) == 0 || 1);
  CHECK (p->cli.pv == 1 && p->cli.mig == 1);
  CHECK_EQ (gq_conn_get_path (p->cli.c, &cur), GQ_OK);
  CHECK (addr_same (&cur.local, &p->net.L[1]));
  /* The old network goes away completely: only the new path carries on.  */
  p->net.m[0].alive_in = 0;
  CHECK (run (&p->net, transfer_done, 60000000));
  CHECK_EQ (s->n, 400000);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  run (&p->net, NULL, 1000000);
  /* The server followed, and the old connection ID was retired.  */
  CHECK (p->srv.mig == 1);
  CHECK (p->srv.retired >= 1);
  /* Migrating to the path we are on is refused; to a validated one is
     immediate.  */
  CHECK_EQ (gq_conn_migrate (p->cli.c, p->net.now, &np), GQ_ERR_INVAL);
  pair_free (p);
}

/* Every connection ID a server behind a QUIC-LB configuration issues
   stays routable to it: the handshake ID, the spare ones offered up
   front, the Retry ID (RFC 9000 section 8.1.2, which the draft also
   requires to be routable), and the fresh one minted after an active
   migration retires the old one.  */
static void
check_all_routable (const gq_quiclb_config *lb, gq_conn *c)
{
  gq_cid cids[8];
  size_t n = gq_conn_local_cids (c, cids, 8), i;

  CHECK (n >= 1);
  for (i = 0; i < n; i++)
    CHECK (gq_quiclb_is_own (lb, cids[i].data, cids[i].len));
}

static void
test_quiclb_routing (void)
{
  gq_quiclb_config lb;
  gq_conn_config cc, sc;
  struct pair *p;
  struct sbuf *s;
  gq_path np;
  uint8_t sid[2] = { 0x11, 0x22 };

  CHECK_EQ (gq_quiclb_config_init (&lb, 4, sid, sizeof sid, 8, NULL, 1),
           GQ_OK);
  memset (&cc, 0, sizeof cc);
  memset (&sc, 0, sizeof sc);
  sc.cid_len = gq_quiclb_cid_len (&lb);
  sc.cid_gen = gq_quiclb_cid_gen;
  sc.cid_gen_user = &lb;
  p = pair_new_paths (&cc, &sc, 105);
  settle (p);
  check_all_routable (&lb, p->srv.c);	/* Handshake ID and the spares.  */
  s = start_transfer (p, 400000);
  run (&p->net, NULL, 40000);
  np.local = p->net.L[1];
  np.remote = p->net.S;
  CHECK_EQ (gq_conn_migrate (p->cli.c, p->net.now, &np), GQ_OK);
  run (&p->net, NULL, 200000);
  p->net.m[0].alive_in = 0;
  CHECK (run (&p->net, transfer_done, 60000000));
  CHECK_EQ (s->n, 400000);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  run (&p->net, NULL, 1000000);
  CHECK (p->srv.mig == 1 && p->srv.retired >= 1);
  check_all_routable (&lb, p->srv.c);	/* Post-migration ID too.  */
  pair_free (p);
}

/* The Retry ID a server behind QUIC-LB hands out is routable before any
   association exists, since RFC 9000 requires the client to address the
   rest of the handshake to it.  */
static void
test_quiclb_retry_routable (void)
{
  gq_quiclb_config lb;
  gq_token_keys keys;
  gq_admit_config ac;
  gq_conn_accept acc;
  gq_long_header h;
  uint8_t sid[3] = { 0xaa, 0xbb, 0xcc };
  uint8_t dg[1300], out[1500], addr[4] = { 9, 9, 9, 9 };
  size_t rl, hl, got_len;
  uint8_t got[8];

  CHECK_EQ (gq_quiclb_config_init (&lb, 2, sid, sizeof sid, 8, NULL, 1),
           GQ_OK);
  memset (&ac, 0, sizeof ac);
  ac.require_retry = 1;
  ac.retry_cid_len = gq_quiclb_cid_len (&lb);
  ac.cid_gen = gq_quiclb_cid_gen;
  ac.cid_gen_user = &lb;
  gq_token_keys_init (&keys);
  memset (dg, 0, sizeof dg);
  {
    uint8_t dcid[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, scid[4] = { 9, 9, 9, 9 };

    CHECK_EQ (gq_long_header_build (GQ_PKT_INITIAL, GQ_VERSION_1, dcid, 8,
                                    scid, 4, NULL, 0, 0, 1, 1100, dg,
                                    sizeof dg, &hl), GQ_OK);
  }
  CHECK_EQ (gq_quic_admit (&keys, &ac, addr, 4, dg, 1200, 5, out, sizeof out,
                           &rl, &acc), GQ_ADMIT_REPLY);
  CHECK_EQ (gq_long_header_parse (out, rl, &h), GQ_OK);
  CHECK_EQ (h.type, (unsigned) GQ_PKT_RETRY);
  CHECK_EQ (h.scid.len, gq_quiclb_cid_len (&lb));
  got_len = sizeof got;
  CHECK_EQ (gq_quiclb_decode_server_id (&lb, h.scid.data, h.scid.len, got,
                                       &got_len), GQ_OK);
  CHECK (got_len == sizeof sid && memcmp (got, sid, sizeof sid) == 0);
  CHECK (gq_quiclb_is_own (&lb, h.scid.data, h.scid.len));
  gq_token_keys_wipe (&keys);
}

static int
cli_migrated (struct net *n)
{
  return n->app[0]->mig > 0;
}

/* The server may go on using the old path until it has seen the new one:
   what arrives there after the client has migrated is still good.  */
static void
test_old_path_traffic (void)
{
  gq_conn_config cfg;
  struct pair *p;
  struct sbuf *s;
  gq_path np;
  gq_conn_stats a, b;
  int i, held;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new_paths (&cfg, &cfg, 108);
  settle (p);
  s = start_transfer (p, 300000);
  run (&p->net, NULL, 30000);
  p->net.hold = 1;
  run (&p->net, NULL, 30000);
  p->net.hold = 0;
  held = p->net.n_held;
  CHECK (held > 0);
  np.local = p->net.L[1];
  np.remote = p->net.S;
  CHECK_EQ (gq_conn_migrate (p->cli.c, p->net.now, &np), GQ_OK);
  /* Stop the moment the client has moved: the server has not yet seen the
     new path, so the datagrams it sent to the old one are still good.  */
  CHECK (run (&p->net, cli_migrated, 1000000));
  CHECK_EQ (p->cli.mig, 1);
  gq_conn_get_stats (p->cli.c, &a);
  for (i = 0; i < held; i++)
    {
      struct pkt *h = p->net.held[i];

      gq_conn_recv_path (p->cli.c, p->net.now, &h->from, h->d, h->len);
      free (h);
    }
  gq_conn_get_stats (p->cli.c, &b);
  CHECK_EQ (b.packets_received - a.packets_received, (uint64_t) held);
  CHECK (run (&p->net, transfer_done, 60000000));
  CHECK_EQ (s->n, 300000);
  /* But a datagram from an address the client has never heard of is not.  */
  {
    gq_path stranger = np;
    uint8_t junk[100];

    stranger.remote = mkaddr ("STRANGER");
    memset (junk, 0x41, sizeof junk);
    gq_conn_get_stats (p->cli.c, &a);
    gq_conn_recv_path (p->cli.c, p->net.now, &stranger, junk, sizeof junk);
    gq_conn_get_stats (p->cli.c, &b);
    CHECK_EQ (a.bytes_received, b.bytes_received);
  }
  pair_free (p);
}

static void
test_probe (void)
{
  gq_conn_config cfg;
  struct pair *p;
  gq_path np, cur;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new_paths (&cfg, &cfg, 102);
  settle (p);
  np.local = p->net.L[2];
  np.remote = p->net.S;
  CHECK_EQ (gq_conn_probe_path (p->cli.c, p->net.now, &np), GQ_OK);
  run (&p->net, NULL, 300000);
  /* Validated, but not moved to; the server answered without migrating.  */
  CHECK_EQ (p->cli.pv, 1);
  CHECK (p->cli.mig == 0 && p->srv.mig == 0);
  CHECK_EQ (gq_conn_get_path (p->cli.c, &cur), GQ_OK);
  CHECK (addr_same (&cur.local, &p->net.L[0]));
  /* Now use it: it is validated already, so the move is immediate.  */
  CHECK_EQ (gq_conn_migrate (p->cli.c, p->net.now, &np), GQ_OK);
  CHECK_EQ (p->cli.mig, 1);
  /* An idle client shows the server nothing; traffic on the new path does
     (only a non-probing packet counts).  */
  run (&p->net, NULL, 300000);
  CHECK_EQ (p->srv.mig, 0);
  start_transfer (p, 5000);
  run (&p->net, transfer_done, 5000000);
  CHECK_EQ (p->srv.mig, 1);
  pair_free (p);
}

static void
test_probe_failure (void)
{
  gq_conn_config cfg;
  struct pair *p;
  struct sbuf *s;
  gq_path np, cur;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new_paths (&cfg, &cfg, 103);
  settle (p);
  /* The new path works towards the server but not back.  */
  p->net.m[2].alive_in = 0;
  np.local = p->net.L[2];
  np.remote = p->net.S;
  s = start_transfer (p, 100000);
  CHECK_EQ (gq_conn_migrate (p->cli.c, p->net.now, &np), GQ_OK);
  CHECK (run (&p->net, transfer_done, 60000000));
  run (&p->net, NULL, 5000000);
  CHECK_EQ (s->n, 100000);
  CHECK (p->cli.pf == 1 && p->cli.pv == 0 && p->cli.mig == 0);
  CHECK_EQ (gq_conn_get_path (p->cli.c, &cur), GQ_OK);
  CHECK (addr_same (&cur.local, &p->net.L[0]));
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  pair_free (p);
}

/* The peer appears at an address that cannot receive: the server moves
   there at once but sends no more than three times what it received, then
   returns to the old path when validation fails, and does not follow again
   for a while.  */
static void
test_migration_failure (void)
{
  gq_conn_config cfg;
  struct pair *p;
  struct sbuf *s;
  gq_conn_stats st;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new_paths (&cfg, &cfg, 104);
  settle (p);
  s = start_transfer (p, 600000);
  run (&p->net, NULL, 30000);
  p->net.out_map[0] = 3;			/* Outgoing appears from EXT-0b,  */
  p->net.m[3].alive_in = 0;			/* which cannot be answered;  */
  /* while EXT-0 still reaches the client.  */
  CHECK (run (&p->net, transfer_done, 60000000));
  CHECK_EQ (s->n, 600000);
  run (&p->net, NULL, 3000000);
  gq_conn_get_stats (p->srv.c, &st);
  CHECK (st.path_failures >= 1);
  CHECK (p->srv.mig >= 2);			/* There, and back.  */
  CHECK (p->net.m[3].to_bytes <= 3 * p->net.m[3].from_bytes);
  CHECK (p->net.m[3].to_bytes > 0);
  CHECK (addr_same (&p->srv.last_mig.remote, &p->net.m[0].ext));
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  pair_free (p);
}

static void
test_migration_limits (void)
{
  gq_conn_config cc, sc;
  struct pair *p;
  gq_path np;
  int i, ok = 0, range = 0;

  /* A server that forbids active migration.  */
  memset (&cc, 0, sizeof cc);
  memset (&sc, 0, sizeof sc);
  sc.disable_active_migration = 1;
  p = pair_new_paths (&cc, &sc, 105);
  settle (p);
  np.local = p->net.L[1];
  np.remote = p->net.S;
  CHECK_EQ (gq_conn_migrate (p->cli.c, p->net.now, &np), GQ_ERR_UNAVAILABLE);
  CHECK_EQ (gq_conn_probe_path (p->cli.c, p->net.now, &np), GQ_OK);
  /* A server never migrates on its own.  */
  CHECK_EQ (gq_conn_migrate (p->srv.c, p->net.now, &np), GQ_ERR_UNAVAILABLE);
  pair_free (p);

  /* Only as many paths at once as there are fresh connection IDs.  */
  memset (&cc, 0, sizeof cc);
  p = pair_new_paths (&cc, &cc, 106);
  settle (p);
  for (i = 0; i < 6; i++)
    {
      char nm[16];

      snprintf (nm, sizeof nm, "CLI-X%d", i);
      np.local = mkaddr (nm);
      np.remote = p->net.S;
      if (gq_conn_probe_path (p->cli.c, p->net.now, &np) == GQ_OK)
        ok++;
      else
        range++;
    }
  CHECK (ok >= 1 && ok <= 3 && range >= 3);
  /* Before the handshake is confirmed there is no migrating at all.  */
  pair_free (p);
  p = pair_new_paths (&cc, &cc, 107);
  CHECK_EQ (gq_conn_probe_path (p->cli.c, p->net.now, &np), GQ_ERR_INVAL);
  pair_free (p);
}

/* ---- 0-RTT ---- */

struct saved
{
  gq_tls_session sess;
  uint8_t params[512];
  size_t params_len;
};

/* A full handshake that leaves a resumable session behind.  */
static void
get_session (const gq_conn_config *ccfg, const gq_conn_config *scfg,
             uint32_t seed, struct saved *out)
{
  struct pair *p;

  g_early_client = 0;
  g_resume = NULL;
  g_resume_params = NULL;
  p = pair_new (ccfg, scfg, 0, seed);
  exchange (p);
  run (&p->net, NULL, 1000000);
  CHECK (p->cli.have_sess);
  out->sess = p->cli.sess;
  memcpy (out->params, p->cli.params, p->cli.params_len);
  out->params_len = p->cli.params_len;
  pair_free (p);
}

/* A connection that offers early data with SAVED.  */
static struct pair *
early_pair (const gq_conn_config *ccfg, const gq_conn_config *scfg,
            unsigned loss, uint32_t seed, struct saved *sv)
{
  struct pair *p;

  g_early_client = 1;
  g_resume = &sv->sess;
  g_resume_params = sv->params;
  g_resume_params_len = sv->params_len;
  p = pair_new (ccfg, scfg, loss, seed);
  g_early_client = 0;
  g_resume = NULL;
  g_resume_params = NULL;
  return p;
}

static void
test_early_data (void)
{
  gq_conn_config cc, sc;
  struct saved sv;
  struct pair *p;
  struct sbuf *s;
  uint64_t t0;
  int i;

  CHECK_EQ (gq_ticket_keys_new (&g_ring), GQ_OK);
  CHECK_EQ (gq_replay_cache_new (&g_replay, 1000), GQ_OK);
  g_early_server = 1;
  memset (&cc, 0, sizeof cc);
  memset (&sc, 0, sizeof sc);
  cc.version = GQ_VERSION_1;
  sc.version = GQ_VERSION_1;

  /* Accepted: the request travels with the ClientHello and is answered
     within a round trip of the handshake, not after it.  */
  get_session (&cc, &sc, 120, &sv);
  p = early_pair (&cc, &sc, 0, 121, &sv);
  t0 = p->net.now;
  s = start_transfer (p, 5000);
  CHECK (run (&p->net, transfer_done, 30000000));
  CHECK_EQ (s->n, 5000);
  CHECK_EQ (p->cli.early_result, 1);
  CHECK_EQ (gq_conn_early_data_accepted (p->cli.c), 1);
  CHECK_EQ (p->srv.early_bytes, 20);
  CHECK (p->cli.info.resumed);
  CHECK (p->net.now < t0 + 35000);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  pair_free (p);

  /* A ticket buys early data once: the second use is refused, and the
     request goes out again in 1-RTT packets, once only.  */
  p = early_pair (&cc, &sc, 0, 122, &sv);
  s = start_transfer (p, 5000);
  CHECK (run (&p->net, transfer_done, 30000000));
  CHECK_EQ (s->n, 5000);
  CHECK_EQ (p->cli.early_result, -1);
  CHECK_EQ (gq_conn_early_data_accepted (p->cli.c), 0);
  CHECK_EQ (p->srv.early_bytes, 0);
  CHECK_EQ (p->srv.total_in, 20);
  pair_free (p);

  /* A server that takes no early data at all.  */
  get_session (&cc, &sc, 123, &sv);
  g_early_server = 0;
  p = early_pair (&cc, &sc, 0, 124, &sv);
  s = start_transfer (p, 5000);
  CHECK (run (&p->net, transfer_done, 30000000));
  CHECK_EQ (s->n, 5000);
  CHECK_EQ (p->cli.early_result, -1);
  CHECK_EQ (p->srv.early_bytes, 0);
  CHECK_EQ (p->srv.total_in, 20);
  pair_free (p);
  g_early_server = 1;

  /* Version 2, and loss and reordering on the way: the data arrives once,
     whatever happens to the first flight.  */
  cc.version = sc.version = GQ_VERSION_2;
  for (i = 0; i < 8; i++)
    {
      struct sbuf *x;

      get_session (&cc, &sc, 130 + (uint32_t) i, &sv);
      p = early_pair (&cc, &sc, i < 4 ? 15 : 0, 140 + (uint32_t) i, &sv);
      p->net.reorder = i >= 4;
      x = start_transfer (p, 30000);
      CHECK (run (&p->net, transfer_done, 60000000));
      CHECK_EQ (x->n, 30000);
      CHECK_EQ (p->srv.total_in, 20);
      CHECK_EQ (p->cli.bad + p->srv.bad, 0);
      CHECK_EQ (p->cli.closed + p->srv.closed, 0);
      pair_free (p);
    }
  cc.version = sc.version = GQ_VERSION_1;

  /* A datagram sent early is delivered early, once; if the early data is
     refused it is reported lost (the application decides what to do).  */
  sc.max_datagram_frame_size = 1200;
  get_session (&cc, &sc, 150, &sv);
  {
    uint8_t d[10] = { 0, 3, 0, 0, 0, 0, 0, 0, 0, 0 };
    uint64_t id;
    int k;

    for (k = 2; k < 10; k++)
      d[k] = (uint8_t) (3 * 5 + k);
    p = early_pair (&cc, &sc, 0, 151, &sv);
    CHECK_EQ (gq_conn_datagram_send (p->cli.c, d, sizeof d, &id), GQ_OK);
    run (&p->net, NULL, 500000);
    CHECK (p->srv.dg_recv == 1 && p->srv.early_dg == 1 && p->srv.dg_bad == 0);
    CHECK_EQ (p->cli.early_result, 1);
    pair_free (p);
    /* The same session again: refused (replay), so the datagram is lost.  */
    p = early_pair (&cc, &sc, 0, 152, &sv);
    CHECK_EQ (gq_conn_datagram_send (p->cli.c, d, sizeof d, &id), GQ_OK);
    run (&p->net, NULL, 500000);
    CHECK (p->srv.dg_recv == 0 && p->cli.dg_lost == 1);
    CHECK_EQ (p->cli.early_result, -1);
    pair_free (p);
  }
  sc.max_datagram_frame_size = 0;

  /* A server that promised less this time than it did before, while
     accepting early data, is in breach: the client ends the connection.  */
  get_session (&cc, &sc, 160, &sv);
  {
    gq_conn_config tight = sc;

    tight.initial_max_data = 1u << 19;
    p = early_pair (&cc, &tight, 0, 161, &sv);
    start_transfer (p, 5000);
    run (&p->net, NULL, 3000000);
    CHECK_EQ (p->cli.closed, 1);
    CHECK (p->cli.ci.error == GQ_QERR_PROTOCOL_VIOLATION);
    pair_free (p);
  }
  g_early_server = 0;
  gq_ticket_keys_free (g_ring);
  g_ring = NULL;
  gq_replay_cache_free (g_replay);
  g_replay = NULL;
}

static void
test_close (void)
{
  struct pair *p;
  gq_conn_config cfg;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new (&cfg, &cfg, 0, 5);
  CHECK (run (&p->net, both_connected, 30000000));
  gq_conn_close (p->cli.c, p->net.now, 1, 4242, "bye");
  CHECK_EQ (p->cli.closed, 1);
  CHECK (p->cli.ci.source == GQ_CLOSE_LOCAL && p->cli.ci.application);
  run (&p->net, NULL, 1000000);
  CHECK_EQ (p->srv.closed, 1);
  CHECK (p->srv.ci.source == GQ_CLOSE_PEER && p->srv.ci.application
         && p->srv.ci.error == 4242);
  CHECK (gq_conn_state (p->srv.c) >= GQ_CONN_DRAINING);
  /* The closing period ends.  */
  run (&p->net, NULL, 20000000);
  CHECK_EQ (gq_conn_state (p->cli.c), GQ_CONN_DONE);
  CHECK_EQ (gq_conn_state (p->srv.c), GQ_CONN_DONE);
  pair_free (p);
}

static void
test_idle (void)
{
  struct pair *p;
  gq_conn_config cfg;

  memset (&cfg, 0, sizeof cfg);
  cfg.idle_timeout_ms = 2000;
  p = pair_new (&cfg, &cfg, 0, 6);
  CHECK (run (&p->net, both_connected, 30000000));
  p->net.loss_pct = 100;		/* The network goes away.  */
  run (&p->net, NULL, 30000000);
  CHECK_EQ (p->cli.closed, 1);
  CHECK (p->cli.ci.source == GQ_CLOSE_IDLE);
  CHECK_EQ (p->srv.closed, 1);
  pair_free (p);
}

static void
test_streams_misc (void)
{
  struct pair *p;
  gq_conn_config cfg;
  uint64_t id, uid;
  struct sbuf *s;
  int i;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new (&cfg, &cfg, 0, 7);
  CHECK (run (&p->net, both_connected, 30000000));
  /* A unidirectional stream: id 2 from the client.  */
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 0, &uid), GQ_OK);
  CHECK_EQ (uid, 2);
  s = sb_get (&p->cli, uid);
  s->out_total = 5000;
  s->out_fin = 1;
  /* A bidirectional stream the client resets, and one the server asks
     it to stop sending on.  */
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  CHECK_EQ (id, 0);
  s = sb_get (&p->cli, id);
  gq_conn_stream_write (p->cli.c, id, (const uint8_t *) "abc", 3);
  run (&p->net, NULL, 500000);
  CHECK (p->srv.opened >= 2);
  gq_conn_stream_reset (p->cli.c, id, 77);
  run (&p->net, NULL, 500000);
  s = sb_get (&p->srv, id);
  CHECK (s->reset && s->err == 77);
  {
    struct sbuf *u = sb_get (&p->srv, uid);

    CHECK (u->fin && u->n == 5000);
  }
  /* Server-side STOP_SENDING: the client's stream 4 gets stopped.  */
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  gq_conn_stream_write (p->cli.c, id, (const uint8_t *) "x", 1);
  run (&p->net, NULL, 500000);
  CHECK_EQ (gq_conn_stream_stop_sending (p->srv.c, id, 55), GQ_OK);
  run (&p->net, NULL, 500000);
  s = sb_get (&p->cli, id);
  CHECK (s->stopped && s->err == 55);
  /* The stream limit is enforced: only 100 bidirectional streams.  */
  for (i = 0; i < 200; i++)
    if (gq_conn_stream_open (p->cli.c, 1, &id) != GQ_OK)
      break;
  CHECK (i < 200 && i > 90);
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_ERR_RANGE);
  /* A server cannot write on a client unidirectional stream.  */
  CHECK_EQ (gq_conn_stream_write (p->srv.c, uid, (const uint8_t *) "x", 1),
            GQ_ERR_INVAL);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  pair_free (p);
}

static void
test_key_update (uint32_t version)
{
  struct pair *p;
  gq_conn_config cfg;
  gq_conn_stats st;
  uint64_t id;
  int round;

  memset (&cfg, 0, sizeof cfg);
  cfg.version = version;
  p = pair_new (&cfg, &cfg, 0, 8);
  p->srv.respond = 20000;
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 1000000);
  for (round = 0; round < 4; round++)
    {
      struct sbuf *s;

      CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
      s = sb_get (&p->cli, id);
      s->out_total = 10;
      s->out_fin = 1;
      run (&p->net, NULL, 1000000);
      CHECK (s->fin && s->n == 20000);
      /* Each side updates in turn; the peer follows.  */
      CHECK_EQ (gq_conn_update_keys (p->cli.c, p->net.now), GQ_OK);
    }
  /* The server can start one too, once the last exchange settled.  */
  run (&p->net, NULL, 1000000);
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  sb_get (&p->cli, id)->out_total = 10;
  sb_get (&p->cli, id)->out_fin = 1;
  run (&p->net, NULL, 1000000);
  CHECK_EQ (gq_conn_update_keys (p->srv.c, p->net.now), GQ_OK);
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  sb_get (&p->cli, id)->out_total = 10;
  sb_get (&p->cli, id)->out_fin = 1;
  run (&p->net, NULL, 1000000);
  CHECK (sb_get (&p->cli, id)->fin);
  gq_conn_get_stats (p->cli.c, &st);
  CHECK (st.key_updates >= 5);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  pair_free (p);
}

static void
test_garbage (void)
{
  struct pair *p;
  gq_conn_config cfg;
  uint8_t junk[1300];
  size_t i;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new (&cfg, &cfg, 0, 9);
  p->net.corrupt = 3;		/* Every third datagram is damaged.  */
  for (i = 0; i < sizeof junk; i++)
    junk[i] = (uint8_t) (i * 13);
  /* Junk of every shape at the server before and during the handshake.  */
  for (i = 1; i < 1300; i += 37)
    {
      junk[0] = (uint8_t) (i & 1 ? 0xc0 : 0x40);
      gq_conn_recv (p->srv.c, p->net.now, junk, i);
    }
  run (&p->net, NULL, 60000000);
  CHECK (p->cli.connected && p->srv.connected);
  pair_free (p);
}

int
main (void)
{
  perturb_allocations ();
  gq_crypto_init ();
  fx_setup ();
  test_handshake (0, 0, 1);		/* Both speak v2 by default.  */
  test_handshake (GQ_VERSION_1, 0, 4);
  test_handshake (GQ_VERSION_2, 0, 2);
  test_handshake (0, 20, 3);
  test_flights ();
  test_lost_handshake_datagram ();
  test_mldsa_handshake ();
  test_requests (0, 11, 1, 20, 100, NULL, NULL, 0);
  test_requests (0, 12, 10, 50, 300000, NULL, NULL, 0);
  test_requests (5, 13, 8, 5000, 100000, NULL, NULL, 0);
  test_requests (20, 14, 5, 100, 60000, NULL, NULL, 1);
  {
    /* Tight flow control forces credit to be re-granted many times.  */
    gq_conn_config small;

    memset (&small, 0, sizeof small);
    small.initial_max_data = 20000;
    small.initial_max_stream_data = 6000;
    small.send_buffer = 4000;
    test_requests (10, 15, 12, 30, 90000, &small, &small, 0);
  }
  {
    int algo;

    for (algo = GQ_CC_CUBIC; algo <= GQ_CC_NEWRENO; algo++)
      {
        test_congestion (algo, 2000000, 0, 0, 0, 0, 0);
        test_congestion (algo, 2000000, 3, 0, 0, 1, 0);
        test_congestion (algo, 4000000, 0, 1000000, 3000000, 1, 1);
      }
    test_congestion (GQ_CC_DEFAULT, 2000000, 0, 0, 0, 0, 0);
    test_pacing (GQ_CC_CUBIC);
    test_qlog_handshake ();
    test_qlog_loss ();
    test_pacing (GQ_CC_NEWRENO);
  }
  test_retry (0, 0, 40);
  test_retry (GQ_VERSION_2, 0, 41);
  test_retry (0, 20, 42);
  test_tokens ();
  test_long_token ();
  test_zero_tail_is_not_a_reset ();
  test_initial_rtt ();
  test_handshake_under_bursty_loss ();
  test_retry_tamper ();
  test_admit_input ();
  test_compat ();
  test_resumption ();
  test_early_data ();
  test_datagrams ();
  test_nat_rebinding ();
  test_active_migration ();
  test_old_path_traffic ();
  test_probe ();
  test_probe_failure ();
  test_migration_failure ();
  test_migration_limits ();
  test_quiclb_routing ();
  test_quiclb_retry_routable ();
  test_version_negotiation ();
  test_downgrade ();
  test_close ();
  test_idle ();
  test_streams_misc ();
  test_key_update (0);
  test_key_update (GQ_VERSION_2);
  {
    /* Everything again on version 2, with loss and tight flow control.  */
    gq_conn_config v2;

    memset (&v2, 0, sizeof v2);
    v2.version = GQ_VERSION_2;
    v2.initial_max_data = 20000;
    v2.initial_max_stream_data = 6000;
    v2.send_buffer = 4000;
    test_requests (10, 80, 12, 30, 90000, &v2, &v2, 1);
    test_requests (0, 81, 4, 50, 300000, &v2, &v2, 0);
  }
  test_garbage ();
  if (getenv ("QLOG_STATS"))
    {
      size_t i;

      fprintf (stderr, "%lu qlog events checked\n", g_qlog_events);
      for (i = 0; qc_events[i]; i++)
        fprintf (stderr, "  %-36s %lu\n", qc_events[i], g_qlog_seen[i]);
    }
  CHECK (g_qlog_events > 100000);
  TST_DONE ();
}

#endif
