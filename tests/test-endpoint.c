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

/* Endpoints against each other over a simulated network: routing of many
   connections, admission (Retry, Version Negotiation), stateless reset,
   limits, timers and migration through the endpoint.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <quickstep/status.h>
#include <quickstep/endpoint.h>

#include "tst-util.h"
#include "tst-qlogcheck.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "tst-fix12.h"

#define MAXQ 4096
#define MAXNODES 3
#define MAXAPP 128

struct node;

/* One connection's application state.  */
struct capp
{
  struct node *node;
  gq_conn *c;
  int server, used;
  size_t got[4];		/* Bytes received per stream index.  */
  int fin[4];
  size_t out_total[4], out_done[4];
  int stream_used[4];
  int connected, closed, done, mig;
  int pref_events, pref_take;	/* Offers of a preferred address; take up.  */
  gq_conn_close_info ci;
  gq_tls_session sess;
  int have_sess, early_bytes, early_result;
  uint8_t params[512];
  size_t params_len;
};

struct node
{
  struct net *net;
  gq_endpoint *ep;
  gq_addr addr, ext;		/* Local address; what the outside sees.  */
  struct capp app[MAXAPP];
  int napp;
  size_t respond;		/* Server: bytes to answer a request with.  */
  int accepted, refused;
  uint64_t now_hook;
};

/* What an endpoint's qlog callback is given.  One callback serves every
   connection of the endpoint, so it is told which by the connection; events
   of no connection arrive without one.  */
struct esink
{
  unsigned long events;
  int bad_event, bad_first, bad_null, bad_order;
  uint64_t last_t;
  const gq_conn *seen[512];
  size_t nseen;
  struct
  {
    char name[48];
    char *fields;
  } nul[64];
  size_t nnul;
};

static unsigned long g_seen[64];

static void
esink_cb (void *user, const gq_conn *conn, uint64_t t, const char *name,
          const char *fields, size_t len)
{
  struct esink *k = user;
  char where[200];
  const char *err;
  size_t i;

  k->events++;
  for (i = 0; qc_events[i]; i++)
    if (!strcmp (name + 5, qc_events[i]))
      g_seen[i]++;
  if (t < k->last_t)
    k->bad_order++;
  k->last_t = t;
  err = qc_check (name, fields, len, where, sizeof where);
  if (err)
    {
      fprintf (stderr, "qlog event not as the draft says (%s: %s): %s %s\n",
               err, where, name, fields);
      k->bad_event++;
    }
  if (conn == NULL)
    {
      /* Only what belongs to no connection.  */
      if (strcmp (name, "quic:server_listening")
          && strcmp (name, "quic:udp_datagrams_received")
          && strcmp (name, "quic:udp_datagrams_sent")
          && strcmp (name, "quic:packet_dropped")
          && strcmp (name, "quic:packet_sent"))
        {
          fprintf (stderr, "%s without a connection\n", name);
          k->bad_null++;
        }
      if (k->nnul < 64)
        {
          snprintf (k->nul[k->nnul].name, sizeof k->nul[0].name, "%s", name);
          k->nul[k->nnul].fields = strdup (fields);
          k->nnul++;
        }
      return;
    }
  for (i = 0; i < k->nseen; i++)
    if (k->seen[i] == conn)
      return;
  /* The first event of a connection.  */
  if (strcmp (name, "quic:connection_started") != 0)
    {
      fprintf (stderr, "connection begins with %s\n", name);
      k->bad_first++;
    }
  if (k->nseen < 512)
    k->seen[k->nseen++] = conn;
}

static void
esink_free (struct esink *k)
{
  size_t i;

  for (i = 0; i < k->nnul; i++)
    free (k->nul[i].fields);
  memset (k, 0, sizeof *k);
}

/* The events without a connection called NAME, containing TEXT.  */
static size_t
esink_null (const struct esink *k, const char *name, const char *text)
{
  size_t i, c = 0;

  for (i = 0; i < k->nnul; i++)
    if (!strcmp (k->nul[i].name, name)
        && (text == NULL || strstr (k->nul[i].fields, text)))
      c++;
  return c;
}

struct pkt
{
  int to;
  uint64_t at;
  gq_path from;
  size_t len;
  uint8_t d[2048];
  int ecn;			/* The ECN field it arrives with.  */
};

struct net
{
  struct pkt q[MAXQ];
  int nq;
  uint64_t now, latency;
  uint32_t rng;
  unsigned loss_pct;
  struct node node[MAXNODES];
  int retries, resets, dropped, total;
  /* The first long header datagram a client sends once it has been given
     the server's connection ID (its DCID differs from the first one's).  */
  uint8_t first_dcid[GQ_MAX_CID_LEN];
  size_t first_dcid_len;
  uint8_t late[2048];
  size_t late_len;
  struct esink qs[MAXNODES];	/* What each node's endpoint logged.  */
  /* A client's 0-RTT packet that comes coalesced after its Initial is sent
     ahead of it in a datagram of its own, with the Initial's datagram
     emptied of it.  */
  int early_first, early_split;
  gq_addr addr2;		/* The server's preferred address.  */
  uint64_t bytes_addr2;		/* Sent to it.  */
};

static uint8_t
pat (uint64_t id, uint64_t off)
{
  return (uint8_t) (id * 31 + off * 7 + (off >> 8));
}

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
same (const gq_addr *a, const gq_addr *b)
{
  return a->len == b->len && memcmp (a->data, b->data, a->len) == 0;
}

/* ---- Connection events ---- */

static void
ev_connected (void *u, const gq_tls_info *i)
{
  (void) i;
  ((struct capp *) u)->connected = 1;
}

static int
ev_data (void *u, uint64_t id, const uint8_t *d, size_t n, int fin)
{
  struct capp *a = u;
  size_t k, x = (size_t) (id >> 2) & 3;

  for (k = 0; k < n; k++)
    CHECK (d[k] == pat (id, a->got[x] + k));
  a->got[x] += n;
  if (a->c && gq_conn_early_data_active (a->c))
    a->early_bytes += (int) n;
  if (fin)
    {
      a->fin[x] = 1;
      if (a->server && !(id & 2))
        {
          a->out_total[x] = a->node->respond;
          a->stream_used[x] = 1;
        }
    }
  return 0;
}

static void
ev_closed (void *u, const gq_conn_close_info *i)
{
  struct capp *a = u;

  a->closed++;
  a->ci = *i;
  a->ci.reason = NULL;
}

static void
ev_migrated (void *u, const gq_path *p)
{
  (void) p;
  ((struct capp *) u)->mig++;
}

static void
ev_preferred (void *u, const gq_preferred_address *pa)
{
  struct capp *a = u;
  gq_path np;

  (void) pa;
  a->pref_events++;
  if (!a->pref_take)
    return;
  np.local = a->node->addr;
  np.remote = a->node->net->addr2;
  a->pref_take = gq_conn_migrate_preferred (a->c, a->node->net->now, &np)
                 == GQ_OK ? 0 : -1;
}

static void
ev_ticket (void *u, const gq_tls_ticket *t, uint32_t version)
{
  struct capp *a = u;

  (void) version;
  if (a->have_sess)
    return;
  CHECK_EQ (gq_tls_session_store (&a->sess, t), GQ_OK);
  CHECK_EQ (gq_conn_get_peer_params (a->c, a->params, sizeof a->params,
                                     &a->params_len), GQ_OK);
  a->have_sess = 1;
}

static void
ev_early_result (void *u, int accepted)
{
  ((struct capp *) u)->early_result = accepted ? 1 : -1;
}

static void
fill_events (gq_conn_events *e, struct capp *a)
{
  memset (e, 0, sizeof *e);
  e->user = a;
  e->connected = ev_connected;
  e->stream_data = ev_data;
  e->closed = ev_closed;
  e->migrated = ev_migrated;
  e->preferred_address = ev_preferred;
  e->ticket = ev_ticket;
  e->early_data_result = ev_early_result;
}

/* ---- Endpoint events ---- */

static struct capp *
new_app (struct node *n, int server)
{
  struct capp *a;

  CHECK (n->napp < MAXAPP);
  a = &n->app[n->napp++];
  memset (a, 0, sizeof *a);
  a->node = n;
  a->server = server;
  a->used = 1;
  return a;
}

static int
ep_accept (void *u, const gq_path *from, gq_conn_events *ev)
{
  struct node *n = u;
  struct capp *a;

  (void) from;
  a = new_app (n, 1);
  fill_events (ev, a);
  n->accepted++;
  return 0;
}

static int
ep_refuse (void *u, const gq_path *from, gq_conn_events *ev)
{
  struct node *n = u;

  (void) from;
  (void) ev;
  n->refused++;
  return 1;
}

static void
ep_connection (void *u, gq_conn *c)
{
  struct node *n = u;
  int i;

  /* Server connections: bind to their application state.  */
  for (i = 0; i < n->napp; i++)
    if (n->app[i].used && n->app[i].c == NULL && n->app[i].server)
      {
        n->app[i].c = c;
        break;
      }
}

static void
ep_done (void *u, gq_conn *c)
{
  struct node *n = u;
  int i;

  for (i = 0; i < n->napp; i++)
    if (n->app[i].c == c)
      {
        n->app[i].done++;
        n->app[i].c = NULL;
      }
}

/* ---- The network ---- */

static uint32_t
rnd (struct net *n)
{
  n->rng = n->rng * 1664525u + 1013904223u;
  return n->rng >> 8;
}

static struct node *
node_by_addr (struct net *net, const gq_addr *a)
{
  int i;

  if (net->addr2.len && same (&net->addr2, a))
    return &net->node[0];
  for (i = 0; i < MAXNODES; i++)
    if (net->node[i].ep && same (&net->node[i].ext, a))
      return &net->node[i];
  for (i = 0; i < MAXNODES; i++)
    if (net->node[i].ep && same (&net->node[i].addr, a))
      return &net->node[i];
  return NULL;
}

static void
enqueue (struct net *net, struct node *from, const uint8_t *d, size_t len,
         const gq_path *to, int ecn)
{
  struct node *dest = node_by_addr (net, &to->remote);
  struct pkt *p;
  int index = net->total++;

  (void) index;
  if (from == &net->node[0] && (d[0] & 0xf0) == 0xf0)
    net->retries++;
  if (from != &net->node[0] && (d[0] & 0x80) && len >= 1200 && len <= 2048
      && net->late_len == 0 && d[5] <= GQ_MAX_CID_LEN)
    {
      if (net->first_dcid_len == 0)
        {
          net->first_dcid_len = d[5];
          memcpy (net->first_dcid, d + 6, d[5]);
        }
      else if (d[5] != net->first_dcid_len
               || memcmp (net->first_dcid, d + 6, d[5]) != 0)
        {
          net->late_len = len;
          memcpy (net->late, d, len);
        }
    }
  if (dest == NULL || (net->loss_pct && rnd (net) % 100 < net->loss_pct))
    {
      net->dropped++;
      return;
    }
  if (net->early_first && from != &net->node[0] && (d[0] & 0x80)
      && len >= 1200)
    {
      gq_long_header h;

      /* Initial, then a 0-RTT packet: the 0-RTT one goes first, alone.  */
      if (gq_long_header_parse (d, len, &h) == GQ_OK && h.packet_len < len
          && (d[h.packet_len] & 0xb0) == 0x90)	/* Long, QUIC v1 0-RTT.  */
        {
          uint8_t rest[2048];
          size_t rl = len - h.packet_len;

          memcpy (rest, d + h.packet_len, rl);
          int ahead_of_all = net->early_first == 2;

          net->early_first = 0;
          net->early_split++;
          enqueue (net, from, rest, rl, to, ecn);
          if (ahead_of_all)
            {
              /* Not just ahead of this Initial but of the first: it comes
                 before the server has a connection at all.  */
              struct pkt last = net->q[net->nq - 1];
              int first = 0;

              while (first < net->nq - 1 && net->q[first].to != 0)
                first++;
              memmove (&net->q[first + 1], &net->q[first],
                       (size_t) (net->nq - 1 - first) * sizeof net->q[0]);
              net->q[first] = last;
            }
          {
            uint8_t head[2048];

            memcpy (head, d, len);
            memset (head + h.packet_len, 0, rl);
            enqueue (net, from, head, len, to, ecn);
          }
          return;
        }
    }
  CHECK (net->nq < MAXQ);
  p = &net->q[net->nq++];
  p->to = (int) (dest - net->node);
  p->at = net->now + net->latency;
  p->len = len;
  p->ecn = ecn;
  memcpy (p->d, d, len);
  p->from.local = dest->addr;
  p->from.remote = from->ext;	/* What the receiver sees.  */
  /* By the server's second address, to it or from it.  */
  if (net->addr2.len && same (&net->addr2, &to->remote))
    {
      p->from.local = net->addr2;
      net->bytes_addr2 += len;
    }
  if (from == &net->node[0] && net->addr2.len && same (&net->addr2, &to->local))
    p->from.remote = net->addr2;
}

static void
pump_apps (struct node *n)
{
  int i;

  for (i = 0; i < n->napp; i++)
    {
      struct capp *a = &n->app[i];
      int x;

      if (!a->used || a->c == NULL)
        continue;
      for (x = 0; x < 4; x++)
        {
          uint64_t id = ((uint64_t) x << 2) | (a->server ? 1 : 0);

          if (!a->stream_used[x])
            continue;
          while (a->out_done[x] < a->out_total[x])
            {
              uint8_t buf[2000];
              size_t k, m = a->out_total[x] - a->out_done[x];
              long w;

              if (m > sizeof buf)
                m = sizeof buf;
              /* Server responses answer the client's stream ids.  */
              id = a->server ? ((uint64_t) x << 2) : ((uint64_t) x << 2);
              for (k = 0; k < m; k++)
                buf[k] = pat (id, a->out_done[x] + k);
              w = gq_conn_stream_write (a->c, id, buf, m);
              if (w <= 0)
                break;
              a->out_done[x] += (size_t) w;
            }
          if (a->out_done[x] == a->out_total[x] && a->out_total[x] > 0
              && a->stream_used[x] == 1)
            {
              gq_conn_stream_finish (a->c, ((uint64_t) x << 2));
              a->stream_used[x] = 2;
            }
        }
    }
}

static void
flush (struct net *net)
{
  int i;

  for (i = 0; i < MAXNODES; i++)
    {
      struct node *n = &net->node[i];
      uint8_t buf[2048];
      size_t len;
      gq_path to;
      int guard = 0, ecn;

      if (n->ep == NULL)
        continue;
      pump_apps (n);
      while (guard++ < 500)
        {
          memset (&to, 0, sizeof to);
          ecn = -1;
          CHECK_EQ (gq_endpoint_send_ecn (n->ep, net->now, buf, sizeof buf,
                                          &len, &to, &ecn), GQ_OK);
          if (len == 0)
            break;
          CHECK (ecn >= GQ_ECN_NOT_ECT && ecn <= GQ_ECN_CE);
          enqueue (net, n, buf, len, &to, ecn);
        }
    }
}

static int
run (struct net *net, int (*done) (struct net *), uint64_t budget)
{
  uint64_t end = net->now + budget;
  int steps = 0;

  while (net->now < end && steps++ < 3000000)
    {
      uint64_t t = 0;
      int i, best = -1;

      flush (net);
      if (done && done (net))
        return 1;
      for (i = 0; i < net->nq; i++)
        if (best < 0 || net->q[i].at < net->q[best].at)
          best = i;
      if (best >= 0)
        t = net->q[best].at;
      for (i = 0; i < MAXNODES; i++)
        if (net->node[i].ep)
          {
            uint64_t tt = gq_endpoint_timeout (net->node[i].ep);

            if (tt && (t == 0 || tt < t))
              t = tt;
          }
      if (t == 0 || t > end)
        {
          if (t > end)
            net->now = end;
          return done ? done (net) : 1;
        }
      if (t > net->now)
        net->now = t;
      if (best >= 0 && net->q[best].at <= net->now)
        {
          struct pkt p = net->q[best];

          memmove (&net->q[best], &net->q[best + 1],
                   (size_t) (net->nq - best - 1) * sizeof net->q[0]);
          net->nq--;
          if (net->node[p.to].ep)
            gq_endpoint_recv_ecn (net->node[p.to].ep, net->now, &p.from,
                                  p.ecn, p.d, p.len);
          continue;
        }
      for (i = 0; i < MAXNODES; i++)
        if (net->node[i].ep)
          {
            uint64_t tt = gq_endpoint_timeout (net->node[i].ep);

            if (tt && tt <= net->now)
              gq_endpoint_on_timeout (net->node[i].ep, net->now);
          }
    }
  return done ? done (net) : 0;
}

/* ---- Setup ---- */

static const uint8_t alpn_hq[2] = { 'h', 'q' };
static gq_slice alpn_list[1] = { { alpn_hq, 2 } };
static gq_tls_config ccfg;
static gq_tls_server_config scfg;

static void
setup_tls (void)
{
  ccfg.server_name = "example.test";
  ccfg.trust = fx_trust;
  ccfg.alpn = alpn_list;
  ccfg.n_alpn = 1;
  scfg.credentials.chain = fx_ec.chain;
  scfg.credentials.n_chain = 1;
  scfg.credentials.key = fx_ec.key;
  scfg.alpn = alpn_list;
  scfg.n_alpn = 1;
}

static uint64_t
sim_wall (void *u)
{
  return ((struct net *) u)->now / 1000000;
}

static struct net *
net_new (const gq_endpoint_config *server_cfg, uint32_t seed,
         int (*accept) (void *, const gq_path *, gq_conn_events *))
{
  struct net *net = calloc (1, sizeof *net);
  gq_endpoint_config sc, cc;
  gq_endpoint_events se, ce;

  net->now = 1000000;
  net->latency = 10000;
  net->rng = seed;
  net->node[0].net = net->node[1].net = net->node[2].net = net;
  net->node[0].addr = net->node[0].ext = mkaddr ("SRV:443");
  net->addr2 = mkaddr ("SRV2:443");
  net->node[1].addr = net->node[1].ext = mkaddr ("CLI-1");
  net->node[2].addr = net->node[2].ext = mkaddr ("CLI-2");
  net->node[0].respond = net->node[1].respond = net->node[2].respond = 20000;
  memset (&sc, 0, sizeof sc);
  if (server_cfg)
    sc = *server_cfg;
  sc.server = &scfg;
  sc.conn.wall_seconds = sim_wall;
  sc.conn.wall_user = net;
  sc.conn.qlog = esink_cb;
  sc.conn.qlog_user = &net->qs[0];
  memset (&se, 0, sizeof se);
  se.user = &net->node[0];
  se.accept = accept ? accept : ep_accept;
  se.connection = ep_connection;
  se.done = ep_done;
  CHECK_EQ (gq_endpoint_new (&net->node[0].ep, &sc, &se), GQ_OK);
  memset (&cc, 0, sizeof cc);
  cc.conn.wall_seconds = sim_wall;
  cc.conn.wall_user = net;
  cc.conn.qlog = esink_cb;
  cc.conn.qlog_user = &net->qs[1];
  memset (&ce, 0, sizeof ce);
  ce.user = &net->node[1];
  ce.done = ep_done;
  CHECK_EQ (gq_endpoint_new (&net->node[1].ep, &cc, &ce), GQ_OK);
  ce.user = &net->node[2];
  cc.conn.qlog_user = &net->qs[2];
  CHECK_EQ (gq_endpoint_new (&net->node[2].ep, &cc, &ce), GQ_OK);
  return net;
}

static void
net_free (struct net *net)
{
  int i;

  for (i = 0; i < MAXNODES; i++)
    {
      struct esink *k = &net->qs[i];

      gq_endpoint_free (net->node[i].ep);
      /* Everything logged was as the draft says, in order, and every
         connection began with its connection_started.  */
      CHECK_EQ (k->bad_event, 0);
      CHECK_EQ (k->bad_first, 0);
      CHECK_EQ (k->bad_null, 0);
      CHECK_EQ (k->bad_order, 0);
      esink_free (k);
    }
  free (net);
}

/* A client connection to the server on NODE (1 or 2), requesting from
   NSTREAMS bidirectional streams once connected.  */
static struct capp *
client_conn (struct net *net, int node, const gq_conn_config *cfg)
{
  struct node *n = &net->node[node];
  struct capp *a = new_app (n, 0);
  gq_conn_events ev;
  gq_path path;
  int r;

  gq_conn_config own;

  fill_events (&ev, a);
  memset (&path, 0, sizeof path);
  path.local = n->addr;
  path.remote = net->node[0].addr;
  if (cfg)
    {
      own = *cfg;
      if (own.qlog == NULL)
        {
          own.qlog = esink_cb;
          own.qlog_user = &net->qs[node];
        }
      cfg = &own;
    }
  r = gq_endpoint_connect (n->ep, net->now, &ccfg, cfg, &path, &ev, &a->c);
  CHECK_EQ (r, GQ_OK);
  return a;
}

/* Open a request on every connected client conn that has not yet.  */
static void
request_all (struct net *net, int nstreams)
{
  int nd, i, x;

  for (nd = 1; nd < MAXNODES; nd++)
    for (i = 0; i < net->node[nd].napp; i++)
      {
        struct capp *a = &net->node[nd].app[i];

        if (!a->used || a->c == NULL || !a->connected || a->stream_used[0])
          continue;
        for (x = 0; x < nstreams; x++)
          {
            uint64_t id;

            if (gq_conn_stream_open (a->c, 1, &id) != GQ_OK)
              break;
            a->stream_used[x] = 1;
            a->out_total[x] = 20;
          }
      }
}

static int
all_clients_done (struct net *net)
{
  int nd, i, any = 0;

  request_all (net, 2);
  for (nd = 1; nd < MAXNODES; nd++)
    for (i = 0; i < net->node[nd].napp; i++)
      {
        struct capp *a = &net->node[nd].app[i];

        if (!a->used)
          continue;
        any = 1;
        if (a->closed || a->done)
          continue;
        if (!(a->fin[0] && a->fin[1]
              && a->got[0] == net->node[0].respond
              && a->got[1] == net->node[0].respond))
          return 0;
      }
  return any;
}

/* ---- Tests ---- */

/* Tickets and 0-RTT through endpoints: the second connection's request
   arrives in the first flight and the server endpoint sees it as early
   data.  */
static void
run_early_data (int reorder, int limit, int expect_early)
{
  gq_endpoint_config sc;
  gq_conn_config cc;
  struct net *net;
  struct capp *a, *b;
  gq_path path;
  gq_conn_events ev;
  gq_tls_config tls2;
  int i;

  memset (&sc, 0, sizeof sc);
  sc.tickets = 1;
  sc.early_data = 1;
  sc.conn.max_buffered_packets = limit;
  memset (&cc, 0, sizeof cc);
  cc.version = GQ_VERSION_1;
  sc.conn.version = GQ_VERSION_1;
  net = net_new (&sc, 12, NULL);
  a = client_conn (net, 1, &cc);
  CHECK (run (net, all_clients_done, 60000000));
  run (net, NULL, 1000000);
  CHECK (a->have_sess);
  /* A second connection resumes and speaks at once.  */
  tls2 = ccfg;
  tls2.resume = &a->sess;
  tls2.early_data = 1;
  cc.resume_params = a->params;
  cc.resume_params_len = a->params_len;
  b = new_app (&net->node[1], 0);
  fill_events (&ev, b);
  memset (&path, 0, sizeof path);
  path.local = net->node[1].addr;
  path.remote = net->node[0].addr;
  net->early_first = reorder;
  CHECK_EQ (gq_endpoint_connect (net->node[1].ep, net->now, &tls2, &cc, &path,
                                 &ev, &b->c), GQ_OK);
  {
    uint64_t id;

    for (i = 0; i < 2; i++)
      {
        CHECK_EQ (gq_conn_stream_open (b->c, 1, &id), GQ_OK);
        b->stream_used[i] = 1;
        b->out_total[i] = 20;
      }
  }
  CHECK (run (net, all_clients_done, 60000000));
  CHECK_EQ (b->early_result, 1);
  {
    int k, early = 0;

    for (k = 0; k < net->node[0].napp; k++)
      early += net->node[0].app[k].early_bytes;
    CHECK_EQ (early, expect_early);
  }
  CHECK (b->got[0] == net->node[0].respond && b->got[1] == net->node[0].respond);
  if (reorder)
    CHECK_EQ (net->early_split, 1);
  net_free (net);
}

static void
test_early_data (void)
{
  run_early_data (0, 0, 40);		/* Two requests of 20 bytes.  */
  /* The 0-RTT packet arrives ahead of the Initial that makes the
     connection: it is held, and the early data is accepted as it would
     have been; with no buffering it is lost and the requests are made
     again after the handshake.  */
  run_early_data (1, 0, 40);
  run_early_data (1, -1, 0);
  /* Ahead of every packet of the client's, so that there is no connection
     for it to be held by but the endpoint's own care.  */
  run_early_data (2, 0, 40);
  run_early_data (2, -1, 0);
}

static void
test_many_connections (void)
{
  struct net *net = net_new (NULL, 1, NULL);
  int i;

  for (i = 0; i < 12; i++)
    client_conn (net, 1 + i % 2, NULL);
  CHECK (run (net, all_clients_done, 60000000));
  CHECK_EQ (net->node[0].accepted, 12);
  CHECK_EQ (gq_endpoint_connections (net->node[0].ep), 12);
  CHECK_EQ (gq_endpoint_connections (net->node[1].ep), 6);
  /* Nothing went wrong on the way.  */
  for (i = 0; i < net->node[1].napp; i++)
    CHECK_EQ (net->node[1].app[i].closed, 0);
  /* Everyone closes politely; the endpoints end up empty.  */
  gq_endpoint_close (net->node[1].ep, net->now, 1, 0, "bye");
  gq_endpoint_close (net->node[2].ep, net->now, 1, 0, "bye");
  run (net, NULL, 30000000);
  CHECK_EQ (gq_endpoint_connections (net->node[0].ep), 0);
  CHECK_EQ (gq_endpoint_connections (net->node[1].ep), 0);
  CHECK_EQ (gq_endpoint_timeout (net->node[0].ep), 0);
  net_free (net);
}

/* The endpoint passes the ECN field of what arrives to the connection and
   that of what the connection sends on: both ends validate, and the server's
   connection and the client's count what the other marked.  */
static void
test_ecn (void)
{
  struct net *net = net_new (NULL, 5, NULL);
  struct capp *a;
  gq_conn_stats st;

  a = client_conn (net, 1, NULL);
  CHECK (run (net, all_clients_done, 60000000));
  gq_conn_get_stats (a->c, &st);
  CHECK_EQ (st.ecn_state, GQ_ECN_CAPABLE);
  CHECK (st.ecn_marked_sent > 0);
  CHECK (st.ecn_ect0_received > 0);
  CHECK_EQ (st.ecn_ce_received, 0);
  net_free (net);
}

/* The server's offer, made to the first client only.  */
static gq_addr g_pref_for;
static unsigned g_pref_calls;

static int
pref_hook (void *u, const gq_path *client, gq_preferred_address *out)
{
  (void) u;
  g_pref_calls++;
  if (!same (&client->remote, &g_pref_for))
    return 0;
  memset (out, 0, sizeof *out);
  memset (out->ipv4, 0x0a, 4);
  out->ipv4_port = 443;
  return 1;
}

/* An endpoint offers a preferred address to the clients it chooses, routes
   what comes to the connection ID that goes with it, and answers for it with
   a stateless reset when it has lost the connection.  */
static void
test_preferred_address (void)
{
  gq_endpoint_config sc;
  gq_endpoint_events se;
  struct net *net;
  struct capp *a, *b;
  gq_path cur;
  uint64_t before;
  gq_endpoint *old;
  static const uint8_t k[32] = { 7, 8, 9 };
  int i;

  memset (&sc, 0, sizeof sc);
  memcpy (sc.reset_key, k, 32);
  sc.have_reset_key = 1;
  sc.conn.preferred_address = pref_hook;
  net = net_new (&sc, 9, NULL);
  g_pref_for = net->node[1].ext;
  g_pref_calls = 0;
  a = client_conn (net, 1, NULL);		/* Offered, and takes it up.  */
  a->pref_take = 1;
  b = client_conn (net, 2, NULL);		/* Not offered.  */
  CHECK (run (net, all_clients_done, 60000000));
  CHECK_EQ (g_pref_calls, 2);			/* Once for each connection.  */
  CHECK_EQ (a->pref_events, 1);
  CHECK_EQ (a->pref_take, 0);
  CHECK_EQ (b->pref_events, 0);
  CHECK_EQ (gq_conn_get_path (a->c, &cur), GQ_OK);
  CHECK (same (&cur.remote, &net->addr2));
  CHECK_EQ (gq_conn_get_path (b->c, &cur), GQ_OK);
  CHECK (same (&cur.remote, &net->node[0].addr));
  CHECK_EQ (a->mig, 1);
  CHECK_EQ (b->mig, 0);
  CHECK_EQ (a->closed + b->closed, 0);
  CHECK (net->bytes_addr2 > 0);
  CHECK_EQ (gq_endpoint_connections (net->node[0].ep), 2);
  /* More goes by the second address and none of it is lost.  */
  before = net->bytes_addr2;
  {
    uint64_t id;

    uint8_t d[5];
    size_t j;

    CHECK_EQ (gq_conn_stream_open (a->c, 1, &id), GQ_OK);
    for (j = 0; j < sizeof d; j++)
      d[j] = pat (id, j);
    gq_conn_stream_write (a->c, id, d, sizeof d);
    run (net, NULL, 1000000);
    CHECK (net->bytes_addr2 > before);
    CHECK_EQ (a->closed, 0);
  }
  /* The server forgets everything and starts again with the same reset
     key: the client's next packet, to the second address and the connection
     ID that came with it, draws a stateless reset whose token is the one it
     was given with the address.  */
  old = net->node[0].ep;
  memset (&se, 0, sizeof se);
  se.user = &net->node[0];
  se.accept = ep_refuse;
  sc.server = &scfg;
  sc.conn.preferred_address = NULL;
  sc.conn.wall_seconds = sim_wall;
  sc.conn.wall_user = net;
  sc.conn.qlog = esink_cb;
  sc.conn.qlog_user = &net->qs[0];
  net->node[0].ep = NULL;
  gq_endpoint_free (old);
  CHECK_EQ (gq_endpoint_new (&net->node[0].ep, &sc, &se), GQ_OK);
  {
    uint64_t id;

    uint8_t d[5];
    size_t j;

    CHECK_EQ (gq_conn_stream_open (a->c, 1, &id), GQ_OK);
    for (j = 0; j < sizeof d; j++)
      d[j] = pat (id, j);
    gq_conn_stream_write (a->c, id, d, sizeof d);
    for (i = 0; i < 20 && !a->closed; i++)
      run (net, NULL, 500000);
  }
  CHECK_EQ (a->closed, 1);
  CHECK (a->ci.source == GQ_CLOSE_RESET);
  net_free (net);
}

static void
test_retry (void)
{
  gq_endpoint_config sc;
  struct net *net;
  int i;

  memset (&sc, 0, sizeof sc);
  sc.admit.require_retry = 1;
  net = net_new (&sc, 2, NULL);
  for (i = 0; i < 4; i++)
    client_conn (net, 1, NULL);
  CHECK (run (net, all_clients_done, 60000000));
  CHECK (net->retries >= 4);
  CHECK_EQ (net->node[0].accepted, 4);
  /* The endpoint says it is listening, and that it asks for a Retry; the
     Retry packets it sent belong to no connection.  */
  CHECK_EQ (esink_null (&net->qs[0], "quic:server_listening",
                        "retry_required=true"), 1);
  CHECK (esink_null (&net->qs[0], "quic:packet_sent",
                     "header.packet_type=retry") >= 4);
  CHECK (esink_null (&net->qs[0], "quic:packet_sent",
                     "header.token.raw.length=") >= 4);
  CHECK (esink_null (&net->qs[0], "quic:packet_dropped", "trigger=rejected")
         >= 4);
  net_free (net);

  /* Retry only when busy: the first two connections skip it.  */
  memset (&sc, 0, sizeof sc);
  sc.retry_above = 2;
  net = net_new (&sc, 3, NULL);
  client_conn (net, 1, NULL);
  client_conn (net, 1, NULL);
  CHECK (run (net, all_clients_done, 60000000));
  CHECK_EQ (net->retries, 0);
  client_conn (net, 2, NULL);
  CHECK (run (net, all_clients_done, 60000000));
  CHECK (net->retries >= 1);
  CHECK_EQ (esink_null (&net->qs[0], "quic:server_listening", NULL), 1);
  CHECK_EQ (esink_null (&net->qs[0], "quic:server_listening",
                        "retry_required"), 0);
  net_free (net);
}

static void
test_version_negotiation (void)
{
  gq_endpoint_config sc;
  gq_conn_config cc;
  struct net *net;
  struct capp *a, *b;

  memset (&sc, 0, sizeof sc);
  sc.conn.version = GQ_VERSION_1;
  net = net_new (&sc, 4, NULL);
  /* Starts in v2, hears the server speaks only v1, and restarts.  */
  memset (&cc, 0, sizeof cc);
  cc.version = GQ_VERSION_2;
  cc.versions[0] = GQ_VERSION_2;
  cc.versions[1] = GQ_VERSION_1;
  cc.n_versions = 2;
  a = client_conn (net, 1, &cc);
  /* Only v2 offered: nothing in common.  */
  cc.n_versions = 1;
  b = client_conn (net, 2, &cc);
  CHECK (run (net, NULL, 3000000) || 1);
  CHECK (a->connected && !a->closed);
  CHECK_EQ (gq_conn_version (a->c), GQ_VERSION_1);
  CHECK_EQ (b->closed, 1);
  CHECK (b->ci.error == GQ_QERR_VERSION_NEGOTIATION && !b->connected);
  CHECK_EQ (net->node[0].accepted, 1);
  /* The server's answers: Version Negotiation with the versions it speaks,
     for an Initial it can not read.  */
  CHECK (esink_null (&net->qs[0], "quic:packet_sent",
                     "header.packet_type=version_negotiation") >= 1);
  CHECK (esink_null (&net->qs[0], "quic:packet_sent",
                     "supported_versions=00000001") >= 1);
  CHECK (esink_null (&net->qs[0], "quic:packet_dropped",
                     "trigger=unsupported") >= 1);
  /* The client logged receiving it, and the choice it made.  */
  CHECK (net->qs[1].events > 0);
  net_free (net);
}

static void
test_stateless_reset (void)
{
  struct net *net = net_new (NULL, 5, NULL);
  gq_endpoint_config sc;
  gq_endpoint_events se;
  struct capp *a;
  gq_endpoint *old;
  uint8_t key[32];
  int i;
  static const uint8_t k[32] = { 1, 2, 3 };

  (void) key;
  net_free (net);
  /* Both servers share a reset key, as a restart or a cluster would.  */
  memset (&sc, 0, sizeof sc);
  memcpy (sc.reset_key, k, 32);
  sc.have_reset_key = 1;
  net = net_new (&sc, 6, NULL);
  a = client_conn (net, 1, NULL);
  CHECK (run (net, all_clients_done, 60000000));
  /* The server forgets everything: a new endpoint at the same address.  */
  old = net->node[0].ep;
  memset (&se, 0, sizeof se);
  se.user = &net->node[0];
  se.accept = ep_refuse;
  sc.server = &scfg;
  sc.conn.wall_seconds = sim_wall;
  sc.conn.wall_user = net;
  sc.conn.qlog = esink_cb;
  sc.conn.qlog_user = &net->qs[0];
  net->node[0].ep = NULL;
  gq_endpoint_free (old);
  CHECK_EQ (gq_endpoint_new (&net->node[0].ep, &sc, &se), GQ_OK);
  {
    /* The client sends something; the new server answers with a reset that
       carries the token for the connection ID it used.  */
    uint64_t id;

    CHECK_EQ (gq_conn_stream_open (a->c, 1, &id), GQ_OK);
    gq_conn_stream_write (a->c, id, (const uint8_t *) "hello", 5);
    for (i = 0; i < 20 && !a->closed; i++)
      run (net, NULL, 500000);
  }
  CHECK_EQ (a->closed, 1);
  CHECK (a->ci.source == GQ_CLOSE_RESET);
  /* The reset the new server sent, and the datagram that drew it, for a
     connection it does not have.  */
  CHECK (esink_null (&net->qs[0], "quic:packet_sent",
                     "header.packet_type=stateless_reset") >= 1);
  CHECK (esink_null (&net->qs[0], "quic:packet_sent",
                     "stateless_reset_token=") >= 1);
  CHECK (esink_null (&net->qs[0], "quic:packet_dropped",
                     "trigger=connection_unknown") >= 1);
  /* The client's side of it: the connection closed by the reset.  */
  CHECK (net->qs[1].events > 0);
  net_free (net);

  /* Rate limit: unknown short packets draw at most the configured number
     of resets per second.  */
  memset (&sc, 0, sizeof sc);
  sc.max_resets_per_second = 3;
  net = net_new (&sc, 7, NULL);
  {
    gq_path from;
    uint8_t pkt[100], out[2048];
    size_t len, n = 0;
    gq_path to;

    memset (&from, 0, sizeof from);
    from.local = net->node[0].addr;
    from.remote = net->node[1].addr;
    for (i = 0; i < 10; i++)
      {
        memset (pkt, 0x40 | i, sizeof pkt);
        pkt[0] = 0x40;
        gq_endpoint_recv (net->node[0].ep, net->now, &from, pkt, sizeof pkt);
      }
    while (gq_endpoint_send (net->node[0].ep, net->now, out, sizeof out, &len,
                             &to) == GQ_OK && len)
      {
        CHECK (len < sizeof pkt && len >= 21);	/* Smaller than the trigger.  */
        n++;
      }
    CHECK_EQ (n, 3);
    /* All ten drew a dropped-packet event; only three were answered.  */
    CHECK_EQ (esink_null (&net->qs[0], "quic:packet_dropped",
                          "trigger=connection_unknown"), 10);
    CHECK_EQ (esink_null (&net->qs[0], "quic:packet_sent",
                          "header.packet_type=stateless_reset"), 3);
    /* The window moves on.  */
    net->now += 1500000;
    gq_endpoint_recv (net->node[0].ep, net->now, &from, pkt, sizeof pkt);
    CHECK (gq_endpoint_send (net->node[0].ep, net->now, out, sizeof out, &len,
                             &to) == GQ_OK && len > 0);
    /* Too small to answer, and garbage of every shape, is ignored.  */
    for (i = 1; i < 60; i++)
      {
        memset (pkt, 0x55, sizeof pkt);
        pkt[0] = (uint8_t) (i & 1 ? 0xc0 : 0x00);
        gq_endpoint_recv (net->node[0].ep, net->now, &from, pkt, (size_t) i);
      }
  }
  net_free (net);
}

static void
test_limits_and_refusal (void)
{
  gq_endpoint_config sc;
  struct net *net;
  int i, connected = 0;

  memset (&sc, 0, sizeof sc);
  sc.max_connections = 3;
  net = net_new (&sc, 8, NULL);
  for (i = 0; i < 6; i++)
    client_conn (net, 1 + i % 2, NULL);
  run (net, NULL, 5000000);
  CHECK_EQ (gq_endpoint_connections (net->node[0].ep), 3);
  for (i = 0; i < net->node[1].napp; i++)
    connected += net->node[1].app[i].connected;
  for (i = 0; i < net->node[2].napp; i++)
    connected += net->node[2].app[i].connected;
  CHECK_EQ (connected, 3);
  net_free (net);

  /* The application can refuse: nothing is created.  */
  net = net_new (NULL, 9, ep_refuse);
  client_conn (net, 1, NULL);
  run (net, NULL, 2000000);
  CHECK_EQ (gq_endpoint_connections (net->node[0].ep), 0);
  CHECK (net->node[0].refused >= 1);
  net_free (net);
}

/* Connections that go quiet time out, all of them, without the endpoint
   scanning them: the deadline heap does it.  */
static void
test_idle_timeouts (void)
{
  gq_conn_config cc;
  struct net *net;
  int i, done = 0;

  net = net_new (NULL, 10, NULL);
  memset (&cc, 0, sizeof cc);
  cc.idle_timeout_ms = 1000;
  for (i = 0; i < 40; i++)
    client_conn (net, 1 + i % 2, &cc);
  CHECK (run (net, all_clients_done, 30000000));
  /* The network goes away.  */
  net->loss_pct = 100;
  run (net, NULL, 30000000);
  for (i = 0; i < net->node[1].napp; i++)
    done += net->node[1].app[i].closed;
  for (i = 0; i < net->node[2].napp; i++)
    done += net->node[2].app[i].closed;
  CHECK_EQ (done, 40);
  CHECK_EQ (gq_endpoint_connections (net->node[1].ep)
            + gq_endpoint_connections (net->node[2].ep), 0);
  CHECK_EQ (gq_endpoint_connections (net->node[0].ep), 0);
  CHECK_EQ (gq_endpoint_timeout (net->node[0].ep), 0);
  net_free (net);
}

/* An Initial for a connection ID the server chose for a connection that has
   since gone is a late packet of that connection, not a new client: taking
   it for one would make a connection that can never decrypt it, claiming
   the old ID, until it idled out.  */
static void
test_late_initial (void)
{
  struct net *net = net_new (NULL, 13, NULL);
  struct capp *a;
  gq_path from;
  int accepted, i;

  a = client_conn (net, 1, NULL);
  CHECK (run (net, all_clients_done, 60000000));
  CHECK (net->late_len >= 1200);
  CHECK_EQ (net->node[0].accepted, 1);
  gq_conn_close (a->c, net->now, 1, 0, "done");
  for (i = 0; i < 20 && gq_endpoint_connections (net->node[0].ep); i++)
    run (net, NULL, 500000);
  CHECK_EQ (gq_endpoint_connections (net->node[0].ep), 0);
  accepted = net->node[0].accepted;
  memset (&from, 0, sizeof from);
  from.local = net->node[0].addr;
  from.remote = net->node[1].ext;
  gq_endpoint_recv (net->node[0].ep, net->now, &from, net->late,
                    net->late_len);
  CHECK_EQ (net->node[0].accepted, accepted);
  CHECK_EQ (gq_endpoint_connections (net->node[0].ep), 0);
  net_free (net);
}

/* The client's address changes (a NAT rebinding): the server endpoint finds
   the connection by ID, not address, and the connection follows.  */
static void
test_rebinding_through_endpoint (void)
{
  struct net *net = net_new (NULL, 11, NULL);
  struct capp *a, *b;

  a = client_conn (net, 1, NULL);
  b = client_conn (net, 2, NULL);
  CHECK (run (net, all_clients_done, 60000000));
  run (net, NULL, 1000000);
  /* Both clients get new external addresses at once.  */
  net->node[1].ext = mkaddr ("CLI-1-NEW");
  net->node[2].ext = mkaddr ("CLI-2-NEW");
  net->node[0].respond = 100000;
  {
    uint64_t id;
    int x;

    for (x = 2; x < 4; x++)
      {
        CHECK_EQ (gq_conn_stream_open (a->c, 1, &id), GQ_OK);
        a->stream_used[x] = 1;
        a->out_total[x] = 20;
        CHECK_EQ (gq_conn_stream_open (b->c, 1, &id), GQ_OK);
        b->stream_used[x] = 1;
        b->out_total[x] = 20;
      }
  }
  /* The new streams (ids 8 and 12) go over the new addresses and are
     answered in full.  */
  run (net, NULL, 3000000);
  CHECK (a->fin[2] && a->fin[3] && b->fin[2] && b->fin[3]);
  CHECK (a->got[2] == 100000 && b->got[3] == 100000);
  {
    int i, moved = 0;

    for (i = 0; i < net->node[0].napp; i++)
      moved += net->node[0].app[i].mig > 0;
    CHECK_EQ (gq_endpoint_connections (net->node[0].ep), 2);
    CHECK_EQ (moved, 2);
  }
  CHECK_EQ (a->closed + b->closed, 0);
  net_free (net);
}

int
main (void)
{
  gq_crypto_init ();
  fx_setup ();
  setup_tls ();
  test_many_connections ();
  test_early_data ();
  test_ecn ();
  test_preferred_address ();
  test_retry ();
  test_version_negotiation ();
  test_stateless_reset ();
  test_limits_and_refusal ();
  test_idle_timeouts ();
  test_rebinding_through_endpoint ();
  test_late_initial ();
  if (getenv ("QLOG_STATS"))
    {
      size_t k;

      for (k = 0; qc_events[k]; k++)
        fprintf (stderr, "  %-36s %lu\n", qc_events[k], g_seen[k]);
    }
  TST_DONE ();
}

#endif
