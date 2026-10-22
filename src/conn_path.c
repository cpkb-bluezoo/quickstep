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

/* Path validation and connection migration (RFC 9000 sections 8.2, 9).

   A path is a pair of opaque addresses the caller supplies.  The table
   holds the current path, possibly the previous one (kept as a fallback
   until the new one validates) and a few candidates under validation.

   Peer migration (server side): a packet that carries a non-probing frame,
   has the highest packet number so far and arrives from a new address means
   the peer moved.  We start sending there at once (RFC 9000 section 9.3),
   limited to three times what has arrived from it until it validates, and
   validate it with PATH_CHALLENGE.  If validation fails we go back to the
   previous path.

   Active migration (client side, gq_conn_migrate): the new path is
   validated first and used once it proves reachable.

   Every path gets its own peer connection ID when one is available, so
   the paths cannot be linked (section 9.5).  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "conn_int.h"

static int
addr_eq (const gq_addr *a, const gq_addr *b)
{
  return a->len == b->len && memcmp (a->data, b->data, a->len) == 0;
}

static int
path_eq (const gq_path *a, const gq_path *b)
{
  return addr_eq (&a->local, &b->local) && addr_eq (&a->remote, &b->remote);
}

static int
find (const gq_conn *c, const gq_path *p)
{
  int i;

  for (i = 0; i < MAX_PATHS; i++)
    if (c->paths[i].used && path_eq (&c->paths[i].p, p))
      return i;
  return -1;
}

/* The entry a received datagram belongs to: its own if it is tracked,
   else (no path information at all) the current one.  */
static int
rx_index (const gq_conn *c)
{
  if (!c->rx_known)
    return c->cur_path;
  return find (c, &c->rx);
}

static int
validated_eff (const gq_conn *c, int idx)
{
  const pathinfo *e = &c->paths[idx];

  if (e->initial)
    return c->role == GQ_ROLE_CLIENT || c->peer_addr_validated || e->validated;
  return e->validated;
}

static unsigned
candidates (const gq_conn *c)
{
  unsigned n = 0;
  int i;

  for (i = 0; i < MAX_PATHS; i++)
    if (c->paths[i].used && i != c->cur_path && i != c->prev_path)
      n++;
  return n;
}

void
conn_path_init (gq_conn *c, const gq_path *initial)
{
  pathinfo *e = &c->paths[0];

  memset (e, 0, sizeof *e);
  e->used = 1;
  e->initial = 1;
  if (initial)
    e->p = *initial;
  c->cur_path = 0;
  c->prev_path = -1;
}

/* A peer connection ID not in use on any path (or NULL); if WANT is not
   negative, the one of that sequence number or none.  */
static pcid *
fresh_cid (gq_conn *c, int64_t want)
{
  int i, k;

  for (i = 0; i < MAX_PCID; i++)
    {
      int used = 0;

      if (!c->p[i].used || c->p[i].retire || c->p[i].seq == c->dcid_seq)
        continue;
      if (want >= 0 && c->p[i].seq != (uint64_t) want)
        continue;
      for (k = 0; k < MAX_PATHS; k++)
        if (c->paths[k].used && c->paths[k].dcid_seq == c->p[i].seq
            && c->paths[k].dcid.len)
          used = 1;
      if (!used)
        return &c->p[i];
    }
  return NULL;
}

static int
path_add (gq_conn *c, const gq_path *p, int local_init, int need_fresh,
          int64_t want)
{
  int i, slot = -1;
  pathinfo *e;
  pcid *f;

  if (candidates (c) >= MAX_CANDIDATES)
    return -1;
  for (i = 0; i < MAX_PATHS; i++)
    if (!c->paths[i].used)
      {
        slot = i;
        break;
      }
  if (slot < 0)
    return -1;
  f = fresh_cid (c, want);
  if (f == NULL && (need_fresh || want >= 0))
    return -2;
  e = &c->paths[slot];
  memset (e, 0, sizeof *e);
  e->used = 1;
  e->p = *p;
  e->local_init = (uint8_t) local_init;
  if (f)
    {
      e->dcid = f->cid;
      e->dcid_seq = f->seq;
    }
  else
    {
      e->dcid = c->dcid;
      e->dcid_seq = c->dcid_seq;
    }
  c->ql.mig[slot] = NULL;
  ql_tuple_assigned (c, slot, 0);
  return slot;
}

static void
start_validation (gq_conn *c, pathinfo *e, uint64_t now)
{
  uint64_t t = 3 * conn_pto_base (c, SP_APP);

  if (t < 6 * K_INITIAL_RTT)
    t = 6 * K_INITIAL_RTT;
  e->need_challenge = 1;
  e->chal_sent = 0;
  e->n_chal = 0;
  e->chal_deadline = now + t;
  e->chal_next = now + t / MAX_CHALLENGES;
  /* Hold the challenge briefly so a PING can go first, and so the peer's
     own challenge is the first packet it sends on the path.  */
  if (e->ping_first)
    {
      uint64_t wait = t / 4;

      if (wait < 1000)
        wait = 1000;
      e->chal_hold = 1;
      e->chal_hold_until = now + wait;
    }
  if (e != &c->paths[c->cur_path])
    ql_migration (c, "probing_started", (int) (e - c->paths));
}

static void
free_entry (gq_conn *c, int idx)
{
  ql_tuple_assigned (c, idx, 1);
  c->ql.mig[idx] = NULL;
  memset (&c->paths[idx], 0, sizeof c->paths[idx]);
  if (c->prev_path == idx)
    c->prev_path = -1;
}

/* Retire the peer ID a path used, so the peer issues a replacement.  */
static void
retire_seq (gq_conn *c, uint64_t seq)
{
  int i;

  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].seq == seq && c->p[i].retire == 0
        && seq != c->dcid_seq)
      c->p[i].retire = 1;
}

/* ANNOUNCE is 0 when the preferred-address PING has moved sending here
   before the path has validated: the peer must see no further traffic on
   the old path, and the migration is reported when validation succeeds.  */
static void
switch_to (gq_conn *c, int idx, int announce)
{
  int old = c->cur_path;
  pathinfo *n = &c->paths[idx];

  if (idx == old)
    return;
  if (old >= 0)
    {
      /* Remember which peer ID the path we leave was using.  */
      c->paths[old].dcid = c->dcid;
      c->paths[old].dcid_seq = c->dcid_seq;
    }
  c->prev_path = old >= 0 && validated_eff (c, old) ? old : -1;
  c->cur_path = idx;
  conn_pmtu_switch (c, old, idx);
  if (n->dcid.len)
    {
      c->dcid = n->dcid;
      c->dcid_seq = n->dcid_seq;
    }
  /* A new path: forget what we knew about the old one's capacity
     (RFC 9000 section 9.4).  */
  cc_init (c);
  conn_spin_reset (c);
  conn_ecn_restart (c);
  c->have_rtt = 0;
  c->srtt = CONN_INITIAL_RTT (c);
  c->rttvar = CONN_INITIAL_RTT (c) / 2;
  if (!announce)
    {
      n->moved_quiet = 1;
      return;
    }
  n->moved_quiet = 0;
  c->migrations++;
  ql_migration (c, "migration_started", idx);
  if (c->ev.migrated)
    c->ev.migrated (c->ev.user, &n->p);
}

/* The preferred-address PING has gone out: this path is where the
   connection sends from now on.  Validation still has to succeed, and
   failure returns to the path that was current.  */
void
conn_path_commit (gq_conn *c, int idx)
{
  if (idx < 0 || idx >= MAX_PATHS || !c->paths[idx].used)
    return;
  if (!c->paths[idx].auto_switch || idx == c->cur_path)
    return;
  switch_to (c, idx, 0);
}

static void
validated (gq_conn *c, int idx)
{
  pathinfo *e = &c->paths[idx];

  e->validated = 1;
  e->n_chal = 0;
  e->need_challenge = 0;
  e->chal_deadline = 0;
  c->path_validations++;
  if (idx != c->cur_path)
    ql_migration (c, "probing_successful", idx);
  if (c->ev.path_validated)
    c->ev.path_validated (c->ev.user, &e->p);
  if (e->auto_switch && idx != c->cur_path)
    switch_to (c, idx, 1);
  else if (idx == c->cur_path && e->moved_quiet)
    {
      e->moved_quiet = 0;
      c->migrations++;
      ql_migration (c, "migration_started", idx);
      if (c->ev.migrated)
        c->ev.migrated (c->ev.user, &e->p);
    }
  if (idx == c->cur_path)
    ql_migration (c, "migration_complete", idx);
  if (idx == c->cur_path && c->prev_path >= 0)
    {
      /* The old path is done with; so is the ID it used.  */
      if (c->paths[c->prev_path].dcid_seq != c->dcid_seq)
        retire_seq (c, c->paths[c->prev_path].dcid_seq);
      free_entry (c, c->prev_path);
    }
}

#define BAD_PATH_COOLDOWN 10000000u

static int
recently_failed (const gq_conn *c, const gq_path *p, uint64_t now)
{
  unsigned i;

  for (i = 0; i < 2; i++)
    if (c->bad_until[i] > now && path_eq (&c->bad_path[i], p))
      return 1;
  return 0;
}

static void
failed (gq_conn *c, int idx)
{
  pathinfo *e = &c->paths[idx];
  gq_path p = e->p;
  int quiet = e->moved_quiet;

  c->path_failures++;
  ql_migration (c, idx == c->cur_path && !quiet ? "migration_abandoned"
                                                : "probing_abandoned", idx);
  e->moved_quiet = 0;
  if (!e->local_init)
    {
      /* Do not switch straight back to something that just failed.  */
      c->bad_path[c->bad_next % 2] = p;
      c->bad_until[c->bad_next % 2] = c->now + BAD_PATH_COOLDOWN;
      c->bad_next++;
    }
  if (idx == c->cur_path)
    {
      if (c->prev_path >= 0)
        {
          int back = c->prev_path;

          c->prev_path = -1;
          c->cur_path = back;
          conn_pmtu_switch (c, idx, back);
          c->dcid = c->paths[back].dcid;
          c->dcid_seq = c->paths[back].dcid_seq;
          free_entry (c, idx);
          if (c->ev.path_failed)
            c->ev.path_failed (c->ev.user, &p);
          /* A move that was never reported has nothing to report now.  */
          if (!quiet && c->ev.migrated)
            c->ev.migrated (c->ev.user, &c->paths[back].p);
          return;
        }
      /* Nowhere to go back to: stay, and stop challenging.  */
      e->chal_deadline = 0;
      e->need_challenge = 0;
      e->n_chal = 0;
    }
  else
    free_entry (c, idx);
  if (c->ev.path_failed)
    c->ev.path_failed (c->ev.user, &p);
}

/* ---- Receiving ---- */

void
conn_path_rx_begin (gq_conn *c, const gq_path *from)
{
  c->rx_known = from != NULL && from->remote.len > 0;
  if (c->rx_known)
    {
      c->rx = *from;
      if (c->paths[c->cur_path].p.remote.len == 0)
        {
          c->paths[c->cur_path].p = *from;	/* The first datagram.  */
          c->rx_pinned = 1;
        }
    }
}

/* The datagram begun with conn_path_rx_begin is processed.  If it set the
   path and no packet in it was accepted, take that back: anyone can send one
   datagram, from anywhere, before the peer's own, and it must not decide
   where the peer is.  */
void
conn_path_rx_done (gq_conn *c, int accepted)
{
  if (c->rx_pinned && !accepted)
    memset (&c->paths[c->cur_path].p, 0, sizeof c->paths[c->cur_path].p);
  c->rx_pinned = 0;
}

void
conn_path_rx_end (gq_conn *c)
{
  c->rx_known = 0;
}

int
conn_path_accept_rx (const gq_conn *c)
{
  /* A client hears from its server's address, on whichever of its own
     sockets (the server may go on using the old path until it has
     validated the new one), and from paths it probes; nowhere else.  */
  if (c->role == GQ_ROLE_CLIENT && c->rx_known)
    {
      int i;

      for (i = 0; i < MAX_PATHS; i++)
        if (c->paths[i].used && addr_eq (&c->paths[i].p.remote, &c->rx.remote))
          return 1;
      return 0;
    }
  return 1;
}

void
conn_path_account_recv (gq_conn *c, size_t len)
{
  int i = rx_index (c);

  if (i >= 0 && !c->paths[i].initial)
    c->paths[i].recv += len;
  else
    c->bytes_recv += len;
}

int
conn_path_rx_initial (const gq_conn *c)
{
  int i = rx_index (c);

  return i >= 0 && c->paths[i].initial;
}

void
conn_path_dcid_changed (gq_conn *c)
{
  c->paths[c->cur_path].dcid = c->dcid;
  c->paths[c->cur_path].dcid_seq = c->dcid_seq;
}

/* The peer has retired connection IDs: no path may go on using one
   (RFC 9000 section 5.1.2).  The current path follows the ID in use; any
   other takes a fresh one, or shares the current one when the peer has
   issued no more.  */
void
conn_path_cids_retired (gq_conn *c)
{
  int k, i;

  for (k = 0; k < MAX_PATHS; k++)
    {
      pathinfo *e = &c->paths[k];
      int live = 0;
      pcid *f;

      if (!e->used || e->dcid.len == 0 || k == c->cur_path)
        continue;
      for (i = 0; i < MAX_PCID; i++)
        if (c->p[i].used && c->p[i].seq == e->dcid_seq && !c->p[i].retire)
          live = 1;
      if (live)
        continue;
      f = fresh_cid (c, -1);
      if (f)
        {
          e->dcid = f->cid;
          e->dcid_seq = f->seq;
        }
      else
        {
          e->dcid = c->dcid;
          e->dcid_seq = c->dcid_seq;
        }
    }
}

void
conn_path_after_packet (gq_conn *c, uint64_t now, int nonprobing, int highest)
{
  int idx;

  if (!c->handshake_confirmed || !c->rx_known || c->role != GQ_ROLE_SERVER)
    return;
  idx = find (c, &c->rx);
  if (idx == c->cur_path || !nonprobing || !highest)
    return;
  if (recently_failed (c, &c->rx, now))
    return;
  if (idx < 0)
    {
      idx = path_add (c, &c->rx, 0, 0, -1);
      if (idx < 0)
        return;
    }
  if (!c->paths[idx].validated && c->paths[idx].n_chal == 0
      && !c->paths[idx].need_challenge)
    start_validation (c, &c->paths[idx], now);
  switch_to (c, idx, 1);
  /* What is in flight went to the old address and may never be
     acknowledged, so the window the new path starts with can be full
     before it has sent anything.  The challenge must still be the first
     thing it gets (RFC 9000 section 9.3), and only an ack-eliciting
     packet carries one: send a probe, which the window does not bar.  */
  if (c->paths[idx].need_challenge && c->sp[SP_APP].probes == 0)
    c->sp[SP_APP].probes = 1;
}

void
conn_path_on_challenge (gq_conn *c, const uint8_t *data)
{
  int idx = rx_index (c);
  pathinfo *e;

  if (idx < 0)
    {
      idx = path_add (c, &c->rx, 0, 0, -1);
      if (idx < 0)
        return;
      /* A path we have not seen: check it too.  */
      start_validation (c, &c->paths[idx], c->now);
    }
  e = &c->paths[idx];
  if (e->n_resp < 2)
    memcpy (e->resp[e->n_resp++], data, 8);
  /* The peer has challenged: ours may go now, and ahead of the response.  */
  e->chal_hold = 0;
}

void
conn_path_on_response (gq_conn *c, const uint8_t *data, uint64_t now)
{
  int i;
  unsigned k;

  (void) now;
  for (i = 0; i < MAX_PATHS; i++)
    {
      pathinfo *e = &c->paths[i];

      if (!e->used || e->validated)
        continue;
      for (k = 0; k < e->n_chal; k++)
        if (memcmp (e->chal[k], data, 8) == 0)
          {
            validated (c, i);
            return;
          }
    }
}

/* ---- Sending ---- */

int
conn_path_budget (const gq_conn *c, int idx, uint64_t *budget)
{
  const pathinfo *e = &c->paths[idx];
  uint64_t recv, sent;

  if (e->initial)
    {
      if (c->role != GQ_ROLE_SERVER || c->peer_addr_validated)
        return 0;
      recv = c->bytes_recv;
      sent = c->bytes_sent;
    }
  else
    {
      if (e->validated || e->local_init)
        return 0;
      recv = e->recv;
      sent = e->sent;
    }
  *budget = 3 * recv > sent ? 3 * recv - sent : 0;
  return 1;
}

void
conn_path_note_sent (gq_conn *c, int idx, size_t len)
{
  if (idx >= 0 && !c->paths[idx].initial)
    c->paths[idx].sent += len;
  else
    c->bytes_sent += len;
}

/* 1 when the datagram in hand arrived on some path other than the current
   one, including a path not in the table yet.  */
int
conn_path_rx_changed (const gq_conn *c)
{
  if (!c->rx_known)
    return 0;
  return find (c, &c->rx) != c->cur_path;
}

int
conn_path_probe_pending (gq_conn *c, uint64_t now)
{
  int i;

  (void) now;
  for (i = 0; i < MAX_PATHS; i++)
    {
      pathinfo *e = &c->paths[i];
      uint64_t b;

      if (!e->used || i == c->cur_path || !e->p.remote.len)
        continue;
      if (e->ping_first && !e->pinged)
        return i;
      if (e->chal_hold && c->now < e->chal_hold_until)
        {
          if (!e->n_resp)
            continue;
        }
      else if (!(e->n_resp || e->need_challenge))
        continue;
      if (conn_path_budget (c, i, &b) && b < 100)
        continue;
      return i;
    }
  return -1;
}

int
conn_path_challenge_data (gq_conn *c, int idx, uint8_t out[8])
{
  pathinfo *e = &c->paths[idx];

  /* Unpredictable, or a peer that cannot receive on the path could still
     answer: without randomness there is no challenge, and it stays owed.  */
  if (gq_random (out, 8) != GQ_OK)
    return GQ_ERR_CRYPTO;
  if (e->n_chal == MAX_CHALLENGES)
    {
      memmove (e->chal[0], e->chal[1], (MAX_CHALLENGES - 1) * 8);
      e->n_chal--;
    }
  memcpy (e->chal[e->n_chal++], out, 8);
  e->chal_sent++;
  e->need_challenge = 0;
  return GQ_OK;
}

uint64_t
conn_path_deadline (const gq_conn *c)
{
  uint64_t t = 0;
  int i;

  for (i = 0; i < MAX_PATHS; i++)
    {
      const pathinfo *e = &c->paths[i];

      if (!e->used || e->chal_deadline == 0)
        continue;
      if (t == 0 || e->chal_deadline < t)
        t = e->chal_deadline;
      if (e->chal_hold && e->chal_hold_until
          && (t == 0 || e->chal_hold_until < t))
        t = e->chal_hold_until;
      if (e->chal_sent < MAX_CHALLENGES && !e->need_challenge
          && e->chal_next < t)
        t = e->chal_next;
    }
  return t;
}

void
conn_path_on_timeout (gq_conn *c, uint64_t now)
{
  int i;

  for (i = 0; i < MAX_PATHS; i++)
    {
      pathinfo *e = &c->paths[i];

      if (!e->used)
        continue;
      if (e->chal_hold && now >= e->chal_hold_until)
        e->chal_hold = 0;
      if (e->chal_deadline == 0)
        continue;
      if (now >= e->chal_deadline)
        failed (c, i);
      else if (e->chal_sent < MAX_CHALLENGES && now >= e->chal_next)
        {
          uint64_t step = (e->chal_deadline - now) / (MAX_CHALLENGES
                                                      - e->chal_sent + 1);

          e->need_challenge = 1;
          e->chal_next = now + (step ? step : 1);
        }
    }
}

/* ---- Application interface ---- */

int
gq_conn_get_path (const gq_conn *c, gq_path *path)
{
  if (c->paths[c->cur_path].p.remote.len == 0)
    return GQ_ERR_UNAVAILABLE;
  *path = c->paths[c->cur_path].p;
  return GQ_OK;
}

/* As gq_conn_probe_path; if WANT is not negative, with the peer connection
   ID of that sequence number.  */
static int
probe_path (gq_conn *c, uint64_t now_us, const gq_path *path, int64_t want)
{
  int idx;

  if (path == NULL || path->remote.len == 0 || !c->handshake_confirmed
      || c->state != GQ_CONN_ESTABLISHED)
    return GQ_ERR_INVAL;
  c->now = now_us;
  idx = find (c, path);
  if (idx == c->cur_path)
    return GQ_ERR_INVAL;
  if (idx >= 0)
    return GQ_OK;		/* Already known: being validated, or done.  */
  idx = path_add (c, path, 1, 1, want);
  if (idx < 0)
    return GQ_ERR_RANGE;
  /* Only the preferred-address move names a connection ID.  It is where
     the client means to stay, so the first packet is not a probe.  */
  if (c->role == GQ_ROLE_CLIENT && want >= 0)
    c->paths[idx].ping_first = 1;
  start_validation (c, &c->paths[idx], now_us);
  conn_wake (c);
  return GQ_OK;
}

int
gq_conn_probe_path (gq_conn *c, uint64_t now_us, const gq_path *path)
{
  return probe_path (c, now_us, path, -1);
}

/* Validate PATH and move to it, with the connection ID of sequence number
   WANT if that is not negative.  */
static int
migrate (gq_conn *c, uint64_t now_us, const gq_path *path, int64_t want)
{
  int idx, r;

  r = probe_path (c, now_us, path, want);
  if (r != GQ_OK)
    return r;
  idx = find (c, path);
  if (idx < 0)
    return GQ_ERR_INVAL;
  if (c->paths[idx].validated)
    {
      switch_to (c, idx, 1);
      ql_migration (c, "migration_complete", idx);
    }
  else
    c->paths[idx].auto_switch = 1;
  conn_wake (c);
  return GQ_OK;
}

int
gq_conn_migrate (gq_conn *c, uint64_t now_us, const gq_path *path)
{
  if (c->role != GQ_ROLE_CLIENT
      || (c->have_peer_tp
          && gq_tp_has (&c->peer_tp, GQ_TP_DISABLE_ACTIVE_MIGRATION)))
    return GQ_ERR_UNAVAILABLE;
  return migrate (c, now_us, path, -1);
}

/* The server's preferred address is the one move that a server which
   forbids active migration allows (RFC 9000 section 18.2); its connection ID
   goes with it.  */
int
gq_conn_migrate_preferred (gq_conn *c, uint64_t now_us, const gq_path *path)
{
  if (c->role != GQ_ROLE_CLIENT || !c->pref_offered)
    return GQ_ERR_UNAVAILABLE;
  return migrate (c, now_us, path, 1);
}
