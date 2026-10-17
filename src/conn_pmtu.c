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

/* Path MTU discovery (RFC 9000 section 14.3, RFC 8899).

   Datagrams start at the smallest size every path must carry, 1200 bytes.
   After the handshake is confirmed a probe, a 1-RTT packet of PING and
   padding of a larger size, is sent; when it is acknowledged that is the
   size, and when it is lost three times the path does not take it.  The
   first probe is at the ceiling (gq_conn_config.max_udp_payload, bounded by
   the peer's max_udp_payload_size), which most paths take; after a failure
   the search halves what is left, and it ends when the sizes still in
   question are PMTU_GRANULARITY apart.

   The search is made again when the path changes (the size is the
   path's own; a path we come back to has the size it had), when packets
   of the size in use stop getting through (three timeouts in a row take
   the size back to 1200 and the search runs below the old size), and
   every PMTU_RAISE_US after it ended below the ceiling.

   A probe is a packet like any other for the window and for the round trip
   time, but its loss says nothing about congestion (RFC 9000 section 14.4):
   it is not counted as lost, does not shrink the window, and does not go
   towards persistent congestion.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "conn_int.h"

#define PMTU_PROBES 3		/* Lost probes of a size before it is given up.  */
#define PMTU_GRANULARITY 16
#define PMTU_BLACK_HOLE_PTOS 3	/* Timeouts in a row that say the size is too big.  */
#define PMTU_RAISE_US 600000000ull

void
conn_pmtu_init (gq_conn *c)
{
  c->pmtu_state = PMTU_START;
  c->pmtu_cur = PMTU_BASE;
  c->pmtu_lo = PMTU_BASE;
  c->pmtu_hi = 0;
  c->pmtu_probe_out = 0;
  c->pmtu_probe_size = 0;
  c->pmtu_fails = 0;
  c->pmtu_raise_at = 0;
  c->pmtu_gen++;		/* Probes still out are of the time before.  */
}

/* The largest size to try: what was configured, within what the peer takes.  */
static size_t
ceiling_of (const gq_conn *c)
{
  size_t m = c->cfg.max_udp_payload;

  if (c->have_peer_tp && c->peer_tp.max_udp_payload_size < m)
    m = (size_t) c->peer_tp.max_udp_payload_size;
  return m < PMTU_BASE ? PMTU_BASE : m;
}

static void
set_size (gq_conn *c, size_t size)
{
  if (c->pmtu_cur == size)
    return;
  c->pmtu_cur = (uint32_t) size;
  cong_set_mss (&c->cc, (uint32_t) size);
  pacer_set_dgram (&c->pace, (uint32_t) size);
}

/* What to probe next, or done: sets the size and the state.  */
static void
plan (gq_conn *c)
{
  size_t ceiling = ceiling_of (c);

  if (c->pmtu_state == PMTU_START)
    {
      c->pmtu_lo = c->pmtu_cur;
      c->pmtu_hi = (uint32_t) (ceiling + 1);
      c->pmtu_state = PMTU_SEARCH;
    }
  c->pmtu_fails = 0;
  if (c->pmtu_hi <= c->pmtu_lo + 1
      || (c->pmtu_hi <= ceiling && c->pmtu_hi - c->pmtu_lo <= PMTU_GRANULARITY))
    {
      c->pmtu_state = PMTU_DONE;
      /* A size short of the ceiling is tried again later.  */
      c->pmtu_raise_at = c->pmtu_cur < ceiling ? c->now + PMTU_RAISE_US : 0;
      return;
    }
  c->pmtu_probe_size = c->pmtu_hi > ceiling ? (uint32_t) ceiling
                       : (c->pmtu_lo + c->pmtu_hi) / 2;
}

size_t
conn_pmtu_next_probe (gq_conn *c, size_t cap)
{
  uint64_t budget;

  if (c->state != GQ_CONN_ESTABLISHED || !c->handshake_confirmed
      || c->pmtu_state == PMTU_DONE || c->pmtu_probe_out
      || !c->sp[SP_APP].have_wk || c->sp[SP_APP].discarded
      || c->sp[SP_APP].probes)
    return 0;
  if (c->pmtu_state == PMTU_START || c->pmtu_probe_size == 0)
    plan (c);
  if (c->pmtu_state == PMTU_DONE)
    return 0;
  /* Not into a buffer too small for it, nor beyond the window or what the
     address of the peer allows.  */
  if (c->pmtu_probe_size > cap || !conn_can_send_ae (c))
    return 0;
  if (conn_path_budget (c, c->cur_path, &budget) && budget < c->pmtu_probe_size)
    return 0;
  return c->pmtu_probe_size;
}

void
conn_pmtu_probe_sent (gq_conn *c)
{
  c->pmtu_probe_out = 1;
}

/* The probe of SIZE bytes, sent in generation GEN of the search, was
   acknowledged: that size works.  */
void
conn_pmtu_acked (gq_conn *c, size_t size, uint32_t gen)
{
  if (gen != c->pmtu_gen)
    return;			/* From before the path changed.  */
  c->pmtu_probe_out = 0;
  if (size > c->pmtu_lo)
    c->pmtu_lo = (uint32_t) size;
  if (size > c->pmtu_cur)
    set_size (c, size);
  c->pmtu_probe_size = 0;
  plan (c);
}

/* The probe was declared lost.  */
void
conn_pmtu_lost (gq_conn *c, size_t size, uint32_t gen)
{
  if (gen != c->pmtu_gen)
    return;
  c->pmtu_probe_out = 0;
  if (size != c->pmtu_probe_size)
    return;
  if (++c->pmtu_fails < PMTU_PROBES)
    return;			/* Try the same size again.  */
  c->pmtu_hi = (uint32_t) size;
  c->pmtu_probe_size = 0;
  plan (c);
}

int
conn_pmtu_done (const gq_conn *c)
{
  return c->pmtu_state == PMTU_DONE;
}

/* The generation to give a probe being sent.  */
uint32_t
conn_pmtu_gen (const gq_conn *c)
{
  return c->pmtu_gen;
}

/* A timeout has fired.  If it is the third in a row and datagrams are
   larger than 1200 bytes, they are probably the trouble: a path that stops
   taking the size it did drops everything of it, acknowledgements included.
   Go back to 1200 and search below the size that failed.  */
void
conn_pmtu_on_pto (gq_conn *c)
{
  if (c->pto_count < PMTU_BLACK_HOLE_PTOS || c->pmtu_cur <= PMTU_BASE)
    return;
  c->pmtu_gen++;
  c->pmtu_probe_out = 0;
  c->pmtu_probe_size = 0;
  c->pmtu_raise_at = 0;
  c->pmtu_state = PMTU_SEARCH;
  c->pmtu_lo = PMTU_BASE;
  c->pmtu_hi = c->pmtu_cur;
  set_size (c, PMTU_BASE);
  plan (c);
}

/* The connection goes from path slot OLD (or -1) to path slot IDX.  The old
   path keeps the size it had, a path we have been on before has the size it
   kept, and any other starts from 1200 and searches.  */
void
conn_pmtu_switch (gq_conn *c, int old, int idx)
{
  size_t want = c->paths[idx].pmtu;

  if (old >= 0 && c->paths[old].used)
    c->paths[old].pmtu = c->pmtu_state == PMTU_DONE ? c->pmtu_cur : 0;
  conn_pmtu_init (c);
  set_size (c, PMTU_BASE);
  if (want > PMTU_BASE)
    {
      /* Known, and not searched for again until the raise timer.  */
      c->pmtu_state = PMTU_DONE;
      c->pmtu_lo = (uint32_t) want;
      set_size (c, want);
      c->pmtu_raise_at = want < ceiling_of (c) ? c->now + PMTU_RAISE_US : 0;
    }
}

/* The raise timer.  */
uint64_t
conn_pmtu_deadline (const gq_conn *c)
{
  return c->pmtu_state == PMTU_DONE ? c->pmtu_raise_at : 0;
}

void
conn_pmtu_on_timeout (gq_conn *c, uint64_t now)
{
  if (c->pmtu_state != PMTU_DONE || c->pmtu_raise_at == 0
      || now < c->pmtu_raise_at)
    return;
  c->pmtu_raise_at = 0;
  c->pmtu_state = PMTU_SEARCH;
  c->pmtu_lo = c->pmtu_cur;
  c->pmtu_hi = (uint32_t) (ceiling_of (c) + 1);
  c->pmtu_probe_size = 0;
  plan (c);
}
