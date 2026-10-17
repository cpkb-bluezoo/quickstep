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

void
conn_pmtu_init (gq_conn *c)
{
  c->pmtu_state = PMTU_START;
  c->pmtu_cur = PMTU_BASE;
  c->pmtu_lo = PMTU_BASE;
  c->pmtu_hi = 0;
  c->pmtu_probe_out = 0;
  c->pmtu_fails = 0;
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

/* The probe of SIZE bytes was acknowledged: that size works.  */
void
conn_pmtu_acked (gq_conn *c, size_t size)
{
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
conn_pmtu_lost (gq_conn *c, size_t size)
{
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
