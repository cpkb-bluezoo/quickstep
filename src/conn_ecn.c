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

/* Explicit Congestion Notification (RFC 9000 section 13.4, RFC 9002
   section 7.1): marking what we send, validating that the path keeps the
   marks and the peer counts them, and taking an increase in its count of CE
   as a congestion event.

   Only the packets of the application space on the current path are marked
   (ECT(0)), and only in a call to gq_conn_send_ecn: a path that drops what
   is marked cannot then stop a handshake, and an application that does not
   set the ECN field of the datagrams is not assumed to.

   The path starts in TESTING and marks its first ECN_TEST_PACKETS packets.
   Then, in UNKNOWN, it marks none until an ACK frame says the peer got a
   marked packet, with counts that add up (CAPABLE), or has not (FAILED).  A
   path that has gone back to TESTING after a change of path is judged only
   by the packets sent since.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>

#include "conn_int.h"

#define ECN_TEST_PACKETS 10

static void
set_state (gq_conn *c, enum gq_ecn_state st)
{
  enum gq_ecn_state old = (enum gq_ecn_state) c->ecn_state;

  if (old == st)
    return;
  c->ecn_state = (uint8_t) st;
  ql_ecn_state_updated (c, old, st);
}

static void
start_test (gq_conn *c)
{
  c->ecn_gen++;
  c->ecn_test_sent = c->ecn_test_ae = c->ecn_test_acked = 0;
  c->ecn_test_lost = 0;
  set_state (c, GQ_ECN_TESTING);
}

/* The connection goes to another path: test it afresh (section 13.4.2).  */
void
conn_ecn_restart (gq_conn *c)
{
  if (c->ecn_state != GQ_ECN_OFF)
    start_test (c);
}

/* Is the datagram of the N packets, in SPACES (EARLY: 0-RTT), for path DEST,
   to be marked?  The first one that could be starts the testing, for an
   application that takes part by calling gq_conn_send_ecn.  */
int
conn_ecn_marks (gq_conn *c, int dest, const int *spaces, const uint8_t *early,
                int n)
{
  int i;

  if (!c->tx_ecn_ok || dest != c->cur_path || c->state >= GQ_CONN_CLOSING)
    return 0;
  for (i = 0; i < n; i++)
    if (spaces[i] != SP_APP || early[i])
      return 0;
  if (c->ecn_state == GQ_ECN_OFF)
    start_test (c);
  return c->ecn_state == GQ_ECN_TESTING || c->ecn_state == GQ_ECN_CAPABLE;
}

/* One packet of ours, AE if ack-eliciting, went out marked.  Returns the
   generation to keep with it if it is tracked, else 0.  */
uint32_t
conn_ecn_sent (gq_conn *c, int ae)
{
  c->sp[SP_APP].ecn_sent++;
  c->ecn_marked_sent++;
  if (c->ecn_state == GQ_ECN_TESTING)
    {
      c->ecn_test_sent++;
      if (ae)
        c->ecn_test_ae++;
    }
  return ae ? c->ecn_gen : 0;
}

/* The datagram is out: ten marked packets end the testing.  */
void
conn_ecn_datagram_sent (gq_conn *c)
{
  if (c->ecn_state == GQ_ECN_TESTING && c->ecn_test_sent >= ECN_TEST_PACKETS)
    set_state (c, GQ_ECN_UNKNOWN);
}

/* If every marked packet of the test that could be followed is lost and none
   got through, the path drops them.  */
static void
check_all_lost (gq_conn *c)
{
  if (c->ecn_state == GQ_ECN_UNKNOWN && c->ecn_test_acked == 0
      && c->ecn_test_ae > 0 && c->ecn_test_lost >= c->ecn_test_ae)
    set_state (c, GQ_ECN_FAILED);
}

/* A packet of ours that was marked has been declared lost.  A packet that
   was not does not count against the path.  */
void
conn_ecn_lost (gq_conn *c, const sent_pkt *p)
{
  if (p->ecn_gen == 0 || p->ecn_gen != c->ecn_gen)
    return;
  c->ecn_test_lost++;
  check_all_lost (c);
}

/* An ACK frame F for the application space has newly acknowledged the N
   packets GOT.  The counts it carries must be those of the packets we
   marked (RFC 9000 section 13.4.2.1):

     - present, if any newly acknowledged packet was marked;
     - never less than before;
     - the ECT(0) and CE increase together at least as many as the marked
       packets newly acknowledged, as each is counted by the peer when it
       is processed;
     - no ECT(1) at all, as none was sent, and in all no more of ECT(0) and
       CE than there were marked packets.

   A failure ends the marking.  An increase in the CE count of a path that
   passes is congestion (RFC 9002 section 7.1).  */
void
conn_ecn_on_ack (gq_conn *c, int sp, const gq_frame *f, const sent_pkt *got,
                 size_t n, uint64_t now)
{
  space *s = &c->sp[SP_APP];
  uint64_t marked = 0, current = 0, d0, d1, dce, sent_us;
  size_t i;

  if (sp != SP_APP || c->ecn_state == GQ_ECN_OFF)
    return;
  /* Only an ACK frame that moves the largest on counts: an older one may
     carry the counts of an earlier time.  */
  if (s->ecn_have_largest && f->u.ack.largest <= s->ecn_largest)
    return;
  s->ecn_largest = f->u.ack.largest;
  s->ecn_have_largest = 1;
  for (i = 0; i < n; i++)
    if (got[i].ecn_gen)
      {
        marked++;
        if (got[i].ecn_gen == c->ecn_gen)
          current++;
      }
  if (c->ecn_state == GQ_ECN_FAILED)
    {
      if (f->u.ack.has_ecn)
        {
          s->ecn_peer[0] = f->u.ack.ect0;
          s->ecn_peer[1] = f->u.ack.ect1;
          s->ecn_peer[2] = f->u.ack.ecn_ce;
        }
      return;
    }
  if (!f->u.ack.has_ecn)
    {
      if (marked)
        set_state (c, GQ_ECN_FAILED);
      return;
    }
  if (f->u.ack.ect0 < s->ecn_peer[0] || f->u.ack.ect1 < s->ecn_peer[1]
      || f->u.ack.ecn_ce < s->ecn_peer[2])
    {
      set_state (c, GQ_ECN_FAILED);
      return;
    }
  d0 = f->u.ack.ect0 - s->ecn_peer[0];
  d1 = f->u.ack.ect1 - s->ecn_peer[1];
  dce = f->u.ack.ecn_ce - s->ecn_peer[2];
  s->ecn_peer[0] = f->u.ack.ect0;
  s->ecn_peer[1] = f->u.ack.ect1;
  s->ecn_peer[2] = f->u.ack.ecn_ce;
  if (d0 + dce < marked || d1 > 0 || f->u.ack.ect1 > 0
      || f->u.ack.ect0 + f->u.ack.ecn_ce > s->ecn_sent)
    {
      set_state (c, GQ_ECN_FAILED);
      return;
    }
  if (current && c->ecn_state != GQ_ECN_CAPABLE)
    {
      c->ecn_test_acked += current;
      set_state (c, GQ_ECN_CAPABLE);
    }
  if (c->ecn_state != GQ_ECN_CAPABLE || dce == 0)
    return;
  /* Congestion experienced: a congestion event, sent at the time of the
     largest packet this ACK frame acknowledges, or if that is not one we
     kept, about a round trip ago.  Not persistent congestion (RFC 9002
     section 7.1): it is not loss.  */
  sent_us = n ? got[n - 1].time_us : (now > c->srtt ? now - c->srtt : 0);
  if (cong_on_congestion_event (&c->cc, sent_us, now))
    {
      c->congestion_events++;
      ql_cc_state (c, "ecn_ce");
    }
}
