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

/* White-box tests of the QUIC connection: the harness of test-conn.c, plus
   the connection's own structures, so that a test can seal frames with one
   end's keys (as that end would, but of its choosing) and look at what the
   other does with them.  Things a well-behaved peer never sends, and state
   that the public interface does not show.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

/* Most of the harness is for tests this file does not run.  */
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"
int test_conn_main (void);
#define main test_conn_main
#include "test-conn.c"
#undef main

#ifdef HAVE_GNUTLS

#include "../src/conn_int.h"

/* The spin bit forge puts in its packets, and the ECN field they arrive
   with.  */
static int forge_spin, forge_ecn;

/* Seal FR (N frames) as a 1-RTT packet from FROM to TO, with FROM's keys and
   next packet number.  FROM is not asked to send anything itself.  BAD flips
   a bit of the tag.  FROM_PATH, if not NULL, is where it appears to come
   from.  */
static void
forge (gq_conn *from, gq_conn *to, uint64_t now, const gq_path *from_path,
       const gq_frame *fr, size_t n, int bad)
{
  uint8_t pl[1100], pkt[1400];
  size_t len = 0, hdr = 0, out = 0, i, w;
  space *s = &from->sp[SP_APP];
  uint64_t pn = s->next_pn++;

  for (i = 0; i < n; i++)
    {
      CHECK_EQ (gq_frame_write (&fr[i], pl + len, sizeof pl - len, &w), GQ_OK);
      len += w;
    }
  while (len < 8)
    pl[len++] = 0;
  CHECK_EQ (gq_short_header_build (from->dcid.data, from->dcid.len,
                                   forge_spin, from->w_phase, pn, 4, pkt,
                                   sizeof pkt, &hdr), GQ_OK);
  memcpy (pkt + hdr, pl, len);
  CHECK_EQ (gq_packet_seal (&s->wk, pn, pkt, hdr - 4, 4, len, sizeof pkt,
                            &out), GQ_OK);
  if (bad)
    pkt[out - 1] ^= 1;
  gq_conn_recv_ecn (to, now, from_path, forge_ecn, pkt, out);
}

/* A connected pair, settled: nothing more to say on either side.  */
static struct pair *
settled_pair (const gq_conn_config *cc, const gq_conn_config *sc)
{
  struct pair *p = pair_new (cc, sc, 0, 1);

  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 3000000);
  return p;
}

/* No path (and not the current ID) names a peer connection ID that has been
   retired.  */
static void
check_no_retired_cids (gq_conn *c)
{
  int k, i, found;

  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].seq == c->dcid_seq)
      CHECK (!c->p[i].retire);
  for (k = 0; k < MAX_PATHS; k++)
    {
      if (!c->paths[k].used || !c->paths[k].dcid.len)
        continue;
      found = 0;
      for (i = 0; i < MAX_PCID; i++)
        if (c->p[i].used && c->p[i].seq == c->paths[k].dcid_seq)
          {
            found = 1;
            CHECK (!c->p[i].retire);
          }
      CHECK (found);
    }
}

/* RFC 9000 section 5.1.2: when NEW_CONNECTION_ID retires the IDs we use, we
   stop using them, on every path we hold, not only the current one.  */
static void
test_retired_cid_on_all_paths (void)
{
  struct pair *p = settled_pair (NULL, NULL);
  gq_conn *c = p->cli.c, *s = p->srv.c;
  gq_frame f;
  gq_path other;
  uint64_t top = 0;
  int i, k, cands = 0;

  /* The server hears from a new address: a candidate path, with an ID of its
     own.  */
  memset (&other, 0, sizeof other);
  other.local = mkaddr ("S");
  other.remote = mkaddr ("home");
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_PING;
  forge (c, s, p->net.now, &other, &f, 1, 0);
  other.remote = mkaddr ("elsewhere");
  forge (c, s, p->net.now, &other, &f, 1, 0);
  for (k = 0; k < MAX_PATHS; k++)
    if (s->paths[k].used && k != s->cur_path)
      cands++;
  CHECK (cands >= 1);
  check_no_retired_cids (s);

  /* The client now retires everything it has issued so far.  */
  for (i = 0; i < MAX_PCID; i++)
    if (s->p[i].used && s->p[i].seq > top)
      top = s->p[i].seq;
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_NEW_CONNECTION_ID;
  f.u.new_connection_id.seq = top + 1;
  f.u.new_connection_id.retire_prior_to = top + 1;
  f.u.new_connection_id.cid_len = 8;
  memset (f.u.new_connection_id.cid, 0x77, 8);
  memset (f.u.new_connection_id.reset_token, 0x55, GQ_RESET_TOKEN_LEN);
  forge (c, s, p->net.now, NULL, &f, 1, 0);
  CHECK_EQ (s->state != GQ_CONN_DONE, 1);
  check_no_retired_cids (s);
  pair_free (p);
}

/* Datagrams CONN has to send now, and deliver them to PEER.  Returns how
   many.  */
static int
hand_over (gq_conn *conn, gq_conn *peer, uint64_t now, int deliver)
{
  uint8_t buf[2048];
  size_t len;
  int n = 0;

  for (;;)
    {
      CHECK_EQ (gq_conn_send_path (conn, now, buf, sizeof buf, &len, NULL),
                GQ_OK);
      if (len == 0)
        return n;
      n++;
      if (deliver)
        gq_conn_recv (peer, now, buf, len);
    }
}

/* RFC 9002 appendix A.7: the probe timeout backs off until the peer has
   completed address validation.  A client may not take an acknowledgement
   of its Initial for that, since the server could still be held by the
   amplification limit: only an acknowledgement of a Handshake packet, or
   a confirmed handshake, resets the backoff.  */
static void
test_pto_backoff_kept_until_validated (void)
{
  struct pair *p = pair_new (NULL, NULL, 0, 1);
  gq_conn *c = p->cli.c, *s = p->srv.c;
  uint64_t now = p->net.now;

  hand_over (c, s, now, 1);
  now += 20000;
  c->pto_count = 2;
  hand_over (s, c, now, 1);
  CHECK (!c->handshake_confirmed);
  CHECK_EQ (c->pto_count, 2);
  /* Once the exchange goes through to the end, it is reset.  The simulated
     network goes on from the time the connections have been given.  */
  p->net.now = now;
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 3000000);
  CHECK_EQ (c->pto_count, 0);
  CHECK_EQ (s->pto_count, 0);
  pair_free (p);
}

/* RFC 9002 section 7.6.2: persistent congestion is judged on packets sent
   after the first round trip sample; a handshake that lost its first
   flights to a blackout has measured nothing yet, and is not congested.  */
static void
test_blackout_is_not_persistent_congestion (void)
{
  struct pair *p = pair_new (NULL, NULL, 100, 1);

  run (&p->net, NULL, 4000000);
  CHECK (!p->cli.connected);
  p->net.loss_pct = 0;
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 2000000);
  CHECK (p->net.min_cwnd > CC_MIN_WINDOW);
  pair_free (p);
}

/* Send REQ bytes on a new stream of CLI (answered as the server is set to),
   and let it settle.  */
static void
traffic (struct pair *p)
{
  uint64_t id;
  struct sbuf *sb;

  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  sb = sb_get (&p->cli, id);
  sb->out_total = 10;
  sb->out_fin = 1;
  run (&p->net, NULL, 1000000);
}

/* RFC 9001 section 6.5: the keys of the previous phase are kept for no more
   than three probe timeouts after the first packet of the new one.  */
static void
test_previous_keys_expire (void)
{
  struct pair *p = settled_pair (NULL, NULL);
  gq_conn *s = p->srv.c;

  p->srv.respond = 100;
  traffic (p);
  CHECK_EQ (gq_conn_update_keys (p->cli.c, p->net.now), GQ_OK);
  traffic (p);
  CHECK_EQ (s->key_updates, 1);
  CHECK (s->have_rk_prev);
  /* Well past three timeouts, then something arrives.  */
  p->net.now += 5000000;
  traffic (p);
  CHECK (!s->have_rk_prev);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  pair_free (p);
}

/* RFC 9001 section 6.6: packets that fail authentication are counted for the
   whole connection, and past the integrity limit it is closed with
   AEAD_LIMIT_REACHED.  */
static void
test_integrity_limit (void)
{
  struct pair *p = settled_pair (NULL, NULL);
  gq_conn *c = p->cli.c, *s = p->srv.c;
  gq_frame f;
  uint64_t limit = s->sp[SP_APP].rk.aead == GQ_AEAD_CHACHA20_POLY1305
    ? (uint64_t) 1 << 36 : (uint64_t) 1 << 52;
  int i;

  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_PING;
  /* A few are no matter.  */
  for (i = 0; i < 3; i++)
    forge (c, s, p->net.now, NULL, &f, 1, 1);
  CHECK (s->state < GQ_CONN_CLOSING);
  s->aead_failed_sp[SP_APP] = limit - 1;
  forge (c, s, p->net.now, NULL, &f, 1, 1);
  CHECK (s->state >= GQ_CONN_CLOSING);
  run (&p->net, NULL, 3000000);
  CHECK_EQ (p->srv.closed, 1);
  CHECK_EQ (p->srv.ci.error, GQ_QERR_AEAD_LIMIT);
  pair_free (p);
}

/* ...and a key may not protect more packets than its confidentiality limit
   when no update can be had: close rather than go on.  */
static void
test_confidentiality_limit (void)
{
  struct pair *p = settled_pair (NULL, NULL);
  gq_conn *c = p->cli.c;
  uint64_t limit = c->sp[SP_APP].wk.aead == GQ_AEAD_CHACHA20_POLY1305
    ? (uint64_t) 1 << 62 : (uint64_t) 1 << 23;

  if (limit > ((uint64_t) 1 << 40))
    return;			/* Out of reach for a test.  */
  /* No update possible: the last one was never acknowledged.  */
  c->w_phase_acked = 0;
  c->sp[SP_APP].next_pn = c->w_first_pn + limit;
  traffic (p);
  CHECK_EQ (p->cli.closed, 1);
  CHECK_EQ (p->cli.ci.error, GQ_QERR_AEAD_LIMIT);
  pair_free (p);
}

/* RFC 9002 section 5.3: an ACK Delay above what the peer said it would
   need is not to be trusted, and one that does not fit is no delay at
   all.  A delay that wraps round must not look like a small one.  */
static void
test_huge_ack_delay (void)
{
  struct pair *p = settled_pair (NULL, NULL);
  gq_conn *c = p->cli.c, *s = p->srv.c;
  space *cs = &s->sp[SP_APP];
  gq_frame f;
  uint8_t rng[16];
  size_t rl = 0;
  gq_ack_range r;
  uint64_t before, largest;

  /* The server has data in flight that the client has not seen.  */
  p->cli.respond = 0;
  CHECK_EQ (gq_conn_stream_open (s, 1, &largest), GQ_OK);
  gq_conn_stream_write (s, largest, (const uint8_t *) "ping", 4);
  hand_over (s, c, p->net.now, 0);
  largest = cs->next_pn - 1;
  /* Before the handshake is confirmed the delay is not clamped.  */
  s->handshake_confirmed = 0;
  p->net.now += 400000;
  s->now = p->net.now;
  r.lo = r.hi = largest;
  CHECK_EQ (gq_ack_ranges_encode (&r, 1, rng, sizeof rng, &rl), GQ_OK);
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_ACK;
  f.u.ack.largest = largest;
  /* Times 2^3 this is 2^64 + 100 ms: it wraps to a plausible delay.  */
  f.u.ack.delay = ((uint64_t) 1 << 61) + 12500;
  f.u.ack.range_count = 0;
  f.u.ack.ranges.data = rng;
  f.u.ack.ranges.len = rl;
  before = s->srtt;
  forge (c, s, p->net.now, NULL, &f, 1, 0);
  /* Not subtracted: the sample is the whole round trip.  */
  CHECK_EQ (s->srtt, (7 * before + s->latest_rtt) / 8);
  pair_free (p);
}

/* RFC 9000 section 14.1: a server's datagram with an ack-eliciting Initial
   packet is at least 1200 bytes, and section 8.1: it sends no more than three
   times what it has received before the client is validated.  With less
   than a full datagram of credit left the Initial waits; it is not sent
   short, and the timer for it is not armed to no purpose (RFC 9002 section
   6.2.2.1).  */
/* RFC 9000 section 8.1: only datagrams from the unvalidated peer address
   count toward the send budget, not the same connection ID from elsewhere.  */
static void
test_amplification_ignores_wrong_source (void)
{
  struct pair *p = pair_new (NULL, NULL, 0, 1);
  gq_conn *c = p->cli.c, *s = p->srv.c;
  gq_path other;
  uint64_t now = p->net.now;
  uint64_t recv0;
  uint8_t buf[2048];
  size_t len;

  hand_over (c, s, now, 1);
  CHECK (!s->peer_addr_validated);
  recv0 = s->bytes_recv;
  CHECK (recv0 > 0);
  memset (&other, 0, sizeof other);
  other.local = s->paths[0].p.local;
  other.remote.len = s->paths[0].p.remote.len;
  memcpy (other.remote.data, s->paths[0].p.remote.data,
          other.remote.len);
  other.remote.data[other.remote.len - 1] ^= 0xff;
  now += 5000;
  for (;;)
    {
      CHECK_EQ (gq_conn_send_path (c, now, buf, sizeof buf, &len, NULL), GQ_OK);
      if (len == 0)
        break;
      gq_conn_recv_path (s, now, &other, buf, len);
    }
  CHECK_EQ (s->bytes_recv, recv0);
  pair_free (p);
}

static void
test_initial_waits_for_amplification_credit (void)
{
  struct pair *p = pair_new (NULL, NULL, 0, 1);
  gq_conn *c = p->cli.c, *s = p->srv.c;
  uint64_t now = p->net.now, t;
  uint8_t buf[2048];
  size_t len;
  int k, shorts = 0, initials = 0;
  unsigned itype;

  hand_over (c, s, now, 1);
  now += 10000;
  CHECK_EQ (gq_conn_send_path (s, now, buf, sizeof buf, &len, NULL), GQ_OK);
  CHECK (len >= GQ_MIN_INITIAL_DATAGRAM);
  /* An Initial is type 0 in version 1 and 1 in version 2.  */
  itype = s->version == GQ_VERSION_2 ? 1 : 0;
  /* Credit for 700 more bytes, and nothing more is heard.  */
  s->bytes_sent = 3 * s->bytes_recv - 700;
  for (k = 0; k < 30; k++)
    {
      t = gq_conn_timeout (s);
      if (t == 0)
        break;
      if (t > now)
        now = t;
      gq_conn_on_timeout (s, now);
      for (;;)
        {
          CHECK_EQ (gq_conn_send_path (s, now, buf, sizeof buf, &len, NULL),
                    GQ_OK);
          if (len == 0)
            break;
          if ((buf[0] & 0x80) && ((buf[0] >> 4) & 3) == itype)
            {
              initials++;
              if (len < GQ_MIN_INITIAL_DATAGRAM)
                shorts++;
            }
        }
      CHECK (s->bytes_sent <= 3 * s->bytes_recv);
    }
  CHECK_EQ (shorts, 0);
  (void) initials;
  pair_free (p);
}

/* With credit for less than any packet, there is nothing a probe could
   send, so no probe timer is set.  */
static void
test_no_probe_timer_without_credit (void)
{
  struct pair *p = pair_new (NULL, NULL, 0, 1);
  gq_conn *c = p->cli.c, *s = p->srv.c;
  uint64_t now = p->net.now, t;
  uint8_t buf[2048];
  size_t len;

  hand_over (c, s, now, 1);
  now += 10000;
  CHECK_EQ (gq_conn_send_path (s, now, buf, sizeof buf, &len, NULL), GQ_OK);
  s->bytes_sent = 3 * s->bytes_recv - 20;
  hand_over (s, c, now, 0);
  t = gq_conn_timeout (s);
  /* Only the idle timeout (or nothing) remains.  */
  CHECK (t == 0 || t >= s->idle_deadline);
  pair_free (p);
}

/* RFC 9001 section 6.1: the first key update waits for an acknowledgement
   of a packet sent under the current keys.  The packets of 0-RTT share the
   packet number space with 1-RTT, but not the keys: acknowledging one of
   them proves nothing about the 1-RTT keys.  */
static void
test_first_update_waits_for_a_1rtt_ack (void)
{
  gq_conn_config cc, sc;
  struct saved sv;
  struct pair *p;

  CHECK_EQ (gq_ticket_keys_new (&g_ring), GQ_OK);
  CHECK_EQ (gq_replay_cache_new (&g_replay, 1000), GQ_OK);
  g_early_server = 1;
  memset (&cc, 0, sizeof cc);
  memset (&sc, 0, sizeof sc);
  cc.version = sc.version = GQ_VERSION_1;
  get_session (&cc, &sc, 120, &sv);
  p = early_pair (&cc, &sc, 0, 121, &sv);
  start_transfer (p, 5000);
  CHECK (run (&p->net, transfer_done, 30000000));
  CHECK_EQ (p->cli.early_result, 1);
  /* Early packets used the first numbers: the 1-RTT keys start after.  */
  CHECK (p->cli.c->sp[SP_APP].next_pn > 1);
  CHECK (p->cli.c->w_first_pn > 0);
  pair_free (p);
  g_early_server = 0;
  gq_ticket_keys_free (g_ring);
  g_ring = NULL;
  gq_replay_cache_free (g_replay);
  g_replay = NULL;
}

/* RFC 9000 section 13.2.4: once an ACK frame has been acknowledged, packet
   numbers up to its largest need not be acknowledged again.  Lost packets
   leave gaps in what was received; without this they stay in every ACK frame
   for as long as the connection lasts.  */
static void
test_acked_acks_are_retired (void)
{
  struct pair *p = pair_new (NULL, NULL, 3, 7);
  int i, worst = 0;

  p->srv.respond = 60000;
  CHECK (run (&p->net, both_connected, 30000000));
  for (i = 0; i < 40; i++)
    {
      uint64_t id;
      struct sbuf *sb;

      if (gq_conn_stream_open (p->cli.c, 1, &id) != GQ_OK)
        {
          run (&p->net, NULL, 200000);
          continue;
        }
      sb = sb_get (&p->cli, id);
      sb->out_total = 10;
      sb->out_fin = 1;
      run (&p->net, NULL, 1000000);
    }
  run (&p->net, NULL, 3000000);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  worst = (int) p->cli.c->sp[SP_APP].recv.n;
  if ((int) p->srv.c->sp[SP_APP].recv.n > worst)
    worst = (int) p->srv.c->sp[SP_APP].recv.n;
  CHECK (worst <= 6);
  pair_free (p);
}

/* RFC 9002 section 7.6.2: persistent congestion is losses over a long enough
   period with nothing sent in it getting through, however many rounds of
   loss detection it takes to declare them lost.  */
static void
test_persistent_congestion_over_several_rounds (void)
{
  struct pair *p = settled_pair (NULL, NULL);
  gq_conn *s = p->srv.c;
  space *sp = &s->sp[SP_APP];
  sent_pkt k;
  uint64_t t0 = p->net.now, pto = 3 * conn_pto_base (s, SP_APP);
  int i;

  sp_sent_clear (s, SP_APP);
  s->first_rtt_us = 0;
  s->cc.cwnd = 100000;
  s->cc.recovery_start = 0;
  memset (&k, 0, sizeof k);
  k.size = 1200;
  k.ack_eliciting = k.in_flight = 1;
  /* pn 0 at t0 and pn 8 four periods later, both unacknowledged, with 9 and
     10 (acknowledged below) after them; 8 stays unlost until the time
     threshold passes.  */
  for (i = 0; i < 4; i++)
    {
      k.pn = i == 0 ? 0 : (uint64_t) (7 + i);
      k.time_us = i == 0 ? t0 : t0 + 4 * pto + (uint64_t) i;
      sp_sent_add (s, SP_APP, &k);
    }
  sp->have_acked = 1;
  sp->largest_acked = 10;
  /* Remove the acknowledged ones from the list, as an ACK would have.  */
  sp->n_sent -= 2;
  s->bytes_in_flight -= 2400;
  /* Round one: packet 0 is lost, by the packet threshold.  */
  s->latest_rtt = s->srtt = 20000;
  loss_detect (s, SP_APP, t0 + 4 * pto + 12);
  CHECK (s->cc.cwnd > CC_MIN_WINDOW);
  /* Round two, later: packet 8, sent four periods after it, is lost too.  */
  loss_detect (s, SP_APP, t0 + 4 * pto + 1000000);
  CHECK_EQ (s->cc.cwnd, CC_MIN_WINDOW);
  pair_free (p);
}

/* RFC 9000 section 3: a STREAM frame for a stream that is over (a late
   retransmission) is ignored; it does not open the stream again.  One for a
   stream of ours that we never opened is an error (section 19.8).  */
static void
test_stream_frames_after_the_end (void)
{
  struct pair *p = settled_pair (NULL, NULL);
  gq_conn *c = p->cli.c, *s = p->srv.c;
  gq_frame f;
  int opened;
  size_t got;

  p->srv.respond = 100;
  traffic (p);
  opened = p->srv.opened;
  got = p->srv.total_in;
  CHECK_EQ (opened, 1);
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_STREAM;
  f.u.stream.id = 0;
  f.u.stream.offset = 0;
  f.u.stream.data.data = (const uint8_t *) "late";
  f.u.stream.data.len = 4;
  forge (c, s, p->net.now, NULL, &f, 1, 0);
  CHECK_EQ (p->srv.opened, opened);
  CHECK_EQ (p->srv.total_in, got);
  CHECK (s->state < GQ_CONN_CLOSING);
  /* Stream 1 is the server's first: it was never opened.  */
  f.u.stream.id = 1;
  forge (c, s, p->net.now, NULL, &f, 1, 0);
  CHECK (s->state >= GQ_CONN_CLOSING);
  run (&p->net, NULL, 3000000);
  CHECK_EQ (p->cli.closed, 1);
  CHECK_EQ (p->cli.ci.error, GQ_QERR_STREAM_STATE);
  pair_free (p);
}

/* A datagram that looks like a stateless reset for TO: it carries one of
   TO's connection IDs (so that it is looked at at all), unpredictable bytes
   and the TOKEN at its end.  */
static size_t
reset_looking (uint8_t *out, const gq_conn *to, const uint8_t *token)
{
  size_t i, n = 0;

  for (i = 0; i < MAX_LCID; i++)
    if (to->l[i].used)
      break;
  out[n++] = 0x40 | 0x15;
  memcpy (out + n, to->l[i].cid.data, to->l[i].cid.len);
  n += to->l[i].cid.len;
  while (n < 60 - GQ_RESET_TOKEN_LEN)
    {
      out[n] = (uint8_t) (0x77 + n);
      n++;
    }
  memcpy (out + n, token, GQ_RESET_TOKEN_LEN);
  return n + GQ_RESET_TOKEN_LEN;
}

/* The peer connection ID in C that is not the one in use and is on no
   path: given to us, never used.  */
static pcid *
spare_pcid (gq_conn *c)
{
  size_t i;
  int k;

  for (i = 0; i < MAX_PCID; i++)
    {
      int on_path = 0;

      if (!c->p[i].used || !c->p[i].has_token || c->p[i].retire
          || c->p[i].seq == c->dcid_seq)
        continue;
      for (k = 0; k < MAX_PATHS; k++)
        if (c->paths[k].used && c->paths[k].dcid.len
            && c->paths[k].dcid_seq == c->p[i].seq)
          on_path = 1;
      if (!on_path)
        return &c->p[i];
    }
  return NULL;
}

/* RFC 9000 section 10.3.1: a datagram that ends in the token of an ID we use
   is a stateless reset; the tokens of IDs we have not used, or have retired,
   are not looked for.  Only the peer knows them, but a token that leaks (a
   server deriving them from a key, say) should be good for as little as the
   RFC allows.  */
static void
test_reset_tokens_of_unused_ids (void)
{
  struct pair *p;
  gq_conn *c;
  pcid *sp;
  uint8_t dg[128], token[GQ_RESET_TOKEN_LEN];
  size_t n, i;

  /* The ID in use: a reset.  */
  p = settled_pair (NULL, NULL);
  c = p->cli.c;
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].seq == c->dcid_seq)
      break;
  CHECK (i < MAX_PCID && c->p[i].has_token);
  n = reset_looking (dg, c, c->p[i].token);
  gq_conn_recv (c, p->net.now, dg, n);
  CHECK (c->state >= GQ_CONN_CLOSING);
  CHECK_EQ (p->cli.ci.source, GQ_CLOSE_RESET);
  pair_free (p);

  /* One we were given and have not used: not looked for.  */
  p = settled_pair (NULL, NULL);
  c = p->cli.c;
  sp = spare_pcid (c);
  CHECK (sp != NULL);
  memcpy (token, sp->token, sizeof token);
  n = reset_looking (dg, c, token);
  gq_conn_recv (c, p->net.now, dg, n);
  CHECK (c->state < GQ_CONN_CLOSING);
  /* One we retired: neither.  */
  sp->retire = 2;
  gq_conn_recv (c, p->net.now, dg, n);
  CHECK (c->state < GQ_CONN_CLOSING);
  /* The endpoint's route to the same decision: it names the token it found
     and the connection says whether that is a reset.  */
  CHECK_EQ (gq_conn_stateless_reset (c, p->net.now, token), 0);
  CHECK (c->state < GQ_CONN_CLOSING);
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].seq == c->dcid_seq)
      break;
  CHECK_EQ (gq_conn_stateless_reset (c, p->net.now, c->p[i].token), 1);
  CHECK (c->state >= GQ_CONN_CLOSING);
  pair_free (p);
}

/* A server Initial for client C, sealed with the Initial keys (which anyone
   can derive), carrying TOKEN_LEN bytes of token (RFC 9000 section 17.2.2: a
   server sends none).  Returns the datagram length.  */
static size_t
server_initial (gq_conn *c, uint8_t *out, size_t cap, size_t token_len)
{
  gq_packet_keys ck, sk;
  gq_cid cc[2];
  uint8_t token[16], scid[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
  size_t hdr, n, pn_off, len;

  CHECK_EQ (gq_conn_local_cids (c, cc, 2), 1);
  memset (token, 0x42, sizeof token);
  CHECK_EQ (gq_packet_keys_initial (c->version, c->initial_dcid.data,
                                    c->initial_dcid.len, &ck, &sk), GQ_OK);
  CHECK_EQ (gq_long_header_build (GQ_PKT_INITIAL, c->version, cc[0].data,
                                  cc[0].len, scid, sizeof scid,
                                  token_len ? token : NULL, token_len, 0, 1,
                                  40, out, cap, &hdr), GQ_OK);
  pn_off = hdr - 1;
  n = hdr;
  out[n++] = 0x01;			/* PING, then PADDING.  */
  memset (out + n, 0, 39);
  n += 39;
  CHECK_EQ (gq_packet_seal (&sk, 0, out, pn_off, 1, 40, cap, &len), GQ_OK);
  return len;
}

/* The same, carrying the frame F instead of a PING.  */
static size_t
server_initial_frame (gq_conn *c, uint8_t *out, size_t cap, const gq_frame *f)
{
  gq_packet_keys ck, sk;
  gq_cid cc[2];
  uint8_t scid[8] = { 9, 8, 7, 6, 5, 4, 3, 2 }, pl[64];
  size_t hdr, w = 0, len;

  CHECK_EQ (gq_conn_local_cids (c, cc, 2), 1);
  CHECK_EQ (gq_packet_keys_initial (c->version, c->initial_dcid.data,
                                    c->initial_dcid.len, &ck, &sk), GQ_OK);
  CHECK_EQ (gq_frame_write (f, pl, sizeof pl, &w), GQ_OK);
  memset (pl + w, 0, 40 - w);			/* PADDING.  */
  CHECK_EQ (gq_long_header_build (GQ_PKT_INITIAL, c->version, cc[0].data,
                                  cc[0].len, scid, sizeof scid, NULL, 0, 0, 1,
                                  40, out, cap, &hdr), GQ_OK);
  memcpy (out + hdr, pl, 40);
  CHECK_EQ (gq_packet_seal (&sk, 0, out, hdr - 1, 1, 40, cap, &len), GQ_OK);
  return len;
}

/* RFC 9000 section 12.5: an Initial or Handshake packet carries the
   transport kind of CONNECTION_CLOSE (0x1c), never the application kind
   (0x1d), which would give away the state of the application; section
   12.4: a frame in a packet type that may not carry it is a
   PROTOCOL_VIOLATION.  */
static void
test_application_close_in_initial (void)
{
  int application;

  for (application = 0; application < 2; application++)
    {
      struct pair *p = pair_new (NULL, NULL, 0, 1);
      gq_conn *c = p->cli.c;
      gq_frame f;
      uint8_t pkt[1500];
      size_t n;

      memset (&f, 0, sizeof f);
      f.type = GQ_FRAME_CONNECTION_CLOSE;
      f.u.connection_close.application = application;
      f.u.connection_close.error = 5;
      n = server_initial_frame (c, pkt, sizeof pkt, &f);
      gq_conn_recv (c, p->net.now, pkt, n);
      CHECK_EQ (p->cli.closed, 1);
      if (application)
        {
          /* Our own error, not the peer's close taken at its word.  */
          CHECK_EQ (p->cli.ci.source, GQ_CLOSE_LOCAL);
          CHECK_EQ (p->cli.ci.error, GQ_QERR_PROTOCOL_VIOLATION);
        }
      else
        {
          CHECK_EQ (p->cli.ci.source, GQ_CLOSE_PEER);
          CHECK_EQ (p->cli.ci.error, 5);
        }
      pair_free (p);
    }
}

/* A client discards what a server may not send it (RFC 9000 section 17.2.2:
   an Initial carrying a token; section 17.2.5.2: a Retry whose source ID is
   the destination ID of the Initial it answers), however well made.  */
static void
test_client_discards_bad_server_packets (void)
{
  struct pair *p;
  gq_conn *c;
  uint8_t pkt[1500], tok[16];
  gq_cid cc[2];
  size_t n, w;

  /* Control: the same Initial without a token is taken.  */
  p = pair_new (NULL, NULL, 0, 1);
  c = p->cli.c;
  n = server_initial (c, pkt, sizeof pkt, 0);
  gq_conn_recv (c, p->net.now, pkt, n);
  CHECK_EQ (c->st.packets_received, 1);
  CHECK (c->state < GQ_CONN_CLOSING);
  pair_free (p);

  /* With a token it is not.  */
  p = pair_new (NULL, NULL, 0, 1);
  c = p->cli.c;
  n = server_initial (c, pkt, sizeof pkt, 16);
  gq_conn_recv (c, p->net.now, pkt, n);
  CHECK_EQ (c->st.packets_received, 0);
  CHECK (c->state < GQ_CONN_CLOSING);
  pair_free (p);

  /* Retry: a proper one is taken (control).  */
  p = pair_new (NULL, NULL, 0, 1);
  c = p->cli.c;
  CHECK_EQ (gq_conn_local_cids (c, cc, 2), 1);
  memset (tok, 0x33, sizeof tok);
  {
    uint8_t scid[8] = { 1, 1, 2, 2, 3, 3, 4, 4 };

    CHECK_EQ (gq_retry_build (c->version, cc[0].data, cc[0].len, scid, 8, tok,
                              sizeof tok, c->initial_dcid.data,
                              c->initial_dcid.len, 0, pkt, sizeof pkt, &w),
              GQ_OK);
    gq_conn_recv (c, p->net.now, pkt, w);
    CHECK_EQ (c->retried, 1);
  }
  pair_free (p);

  /* One naming the client's own destination ID as its source is not.  */
  p = pair_new (NULL, NULL, 0, 1);
  c = p->cli.c;
  CHECK_EQ (gq_conn_local_cids (c, cc, 2), 1);
  CHECK_EQ (gq_retry_build (c->version, cc[0].data, cc[0].len,
                            c->initial_dcid.data, c->initial_dcid.len, tok,
                            sizeof tok, c->initial_dcid.data,
                            c->initial_dcid.len, 0, pkt, sizeof pkt, &w),
            GQ_OK);
  gq_conn_recv (c, p->net.now, pkt, w);
  CHECK_EQ (c->retried, 0);
  pair_free (p);
}

/* RFC 9000 section 19.15: an endpoint whose packets go to a zero-length
   connection ID has no ID to retire or switch, so a NEW_CONNECTION_ID from
   that peer is a PROTOCOL_VIOLATION.  */
static void
test_new_cid_to_zero_length_peer (void)
{
  struct pair *p = settled_pair (NULL, NULL);
  gq_conn *c = p->cli.c, *s = p->srv.c;
  gq_frame f;

  /* Ordinary, with an ID to send to: taken.  */
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_NEW_CONNECTION_ID;
  f.u.new_connection_id.seq = 40;
  f.u.new_connection_id.retire_prior_to = 40;	/* Room for it.  */
  f.u.new_connection_id.cid_len = 8;
  memset (f.u.new_connection_id.cid, 0x44, 8);
  memset (f.u.new_connection_id.reset_token, 0x45, GQ_RESET_TOKEN_LEN);
  forge (s, c, p->net.now, NULL, &f, 1, 0);
  CHECK (c->state < GQ_CONN_CLOSING);
  /* The peer is one with a zero-length ID.  */
  c->dcid.len = 0;
  f.u.new_connection_id.seq = 41;
  f.u.new_connection_id.retire_prior_to = 41;
  forge (s, c, p->net.now, NULL, &f, 1, 0);
  CHECK (c->state >= GQ_CONN_CLOSING);
  pair_free (p);
}

/* A client given no path takes the server's address from the first
   datagram it receives.  One datagram from anywhere, which no packet in it
   could be unprotected, must not decide that: the server's own first packet
   would then come from the wrong address and be ignored.  */
static void
test_client_path_not_set_by_garbage (void)
{
  struct pair *p = pair_new (NULL, NULL, 0, 1);
  gq_conn *c = p->cli.c;
  gq_path forged, server;
  uint8_t junk[200], pkt[1500];
  size_t n;

  memset (&forged, 0, sizeof forged);
  memset (&server, 0, sizeof server);
  forged.local.len = server.local.len = 6;
  memcpy (forged.local.data, "\x0a\x00\x00\x01\x1f\x90", 6);
  memcpy (server.local.data, "\x0a\x00\x00\x01\x1f\x90", 6);
  forged.remote.len = server.remote.len = 6;
  memcpy (forged.remote.data, "\xc6\x33\x64\x09\x00\x50", 6);
  memcpy (server.remote.data, "\x0a\x00\x00\x02\x01\xbb", 6);
  memset (junk, 0x5a, sizeof junk);
  junk[0] = 0xc0;			/* Looks long-headed, and is nothing.  */
  gq_conn_recv_path (c, p->net.now, &forged, junk, sizeof junk);
  CHECK_EQ (c->st.packets_received, 0);
  n = server_initial (c, pkt, sizeof pkt, 0);
  gq_conn_recv_path (c, p->net.now, &server, pkt, n);
  CHECK_EQ (c->st.packets_received, 1);
  pair_free (p);
}

/* RFC 9001 section 6.6: packets that fail authentication are counted
   against the integrity limit across all keys, 0-RTT ones included.  */
static void
test_early_failures_are_counted (void)
{
  gq_conn_config cc, sc;
  struct saved sv;
  struct pair *p;
  uint8_t d[4][2048];
  size_t dl[4], n = 0, k;
  int idx = -1;

  CHECK_EQ (gq_ticket_keys_new (&g_ring), GQ_OK);
  CHECK_EQ (gq_replay_cache_new (&g_replay, 100), GQ_OK);
  g_early_server = 1;
  memset (&cc, 0, sizeof cc);
  memset (&sc, 0, sizeof sc);
  cc.version = GQ_VERSION_1;
  sc.version = GQ_VERSION_1;
  get_session (&cc, &sc, 130, &sv);
  p = early_pair (&cc, &sc, 0, 131, &sv);
  start_transfer (p, 100);
  pump (&p->cli);
  while (n < 4)
    {
      size_t l = 0;

      CHECK_EQ (gq_conn_send (p->cli.c, p->net.now, d[n], sizeof d[n], &l),
                GQ_OK);
      if (l == 0)
        break;
      dl[n++] = l;
    }
  /* The datagram whose last packet is 0-RTT.  */
  for (k = 0; k < n; k++)
    {
      size_t off = 0;
      enum gq_packet_type last = 0;

      while (off < dl[k] && (d[k][off] & 0x80))
        {
          gq_long_header h;

          if (gq_long_header_parse (d[k] + off, dl[k] - off, &h) != GQ_OK)
            break;
          last = h.type;
          off += h.packet_len;
        }
      if (last == GQ_PKT_ZERO_RTT)
        idx = (int) k;
    }
  CHECK (idx >= 0);
  if (idx >= 0)
    {
      for (k = 0; k < (size_t) idx; k++)
        gq_conn_recv (p->srv.c, p->net.now, d[k], dl[k]);
      CHECK_EQ (p->srv.c->aead_failed_sp[SP_APP], 0);
      d[idx][dl[idx] - 1] ^= 1;		/* The tag of the 0-RTT packet.  */
      gq_conn_recv (p->srv.c, p->net.now, d[idx], dl[idx]);
      CHECK_EQ (p->srv.c->aead_failed_sp[SP_APP], 1);
    }
  pair_free (p);
  g_early_server = 0;
  gq_ticket_keys_free (g_ring);
  g_ring = NULL;
  gq_replay_cache_free (g_replay);
  g_replay = NULL;
}

/* Events of K that mention a stateless reset token anywhere.  */
static size_t
token_mentions (const struct qsink *k)
{
  size_t j, n = 0;

  for (j = 0; j < k->n; j++)
    if (strstr (k->e[j].fields, "stateless_reset_token"))
      n++;
  return n;
}

/* RFC 9000 section 10.3.2: reset tokens are secrets, and the log of a
   connection (the transport parameters, NEW_CONNECTION_ID frames, the
   preferred address) is shipped and pasted into bug reports.  Not logged,
   unless the bytes of frames are asked for, as for the other secrets.  */
static void
test_qlog_reset_tokens_are_opt_in (void)
{
  gq_conn_config cc;
  struct pair *p;
  size_t seen;

  memset (&cc, 0, sizeof cc);
  p = pair_new (&cc, &cc, 0, 1);
  p->qlog_sink[0].keep = p->qlog_sink[1].keep = 1;
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 3000000);
  CHECK (p->qlog_sink[0].n > 10 && p->qlog_sink[1].n > 10);
  CHECK_EQ (token_mentions (&p->qlog_sink[0]), 0);
  CHECK_EQ (token_mentions (&p->qlog_sink[1]), 0);
  pair_free (p);

  cc.qlog_raw = 16;
  p = pair_new (&cc, &cc, 0, 1);
  p->qlog_sink[0].keep = p->qlog_sink[1].keep = 1;
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 3000000);
  seen = token_mentions (&p->qlog_sink[0]) + token_mentions (&p->qlog_sink[1]);
  CHECK (seen > 0);
  pair_free (p);
}

/* Flow control limits are varints, 62 bits at most (RFC 9000 section 16): a
   window configured beyond that cannot be advertised.  It is clamped, and
   the connection works.  */
static void
test_flow_windows_are_clamped (void)
{
  gq_conn_config cc;
  struct pair *p;
  const uint64_t max62 = (UINT64_C (1) << 62) - 1;

  memset (&cc, 0, sizeof cc);
  cc.initial_max_data = UINT64_MAX;
  cc.initial_max_stream_data = UINT64_MAX;
  cc.initial_max_streams_bidi = UINT64_MAX;
  cc.initial_max_streams_uni = UINT64_MAX;
  p = pair_new (&cc, &cc, 0, 1);
  CHECK (run (&p->net, both_connected, 30000000));
  CHECK (p->cli.c->cfg.initial_max_data <= max62);
  CHECK (p->cli.c->cfg.initial_max_stream_data <= max62);
  CHECK (p->srv.c->max_data_peer <= max62);
  CHECK (p->srv.c->cfg.initial_max_streams_bidi <= ((uint64_t) 1 << 60));
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  pair_free (p);
}

/* Idle timeouts are milliseconds on the wire and microseconds here.  A peer
   that sends 18446744073709552 ms (not above the 62 bits a varint holds)
   multiplied by 1000 wraps to 384 microseconds: it must not shorten our
   timeout to that, nor may a deadline wrap round.  */
static void
test_idle_timeout_does_not_wrap (void)
{
  gq_conn_config sc;
  struct pair *p;
  gq_conn c;

  memset (&sc, 0, sizeof sc);
  sc.idle_timeout_ms = UINT64_C (18446744073709552);
  p = pair_new (NULL, &sc, 0, 1);
  CHECK (run (&p->net, both_connected, 30000000));
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  /* The client's own, 30 seconds, is the shorter.  */
  CHECK_EQ (p->cli.c->idle_timeout_us, UINT64_C (30000000));
  /* And that of the server, whose setting wrapped on the way, is not tiny.  */
  CHECK (p->srv.c->idle_timeout_us >= UINT64_C (30000000));
  pair_free (p);

  memset (&c, 0, sizeof c);
  c.idle_timeout_us = UINT64_MAX;
  conn_recompute_idle (&c, UINT64_C (1) << 63);
  CHECK (c.idle_deadline >= UINT64_C (1) << 63);
}

/* As forge, with the payload given as bytes.  */
static void
forge_raw (gq_conn *from, gq_conn *to, uint64_t now, const uint8_t *payload,
           size_t plen)
{
  uint8_t pl[1100], pkt[1400];
  size_t len = plen, hdr = 0, out = 0;
  space *s = &from->sp[SP_APP];
  uint64_t pn = s->next_pn++;

  memcpy (pl, payload, plen);
  while (len < 8)
    pl[len++] = 0;
  CHECK_EQ (gq_short_header_build (from->dcid.data, from->dcid.len, 0,
                                   from->w_phase, pn, 4, pkt, sizeof pkt,
                                   &hdr), GQ_OK);
  memcpy (pkt + hdr, pl, len);
  CHECK_EQ (gq_packet_seal (&s->wk, pn, pkt, hdr - 4, 4, len, sizeof pkt,
                            &out), GQ_OK);
  gq_conn_recv (to, now, pkt, out);
}

/* A STREAM frame of LEN bytes of what the test applications expect on
   stream ID at OFF (they check what they are given).  */
static gq_frame
f_stream (uint64_t id, uint64_t off, size_t len, int fin)
{
  static uint8_t data[8][64];
  static unsigned next;
  uint8_t *d = data[next++ % 8];
  size_t i;
  gq_frame f;

  for (i = 0; i < len && i < 64; i++)
    d[i] = pat (id, off + i);
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_STREAM;
  f.u.stream.id = id;
  f.u.stream.offset = off;
  f.u.stream.data.data = d;
  f.u.stream.data.len = len;
  f.u.stream.fin = fin;
  return f;
}

static gq_frame
f_reset (uint64_t id, uint64_t final_size)
{
  gq_frame f;

  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_RESET_STREAM;
  f.u.reset_stream.id = id;
  f.u.reset_stream.error = 1;
  f.u.reset_stream.final_size = final_size;
  return f;
}

/* Send FR (N frames) from a settled client to a settled server.  EXPECT is
   the transport error code the client then learns the server closed with,
   or -1 if the server is to carry on.  */
static void
violation_cfg (const gq_frame *fr, size_t n, int expect,
               const gq_conn_config *scfg)
{
  struct pair *p = settled_pair (NULL, scfg);

  forge (p->cli.c, p->srv.c, p->net.now, NULL, fr, n, 0);
  if (expect < 0)
    {
      CHECK (p->srv.c->state < GQ_CONN_CLOSING);
    }
  else
    {
      CHECK (p->srv.c->state >= GQ_CONN_CLOSING);
      run (&p->net, NULL, 3000000);
      CHECK_EQ (p->cli.closed, 1);
      CHECK_EQ (p->cli.ci.source, GQ_CLOSE_PEER);
      CHECK_EQ (p->cli.ci.application, 0);
      CHECK_EQ ((int) p->cli.ci.error, expect);
    }
  pair_free (p);
}

static void
violation (const gq_frame *fr, size_t n, int expect)
{
  violation_cfg (fr, n, expect, NULL);
}

static void
violation_raw (const char *hex, int expect)
{
  struct pair *p = settled_pair (NULL, NULL);
  uint8_t pl[64];
  size_t n = tst_unhex (hex, pl, sizeof pl);

  forge_raw (p->cli.c, p->srv.c, p->net.now, pl, n);
  CHECK (p->srv.c->state >= GQ_CONN_CLOSING);
  run (&p->net, NULL, 3000000);
  CHECK_EQ (p->cli.closed, 1);
  CHECK_EQ ((int) p->cli.ci.error, expect);
  pair_free (p);
}

/* What a peer may not do with streams and credit (RFC 9000 sections 4 and
   19), as the wire says it, each ending the connection with the right
   error and nothing else.  The defaults are 100 streams of each kind,
   256 KiB per stream and 1 MiB in all.  */
static void
test_stream_and_credit_violations (void)
{
  gq_frame f[5];

  /* Streams: the last one of the limit is fine, the next is not.  The
     server here allows three of each kind (ids 0, 4, 8 and 2, 6, 10); the
     test applications look at every stream the server opens, so a limit of
     a hundred is checked only beyond it.  */
  {
    gq_conn_config sc;

    memset (&sc, 0, sizeof sc);
    sc.initial_max_streams_bidi = 3;
    sc.initial_max_streams_uni = 3;
    f[0] = f_stream (8, 0, 5, 0);
    f[1] = f_stream (10, 0, 5, 0);
    violation_cfg (f, 2, -1, &sc);
    f[0] = f_stream (12, 0, 5, 0);
    violation_cfg (f, 1, GQ_QERR_STREAM_LIMIT, &sc);
    f[0] = f_stream (14, 0, 5, 0);
    violation_cfg (f, 1, GQ_QERR_STREAM_LIMIT, &sc);
  }
  f[0] = f_stream (400, 0, 5, 0);
  violation (f, 1, GQ_QERR_STREAM_LIMIT);
  f[0] = f_stream (402, 0, 5, 0);
  violation (f, 1, GQ_QERR_STREAM_LIMIT);

  /* Frames a stream's direction does not allow.  Stream 3 is the server's
     unidirectional: the client cannot send on it.  Stream 2 is the
     client's own: the server never sends on it.  Stream 1 is the server's,
     never opened.  */
  f[0] = f_stream (3, 0, 5, 0);
  violation (f, 1, GQ_QERR_STREAM_STATE);
  f[0] = f_reset (3, 0);
  violation (f, 1, GQ_QERR_STREAM_STATE);
  memset (&f[0], 0, sizeof f[0]);
  f[0].type = GQ_FRAME_STREAM_DATA_BLOCKED;
  f[0].u.stream_data_blocked.id = 3;
  f[0].u.stream_data_blocked.limit = 5;
  violation (f, 1, GQ_QERR_STREAM_STATE);
  memset (&f[0], 0, sizeof f[0]);
  f[0].type = GQ_FRAME_STOP_SENDING;
  f[0].u.stop_sending.id = 2;
  violation (f, 1, GQ_QERR_STREAM_STATE);
  memset (&f[0], 0, sizeof f[0]);
  f[0].type = GQ_FRAME_MAX_STREAM_DATA;
  f[0].u.max_stream_data.id = 2;
  f[0].u.max_stream_data.max = 1000;
  violation (f, 1, GQ_QERR_STREAM_STATE);
  f[0] = f_stream (1, 0, 5, 0);
  violation (f, 1, GQ_QERR_STREAM_STATE);

  /* Credit.  The last byte of a stream's 256 KiB is fine, the next is not.  */
  f[0] = f_stream (0, 262143, 1, 0);
  violation (f, 1, -1);
  f[0] = f_stream (0, 262144, 1, 0);
  violation (f, 1, GQ_QERR_FLOW_CONTROL);
  /* Four streams at their limit use the connection's 1 MiB; a fifth byte,
     on any stream, is past it.  */
  f[0] = f_stream (0, 262143, 1, 0);
  f[1] = f_stream (4, 262143, 1, 0);
  f[2] = f_stream (8, 262143, 1, 0);
  f[3] = f_stream (12, 262143, 1, 0);
  violation (f, 4, -1);
  f[4] = f_stream (16, 0, 1, 0);
  violation (f, 5, GQ_QERR_FLOW_CONTROL);
  /* A reset counts the final size against the credit as well.  */
  f[0] = f_reset (0, 262145);
  violation (f, 1, GQ_QERR_FLOW_CONTROL);

  /* Final sizes (RFC 9000 section 4.5).  */
  f[0] = f_stream (0, 0, 10, 1);
  f[1] = f_stream (0, 10, 1, 0);		/* Data past the end.  */
  violation (f, 2, GQ_QERR_FINAL_SIZE);
  f[0] = f_stream (0, 0, 10, 0);
  f[1] = f_stream (0, 0, 5, 1);			/* An end before data seen.  */
  violation (f, 2, GQ_QERR_FINAL_SIZE);
  f[0] = f_stream (0, 0, 10, 1);
  f[1] = f_reset (0, 5);			/* Another final size.  */
  violation (f, 2, GQ_QERR_FINAL_SIZE);
  f[0] = f_reset (0, 10);
  f[1] = f_reset (0, 11);
  violation (f, 2, GQ_QERR_FINAL_SIZE);
  f[0] = f_stream (0, 0, 10, 1);
  f[1] = f_stream (0, 0, 10, 1);		/* The same, again: fine.  */
  violation (f, 2, -1);

  /* Frames that are not valid, or not allowed here.  */
  violation_raw ("12""d000000000000001", GQ_QERR_FRAME_ENCODING);	/* 2^60+1 */
  violation_raw ("1f", GQ_QERR_FRAME_ENCODING);			/* Unknown.  */
  violation_raw ("0600""40ff", GQ_QERR_FRAME_ENCODING);	/* Cut off.  */
  violation_raw ("0e0000""ff", GQ_QERR_FRAME_ENCODING);
  violation_raw ("4001", GQ_QERR_FRAME_ENCODING);	/* Non-minimal PING.  */
  /* A DATAGRAM when the server asked for none.  */
  memset (&f[0], 0, sizeof f[0]);
  f[0].type = GQ_FRAME_DATAGRAM;
  f[0].u.datagram.data.data = (const uint8_t *) "abc";
  f[0].u.datagram.data.len = 3;
  violation (f, 1, GQ_QERR_PROTOCOL_VIOLATION);
  /* An ACK for a packet the server has not sent.  */
  {
    static const uint8_t first_range[1] = { 0 };

    memset (&f[0], 0, sizeof f[0]);
    f[0].type = GQ_FRAME_ACK;
    f[0].u.ack.largest = 1000000;
    f[0].u.ack.ranges.data = first_range;
    f[0].u.ack.ranges.len = 1;
    violation (f, 1, GQ_QERR_PROTOCOL_VIOLATION);
  }
}

/* RFC 9000 section 19.16: RETIRE_CONNECTION_ID for a sequence number we have
   not sent is a PROTOCOL_VIOLATION.  An ID is minted (and counted) when its
   predecessor is retired, before its NEW_CONNECTION_ID is on the wire, so
   accepting a retirement of that one lets a peer chain retirements through
   IDs it was never given, each mint costing us random bytes and callbacks.  */
static void
test_retire_of_unsent_cid (void)
{
  struct pair *p = settled_pair (NULL, NULL);
  gq_conn *c = p->cli.c, *s = p->srv.c;
  gq_frame f;
  uint64_t unsent;

  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_RETIRE_CONNECTION_ID;
  /* An ID we gave out and the client is not using (it addresses us by the
     first): retiring it is fine, and mints a replacement that has not been
     sent yet.  */
  f.u.retire_connection_id.seq = 3;
  forge (c, s, p->net.now, NULL, &f, 1, 0);
  CHECK (s->state < GQ_CONN_CLOSING);
  unsent = s->next_lseq - 1;
  CHECK (unsent > 0);
  /* Retiring the one nobody has been told of is an error.  */
  f.u.retire_connection_id.seq = unsent;
  forge (c, s, p->net.now, NULL, &f, 1, 0);
  CHECK (s->state >= GQ_CONN_CLOSING);
  run (&p->net, NULL, 3000000);
  CHECK_EQ (p->cli.closed, 1);
  CHECK_EQ (p->cli.ci.error, GQ_QERR_PROTOCOL_VIOLATION);
  pair_free (p);

  /* A chain of them in one packet stops at the first.  */
  p = settled_pair (NULL, NULL);
  c = p->cli.c;
  s = p->srv.c;
  {
    gq_frame fr[8];
    uint64_t first = s->next_lseq;
    size_t k;

    memset (fr, 0, sizeof fr);
    for (k = 0; k < 8; k++)
      {
        fr[k].type = GQ_FRAME_RETIRE_CONNECTION_ID;
        fr[k].u.retire_connection_id.seq = k == 0 ? 0 : first + k - 1;
      }
    forge (c, s, p->net.now, NULL, fr, 8, 0);
    CHECK (s->state >= GQ_CONN_CLOSING);
    /* Only the replacement for the one legitimate retirement was minted.  */
    CHECK_EQ (s->next_lseq, first + 1);
  }
  pair_free (p);
}

/* An Initial whose Length field is too small to hold a header protection
   sample cannot be unprotected, and anyone who has seen the connection IDs
   (they are in the clear) can send one.  RFC 9000 section 12.2 and RFC 9001
   section 5.4: it is discarded; it must not close the connection.  */
static size_t
tiny_initial (uint8_t *out, uint32_t version, const uint8_t *dcid,
              size_t dcid_len, const uint8_t *scid, size_t scid_len,
              unsigned length)
{
  size_t n = 0;

  out[n++] = version == GQ_VERSION_2 ? 0xd0 : 0xc0;
  out[n++] = (uint8_t) (version >> 24);
  out[n++] = (uint8_t) (version >> 16);
  out[n++] = (uint8_t) (version >> 8);
  out[n++] = (uint8_t) version;
  out[n++] = (uint8_t) dcid_len;
  memcpy (out + n, dcid, dcid_len);
  n += dcid_len;
  out[n++] = (uint8_t) scid_len;
  memcpy (out + n, scid, scid_len);
  n += scid_len;
  out[n++] = 0;			/* No token.  */
  out[n++] = (uint8_t) length;	/* Under 64: one byte.  */
  memset (out + n, 0x5a, length);
  return n + length;
}

static void
test_tiny_long_packets_are_dropped (void)
{
  struct pair *p = pair_new (NULL, NULL, 0, 1);
  gq_conn *c = p->cli.c, *s = p->srv.c;
  uint8_t pkt[256], first[2048];
  gq_cid ccid[4];
  size_t n, flen = 0;
  unsigned len;
  uint8_t fake_scid[8] = { 9, 9, 9, 9, 9, 9, 9, 9 };

  CHECK_EQ (gq_conn_local_cids (c, ccid, 4), 1);
  /* Client, before the server has said anything.  */
  for (len = 1; len < 20; len++)
    {
      n = tiny_initial (pkt, gq_conn_version (c), ccid[0].data, ccid[0].len,
                        fake_scid, sizeof fake_scid, len);
      gq_conn_recv (c, p->net.now, pkt, n);
      CHECK (c->state < GQ_CONN_CLOSING);
      CHECK_EQ (p->cli.closed, 0);
    }
  /* Server, once the client's Initial has started it.  */
  CHECK_EQ (gq_conn_send (c, p->net.now, first, sizeof first, &flen), GQ_OK);
  CHECK (flen >= GQ_MIN_INITIAL_DATAGRAM);
  gq_conn_recv (s, p->net.now, first, flen);
  CHECK (s->state < GQ_CONN_CLOSING);
  for (len = 1; len < 20; len++)
    {
      n = tiny_initial (pkt, gq_conn_version (s), s->initial_dcid.data,
                        s->initial_dcid.len, ccid[0].data, ccid[0].len, len);
      gq_conn_recv (s, p->net.now, pkt, n);
      CHECK (s->state < GQ_CONN_CLOSING);
      CHECK_EQ (p->srv.closed, 0);
    }
  pair_free (p);
}

/* RFC 9000 section 14.1: the datagram of a server's first flight is padded to
   1200 bytes.  */
static void
test_server_first_flight_padded (void)
{
  struct pair *p = pair_new (NULL, NULL, 0, 1);
  uint8_t buf[2048];
  size_t len;

  hand_over (p->cli.c, p->srv.c, p->net.now, 1);
  CHECK_EQ (gq_conn_send_path (p->srv.c, p->net.now + 5000, buf, sizeof buf,
                               &len, NULL), GQ_OK);
  CHECK (len >= GQ_MIN_INITIAL_DATAGRAM);
  pair_free (p);
}

/* The packets of a datagram: for each, its size and whether its header is
   long.  Returns how many; a short header packet runs to the end.  */
static int
datagram_packets (const uint8_t *d, size_t len, size_t *size, int *is_long,
                  int max)
{
  size_t off = 0;
  int n = 0;

  while (off < len && n < max)
    {
      size_t used = len - off;
      gq_long_header h;

      is_long[n] = (d[off] & 0x80) != 0;
      if (is_long[n])
        {
          CHECK_EQ (gq_long_header_parse (d + off, len - off, &h), GQ_OK);
          used = h.packet_len;
        }
      size[n++] = used;
      off += used;
    }
  return n;
}

/* RFC 9000 section 14.1 only asks for the datagram to be 1200 bytes.  The
   interop runner's 0-RTT test counts the client's 1-RTT payload, PADDING
   included, so the padding of the client's third flight (Initial ACK,
   Handshake Finished and the first 1-RTT packet in one datagram) goes in
   the Initial packet, which no one counts, and not in the 1-RTT one.  */
static void
test_padding_not_in_1rtt (void)
{
  struct pair *p = pair_new (NULL, NULL, 0, 1);
  gq_conn *c = p->cli.c, *s = p->srv.c;
  uint64_t now = p->net.now;
  uint8_t buf[2048];
  size_t len, size[8];
  int is_long[8], n, k, found = 0;

  hand_over (c, s, now, 1);
  now += 10000;
  hand_over (s, c, now, 1);
  now += 10000;
  for (k = 0; k < 8; k++)
    {
      CHECK_EQ (gq_conn_send_path (c, now, buf, sizeof buf, &len, NULL), GQ_OK);
      if (len == 0)
        break;
      n = datagram_packets (buf, len, size, is_long, 8);
      if (n >= 2 && is_long[0] && !is_long[n - 1])
        {
          found++;
          CHECK (len >= GQ_MIN_INITIAL_DATAGRAM);
          /* A 1-RTT packet with a few control frames, not the filler.  */
          CHECK (size[n - 1] < 300);
        }
      gq_conn_recv (s, now, buf, len);
    }
  CHECK (found >= 1);
  pair_free (p);
}

/* Whether the sent packet K carries CRYPTO data.  */
static int
sent_has_crypto (const sent_pkt *k)
{
  uint32_t i;

  for (i = 0; i < k->nframes; i++)
    if (k->frames[i].type == SF_CRYPTO)
      return 1;
  return 0;
}

/* RFC 9002 section 6.2.4: a probe in the Initial or Handshake space
   carries the CRYPTO data still in flight.  A PING-only Initial probe is no
   use when the first Initial was lost: a server with no connection for it
   ignores it, and some (aioquic) close on an Initial with no CRYPTO frame.
   A PTO used to requeue the oldest packet not yet requeued, which after a
   round or two was one of the PING probes, so some probes had nothing to
   carry.  Every ack-eliciting Initial the client sends while it hears
   nothing carries CRYPTO.  */
static void
test_handshake_probes_carry_crypto (void)
{
  struct pair *p = pair_new (NULL, NULL, 0, 1);
  gq_conn *c = p->cli.c;
  space *s = &c->sp[SP_INITIAL];
  uint64_t now = p->net.now, t, first;
  size_t i;
  int round, probes = 0;

  /* The first flight is sent, and lost.  */
  hand_over (c, p->srv.c, now, 0);
  CHECK (s->next_pn >= 1);
  for (round = 0; round < 12 && probes < 6; round++)
    {
      /* Packets declared lost leave the list, so go by packet number.  */
      first = s->next_pn;
      t = gq_conn_timeout (c);
      CHECK (t != 0);
      if (t > now)
        now = t;
      gq_conn_on_timeout (c, now);
      hand_over (c, p->srv.c, now, 0);
      for (i = 0; i < s->n_sent; i++)
        if (s->sent[i].pn >= first && s->sent[i].ack_eliciting)
          {
            probes++;
            CHECK (sent_has_crypto (&s->sent[i]));
          }
    }
  /* Not every timer is a probe timeout: some declare packets lost.  */
  CHECK (probes >= 5);
  pair_free (p);
}

/* The first datagram a server sends to a client's new address (RFC 9000
   section 9.3) carries the PATH_CHALLENGE, even when the packets it has in
   flight, all lost with the old address, fill the congestion window.  Only
   an ack-eliciting packet could carry it, so it used to wait for loss
   detection to make room, and an ACK-only packet (the answer to the
   client's PING) went first.  */
struct first_to
{
  const gq_addr *ext;
  int seen, challenged;
  gq_conn *srv;
};

static void
first_to_tap (struct net *n, int from, const gq_path *to, void *user)
{
  struct first_to *f = user;

  (void) n;
  if (from != 1 || to == NULL || f->seen || !addr_same (&to->remote, f->ext))
    return;
  f->seen = 1;
  /* The challenge was written into this very datagram if the path's count
     of challenges sent is not zero.  */
  f->challenged = f->srv->paths[f->srv->cur_path].chal_sent > 0;
}

static void
test_challenge_first_on_new_path (void)
{
  gq_conn_config cfg;
  struct pair *p;
  struct sbuf *s;
  struct first_to f;
  int i, k = 0;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new_paths (&cfg, &cfg, 130);
  settle (p);
  s = start_transfer (p, 40000000);
  run (&p->net, NULL, 400000);
  CHECK (!s->fin && s->n > 0);
  memset (&f, 0, sizeof f);
  f.ext = &p->net.m[3].ext;
  f.srv = p->srv.c;
  p->net.tap = first_to_tap;
  p->net.tap_user = &f;
  p->net.out_map[0] = 3;
  p->net.m[3].alive_in = 1;
  p->net.m[0].alive_in = 0;
  /* What the server had sent to the old address and not yet delivered is
     lost with it: its window stays full of packets that will never be
     acknowledged.  */
  for (i = 0; i < p->net.nq; i++)
    if (p->net.q[i].to == 1)
      p->net.q[k++] = p->net.q[i];
  p->net.nq = k;
  /* The client probes with a PING, which the server answers at once.  */
  p->cli.c->sp[SP_APP].probes = 1;
  CHECK (run (&p->net, transfer_done, 60000000));
  CHECK (f.seen);
  CHECK (f.challenged);
  CHECK_EQ (s->n, 40000000);
  pair_free (p);
}

/* RFC 9002 section 7.8: a sender that is not using its window, because it
   has no more to send than the window allows, does not grow it however many
   acknowledgements arrive.  */
static void
test_window_unused_does_not_grow (void)
{
  struct pair *p = settled_pair (NULL, NULL);
  gq_conn *s = p->srv.c;
  uint64_t before = s->cc.cwnd;
  int i;

  p->srv.respond = 3000;
  for (i = 0; i < 20; i++)
    {
      uint64_t id;
      struct sbuf *b;

      CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
      b = sb_get (&p->cli, id);
      b->out_total = 10;
      b->out_fin = 1;
      CHECK (wait_for_stream (p, b, 3000, 5000000));
    }
  run (&p->net, NULL, 1000000);
  CHECK (!s->send_blocked);
  CHECK_EQ (s->cc.cwnd, before);
  pair_free (p);
}

/* The pacer's wait is a deadline of the connection (gq_conn_timeout), so
   that a caller driven by it comes back when credit has accrued; it is
   there only while stream data is held back.  */
static void
test_pacing_deadline (void)
{
  gq_conn_config cfg;
  struct pair *p;
  gq_conn *s;
  const size_t size = 600000;
  uint64_t id;
  struct sbuf *b;
  int seen = 0, guard = 0;

  memset (&cfg, 0, sizeof cfg);
  cfg.initial_max_data = 100u << 20;
  cfg.initial_max_stream_data = 100u << 20;
  p = pair_new (&cfg, &cfg, 0, 33);
  s = p->srv.c;
  p->net.latency = 50000;
  p->srv.respond = size;
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 500000);
  CHECK_EQ (s->pace_deadline, 0);
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  b = sb_get (&p->cli, id);
  b->out_total = 10;
  b->out_fin = 1;
  while (!(b->fin && b->n == size) && guard++ < 100000)
    {
      run (&p->net, NULL, 500);
      if (s->pace_deadline)
        {
          uint64_t t = gq_conn_timeout (s);

          seen++;
          CHECK (t != 0 && t <= s->pace_deadline);
          CHECK (s->pace_deadline > s->now);
          CHECK (s->pace_wait_us > 0);
        }
    }
  CHECK (b->fin && b->n == size);
  CHECK (seen > 10);
  run (&p->net, NULL, 1000000);
  CHECK_EQ (s->pace_deadline, 0);
  pair_free (p);
}

/* The events of a connection come in time order whatever the caller's clock
   does between calls: a call that reads earlier than a previous one reports
   at the latest time there was, not before it.  The sink every connection of
   these tests has fails the test on an event that goes back.  */
static void
test_qlog_clock_going_back (void)
{
  struct pair *p = settled_pair (NULL, NULL);
  gq_conn *c = p->cli.c;
  struct qsink *k = &p->qlog_sink[0];
  uint64_t t, id, before;
  uint8_t buf[2048];
  size_t len;

  /* The time of the last event reported.  */
  CHECK (k->last_t > 5000 && k->total > 0);
  t = k->last_t;
  CHECK_EQ (gq_conn_stream_open (c, 1, &id), GQ_OK);
  CHECK (gq_conn_stream_write (c, id, (const uint8_t *) "hello", 5) == 5);
  before = k->total;
  /* A call whose clock reads 5 ms before the last event.  */
  CHECK_EQ (gq_conn_send_path (c, t - 5000, buf, sizeof buf, &len, NULL),
            GQ_OK);
  CHECK (len > 0);
  CHECK (k->total > before);
  CHECK (k->last_t >= t);
  CHECK_EQ (k->bad_order, 0);
  /* And a timer serviced early.  */
  gq_conn_on_timeout (c, t - 9000);
  CHECK_EQ (k->bad_order, 0);
  pair_free (p);
}

/* What an observer on the path sees of the spin bit in each direction
   (0: the client's packets, 1: the server's).  */
#define SPIN_GAPS 512
struct spin_obs
{
  int armed;
  struct
  {
    unsigned pkts, edges, ngaps;
    int last;
    uint64_t last_edge;
    uint64_t gap[SPIN_GAPS];
  } d[2];
};

static void
spin_snoop (struct net *n, int from, const uint8_t *dg, size_t len,
            int ecn, void *user)
{
  struct spin_obs *o = user;
  int bit;

  (void) ecn;
  if (!o->armed || len == 0 || (dg[0] & 0x80))
    return;				/* Not a 1-RTT packet.  */
  bit = (dg[0] >> 5) & 1;
  if (o->d[from].pkts++ > 0 && bit != o->d[from].last)
    {
      if (o->d[from].edges++ > 0 && o->d[from].ngaps < SPIN_GAPS)
        o->d[from].gap[o->d[from].ngaps++] = n->now - o->d[from].last_edge;
      o->d[from].last_edge = n->now;
    }
  o->d[from].last = bit;
}

/* The mean gap between the edges of one direction, in microseconds.  */
static uint64_t
spin_mean_gap (const struct spin_obs *o, int dir)
{
  uint64_t sum = 0;
  unsigned i;

  for (i = 0; i < o->d[dir].ngaps; i++)
    sum += o->d[dir].gap[i];
  return o->d[dir].ngaps ? sum / o->d[dir].ngaps : 0;
}

/* A bulk transfer over a 100 ms round trip with both ends configured as CFG
   and the server's response RESP bytes.  OBS sees every datagram; the
   qlogs, in P, are left for the caller.  */
static struct pair *
spin_transfer (const gq_conn_config *cfg, struct spin_obs *obs, size_t resp)
{
  struct pair *p;
  struct sbuf *s;
  uint64_t id;

  p = pair_new (cfg, cfg, 0, 61);
  p->qlog_sink[0].keep = p->qlog_sink[1].keep = 1;
  p->net.latency = 50000;
  p->srv.respond = resp;
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 500000);
  memset (obs, 0, sizeof *obs);
  obs->armed = 1;
  p->net.snoop = spin_snoop;
  p->net.snoop_user = obs;
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  s = sb_get (&p->cli, id);
  s->out_total = 10;
  s->out_fin = 1;
  CHECK (wait_for_stream (p, s, resp, 120000000));
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  return p;
}

/* As spin_transfer, but for a pair with the bit on at both ends: each
   connection is drawn at random to have it off one time in eight, so try
   again until there is one.  */
static struct pair *
spin_pair (const gq_conn_config *cfg, struct spin_obs *obs, size_t resp)
{
  int tries;

  for (tries = 0; tries < 100; tries++)
    {
      struct pair *p = spin_transfer (cfg, obs, resp);

      if (p->cli.c->spin_on && p->srv.c->spin_on)
        return p;
      pair_free (p);
    }
  CHECK (0);
  return spin_transfer (cfg, obs, resp);
}

/* RFC 9000 section 17.4: with the spin bit on, the value in each direction
   toggles once per round trip, so an observer can time it.  */
static void
test_spin_bit (void)
{
  gq_conn_config cfg;
  struct spin_obs obs;
  struct pair *p;
  int dir;
  const uint64_t rtt = 100000;

  memset (&cfg, 0, sizeof cfg);
  cfg.initial_max_data = 100u << 20;
  cfg.initial_max_stream_data = 100u << 20;
  /* Every connection is drawn at random to have it off one time in eight,
     so look for a pair that has it on at both ends.  */
  p = spin_pair (&cfg, &obs, 4000000);
  for (dir = 0; dir < 2; dir++)
    {
      unsigned i;

      CHECK (obs.d[dir].pkts > 50);
      CHECK (obs.d[dir].edges >= 6);
      /* Time between edges is a round trip at the least, and not much more
         with a steady stream of packets both ways.  */
      for (i = 0; i < obs.d[dir].ngaps; i++)
        CHECK (obs.d[dir].gap[i] >= rtt);
      CHECK (spin_mean_gap (&obs, dir) < rtt * 3 / 2);
    }
  pair_free (p);
}

/* Switched off by configuration, the bit is random in each packet: it
   changes about every other packet, and not once a round trip.  */
static void
test_spin_bit_disabled (void)
{
  gq_conn_config cfg;
  struct spin_obs obs;
  struct pair *p;
  int dir;

  memset (&cfg, 0, sizeof cfg);
  cfg.initial_max_data = 100u << 20;
  cfg.initial_max_stream_data = 100u << 20;
  cfg.disable_spin_bit = 1;
  p = spin_transfer (&cfg, &obs, 4000000);
  for (dir = 0; dir < 2; dir++)
    {
      CHECK (obs.d[dir].pkts >= 100);
      CHECK (obs.d[dir].edges >= obs.d[dir].pkts / 4);
      CHECK (obs.d[dir].edges <= obs.d[dir].pkts * 3 / 4);
      CHECK (spin_mean_gap (&obs, dir) < 50000);
    }
  /* Nothing to report: the value we send is not a state.  */
  CHECK_EQ (qsink_count (&p->qlog_sink[0], "quic:spin_bit_updated"), 0);
  CHECK_EQ (qsink_count (&p->qlog_sink[1], "quic:spin_bit_updated"), 0);
  pair_free (p);
}

/* RFC 9000 section 17.4: the connection is without the bit for a random
   selection of at least one in sixteen, whatever the draw, and the
   configuration turns it off for every one.  */
static void
test_spin_bit_selection (void)
{
  gq_conn_config cfg;
  unsigned draw, off = 0;

  memset (&cfg, 0, sizeof cfg);
  for (draw = 0; draw < 256; draw++)
    if (!conn_spin_enabled (&cfg, draw))
      off++;
  CHECK (off >= 256 / 16);
  CHECK (off <= 256 / 4);		/* Most connections still spin.  */
  cfg.disable_spin_bit = 1;
  for (draw = 0; draw < 256; draw++)
    CHECK (!conn_spin_enabled (&cfg, draw));
}

/* Seal a PING from FROM to TO with the spin bit SPIN, as if from PATH.  */
static void
spin_ping (gq_conn *from, gq_conn *to, uint64_t now, const gq_path *path,
           int spin)
{
  gq_frame f;

  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_PING;
  forge_spin = spin;
  forge (from, to, now, path, &f, 1, 0);
  forge_spin = 0;
}

/* A server echoes the bit of the highest-numbered packet it has received
   from the client, so an old one that turns up late changes nothing; a
   client sends the opposite; and a change of path starts again, as a new
   path is a new thing to observe.  */
static void
test_spin_bit_rules (void)
{
  gq_conn_config cfg;
  struct pair *p;
  gq_conn *cli, *srv;
  space *cs;
  uint64_t pn;
  gq_path np, to_srv, to_cli;
  int tries;

  memset (&cfg, 0, sizeof cfg);
  for (tries = 0;; tries++)
    {
      p = pair_new_paths (&cfg, &cfg, 62);
      settle (p);
      if ((p->cli.c->spin_on && p->srv.c->spin_on) || tries == 99)
        break;
      pair_free (p);
    }
  CHECK (p->cli.c->spin_on && p->srv.c->spin_on);
  to_srv.local = p->net.S;
  to_srv.remote = p->net.m[0].ext;
  to_cli.local = p->net.L[0];
  to_cli.remote = p->net.S;
  cli = p->cli.c;
  srv = p->srv.c;
  cs = &cli->sp[SP_APP];

  /* The server follows the client's bit...  */
  spin_ping (cli, srv, p->net.now, &to_srv, 1);
  CHECK_EQ (srv->spin_val, 1);
  spin_ping (cli, srv, p->net.now, &to_srv, 0);
  CHECK_EQ (srv->spin_val, 0);
  /* ...but not from a packet older than the newest.  */
  pn = cs->next_pn;
  cs->next_pn = pn + 10;
  spin_ping (cli, srv, p->net.now, &to_srv, 1);	/* pn + 10, newest.  */
  CHECK_EQ (srv->spin_val, 1);
  cs->next_pn = pn + 5;
  spin_ping (cli, srv, p->net.now, &to_srv, 0);	/* Older: ignored.  */
  CHECK_EQ (srv->spin_val, 1);
  cs->next_pn = pn + 11;

  /* The client sends the inverse of the server's.  */
  spin_ping (srv, cli, p->net.now, &to_cli, 0);
  CHECK_EQ (cli->spin_val, 1);
  spin_ping (srv, cli, p->net.now, &to_cli, 1);
  CHECK_EQ (cli->spin_val, 0);

  /* A packet from a path the server has not seen moves it there, and the
     spin state restarts from zero rather than carrying the old path's.  */
  spin_ping (cli, srv, p->net.now, &to_srv, 1);
  CHECK_EQ (srv->spin_val, 1);
  np.local = p->net.S;
  np.remote = p->net.m[3].ext;
  spin_ping (cli, srv, p->net.now, &np, 1);
  CHECK_EQ (srv->migrations, 1);
  CHECK_EQ (srv->spin_val, 0);
  pair_free (p);
}

/* The 1-RTT packets in the log carry the bit; spin_bit_updated reports each
   change of the value we send, and only changes.  */
static void
test_spin_bit_qlog (void)
{
  gq_conn_config cfg;
  struct spin_obs obs;
  struct pair *p;
  int end;

  memset (&cfg, 0, sizeof cfg);
  cfg.initial_max_data = 100u << 20;
  cfg.initial_max_stream_data = 100u << 20;
  p = spin_pair (&cfg, &obs, 1000000);
  for (end = 0; end < 2; end++)
    {
      const struct qsink *k = &p->qlog_sink[end];
      size_t i, n = qsink_count (k, "quic:spin_bit_updated"), onertt = 0;
      int prev = 0;
      static const char *const ev[] = { "quic:packet_sent",
                                        "quic:packet_received" };
      int e;

      CHECK (n >= 4);
      for (i = 0; i < n; i++)
        {
          qline q;
          int now;

          CHECK (qsink_nth (k, "quic:spin_bit_updated", i, &q));
          now = qline_is (&q, "state", "true");
          CHECK (now || qline_is (&q, "state", "false"));
          CHECK (now != prev);
          prev = now;
          qline_free (&q);
        }
      for (e = 0; e < 2; e++)
        for (i = 0; i < qsink_count (k, ev[e]); i++)
          {
            qline q;

            CHECK (qsink_nth (k, ev[e], i, &q));
            if (qline_is (&q, "header.packet_type", "1RTT"))
              {
                onertt++;
                CHECK (qline_get (&q, "header.spin_bit") != NULL);
              }
            else
              CHECK (qline_get (&q, "header.spin_bit") == NULL);
            qline_free (&q);
          }
      CHECK (onertt > 50);
      CHECK_EQ (k->bad_event + k->bad_line, 0);
    }
  pair_free (p);
}

/* The ECN counts of the newest 1-RTT ACK frame END's qlog has for a packet
   it sent (EVENT is packet_sent) or received.  1 if there was one.  */
static int
last_ack_ecn (const struct qsink *k, const char *event, uint64_t v[3])
{
  size_t i, f;

  for (i = k->n; i-- > 0;)
    {
      qline q;

      if (strcmp (k->e[i].name, event)
          || !qline_parse (k->e[i].fields, strlen (k->e[i].fields), &q))
        continue;
      if (qline_is (&q, "header.packet_type", "1RTT"))
        for (f = 0; f < 8; f++)
          {
            char key[48];
            const char *t;

            snprintf (key, sizeof key, "frames.%zu.frame_type", f);
            t = qline_get (&q, key);
            if (t && !strcmp (t, "ack"))
              {
                const char *e0, *e1, *ce;

                snprintf (key, sizeof key, "frames.%zu.ect0", f);
                e0 = qline_get (&q, key);
                snprintf (key, sizeof key, "frames.%zu.ect1", f);
                e1 = qline_get (&q, key);
                snprintf (key, sizeof key, "frames.%zu.ce", f);
                ce = qline_get (&q, key);
                if (e0 && e1 && ce)
                  {
                    v[0] = strtoull (e0, NULL, 10);
                    v[1] = strtoull (e1, NULL, 10);
                    v[2] = strtoull (ce, NULL, 10);
                    qline_free (&q);
                    return 1;
                  }
                qline_free (&q);
                return 0;
              }
          }
      qline_free (&q);
    }
  return 0;
}

/* A PING from FROM to TO carrying ECN.  */
static void
ecn_ping (gq_conn *from, gq_conn *to, uint64_t now, const gq_path *path,
          int ecn)
{
  gq_frame f;

  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_PING;
  forge_ecn = ecn;
  forge (from, to, now, path, &f, 1, 0);
  forge_ecn = 0;
}

/* RFC 9000 section 13.4.1: each packet's ECN codepoint is counted in its
   packet number space, a duplicate or an invalid packet not at all, the
   counts go back in ACK frames (type 0x03), and RFC 9000 section 13.2.1: one
   marked CE is acknowledged without delay.  */
static void
test_ecn_receive_counts (void)
{
  struct pair *p;
  gq_conn *cli, *srv;
  space *cs, *ss;
  gq_path to_srv;
  uint64_t v[3], pn, now;
  uint8_t buf[1500];
  size_t len;
  gq_conn_stats st, base;
  int i;

  p = pair_new_paths (&(gq_conn_config) { 0 }, &(gq_conn_config) { 0 }, 63);
  settle (p);
  cli = p->cli.c;
  srv = p->srv.c;
  cs = &cli->sp[SP_APP];
  ss = &srv->sp[SP_APP];
  to_srv.local = p->net.S;
  to_srv.remote = p->net.m[0].ext;
  p->qlog_sink[1].keep = 1;
  memset (ss->ecn_in, 0, sizeof ss->ecn_in);
  gq_conn_get_stats (srv, &st);
  base = st;
  now = p->net.now;

  /* Three ECT(0), two ECT(1), one CE, and one without a codepoint.  */
  for (i = 0; i < 3; i++)
    ecn_ping (cli, srv, now, &to_srv, GQ_ECN_ECT0);
  for (i = 0; i < 2; i++)
    ecn_ping (cli, srv, now, &to_srv, GQ_ECN_ECT1);
  ecn_ping (cli, srv, now, &to_srv, GQ_ECN_CE);
  ecn_ping (cli, srv, now, &to_srv, GQ_ECN_NOT_ECT);
  CHECK_EQ (ss->ecn_in[0], 3);
  CHECK_EQ (ss->ecn_in[1], 2);
  CHECK_EQ (ss->ecn_in[2], 1);
  gq_conn_get_stats (srv, &st);
  CHECK_EQ (st.ecn_ect0_received - base.ecn_ect0_received, 3);
  CHECK_EQ (st.ecn_ect1_received - base.ecn_ect1_received, 2);
  CHECK_EQ (st.ecn_ce_received - base.ecn_ce_received, 1);

  /* The same packet number again is a duplicate: not counted.  */
  pn = cs->next_pn;
  cs->next_pn = pn - 1;
  ecn_ping (cli, srv, now, &to_srv, GQ_ECN_ECT0);
  cs->next_pn = pn;
  CHECK_EQ (ss->ecn_in[0], 3);
  /* One that does not authenticate is not counted either.  */
  {
    gq_frame f;

    memset (&f, 0, sizeof f);
    f.type = GQ_FRAME_PING;
    forge_ecn = GQ_ECN_CE;
    forge (cli, srv, now, &to_srv, &f, 1, 1);
    forge_ecn = 0;
  }
  CHECK_EQ (ss->ecn_in[2], 1);

  /* The ACK the server sends carries the counts.  */
  gq_conn_on_timeout (srv, now + 50000);
  CHECK_EQ (gq_conn_send (srv, now + 50000, buf, sizeof buf, &len), GQ_OK);
  CHECK (len > 0);
  CHECK (last_ack_ecn (&p->qlog_sink[1], "quic:packet_sent", v));
  CHECK_EQ (v[0], 3);
  CHECK_EQ (v[1], 2);
  CHECK_EQ (v[2], 1);
  pair_free (p);

  /* Without a codepoint on anything, the ACK is the plain type.  */
  p = pair_new_paths (&(gq_conn_config) { 0 }, &(gq_conn_config) { 0 }, 64);
  p->net.bleach[0] = p->net.bleach[1] = 1;
  settle (p);
  p->qlog_sink[1].keep = 1;
  to_srv.local = p->net.S;
  to_srv.remote = p->net.m[0].ext;
  now = p->net.now;
  ecn_ping (p->cli.c, p->srv.c, now, &to_srv, GQ_ECN_NOT_ECT);
  ecn_ping (p->cli.c, p->srv.c, now, &to_srv, GQ_ECN_NOT_ECT);
  gq_conn_on_timeout (p->srv.c, now + 50000);
  CHECK_EQ (gq_conn_send (p->srv.c, now + 50000, buf, sizeof buf, &len),
            GQ_OK);
  CHECK (len > 0);
  CHECK (!last_ack_ecn (&p->qlog_sink[1], "quic:packet_sent", v));
  pair_free (p);

  /* A value that is not a codepoint.  */
  p = pair_new_paths (&(gq_conn_config) { 0 }, &(gq_conn_config) { 0 }, 65);
  settle (p);
  buf[0] = 0;
  CHECK_EQ (gq_conn_recv_ecn (p->srv.c, p->net.now, NULL, 4, buf, 1),
            GQ_ERR_INVAL);
  CHECK_EQ (gq_conn_recv_ecn (p->srv.c, p->net.now, NULL, -1, buf, 1),
            GQ_ERR_INVAL);
  pair_free (p);
}

/* A packet marked CE is acknowledged at once; one with ECT(0), a lone
   packet in order, waits for the delay as any other.  */
static void
test_ecn_ce_acked_at_once (void)
{
  int ecn;

  for (ecn = GQ_ECN_NOT_ECT; ecn <= GQ_ECN_CE; ecn++)
    {
      struct pair *p;
      gq_path to_srv;

      p = pair_new_paths (&(gq_conn_config) { 0 }, &(gq_conn_config) { 0 },
                          66);
      settle (p);
      to_srv.local = p->net.S;
      to_srv.remote = p->net.m[0].ext;
      p->srv.c->sp[SP_APP].ack_now = 0;
      p->srv.c->sp[SP_APP].ae_since_ack = 0;
      ecn_ping (p->cli.c, p->srv.c, p->net.now, &to_srv, ecn);
      CHECK_EQ (p->srv.c->sp[SP_APP].ack_now, ecn == GQ_ECN_CE);
      pair_free (p);
    }
}

/* Everything the server sends arrives marked ECT(0): the client counts
   them, says so in its ACK frames, the counts only grow, and the log shows
   the codepoint of each datagram.  */
static void
test_ecn_receive_transfer (void)
{
  gq_conn_config cfg;
  struct pair *p;
  struct sbuf *s;
  uint64_t id, last[3] = { 0, 0, 0 }, v[3];
  gq_conn_stats st;
  size_t i, n, marked = 0;
  const struct qsink *k;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new (&cfg, &cfg, 0, 67);
  p->qlog_sink[0].keep = p->qlog_sink[1].keep = 1;
  p->net.mark[1] = GQ_ECN_ECT0;
  p->net.bleach[0] = 1;		/* Nothing the client sends is marked.  */
  p->srv.respond = 200000;
  CHECK (run (&p->net, both_connected, 30000000));
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  s = sb_get (&p->cli, id);
  s->out_total = 10;
  s->out_fin = 1;
  CHECK (wait_for_stream (p, s, 200000, 30000000));
  run (&p->net, NULL, 500000);
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  gq_conn_get_stats (p->cli.c, &st);
  CHECK (st.ecn_ect0_received > 100);
  CHECK_EQ (st.ecn_ect1_received + st.ecn_ce_received, 0);
  gq_conn_get_stats (p->srv.c, &st);
  CHECK_EQ (st.ecn_ect0_received + st.ecn_ect1_received
            + st.ecn_ce_received, 0);
  /* What the server heard from the client, newest last: it only grows.  */
  k = &p->qlog_sink[1];
  n = qsink_count (k, "quic:packet_received");
  for (i = 0; i < n; i++)
    {
      qline q;
      size_t f;

      CHECK (qsink_nth (k, "quic:packet_received", i, &q));
      for (f = 0; f < 8; f++)
        {
          char key[48];
          const char *e0;

          snprintf (key, sizeof key, "frames.%zu.ect0", f);
          if ((e0 = qline_get (&q, key)) != NULL)
            {
              uint64_t x = strtoull (e0, NULL, 10);

              CHECK (x >= last[0] || qline_is (&q, "header.packet_type",
                                               "handshake"));
              if (qline_is (&q, "header.packet_type", "1RTT"))
                last[0] = x;
            }
        }
      qline_free (&q);
    }
  CHECK (last[0] > 0);
  CHECK (last_ack_ecn (&p->qlog_sink[1], "quic:packet_received", v));
  CHECK_EQ (v[1] + v[2], 0);
  /* The client's log names the codepoint of the datagrams it received.  */
  k = &p->qlog_sink[0];
  n = qsink_count (k, "quic:udp_datagrams_received");
  for (i = 0; i < n; i++)
    {
      qline q;

      CHECK (qsink_nth (k, "quic:udp_datagrams_received", i, &q));
      if (qline_is (&q, "ecn", "ECT(0)"))
        marked++;
      else
        CHECK (qline_is (&q, "ecn", "Not-ECT"));
      qline_free (&q);
    }
  CHECK (marked > 100);
  CHECK_EQ (k->bad_event + k->bad_line, 0);
  pair_free (p);
}

/* What the path saw of the ECN fields: datagrams each end sent, how many
   were marked, and those with a long header (the handshake), which must
   never be.  */
struct ecn_obs
{
  unsigned dgrams[2], marked[2], long_marked[2];
  unsigned marked_after[2];	/* Marked after AFTER_AT datagrams of it.  */
  unsigned after_at;
};

static void
ecn_snoop (struct net *n, int from, const uint8_t *dg, size_t len, int ecn,
           void *user)
{
  struct ecn_obs *o = user;

  (void) n;
  o->dgrams[from]++;
  if (ecn != GQ_ECN_NOT_ECT)
    {
      o->marked[from]++;
      if (len && (dg[0] & 0x80))
        o->long_marked[from]++;
      if (o->after_at && o->dgrams[from] > o->after_at)
        o->marked_after[from]++;
    }
}

/* The states the ECN log of one end went through, as a string such as
   "testing,unknown,capable".  */
static void
ecn_states (const struct qsink *k, char *out, size_t cap)
{
  size_t i, n = qsink_count (k, "quic:ecn_state_updated");

  out[0] = '\0';
  for (i = 0; i < n; i++)
    {
      qline q;
      const char *s;

      CHECK (qsink_nth (k, "quic:ecn_state_updated", i, &q));
      s = qline_get (&q, "new");
      CHECK (s != NULL);
      if (s && strlen (out) + strlen (s) + 2 < cap)
        {
          if (i)
            strcat (out, ",");
          strcat (out, s);
        }
      qline_free (&q);
    }
}

/* A connection, and a transfer of RESP bytes to the client over a path
   that SETUP shapes before anything is sent.  */
static struct pair *
ecn_transfer (struct ecn_obs *obs, void (*setup) (struct net *), size_t resp)
{
  gq_conn_config cfg;
  struct pair *p;
  struct sbuf *s;
  uint64_t id;

  memset (&cfg, 0, sizeof cfg);
  cfg.initial_max_data = 100u << 20;
  cfg.initial_max_stream_data = 100u << 20;
  p = pair_new (&cfg, &cfg, 0, 68);
  p->qlog_sink[0].keep = p->qlog_sink[1].keep = 1;
  p->net.latency = 20000;
  if (setup)
    setup (&p->net);
  memset (obs, 0, sizeof *obs);
  p->net.snoop = ecn_snoop;
  p->net.snoop_user = obs;
  p->srv.respond = resp;
  CHECK (run (&p->net, both_connected, 30000000));
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  s = sb_get (&p->cli, id);
  s->out_total = 10;
  s->out_fin = 1;
  CHECK (wait_for_stream (p, s, resp, 60000000));
  run (&p->net, NULL, 500000);
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  return p;
}

static int
ecn_state_of (const gq_conn *c)
{
  gq_conn_stats st;

  gq_conn_get_stats (c, &st);
  return st.ecn_state;
}

/* A path that passes the marks: both ends test, see the counts come back,
   and mark from then on; the handshake is never marked; the log has each
   step.  */
static void
test_ecn_validates (void)
{
  struct ecn_obs obs;
  struct pair *p = ecn_transfer (&obs, NULL, 300000);
  char st[128];
  gq_conn_stats cs, ss;
  int e;

  CHECK_EQ (ecn_state_of (p->cli.c), GQ_ECN_CAPABLE);
  CHECK_EQ (ecn_state_of (p->srv.c), GQ_ECN_CAPABLE);
  CHECK_EQ (obs.long_marked[0] + obs.long_marked[1], 0);
  CHECK (obs.marked[0] > 10 && obs.marked[1] > 100);
  /* Nearly everything after the first few packets is marked.  */
  CHECK (obs.marked[1] * 10 > obs.dgrams[1] * 8);
  gq_conn_get_stats (p->cli.c, &cs);
  gq_conn_get_stats (p->srv.c, &ss);
  CHECK (cs.ecn_marked_sent >= 10 && ss.ecn_marked_sent >= 10);
  /* The peer counted what we marked.  */
  CHECK (cs.ecn_marked_sent >= ss.ecn_ect0_received);
  CHECK (ss.ecn_ect0_received > 0 && cs.ecn_ect0_received > 0);
  CHECK_EQ (cs.ecn_ect1_received + cs.ecn_ce_received, 0);
  CHECK_EQ (ss.congestion_events, 0);
  CHECK_EQ (ss.packets_lost, 0);
  for (e = 0; e < 2; e++)
    {
      ecn_states (&p->qlog_sink[e], st, sizeof st);
      CHECK (!strncmp (st, "testing,", 8));
      CHECK (strstr (st, "capable") != NULL);
      CHECK (strstr (st, "failed") == NULL);
      CHECK_EQ (p->qlog_sink[e].bad_event + p->qlog_sink[e].bad_line, 0);
    }
  /* udp_datagrams_sent says which datagrams were marked.  */
  {
    const struct qsink *k = &p->qlog_sink[1];
    size_t i, n = qsink_count (k, "quic:udp_datagrams_sent"), ect0 = 0;

    for (i = 0; i < n; i++)
      {
        qline q;

        CHECK (qsink_nth (k, "quic:udp_datagrams_sent", i, &q));
        if (qline_is (&q, "ecn", "ECT(0)"))
          ect0++;
        else
          CHECK (qline_is (&q, "ecn", "Not-ECT"));
        qline_free (&q);
      }
    CHECK_EQ (ect0, obs.marked[1]);
  }
  pair_free (p);
}

/* The application that does not use the ECN calls gets none of it.  */
static void
ecn_off_setup (struct net *n)
{
  n->no_ecn = 1;
}

static void
test_ecn_off_without_the_api (void)
{
  struct ecn_obs obs;
  struct pair *p = ecn_transfer (&obs, ecn_off_setup, 100000);
  gq_conn_stats st;

  CHECK_EQ (obs.marked[0] + obs.marked[1], 0);
  CHECK_EQ (ecn_state_of (p->cli.c), GQ_ECN_OFF);
  CHECK_EQ (ecn_state_of (p->srv.c), GQ_ECN_OFF);
  CHECK_EQ (qsink_count (&p->qlog_sink[0], "quic:ecn_state_updated"), 0);
  CHECK_EQ (qsink_count (&p->qlog_sink[1], "quic:ecn_state_updated"), 0);
  gq_conn_get_stats (p->srv.c, &st);
  CHECK_EQ (st.ecn_marked_sent, 0);
  CHECK_EQ (qsink_count (&p->qlog_sink[1], "quic:udp_datagrams_sent") > 0, 1);
  {
    qline q;

    CHECK (qsink_nth (&p->qlog_sink[1], "quic:udp_datagrams_sent", 0, &q));
    CHECK (qline_get (&q, "ecn") == NULL);
    qline_free (&q);
  }
  pair_free (p);
}

/* A path that clears the marks: the peer's counts never come, validation
   fails on the first acknowledgement of a marked packet and no more are
   marked.  The connection is not troubled by it.  */
static void
ecn_bleach_setup (struct net *n)
{
  n->bleach[0] = n->bleach[1] = 1;
}

static void
test_ecn_bleached_path (void)
{
  struct ecn_obs obs;
  struct pair *p = ecn_transfer (&obs, ecn_bleach_setup, 300000);
  char st[128];
  int e;

  CHECK_EQ (ecn_state_of (p->cli.c), GQ_ECN_FAILED);
  CHECK_EQ (ecn_state_of (p->srv.c), GQ_ECN_FAILED);
  /* At most the ten of the test.  */
  CHECK (obs.marked[0] <= 10 && obs.marked[1] <= 10);
  CHECK_EQ (obs.long_marked[0] + obs.long_marked[1], 0);
  for (e = 0; e < 2; e++)
    {
      ecn_states (&p->qlog_sink[e], st, sizeof st);
      CHECK (!strncmp (st, "testing,", 8));
      CHECK (strstr (st, "failed") != NULL);
      CHECK (strstr (st, "capable") == NULL);
    }
  pair_free (p);
}

/* A path that drops what is marked: the packets of the test are lost, and
   that fails it; what is sent then gets through, so the transfer completes
   all the same, and the handshake, unmarked, was never at risk.  */
static void
ecn_drop_setup (struct net *n)
{
  n->drop_ect[0] = n->drop_ect[1] = 1;
}

static void
test_ecn_dropping_path (void)
{
  struct ecn_obs obs;
  struct pair *p = ecn_transfer (&obs, ecn_drop_setup, 300000);
  gq_conn_stats ss;

  CHECK_EQ (ecn_state_of (p->cli.c), GQ_ECN_FAILED);
  CHECK_EQ (ecn_state_of (p->srv.c), GQ_ECN_FAILED);
  CHECK (obs.marked[0] <= 10 && obs.marked[1] <= 10);
  gq_conn_get_stats (p->srv.c, &ss);
  CHECK (ss.packets_lost > 0);
  pair_free (p);
}

/* A bottleneck that marks every so often: the sender takes each as a
   congestion event, as for a loss, with nothing lost.  */
static void
ecn_ce_setup (struct net *n)
{
  n->ce_every[1] = 50;
}

static void
test_ecn_ce_is_congestion (void)
{
  struct ecn_obs obs;
  struct pair *p = ecn_transfer (&obs, ecn_ce_setup, 3000000);
  gq_conn_stats ss, cs;

  gq_conn_get_stats (p->srv.c, &ss);
  gq_conn_get_stats (p->cli.c, &cs);
  CHECK_EQ (ecn_state_of (p->srv.c), GQ_ECN_CAPABLE);
  CHECK (cs.ecn_ce_received > 5);
  CHECK (ss.congestion_events >= 2);
  CHECK_EQ (ss.packets_lost, 0);
  /* The window came down but not to the persistent congestion minimum.  */
  CHECK (p->net.min_cwnd > 2400);
  CHECK (p->net.max_cwnd > p->net.min_cwnd);
  pair_free (p);

  /* Without the marks, the same transfer has no events at all.  */
  p = ecn_transfer (&obs, NULL, 3000000);
  gq_conn_get_stats (p->srv.c, &ss);
  CHECK_EQ (ss.congestion_events, 0);
  CHECK_EQ (ss.packets_lost, 0);
  pair_free (p);
}

/* The newly acknowledged packets of the test below.  */
struct ecn_sent
{
  uint64_t lo, hi;
};

/* Send three packets of stream data from C, marked or not as the library
   chooses, and say what range of packet numbers they are.  */
static struct ecn_sent
ecn_send_three (struct pair *p, gq_conn *c, uint64_t *now, int *marked)
{
  struct ecn_sent r;
  uint64_t id;
  uint8_t data[1000], out[1500];
  int k;

  memset (data, 'x', sizeof data);
  CHECK_EQ (gq_conn_stream_open (c, 1, &id), GQ_OK);
  r.lo = c->sp[SP_APP].next_pn;
  *marked = 0;
  for (k = 0; k < 3; k++)
    {
      size_t len = 0;
      int ecn = -1;

      CHECK (gq_conn_stream_write (c, id, data, sizeof data) == sizeof data);
      *now += 10000;
      CHECK_EQ (gq_conn_send_ecn (c, *now, out, sizeof out, &len, NULL,
                                  &ecn), GQ_OK);
      CHECK (len > 0);
      if (ecn == GQ_ECN_ECT0)
        (*marked)++;
    }
  r.hi = c->sp[SP_APP].next_pn - 1;
  (void) p;
  return r;
}

/* An ACK from FROM to TO for [LO, HI] with the counts E0, E1, CE, or none.  */
static void
ecn_forge_ack (gq_conn *from, gq_conn *to, uint64_t now, uint64_t lo,
               uint64_t hi, int has_ecn, uint64_t e0, uint64_t e1, uint64_t ce)
{
  gq_frame f;
  gq_ack_range r;
  uint8_t enc[32];
  size_t w = 0;

  r.lo = lo;
  r.hi = hi;
  CHECK_EQ (gq_ack_ranges_encode (&r, 1, enc, sizeof enc, &w), GQ_OK);
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_ACK;
  f.u.ack.largest = hi;
  f.u.ack.ranges.data = enc;
  f.u.ack.ranges.len = w;
  f.u.ack.has_ecn = has_ecn;
  f.u.ack.ect0 = e0;
  f.u.ack.ect1 = e1;
  f.u.ack.ecn_ce = ce;
  forge (from, to, now, NULL, &f, 1, 0);
}

/* As ecn_send_three, but three packets that carry only an ACK, as those of
   a connection that is downloading do: the peer acknowledges them in its
   ranges but they are not ack-eliciting, so are not themselves tracked.  */
static struct ecn_sent
ecn_send_three_acks (gq_conn *a, gq_conn *b, const gq_path *to_a,
                     uint64_t *now, int *marked)
{
  struct ecn_sent r;
  uint8_t out[1500];
  int k;

  r.lo = a->sp[SP_APP].next_pn;
  *marked = 0;
  for (k = 0; k < 3; k++)
    {
      size_t len = 0;
      int ecn = -1;
      gq_frame f;

      /* A PING from the peer makes an ACK owed.  */
      memset (&f, 0, sizeof f);
      f.type = GQ_FRAME_PING;
      forge (b, a, *now, to_a, &f, 1, 0);
      *now += 30000;
      gq_conn_on_timeout (a, *now);
      CHECK_EQ (gq_conn_send_ecn (a, *now, out, sizeof out, &len, NULL,
                                  &ecn), GQ_OK);
      CHECK (len > 0);
      if (ecn == GQ_ECN_ECT0)
        (*marked)++;
    }
  r.hi = a->sp[SP_APP].next_pn - 1;
  CHECK_EQ (r.hi - r.lo + 1, 3);
  CHECK_EQ (a->sp[SP_APP].n_sent, 0);	/* None was ack-eliciting.  */
  return r;
}

enum ack_kind
{
  ACK_GOOD, ACK_GOOD_WITH_CE, ACK_NO_COUNTS, ACK_UNDERCOUNT, ACK_ECT1,
  ACK_DECREASE, ACK_OVERCOUNT
};

/* RFC 9000 section 13.4.2.1: the counts in the ACK frame that acknowledges
   the marked packets of the test are right, or validation fails.  */
static void
ecn_ack_case (enum ack_kind kind, int ack_only)
{
  struct pair *p = settled_pair (NULL, NULL);
  gq_conn *a = p->cli.c, *b = p->srv.c;
  space *s = &a->sp[SP_APP];
  struct ecn_sent r;
  uint64_t now = p->net.now + 1000000, b0, b1, bce;
  gq_conn_stats before, after;
  uint8_t out[1500];
  size_t len = 0;
  int marked = 0, ecn = -1;

  conn_ecn_restart (a);
  if (ack_only)
    r = ecn_send_three_acks (a, b, NULL, &now, &marked);
  else
    r = ecn_send_three (p, a, &now, &marked);
  CHECK_EQ (marked, 3);
  b0 = s->ecn_peer[0];
  b1 = s->ecn_peer[1];
  bce = s->ecn_peer[2];
  if (kind == ACK_DECREASE)
    {
      /* The counts have to have been something to go down from.  */
      now += 20000;
      ecn_forge_ack (b, a, now, r.lo, r.hi, 1, b0 + 3, b1, bce);
      CHECK_EQ (ecn_state_of (a), GQ_ECN_CAPABLE);
      b0 += 3;
      if (ack_only)
        r = ecn_send_three_acks (a, b, NULL, &now, &marked);
      else
        r = ecn_send_three (p, a, &now, &marked);
      CHECK_EQ (marked, 3);
    }
  gq_conn_get_stats (a, &before);
  now += 20000;
  switch (kind)
    {
    case ACK_GOOD:
      ecn_forge_ack (b, a, now, r.lo, r.hi, 1, b0 + 3, b1, bce);
      break;
    case ACK_GOOD_WITH_CE:
      ecn_forge_ack (b, a, now, r.lo, r.hi, 1, b0 + 2, b1, bce + 1);
      break;
    case ACK_NO_COUNTS:
      ecn_forge_ack (b, a, now, r.lo, r.hi, 0, 0, 0, 0);
      break;
    case ACK_UNDERCOUNT:
      ecn_forge_ack (b, a, now, r.lo, r.hi, 1, b0 + 2, b1, bce);
      break;
    case ACK_ECT1:
      ecn_forge_ack (b, a, now, r.lo, r.hi, 1, b0 + 3, b1 + 1, bce);
      break;
    case ACK_DECREASE:
      /* ECT(0) goes down, with CE making up for it in the sum.  */
      ecn_forge_ack (b, a, now, r.lo, r.hi, 1, b0 - 2, b1, bce + 5);
      break;
    case ACK_OVERCOUNT:
      ecn_forge_ack (b, a, now, r.lo, r.hi, 1, b0 + 3 + s->ecn_sent, b1,
                     bce);
      break;
    }
  gq_conn_get_stats (a, &after);
  if (kind == ACK_GOOD || kind == ACK_GOOD_WITH_CE)
    CHECK_EQ (ecn_state_of (a), GQ_ECN_CAPABLE);
  else
    CHECK_EQ (ecn_state_of (a), GQ_ECN_FAILED);
  /* Only a count of CE that grew is congestion.  */
  CHECK_EQ (after.congestion_events - before.congestion_events,
            kind == ACK_GOOD_WITH_CE);
  CHECK_EQ (after.packets_lost, before.packets_lost);
  /* And a connection that failed it marks no more; one that passed does.  */
  {
    uint64_t id;
    uint8_t data[100];

    memset (data, 'y', sizeof data);
    CHECK_EQ (gq_conn_stream_open (a, 1, &id), GQ_OK);
    CHECK (gq_conn_stream_write (a, id, data, sizeof data) == sizeof data);
    now += 10000;
    CHECK_EQ (gq_conn_send_ecn (a, now, out, sizeof out, &len, NULL, &ecn),
              GQ_OK);
    CHECK (len > 0);
    if (kind == ACK_GOOD || kind == ACK_GOOD_WITH_CE)
      CHECK_EQ (ecn, GQ_ECN_ECT0);
    else
      CHECK_EQ (ecn, GQ_ECN_NOT_ECT);
  }
  pair_free (p);
}

static void
test_ecn_validation_of_counts (void)
{
  enum ack_kind k;

  for (k = ACK_GOOD; k <= ACK_OVERCOUNT; k++)
    {
      ecn_ack_case (k, 0);
      ecn_ack_case (k, 1);
    }
}

/* A new path starts the test again (RFC 9000 section 13.4.2): the server
   of a connection that validated ECN, whose peer's address changes, goes
   through testing once more.  */
static void
test_ecn_restarts_on_new_path (void)
{
  gq_conn_config cfg;
  struct pair *p;
  struct sbuf *s;
  char st[160];
  const char *again;

  memset (&cfg, 0, sizeof cfg);
  p = pair_new_paths (&cfg, &cfg, 69);
  p->qlog_sink[1].keep = 1;
  settle (p);
  s = start_transfer (p, 400000);
  run (&p->net, NULL, 60000);
  CHECK_EQ (ecn_state_of (p->srv.c), GQ_ECN_CAPABLE);
  p->net.out_map[0] = 3;
  p->net.m[3].alive_in = 1;
  p->net.m[0].alive_in = 0;
  CHECK (run (&p->net, transfer_done, 60000000));
  CHECK_EQ (s->n, 400000);
  run (&p->net, NULL, 500000);
  ecn_states (&p->qlog_sink[1], st, sizeof st);
  again = strstr (st, "capable");
  CHECK (again != NULL);
  /* After capable, it is testing again, and in the end capable again.  */
  CHECK (again && strstr (again, "testing") != NULL);
  CHECK_EQ (ecn_state_of (p->srv.c), GQ_ECN_CAPABLE);
  pair_free (p);
}

/* ---- Path MTU discovery (RFC 9000 section 14.3, RFC 8899) ---- */

/* What the path saw of datagram sizes, and when.  */
struct pmtu_obs
{
  size_t max[2];		/* The largest each end sent that got through.  */
  size_t over_1200_before_confirm;
  unsigned bigger_than[2];	/* Sent above the MTU of the path (probes).  */
  size_t limit;
};

static void
pmtu_snoop (struct net *n, int from, const uint8_t *dg, size_t len, int ecn,
            void *user)
{
  struct pmtu_obs *o = user;
  gq_conn *c = n->app[from]->c;

  (void) dg;
  (void) ecn;
  if (len > 1200 && !c->handshake_confirmed)
    o->over_1200_before_confirm++;
  if (o->limit && len > o->limit)
    {
      o->bigger_than[from]++;
      return;
    }
  if (len > o->max[from])
    o->max[from] = len;
}

/* A transfer of RESP bytes to the client over a path with MTU, both ends
   with CEILING; the observer is left in OBS.  */
static struct pair *
pmtu_run (const gq_conn_config *cfg, size_t mtu, size_t mtu_then,
          uint64_t change_after_us, size_t resp, struct pmtu_obs *obs)
{
  struct pair *p;
  struct sbuf *s;
  uint64_t id;

  p = pair_new (cfg, cfg, 0, 70);
  p->qlog_sink[0].keep = p->qlog_sink[1].keep = 1;
  p->net.latency = 20000;
  p->net.mtu = mtu;
  memset (obs, 0, sizeof *obs);
  obs->limit = mtu;
  p->net.snoop = pmtu_snoop;
  p->net.snoop_user = obs;
  p->srv.respond = resp;
  CHECK (run (&p->net, both_connected, 30000000));
  if (change_after_us)
    {
      p->net.mtu_then = mtu_then;
      p->net.mtu_change_at = p->net.now + change_after_us;
    }
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  s = sb_get (&p->cli, id);
  s->out_total = 10;
  s->out_fin = 1;
  CHECK (wait_for_stream (p, s, resp, 120000000));
  run (&p->net, NULL, 2000000);
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  return p;
}

static struct pair *
pmtu_transfer (size_t ceiling, size_t mtu, size_t resp, struct pmtu_obs *obs)
{
  gq_conn_config cfg;

  memset (&cfg, 0, sizeof cfg);
  cfg.initial_max_data = 100u << 20;
  cfg.initial_max_stream_data = 100u << 20;
  cfg.max_udp_payload = ceiling;
  return pmtu_run (&cfg, mtu, 0, 0, resp, obs);
}

/* A path that takes 1400 bytes: the search, with a ceiling of 1452, finds a
   size within a few bytes of it and the data goes in datagrams that big.  */
static void
test_pmtu_discovers (void)
{
  struct pmtu_obs obs;
  struct pair *p = pmtu_transfer (1452, 1400, 2000000, &obs);
  gq_conn_stats st;
  int e;

  for (e = 0; e < 2; e++)
    {
      gq_conn_get_stats (e ? p->srv.c : p->cli.c, &st);
      CHECK (st.max_datagram_size <= 1400);
      CHECK (st.max_datagram_size >= 1400 - 16);
      CHECK (st.pmtu_done);
      CHECK (obs.max[e] >= 1400 - 16);
    }
  /* What did not fit was a probe, and not many of them.  */
  CHECK (obs.bigger_than[0] + obs.bigger_than[1] > 0);
  CHECK (p->net.mtu_drops < 60);
  pair_free (p);
}

/* A path that takes what the ceiling is: the first probe is at the ceiling
   and the search is over.  */
static void
test_pmtu_ceiling_reached (void)
{
  struct pmtu_obs obs;
  struct pair *p = pmtu_transfer (1452, 1500, 1000000, &obs);
  gq_conn_stats st;

  gq_conn_get_stats (p->srv.c, &st);
  CHECK_EQ (st.max_datagram_size, 1452);
  CHECK (st.pmtu_done);
  CHECK_EQ (p->net.mtu_drops, 0);
  CHECK_EQ (obs.max[1], 1452);
  CHECK_EQ (obs.max[0], 1452);
  pair_free (p);
}

/* The configured size is the most that is sent, and 1200 sends nothing
   larger or probes for it.  */
static void
test_pmtu_ceiling_is_a_ceiling (void)
{
  struct pmtu_obs obs;
  struct pair *p = pmtu_transfer (1300, 0, 1000000, &obs);
  gq_conn_stats st;

  gq_conn_get_stats (p->srv.c, &st);
  CHECK_EQ (st.max_datagram_size, 1300);
  CHECK_EQ (obs.max[1], 1300);
  CHECK_EQ (obs.max[0], 1300);
  pair_free (p);
  p = pmtu_transfer (1200, 0, 1000000, &obs);
  gq_conn_get_stats (p->srv.c, &st);
  CHECK_EQ (st.max_datagram_size, 1200);
  CHECK (st.pmtu_done);
  CHECK_EQ (obs.max[1], 1200);
  CHECK_EQ (obs.max[0], 1200);
  pair_free (p);
}

/* Nothing larger than 1200 is sent before the handshake is confirmed
   (RFC 9000 section 14.3: probing starts then).  */
static void
test_pmtu_waits_for_the_handshake (void)
{
  struct pmtu_obs obs;
  struct pair *p = pmtu_transfer (1452, 0, 200000, &obs);

  CHECK_EQ (obs.over_1200_before_confirm, 0);
  CHECK (obs.max[1] > 1200);
  pair_free (p);
}

/* A probe that is lost is not a sign of congestion (RFC 9000 section 14.4):
   the transfer over a path that drops them has no congestion events, and
   the window is what it is without any probing.  */
static void
test_pmtu_probe_loss_is_not_congestion (void)
{
  struct pmtu_obs obs;
  struct pair *p = pmtu_transfer (1452, 1300, 3000000, &obs);
  gq_conn_stats st;

  CHECK (p->net.mtu_drops >= 3);
  gq_conn_get_stats (p->srv.c, &st);
  CHECK_EQ (st.congestion_events, 0);
  CHECK_EQ (st.packets_lost, 0);
  CHECK (p->net.min_cwnd > 2 * 1200);
  CHECK (st.pmtu_done);
  pair_free (p);
}

/* The congestion controller and the pacer count in the size of the
   datagrams in use.  */
static void
test_pmtu_controller_follows (void)
{
  struct pmtu_obs obs;
  struct pair *p = pmtu_transfer (1452, 0, 500000, &obs);

  CHECK_EQ (p->srv.c->cc.mss, 1452);
  CHECK_EQ (p->srv.c->pace.dgram, 1452);
  CHECK_EQ (p->cli.c->cc.mss, 1452);
  pair_free (p);
}

/* The default ceiling is a size a path usually takes.  */
static void
test_pmtu_default_ceiling (void)
{
  gq_conn_config cfg;
  struct pair *p;

  memset (&cfg, 0, sizeof cfg);
  g_ceiling = 0;
  p = pair_new (&cfg, &cfg, 0, 71);
  g_ceiling = 1200;
  CHECK_EQ (p->cli.c->cfg.max_udp_payload, 1452);
  CHECK_EQ (p->srv.c->cfg.max_udp_payload, 1452);
  pair_free (p);
}

/* The path stops taking what it did (a route change, a tunnel): packets of
   the size in use vanish, the timeouts that follow take the size back to
   1200 so the data gets through, and the search starts again below the old
   size (RFC 8899 section 5.3.3).  */
static void
test_pmtu_black_hole (void)
{
  struct pmtu_obs obs;
  gq_conn_config cfg;
  struct pair *p;
  gq_conn_stats st;

  memset (&cfg, 0, sizeof cfg);
  cfg.initial_max_data = 100u << 20;
  cfg.initial_max_stream_data = 100u << 20;
  cfg.max_udp_payload = 1452;
  p = pmtu_run (&cfg, 0, 1300, 400000, 6000000, &obs);
  CHECK (p->net.mtu_drops > 0);
  /* The server sent the data in large packets and noticed; the client sent
     acknowledgements, which are small and got through, and has had no
     reason to look.  */
  gq_conn_get_stats (p->srv.c, &st);
  CHECK (st.max_datagram_size <= 1300);
  CHECK (st.max_datagram_size >= 1300 - 16);
  pair_free (p);
}

/* A search that ended below the ceiling is made again after a long time
   (RFC 8899's raise timer is 600 seconds), as the path may have changed
   for the better.  */
static void
test_pmtu_raise_timer (void)
{
  struct pmtu_obs obs;
  gq_conn_config cfg;
  struct pair *p;
  gq_conn_stats st;
  int e;

  memset (&cfg, 0, sizeof cfg);
  cfg.initial_max_data = 100u << 20;
  cfg.initial_max_stream_data = 100u << 20;
  cfg.max_udp_payload = 1452;
  cfg.idle_timeout_ms = 3600000;
  p = pmtu_run (&cfg, 1400, 0, 0, 200000, &obs);
  gq_conn_get_stats (p->srv.c, &st);
  CHECK (st.max_datagram_size <= 1400 && st.pmtu_done);
  /* The path now takes more, and nothing is sent for a while.  */
  p->net.mtu = 0;
  obs.limit = 0;
  run (&p->net, NULL, 300000000);
  for (e = 0; e < 2; e++)
    {
      gq_conn_get_stats (e ? p->srv.c : p->cli.c, &st);
      CHECK (st.max_datagram_size <= 1400);
    }
  run (&p->net, NULL, 400000000);
  for (e = 0; e < 2; e++)
    {
      gq_conn_get_stats (e ? p->srv.c : p->cli.c, &st);
      CHECK_EQ (st.max_datagram_size, 1452);
      CHECK (st.pmtu_done);
    }
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  pair_free (p);
}

/* The peer's address changes to one behind a path of 1300 bytes: the size is
   the new path's to find, not the old one's.  */
static void
test_pmtu_new_path_is_smaller (void)
{
  gq_conn_config cfg;
  struct pair *p;
  struct sbuf *s;
  gq_conn_stats st;

  memset (&cfg, 0, sizeof cfg);
  cfg.max_udp_payload = 1452;
  p = pair_new_paths (&cfg, &cfg, 72);
  p->net.m[3].mtu = 1300;
  settle (p);
  gq_conn_get_stats (p->srv.c, &st);
  CHECK_EQ (st.max_datagram_size, 1452);
  s = start_transfer (p, 3000000);
  run (&p->net, NULL, 100000);
  p->net.out_map[0] = 3;
  p->net.m[3].alive_in = 1;
  p->net.m[0].alive_in = 0;
  CHECK (run (&p->net, transfer_done, 120000000));
  CHECK_EQ (s->n, 3000000);
  run (&p->net, NULL, 5000000);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  /* The server, which followed the client to the new address, searched
     afresh.  The client, whose own network did not change and which sends
     only small packets, has no reason to.  */
  gq_conn_get_stats (p->srv.c, &st);
  CHECK (st.max_datagram_size <= 1300);
  CHECK (st.max_datagram_size >= 1300 - 16);
  pair_free (p);
}

/* A path that is left and failed to validate is gone back from: the size it
   had is its own and comes back with it.  */
static int
two_moves (struct net *n)
{
  return n->app[1]->mig >= 2;
}

static void
test_pmtu_size_is_kept_per_path (void)
{
  gq_conn_config cfg;
  struct pair *p;
  struct sbuf *s;
  gq_conn_stats st;

  memset (&cfg, 0, sizeof cfg);
  cfg.max_udp_payload = 1452;
  p = pair_new_paths (&cfg, &cfg, 73);
  settle (p);
  s = start_transfer (p, 600000);
  run (&p->net, NULL, 30000);
  p->net.out_map[0] = 3;			/* The new address cannot be  */
  p->net.m[3].alive_in = 0;			/* answered, so it fails.  */
  CHECK (run (&p->net, two_moves, 60000000));
  /* Back on the first, with what it had, before anything was sent on it.  */
  gq_conn_get_stats (p->srv.c, &st);
  CHECK_EQ (st.max_datagram_size, 1452);
  CHECK (run (&p->net, transfer_done, 60000000));
  CHECK_EQ (s->n, 600000);
  pair_free (p);
}

/* The log of the search: mtu_updated for each change of size and when the
   search ends, the probes marked as such in packet_sent and packet_lost, and
   the recovery parameters again when the datagram size they name changes.  */
static void
test_pmtu_qlog (void)
{
  struct pmtu_obs obs;
  struct pair *p = pmtu_transfer (1452, 1400, 1000000, &obs);
  gq_conn_stats st;
  size_t lost_probes = 0, e;

  for (e = 0; e < 2; e++)
    {
      const struct qsink *k = &p->qlog_sink[e];
      size_t i, n = qsink_count (k, "quic:mtu_updated");
      size_t probes = 0, big_probe = 0;
      uint64_t last_new = 0, first_old = 0;
      qline q;

      gq_conn_get_stats (e ? p->srv.c : p->cli.c, &st);
      CHECK (n >= 3);
      for (i = 0; i < n; i++)
        {
          CHECK (qsink_nth (k, "quic:mtu_updated", i, &q));
          if (i == 0 && qline_get (&q, "old"))
            first_old = strtoull (qline_get (&q, "old"), NULL, 10);
          if (i + 1 < n)
            {
              /* A change of size, and not the end of the search.  */
              CHECK (qline_is (&q, "done", "false"));
              CHECK (strtoull (qline_get (&q, "new"), NULL, 10)
                     > strtoull (qline_get (&q, "old"), NULL, 10));
            }
          else
            {
              CHECK (qline_is (&q, "done", "true"));
              last_new = strtoull (qline_get (&q, "new"), NULL, 10);
            }
          qline_free (&q);
        }
      CHECK_EQ (first_old, 1200);
      CHECK_EQ (last_new, st.max_datagram_size);
      for (i = 0; i < qsink_count (k, "quic:packet_sent"); i++)
        {
          CHECK (qsink_nth (k, "quic:packet_sent", i, &q));
          if (qline_is (&q, "is_mtu_probe_packet", "true"))
            {
              probes++;
              CHECK (strtoull (qline_get (&q, "raw.length"), NULL, 10) > 1200);
              if (qline_is_u (&q, "raw.length", 1452))
                big_probe++;
            }
          else
            CHECK (qline_get (&q, "is_mtu_probe_packet") == NULL);
          qline_free (&q);
        }
      CHECK (probes >= 4);
      CHECK (big_probe >= 3);
      for (i = 0; i < qsink_count (k, "quic:packet_lost"); i++)
        {
          CHECK (qsink_nth (k, "quic:packet_lost", i, &q));
          if (qline_is (&q, "is_mtu_probe_packet", "true"))
            lost_probes++;
          qline_free (&q);
        }
      /* The parameters are given at the start (the client's came before
         the test began to keep the log) and again for each new size, the
         last of them with the size now in use.  */
      n = qsink_count (k, "quic:recovery_parameters_set");
      CHECK (n >= qsink_count (k, "quic:mtu_updated") - 1);
      if (e == 1)
        {
          CHECK (qsink_nth (k, "quic:recovery_parameters_set", 0, &q));
          CHECK (qline_is_u (&q, "max_datagram_size", 1200));
          qline_free (&q);
        }
      CHECK (qsink_nth (k, "quic:recovery_parameters_set", n - 1, &q));
      CHECK (qline_is_u (&q, "max_datagram_size", st.max_datagram_size));
      qline_free (&q);
      CHECK_EQ (k->bad_event + k->bad_line, 0);
    }
  /* Every datagram the path dropped was a probe, and each was reported.  */
  CHECK_EQ (lost_probes, p->net.mtu_drops);
  pair_free (p);
}

/* A search that has nothing to find says so once.  */
static void
test_pmtu_qlog_nothing_to_find (void)
{
  struct pmtu_obs obs;
  struct pair *p = pmtu_transfer (1200, 0, 100000, &obs);
  const struct qsink *k = &p->qlog_sink[1];
  qline q;

  CHECK_EQ (qsink_count (k, "quic:mtu_updated"), 1);
  CHECK (qsink_nth (k, "quic:mtu_updated", 0, &q));
  CHECK (qline_is (&q, "done", "true"));
  CHECK (qline_is_u (&q, "new", 1200));
  qline_free (&q);
  CHECK_EQ (qsink_count (k, "quic:recovery_parameters_set"), 1);
  pair_free (p);
}

/* ---- Packets that arrive before their keys (RFC 9001 section 5.7) ---- */

#define MAXPIECES 64

struct piece
{
  uint8_t d[2048];
  size_t len;
};

/* A datagram split into the packets it holds (as separate datagrams, so
   that they can be delivered in another order).  */
static size_t
split_datagram (const uint8_t *d, size_t len, struct piece *out, size_t max)
{
  size_t off = 0, n = 0;

  while (off < len && n < max)
    {
      size_t used = len - off;

      if (d[off] & 0x80)
        {
          gq_long_header h;

          if (gq_long_header_parse (d + off, len - off, &h) == GQ_OK)
            used = h.packet_len;
        }
      memcpy (out[n].d, d + off, used);
      out[n].len = used;
      n++;
      off += used;
    }
  return n;
}

/* Everything FROM sends now: as datagrams, or if SPLIT as the packets in
   them.  */
static size_t
collect (gq_conn *from, uint64_t now, struct piece *out, size_t max, int split)
{
  uint8_t buf[2048];
  size_t len = 0, n = 0;
  int guard;

  for (guard = 0; guard < 100 && n < max; guard++)
    {
      CHECK_EQ (gq_conn_send (from, now, buf, sizeof buf, &len), GQ_OK);
      if (len == 0)
        break;
      if (split)
        n += split_datagram (buf, len, out + n, max - n);
      else
        {
          memcpy (out[n].d, buf, len);
          out[n].len = len;
          n++;
        }
    }
  return n;
}

static void
deliver (gq_conn *to, uint64_t now, struct piece *pc, size_t n, int reverse)
{
  size_t i;

  for (i = 0; i < n; i++)
    {
      struct piece *x = &pc[reverse ? n - 1 - i : i];

      gq_conn_recv (to, now, x->d, x->len);
    }
}

/* Run a handshake by hand, round by round, with no timers: the client's
   flight, then the server's.  What a side sends after the first flight is
   taken apart into its packets and given to the other in reverse order if
   REV_CLI / REV_SRV; and once connected the client asks for something.  */
static void
by_hand (struct pair *p, int rev_cli, int rev_srv, int rounds)
{
  static struct piece pc[MAXPIECES];
  uint64_t now = p->net.now;
  int r, asked = 0;
  size_t n;

  for (r = 0; r < rounds; r++)
    {
      if (p->cli.connected && !asked)
        {
          uint64_t id;
          uint8_t req[100];
          size_t k;

          asked = 1;
          CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
          for (k = 0; k < sizeof req; k++)
            req[k] = pat (id, k);
          CHECK (gq_conn_stream_write (p->cli.c, id, req, sizeof req) == 100);
        }
      n = collect (p->cli.c, now, pc, MAXPIECES, rev_cli && r > 0);
      now += 10000;
      deliver (p->srv.c, now, pc, n, rev_cli && r > 0);
      n = collect (p->srv.c, now, pc, MAXPIECES, rev_srv);
      now += 10000;
      deliver (p->cli.c, now, pc, n, rev_srv);
    }
  p->net.now = now;
}

static struct pair *
buffer_pair (int limit)
{
  gq_conn_config cfg;
  struct pair *p;

  memset (&cfg, 0, sizeof cfg);
  cfg.max_buffered_packets = limit;
  p = pair_new (&cfg, &cfg, 0, 80);
  p->qlog_sink[0].keep = p->qlog_sink[1].keep = 1;
  if (getenv ("QDUMP"))
    p->qlog_sink[0].dump = p->qlog_sink[1].dump = 1;
  return p;
}

static size_t
count_dropped (const struct qsink *k, const char *trigger)
{
  size_t i, c = 0;
  qline q;

  for (i = 0; i < qsink_count (k, "quic:packet_dropped"); i++)
    {
      CHECK (qsink_nth (k, "quic:packet_dropped", i, &q));
      if (qline_is (&q, "trigger", trigger))
        c++;
      qline_free (&q);
    }
  return c;
}

static size_t
count_received_after_keys (const struct qsink *k)
{
  size_t i, c = 0;
  qline q;

  for (i = 0; i < qsink_count (k, "quic:packet_received"); i++)
    {
      CHECK (qsink_nth (k, "quic:packet_received", i, &q));
      if (qline_is (&q, "trigger", "keys_available"))
        c++;
      qline_free (&q);
    }
  return c;
}

/* The server's first flight arrives with its Handshake packets ahead of the
   Initial that gives the client the keys for them: they are held and read
   when the keys come, and the handshake needs no retransmission.  */
static void
test_buffer_handshake_before_initial (void)
{
  struct pair *p = buffer_pair (0);
  gq_conn_stats st;

  by_hand (p, 0, 1, 6);
  CHECK (p->cli.connected && p->srv.connected);
  gq_conn_get_stats (p->cli.c, &st);
  CHECK (st.packets_buffered >= 1);
  CHECK (qsink_count (&p->qlog_sink[0], "quic:packet_buffered") >= 1);
  {
    qline q;
    size_t i, handshake = 0;

    for (i = 0; i < qsink_count (&p->qlog_sink[0], "quic:packet_buffered");
         i++)
      {
        CHECK (qsink_nth (&p->qlog_sink[0], "quic:packet_buffered", i, &q));
        CHECK (qline_is (&q, "trigger", "keys_unavailable"));
        if (qline_is (&q, "header.packet_type", "handshake"))
          handshake++;
        qline_free (&q);
      }
    CHECK (handshake >= 1);
  }
  CHECK (count_received_after_keys (&p->qlog_sink[0]) >= 1);
  CHECK_EQ (count_dropped (&p->qlog_sink[0], "key_unavailable"), 0);
  CHECK_EQ (p->qlog_sink[0].bad_event + p->qlog_sink[0].bad_line, 0);
  CHECK_EQ (p->cli.c->n_held, 0);
  pair_free (p);

  /* With the buffering off, the same order costs the handshake.  */
  p = buffer_pair (-1);
  by_hand (p, 0, 1, 6);
  CHECK (!(p->cli.connected && p->srv.connected));
  gq_conn_get_stats (p->cli.c, &st);
  CHECK_EQ (st.packets_buffered, 0);
  CHECK (count_dropped (&p->qlog_sink[0], "key_unavailable") >= 1);
  pair_free (p);
}

/* A 1-RTT packet ahead of the client's Finished, which gives the server its
   keys: held, and the request in it is not lost.  */
static void
test_buffer_one_rtt_before_finished (void)
{
  struct pair *p = buffer_pair (0);
  gq_conn_stats st;

  by_hand (p, 1, 0, 8);
  CHECK (p->cli.connected && p->srv.connected);
  gq_conn_get_stats (p->srv.c, &st);
  CHECK (st.packets_buffered >= 1);
  CHECK_EQ (p->srv.total_in, 100);
  CHECK_EQ (p->srv.c->n_held, 0);
  pair_free (p);

  p = buffer_pair (-1);
  by_hand (p, 1, 0, 8);
  gq_conn_get_stats (p->srv.c, &st);
  CHECK_EQ (st.packets_buffered, 0);
  CHECK_EQ (p->srv.total_in, 0);
  pair_free (p);
}

/* A short-header packet with the connection ID of CONN, which nothing can
   open: garbage after the header.  */
static size_t
junk_short (const gq_conn *conn, uint8_t *out, uint8_t salt)
{
  size_t i, n = 0;

  out[n++] = 0x40 | (salt & 0x1f);
  memcpy (out + n, conn->l[0].cid.data, conn->l[0].cid.len);
  n += conn->l[0].cid.len;
  for (i = 0; i < 60; i++)
    out[n++] = (uint8_t) (salt * 7 + i);
  return n;
}

/* Plausible packets that cannot be read are held only up to the limit, and
   what is held is freed when the keys come and they prove to be junk.  */
static void
test_buffer_is_bounded (void)
{
  gq_conn_config cfg;
  struct pair *p;
  static struct piece pc[MAXPIECES];
  uint8_t junk[200];
  size_t n, len;
  int i;
  gq_conn_stats st;

  memset (&cfg, 0, sizeof cfg);
  cfg.max_buffered_packets = 5;
  p = pair_new (&cfg, &cfg, 0, 81);
  p->qlog_sink[0].keep = p->qlog_sink[1].keep = 1;
  /* The client's Initial starts the server, whose 1-RTT keys come with the
     client's Finished.  */
  n = collect (p->cli.c, p->net.now, pc, MAXPIECES, 0);
  deliver (p->srv.c, p->net.now, pc, n, 0);
  for (i = 0; i < 40; i++)
    {
      len = junk_short (p->srv.c, junk, (uint8_t) i);
      gq_conn_recv (p->srv.c, p->net.now, junk, len);
    }
  CHECK_EQ (p->srv.c->n_held, 5);
  gq_conn_get_stats (p->srv.c, &st);
  CHECK_EQ (st.packets_buffered, 5);
  CHECK_EQ (count_dropped (&p->qlog_sink[1], "rejected"), 35);
  CHECK_EQ (qsink_count (&p->qlog_sink[1], "quic:packet_buffered"), 5);
  /* Not one of our connection IDs: not worth holding.  */
  junk[1] ^= 0xff;
  gq_conn_recv (p->srv.c, p->net.now, junk, len);
  CHECK_EQ (p->srv.c->n_held, 5);
  CHECK_EQ (count_dropped (&p->qlog_sink[1], "connection_unknown"), 1);
  /* Finish the handshake: the keys come, the junk does not open and goes.  */
  by_hand (p, 0, 0, 6);
  CHECK (p->cli.connected && p->srv.connected);
  CHECK_EQ (p->srv.c->n_held, 0);
  CHECK_EQ (count_dropped (&p->qlog_sink[1], "decryption_failure"), 5);
  CHECK_EQ (p->srv.bad, 0);
  pair_free (p);
}

/* Packets held for the Handshake keys are let go when those keys are
   discarded for good.  */
static void
test_buffer_freed_with_the_keys (void)
{
  struct pair *p = buffer_pair (0);
  gq_conn *c = p->cli.c;
  uint8_t junk[200];
  size_t i, n = 0;

  /* Long-header Handshake packets for the client, which has no Handshake
     keys yet: v1 or v2 code points as the connection has.  */
  for (i = 0; i < 3; i++)
    {
      gq_long_header h;
      uint8_t cid_len = c->l[0].cid.len;

      n = 0;
      junk[n++] = c->version == GQ_VERSION_2 ? 0xd0 : 0xe0;
      junk[n++] = (uint8_t) (c->version >> 24);
      junk[n++] = (uint8_t) (c->version >> 16);
      junk[n++] = (uint8_t) (c->version >> 8);
      junk[n++] = (uint8_t) c->version;
      junk[n++] = cid_len;
      memcpy (junk + n, c->l[0].cid.data, cid_len);
      n += cid_len;
      junk[n++] = 4;
      memcpy (junk + n, "\x01\x02\x03\x04", 4);
      n += 4;
      junk[n++] = 0x40;		/* Length: 64.  */
      junk[n++] = 0x40;
      memset (junk + n, (int) (i + 1), 64);
      n += 64;
      CHECK_EQ (gq_long_header_parse (junk, n, &h), GQ_OK);
      gq_conn_recv (c, p->net.now, junk, n);
    }
  CHECK_EQ (c->n_held, 3);
  conn_discard_space (c, SP_HANDSHAKE);
  CHECK_EQ (c->n_held, 0);
  CHECK_EQ (count_dropped (&p->qlog_sink[0], "key_unavailable"), 3);
  pair_free (p);
}

/* ---- The server's preferred address (RFC 9000 section 9.6) ---- */

struct pref_hook
{
  unsigned calls;
  gq_path client;
  int answer;		/* What to return.  */
  int zero_ports;	/* Offer addresses that cannot be used.  */
};

static int
pref_cb (void *user, const gq_path *client, gq_preferred_address *out)
{
  struct pref_hook *h = user;

  h->calls++;
  h->client = *client;
  memset (out, 0, sizeof *out);
  if (!h->zero_ports)
    {
      memset (out->ipv4, 0x0a, 4);
      out->ipv4[3] = 7;
      out->ipv4_port = 4433;
      out->ipv6[15] = 1;
      out->ipv6_port = 4434;
    }
  return h->answer;
}

static struct pair *
pref_pair (struct pref_hook *h, gq_conn_config *scfg, uint32_t seed)
{
  gq_conn_config cc;
  struct pair *p;

  memset (&cc, 0, sizeof cc);
  scfg->preferred_address = pref_cb;
  scfg->preferred_address_user = h;
  p = pair_new_paths (&cc, scfg, seed);
  p->qlog_sink[0].keep = p->qlog_sink[1].keep = 1;
  settle (p);
  return p;
}

/* The server names an address for the client as the connection starts and
   puts it in its transport parameters with a connection ID of sequence 1,
   the stateless reset token that goes with it, and no NEW_CONNECTION_ID
   frame to say it again; the client keeps the ID as the peer's second.  */
static void
test_preferred_address_offered (void)
{
  struct pref_hook h;
  gq_conn_config sc;
  struct pair *p;
  gq_conn *cli, *srv;
  const gq_preferred_address *pa;
  size_t i, frames = 0, found = 0;
  qline q;

  memset (&h, 0, sizeof h);
  h.answer = 1;
  memset (&sc, 0, sizeof sc);
  p = pref_pair (&h, &sc, 90);
  cli = p->cli.c;
  srv = p->srv.c;
  CHECK_EQ (h.calls, 1);
  CHECK (h.client.remote.len > 0);		/* Where the client is.  */
  CHECK (addr_same (&h.client.remote, &p->net.m[0].ext));
  /* What the client was told.  */
  CHECK (gq_tp_has (&cli->peer_tp, GQ_TP_PREFERRED_ADDRESS));
  pa = &cli->peer_tp.preferred_address;
  CHECK_EQ (pa->ipv4_port, 4433);
  CHECK_EQ (pa->ipv4[3], 7);
  CHECK_EQ (pa->ipv6_port, 4434);
  CHECK_EQ (pa->ipv6[15], 1);
  CHECK_EQ (pa->cid.len, srv->cfg.cid_len);
  /* It is the server's second connection ID, announced already.  */
  CHECK (srv->l[1].used && srv->l[1].seq == 1 && srv->l[1].announced
         && !srv->l[1].need_send);
  CHECK (srv->l[1].cid.len == pa->cid.len
         && !memcmp (srv->l[1].cid.data, pa->cid.data, pa->cid.len));
  CHECK (!memcmp (srv->l[1].token, pa->reset_token, GQ_RESET_TOKEN_LEN));
  CHECK (memcmp (srv->l[1].cid.data, srv->l[0].cid.data, srv->l[1].cid.len));
  /* The client has it as sequence 1 with the token.  */
  for (i = 0; i < MAX_PCID; i++)
    if (cli->p[i].used && cli->p[i].seq == 1)
      {
        found++;
        CHECK (cli->p[i].has_token);
        CHECK (!memcmp (cli->p[i].token, pa->reset_token, GQ_RESET_TOKEN_LEN));
        CHECK (cli->p[i].cid.len == pa->cid.len
               && !memcmp (cli->p[i].cid.data, pa->cid.data, pa->cid.len));
      }
  CHECK_EQ (found, 1);
  /* Further IDs come in frames from sequence 2, never 1.  */
  for (i = 0; i < qsink_count (&p->qlog_sink[1], "quic:packet_sent"); i++)
    {
      size_t f;

      CHECK (qsink_nth (&p->qlog_sink[1], "quic:packet_sent", i, &q));
      for (f = 0; f < 8; f++)
        {
          char key[48];

          snprintf (key, sizeof key, "frames.%zu.frame_type", f);
          if (qline_is (&q, key, "new_connection_id"))
            {
              snprintf (key, sizeof key, "frames.%zu.sequence_number", f);
              frames++;
              CHECK (!qline_is (&q, key, "1"));
              CHECK (!qline_is (&q, key, "0"));
            }
        }
      qline_free (&q);
    }
  CHECK (frames >= 1);
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  CHECK_EQ (p->srv.closed + p->cli.closed, 0);
  pair_free (p);
}

/* The largest parameters the server sends still fit: 20-byte connection IDs
   everywhere, the preferred address, and all the options.  */
static void
test_preferred_address_large_params (void)
{
  struct pref_hook h;
  gq_conn_config sc;
  struct pair *p;

  memset (&h, 0, sizeof h);
  h.answer = 1;
  memset (&sc, 0, sizeof sc);
  sc.cid_len = 20;
  sc.max_datagram_frame_size = 1200;
  sc.disable_active_migration = 1;
  p = pref_pair (&h, &sc, 95);
  CHECK (gq_tp_has (&p->cli.c->peer_tp, GQ_TP_PREFERRED_ADDRESS));
  CHECK_EQ (p->cli.c->peer_tp.preferred_address.cid.len, 20);
  CHECK (gq_tp_has (&p->cli.c->peer_tp, GQ_TP_DISABLE_ACTIVE_MIGRATION));
  CHECK_EQ (p->srv.closed + p->cli.closed, 0);
  pair_free (p);
}

/* Not offered: no hook, a hook that declines, and one that offers what
   cannot be used.  */
static void
test_preferred_address_not_offered (void)
{
  struct pref_hook h;
  gq_conn_config sc;
  struct pair *p;
  gq_conn_config cc;
  int k;

  /* No hook at all.  */
  memset (&sc, 0, sizeof sc);
  memset (&cc, 0, sizeof cc);
  p = pair_new_paths (&cc, &sc, 91);
  settle (p);
  CHECK (!gq_tp_has (&p->cli.c->peer_tp, GQ_TP_PREFERRED_ADDRESS));
  pair_free (p);
  for (k = 0; k < 2; k++)
    {
      memset (&h, 0, sizeof h);
      h.answer = k == 0 ? 0 : 1;	/* Declined; or nothing usable.  */
      h.zero_ports = k == 1;
      memset (&sc, 0, sizeof sc);
      p = pref_pair (&h, &sc, 92 + (uint32_t) k);
      CHECK_EQ (h.calls, 1);
      CHECK (!gq_tp_has (&p->cli.c->peer_tp, GQ_TP_PREFERRED_ADDRESS));
      CHECK_EQ (p->srv.closed + p->cli.closed, 0);
      /* The second ID is an ordinary one, announced in a frame.  */
      CHECK (p->srv.c->l[1].used && p->srv.c->l[1].seq == 1);
      pair_free (p);
    }
}

/* As settle, for a connection that is allowed to move.  */
static void
settle_moving (struct pair *p)
{
  CHECK (run (&p->net, both_connected, 30000000));
  run (&p->net, NULL, 1000000);
}

/* The preferred address taken up: the client moves to the server's second
   address with the connection ID that came with it, the path is validated
   from both ends, the old ID is retired, and the rest of the connection
   goes by the new address only.  */
static void
test_preferred_address_migration (void)
{
  struct pref_hook h;
  gq_conn_config sc;
  gq_conn_config cc;
  struct pair *p;
  struct sbuf *s;
  gq_path cur;
  gq_conn_stats st;
  uint64_t before;

  memset (&h, 0, sizeof h);
  h.answer = 1;
  memset (&sc, 0, sizeof sc);
  memset (&cc, 0, sizeof cc);
  sc.preferred_address = pref_cb;
  sc.preferred_address_user = &h;
  p = pair_new_paths (&cc, &sc, 100);
  p->cli.pref_take = 1;
  p->qlog_sink[0].keep = p->qlog_sink[1].keep = 1;
  settle_moving (p);
  CHECK_EQ (p->cli.pref_events, 1);
  CHECK_EQ (p->cli.pref_take, 0);		/* Taken up.  */
  CHECK_EQ (p->cli.pref.ipv4_port, 4433);
  CHECK_EQ (gq_conn_get_path (p->cli.c, &cur), GQ_OK);
  CHECK (addr_same (&cur.remote, &p->net.S2));
  CHECK_EQ (p->cli.pv, 1);
  CHECK_EQ (p->cli.mig, 1);
  CHECK_EQ (p->cli.c->dcid_seq, 1);		/* The offered ID.  */
  CHECK (p->net.s2_to > 0 && p->net.s2_from > 0);
  gq_conn_get_stats (p->srv.c, &st);
  CHECK_EQ (st.migrations, 1);
  CHECK (p->srv.retired >= 1);
  /* A transfer goes by the second address and not the first.  */
  before = p->net.s1_to;
  s = start_transfer (p, 400000);
  CHECK (run (&p->net, transfer_done, 60000000));
  CHECK_EQ (s->n, 400000);
  CHECK_EQ (p->net.s1_to, before);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  CHECK (qsink_count (&p->qlog_sink[0], "quic:migration_state_updated") >= 3);
  /* Once; and no second go at it.  */
  CHECK_EQ (gq_conn_migrate_preferred (p->cli.c, p->net.now, &cur),
            GQ_ERR_INVAL);
  pair_free (p);
}

/* The new address does not answer: validation fails, the client stays where
   it was and the transfer is not troubled.  */
static void
test_preferred_address_unreachable (void)
{
  struct pref_hook h;
  gq_conn_config sc;
  gq_conn_config cc;
  struct pair *p;
  struct sbuf *s;
  gq_path cur;

  memset (&h, 0, sizeof h);
  h.answer = 1;
  memset (&sc, 0, sizeof sc);
  memset (&cc, 0, sizeof cc);
  sc.preferred_address = pref_cb;
  sc.preferred_address_user = &h;
  p = pair_new_paths (&cc, &sc, 101);
  p->net.s2_dead = 1;
  p->cli.pref_take = 1;
  settle (p);
  run (&p->net, NULL, 5000000);
  CHECK_EQ (p->cli.pref_events, 1);
  CHECK (p->cli.pf >= 1);
  CHECK_EQ (gq_conn_get_path (p->cli.c, &cur), GQ_OK);
  CHECK (addr_same (&cur.remote, &p->net.S));
  s = start_transfer (p, 300000);
  CHECK (run (&p->net, transfer_done, 60000000));
  CHECK_EQ (s->n, 300000);
  CHECK_EQ (p->net.s2_from, 0);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  pair_free (p);
}

/* A server that forbids migration in general still lets a client move to the
   address it offered (RFC 9000 section 18.2), and to no other.  */
static void
test_preferred_address_with_disable_active_migration (void)
{
  struct pref_hook h;
  gq_conn_config sc;
  gq_conn_config cc;
  struct pair *p;
  gq_path np, cur;

  memset (&h, 0, sizeof h);
  h.answer = 1;
  memset (&sc, 0, sizeof sc);
  memset (&cc, 0, sizeof cc);
  sc.preferred_address = pref_cb;
  sc.preferred_address_user = &h;
  sc.disable_active_migration = 1;
  p = pair_new_paths (&cc, &sc, 102);
  p->cli.pref_take = 1;
  settle_moving (p);
  CHECK_EQ (gq_conn_get_path (p->cli.c, &cur), GQ_OK);
  CHECK (addr_same (&cur.remote, &p->net.S2));
  np.local = p->net.L[1];
  np.remote = p->net.S2;
  CHECK_EQ (gq_conn_migrate (p->cli.c, p->net.now, &np), GQ_ERR_UNAVAILABLE);
  pair_free (p);
}

/* The client that does not take it up stays where it is, can still do so
   later, and a call without an offer is refused.  */
static void
test_preferred_address_declined_then_taken (void)
{
  struct pref_hook h;
  gq_conn_config sc;
  gq_conn_config cc;
  struct pair *p;
  gq_path np, cur;

  memset (&h, 0, sizeof h);
  h.answer = 1;
  memset (&sc, 0, sizeof sc);
  memset (&cc, 0, sizeof cc);
  sc.preferred_address = pref_cb;
  sc.preferred_address_user = &h;
  p = pair_new_paths (&cc, &sc, 103);
  settle (p);
  CHECK_EQ (p->cli.pref_events, 1);
  CHECK_EQ (gq_conn_get_path (p->cli.c, &cur), GQ_OK);
  CHECK (addr_same (&cur.remote, &p->net.S));
  /* A server cannot.  */
  np.local = p->net.S2;
  np.remote = p->net.L[0];
  CHECK_EQ (gq_conn_migrate_preferred (p->srv.c, p->net.now, &np),
            GQ_ERR_UNAVAILABLE);
  /* Later, the client does.  */
  np.local = p->net.L[0];
  np.remote = p->net.S2;
  CHECK_EQ (gq_conn_migrate_preferred (p->cli.c, p->net.now, &np), GQ_OK);
  run (&p->net, NULL, 1000000);
  CHECK_EQ (gq_conn_get_path (p->cli.c, &cur), GQ_OK);
  CHECK (addr_same (&cur.remote, &p->net.S2));
  pair_free (p);

  /* No offer, nothing to move to.  */
  memset (&sc, 0, sizeof sc);
  p = pair_new_paths (&cc, &sc, 104);
  settle (p);
  CHECK_EQ (p->cli.pref_events, 0);
  np.local = p->net.L[0];
  np.remote = p->net.S2;
  CHECK_EQ (gq_conn_migrate_preferred (p->cli.c, p->net.now, &np),
            GQ_ERR_UNAVAILABLE);
  pair_free (p);
}

/* The packets a connection sends in the ordinary way are not path MTU
   probes, whatever the heap held when they were made: the mark is part of
   the storage a packet is assembled in, which is not cleared.  Looked at
   while the first flights are still unacknowledged (the latency is 10 ms
   each way, so the client's Initial packets are known to the server and
   the server's flight is on its way).  */
static void
test_ordinary_packets_are_not_mtu_probes (void)
{
  struct pair *p;
  gq_conn_config cfg;
  int k, s;
  size_t j, seen[2] = { 0, 0 };

  memset (&cfg, 0, sizeof cfg);
  g_server_ident = &fx_rsa;
  p = pair_new (&cfg, &cfg, 0, 1);
  g_server_ident = NULL;
  run (&p->net, NULL, 15000);
  for (k = 0; k < 2; k++)
    for (s = 0; s < N_SPACES; s++)
      {
        const space *sp = &(k ? p->srv.c : p->cli.c)->sp[s];

        for (j = 0; j < sp->n_sent; j++)
          {
            CHECK_EQ (sp->sent[j].pmtu_probe, 0);
            seen[k]++;
          }
      }
  CHECK (seen[0] >= 2 && seen[1] >= 4);	/* There was something to look at.  */
  pair_free (p);
}

int
main (void)
{
  perturb_allocations ();
  gq_crypto_init ();
  fx_setup ();
  test_ordinary_packets_are_not_mtu_probes ();
  test_retired_cid_on_all_paths ();
  test_pto_backoff_kept_until_validated ();
  test_blackout_is_not_persistent_congestion ();
  test_previous_keys_expire ();
  test_integrity_limit ();
  test_confidentiality_limit ();
  test_huge_ack_delay ();
  test_amplification_ignores_wrong_source ();
  test_initial_waits_for_amplification_credit ();
  test_no_probe_timer_without_credit ();
  test_first_update_waits_for_a_1rtt_ack ();
  test_acked_acks_are_retired ();
  test_persistent_congestion_over_several_rounds ();
  test_stream_frames_after_the_end ();
  test_flow_windows_are_clamped ();
  test_idle_timeout_does_not_wrap ();
  test_stream_and_credit_violations ();
  test_reset_tokens_of_unused_ids ();
  test_client_discards_bad_server_packets ();
  test_application_close_in_initial ();
  test_new_cid_to_zero_length_peer ();
  test_client_path_not_set_by_garbage ();
  test_early_failures_are_counted ();
  test_qlog_reset_tokens_are_opt_in ();
  test_retire_of_unsent_cid ();
  test_tiny_long_packets_are_dropped ();
  test_server_first_flight_padded ();
  test_padding_not_in_1rtt ();
  test_handshake_probes_carry_crypto ();
  test_challenge_first_on_new_path ();
  test_window_unused_does_not_grow ();
  test_pacing_deadline ();
  test_qlog_clock_going_back ();
  test_spin_bit_selection ();
  test_spin_bit_rules ();
  test_spin_bit ();
  test_spin_bit_disabled ();
  test_spin_bit_qlog ();
  test_ecn_receive_counts ();
  test_ecn_ce_acked_at_once ();
  test_ecn_receive_transfer ();
  test_ecn_validates ();
  test_ecn_off_without_the_api ();
  test_ecn_bleached_path ();
  test_ecn_dropping_path ();
  test_ecn_ce_is_congestion ();
  test_ecn_validation_of_counts ();
  test_ecn_restarts_on_new_path ();
  test_pmtu_discovers ();
  test_pmtu_ceiling_reached ();
  test_pmtu_ceiling_is_a_ceiling ();
  test_pmtu_waits_for_the_handshake ();
  test_pmtu_probe_loss_is_not_congestion ();
  test_pmtu_controller_follows ();
  test_pmtu_default_ceiling ();
  test_pmtu_black_hole ();
  test_pmtu_raise_timer ();
  test_pmtu_new_path_is_smaller ();
  test_pmtu_size_is_kept_per_path ();
  test_pmtu_qlog ();
  test_pmtu_qlog_nothing_to_find ();
  test_buffer_handshake_before_initial ();
  test_buffer_one_rtt_before_finished ();
  test_buffer_is_bounded ();
  test_buffer_freed_with_the_keys ();
  test_preferred_address_offered ();
  test_preferred_address_not_offered ();
  test_preferred_address_large_params ();
  test_preferred_address_migration ();
  test_preferred_address_unreachable ();
  test_preferred_address_with_disable_active_migration ();
  test_preferred_address_declined_then_taken ();
  TST_DONE ();
}

#else

int
main (void)
{
  return 77;
}

#endif
