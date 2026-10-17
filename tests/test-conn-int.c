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
  s->aead_failed = limit - 1;
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
pmtu_transfer (size_t ceiling, size_t mtu, size_t resp, struct pmtu_obs *obs)
{
  gq_conn_config cfg;
  struct pair *p;
  struct sbuf *s;
  uint64_t id;

  memset (&cfg, 0, sizeof cfg);
  cfg.initial_max_data = 100u << 20;
  cfg.initial_max_stream_data = 100u << 20;
  cfg.max_udp_payload = ceiling;
  p = pair_new (&cfg, &cfg, 0, 70);
  p->qlog_sink[0].keep = p->qlog_sink[1].keep = 1;
  p->net.latency = 20000;
  p->net.mtu = mtu;
  memset (obs, 0, sizeof *obs);
  obs->limit = mtu;
  p->net.snoop = pmtu_snoop;
  p->net.snoop_user = obs;
  p->srv.respond = resp;
  CHECK (run (&p->net, both_connected, 30000000));
  CHECK_EQ (gq_conn_stream_open (p->cli.c, 1, &id), GQ_OK);
  s = sb_get (&p->cli, id);
  s->out_total = 10;
  s->out_fin = 1;
  CHECK (wait_for_stream (p, s, resp, 60000000));
  run (&p->net, NULL, 2000000);
  CHECK_EQ (p->cli.bad + p->srv.bad, 0);
  CHECK_EQ (p->cli.closed + p->srv.closed, 0);
  return p;
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

int
main (void)
{
  gq_crypto_init ();
  fx_setup ();
  test_retired_cid_on_all_paths ();
  test_pto_backoff_kept_until_validated ();
  test_blackout_is_not_persistent_congestion ();
  test_previous_keys_expire ();
  test_integrity_limit ();
  test_confidentiality_limit ();
  test_huge_ack_delay ();
  test_initial_waits_for_amplification_credit ();
  test_no_probe_timer_without_credit ();
  test_first_update_waits_for_a_1rtt_ack ();
  test_acked_acks_are_retired ();
  test_persistent_congestion_over_several_rounds ();
  test_stream_frames_after_the_end ();
  test_server_first_flight_padded ();
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
  TST_DONE ();
}

#else

int
main (void)
{
  return 77;
}

#endif
