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
  CHECK_EQ (gq_short_header_build (from->dcid.data, from->dcid.len, 0,
                                   from->w_phase, pn, 4, pkt, sizeof pkt,
                                   &hdr), GQ_OK);
  memcpy (pkt + hdr, pl, len);
  CHECK_EQ (gq_packet_seal (&s->wk, pn, pkt, hdr - 4, 4, len, sizeof pkt,
                            &out), GQ_OK);
  if (bad)
    pkt[out - 1] ^= 1;
  if (from_path)
    gq_conn_recv_path (to, now, from_path, pkt, out);
  else
    gq_conn_recv (to, now, pkt, out);
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
  /* Once the exchange goes through to the end, it is reset.  */
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
  s->cwnd = 100000;
  s->recovery_start = 0;
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
  CHECK (s->cwnd > CC_MIN_WINDOW);
  /* Round two, later: packet 8, sent four periods after it, is lost too.  */
  loss_detect (s, SP_APP, t0 + 4 * pto + 1000000);
  CHECK_EQ (s->cwnd, CC_MIN_WINDOW);
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
  TST_DONE ();
}

#else

int
main (void)
{
  return 77;
}

#endif
