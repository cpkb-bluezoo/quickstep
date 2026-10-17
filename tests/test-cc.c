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

/* The congestion controller and the pacer (src/cc.c) on their own: NewReno
   (RFC 9002 section 7), CUBIC (RFC 9438), HyStart++ (RFC 9406) and the token
   bucket of RFC 9002 section 7.7.  Windows are in bytes with a 1200-byte
   datagram, so 120000 bytes is 100 segments.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "cc.h"

#include "tst-util.h"

#define MSS 1200u
#define RTT 100000u
#define TOLERANCE 0.08

/* ---- Helpers ---- */

static cong
new_cong (int algo)
{
  cong cc;

  cong_init (&cc, algo, MSS);
  return cc;
}

/* Grow the window to BYTES in slow start.  */
static void
grow_to (cong *cc, uint64_t bytes, uint64_t now)
{
  cong_on_ack (cc, now - 1, (uint32_t) (bytes - cc->cwnd), 1, now, RTT);
  CHECK_EQ (cc->cwnd, bytes);
}

/* One round trip of acknowledgements, a window's worth in whole datagrams,
   each sent a round trip ago.  Returns the new time.  */
static uint64_t
round_trip (cong *cc, uint64_t now, uint64_t rtt)
{
  uint64_t window = cc->cwnd, acked;

  for (acked = 0; acked + MSS <= window; acked += MSS)
    cong_on_ack (cc, now - rtt, MSS, 1, now, rtt);
  return now + rtt;
}

static void
near (const char *what, double expected, uint64_t actual)
{
  double d = (double) actual - expected;

  if (d < 0)
    d = -d;
  if (d > expected * TOLERANCE)
    {
      fprintf (stderr, "%s: expected about %.0f but was %llu\n", what,
               expected, (unsigned long long) actual);
      tst_failures++;
    }
}

/* ---- The cube root ---- */

static void
test_cbrt (void)
{
  double xs[] = { 1, 2, 8, 27, 0.001, 75, 1e12, 3.5e-7, 123456789.0 };
  size_t i;

  CHECK (cong_cbrt (0) == 0);
  CHECK (cong_cbrt (-8) == 0);
  for (i = 0; i < sizeof xs / sizeof xs[0]; i++)
    {
      double r = cong_cbrt (xs[i]), e = r * r * r - xs[i];

      if (e < 0)
        e = -e;
      CHECK (e <= xs[i] * 1e-12);
    }
}

/* ---- The pacer ---- */

/* A 12000-byte window over a 100 ms round trip: 0.12 bytes per microsecond,
   1200 bytes per 10 ms.  */
#define RATE 0.12

static void
test_pacer_burst (void)
{
  pacer p;
  int i;

  pacer_init (&p, 12000, MSS);
  for (i = 0; i < 10; i++)
    {
      CHECK_EQ (pacer_delay (&p, MSS, 1000, RATE, 0), 0);
      pacer_on_sent (&p, MSS, 1000, RATE, 0);
    }
  /* The bucket is empty: one more datagram takes 1200 / 0.12 = 10000 us.  */
  CHECK_EQ (pacer_delay (&p, MSS, 1000, RATE, 0), 10000);
}

/* Credit accrues from the time of the check, not from when it was due: a
   late timer does not lose any.  */
static void
test_pacer_late_check (void)
{
  pacer p;

  pacer_init (&p, 12000, MSS);
  pacer_on_sent (&p, 12000, 1000, RATE, 0);
  /* Four ms later: 480 bytes, 720 short, 6000 us to go.  */
  CHECK_EQ (pacer_delay (&p, MSS, 5000, RATE, 0), 6000);
  /* Ten ms from the start is exactly one datagram.  */
  CHECK_EQ (pacer_delay (&p, MSS, 11000, RATE, 0), 0);
}

/* However long it is idle, the bucket never holds more than the burst.  */
static void
test_pacer_burst_cap (void)
{
  pacer p;
  int i;

  pacer_init (&p, 12000, MSS);
  pacer_on_sent (&p, 12000, 1000, RATE, 1);
  for (i = 0; i < 10; i++)
    pacer_on_sent (&p, MSS, 1000001, RATE, i == 0);
  CHECK_EQ (pacer_delay (&p, MSS, 1000001, RATE, 0), 10000);
}

/* 1 Gbit/s is 125 bytes per microsecond: a millisecond timer that could
   release only the 12000-byte burst would cap sending at 96 Mbit/s, so a
   tick's worth of credit is always allowed.  */
static void
test_pacer_tick_at_high_rates (void)
{
  double rate = 125.0;
  pacer p;
  int sent = 0;

  pacer_init (&p, 12000, MSS);
  pacer_on_sent (&p, 12000, 1000, rate, 0);
  CHECK (pacer_delay (&p, MSS, 1000, rate, 0) > 0);
  /* A tick later: 125000 bytes, 104 datagrams.  */
  while (pacer_delay (&p, MSS, 2000, rate, 0) == 0 && sent < 200)
    {
      pacer_on_sent (&p, MSS, 2000, rate, 0);
      sent++;
    }
  CHECK_EQ (sent, 104);
  /* However long the wait with data in flight, no more than a tick plus
     one datagram: 126200 bytes, 105 datagrams.  */
  sent = 0;
  while (pacer_delay (&p, MSS, 5000000, rate, 0) == 0 && sent < 200)
    {
      pacer_on_sent (&p, MSS, 5000000, rate, 0);
      sent++;
    }
  CHECK_EQ (sent, 105);
}

/* From idle, RFC 9002 section 7.7 lets the whole initial window go.  */
static void
test_pacer_from_idle (void)
{
  pacer p;
  int sent = 0;

  pacer_init (&p, 12000, MSS);
  while (pacer_delay (&p, MSS, 1000000, RATE, 1) == 0 && sent < 20)
    {
      pacer_on_sent (&p, MSS, 1000000, RATE, sent == 0);
      sent++;
    }
  CHECK_EQ (sent, 10);
}

/* While the sender waits on the window with data in flight, credit must not
   pile up into a burst for the next acknowledgement to release: at 1 Mbit/s
   a tick is a tenth of a datagram, so after any wait at all exactly one
   datagram may leave and the next waits its turn.  Pairs of datagrams
   arriving back to back at a nearly full queue lose one where a single
   gets through.  */
static void
test_pacer_singles_in_flight (void)
{
  pacer p;

  pacer_init (&p, 12000, MSS);
  pacer_on_sent (&p, 12000, 1000, RATE, 1);
  CHECK (pacer_delay (&p, MSS, 1000, RATE, 0) > 0);
  CHECK_EQ (pacer_delay (&p, MSS, 101000, RATE, 0), 0);
  pacer_on_sent (&p, MSS, 101000, RATE, 0);
  CHECK (pacer_delay (&p, MSS, 101000, RATE, 0) > 0);
  /* A tick later there is still less than a datagram.  */
  CHECK (pacer_delay (&p, MSS, 102000, RATE, 0) > 0);
  CHECK_EQ (pacer_delay (&p, MSS, 112000, RATE, 0), 0);
}

/* A surplus earned at a high rate is not spent as a burst once the rate has
   dropped, which is just after a loss.  */
static void
test_pacer_no_stale_surplus (void)
{
  pacer p;
  int sent = 0;

  pacer_init (&p, 12000, MSS);
  pacer_on_sent (&p, 12000, 1000, 125.0, 0);
  /* A tick at 1 Gbit/s earns 125000 bytes...  */
  CHECK_EQ (pacer_delay (&p, MSS, 2000, 125.0, 0), 0);
  /* ...but at 1 Mbit/s, with data in flight, what is held drops to the
     burst and a datagram at most.  */
  while (pacer_delay (&p, MSS, 3000, RATE, 0) == 0 && sent < 200)
    {
      pacer_on_sent (&p, MSS, 3000, RATE, 0);
      sent++;
    }
  CHECK (sent <= 10);
}

static void
test_pacer_time (void)
{
  pacer p;

  /* The clock has any origin, and never needs to run forwards.  */
  pacer_init (&p, 12000, MSS);
  pacer_on_sent (&p, 12000, 5000000000ull, RATE, 0);
  CHECK_EQ (pacer_delay (&p, MSS, 5000000000ull, RATE, 0), 10000);
  CHECK_EQ (pacer_delay (&p, MSS, 4999990000ull, RATE, 0), 10000);
  CHECK_EQ (pacer_delay (&p, MSS, 5000010000ull, RATE, 0), 0);
}

static void
test_pacer_unpaced (void)
{
  pacer p;
  int i;

  pacer_init (&p, 12000, MSS);
  for (i = 0; i < 100; i++)
    pacer_on_sent (&p, MSS, 1000, 0, 0);
  CHECK_EQ (pacer_delay (&p, MSS, 1000, 0, 0), 0);
}

static void
test_pacer_rate (void)
{
  /* 1.25 windows per round trip in congestion avoidance, 2 in slow start,
     none without a round trip time.  */
  CHECK (pacer_rate (12000, 6000, 100000) == 1.25 * 12000 / 100000);
  CHECK (pacer_rate (12000, UINT64_MAX, 100000) == 2.0 * 12000 / 100000);
  CHECK (pacer_rate (12000, UINT64_MAX, 0) == 0);
}

/* ---- NewReno ---- */

static void
test_newreno_halves (void)
{
  cong cc = new_cong (GQ_CC_NEWRENO);

  CHECK_EQ (cc.cwnd, 12000);
  grow_to (&cc, 120000, 1000);
  CHECK_EQ (cong_on_congestion_event (&cc, 500, 2000), 1);
  CHECK_EQ (cc.ssthresh, 60000);
  CHECK_EQ (cc.cwnd, 60000);
  /* Another loss of something sent before recovery began is the same event.  */
  CHECK_EQ (cong_on_congestion_event (&cc, 1500, 2500), 0);
  CHECK_EQ (cc.cwnd, 60000);
  /* The floor is two datagrams.  */
  cc = new_cong (GQ_CC_NEWRENO);
  CHECK_EQ (cong_on_congestion_event (&cc, 500, 2000), 1);
  CHECK_EQ (cong_on_congestion_event (&cc, 2500, 3000), 1);
  CHECK_EQ (cong_on_congestion_event (&cc, 3500, 4000), 1);
  CHECK_EQ (cong_on_congestion_event (&cc, 4500, 5000), 1);
  CHECK_EQ (cc.cwnd, 2 * MSS);
}

/* One datagram for each window acknowledged, exactly.  */
static void
test_newreno_avoidance (void)
{
  cong cc = new_cong (GQ_CC_NEWRENO);
  int i;

  grow_to (&cc, 24000, 1000);
  cong_on_congestion_event (&cc, 500, 2000);
  CHECK_EQ (cc.cwnd, 12000);
  /* Acknowledgements of packets sent before recovery began change nothing.  */
  cong_on_ack (&cc, 1900, 12000, 1, 3000, RTT);
  CHECK_EQ (cc.cwnd, 12000);
  for (i = 0; i < 9; i++)
    cong_on_ack (&cc, 2500, MSS, 1, 3000, RTT);
  CHECK_EQ (cc.cwnd, 12000);
  cong_on_ack (&cc, 2500, MSS, 1, 3000, RTT);
  cong_on_ack (&cc, 2500, MSS, 1, 3000, RTT);
  CHECK_EQ (cc.cwnd, 12000 + MSS);
}

/* The window grows only while it is in use (RFC 9002 section 7.8).  */
static void
test_not_limited_does_not_grow (void)
{
  int algo;

  for (algo = GQ_CC_CUBIC; algo <= GQ_CC_NEWRENO; algo++)
    {
      cong cc = new_cong (algo);
      int i;

      for (i = 0; i < 20; i++)
        cong_on_ack (&cc, 1000, MSS, 0, 2000, RTT);
      CHECK_EQ (cc.cwnd, 12000);
      cong_on_congestion_event (&cc, 500, 3000);
      for (i = 0; i < 200; i++)
        cong_on_ack (&cc, 4000, MSS, 0, 5000, RTT);
      CHECK_EQ (cc.cwnd, algo == GQ_CC_CUBIC ? 8400 : 6000);
    }
}

/* ---- CUBIC ---- */

static void
test_cubic_beta (void)
{
  cong cc = new_cong (GQ_CC_CUBIC);

  grow_to (&cc, 120000, 1000);
  cong_on_congestion_event (&cc, 500, 2000);
  /* beta_cubic = 0.7 (RFC 9438 section 4.6).  */
  CHECK_EQ (cc.ssthresh, 84000);
  CHECK_EQ (cc.cwnd, 84000);
  CHECK_EQ (cc.w_max, 120000);
}

/* Back to W_max after K seconds, and beyond.  */
static void
test_cubic_curve (void)
{
  cong cc = new_cong (GQ_CC_CUBIC);
  uint64_t now = 1000000, epoch;
  double k;

  grow_to (&cc, 120000, 1000);
  cong_on_congestion_event (&cc, 500, now);
  /* K = cbrt ((W_max - cwnd) / C) = cbrt (30 / 0.4) = 4.217 s.  */
  k = cong_cbrt (30 / 0.4);
  epoch = now;
  while (now - epoch < (uint64_t) (k * 1e6))
    now = round_trip (&cc, now, RTT);
  near ("window at t = K", 120000, cc.cwnd);
  while (now - epoch < (uint64_t) (2 * k * 1e6))
    now = round_trip (&cc, now, RTT);
  /* W_cubic (2K) = W_max + C K^3 = 100 + 30 segments.  */
  near ("window at t = 2K", 120000 + 36000, cc.cwnd);
}

/* A small window on a short path: the cubic function alone would barely
   move in ten round trips, but section 4.3 grows the window like Reno
   (alpha = 3 (1 - beta) / (1 + beta) = 0.53 segments per round trip) when
   that is faster.  */
static void
test_cubic_reno_friendly (void)
{
  cong cc = new_cong (GQ_CC_CUBIC);
  uint64_t now = 1000000;
  int i;

  cong_on_congestion_event (&cc, 500, now);
  CHECK_EQ (cc.cwnd, 8400);
  for (i = 0; i < 10; i++)
    now = round_trip (&cc, now, 10000);
  /* Cubic alone: 7.4 segments.  Reno-friendly: 7 + 10 * 0.53 = 12.3.  */
  CHECK (cc.cwnd > 13000);
}

/* Section 4.7: a loss before the window regained W_max means the capacity
   shrank, so aim lower.  */
static void
test_cubic_fast_convergence (void)
{
  cong cc = new_cong (GQ_CC_CUBIC);
  uint64_t now, window;

  grow_to (&cc, 120000, 1000);
  cong_on_congestion_event (&cc, 500, 2000);
  CHECK_EQ (cc.w_max, 120000);
  now = round_trip (&cc, 1000000, RTT);
  window = cc.cwnd;
  CHECK (window < 120000);
  cong_on_congestion_event (&cc, now - 1, now + 1);
  CHECK_EQ (cc.w_max, (uint64_t) ((double) window * (1 + 0.7) / 2));
  CHECK_EQ (cc.cwnd, (uint64_t) ((double) window * 0.7));
}

static void
test_cubic_persistent_and_reset (void)
{
  cong cc = new_cong (GQ_CC_CUBIC);

  grow_to (&cc, 120000, 1000);
  cong_on_congestion_event (&cc, 500, 900000);
  cong_on_persistent (&cc);
  CHECK_EQ (cc.cwnd, 2 * MSS);
  CHECK_EQ (cc.recovery_start, 0);
  /* Slow start again up to ssthresh; no jump towards the old W_max.  */
  round_trip (&cc, 1000000, RTT);
  CHECK_EQ (cc.cwnd, 4 * MSS);

  cong_init (&cc, GQ_CC_CUBIC, MSS);
  CHECK_EQ (cc.cwnd, 12000);
  CHECK_EQ (cc.ssthresh, UINT64_MAX);
  CHECK_EQ (cc.w_max, 0);
}

/* The initial window is ten datagrams, within RFC 9002 section 7.2's bounds.  */
static void
test_initial_window (void)
{
  cong cc;

  cong_init (&cc, GQ_CC_CUBIC, 1200);
  CHECK_EQ (cc.cwnd, 12000);
  cong_init (&cc, GQ_CC_CUBIC, 1472);
  CHECK_EQ (cc.cwnd, 14720);
  cong_init (&cc, GQ_CC_NEWRENO, 2048);
  CHECK_EQ (cc.cwnd, 14720);
  cong_init (&cc, GQ_CC_NEWRENO, 9000);
  CHECK_EQ (cc.cwnd, 18000);
}

/* ---- HyStart++ ---- */

static uint64_t hs_now, hs_sent;

static void
hs_start (void)
{
  hs_now = 1000000;
  /* When the packets acknowledged in a round were sent: as the last round's
     acknowledgements arrived, so the first of each round ends the one
     before.  */
  hs_sent = 900000;
}

/* A round trip of acknowledgements in slow start: SAMPLES round trip time
   samples at RTT_US, and a window's worth of bytes acknowledged.  */
static void
hs_round (cong *cc, uint64_t rtt_us, unsigned samples)
{
  uint64_t packets = cc->cwnd / MSS, i;

  for (i = 0; i < packets; i++)
    {
      if (i < samples)
        cong_on_rtt_sample (cc, rtt_us);
      cong_on_ack (cc, hs_sent, MSS, 1, hs_now, rtt_us);
    }
  hs_sent = hs_now;
  hs_now += rtt_us;
}

static void
test_hystart_flat_rtt (void)
{
  cong cc = new_cong (GQ_CC_NEWRENO);
  int i;

  hs_start ();
  for (i = 0; i < 6; i++)
    {
      uint64_t before = cc.cwnd;

      hs_round (&cc, RTT, 10);
      CHECK_EQ (cc.cwnd, 2 * before);
    }
  CHECK_EQ (cc.ssthresh, UINT64_MAX);
}

/* A rise of an eighth of the round trip (between 4 and 16 ms) is detected
   within the round, growth drops to a quarter, and the fifth such round
   ends slow start.  */
static void
test_hystart_rising_rtt (void)
{
  cong cc = new_cong (GQ_CC_NEWRENO);
  uint64_t before, after;
  int i;

  hs_start ();
  hs_round (&cc, RTT, 10);
  hs_round (&cc, RTT, 10);
  before = cc.cwnd;
  hs_round (&cc, RTT + 20000, 10);
  after = cc.cwnd;
  CHECK (after - before < before);
  CHECK_EQ (cc.ssthresh, UINT64_MAX);
  for (i = 0; i < 4; i++)
    {
      before = cc.cwnd;
      hs_round (&cc, RTT + 20000, 10);
      after = cc.cwnd;
      CHECK (after - before <= before / 4 + MSS);
      CHECK_EQ (cc.ssthresh, UINT64_MAX);
    }
  hs_round (&cc, RTT + 20000, 10);
  CHECK (cc.ssthresh < UINT64_MAX);
  CHECK (cc.ssthresh <= cc.cwnd);
}

/* An RTT that falls back below the level that triggered the change returns
   to normal slow start.  */
static void
test_hystart_spurious (void)
{
  cong cc = new_cong (GQ_CC_NEWRENO);
  uint64_t before;

  hs_start ();
  hs_round (&cc, RTT, 10);
  hs_round (&cc, RTT, 10);
  hs_round (&cc, RTT + 20000, 10);	/* Conservative.  */
  hs_round (&cc, RTT, 10);		/* Back below: spurious.  */
  before = cc.cwnd;
  hs_round (&cc, RTT, 10);
  CHECK_EQ (cc.cwnd, 2 * before);
  CHECK_EQ (cc.ssthresh, UINT64_MAX);
}

static void
test_hystart_few_samples (void)
{
  cong cc = new_cong (GQ_CC_NEWRENO);
  uint64_t before;

  hs_start ();
  hs_round (&cc, RTT, 7);
  hs_round (&cc, RTT, 7);
  before = cc.cwnd;
  hs_round (&cc, RTT + 50000, 7);
  CHECK_EQ (cc.cwnd, 2 * before);
}

/* Slow start that ends without a loss hands CUBIC a curve that starts at
   the window it ended at.  */
static void
test_hystart_then_cubic (void)
{
  cong cc = new_cong (GQ_CC_CUBIC);
  uint64_t exit_window, before;
  int i;

  hs_start ();
  hs_round (&cc, RTT, 10);
  hs_round (&cc, RTT, 10);
  for (i = 0; i < 6; i++)
    hs_round (&cc, RTT + 20000, 10);
  exit_window = cc.ssthresh;
  CHECK (exit_window < UINT64_MAX);
  CHECK_EQ (cc.w_max, exit_window);
  CHECK (cc.cwnd >= exit_window);
  before = cc.cwnd;
  hs_round (&cc, RTT + 20000, 10);
  CHECK (cc.cwnd > before);
}

/* A loss starts HyStart++ afresh, so a stale rise does not carry over.  */
static void
test_hystart_reset_by_loss (void)
{
  cong cc = new_cong (GQ_CC_NEWRENO);

  hs_start ();
  hs_round (&cc, RTT, 10);
  hs_round (&cc, RTT, 10);
  hs_round (&cc, RTT + 20000, 10);
  CHECK (cc.hs_css);
  cong_on_congestion_event (&cc, 500, hs_now);
  CHECK (!cc.hs_css);
  CHECK (!cc.hs_round_started);
}

/* A larger datagram (path MTU discovery) moves the minimum window and the
   growth per round trip with it, and leaves the window itself.  */
static void
test_mss_change (void)
{
  int algo;

  for (algo = GQ_CC_CUBIC; algo <= GQ_CC_NEWRENO; algo++)
    {
      cong cc = new_cong (algo);
      uint64_t before = cc.cwnd;
      pacer p;

      grow_to (&cc, 120000, 1000);
      before = cc.cwnd;
      cong_set_mss (&cc, 1452);
      CHECK_EQ (cc.mss, 1452);
      CHECK_EQ (cc.cwnd, before);
      /* So low a window that the minimum decides: twice the new size.  */
      cc.cwnd = 1000;
      cc.recovery_start = 0;
      cong_on_congestion_event (&cc, 2000, 3000);
      CHECK_EQ (cc.cwnd, 2 * 1452);
      CHECK_EQ (cc.ssthresh, 2 * 1452);
      cong_on_persistent (&cc);
      CHECK_EQ (cc.cwnd, 2 * 1452);
      pacer_init (&p, 12000, 1200);
      pacer_set_dgram (&p, 1452);
      CHECK_EQ (p.dgram, 1452);
    }
}

int
main (void)
{
  test_cbrt ();
  test_mss_change ();
  test_pacer_burst ();
  test_pacer_late_check ();
  test_pacer_burst_cap ();
  test_pacer_tick_at_high_rates ();
  test_pacer_from_idle ();
  test_pacer_singles_in_flight ();
  test_pacer_no_stale_surplus ();
  test_pacer_time ();
  test_pacer_unpaced ();
  test_pacer_rate ();
  test_newreno_halves ();
  test_newreno_avoidance ();
  test_not_limited_does_not_grow ();
  test_cubic_beta ();
  test_cubic_curve ();
  test_cubic_reno_friendly ();
  test_cubic_fast_convergence ();
  test_cubic_persistent_and_reset ();
  test_initial_window ();
  test_hystart_flat_rtt ();
  test_hystart_rising_rtt ();
  test_hystart_spurious ();
  test_hystart_few_samples ();
  test_hystart_then_cubic ();
  test_hystart_reset_by_loss ();
  TST_DONE ();
}
