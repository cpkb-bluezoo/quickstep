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

/* Congestion control and pacing, apart from the connection: NewReno (RFC
   9002 section 7) or CUBIC (RFC 9438) with HyStart++ (RFC 9406) in slow
   start, and the token bucket that spreads a window over the round trip
   (RFC 9002 section 7.7).  Both take the time as an argument, in
   microseconds from any origin, and know nothing of packets: the
   connection reports what it sent, what was acknowledged and what was
   lost, and asks what it may do.  Bytes in flight stay with the
   connection.  */

#ifndef QUICKSTEP_CC_H
#define QUICKSTEP_CC_H

#include <stdint.h>

#include <quickstep/conn.h>

typedef struct cong
{
  int algo;			/* GQ_CC_CUBIC or GQ_CC_NEWRENO.  */
  uint32_t mss;			/* The maximum datagram size.  */
  uint64_t cwnd, ssthresh;	/* Congestion window; UINT64_MAX: none.  */
  /* When recovery began, or 0: not in recovery.  A packet sent at or
     before then cannot end it (RFC 9002 appendix B.5).  */
  uint64_t recovery_start;
  uint64_t ca_acked;		/* NewReno: bytes acked in congestion avoidance.  */
  /* In recovery: from a congestion event until a packet sent after it is
     acknowledged.  Only for reporting; recovery_start decides.  */
  uint8_t in_recovery;

  /* CUBIC (RFC 9438 section 4).  An epoch is a stretch of congestion
     avoidance, from the first acknowledgement after a loss (or after slow
     start) to the next loss.  */
  uint64_t w_max;		/* Bytes; 0 until the first loss.  */
  uint64_t w_prior;		/* The window at the last loss.  */
  uint8_t epoch_started;
  uint64_t epoch_start;
  double k;			/* Seconds from the epoch start to w_max.  */
  double w_est;			/* The Reno-friendly estimate, bytes.  */

  /* HyStart++ (RFC 9406 section 4.2).  A round is a window's worth of
     acknowledgements; it starts when a packet sent after the previous
     round started is acknowledged.  */
  uint8_t hs_round_started, hs_css;
  uint64_t hs_round_start;
  uint64_t hs_last_min_rtt, hs_cur_min_rtt;	/* UINT64_MAX: none.  */
  unsigned hs_samples, hs_css_rounds;
  uint64_t hs_css_baseline;
} cong;

/* Start (or start again, as on a new path) with the initial window.  ALGO
   is GQ_CC_CUBIC or GQ_CC_NEWRENO.  */
void cong_init (cong *cc, int algo, uint32_t mss);

/* A packet that was in flight, sent at SENT_US and SIZE bytes long, was
   acknowledged at NOW_US.  LIMITED: the sender was held back by the window
   (or the pacer) rather than by lack of data or the peer's flow control;
   the window grows only then (RFC 9002 section 7.8).  SRTT_US is the
   smoothed round trip time, which CUBIC looks one round ahead by.  */
void cong_on_ack (cong *cc, uint64_t sent_us, uint32_t size, int limited,
                  uint64_t now_us, uint64_t srtt_us);

/* A round trip time sample (the latest, unadjusted), which HyStart++
   watches for the rise that marks the end of slow start.  */
void cong_on_rtt_sample (cong *cc, uint64_t rtt_us);

/* A packet sent at LOST_SENT_US was lost, at NOW_US.  Returns 1 if that
   began a new recovery period, 0 if it belongs to the one in progress.  */
int cong_on_congestion_event (cong *cc, uint64_t lost_sent_us,
                              uint64_t now_us);

/* Persistent congestion (RFC 9002 section 7.6.2): the minimum window.  */
void cong_on_persistent (cong *cc);

/* The cube root, without a math library.  */
double cong_cbrt (double x);

/* ---- Pacing (RFC 9002 section 7.7) ---- */

/* A token bucket.  Credit, in bytes, accrues at the pacing rate from the
   time of each check, up to a cap.  From idle (nothing in flight) the cap
   is the burst, the initial window, which the RFC lets leave at once.  With
   data in flight it is one datagram plus a timer tick's worth at the
   current rate: enough to sustain any rate with a millisecond timer, and at
   the rates a contended bottleneck allows, where a tick is a fraction of a
   datagram, it releases datagrams one at a time rather than the pair or
   more that an acknowledgement would otherwise let go together.  Credit
   accrues from when the check really runs, not from when it was due, so a
   late timer only makes the next release larger and never lowers the
   average rate.  Rates are bytes per microsecond, 0 meaning "do not
   pace".  */
typedef struct pacer
{
  double burst, credit;
  uint32_t dgram;
  uint8_t started;
  uint64_t last_us;
} pacer;

/* The coarsest timer the connection's owner is assumed to have.  */
#define PACER_TICK_US 1000u

/* The bucket starts full.  BURST is the most that may go back to back from
   idle; DGRAM the maximum datagram size.  */
void pacer_init (pacer *p, uint64_t burst, uint32_t dgram);

/* The rate for a window: 1.25 windows per round trip in congestion
   avoidance, 2 in slow start (which grows the window by up to a factor of
   two a round).  0 without a round trip time.  */
double pacer_rate (uint64_t cwnd, uint64_t ssthresh, uint64_t srtt_us);

/* How long to wait before BYTES may be sent: 0 for now.  IDLE: nothing is
   in flight.  */
uint64_t pacer_delay (pacer *p, uint32_t bytes, uint64_t now_us, double rate,
                      int idle);

/* A packet was sent.  Those that are not paced (probes) can leave the
   bucket in debt, which later sends repay by waiting; the debt is bounded
   by one burst.  IDLE: nothing was in flight before it.  */
void pacer_on_sent (pacer *p, uint32_t bytes, uint64_t now_us, double rate,
                    int idle);

#endif /* QUICKSTEP_CC_H */
