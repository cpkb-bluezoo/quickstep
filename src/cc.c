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

/* Congestion control (RFC 9002 section 7, RFC 9438, RFC 9406) and pacing
   (RFC 9002 section 7.7).  See cc.h.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>

#include "cc.h"

/* RFC 9002 section 7.3.2: NewReno halves the window on entering recovery.  */
#define NEWRENO_BETA 0.5
/* RFC 9438 section 4.6: CUBIC's multiplicative decrease factor.  */
#define CUBIC_BETA 0.7
/* RFC 9438 section 5: the cubic constant, in segments per second cubed.  */
#define CUBIC_C 0.4
/* RFC 9438 section 4.3: Reno-friendly growth per round trip, in segments:
   3 (1 - beta) / (1 + beta).  */
#define CUBIC_ALPHA (3 * (1 - CUBIC_BETA) / (1 + CUBIC_BETA))
/* RFC 9002 section 7.2: the floor on the initial window, whatever the
   datagram size.  */
#define INITIAL_WINDOW_FLOOR 14720u

/* HyStart++ (RFC 9406 section 4.2) parameters, microseconds.  */
#define HS_MIN_RTT_THRESH 4000u
#define HS_MAX_RTT_THRESH 16000u
#define HS_MIN_RTT_DIVISOR 8u
#define HS_N_RTT_SAMPLE 8u
#define HS_CSS_GROWTH_DIVISOR 4u
#define HS_CSS_ROUNDS 5u

/* The cube root by Newton's method from above, which falls monotonically to
   it.  The library needs no math library otherwise.  */
double
cong_cbrt (double x)
{
  double r, prev;
  int i;

  if (x <= 0)
    return 0;
  r = x > 1 ? x : 1;
  for (i = 0; i < 400; i++)
    {
      prev = r;
      r = (2 * r + x / (r * r)) / 3;
      if (r >= prev)
        return prev;
    }
  return r;
}

static void
hystart_reset (cong *cc)
{
  cc->hs_round_started = 0;
  cc->hs_last_min_rtt = UINT64_MAX;
  cc->hs_cur_min_rtt = UINT64_MAX;
  cc->hs_samples = 0;
  cc->hs_css = 0;
  cc->hs_css_rounds = 0;
}

void
cong_init (cong *cc, int algo, uint32_t mss)
{
  uint64_t w = 2 * (uint64_t) mss;

  memset (cc, 0, sizeof *cc);
  cc->algo = algo;
  cc->mss = mss;
  if (w < INITIAL_WINDOW_FLOOR)
    w = INITIAL_WINDOW_FLOOR;
  if (w > 10 * (uint64_t) mss)
    w = 10 * (uint64_t) mss;
  cc->cwnd = w;
  cc->ssthresh = UINT64_MAX;
  hystart_reset (cc);
}

void
cong_on_rtt_sample (cong *cc, uint64_t rtt_us)
{
  if (rtt_us < cc->hs_cur_min_rtt)
    cc->hs_cur_min_rtt = rtt_us;
  cc->hs_samples++;
}

/* A new HyStart++ round, or the end of slow start (returned as 0).  */
static int
hystart_round (cong *cc, uint64_t now)
{
  if (cc->hs_css && cc->hs_round_started)
    {
      cc->hs_css_rounds++;
      if (cc->hs_css_rounds >= HS_CSS_ROUNDS)
        {
          /* Slow start is over without a loss.  */
          cc->ssthresh = cc->cwnd;
          hystart_reset (cc);
          return 0;
        }
    }
  cc->hs_round_started = 1;
  cc->hs_round_start = now;
  cc->hs_last_min_rtt = cc->hs_cur_min_rtt;
  cc->hs_cur_min_rtt = UINT64_MAX;
  cc->hs_samples = 0;
  return 1;
}

/* Slow start with HyStart++ (RFC 9406 section 4.2).  Once the round trip
   time starts to rise, growth drops to a quarter (conservative slow start),
   and enough rounds of that end slow start.  The limit on growth per
   acknowledgement that the RFC puts on senders that do not pace is not
   needed: this one does.  */
static void
slow_start (cong *cc, uint64_t sent_us, uint32_t size, uint64_t now)
{
  int enough;

  if (!cc->hs_round_started || sent_us >= cc->hs_round_start)
    if (!hystart_round (cc, now))
      return;			/* It ended here: this ack grows nothing.  */
  enough = cc->hs_samples >= HS_N_RTT_SAMPLE
           && cc->hs_cur_min_rtt != UINT64_MAX;
  if (!cc->hs_css)
    {
      cc->cwnd += size;
      if (enough && cc->hs_last_min_rtt != UINT64_MAX)
        {
          uint64_t th = cc->hs_last_min_rtt / HS_MIN_RTT_DIVISOR;

          if (th < HS_MIN_RTT_THRESH)
            th = HS_MIN_RTT_THRESH;
          if (th > HS_MAX_RTT_THRESH)
            th = HS_MAX_RTT_THRESH;
          if (cc->hs_cur_min_rtt >= cc->hs_last_min_rtt + th)
            {
              cc->hs_css = 1;
              cc->hs_css_baseline = cc->hs_cur_min_rtt;
              cc->hs_css_rounds = 0;
            }
        }
      return;
    }
  cc->cwnd += size / HS_CSS_GROWTH_DIVISOR;
  if (enough && cc->hs_cur_min_rtt < cc->hs_css_baseline)
    cc->hs_css = 0;		/* The rise did not last.  */
}

/* RFC 9438 sections 4.2 to 4.5, in bytes rather than segments.  */
static void
cubic_avoidance (cong *cc, uint32_t size, uint64_t now, uint64_t srtt)
{
  double alpha, t, off, target, w_cubic, cwnd = (double) cc->cwnd;

  if (!cc->epoch_started)
    {
      cc->epoch_started = 1;
      cc->epoch_start = now;
      cc->w_est = cwnd;
      if (cc->cwnd < cc->w_max)
        /* Section 4.2: K = cbrt ((W_max - cwnd_epoch) / C), in seconds.  */
        cc->k = cong_cbrt ((double) (cc->w_max - cc->cwnd)
                           / (CUBIC_C * cc->mss));
      else
        {
          cc->k = 0;
          cc->w_max = cc->cwnd;
        }
    }
  /* Section 4.3: the Reno-friendly estimate grows alpha segments per window
     acknowledged, and a full segment once it has regained the window the
     loss happened at.  */
  alpha = cc->w_est >= (double) cc->w_prior ? 1.0 : CUBIC_ALPHA;
  cc->w_est += alpha * cc->mss * size / cwnd;

  /* Section 4.2: the window the cubic function gives one round trip from
     now.  */
  t = (double) ((now > cc->epoch_start ? now - cc->epoch_start : 0) + srtt)
      / 1e6;
  off = t - cc->k;
  w_cubic = CUBIC_C * cc->mss * off * off * off + (double) cc->w_max;
  if (w_cubic < cc->w_est)
    {
      /* Section 4.3: the Reno-friendly region.  */
      if ((uint64_t) cc->w_est > cc->cwnd)
        cc->cwnd = (uint64_t) cc->w_est;
      return;
    }
  /* Sections 4.4 and 4.5: head for the target, but no more than half again
     the window per round trip.  */
  target = w_cubic > cwnd ? w_cubic : cwnd;
  if (target > 1.5 * cwnd)
    target = 1.5 * cwnd;
  cc->cwnd += (uint64_t) ((target - cwnd) * size / cwnd);
}

void
cong_on_ack (cong *cc, uint64_t sent_us, uint32_t size, int limited,
             uint64_t now_us, uint64_t srtt_us)
{
  if (cc->in_recovery && cc->recovery_start && sent_us > cc->recovery_start)
    cc->in_recovery = 0;
  if (!limited)
    return;
  if (cc->recovery_start && sent_us <= cc->recovery_start)
    return;			/* Sent before recovery began.  */
  if (cc->cwnd < cc->ssthresh)
    {
      slow_start (cc, sent_us, size, now_us);
      return;
    }
  if (cc->algo == GQ_CC_CUBIC)
    {
      cubic_avoidance (cc, size, now_us, srtt_us);
      return;
    }
  /* NewReno: one datagram for each window acknowledged.  */
  cc->ca_acked += size;
  if (cc->ca_acked >= cc->cwnd)
    {
      cc->ca_acked -= cc->cwnd;
      cc->cwnd += cc->mss;
    }
}

int
cong_on_congestion_event (cong *cc, uint64_t lost_sent_us, uint64_t now_us)
{
  uint64_t min = 2 * (uint64_t) cc->mss;

  if (cc->recovery_start && lost_sent_us <= cc->recovery_start)
    return 0;			/* Already in recovery for this loss.  */
  cc->recovery_start = now_us;
  cc->in_recovery = 1;
  if (cc->algo == GQ_CC_CUBIC)
    {
      /* RFC 9438 section 4.7, fast convergence: a loss before the window
         regained the last W_max means the capacity on offer has shrunk, so
         aim lower than the window the loss happened at.  */
      cc->w_max = cc->cwnd < cc->w_max
                  ? (uint64_t) ((double) cc->cwnd * (1 + CUBIC_BETA) / 2)
                  : cc->cwnd;
      cc->w_prior = cc->cwnd;
      cc->epoch_started = 0;
      cc->ssthresh = (uint64_t) ((double) cc->cwnd * CUBIC_BETA);
    }
  else
    cc->ssthresh = (uint64_t) ((double) cc->cwnd * NEWRENO_BETA);
  if (cc->ssthresh < min)
    cc->ssthresh = min;
  cc->cwnd = cc->ssthresh;
  cc->ca_acked = 0;
  hystart_reset (cc);
  return 1;
}

/* The window goes straight to the minimum, and recovery is over so that
   slow start can run again, rather than the connection staying capped by a
   recovery period that has gone stale (RFC 9002 appendix B.8).  CUBIC's
   epoch ends too: congestion avoidance starts a fresh curve from the lower
   window.  */
void
cong_on_persistent (cong *cc)
{
  cc->cwnd = 2 * (uint64_t) cc->mss;
  cc->recovery_start = 0;
  cc->in_recovery = 0;
  cc->ca_acked = 0;
  cc->epoch_started = 0;
  hystart_reset (cc);
}

/* ---- Pacing ---- */

void
pacer_init (pacer *p, uint64_t burst, uint32_t dgram)
{
  memset (p, 0, sizeof *p);
  p->burst = (double) burst;
  p->credit = (double) burst;
  p->dgram = dgram;
}

double
pacer_rate (uint64_t cwnd, uint64_t ssthresh, uint64_t srtt_us)
{
  double gain;

  if (srtt_us == 0)
    return 0;
  gain = cwnd < ssthresh ? 2.0 : 1.25;
  return gain * (double) cwnd / (double) srtt_us;
}

static void
refill (pacer *p, uint64_t now, double rate, int idle)
{
  double tick, cap, accrued, hold;

  if (!p->started)
    {
      p->started = 1;
      p->last_us = now;
      return;
    }
  if (now <= p->last_us)
    return;
  accrued = (double) (now - p->last_us);
  p->last_us = now;
  if (rate <= 0)
    {
      p->credit = p->burst;
      return;
    }
  tick = rate * PACER_TICK_US;
  cap = idle ? (p->burst > tick ? p->burst : tick) : p->dgram + tick;
  accrued = p->credit + accrued * rate;
  if (accrued <= cap)
    {
      p->credit = accrued;
      return;
    }
  /* Accrual stops at the cap.  Credit already held is kept, so that a burst
     from idle completes once started, but never beyond the burst size: a
     surplus earned at a higher rate (a tick's worth on a fast path) must
     not be spent as a burst once the rate has dropped, which is just after
     a loss.  */
  hold = p->credit < (p->burst > cap ? p->burst : cap)
         ? p->credit : (p->burst > cap ? p->burst : cap);
  p->credit = cap > hold ? cap : hold;
}

uint64_t
pacer_delay (pacer *p, uint32_t bytes, uint64_t now_us, double rate,
             int idle)
{
  double w;
  uint64_t n;

  refill (p, now_us, rate, idle);
  if (rate <= 0 || p->credit >= bytes)
    return 0;
  w = ((double) bytes - p->credit) / rate;
  n = (uint64_t) w;
  if ((double) n < w)
    n++;
  return n;
}

void
pacer_on_sent (pacer *p, uint32_t bytes, uint64_t now_us, double rate,
               int idle)
{
  refill (p, now_us, rate, idle);
  p->credit -= bytes;
  if (p->credit < -p->burst)
    p->credit = -p->burst;
}
