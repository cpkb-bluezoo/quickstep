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

/* Building datagrams: what goes into each packet, coalescing, padding,
   protection and the bookkeeping recovery needs.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "conn_int.h"

#define MAX_DGRAM 2048
#define ACK_RANGES_MAX 24
#define MIN_PACKET_ROOM 40	/* Not worth starting a packet in less.  */

static int early_usable (const gq_conn *c);

/* One packet under construction.  */
typedef struct pk
{
  int sp;
  uint8_t pl[MAX_DGRAM];
  size_t cap, len;
  sent_frame sf[MAX_FRAMES_PER_PACKET];
  unsigned nsf;
  int ae;			/* Contains an ack-eliciting frame.  */
  int closing;
  int ack_valid;		/* Carries an ACK frame; its largest:  */
  uint64_t ack_largest;
  int challenge;		/* Carries a PATH_CHALLENGE.  */
  int early;			/* A 0-RTT packet.  */
  size_t hdr_est;		/* Header estimate used to size cap.  */
  /* For the log: the frames as fields (frames.N.*), the PADDING bytes,
     the raw bytes of data to include, and what made this packet go.  */
  char *qf;
  size_t qf_len, qf_cap, qraw, pad;
  unsigned qf_n;
  const char *qtrigger;
  int spin;			/* The spin bit it was sealed with.  */
} pk;

/* Start keeping what the log wants of the packet in slot SLOT of the
   datagram, if it is wanted.  */
static void
pk_log_reset (gq_conn *c, pk *p, int slot)
{
  p->qf = QLOG_ON (c, QE_PACKET_SENT) ? c->ql.frames[slot] : NULL;
  p->qf_cap = c->ql.frames_cap;
  p->qf_len = 0;
  p->qf_n = 0;
  p->qraw = c->ql.raw_max;
  p->pad = 0;
  p->qtrigger = NULL;
}

static size_t
room (const pk *p)
{
  return p->cap - p->len;
}

static int
add (pk *p, const gq_frame *f, int ae, const sent_frame *e)
{
  size_t w;

  if (e && p->nsf >= MAX_FRAMES_PER_PACKET)
    return -1;
  if (gq_frame_write (f, p->pl + p->len, room (p), &w) != GQ_OK)
    return -1;
  p->len += w;
  if (ae)
    p->ae = 1;
  if (e)
    p->sf[p->nsf++] = *e;
  if (p->qf)
    ql_frames_add (p->qf, p->qf_cap, &p->qf_len, &p->qf_n, f, 3, p->qraw);
  return 0;
}

static uint64_t
window_credit (uint64_t max, uint64_t used)
{
  return max > used ? max - used : 0;
}

/* ---- What is waiting to be sent? ---- */

static int
stream_wants (const gq_conn *c, stream *st)
{
  uint64_t lim;

  if (st->has_send)
    {
      if (gq_sstream_pending (&st->s, window_credit (c->max_data_peer,
                                                      c->data_sent)))
        return 1;
      if (!st->s.reset && st->s.sent >= st->s.max_data
          && st->s.blocked_at != st->s.max_data + 1
          && st->s.len + st->s.base > st->s.sent)
        return 1;
      (void) lim;
    }
  if (st->has_recv)
    {
      if (st->r.stop_pending)
        return 1;
      if (!st->r.final_known && !st->r.reset
          && st->r.max_data > st->r.max_sent)
        return 1;
      if (!st->r.final_known && !st->r.reset
          && st->r.off + c->cfg.initial_max_stream_data > st->r.max_data
          && st->r.off + c->cfg.initial_max_stream_data - st->r.max_data
             >= c->cfg.initial_max_stream_data / 2)
        return 1;
    }
  return 0;
}

static int
conn_update_wanted (const gq_conn *c)
{
  uint64_t w = c->cfg.initial_max_data;

  return c->max_data_local > c->max_data_sent
         || (c->data_consumed + w > c->max_data_local
             && c->data_consumed + w - c->max_data_local >= w / 2);
}

static int
app_pending (gq_conn *c)
{
  size_t i;

  if (c->handshake_done_pending || c->new_token_pending || c->dq_n
      || c->paths[c->cur_path].n_resp || c->paths[c->cur_path].need_challenge
      || conn_update_wanted (c))
    return 1;
  for (i = 0; i < MAX_LCID; i++)
    if (c->l[i].used && c->l[i].need_send)
      return 1;
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].retire == 1)
      return 1;
  if (c->max_streams_local[0] > c->max_streams_local_sent[0]
      || c->max_streams_local[1] > c->max_streams_local_sent[1])
    return 1;
  for (i = 0; i < c->n_streams; i++)
    if (stream_wants (c, c->streams[i]))
      return 1;
  return 0;
}

/* Something ack-eliciting is waiting in SP, if only the congestion window
   allowed it out.  */
static int
wants_data (gq_conn *c, int sp)
{
  space *s = &c->sp[sp];

  if (sp == SP_APP && early_usable (c))
    return app_pending (c);
  if (s->discarded || !s->have_wk)
    return 0;
  if (gq_sstream_pending (&s->cs, UINT64_MAX))
    return 1;
  return sp == SP_APP && app_pending (c);
}

int
conn_have_work (gq_conn *c, int sp)
{
  space *s = &c->sp[sp];

  if (sp == SP_APP && early_usable (c))
    return conn_can_send_ae (c) && app_pending (c);
  if (s->discarded || !s->have_wk)
    return 0;
  if (s->ack_now || s->probes)
    return 1;
  return conn_can_send_ae (c) && wants_data (c, sp);
}

/* ---- Frames ---- */

static void
add_ack (gq_conn *c, pk *p, uint64_t now)
{
  space *s = &c->sp[p->sp];
  gq_ack_range r[ACK_RANGES_MAX];
  uint8_t enc[ACK_RANGES_MAX * 16];
  size_t n = 0, i, w;
  gq_frame f;
  unsigned e = 3;			/* Our ack_delay_exponent.  */

  if (!s->ack_pending || s->recv.n == 0)
    {
      s->ack_pending = s->ack_now = 0;
      return;
    }
  for (i = s->recv.n; i > 0 && n < ACK_RANGES_MAX; i--, n++)
    {
      r[n].lo = s->recv.r[i - 1].lo;
      r[n].hi = s->recv.r[i - 1].hi - 1;
    }
  while (n > 0)
    {
      if (gq_ack_ranges_encode (r, n, enc, sizeof enc, &w) == GQ_OK)
        break;
      n--;
    }
  if (n == 0)
    return;
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_ACK;
  f.u.ack.largest = r[0].hi;
  f.u.ack.delay = (now > s->largest_recv_time
                   ? now - s->largest_recv_time : 0) >> e;
  f.u.ack.range_count = n - 1;
  f.u.ack.ranges.data = enc;
  f.u.ack.ranges.len = w;
  if (add (p, &f, 0, NULL) == 0)
    {
      p->ack_valid = 1;
      p->ack_largest = r[0].hi;
      s->ack_pending = s->ack_now = 0;
      s->ack_deadline = 0;
      s->ae_since_ack = 0;
    }
}

static void
add_crypto (gq_conn *c, pk *p)
{
  space *s = &c->sp[p->sp];
  uint64_t off, nb;
  const uint8_t *d;
  size_t n;
  int fin;

  while (room (p) > 16 && p->nsf < MAX_FRAMES_PER_PACKET)
    {
      gq_frame f;
      sent_frame e;

      if (!gq_sstream_next (&s->cs, room (p) - 11, UINT64_MAX, &off, &d, &n,
                            &fin, &nb))
        break;
      memset (&f, 0, sizeof f);
      f.type = GQ_FRAME_CRYPTO;
      f.u.crypto.offset = off;
      f.u.crypto.data.data = d;
      f.u.crypto.data.len = n;
      memset (&e, 0, sizeof e);
      e.type = SF_CRYPTO;
      e.a = off;
      e.len = (uint32_t) n;
      if (add (p, &f, 1, &e))
        {
          gq_sstream_on_lost (&s->cs, off, n, 0);
          break;
        }
    }
}

/* Simple one-value control frames.  */
static int
add_simple (pk *p, enum gq_frame_type t, uint64_t v1, uint64_t v2,
            const sent_frame *e)
{
  gq_frame f;

  memset (&f, 0, sizeof f);
  f.type = t;
  switch (t)
    {
    case GQ_FRAME_MAX_DATA:		f.u.max_data.max = v1; break;
    case GQ_FRAME_MAX_STREAM_DATA:
      f.u.max_stream_data.id = v1;
      f.u.max_stream_data.max = v2;
      break;
    case GQ_FRAME_DATA_BLOCKED:		f.u.data_blocked.limit = v1; break;
    case GQ_FRAME_STREAM_DATA_BLOCKED:
      f.u.stream_data_blocked.id = v1;
      f.u.stream_data_blocked.limit = v2;
      break;
    case GQ_FRAME_STOP_SENDING:
      f.u.stop_sending.id = v1;
      f.u.stop_sending.error = v2;
      break;
    case GQ_FRAME_RETIRE_CONNECTION_ID:
      f.u.retire_connection_id.seq = v1;
      break;
    default:
      break;
    }
  return add (p, &f, 1, e);
}

static void
add_stream_control (gq_conn *c, pk *p, stream *st)
{
  sent_frame e;
  uint64_t v, err, fin;
  gq_frame f;

  memset (&e, 0, sizeof e);
  if (st->has_send)
    {
      if (st->s.reset_pending && room (p) >= 26)
        {
          gq_sstream_take_reset (&st->s, &err, &fin);
          memset (&f, 0, sizeof f);
          f.type = GQ_FRAME_RESET_STREAM;
          f.u.reset_stream.id = st->id;
          f.u.reset_stream.error = err;
          f.u.reset_stream.final_size = fin;
          e.type = SF_RESET_STREAM;
          e.a = st->id;
          if (add (p, &f, 1, &e))
            gq_sstream_reset_lost (&st->s);
          ql_stream_states (c, st, "local");
        }
      if (room (p) >= 20 && gq_sstream_take_blocked (&st->s, &v))
        {
          e.type = SF_STREAM_DATA_BLOCKED;
          e.a = st->id;
          e.b = v;
          if (add_simple (p, GQ_FRAME_STREAM_DATA_BLOCKED, st->id, v, &e))
            st->s.blocked_at = 0;
        }
    }
  if (st->has_recv)
    {
      if (room (p) >= 20 && gq_rstream_take_stop (&st->r, &err))
        {
          e.type = SF_STOP_SENDING;
          e.a = st->id;
          if (add_simple (p, GQ_FRAME_STOP_SENDING, st->id, err, &e))
            gq_rstream_stop_lost (&st->r);
        }
      if (room (p) >= 20
          && gq_rstream_take_update (&st->r, c->cfg.initial_max_stream_data,
                                     &v))
        {
          e.type = SF_MAX_STREAM_DATA;
          e.a = st->id;
          e.b = v;
          if (add_simple (p, GQ_FRAME_MAX_STREAM_DATA, st->id, v, &e))
            gq_rstream_update_lost (&st->r, v);
        }
    }
}

static void
add_stream_data (gq_conn *c, pk *p, stream *st)
{
  uint64_t off, nb;
  const uint8_t *d;
  size_t n;
  int fin;

  if (!st->has_send)
    return;
  while (room (p) > 24 && p->nsf < MAX_FRAMES_PER_PACKET)
    {
      gq_frame f;
      sent_frame e;
      size_t over = 1 + gq_varint_size (st->id) + 8 + 2;

      if (room (p) <= over)
        break;
      if (!gq_sstream_next (&st->s, room (p) - over,
                            window_credit (c->max_data_peer, c->data_sent),
                            &off, &d, &n, &fin, &nb))
        break;
      /* The stream has taken them as sent whatever becomes of this packet:
         what is resent after a failure is not new (nb 0), so charge now.  */
      c->data_sent += nb;
      ql_stream_states (c, st, "local");
      memset (&f, 0, sizeof f);
      f.type = GQ_FRAME_STREAM;
      f.u.stream.id = st->id;
      f.u.stream.offset = off;
      f.u.stream.data.data = d;
      f.u.stream.data.len = n;
      f.u.stream.fin = fin;
      memset (&e, 0, sizeof e);
      e.type = SF_STREAM;
      e.a = st->id;
      e.b = off;
      e.len = (uint32_t) n;
      e.fin = (uint8_t) fin;
      if (add (p, &f, 1, &e))
        {
          gq_sstream_on_lost (&st->s, off, n, fin);
          break;
        }
    }
}

static void
add_datagrams (gq_conn *c, pk *p)
{
  sent_frame e;

  /* Datagrams before stream data: they are the latency sensitive ones.  */
  while (c->dq_n)
    {
      struct dgram *d = datagram_front (c);
      gq_frame df;

      if (room (p) < 1 + 2 + d->len || p->nsf >= MAX_FRAMES_PER_PACKET)
        break;
      memset (&df, 0, sizeof df);
      df.type = GQ_FRAME_DATAGRAM;
      df.u.datagram.data.data = d->data;
      df.u.datagram.data.len = d->len;
      memset (&e, 0, sizeof e);
      e.type = SF_DATAGRAM;
      e.a = d->id;
      if (add (p, &df, 1, &e))
        break;
      c->datagrams_sent++;
      datagram_pop (c);
    }
}

/* Stream data is the bulk of what a connection sends, and the part that can
   wait: with the pacer out of credit it is held back (everything else, the
   ACKs, probes, path validation and close, is not paced), and the time it
   will take to earn a datagram's worth is noted for the timer.  Returns 0
   if some stream has data to send but must wait.  */
static int
pacing_allows_data (gq_conn *c)
{
  uint64_t wait;
  size_t i;

  wait = pacer_delay (&c->pace, (uint32_t) conn_max_datagram (c), c->now,
                      conn_pacing_rate (c), c->bytes_in_flight == 0);
  if (wait == 0)
    return 1;
  for (i = 0; i < c->n_streams; i++)
    if (c->streams[i]->has_send
        && gq_sstream_pending (&c->streams[i]->s,
                               window_credit (c->max_data_peer,
                                              c->data_sent)))
      {
        if (c->pace_wait_us == 0 || wait < c->pace_wait_us)
          c->pace_wait_us = wait;
        return 0;
      }
  return 1;
}

static void
add_streams (gq_conn *c, pk *p)
{
  size_t i, start;
  int pace;

  /* Streams, starting one further along each time for fairness.  */
  start = c->n_streams ? c->rr % c->n_streams : 0;
  for (i = 0; i < c->n_streams; i++)
    add_stream_control (c, p, c->streams[(start + i) % c->n_streams]);
  pace = pacing_allows_data (c);
  for (i = 0; pace && i < c->n_streams; i++)
    add_stream_data (c, p, c->streams[(start + i) % c->n_streams]);
  if (c->n_streams)
    c->rr = (start + 1) % c->n_streams;
}

static void
add_app_frames (gq_conn *c, pk *p)
{
  size_t i;
  sent_frame e;
  gq_frame f;

  memset (&e, 0, sizeof e);
  if (c->handshake_done_pending && room (p) >= 1)
    {
      memset (&f, 0, sizeof f);
      f.type = GQ_FRAME_HANDSHAKE_DONE;
      e.type = SF_HANDSHAKE_DONE;
      if (add (p, &f, 1, &e) == 0)
        c->handshake_done_pending = 0;
    }
  if (c->new_token_pending && room (p) >= GQ_TOKEN_MAX + 8)
    {
      uint8_t tok[GQ_TOKEN_MAX];
      size_t tl;

      if (gq_token_make (c->token_keys, GQ_TOKEN_NEW_TOKEN, c->addr,
                         c->addr_len, NULL, NULL, conn_wall_seconds (c), tok,
                         &tl) == GQ_OK)
        {
          memset (&f, 0, sizeof f);
          f.type = GQ_FRAME_NEW_TOKEN;
          f.u.new_token.token.data = tok;
          f.u.new_token.token.len = tl;
          memset (&e, 0, sizeof e);
          e.type = SF_NEW_TOKEN;
          if (add (p, &f, 1, &e) == 0)
            c->new_token_pending = 0;
        }
      else
        c->new_token_pending = 0;
    }
  {
    pathinfo *cp = &c->paths[c->cur_path];
    unsigned k;

    for (k = 0; k < cp->n_resp; k++)
      if (room (p) >= 9)
        {
          memset (&f, 0, sizeof f);
          f.type = GQ_FRAME_PATH_RESPONSE;
          memcpy (f.u.path_challenge.data, cp->resp[k], 8);
          memset (&e, 0, sizeof e);
          e.type = SF_PATH_RESPONSE;
          add (p, &f, 1, &e);
        }
    cp->n_resp = 0;
    if (cp->need_challenge && room (p) >= 9)
      {
        memset (&f, 0, sizeof f);
        f.type = GQ_FRAME_PATH_CHALLENGE;
        conn_path_challenge_data (c, c->cur_path, f.u.path_challenge.data);
        memset (&e, 0, sizeof e);
        e.type = SF_PATH_CHALLENGE;
        add (p, &f, 1, &e);
        p->challenge = 1;
      }
  }
  for (i = 0; i < MAX_LCID; i++)
    if (c->l[i].used && c->l[i].need_send && room (p) >= 40)
      {
        memset (&f, 0, sizeof f);
        f.type = GQ_FRAME_NEW_CONNECTION_ID;
        f.u.new_connection_id.seq = c->l[i].seq;
        f.u.new_connection_id.cid_len = c->l[i].cid.len;
        memcpy (f.u.new_connection_id.cid, c->l[i].cid.data, c->l[i].cid.len);
        memcpy (f.u.new_connection_id.reset_token, c->l[i].token,
                GQ_RESET_TOKEN_LEN);
        memset (&e, 0, sizeof e);
        e.type = SF_NEW_CID;
        e.a = c->l[i].seq;
        if (add (p, &f, 1, &e) == 0)
          c->l[i].need_send = 0;
      }
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].retire == 1 && room (p) >= 12)
      {
        memset (&e, 0, sizeof e);
        e.type = SF_RETIRE_CID;
        e.a = c->p[i].seq;
        if (add_simple (p, GQ_FRAME_RETIRE_CONNECTION_ID, c->p[i].seq, 0, &e)
            == 0)
          c->p[i].retire = 2;
      }
  /* Connection-level credit.  */
  {
    uint64_t w = c->cfg.initial_max_data;

    if (c->data_consumed + w > c->max_data_local
        && c->data_consumed + w - c->max_data_local >= w / 2)
      c->max_data_local = c->data_consumed + w;
  }
  if (c->max_data_local > c->max_data_sent && room (p) >= 10)
    {
      memset (&e, 0, sizeof e);
      e.type = SF_MAX_DATA;
      e.a = c->max_data_local;
      if (add_simple (p, GQ_FRAME_MAX_DATA, c->max_data_local, 0, &e) == 0)
        c->max_data_sent = c->max_data_local;
    }
  for (i = 0; i < 2; i++)
    if (c->max_streams_local[i] > c->max_streams_local_sent[i]
        && room (p) >= 10)
      {
        memset (&f, 0, sizeof f);
        f.type = GQ_FRAME_MAX_STREAMS;
        f.u.max_streams.bidi = (int) i;
        f.u.max_streams.max = c->max_streams_local[i];
        memset (&e, 0, sizeof e);
        e.type = SF_MAX_STREAMS;
        e.a = i;
        e.b = c->max_streams_local[i];
        if (add (p, &f, 1, &e) == 0)
          c->max_streams_local_sent[i] = c->max_streams_local[i];
      }
  if (c->data_sent >= c->max_data_peer && c->blocked_sent_at
      != c->max_data_peer + 1 && room (p) >= 10)
    {
      size_t k;
      int want = 0;

      for (k = 0; k < c->n_streams; k++)
        if (c->streams[k]->has_send
            && c->streams[k]->s.len + c->streams[k]->s.base
               > c->streams[k]->s.sent)
          want = 1;
      if (want)
        {
          memset (&e, 0, sizeof e);
          e.type = SF_DATA_BLOCKED;
          e.a = c->max_data_peer;
          if (add_simple (p, GQ_FRAME_DATA_BLOCKED, c->max_data_peer, 0, &e)
              == 0)
            c->blocked_sent_at = c->max_data_peer + 1;
        }
    }
  add_datagrams (c, p);
  add_streams (c, p);
}

/* ---- Packet assembly ---- */

static size_t
overhead_of (const gq_conn *c, int sp)
{
  size_t pn = 4;

  if (sp == SP_APP)
    return 1 + c->dcid.len + pn + GQ_AEAD_TAG_LEN;
  /* First byte, version, both connection IDs with their lengths, the
     token length, a two-byte Length, the packet number, the tag.  */
  return 1 + 4 + 1 + c->dcid.len + 1 + c->scid_first.len
         + (sp == SP_INITIAL ? gq_varint_size (c->token_len) + c->token_len : 0)
         + 2 + pn + GQ_AEAD_TAG_LEN;
}

/* The least credit under which an ack-eliciting packet of SP is worth
   sending.  A server's Initial must go in a datagram of 1200 bytes (RFC 9000
   section 14.1), so it needs that much; the other spaces need only room for
   a packet.  */
size_t
conn_min_ae_datagram (const gq_conn *c, int sp)
{
  if (sp == SP_INITIAL && c->role == GQ_ROLE_SERVER)
    return GQ_MIN_INITIAL_DATAGRAM;
  return overhead_of (c, sp) + MIN_PACKET_ROOM;
}

static void
add_close (gq_conn *c, pk *p)
{
  gq_frame f;
  int app = c->close_app;

  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_CONNECTION_CLOSE;
  /* Handshake packets cannot carry application errors.  */
  if (p->sp != SP_APP && app)
    {
      f.u.connection_close.application = 0;
      f.u.connection_close.error = GQ_QERR_APPLICATION;
    }
  else
    {
      f.u.connection_close.application = app;
      f.u.connection_close.error = c->close_err;
      if (p->sp != SP_APP || !app)
        {
          f.u.connection_close.reason.data
            = (const uint8_t *) c->close_reason;
          f.u.connection_close.reason.len = c->close_reason_len;
        }
    }
  if (app && p->sp == SP_APP)
    {
      f.u.connection_close.reason.data = (const uint8_t *) c->close_reason;
      f.u.connection_close.reason.len = c->close_reason_len;
    }
  f.u.connection_close.frame_type = c->close_frame;
  add (p, &f, 0, NULL);
  p->closing = 1;
}

/* 0-RTT: the client may send before it has 1-RTT keys.  */
static int
early_usable (const gq_conn *c)
{
  return c->role == GQ_ROLE_CLIENT && c->have_early_wk && !c->early_rejected
         && !c->sp[SP_APP].have_wk && c->state == GQ_CONN_HANDSHAKE;
}

/* A 0-RTT packet: stream data and datagrams only (RFC 9001 section 4.6
   allows more, but this is all that is worth sending this early).  */
static int
assemble_early (gq_conn *c, uint64_t now, size_t budget, pk *p)
{
  size_t ov = overhead_of (c, SP_HANDSHAKE);	/* Long header, no token.  */

  (void) now;
  if (budget < ov + MIN_PACKET_ROOM || !conn_can_send_ae (c))
    return 0;
  p->sp = SP_APP;
  p->early = 1;
  p->len = 0;
  p->nsf = 0;
  p->ae = 0;
  p->closing = 0;
  p->ack_valid = 0;
  p->challenge = 0;
  p->cap = budget - ov;
  p->hdr_est = ov;
  add_datagrams (c, p);
  add_streams (c, p);
  return p->len > 0;
}

/* Fill P with what SP has to say.  Returns 1 if there is a packet.  */
static int
assemble (gq_conn *c, int sp, uint64_t now, size_t budget, size_t maxdg,
          pk *p)
{
  space *s = &c->sp[sp];
  size_t ov = overhead_of (c, sp);

  p->early = 0;
  if (sp == SP_APP && early_usable (c))
    return assemble_early (c, now, budget, p);
  if (budget < ov + MIN_PACKET_ROOM)
    return 0;
  memset (&p->sf, 0, 0);
  p->sp = sp;
  p->len = 0;
  p->nsf = 0;
  p->ae = 0;
  p->closing = 0;
  p->ack_valid = 0;
  p->challenge = 0;
  p->cap = budget - ov;
  p->hdr_est = ov;
  if (c->state == GQ_CONN_CLOSING)
    {
      add_close (c, p);
      return p->len > 0;
    }
  if (!conn_have_work (c, sp))
    return 0;
  add_ack (c, p, now);
  /* A server's ack-eliciting Initial cannot go in a datagram too short to
     pad to 1200 bytes (the credit does not allow it): it waits.  */
  if (sp == SP_INITIAL && c->role == GQ_ROLE_SERVER
      && maxdg < GQ_MIN_INITIAL_DATAGRAM)
    return p->len > 0;
  if (conn_can_send_ae (c) || s->probes)
    {
      add_crypto (c, p);
      if (sp == SP_APP)
        add_app_frames (c, p);
    }
  if (s->probes)
    {
      if (!p->ae && room (p) >= 1)
        {
          gq_frame f;

          memset (&f, 0, sizeof f);
          f.type = GQ_FRAME_PING;
          add (p, &f, 1, NULL);
        }
      if (p->ae)
        {
          s->probes--;
          p->qtrigger = "pto_probe";
        }
    }
  return p->len > 0;
}

/* ---- Sealing ---- */

static size_t
hdr_len_for (const gq_conn *c, int sp, int early, size_t payload_len,
             size_t pn_len, uint64_t pn)
{
  /* The longest long header: both connection IDs at 20 bytes, a token of
     512 (the most conn_int.h keeps), the lengths and the packet number.  */
  uint8_t tmp[1 + 4 + 1 + 20 + 1 + 20 + 2 + 512 + 8 + 4];
  size_t h = 0;

  if (sp == SP_APP && !early)
    gq_short_header_build (c->dcid.data, c->dcid.len, 0, c->w_phase, pn,
                           pn_len, tmp, sizeof tmp, &h);
  else
    gq_long_header_build (early ? GQ_PKT_ZERO_RTT
                          : sp == SP_INITIAL ? GQ_PKT_INITIAL
                                             : GQ_PKT_HANDSHAKE,
                          c->version, c->dcid.data, c->dcid.len,
                          c->scid_first.data, c->scid_first.len,
                          sp == SP_INITIAL ? c->token : NULL,
                          sp == SP_INITIAL ? c->token_len : 0, pn,
                          pn_len, payload_len, tmp, sizeof tmp, &h);
  return h;
}

static int
seal (gq_conn *c, uint64_t now, pk *p, uint64_t pn, size_t pn_len, uint8_t *out,
      size_t cap, size_t *out_len)
{
  space *s = &c->sp[p->sp];
  size_t hdr = 0;
  int r;

  if (p->sp == SP_APP && !p->early)
    {
      p->spin = conn_spin_value (c);
      r = gq_short_header_build (c->dcid.data, c->dcid.len, p->spin,
                                 c->w_phase, pn, pn_len, out, cap, &hdr);
    }
  else
    r = gq_long_header_build (p->early ? GQ_PKT_ZERO_RTT
                              : p->sp == SP_INITIAL ? GQ_PKT_INITIAL
                                                    : GQ_PKT_HANDSHAKE,
                              c->version, c->dcid.data, c->dcid.len,
                              c->scid_first.data, c->scid_first.len,
                              p->sp == SP_INITIAL ? c->token : NULL,
                              p->sp == SP_INITIAL ? c->token_len : 0,
                              pn, pn_len, p->len, out, cap, &hdr);
  if (r != GQ_OK)
    return r;
  if (hdr + p->len + GQ_AEAD_TAG_LEN > cap)
    return GQ_ERR_BUFSIZE;
  memcpy (out + hdr, p->pl, p->len);
  r = gq_packet_seal (p->early ? &c->early_wk : &s->wk, pn, out,
                      hdr - pn_len, pn_len, p->len, cap, out_len);
  (void) now;
  return r;
}

/* Report a packet that was sent: W bytes on the wire, in datagram DID.  */
static void
log_sent (gq_conn *c, pk *p, uint64_t pn, size_t pnl, size_t w, uint32_t did,
          int dest)
{
  qlog_hdr h;

  memset (&h, 0, sizeof h);
  h.type = qlog_packet_type_name (p->sp, p->early);
  h.have_pn = 1;
  h.pn = pn;
  h.pn_len = (unsigned) pnl;
  h.have_dcid = 1;
  h.dcid = c->dcid.data;
  h.dcid_len = c->dcid.len;
  if (p->sp == SP_APP && !p->early)
    {
      h.have_key_phase = 1;
      h.key_phase = c->w_phase;
      h.have_spin = 1;
      h.spin = (unsigned) p->spin;
    }
  else
    {
      h.have_version = 1;
      h.version = c->version;
      h.have_scid = 1;
      h.scid = c->scid_first.data;
      h.scid_len = c->scid_first.len;
      h.have_length = 1;
      h.length = pnl + p->len + GQ_AEAD_TAG_LEN;
      if (p->sp == SP_INITIAL && c->token_len)
        {
          h.have_token = 1;
          h.token = c->token;
          h.token_len = c->token_len;
        }
    }
  ql_frames_add_padding (p->qf, p->qf_cap, &p->qf_len, &p->qf_n, p->pad);
  ql_packet_sent (c, &h, w, p->len, p->qf, p->qf_len, did, p->qtrigger, dest);
}

/* Pad, protect and account for the N packets of one datagram bound for
   path DEST (an index into the path table).  */
static int
finish_datagram (gq_conn *c, uint64_t now, pk **pks, const uint64_t *pns,
                 const size_t *pnl, int n, int need_pad, size_t maxdg,
                 int dest, uint8_t *out, size_t *len)
{
  size_t total = 0;
  int i, ae = 0, sent_handshake = 0, r = GQ_OK;
  uint32_t did = c->ql.next_dgram_id++;

  if (need_pad && maxdg >= GQ_MIN_INITIAL_DATAGRAM)
    {
      pk *last = pks[n - 1];
      size_t t = 0, guard, padded = 0;

      for (guard = 0; guard < 3; guard++)
        {
          t = 0;
          for (i = 0; i < n; i++)
            t += hdr_len_for (c, pks[i]->sp, pks[i]->early, pks[i]->len, pnl[i],
                         pns[i])
                 + pks[i]->len + GQ_AEAD_TAG_LEN;
          if (t >= GQ_MIN_INITIAL_DATAGRAM)
            break;
          {
            size_t add_n = GQ_MIN_INITIAL_DATAGRAM - t;

            if (add_n > sizeof last->pl - last->len)
              add_n = sizeof last->pl - last->len;
            memset (last->pl + last->len, 0, add_n);
            last->len += add_n;
            padded += add_n;
          }
        }
      /* A longer payload can widen the Length field by a byte.  */
      if (t > GQ_MIN_INITIAL_DATAGRAM && padded >= t - GQ_MIN_INITIAL_DATAGRAM)
        {
          last->len -= t - GQ_MIN_INITIAL_DATAGRAM;
          padded -= t - GQ_MIN_INITIAL_DATAGRAM;
        }
      last->pad += padded;
    }
  for (i = 0; i < n && r == GQ_OK; i++)
    {
      pk *p = pks[i];
      size_t w = 0;

      r = seal (c, now, p, pns[i], pnl[i], out + total, maxdg - total, &w);
      if (r != GQ_OK)
        break;
      total += w;
      c->st.packets_sent++;
      if (p->qf)
        log_sent (c, p, pns[i], pnl[i], w, did, dest);
      if (p->ack_valid)
        conn_note_ack_sent (c, p->sp, pns[i], p->ack_largest);
      if (p->ae)
        {
          sent_pkt sp;

          ae = 1;
          memset (&sp, 0, sizeof sp);
          sp.pn = pns[i];
          sp.time_us = now;
          sp.size = (uint32_t) w;
          sp.ack_eliciting = 1;
          sp.in_flight = 1;
          sp.early = (uint8_t) p->early;
          if (p->nsf)
            {
              sp.frames = malloc (p->nsf * sizeof *sp.frames);
              if (sp.frames == NULL)
                r = GQ_ERR_NOMEM;
              else
                {
                  memcpy (sp.frames, p->sf, p->nsf * sizeof *sp.frames);
                  sp.nframes = p->nsf;
                }
            }
          if (r == GQ_OK)
            sp_sent_add (c, p->sp, &sp);
        }
      if (p->sp == SP_HANDSHAKE)
        {
          sent_handshake = 1;
          ql_handshake_started (c);
        }
    }
  if (r != GQ_OK)
    {
      conn_fail (c, GQ_QERR_INTERNAL, "cannot build packet");
      return r;
    }
  *len = total;
  ql_datagram (c, QE_UDP_DATAGRAMS_SENT, did, total);
  conn_path_note_sent (c, dest, total);
  c->st.bytes_sent += total;
  if (c->state == GQ_CONN_CLOSING)
    {
      c->close_pending = 0;
      c->last_close_sent = now;
    }
  if (ae && !c->idle_send_reset)
    {
      c->idle_send_reset = 1;
      conn_recompute_idle (c, now);
    }
  if (sent_handshake && c->role == GQ_ROLE_CLIENT)
    conn_discard_space (c, SP_INITIAL);
  /* Rekey before the AEAD limits (2^23 packets for AES-GCM).  */
  if (c->sp[SP_APP].next_pn - c->w_first_pn > ((uint64_t) 1 << 22))
    gq_conn_update_keys (c, now);
  return GQ_OK;
}

/* A datagram for a path other than the current one: what the peer is
   owed there (PATH_RESPONSE) and our PATH_CHALLENGE, padded to 1200 bytes
   when the amplification limit allows (RFC 9000 section 8.2.1).  It goes
   out under the peer connection ID chosen for that path.  */
static int
build_probe (gq_conn *c, uint64_t now, uint8_t *out, size_t cap, size_t *len,
             int idx)
{
  pathinfo *e = &c->paths[idx];
  space *s = &c->sp[SP_APP];
  size_t maxdg = conn_max_datagram (c);
  uint64_t budget;
  gq_cid saved = c->dcid;
  pk *p;
  uint64_t pn;
  size_t pnl;
  unsigned k;
  int r;
  int limited = conn_path_budget (c, idx, &budget);

  if (maxdg > cap)
    maxdg = cap;
  if (limited && budget < maxdg)
    maxdg = (size_t) budget;
  if (!s->have_wk || s->discarded || maxdg < 100)
    return GQ_OK;
  p = malloc (sizeof *p);
  if (p == NULL)
    return GQ_ERR_NOMEM;
  memset (p, 0, sizeof *p);
  pk_log_reset (c, p, 0);
  p->sp = SP_APP;
  c->dcid = e->dcid;		/* Header size and header both use it.  */
  p->cap = maxdg - overhead_of (c, SP_APP);
  p->hdr_est = overhead_of (c, SP_APP);
  for (k = 0; k < e->n_resp; k++)
    if (room (p) >= 9)
      {
        gq_frame f;
        sent_frame sf;

        memset (&f, 0, sizeof f);
        f.type = GQ_FRAME_PATH_RESPONSE;
        memcpy (f.u.path_challenge.data, e->resp[k], 8);
        memset (&sf, 0, sizeof sf);
        sf.type = SF_PATH_RESPONSE;
        add (p, &f, 1, &sf);
      }
  e->n_resp = 0;
  if (e->need_challenge && room (p) >= 9)
    {
      gq_frame f;
      sent_frame sf;

      memset (&f, 0, sizeof f);
      f.type = GQ_FRAME_PATH_CHALLENGE;
      conn_path_challenge_data (c, idx, f.u.path_challenge.data);
      memset (&sf, 0, sizeof sf);
      sf.type = SF_PATH_CHALLENGE;
      add (p, &f, 1, &sf);
      p->challenge = 1;
    }
  if (p->len == 0)
    {
      c->dcid = saved;
      free (p);
      return GQ_OK;
    }
  {
    pk *pks[1];

    pks[0] = p;
    pn = s->next_pn++;
    pnl = gq_pn_encoded_len (pn, s->have_acked, s->largest_acked);
    while (p->len < 4 - pnl && p->len < p->cap)
      {
        p->pl[p->len++] = 0;
        p->pad++;
      }
    r = finish_datagram (c, now, pks, &pn, &pnl, 1, 1, maxdg, idx, out, len);
  }
  c->dcid = saved;
  c->tx_path = idx;
  free (p);
  return r;
}

static int
build_datagram (gq_conn *c, uint64_t now, uint8_t *out, size_t cap,
                size_t *len)
{
  size_t maxdg = conn_max_datagram (c), est = 0;
  static const int order[N_SPACES] = { SP_INITIAL, SP_HANDSHAKE, SP_APP };
  pk *pks[N_SPACES];
  uint64_t pns[N_SPACES];
  size_t pnl[N_SPACES];
  int n = 0, i, need_pad = 0, r;
  uint64_t budget;
  pk *storage;

  *len = 0;
  if (maxdg > cap)
    maxdg = cap;
  /* If no update was possible, stop at the limit: a key may not protect
     more packets than its confidentiality limit (RFC 9001 section 6.6).  */
  if (c->sp[SP_APP].have_wk
      && c->sp[SP_APP].wk.aead != GQ_AEAD_CHACHA20_POLY1305
      && c->sp[SP_APP].next_pn - c->w_first_pn >= ((uint64_t) 1 << 23))
    conn_fail (c, GQ_QERR_AEAD_LIMIT, "AEAD confidentiality limit reached");
  if (c->state == GQ_CONN_ESTABLISHED)
    {
      int idx = conn_path_probe_pending (c, now);

      if (idx >= 0)
        return build_probe (c, now, out, cap, len, idx);
    }
  if (conn_path_budget (c, c->cur_path, &budget))
    {
      if (budget == 0)
        return GQ_OK;
      if (budget < maxdg)
        maxdg = (size_t) budget;
    }
  if (c->state == GQ_CONN_CLOSING && !c->close_pending)
    return GQ_OK;
  storage = malloc (N_SPACES * sizeof *storage);
  if (storage == NULL)
    return GQ_ERR_NOMEM;
  for (i = 0; i < N_SPACES; i++)
    {
      int sp = order[i];
      pk *p = &storage[n];
      space *s = &c->sp[sp];

      if (s->discarded || (!s->have_wk && !(sp == SP_APP && early_usable (c))))
        continue;
      if (est + 1 >= maxdg)
        break;
      pk_log_reset (c, p, n);
      if (!assemble (c, sp, now, maxdg - est, maxdg, p))
        continue;
      pks[n] = p;
      pns[n] = s->next_pn++;
      pnl[n] = gq_pn_encoded_len (pns[n], s->have_acked, s->largest_acked);
      /* Pad tiny payloads so the header protection sample exists.  */
      while (p->len < 4 - pnl[n] + 0 && p->len < p->cap)
        {
          p->pl[p->len++] = 0;
          p->pad++;
        }
      est += p->hdr_est + p->len;
      n++;
      if (c->state == GQ_CONN_CLOSING)
        continue;
    }
  if (n == 0)
    {
      free (storage);
      return GQ_OK;
    }
  /* Datagrams with an Initial packet are padded to 1200 bytes: always for
     a client, and for a server when the Initial is ack-eliciting.  One with
     a PATH_CHALLENGE is padded too (RFC 9000 section 8.2.1).  */
  for (i = 0; i < n; i++)
    if ((pks[i]->sp == SP_INITIAL
         && (c->role == GQ_ROLE_CLIENT || pks[i]->ae || pks[i]->closing))
        || pks[i]->challenge)
      need_pad = 1;
  r = finish_datagram (c, now, pks, pns, pnl, n, need_pad, maxdg, c->cur_path,
                       out, len);
  free (storage);
  return r;
}

/* Whether the window is what stopped the sending: something is waiting that
   the congestion window, or the pacer, will not yet let out.  Having
   nothing to send, or only what the peer's flow control bars, is not.  */
static int
window_limited (gq_conn *c)
{
  int sp;

  if (c->pace_wait_us)
    return 1;
  if (conn_can_send_ae (c))
    return 0;
  for (sp = 0; sp < N_SPACES; sp++)
    if (wants_data (c, sp))
      return 1;
  return 0;
}

/* Report what is holding data back, and what is not any longer.  Looked at
   when a send ends without a datagram, which is when something is held.  */
static void
log_blocked (gq_conn *c)
{
  const char *why = NULL, *dgram_why = NULL;
  uint64_t budget;
  int sp, wants = 0, flow_blocked = 0, any_queued = 0;
  size_t i;

  if (!QLOG_ON (c, QE_CONNECTION_DATA_BLOCKED_UPDATED)
      && !QLOG_ON (c, QE_STREAM_DATA_BLOCKED_UPDATED)
      && !QLOG_ON (c, QE_DATAGRAM_DATA_BLOCKED_UPDATED))
    return;
  if (c->state >= GQ_CONN_CLOSING)
    {
      ql_blocked (c, NULL, NULL);
      return;
    }
  for (sp = 0; sp < N_SPACES; sp++)
    if (wants_data (c, sp))
      wants = 1;
  /* Data queued on streams, and whether a stream's own credit holds it.  */
  for (i = 0; i < c->n_streams; i++)
    {
      stream *st = c->streams[i];
      int queued, blocked;

      if (!st->has_send)
        continue;
      queued = st->s.len + st->s.base > st->s.sent;
      blocked = queued && st->s.sent >= st->s.max_data;
      any_queued |= queued;
      flow_blocked |= blocked;
      if (QLOG_ON (c, QE_STREAM_DATA_BLOCKED_UPDATED))
        ql_stream_blocked (c, st, blocked);
    }
  if (wants && conn_path_budget (c, c->cur_path, &budget) && budget == 0)
    why = "amplification_protection";
  else if (wants && !conn_can_send_ae (c))
    why = "congestion_control";
  else if (c->pace_wait_us)
    why = "pacing";
  else if (any_queued && c->data_sent >= c->max_data_peer)
    why = "connection_flow_control";
  else if (flow_blocked)
    why = "stream_flow_control";
  /* Queued datagrams wait for the same things as stream data does, bar the
     peer's flow control.  */
  if (c->dq_n && why && strcmp (why, "connection_flow_control")
      && strcmp (why, "stream_flow_control"))
    dgram_why = why;
  ql_blocked (c, why, dgram_why);
}

int
conn_build_datagram (gq_conn *c, uint64_t now, uint8_t *out, size_t cap,
                     size_t *len)
{
  int r;

  c->pace_wait_us = 0;
  r = build_datagram (c, now, out, cap, len);
  /* The timer is for the pacer to let go of what it holds back: a send that
     got everything out has none.  */
  c->pace_deadline = c->pace_wait_us ? now + c->pace_wait_us : 0;
  /* When a send ends without a datagram, that is where the sender stopped.  */
  if (*len == 0)
    {
      c->send_blocked = (uint8_t) window_limited (c);
      log_blocked (c);
    }
  return r;
}
