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

/* qlog: the writer of the line format, the event table, and the serializers
   for frames and packet headers (draft-ietf-quic-qlog-quic-events).  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>

#include "conn_int.h"
#include "qlog.h"

/* ---- The writer ---- */

void
qkv_init (qkv *w, char *buf, size_t cap)
{
  w->buf = buf;
  w->cap = cap;
  w->len = 0;
  w->err = cap == 0;
  w->plen = 0;
  w->prefix[0] = '\0';
  w->depth = 0;
  w->in_list = 0;
  w->first_item = 0;
  if (cap)
    buf[0] = '\0';
}

static void
put (qkv *w, const char *s, size_t n)
{
  if (w->err)
    return;
  /* Room for the terminating NUL as well.  */
  if (n >= w->cap - w->len)
    {
      w->err = 1;
      return;
    }
  memcpy (w->buf + w->len, s, n);
  w->len += n;
  w->buf[w->len] = '\0';
}

static void
prefix_add (qkv *w, const char *s, size_t n)
{
  if (w->plen + n >= sizeof w->prefix)
    {
      w->err = 1;
      return;
    }
  memcpy (w->prefix + w->plen, s, n);
  w->plen += n;
  w->prefix[w->plen] = '\0';
}

static size_t
fmt_u64 (char *tmp, size_t cap, uint64_t v)
{
  size_t i = cap;

  do
    tmp[--i] = (char) ('0' + v % 10);
  while ((v /= 10) != 0);
  return i;
}

void
qkv_push (qkv *w, const char *name)
{
  if (w->depth >= QKV_DEPTH_MAX)
    {
      w->err = 1;
      return;
    }
  w->saved[w->depth++] = w->plen;
  prefix_add (w, name, strlen (name));
  prefix_add (w, ".", 1);
}

void
qkv_push_i (qkv *w, const char *name, unsigned i)
{
  char tmp[24];
  size_t k = fmt_u64 (tmp, sizeof tmp, i);

  if (w->depth >= QKV_DEPTH_MAX)
    {
      w->err = 1;
      return;
    }
  w->saved[w->depth++] = w->plen;
  prefix_add (w, name, strlen (name));
  prefix_add (w, ".", 1);
  prefix_add (w, tmp + k, sizeof tmp - k);
  prefix_add (w, ".", 1);
}

void
qkv_pop (qkv *w)
{
  if (w->depth > 0)
    {
      w->plen = w->saved[--w->depth];
      w->prefix[w->plen] = '\0';
    }
}

/* A new field: a space after the last one, then PREFIX KEY =.  */
static void
begin (qkv *w, const char *key)
{
  if (w->len)
    put (w, " ", 1);
  put (w, w->prefix, w->plen);
  put (w, key, strlen (key));
  put (w, "=", 1);
}

/* The bytes of a value: those that would split or confuse the line are
   written %XX.  */
static void
escaped (qkv *w, const char *s, size_t n)
{
  static const char hexd[] = "0123456789ABCDEF";
  size_t i;

  for (i = 0; i < n; i++)
    {
      unsigned char ch = (unsigned char) s[i];

      if (ch > 0x20 && ch < 0x7f && ch != '%')
        put (w, s + i, 1);
      else
        {
          char e[3] = { '%', hexd[ch >> 4], hexd[ch & 15] };

          put (w, e, 3);
        }
    }
}

static void
hexed (qkv *w, const uint8_t *p, size_t n)
{
  static const char hexd[] = "0123456789abcdef";
  size_t i;

  for (i = 0; i < n; i++)
    {
      char two[2] = { hexd[p[i] >> 4], hexd[p[i] & 15] };

      put (w, two, 2);
    }
}

static void
number (qkv *w, uint64_t v)
{
  char tmp[24];
  size_t i = fmt_u64 (tmp, sizeof tmp, v);

  put (w, tmp + i, sizeof tmp - i);
}

void
qkv_u64 (qkv *w, const char *key, uint64_t v)
{
  begin (w, key);
  number (w, v);
}

void
qkv_strn (qkv *w, const char *key, const char *s, size_t n)
{
  begin (w, key);
  escaped (w, s, n);
}

void
qkv_str (qkv *w, const char *key, const char *s)
{
  qkv_strn (w, key, s, strlen (s));
}

void
qkv_bool (qkv *w, const char *key, int v)
{
  begin (w, key);
  if (v)
    put (w, "true", 4);
  else
    put (w, "false", 5);
}

void
qkv_hex (qkv *w, const char *key, const uint8_t *p, size_t n)
{
  begin (w, key);
  hexed (w, p, n);
}

/* WHOLE.FRAC with DIGITS decimals, FRAC less than 10^DIGITS.  */
static void
fixed (qkv *w, uint64_t whole, uint64_t frac, int digits)
{
  char tmp[8];
  int d;

  number (w, whole);
  put (w, ".", 1);
  for (d = digits - 1; d >= 0; d--)
    {
      tmp[d] = (char) ('0' + frac % 10);
      frac /= 10;
    }
  put (w, tmp, (size_t) digits);
}

void
qkv_ms (qkv *w, const char *key, uint64_t us)
{
  begin (w, key);
  fixed (w, us / 1000, us % 1000, 3);
}

void
qkv_milli (qkv *w, const char *key, uint64_t thousandths)
{
  begin (w, key);
  fixed (w, thousandths / 1000, thousandths % 1000, 3);
}

void
qkv_list (qkv *w, const char *key)
{
  begin (w, key);
  w->in_list = 1;
  w->first_item = 1;
}

static void
item_sep (qkv *w)
{
  if (!w->first_item)
    put (w, ",", 1);
  w->first_item = 0;
}

void
qkv_item_u64 (qkv *w, uint64_t v)
{
  item_sep (w);
  number (w, v);
}

void
qkv_item_str (qkv *w, const char *s)
{
  item_sep (w);
  escaped (w, s, strlen (s));
}

void
qkv_item_hex (qkv *w, const uint8_t *p, size_t n)
{
  item_sep (w);
  hexed (w, p, n);
}

void
qkv_item_range (qkv *w, uint64_t lo, uint64_t hi)
{
  item_sep (w);
  number (w, lo);
  if (hi != lo)
    {
      put (w, "-", 1);
      number (w, hi);
    }
}

void
qkv_end_list (qkv *w)
{
  w->in_list = 0;
}

void
qkv_append (qkv *w, const char *fields, size_t n)
{
  if (n == 0)
    return;
  if (w->len)
    put (w, " ", 1);
  put (w, fields, n);
}

int
qkv_utf8_ok (const uint8_t *p, size_t n)
{
  size_t i = 0;

  while (i < n)
    {
      uint8_t b = p[i];
      size_t extra;
      uint32_t cp;

      if (b < 0x80)
        {
          i++;
          continue;
        }
      if (b >= 0xc2 && b <= 0xdf)
        {
          extra = 1;
          cp = b & 0x1f;
        }
      else if (b >= 0xe0 && b <= 0xef)
        {
          extra = 2;
          cp = b & 0x0f;
        }
      else if (b >= 0xf0 && b <= 0xf4)
        {
          extra = 3;
          cp = b & 0x07;
        }
      else
        return 0;
      if (n - i <= extra)
        return 0;		/* Truncated.  */
      for (size_t k = 1; k <= extra; k++)
        {
          if ((p[i + k] & 0xc0) != 0x80)
            return 0;
          cp = (cp << 6) | (p[i + k] & 0x3f);
        }
      /* Overlong forms, surrogates, and beyond Unicode.  */
      if ((extra == 2 && cp < 0x800) || (extra == 3 && cp < 0x10000)
          || (cp >= 0xd800 && cp <= 0xdfff) || cp > 0x10ffff)
        return 0;
      i += extra + 1;
    }
  return 1;
}

/* ---- Events ---- */

static const struct
{
  const char *name;
  int level;
} events[QE_COUNT] = {
  [QE_SERVER_LISTENING] = { "quic:server_listening", GQ_QLOG_EXTRA },
  [QE_CONNECTION_STARTED] = { "quic:connection_started", GQ_QLOG_BASE },
  [QE_CONNECTION_CLOSED] = { "quic:connection_closed", GQ_QLOG_BASE },
  [QE_CONNECTION_ID_UPDATED] = { "quic:connection_id_updated", GQ_QLOG_BASE },
  [QE_SPIN_BIT_UPDATED] = { "quic:spin_bit_updated", GQ_QLOG_BASE },
  [QE_CONNECTION_STATE_UPDATED]
    = { "quic:connection_state_updated", GQ_QLOG_BASE },
  [QE_TUPLE_ASSIGNED] = { "quic:tuple_assigned", GQ_QLOG_BASE },
  [QE_MTU_UPDATED] = { "quic:mtu_updated", GQ_QLOG_EXTRA },
  [QE_VERSION_INFORMATION] = { "quic:version_information", GQ_QLOG_CORE },
  [QE_ALPN_INFORMATION] = { "quic:alpn_information", GQ_QLOG_CORE },
  [QE_PARAMETERS_SET] = { "quic:parameters_set", GQ_QLOG_CORE },
  [QE_PARAMETERS_RESTORED] = { "quic:parameters_restored", GQ_QLOG_BASE },
  [QE_PACKET_SENT] = { "quic:packet_sent", GQ_QLOG_CORE },
  [QE_PACKET_RECEIVED] = { "quic:packet_received", GQ_QLOG_CORE },
  [QE_PACKET_DROPPED] = { "quic:packet_dropped", GQ_QLOG_BASE },
  [QE_PACKET_BUFFERED] = { "quic:packet_buffered", GQ_QLOG_BASE },
  [QE_PACKETS_ACKED] = { "quic:packets_acked", GQ_QLOG_EXTRA },
  [QE_UDP_DATAGRAMS_SENT] = { "quic:udp_datagrams_sent", GQ_QLOG_EXTRA },
  [QE_UDP_DATAGRAMS_RECEIVED]
    = { "quic:udp_datagrams_received", GQ_QLOG_EXTRA },
  [QE_UDP_DATAGRAM_DROPPED] = { "quic:udp_datagram_dropped", GQ_QLOG_EXTRA },
  [QE_STREAM_STATE_UPDATED] = { "quic:stream_state_updated", GQ_QLOG_BASE },
  [QE_FRAMES_CREATED] = { "quic:frames_created", GQ_QLOG_EXTRA },
  [QE_FRAMES_PARSED] = { "quic:frames_parsed", GQ_QLOG_EXTRA },
  [QE_FRAMES_PROCESSED] = { "quic:frames_processed", GQ_QLOG_EXTRA },
  [QE_STREAM_DATA_MOVED] = { "quic:stream_data_moved", GQ_QLOG_BASE },
  [QE_DATAGRAM_DATA_MOVED] = { "quic:datagram_data_moved", GQ_QLOG_BASE },
  [QE_CONNECTION_DATA_BLOCKED_UPDATED]
    = { "quic:connection_data_blocked_updated", GQ_QLOG_EXTRA },
  [QE_STREAM_DATA_BLOCKED_UPDATED]
    = { "quic:stream_data_blocked_updated", GQ_QLOG_EXTRA },
  [QE_DATAGRAM_DATA_BLOCKED_UPDATED]
    = { "quic:datagram_data_blocked_updated", GQ_QLOG_EXTRA },
  [QE_MIGRATION_STATE_UPDATED]
    = { "quic:migration_state_updated", GQ_QLOG_EXTRA },
  [QE_TIMER_UPDATED] = { "quic:timer_updated", GQ_QLOG_EXTRA },
  [QE_KEY_UPDATED] = { "quic:key_updated", GQ_QLOG_BASE },
  [QE_KEY_DISCARDED] = { "quic:key_discarded", GQ_QLOG_BASE },
  [QE_RECOVERY_PARAMETERS_SET]
    = { "quic:recovery_parameters_set", GQ_QLOG_BASE },
  [QE_RECOVERY_METRICS_UPDATED]
    = { "quic:recovery_metrics_updated", GQ_QLOG_CORE },
  [QE_CONGESTION_STATE_UPDATED]
    = { "quic:congestion_state_updated", GQ_QLOG_BASE },
  [QE_PACKET_LOST] = { "quic:packet_lost", GQ_QLOG_CORE },
  [QE_MARKED_FOR_RETRANSMIT]
    = { "quic:marked_for_retransmit", GQ_QLOG_EXTRA },
  [QE_ECN_STATE_UPDATED] = { "quic:ecn_state_updated", GQ_QLOG_EXTRA },
};

const char *
qlog_event_name (int ev)
{
  return ev >= 0 && ev < QE_COUNT ? events[ev].name : NULL;
}

int
qlog_event_level (int ev)
{
  return ev >= 0 && ev < QE_COUNT ? events[ev].level : 0;
}

uint64_t
qlog_mask_for (int level)
{
  uint64_t m = 0;
  int i;

  if (level < GQ_QLOG_CORE || level > GQ_QLOG_EXTRA)
    level = GQ_QLOG_EXTRA;
  for (i = 0; i < QE_COUNT; i++)
    if (events[i].level <= level)
      m |= (uint64_t) 1 << i;
  return m;
}

/* ---- Names ---- */

const char *
qlog_transport_error (uint64_t code)
{
  static const char *const names[] = {
    "no_error", "internal_error", "connection_refused", "flow_control_error",
    "stream_limit_error", "stream_state_error", "final_size_error",
    "frame_encoding_error", "transport_parameter_error",
    "connection_id_limit_error", "protocol_violation", "invalid_token",
    "application_error", "crypto_buffer_exceeded", "key_update_error",
    "aead_limit_reached", "no_viable_path"
  };

  if (code < sizeof names / sizeof names[0])
    return names[code];
  return NULL;
}

const char *
qlog_packet_type_name (int sp, int early)
{
  if (early)
    return "0RTT";
  return sp == SP_INITIAL ? "initial" : sp == SP_HANDSHAKE ? "handshake"
         : "1RTT";
}

/* An error code as the draft has it: CRYPTO_ERROR as a string of its own,
   a transport error by name, and anything else "unknown" with the number.
   APP: the code is an application's, which has no names here.  The fields
   are KEY and, for an unknown one, error_code.  */
void
qlog_error (qkv *w, const char *key, uint64_t code, int app)
{
  const char *name = app ? NULL : qlog_transport_error (code);

  if (!app && code >= GQ_QERR_CRYPTO_BASE && code <= GQ_QERR_CRYPTO_BASE + 0xff)
    {
      static const char hexd[] = "0123456789abcdef";
      char s[] = "crypto_error_0x1xx";

      s[16] = hexd[(code >> 4) & 15];
      s[17] = hexd[code & 15];
      qkv_str (w, key, s);
      return;
    }
  if (name)
    {
      qkv_str (w, key, name);
      return;
    }
  qkv_str (w, key, "unknown");
  qkv_u64 (w, "error_code", code);
}

/* The "raw" member of a frame: the length of its data, and the first
   RAW_MAX bytes of it when asked to.  */
static void
raw_data (qkv *w, const uint8_t *p, size_t n, size_t raw_max)
{
  qkv_push (w, "raw");
  qkv_u64 (w, "length", n);
  if (raw_max && n)
    qkv_hex (w, "data", p, n < raw_max ? n : raw_max);
  qkv_pop (w);
}

static const char *
stream_type_name (int bidi)
{
  return bidi ? "bidirectional" : "unidirectional";
}

static int
ack_range_out (void *user, uint64_t lo, uint64_t hi)
{
  qkv_item_range (user, lo, hi);
  return 0;
}

void
qlog_frame (qkv *w, const gq_frame *f, unsigned ack_delay_exp, size_t raw_max)
{
  switch (f->type)
    {
    case GQ_FRAME_PADDING:
      qkv_str (w, "frame_type", "padding");
      qkv_push (w, "raw");
      qkv_u64 (w, "payload_length", f->u.padding.len);
      qkv_pop (w);
      break;
    case GQ_FRAME_PING:
      qkv_str (w, "frame_type", "ping");
      break;
    case GQ_FRAME_ACK:
      {
        uint64_t delay_us;
        unsigned e = ack_delay_exp > 20 ? 20 : ack_delay_exp;

        delay_us = f->u.ack.delay > (UINT64_MAX >> e) ? UINT64_MAX
                                                      : f->u.ack.delay << e;
        qkv_str (w, "frame_type", "ack");
        qkv_ms (w, "ack_delay", delay_us);
        qkv_list (w, "acked_ranges");
        gq_ack_foreach (f, ack_range_out, w);
        qkv_end_list (w);
        if (f->u.ack.has_ecn)
          {
            qkv_u64 (w, "ect1", f->u.ack.ect1);
            qkv_u64 (w, "ect0", f->u.ack.ect0);
            qkv_u64 (w, "ce", f->u.ack.ecn_ce);
          }
        break;
      }
    case GQ_FRAME_RESET_STREAM:
      qkv_str (w, "frame_type", "reset_stream");
      qkv_u64 (w, "stream_id", f->u.reset_stream.id);
      qlog_error (w, "error", f->u.reset_stream.error, 1);
      qkv_u64 (w, "final_size", f->u.reset_stream.final_size);
      break;
    case GQ_FRAME_STOP_SENDING:
      qkv_str (w, "frame_type", "stop_sending");
      qkv_u64 (w, "stream_id", f->u.stop_sending.id);
      qlog_error (w, "error", f->u.stop_sending.error, 1);
      break;
    case GQ_FRAME_CRYPTO:
      qkv_str (w, "frame_type", "crypto");
      qkv_u64 (w, "offset", f->u.crypto.offset);
      raw_data (w, f->u.crypto.data.data, f->u.crypto.data.len, raw_max);
      break;
    case GQ_FRAME_NEW_TOKEN:
      qkv_str (w, "frame_type", "new_token");
      qkv_push (w, "token");
      raw_data (w, f->u.new_token.token.data, f->u.new_token.token.len,
                raw_max);
      qkv_pop (w);
      break;
    case GQ_FRAME_STREAM:
      qkv_str (w, "frame_type", "stream");
      qkv_u64 (w, "stream_id", f->u.stream.id);
      qkv_u64 (w, "offset", f->u.stream.offset);
      if (f->u.stream.fin)
        qkv_bool (w, "fin", 1);
      raw_data (w, f->u.stream.data.data, f->u.stream.data.len, raw_max);
      break;
    case GQ_FRAME_MAX_DATA:
      qkv_str (w, "frame_type", "max_data");
      qkv_u64 (w, "maximum", f->u.max_data.max);
      break;
    case GQ_FRAME_MAX_STREAM_DATA:
      qkv_str (w, "frame_type", "max_stream_data");
      qkv_u64 (w, "stream_id", f->u.max_stream_data.id);
      qkv_u64 (w, "maximum", f->u.max_stream_data.max);
      break;
    case GQ_FRAME_MAX_STREAMS:
      qkv_str (w, "frame_type", "max_streams");
      qkv_str (w, "stream_type", stream_type_name (f->u.max_streams.bidi));
      qkv_u64 (w, "maximum", f->u.max_streams.max);
      break;
    case GQ_FRAME_DATA_BLOCKED:
      qkv_str (w, "frame_type", "data_blocked");
      qkv_u64 (w, "limit", f->u.data_blocked.limit);
      break;
    case GQ_FRAME_STREAM_DATA_BLOCKED:
      qkv_str (w, "frame_type", "stream_data_blocked");
      qkv_u64 (w, "stream_id", f->u.stream_data_blocked.id);
      qkv_u64 (w, "limit", f->u.stream_data_blocked.limit);
      break;
    case GQ_FRAME_STREAMS_BLOCKED:
      qkv_str (w, "frame_type", "streams_blocked");
      qkv_str (w, "stream_type", stream_type_name (f->u.streams_blocked.bidi));
      qkv_u64 (w, "limit", f->u.streams_blocked.limit);
      break;
    case GQ_FRAME_NEW_CONNECTION_ID:
      qkv_str (w, "frame_type", "new_connection_id");
      qkv_u64 (w, "sequence_number", f->u.new_connection_id.seq);
      qkv_u64 (w, "retire_prior_to", f->u.new_connection_id.retire_prior_to);
      qkv_u64 (w, "connection_id_length", f->u.new_connection_id.cid_len);
      qkv_hex (w, "connection_id", f->u.new_connection_id.cid,
               f->u.new_connection_id.cid_len);
      qkv_hex (w, "stateless_reset_token", f->u.new_connection_id.reset_token,
               GQ_RESET_TOKEN_LEN);
      break;
    case GQ_FRAME_RETIRE_CONNECTION_ID:
      qkv_str (w, "frame_type", "retire_connection_id");
      qkv_u64 (w, "sequence_number", f->u.retire_connection_id.seq);
      break;
    case GQ_FRAME_PATH_CHALLENGE:
    case GQ_FRAME_PATH_RESPONSE:
      qkv_str (w, "frame_type",
               f->type == GQ_FRAME_PATH_CHALLENGE ? "path_challenge"
                                                  : "path_response");
      qkv_hex (w, "data", f->u.path_challenge.data, 8);
      break;
    case GQ_FRAME_CONNECTION_CLOSE:
      {
        const gq_slice *r = &f->u.connection_close.reason;
        int app = f->u.connection_close.application;

        qkv_str (w, "frame_type", "connection_close");
        qkv_str (w, "error_space", app ? "application" : "transport");
        qlog_error (w, "error", f->u.connection_close.error, app);
        if (r->len)
          {
            if (qkv_utf8_ok (r->data, r->len))
              qkv_strn (w, "reason", (const char *) r->data, r->len);
            else
              qkv_hex (w, "reason_bytes", r->data, r->len);
          }
        if (!app)
          qkv_u64 (w, "trigger_frame_type", f->u.connection_close.frame_type);
        break;
      }
    case GQ_FRAME_HANDSHAKE_DONE:
      qkv_str (w, "frame_type", "handshake_done");
      break;
    case GQ_FRAME_DATAGRAM:
      qkv_str (w, "frame_type", "datagram");
      raw_data (w, f->u.datagram.data.data, f->u.datagram.data.len, raw_max);
      break;
    default:
      qkv_str (w, "frame_type", "unknown");
      qkv_u64 (w, "frame_type_bytes", (uint64_t) f->type);
      break;
    }
}

int
qlog_sent_frame (qkv *w, const sent_frame *f)
{
  /* Only what the record of a sent frame holds: a frame whose required
     fields are not in it is left out.  */
  switch (f->type)
    {
    case SF_CRYPTO:
      qkv_str (w, "frame_type", "crypto");
      qkv_u64 (w, "offset", f->a);
      qkv_push (w, "raw");
      qkv_u64 (w, "length", f->len);
      qkv_pop (w);
      return 1;
    case SF_STREAM:
      qkv_str (w, "frame_type", "stream");
      qkv_u64 (w, "stream_id", f->a);
      qkv_u64 (w, "offset", f->b);
      if (f->fin)
        qkv_bool (w, "fin", 1);
      qkv_push (w, "raw");
      qkv_u64 (w, "length", f->len);
      qkv_pop (w);
      return 1;
    case SF_MAX_DATA:
      qkv_str (w, "frame_type", "max_data");
      qkv_u64 (w, "maximum", f->a);
      return 1;
    case SF_MAX_STREAM_DATA:
      qkv_str (w, "frame_type", "max_stream_data");
      qkv_u64 (w, "stream_id", f->a);
      qkv_u64 (w, "maximum", f->b);
      return 1;
    case SF_MAX_STREAMS:
      qkv_str (w, "frame_type", "max_streams");
      qkv_str (w, "stream_type", stream_type_name (f->a != 0));
      qkv_u64 (w, "maximum", f->b);
      return 1;
    case SF_DATA_BLOCKED:
      qkv_str (w, "frame_type", "data_blocked");
      qkv_u64 (w, "limit", f->a);
      return 1;
    case SF_RETIRE_CID:
      qkv_str (w, "frame_type", "retire_connection_id");
      qkv_u64 (w, "sequence_number", f->a);
      return 1;
    case SF_HANDSHAKE_DONE:
      qkv_str (w, "frame_type", "handshake_done");
      return 1;
    case SF_PATH_CHALLENGE:
    case SF_PATH_RESPONSE:
      qkv_str (w, "frame_type",
               f->type == SF_PATH_CHALLENGE ? "path_challenge"
                                            : "path_response");
      return 1;
    case SF_DATAGRAM:
      qkv_str (w, "frame_type", "datagram");
      return 1;
    default:
      return 0;
    }
}

void
qlog_header (qkv *w, const qlog_hdr *h, size_t raw_max)
{
  qkv_push (w, "header");
  qkv_str (w, "packet_type", h->type);
  if (h->have_spin)
    qkv_bool (w, "spin_bit", h->spin);
  if (h->have_key_phase)
    qkv_bool (w, "key_phase_bit", h->key_phase);
  if (h->have_pn)
    {
      qkv_u64 (w, "packet_number_length", h->pn_len);
      qkv_u64 (w, "packet_number", h->pn);
    }
  if (h->have_token)
    {
      qkv_push (w, "token");
      raw_data (w, h->token, h->token_len, raw_max);
      qkv_pop (w);
    }
  if (h->have_length)
    qkv_u64 (w, "length", h->length);
  if (h->have_version)
    {
      uint8_t v[4] = { (uint8_t) (h->version >> 24), (uint8_t) (h->version >> 16),
                       (uint8_t) (h->version >> 8), (uint8_t) h->version };

      qkv_hex (w, "version", v, 4);
    }
  if (h->have_scid)
    {
      qkv_u64 (w, "scil", h->scid_len);
      qkv_hex (w, "scid", h->scid, h->scid_len);
    }
  if (h->have_dcid)
    {
      qkv_u64 (w, "dcil", h->dcid_len);
      qkv_hex (w, "dcid", h->dcid, h->dcid_len);
    }
  qkv_pop (w);
}
