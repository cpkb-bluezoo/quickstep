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

/* The qlog line format (src/qlog.c) on its own: the writer, the event
   table against Table 1 of draft-ietf-quic-qlog-quic-events, and the
   serializers of frames and packet headers.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "conn_int.h"
#include "qlog.h"

#include "tst-util.h"
#include "tst-qkv.h"
#include "tst-qlogcheck.h"

/* Write with FILL into a buffer and parse what came out.  */
#define PARSE_OK(w, q) \
  do { CHECK (!(w).err); CHECK (qline_parse ((w).buf, (w).len, &(q))); } while (0)

/* ---- The writer ---- */

static void
test_writer_basics (void)
{
  char buf[256];
  qkv w;
  qline q;

  qkv_init (&w, buf, sizeof buf);
  qkv_u64 (&w, "a", 0);
  qkv_u64 (&w, "big", UINT64_MAX);
  qkv_bool (&w, "yes", 1);
  qkv_bool (&w, "no", 0);
  qkv_str (&w, "s", "quic");
  CHECK_EQ (strcmp (buf, "a=0 big=18446744073709551615 yes=true no=false s=quic"),
            0);
  PARSE_OK (w, q);
  CHECK (qline_is_u (&q, "big", UINT64_MAX));
  CHECK (qline_is (&q, "yes", "true"));
  qline_free (&q);
}

static void
test_writer_escapes (void)
{
  char buf[256];
  qkv w;
  qline q;
  static const char odd[] = "a b%c=d\n\t\xc3\xa9\x01~";

  qkv_init (&w, buf, sizeof buf);
  qkv_strn (&w, "reason", odd, sizeof odd - 1);
  /* No space, no newline: it is one field however odd the bytes.  */
  CHECK (strchr (buf, ' ') == NULL);
  CHECK (strchr (buf, '\n') == NULL);
  /* A '=' in a value is fine: a field splits at the first.  */
  CHECK (strchr (buf + 7, '=') != NULL);
  PARSE_OK (w, q);
  CHECK_EQ (q.n, 1);
  CHECK_EQ (memcmp (q.val[0], odd, sizeof odd - 1), 0);
  qline_free (&q);
  /* An empty string is a field with an empty value.  */
  qkv_init (&w, buf, sizeof buf);
  qkv_str (&w, "e", "");
  CHECK_EQ (strcmp (buf, "e="), 0);
}

static void
test_writer_decimals (void)
{
  char buf[256];
  qkv w;

  qkv_init (&w, buf, sizeof buf);
  qkv_ms (&w, "a", 0);
  qkv_ms (&w, "b", 125);
  qkv_ms (&w, "c", 1999);
  qkv_ms (&w, "d", 100000);
  qkv_milli (&w, "f", 700);
  qkv_milli (&w, "g", 1125);
  CHECK_EQ (strcmp (buf, "a=0.000 b=0.125 c=1.999 d=100.000 f=0.700 g=1.125"),
            0);
}

static void
test_writer_prefix_and_lists (void)
{
  char buf[512];
  qkv w;
  qline q;
  static const uint8_t cid[] = { 0x00, 0xab, 0xff };

  qkv_init (&w, buf, sizeof buf);
  qkv_u64 (&w, "n", 1);
  qkv_push (&w, "header");
  qkv_str (&w, "packet_type", "1RTT");
  qkv_push (&w, "token");
  qkv_push (&w, "raw");
  qkv_u64 (&w, "length", 8);
  qkv_pop (&w);
  qkv_pop (&w);
  qkv_hex (&w, "dcid", cid, sizeof cid);
  qkv_pop (&w);
  qkv_push_i (&w, "frames", 12);
  qkv_str (&w, "frame_type", "ping");
  qkv_pop (&w);
  qkv_list (&w, "packet_numbers");
  qkv_item_u64 (&w, 1);
  qkv_item_u64 (&w, 2);
  qkv_item_u64 (&w, 30);
  qkv_end_list (&w);
  qkv_list (&w, "ranges");
  qkv_item_range (&w, 3, 7);
  qkv_item_range (&w, 9, 9);
  qkv_item_range (&w, 11, 12);
  qkv_end_list (&w);
  qkv_list (&w, "empty");
  qkv_end_list (&w);
  qkv_list (&w, "names");
  qkv_item_str (&w, "a");
  qkv_item_str (&w, "b c");
  qkv_item_hex (&w, cid, sizeof cid);
  qkv_end_list (&w);
  qkv_u64 (&w, "last", 2);
  PARSE_OK (w, q);
  CHECK (qline_is (&q, "header.packet_type", "1RTT"));
  CHECK (qline_is_u (&q, "header.token.raw.length", 8));
  CHECK (qline_is (&q, "header.dcid", "00abff"));
  CHECK (qline_is (&q, "frames.12.frame_type", "ping"));
  CHECK (qline_is (&q, "packet_numbers", "1,2,30"));
  CHECK (qline_is (&q, "ranges", "3-7,9,11-12"));
  CHECK (qline_is (&q, "empty", ""));
  CHECK (qline_is (&q, "names", "a,b c,00abff"));
  /* The prefix is back to nothing after the pops.  */
  CHECK (qline_is_u (&q, "n", 1));
  CHECK (qline_is_u (&q, "last", 2));
  qline_free (&q);
}

static void
test_writer_overflow (void)
{
  char buf[16];
  qkv w;

  /* Never beyond the buffer, and the failure is remembered.  */
  qkv_init (&w, buf, sizeof buf);
  qkv_str (&w, "key", "a long enough value to run out of room");
  CHECK (w.err);
  CHECK (strlen (buf) < sizeof buf);
  qkv_init (&w, buf, sizeof buf);
  qkv_u64 (&w, "k", 1);
  CHECK (!w.err);
  qkv_init (&w, buf, 0);
  CHECK (w.err);
  /* A prefix that is too deep or too long is an error, not an overflow.  */
  qkv_init (&w, buf, sizeof buf);
  {
    int i;

    for (i = 0; i < QKV_DEPTH_MAX + 1; i++)
      qkv_push (&w, "x");
  }
  CHECK (w.err);
}

static void
test_utf8 (void)
{
  CHECK (qkv_utf8_ok ((const uint8_t *) "plain", 5));
  CHECK (qkv_utf8_ok ((const uint8_t *) "\xc3\xa9", 2));
  CHECK (qkv_utf8_ok ((const uint8_t *) "\xe2\x82\xac", 3));
  CHECK (qkv_utf8_ok ((const uint8_t *) "\xf0\x9f\x98\x80", 4));
  CHECK (qkv_utf8_ok ((const uint8_t *) "", 0));
  CHECK (!qkv_utf8_ok ((const uint8_t *) "\xc3", 1));	/* Truncated.  */
  CHECK (!qkv_utf8_ok ((const uint8_t *) "\xc0\x80", 2));	/* Overlong.  */
  CHECK (!qkv_utf8_ok ((const uint8_t *) "\xed\xa0\x80", 3));	/* Surrogate.  */
  CHECK (!qkv_utf8_ok ((const uint8_t *) "\xf5\x80\x80\x80", 4));
  CHECK (!qkv_utf8_ok ((const uint8_t *) "\xff", 1));
  CHECK (!qkv_utf8_ok ((const uint8_t *) "a\x80", 2));
}

/* ---- The events ---- */

/* Table 1 of the draft: every name, and its importance.  */
static const struct
{
  const char *name;
  int level;
} table1[] = {
  { "quic:server_listening", GQ_QLOG_EXTRA },
  { "quic:connection_started", GQ_QLOG_BASE },
  { "quic:connection_closed", GQ_QLOG_BASE },
  { "quic:connection_id_updated", GQ_QLOG_BASE },
  { "quic:spin_bit_updated", GQ_QLOG_BASE },
  { "quic:connection_state_updated", GQ_QLOG_BASE },
  { "quic:tuple_assigned", GQ_QLOG_BASE },
  { "quic:mtu_updated", GQ_QLOG_EXTRA },
  { "quic:version_information", GQ_QLOG_CORE },
  { "quic:alpn_information", GQ_QLOG_CORE },
  { "quic:parameters_set", GQ_QLOG_CORE },
  { "quic:parameters_restored", GQ_QLOG_BASE },
  { "quic:packet_sent", GQ_QLOG_CORE },
  { "quic:packet_received", GQ_QLOG_CORE },
  { "quic:packet_dropped", GQ_QLOG_BASE },
  { "quic:packet_buffered", GQ_QLOG_BASE },
  { "quic:packets_acked", GQ_QLOG_EXTRA },
  { "quic:udp_datagrams_sent", GQ_QLOG_EXTRA },
  { "quic:udp_datagrams_received", GQ_QLOG_EXTRA },
  { "quic:udp_datagram_dropped", GQ_QLOG_EXTRA },
  { "quic:stream_state_updated", GQ_QLOG_BASE },
  { "quic:frames_created", GQ_QLOG_EXTRA },
  { "quic:frames_parsed", GQ_QLOG_EXTRA },
  { "quic:frames_processed", GQ_QLOG_EXTRA },
  { "quic:stream_data_moved", GQ_QLOG_BASE },
  { "quic:datagram_data_moved", GQ_QLOG_BASE },
  { "quic:connection_data_blocked_updated", GQ_QLOG_EXTRA },
  { "quic:stream_data_blocked_updated", GQ_QLOG_EXTRA },
  { "quic:datagram_data_blocked_updated", GQ_QLOG_EXTRA },
  { "quic:migration_state_updated", GQ_QLOG_EXTRA },
  { "quic:timer_updated", GQ_QLOG_EXTRA },
  { "quic:key_updated", GQ_QLOG_BASE },
  { "quic:key_discarded", GQ_QLOG_BASE },
  { "quic:recovery_parameters_set", GQ_QLOG_BASE },
  { "quic:recovery_metrics_updated", GQ_QLOG_CORE },
  { "quic:congestion_state_updated", GQ_QLOG_BASE },
  { "quic:packet_lost", GQ_QLOG_CORE },
  { "quic:marked_for_retransmit", GQ_QLOG_EXTRA },
  { "quic:ecn_state_updated", GQ_QLOG_EXTRA },
};

static void
test_event_table (void)
{
  size_t i;
  uint64_t core, base, extra;

  CHECK_EQ (QE_COUNT, sizeof table1 / sizeof table1[0]);
  for (i = 0; i < sizeof table1 / sizeof table1[0]; i++)
    {
      CHECK (qlog_event_name ((int) i) != NULL);
      if (qlog_event_name ((int) i))
        CHECK_EQ (strcmp (qlog_event_name ((int) i), table1[i].name), 0);
      CHECK_EQ (qlog_event_level ((int) i), table1[i].level);
    }
  CHECK (qlog_event_name (QE_COUNT) == NULL);
  CHECK (qlog_event_name (-1) == NULL);
  core = qlog_mask_for (GQ_QLOG_CORE);
  base = qlog_mask_for (GQ_QLOG_BASE);
  extra = qlog_mask_for (GQ_QLOG_EXTRA);
  /* Each level includes the one before; 0 is everything.  */
  CHECK ((core & base) == core && core != base);
  CHECK ((base & extra) == base && base != extra);
  CHECK_EQ (qlog_mask_for (GQ_QLOG_ALL), extra);
  CHECK_EQ (extra, ((uint64_t) 1 << QE_COUNT) - 1);
  CHECK ((core >> QE_PACKET_SENT) & 1);
  CHECK (!((core >> QE_PACKET_DROPPED) & 1));
  CHECK ((base >> QE_PACKET_DROPPED) & 1);
  CHECK (!((base >> QE_TIMER_UPDATED) & 1));
  CHECK ((extra >> QE_TIMER_UPDATED) & 1);
}

static void
test_errors (void)
{
  CHECK_EQ (strcmp (qlog_transport_error (0), "no_error"), 0);
  CHECK_EQ (strcmp (qlog_transport_error (0xa), "protocol_violation"), 0);
  CHECK_EQ (strcmp (qlog_transport_error (0x10), "no_viable_path"), 0);
  CHECK (qlog_transport_error (0x11) == NULL);
  CHECK (qlog_transport_error (0x1234) == NULL);
  CHECK_EQ (strcmp (qlog_packet_type_name (SP_INITIAL, 0), "initial"), 0);
  CHECK_EQ (strcmp (qlog_packet_type_name (SP_HANDSHAKE, 0), "handshake"), 0);
  CHECK_EQ (strcmp (qlog_packet_type_name (SP_APP, 0), "1RTT"), 0);
  CHECK_EQ (strcmp (qlog_packet_type_name (SP_APP, 1), "0RTT"), 0);
}

/* ---- Frames ---- */

/* Serialize F as item 0 of a list of frames and parse it back.  */
static int
frame_line (const gq_frame *f, unsigned ade, size_t raw_max, qline *q)
{
  static char buf[4096];
  qkv w;

  qkv_init (&w, buf, sizeof buf);
  qkv_push_i (&w, "frames", 0);
  qlog_frame (&w, f, ade, raw_max);
  qkv_pop (&w);
  return !w.err && qline_parse (w.buf, w.len, q);
}

static void
test_frames_simple (void)
{
  gq_frame f;
  qline q;

  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_PADDING;
  f.u.padding.len = 37;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "padding"));
  CHECK (qline_is_u (&q, "frames.0.raw.payload_length", 37));
  qline_free (&q);

  f.type = GQ_FRAME_PING;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "ping"));
  CHECK_EQ (q.n, 1);
  qline_free (&q);

  f.type = GQ_FRAME_HANDSHAKE_DONE;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "handshake_done"));
  qline_free (&q);

  f.type = GQ_FRAME_MAX_DATA;
  f.u.max_data.max = 1u << 20;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "max_data"));
  CHECK (qline_is_u (&q, "frames.0.maximum", 1u << 20));
  qline_free (&q);

  f.type = GQ_FRAME_MAX_STREAM_DATA;
  f.u.max_stream_data.id = 4;
  f.u.max_stream_data.max = 99;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "max_stream_data"));
  CHECK (qline_is_u (&q, "frames.0.stream_id", 4));
  CHECK (qline_is_u (&q, "frames.0.maximum", 99));
  qline_free (&q);

  f.type = GQ_FRAME_MAX_STREAMS;
  f.u.max_streams.bidi = 1;
  f.u.max_streams.max = 100;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.stream_type", "bidirectional"));
  CHECK (qline_is_u (&q, "frames.0.maximum", 100));
  qline_free (&q);
  f.u.max_streams.bidi = 0;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.stream_type", "unidirectional"));
  qline_free (&q);

  f.type = GQ_FRAME_DATA_BLOCKED;
  f.u.data_blocked.limit = 77;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "data_blocked"));
  CHECK (qline_is_u (&q, "frames.0.limit", 77));
  qline_free (&q);

  f.type = GQ_FRAME_STREAM_DATA_BLOCKED;
  f.u.stream_data_blocked.id = 8;
  f.u.stream_data_blocked.limit = 5;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "stream_data_blocked"));
  CHECK (qline_is_u (&q, "frames.0.stream_id", 8));
  CHECK (qline_is_u (&q, "frames.0.limit", 5));
  qline_free (&q);

  f.type = GQ_FRAME_STREAMS_BLOCKED;
  f.u.streams_blocked.bidi = 0;
  f.u.streams_blocked.limit = 3;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "streams_blocked"));
  CHECK (qline_is (&q, "frames.0.stream_type", "unidirectional"));
  CHECK (qline_is_u (&q, "frames.0.limit", 3));
  qline_free (&q);

  f.type = GQ_FRAME_RETIRE_CONNECTION_ID;
  f.u.retire_connection_id.seq = 6;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "retire_connection_id"));
  CHECK (qline_is_u (&q, "frames.0.sequence_number", 6));
  qline_free (&q);

  f.type = GQ_FRAME_PATH_CHALLENGE;
  memcpy (f.u.path_challenge.data, "\x01\x02\x03\x04\x05\x06\x07\xff", 8);
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "path_challenge"));
  CHECK (qline_is (&q, "frames.0.data", "01020304050607ff"));
  qline_free (&q);
  f.type = GQ_FRAME_PATH_RESPONSE;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "path_response"));
  qline_free (&q);
}

static void
test_frame_ack (void)
{
  static const gq_ack_range ranges[] = { { 11, 12 }, { 9, 9 }, { 3, 7 } };
  uint8_t enc[64];
  size_t w = 0;
  gq_frame f;
  qline q;

  CHECK_EQ (gq_ack_ranges_encode (ranges, 3, enc, sizeof enc, &w), GQ_OK);
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_ACK;
  f.u.ack.largest = 12;
  f.u.ack.range_count = 2;
  f.u.ack.ranges.data = enc;
  f.u.ack.ranges.len = w;
  f.u.ack.delay = 125;
  /* 125 units of 2^3 us is a millisecond.  */
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "ack"));
  CHECK (qline_is (&q, "frames.0.ack_delay", "1.000"));
  CHECK (qline_is (&q, "frames.0.acked_ranges", "11-12,9,3-7"));
  CHECK (qline_get (&q, "frames.0.ect0") == NULL);
  qline_free (&q);
  /* The exponent is the sender's.  */
  CHECK (frame_line (&f, 0, 0, &q));
  CHECK (qline_is (&q, "frames.0.ack_delay", "0.125"));
  qline_free (&q);
  /* A delay too big to represent saturates, it does not wrap.  */
  f.u.ack.delay = UINT64_MAX;
  CHECK (frame_line (&f, 20, 0, &q));
  CHECK (qline_get (&q, "frames.0.ack_delay") != NULL);
  qline_free (&q);
  f.u.ack.delay = 1;
  f.u.ack.has_ecn = 1;
  f.u.ack.ect0 = 5;
  f.u.ack.ect1 = 6;
  f.u.ack.ecn_ce = 7;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is_u (&q, "frames.0.ect0", 5));
  CHECK (qline_is_u (&q, "frames.0.ect1", 6));
  CHECK (qline_is_u (&q, "frames.0.ce", 7));
  qline_free (&q);
}

static void
test_frames_data (void)
{
  static const uint8_t data[] = { 0xde, 0xad, 0xbe, 0xef, 0x01 };
  gq_frame f;
  qline q;

  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_STREAM;
  f.u.stream.id = 4;
  f.u.stream.offset = 1000;
  f.u.stream.data.data = data;
  f.u.stream.data.len = sizeof data;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "stream"));
  CHECK (qline_is_u (&q, "frames.0.stream_id", 4));
  CHECK (qline_is_u (&q, "frames.0.offset", 1000));
  CHECK (qline_get (&q, "frames.0.fin") == NULL);
  CHECK (qline_is_u (&q, "frames.0.raw.length", 5));
  CHECK (qline_get (&q, "frames.0.raw.data") == NULL);	/* Not asked for.  */
  qline_free (&q);
  f.u.stream.fin = 1;
  CHECK (frame_line (&f, 3, 3, &q));
  CHECK (qline_is (&q, "frames.0.fin", "true"));
  CHECK (qline_is_u (&q, "frames.0.raw.length", 5));
  CHECK (qline_is (&q, "frames.0.raw.data", "deadbe"));	/* First 3 bytes.  */
  qline_free (&q);
  CHECK (frame_line (&f, 3, 100, &q));
  CHECK (qline_is (&q, "frames.0.raw.data", "deadbeef01"));
  qline_free (&q);

  f.type = GQ_FRAME_CRYPTO;
  f.u.crypto.offset = 7;
  f.u.crypto.data.data = data;
  f.u.crypto.data.len = 4;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "crypto"));
  CHECK (qline_is_u (&q, "frames.0.offset", 7));
  CHECK (qline_is_u (&q, "frames.0.raw.length", 4));
  qline_free (&q);

  f.type = GQ_FRAME_NEW_TOKEN;
  f.u.new_token.token.data = data;
  f.u.new_token.token.len = 5;
  CHECK (frame_line (&f, 3, 2, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "new_token"));
  CHECK (qline_is_u (&q, "frames.0.token.raw.length", 5));
  CHECK (qline_is (&q, "frames.0.token.raw.data", "dead"));
  qline_free (&q);

  f.type = GQ_FRAME_DATAGRAM;
  f.u.datagram.data.data = data;
  f.u.datagram.data.len = 5;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "datagram"));
  CHECK (qline_is_u (&q, "frames.0.raw.length", 5));
  qline_free (&q);
}

static void
test_frames_reset_and_cids (void)
{
  gq_frame f;
  qline q;

  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_RESET_STREAM;
  f.u.reset_stream.id = 12;
  f.u.reset_stream.error = 0x42;
  f.u.reset_stream.final_size = 9000;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "reset_stream"));
  CHECK (qline_is_u (&q, "frames.0.stream_id", 12));
  /* An application error has no name here.  */
  CHECK (qline_is (&q, "frames.0.error", "unknown"));
  CHECK (qline_is_u (&q, "frames.0.error_code", 0x42));
  CHECK (qline_is_u (&q, "frames.0.final_size", 9000));
  qline_free (&q);

  f.type = GQ_FRAME_STOP_SENDING;
  f.u.stop_sending.id = 16;
  f.u.stop_sending.error = 7;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "stop_sending"));
  CHECK (qline_is_u (&q, "frames.0.stream_id", 16));
  CHECK (qline_is_u (&q, "frames.0.error_code", 7));
  qline_free (&q);

  f.type = GQ_FRAME_NEW_CONNECTION_ID;
  f.u.new_connection_id.seq = 2;
  f.u.new_connection_id.retire_prior_to = 1;
  f.u.new_connection_id.cid_len = 4;
  memcpy (f.u.new_connection_id.cid, "\xaa\xbb\xcc\xdd", 4);
  memset (f.u.new_connection_id.reset_token, 0x5a, GQ_RESET_TOKEN_LEN);
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "new_connection_id"));
  CHECK (qline_is_u (&q, "frames.0.sequence_number", 2));
  CHECK (qline_is_u (&q, "frames.0.retire_prior_to", 1));
  CHECK (qline_is_u (&q, "frames.0.connection_id_length", 4));
  CHECK (qline_is (&q, "frames.0.connection_id", "aabbccdd"));
  CHECK (qline_is (&q, "frames.0.stateless_reset_token",
                   "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"));
  qline_free (&q);
}

static void
test_frame_connection_close (void)
{
  static const uint8_t utf8[] = "bad request \xc3\xa9";
  static const uint8_t binary[] = { 0xff, 0xfe, 0x00 };
  gq_frame f;
  qline q;

  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_CONNECTION_CLOSE;
  f.u.connection_close.error = GQ_QERR_PROTOCOL_VIOLATION;
  f.u.connection_close.frame_type = 0x08;
  f.u.connection_close.reason.data = utf8;
  f.u.connection_close.reason.len = sizeof utf8 - 1;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.frame_type", "connection_close"));
  CHECK (qline_is (&q, "frames.0.error_space", "transport"));
  CHECK (qline_is (&q, "frames.0.error", "protocol_violation"));
  CHECK (qline_get (&q, "frames.0.error_code") == NULL);
  CHECK (qline_is (&q, "frames.0.reason", "bad request \xc3\xa9"));
  CHECK (qline_get (&q, "frames.0.reason_bytes") == NULL);
  CHECK (qline_is_u (&q, "frames.0.trigger_frame_type", 8));
  qline_free (&q);

  /* A reason that is not text goes as bytes.  */
  f.u.connection_close.reason.data = binary;
  f.u.connection_close.reason.len = sizeof binary;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_get (&q, "frames.0.reason") == NULL);
  CHECK (qline_is (&q, "frames.0.reason_bytes", "fffe00"));
  qline_free (&q);

  /* A TLS alert is a CRYPTO_ERROR of its own name.  */
  f.u.connection_close.error = GQ_QERR_CRYPTO_BASE + 0x28;
  f.u.connection_close.reason.len = 0;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.error", "crypto_error_0x128"));
  qline_free (&q);

  /* A code with no name is unknown, with its number.  */
  f.u.connection_close.error = 0x7777;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.error", "unknown"));
  CHECK (qline_is_u (&q, "frames.0.error_code", 0x7777));
  qline_free (&q);

  /* An application's: its own space, its numbers, no trigger frame.  */
  f.u.connection_close.application = 1;
  f.u.connection_close.error = 0x0a;
  CHECK (frame_line (&f, 3, 0, &q));
  CHECK (qline_is (&q, "frames.0.error_space", "application"));
  CHECK (qline_is (&q, "frames.0.error", "unknown"));
  CHECK (qline_is_u (&q, "frames.0.error_code", 0x0a));
  CHECK (qline_get (&q, "frames.0.trigger_frame_type") == NULL);
  qline_free (&q);
}

/* A frame that was kept when a packet was sent.  */
static void
test_sent_frames (void)
{
  static char buf[1024];
  qkv w;
  sent_frame f;
  qline q;

  memset (&f, 0, sizeof f);
  f.type = SF_STREAM;
  f.a = 8;
  f.b = 4096;
  f.len = 1100;
  f.fin = 1;
  qkv_init (&w, buf, sizeof buf);
  qkv_push_i (&w, "frames", 0);
  CHECK (qlog_sent_frame (&w, &f));
  qkv_pop (&w);
  f.type = SF_MAX_STREAMS;
  f.a = 1;
  f.b = 55;
  qkv_push_i (&w, "frames", 1);
  CHECK (qlog_sent_frame (&w, &f));
  qkv_pop (&w);
  /* One whose required fields were not kept is not logged at all.  */
  f.type = SF_RESET_STREAM;
  CHECK (!qlog_sent_frame (&w, &f));
  f.type = SF_NEW_CID;
  CHECK (!qlog_sent_frame (&w, &f));
  PARSE_OK (w, q);
  CHECK (qline_is (&q, "frames.0.frame_type", "stream"));
  CHECK (qline_is_u (&q, "frames.0.stream_id", 8));
  CHECK (qline_is_u (&q, "frames.0.offset", 4096));
  CHECK (qline_is (&q, "frames.0.fin", "true"));
  CHECK (qline_is_u (&q, "frames.0.raw.length", 1100));
  CHECK (qline_is (&q, "frames.1.frame_type", "max_streams"));
  CHECK (qline_is (&q, "frames.1.stream_type", "bidirectional"));
  CHECK (qline_is_u (&q, "frames.1.maximum", 55));
  CHECK_EQ (q.n, 5 + 3);
  CHECK_EQ (qline_count (&q, "frames.0."), 5);
  CHECK_EQ (qline_count (&q, "frames.1."), 3);
  qline_free (&q);
}

/* ---- Packet headers ---- */

static void
test_header (void)
{
  static char buf[1024];
  static const uint8_t dcid[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  static const uint8_t scid[] = { 9, 8 };
  static const uint8_t tok[] = { 0xca, 0xfe, 0xba, 0xbe };
  qlog_hdr h;
  qkv w;
  qline q;

  memset (&h, 0, sizeof h);
  h.type = "initial";
  h.have_pn = 1;
  h.pn = 3;
  h.pn_len = 2;
  h.have_length = 1;
  h.length = 1180;
  h.have_version = 1;
  h.version = 0x00000001;
  h.have_dcid = h.have_scid = 1;
  h.dcid = dcid;
  h.dcid_len = sizeof dcid;
  h.scid = scid;
  h.scid_len = sizeof scid;
  h.have_token = 1;
  h.token = tok;
  h.token_len = sizeof tok;
  qkv_init (&w, buf, sizeof buf);
  qlog_header (&w, &h, 0);
  PARSE_OK (w, q);
  CHECK (qline_is (&q, "header.packet_type", "initial"));
  CHECK (qline_is_u (&q, "header.packet_number", 3));
  CHECK (qline_is_u (&q, "header.packet_number_length", 2));
  CHECK (qline_is_u (&q, "header.length", 1180));
  CHECK (qline_is (&q, "header.version", "00000001"));
  CHECK (qline_is_u (&q, "header.dcil", 8));
  CHECK (qline_is (&q, "header.dcid", "0102030405060708"));
  CHECK (qline_is_u (&q, "header.scil", 2));
  CHECK (qline_is (&q, "header.scid", "0908"));
  CHECK (qline_is_u (&q, "header.token.raw.length", 4));
  CHECK (qline_get (&q, "header.token.raw.data") == NULL);
  CHECK (qline_get (&q, "header.key_phase_bit") == NULL);
  qline_free (&q);

  qkv_init (&w, buf, sizeof buf);
  qlog_header (&w, &h, 2);
  PARSE_OK (w, q);
  CHECK (qline_is (&q, "header.token.raw.data", "cafe"));
  qline_free (&q);

  /* A short header: a key phase, no version, no source ID.  */
  memset (&h, 0, sizeof h);
  h.type = "1RTT";
  h.have_pn = 1;
  h.pn = 1u << 30;
  h.pn_len = 4;
  h.have_key_phase = 1;
  h.key_phase = 1;
  h.have_spin = 1;
  h.spin = 0;
  h.have_dcid = 1;
  h.dcid = dcid;
  h.dcid_len = 4;
  qkv_init (&w, buf, sizeof buf);
  qlog_header (&w, &h, 0);
  PARSE_OK (w, q);
  CHECK (qline_is (&q, "header.packet_type", "1RTT"));
  CHECK (qline_is (&q, "header.key_phase_bit", "true"));
  CHECK (qline_is (&q, "header.spin_bit", "false"));
  CHECK (qline_get (&q, "header.version") == NULL);
  CHECK (qline_get (&q, "header.scid") == NULL);
  CHECK (qline_get (&q, "header.length") == NULL);
  qline_free (&q);

  /* A packet type alone: a stateless reset, say.  */
  memset (&h, 0, sizeof h);
  h.type = "stateless_reset";
  qkv_init (&w, buf, sizeof buf);
  qlog_header (&w, &h, 0);
  PARSE_OK (w, q);
  CHECK_EQ (q.n, 1);
  qline_free (&q);
}

/* ---- The checker of events ---- */

static const char *
check (const char *name, const char *fields)
{
  static char where[200];

  return qc_check (name, fields, strlen (fields), where, sizeof where);
}

/* What the checker passes and what it does not: it is only worth anything if
   it refuses what the draft does not allow.  */
static void
test_checker (void)
{
  /* Good.  */
  CHECK (check ("quic:connection_started", "") == NULL);
  CHECK (check ("quic:packet_sent",
                "header.packet_type=1RTT header.packet_number=3 "
                "frames.0.frame_type=ack frames.0.ack_delay=0.125 "
                "frames.0.acked_ranges=1-3,5 frames.1.frame_type=stream "
                "frames.1.stream_id=0 frames.1.raw.length=10") == NULL);
  CHECK (check ("quic:connection_state_updated",
                "old=attempted new=handshake_started") == NULL);
  CHECK (check ("quic:recovery_metrics_updated",
                "congestion_window=12000") == NULL);
  /* The name.  */
  CHECK (check ("packet_sent", "header.packet_type=1RTT") != NULL);
  CHECK (check ("quic:packet_send", "header.packet_type=1RTT") != NULL);
  CHECK (check ("http3:packet_sent", "header.packet_type=1RTT") != NULL);
  /* The line.  */
  CHECK (check ("quic:packet_sent", "header.packet_type=1RTT  x=1") != NULL);
  CHECK (check ("quic:packet_sent", "header.packet_type") != NULL);
  /* A required field.  */
  CHECK (check ("quic:packet_sent", "header.packet_number=3") != NULL);
  CHECK (check ("quic:connection_state_updated", "old=attempted") != NULL);
  CHECK (check ("quic:recovery_metrics_updated", "") != NULL);
  CHECK (check ("quic:timer_updated", "timer_type=ack") != NULL);
  /* A value that is not allowed.  */
  CHECK (check ("quic:packet_sent", "header.packet_type=2RTT") != NULL);
  CHECK (check ("quic:packet_dropped", "trigger=because") != NULL);
  CHECK (check ("quic:connection_state_updated", "new=sleeping") != NULL);
  CHECK (check ("quic:stream_state_updated",
                "stream_id=0 new=open stream_side=both") != NULL);
  CHECK (check ("quic:key_updated", "key_type=client_secret") != NULL);
  /* A value of the wrong type.  */
  CHECK (check ("quic:packet_sent",
                "header.packet_type=1RTT header.packet_number=x") != NULL);
  CHECK (check ("quic:packet_sent",
                "header.packet_type=1RTT header.dcid=xyz") != NULL);
  CHECK (check ("quic:packet_sent",
                "header.packet_type=1RTT header.dcid=abc") != NULL);
  CHECK (check ("quic:packet_sent",
                "header.packet_type=1RTT frames.0.frame_type=ack "
                "frames.0.ack_delay=12 frames.0.acked_ranges=1") != NULL);
  CHECK (check ("quic:packet_sent",
                "header.packet_type=1RTT frames.0.frame_type=stream "
                "frames.0.stream_id=1 frames.0.fin=yes") != NULL);
  /* An ACK range backwards or empty.  */
  CHECK (check ("quic:packet_received",
                "header.packet_type=1RTT frames.0.frame_type=ack "
                "frames.0.acked_ranges=5-3") != NULL);
  CHECK (check ("quic:packet_received",
                "header.packet_type=1RTT frames.0.frame_type=ack "
                "frames.0.acked_ranges=") != NULL);
  /* Frames: an unknown type, and one without what it must have.  */
  CHECK (check ("quic:packet_sent",
                "header.packet_type=1RTT frames.0.frame_type=teleport") != NULL);
  CHECK (check ("quic:packet_sent",
                "header.packet_type=1RTT frames.0.frame_type=stream") != NULL);
  CHECK (check ("quic:packet_sent",
                "header.packet_type=1RTT frames.0.stream_id=1") != NULL);
  CHECK (check ("quic:packet_sent",
                "header.packet_type=1RTT frames.0.frame_type=max_streams "
                "frames.0.stream_type=both frames.0.maximum=3") != NULL);
  /* A field the draft does not give the event: misspelled, or misplaced.  */
  CHECK (check ("quic:recovery_metrics_updated", "congestion_windw=1") != NULL);
  CHECK (check ("quic:packet_sent",
                "header.packet_type=1RTT bytes_in_flight=3") != NULL);
  CHECK (check ("quic:packet_sent",
                "header.packet_type=1RTT header.pn=3") != NULL);
  CHECK (check ("quic:packet_sent",
                "header.packet_type=1RTT frames.0.frame_type=ping "
                "frames.0.sream_id=3") != NULL);
  CHECK (check ("quic:key_updated", "key_type=client_1rtt_secret key=00") != NULL);
  CHECK (check ("quic:key_discarded", "key_type=client_1rtt_secret key=00") == NULL);
  /* The tuple leads.  */
  CHECK (check ("quic:packet_sent", "tuple=p1 header.packet_type=1RTT") == NULL);
  CHECK (check ("quic:packet_sent", "header.packet_type=1RTT tuple=p1") != NULL);
}

/* ---- The reader itself ---- */

static void
test_reader_is_strict (void)
{
  static const char *const bad[] = {
    "a",			/* No value.  */
    "=1",			/* No key.  */
    "a=1  b=2",			/* Two spaces.  */
    "a=1 ",			/* A trailing space.  */
    " a=1",			/* A leading space.  */
    "A=1",			/* An uppercase key.  */
    "a-b=1",			/* A hyphen in a key.  */
    "a=%zz",			/* A bad escape.  */
    "a=%4",			/* A truncated escape.  */
    "a=b\tc",			/* A tab in a value.  */
    "a=\xc3\xa9",		/* A byte outside ASCII.  */
  };
  qline q;
  size_t i;

  for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
    {
      if (qline_parse (bad[i], strlen (bad[i]), &q))
        {
          fprintf (stderr, "accepted %s\n", bad[i]);
          tst_failures++;
          qline_free (&q);
        }
    }
  CHECK (qline_parse ("a=1 b=2=3 c=", 12, &q));
  CHECK (qline_is (&q, "b", "2=3"));
  CHECK (qline_is (&q, "c", ""));
  qline_free (&q);
  CHECK (qline_parse ("", 0, &q));
  CHECK_EQ (q.n, 0);
  qline_free (&q);
}

int
main (void)
{
  test_reader_is_strict ();
  test_writer_basics ();
  test_writer_escapes ();
  test_writer_decimals ();
  test_writer_prefix_and_lists ();
  test_writer_overflow ();
  test_utf8 ();
  test_event_table ();
  test_errors ();
  test_frames_simple ();
  test_frame_ack ();
  test_frames_data ();
  test_frames_reset_and_cids ();
  test_frame_connection_close ();
  test_sent_frames ();
  test_header ();
  test_checker ();
  TST_DONE ();
}
