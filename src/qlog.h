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

/* qlog internals: the writer of the line format, the events and how they are
   named and ranked, and the serializers for frames and packet headers.  The
   public side, and the format, is <quickstep/qlog.h>.  */

#ifndef QUICKSTEP_QLOG_INT_H
#define QUICKSTEP_QLOG_INT_H

#include <stddef.h>
#include <stdint.h>

#include <quickstep/frame.h>
#include <quickstep/qlog.h>

/* ---- The writer ----

   Appends KEY=VALUE fields, separated by spaces, to a buffer of the caller's
   and never beyond it: once something does not fit ERR is set and the rest
   is discarded.  Keys are written under a prefix, which is how an object's
   members and the items of a list of objects are named: qkv_push (w,
   "header") and the keys that follow are header.*, until qkv_pop.  Numbers
   are written with integer arithmetic, so the locale does not matter.  */

#define QKV_PREFIX_MAX 80
#define QKV_DEPTH_MAX 8

typedef struct qkv
{
  char *buf;
  size_t cap, len;
  int err;
  char prefix[QKV_PREFIX_MAX];
  size_t plen;
  size_t saved[QKV_DEPTH_MAX];
  int depth;
  int in_list, first_item;
} qkv;

void qkv_init (qkv *w, char *buf, size_t cap);
void qkv_push (qkv *w, const char *name);
/* The I'th item of a list of objects: NAME.I.  */
void qkv_push_i (qkv *w, const char *name, unsigned i);
void qkv_pop (qkv *w);

void qkv_u64 (qkv *w, const char *key, uint64_t v);
/* A string with the bytes that cannot be in a value written as %XX.  */
void qkv_str (qkv *w, const char *key, const char *s);
void qkv_strn (qkv *w, const char *key, const char *s, size_t n);
void qkv_bool (qkv *w, const char *key, int v);
void qkv_hex (qkv *w, const char *key, const uint8_t *p, size_t n);
/* A duration in microseconds as milliseconds with three decimals.  */
void qkv_ms (qkv *w, const char *key, uint64_t us);
/* A factor in thousandths as a decimal ("0.700").  */
void qkv_milli (qkv *w, const char *key, uint64_t thousandths);

/* A list of numbers, strings or ranges: begin it, add its items, end it.  */
void qkv_list (qkv *w, const char *key);
void qkv_item_u64 (qkv *w, uint64_t v);
void qkv_item_str (qkv *w, const char *s);
void qkv_item_hex (qkv *w, const uint8_t *p, size_t n);
void qkv_item_range (qkv *w, uint64_t lo, uint64_t hi);
void qkv_end_list (qkv *w);

/* Fields already written (a frame kept for later), as they are.  */
void qkv_append (qkv *w, const char *fields, size_t n);

/* Whether N bytes at P are well-formed UTF-8.  */
int qkv_utf8_ok (const uint8_t *p, size_t n);

/* ---- Events ---- */

/* Every event of draft-ietf-quic-qlog-quic-events, in the order of its
   Table 1.  */
enum qlog_event
{
  QE_SERVER_LISTENING,
  QE_CONNECTION_STARTED,
  QE_CONNECTION_CLOSED,
  QE_CONNECTION_ID_UPDATED,
  QE_SPIN_BIT_UPDATED,
  QE_CONNECTION_STATE_UPDATED,
  QE_TUPLE_ASSIGNED,
  QE_MTU_UPDATED,
  QE_VERSION_INFORMATION,
  QE_ALPN_INFORMATION,
  QE_PARAMETERS_SET,
  QE_PARAMETERS_RESTORED,
  QE_PACKET_SENT,
  QE_PACKET_RECEIVED,
  QE_PACKET_DROPPED,
  QE_PACKET_BUFFERED,
  QE_PACKETS_ACKED,
  QE_UDP_DATAGRAMS_SENT,
  QE_UDP_DATAGRAMS_RECEIVED,
  QE_UDP_DATAGRAM_DROPPED,
  QE_STREAM_STATE_UPDATED,
  QE_FRAMES_CREATED,
  QE_FRAMES_PARSED,
  QE_FRAMES_PROCESSED,
  QE_STREAM_DATA_MOVED,
  QE_DATAGRAM_DATA_MOVED,
  QE_CONNECTION_DATA_BLOCKED_UPDATED,
  QE_STREAM_DATA_BLOCKED_UPDATED,
  QE_DATAGRAM_DATA_BLOCKED_UPDATED,
  QE_MIGRATION_STATE_UPDATED,
  QE_TIMER_UPDATED,
  QE_KEY_UPDATED,
  QE_KEY_DISCARDED,
  QE_RECOVERY_PARAMETERS_SET,
  QE_RECOVERY_METRICS_UPDATED,
  QE_CONGESTION_STATE_UPDATED,
  QE_PACKET_LOST,
  QE_MARKED_FOR_RETRANSMIT,
  QE_ECN_STATE_UPDATED,
  QE_COUNT
};

const char *qlog_event_name (int ev);	/* "quic:packet_sent" */
int qlog_event_level (int ev);		/* A gq_qlog_importance, 1 to 3.  */
/* The events up to importance LEVEL (0: all), as a mask of 1 << event.  */
uint64_t qlog_mask_for (int level);

/* ---- Serializers ----

   Each appends fields at the writer's current prefix.  */

/* The wire's names.  */
const char *qlog_transport_error (uint64_t code);	/* NULL: unknown.  */
/* An error code as the draft has it: a name, CRYPTO_ERROR a string of its
   own, or "unknown" followed by error_code with the number.  APP: the code
   is an application's, which has no names here.  */
void qlog_error (qkv *w, const char *key, uint64_t code, int app);
const char *qlog_packet_type_name (int sp, int early);

/* A frame, as the draft's "$QuicFrame".  ACK_DELAY_EXP is the exponent of
   the sender of the frame (RFC 9000 section 18.2).  RAW_MAX is how many
   bytes of data of CRYPTO, STREAM, DATAGRAM and NEW_TOKEN frames to
   include (0: only their length).  */
void qlog_frame (qkv *w, const gq_frame *f, unsigned ack_delay_exp,
                 size_t raw_max);

/* Where a frame's data was kept when it was sent: what a lost packet
   carried.  A frame whose required fields are not kept cannot be logged
   and returns 0; otherwise 1.  */
struct sent_frame;
int qlog_sent_frame (qkv *w, const struct sent_frame *f);

/* A packet header (the draft's PacketHeader), under "header".  Fields not
   present are left at zero length, or HAVE_ clear.  */
typedef struct qlog_hdr
{
  const char *type;		/* "initial", "1RTT" ...: required.  */
  unsigned have_pn, pn_len;
  uint64_t pn;
  unsigned have_length;
  uint64_t length;		/* Of a long header: packet number + payload.  */
  unsigned have_version;
  uint32_t version;
  unsigned have_dcid, have_scid;
  const uint8_t *dcid, *scid;
  size_t dcid_len, scid_len;
  unsigned have_key_phase;	/* 1RTT: the key phase bit.  */
  unsigned key_phase;
  unsigned have_spin, spin;
  unsigned have_token;		/* Initial and Retry.  */
  size_t token_len;
  const uint8_t *token;
} qlog_hdr;

void qlog_header (qkv *w, const qlog_hdr *h, size_t raw_max);

/* ---- A connection's logging ---- */

struct gq_conn;

typedef struct qlog_conn
{
  gq_qlog_fn fn;		/* NULL: no logging.  */
  void *user;
  uint64_t mask;		/* The events that are on, 1 << qlog_event.  */
  int level;			/* gq_qlog_importance, 1 to 3.  */
  size_t raw_max;
  char *buf;			/* The event being built.  */
  size_t cap;
  qkv w;
  int busy;			/* An event is being built or delivered.  */
  char tuple[8];
  /* Frames of the packets being built (one per packet of a datagram) and
     of the packet being received, which an event for the packet carries.  */
  char *frames[3];
  size_t frames_len[3];
  unsigned frames_n[3];
  char *rx_frames;
  size_t rx_frames_len;
  size_t frames_cap;
  /* What was last reported, for the events that report a change.  */
  uint64_t last_t;		/* The latest time reported.  */
  uint32_t next_dgram_id;	/* The id of the next datagram to send.  */
  uint32_t dgram_id;		/* Of the datagram being received.  */
  const char *cstate;
  uint8_t started, hs_started, validated, closed;
  uint8_t pending_dgram;	/* A datagram came before the log began.  */
  size_t pending_len;
  int pending_ecn;		/* Its ECN codepoint, or -1: not known.  */
  uint8_t have_dcid;
  uint8_t dcid[20];
  uint8_t dcid_len;
  uint8_t have_rx_dcid;
  uint8_t rx_dcid[20];
  uint8_t rx_dcid_len;
  unsigned w_phase, r_phase;	/* Full key phase numbers.  */
  /* The recovery metrics as last reported, to report what changed.  */
  struct
  {
    uint8_t valid, have_rtt, have_ssthresh;
    uint64_t min_rtt, srtt, latest, rttvar, cwnd, inflight, ssthresh, pacing,
      packets;
    unsigned pto;
  } met;
  const char *cc_state;
  const char *conn_blocked, *dgram_blocked;	/* The reason, or NULL.  */
  const char *mig[4];		/* Migration state last reported, per path.  */
  uint64_t timer[6];		/* Deadlines as last reported; 0: none.  */
} qlog_conn;

/* The event is on.  */
#define QLOG_ON(c, ev) \
  ((c)->ql.fn != NULL && (((c)->ql.mask >> (ev)) & 1))

int qlog_conn_init (struct gq_conn *c);
void qlog_conn_free (struct gq_conn *c);
/* Start an event: the writer, with tuple= in it if TUPLE is not NULL or
   empty, or NULL if the event is off (or another is being delivered).
   qlog_end delivers it.  */
qkv *qlog_begin (struct gq_conn *c, int ev, const char *tuple);
void qlog_end (struct gq_conn *c, int ev);

#endif /* QUICKSTEP_QLOG_INT_H */
