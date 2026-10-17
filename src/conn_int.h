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

/* Internals shared by the QUIC connection source files.  */

#ifndef QUICKSTEP_CONN_INT_H
#define QUICKSTEP_CONN_INT_H

#include <quickstep/status.h>
#include <quickstep/crypto.h>
#include <quickstep/varint.h>
#include <quickstep/frame.h>
#include <quickstep/packet.h>
#include <quickstep/protect.h>
#include <quickstep/tparams.h>
#include <quickstep/ranges.h>
#include <quickstep/stream.h>
#include <quickstep/tls.h>
#include <quickstep/conn.h>
#include "cc.h"
#include "qlog.h"

enum { SP_INITIAL, SP_HANDSHAKE, SP_APP, N_SPACES };

/* RFC 9002 constants, in microseconds.  */
#define K_GRANULARITY 1000u
#define K_INITIAL_RTT 333000u
/* The round trip time before the first sample: the configured one, or this.  */
#define CONN_INITIAL_RTT(c) \
  ((c)->cfg.initial_rtt_us ? (c)->cfg.initial_rtt_us : (uint64_t) K_INITIAL_RTT)
#define K_PACKET_THRESHOLD 3
/* RFC 9002 section 7.2: the datagram size congestion control counts in, and
   the initial and minimum windows.  */
#define CC_MAX_DATAGRAM 1200u
#define CC_INITIAL_WINDOW (10u * CC_MAX_DATAGRAM)
#define CC_MIN_WINDOW (2u * CC_MAX_DATAGRAM)
#define K_PERSISTENT_CONGESTION_THRESHOLD 3
#define MAX_FRAMES_PER_PACKET 48
#define MAX_LCID 8
#define MAX_PCID 16
#define MAX_PATHS 4
#define MAX_CANDIDATES 3
#define MAX_CHALLENGES 3

/* What a sent packet carried that must be retransmitted if it is lost.  */
enum sf_type
{
  SF_CRYPTO = 1, SF_STREAM, SF_RESET_STREAM, SF_STOP_SENDING, SF_MAX_DATA,
  SF_MAX_STREAM_DATA, SF_MAX_STREAMS, SF_DATA_BLOCKED,
  SF_STREAM_DATA_BLOCKED, SF_NEW_CID, SF_RETIRE_CID, SF_HANDSHAKE_DONE,
  SF_ACK, SF_PATH_RESPONSE, SF_NEW_TOKEN, SF_PATH_CHALLENGE, SF_DATAGRAM
};

typedef struct sent_frame
{
  uint8_t type;
  uint8_t fin;			/* STREAM; MAX_STREAMS: bidi.  */
  uint32_t len;
  uint64_t a, b;
} sent_frame;

/* The packets of an ECN test (RFC 9000 section 13.4.2).  */
#define ECN_TEST_PACKETS 10

typedef struct sent_pkt
{
  uint64_t pn;
  uint64_t time_us;
  uint32_t size;
  uint8_t ack_eliciting, in_flight, requeued;
  uint8_t early;		/* Sent as a 0-RTT packet.  */
  uint32_t pmtu_probe;		/* Not 0: a path MTU probe of that search, whose
				   loss is not congestion.  */
  uint32_t ecn_gen;		/* Sent marked ECT(0), in this test: else 0.  */
  uint32_t nframes;
  sent_frame *frames;
} sent_pkt;

/* ACK frames sent and not yet acknowledged, per space (RFC 9000 section
   13.2.4).  */
#define ACK_SENT_MAX 16

typedef struct space
{
  gq_packet_keys rk, wk;
  uint8_t have_rk, have_wk, discarded;
  uint64_t next_pn;
  uint64_t largest_acked;
  uint8_t have_acked;
  uint64_t largest_recv;
  uint64_t largest_recv_time;
  uint8_t have_recv;
  gq_ranges recv;		/* Packet numbers received.  */
  uint8_t ack_pending;		/* An ACK should go out.  */
  uint8_t ack_now;		/* ...without waiting.  */
  unsigned ae_since_ack;	/* Ack-eliciting packets not yet acked.  */
  uint64_t ack_deadline;	/* 0: none.  */
  gq_sstream cs;		/* CRYPTO send half.  */
  gq_rstream cr;		/* CRYPTO receive half.  */
  sent_pkt *sent;		/* Ordered by pn.  */
  size_t n_sent, cap_sent;
  uint64_t loss_time;		/* 0: none.  */
  uint64_t last_ae_time;	/* Time of the last ack-eliciting send.  */
  gq_ranges acked_pns;		/* Recently acknowledged packet numbers.  */
  uint64_t recv_floor;		/* Packet numbers below this count as seen.  */
  unsigned ae_in_flight;	/* Ack-eliciting packets outstanding.  */
  unsigned probes;		/* Probe packets still to send.  */
  struct
  {
    uint64_t pn, largest;	/* The packet, and what its ACK frame named.  */
  } ack_sent[ACK_SENT_MAX];
  unsigned n_ack_sent;
  uint64_t ecn_in[3];		/* Received with ECT(0), ECT(1), CE.  */
  /* Validating ECN (section 13.4.2): the counts the peer last reported,
     the packets we marked ECT(0), and the largest packet number of the ACK
     frames whose counts were last looked at.  */
  uint64_t ecn_peer[3];
  uint64_t ecn_sent;
  uint64_t ecn_largest;
  uint8_t ecn_have_largest;
} space;

typedef struct lcid
{
  uint64_t seq;
  gq_cid cid;
  uint8_t token[GQ_RESET_TOKEN_LEN];
  uint8_t used;			/* Slot in use.  */
  uint8_t announced;		/* NEW_CONNECTION_ID acked or seq 0.  */
  uint8_t need_send;		/* NEW_CONNECTION_ID must be (re)sent.  */
} lcid;

typedef struct pcid
{
  uint64_t seq;
  gq_cid cid;
  uint8_t token[GQ_RESET_TOKEN_LEN];
  uint8_t has_token;		/* The peer gave one for this ID: a client
				   gives none for its first (RFC 9000
				   section 18.2), and zeros are no token.  */
  uint8_t used;
  uint8_t retire;		/* 0: active, 1: RETIRE to send, 2: sent.  */
} pcid;

/* One network path (RFC 9000 section 8.2, 9).  */
typedef struct pathinfo
{
  gq_path p;
  uint8_t used;
  uint8_t initial;		/* The path the handshake ran on.  */
  uint8_t validated;
  uint8_t local_init;		/* We started it (probe or migration).  */
  uint8_t auto_switch;		/* Migrate to it once validated.  */
  gq_cid dcid;			/* Peer ID used on this path.  */
  uint64_t dcid_seq;
  uint64_t recv, sent;		/* Bytes, for the amplification limit.  */
  uint8_t chal[MAX_CHALLENGES][8];	/* Outstanding challenge data.  */
  unsigned n_chal;
  uint8_t need_challenge;
  unsigned chal_sent;
  uint64_t chal_next, chal_deadline;
  uint32_t pmtu;		/* The datagram size found for it, or 0.  */
  uint8_t resp[2][8];		/* Responses owed to the peer on this path.  */
  unsigned n_resp;
} pathinfo;

typedef struct stream
{
  uint64_t id;
  uint8_t has_send, has_recv;
  uint8_t opened_notified, full;	/* full: send buffer was full.  */
  const char *ql_send, *ql_recv;	/* States last logged.  */
  uint8_t ql_blocked;			/* Last logged as blocked by flow control.  */
  gq_sstream s;
  gq_rstream r;
} stream;

struct gq_conn
{
  enum gq_role role;
  enum gq_conn_state state;
  gq_conn_config cfg;
  gq_conn_events ev;
  gq_conn_router router;
  uint32_t version;
  uint32_t orig_version;	/* Version of the first flight.  */
  uint8_t switched;		/* A compatible version switch happened.  */
  uint8_t vn_received;		/* Restarted after Version Negotiation.  */
  /* 0-RTT (RFC 9001 section 4.6).  */
  gq_packet_keys early_wk, early_rk;
  uint8_t have_early_wk, have_early_rk;
  uint8_t early_offered;	/* Client: we sent (or may send) early data.  */
  uint8_t early_provisional;	/* Limits are the remembered ones.  */
  uint8_t early_accepted, early_rejected;
  uint8_t rx_early;		/* The packet being processed is 0-RTT.  */
  uint64_t early_rk_deadline;
  gq_transport_params resume_tp;
  uint8_t peer_tp_raw[512];
  size_t peer_tp_raw_len;
  gq_packet_keys orig_rk;	/* Server: Initial keys of orig_version.  */
  uint8_t have_orig_rk;

  gq_tls *tls;
  gq_tls_config ctls;		/* Copies of the caller's configuration:  */
  gq_tls_server_config stls;
  gq_ticket_keys *ticket_base;	/* Server: the caller's ring (v1 tickets).  */
  gq_ticket_keys *ticket_v2;	/* ...and the ring derived for v2.  */	/* the engine keeps pointers into them.  */
  uint8_t tp_buf[256];
  size_t tp_len;
  gq_transport_params peer_tp;
  int have_peer_tp;
  int tls_started;

  space sp[N_SPACES];
  uint8_t handshake_complete;		/* TLS finished.  */
  uint8_t handshake_confirmed;
  uint8_t handshake_done_pending;
  uint8_t handshake_done_sent;
  uint8_t connected_notified;
  uint8_t got_first_initial;		/* Server: keys derived.  */
  uint8_t peer_addr_validated;
  uint8_t got_peer_packet;

  gq_cid odcid;			/* Original destination CID (client's).  */
  gq_cid initial_dcid;		/* Destination ID the Initial keys come from.  */
  gq_cid retry_scid;		/* Retry: the ID the server chose (len 0: none).  */
  uint8_t retried;
  uint8_t token[512];		/* Client: token for Initial packets.  */
  size_t token_len;
  const gq_token_keys *token_keys;	/* Server: issue NEW_TOKEN.  */
  uint8_t addr[64];
  size_t addr_len;
  uint8_t new_token_pending;
  gq_cid scid_first;		/* Our first source CID.  */
  lcid l[MAX_LCID];
  pcid p[MAX_PCID];
  uint64_t next_lseq;
  uint64_t peer_retire_prior;
  gq_cid dcid;			/* Current destination CID.  */
  uint8_t dcid_set;
  uint64_t dcid_seq;
  size_t peer_cid_limit;		/* Peer's active_connection_id_limit.  */

  /* Application key state (RFC 9001 section 6).  */
  uint8_t rsec[GQ_MAX_HASH_LEN], wsec[GQ_MAX_HASH_LEN];
  uint8_t rsec_next[GQ_MAX_HASH_LEN];
  size_t rsec_len, wsec_len;
  gq_packet_keys rk_prev, rk_next;
  uint8_t have_rk_prev, have_rk_next;
  uint8_t r_phase, w_phase;
  uint64_t r_first_pn;		/* First pn of the current read phase.  */
  uint64_t w_first_pn;		/* First pn we sent in the write phase.  */
  uint8_t w_phase_acked;
  uint64_t rk_prev_until;	/* When the previous phase's read keys go.  */
  uint64_t aead_failed;		/* Packets that failed authentication.  */
  uint8_t ecn_state;		/* A gq_ecn_state.  */
  /* Path MTU discovery: the size of datagrams sent now, the largest known
     to work and the smallest known not to (or one past the ceiling, before
     the first probe), and the probe being sent.  */
  uint8_t pmtu_state, pmtu_probe_out, pmtu_fails;
  uint32_t pmtu_cur, pmtu_lo, pmtu_hi, pmtu_probe_size;
  uint32_t pmtu_gen;		/* Counts the searches; a probe carries it.  */
  uint64_t pmtu_raise_at;	/* When a finished search is made again.  */
  uint32_t ecn_gen;		/* Counts the tests; packets sent in one carry
				   it, and none is 0.  */
  uint64_t ecn_test_sent, ecn_test_ae, ecn_test_acked, ecn_test_lost;
  uint64_t ecn_marked_sent;
  uint64_t ecn_test_pns[ECN_TEST_PACKETS];	/* Packet numbers of the test that carry only
				   an ACK and so are not in a sent list.  */
  unsigned ecn_n_test_pns, ecn_test_acked_pns;
  uint8_t tx_ecn_ok;		/* The send in progress may mark packets.  */
  uint8_t tx_ecn;		/* The codepoint of the datagram it made.  */
  int8_t rx_ecn;		/* ECN field of the datagram being processed
				   (a gq_ecn), or -1 if we are not told.  */
  uint64_t ecn_in[3];		/* Packets received with ECT(0), ECT(1), CE.  */
  uint8_t spin_on;		/* The spin bit is in use (else random).  */
  uint8_t spin_val;		/* The value the next packet carries.  */
  uint64_t spin_bits, spin_nbits;	/* Random bits for when it is off.  */
  uint64_t key_updates;

  /* Timing.  */
  uint64_t now;
  uint64_t latest_rtt, srtt, rttvar, min_rtt;
  uint8_t have_rtt;
  uint64_t first_rtt_us;	/* When the first RTT sample was taken.  */
  uint8_t pc_active;		/* A run of lost packets is being followed:  */
  uint64_t pc_first_us, pc_last_us;	/* ...when its first and last were sent.  */
  uint8_t hs_acked;		/* A Handshake packet of ours was acknowledged.  */
  unsigned pto_count;
  uint64_t idle_timeout_us;
  uint64_t idle_deadline;
  uint64_t close_deadline;
  uint64_t last_close_sent;
  uint8_t idle_send_reset;
  uint64_t last_sent_ae;
  uint64_t peer_max_ack_delay_us;
  unsigned peer_ack_delay_exp;

  /* Amplification and totals.  */
  uint64_t bytes_recv, bytes_sent;
  uint64_t bytes_in_flight;
  qlog_conn ql;
  cong cc;			/* Congestion window, threshold and recovery.  */
  pacer pace;			/* Spreads the window over the round trip.  */
  uint64_t congestion_events;
  /* The last attempt to send stopped for lack of window or pacing credit
     (not of data, or of the peer's flow control), so the window is in use
     and may grow when data is acknowledged (RFC 9002 section 7.8).  */
  uint8_t send_blocked;
  /* Stream data is held back until then for lack of pacing credit; 0: not
     held back.  PACE_WAIT_US is how long, noted while a datagram is built.  */
  uint64_t pace_deadline, pace_wait_us;
  gq_conn_stats st;

  /* Flow control.  */
  uint64_t max_data_peer, data_sent;	/* What we may send / have sent.  */
  uint64_t blocked_sent_at;
  uint64_t max_data_local, max_data_sent;
  uint64_t data_recv_total, data_consumed;
  uint64_t max_streams_peer[2];		/* [bidi], [uni]: we may open.  */
  uint64_t next_local_stream[2];	/* Next index to open.  */
  uint64_t max_streams_local[2];	/* Peer may open.  */
  uint64_t max_streams_local_sent[2];
  uint64_t next_peer_stream[2];		/* Next peer index expected.  */
  uint64_t closed_peer_streams[2];	/* Peer streams fully closed.  */
  uint8_t streams_blocked_pending[2];

  stream **streams;		/* Sorted by id.  */
  size_t n_streams, cap_streams, rr;

  /* Pending control frames.  */
  /* Queued outgoing DATAGRAMs (RFC 9221).  */
  struct dgram { uint8_t *data; size_t len; uint64_t id; } *dq;
  size_t dq_head, dq_n, dq_cap, dq_bytes;
  uint64_t next_dgram_id;
  uint64_t datagrams_sent, datagrams_received, datagrams_dropped;
  pathinfo paths[MAX_PATHS];
  int cur_path, prev_path;	/* Indices, -1: none.  */
  int tx_path;			/* Where the datagram being built goes.  */
  gq_path bad_path[2];		/* Recently failed candidates,  */
  uint64_t bad_until[2];	/* ignored until then.  */
  unsigned bad_next;
  gq_path rx;			/* Where the datagram being processed came from.  */
  int rx_known;
  uint64_t path_validations, path_failures, migrations;

  /* Closing.  */
  uint8_t close_pending;
  uint8_t close_app;
  uint64_t close_err, close_frame;
  char close_reason[64];
  size_t close_reason_len;
  uint8_t closed_notified;

  /* Set by a handler that decided the connection must close.  */
  int err_set;
  uint64_t err_code;
  const char *err_reason;
};

/* conn.c */
void conn_fail (gq_conn *c, uint64_t code, const char *reason);

/* Path MTU discovery (conn_pmtu.c).  */
#define PMTU_BASE 1200
enum { PMTU_START = 0, PMTU_SEARCH, PMTU_DONE };
void conn_pmtu_init (gq_conn *c);
size_t conn_pmtu_next_probe (gq_conn *c, size_t cap);
void conn_pmtu_probe_sent (gq_conn *c);
void conn_pmtu_acked (gq_conn *c, size_t size, uint32_t gen);
void conn_pmtu_lost (gq_conn *c, size_t size, uint32_t gen);
int conn_pmtu_done (const gq_conn *c);
uint32_t conn_pmtu_gen (const gq_conn *c);
void conn_pmtu_on_pto (gq_conn *c);
void conn_pmtu_switch (gq_conn *c, int old, int idx);
uint64_t conn_pmtu_deadline (const gq_conn *c);
void conn_pmtu_on_timeout (gq_conn *c, uint64_t now);

/* ECN (conn_ecn.c).  */
void conn_ecn_restart (gq_conn *c);
int conn_ecn_marks (gq_conn *c, int dest, const int *spaces,
                    const uint8_t *early, int n);
uint32_t conn_ecn_sent (gq_conn *c, int ae, uint64_t pn);
void conn_ecn_datagram_sent (gq_conn *c);
void conn_ecn_lost (gq_conn *c, const sent_pkt *p);
void conn_ecn_on_ack (gq_conn *c, int sp, const gq_frame *f,
                      const sent_pkt *got, size_t n, uint64_t now);

/* The latency spin bit (conn.c).  */
int conn_spin_enabled (const gq_conn_config *cfg, unsigned draw);
void conn_spin_draw (gq_conn *c);
void conn_spin_reset (gq_conn *c);
void conn_spin_received (gq_conn *c, int bit, int highest);
int conn_spin_value (gq_conn *c);
void conn_enter_closing (gq_conn *c, gq_conn_close_info *info, int draining);
int conn_server_start (gq_conn *c, const uint8_t *odcid, size_t odcid_len,
                       const uint8_t *client_scid, size_t client_scid_len);
void conn_recompute_idle (gq_conn *c, uint64_t now);
void conn_wake (gq_conn *c);
void conn_peer_token (gq_conn *c, const uint8_t *token);
void conn_cid_retired (gq_conn *c, const gq_cid *cid);
int conn_client_restart (gq_conn *c, uint32_t version);
int conn_version_compatible (uint32_t a, uint32_t b);
int conn_version_listed (const gq_conn *c, uint32_t v);
void conn_abandon (gq_conn *c, uint64_t error, const char *reason);
uint64_t conn_pto_base (const gq_conn *c, int sp);
int conn_new_lcid (gq_conn *c, int announced);
uint64_t conn_wall_seconds (const gq_conn *c);
int conn_apply_peer_params (gq_conn *c);
int conn_discard_space (gq_conn *c, int sp);
void conn_maybe_confirm (gq_conn *c);
void conn_notify_connected (gq_conn *c, const gq_tls_info *info);
size_t conn_max_datagram (const gq_conn *c);

/* conn_qlog.c: the qlog events (see qlog.h).  */
const char *ql_tuple (gq_conn *c, int idx);
void ql_connection_started (gq_conn *c);
void ql_state (gq_conn *c, const char *state, int granular);
void ql_handshake_started (gq_conn *c);
void ql_peer_validated (gq_conn *c);
void ql_closed (gq_conn *c, int source, int application, uint64_t error,
                const uint8_t *reason, size_t reason_len, const char *trigger);
void ql_cid_check (gq_conn *c);
void ql_spin_bit_updated (gq_conn *c, int state);
void ql_ecn_state_updated (gq_conn *c, int old, int state);
void ql_mtu_updated (gq_conn *c, size_t old, size_t new, int done);
void ql_rx_cid (gq_conn *c, const uint8_t *cid, size_t len);
void ql_version_information (gq_conn *c, const uint32_t *client,
                             size_t nclient, const uint32_t *server,
                             size_t nserver, uint32_t chosen);
void ql_alpn_information (gq_conn *c, const gq_slice *client, size_t nclient,
                          const gq_slice *server, size_t nserver,
                          const uint8_t *chosen, size_t chosen_len);
void ql_parameters_set (gq_conn *c, int remote, const gq_transport_params *tp);
void ql_parameters_tls (gq_conn *c, const gq_tls_info *info);
void ql_parameters_restored (gq_conn *c, const gq_transport_params *tp);
void ql_key_updated (gq_conn *c, enum gq_level level, enum gq_dir dir,
                     const char *trigger);
void ql_key_discarded (gq_conn *c, enum gq_level level, enum gq_dir dir,
                       int have_phase, unsigned phase, const char *trigger);
void ql_recovery_parameters (gq_conn *c);
void ql_packets_acked (gq_conn *c, int sp, const sent_pkt *got, size_t n);
void ql_packet_lost (gq_conn *c, int sp, const sent_pkt *p, int reordering);
void ql_marked_for_retransmit (gq_conn *c, const sent_pkt *p);
void ql_metrics (gq_conn *c);
void ql_cc_state (gq_conn *c, const char *trigger);
void ql_timers (gq_conn *c);
void ql_after (gq_conn *c);
void ql_tuple_assigned (gq_conn *c, int idx, int abandoned);
void ql_migration (gq_conn *c, const char *state, int idx);
void ql_blocked (gq_conn *c, const char *conn_reason, const char *dgram_reason);
void ql_stream_blocked (gq_conn *c, struct stream *st, int blocked);
struct stream;
void ql_stream_states (gq_conn *c, struct stream *st, const char *trigger);
void ql_stream_moved (gq_conn *c, uint64_t id, int have_off, uint64_t off,
                      const char *from, const char *to, size_t len,
                      const char *info);
void ql_datagram_moved (gq_conn *c, const char *from, const char *to,
                        size_t len);
void ql_timers_expired (gq_conn *c, uint64_t now);
void ql_frames_add (char *buf, size_t cap, size_t *len, unsigned *n,
                    const gq_frame *f, unsigned ack_delay_exp, size_t raw_max);
void ql_frames_add_padding (char *buf, size_t cap, size_t *len, unsigned *n,
                            size_t pad);
void ql_datagram (gq_conn *c, int ev, uint32_t id, size_t len, int ecn);
void ql_rx_datagram (gq_conn *c, size_t len);
void ql_datagram_dropped (gq_conn *c, size_t len);
void ql_packet_sent (gq_conn *c, const qlog_hdr *h, size_t raw_len,
                     size_t payload_len, const char *frames,
                     size_t frames_len, uint32_t dgram_id,
                     const char *trigger, int path_idx, int mtu_probe);
void ql_packet_received (gq_conn *c, const qlog_hdr *h, size_t raw_len,
                         const uint8_t *payload, size_t payload_len,
                         int path_idx, const uint32_t *vn, size_t n_vn,
                         const uint8_t *reset_token);
void ql_packet_dropped (gq_conn *c, const qlog_hdr *h, size_t raw_len,
                        const char *trigger);

/* conn_loss.c */
void sp_sent_add (gq_conn *c, int sp, const sent_pkt *p);
void sp_sent_clear (gq_conn *c, int sp);
void conn_note_ack_sent (gq_conn *c, int sp, uint64_t pn, uint64_t largest);
void free_sent_frames (sent_pkt *p);
void process_ack (gq_conn *c, int sp, const gq_frame *f, uint64_t now);
void loss_detect (gq_conn *c, int sp, uint64_t now);
uint64_t conn_loss_deadline (const gq_conn *c);
void on_loss_timeout (gq_conn *c, uint64_t now);
void requeue_frames (gq_conn *c, int sp, sent_pkt *p);
uint64_t pto_interval (const gq_conn *c, int sp);
int conn_can_send_ae (const gq_conn *c);
void cc_init (gq_conn *c);
double conn_pacing_rate (const gq_conn *c);

/* conn_loss.c (0-RTT) */
void conn_early_rejected (gq_conn *c);
void conn_early_accepted (gq_conn *c);

/* conn_stream.c */
stream *stream_find (const gq_conn *c, uint64_t id);
stream *stream_for_frame (gq_conn *c, uint64_t id, int for_send);
void stream_remove_if_done (gq_conn *c, stream *st);
void streams_free (gq_conn *c);
void streams_apply_peer_params (gq_conn *c);
uint64_t stream_initial_send_credit (const gq_conn *c, uint64_t id);
uint64_t stream_initial_recv_credit (const gq_conn *c, uint64_t id);
int stream_handle_frame (gq_conn *c, const gq_frame *f);
void stream_on_acked (gq_conn *c, uint64_t id);

/* conn_datagram.c */
void datagrams_free (gq_conn *c);
struct dgram *datagram_front (gq_conn *c);
void datagram_pop (gq_conn *c);

/* conn_path.c */
void conn_path_init (gq_conn *c, const gq_path *initial);
void conn_path_rx_begin (gq_conn *c, const gq_path *from);
void conn_path_rx_end (gq_conn *c);
int conn_path_accept_rx (const gq_conn *c);
void conn_path_after_packet (gq_conn *c, uint64_t now, int nonprobing,
                             int highest);
void conn_path_account_recv (gq_conn *c, size_t len);
void conn_path_on_challenge (gq_conn *c, const uint8_t *data);
void conn_path_on_response (gq_conn *c, const uint8_t *data, uint64_t now);
int conn_path_probe_pending (gq_conn *c, uint64_t now);
void conn_path_challenge_data (gq_conn *c, int idx, uint8_t out[8]);
uint64_t conn_path_deadline (const gq_conn *c);
void conn_path_on_timeout (gq_conn *c, uint64_t now);
int conn_path_budget (const gq_conn *c, int idx, uint64_t *budget);
size_t conn_min_ae_datagram (const gq_conn *c, int sp);
void conn_path_note_sent (gq_conn *c, int idx, size_t len);
void conn_path_dcid_changed (gq_conn *c);
void conn_path_cids_retired (gq_conn *c);
int conn_path_rx_initial (const gq_conn *c);

/* conn_send.c */
int conn_build_datagram (gq_conn *c, uint64_t now, uint8_t *out, size_t cap,
                         size_t *len);
int conn_have_work (gq_conn *c, int sp);

/* conn_recv.c */
int conn_receive_datagram (gq_conn *c, uint64_t now, uint8_t *data,
                           size_t len);
void conn_install_keys (gq_conn *c, const gq_tls_secret *s);

#define SPACE_OF_LEVEL(l) ((l) == GQ_LEVEL_INITIAL ? SP_INITIAL \
                           : (l) == GQ_LEVEL_HANDSHAKE ? SP_HANDSHAKE \
                           : (l) == GQ_LEVEL_APPLICATION ? SP_APP : -1)

#endif /* QUICKSTEP_CONN_INT_H */
