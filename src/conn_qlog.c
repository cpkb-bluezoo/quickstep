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

/* The qlog events of a connection (draft-ietf-quic-qlog-quic-events).  The
   rest of the library calls these where something happens, and they decide
   whether anyone is listening: with no callback set, each is one pointer
   test.  The format is described in <quickstep/qlog.h>.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "conn_int.h"

#define EVENT_BUF (16u << 10)
#define FRAMES_BUF (8u << 10)

/* ---- Setup, and delivery ---- */

int
qlog_conn_init (gq_conn *c)
{
  qlog_conn *q = &c->ql;
  int i;

  if (c->cfg.qlog == NULL)
    return 0;
  q->fn = c->cfg.qlog;
  q->user = c->cfg.qlog_user;
  q->level = c->cfg.qlog_importance;
  if (q->level < GQ_QLOG_CORE || q->level > GQ_QLOG_EXTRA)
    q->level = GQ_QLOG_EXTRA;
  q->mask = qlog_mask_for (q->level);
  q->raw_max = c->cfg.qlog_raw;
  q->cap = EVENT_BUF;
  q->frames_cap = FRAMES_BUF;
  q->buf = malloc (q->cap);
  q->rx_frames = malloc (q->frames_cap);
  for (i = 0; i < 3; i++)
    q->frames[i] = malloc (q->frames_cap);
  if (q->buf == NULL || q->rx_frames == NULL || q->frames[0] == NULL
      || q->frames[1] == NULL || q->frames[2] == NULL)
    {
      /* No room: no logging, and the connection carries on.  */
      qlog_conn_free (c);
      return -1;
    }
  return 0;
}

void
qlog_conn_free (gq_conn *c)
{
  qlog_conn *q = &c->ql;
  int i;

  free (q->buf);
  free (q->rx_frames);
  for (i = 0; i < 3; i++)
    free (q->frames[i]);
  memset (q, 0, sizeof *q);
}

qkv *
qlog_begin (gq_conn *c, int ev, const char *tuple)
{
  qlog_conn *q = &c->ql;

  if (!QLOG_ON (c, ev) || q->busy)
    return NULL;
  /* A server's log begins when its connection does, which is when the first
     Initial is read; nothing comes before that.  */
  if (!q->started)
    return NULL;
  q->busy = 1;
  qkv_init (&q->w, q->buf, q->cap);
  if (tuple && *tuple)
    qkv_str (&q->w, "tuple", tuple);
  return &q->w;
}

void
qlog_end (gq_conn *c, int ev)
{
  qlog_conn *q = &c->ql;

  /* The events come in time order whatever the caller's clock does between
     calls: one that reads a little earlier than the last is held at it.  An
     event that did not fit is not delivered half-written.  */
  if (c->now > q->last_t)
    q->last_t = c->now;
  if (!q->w.err)
    q->fn (q->user, c, q->last_t, qlog_event_name (ev), q->w.buf, q->w.len);
  q->busy = 0;
}

/* The tuple an event on path slot IDX belongs to: none for the first.  */
const char *
ql_tuple (gq_conn *c, int idx)
{
  if (idx <= 0)
    return NULL;
  c->ql.tuple[0] = 'p';
  c->ql.tuple[1] = (char) ('0' + idx % 10);
  c->ql.tuple[2] = '\0';
  return c->ql.tuple;
}

/* ---- Pieces ---- */

static void
version_out (qkv *w, const char *key, uint32_t v)
{
  uint8_t b[4] = { (uint8_t) (v >> 24), (uint8_t) (v >> 16), (uint8_t) (v >> 8),
                   (uint8_t) v };

  qkv_hex (w, key, b, 4);
}

static void
versions_out (qkv *w, const char *key, const uint32_t *v, size_t n)
{
  size_t i;

  qkv_list (w, key);
  for (i = 0; i < n; i++)
    {
      uint8_t b[4] = { (uint8_t) (v[i] >> 24), (uint8_t) (v[i] >> 16),
                       (uint8_t) (v[i] >> 8), (uint8_t) v[i] };

      qkv_item_hex (w, b, 4);
    }
  qkv_end_list (w);
}

/* One half of a tuple: the address, if the application can tell us what it
   is, and the connection ID in use there.  */
static void
endpoint_out (gq_conn *c, qkv *w, const char *name, const gq_addr *a,
              const gq_cid *cid)
{
  qkv_push (w, name);
  if (c->cfg.qlog_addr && a && a->len)
    {
      char ip[64];
      uint16_t port = 0;
      int fam = c->cfg.qlog_addr (c->cfg.qlog_user, a, ip, sizeof ip, &port);

      if (fam == 4)
        {
          qkv_str (w, "ip_v4", ip);
          qkv_u64 (w, "port_v4", port);
        }
      else if (fam == 6)
        {
          qkv_str (w, "ip_v6", ip);
          qkv_u64 (w, "port_v6", port);
        }
    }
  if (cid && cid->len)
    {
      qkv_list (w, "connection_ids");
      qkv_item_hex (w, cid->data, cid->len);
      qkv_end_list (w);
    }
  qkv_pop (w);
}

/* ---- Connectivity ---- */

void
ql_connection_started (gq_conn *c)
{
  qkv *w;
  const pathinfo *e = &c->paths[c->cur_path];

  if (c->ql.started)
    return;
  c->ql.started = 1;
  if ((w = qlog_begin (c, QE_CONNECTION_STARTED, NULL)) == NULL)
    return;
  endpoint_out (c, w, "local", e->used ? &e->p.local : NULL, &c->scid_first);
  endpoint_out (c, w, "remote", e->used ? &e->p.remote : NULL,
                c->dcid_set ? &c->dcid : NULL);
  qlog_end (c, QE_CONNECTION_STARTED);
  ql_state (c, "attempted", 0);
  if (c->ql.pending_dgram)
    {
      c->ql.pending_dgram = 0;
      ql_datagram (c, QE_UDP_DATAGRAMS_RECEIVED, c->ql.dgram_id,
                   c->ql.pending_len, c->ql.pending_ecn);
    }
}

/* The connection moved to STATE.  GRANULAR: one of the draft's more detailed
   states, logged only when the importance asks for the most.  */
void
ql_state (gq_conn *c, const char *state, int granular)
{
  qkv *w;
  const char *old = c->ql.cstate;

  if (granular && c->ql.level < GQ_QLOG_EXTRA)
    return;
  if (old && !strcmp (old, state))
    return;
  if ((w = qlog_begin (c, QE_CONNECTION_STATE_UPDATED, NULL)) == NULL)
    return;
  if (old)
    qkv_str (w, "old", old);
  qkv_str (w, "new", state);
  c->ql.cstate = state;
  qlog_end (c, QE_CONNECTION_STATE_UPDATED);
}

/* The states that are entered once, whatever order things happen in.  */
void
ql_handshake_started (gq_conn *c)
{
  if (c->ql.hs_started)
    return;
  c->ql.hs_started = 1;
  ql_state (c, "handshake_started", 0);
}

void
ql_peer_validated (gq_conn *c)
{
  if (c->ql.validated)
    return;
  c->ql.validated = 1;
  ql_state (c, "peer_validated", 1);
}

void
ql_closed (gq_conn *c, int source, int application, uint64_t error,
           const uint8_t *reason, size_t reason_len, const char *trigger)
{
  qkv *w;

  if (c->ql.closed)
    return;
  c->ql.closed = 1;
  if ((w = qlog_begin (c, QE_CONNECTION_CLOSED, NULL)) == NULL)
    return;
  qkv_str (w, "initiator",
           source == GQ_CLOSE_PEER || source == GQ_CLOSE_RESET ? "remote"
                                                              : "local");
  if (source == GQ_CLOSE_LOCAL || source == GQ_CLOSE_PEER)
    {
      if (application)
        qlog_error (w, "application_error", error, 1);
      else
        qlog_error (w, "connection_error", error, 0);
    }
  if (reason_len && qkv_utf8_ok (reason, reason_len))
    qkv_strn (w, "reason", (const char *) reason, reason_len);
  qkv_str (w, "trigger", trigger);
  qlog_end (c, QE_CONNECTION_CLOSED);
}

/* Report a change of the connection ID we send to (the peer's, "remote"), or
   the one the peer sends to (ours, "local").  Looked at after each call,
   which is when it can have changed.  */
void
ql_cid_check (gq_conn *c)
{
  qlog_conn *q = &c->ql;
  qkv *w;

  if (!QLOG_ON (c, QE_CONNECTION_ID_UPDATED))
    return;
  if (c->dcid_set
      && (!q->have_dcid || q->dcid_len != c->dcid.len
          || memcmp (q->dcid, c->dcid.data, c->dcid.len)))
    {
      if (q->have_dcid && (w = qlog_begin (c, QE_CONNECTION_ID_UPDATED, NULL)))
        {
          qkv_str (w, "initiator", "remote");
          qkv_hex (w, "old", q->dcid, q->dcid_len);
          qkv_hex (w, "new", c->dcid.data, c->dcid.len);
          qlog_end (c, QE_CONNECTION_ID_UPDATED);
        }
      q->have_dcid = 1;
      q->dcid_len = c->dcid.len;
      memcpy (q->dcid, c->dcid.data, c->dcid.len);
    }
}

/* The connection ID the peer addressed a packet to.  */
void
ql_rx_cid (gq_conn *c, const uint8_t *cid, size_t len)
{
  qlog_conn *q = &c->ql;
  qkv *w;

  if (!QLOG_ON (c, QE_CONNECTION_ID_UPDATED) || len > sizeof q->rx_dcid)
    return;
  if (q->have_rx_dcid && q->rx_dcid_len == len && !memcmp (q->rx_dcid, cid, len))
    return;
  if (q->have_rx_dcid && (w = qlog_begin (c, QE_CONNECTION_ID_UPDATED, NULL)))
    {
      qkv_str (w, "initiator", "local");
      qkv_hex (w, "old", q->rx_dcid, q->rx_dcid_len);
      qkv_hex (w, "new", cid, len);
      qlog_end (c, QE_CONNECTION_ID_UPDATED);
    }
  q->have_rx_dcid = 1;
  q->rx_dcid_len = (uint8_t) len;
  memcpy (q->rx_dcid, cid, len);
}

/* ---- Versions, ALPN, parameters ---- */

void
ql_version_information (gq_conn *c, const uint32_t *client, size_t nclient,
                        const uint32_t *server, size_t nserver,
                        uint32_t chosen)
{
  qkv *w;

  if ((w = qlog_begin (c, QE_VERSION_INFORMATION, NULL)) == NULL)
    return;
  if (nserver)
    versions_out (w, "server_versions", server, nserver);
  if (nclient)
    versions_out (w, "client_versions", client, nclient);
  if (chosen)
    version_out (w, "chosen_version", chosen);
  qlog_end (c, QE_VERSION_INFORMATION);
}

static void
alpns_out (qkv *w, const char *key, const gq_slice *a, size_t n)
{
  size_t i;

  for (i = 0; i < n; i++)
    {
      qkv_push_i (w, key, (unsigned) i);
      qkv_hex (w, "byte_value", a[i].data, a[i].len);
      if (qkv_utf8_ok (a[i].data, a[i].len))
        qkv_strn (w, "string_value", (const char *) a[i].data, a[i].len);
      qkv_pop (w);
    }
}

void
ql_alpn_information (gq_conn *c, const gq_slice *client, size_t nclient,
                     const gq_slice *server, size_t nserver,
                     const uint8_t *chosen, size_t chosen_len)
{
  qkv *w;

  if ((w = qlog_begin (c, QE_ALPN_INFORMATION, NULL)) == NULL)
    return;
  if (nserver)
    alpns_out (w, "server_alpns", server, nserver);
  if (nclient)
    alpns_out (w, "client_alpns", client, nclient);
  if (chosen)
    {
      qkv_push (w, "chosen_alpn");
      qkv_hex (w, "byte_value", chosen, chosen_len);
      if (qkv_utf8_ok (chosen, chosen_len))
        qkv_strn (w, "string_value", (const char *) chosen, chosen_len);
      qkv_pop (w);
    }
  qlog_end (c, QE_ALPN_INFORMATION);
}

/* The transport parameters TP carries (those on the wire, not defaults),
   under the draft's names.  */
static void
params_out (qkv *w, const gq_transport_params *tp, int secrets)
{
  if (gq_tp_has (tp, GQ_TP_ORIGINAL_DESTINATION_CONNECTION_ID))
    qkv_hex (w, "original_destination_connection_id",
             tp->original_destination_connection_id.data,
             tp->original_destination_connection_id.len);
  if (gq_tp_has (tp, GQ_TP_INITIAL_SOURCE_CONNECTION_ID))
    qkv_hex (w, "initial_source_connection_id",
             tp->initial_source_connection_id.data,
             tp->initial_source_connection_id.len);
  if (gq_tp_has (tp, GQ_TP_RETRY_SOURCE_CONNECTION_ID))
    qkv_hex (w, "retry_source_connection_id",
             tp->retry_source_connection_id.data,
             tp->retry_source_connection_id.len);
  if (secrets && gq_tp_has (tp, GQ_TP_STATELESS_RESET_TOKEN))
    qkv_hex (w, "stateless_reset_token", tp->stateless_reset_token,
             GQ_RESET_TOKEN_LEN);
  if (gq_tp_has (tp, GQ_TP_DISABLE_ACTIVE_MIGRATION))
    qkv_bool (w, "disable_active_migration", 1);
  if (gq_tp_has (tp, GQ_TP_MAX_IDLE_TIMEOUT))
    qkv_u64 (w, "max_idle_timeout", tp->max_idle_timeout);
  if (gq_tp_has (tp, GQ_TP_MAX_UDP_PAYLOAD_SIZE))
    qkv_u64 (w, "max_udp_payload_size", tp->max_udp_payload_size);
  if (gq_tp_has (tp, GQ_TP_ACK_DELAY_EXPONENT))
    qkv_u64 (w, "ack_delay_exponent", tp->ack_delay_exponent);
  if (gq_tp_has (tp, GQ_TP_MAX_ACK_DELAY))
    qkv_u64 (w, "max_ack_delay", tp->max_ack_delay);
  if (gq_tp_has (tp, GQ_TP_ACTIVE_CONNECTION_ID_LIMIT))
    qkv_u64 (w, "active_connection_id_limit", tp->active_connection_id_limit);
  if (gq_tp_has (tp, GQ_TP_INITIAL_MAX_DATA))
    qkv_u64 (w, "initial_max_data", tp->initial_max_data);
  if (gq_tp_has (tp, GQ_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL))
    qkv_u64 (w, "initial_max_stream_data_bidi_local",
             tp->initial_max_stream_data_bidi_local);
  if (gq_tp_has (tp, GQ_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE))
    qkv_u64 (w, "initial_max_stream_data_bidi_remote",
             tp->initial_max_stream_data_bidi_remote);
  if (gq_tp_has (tp, GQ_TP_INITIAL_MAX_STREAM_DATA_UNI))
    qkv_u64 (w, "initial_max_stream_data_uni",
             tp->initial_max_stream_data_uni);
  if (gq_tp_has (tp, GQ_TP_INITIAL_MAX_STREAMS_BIDI))
    qkv_u64 (w, "initial_max_streams_bidi", tp->initial_max_streams_bidi);
  if (gq_tp_has (tp, GQ_TP_INITIAL_MAX_STREAMS_UNI))
    qkv_u64 (w, "initial_max_streams_uni", tp->initial_max_streams_uni);
  if (gq_tp_has (tp, GQ_TP_PREFERRED_ADDRESS))
    {
      static const uint8_t zero16[16];
      const gq_preferred_address *pa = &tp->preferred_address;

      qkv_push (w, "preferred_address");
      if (memcmp (pa->ipv4, zero16, 4) || pa->ipv4_port)
        {
          qkv_hex (w, "ip_v4", pa->ipv4, 4);
          qkv_u64 (w, "port_v4", pa->ipv4_port);
        }
      if (memcmp (pa->ipv6, zero16, 16) || pa->ipv6_port)
        {
          qkv_hex (w, "ip_v6", pa->ipv6, 16);
          qkv_u64 (w, "port_v6", pa->ipv6_port);
        }
      qkv_hex (w, "connection_id", pa->cid.data, pa->cid.len);
      if (secrets)
        qkv_hex (w, "stateless_reset_token", pa->reset_token,
                 GQ_RESET_TOKEN_LEN);
      qkv_pop (w);
    }
  if (gq_tp_has (tp, GQ_TP_MAX_DATAGRAM_FRAME_SIZE))
    qkv_u64 (w, "max_datagram_frame_size", tp->max_datagram_frame_size);
}

typedef struct unknown_ctx
{
  qkv *w;
  unsigned n;
} unknown_ctx;

static int
unknown_param (void *user, uint64_t id, gq_slice value)
{
  unknown_ctx *u = user;

  if (id <= 0x11 || id == GQ_TP_MAX_DATAGRAM_FRAME_SIZE)
    return 0;
  qkv_push_i (u->w, "unknown_parameters", u->n++);
  qkv_u64 (u->w, "id", id);
  if (value.len)
    qkv_hex (u->w, "value", value.data, value.len);
  qkv_pop (u->w);
  return 0;
}

/* The parameters of one side: ours (REMOTE 0), or the peer's as it sent
   them.  */
void
ql_parameters_set (gq_conn *c, int remote, const gq_transport_params *tp)
{
  qkv *w;

  if ((w = qlog_begin (c, QE_PARAMETERS_SET, NULL)) == NULL)
    return;
  qkv_str (w, "initiator", remote ? "remote" : "local");
  params_out (w, tp, c->ql.raw_max > 0);
  if (remote && c->peer_tp_raw_len)
    {
      unknown_ctx u;

      u.w = w;
      u.n = 0;
      gq_tp_foreach (c->peer_tp_raw, c->peer_tp_raw_len, unknown_param, &u);
    }
  qlog_end (c, QE_PARAMETERS_SET);
}

static const char *
cipher_name (uint16_t suite)
{
  switch (suite)
    {
    case 0x1301: return "AES_128_GCM_SHA256";
    case 0x1302: return "AES_256_GCM_SHA384";
    case 0x1303: return "CHACHA20_POLY1305_SHA256";
    default: return NULL;
    }
}

/* What the handshake settled that is not a transport parameter.  */
void
ql_parameters_tls (gq_conn *c, const gq_tls_info *info)
{
  qkv *w;
  const char *cipher = cipher_name (info->cipher_suite);

  if ((w = qlog_begin (c, QE_PARAMETERS_SET, NULL)) == NULL)
    return;
  qkv_str (w, "initiator", "local");
  if (cipher)
    qkv_str (w, "tls_cipher", cipher);
  qkv_bool (w, "resumption_allowed", info->resumed);
  qkv_bool (w, "early_data_enabled", info->early_data_accepted);
  qlog_end (c, QE_PARAMETERS_SET);
}

/* 0-RTT: the server's parameters remembered from the earlier connection.  */
void
ql_parameters_restored (gq_conn *c, const gq_transport_params *tp)
{
  qkv *w;

  if ((w = qlog_begin (c, QE_PARAMETERS_RESTORED, NULL)) == NULL)
    return;
  if (gq_tp_has (tp, GQ_TP_DISABLE_ACTIVE_MIGRATION))
    qkv_bool (w, "disable_active_migration", 1);
  if (gq_tp_has (tp, GQ_TP_MAX_IDLE_TIMEOUT))
    qkv_u64 (w, "max_idle_timeout", tp->max_idle_timeout);
  if (gq_tp_has (tp, GQ_TP_MAX_UDP_PAYLOAD_SIZE))
    qkv_u64 (w, "max_udp_payload_size", tp->max_udp_payload_size);
  if (gq_tp_has (tp, GQ_TP_ACTIVE_CONNECTION_ID_LIMIT))
    qkv_u64 (w, "active_connection_id_limit", tp->active_connection_id_limit);
  if (gq_tp_has (tp, GQ_TP_INITIAL_MAX_DATA))
    qkv_u64 (w, "initial_max_data", tp->initial_max_data);
  if (gq_tp_has (tp, GQ_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL))
    qkv_u64 (w, "initial_max_stream_data_bidi_local",
             tp->initial_max_stream_data_bidi_local);
  if (gq_tp_has (tp, GQ_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE))
    qkv_u64 (w, "initial_max_stream_data_bidi_remote",
             tp->initial_max_stream_data_bidi_remote);
  if (gq_tp_has (tp, GQ_TP_INITIAL_MAX_STREAM_DATA_UNI))
    qkv_u64 (w, "initial_max_stream_data_uni",
             tp->initial_max_stream_data_uni);
  if (gq_tp_has (tp, GQ_TP_INITIAL_MAX_STREAMS_BIDI))
    qkv_u64 (w, "initial_max_streams_bidi", tp->initial_max_streams_bidi);
  if (gq_tp_has (tp, GQ_TP_INITIAL_MAX_STREAMS_UNI))
    qkv_u64 (w, "initial_max_streams_uni", tp->initial_max_streams_uni);
  if (gq_tp_has (tp, GQ_TP_MAX_DATAGRAM_FRAME_SIZE))
    qkv_u64 (w, "max_datagram_frame_size", tp->max_datagram_frame_size);
  qlog_end (c, QE_PARAMETERS_RESTORED);
}

/* ---- Keys ---- */

/* The draft's name for the secret that protects what ROLE sends at LEVEL.  */
static const char *
key_type (enum gq_role sender, enum gq_level level)
{
  int cl = sender == GQ_ROLE_CLIENT;

  switch (level)
    {
    case GQ_LEVEL_INITIAL:
      return cl ? "client_initial_secret" : "server_initial_secret";
    case GQ_LEVEL_EARLY:
      return cl ? "client_0rtt_secret" : "server_0rtt_secret";
    case GQ_LEVEL_HANDSHAKE:
      return cl ? "client_handshake_secret" : "server_handshake_secret";
    default:
      return cl ? "client_1rtt_secret" : "server_1rtt_secret";
    }
}

static enum gq_role
peer_role (enum gq_role r)
{
  return r == GQ_ROLE_CLIENT ? GQ_ROLE_SERVER : GQ_ROLE_CLIENT;
}

/* Keys for LEVEL in direction DIR came into use.  Never the key itself.  */
void
ql_key_updated (gq_conn *c, enum gq_level level, enum gq_dir dir,
                const char *trigger)
{
  qkv *w;
  enum gq_role sender = dir == GQ_DIR_WRITE ? c->role : peer_role (c->role);

  if ((w = qlog_begin (c, QE_KEY_UPDATED, NULL)) == NULL)
    return;
  qkv_str (w, "key_type", key_type (sender, level));
  if (level == GQ_LEVEL_APPLICATION)
    qkv_u64 (w, "key_phase",
             dir == GQ_DIR_WRITE ? c->ql.w_phase : c->ql.r_phase);
  qkv_str (w, "trigger", trigger);
  qlog_end (c, QE_KEY_UPDATED);
}

void
ql_key_discarded (gq_conn *c, enum gq_level level, enum gq_dir dir,
                  int have_phase, unsigned phase, const char *trigger)
{
  qkv *w;
  enum gq_role sender = dir == GQ_DIR_WRITE ? c->role : peer_role (c->role);

  if ((w = qlog_begin (c, QE_KEY_DISCARDED, NULL)) == NULL)
    return;
  qkv_str (w, "key_type", key_type (sender, level));
  if (have_phase)
    qkv_u64 (w, "key_phase", phase);
  if (trigger)
    qkv_str (w, "trigger", trigger);
  qlog_end (c, QE_KEY_DISCARDED);
}

/* ---- Recovery ---- */

void
ql_recovery_parameters (gq_conn *c)
{
  qkv *w;

  if ((w = qlog_begin (c, QE_RECOVERY_PARAMETERS_SET, NULL)) == NULL)
    return;
  qkv_u64 (w, "reordering_threshold", K_PACKET_THRESHOLD);
  qkv_milli (w, "time_threshold", 1125);
  qkv_u64 (w, "timer_granularity", K_GRANULARITY / 1000);
  qkv_ms (w, "initial_rtt", CONN_INITIAL_RTT (c));
  qkv_u64 (w, "max_datagram_size", conn_max_datagram (c));
  qkv_u64 (w, "initial_congestion_window", c->cc.cwnd);
  qkv_u64 (w, "minimum_congestion_window", 2 * (uint64_t) c->cc.mss);
  qkv_milli (w, "loss_reduction_factor",
             c->cc.algo == GQ_CC_CUBIC ? 700 : 500);
  qkv_u64 (w, "persistent_congestion_threshold",
           K_PERSISTENT_CONGESTION_THRESHOLD);
  qlog_end (c, QE_RECOVERY_PARAMETERS_SET);
}

/* ---- Packets and datagrams ---- */

/* Append FRAME to the frames kept for a packet (BUF, CAP, *LEN, numbered
   from *N): as fields, frames.N.*.  A frame that does not fit is left out of
   the log; nothing else is affected.  */
void
ql_frames_add (char *buf, size_t cap, size_t *len, unsigned *n,
               const gq_frame *f, unsigned ack_delay_exp, size_t raw_max)
{
  qkv w;
  size_t sep = *len ? 1 : 0;

  if (cap - *len < sep + 32)
    return;
  qkv_init (&w, buf + *len + sep, cap - *len - sep);
  qkv_push_i (&w, "frames", *n);
  qlog_frame (&w, f, ack_delay_exp, raw_max);
  qkv_pop (&w);
  if (w.err)
    return;
  if (sep)
    buf[*len] = ' ';
  *len += sep + w.len;
  (*n)++;
}

/* A PADDING frame of N bytes, which the draft has as one frame.  */
void
ql_frames_add_padding (char *buf, size_t cap, size_t *len, unsigned *n,
                       size_t pad)
{
  gq_frame f;

  if (pad == 0)
    return;
  memset (&f, 0, sizeof f);
  f.type = GQ_FRAME_PADDING;
  f.u.padding.len = pad;
  ql_frames_add (buf, cap, len, n, &f, 0, 0);
}

typedef struct rx_frames
{
  gq_conn *c;
  size_t len;
  unsigned n;
} rx_frames;

static int
rx_frame_cb (void *user, const gq_frame *f)
{
  rx_frames *x = user;

  ql_frames_add (x->c->ql.rx_frames, x->c->ql.frames_cap, &x->len, &x->n, f,
                 x->c->peer_ack_delay_exp, x->c->ql.raw_max);
  return 0;
}

/* The fields every packet event has after its header: sizes, and the id of
   the datagram it came in or went out in.  */
static void
packet_tail (qkv *w, size_t raw_len, size_t payload_len, uint32_t dgram_id)
{
  qkv_push (w, "raw");
  qkv_u64 (w, "length", raw_len);
  qkv_u64 (w, "payload_length", payload_len);
  qkv_pop (w);
  qkv_u64 (w, "datagram_id", dgram_id);
}

/* The name the draft gives ECN codepoint ECN.  */
static const char *
ecn_name (int ecn)
{
  return ecn == GQ_ECN_ECT0 ? "ECT(0)" : ecn == GQ_ECN_ECT1 ? "ECT(1)"
         : ecn == GQ_ECN_CE ? "CE" : "Not-ECT";
}

/* A datagram of LEN bytes, with the ECN codepoint ECN, or -1 if that is not
   known (the application did not say).  */
void
ql_datagram (gq_conn *c, int ev, uint32_t id, size_t len, int ecn)
{
  qkv *w;

  if ((w = qlog_begin (c, ev, NULL)) == NULL)
    return;
  qkv_u64 (w, "count", 1);
  qkv_push_i (w, "raw", 0);
  qkv_u64 (w, "length", len);
  qkv_pop (w);
  if (ecn >= 0)
    {
      qkv_list (w, "ecn");
      qkv_item_str (w, ecn_name (ecn));
      qkv_end_list (w);
    }
  qkv_list (w, "datagram_ids");
  qkv_item_u64 (w, id);
  qkv_end_list (w);
  qlog_end (c, ev);
}

/* A datagram came in: the next id, and the event.  */
void
ql_rx_datagram (gq_conn *c, size_t len)
{
  c->ql.dgram_id = c->ql.next_dgram_id++;
  if (!c->ql.started)
    {
      /* A server's first datagram: reported once the connection is.  */
      c->ql.pending_dgram = 1;
      c->ql.pending_len = len;
      c->ql.pending_ecn = c->rx_ecn;
      return;
    }
  ql_datagram (c, QE_UDP_DATAGRAMS_RECEIVED, c->ql.dgram_id, len, c->rx_ecn);
}

void
ql_datagram_dropped (gq_conn *c, size_t len)
{
  qkv *w;

  if ((w = qlog_begin (c, QE_UDP_DATAGRAM_DROPPED, NULL)) == NULL)
    return;
  qkv_push (w, "raw");
  qkv_u64 (w, "length", len);
  qkv_pop (w);
  qlog_end (c, QE_UDP_DATAGRAM_DROPPED);
}

/* A packet was sent.  FRAMES are those kept while it was built.  */
void
ql_packet_sent (gq_conn *c, const qlog_hdr *h, size_t raw_len,
                size_t payload_len, const char *frames, size_t frames_len,
                uint32_t dgram_id, const char *trigger, int path_idx,
                int mtu_probe)
{
  qkv *w;

  if ((w = qlog_begin (c, QE_PACKET_SENT, ql_tuple (c, path_idx))) == NULL)
    return;
  qlog_header (w, h, c->ql.raw_max);
  qkv_append (w, frames, frames_len);
  packet_tail (w, raw_len, payload_len, dgram_id);
  if (mtu_probe)
    qkv_bool (w, "is_mtu_probe_packet", 1);
  if (trigger)
    qkv_str (w, "trigger", trigger);
  qlog_end (c, QE_PACKET_SENT);
}

/* A packet was received and opened.  PAYLOAD (PAYLOAD_LEN bytes) holds its
   frames, which are read here once more for the log, before they are acted
   on, so that the events that follow come after the packet's.  VN: the
   versions of a Version Negotiation packet (N_VN of them); RESET_TOKEN: a
   stateless reset's.  */
void
ql_packet_received (gq_conn *c, const qlog_hdr *h, size_t raw_len,
                    const uint8_t *payload, size_t payload_len, int path_idx,
                    const uint32_t *vn, size_t n_vn,
                    const uint8_t *reset_token)
{
  qkv *w;
  rx_frames x;

  if (!QLOG_ON (c, QE_PACKET_RECEIVED) || c->ql.busy)
    return;
  x.c = c;
  x.len = 0;
  x.n = 0;
  if (payload && payload_len)
    {
      const uint8_t *p = payload;
      size_t n = payload_len;

      gq_frame_parse (&p, &n, rx_frame_cb, &x);
    }
  if ((w = qlog_begin (c, QE_PACKET_RECEIVED, ql_tuple (c, path_idx))) == NULL)
    return;
  qlog_header (w, h, c->ql.raw_max);
  qkv_append (w, c->ql.rx_frames, x.len);
  if (reset_token && c->ql.raw_max > 0)
    qkv_hex (w, "stateless_reset_token", reset_token, GQ_RESET_TOKEN_LEN);
  if (vn)
    versions_out (w, "supported_versions", vn, n_vn);
  packet_tail (w, raw_len, payload_len, c->ql.dgram_id);
  if (c->ql.rx_trigger)
    qkv_str (w, "trigger", c->ql.rx_trigger);
  qlog_end (c, QE_PACKET_RECEIVED);
}

/* A packet was dropped.  H, if there is one, has whatever of the header could
   be read.  */
void
ql_packet_dropped (gq_conn *c, const qlog_hdr *h, size_t raw_len,
                   const char *trigger)
{
  qkv *w;

  if ((w = qlog_begin (c, QE_PACKET_DROPPED, NULL)) == NULL)
    return;
  if (h)
    qlog_header (w, h, 0);
  qkv_push (w, "raw");
  qkv_u64 (w, "length", raw_len);
  qkv_pop (w);
  qkv_u64 (w, "datagram_id", c->ql.dgram_id);
  qkv_str (w, "trigger", trigger);
  qlog_end (c, QE_PACKET_DROPPED);
}

/* ---- Loss and recovery ---- */

static const char *
space_name (int sp)
{
  return sp == SP_INITIAL ? "initial" : sp == SP_HANDSHAKE ? "handshake"
         : "application_data";
}

/* An ACK frame acknowledged GOT (N packets) for the first time.  */
void
ql_packets_acked (gq_conn *c, int sp, const sent_pkt *got, size_t n)
{
  qkv *w;
  size_t i;

  if (n == 0 || (w = qlog_begin (c, QE_PACKETS_ACKED, NULL)) == NULL)
    return;
  qkv_str (w, "packet_number_space", space_name (sp));
  qkv_list (w, "packet_numbers");
  for (i = 0; i < n; i++)
    qkv_item_u64 (w, got[i].pn);
  qkv_end_list (w);
  qlog_end (c, QE_PACKETS_ACKED);
}

/* P was declared lost: by the packet threshold (REORDERING) or the time
   threshold.  What it carried is listed as far as it was kept.  */
void
ql_packet_lost (gq_conn *c, int sp, const sent_pkt *p, int reordering)
{
  qkv *w;
  uint32_t i;
  unsigned n = 0;

  if ((w = qlog_begin (c, QE_PACKET_LOST, NULL)) == NULL)
    return;
  qkv_push (w, "header");
  qkv_str (w, "packet_type", qlog_packet_type_name (sp, p->early));
  qkv_u64 (w, "packet_number", p->pn);
  qkv_pop (w);
  for (i = 0; i < p->nframes; i++)
    {
      qkv_push_i (w, "frames", n);
      if (qlog_sent_frame (w, &p->frames[i]))
        n++;
      qkv_pop (w);
    }
  if (p->pmtu_probe)
    qkv_bool (w, "is_mtu_probe_packet", 1);
  qkv_str (w, "trigger", reordering ? "reordering_threshold" : "time_threshold");
  qlog_end (c, QE_PACKET_LOST);
}

/* What P carried goes back on the queues to be sent again.  */
void
ql_marked_for_retransmit (gq_conn *c, const sent_pkt *p)
{
  qkv *w;
  uint32_t i;
  unsigned n = 0;

  if (!QLOG_ON (c, QE_MARKED_FOR_RETRANSMIT) || p->nframes == 0)
    return;
  if ((w = qlog_begin (c, QE_MARKED_FOR_RETRANSMIT, NULL)) == NULL)
    return;
  for (i = 0; i < p->nframes; i++)
    {
      qkv_push_i (w, "frames", n);
      if (qlog_sent_frame (w, &p->frames[i]))
        n++;
      qkv_pop (w);
    }
  if (n)
    qlog_end (c, QE_MARKED_FOR_RETRANSMIT);
  else
    c->ql.busy = 0;		/* Nothing to say: no event.  */
}

/* The recovery metrics that changed since they were last reported.  */
void
ql_metrics (gq_conn *c)
{
  qlog_conn *q = &c->ql;
  qkv *w;
  uint64_t packets = 0, pacing = (uint64_t) (conn_pacing_rate (c) * 8e6);
  int i, fields = 0, first = !q->met.valid;
  int have_rtt = c->have_rtt, have_ss = c->cc.ssthresh != UINT64_MAX;

  if (!QLOG_ON (c, QE_RECOVERY_METRICS_UPDATED))
    return;
  for (i = 0; i < N_SPACES; i++)
    if (!c->sp[i].discarded)
      packets += c->sp[i].ae_in_flight;
  if ((w = qlog_begin (c, QE_RECOVERY_METRICS_UPDATED, NULL)) == NULL)
    return;
  if (have_rtt && (first || !q->met.have_rtt || q->met.min_rtt != c->min_rtt))
    {
      qkv_ms (w, "min_rtt", c->min_rtt);
      fields++;
    }
  if (have_rtt && (first || !q->met.have_rtt || q->met.srtt != c->srtt))
    {
      qkv_ms (w, "smoothed_rtt", c->srtt);
      fields++;
    }
  if (have_rtt && (first || !q->met.have_rtt || q->met.latest != c->latest_rtt))
    {
      qkv_ms (w, "latest_rtt", c->latest_rtt);
      fields++;
    }
  if (have_rtt && (first || !q->met.have_rtt || q->met.rttvar != c->rttvar))
    {
      qkv_ms (w, "rtt_variance", c->rttvar);
      fields++;
    }
  if (first || q->met.pto != c->pto_count)
    {
      qkv_u64 (w, "pto_count", c->pto_count);
      fields++;
    }
  if (first || q->met.cwnd != c->cc.cwnd)
    {
      qkv_u64 (w, "congestion_window", c->cc.cwnd);
      fields++;
    }
  if (first || q->met.inflight != c->bytes_in_flight)
    {
      qkv_u64 (w, "bytes_in_flight", c->bytes_in_flight);
      fields++;
    }
  if (have_ss && (first || !q->met.have_ssthresh
                  || q->met.ssthresh != c->cc.ssthresh))
    {
      qkv_u64 (w, "ssthresh", c->cc.ssthresh);
      fields++;
    }
  if (first || q->met.packets != packets)
    {
      qkv_u64 (w, "packets_in_flight", packets);
      fields++;
    }
  if (pacing && q->met.pacing != pacing)
    {
      qkv_u64 (w, "pacing_rate", pacing);
      fields++;
    }
  q->met.valid = 1;
  q->met.have_rtt = (uint8_t) have_rtt;
  q->met.have_ssthresh = (uint8_t) have_ss;
  q->met.min_rtt = c->min_rtt;
  q->met.srtt = c->srtt;
  q->met.latest = c->latest_rtt;
  q->met.rttvar = c->rttvar;
  q->met.pto = c->pto_count;
  q->met.cwnd = c->cc.cwnd;
  q->met.inflight = c->bytes_in_flight;
  q->met.ssthresh = c->cc.ssthresh;
  q->met.packets = packets;
  q->met.pacing = pacing;
  if (fields)
    qlog_end (c, QE_RECOVERY_METRICS_UPDATED);
  else
    q->busy = 0;
}

/* The state the congestion controller is in, by the names of RFC 9002
   section 7.3, with HyStart++'s slower slow start as a state of its own
   (the draft leaves the names to the implementation).  */
static const char *
cc_state_name (const gq_conn *c)
{
  if (c->cc.in_recovery)
    return "recovery";
  if (c->cc.cwnd < c->cc.ssthresh)
    return c->cc.hs_css ? "conservative_slow_start" : "slow_start";
  return "congestion_avoidance";
}

void
ql_cc_state (gq_conn *c, const char *trigger)
{
  qkv *w;
  const char *now = cc_state_name (c), *old = c->ql.cc_state;

  if (!QLOG_ON (c, QE_CONGESTION_STATE_UPDATED))
    return;
  if (old && !strcmp (old, now))
    return;
  if (trigger == NULL && old)
    {
      if (!strcmp (old, "recovery"))
        trigger = "recovery_exit";
      else if (!strcmp (now, "conservative_slow_start"))
        trigger = "rtt_increase";
      else if (!strcmp (now, "congestion_avoidance"))
        trigger = "ssthresh_reached";
    }
  if ((w = qlog_begin (c, QE_CONGESTION_STATE_UPDATED, NULL)) == NULL)
    return;
  if (old)
    qkv_str (w, "old", old);
  qkv_str (w, "new", now);
  if (trigger)
    qkv_str (w, "trigger", trigger);
  c->ql.cc_state = now;
  qlog_end (c, QE_CONGESTION_STATE_UPDATED);
}

/* ---- Timers ---- */

enum { TM_ACK, TM_LOSS, TM_IDLE, TM_PATH, TM_PACING, TM_N };

static const char *const timer_names[TM_N] = {
  "ack", "loss_timeout", "idle_timeout", "path_validation", "pacing"
};

static uint64_t
timer_deadline (const gq_conn *c, int t)
{
  uint64_t d = 0;
  int i;

  switch (t)
    {
    case TM_ACK:
      for (i = 0; i < N_SPACES; i++)
        if (!c->sp[i].discarded && c->sp[i].ack_deadline
            && (d == 0 || c->sp[i].ack_deadline < d))
          d = c->sp[i].ack_deadline;
      return d;
    case TM_LOSS:
      return conn_loss_deadline (c);
    case TM_IDLE:
      return c->idle_deadline;
    case TM_PATH:
      return conn_path_deadline (c);
    default:
      return c->pace_deadline;
    }
}

static void
timer_event (gq_conn *c, int t, const char *kind, uint64_t delta_us)
{
  qkv *w;

  if ((w = qlog_begin (c, QE_TIMER_UPDATED, NULL)) == NULL)
    return;
  qkv_str (w, "timer_type", timer_names[t]);
  qkv_str (w, "event_type", kind);
  if (!strcmp (kind, "set"))
    qkv_ms (w, "delta", delta_us);
  qlog_end (c, QE_TIMER_UPDATED);
}

/* Report the timers that were set, moved or cancelled since last time.  The
   idle timer is pushed back by every packet, which would be most of the log:
   it is reported when it is armed, cancelled or expires.  */
void
ql_timers (gq_conn *c)
{
  int t;

  if (!QLOG_ON (c, QE_TIMER_UPDATED) || !c->ql.started)
    return;
  for (t = 0; t < TM_N; t++)
    {
      uint64_t d = timer_deadline (c, t), old = c->ql.timer[t];

      if (c->state >= GQ_CONN_CLOSING && t != TM_IDLE)
        d = 0;
      if (d == old)
        continue;
      if (t == TM_IDLE && d && old)
        {
          c->ql.timer[t] = d;
          continue;
        }
      c->ql.timer[t] = d;
      if (d)
        timer_event (c, t, "set", d > c->now ? d - c->now : 0);
      else
        timer_event (c, t, "cancelled", 0);
    }
}

/* Called as the timers are serviced: those that are due have expired.  */
void
ql_timers_expired (gq_conn *c, uint64_t now)
{
  int t;

  if (!QLOG_ON (c, QE_TIMER_UPDATED))
    return;
  for (t = 0; t < TM_N; t++)
    if (c->ql.timer[t] && now >= c->ql.timer[t])
      {
        c->ql.timer[t] = 0;
        timer_event (c, t, "expired", 0);
      }
}

/* Everything that is reported as a change, after a call into the
   connection: the IDs in use, the congestion state, the recovery metrics
   and the timers.  */
void
ql_after (gq_conn *c)
{
  if (c->ql.fn == NULL)
    return;
  ql_cid_check (c);
  ql_cc_state (c, NULL);
  ql_metrics (c);
  ql_timers (c);
}

/* ---- Streams and datagrams ---- */

/* The states of a stream's halves by the draft's names: the detailed ones
   (RFC 9000 sections 3.1 and 3.2) when the importance asks for the most,
   and else the simple ones, open and closed.  */
static const char *
send_state_name (const gq_conn *c, enum gq_send_state s)
{
  static const char *const detailed[] = { "ready", "send", "data_sent",
                                          "data_received", "reset_sent",
                                          "reset_received" };

  if (c->ql.level >= GQ_QLOG_EXTRA)
    return detailed[s];
  return s == GQ_SS_DATA_RECVD || s == GQ_SS_RESET_RECVD ? "closed" : "open";
}

static const char *
recv_state_name (const gq_conn *c, enum gq_recv_state s)
{
  static const char *const detailed[] = { "receive", "size_known", "data_read",
                                          "reset_received" };

  if (c->ql.level >= GQ_QLOG_EXTRA)
    return detailed[s];
  return s == GQ_RS_DATA_READ || s == GQ_RS_RESET_RECVD ? "closed" : "open";
}

static void
side_state (gq_conn *c, stream *st, int sending, const char *now,
            const char *trigger)
{
  const char **last = sending ? &st->ql_send : &st->ql_recv;
  qkv *w;

  if (*last && !strcmp (*last, now))
    return;
  if ((w = qlog_begin (c, QE_STREAM_STATE_UPDATED, NULL)) == NULL)
    return;
  qkv_u64 (w, "stream_id", st->id);
  qkv_str (w, "stream_type", (st->id & 2) ? "unidirectional" : "bidirectional");
  if (*last)
    qkv_str (w, "old", *last);
  qkv_str (w, "new", now);
  qkv_str (w, "stream_side", sending ? "sending" : "receiving");
  if (trigger)
    qkv_str (w, "trigger", trigger);
  *last = now;
  qlog_end (c, QE_STREAM_STATE_UPDATED);
}

/* Report the halves of ST that changed state since last time.  TRIGGER:
   "local" if we caused it, "remote" if the peer did, or NULL if not known.  */
void
ql_stream_states (gq_conn *c, stream *st, const char *trigger)
{
  if (!QLOG_ON (c, QE_STREAM_STATE_UPDATED) || !c->ql.started)
    return;
  if (st->has_send)
    side_state (c, st, 1, send_state_name (c, gq_sstream_state (&st->s)),
                trigger);
  if (st->has_recv)
    side_state (c, st, 0, recv_state_name (c, gq_rstream_state (&st->r)),
                trigger);
}

/* Stream data moved between layers.  INFO: fin_set or stream_reset.  */
void
ql_stream_moved (gq_conn *c, uint64_t id, int have_off, uint64_t off,
                 const char *from, const char *to, size_t len,
                 const char *info)
{
  qkv *w;

  if ((w = qlog_begin (c, QE_STREAM_DATA_MOVED, NULL)) == NULL)
    return;
  qkv_u64 (w, "stream_id", id);
  if (have_off)
    qkv_u64 (w, "offset", off);
  qkv_str (w, "from", from);
  qkv_str (w, "to", to);
  if (info)
    qkv_str (w, "additional_info", info);
  if (len)
    {
      qkv_push (w, "raw");
      qkv_u64 (w, "length", len);
      qkv_pop (w);
    }
  qlog_end (c, QE_STREAM_DATA_MOVED);
}

void
ql_datagram_moved (gq_conn *c, const char *from, const char *to, size_t len)
{
  qkv *w;

  if ((w = qlog_begin (c, QE_DATAGRAM_DATA_MOVED, NULL)) == NULL)
    return;
  qkv_str (w, "from", from);
  qkv_str (w, "to", to);
  qkv_push (w, "raw");
  qkv_u64 (w, "length", len);
  qkv_pop (w);
  qlog_end (c, QE_DATAGRAM_DATA_MOVED);
}

/* ---- Blocked ---- */

static void
blocked_event (gq_conn *c, int ev, const char **last, const char *reason,
               int have_stream, uint64_t stream_id)
{
  qkv *w;

  if (*last == reason || (*last && reason && !strcmp (*last, reason)))
    return;
  if ((w = qlog_begin (c, ev, NULL)) == NULL)
    return;
  qkv_str (w, "old", *last ? "blocked" : "unblocked");
  qkv_str (w, "new", reason ? "blocked" : "unblocked");
  if (have_stream)
    qkv_u64 (w, "stream_id", stream_id);
  if (reason)
    qkv_str (w, "reason", reason);
  *last = reason;
  qlog_end (c, ev);
}

/* Whether the connection (stream and datagram data) is held back from
   sending, and why: REASON is the draft's name for it, or NULL if it is
   not.  */
void
ql_blocked (gq_conn *c, const char *conn_reason, const char *dgram_reason)
{
  if (!c->ql.started)
    return;
  blocked_event (c, QE_CONNECTION_DATA_BLOCKED_UPDATED, &c->ql.conn_blocked,
                 conn_reason, 0, 0);
  blocked_event (c, QE_DATAGRAM_DATA_BLOCKED_UPDATED, &c->ql.dgram_blocked,
                 dgram_reason, 0, 0);
}

/* A stream is held back by its own flow control credit, or no longer.  */
void
ql_stream_blocked (gq_conn *c, stream *st, int blocked)
{
  const char *last = st->ql_blocked ? "stream_flow_control" : NULL;
  const char *now = blocked ? "stream_flow_control" : NULL;

  if (!c->ql.started)
    return;
  blocked_event (c, QE_STREAM_DATA_BLOCKED_UPDATED, &last, now, 1, st->id);
  st->ql_blocked = (uint8_t) (last != NULL);
}

/* ---- Paths ---- */

typedef char paths_fit[MAX_PATHS <= 4 ? 1 : -1];

/* Path slot IDX is a tuple of its own (the first is the default, ""), with
   the addresses it has; or, ABANDONED, it is no more.  */
void
ql_tuple_assigned (gq_conn *c, int idx, int abandoned)
{
  qkv *w;
  const pathinfo *e = &c->paths[idx];
  const char *id = ql_tuple (c, idx);

  if (idx == 0 && !abandoned)
    return;
  if ((w = qlog_begin (c, QE_TUPLE_ASSIGNED, NULL)) == NULL)
    return;
  qkv_str (w, "tuple_id", id ? id : "");
  if (!abandoned)
    {
      endpoint_out (c, w, "tuple_remote", &e->p.remote,
                    e->dcid.len ? &e->dcid : NULL);
      endpoint_out (c, w, "tuple_local", &e->p.local, NULL);
    }
  qlog_end (c, QE_TUPLE_ASSIGNED);
}

/* A packet that cannot be read yet is held (RFC 9001 section 5.7).  */
void
ql_packet_buffered (gq_conn *c, const qlog_hdr *h, size_t raw_len)
{
  qkv *w;

  if ((w = qlog_begin (c, QE_PACKET_BUFFERED, NULL)) == NULL)
    return;
  qlog_header (w, h, 0);
  qkv_push (w, "raw");
  qkv_u64 (w, "length", raw_len);
  qkv_pop (w);
  qkv_u64 (w, "datagram_id", c->ql.dgram_id);
  qkv_str (w, "trigger", "keys_unavailable");
  qlog_end (c, QE_PACKET_BUFFERED);
}

/* The datagram size changed from OLD (0: not given) to NEW, or, with DONE,
   the search for the path MTU ended at NEW.  */
void
ql_mtu_updated (gq_conn *c, size_t old, size_t new, int done)
{
  qkv *w;

  if ((w = qlog_begin (c, QE_MTU_UPDATED, NULL)) == NULL)
    return;
  if (old)
    qkv_u64 (w, "old", old);
  qkv_u64 (w, "new", new);
  qkv_bool (w, "done", done);
  qlog_end (c, QE_MTU_UPDATED);
}

/* ECN validation went from state OLD (a gq_ecn_state) to STATE.  */
void
ql_ecn_state_updated (gq_conn *c, int old, int state)
{
  static const char *const name[] = { NULL, "testing", "unknown", "capable",
                                      "failed" };
  qkv *w;

  if ((w = qlog_begin (c, QE_ECN_STATE_UPDATED, NULL)) == NULL)
    return;
  if (old != GQ_ECN_OFF)
    qkv_str (w, "old", name[old]);
  qkv_str (w, "new", name[state]);
  qlog_end (c, QE_ECN_STATE_UPDATED);
}

/* The spin bit we send changed to STATE.  */
void
ql_spin_bit_updated (gq_conn *c, int state)
{
  qkv *w;

  if ((w = qlog_begin (c, QE_SPIN_BIT_UPDATED, NULL)) == NULL)
    return;
  qkv_bool (w, "state", state);
  qlog_end (c, QE_SPIN_BIT_UPDATED);
}

/* A step in a migration, or the probing before one, on path slot IDX.  */
void
ql_migration (gq_conn *c, const char *state, int idx)
{
  qkv *w;
  const pathinfo *e = &c->paths[idx];
  const char *id = ql_tuple (c, idx), *old = c->ql.mig[idx];

  if (old && !strcmp (old, state))
    return;
  if ((w = qlog_begin (c, QE_MIGRATION_STATE_UPDATED, NULL)) == NULL)
    return;
  if (old)
    qkv_str (w, "old", old);
  qkv_str (w, "new", state);
  qkv_str (w, "tuple_id", id ? id : "");
  endpoint_out (c, w, "tuple_remote", &e->p.remote,
                e->dcid.len ? &e->dcid : NULL);
  endpoint_out (c, w, "tuple_local", &e->p.local, NULL);
  c->ql.mig[idx] = state;
  qlog_end (c, QE_MIGRATION_STATE_UPDATED);
}
