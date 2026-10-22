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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "conn_int.h"

#define DEFAULT_IDLE_MS 30000
#define DEFAULT_MAX_DATA (1u << 20)
#define DEFAULT_STREAM_DATA (256u << 10)
#define DEFAULT_STREAMS 100
#define CRYPTO_BUFFER (1u << 17)

static void encode_params (gq_conn *c);

static uint64_t
umax (uint64_t a, uint64_t b)
{
  return a > b ? a : b;
}

/* The size of the datagrams being sent: 1200 until path MTU discovery finds
   that the path takes more, within what the peer receives.  */
size_t
conn_max_datagram (const gq_conn *c)
{
  size_t m = c->pmtu_cur;

  if (c->have_peer_tp && c->peer_tp.max_udp_payload_size < m)
    m = (size_t) c->peer_tp.max_udp_payload_size;
  return m;
}

/* ---- Timing helpers ---- */

uint64_t
conn_pto_base (const gq_conn *c, int sp)
{
  uint64_t v = 4 * c->rttvar;

  if (v < K_GRANULARITY)
    v = K_GRANULARITY;
  v += c->srtt;
  if (sp == SP_APP)
    v += c->peer_max_ack_delay_us;
  return v;
}

void
conn_recompute_idle (gq_conn *c, uint64_t now)
{
  uint64_t t = c->idle_timeout_us;

  if (t == 0)
    {
      c->idle_deadline = 0;
      return;
    }
  /* At least three probe timeouts, so a lossy path does not kill us.  */
  t = umax (t, 3 * conn_pto_base (c, SP_APP));
  c->idle_deadline = now + t;
}

/* ---- Connection IDs ---- */

uint64_t
conn_wall_seconds (const gq_conn *c)
{
  if (c->cfg.wall_seconds)
    return c->cfg.wall_seconds (c->cfg.wall_user);
  return (uint64_t) time (NULL);
}

static int
new_lcid (gq_conn *c, int announced, const gq_cid *fixed)
{
  size_t i;
  lcid *l = NULL;

  for (i = 0; i < MAX_LCID; i++)
    if (!c->l[i].used)
      {
        l = &c->l[i];
        break;
      }
  if (l == NULL)
    return GQ_ERR_RANGE;
  memset (l, 0, sizeof *l);
  l->used = 1;
  l->seq = c->next_lseq++;
  l->cid.len = (uint8_t) c->cfg.cid_len;
  if (fixed)
    l->cid = *fixed;
  if ((!fixed && (c->cfg.cid_gen
                  ? c->cfg.cid_gen (c->cfg.cid_gen_user, l->cid.data,
                                    l->cid.len)
                  : gq_random (l->cid.data, l->cid.len)) != GQ_OK)
      || (!c->cfg.reset_token
          && gq_random (l->token, sizeof l->token) != GQ_OK))
    {
      l->used = 0;
      return GQ_ERR_CRYPTO;
    }
  if (c->cfg.reset_token)
    c->cfg.reset_token (c->cfg.reset_user, l->cid.data, l->cid.len, l->token);
  l->announced = (uint8_t) announced;
  l->need_send = !announced;
  if (c->ev.cid_issued)
    c->ev.cid_issued (c->ev.user, l->cid.data, l->cid.len, l->token);
  if (c->router.cid_issued)
    c->router.cid_issued (c->router.user, c, l->cid.data, l->cid.len);
  return GQ_OK;
}

int
conn_new_lcid (gq_conn *c, int announced)
{
  return new_lcid (c, announced, NULL);
}

void
conn_wake (gq_conn *c)
{
  if (c->router.wake)
    c->router.wake (c->router.user, c);
}

void
conn_peer_token (gq_conn *c, const uint8_t *token)
{
  if (c->router.peer_token)
    c->router.peer_token (c->router.user, c, token);
}

void
gq_conn_stateless_reset (gq_conn *c, uint64_t now_us)
{
  gq_conn_close_info info;

  c->now = now_us;
  memset (&info, 0, sizeof info);
  info.source = GQ_CLOSE_RESET;
  conn_enter_closing (c, &info, 1);
}

void
conn_cid_retired (gq_conn *c, const gq_cid *cid)
{
  if (c->ev.cid_retired)
    c->ev.cid_retired (c->ev.user, cid->data, cid->len);
  if (c->router.cid_retired)
    c->router.cid_retired (c->router.user, c, cid->data, cid->len);
}

void
gq_conn_set_router (gq_conn *c, const gq_conn_router *router)
{
  if (router)
    c->router = *router;
  else
    memset (&c->router, 0, sizeof c->router);
}

size_t
gq_conn_local_cids (const gq_conn *c, gq_cid *out, size_t max)
{
  size_t i, n = 0;

  for (i = 0; i < MAX_LCID && n < max; i++)
    if (c->l[i].used)
      out[n++] = c->l[i].cid;
  return n;
}

/* ---- Failure and closing ---- */

void
conn_enter_closing (gq_conn *c, gq_conn_close_info *info, int draining)
{
  uint64_t pto = 3 * conn_pto_base (c, SP_APP);

  if (c->state >= GQ_CONN_CLOSING)
    return;
  c->state = draining ? GQ_CONN_DRAINING : GQ_CONN_CLOSING;
  c->close_deadline = c->now + pto;
  {
    const char *trigger;

    if (info->source == GQ_CLOSE_RESET)
      trigger = "stateless_reset";
    else if (info->source == GQ_CLOSE_LOCAL)
      trigger = info->application ? "application"
                : info->error == GQ_QERR_VERSION_NEGOTIATION
                  ? "version_mismatch" : "error";
    else
      trigger = "unspecified";
    ql_closed (c, info->source, info->application, info->error, info->reason,
               info->reason_len, trigger);
    /* The base state, "closed", is entered when the CONNECTION_CLOSE is
       sent or seen; the detailed ones keep it for the end of the period.  */
    if (c->ql.level >= GQ_QLOG_EXTRA)
      ql_state (c, draining ? "draining" : "closing", 1);
    else
      ql_state (c, "closed", 0);
  }
  if (!c->closed_notified)
    {
      c->closed_notified = 1;
      if (c->ev.closed)
        c->ev.closed (c->ev.user, info);
    }
}

/* ---- The latency spin bit (RFC 9000 section 17.4) ---- */

/* The RFC requires that it be off for a random selection of at least one in
   sixteen paths or connection IDs, so that an observer cannot rely on it,
   and RFC 9312 suggests one in eight.  DRAW is a random byte.  */
int
conn_spin_enabled (const gq_conn_config *cfg, unsigned draw)
{
  return !cfg->disable_spin_bit && (draw & 0xff) % 8 != 0;
}

/* Decide afresh whether this connection spins: when it starts, and when it
   goes to another path.  */
void
conn_spin_draw (gq_conn *c)
{
  uint8_t draw = 0;

  if (gq_random (&draw, 1) != GQ_OK)
    draw = 0;			/* No randomness: stay out of it.  */
  c->spin_on = conn_spin_enabled (&c->cfg, draw);
}

/* The value the next 1-RTT packet carries is V.  It is reported only when
   it differs from the last one.  */
static void
spin_set (gq_conn *c, int v)
{
  if (c->spin_val == v)
    return;
  c->spin_val = (uint8_t) v;
  if (c->spin_on)
    ql_spin_bit_updated (c, v);
}

/* A new path starts from the beginning: the bit of the last one says
   nothing about this one's round trip.  */
void
conn_spin_reset (gq_conn *c)
{
  spin_set (c, 0);
  conn_spin_draw (c);
}

/* A 1-RTT packet with the spin bit BIT arrived.  Only the highest-numbered
   one counts, as an older one that was reordered would end a period early.
   A server echoes the bit and a client inverts it.  Without the bit, what
   the peer sends is not looked at (section 17.4).  */
void
conn_spin_received (gq_conn *c, int bit, int highest)
{
  if (!c->spin_on || !highest)
    return;
  spin_set (c, c->role == GQ_ROLE_SERVER ? bit : !bit);
}

/* The bit for a 1-RTT packet about to be sent: the state, or a random value
   when the bit is off, which looks like a connection whose peer spins at
   random.  */
int
conn_spin_value (gq_conn *c)
{
  int v;

  if (c->spin_on)
    return c->spin_val;
  if (c->spin_nbits == 0)
    {
      uint8_t b[8];
      unsigned i;

      c->spin_bits = 0;		/* If there is no randomness: always 0.  */
      if (gq_random (b, sizeof b) == GQ_OK)
        for (i = 0; i < sizeof b; i++)
          c->spin_bits = c->spin_bits << 8 | b[i];
      c->spin_nbits = 64;
    }
  v = (int) (c->spin_bits & 1);
  c->spin_bits >>= 1;
  c->spin_nbits--;
  return v;
}

void
conn_fail (gq_conn *c, uint64_t code, const char *reason)
{
  gq_conn_close_info info;
  size_t n = reason ? strlen (reason) : 0;

  if (c->state >= GQ_CONN_CLOSING)
    return;
  if (!c->err_set)
    {
      c->err_set = 1;
      c->err_code = code;
    }
  c->close_pending = 1;
  c->close_app = 0;
  c->close_err = c->err_code;
  c->close_frame = 0;
  if (n >= sizeof c->close_reason)
    n = sizeof c->close_reason - 1;
  if (n)
    memcpy (c->close_reason, reason, n);
  c->close_reason_len = n;
  memset (&info, 0, sizeof info);
  info.source = GQ_CLOSE_LOCAL;
  info.error = c->close_err;
  info.reason = (const uint8_t *) c->close_reason;
  info.reason_len = n;
  conn_enter_closing (c, &info, 0);
}

int
gq_conn_close (gq_conn *c, uint64_t now_us, int application, uint64_t error,
               const char *reason)
{
  gq_conn_close_info info;
  size_t n = reason ? strlen (reason) : 0;

  if (c->state >= GQ_CONN_CLOSING)
    return GQ_OK;
  c->now = now_us;
  conn_wake (c);
  c->close_pending = 1;
  c->close_app = application != 0;
  c->close_err = error;
  c->close_frame = 0;
  if (n >= sizeof c->close_reason)
    n = sizeof c->close_reason - 1;
  if (n)
    memcpy (c->close_reason, reason, n);
  c->close_reason_len = n;
  memset (&info, 0, sizeof info);
  info.source = GQ_CLOSE_LOCAL;
  info.application = c->close_app;
  info.error = error;
  info.reason = (const uint8_t *) c->close_reason;
  info.reason_len = n;
  conn_enter_closing (c, &info, 0);
  return GQ_OK;
}

/* ---- Spaces ---- */

int
conn_discard_space (gq_conn *c, int sp)
{
  space *s = &c->sp[sp];

  if (s->discarded)
    return GQ_OK;
  if (sp != SP_APP)
    {
      enum gq_level lv = sp == SP_INITIAL ? GQ_LEVEL_INITIAL
                                          : GQ_LEVEL_HANDSHAKE;

      if (s->have_rk)
        ql_key_discarded (c, lv, GQ_DIR_READ, 0, 0, "tls");
      if (s->have_wk)
        ql_key_discarded (c, lv, GQ_DIR_WRITE, 0, 0, "tls");
    }
  s->discarded = 1;
  s->have_rk = s->have_wk = 0;
  if (sp != SP_INITIAL)
    conn_held_drop (c, sp == SP_HANDSHAKE ? HELD_HANDSHAKE : HELD_APP);
  gq_packet_keys_wipe (&s->rk);
  gq_packet_keys_wipe (&s->wk);
  sp_sent_clear (c, sp);
  gq_ranges_free (&s->recv);
  gq_ranges_free (&s->acked_pns);
  gq_sstream_free (&s->cs);
  gq_rstream_free (&s->cr);
  s->ack_pending = s->ack_now = 0;
  s->ack_deadline = 0;
  s->loss_time = 0;
  s->probes = 0;
  s->n_ack_sent = 0;
  c->pto_count = 0;
  return GQ_OK;
}

void
conn_maybe_confirm (gq_conn *c)
{
  if (!c->handshake_confirmed)
    {
      c->handshake_confirmed = 1;
      ql_state (c, "handshake_confirmed", 1);
      /* The server's preferred address can be taken up now (RFC 9000
         section 9.6.2).  */
      if (c->pref_pending)
        {
          c->pref_pending = 0;
          if (c->ev.preferred_address)
            c->ev.preferred_address (c->ev.user, &c->peer_pref);
        }
    }
  /* A server keeps its Handshake keys until HANDSHAKE_DONE is
     acknowledged: a client that lost the frame goes on sending at the
     Handshake level, and from a new address that is the only authenticated
     packet the server will see (RFC 9001 section 4.9.2, held back).
     It does not send at that level any more.  The peer discards its
     Handshake keys when it receives HANDSHAKE_DONE, so a packet sent
     afterwards cannot be read.  */
  if (c->role == GQ_ROLE_SERVER && !c->handshake_done_acked)
    {
      space *s = &c->sp[SP_HANDSHAKE];

      s->ack_pending = s->ack_now = 0;
      s->ack_deadline = 0;
      s->probes = 0;
      return;
    }
  conn_discard_space (c, SP_HANDSHAKE);
}

void
conn_notify_connected (gq_conn *c, const gq_tls_info *info)
{
  if (c->connected_notified)
    return;
  c->connected_notified = 1;
  if (c->state == GQ_CONN_HANDSHAKE)
    c->state = GQ_CONN_ESTABLISHED;
  if (c->ev.connected)
    c->ev.connected (c->ev.user, info);
}

/* ---- Transport parameters ---- */

int
conn_version_compatible (uint32_t a, uint32_t b)
{
  return a == b
         || ((a == GQ_VERSION_1 || a == GQ_VERSION_2)
             && (b == GQ_VERSION_1 || b == GQ_VERSION_2));
}

int
conn_version_listed (const gq_conn *c, uint32_t v)
{
  size_t i;

  for (i = 0; i < c->cfg.n_versions; i++)
    if (c->cfg.versions[i] == v)
      return 1;
  return 0;
}

/* A family of PA is offered if it has a port and an address that is not all
   zeros (RFC 9000 section 18.2); clear what is not.  1 if either is.  */
static int
preferred_usable (gq_preferred_address *pa)
{
  static const uint8_t zero[16];

  if (pa->ipv4_port == 0 || memcmp (pa->ipv4, zero, 4) == 0)
    {
      memset (pa->ipv4, 0, sizeof pa->ipv4);
      pa->ipv4_port = 0;
    }
  if (pa->ipv6_port == 0 || memcmp (pa->ipv6, zero, 16) == 0)
    {
      memset (pa->ipv6, 0, sizeof pa->ipv6);
      pa->ipv6_port = 0;
    }
  return pa->ipv4_port != 0 || pa->ipv6_port != 0;
}

/* Server: ask the application for an address to offer this client
   (RFC 9000 section 9.6.1).  The connection ID that goes with it has
   sequence number 1, is not announced in a frame, and comes with its
   stateless reset token.  */
static void
make_offer (gq_conn *c)
{
  gq_preferred_address pa;
  gq_path none;
  const gq_path *from = &none;
  size_t i;

  if (c->cfg.preferred_address == NULL || c->have_offer)
    return;
  memset (&none, 0, sizeof none);
  if (c->rx_known)
    from = &c->rx;
  memset (&pa, 0, sizeof pa);
  if (!c->cfg.preferred_address (c->cfg.preferred_address_user, from, &pa)
      || !preferred_usable (&pa))
    return;
  if (new_lcid (c, 1, NULL) != GQ_OK)
    return;
  for (i = 0; i < MAX_LCID; i++)
    if (c->l[i].used && c->l[i].seq == c->next_lseq - 1)
      {
        pa.cid = c->l[i].cid;
        memcpy (pa.reset_token, c->l[i].token, GQ_RESET_TOKEN_LEN);
      }
  c->offer = pa;
  c->have_offer = 1;
}

static void
local_params (gq_conn *c, gq_transport_params *tp)
{
  const gq_conn_config *g = &c->cfg;

  gq_tp_defaults (tp);
  tp->max_idle_timeout = g->idle_timeout_ms;
  gq_tp_set_present (tp, GQ_TP_MAX_IDLE_TIMEOUT);
  tp->initial_max_data = g->initial_max_data;
  gq_tp_set_present (tp, GQ_TP_INITIAL_MAX_DATA);
  tp->initial_max_stream_data_bidi_local = g->initial_max_stream_data;
  gq_tp_set_present (tp, GQ_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
  tp->initial_max_stream_data_bidi_remote = g->initial_max_stream_data;
  gq_tp_set_present (tp, GQ_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
  tp->initial_max_stream_data_uni = g->initial_max_stream_data;
  gq_tp_set_present (tp, GQ_TP_INITIAL_MAX_STREAM_DATA_UNI);
  tp->initial_max_streams_bidi = g->initial_max_streams_bidi;
  gq_tp_set_present (tp, GQ_TP_INITIAL_MAX_STREAMS_BIDI);
  tp->initial_max_streams_uni = g->initial_max_streams_uni;
  gq_tp_set_present (tp, GQ_TP_INITIAL_MAX_STREAMS_UNI);
  tp->active_connection_id_limit = g->active_cid_limit;
  gq_tp_set_present (tp, GQ_TP_ACTIVE_CONNECTION_ID_LIMIT);
  tp->initial_source_connection_id = c->scid_first;
  gq_tp_set_present (tp, GQ_TP_INITIAL_SOURCE_CONNECTION_ID);
  tp->chosen_version = c->version;
  {
    /* Those compatible with the version in use, in our order; always
       including it (RFC 9368 section 3).  */
    size_t i, n = 0;
    int saw = 0;

    for (i = 0; i < g->n_versions; i++)
      if (conn_version_compatible (c->version, g->versions[i]))
        {
          tp->available_versions[n++] = g->versions[i];
          saw |= g->versions[i] == c->version;
        }
    if (!saw && n < GQ_TP_MAX_VERSIONS)
      tp->available_versions[n++] = c->version;
    tp->n_available_versions = n;
  }
  gq_tp_set_present (tp, GQ_TP_VERSION_INFORMATION);
  if (g->max_datagram_frame_size)
    {
      tp->max_datagram_frame_size = g->max_datagram_frame_size;
      gq_tp_set_present (tp, GQ_TP_MAX_DATAGRAM_FRAME_SIZE);
    }
  if (g->disable_active_migration)
    gq_tp_set_present (tp, GQ_TP_DISABLE_ACTIVE_MIGRATION);
  if (c->role == GQ_ROLE_SERVER)
    {
      tp->original_destination_connection_id = c->odcid;
      gq_tp_set_present (tp, GQ_TP_ORIGINAL_DESTINATION_CONNECTION_ID);
      memcpy (tp->stateless_reset_token, c->l[0].token, GQ_RESET_TOKEN_LEN);
      gq_tp_set_present (tp, GQ_TP_STATELESS_RESET_TOKEN);
      if (c->have_offer)
        {
          tp->preferred_address = c->offer;
          gq_tp_set_present (tp, GQ_TP_PREFERRED_ADDRESS);
        }
      if (c->retried)
        {
          tp->retry_source_connection_id = c->retry_scid;
          gq_tp_set_present (tp, GQ_TP_RETRY_SOURCE_CONNECTION_ID);
        }
    }
}

static int
cid_equal (const gq_cid *a, const gq_cid *b)
{
  return a->len == b->len && memcmp (a->data, b->data, a->len) == 0;
}

/* Client: the server's preferred address (RFC 9000 section 9.6.1) comes with
   a connection ID of sequence number 1 and its stateless reset token, as if
   in a NEW_CONNECTION_ID frame; keep them with the others.  The address is
   used when the application takes it up (gq_conn_migrate_preferred).  */
static void
store_preferred_address (gq_conn *c)
{
  gq_preferred_address pa;
  size_t i;
  pcid *slot = NULL;

  if (c->role != GQ_ROLE_CLIENT
      || !gq_tp_has (&c->peer_tp, GQ_TP_PREFERRED_ADDRESS))
    return;
  pa = c->peer_tp.preferred_address;
  if (!preferred_usable (&pa))
    return;
  for (i = 0; i < MAX_PCID; i++)
    {
      if (c->p[i].used && c->p[i].seq == 1)
        return;
      if (!c->p[i].used && slot == NULL)
        slot = &c->p[i];
    }
  if (slot == NULL)
    return;
  memset (slot, 0, sizeof *slot);
  slot->used = 1;
  slot->seq = 1;
  slot->cid = pa.cid;
  memcpy (slot->token, pa.reset_token, GQ_RESET_TOKEN_LEN);
  slot->has_token = 1;
  conn_peer_token (c, slot->token);
  c->peer_pref = pa;
  c->pref_offered = c->pref_pending = 1;
}

static void conn_issue_cids (gq_conn *c);

int
conn_apply_peer_params (gq_conn *c)
{
  const gq_transport_params *p = &c->peer_tp;
  uint64_t idle;

  if (!gq_tp_has (p, GQ_TP_INITIAL_SOURCE_CONNECTION_ID)
      || !cid_equal (&p->initial_source_connection_id, &c->dcid))
    return GQ_ERR_PROTOCOL;
  if (c->role == GQ_ROLE_CLIENT
      && (!gq_tp_has (p, GQ_TP_ORIGINAL_DESTINATION_CONNECTION_ID)
          || !cid_equal (&p->original_destination_connection_id, &c->odcid)))
    return GQ_ERR_PROTOCOL;
  if (c->role == GQ_ROLE_CLIENT
      && (c->retried
          ? (!gq_tp_has (p, GQ_TP_RETRY_SOURCE_CONNECTION_ID)
             || !cid_equal (&p->retry_source_connection_id, &c->retry_scid))
          : gq_tp_has (p, GQ_TP_RETRY_SOURCE_CONNECTION_ID)))
    return GQ_ERR_PROTOCOL;
  c->have_peer_tp = 1;
  c->max_data_peer = p->initial_max_data;
  c->max_streams_peer[1] = p->initial_max_streams_bidi;
  c->max_streams_peer[0] = p->initial_max_streams_uni;
  c->peer_ack_delay_exp = (unsigned) p->ack_delay_exponent;
  c->peer_max_ack_delay_us = p->max_ack_delay * 1000;
  c->peer_cid_limit = (size_t) p->active_connection_id_limit;
  if (gq_tp_has (p, GQ_TP_STATELESS_RESET_TOKEN))
    {
      memcpy (c->p[0].token, p->stateless_reset_token, GQ_RESET_TOKEN_LEN);
      c->p[0].has_token = 1;
      conn_peer_token (c, c->p[0].token);
    }
  idle = p->max_idle_timeout * 1000;
  if (idle && (c->idle_timeout_us == 0 || idle < c->idle_timeout_us))
    c->idle_timeout_us = idle;
  streams_apply_peer_params (c);
  store_preferred_address (c);
  conn_issue_cids (c);
  return GQ_OK;
}

/* IDs the peer is still to keep: retire_prior_to does not cover them.  */
static size_t
local_cids_active (const gq_conn *c)
{
  size_t i, n = 0;

  for (i = 0; i < MAX_LCID; i++)
    if (c->l[i].used && c->l[i].seq >= c->our_retire_prior)
      n++;
  return n;
}

/* Issue spares up to the peer's active_connection_id_limit.  */
static void
conn_issue_cids (gq_conn *c)
{
  if (c->peer_cid_limit == 0)
    return;
  while (local_cids_active (c) < c->peer_cid_limit
         && local_cids_active (c) < MAX_LCID)
    if (conn_new_lcid (c, 0) != GQ_OK)
      break;
}

/* The peer has addressed us with one of our connection IDs.  When that is
   not the oldest and the peer is already at its limit, retire the ones it
   has moved on from and issue a replacement (RFC 9000 section 5.1.2).  A
   peer that retires IDs itself is left alone: this runs only at the limit.  */
void
conn_cid_peer_using (gq_conn *c, const uint8_t *cid, size_t len)
{
  size_t i;
  uint64_t seq = UINT64_MAX;

  if (!c->handshake_confirmed || cid == NULL || len == 0)
    return;
  if (c->role == GQ_ROLE_SERVER && !conn_path_rx_changed (c))
    return;
  for (i = 0; i < MAX_LCID; i++)
    if (c->l[i].used && c->l[i].cid.len == len
        && memcmp (c->l[i].cid.data, cid, len) == 0)
      {
        seq = c->l[i].seq;
        break;
      }
  if (seq == UINT64_MAX || seq <= c->our_retire_prior)
    return;
  if (local_cids_active (c) < c->peer_cid_limit)
    return;
  c->our_retire_prior = seq;
  conn_issue_cids (c);
}

/* ---- TLS sink ---- */

static int
sink_send (void *user, enum gq_level level, const uint8_t *data, size_t len)
{
  gq_conn *c = user;
  int sp = SPACE_OF_LEVEL (level);
  long w;

  if (sp < 0 || c->sp[sp].discarded)
    return 0;
  w = gq_sstream_write (&c->sp[sp].cs, data, len);
  return w == (long) len ? 0 : 1;
}

static int
sink_secret (void *user, const gq_tls_secret *s)
{
  conn_install_keys (user, s);
  return 0;
}

/* Server: select the ticket ring bound to the version in use: tickets
   issued under one QUIC version are not valid under the other (RFC 9369
   section 5).  Version 1 keeps the caller's ring, so tickets issued
   before versions existed still resume.  */
static void
apply_ticket_keys (gq_conn *c)
{
  if (c->ticket_base == NULL || c->tls == NULL)
    return;
  if (c->version != GQ_VERSION_2)
    {
      gq_tls_server_set_ticket_keys (c->tls, c->ticket_base);
      return;
    }
  if (c->ticket_v2 == NULL)
    gq_ticket_keys_derive (c->ticket_base, "quic version 2", &c->ticket_v2);
  /* Without a derived ring, no tickets: a full handshake is always safe.  */
  gq_tls_server_set_ticket_keys (c->tls, c->ticket_v2);
}

/* Server: switch to VERSION, a compatible version preferred over the one
   the client started with (RFC 9368 section 4).  */
static int
switch_server_version (gq_conn *c, uint32_t version)
{
  gq_packet_keys ck, sk;
  size_t before = c->tp_len;

  if (gq_packet_keys_initial (version, c->initial_dcid.data,
                              c->initial_dcid.len, &ck, &sk) != GQ_OK)
    return GQ_ERR_CRYPTO;
  c->orig_rk = c->sp[SP_INITIAL].rk;
  c->have_orig_rk = 1;
  c->sp[SP_INITIAL].rk = ck;
  c->sp[SP_INITIAL].wk = sk;
  c->version = version;
  c->switched = 1;
  /* The engine holds a pointer to these bytes; the length is unchanged.  */
  encode_params (c);
  return c->tp_len == before ? GQ_OK : GQ_ERR_INVAL;
}

/* RFC 9368 section 5: check the peer's version_information against what
   happened, and (server) pick the version to use.  */
static int
negotiate_version (gq_conn *c)
{
  const gq_transport_params *p = &c->peer_tp;
  int has = gq_tp_has (p, GQ_TP_VERSION_INFORMATION);
  size_t i, j;

  if (c->role == GQ_ROLE_SERVER)
    {
      uint32_t pick = 0;

      if (!has)
        return GQ_OK;		/* A client that knows only one version.  */
      if (p->chosen_version != c->orig_version)
        return GQ_ERR_PROTOCOL;
      /* The client's most preferred version that we also list and that
         the one it started with is compatible with.  */
      for (j = 0; j < p->n_available_versions && !pick; j++)
        {
          uint32_t v = p->available_versions[j];

          if (gq_version_supported (v) && conn_version_listed (c, v)
              && conn_version_compatible (c->orig_version, v))
            pick = v;
        }
      if (pick && pick != c->version)
        {
          if (switch_server_version (c, pick) != GQ_OK)
            return GQ_ERR_PROTOCOL;
          apply_ticket_keys (c);
        }
      return GQ_OK;
    }
  if (has)
    {
      if (p->chosen_version != c->version)
        return GQ_ERR_PROTOCOL;
      if (c->vn_received)
        {
          /* It must be the version we would have picked from the server's
             own list, or the Version Negotiation packet was forged.  */
          uint32_t best = 0;

          for (i = 0; i < c->cfg.n_versions && !best; i++)
            for (j = 0; j < p->n_available_versions; j++)
              if (p->available_versions[j] == c->cfg.versions[i]
                  && gq_version_supported (c->cfg.versions[i]))
                {
                  best = c->cfg.versions[i];
                  break;
                }
          if (best != c->version)
            return GQ_ERR_PROTOCOL;
        }
    }
  else if (c->switched || c->vn_received)
    return GQ_ERR_PROTOCOL;
  return GQ_OK;
}

static int
sink_peer_params (void *user, const uint8_t *data, size_t len)
{
  gq_conn *c = user;
  int r;

  c->peer_tp_raw_len = len <= sizeof c->peer_tp_raw ? len : 0;
  if (c->peer_tp_raw_len)
    memcpy (c->peer_tp_raw, data, len);
  c->early_provisional = 0;
  r = gq_tp_decode (data, len,
                    c->role == GQ_ROLE_CLIENT ? GQ_ROLE_SERVER
                                              : GQ_ROLE_CLIENT,
                    &c->peer_tp);
  if (r == GQ_OK)
    r = conn_apply_peer_params (c);
  if (r != GQ_OK)
    {
      conn_fail (c, GQ_QERR_TRANSPORT_PARAMETER, "bad transport parameters");
      return 1;
    }
  ql_parameters_set (c, 1, &c->peer_tp);
  if (negotiate_version (c) != GQ_OK)
    {
      conn_fail (c, GQ_QERR_VERSION_NEGOTIATION, "version negotiation failed");
      return 1;
    }
  if (c->switched && gq_tp_has (&c->peer_tp, GQ_TP_VERSION_INFORMATION))
    {
      /* A compatible switch: what each side offered, and what was chosen.  */
      if (c->role == GQ_ROLE_SERVER)
        ql_version_information (c, c->peer_tp.available_versions,
                                c->peer_tp.n_available_versions,
                                c->cfg.versions, c->cfg.n_versions, c->version);
      else
        ql_version_information (c, c->cfg.versions, c->cfg.n_versions,
                                c->peer_tp.available_versions,
                                c->peer_tp.n_available_versions, c->version);
    }
  return 0;
}

static int
sink_complete (void *user, const gq_tls_info *info)
{
  gq_conn *c = user;

  c->handshake_complete = 1;
  ql_state (c, "handshake_complete", 0);
  ql_parameters_tls (c, info);
  ql_alpn_information (c, NULL, 0, NULL, 0, info->alpn_len ? info->alpn : NULL,
                       info->alpn_len);
  c->early_rk_deadline = c->now + 3 * conn_pto_base (c, SP_APP);
  if (c->role == GQ_ROLE_SERVER)
    {
      c->handshake_done_pending = 1;
      if (c->token_keys && c->addr_len)
        c->new_token_pending = 1;
      conn_maybe_confirm (c);
    }
  conn_notify_connected (c, info);
  return 0;
}

static int
sink_early_data (void *user, int accepted)
{
  gq_conn *c = user;

  if (accepted)
    conn_early_accepted (c);
  else
    conn_early_rejected (c);
  return c->state >= GQ_CONN_CLOSING;
}

static int
sink_ticket (void *user, const gq_tls_ticket *t)
{
  gq_conn *c = user;

  if (c->ev.ticket)
    c->ev.ticket (c->ev.user, t, c->version);
  return 0;
}

static int
sink_alert (void *user, unsigned code)
{
  gq_conn *c = user;

  conn_fail (c, GQ_QERR_CRYPTO_BASE + code, "TLS handshake failed");
  return 0;
}

static int
sink_verify (void *user, const gq_slice *chain, size_t n, const char *name)
{
  gq_conn *c = user;

  return c->ev.verify_peer (c->ev.user, chain, n, name);
}

static void
make_sink (gq_conn *c, gq_tls_sink *k)
{
  memset (k, 0, sizeof *k);
  k->user = c;
  k->send = sink_send;
  k->secret = sink_secret;
  k->peer_params = sink_peer_params;
  k->ticket = sink_ticket;
  k->early_data = sink_early_data;
  k->complete = sink_complete;
  k->alert = sink_alert;
  /* Only a client verifies a certificate chain here.  */
  if (c->role == GQ_ROLE_CLIENT && c->ev.verify_peer)
    k->verify_peer = sink_verify;
}

/* ---- Creation ---- */

static void
fill_defaults (gq_conn_config *g)
{
  if (g->idle_timeout_ms == 0)
    g->idle_timeout_ms = DEFAULT_IDLE_MS;
  if (g->initial_max_data == 0)
    g->initial_max_data = DEFAULT_MAX_DATA;
  if (g->initial_max_stream_data == 0)
    g->initial_max_stream_data = DEFAULT_STREAM_DATA;
  if (g->initial_max_streams_bidi == 0)
    g->initial_max_streams_bidi = DEFAULT_STREAMS;
  if (g->initial_max_streams_uni == 0)
    g->initial_max_streams_uni = DEFAULT_STREAMS;
  if (g->datagram_queue == 0)
    g->datagram_queue = 64u << 10;
  if (g->send_buffer == 0)
    g->send_buffer = 256u << 10;
  if (g->max_udp_payload == 0)
    g->max_udp_payload = 1452;
  if (g->max_buffered_packets == 0)
    g->max_buffered_packets = 16;
  if (g->max_buffered_packets > 256)
    g->max_buffered_packets = 256;
  if (g->n_versions == 0)
    {
      if (g->version)
        {
          g->versions[0] = g->version;
          g->n_versions = 1;
        }
      else
        {
          g->versions[0] = GQ_VERSION_2;
          g->versions[1] = GQ_VERSION_1;
          g->n_versions = 2;
        }
    }
  if (g->n_versions > GQ_TP_MAX_VERSIONS)
    g->n_versions = GQ_TP_MAX_VERSIONS;
  if (g->version == 0)
    {
      /* The oldest listed: v1 if it is there.  */
      size_t i;

      g->version = g->versions[0];
      for (i = 0; i < g->n_versions; i++)
        if (g->versions[i] == GQ_VERSION_1)
          g->version = GQ_VERSION_1;
    }
  if (g->max_udp_payload > 2048)
    g->max_udp_payload = 2048;
  if (g->max_udp_payload < 1200)
    g->max_udp_payload = 1200;
  if (g->cid_len == 0)
    g->cid_len = 8;
  if (g->cid_len > GQ_MAX_CID_LEN)
    g->cid_len = GQ_MAX_CID_LEN;
  if (g->active_cid_limit < 2)
    g->active_cid_limit = 4;
  if (g->active_cid_limit > MAX_LCID)
    g->active_cid_limit = MAX_LCID;
}

static void
space_init (space *s)
{
  gq_ranges_init (&s->recv, 64);
  gq_ranges_init (&s->acked_pns, 32);
  gq_sstream_init (&s->cs, CRYPTO_BUFFER, UINT64_MAX);
  gq_rstream_init (&s->cr, CRYPTO_BUFFER);
}

static gq_conn *
conn_alloc (enum gq_role role, const gq_conn_config *config,
            const gq_conn_events *events, uint64_t now, const gq_cid *fixed)
{
  gq_conn *c = calloc (1, sizeof *c);
  int i;

  if (c == NULL)
    return NULL;
  c->role = role;
  c->rx_ecn = -1;
  conn_pmtu_init (c);
  c->state = GQ_CONN_HANDSHAKE;
  if (config)
    c->cfg = *config;
  fill_defaults (&c->cfg);
  conn_spin_draw (c);
  conn_path_init (c, &c->cfg.path);
  if (events)
    c->ev = *events;
  c->version = c->orig_version = c->cfg.version;
  c->now = now;
  c->srtt = CONN_INITIAL_RTT (c);
  c->rttvar = CONN_INITIAL_RTT (c) / 2;
  c->peer_max_ack_delay_us = 25000;
  c->peer_ack_delay_exp = 3;
  c->idle_timeout_us = c->cfg.idle_timeout_ms * 1000;
  c->max_data_local = c->max_data_sent = c->cfg.initial_max_data;
  c->max_streams_local[1] = c->max_streams_local_sent[1]
    = c->cfg.initial_max_streams_bidi;
  c->max_streams_local[0] = c->max_streams_local_sent[0]
    = c->cfg.initial_max_streams_uni;
  for (i = 0; i < N_SPACES; i++)
    {
      space_init (&c->sp[i]);
    }
  cc_init (c);
  qlog_conn_init (c);
  conn_recompute_idle (c, now);
  /* Our first connection ID.  */
  if (new_lcid (c, 1, fixed) != GQ_OK)
    {
      gq_conn_free (c);
      return NULL;
    }
  c->scid_first = c->l[0].cid;
  c->p[0].used = 1;			/* The peer's first ID: set later.  */
  return c;
}

static void
encode_params (gq_conn *c)
{
  gq_transport_params tp;

  local_params (c, &tp);
  ql_parameters_set (c, 0, &tp);
  c->tp_len = 0;
  gq_tp_encode (&tp, c->role, c->tp_buf, sizeof c->tp_buf, &c->tp_len);
}

/* Client: pick the first destination ID, derive the Initial keys, and
   start the TLS handshake.  Also the restart after Version Negotiation.  */
static int
client_setup (gq_conn *c, int use_token)
{
  gq_tls_sink sink;
  gq_packet_keys ck, sk;
  int r;

  /* Random first destination connection ID, at least 8 bytes.  */
  c->odcid.len = 8;
  if (gq_random (c->odcid.data, c->odcid.len) != GQ_OK)
    return GQ_ERR_CRYPTO;
  c->dcid = c->odcid;
  c->initial_dcid = c->odcid;
  c->dcid_set = 1;
  c->p[0].cid = c->odcid;
  ql_connection_started (c);
  c->token_len = 0;
  if (use_token && c->cfg.token && c->cfg.token_len
      && c->cfg.token_len <= sizeof c->token)
    {
      memcpy (c->token, c->cfg.token, c->cfg.token_len);
      c->token_len = c->cfg.token_len;
    }
  r = gq_packet_keys_initial (c->version, c->odcid.data, c->odcid.len, &ck,
                              &sk);
  if (r != GQ_OK)
    return r;
  c->sp[SP_INITIAL].wk = ck;
  c->sp[SP_INITIAL].rk = sk;
  c->sp[SP_INITIAL].have_wk = c->sp[SP_INITIAL].have_rk = 1;
  ql_key_updated (c, GQ_LEVEL_INITIAL, GQ_DIR_WRITE, "tls");
  ql_key_updated (c, GQ_LEVEL_INITIAL, GQ_DIR_READ, "tls");
  encode_params (c);
  c->ctls.quic = 1;
  c->ctls.transport_params = c->tp_buf;
  c->ctls.transport_params_len = c->tp_len;
  make_sink (c, &sink);
  r = gq_tls_client_new (&c->tls, &c->ctls, &sink);
  if (r == GQ_OK)
    r = gq_tls_start (c->tls);
  return r;
}

int
gq_conn_client_new (gq_conn **out, const gq_conn_config *config,
                    const gq_tls_config *tls, const gq_conn_events *events,
                    uint64_t now_us)
{
  gq_conn *c;
  int r;

  if (out == NULL || tls == NULL || tls->n_alpn == 0)
    return GQ_ERR_INVAL;
  *out = NULL;
  c = conn_alloc (GQ_ROLE_CLIENT, config, events, now_us, NULL);
  if (c == NULL)
    return GQ_ERR_NOMEM;
  if (!gq_version_supported (c->version))
    {
      gq_conn_free (c);
      return GQ_ERR_UNSUPPORTED;
    }
  /* The version we start with is always among those we offer.  */
  if (!conn_version_listed (c, c->version))
    {
      if (c->cfg.n_versions == GQ_TP_MAX_VERSIONS)
        c->cfg.n_versions--;
      memmove (c->cfg.versions + 1, c->cfg.versions,
               c->cfg.n_versions * sizeof c->cfg.versions[0]);
      c->cfg.versions[0] = c->version;
      c->cfg.n_versions++;
    }
  c->ctls = *tls;
  if (tls->resume && tls->early_data && c->cfg.resume_params
      && c->cfg.resume_params_len
      && gq_tp_decode (c->cfg.resume_params, c->cfg.resume_params_len,
                       GQ_ROLE_SERVER, &c->resume_tp) == GQ_OK)
    {
      /* Until the server's own parameters arrive, the remembered ones
         stand in for them (RFC 9000 section 7.4.1).  */
      c->early_offered = 1;
      c->early_provisional = 1;
      c->peer_tp = c->resume_tp;
      c->have_peer_tp = 1;
      c->max_data_peer = c->resume_tp.initial_max_data;
      c->max_streams_peer[1] = c->resume_tp.initial_max_streams_bidi;
      c->max_streams_peer[0] = c->resume_tp.initial_max_streams_uni;
    }
  r = client_setup (c, 1);
  if (r != GQ_OK)
    {
      gq_conn_free (c);
      return r;
    }
  ql_version_information (c, c->cfg.versions, c->cfg.n_versions, NULL, 0,
                          c->version);
  ql_alpn_information (c, c->ctls.alpn, c->ctls.n_alpn, NULL, 0, NULL, 0);
  ql_recovery_parameters (c);
  if (c->early_offered)
    ql_parameters_restored (c, &c->resume_tp);
  *out = c;
  return GQ_OK;
}

/* A Version Negotiation packet named a version we prefer: start the
   connection again with it (RFC 9000 section 6.2).  Nothing has been
   received from the server yet, so all state is the first flight's.  */
int
conn_client_restart (gq_conn *c, uint32_t version)
{
  int i;

  gq_tls_free (c->tls);
  c->tls = NULL;
  for (i = 0; i < N_SPACES; i++)
    {
      space *s = &c->sp[i];

      sp_sent_clear (c, i);
      free (s->sent);
      gq_ranges_free (&s->recv);
      gq_ranges_free (&s->acked_pns);
      gq_sstream_free (&s->cs);
      gq_rstream_free (&s->cr);
      gq_packet_keys_wipe (&s->rk);
      gq_packet_keys_wipe (&s->wk);
      memset (s, 0, sizeof *s);
      space_init (s);
    }
  c->version = c->orig_version = version;
  c->vn_received = 1;
  c->switched = 0;
  c->retried = 0;
  c->retry_scid.len = 0;
  c->pto_count = 0;
  c->have_peer_tp = 0;
  c->bytes_in_flight = 0;
  return client_setup (c, 0);
}

/* The connection cannot continue and there is nobody to tell.  */
void
conn_abandon (gq_conn *c, uint64_t error, const char *reason)
{
  gq_conn_close_info info;

  memset (&info, 0, sizeof info);
  info.source = GQ_CLOSE_LOCAL;
  info.error = error;
  info.reason = (const uint8_t *) reason;
  info.reason_len = strlen (reason);
  c->close_pending = 0;
  c->state = GQ_CONN_DONE;
  ql_closed (c, GQ_CLOSE_LOCAL, 0, error, (const uint8_t *) reason,
             strlen (reason),
             error == GQ_QERR_VERSION_NEGOTIATION ? "version_mismatch"
                                                  : "error");
  ql_state (c, "closed", 0);
  if (!c->closed_notified)
    {
      c->closed_notified = 1;
      if (c->ev.closed)
        c->ev.closed (c->ev.user, &info);
    }
}

int
gq_conn_server_accept (gq_conn **out, const gq_conn_config *config,
                       const gq_tls_server_config *tls,
                       const gq_conn_events *events, uint64_t now_us,
                       const gq_conn_accept *acc)
{
  gq_conn *c;

  if (out == NULL || tls == NULL || tls->n_alpn == 0)
    return GQ_ERR_INVAL;
  *out = NULL;
  c = conn_alloc (GQ_ROLE_SERVER, config, events, now_us,
                  acc && acc->retry_scid.len ? &acc->retry_scid : NULL);
  if (c == NULL)
    return GQ_ERR_NOMEM;
  if (!gq_version_supported (c->version))
    {
      gq_conn_free (c);
      return GQ_ERR_UNSUPPORTED;
    }
  c->stls = *tls;
  if (acc)
    {
      c->peer_addr_validated = acc->validated != 0;
      if (acc->retry_scid.len)
        {
          c->retried = 1;
          c->retry_scid = acc->retry_scid;
          c->odcid = acc->odcid;
        }
      if (acc->token_keys && acc->addr_len <= sizeof c->addr)
        {
          c->token_keys = acc->token_keys;
          memcpy (c->addr, acc->addr, acc->addr_len);
          c->addr_len = acc->addr_len;
        }
    }
  *out = c;
  return GQ_OK;
}

int
gq_conn_server_new (gq_conn **out, const gq_conn_config *config,
                    const gq_tls_server_config *tls,
                    const gq_conn_events *events, uint64_t now_us)
{
  return gq_conn_server_accept (out, config, tls, events, now_us, NULL);
}

/* Server: the first Initial arrived.  Derive its keys and start TLS.  */
int
conn_server_start (gq_conn *c, const uint8_t *odcid, size_t odcid_len,
                   const uint8_t *client_scid, size_t client_scid_len)
{
  gq_tls_sink sink;
  gq_packet_keys ck, sk;
  int r;

  c->initial_dcid.len = (uint8_t) odcid_len;
  memcpy (c->initial_dcid.data, odcid, odcid_len);
  if (!c->retried)
    c->odcid = c->initial_dcid;
  c->dcid.len = (uint8_t) client_scid_len;
  memcpy (c->dcid.data, client_scid, client_scid_len);
  c->dcid_set = 1;
  c->p[0].cid = c->dcid;
  ql_connection_started (c);
  ql_version_information (c, NULL, 0, c->cfg.versions, c->cfg.n_versions,
                          c->version);
  ql_alpn_information (c, NULL, 0, c->stls.alpn, c->stls.n_alpn, NULL, 0);
  ql_recovery_parameters (c);
  r = gq_packet_keys_initial (c->version, odcid, odcid_len, &ck, &sk);
  if (r != GQ_OK)
    return r;
  c->sp[SP_INITIAL].rk = ck;
  c->sp[SP_INITIAL].wk = sk;
  c->sp[SP_INITIAL].have_rk = c->sp[SP_INITIAL].have_wk = 1;
  ql_key_updated (c, GQ_LEVEL_INITIAL, GQ_DIR_READ, "tls");
  ql_key_updated (c, GQ_LEVEL_INITIAL, GQ_DIR_WRITE, "tls");
  make_offer (c);
  encode_params (c);
  c->stls.quic = 1;
  c->stls.transport_params = c->tp_buf;
  c->stls.transport_params_len = c->tp_len;
  make_sink (c, &sink);
  c->ticket_base = c->stls.ticket_keys;
  r = gq_tls_server_new (&c->tls, &c->stls, &sink);
  if (r != GQ_OK)
    return r;
  apply_ticket_keys (c);
  c->got_first_initial = 1;
  return GQ_OK;
}

void
gq_conn_free (gq_conn *c)
{
  int i;

  if (c == NULL)
    return;
  gq_tls_free (c->tls);
  gq_ticket_keys_free (c->ticket_v2);
  conn_held_free (c);
  datagrams_free (c);
  for (i = 0; i < N_SPACES; i++)
    {
      space *s = &c->sp[i];

      sp_sent_clear (c, i);
      free (s->sent);
      gq_ranges_free (&s->recv);
      gq_ranges_free (&s->acked_pns);
      gq_sstream_free (&s->cs);
      gq_rstream_free (&s->cr);
      gq_packet_keys_wipe (&s->rk);
      gq_packet_keys_wipe (&s->wk);
    }
  streams_free (c);
  qlog_conn_free (c);
  gq_packet_keys_wipe (&c->rk_prev);
  gq_packet_keys_wipe (&c->rk_next);
  memset (c->rsec, 0, sizeof c->rsec);
  memset (c->wsec, 0, sizeof c->wsec);
  free (c);
}

/* ---- Public accessors, datagram entry points, timers ---- */

enum gq_conn_state
gq_conn_state (const gq_conn *c)
{
  return c->state;
}

int
gq_conn_is_established (const gq_conn *c)
{
  return c->state == GQ_CONN_ESTABLISHED;
}

int
gq_conn_get_peer_params (const gq_conn *c, uint8_t *out, size_t cap,
                         size_t *len)
{
  if (c->peer_tp_raw_len == 0)
    return GQ_ERR_UNAVAILABLE;
  if (cap < c->peer_tp_raw_len)
    return GQ_ERR_BUFSIZE;
  memcpy (out, c->peer_tp_raw, c->peer_tp_raw_len);
  *len = c->peer_tp_raw_len;
  return GQ_OK;
}

const uint8_t *
gq_conn_original_dcid (const gq_conn *c, size_t *len)
{
  *len = c->odcid.len;
  return c->odcid.data;
}

int
gq_conn_early_data_active (const gq_conn *c)
{
  return c->rx_early;
}

int
gq_conn_early_data_accepted (const gq_conn *c)
{
  if (!c->early_offered || (!c->early_accepted && !c->early_rejected))
    return -1;
  return c->early_accepted;
}

uint32_t
gq_conn_version (const gq_conn *c)
{
  return c->version;
}

const uint8_t *
gq_conn_initial_dcid (const gq_conn *c, size_t *len)
{
  *len = c->initial_dcid.len;
  return c->initial_dcid.data;
}

void
gq_conn_get_stats (const gq_conn *c, gq_conn_stats *st)
{
  *st = c->st;
  st->srtt_us = c->srtt;
  st->min_rtt_us = c->min_rtt;
  st->rttvar_us = c->rttvar;
  st->bytes_in_flight = c->bytes_in_flight;
  st->cwnd = c->cc.cwnd;
  st->ssthresh = c->cc.ssthresh;
  st->pacing_rate_bps = (uint64_t) (conn_pacing_rate (c) * 8e6);
  st->congestion_events = c->congestion_events;
  st->pto_count = c->pto_count;
  st->key_updates = c->key_updates;
  st->path_validations = c->path_validations;
  st->path_failures = c->path_failures;
  st->migrations = c->migrations;
  st->datagrams_sent = c->datagrams_sent;
  st->datagrams_received = c->datagrams_received;
  st->datagrams_dropped = c->datagrams_dropped;
  st->ecn_ect0_received = c->ecn_in[0];
  st->ecn_ect1_received = c->ecn_in[1];
  st->ecn_ce_received = c->ecn_in[2];
  st->ecn_state = c->ecn_state;
  st->ecn_marked_sent = c->ecn_marked_sent;
  st->max_datagram_size = conn_max_datagram (c);
  st->pmtu_done = conn_pmtu_done (c);
  st->packets_buffered = c->packets_buffered;
}

/* ECN is a gq_ecn, or -1 when the caller does not say.  */
static int
recv_datagram (gq_conn *c, uint64_t now_us, const gq_path *from, int ecn,
               uint8_t *data, size_t len)
{
  int r;

  c->now = now_us;
  if (c->state == GQ_CONN_DONE || c->state == GQ_CONN_DRAINING)
    return GQ_OK;
  conn_path_rx_begin (c, from);
  if (!conn_path_accept_rx (c))
    {
      conn_path_rx_end (c);
      return GQ_OK;
    }
  c->rx_ecn = (int8_t) ecn;
  r = conn_receive_datagram (c, now_us, data, len);
  c->rx_ecn = -1;
  conn_path_rx_end (c);
  /* The keys this datagram brought open what came ahead of them.  */
  conn_replay_held (c);
  ql_after (c);
  return r;
}

int
gq_conn_recv_ecn (gq_conn *c, uint64_t now_us, const gq_path *from, int ecn,
                  uint8_t *data, size_t len)
{
  if (ecn < GQ_ECN_NOT_ECT || ecn > GQ_ECN_CE)
    return GQ_ERR_INVAL;
  return recv_datagram (c, now_us, from, ecn, data, len);
}

int
gq_conn_recv_path (gq_conn *c, uint64_t now_us, const gq_path *from,
                   uint8_t *data, size_t len)
{
  return recv_datagram (c, now_us, from, -1, data, len);
}


int
gq_conn_recv (gq_conn *c, uint64_t now_us, uint8_t *data, size_t len)
{
  return gq_conn_recv_path (c, now_us, NULL, data, len);
}

int
gq_conn_send_path (gq_conn *c, uint64_t now_us, uint8_t *out, size_t cap,
                   size_t *len, gq_path *to)
{
  int r;

  *len = 0;
  c->now = now_us;
  c->tx_path = c->cur_path;
  if (c->state == GQ_CONN_DONE || c->state == GQ_CONN_DRAINING)
    return GQ_OK;
  if (cap < conn_max_datagram (c))
    return GQ_ERR_BUFSIZE;
  if (c->lead_ack)
    r = conn_send_version_ack (c, now_us, out, cap, len);
  else
    r = conn_build_datagram (c, now_us, out, cap, len);
  ql_after (c);
  if (to)
    *to = c->paths[c->tx_path].p;
  return r;
}

int
gq_conn_send_ecn (gq_conn *c, uint64_t now_us, uint8_t *out, size_t cap,
                  size_t *len, gq_path *to, int *ecn)
{
  int r;

  c->tx_ecn_ok = 1;
  c->tx_ecn = GQ_ECN_NOT_ECT;
  r = gq_conn_send_path (c, now_us, out, cap, len, to);
  c->tx_ecn_ok = 0;
  *ecn = *len ? c->tx_ecn : GQ_ECN_NOT_ECT;
  return r;
}

int
gq_conn_send (gq_conn *c, uint64_t now_us, uint8_t *out, size_t cap,
              size_t *len)
{
  return gq_conn_send_path (c, now_us, out, cap, len, NULL);
}

uint64_t
gq_conn_timeout (const gq_conn *c)
{
  uint64_t t = 0;
  int i;

#define EARLIER(v) do { uint64_t v_ = (v); if (v_ && (t == 0 || v_ < t)) t = v_; } while (0)
  if (c->state == GQ_CONN_DONE)
    return 0;
  if (c->state >= GQ_CONN_CLOSING)
    return c->close_deadline;
  EARLIER (c->idle_deadline);
  for (i = 0; i < N_SPACES; i++)
    if (!c->sp[i].discarded)
      EARLIER (c->sp[i].ack_deadline);
  EARLIER (conn_loss_deadline (c));
  EARLIER (conn_path_deadline (c));
  EARLIER (conn_pmtu_deadline (c));
  EARLIER (c->pace_deadline);
#undef EARLIER
  return t;
}

void
gq_conn_on_timeout (gq_conn *c, uint64_t now_us)
{
  int i;

  c->now = now_us;
  if (c->state == GQ_CONN_DONE)
    return;
  ql_timers_expired (c, now_us);
  if (c->state >= GQ_CONN_CLOSING)
    {
      if (c->close_deadline && now_us >= c->close_deadline)
        {
          c->state = GQ_CONN_DONE;
          ql_state (c, "closed", 0);
        }
      return;
    }
  if (c->idle_deadline && now_us >= c->idle_deadline)
    {
      gq_conn_close_info info;

      memset (&info, 0, sizeof info);
      info.source = GQ_CLOSE_IDLE;
      c->closed_notified = 1;
      c->state = GQ_CONN_DONE;
      ql_closed (c, GQ_CLOSE_IDLE, 0, 0, NULL, 0, "idle_timeout");
      ql_state (c, "closed", 0);
      if (c->ev.closed)
        c->ev.closed (c->ev.user, &info);
      return;
    }
  for (i = 0; i < N_SPACES; i++)
    {
      space *s = &c->sp[i];

      if (!s->discarded && s->ack_deadline && now_us >= s->ack_deadline)
        {
          s->ack_now = 1;
          s->ack_deadline = 0;
        }
    }
  /* The pacer has earned its credit: a send will use it.  */
  if (c->pace_deadline && now_us >= c->pace_deadline)
    c->pace_deadline = 0;
  on_loss_timeout (c, now_us);
  conn_path_on_timeout (c, now_us);
  conn_pmtu_on_timeout (c, now_us);
  ql_after (c);
}
