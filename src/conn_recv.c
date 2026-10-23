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

#include "conn_int.h"


/* ---- Logging ---- */

static const char *
long_type_name (enum gq_packet_type t)
{
  switch (t)
    {
    case GQ_PKT_INITIAL: return "initial";
    case GQ_PKT_ZERO_RTT: return "0RTT";
    case GQ_PKT_HANDSHAKE: return "handshake";
    case GQ_PKT_RETRY: return "retry";
    case GQ_PKT_VERSION_NEGOTIATION: return "version_negotiation";
    default: return "unknown";
    }
}

/* What of a long header is known before it is opened.  */
static void
long_hdr (qlog_hdr *q, const gq_long_header *h)
{
  memset (q, 0, sizeof *q);
  q->type = long_type_name (h->type);
  q->have_version = 1;
  q->version = h->version;
  q->have_dcid = q->have_scid = 1;
  q->dcid = h->dcid.data;
  q->dcid_len = h->dcid.len;
  q->scid = h->scid.data;
  q->scid_len = h->scid.len;
  if (h->type == GQ_PKT_INITIAL || h->type == GQ_PKT_ZERO_RTT
      || h->type == GQ_PKT_HANDSHAKE)
    {
      q->have_length = 1;
      q->length = h->length;
    }
  if ((h->type == GQ_PKT_INITIAL && h->token.len) || h->type == GQ_PKT_RETRY)
    {
      q->have_token = 1;
      q->token = h->token.data;
      q->token_len = h->token.len;
    }
}

static void
drop_long (gq_conn *c, const gq_long_header *h, const char *trigger)
{
  qlog_hdr q;

  if (!QLOG_ON (c, QE_PACKET_DROPPED))
    return;
  long_hdr (&q, h);
  ql_packet_dropped (c, &q, h->packet_len, trigger);
}

static void
drop_short (gq_conn *c, size_t rem, const char *trigger)
{
  qlog_hdr q;

  if (!QLOG_ON (c, QE_PACKET_DROPPED))
    return;
  memset (&q, 0, sizeof q);
  q.type = "1RTT";
  ql_packet_dropped (c, &q, rem, trigger);
}

/* A long-header packet that was opened: PN, its length of PN_LEN bytes,
   and a payload of PLEN bytes at POFF.  */
static void
log_long (gq_conn *c, const gq_long_header *h, const uint8_t *pkt,
          uint64_t pn, size_t poff, size_t plen)
{
  qlog_hdr q;

  if (!QLOG_ON (c, QE_PACKET_RECEIVED))
    return;
  long_hdr (&q, h);
  q.have_pn = 1;
  q.pn = pn;
  q.pn_len = (unsigned) (poff - h->pn_offset);
  ql_packet_received (c, &q, h->packet_len, pkt + poff, plen,
                      c->rx_known ? c->cur_path : 0, NULL, 0, NULL);
}

/* ---- Keys ---- */

static int
derive_next_read (gq_conn *c)
{
  gq_packet_keys *cur = &c->sp[SP_APP].rk;
  int r;

  /* The next keys, made ahead: they have ciphers of their own if the keys
     they follow do, and share the header protection one.  */
  gq_packet_keys_wipe (&c->rk_next);
  r = gq_packet_keys_update (c->version, cur, c->rsec, c->rsec_len,
                             c->rsec_next, &c->rk_next);
  c->have_rk_next = r == GQ_OK;
  return r;
}

void
conn_install_keys (gq_conn *c, const gq_tls_secret *s)
{
  int sp = SPACE_OF_LEVEL (s->level);
  gq_packet_keys k;

  if (s->level == GQ_LEVEL_EARLY)
    {
      /* 0-RTT keys: the client writes with them, the server reads.  */
      if (gq_packet_keys_derive (c->version, s->aead, s->secret, s->len, &k)
          != GQ_OK)
        {
          conn_fail (c, GQ_QERR_INTERNAL, "key derivation failed");
          return;
        }
      if (s->dir == GQ_DIR_WRITE && c->role == GQ_ROLE_CLIENT)
        {
          gq_packet_keys_move (&c->early_wk, &k);
          c->have_early_wk = 1;
          ql_key_updated (c, GQ_LEVEL_EARLY, GQ_DIR_WRITE, "tls");
        }
      else if (s->dir == GQ_DIR_READ && c->role == GQ_ROLE_SERVER)
        {
          gq_packet_keys_move (&c->early_rk, &k);
          c->have_early_rk = 1;
          ql_key_updated (c, GQ_LEVEL_EARLY, GQ_DIR_READ, "tls");
        }
      return;
    }
  if (sp < 0)
    return;
  if (gq_packet_keys_derive (c->version, s->aead, s->secret, s->len, &k)
      != GQ_OK)
    {
      conn_fail (c, GQ_QERR_INTERNAL, "key derivation failed");
      return;
    }
  ql_key_updated (c, s->level, s->dir, "tls");
  if (s->dir == GQ_DIR_READ)
    {
      gq_packet_keys_move (&c->sp[sp].rk, &k);
      c->sp[sp].have_rk = 1;
      if (sp == SP_APP)
        {
          /* These keys protect the packets of the whole connection: keep
             their ciphers open.  (Not being able to is no matter: they are
             set up for each packet then.)  Initial, Handshake and 0-RTT keys
             protect a handful, and are not worth it.  */
          gq_packet_keys_prepare (&c->sp[sp].rk);
          memcpy (c->rsec, s->secret, s->len);
          c->rsec_len = s->len;
          derive_next_read (c);
        }
    }
  else
    {
      gq_packet_keys_move (&c->sp[sp].wk, &k);
      c->sp[sp].have_wk = 1;
      if (sp == SP_APP)
        {
          gq_packet_keys_prepare (&c->sp[sp].wk);
          if (c->have_early_wk)
            ql_key_discarded (c, GQ_LEVEL_EARLY, GQ_DIR_WRITE, 0, 0, "tls");
          if (c->role == GQ_ROLE_SERVER && !c->handshake_complete)
            ql_state (c, "early_write", 1);
          c->have_early_wk = 0;
          gq_packet_keys_wipe (&c->early_wk);
          memcpy (c->wsec, s->secret, s->len);
          c->wsec_len = s->len;
          /* Packets sent early (0-RTT) were not under these keys.  */
          c->w_first_pn = c->sp[SP_APP].next_pn;
        }
    }
}

/* Replace our sending keys with the next generation.  REMOTE: the peer
   updated first and this follows.  */
static int
write_key_update (gq_conn *c, int remote)
{
  space *s = &c->sp[SP_APP];
  gq_packet_keys next;
  uint8_t next_secret[GQ_MAX_HASH_LEN];

  if (gq_packet_keys_update (c->version, &s->wk, c->wsec, c->wsec_len,
                             next_secret, &next) != GQ_OK)
    return GQ_ERR_CRYPTO;
  gq_packet_keys_move (&s->wk, &next);
  memcpy (c->wsec, next_secret, c->wsec_len);
  c->w_phase ^= 1;
  c->w_first_pn = s->next_pn;
  c->w_phase_acked = 0;
  c->key_updates++;
  memset (next_secret, 0, sizeof next_secret);
  c->ql.w_phase++;
  ql_key_updated (c, GQ_LEVEL_APPLICATION, GQ_DIR_WRITE,
                  remote ? "remote_update" : "local_update");
  return GQ_OK;
}

int
gq_conn_update_keys (gq_conn *c, uint64_t now_us)
{
  (void) now_us;
  if (!c->handshake_confirmed || !c->sp[SP_APP].have_wk || !c->w_phase_acked
      || c->w_phase != c->r_phase)
    return GQ_ERR_INVAL;
  conn_wake (c);
  return write_key_update (c, 0);
}

static void
rotate_read_keys (gq_conn *c, uint64_t pn)
{
  space *s = &c->sp[SP_APP];

  gq_packet_keys_move (&c->rk_prev, &s->rk);
  c->have_rk_prev = 1;
  /* Kept for reordered packets, but not for long (RFC 9001 section 6.5).  */
  c->rk_prev_until = c->now + 3 * conn_pto_base (c, SP_APP);
  gq_packet_keys_move (&s->rk, &c->rk_next);
  memcpy (c->rsec, c->rsec_next, c->rsec_len);
  c->r_phase ^= 1;
  c->r_first_pn = pn;
  derive_next_read (c);
  c->ql.r_phase++;
  ql_key_updated (c, GQ_LEVEL_APPLICATION, GQ_DIR_READ, "remote_update");
  /* The peer started an update: follow it with our own keys.  */
  if (c->w_phase != c->r_phase)
    write_key_update (c, 1);
}

/* ---- Frame handling ---- */

typedef struct rctx
{
  gq_conn *c;
  int sp;
  int ae;			/* Saw an ack-eliciting frame.  */
  int nonprobing;		/* Saw a frame other than PADDING and the
				   path probing ones.  */
  int closing;			/* Saw CONNECTION_CLOSE.  */
} rctx;

typedef struct crypto_user
{
  gq_conn *c;
  enum gq_level level;
} crypto_user;

static int
crypto_deliver (void *user, uint64_t off, const uint8_t *data, size_t len,
                int fin)
{
  crypto_user *u = user;
  const uint8_t *p = data;
  size_t n = len;
  int r;

  (void) off;
  (void) fin;
  if (n == 0)
    return 0;
  r = gq_tls_feed (u->c->tls, u->level, &p, &n);
  if (r < 0)
    {
      int alert = gq_tls_alert (u->c->tls);

      conn_fail (u->c, alert >= 0 ? GQ_QERR_CRYPTO_BASE + (unsigned) alert
                                  : GQ_QERR_PROTOCOL_VIOLATION,
                 "handshake failed");
      return 1;
    }
  return u->c->state >= GQ_CONN_CLOSING;
}

static int
cid_store (gq_conn *c, const gq_frame *f)
{
#define NC (&f->u.new_connection_id)
  size_t i, active = 0;
  pcid *slot = NULL;

  /* RFC 9000 section 19.15: packets sent to a zero-length ID leave nothing
     to switch to or retire.  */
  if (c->dcid.len == 0)
    {
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION,
                 "NEW_CONNECTION_ID with a zero-length ID in use");
      return 1;
    }
  if (NC->retire_prior_to > NC->seq || NC->cid_len == 0)
    {
      conn_fail (c, GQ_QERR_FRAME_ENCODING, "bad NEW_CONNECTION_ID");
      return 1;
    }
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].seq == NC->seq)
      {
        if (c->p[i].cid.len != NC->cid_len
            || memcmp (c->p[i].cid.data, NC->cid, NC->cid_len))
          {
            conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "connection ID reused");
            return 1;
          }
        return 0;		/* Retransmission.  */
      }
  for (i = 0; i < MAX_PCID; i++)
    if (!c->p[i].used)
      {
        slot = &c->p[i];
        break;
      }
  if (slot == NULL)
    {
      conn_fail (c, GQ_QERR_CONNECTION_ID_LIMIT, "too many connection IDs");
      return 1;
    }
  memset (slot, 0, sizeof *slot);
  slot->used = 1;
  slot->seq = NC->seq;
  slot->cid.len = NC->cid_len;
  memcpy (slot->cid.data, NC->cid, NC->cid_len);
  memcpy (slot->token, NC->reset_token, GQ_RESET_TOKEN_LEN);
  slot->has_token = 1;
  conn_peer_token (c, slot->token);
  if (NC->retire_prior_to > c->peer_retire_prior)
    c->peer_retire_prior = NC->retire_prior_to;
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].seq < c->peer_retire_prior
        && c->p[i].retire == 0)
      c->p[i].retire = 1;
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].retire == 0)
      active++;
  if (active > c->cfg.active_cid_limit)
    {
      conn_fail (c, GQ_QERR_CONNECTION_ID_LIMIT, "too many connection IDs");
      return 1;
    }
  /* If the ID in use was retired, switch to another.  */
  for (i = 0; i < MAX_PCID; i++)
    if (c->p[i].used && c->p[i].seq == c->dcid_seq && c->p[i].retire)
      {
        size_t j;

        for (j = 0; j < MAX_PCID; j++)
          if (c->p[j].used && !c->p[j].retire)
            {
              c->dcid = c->p[j].cid;
              c->dcid_seq = c->p[j].seq;
              conn_path_dcid_changed (c);
              break;
            }
        break;
      }
  conn_path_cids_retired (c);
#undef NC
  return 0;
}

static int
cid_retire (gq_conn *c, uint64_t seq)
{
  size_t i, active = 0;

  if (seq >= c->next_lseq)
    {
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "retired unissued ID");
      return 1;
    }
  for (i = 0; i < MAX_LCID; i++)
    if (c->l[i].used && c->l[i].seq == seq)
      {
        /* RFC 9000 section 19.16: one we have not sent is as unissued as
           one never made.  Replacements are made as IDs are retired, so
           without this a peer could retire them in a chain, each costing a
           mint, though it has been told of none of them.  */
        if (!c->l[i].sent)
          {
            conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "retired unsent ID");
            return 1;
          }
        c->l[i].used = 0;
        conn_cid_retired (c, &c->l[i].cid);
        break;
      }
  for (i = 0; i < MAX_LCID; i++)
    active += c->l[i].used;
  if (active < c->peer_cid_limit && active < MAX_LCID)
    conn_new_lcid (c, 0);
  return 0;
}

static int
on_frame (void *user, const gq_frame *f)
{
  rctx *x = user;
  gq_conn *c = x->c;
  int sp = x->sp;

  if (f->type != GQ_FRAME_PADDING && f->type != GQ_FRAME_ACK
      && f->type != GQ_FRAME_CONNECTION_CLOSE)
    x->ae = 1;
  if (f->type != GQ_FRAME_PADDING && f->type != GQ_FRAME_PATH_CHALLENGE
      && f->type != GQ_FRAME_PATH_RESPONSE
      && f->type != GQ_FRAME_NEW_CONNECTION_ID)
    x->nonprobing = 1;
  if (sp != SP_APP && f->type != GQ_FRAME_PADDING && f->type != GQ_FRAME_PING
      && f->type != GQ_FRAME_ACK && f->type != GQ_FRAME_CRYPTO
      && f->type != GQ_FRAME_CONNECTION_CLOSE)
    {
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "frame not allowed here");
      return 1;
    }
  /* RFC 9000 sections 12.4 and 12.5: only the transport kind of
     CONNECTION_CLOSE (0x1c) is allowed in Initial and Handshake packets.  */
  if (sp != SP_APP && f->type == GQ_FRAME_CONNECTION_CLOSE
      && f->u.connection_close.application)
    {
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "frame not allowed here");
      return 1;
    }
  if (c->rx_early
      && (f->type == GQ_FRAME_ACK || f->type == GQ_FRAME_CRYPTO
          || f->type == GQ_FRAME_NEW_TOKEN
          || f->type == GQ_FRAME_PATH_RESPONSE
          || f->type == GQ_FRAME_HANDSHAKE_DONE))
    {
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "frame not allowed in 0-RTT");
      return 1;
    }
  switch (f->type)
    {
    case GQ_FRAME_PADDING:
    case GQ_FRAME_PING:
      /* A PING in Initial, before the handshake finishes, is the client's
         probe: its timer ran out without hearing from this server.  */
      if (f->type == GQ_FRAME_PING && c->role == GQ_ROLE_SERVER
          && sp == SP_INITIAL && !c->handshake_complete)
        c->client_probed = 1;
      return 0;
    case GQ_FRAME_PATH_RESPONSE:
      conn_path_on_response (c, f->u.path_challenge.data, c->now);
      return 0;
    case GQ_FRAME_ACK:
      if (f->u.ack.largest >= c->sp[sp].next_pn)
        {
          conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "ACK of unsent packet");
          return 1;
        }
      process_ack (c, sp, f, c->now);
      return 0;
    case GQ_FRAME_CRYPTO:
      {
        crypto_user u;
        int r;

        u.c = c;
        u.level = sp == SP_INITIAL ? GQ_LEVEL_INITIAL
                : sp == SP_HANDSHAKE ? GQ_LEVEL_HANDSHAKE
                : GQ_LEVEL_APPLICATION;
        c->pkt_crypto = 1;
        /* A ClientHello the server has already seen, said again, is the
           same probe as a PING: quic-go retransmits it without one.  */
        if (c->role == GQ_ROLE_SERVER && sp == SP_INITIAL
            && !c->handshake_complete)
          {
            uint64_t end = f->u.crypto.offset + f->u.crypto.data.len;

            if (end <= c->initial_crypto_end)
              c->client_probed = 1;
            if (end > c->initial_crypto_end)
              c->initial_crypto_end = end;
          }
        if (c->sp[sp].discarded || c->tls == NULL)
          return 0;
        r = gq_rstream_push (&c->sp[sp].cr, f->u.crypto.offset,
                             f->u.crypto.data.data, f->u.crypto.data.len, 0,
                             crypto_deliver, &u, NULL);
        if (r == GQ_ERR_FLOW)
          conn_fail (c, GQ_QERR_CRYPTO_BUFFER, "CRYPTO data too far ahead");
        else if (r == GQ_ERR_HANDLER)
          ;			/* crypto_deliver already failed us.  */
        else if (r != GQ_OK)
          conn_fail (c, GQ_QERR_INTERNAL, "CRYPTO frame failed");
        return c->state >= GQ_CONN_CLOSING;
      }
    case GQ_FRAME_NEW_TOKEN:
      if (c->role == GQ_ROLE_SERVER)
        {
          conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "client sent NEW_TOKEN");
          return 1;
        }
      if (c->ev.new_token)
        c->ev.new_token (c->ev.user, f->u.new_token.token.data,
                         f->u.new_token.token.len);
      return 0;
    case GQ_FRAME_HANDSHAKE_DONE:
      if (c->role == GQ_ROLE_SERVER)
        {
          conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION,
                     "client sent HANDSHAKE_DONE");
          return 1;
        }
      conn_maybe_confirm (c);
      return 0;
    case GQ_FRAME_NEW_CONNECTION_ID:
      return cid_store (c, f);
    case GQ_FRAME_RETIRE_CONNECTION_ID:
      return cid_retire (c, f->u.retire_connection_id.seq);
    case GQ_FRAME_PATH_CHALLENGE:
      conn_path_on_challenge (c, f->u.path_challenge.data);
      return 0;
    case GQ_FRAME_CONNECTION_CLOSE:
      {
        gq_conn_close_info info;

        memset (&info, 0, sizeof info);
        info.source = GQ_CLOSE_PEER;
        info.application = f->u.connection_close.application;
        info.error = f->u.connection_close.error;
        info.frame_type = f->u.connection_close.frame_type;
        info.reason = f->u.connection_close.reason.data;
        info.reason_len = f->u.connection_close.reason.len;
        x->closing = 1;
        /* Handshake (and Initial) can only send APPLICATION_ERROR for an
           application close.  The code itself follows in the 1-RTT packet
           of this datagram; remember this until the datagram is done.
           The reason is copied: a replayed packet is freed first.
           Return 0 so parsing this packet is not a handler failure:
           the connection is not closing until the datagram has been read.  */
        if ((!info.application && info.error == GQ_QERR_APPLICATION
             && !c->rx_close_set)
            || (info.application && c->rx_close_set
                && !c->rx_close.application))
          {
            size_t n = info.reason_len;

            if (n > sizeof c->rx_close_reason)
              n = sizeof c->rx_close_reason;
            if (n && info.reason)
              memcpy (c->rx_close_reason, info.reason, n);
            info.reason_len = n;
            info.reason = (const uint8_t *) c->rx_close_reason;
            c->rx_close = info;
            c->rx_close_set = 1;
            return 0;
          }
        c->rx_close_set = 0;
        conn_enter_closing (c, &info, 1);
        return 1;
      }
    case GQ_FRAME_DATAGRAM:
      /* Only if we said we would take them, and not bigger than promised
         (RFC 9221 section 4).  */
      if (c->cfg.max_datagram_frame_size == 0
          || 1 + f->u.datagram.data.len > c->cfg.max_datagram_frame_size)
        {
          conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "unexpected DATAGRAM");
          return 1;
        }
      c->datagrams_received++;
      ql_datagram_moved (c, "transport", "application",
                         f->u.datagram.data.len);
      if (c->ev.datagram)
        c->ev.datagram (c->ev.user, f->u.datagram.data.data,
                        f->u.datagram.data.len);
      return c->state >= GQ_CONN_CLOSING;
    default:
      return stream_handle_frame (c, f);
    }
}

/* Returns 0 if the connection can go on, -1 if it must stop.  */
static int
process_payload (gq_conn *c, int sp, const uint8_t *p, size_t n, int *ae,
                 int *nonprobing)
{
  rctx x;
  int r;

  x.c = c;
  x.sp = sp;
  x.ae = 0;
  x.nonprobing = 0;
  x.closing = 0;
  if (n == 0)
    {
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "empty packet");
      return -1;
    }
  r = gq_frame_parse (&p, &n, on_frame, &x);
  *ae = x.ae;
  if (nonprobing)
    *nonprobing = x.nonprobing;
  if (c->state >= GQ_CONN_CLOSING)
    return -1;
  if (r == GQ_ERR_ENCODING || r == GQ_NEED_MORE)
    {
      conn_fail (c, GQ_QERR_FRAME_ENCODING, "malformed frame");
      return -1;
    }
  if (r != GQ_OK)
    {
      conn_fail (c, GQ_QERR_INTERNAL, "frame handler failed");
      return -1;
    }
  return 0;
}

/* ---- Packet acceptance ---- */

/* The index of ECN codepoint ECN in the counts: ECT(0), ECT(1), CE.  */
static int
ecn_slot (int ecn)
{
  return ecn == GQ_ECN_ECT0 ? 0 : ecn == GQ_ECN_ECT1 ? 1 : 2;
}

static void
note_received (gq_conn *c, int sp, uint64_t pn, int ae, uint64_t now)
{
  space *s = &c->sp[sp];
  int gap = s->have_recv && pn != s->largest_recv + 1;

  gq_ranges_add (&s->recv, pn, pn + 1, 1);
  if (s->recv.n >= s->recv.max)
    s->recv_floor = s->recv.r[0].lo;
  if (!s->have_recv || pn > s->largest_recv)
    {
      s->largest_recv = pn;
      s->largest_recv_time = now;
      s->have_recv = 1;
    }
  c->st.packets_received++;
  c->idle_send_reset = 0;
  conn_recompute_idle (c, now);
  /* RFC 9000 section 13.4.1: count the codepoint of each packet processed,
     per space, for the ACK frames.  Not-ECT has no count.  */
  if (c->rx_ecn == GQ_ECN_ECT0 || c->rx_ecn == GQ_ECN_ECT1
      || c->rx_ecn == GQ_ECN_CE)
    {
      s->ecn_in[ecn_slot (c->rx_ecn)]++;
      c->ecn_in[ecn_slot (c->rx_ecn)]++;
    }
  if (!ae)
    return;
  /* The server keeps Handshake keys to read a late packet, and does not
     acknowledge it: the peer has dropped its own keys.  */
  if (sp == SP_HANDSHAKE && c->role == GQ_ROLE_SERVER && c->handshake_confirmed)
    return;
  s->ack_pending = 1;
  s->ae_since_ack++;
  /* A packet marked CE is acknowledged at once, so the peer hears of the
     congestion as soon as it can (section 13.2.1).  */
  if (sp != SP_APP || gap || s->ae_since_ack >= 2 || c->rx_ecn == GQ_ECN_CE)
    s->ack_now = 1;
  else if (s->ack_deadline == 0)
    s->ack_deadline = now + 25000;
}

static int
is_our_cid (const gq_conn *c, const uint8_t *cid, size_t len)
{
  size_t i;

  for (i = 0; i < MAX_LCID; i++)
    if (c->l[i].used && c->l[i].cid.len == len
        && memcmp (c->l[i].cid.data, cid, len) == 0)
      return 1;
  return 0;
}

static int
stateless_reset_check (gq_conn *c, const uint8_t *data, size_t len)
{
  if (len < GQ_STATELESS_RESET_MIN_LEN)
    return 0;
  if (conn_reset_token_live (c, data + len - GQ_RESET_TOKEN_LEN))
    {
      gq_conn_close_info info;

      memset (&info, 0, sizeof info);
      info.source = GQ_CLOSE_RESET;
      conn_enter_closing (c, &info, 1);
      return 1;
    }
  return 0;
}

/* ---- Packets that came before their keys (RFC 9001 section 5.7) ---- */

/* Keep the packet PKT (LEN bytes, of the datagram of DGRAM) of KIND, which
   cannot be read yet, to be tried again when the keys come.  Q is what the
   log is told of its header.  Returns 1 if it is held; 0 if packets are not
   held at all, 2 if the limit has been reached: the caller drops it.  A
   packet only gets here once its connection IDs are plausible.  */
static int
hold (gq_conn *c, uint64_t now, int kind, const uint8_t *pkt, size_t len,
      size_t dgram, const qlog_hdr *q)
{
  held_pkt *h;

  if (c->cfg.max_buffered_packets <= 0 || c->replaying)
    return 0;
  if (c->n_held >= (unsigned) c->cfg.max_buffered_packets)
    return 2;
  if (c->n_held == c->cap_held)
    {
      unsigned cap = c->cap_held ? c->cap_held * 2 : 4;
      held_pkt *nv = realloc (c->held, cap * sizeof *nv);

      if (nv == NULL)
        return 2;
      c->held = nv;
      c->cap_held = cap;
    }
  h = &c->held[c->n_held];
  memset (h, 0, sizeof *h);
  h->d = malloc (len);
  if (h->d == NULL)
    return 2;
  memcpy (h->d, pkt, len);
  h->len = len;
  h->dgram = dgram;
  h->at = now;
  h->dgram_id = c->ql.dgram_id;
  h->kind = (uint8_t) kind;
  h->ecn = c->rx_ecn;
  if (c->rx_known)
    {
      h->from = c->rx;
      h->has_from = 1;
    }
  c->n_held++;
  c->packets_buffered++;
  ql_packet_buffered (c, q, len);
  return 1;
}

/* What to say of a held packet that is let go: the header is not read.  */
static void
drop_held (gq_conn *c, const held_pkt *h, const char *trigger)
{
  qlog_hdr q;

  if (!QLOG_ON (c, QE_PACKET_DROPPED))
    return;
  memset (&q, 0, sizeof q);
  q.type = h->kind == HELD_APP ? "1RTT" : h->kind == HELD_EARLY ? "0RTT"
                                                               : "handshake";
  c->ql.dgram_id = h->dgram_id;
  ql_packet_dropped (c, &q, h->len, trigger);
}

/* The keys for packets of KIND will not come (0: all kinds): let them go.  */
void
conn_held_drop (gq_conn *c, int kind)
{
  unsigned i = 0;

  while (i < c->n_held)
    {
      held_pkt *h = &c->held[i];

      if (kind && h->kind != kind)
        {
          i++;
          continue;
        }
      drop_held (c, h, "key_unavailable");
      free (h->d);
      memmove (h, h + 1, (c->n_held - i - 1) * sizeof *h);
      c->n_held--;
    }
}

void
conn_held_free (gq_conn *c)
{
  unsigned i;

  for (i = 0; i < c->n_held; i++)
    free (c->held[i].d);
  free (c->held);
  c->held = NULL;
  c->n_held = c->cap_held = 0;
}

/* Client: a Retry packet (RFC 9000 section 17.2.5).  Restart the Initial
   flight with the server's token and connection ID.  */
static int
recv_retry (gq_conn *c, const gq_long_header *h, const uint8_t *pkt, size_t len)
{
  space *s = &c->sp[SP_INITIAL];
  gq_packet_keys ck, sk;
  size_t i;

  if (c->role != GQ_ROLE_CLIENT || c->got_peer_packet || c->retried
      || h->version != c->version || h->token.len == 0
      || h->token.len > sizeof c->token || h->scid.len == 0
      || !is_our_cid (c, h->dcid.data, h->dcid.len)
      || s->discarded)
    return 0;
  /* RFC 9000 section 17.2.5.2: a Retry must name another ID than the one the
     Initial it answers was sent to.  */
  if (h->scid.len == c->initial_dcid.len
      && memcmp (h->scid.data, c->initial_dcid.data, h->scid.len) == 0)
    return 0;
  if (gq_retry_verify (h, pkt, len, c->initial_dcid.data,
                       c->initial_dcid.len) != GQ_OK)
    return 0;
  if (gq_packet_keys_initial (c->version, h->scid.data, h->scid.len, &ck, &sk)
      != GQ_OK)
    return 0;
  c->retried = 1;
  memcpy (c->token, h->token.data, h->token.len);
  c->token_len = h->token.len;
  c->dcid.len = c->retry_scid.len = c->initial_dcid.len = (uint8_t) h->scid.len;
  memcpy (c->dcid.data, h->scid.data, h->scid.len);
  c->retry_scid = c->dcid;
  c->initial_dcid = c->dcid;
  c->p[0].cid = c->dcid;
  s->wk = ck;
  s->rk = sk;
  /* Everything sent so far goes out again under the new keys.  */
  for (i = 0; i < s->n_sent; i++)
    requeue_frames (c, SP_INITIAL, &s->sent[i]);
  sp_sent_clear (c, SP_INITIAL);
  s->probes = 0;
  s->loss_time = 0;
  c->pto_count = 0;
  /* The server discarded 0-RTT as well.  Send it again as 0-RTT, and do
     not leave it counting against the window until loss detection, which
     would be after the handshake and so at 1-RTT.  */
  conn_discard_early_sent (c);
  return 1;
}

/* Client: a Version Negotiation packet (RFC 9000 section 6.2).  Genuine
   ones echo our connection IDs and do not list the version we used.  */
static int
recv_vn (gq_conn *c, const gq_long_header *h)
{
  size_t i, j, n = gq_vn_count (h);
  uint32_t pick = 0;

  if (c->role != GQ_ROLE_CLIENT || c->got_peer_packet || c->vn_received
      || c->retried || h->dcid.len != c->scid_first.len
      || memcmp (h->dcid.data, c->scid_first.data, h->dcid.len)
      || h->scid.len != c->initial_dcid.len
      || memcmp (h->scid.data, c->initial_dcid.data, h->scid.len))
    return 0;
  for (i = 0; i < n; i++)
    if (gq_vn_get (h, i) == c->version)
      return 0;			/* Cannot be a real one.  */
  for (i = 0; i < c->cfg.n_versions && !pick; i++)
    for (j = 0; j < n; j++)
      if (gq_vn_get (h, j) == c->cfg.versions[i]
          && gq_version_supported (c->cfg.versions[i]))
        {
          pick = c->cfg.versions[i];
          break;
        }
  if (pick == 0)
    {
      conn_abandon (c, GQ_QERR_VERSION_NEGOTIATION, "no common version");
      return 1;
    }
  if (conn_client_restart (c, pick) != GQ_OK)
    conn_abandon (c, GQ_QERR_INTERNAL, "cannot restart");
  return 1;
}

static int count_failed (gq_conn *c);

/* Server: a 0-RTT packet (RFC 9001 section 4.6).  It is a packet of the
   application data space, protected with the early keys the handshake
   engine derived from the resumption ticket.  */
static int
recv_early (gq_conn *c, uint64_t now, uint8_t *pkt, const gq_long_header *h)
{
  space *s = &c->sp[SP_APP];
  uint64_t pn;
  size_t poff, plen;
  int r, ae, nonprobing = 0;

  if (c->role != GQ_ROLE_SERVER || !c->have_early_rk || c->switched
      || h->version != c->version || s->discarded)
    {
      drop_long (c, h, c->have_early_rk ? "rejected" : "key_unavailable");
      return 0;
    }
  if (c->handshake_complete && now > c->early_rk_deadline)
    {
      /* The window for stragglers has passed.  */
      ql_key_discarded (c, GQ_LEVEL_EARLY, GQ_DIR_READ, 0, 0, NULL);
      c->have_early_rk = 0;
      gq_packet_keys_wipe (&c->early_rk);
      drop_long (c, h, "key_unavailable");
      return 0;
    }
  /* Until the client hears from us it addresses us by the ID it invented.  */
  if (!(is_our_cid (c, h->dcid.data, h->dcid.len)
        || (h->dcid.len == c->initial_dcid.len
            && memcmp (h->dcid.data, c->initial_dcid.data, h->dcid.len) == 0))
      || h->scid.len != c->dcid.len
      || memcmp (h->scid.data, c->dcid.data, h->scid.len))
    {
      drop_long (c, h, "connection_unknown");
      return 0;
    }
  r = gq_packet_open (&c->early_rk, s->have_recv, s->largest_recv, pkt,
                      h->packet_len, h->pn_offset, &pn, &poff, &plen);
  if (r == GQ_ERR_ENCODING)
    {
      drop_long (c, h, "invalid");
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "reserved bits set");
      return 1;
    }
  if (r != GQ_OK)
    {
      drop_long (c, h, "decryption_failure");
      /* RFC 9001 section 6.6: counted across all keys, like the others.  */
      return r == GQ_ERR_CRYPTO && count_failed (c);
    }
  if (pn < s->recv_floor || gq_ranges_contains (&s->recv, pn))
    {
      drop_long (c, h, "duplicate");
      return 1;
    }
  ql_rx_cid (c, h->dcid.data, h->dcid.len);
  log_long (c, h, pkt, pn, poff, plen);
  c->rx_early = 1;
  r = process_payload (c, SP_APP, pkt + poff, plen, &ae, &nonprobing);
  c->rx_early = 0;
  if (r != 0)
    return 1;
  note_received (c, SP_APP, pn, ae, now);
  return 1;
}

/* RFC 9001 section 6.6: packets that fail authentication are counted for the
   whole connection; past the integrity limit of the AEAD the connection is
   closed.  Returns 1 if it was.  */
static int
count_failed (gq_conn *c)
{
  const space *s = &c->sp[SP_APP];
  uint64_t limit = s->have_rk && s->rk.aead == GQ_AEAD_CHACHA20_POLY1305
    ? (uint64_t) 1 << 36 : (uint64_t) 1 << 52;

  if (++c->aead_failed < limit)
    return 0;
  conn_fail (c, GQ_QERR_AEAD_LIMIT, "AEAD integrity limit reached");
  return 1;
}

/* Handle one long-header packet.  *USED is the number of bytes it took
   (0: stop, the rest of the datagram is unusable).  Returns 1 if a packet
   was processed.  */
static int
recv_long (gq_conn *c, uint64_t now, uint8_t *pkt, size_t rem, size_t dgram,
           size_t *used)
{
  gq_long_header h;
  space *s;
  int sp, r, ae, adopt = 0, future = 0;
  uint64_t pn;
  size_t poff, plen;
  gq_packet_keys ck, sk;
  const gq_packet_keys *rk = NULL;

  *used = 0;
  r = gq_long_header_parse (pkt, rem, &h);
  if (r != GQ_OK)
    {
      if (QLOG_ON (c, QE_PACKET_DROPPED))
        {
          qlog_hdr q;

          memset (&q, 0, sizeof q);
          q.type = "unknown";
          if (r == GQ_ERR_UNSUPPORTED)
            {
              long_hdr (&q, &h);
              q.type = "unknown";
            }
          ql_packet_dropped (c, &q, rem,
                             r == GQ_ERR_UNSUPPORTED ? "unsupported"
                                                     : "invalid");
        }
      return 0;
    }
  *used = h.packet_len;
  if (h.type == GQ_PKT_VERSION_NEGOTIATION)
    {
      int ok = recv_vn (c, &h);

      if (!ok)
        drop_long (c, &h, "invalid");
      else if (QLOG_ON (c, QE_PACKET_RECEIVED))
        {
          uint32_t vn[32];
          size_t i, n = gq_vn_count (&h);
          qlog_hdr q;

          if (n > 32)
            n = 32;
          for (i = 0; i < n; i++)
            vn[i] = gq_vn_get (&h, i);
          long_hdr (&q, &h);
          ql_packet_received (c, &q, h.packet_len, NULL, 0, 0, vn, n, NULL);
        }
      return ok;
    }
  if (h.version != c->version)
    {
      /* Only Initial packets may differ, and only during a compatible
         version negotiation: a server still hears the client's first
         version until the client has switched, and a client hears the
         server's new one once.  */
      if (h.type == GQ_PKT_HANDSHAKE && c->role == GQ_ROLE_CLIENT
          && !c->switched && !c->sp[SP_HANDSHAKE].have_rk
          && conn_version_listed (c, h.version)
          && conn_version_compatible (c->version, h.version)
          && gq_version_supported (h.version))
        future = 1;	/* Ahead of the Initial that moves us to it.  */
      else if (h.type != GQ_PKT_INITIAL)
        {
          drop_long (c, &h, "unsupported");
          return 0;
        }
      else if (c->role == GQ_ROLE_SERVER)
        {
          if (!c->got_first_initial && gq_version_supported (h.version)
              && conn_version_listed (c, h.version))
            ;	/* Trial keys use h.version; commit after decrypt.  */
          else if (!c->switched || h.version != c->orig_version
                   || !c->have_orig_rk)
            {
              drop_long (c, &h, "unsupported");
              return 0;
            }
          else
            rk = &c->orig_rk;
        }
      else if (c->switched || c->sp[SP_HANDSHAKE].have_rk
               || !conn_version_listed (c, h.version)
               || !conn_version_compatible (c->version, h.version)
               || !gq_version_supported (h.version)
               || gq_packet_keys_initial (h.version, c->initial_dcid.data,
                                          c->initial_dcid.len, &ck, &sk)
                  != GQ_OK)
        {
          drop_long (c, &h, "unsupported");
          return 0;
        }
      else
        {
          rk = &sk;
          adopt = 1;
        }
    }
  if (h.type == GQ_PKT_RETRY)
    {
      int ok = recv_retry (c, &h, pkt, h.packet_len);

      if (!ok)
        drop_long (c, &h, "invalid");
      else if (QLOG_ON (c, QE_PACKET_RECEIVED))
        {
          qlog_hdr q;

          long_hdr (&q, &h);
          ql_packet_received (c, &q, h.packet_len, NULL, 0, 0, NULL, 0, NULL);
        }
      return ok;
    }
  if (h.type == GQ_PKT_ZERO_RTT)
    {
      if (c->role == GQ_ROLE_SERVER && !c->have_early_rk
          && !c->handshake_complete && !c->switched)
        {
          /* It came before the ClientHello that gives the keys for it, or
             the Initial that has it (or the rest of it).  */
          qlog_hdr q;
          int k;

          long_hdr (&q, &h);
          k = hold (c, now, HELD_EARLY, pkt, h.packet_len, dgram, &q);
          if (k != 1)
            drop_long (c, &h, k ? "rejected" : "key_unavailable");
          return k == 1;
        }
      return recv_early (c, now, pkt, &h);
    }
  if (h.type != GQ_PKT_INITIAL && h.type != GQ_PKT_HANDSHAKE)
    {
      drop_long (c, &h, "invalid");
      return 0;
    }
  /* RFC 9000 section 17.2.2: a server sends no token in an Initial, and a
     client that receives one discards the packet.  */
  if (c->role == GQ_ROLE_CLIENT && h.type == GQ_PKT_INITIAL && h.token.len)
    {
      drop_long (c, &h, "invalid");
      return 0;
    }
  sp = h.type == GQ_PKT_INITIAL ? SP_INITIAL : SP_HANDSHAKE;
  if (c->role == GQ_ROLE_SERVER && sp == SP_INITIAL && !c->got_first_initial)
    {
      uint32_t serve_ver = c->version;

      if (dgram < GQ_MIN_INITIAL_DATAGRAM || h.dcid.len < 8)
        {
          drop_long (c, &h, "invalid");
          return 0;
        }
      if (h.version != c->version && gq_version_supported (h.version)
          && conn_version_listed (c, h.version))
        serve_ver = h.version;
      if (conn_server_initial_keys (c, serve_ver, h.dcid.data, h.dcid.len)
          != GQ_OK)
        {
          drop_long (c, &h, "key_unavailable");
          return 0;
        }
    }
  if (c->role == GQ_ROLE_SERVER && !c->got_first_initial)
    {
      /* A Handshake packet ahead of the Initial that starts us.  */
      qlog_hdr q;
      int k = 0;

      if (sp == SP_HANDSHAKE)
        {
          long_hdr (&q, &h);
          k = hold (c, now, HELD_HANDSHAKE, pkt, h.packet_len, dgram, &q);
        }
      if (k != 1)
        drop_long (c, &h, k == 2 ? "rejected" : sp == SP_HANDSHAKE
                   ? "key_unavailable" : "invalid");
      return k == 1;
    }
  s = &c->sp[sp];
  if (s->discarded)
    {
      drop_long (c, &h, "key_unavailable");
      return 0;
    }
  if (!is_our_cid (c, h.dcid.data, h.dcid.len)
      && !(c->role == GQ_ROLE_SERVER && sp == SP_INITIAL
           && h.dcid.len == c->initial_dcid.len
           && memcmp (h.dcid.data, c->initial_dcid.data, h.dcid.len) == 0))
    {
      drop_long (c, &h, "connection_unknown");
      return 0;
    }
  /* Until an Initial carrying CRYPTO settles it, a client accepts a new
     Source Connection ID on an Initial: a Retry's is provisional, and so
     is an acknowledgement-only Initial (RFC 9000 section 7.2).  */
  if (c->dcid_set
      && (c->role == GQ_ROLE_SERVER || c->got_peer_packet)
      && !(c->role == GQ_ROLE_CLIENT && sp == SP_INITIAL && !c->scid_settled)
      && (h.scid.len != c->dcid.len
          || memcmp (h.scid.data, c->dcid.data, h.scid.len)))
    {
      drop_long (c, &h, "invalid");
      return 0;
    }
  if (!s->have_rk || future)
    {
      /* The connection IDs are ours, so this is plausibly a packet for us
         that is ahead of its keys.  */
      qlog_hdr q;
      int k = 0;

      if (sp == SP_HANDSHAKE)
        {
          long_hdr (&q, &h);
          k = hold (c, now, HELD_HANDSHAKE, pkt, h.packet_len, dgram, &q);
        }
      if (k != 1)
        drop_long (c, &h, k == 2 ? "rejected" : "key_unavailable");
      return k == 1;
    }
  if (rk == NULL)
    rk = &s->rk;
  r = gq_packet_open (rk, s->have_recv, s->largest_recv, pkt, h.packet_len,
                      h.pn_offset, &pn, &poff, &plen);
  if (r == GQ_ERR_ENCODING)
    {
      drop_long (c, &h, "invalid");
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "reserved bits set");
      return 1;
    }
  if (r != GQ_OK)
    {
      if (c->role == GQ_ROLE_SERVER && sp == SP_INITIAL && !c->got_first_initial)
        conn_server_initial_abort (c);
      drop_long (c, &h, "decryption_failure");
      return r == GQ_ERR_CRYPTO && count_failed (c);
    }
  if (c->role == GQ_ROLE_SERVER && sp == SP_INITIAL && !c->got_first_initial)
    {
      if (h.version != c->version && gq_version_supported (h.version)
          && conn_version_listed (c, h.version))
        c->version = c->orig_version = h.version;
      if (conn_server_start (c, h.dcid.data, h.dcid.len, h.scid.data,
                             h.scid.len) != GQ_OK)
        {
          conn_server_initial_abort (c);
          drop_long (c, &h, "internal_error");
          conn_fail (c, GQ_QERR_INTERNAL, "cannot start handshake");
          return 0;
        }
      if (c->peer_addr_validated)
        ql_peer_validated (c);
    }
  if (pn < s->recv_floor || gq_ranges_contains (&s->recv, pn))
    {
      drop_long (c, &h, "duplicate");
      return 1;
    }
  if (adopt)
    {
      /* The server moved us to another compatible version: everything
         from here on uses it.  */
      c->orig_version = c->version;
      c->version = h.version;
      c->switched = 1;
      s->rk = sk;
      s->wk = ck;
    }
  c->got_peer_packet = 1;
  ql_rx_cid (c, h.dcid.data, h.dcid.len);
  if (sp == SP_HANDSHAKE)
    ql_handshake_started (c);
  log_long (c, &h, pkt, pn, poff, plen);
  {
    gq_packet_keys pre_wk;
    int nonprobing = 0, highest, arm = 0;

    /* RFC 9368 section 2.3: acknowledge the first Initial in the client's
       version before its frames reach TLS, which may switch the version
       in this same call.  The ACK goes out ahead of that flight.  */
    if (c->role == GQ_ROLE_SERVER && sp == SP_INITIAL && s->next_pn == 0
        && c->cfg.n_versions > 1 && !c->switched)
      {
        pre_wk = s->wk;
        arm = 1;
      }
    c->pkt_crypto = 0;
    highest = !s->have_recv || pn > s->largest_recv;
    if (process_payload (c, sp, pkt + poff, plen, &ae, &nonprobing) != 0)
      return 1;
    if (arm && c->switched && c->state < GQ_CONN_CLOSING)
      {
        c->lead_wk = pre_wk;
        c->lead_version = c->orig_version;
        c->lead_ack = 1;
      }
    /* Each server Initial that decrypts may move the destination
       connection ID; the first that carries CRYPTO settles it.  */
    if (c->role == GQ_ROLE_CLIENT && sp == SP_INITIAL && !c->scid_settled)
      {
        if (h.scid.len != c->dcid.len
            || memcmp (h.scid.data, c->dcid.data, c->dcid.len) != 0)
          {
            c->dcid.len = (uint8_t) h.scid.len;
            memcpy (c->dcid.data, h.scid.data, h.scid.len);
            c->p[0].cid = c->dcid;
          }
        if (c->pkt_crypto)
          c->scid_settled = 1;
      }
    note_received (c, sp, pn, ae, now);
    /* A Handshake packet after the handshake finished still decrypts
       until HANDSHAKE_DONE is acknowledged.  While the server is still on
       the path the handshake used, a new address on it is a migration like
       one on a 1-RTT packet.  After the server has moved, a late Handshake
       packet from the old address is not another migration.  */
    if (sp == SP_HANDSHAKE && c->role == GQ_ROLE_SERVER
        && c->handshake_confirmed && c->paths[c->cur_path].initial)
      conn_path_after_packet (c, now, nonprobing, highest);
  }
  if (c->role == GQ_ROLE_SERVER && sp == SP_HANDSHAKE)
    {
      /* The client has proven it can receive at its address, and has
         moved on from Initial keys.  */
      c->peer_addr_validated = 1;
      ql_peer_validated (c);
      conn_discard_space (c, SP_INITIAL);
    }
  return 1;
}

static int
recv_short (gq_conn *c, uint64_t now, uint8_t *pkt, size_t rem, size_t *used)
{
  gq_short_header h;
  space *s = &c->sp[SP_APP];
  const gq_packet_keys *keys;
  size_t pn_len, poff, plen, i;
  uint64_t trunc = 0, pn;
  int update = 0, ae, r, highest, nonprobing = 0;

  *used = rem;
  if (s->discarded)
    {
      drop_short (c, rem, "key_unavailable");
      return 0;
    }
  if (!s->have_rk)
    {
      /* Ahead of its keys, if it is for us.  */
      qlog_hdr q;
      int k = 0;

      if (gq_short_header_parse (pkt, rem, c->cfg.cid_len, &h) != GQ_OK)
        {
          drop_short (c, rem, "invalid");
          return 0;
        }
      if (!is_our_cid (c, h.dcid.data, h.dcid.len))
        {
          drop_short (c, rem, "connection_unknown");
          return 0;
        }
      memset (&q, 0, sizeof q);
      q.type = "1RTT";
      k = hold (c, now, HELD_APP, pkt, rem, rem, &q);
      if (k != 1)
        drop_short (c, rem, k == 2 ? "rejected" : "key_unavailable");
      return k == 1;
    }
  if (c->have_rk_prev && now >= c->rk_prev_until)
    {
      ql_key_discarded (c, GQ_LEVEL_APPLICATION, GQ_DIR_READ, 1,
                        c->ql.r_phase - 1, NULL);
      gq_packet_keys_wipe (&c->rk_prev);
      c->have_rk_prev = 0;
    }
  if (gq_short_header_parse (pkt, rem, c->cfg.cid_len, &h) != GQ_OK)
    {
      drop_short (c, rem, "invalid");
      return 0;
    }
  if (!is_our_cid (c, h.dcid.data, h.dcid.len))
    {
      drop_short (c, rem, "connection_unknown");
      return 0;
    }
  if (gq_hp_remove (&s->rk, pkt, rem, h.pn_offset, &pn_len) != GQ_OK)
    goto failed;
  for (i = 0; i < pn_len; i++)
    trunc = (trunc << 8) | pkt[h.pn_offset + i];
  pn = gq_pn_decode (s->have_recv, s->largest_recv, trunc, pn_len);
  {
    int phase = (pkt[0] >> 2) & 1;

    if (phase == c->r_phase)
      keys = &s->rk;
    else if (c->have_rk_prev && pn < c->r_first_pn)
      keys = &c->rk_prev;
    else if (c->have_rk_next)
      {
        keys = &c->rk_next;
        update = 1;
      }
    else
      goto failed;
  }
  r = gq_packet_decrypt (keys, pn, pkt, rem, h.pn_offset, pn_len, &poff,
                         &plen);
  if (r == GQ_ERR_ENCODING)
    {
      drop_short (c, rem, "invalid");
      conn_fail (c, GQ_QERR_PROTOCOL_VIOLATION, "reserved bits set");
      return 1;
    }
  if (r != GQ_OK)
    {
      if (r == GQ_ERR_CRYPTO && count_failed (c))
        return 1;
      goto failed;
    }
  if (pn < s->recv_floor || gq_ranges_contains (&s->recv, pn))
    {
      drop_short (c, rem, "duplicate");
      return 1;
    }
  if (update)
    rotate_read_keys (c, pn);
  c->got_peer_packet = 1;
  if (c->role == GQ_ROLE_SERVER && conn_path_rx_initial (c))
    {
      c->peer_addr_validated = 1;
      ql_peer_validated (c);
    }
  highest = !s->have_recv || pn > s->largest_recv;
  ql_rx_cid (c, h.dcid.data, h.dcid.len);
  if (QLOG_ON (c, QE_PACKET_RECEIVED))
    {
      qlog_hdr q;

      memset (&q, 0, sizeof q);
      q.type = "1RTT";
      q.have_pn = 1;
      q.pn = pn;
      q.pn_len = (unsigned) pn_len;
      q.have_key_phase = 1;
      q.key_phase = (pkt[0] >> 2) & 1;
      q.have_spin = 1;
      q.spin = (pkt[0] >> 5) & 1;
      q.have_dcid = 1;
      q.dcid = h.dcid.data;
      q.dcid_len = h.dcid.len;
      ql_packet_received (c, &q, rem, pkt + poff, plen,
                          c->rx_known ? c->cur_path : 0, NULL, 0, NULL);
    }
  if (process_payload (c, SP_APP, pkt + poff, plen, &ae, &nonprobing) != 0)
    return 1;
  note_received (c, SP_APP, pn, ae, now);
  conn_spin_received (c, (pkt[0] >> 5) & 1, highest);
  conn_cid_peer_using (c, h.dcid.data, h.dcid.len);
  conn_path_after_packet (c, now, nonprobing, highest);
  return 1;
failed:
  if (stateless_reset_check (c, pkt, rem))
    {
      if (QLOG_ON (c, QE_PACKET_RECEIVED))
        {
          qlog_hdr q;

          memset (&q, 0, sizeof q);
          q.type = "stateless_reset";
          ql_packet_received (c, &q, rem, NULL, 0, 0, NULL, 0,
                              pkt + rem - GQ_RESET_TOKEN_LEN);
        }
    }
  else
    drop_short (c, rem, "decryption_failure");
  return 0;
}

/* The keys that a datagram brought may be those that held packets were
   waiting for: read them, in the order they came and as of the time they
   came, as often as it takes (a Handshake packet can bring the 1-RTT keys).
   They are not counted again towards the amplification limit, which counted
   them when they arrived.  */
void
conn_replay_held (gq_conn *c)
{
  int progress;
  unsigned i;

  if (c->replaying || c->n_held == 0)
    return;
  c->replaying = 1;
  do
    {
      progress = 0;
      i = 0;
      while (i < c->n_held && c->state < GQ_CONN_CLOSING)
        {
          held_pkt h = c->held[i];
          int ready;
          size_t used;

          switch (h.kind)
            {
            case HELD_HANDSHAKE:
              ready = c->sp[SP_HANDSHAKE].have_rk
                      || c->sp[SP_HANDSHAKE].discarded;
              break;
            case HELD_EARLY:
              ready = c->have_early_rk || c->handshake_complete
                      || c->switched || c->state >= GQ_CONN_CLOSING;
              break;
            default:
              ready = c->sp[SP_APP].have_rk || c->sp[SP_APP].discarded;
              break;
            }
          if (!ready)
            {
              i++;
              continue;
            }
          memmove (&c->held[i], &c->held[i + 1],
                   (c->n_held - i - 1) * sizeof *c->held);
          c->n_held--;
          conn_path_rx_begin (c, h.has_from ? &h.from : NULL);
          c->rx_ecn = h.ecn;
          c->ql.dgram_id = h.dgram_id;
          c->ql.rx_trigger = "keys_available";
          if (h.kind == HELD_APP)
            recv_short (c, h.at, h.d, h.len, &used);
          else
            recv_long (c, h.at, h.d, h.len, h.dgram, &used);
          c->ql.rx_trigger = NULL;
          c->rx_ecn = -1;
          conn_path_rx_end (c);
          free (h.d);
          progress = 1;
        }
    }
  while (progress && c->state < GQ_CONN_CLOSING);
  c->replaying = 0;
  if (c->rx_close_set && c->state < GQ_CONN_CLOSING)
    {
      gq_conn_close_info info = c->rx_close;

      c->rx_close_set = 0;
      conn_enter_closing (c, &info, 1);
    }
  else
    c->rx_close_set = 0;
  if (c->state >= GQ_CONN_CLOSING)
    conn_held_free (c);
}

int
conn_receive_datagram (gq_conn *c, uint64_t now, uint8_t *data, size_t len)
{
  size_t off = 0;
  int any = 0;

  ql_rx_datagram (c, len);
  if (c->state == GQ_CONN_CLOSING)
    {
      /* Answer with the close again, but not for every packet.  */
      if (now - c->last_close_sent >= c->srtt)
        c->close_pending = 1;
      return GQ_OK;
    }
  while (off < len && c->state < GQ_CONN_CLOSING)
    {
      uint8_t *pkt = data + off;
      size_t rem = len - off, used = 0;
      int got;

      if (pkt[0] & 0x80)
        got = recv_long (c, now, pkt, rem, len, &used);
      else
        got = recv_short (c, now, pkt, rem, &used);
      if (got && !any)
        {
          any = 1;
          conn_path_account_recv (c, len);
          c->st.bytes_received += len;
        }
      if (used == 0)
        {
          if (off == 0)
            ql_datagram_dropped (c, len);
          break;
        }
      off += used;
    }
  if (c->client_probed && c->state < GQ_CONN_CLOSING)
    {
      c->client_probed = 0;
      conn_repeat_oldest (c, SP_INITIAL);
      conn_repeat_oldest (c, SP_HANDSHAKE);
    }
  if (c->rx_close_set && c->state < GQ_CONN_CLOSING)
    {
      gq_conn_close_info info = c->rx_close;

      c->rx_close_set = 0;
      conn_enter_closing (c, &info, 1);
    }
  else
    c->rx_close_set = 0;
  return GQ_OK;
}
