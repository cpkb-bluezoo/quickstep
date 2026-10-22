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

#include <quickstep/status.h>
#include <quickstep/record.h>
#include <quickstep/tlsconn.h>

#include "tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "tst-x509.h"
#include "tst-mldsa-cert.h"
#include "tst-tlspeer.h"

/* ---- Fixtures (one CA and server certificate) ---- */

static struct tst_cert ca, leaf;
static gq_privkey *server_key;
static uint8_t leaf_der[2048];
static size_t leaf_len;
static gq_trust *trust;

static void
setup_fixtures (void)
{
  gnutls_datum_t pem, d;

  CHECK_EQ (tst_make_cert (&ca, TST_ECDSA256, "Test CA", NULL, NULL, -3600,
                           86400, GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (tst_make_cert (&leaf, TST_ECDSA256, "example.test", "example.test",
                           &ca, -3600, 86400, GNUTLS_DIG_SHA256), 0);
  gnutls_x509_crt_export2 (leaf.crt, GNUTLS_X509_FMT_DER, &d);
  leaf_len = d.size;
  memcpy (leaf_der, d.data, d.size);
  gnutls_free (d.data);
  gnutls_x509_privkey_export2_pkcs8 (leaf.key, GNUTLS_X509_FMT_PEM, NULL,
                                     GNUTLS_PKCS_PLAIN, &pem);
  CHECK_EQ (gq_privkey_from_pem (&server_key, pem.data, pem.size), GQ_OK);
  gnutls_free (pem.data);
  CHECK_EQ (gq_trust_new (&trust), GQ_OK);
  gnutls_x509_crt_export2 (ca.crt, GNUTLS_X509_FMT_PEM, &pem);
  CHECK_EQ (gq_trust_add_pem (trust, pem.data, pem.size), GQ_OK);
  gnutls_free (pem.data);
}

/* ---- A growable byte string ---- */

struct bytes
{
  uint8_t *p;
  size_t n, cap;
};

static void
bytes_add (struct bytes *b, const uint8_t *d, size_t n)
{
  if (b->n + n > b->cap)
    {
      b->cap = (b->n + n) * 2 + 64;
      b->p = realloc (b->p, b->cap);
    }
  memcpy (b->p + b->n, d, n);
  b->n += n;
}

/* ---- Events from the connection under test ---- */

struct ev
{
  struct bytes wire;		/* What the client wrote.  */
  struct bytes app;		/* Application data it delivered.  */
  int connected;
  int closed, close_error, close_alert;
  int tickets;
};

static int
ev_write (void *u, const uint8_t *d, size_t n)
{
  bytes_add (&((struct ev *) u)->wire, d, n);
  return 0;
}

static int
ev_data (void *u, const uint8_t *d, size_t n)
{
  bytes_add (&((struct ev *) u)->app, d, n);
  return 0;
}

static int
ev_connected (void *u, const gq_tls_info *i)
{
  (void) i;
  ((struct ev *) u)->connected = 1;
  return 0;
}

static int
ev_ticket (void *u, const gq_tls_ticket *t)
{
  (void) t;
  ((struct ev *) u)->tickets++;
  return 0;
}

static void
ev_closed (void *u, int error, int alert)
{
  struct ev *e = u;

  e->closed++;
  e->close_error = error;
  e->close_alert = alert;
}

/* ---- The peer side: a record layer plus the scripted server ---- */

struct side
{
  gq_tlsconn *conn;
  struct ev ev;
  gq_tls_config cfg;
  gq_tlsconn_events events;
  struct tst_peer peer;
  gq_record rin, rout;		/* Peer's read and write protection.  */
  struct bytes to_client;	/* Bytes the peer is sending.  */
  /* What the peer decoded from the client.  */
  struct bytes app_in;
  struct bytes hs_in;
  int alerts_in[8][2];
  int n_alerts;
  int rekeys_seen;
};

static int
peer_on_record (void *u, unsigned type, const uint8_t *d, size_t n)
{
  struct side *s = u;

  if (type == GQ_CT_APPLICATION_DATA)
    bytes_add (&s->app_in, d, n);
  else if (type == GQ_CT_ALERT && n == 2 && s->n_alerts < 8)
    {
      s->alerts_in[s->n_alerts][0] = d[0];
      s->alerts_in[s->n_alerts][1] = d[1];
      s->n_alerts++;
    }
  else if (type == GQ_CT_HANDSHAKE)
    {
      /* KeyUpdate: ratchet the client's sending secret, and follow it.  */
      if (n == 5 && d[0] == GQ_HS_KEY_UPDATE)
        {
          uint8_t next[48];

          gq_traffic_secret_update (s->peer.hash, s->peer.cas, next);
          memcpy (s->peer.cas, next, s->peer.hlen);
          CHECK_EQ (gq_record_set_keys (&s->rin, GQ_DIR_READ, s->peer.aead,
                                        s->peer.cas, s->peer.hlen), GQ_OK);
          s->rekeys_seen++;
        }
      else
        bytes_add (&s->hs_in, d, n);
    }
  return 0;
}

/* Take everything the client wrote and decode it with the peer's reader.  */
static int
peer_read_client (struct side *s)
{
  uint8_t *copy;
  uint8_t *p;
  size_t l = s->ev.wire.n;
  int r;

  if (l == 0)
    return GQ_OK;
  copy = malloc (l);
  memcpy (copy, s->ev.wire.p, l);
  s->ev.wire.n = 0;
  p = copy;
  r = gq_record_receive (&s->rin, &p, &l, peer_on_record, s);
  CHECK (l == 0 || r == GQ_NEED_MORE);
  free (copy);
  return r;
}

static void
peer_write (struct side *s, unsigned type, const uint8_t *d, size_t n)
{
  uint8_t out[GQ_REC_MAX_RECORD];
  size_t k;

  while (n > 0 || type == GQ_CT_APPLICATION_DATA)
    {
      size_t c = n < GQ_REC_MAX_PLAINTEXT ? n : GQ_REC_MAX_PLAINTEXT;

      CHECK_EQ (gq_record_protect (&s->rout, type, d, c, 0, out, sizeof out,
                                   &k), GQ_OK);
      bytes_add (&s->to_client, out, k);
      d += c;
      n -= c;
      if (n == 0)
        break;
    }
}

/* Deliver the peer's pending bytes to the client in CHUNK-byte pieces.  */
static int
deliver (struct side *s, size_t chunk)
{
  size_t pos = 0;
  int r = GQ_OK;

  while (pos < s->to_client.n && r == GQ_OK)
    {
      size_t k = s->to_client.n - pos;

      if (chunk && k > chunk)
        k = chunk;
      r = gq_tlsconn_receive (s->conn, s->to_client.p + pos, k);
      pos += k;
    }
  s->to_client.n = 0;
  return r;
}

static struct side *
side_new (void)
{
  struct side *s = calloc (1, sizeof *s);

  s->cfg.server_name = "example.test";
  s->cfg.trust = trust;
  s->events.user = &s->ev;
  s->events.write = ev_write;
  s->events.data = ev_data;
  s->events.connected = ev_connected;
  s->events.ticket = ev_ticket;
  s->events.closed = ev_closed;
  s->peer.key = server_key;
  s->peer.chain[0] = (gq_slice) { leaf_der, leaf_len };
  s->peer.n_chain = 1;
  gq_record_init (&s->rin);
  gq_record_init (&s->rout);
  gq_record_allow_ccs (&s->rin, 1);
  s->ev.close_alert = -2;
  return s;
}

static void
side_free (struct side *s)
{
  gq_tlsconn_free (s->conn);
  if (s->peer.tr)
    gq_transcript_free (s->peer.tr);
  free (s->ev.wire.p);
  free (s->ev.app.p);
  free (s->to_client.p);
  free (s->app_in.p);
  free (s->hs_in.p);
  free (s);
}

/* Run the handshake.  RECORD_STYLE selects how the server flight is cut
   into records (0: one record for the whole flight, 1: one per message,
   2: at most 50 bytes per record).  */
static void
handshake (struct side *s, size_t chunk, int record_style)
{
  struct flight init, hs;
  static const uint8_t ccs = 1;
  int i;

  CHECK_EQ (gq_tlsconn_client_new (&s->conn, &s->cfg, &s->events), GQ_OK);
  CHECK_EQ (gq_tlsconn_start (s->conn), GQ_OK);
  CHECK_EQ (peer_read_client (s), GQ_OK);
  CHECK (s->hs_in.n > 4);
  CHECK_EQ (peer_handle_ch (&s->peer, s->hs_in.p, s->hs_in.n, &init, &hs),
            GQ_OK);
  s->hs_in.n = 0;

  /* ServerHello in the clear, compatibility CCS, then protected data.  */
  peer_write (s, GQ_CT_HANDSHAKE, init.data, init.used);
  peer_write (s, GQ_CT_CHANGE_CIPHER_SPEC, &ccs, 1);
  CHECK_EQ (gq_record_set_keys (&s->rout, GQ_DIR_WRITE, s->peer.aead,
                                s->peer.shs, s->peer.hlen), GQ_OK);
  CHECK_EQ (gq_record_set_keys (&s->rin, GQ_DIR_READ, s->peer.aead,
                                s->peer.chs, s->peer.hlen), GQ_OK);
  if (record_style == 0)
    peer_write (s, GQ_CT_HANDSHAKE, hs.data, hs.used);
  else if (record_style == 1)
    for (i = 0; i < hs.n; i++)
      peer_write (s, GQ_CT_HANDSHAKE, hs.data + hs.off[i], hs.len[i]);
  else
    {
      size_t pos;

      for (pos = 0; pos < hs.used; pos += 50)
        peer_write (s, GQ_CT_HANDSHAKE, hs.data + pos,
                    hs.used - pos < 50 ? hs.used - pos : 50);
    }
  CHECK_EQ (deliver (s, chunk), GQ_OK);
  CHECK (gq_tlsconn_is_connected (s->conn));
  CHECK (s->ev.connected);

  /* The client's Finished arrives after a CCS, encrypted; the peer checks
     it and switches to application keys.  */
  CHECK_EQ (peer_read_client (s), GQ_OK);
  CHECK_EQ (s->hs_in.n, 36);
  CHECK_EQ (peer_handle_client_flight (&s->peer, s->hs_in.p, s->hs_in.n),
            GQ_OK);
  s->hs_in.n = 0;
  CHECK_EQ (gq_record_set_keys (&s->rout, GQ_DIR_WRITE, s->peer.aead,
                                s->peer.sas, s->peer.hlen), GQ_OK);
  CHECK_EQ (gq_record_set_keys (&s->rin, GQ_DIR_READ, s->peer.aead,
                                s->peer.cas, s->peer.hlen), GQ_OK);
  gq_record_allow_ccs (&s->rin, 0);
}

static void
fill (uint8_t *b, size_t n, unsigned seed)
{
  size_t i;

  for (i = 0; i < n; i++)
    b[i] = (uint8_t) (seed + i * 31 + (i >> 8));
}

static void
test_handshake_and_data (size_t chunk, int style)
{
  struct side *s = side_new ();
  uint8_t msg[300000], back[300000];
  size_t n = 250000;

  handshake (s, chunk, style);

  /* Client to peer: small then large (many records).  */
  CHECK_EQ (gq_tlsconn_send (s->conn, (const uint8_t *) "hello", 5), GQ_OK);
  fill (msg, n, 1);
  CHECK_EQ (gq_tlsconn_send (s->conn, msg, n), GQ_OK);
  CHECK_EQ (peer_read_client (s), GQ_OK);
  CHECK_EQ (s->app_in.n, 5 + n);
  CHECK (memcmp (s->app_in.p, "hello", 5) == 0);
  CHECK (memcmp (s->app_in.p + 5, msg, n) == 0);

  /* Peer to client.  */
  fill (back, n, 9);
  peer_write (s, GQ_CT_APPLICATION_DATA, back, n);
  CHECK_EQ (deliver (s, chunk), GQ_OK);
  CHECK_EQ (s->ev.app.n, n);
  CHECK (memcmp (s->ev.app.p, back, n) == 0);
  CHECK (gq_tlsconn_read_seq (s->conn) > 10);

  /* A session ticket after the handshake.  */
  {
    static const uint8_t nonce[1] = { 1 }, ticket[4] = { 9, 8, 7, 6 };
    uint8_t buf[64];
    gq_wbuf w;

    gq_wbuf_init (&w, buf, sizeof buf);
    gq_build_new_session_ticket (&w, 100, 5, (gq_slice) { nonce, 1 },
                                 (gq_slice) { ticket, 4 }, NULL, 0);
    peer_write (s, GQ_CT_HANDSHAKE, buf, w.len);
    /* The peer's resumption secret is derived from the client Finished.  */
  }
  CHECK_EQ (deliver (s, chunk), GQ_OK);
  CHECK_EQ (s->ev.tickets, 1);

  /* Orderly shutdown: we send close_notify, peer answers, we are closed.  */
  CHECK_EQ (gq_tlsconn_close (s->conn), GQ_OK);
  CHECK_EQ (peer_read_client (s), GQ_OK);
  CHECK (s->n_alerts == 1 && s->alerts_in[0][0] == 1 && s->alerts_in[0][1] == 0);
  CHECK_EQ (s->ev.closed, 0);
  {
    static const uint8_t cn[2] = { 1, 0 };

    peer_write (s, GQ_CT_ALERT, cn, 2);
  }
  CHECK_EQ (deliver (s, chunk), GQ_OK);
  CHECK_EQ (s->ev.closed, 1);
  CHECK_EQ (s->ev.close_error, 0);
  CHECK (gq_tlsconn_is_closed (s->conn));
  CHECK_EQ (gq_tlsconn_send (s->conn, msg, 1), GQ_ERR_INVAL);
  side_free (s);
}

/* ---- Large flights: ML-DSA's sizes, over a byte stream ---- */

/* A client and a server connection, and what each has written for the
   other.  */
struct tc_end
{
  gq_tlsconn *c;
  struct bytes out, app;
  int connected, closed, err;
};

static int
tc_write (void *u, const uint8_t *d, size_t n)
{
  bytes_add (&((struct tc_end *) u)->out, d, n);
  return 0;
}

static int
tc_data (void *u, const uint8_t *d, size_t n)
{
  bytes_add (&((struct tc_end *) u)->app, d, n);
  return 0;
}

static int
tc_connected (void *u, const gq_tls_info *i)
{
  (void) i;
  ((struct tc_end *) u)->connected = 1;
  return 0;
}

static void
tc_closed (void *u, int error, int alert)
{
  struct tc_end *e = u;

  (void) alert;
  e->closed++;
  e->err = error;
}

/* Move what each side wrote to the other, CHUNK bytes at a time (0: all),
   until neither has anything to say.  Returns the first error.  */
static int
tc_run (struct tc_end *cl, struct tc_end *sv, size_t chunk)
{
  int r = GQ_OK;

  for (;;)
    {
      struct tc_end *from[2] = { cl, sv }, *to[2] = { sv, cl };
      int k, moved = 0;

      for (k = 0; k < 2 && r == GQ_OK; k++)
        {
          size_t off = 0, n = from[k]->out.n;
          uint8_t *copy;

          if (n == 0)
            continue;
          copy = malloc (n);
          memcpy (copy, from[k]->out.p, n);
          from[k]->out.n = 0;
          moved = 1;
          while (off < n && r == GQ_OK)
            {
              size_t m = chunk && n - off > chunk ? chunk : n - off;

              r = gq_tlsconn_receive (to[k]->c, copy + off, m);
              off += m;
            }
          free (copy);
        }
      if (!moved || r != GQ_OK)
        return r;
    }
}

/* One handshake over a stream with the chain CH (N certificates), the
   client taking messages of up to CLIENT_MAX bytes (0: the default), and
   fed in CHUNK byte pieces.  Returns the status of the exchange; on success
   data is exchanged each way to show the connection works.  */
static int
tc_flight (const struct tst_mlchain *ch, size_t client_max, size_t chunk)
{
  struct tc_end cl, sv;
  gq_tls_config cc;
  gq_tls_server_config sc;
  gq_tlsconn_events ce, se;
  static uint8_t msg[40000];
  int r;
  size_t i;

  memset (&cl, 0, sizeof cl);
  memset (&sv, 0, sizeof sv);
  memset (&cc, 0, sizeof cc);
  memset (&sc, 0, sizeof sc);
  memset (&ce, 0, sizeof ce);
  memset (&se, 0, sizeof se);
  cc.server_name = "example.test";
  cc.trust = trust;
  cc.max_message_len = client_max;
  sc.credentials.chain = ch->chain;
  sc.credentials.n_chain = 2;
  sc.credentials.key = ch->key;
  ce.user = &cl;
  se.user = &sv;
  ce.write = se.write = tc_write;
  ce.data = se.data = tc_data;
  ce.connected = se.connected = tc_connected;
  ce.closed = se.closed = tc_closed;
  CHECK_EQ (gq_tlsconn_client_new (&cl.c, &cc, &ce), GQ_OK);
  CHECK_EQ (gq_tlsconn_server_new (&sv.c, &sc, &se), GQ_OK);
  CHECK_EQ (gq_tlsconn_start (cl.c), GQ_OK);
  r = tc_run (&cl, &sv, chunk);
  if (r == GQ_OK)
    {
      CHECK (cl.connected && sv.connected);
      CHECK (gq_tlsconn_is_connected (cl.c) && gq_tlsconn_is_connected (sv.c));
      /* Data each way, after a handshake of several records.  */
      for (i = 0; i < sizeof msg; i++)
        msg[i] = (uint8_t) (i * 7);
      CHECK_EQ (gq_tlsconn_send (cl.c, msg, sizeof msg), GQ_OK);
      CHECK_EQ (gq_tlsconn_send (sv.c, msg, sizeof msg), GQ_OK);
      CHECK_EQ (tc_run (&cl, &sv, chunk), GQ_OK);
      CHECK (sv.app.n == sizeof msg && memcmp (sv.app.p, msg, sizeof msg) == 0);
      CHECK (cl.app.n == sizeof msg && memcmp (cl.app.p, msg, sizeof msg) == 0);
    }
  gq_tlsconn_free (cl.c);
  gq_tlsconn_free (sv.c);
  free (cl.out.p); free (cl.app.p); free (sv.out.p); free (sv.app.p);
  return r;
}

/* The Certificate message of the chain: 4 bytes of header, the request
   context (1), the list (3), and for each certificate its length (3), its
   bytes and its (empty) extensions (2).  */
static size_t
certificate_message_len (const struct tst_mlchain *ch)
{
  return 4 + 1 + 3 + (3 + ch->chain[0].len + 2) + (3 + ch->chain[1].len + 2);
}

static void
flights_over_tcp (int mode)
{
  static const unsigned schemes[] = { GQ_SIG_MLDSA44, GQ_SIG_MLDSA65,
                                      GQ_SIG_MLDSA87 };
  static const size_t chunks[] = { 0, 1460, 17, 1 };
  static struct tst_mlchain ch;
  size_t i, k, cert;

  for (i = 0; i < 3; i++)
    {
      CHECK_EQ (tst_make_mldsa_chain (&ch, schemes[i], &ca, "example.test",
                                      mode), 0);
      cert = certificate_message_len (&ch);
      /* The records hold 16 KiB, so the biggest of them spans two.  */
      for (k = 0; k < sizeof chunks / sizeof chunks[0]; k++)
        CHECK_EQ (tc_flight (&ch, 0, chunks[k]), GQ_OK);

      /* max_message_len is the length of the body of a message: the
         Certificate message just fits at its own length, and not at one
         less (illegal_parameter, section 4.2 of RFC 8446 not allowing a
         peer to be made to buffer more than it chose to).  */
      CHECK_EQ (tc_flight (&ch, cert - 4, 0), GQ_OK);
      CHECK_EQ (tc_flight (&ch, cert - 5, 0), GQ_ERR_PROTOCOL);
      CHECK_EQ (tc_flight (&ch, cert - 5, 1), GQ_ERR_PROTOCOL);
      tst_free_mldsa_chain (&ch);
    }
}

static void
test_flights_over_tcp (void)
{
  int real = tst_mldsa_ready (tst_gnutls_validates_mldsa (),
                              "the large flights with real ML-DSA keys");

  flights_over_tcp (TST_CHAIN_CLASSIC);
  if (real)
    flights_over_tcp (TST_CHAIN_ML);
}


static void
test_rekey_by_count (void)
{
  struct side *s = side_new ();
  uint8_t chunk[100];
  int i;
  size_t total = 0;

  s->events.rekey_records = 4;
  handshake (s, 0, 1);
  for (i = 0; i < 30; i++)
    {
      fill (chunk, sizeof chunk, (unsigned) i);
      CHECK_EQ (gq_tlsconn_send (s->conn, chunk, sizeof chunk), GQ_OK);
      total += sizeof chunk;
      CHECK_EQ (peer_read_client (s), GQ_OK);
      CHECK_EQ (s->app_in.n, total);
      CHECK (memcmp (s->app_in.p + total - sizeof chunk, chunk,
                     sizeof chunk) == 0);
    }
  /* Every four records the connection updated its keys, and the peer,
     following the ratchet, kept decrypting.  */
  CHECK (s->rekeys_seen >= 5);
  CHECK (gq_tlsconn_write_seq (s->conn) < 8);

  /* Explicit update asking the peer to follow: it is the peer that
     rekeys its own sending keys in response.  */
  CHECK_EQ (gq_tlsconn_key_update (s->conn, 1), GQ_OK);
  side_free (s);
}

/* RFC 8446 section 5.1: the messages before a key change must end their
   record, because what follows was protected under the keys that KeyUpdate
   retires.  A record carrying several KeyUpdates (3,000 fit in one) would
   otherwise be taken whole, each one rekeying both directions and each
   requesting one back, from a single record of the peer's.  */
static void
test_coalesced_key_updates (void)
{
  struct side *s;
  static const uint8_t one[5] = { GQ_HS_KEY_UPDATE, 0, 0, 1, 1 };
  uint8_t many[5 * 8];
  int i;

  /* One, asking for ours in return: answered once.  */
  s = side_new ();
  handshake (s, 0, 1);
  peer_write (s, GQ_CT_HANDSHAKE, one, sizeof one);
  CHECK_EQ (deliver (s, 0), GQ_OK);
  CHECK_EQ (s->ev.closed, 0);
  CHECK_EQ (peer_read_client (s), GQ_OK);
  CHECK_EQ (s->rekeys_seen, 1);
  side_free (s);

  /* Eight in one record: refused, unexpected_message, nothing answered.  */
  s = side_new ();
  handshake (s, 0, 1);
  for (i = 0; i < 8; i++)
    memcpy (many + 5 * i, one, sizeof one);
  peer_write (s, GQ_CT_HANDSHAKE, many, sizeof many);
  deliver (s, 0);
  CHECK_EQ (s->ev.closed, 1);
  CHECK_EQ (s->ev.close_error, GQ_ERR_PROTOCOL);
  CHECK_EQ (s->ev.close_alert, GQ_ALERT_UNEXPECTED_MESSAGE);
  peer_read_client (s);
  CHECK (s->rekeys_seen <= 1);
  side_free (s);

  /* Two, not asking for anything back: still more than one before the key
     change.  */
  s = side_new ();
  handshake (s, 0, 1);
  memcpy (many, one, sizeof one);
  memcpy (many + 5, one, sizeof one);
  many[4] = many[9] = 0;
  peer_write (s, GQ_CT_HANDSHAKE, many, 10);
  deliver (s, 0);
  CHECK_EQ (s->ev.closed, 1);
  CHECK_EQ (s->ev.close_alert, GQ_ALERT_UNEXPECTED_MESSAGE);
  side_free (s);
}

/* End of file on the transport is not the end of the data unless the peer
   said so with close_notify (RFC 8446 section 6.1): whoever can inject a FIN
   or a reset would otherwise cut what is read off, undetected.  */
/* RFC 8446 appendix D.4: a ChangeCipherSpec may come at any time after the
   first ClientHello has been sent or received, not before.  */
static void
test_ccs_before_the_hello (void)
{
  struct side *s = side_new ();
  static const uint8_t ccs[6] = { 20, 3, 3, 0, 1, 1 };

  CHECK_EQ (gq_tlsconn_client_new (&s->conn, &s->cfg, &s->events), GQ_OK);
  CHECK_EQ (gq_tlsconn_receive (s->conn, ccs, sizeof ccs), GQ_ERR_PROTOCOL);
  CHECK_EQ (s->ev.closed, 1);
  CHECK_EQ (s->ev.close_alert, GQ_ALERT_UNEXPECTED_MESSAGE);
  side_free (s);

  /* Once the hello is out the server may send it, as the compatibility
     mode of TLS 1.3 does.  */
  s = side_new ();
  CHECK_EQ (gq_tlsconn_client_new (&s->conn, &s->cfg, &s->events), GQ_OK);
  CHECK_EQ (gq_tlsconn_start (s->conn), GQ_OK);
  CHECK_EQ (gq_tlsconn_receive (s->conn, ccs, sizeof ccs), GQ_OK);
  CHECK_EQ (s->ev.closed, 0);
  side_free (s);
}

static void
test_transport_eof (void)
{
  struct side *s;
  static const uint8_t cn[2] = { 1, 0 };

  /* Data, then a FIN with no close_notify: truncation.  */
  s = side_new ();
  handshake (s, 0, 1);
  peer_write (s, GQ_CT_APPLICATION_DATA, (const uint8_t *) "part", 4);
  CHECK_EQ (deliver (s, 0), GQ_OK);
  CHECK_EQ (s->ev.app.n, 4);
  CHECK_EQ (gq_tlsconn_eof (s->conn), GQ_ERR_PROTOCOL);
  CHECK_EQ (s->ev.closed, 1);
  CHECK_EQ (s->ev.close_error, GQ_ERR_PROTOCOL);
  CHECK (gq_tlsconn_is_closed (s->conn));
  /* Said once.  */
  CHECK_EQ (gq_tlsconn_eof (s->conn), GQ_ERR_PROTOCOL);
  CHECK_EQ (s->ev.closed, 1);
  side_free (s);

  /* After the peer's close_notify it is the end.  */
  s = side_new ();
  handshake (s, 0, 1);
  peer_write (s, GQ_CT_ALERT, cn, 2);
  CHECK_EQ (deliver (s, 0), GQ_OK);
  CHECK_EQ (s->ev.closed, 1);
  CHECK_EQ (s->ev.close_error, 0);
  CHECK_EQ (gq_tlsconn_eof (s->conn), GQ_OK);
  CHECK_EQ (s->ev.closed, 1);
  side_free (s);

  /* Before the handshake is done.  */
  s = side_new ();
  CHECK_EQ (gq_tlsconn_client_new (&s->conn, &s->cfg, &s->events), GQ_OK);
  CHECK_EQ (gq_tlsconn_start (s->conn), GQ_OK);
  CHECK_EQ (gq_tlsconn_eof (s->conn), GQ_ERR_PROTOCOL);
  CHECK_EQ (s->ev.closed, 1);
  side_free (s);
}

static void
test_failures (void)
{
  struct side *s;
  uint8_t junk[64];
  int r;

  /* Tampered record after the handshake: bad_record_mac alert sent, and
     the connection closes with an error.  */
  s = side_new ();
  handshake (s, 0, 1);
  peer_write (s, GQ_CT_APPLICATION_DATA, (const uint8_t *) "data", 4);
  s->to_client.p[s->to_client.n - 3] ^= 1;
  r = deliver (s, 0);
  CHECK_EQ (r, GQ_ERR_CRYPTO);
  CHECK (s->ev.closed == 1 && s->ev.close_alert == 20);
  CHECK_EQ (peer_read_client (s), GQ_OK);
  CHECK (s->n_alerts == 1 && s->alerts_in[0][0] == 2
         && s->alerts_in[0][1] == 20);
  side_free (s);

  /* A fatal alert from the peer.  */
  s = side_new ();
  handshake (s, 0, 1);
  {
    static const uint8_t al[2] = { 2, 40 };

    peer_write (s, GQ_CT_ALERT, al, 2);
  }
  deliver (s, 0);
  CHECK (s->ev.closed == 1 && s->ev.close_error == GQ_ERR_PROTOCOL
         && s->ev.close_alert == 40);
  side_free (s);

  /* user_canceled is a closure alert, not an error (RFC 8446 section 6.1):
     the connection goes on, to the close_notify that should follow.  Any
     other alert is an error whatever its level field says (section 6: the
     level is implicit in the type), so a warning-level one ends it.  */
  s = side_new ();
  handshake (s, 0, 1);
  {
    static const uint8_t uc[2] = { 1, GQ_ALERT_USER_CANCELED };
    static const uint8_t un[2] = { 1, 112 };	/* unrecognized_name */

    peer_write (s, GQ_CT_ALERT, uc, 2);
    CHECK_EQ (deliver (s, 0), GQ_OK);
    CHECK_EQ (s->ev.closed, 0);
    CHECK (!gq_tlsconn_is_closed (s->conn));
    peer_write (s, GQ_CT_APPLICATION_DATA, (const uint8_t *) "data", 4);
    CHECK_EQ (deliver (s, 0), GQ_OK);
    CHECK_EQ (s->ev.app.n, 4);
    peer_write (s, GQ_CT_ALERT, un, 2);
    CHECK (deliver (s, 0) < 0 || s->ev.closed);
    CHECK (s->ev.closed == 1 && s->ev.close_error == GQ_ERR_PROTOCOL
           && s->ev.close_alert == 112);
  }
  side_free (s);

  /* The peer closes first: we answer close_notify.  */
  s = side_new ();
  handshake (s, 1, 1);
  {
    static const uint8_t cn[2] = { 1, 0 };

    peer_write (s, GQ_CT_ALERT, cn, 2);
  }
  CHECK_EQ (deliver (s, 1), GQ_OK);
  CHECK (s->ev.closed == 1 && s->ev.close_error == 0);
  CHECK_EQ (peer_read_client (s), GQ_OK);
  CHECK (s->n_alerts == 1 && s->alerts_in[0][1] == 0);
  side_free (s);

  /* Garbage instead of TLS: unexpected_message.  */
  s = side_new ();
  CHECK_EQ (gq_tlsconn_client_new (&s->conn, &s->cfg, &s->events), GQ_OK);
  CHECK_EQ (gq_tlsconn_start (s->conn), GQ_OK);
  memcpy (junk, "HTTP/1.1 400 Bad Request\r\n\r\n", 28);
  r = gq_tlsconn_receive (s->conn, junk, 28);
  CHECK_EQ (r, GQ_ERR_PROTOCOL);
  CHECK (s->ev.closed == 1 && s->ev.close_alert == 10);
  side_free (s);

  /* Application data before the handshake is finished.  */
  s = side_new ();
  CHECK_EQ (gq_tlsconn_client_new (&s->conn, &s->cfg, &s->events), GQ_OK);
  CHECK_EQ (gq_tlsconn_start (s->conn), GQ_OK);
  {
    static const uint8_t bad[6] = { 23, 3, 3, 0, 1, 9 };

    r = gq_tlsconn_receive (s->conn, bad, 6);
    CHECK (r != GQ_OK);
  }
  side_free (s);

  /* A bad server Finished: the engine's alert goes out under the
     handshake keys.  */
  s = side_new ();
  {
    struct flight init, hs;
    static const uint8_t ccs = 1;

    CHECK_EQ (gq_tlsconn_client_new (&s->conn, &s->cfg, &s->events), GQ_OK);
    CHECK_EQ (gq_tlsconn_start (s->conn), GQ_OK);
    CHECK_EQ (peer_read_client (s), GQ_OK);
    CHECK_EQ (peer_handle_ch (&s->peer, s->hs_in.p, s->hs_in.n, &init, &hs),
              GQ_OK);
    s->hs_in.n = 0;
    hs.data[hs.off[3] + hs.len[3] - 1] ^= 1;	/* Corrupt Finished.  */
    peer_write (s, GQ_CT_HANDSHAKE, init.data, init.used);
    peer_write (s, GQ_CT_CHANGE_CIPHER_SPEC, &ccs, 1);
    gq_record_set_keys (&s->rout, GQ_DIR_WRITE, s->peer.aead, s->peer.shs,
                        s->peer.hlen);
    gq_record_set_keys (&s->rin, GQ_DIR_READ, s->peer.aead, s->peer.chs,
                        s->peer.hlen);
    peer_write (s, GQ_CT_HANDSHAKE, hs.data, hs.used);
    r = deliver (s, 0);
    CHECK_EQ (r, GQ_ERR_CRYPTO);
    CHECK (s->ev.closed == 1 && s->ev.close_alert == 51);
    CHECK_EQ (peer_read_client (s), GQ_OK);
    CHECK (s->n_alerts == 1 && s->alerts_in[0][1] == 51);
  }
  side_free (s);

  /* QUIC configuration is not for stream use.  */
  {
    gq_tlsconn *c;
    gq_tls_config cfg;
    struct ev e;
    gq_tlsconn_events ev;

    memset (&cfg, 0, sizeof cfg);
    memset (&e, 0, sizeof e);
    memset (&ev, 0, sizeof ev);
    cfg.trust = trust;
    cfg.quic = 1;
    ev.user = &e;
    ev.write = ev_write;
    ev.data = ev_data;
    CHECK_EQ (gq_tlsconn_client_new (&c, &cfg, &ev), GQ_ERR_INVAL);
  }
}

int
main (void)
{
  setup_fixtures ();
  test_handshake_and_data (0, 0);
  test_handshake_and_data (1, 1);
  test_handshake_and_data (13, 2);
  test_rekey_by_count ();
  test_flights_over_tcp ();
  test_coalesced_key_updates ();
  test_ccs_before_the_hello ();
  test_transport_eof ();
  test_failures ();
  TST_DONE ();
}

#endif
