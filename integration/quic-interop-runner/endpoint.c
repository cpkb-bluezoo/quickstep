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

/* quickstep's endpoint for the quic-interop-runner
   (https://github.com/quic-interop/quic-interop-runner).  The runner starts
   a container with this program as a client or a server on either side of
   a network simulator and drives it only through the environment:

     ROLE         "client" or "server"
     TESTCASE     the test case; an unknown or unsupported one exits 127
     REQUESTS     client: the URLs to fetch, separated by white space
     SSLKEYLOGFILE  where to write TLS secrets (NSS key log format)

   and these directories: /www (server: the files to serve), /downloads
   (client: where to put what was fetched) and /certs (priv.key and cert.pem
   for a server, ca.pem for a client).  The server listens on UDP port 443.
   INTEROP_WWW, INTEROP_DOWNLOADS, INTEROP_CERTS and INTEROP_PORT override
   the paths and the port, to run it outside the container.

   Every test case but http3 speaks "hq-interop": HTTP/0.9 over QUIC, one
   "GET /path" request per bidirectional stream, answered with the file and
   a FIN.  Exit status: 0 success, 1 failure, 127 test case not supported.
   A test tool, not part of the library.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <quickstep/status.h>
#include <quickstep/crypto.h>
#include <quickstep/policy.h>
#include <quickstep/conn.h>
#include <quickstep/endpoint.h>
#include <quickstep/sign.h>
#include <quickstep/trust.h>

#include "../interop-util.h"

#define EXIT_UNSUPPORTED 127
#define ALPN "hq-interop"
#define MAX_URLS 4096
#define MAX_REQ 1100
#define KEY_UPDATE_AFTER (100 * 1024)	/* Bytes received before we rekey.  */
#define SESSION_TIMEOUT_S 120
/* The round trip assumed before one is measured.  The runner's paths are
   30 ms, and under its handshake loss (30% in bursts of 3) a handshake that
   waits out the default 333 ms backoff can take longer than a peer is
   willing to keep it: quic-go drops a half-open handshake after 5 seconds,
   and a late retransmission then starts a second one, which the runner
   counts.  RFC 9002 allows a different value.  */
#define INITIAL_RTT_US 100000

enum testcase
{
  TC_HANDSHAKE, TC_TRANSFER, TC_MULTICONNECT, TC_CHACHA20, TC_RETRY,
  TC_RESUMPTION, TC_ZERORTT, TC_KEYUPDATE, TC_V2, TC_IPV6, TC_UNSUPPORTED
};

/* What the runner may ask for.  The server side of keyupdate, blackhole,
   multiplexing and the like arrives as "transfer"; the client side of
   multiplexing, loss and corruption as "transfer" or "multiconnect".  Left
   out, and answered with 127: http3 (no HTTP/3 here), ecn (no ECN
   codepoints in the library), connectionmigration (the server's
   preferred_address is not used) and versionnegotiation.  */
static const struct
{
  const char *name;
  enum testcase tc;
} testcases[] = {
  { "handshake", TC_HANDSHAKE }, { "transfer", TC_TRANSFER },
  { "multiconnect", TC_MULTICONNECT }, { "chacha20", TC_CHACHA20 },
  { "retry", TC_RETRY }, { "resumption", TC_RESUMPTION },
  { "zerortt", TC_ZERORTT }, { "keyupdate", TC_KEYUPDATE },
  { "v2", TC_V2 }, { "ipv6", TC_IPV6 }
};

/* ---- Environment ---- */

struct url
{
  char host[256];
  char port[8];
  char path[MAX_REQ - 8];
};

struct saved_session
{
  int have;
  gq_tls_session sess;
  uint8_t params[512];
  size_t params_len;
  uint32_t version;
};

struct run
{
  int server;
  enum testcase tc;
  const char *www, *downloads, *certs, *port;
  struct url *urls;
  size_t n_urls;
  FILE *keylog;
  struct saved_session saved;
};

/* The console, and a copy of it in the file INTEROP_LOG names (the image
   puts it in /logs, which the runner keeps with the traces and the key log:
   the endpoint's view of each connection is then in the uploaded logs, next
   to what the simulator saw).  */
static FILE *logfile;

static void say (const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));

static void
say (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  vprintf (fmt, ap);
  va_end (ap);
  if (logfile)
    {
      va_start (ap, fmt);
      vfprintf (logfile, fmt, ap);
      va_end (ap);
      fflush (logfile);
    }
}

/* ---- qlog ----

   The runner sets QLOGDIR for every endpoint it starts, and keeps what is
   written there.  Each connection gets a file of its own, named as the qlog
   draft suggests: the original destination connection ID and the side
   (abcd1234_server.qlog.txt), with one line per event as <quickstep/qlog.h>
   describes: the time in microseconds from the first event, the event's
   name and its fields.  The events that belong to no connection (the
   server listening, datagrams that matched none, the replies of the
   endpoint's own) go to endpoint_server.qlog.txt.  The first line of a file
   begins with '#' and says what it is.  An awk script reads them:

     awk '$2 == "quic:packet_lost"' abcd1234_server.qlog.txt

   QUICKSTEP_QLOG_LEVEL (core, base or extra; default extra) chooses how much
   is logged, and QUICKSTEP_QLOG_RAW how many bytes of frame data.  */

#define QLOG_FILES 1024

static const char *qlogdir;
static int qlog_is_server;
static struct qlog_file
{
  const gq_conn *conn;
  FILE *f;
  uint64_t origin;
} qlog_files[QLOG_FILES];
static size_t n_qlog_files;
static struct qlog_file qlog_endpoint;

static FILE *
qlog_open (const char *path, const char *what, const char *odcid)
{
  FILE *f = fopen (path, "w");

  if (f == NULL)
    {
      fprintf (stderr, "cannot open %s\n", path);
      return NULL;
    }
  fprintf (f, "# qlog lines 1 %s vantage_point=%s%s%s\n", what,
           qlog_is_server ? "server" : "client", odcid ? " odcid=" : "",
           odcid ? odcid : "");
  return f;
}

static struct qlog_file *
qlog_file_for (const gq_conn *conn, uint64_t t)
{
  size_t i;
  char path[512], hex[2 * GQ_MAX_CID_LEN + 1];
  const uint8_t *id;
  size_t idlen;
  struct qlog_file *q;

  if (conn == NULL)
    {
      q = &qlog_endpoint;
      if (q->f == NULL && q->origin == 0)
        {
          snprintf (path, sizeof path, "%s/endpoint_%s.qlog.txt", qlogdir,
                    qlog_is_server ? "server" : "client");
          q->f = qlog_open (path, "endpoint", NULL);
          q->origin = t ? t : 1;
        }
      return q->f ? q : NULL;
    }
  for (i = 0; i < n_qlog_files; i++)
    if (qlog_files[i].conn == conn)
      return qlog_files[i].f ? &qlog_files[i] : NULL;
  if (n_qlog_files == QLOG_FILES)
    return NULL;
  q = &qlog_files[n_qlog_files++];
  q->conn = conn;
  q->origin = t;
  /* The first event of a connection is its connection_started, by when the
     original destination connection ID is known.  */
  id = gq_conn_original_dcid (conn, &idlen);
  for (i = 0; i < idlen && i < GQ_MAX_CID_LEN; i++)
    snprintf (hex + 2 * i, 3, "%02x", id[i]);
  hex[2 * i] = '\0';
  snprintf (path, sizeof path, "%s/%s_%s.qlog.txt", qlogdir, hex,
            qlog_is_server ? "server" : "client");
  q->f = qlog_open (path, "connection", hex);
  return q->f ? q : NULL;
}

static void
qlog_event (void *user, const gq_conn *conn, uint64_t t, const char *name,
            const char *fields, size_t len)
{
  struct qlog_file *q = qlog_file_for (conn, t);

  (void) user;
  if (q == NULL)
    return;
  fprintf (q->f, "%llu %s %.*s\n",
           (unsigned long long) (t > q->origin ? t - q->origin : 0), name,
           (int) len, fields);
  fflush (q->f);
}

/* The addresses of the endpoint's paths: the bytes of an address and its port.  */
static int
qlog_addr (void *user, const gq_addr *a, char *ip, size_t ipcap, uint16_t *port)
{
  (void) user;
  if (a->len == 6 && inet_ntop (AF_INET, a->data, ip, (socklen_t) ipcap))
    {
      *port = (uint16_t) (a->data[4] << 8 | a->data[5]);
      return 4;
    }
  if (a->len == 18 && inet_ntop (AF_INET6, a->data, ip, (socklen_t) ipcap))
    {
      *port = (uint16_t) (a->data[16] << 8 | a->data[17]);
      return 6;
    }
  return 0;
}

/* Log what the library reports, if QLOGDIR says where.  */
static void
qlog_setup (gq_conn_config *c, int server)
{
  const char *level = getenv ("QUICKSTEP_QLOG_LEVEL");
  const char *raw = getenv ("QUICKSTEP_QLOG_RAW");

  qlogdir = getenv ("QLOGDIR");
  if (qlogdir == NULL || *qlogdir == '\0')
    {
      qlogdir = NULL;
      return;
    }
  /* The runner's value ends with a '/'.  */
  {
    static char dir[400];
    size_t n = strlen (qlogdir);

    snprintf (dir, sizeof dir, "%s", qlogdir);
    while (n > 1 && dir[n - 1] == '/')
      dir[--n] = '\0';
    qlogdir = dir;
  }
  mkdir (qlogdir, 0777);
  qlog_is_server = server;
  c->qlog = qlog_event;
  c->qlog_addr = qlog_addr;
  if (level && !strcmp (level, "core"))
    c->qlog_importance = GQ_QLOG_CORE;
  else if (level && !strcmp (level, "base"))
    c->qlog_importance = GQ_QLOG_BASE;
  if (raw && *raw)
    c->qlog_raw = (size_t) strtoul (raw, NULL, 10);
}

static volatile sig_atomic_t stop_requested;

static void
on_signal (int sig)
{
  (void) sig;
  stop_requested = 1;
}

static const char *
env_or (const char *name, const char *fallback)
{
  const char *v = getenv (name);

  return v && *v ? v : fallback;
}

/* The congestion controller, from QUICKSTEP_CC: "cubic", "newreno", or unset
   for the library's default.  The runner passes the container only its own
   variables, so the image sets this (Dockerfile, CONGESTION_CONTROL).  An
   unknown value is an error rather than a silent default, so that a
   mistyped workflow input does not test the wrong thing.  */
static int
congestion_control (void)
{
  const char *v = getenv ("QUICKSTEP_CC");

  if (v == NULL || *v == '\0')
    return GQ_CC_DEFAULT;
  if (!strcmp (v, "cubic"))
    return GQ_CC_CUBIC;
  if (!strcmp (v, "newreno"))
    return GQ_CC_NEWRENO;
  fprintf (stderr, "unknown QUICKSTEP_CC \"%s\" (cubic or newreno)\n", v);
  exit (1);
}

static const char *
congestion_control_name (void)
{
  switch (congestion_control ())
    {
    case GQ_CC_NEWRENO:
      return "newreno";
    default:
      return "cubic";
    }
}

static uint64_t
now_us (void)
{
  struct timespec ts;

  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
}

static void
keylog_line (void *user, const char *line)
{
  struct run *r = user;

  fprintf (r->keylog, "%s\n", line);
  fflush (r->keylog);
}

/* https://HOST[:PORT]/PATH, HOST as [v6] for a literal IPv6 address.  */
static int
parse_url (const char *s, struct url *u)
{
  const char *p, *end, *colon = NULL;
  size_t hl;

  if (strncmp (s, "https://", 8) != 0)
    return -1;
  p = s + 8;
  end = strchr (p, '/');
  if (end == NULL)
    end = p + strlen (p);
  if (*p == '[')
    {
      const char *rb = memchr (p, ']', (size_t) (end - p));

      if (rb == NULL)
        return -1;
      if (rb + 1 < end && rb[1] == ':')
        colon = rb + 1;
      hl = (size_t) (rb - p) - 1;
      p++;
    }
  else
    {
      const char *c;

      for (c = p; c < end; c++)
        if (*c == ':')
          colon = c;
      hl = (size_t) ((colon ? colon : end) - p);
    }
  if (hl == 0 || hl >= sizeof u->host)
    return -1;
  memcpy (u->host, p, hl);
  u->host[hl] = 0;
  if (colon)
    {
      size_t pl = (size_t) (end - colon) - 1;

      if (pl == 0 || pl >= sizeof u->port)
        return -1;
      memcpy (u->port, colon + 1, pl);
      u->port[pl] = 0;
    }
  else
    strcpy (u->port, "443");
  if (*end == 0)
    strcpy (u->path, "/");
  else if (strlen (end) >= sizeof u->path)
    return -1;
  else
    strcpy (u->path, end);
  return 0;
}

static int
parse_requests (struct run *r, const char *requests)
{
  char *copy = strdup (requests), *save = NULL, *tok;

  if (copy == NULL)
    return -1;
  r->urls = calloc (MAX_URLS, sizeof *r->urls);
  if (r->urls == NULL)
    return -1;
  for (tok = strtok_r (copy, " \t\r\n", &save); tok;
       tok = strtok_r (NULL, " \t\r\n", &save))
    {
      if (r->n_urls == MAX_URLS || parse_url (tok, &r->urls[r->n_urls]) != 0)
        {
          fprintf (stderr, "bad request URL: %s\n", tok);
          free (copy);
          return -1;
        }
      r->n_urls++;
    }
  free (copy);
  return 0;
}

/* ---- Sockets ---- */

/* Addresses go to the library as the raw address followed by the port,
   in the family of the socket: 6 bytes for IPv4, 18 for IPv6.  */
struct net
{
  int fd;
  int family;
  gq_addr local;
};

static void
sa_to_addr (const struct sockaddr *sa, gq_addr *a)
{
  memset (a, 0, sizeof *a);
  if (sa->sa_family == AF_INET6)
    {
      const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *) sa;

      a->len = 18;
      memcpy (a->data, &s6->sin6_addr, 16);
      memcpy (a->data + 16, &s6->sin6_port, 2);
    }
  else
    {
      const struct sockaddr_in *s4 = (const struct sockaddr_in *) sa;

      a->len = 6;
      memcpy (a->data, &s4->sin_addr, 4);
      memcpy (a->data + 4, &s4->sin_port, 2);
    }
}

static socklen_t
addr_to_sa (int family, const gq_addr *a, struct sockaddr_storage *ss)
{
  memset (ss, 0, sizeof *ss);
  if (family == AF_INET6)
    {
      struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) ss;

      s6->sin6_family = AF_INET6;
      memcpy (&s6->sin6_addr, a->data, 16);
      memcpy (&s6->sin6_port, a->data + 16, 2);
      return sizeof *s6;
    }
  else
    {
      struct sockaddr_in *s4 = (struct sockaddr_in *) ss;

      s4->sin_family = AF_INET;
      memcpy (&s4->sin_addr, a->data, 4);
      memcpy (&s4->sin_port, a->data + 4, 2);
      return sizeof *s4;
    }
}

static void
set_buffers (int fd)
{
  int size = 2 * 1024 * 1024;

  setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof size);
  setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof size);
}

/* A UDP socket on the wildcard address, dual-stack where the host has IPv6.  */
static int
net_listen (struct net *n, const char *port)
{
  struct sockaddr_storage ss;
  socklen_t sl = sizeof ss;
  int off = 0;
  struct sockaddr_in6 s6;

  memset (n, 0, sizeof *n);
  n->fd = socket (AF_INET6, SOCK_DGRAM, 0);
  if (n->fd >= 0)
    {
      n->family = AF_INET6;
      setsockopt (n->fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
      memset (&s6, 0, sizeof s6);
      s6.sin6_family = AF_INET6;
      s6.sin6_addr = in6addr_any;
      s6.sin6_port = htons ((uint16_t) atoi (port));
      if (bind (n->fd, (struct sockaddr *) &s6, sizeof s6) != 0)
        {
          close (n->fd);
          n->fd = -1;
        }
    }
  if (n->fd < 0)
    {
      struct sockaddr_in s4;

      n->family = AF_INET;
      n->fd = socket (AF_INET, SOCK_DGRAM, 0);
      if (n->fd < 0)
        return -1;
      memset (&s4, 0, sizeof s4);
      s4.sin_family = AF_INET;
      s4.sin_addr.s_addr = htonl (INADDR_ANY);
      s4.sin_port = htons ((uint16_t) atoi (port));
      if (bind (n->fd, (struct sockaddr *) &s4, sizeof s4) != 0)
        {
          perror ("bind");
          close (n->fd);
          return -1;
        }
    }
  fcntl (n->fd, F_SETFL, fcntl (n->fd, F_GETFL) | O_NONBLOCK);
  set_buffers (n->fd);
  if (getsockname (n->fd, (struct sockaddr *) &ss, &sl) == 0)
    sa_to_addr ((struct sockaddr *) &ss, &n->local);
  return 0;
}

/* An unbound-port UDP socket of the family the server's address is in.  */
static int
net_open (struct net *n, int family)
{
  struct sockaddr_storage ss;
  socklen_t sl = sizeof ss;

  memset (n, 0, sizeof *n);
  n->family = family;
  n->fd = socket (family, SOCK_DGRAM, 0);
  if (n->fd < 0)
    return -1;
  memset (&ss, 0, sizeof ss);
  if (family == AF_INET6)
    {
      struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) &ss;

      s6->sin6_family = AF_INET6;
      s6->sin6_addr = in6addr_any;
      sl = sizeof *s6;
    }
  else
    {
      struct sockaddr_in *s4 = (struct sockaddr_in *) &ss;

      s4->sin_family = AF_INET;
      s4->sin_addr.s_addr = htonl (INADDR_ANY);
      sl = sizeof *s4;
    }
  if (bind (n->fd, (struct sockaddr *) &ss, sl) != 0)
    {
      close (n->fd);
      return -1;
    }
  fcntl (n->fd, F_SETFL, fcntl (n->fd, F_GETFL) | O_NONBLOCK);
  set_buffers (n->fd);
  sl = sizeof ss;
  if (getsockname (n->fd, (struct sockaddr *) &ss, &sl) == 0)
    sa_to_addr ((struct sockaddr *) &ss, &n->local);
  return 0;
}

/* Send everything the endpoint has for the network.  */
static void
net_flush (gq_endpoint *ep, struct net *n)
{
  uint8_t out[2048];
  size_t len;
  gq_path to;
  int guard;

  for (guard = 0; guard < 4096; guard++)
    {
      struct sockaddr_storage dest;
      socklen_t dl;

      memset (&to, 0, sizeof to);
      if (gq_endpoint_send (ep, now_us (), out, sizeof out, &len, &to) != GQ_OK
          || len == 0)
        break;
      if (to.remote.len != (n->family == AF_INET6 ? 18 : 6))
        continue;
      dl = addr_to_sa (n->family, &to.remote, &dest);
      /* A full socket buffer is a lost packet, which QUIC recovers from.  */
      (void) sendto (n->fd, out, len, 0, (struct sockaddr *) &dest, dl);
    }
}

/* Wait up to MS for the socket, then hand the endpoint what arrived and
   run its timers.  */
static void
net_service (gq_endpoint *ep, struct net *n, int ms)
{
  static uint8_t buf[65536];
  struct pollfd pfd;
  uint64_t t = gq_endpoint_timeout (ep), now = now_us ();
  int k;

  if (t)
    {
      int until = t > now ? (int) ((t - now + 999) / 1000) : 0;

      if (until < ms)
        ms = until;
    }
  pfd.fd = n->fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  if (poll (&pfd, 1, ms) > 0 && (pfd.revents & POLLIN))
    for (k = 0; k < 256; k++)
      {
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        gq_path path;
        ssize_t got = recvfrom (n->fd, buf, sizeof buf, 0,
                                (struct sockaddr *) &from, &fl);

        if (got <= 0)
          break;
        path.local = n->local;
        sa_to_addr ((struct sockaddr *) &from, &path.remote);
        gq_endpoint_recv (ep, now_us (), &path, buf, (size_t) got);
      }
  t = gq_endpoint_timeout (ep);
  if (t && t <= now_us ())
    gq_endpoint_on_timeout (ep, now_us ());
}

/* ---- Connections and their streams, for both roles ---- */

struct stream
{
  uint64_t id;
  /* Server: the request as it arrives, and the response being sent.  */
  char req[MAX_REQ];
  size_t req_len;
  uint8_t *data;
  size_t len, off;
  int served, fin_done;
  /* Client: the URL it carries (an index), how much of its request went
     out, and where the answer goes.  */
  size_t url, sent;
  int request_done;
  FILE *out;
  size_t got;
  int done;
};

struct cs
{
  struct run *r;
  struct cs *next;
  gq_conn *c;
  struct stream *s;
  size_t ns, cap;
  int established, finished;
  /* Client: the URLs of this connection, which of them have a stream, and
     how many came back whole.  */
  size_t first, count, opened, completed, received;
  int updated;
  uint64_t started_us;
  int stats_logged;
};

static struct stream *
stream_find (struct cs *cs, uint64_t id, int create)
{
  size_t i;

  for (i = 0; i < cs->ns; i++)
    if (cs->s[i].id == id)
      return &cs->s[i];
  if (!create)
    return NULL;
  if (cs->ns == cs->cap)
    {
      size_t cap = cs->cap ? cs->cap * 2 : 16;
      struct stream *s = realloc (cs->s, cap * sizeof *s);

      if (s == NULL)
        return NULL;
      cs->s = s;
      cs->cap = cap;
    }
  memset (&cs->s[cs->ns], 0, sizeof cs->s[0]);
  cs->s[cs->ns].id = id;
  return &cs->s[cs->ns++];
}

static void
stream_release (struct stream *s)
{
  free (s->data);
  if (s->out)
    fclose (s->out);
  s->data = NULL;
  s->out = NULL;
}

static void
cs_free (struct cs *cs)
{
  size_t i;

  for (i = 0; i < cs->ns; i++)
    stream_release (&cs->s[i]);
  free (cs->s);
  free (cs);
}

/* ---- Server ---- */

/* Read the file a request names into the stream, as the response.  */
static void
serve_request (struct cs *cs, struct stream *x)
{
  char full[1024], *p = x->req, *e;
  FILE *f;
  struct stat st;

  x->req[x->req_len] = 0;
  x->served = 1;
  if (strncmp (p, "GET ", 4) != 0)
    return;
  p += 4;
  e = strpbrk (p, "\r\n ");
  if (e)
    *e = 0;
  if (strstr (p, "..") != NULL)
    return;
  snprintf (full, sizeof full, "%s/%s", cs->r->www, p);
  f = fopen (full, "rb");
  if (f == NULL || fstat (fileno (f), &st) != 0)
    {
      if (f)
        fclose (f);
      say ("404 %s\n", p);
      x->data = (uint8_t *) strdup ("404\n");
      x->len = x->data ? 4 : 0;
    }
  else
    {
      x->data = malloc ((size_t) st.st_size + 1);
      x->len = x->data ? fread (x->data, 1, (size_t) st.st_size, f) : 0;
      fclose (f);
    }
  say ("REQUEST stream=%llu %s %zu bytes\n", (unsigned long long) x->id, p,
          x->len);
}

static int
server_data (void *u, uint64_t id, const uint8_t *d, size_t n, int fin)
{
  struct cs *cs = u;
  struct stream *x = stream_find (cs, id, 1);

  if (x == NULL || x->served)
    return 0;
  if (x->req_len + n < sizeof x->req)
    {
      memcpy (x->req + x->req_len, d, n);
      x->req_len += n;
    }
  /* A request is a line: answer it without waiting for the FIN.  */
  x->req[x->req_len] = 0;
  if (fin || strchr (x->req, '\n') != NULL)
    serve_request (cs, x);
  return 0;
}

static void
server_pump (struct cs *cs)
{
  size_t i;

  if (cs->c == NULL || gq_conn_state (cs->c) >= GQ_CONN_CLOSING)
    return;
  for (i = 0; i < cs->ns; i++)
    {
      struct stream *x = &cs->s[i];

      if (!x->served || x->fin_done)
        continue;
      while (x->off < x->len)
        {
          long w = gq_conn_stream_write (cs->c, x->id, x->data + x->off,
                                         x->len - x->off);

          if (w <= 0)
            break;
          x->off += (size_t) w;
        }
      if (x->off == x->len)
        {
          gq_conn_stream_finish (cs->c, x->id);
          x->fin_done = 1;
          free (x->data);
          x->data = NULL;
        }
    }
}

static void
stream_closed (void *u, uint64_t id)
{
  struct cs *cs = u;
  struct stream *x = stream_find (cs, id, 0);

  if (x == NULL)
    return;
  stream_release (x);
  cs->ns--;
  if (x != &cs->s[cs->ns])
    *x = cs->s[cs->ns];
}

static void
ev_connected (void *u, const gq_tls_info *info)
{
  struct cs *cs = u;

  cs->established = 1;
  say ("CONNECTED version=0x%08x alpn=%.*s%s%s\n",
          cs->c ? (unsigned) gq_conn_version (cs->c) : 0,
          (int) info->alpn_len, info->alpn, info->resumed ? " resumed" : "",
          info->early_data_accepted ? " early-data" : "");
}

/* One line of the connection's own counters, once, for a rough picture of
   how a transfer went: loss, round trip, congestion window, and the time and
   bytes behind a goodput figure.  With the packet traces, this is where to
   look when a case is slow or the ACKs look wrong.  */
static void
log_stats (struct cs *cs, const char *when)
{
  gq_conn_stats st;
  uint64_t ms = (now_us () - cs->started_us) / 1000;

  if (cs->c == NULL || cs->stats_logged)
    return;
  cs->stats_logged = 1;
  gq_conn_get_stats (cs->c, &st);
  say ("STATS %s cc=%s duration_ms=%llu packets_sent=%llu packets_received=%llu"
          " packets_lost=%llu bytes_sent=%llu bytes_received=%llu"
          " srtt_us=%llu min_rtt_us=%llu rttvar_us=%llu cwnd=%llu"
          " ssthresh=%llu bytes_in_flight=%llu congestion_events=%llu"
          " pacing_rate_bps=%llu pto_count=%u key_updates=%llu",
          when, congestion_control_name (), (unsigned long long) ms,
          (unsigned long long) st.packets_sent,
          (unsigned long long) st.packets_received,
          (unsigned long long) st.packets_lost,
          (unsigned long long) st.bytes_sent,
          (unsigned long long) st.bytes_received,
          (unsigned long long) st.srtt_us, (unsigned long long) st.min_rtt_us,
          (unsigned long long) st.rttvar_us, (unsigned long long) st.cwnd,
          (unsigned long long) st.ssthresh,
          (unsigned long long) st.bytes_in_flight,
          (unsigned long long) st.congestion_events,
          (unsigned long long) st.pacing_rate_bps, st.pto_count,
          (unsigned long long) st.key_updates);
  if (!cs->r->server && ms > 0)
    say (" app_bytes=%zu goodput_kbps=%llu", cs->received,
            (unsigned long long) ((uint64_t) cs->received * 8 / ms));
  say ("\n");
}

static void
ev_closed (void *u, const gq_conn_close_info *i)
{
  struct cs *cs = u;

  say ("CLOSED source=%d application=%d error=%llu reason=%.*s\n",
          i->source, i->application, (unsigned long long) i->error,
          (int) i->reason_len, i->reason ? (const char *) i->reason : "");
  log_stats (cs, "closed");
}

static void
ev_early_result (void *u, int accepted)
{
  (void) u;
  say ("EARLY_DATA accepted=%d\n", accepted);
}

static void
ev_ticket (void *u, const gq_tls_ticket *t, uint32_t version)
{
  struct cs *cs = u;
  struct saved_session *sv = &cs->r->saved;

  /* Keep the first ticket, with what 0-RTT needs alongside it: the
     server's transport parameters and the QUIC version.  */
  if (sv->have || cs->c == NULL)
    return;
  if (gq_tls_session_store (&sv->sess, t) != GQ_OK
      || gq_conn_get_peer_params (cs->c, sv->params, sizeof sv->params,
                                  &sv->params_len) != GQ_OK)
    return;
  sv->version = version;
  sv->have = 1;
  say ("TICKET saved\n");
}

static void
set_events (gq_conn_events *ev, struct cs *cs)
{
  memset (ev, 0, sizeof *ev);
  ev->user = cs;
  ev->connected = ev_connected;
  ev->closed = ev_closed;
  ev->stream_closed = stream_closed;
  ev->early_data_result = ev_early_result;
  ev->ticket = ev_ticket;
}

struct server
{
  struct run *r;
  struct cs *conns, *pending;
};

static int
srv_accept (void *u, const gq_path *from, gq_conn_events *ev)
{
  struct server *sv = u;
  struct cs *cs = calloc (1, sizeof *cs);

  (void) from;
  if (cs == NULL)
    return -1;
  cs->r = sv->r;
  cs->started_us = now_us ();
  cs->next = sv->conns;
  sv->conns = cs;
  sv->pending = cs;
  set_events (ev, cs);
  ev->stream_data = server_data;
  return 0;
}

static void
srv_connection (void *u, gq_conn *c)
{
  struct server *sv = u;

  if (sv->pending)
    sv->pending->c = c;
  sv->pending = NULL;
}

static void
srv_done (void *u, gq_conn *c)
{
  struct server *sv = u;
  struct cs **pp;

  for (pp = &sv->conns; *pp; pp = &(*pp)->next)
    if ((*pp)->c == c)
      {
        struct cs *cs = *pp;

        *pp = cs->next;
        cs_free (cs);
        break;
      }
}

static int
run_server (struct run *r, const char *cert, const char *key)
{
  static gq_slice alpn;
  static uint16_t chacha[] = { GQ_TLS_CHACHA20_POLY1305_SHA256 };
  gq_tls_server_config sc;
  gq_endpoint_config ec;
  gq_endpoint_events ee;
  gq_endpoint *ep;
  struct server sv;
  struct net net;
  gq_slice *chain;
  size_t n_chain;
  gq_privkey *pk;

  if (load_chain (cert, &chain, &n_chain) != 0
      || gq_privkey_from_pem_file (&pk, key) != GQ_OK)
    {
      fprintf (stderr, "cannot load %s and %s\n", cert, key);
      return 1;
    }
  alpn.data = (const uint8_t *) ALPN;
  alpn.len = strlen (ALPN);
  memset (&sc, 0, sizeof sc);
  sc.credentials.chain = chain;
  sc.credentials.n_chain = n_chain;
  sc.credentials.key = pk;
  sc.alpn = &alpn;
  sc.n_alpn = 1;
  if (r->tc == TC_CHACHA20)
    {
      sc.suites = chacha;
      sc.n_suites = 1;
    }
  if (r->keylog)
    {
      sc.keylog = keylog_line;
      sc.keylog_user = r;
    }

  memset (&ec, 0, sizeof ec);
  ec.conn.initial_rtt_us = INITIAL_RTT_US;
  ec.conn.congestion_control = congestion_control ();
  qlog_setup (&ec.conn, 1);
  ec.server = &sc;
  /* Only the retry case may send a Retry: handshake fails if one arrives.  */
  ec.admit.require_retry = r->tc == TC_RETRY;
  ec.tickets = 1;
  ec.early_data = r->tc == TC_ZERORTT;
  /* A client that opens in v1 and offers v2 is moved to v2 only in the v2
     case; every other case checks for v1 throughout.  */
  if (r->tc == TC_V2)
    {
      ec.conn.versions[0] = GQ_VERSION_2;
      ec.conn.versions[1] = GQ_VERSION_1;
      ec.conn.n_versions = 2;
    }
  else
    {
      ec.conn.versions[0] = GQ_VERSION_1;
      ec.conn.n_versions = 1;
    }
  memset (&sv, 0, sizeof sv);
  sv.r = r;
  memset (&ee, 0, sizeof ee);
  ee.user = &sv;
  ee.accept = srv_accept;
  ee.connection = srv_connection;
  ee.done = srv_done;
  if (gq_endpoint_new (&ep, &ec, &ee) != GQ_OK)
    {
      fprintf (stderr, "cannot create the endpoint\n");
      return 1;
    }
  if (net_listen (&net, r->port) != 0)
    {
      fprintf (stderr, "cannot listen on port %s\n", r->port);
      return 1;
    }
  say ("LISTENING port=%s family=%s\n", r->port,
          net.family == AF_INET6 ? "dual-stack" : "ipv4");
  fflush (stdout);
  while (!stop_requested)
    {
      struct cs *cs;

      for (cs = sv.conns; cs; cs = cs->next)
        server_pump (cs);
      net_flush (ep, &net);
      net_service (ep, &net, 50);
    }
  gq_endpoint_free (ep);
  close (net.fd);
  return 0;
}

/* ---- Client ---- */

static int
client_data (void *u, uint64_t id, const uint8_t *d, size_t n, int fin)
{
  struct cs *cs = u;
  struct stream *x = stream_find (cs, id, 0);

  if (x == NULL || x->done)
    return 0;
  if (x->out && n)
    fwrite (d, 1, n, x->out);
  x->got += n;
  cs->received += n;
  if (fin)
    {
      if (x->out)
        fclose (x->out);
      x->out = NULL;
      x->done = 1;
      cs->completed++;
    }
  return 0;
}

/* Open a stream for each URL the stream limit allows, and send its request.
   With early data this goes out before the handshake is done.  */
static void
client_pump (struct cs *cs)
{
  struct run *r = cs->r;
  size_t i;

  if (cs->c == NULL || gq_conn_state (cs->c) >= GQ_CONN_CLOSING)
    return;
  while (cs->opened < cs->count)
    {
      const struct url *u = &r->urls[cs->first + cs->opened];
      const char *base = strrchr (u->path, '/');
      char name[1100];
      uint64_t id;
      struct stream *x;

      if (gq_conn_stream_open (cs->c, 1, &id) != GQ_OK)
        break;
      x = stream_find (cs, id, 1);
      if (x == NULL)
        break;
      snprintf (name, sizeof name, "%s/%s", r->downloads,
                base ? base + 1 : u->path);
      x->out = fopen (name, "wb");
      if (x->out == NULL)
        fprintf (stderr, "cannot write %s\n", name);
      x->url = cs->first + cs->opened;
      cs->opened++;
    }
  for (i = 0; i < cs->ns; i++)
    {
      struct stream *x = &cs->s[i];
      char req[MAX_REQ];
      size_t rl;

      if (x->request_done)
        continue;
      rl = (size_t) snprintf (req, sizeof req, "GET %s\r\n",
                              r->urls[x->url].path);
      while (x->sent < rl)
        {
          long w = gq_conn_stream_write (cs->c, x->id,
                                         (const uint8_t *) req + x->sent,
                                         rl - x->sent);

          if (w <= 0)
            break;
          x->sent += (size_t) w;
        }
      if (x->sent == rl)
        {
          gq_conn_stream_finish (cs->c, x->id);
          x->request_done = 1;
        }
    }
  /* The keyupdate case: rekey once the transfer is under way.  The library
     refuses until the handshake is confirmed, so ask again until it takes.  */
  if (r->tc == TC_KEYUPDATE && !cs->updated && cs->received >= KEY_UPDATE_AFTER
      && gq_conn_update_keys (cs->c, now_us ()) == GQ_OK)
    {
      cs->updated = 1;
      say ("KEY_UPDATE\n");
    }
}

static void
cli_done (void *u, gq_conn *c)
{
  struct cs *cs = u;

  (void) c;
  cs->c = NULL;
  cs->finished = 1;
}

static void
cli_connection (void *u, gq_conn *c)
{
  (void) u;
  (void) c;
}

/* One connection fetching URLS[FIRST .. FIRST + COUNT).  WANT_TICKET: do not
   hang up before the server's session ticket has arrived.  RESUME: offer
   the saved session (with early data in the zerortt case).  Returns 0 if
   every file came back.  */
static int
client_session (struct run *r, const gq_trust *trust, size_t first,
                size_t count, int want_ticket, int resume)
{
  static gq_slice alpn;
  static uint16_t chacha[] = { GQ_TLS_CHACHA20_POLY1305_SHA256 };
  static uint16_t x25519_only[] = { GQ_GROUP_X25519 };
  const struct url *u = &r->urls[first];
  gq_tls_config tc;
  gq_endpoint_config ec;
  gq_endpoint_events ee;
  gq_conn_events ev;
  gq_conn_config cc;
  gq_endpoint *ep;
  gq_conn *conn = NULL;
  struct cs *cs;
  struct net net;
  struct addrinfo hints, *ai, *a;
  gq_path path;
  uint64_t start = now_us (), wait_from = 0;
  int ok = 1, rc, closing = 0;

  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  rc = getaddrinfo (u->host, u->port, &hints, &ai);
  if (rc != 0)
    {
      fprintf (stderr, "cannot resolve %s: %s\n", u->host, gai_strerror (rc));
      return 1;
    }
  for (a = ai; a; a = a->ai_next)
    if (a->ai_family == AF_INET || a->ai_family == AF_INET6)
      break;
  if (a == NULL || net_open (&net, a->ai_family) != 0)
    {
      fprintf (stderr, "cannot open a socket for %s\n", u->host);
      freeaddrinfo (ai);
      return 1;
    }
  path.local = net.local;
  sa_to_addr (a->ai_addr, &path.remote);
  freeaddrinfo (ai);

  cs = calloc (1, sizeof *cs);
  cs->r = r;
  cs->started_us = start;
  cs->first = first;
  cs->count = count;

  alpn.data = (const uint8_t *) ALPN;
  alpn.len = strlen (ALPN);
  memset (&tc, 0, sizeof tc);
  tc.server_name = u->host;
  tc.trust = trust;
  tc.alpn = &alpn;
  tc.n_alpn = 1;
  if (r->tc == TC_CHACHA20)
    {
      tc.suites = chacha;
      tc.n_suites = 1;
    }
  /* multiconnect is what the runner's handshake loss and corruption cases
     run: fifty handshakes, each of which fails to finish if a datagram of
     its first flight is lost.  The hybrid key share makes the ClientHello
     too big for one datagram, so offer only X25519, whose ClientHello fits
     in one: half the datagrams to lose.  */
  if (r->tc == TC_MULTICONNECT)
    {
      tc.groups = x25519_only;
      tc.n_groups = 1;
    }
  if (r->keylog)
    {
      tc.keylog = keylog_line;
      tc.keylog_user = r;
    }
  memset (&cc, 0, sizeof cc);
  cc.initial_rtt_us = INITIAL_RTT_US;
  cc.congestion_control = congestion_control ();
  qlog_setup (&cc, 0);
  /* Open in v1 whatever else is offered, as the runner checks; the v2 case
     lists v2 first among what the server may switch us to.  */
  if (r->tc == TC_V2)
    {
      cc.versions[0] = GQ_VERSION_2;
      cc.versions[1] = GQ_VERSION_1;
      cc.n_versions = 2;
      cc.version = GQ_VERSION_1;
    }
  else
    {
      cc.versions[0] = GQ_VERSION_1;
      cc.n_versions = 1;
      cc.version = GQ_VERSION_1;
    }
  if (resume && r->saved.have)
    {
      tc.resume = &r->saved.sess;
      /* A ticket is good only in the version it came from.  */
      cc.version = cc.versions[0] = r->saved.version;
      cc.n_versions = 1;
      if (r->tc == TC_ZERORTT)
        {
          tc.early_data = 1;
          cc.resume_params = r->saved.params;
          cc.resume_params_len = r->saved.params_len;
        }
      say ("RESUMING%s\n", tc.early_data ? " with early data" : "");
    }
  cc.path = path;

  memset (&ec, 0, sizeof ec);
  ec.conn = cc;
  memset (&ee, 0, sizeof ee);
  ee.user = cs;
  ee.connection = cli_connection;
  ee.done = cli_done;
  if (gq_endpoint_new (&ep, &ec, &ee) != GQ_OK)
    {
      close (net.fd);
      free (cs);
      return 1;
    }
  set_events (&ev, cs);
  ev.stream_data = client_data;
  if (gq_endpoint_connect (ep, now_us (), &tc, &cc, &path, &ev, &conn) != GQ_OK)
    {
      fprintf (stderr, "cannot start a connection to %s\n", u->host);
      gq_endpoint_free (ep);
      close (net.fd);
      free (cs);
      return 1;
    }
  cs->c = conn;

  for (;;)
    {
      uint64_t now = now_us ();

      client_pump (cs);
      net_flush (ep, &net);
      if (cs->finished)
        {
          ok = cs->completed == cs->count;
          break;
        }
      if (!closing && cs->completed == cs->count)
        {
          /* Everything arrived.  If a ticket is wanted, give it a few
             seconds; then close politely and let the peer see it.  */
          if (want_ticket && !r->saved.have && wait_from == 0)
            wait_from = now;
          if (!want_ticket || r->saved.have || now - wait_from > 3000000)
            {
              if (cs->c)
                gq_conn_close (cs->c, now, 1, 0, "done");
              closing = 1;
              wait_from = now;
            }
        }
      if (closing && now - wait_from > 300000)
        {
          ok = cs->completed == cs->count;
          break;
        }
      if (now - start > (uint64_t) SESSION_TIMEOUT_S * 1000000)
        {
          fprintf (stderr, "timeout: %zu of %zu files\n", cs->completed,
                   cs->count);
          log_stats (cs, "timeout");
          ok = 0;
          break;
        }
      net_service (ep, &net, 20);
    }
  log_stats (cs, "end");
  say ("COMPLETED %zu of %zu\n", cs->completed, cs->count);
  fflush (stdout);
  gq_endpoint_free (ep);
  close (net.fd);
  cs_free (cs);
  return ok ? 0 : 1;
}

static int
run_client (struct run *r, const char *ca)
{
  gq_trust *trust;
  int bad = 0;
  size_t i;

  if (r->n_urls == 0)
    {
      fprintf (stderr, "no REQUESTS\n");
      return 1;
    }
  if (gq_trust_new (&trust) != GQ_OK || gq_trust_add_pem_file (trust, ca) != GQ_OK)
    {
      fprintf (stderr, "cannot load %s\n", ca);
      return 1;
    }
  switch (r->tc)
    {
    case TC_MULTICONNECT:
      /* One connection, and so one handshake, per file.  */
      for (i = 0; i < r->n_urls; i++)
        bad |= client_session (r, trust, i, 1, 0, 0);
      return bad;
    case TC_RESUMPTION:
    case TC_ZERORTT:
      /* The first file on a connection that leaves a session behind, the
         rest on one that resumes it (and, for zerortt, asks in 0-RTT).  */
      if (r->n_urls < 2)
        return client_session (r, trust, 0, r->n_urls, 0, 0);
      if (client_session (r, trust, 0, 1, 1, 0) != 0)
        return 1;
      if (!r->saved.have)
        fprintf (stderr, "no session ticket arrived: the second connection "
                         "cannot resume\n");
      return client_session (r, trust, 1, r->n_urls - 1, 0, 1);
    default:
      return client_session (r, trust, 0, r->n_urls, 0, 0);
    }
}

int
main (void)
{
  struct run r;
  const char *role = getenv ("ROLE"), *tcname = getenv ("TESTCASE");
  const char *keylog = getenv ("SSLKEYLOGFILE");
  char path1[1024], path2[1024];
  size_t i;

  memset (&r, 0, sizeof r);
  r.tc = TC_UNSUPPORTED;
  setvbuf (stdout, NULL, _IOLBF, 0);
  if (role == NULL || (strcmp (role, "client") && strcmp (role, "server")))
    {
      fprintf (stderr, "ROLE must be client or server\n");
      return 1;
    }
  r.server = strcmp (role, "server") == 0;
  for (i = 0; tcname && i < sizeof testcases / sizeof testcases[0]; i++)
    if (strcmp (tcname, testcases[i].name) == 0)
      r.tc = testcases[i].tc;
  say ("quickstep interop endpoint: ROLE=%s TESTCASE=%s\n", role,
          tcname ? tcname : "");
  if (r.tc == TC_UNSUPPORTED)
    {
      fprintf (stderr, "unsupported test case\n");
      return EXIT_UNSUPPORTED;
    }
  r.www = env_or ("INTEROP_WWW", "/www");
  r.downloads = env_or ("INTEROP_DOWNLOADS", "/downloads");
  r.certs = env_or ("INTEROP_CERTS", "/certs");
  r.port = env_or ("INTEROP_PORT", "443");
  if (keylog && *keylog)
    {
      r.keylog = fopen (keylog, "a");
      if (r.keylog == NULL)
        fprintf (stderr, "cannot open %s\n", keylog);
    }
  if (getenv ("INTEROP_LOG") && *getenv ("INTEROP_LOG"))
    logfile = fopen (getenv ("INTEROP_LOG"), "a");
  /* A bad QUICKSTEP_CC fails at once, not after a handshake is under way.  */
  (void) congestion_control ();
  signal (SIGPIPE, SIG_IGN);
  signal (SIGTERM, on_signal);
  signal (SIGINT, on_signal);
  if (gq_crypto_init () != GQ_OK)
    return 1;
  if (r.server)
    {
      snprintf (path1, sizeof path1, "%s/cert.pem", r.certs);
      snprintf (path2, sizeof path2, "%s/priv.key", r.certs);
      return run_server (&r, path1, path2);
    }
  if (parse_requests (&r, env_or ("REQUESTS", "")) != 0)
    return 1;
  snprintf (path1, sizeof path1, "%s/ca.pem", r.certs);
  return run_client (&r, path1);
}
