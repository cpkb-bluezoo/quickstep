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

/* qlog: a log of what a QUIC connection does, as the events of
   draft-ietf-quic-qlog-quic-events (the "quic" namespace).  The draft
   defines the events, their fields and their units, and leaves the
   serialization open; this one is made of lines, to be read with the
   standard Unix text tools.

   Like everything in quickstep this is a callback and nothing else.  The
   library opens no file, reads no environment variable and writes nothing to
   stderr: set gq_conn_config.qlog and each event arrives as a time, a name
   and a line of fields.  What to do with them is the application's.  With no
   callback set, logging costs one pointer test where an event would be.

   Events are reported from inside the call that caused them (gq_conn_recv,
   gq_conn_send, gq_conn_on_timeout, stream writes ...), with the time that
   call was given.  They arrive in time order: should the caller's clock read
   a little less than at an earlier call, the time of the event is held at the
   latest there was.  The callback must not call back into the connection,
   other than the read-only questions its CONN argument allows; events a call
   would cause are dropped.

   gq_conn_config.qlog_importance chooses how much is logged, by the draft's
   importance levels, and qlog_raw how many bytes of the data in frames are
   included.  Secrets are never logged: key_updated names the key and its
   phase but carries no key bytes.

   Every event of the draft is produced but these.  The spin bit, path MTU
   discovery, ECN and the buffering of packets that arrive before their keys
   are not implemented, so spin_bit_updated, mtu_updated, ecn_state_updated
   and packet_buffered have nothing to report.  frames_created, frames_parsed
   and frames_processed repeat what packet_sent and packet_received carry,
   which the draft advises against.

   The line

   An application that writes one line per event writes the time, the name and
   the fields, separated by spaces (and, for a log of many connections, a
   connection ID in front):

     1234567 quic:packet_sent header.packet_type=1RTT header.packet_number=42
       frames.0.frame_type=ack frames.0.acked_ranges=3-7,9
       frames.1.frame_type=stream frames.1.stream_id=0 frames.1.fin=true
       frames.1.raw.length=1200

   (all on one line).  The time is microseconds on the clock the caller gives
   the connection.  The name is the draft's, with its namespace.

   The fields are the members of the event's data in the draft, flattened:

   - A field is KEY=VALUE, and fields are separated by single spaces.  A key
     is made of lowercase letters, digits, '_' and '.'.  The value is
     whatever follows the first '=' and has no space in it: a space, '%',
     control character or byte outside ASCII is written as %XX (two hex
     digits), so the line splits into fields on spaces, each into key and
     value on the first '=', and any value is decoded by reversing that.
   - A member of an object is named after the object that holds it, joined by
     '.': header.packet_type.
   - A list of objects is numbered from 0, as frames.0.frame_type.
   - A list of numbers or strings is one value, comma-separated:
     packet_numbers=1,2,3.  A list of ACK ranges is written with each as
     LOW-HIGH, or LOW if the two are the same: acked_ranges=3-7,9.  An empty
     list is an empty value.
   - Numbers are decimal.  Durations are in the draft's units, milliseconds,
     with three decimals (ack_delay=0.125).  Booleans are true and false.
     The draft's hexstrings (connection IDs, tokens, raw data) are lowercase
     hex.
   - The draft's optional "tuple" of an event, the network path it belongs
     to, is a first field tuple=ID when the event is not on the default
     path.

   The names and fields of each event are those of the draft; what it
   leaves out, or what this library cannot know, is simply absent.  */

#ifndef QUICKSTEP_QLOG_H
#define QUICKSTEP_QLOG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The importance levels of the event definitions (qlog main schema section
   8.3).  A level includes the ones before it: Core is the least, and Extra
   everything.  */
enum gq_qlog_importance
{
  GQ_QLOG_ALL = 0,		/* In gq_conn_config: Extra.  */
  GQ_QLOG_CORE = 1,
  GQ_QLOG_BASE = 2,
  GQ_QLOG_EXTRA = 3
};

struct gq_conn;

/* One event: CONN, the connection it belongs to (NULL for an event of an
   endpoint that belongs to none: the draft's server_listening, and
   datagrams for connections that do not exist); TIME_US on the clock the
   connection was given; NAME such as "quic:packet_sent"; and its FIELDS (LEN
   bytes, NUL-terminated, no newline).  The strings are valid during the
   call only.

   An endpoint serves all its connections with one callback, so CONN is how
   a callback tells them apart: a pointer that is the same for every event of
   a connection.  It may be asked what only reads the connection
   (gq_conn_original_dcid to name a log, gq_conn_version, gq_conn_state,
   gq_conn_get_stats) and must not be used for anything else.  The first
   event of a connection is always its connection_started.  */
typedef void (*gq_qlog_fn) (void *user, const struct gq_conn *conn,
                            uint64_t time_us, const char *name,
                            const char *fields, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* QUICKSTEP_QLOG_H */
