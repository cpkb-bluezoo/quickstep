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

/* Does a qlog event say what draft-ietf-quic-qlog-quic-events lets it?  This
   checks the name against the draft's Table 1, the fields every event of that
   name must have, the values its enumerated fields may take, and the type of
   a field by its name (a number, a time in milliseconds, hex).  It is written
   from the draft's definitions, apart from the library, so that a mistake in
   one is not a mistake in both.  Needs tst-qkv.h.  */

#ifndef GQ_TST_QLOGCHECK_H
#define GQ_TST_QLOGCHECK_H

#include <stdio.h>
#include <string.h>

#include "tst-qkv.h"

#if defined __GNUC__
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wunused-function"
#endif

static const char *const qc_events[] = {
  "server_listening", "connection_started", "connection_closed",
  "connection_id_updated", "spin_bit_updated", "connection_state_updated",
  "tuple_assigned", "mtu_updated", "version_information", "alpn_information",
  "parameters_set", "parameters_restored", "packet_sent", "packet_received",
  "packet_dropped", "packet_buffered", "packets_acked", "udp_datagrams_sent",
  "udp_datagrams_received", "udp_datagram_dropped", "stream_state_updated",
  "frames_created", "frames_parsed", "frames_processed", "stream_data_moved",
  "datagram_data_moved", "connection_data_blocked_updated",
  "stream_data_blocked_updated", "datagram_data_blocked_updated",
  "migration_state_updated", "timer_updated", "key_updated", "key_discarded",
  "recovery_parameters_set", "recovery_metrics_updated",
  "congestion_state_updated", "packet_lost", "marked_for_retransmit",
  "ecn_state_updated", NULL
};

static int
qc_digits_n (const char *s, size_t n)
{
  size_t i;

  if (n == 0)
    return 0;
  for (i = 0; i < n; i++)
    if (s[i] < '0' || s[i] > '9')
      return 0;
  return 1;
}

/* The fields each event may have, from the draft's definitions, as paths with
   the numbers of lists written N.  The library has no business emitting
   anything else, so a misspelled or misplaced field is a failure.  */
#define QC_HDR \
  "header.packet_type|header.packet_type_bytes|header.spin_bit|" \
  "header.key_phase|header.key_phase_bit|header.packet_number_length|" \
  "header.packet_number|header.token.type|header.token.raw.length|" \
  "header.token.raw.payload_length|header.token.raw.data|header.length|" \
  "header.version|header.scil|header.dcil|header.scid|header.dcid"
#define QC_RAW "raw.length|raw.payload_length|raw.data"
#define QC_RAWN "raw.N.length|raw.N.payload_length|raw.N.data"
#define QC_FRAMES \
  "frames.N.frame_type|frames.N.raw.length|frames.N.raw.payload_length|" \
  "frames.N.raw.data|frames.N.ack_delay|frames.N.acked_ranges|" \
  "frames.N.ect1|frames.N.ect0|frames.N.ce|frames.N.stream_id|" \
  "frames.N.error|frames.N.error_code|frames.N.final_size|" \
  "frames.N.reliable_size|frames.N.offset|frames.N.token.type|" \
  "frames.N.token.raw.length|frames.N.token.raw.payload_length|" \
  "frames.N.token.raw.data|frames.N.fin|frames.N.maximum|" \
  "frames.N.stream_type|frames.N.limit|frames.N.sequence_number|" \
  "frames.N.retire_prior_to|frames.N.connection_id_length|" \
  "frames.N.connection_id|frames.N.stateless_reset_token|frames.N.data|" \
  "frames.N.error_space|frames.N.reason|frames.N.reason_bytes|" \
  "frames.N.trigger_frame_type|frames.N.frame_type_bytes"
#define QC_ENDPOINT(p) \
  p ".ip_v4|" p ".port_v4|" p ".ip_v6|" p ".port_v6|" p ".connection_ids"
#define QC_PARAMS \
  "original_destination_connection_id|initial_source_connection_id|" \
  "retry_source_connection_id|stateless_reset_token|" \
  "disable_active_migration|max_idle_timeout|max_udp_payload_size|" \
  "ack_delay_exponent|max_ack_delay|active_connection_id_limit|" \
  "initial_max_data|initial_max_stream_data_bidi_local|" \
  "initial_max_stream_data_bidi_remote|initial_max_stream_data_uni|" \
  "initial_max_streams_bidi|initial_max_streams_uni|" \
  "max_datagram_frame_size|grease_quic_bit"
#define QC_ALPN(p) p ".N.byte_value|" p ".N.string_value"

static const struct
{
  const char *event, *paths;
} qc_allowed[] = {
  { "server_listening",
    "ip_v4|port_v4|ip_v6|port_v6|retry_required" },
  { "connection_started", QC_ENDPOINT ("local") "|" QC_ENDPOINT ("remote") },
  { "connection_closed",
    "initiator|connection_error|application_error|error_code|internal_code|"
    "reason|trigger" },
  { "connection_id_updated", "initiator|old|new" },
  { "spin_bit_updated", "state" },
  { "connection_state_updated", "old|new" },
  { "tuple_assigned",
    "tuple_id|" QC_ENDPOINT ("tuple_remote") "|" QC_ENDPOINT ("tuple_local") },
  { "mtu_updated", "old|new|done" },
  { "version_information", "server_versions|client_versions|chosen_version" },
  { "alpn_information",
    QC_ALPN ("server_alpns") "|" QC_ALPN ("client_alpns") "|"
    "chosen_alpn.byte_value|chosen_alpn.string_value" },
  { "parameters_set",
    "initiator|resumption_allowed|early_data_enabled|tls_cipher|" QC_PARAMS
    "|preferred_address.ip_v4|preferred_address.port_v4|"
    "preferred_address.ip_v6|preferred_address.port_v6|"
    "preferred_address.connection_id|preferred_address.stateless_reset_token|"
    "unknown_parameters.N.id|unknown_parameters.N.value|reset_stream_at" },
  { "parameters_restored", QC_PARAMS },
  { "packet_sent",
    QC_HDR "|" QC_FRAMES "|" QC_RAW "|stateless_reset_token|"
    "supported_versions|datagram_id|is_mtu_probe_packet|trigger" },
  { "packet_received",
    QC_HDR "|" QC_FRAMES "|" QC_RAW "|stateless_reset_token|"
    "supported_versions|datagram_id|trigger" },
  { "packet_dropped", QC_HDR "|" QC_RAW "|datagram_id|trigger" },
  { "packet_buffered", QC_HDR "|" QC_RAW "|datagram_id|trigger" },
  { "packets_acked", "packet_number_space|packet_numbers" },
  { "udp_datagrams_sent", "count|" QC_RAWN "|ecn|datagram_ids" },
  { "udp_datagrams_received", "count|" QC_RAWN "|ecn|datagram_ids" },
  { "udp_datagram_dropped", QC_RAW },
  { "stream_state_updated",
    "stream_id|stream_type|old|new|stream_side|trigger" },
  { "frames_created", QC_FRAMES "|packet_numbers" },
  { "frames_parsed", QC_FRAMES "|packet_numbers" },
  { "frames_processed", QC_FRAMES "|packet_numbers" },
  { "stream_data_moved",
    "stream_id|offset|from|to|additional_info|" QC_RAW },
  { "datagram_data_moved", "from|to|" QC_RAW },
  { "connection_data_blocked_updated", "old|new|reason" },
  { "stream_data_blocked_updated", "old|new|stream_id|reason" },
  { "datagram_data_blocked_updated", "old|new|reason" },
  { "migration_state_updated",
    "old|new|tuple_id|" QC_ENDPOINT ("tuple_remote") "|"
    QC_ENDPOINT ("tuple_local") },
  { "timer_updated",
    "timer_type|timer_id|packet_number_space|event_type|delta" },
  { "key_updated", "key_type|old|new|key_phase|trigger" },
  { "key_discarded", "key_type|key|key_phase|trigger" },
  { "recovery_parameters_set",
    "reordering_threshold|time_threshold|timer_granularity|initial_rtt|"
    "max_datagram_size|initial_congestion_window|minimum_congestion_window|"
    "loss_reduction_factor|persistent_congestion_threshold" },
  { "recovery_metrics_updated",
    "min_rtt|smoothed_rtt|latest_rtt|rtt_variance|pto_count|"
    "congestion_window|bytes_in_flight|ssthresh|packets_in_flight|"
    "pacing_rate" },
  { "congestion_state_updated", "old|new|trigger" },
  { "packet_lost",
    QC_HDR "|" QC_FRAMES "|is_mtu_probe_packet|trigger" },
  { "marked_for_retransmit", QC_FRAMES },
  { "ecn_state_updated", "old|new" },
  { NULL, NULL }
};

/* KEY with the numbers of its list items as N.  */
static void
qc_normalize (const char *key, char *out, size_t cap)
{
  size_t o = 0;
  const char *p = key;

  while (*p && o + 2 < cap)
    {
      const char *dot = strchr (p, '.');
      size_t n = dot ? (size_t) (dot - p) : strlen (p);

      if (qc_digits_n (p, n))
        out[o++] = 'N';
      else
        {
          if (o + n + 2 >= cap)
            break;
          memcpy (out + o, p, n);
          o += n;
        }
      if (!dot)
        break;
      out[o++] = '.';
      p = dot + 1;
    }
  out[o] = '\0';
}

/* A list of the values a field may take, "|" between.  The empty set after
   the last entry ends the table.  EVENT "*" is for a field of any event;
   frames are checked as "frame:" plus the frame type.  */
struct qc_enum
{
  const char *event, *key, *values;
};

#define QC_PACKET_TYPES \
  "initial|handshake|0RTT|1RTT|retry|version_negotiation|stateless_reset|unknown"
#define QC_STATES_BASE "attempted|handshake_started|handshake_complete|closed"
#define QC_STATES_GRAN "peer_validated|early_write|handshake_confirmed|closing|draining"
#define QC_STREAM_STATES \
  "idle|open|closed|half_closed_local|half_closed_remote|ready|send|data_sent|" \
  "reset_sent|reset_received|receive|size_known|data_read|reset_read|" \
  "data_received|destroyed"
#define QC_BLOCK_REASONS \
  "scheduling|pacing|amplification_protection|congestion_control|" \
  "connection_flow_control|stream_flow_control|stream_id|application"
#define QC_KEY_TYPES \
  "server_initial_secret|client_initial_secret|server_handshake_secret|" \
  "client_handshake_secret|server_0rtt_secret|client_0rtt_secret|" \
  "server_1rtt_secret|client_1rtt_secret"

static const struct qc_enum qc_enums[] = {
  { "*", "initiator", "local|remote" },
  { "*", "header.packet_type", QC_PACKET_TYPES },
  { "packet_sent", "trigger",
    "retransmit_reordered|retransmit_timeout|pto_probe|retransmit_crypto|"
    "cc_bandwidth_probe" },
  { "packet_received", "trigger", "keys_available" },
  { "packet_dropped", "trigger",
    "internal_error|rejected|unsupported|invalid|duplicate|connection_unknown|"
    "decryption_failure|key_unavailable|general" },
  { "packet_buffered", "trigger", "backpressure|keys_unavailable" },
  { "packet_lost", "trigger", "reordering_threshold|time_threshold|pto_expired" },
  { "connection_closed", "trigger",
    "idle_timeout|application|error|version_mismatch|stateless_reset|aborted|"
    "unspecified" },
  { "connection_state_updated", "old", QC_STATES_BASE "|" QC_STATES_GRAN },
  { "connection_state_updated", "new", QC_STATES_BASE "|" QC_STATES_GRAN },
  { "stream_state_updated", "old", QC_STREAM_STATES },
  { "stream_state_updated", "new", QC_STREAM_STATES },
  { "stream_state_updated", "stream_side", "sending|receiving" },
  { "stream_state_updated", "trigger", "local|remote" },
  { "stream_state_updated", "stream_type", "unidirectional|bidirectional" },
  { "stream_data_moved", "from", "application|transport|network" },
  { "stream_data_moved", "to", "application|transport|network" },
  { "stream_data_moved", "additional_info", "fin_set|stream_reset" },
  { "datagram_data_moved", "from", "application|transport|network" },
  { "datagram_data_moved", "to", "application|transport|network" },
  { "connection_data_blocked_updated", "old", "blocked|unblocked" },
  { "connection_data_blocked_updated", "new", "blocked|unblocked" },
  { "connection_data_blocked_updated", "reason", QC_BLOCK_REASONS },
  { "stream_data_blocked_updated", "old", "blocked|unblocked" },
  { "stream_data_blocked_updated", "new", "blocked|unblocked" },
  { "stream_data_blocked_updated", "reason", QC_BLOCK_REASONS },
  { "datagram_data_blocked_updated", "old", "blocked|unblocked" },
  { "datagram_data_blocked_updated", "new", "blocked|unblocked" },
  { "datagram_data_blocked_updated", "reason", QC_BLOCK_REASONS },
  { "migration_state_updated", "old",
    "probing_started|probing_abandoned|probing_successful|migration_started|"
    "migration_abandoned|migration_complete" },
  { "migration_state_updated", "new",
    "probing_started|probing_abandoned|probing_successful|migration_started|"
    "migration_abandoned|migration_complete" },
  /* The draft's timers, and pacing, which its list leaves open to others.  */
  { "timer_updated", "timer_type",
    "ack|pto|loss_timeout|path_validation|handshake_timeout|idle_timeout|"
    "pacing" },
  { "timer_updated", "event_type", "set|expired|cancelled" },
  { "timer_updated", "packet_number_space", "initial|handshake|application_data" },
  { "packets_acked", "packet_number_space", "initial|handshake|application_data" },
  { "key_updated", "key_type", QC_KEY_TYPES },
  { "key_updated", "trigger", "tls|remote_update|local_update" },
  { "key_discarded", "key_type", QC_KEY_TYPES },
  { "key_discarded", "trigger", "tls|remote_update|local_update" },
  { "ecn_state_updated", "new", "testing|unknown|failed|capable" },
  { "ecn_state_updated", "old", "testing|unknown|failed|capable" },
  /* Frames.  */
  { "frame:*", "frame_type",
    "padding|ping|ack|reset_stream|reset_stream_at|stop_sending|crypto|"
    "new_token|stream|max_data|max_stream_data|max_streams|data_blocked|"
    "stream_data_blocked|streams_blocked|new_connection_id|"
    "retire_connection_id|path_challenge|path_response|connection_close|"
    "handshake_done|unknown|datagram" },
  { "frame:max_streams", "stream_type", "unidirectional|bidirectional" },
  { "frame:streams_blocked", "stream_type", "unidirectional|bidirectional" },
  { "frame:connection_close", "error_space", "transport|application" },
  { NULL, NULL, NULL }
};

/* The fields an event must have, as the draft's CDDL lacks a "?" on them.
   "|" lists alternatives, one of which must be present.  */
static const struct
{
  const char *event, *required;
} qc_required[] = {
  { "connection_id_updated", "initiator" },
  { "connection_state_updated", "new" },
  { "tuple_assigned", "tuple_id" },
  { "packet_sent", "header.packet_type" },
  { "packet_received", "header.packet_type" },
  { "stream_state_updated", "stream_id" },
  { "stream_state_updated", "new" },
  { "stream_state_updated", "stream_side" },
  { "connection_data_blocked_updated", "new" },
  { "stream_data_blocked_updated", "new" },
  { "stream_data_blocked_updated", "stream_id" },
  { "datagram_data_blocked_updated", "new" },
  { "migration_state_updated", "new" },
  { "timer_updated", "event_type" },
  { "key_updated", "key_type" },
  { "key_discarded", "key_type" },
  { "recovery_parameters_set", "timer_granularity" },
  { "congestion_state_updated", "new" },
  { "marked_for_retransmit", "frames.0.frame_type" },
  { "recovery_metrics_updated",
    "min_rtt|smoothed_rtt|latest_rtt|rtt_variance|pto_count|congestion_window|"
    "bytes_in_flight|ssthresh|packets_in_flight|pacing_rate" },
  { NULL, NULL }
};

/* The fields each frame must have.  */
static const struct
{
  const char *frame, *required;
} qc_frame_required[] = {
  { "ack", "acked_ranges" },
  { "reset_stream", "stream_id|error|final_size" },
  { "stop_sending", "stream_id|error" },
  { "crypto", "offset|raw.length" },
  { "new_token", "token.raw.length" },
  { "stream", "stream_id" },
  { "max_data", "maximum" },
  { "max_stream_data", "stream_id|maximum" },
  { "max_streams", "stream_type|maximum" },
  { "data_blocked", "limit" },
  { "stream_data_blocked", "stream_id|limit" },
  { "streams_blocked", "stream_type|limit" },
  { "new_connection_id",
    "sequence_number|retire_prior_to|connection_id" },
  { "retire_connection_id", "sequence_number" },
  { NULL, NULL }
};

static int
qc_in_list (const char *list, const char *v)
{
  size_t n = strlen (v);

  while (*list)
    {
      const char *bar = strchr (list, '|');
      size_t m = bar ? (size_t) (bar - list) : strlen (list);

      if (m == n && !strncmp (list, v, n))
        return 1;
      if (!bar)
        break;
      list = bar + 1;
    }
  return 0;
}

/* Every alternative of "a|b|c" needs to be there? No: at least one.  */
static int
qc_has_any (const qline *q, const char *alts, const char *frame_prefix)
{
  char key[160];
  const char *p = alts;

  while (*p)
    {
      const char *bar = strchr (p, '|');
      size_t m = bar ? (size_t) (bar - p) : strlen (p);

      snprintf (key, sizeof key, "%s%.*s", frame_prefix, (int) m, p);
      if (qline_get (q, key))
        return 1;
      if (!bar)
        break;
      p = bar + 1;
    }
  return 0;
}

/* A value's type by the name of its field (the last component of it). */
static const char *const qc_uint_keys[] = {
  "packet_number", "packet_number_length", "length", "payload_length",
  "stream_id", "offset", "maximum", "limit", "final_size", "sequence_number",
  "retire_prior_to", "connection_id_length", "scil", "dcil", "error_code",
  "trigger_frame_type", "frame_type_bytes", "ect0", "ect1", "ce", "count",
  "datagram_id", "max_idle_timeout", "max_udp_payload_size",
  "ack_delay_exponent", "max_ack_delay", "active_connection_id_limit",
  "initial_max_data", "initial_max_stream_data_bidi_local",
  "initial_max_stream_data_bidi_remote", "initial_max_stream_data_uni",
  "initial_max_streams_bidi", "initial_max_streams_uni",
  "max_datagram_frame_size", "port_v4", "port_v6", "pto_count",
  "congestion_window", "bytes_in_flight", "ssthresh", "packets_in_flight",
  "pacing_rate", "reordering_threshold", "timer_granularity",
  "max_datagram_size", "initial_congestion_window",
  "minimum_congestion_window", "persistent_congestion_threshold", "key_phase",
  "id", NULL
};
static const char *const qc_ms_keys[] = {
  "ack_delay", "min_rtt", "smoothed_rtt", "latest_rtt", "rtt_variance",
  "initial_rtt", "delta", NULL
};
static const char *const qc_milli_keys[] = {
  "time_threshold", "loss_reduction_factor", NULL
};
static const char *const qc_bool_keys[] = {
  "fin", "key_phase_bit", "spin_bit", "disable_active_migration",
  "resumption_allowed", "early_data_enabled", "retry_required", "done",
  "grease_quic_bit", "reset_stream_at", NULL
};
static const char *const qc_hex_keys[] = {
  "dcid", "scid", "version", "connection_id", "stateless_reset_token", "data",
  "byte_value", "original_destination_connection_id",
  "initial_source_connection_id", "retry_source_connection_id",
  "chosen_version", "reason_bytes", "value", NULL
};

static int
qc_key_in (const char *const *list, const char *last)
{
  for (; *list; list++)
    if (!strcmp (*list, last))
      return 1;
  return 0;
}

/* Does V look like a (comma-separated list of) decimal numbers, N.NNN
   milliseconds, hex?  */
static int
qc_digits (const char *v)
{
  if (!*v)
    return 0;
  for (; *v; v++)
    if (*v < '0' || *v > '9')
      return 0;
  return 1;
}

static int
qc_is_ms (const char *v)
{
  const char *dot = strchr (v, '.');
  char whole[32];

  if (!dot || strlen (dot + 1) != 3 || !qc_digits (dot + 1))
    return 0;
  if ((size_t) (dot - v) >= sizeof whole)
    return 0;
  memcpy (whole, v, (size_t) (dot - v));
  whole[dot - v] = '\0';
  return qc_digits (whole);
}

static int
qc_is_hex (const char *v)
{
  size_t n = strlen (v);

  if (n % 2)
    return 0;
  for (; *v; v++)
    if (!((*v >= '0' && *v <= '9') || (*v >= 'a' && *v <= 'f')))
      return 0;
  return 1;
}

/* The checks for one field.  Returns an error text or NULL.  */
static const char *
qc_check_field (const char *event, const char *key, const char *val)
{
  const char *last = strrchr (key, '.');
  size_t i;
  char frame[48] = "";

  last = last ? last + 1 : key;
  /* Which frame a field of frames.N.* belongs to is in its frame_type;
     the enumerated values of frames are checked by the frame check.  */
  (void) frame;
  /* A field that is a list of ranges, or of anything, is not a scalar.  */
  if (!strcmp (last, "acked_ranges"))
    {
      /* LOW or LOW-HIGH, comma-separated, LOW <= HIGH.  */
      const char *p = val;

      if (!*p)
        return "empty acked_ranges";
      while (*p)
        {
          char *end;
          unsigned long long lo = strtoull (p, &end, 10), hi = lo;

          if (end == p)
            return "bad range";
          if (*end == '-')
            {
              p = end + 1;
              hi = strtoull (p, &end, 10);
              if (end == p || hi <= lo)
                return "bad range";
            }
          if (*end == ',')
            end++;
          else if (*end)
            return "bad range";
          p = end;
        }
      return NULL;
    }
  if (!strcmp (last, "packet_numbers") || !strcmp (last, "datagram_ids"))
    {
      const char *p = val;

      if (!*p)
        return "empty list of numbers";
      while (*p)
        {
          char *end;

          strtoull (p, &end, 10);
          if (end == p || (*end && *end != ','))
            return "bad number list";
          p = *end ? end + 1 : end;
        }
      return NULL;
    }
  if (!strcmp (last, "client_versions") || !strcmp (last, "server_versions")
      || !strcmp (last, "supported_versions")
      || !strcmp (last, "connection_ids"))
    {
      char *copy = strdup (val), *tok, *save = NULL;
      const char *err = NULL;

      for (tok = strtok_r (copy, ",", &save); tok;
           tok = strtok_r (NULL, ",", &save))
        if (!qc_is_hex (tok) || !*tok)
          err = "bad hex in list";
      free (copy);
      return err;
    }
  if (qc_key_in (qc_uint_keys, last) && !qc_digits (val))
    return "not a number";
  if (qc_key_in (qc_ms_keys, last) && !qc_is_ms (val))
    return "not a time in milliseconds";
  if (qc_key_in (qc_milli_keys, last) && !qc_is_ms (val))
    return "not a decimal";
  if (qc_key_in (qc_bool_keys, last) && strcmp (val, "true")
      && strcmp (val, "false"))
    return "not a boolean";
  if (qc_key_in (qc_hex_keys, last) && !qc_is_hex (val))
    return "not hex";
  for (i = 0; qc_enums[i].event; i++)
    {
      const struct qc_enum *e = &qc_enums[i];

      if (strncmp (e->event, "frame:", 6) == 0)
        continue;
      if (strcmp (e->key, key))
        continue;
      if (strcmp (e->event, "*") && strcmp (e->event, event))
        continue;
      if (!qc_in_list (e->values, val))
        return "value not allowed here";
    }
  return NULL;
}

/* Check the frames of a packet event.  Each frame is a set of fields
   frames.N.*, and has all the fields its type requires (qc_frame_required
   lists them with "|" between) and only the values its enumerated fields
   allow.  */
static const char *
qc_check_frames (const qline *q)
{
  size_t i;

  for (i = 0; i < q->n; i++)
    {
      const char *dot, *key = q->key[i], *ft;
      char prefix[48], fk[160];
      size_t k;

      if (strncmp (key, "frames.", 7) != 0)
        continue;
      dot = strchr (key + 7, '.');
      if (!dot || dot - key >= (long) sizeof prefix - 1)
        return "malformed frames key";
      memcpy (prefix, key, (size_t) (dot - key + 1));
      prefix[dot - key + 1] = '\0';
      snprintf (fk, sizeof fk, "%sframe_type", prefix);
      ft = qline_get (q, fk);
      if (ft == NULL)
        return "frame without a frame_type";
      if (strcmp (fk, key) != 0)
        continue;			/* Once per frame.  */
      for (k = 0; qc_enums[k].event; k++)
        {
          const char *e = qc_enums[k].event;
          const char *v;

          if (strncmp (e, "frame:", 6) != 0)
            continue;
          if (strcmp (e + 6, "*") && strcmp (e + 6, ft))
            continue;
          snprintf (fk, sizeof fk, "%s%s", prefix, qc_enums[k].key);
          v = qline_get (q, fk);
          if (v && !qc_in_list (qc_enums[k].values, v))
            return "frame value not allowed here";
        }
      for (k = 0; qc_frame_required[k].frame; k++)
        if (!strcmp (qc_frame_required[k].frame, ft))
          {
            const char *p = qc_frame_required[k].required;

            while (*p)
              {
                const char *bar = strchr (p, '|');
                size_t m = bar ? (size_t) (bar - p) : strlen (p);

                snprintf (fk, sizeof fk, "%s%.*s", prefix, (int) m, p);
                if (!qline_get (q, fk))
                  return "frame lacks a required field";
                if (!bar)
                  break;
                p = bar + 1;
              }
          }
    }
  return NULL;
}

/* Check an event: NAME as the library reports it ("quic:packet_sent") and
   FIELDS.  Returns NULL if it is as the draft says, or what is wrong, with
   WHERE set to the field if it is one.  */
static const char *
qc_check (const char *name, const char *fields, size_t len, char *where,
          size_t wherecap)
{
  qline q;
  const char *event, *err = NULL;
  size_t i, k;
  int known = 0;

  where[0] = '\0';
  if (strncmp (name, "quic:", 5) != 0)
    return "event outside the quic namespace";
  event = name + 5;
  for (i = 0; qc_events[i]; i++)
    if (!strcmp (qc_events[i], event))
      known = 1;
  if (!known)
    return "event not in the draft";
  if (!qline_parse (fields, len, &q))
    return "line does not parse";
  for (i = 0; i < q.n && !err; i++)
    {
      char norm[160];
      const char *allowed = NULL;

      err = qc_check_field (event, q.key[i], q.val[i]);
      if (!err && strcmp (q.key[i], "tuple") != 0)
        {
          qc_normalize (q.key[i], norm, sizeof norm);
          for (k = 0; qc_allowed[k].event; k++)
            if (!strcmp (qc_allowed[k].event, event))
              allowed = qc_allowed[k].paths;
          if (allowed && !qc_in_list (allowed, norm))
            err = "a field the draft does not give this event";
        }
      if (err)
        snprintf (where, wherecap, "%s=%s", q.key[i], q.val[i]);
    }
  for (i = 0; !err && qc_required[i].event; i++)
    if (!strcmp (qc_required[i].event, event)
        && !qc_has_any (&q, qc_required[i].required, ""))
      {
        err = "required field missing";
        snprintf (where, wherecap, "%s", qc_required[i].required);
      }
  if (!err)
    {
      err = qc_check_frames (&q);
      if (err)
        snprintf (where, wherecap, "frames");
    }
  /* The tuple, if there is one, is a field of its own and first.  */
  for (k = 0; !err && k < q.n; k++)
    if (!strcmp (q.key[k], "tuple") && k != 0)
      err = "tuple is not the first field";
  qline_free (&q);
  return err;
}

#if defined __GNUC__
# pragma GCC diagnostic pop
#endif

#endif /* GQ_TST_QLOGCHECK_H */
