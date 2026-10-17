## Copyright (C) 2026 Chris Burdess <dog@gnu.org>
##
## This file is part of quickstep.
##
## quickstep is free software: you can redistribute it and/or modify it
## under the terms of the GNU General Public License as published
## by the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## quickstep is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
##
## You should have received a copy of the GNU General Public
## License along with this program.  If not, see
## <https://www.gnu.org/licenses/>.

## The integration suite: tests that use real I/O (sockets, processes, files,
## the host's own programs and trust store) or the real clock, and so can be
## slow, depend on what the host has installed, and fail for reasons outside
## the library.  The unit tests are in ../tests and are what "make check"
## runs; this directory is not part of "make", "make check" or "make
## install", only of "make check-integration" at the top level (or "make
## check" here).  Each test skips itself (exit 77) when what it needs is not
## there.

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = $(STD_CFLAGS) $(WARN_CFLAGS) $(GNUTLS_CFLAGS)
LDADD = $(top_builddir)/src/libquickstep.la $(GNUTLS_LIBS)

INTEGRATION_PROGS =
INTEGRATION_TESTS =

## Against OpenSSL, GnuTLS and quiche, and the quic-interop-runner endpoint
## (quic-interop-runner/README.md) against itself.
if HAVE_GNUTLS
INTEGRATION_PROGS += interop-client interop-server interop-dtls interop-quic \
  interop-probe quic-interop-endpoint qlog-lint integ-files
INTEGRATION_TESTS += interop.sh interop-quic.sh quic-interop-runner/smoke.sh \
  integ-files
endif

## DTLS 1.3 and 1.2 against wolfSSL, if it is installed with DTLS 1.3.
if HAVE_WOLFSSL
if HAVE_GNUTLS
INTEGRATION_PROGS += wolf-dtls
INTEGRATION_TESTS += interop-dtls.sh interop-dtls12.sh
endif
endif

check_PROGRAMS = $(INTEGRATION_PROGS)
TESTS = $(INTEGRATION_TESTS)

interop_client_SOURCES = interop-client.c
interop_server_SOURCES = interop-server.c
interop_dtls_SOURCES = interop-dtls.c
interop_quic_SOURCES = interop-quic.c
interop_probe_SOURCES = interop-probe.c
quic_interop_endpoint_SOURCES = quic-interop-runner/endpoint.c
qlog_lint_SOURCES = quic-interop-runner/qlog_lint.c
qlog_lint_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/tests
integ_files_SOURCES = integ-files.c
integ_files_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/tests
wolf_dtls_SOURCES = wolf-dtls.c
wolf_dtls_CFLAGS = $(AM_CFLAGS) $(WOLFSSL_CFLAGS)
wolf_dtls_LDADD = $(WOLFSSL_LIBS)

TESTS_ENVIRONMENT = INTEROP_CLIENT=./interop-client; export INTEROP_CLIENT; \
  INTEROP_SERVER=./interop-server; export INTEROP_SERVER; \
  INTEROP_DTLS=./interop-dtls; export INTEROP_DTLS; \
  INTEROP_QUIC=./interop-quic; export INTEROP_QUIC; \
  INTEROP_PROBE=./interop-probe; export INTEROP_PROBE; \
  QUIC_INTEROP_ENDPOINT=./quic-interop-endpoint; export QUIC_INTEROP_ENDPOINT; \
  QLOG_LINT=./qlog-lint; export QLOG_LINT; \
  WOLF_DTLS=./wolf-dtls; export WOLF_DTLS;

EXTRA_DIST = interop.sh interop-dtls.sh interop-dtls12.sh interop-quic.sh \
  interop-util.h quic-interop-runner/smoke.sh quic-interop-runner/README.md \
  quic-interop-runner/Dockerfile quic-interop-runner/run_endpoint.sh \
  quic-interop-runner/ack_stats.py quic-interop-runner/dump_frames.py \
  quic-interop-runner/qlog_lint.c
