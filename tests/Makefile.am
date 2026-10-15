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

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = $(STD_CFLAGS) $(WARN_CFLAGS) $(GNUTLS_CFLAGS)
LDADD = $(top_builddir)/src/libquickstep.la $(GNUTLS_LIBS)

UNIT_TESTS = test-varint test-frame test-crypto test-policy test-trust \
  test-packet test-protect test-tparams test-kx test-sign \
  test-tlsmsg test-keysched test-tls-client test-record test-tlsconn test-tls-server \
  test-resume test-tickets test-early test-tls12ks test-record12 test-tls12 \
  test-tls12conn test-dtlsrec test-dtlshs test-dtls test-dtls12rec test-dtls12 test-ranges test-stream test-tlsauto test-dtlsauto test-quiclb test-conn test-conn-int test-token test-endpoint

TESTS = $(UNIT_TESTS)
check_PROGRAMS = $(UNIT_TESTS)

# It uses the library's internals, which a shared library does not export.
test_conn_int_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src
test_conn_int_LDFLAGS = -static

EXTRA_DIST = tst-util.h tst-x509.h tst-fix12.h tst-tlspeer.h vectors.h vectors-tls.h vectors-resume.h
