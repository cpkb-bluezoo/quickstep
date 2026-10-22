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
  test-packet test-protect test-tparams test-kx test-mlkem test-mldsa test-sign \
  test-tlsmsg test-keysched test-tls-client test-record test-tlsconn test-tls-server \
  test-resume test-tickets test-early test-tls12ks test-record12 test-tls12 \
  test-tls12conn test-dtlsrec test-dtlshs test-dtls test-dtls12rec test-dtls12 test-ranges test-stream test-tlsauto test-dtlsauto test-quiclb test-conn test-conn-int test-cc test-qlog test-token test-endpoint test-replay

TESTS = $(UNIT_TESTS)
check_PROGRAMS = $(UNIT_TESTS)

# It uses the library's own ML-DSA module, which a shared library does not
# export.
test_tlsconn_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src
test_tlsconn_LDFLAGS = -static
test_dtls_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src
test_dtls_LDFLAGS = -static
test_conn_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src
test_conn_LDFLAGS = -static
test_tls_server_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src
test_tls_server_LDFLAGS = -static
test_trust_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src
test_trust_LDFLAGS = -static
test_sign_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src
test_sign_LDFLAGS = -static
test_mldsa_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src
test_mldsa_LDFLAGS = -static

# Calls libgcrypt's KEM interface directly to check it against the FIPS 203
# vectors.
test_mlkem_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS)
test_mlkem_LDADD = $(LDADD) $(LIBGCRYPT_LIBS)
# These count libgcrypt's allocations (tst-alloc.h) to see how many cipher
# contexts a packet or a record opens.
test_protect_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS)
test_protect_LDADD = $(LDADD) $(LIBGCRYPT_LIBS)
# These read libgcrypt's random statistics (tst-rndstats.h) to see what a key
# share or an HMAC asks of the generator.
test_kx_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS)
test_kx_LDADD = $(LDADD) $(LIBGCRYPT_LIBS)
test_crypto_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS)
test_crypto_LDADD = $(LDADD) $(LIBGCRYPT_LIBS)
test_record_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS)
test_record_LDADD = $(LDADD) $(LIBGCRYPT_LIBS)
test_record12_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS)
test_record12_LDADD = $(LDADD) $(LIBGCRYPT_LIBS)
test_dtlsrec_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS)
test_dtlsrec_LDADD = $(LDADD) $(LIBGCRYPT_LIBS)
test_dtls12rec_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS)
test_dtls12rec_LDADD = $(LDADD) $(LIBGCRYPT_LIBS)

# It uses the library's internals, which a shared library does not export.
test_conn_int_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src
test_conn_int_LDFLAGS = -static
test_cc_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src
test_cc_LDFLAGS = -static
test_qlog_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src
test_qlog_LDFLAGS = -static
test_replay_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src
test_replay_LDFLAGS = -static

EXTRA_DIST = tst-alloc.h tst-rndstats.h tst-qkv.h tst-util.h tst-x509.h tst-fix12.h tst-tlspeer.h vectors.h vectors-tls.h vectors-resume.h vectors-mlkem.h vectors-mldsa.h tst-mldsa-cert.h tst-qlogcheck.h vectors-pss.h
