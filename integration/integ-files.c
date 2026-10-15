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

/* What the unit tests leave out because it reads the file system: loading
   a private key from a file, and loading the host's own trust store (whose
   contents vary from host to host, so only that it loads is checked).  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h>

#include <quickstep/status.h>
#include <quickstep/policy.h>
#include <quickstep/sign.h>
#include <quickstep/trust.h>

#include "../tests/tst-util.h"

#ifndef HAVE_GNUTLS

int
main (void)
{
  return 77;
}

#else

#include "../tests/tst-x509.h"

static void
test_key_file (void)
{
  struct tst_cert c;
  gq_privkey *k;
  char path[] = "/tmp/gq-key-XXXXXX";
  int fd;
  gnutls_datum_t pem;

  CHECK_EQ (tst_make_cert (&c, TST_ECDSA256, "file test", "example.test", NULL,
                           -3600, 86400, GNUTLS_DIG_SHA256), 0);
  CHECK_EQ (gq_privkey_from_pem_file (&k, "/nonexistent/key.pem"),
            GQ_ERR_INVAL);
  fd = mkstemp (path);
  CHECK (fd >= 0);
  if (fd >= 0)
    {
      CHECK_EQ (gnutls_x509_privkey_export2_pkcs8 (c.key, GNUTLS_X509_FMT_PEM,
                                                   NULL, GNUTLS_PKCS_PLAIN,
                                                   &pem), 0);
      CHECK_EQ ((size_t) write (fd, pem.data, pem.size), (size_t) pem.size);
      close (fd);
      CHECK_EQ (gq_privkey_from_pem_file (&k, path), GQ_OK);
      CHECK (gq_privkey_supports (k, GQ_SIG_ECDSA_SECP256R1_SHA256));
      gq_privkey_free (k);
      gnutls_free (pem.data);
      unlink (path);
    }
  tst_free_cert (&c);
}

static void
test_system_store (void)
{
  gq_trust *t;
  size_t count = 0;

  CHECK_EQ (gq_trust_new (&t), GQ_OK);
  CHECK_EQ (gq_trust_add_system (t, &count), GQ_OK);
  gq_trust_free (t);
}

int
main (void)
{
  test_key_file ();
  test_system_store ();
  TST_DONE ();
}

#endif
