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

/* What this build can do, for the interop scripts to decide what to run.

     interop-probe mldsa-chain

   exits 0 if the GnuTLS the library validates certificates with can check an
   ML-DSA signature, which is what a chain under an ML-DSA CA needs (a chain
   under a classical CA does not, and ML-DSA signing itself is libgcrypt's);
   1 if it cannot; 2 for a probe it does not know.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#ifdef HAVE_GNUTLS
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
#endif

int
main (int argc, char **argv)
{
  if (argc != 2 || strcmp (argv[1], "mldsa-chain") != 0)
    {
      fprintf (stderr, "usage: interop-probe mldsa-chain\n");
      return 2;
    }
#if defined HAVE_GNUTLS && HAVE_DECL_GNUTLS_PK_MLDSA65
  {
    /* The backend is there if it can make a key.  */
    gnutls_x509_privkey_t k;
    int ok = 0;

    if (gnutls_x509_privkey_init (&k) >= 0)
      {
        ok = gnutls_x509_privkey_generate (k, GNUTLS_PK_MLDSA65, 0, 0) >= 0;
        gnutls_x509_privkey_deinit (k);
      }
    return ok ? 0 : 1;
  }
#else
  return 1;
#endif
}
