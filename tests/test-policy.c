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

#include <quickstep/policy.h>

#include "tst-util.h"

int
main (void)
{
  size_t n, i;
  const uint16_t *l;

  CHECK (gq_policy_allows_version (GQ_TLS_1_3));
  CHECK (gq_policy_allows_version (GQ_DTLS_1_2));
  CHECK (!gq_policy_allows_version (0x0301));	/* TLS 1.0.  */
  CHECK (!gq_policy_allows_version (0x0302));	/* TLS 1.1.  */
  CHECK (!gq_policy_allows_version (0x0300));	/* SSL 3.0.  */
  CHECK (!gq_policy_allows_version (0xfeff));	/* DTLS 1.0.  */

  /* Suites are scoped to the version generation.  */
  CHECK (gq_policy_allows_suite (GQ_TLS_1_3, GQ_TLS_AES_128_GCM_SHA256));
  CHECK (!gq_policy_allows_suite (GQ_TLS_1_2, GQ_TLS_AES_128_GCM_SHA256));
  CHECK (gq_policy_allows_suite (GQ_TLS_1_2,
                                 GQ_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256));
  CHECK (!gq_policy_allows_suite (GQ_TLS_1_3,
                                  GQ_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256));
  CHECK (!gq_policy_allows_suite (GQ_TLS_1_2, 0xc013));	/* CBC.  */
  CHECK (!gq_policy_allows_suite (GQ_TLS_1_2, 0x009c));	/* Static RSA GCM.  */
  CHECK (!gq_policy_allows_suite (GQ_TLS_1_2, 0x0005));	/* RC4.  */

  CHECK (gq_policy_allows_group (GQ_GROUP_X25519_MLKEM768));
  CHECK (!gq_policy_allows_group (0x0100));		/* ffdhe2048.  */

  /* The pure ML-KEM groups are permitted for the 1.3 protocols, not 1.2.  */
  CHECK (gq_policy_allows_group (GQ_GROUP_MLKEM512));
  CHECK (gq_policy_allows_group (GQ_GROUP_MLKEM768));
  CHECK (gq_policy_allows_group (GQ_GROUP_MLKEM1024));
  CHECK (gq_policy_allows_group_for (GQ_TLS_1_3, GQ_GROUP_MLKEM768));
  CHECK (gq_policy_allows_group_for (GQ_DTLS_1_3, GQ_GROUP_MLKEM1024));
  CHECK (!gq_policy_allows_group_for (GQ_TLS_1_2, GQ_GROUP_MLKEM768));
  CHECK (!gq_policy_allows_group_for (GQ_DTLS_1_2, GQ_GROUP_MLKEM768));
  CHECK (!gq_policy_allows_group (0x0019));		/* secp521r1.  */

  CHECK (gq_policy_allows_sigscheme (GQ_TLS_1_3, GQ_SIG_MLDSA65));
  CHECK (!gq_policy_allows_sigscheme (GQ_TLS_1_2, GQ_SIG_MLDSA65));
  CHECK (!gq_policy_allows_sigscheme (GQ_TLS_1_3, 0x0201));	/* RSA SHA-1.  */
  CHECK (!gq_policy_allows_sigscheme (GQ_TLS_1_3, 0x0401));	/* PKCS1 SHA256.  */

  /* TLS 1.2 is narrower on groups and signatures, wider on RSA.  */
  CHECK (gq_policy_allows_sigscheme (GQ_TLS_1_2, GQ_SIG_RSA_PKCS1_SHA256));
  CHECK (gq_policy_allows_sigscheme (GQ_DTLS_1_2, GQ_SIG_RSA_PKCS1_SHA384));
  CHECK (gq_policy_allows_sigscheme (GQ_TLS_1_2, GQ_SIG_ECDSA_SECP256R1_SHA256));
  CHECK (gq_policy_allows_sigscheme (GQ_TLS_1_2, GQ_SIG_ED25519));	/* RFC 8422.  */
  CHECK (!gq_policy_allows_sigscheme (GQ_TLS_1_2, 0x0201));	/* RSA SHA-1.  */
  CHECK (!gq_policy_allows_sigscheme (GQ_TLS_1_2, 0x0203));	/* ECDSA SHA-1.  */
  CHECK (gq_policy_allows_group_for (GQ_TLS_1_2, GQ_GROUP_SECP256R1));
  CHECK (gq_policy_allows_group_for (GQ_TLS_1_2, GQ_GROUP_X25519));
  CHECK (!gq_policy_allows_group_for (GQ_TLS_1_2, GQ_GROUP_SECP384R1));
  CHECK (!gq_policy_allows_group_for (GQ_DTLS_1_2, GQ_GROUP_X25519_MLKEM768));
  CHECK (gq_policy_allows_group_for (GQ_TLS_1_3, GQ_GROUP_X25519));
  CHECK (!gq_policy_allows_group_for (0x0301, GQ_GROUP_SECP256R1));

  /* DTLS 1.2 has the TLS 1.2 profile.  */
  CHECK (gq_policy_allows_group_for (GQ_DTLS_1_2, GQ_GROUP_SECP256R1));
  CHECK (gq_policy_allows_group_for (GQ_DTLS_1_2, GQ_GROUP_X25519));
  CHECK (gq_policy_allows_sigscheme (GQ_DTLS_1_2, GQ_SIG_RSA_PKCS1_SHA256));
  CHECK (gq_policy_allows_sigscheme (GQ_DTLS_1_2, GQ_SIG_ED25519));
  CHECK (gq_policy_allows_suite (GQ_DTLS_1_2,
                                 GQ_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305));
  CHECK (!gq_policy_allows_suite (GQ_DTLS_1_2, GQ_TLS_AES_128_GCM_SHA256));

  /* Every default is itself permitted, and PQ hybrids lead.  */
  l = gq_policy_default_groups (&n);
  CHECK (n > 0 && l[0] == GQ_GROUP_X25519_MLKEM768);
  for (i = 0; i < n; i++)
    CHECK (gq_policy_allows_group (l[i]));

  /* The pure groups are opt-in: no default list offers them, so the
     default stays hybrid first.  */
  l = gq_policy_default_groups (&n);
  for (i = 0; i < n; i++)
    CHECK (l[i] != GQ_GROUP_MLKEM512 && l[i] != GQ_GROUP_MLKEM768
           && l[i] != GQ_GROUP_MLKEM1024);
  l = gq_policy_default_groups_for (GQ_DTLS_1_3, &n);
  for (i = 0; i < n; i++)
    CHECK (l[i] != GQ_GROUP_MLKEM512 && l[i] != GQ_GROUP_MLKEM768
           && l[i] != GQ_GROUP_MLKEM1024);

  /* The supported list is every permitted TLS 1.3 group in the policy's
     own order: the hybrids, then the pure groups, then the classical
     ones.  It contains the default list as a subsequence.  */
  {
    static const uint16_t want[] = {
      GQ_GROUP_X25519_MLKEM768, GQ_GROUP_SECP256R1_MLKEM768,
      GQ_GROUP_SECP384R1_MLKEM1024, GQ_GROUP_MLKEM768, GQ_GROUP_MLKEM1024,
      GQ_GROUP_MLKEM512, GQ_GROUP_X25519, GQ_GROUP_SECP256R1,
      GQ_GROUP_SECP384R1
    };
    size_t nd, j = 0;
    const uint16_t *d = gq_policy_default_groups (&nd);

    l = gq_policy_supported_groups (&n);
    CHECK_EQ (n, sizeof want / sizeof want[0]);
    for (i = 0; i < n && i < sizeof want / sizeof want[0]; i++)
      CHECK_EQ (l[i], want[i]);
    for (i = 0; i < n; i++)
      CHECK (gq_policy_allows_group (l[i]));
    for (i = 0; i < n && j < nd; i++)
      if (l[i] == d[j])
        j++;
    CHECK_EQ (j, nd);
  }

  l = gq_policy_default_suites (GQ_TLS_1_3, &n);
  for (i = 0; i < n; i++)
    CHECK (gq_policy_allows_suite (GQ_TLS_1_3, l[i]));
  l = gq_policy_default_suites (GQ_DTLS_1_2, &n);
  for (i = 0; i < n; i++)
    CHECK (gq_policy_allows_suite (GQ_DTLS_1_2, l[i]));
  l = gq_policy_default_sigschemes_for (GQ_TLS_1_2, &n);
  CHECK (n > 0);
  for (i = 0; i < n; i++)
    CHECK (gq_policy_allows_sigscheme (GQ_TLS_1_2, l[i]));
  l = gq_policy_default_groups_for (GQ_TLS_1_2, &n);
  CHECK (n == 2 && l[0] == GQ_GROUP_SECP256R1 && l[1] == GQ_GROUP_X25519);
  l = gq_policy_default_suites (0x0301, &n);
  CHECK (l == NULL && n == 0);

  TST_DONE ();
}
