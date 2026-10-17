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

/* Known-answer tests for ML-KEM-512, ML-KEM-768 and ML-KEM-1024 as libgcrypt
   provides them, against the NIST ACVP vectors for FIPS 203 (see
   vectors-mlkem.h).  libgcrypt 1.11 implements the initial public draft
   of the standard, which gives different keys, ciphertexts and secrets
   and does not interoperate; this is what notices a library built from
   it, or one that regressed to it.

   libgcrypt lets the caller supply the randomness, so all three
   operations are checked in full: key generation from the seed d || z
   (the OPTIONAL argument of gcry_kem_genkey), encapsulation with the
   message m (the OPTIONAL argument of gcry_kem_encap), and decapsulation,
   including the implicit rejection of a modified ciphertext.  Nothing the
   interface hides is left untested.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gcrypt.h>

#include <quickstep/status.h>
#include <quickstep/crypto.h>

#include "tst-util.h"
#include "vectors-mlkem.h"

#define MAX_EK GCRY_KEM_MLKEM1024_PUBKEY_LEN
#define MAX_DK GCRY_KEM_MLKEM1024_SECKEY_LEN
#define MAX_CT GCRY_KEM_MLKEM1024_CIPHER_LEN

struct params
{
  const char *name;
  int algo;
  size_t ek, dk, ct;
};

static const struct params p512 =
  { "ML-KEM-512", GCRY_KEM_MLKEM512, GCRY_KEM_MLKEM512_PUBKEY_LEN,
    GCRY_KEM_MLKEM512_SECKEY_LEN, GCRY_KEM_MLKEM512_CIPHER_LEN };
static const struct params p768 =
  { "ML-KEM-768", GCRY_KEM_MLKEM768, GCRY_KEM_MLKEM768_PUBKEY_LEN,
    GCRY_KEM_MLKEM768_SECKEY_LEN, GCRY_KEM_MLKEM768_CIPHER_LEN };
static const struct params p1024 =
  { "ML-KEM-1024", GCRY_KEM_MLKEM1024, GCRY_KEM_MLKEM1024_PUBKEY_LEN,
    GCRY_KEM_MLKEM1024_SECKEY_LEN, GCRY_KEM_MLKEM1024_CIPHER_LEN };

/* Key generation from d || z must give exactly the vector's ek and dk.  */
static void
check_keygen (const struct params *p, const char *const *d,
              const char *const *z, const char *const *ek,
              const char *const *dk)
{
  uint8_t seed[64], want_ek[MAX_EK], want_dk[MAX_DK];
  uint8_t got_ek[MAX_EK], got_dk[MAX_DK];

  CHECK_EQ (tst_unhex_parts (d, seed, 32), 32);
  CHECK_EQ (tst_unhex_parts (z, seed + 32, 32), 32);
  CHECK_EQ (tst_unhex_parts (ek, want_ek, sizeof want_ek), p->ek);
  CHECK_EQ (tst_unhex_parts (dk, want_dk, sizeof want_dk), p->dk);

  CHECK_EQ (gcry_kem_genkey (p->algo, got_ek, p->ek, got_dk, p->dk, seed,
                             sizeof seed), 0);
  if (memcmp (got_ek, want_ek, p->ek) != 0)
    fprintf (stderr, "%s: encapsulation key differs\n", p->name);
  if (memcmp (got_dk, want_dk, p->dk) != 0)
    fprintf (stderr, "%s: decapsulation key differs\n", p->name);
  CHECK (memcmp (got_ek, want_ek, p->ek) == 0);
  CHECK (memcmp (got_dk, want_dk, p->dk) == 0);
}

/* Encapsulation under ek with the message m must give the vector's
   ciphertext and shared secret.  */
static void
check_encap (const struct params *p, const char *const *ek,
             const char *const *m, const char *const *c,
             const char *const *k)
{
  uint8_t pk[MAX_EK], msg[32], want_c[MAX_CT], want_k[32];
  uint8_t got_c[MAX_CT], got_k[32];

  CHECK_EQ (tst_unhex_parts (ek, pk, sizeof pk), p->ek);
  CHECK_EQ (tst_unhex_parts (m, msg, sizeof msg), 32);
  CHECK_EQ (tst_unhex_parts (c, want_c, sizeof want_c), p->ct);
  CHECK_EQ (tst_unhex_parts (k, want_k, sizeof want_k), 32);

  CHECK_EQ (gcry_kem_encap (p->algo, pk, p->ek, got_c, p->ct, got_k, 32,
                            msg, sizeof msg), 0);
  if (memcmp (got_c, want_c, p->ct) != 0)
    fprintf (stderr, "%s: ciphertext differs\n", p->name);
  if (memcmp (got_k, want_k, 32) != 0)
    fprintf (stderr, "%s: encapsulated shared secret differs\n", p->name);
  CHECK (memcmp (got_c, want_c, p->ct) == 0);
  CHECK (memcmp (got_k, want_k, 32) == 0);
}

/* Decapsulation of c with dk must give k.  For a modified ciphertext k
   is the implicit-rejection secret, which is just as deterministic.  */
static void
check_decap (const struct params *p, const char *const *dk,
             const char *const *c, const char *const *k)
{
  uint8_t sk[MAX_DK], ct[MAX_CT], want_k[32], got_k[32];

  CHECK_EQ (tst_unhex_parts (dk, sk, sizeof sk), p->dk);
  CHECK_EQ (tst_unhex_parts (c, ct, sizeof ct), p->ct);
  CHECK_EQ (tst_unhex_parts (k, want_k, sizeof want_k), 32);

  CHECK_EQ (gcry_kem_decap (p->algo, sk, p->dk, ct, p->ct, got_k, 32,
                            NULL, 0), 0);
  if (memcmp (got_k, want_k, 32) != 0)
    fprintf (stderr, "%s: decapsulated shared secret differs\n", p->name);
  CHECK (memcmp (got_k, want_k, 32) == 0);
}

#define KEYGEN(p, tag, n) \
  check_keygen (&p, (const char *const[]) { MLKEM##tag##_KEYGEN##n##_D }, \
                (const char *const[]) { MLKEM##tag##_KEYGEN##n##_Z }, \
                (const char *const[]) { MLKEM##tag##_KEYGEN##n##_EK }, \
                (const char *const[]) { MLKEM##tag##_KEYGEN##n##_DK })

#define ENCAP(p, tag, n) \
  check_encap (&p, (const char *const[]) { MLKEM##tag##_ENCAP##n##_EK }, \
               (const char *const[]) { MLKEM##tag##_ENCAP##n##_M }, \
               (const char *const[]) { MLKEM##tag##_ENCAP##n##_C }, \
               (const char *const[]) { MLKEM##tag##_ENCAP##n##_K })

#define DECAP(p, tag, n) \
  check_decap (&p, (const char *const[]) { MLKEM##tag##_DECAP##n##_DK }, \
               (const char *const[]) { MLKEM##tag##_DECAP##n##_C }, \
               (const char *const[]) { MLKEM##tag##_DECAP##n##_K })

static void
test_mlkem512 (void)
{
  KEYGEN (p512, 512, 1);
  KEYGEN (p512, 512, 2);
  ENCAP (p512, 512, 1);
  ENCAP (p512, 512, 2);
  DECAP (p512, 512, 1);
  DECAP (p512, 512, 2);		/* Modified ciphertext.  */
}

static void
test_mlkem768 (void)
{
  KEYGEN (p768, 768, 1);
  KEYGEN (p768, 768, 2);
  ENCAP (p768, 768, 1);
  ENCAP (p768, 768, 2);
  DECAP (p768, 768, 1);
  DECAP (p768, 768, 2);		/* Modified ciphertext.  */
}

static void
test_mlkem1024 (void)
{
  KEYGEN (p1024, 1024, 1);
  KEYGEN (p1024, 1024, 2);
  ENCAP (p1024, 1024, 1);
  ENCAP (p1024, 1024, 2);
  DECAP (p1024, 1024, 1);
  DECAP (p1024, 1024, 2);	/* Modified ciphertext.  */
}

int
main (void)
{
  CHECK_EQ (gq_crypto_init (), GQ_OK);
  test_mlkem512 ();
  test_mlkem768 ();
  test_mlkem1024 ();
  TST_DONE ();
}
