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

/* Minimal helpers shared by the test programs.  */

#ifndef GQ_TST_UTIL_H
#define GQ_TST_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tst_failures;

#define CHECK(cond) \
  do { \
    if (!(cond)) \
      { \
        fprintf (stderr, "%s:%d: check failed: %s\n", \
                 __FILE__, __LINE__, #cond); \
        tst_failures++; \
      } \
  } while (0)

#define CHECK_EQ(a, b) \
  do { \
    long long a_ = (long long) (a), b_ = (long long) (b); \
    if (a_ != b_) \
      { \
        fprintf (stderr, "%s:%d: %s == %s failed (%lld vs %lld)\n", \
                 __FILE__, __LINE__, #a, #b, a_, b_); \
        tst_failures++; \
      } \
  } while (0)

/* Decode HEX (no separators) into OUT; returns the byte count.  */
static inline size_t
tst_unhex (const char *hex, uint8_t *out, size_t cap)
{
  size_t n = 0;

  while (hex[0] && hex[1] && n < cap)
    {
      unsigned v;

      if (sscanf (hex, "%2x", &v) != 1)
        break;
      out[n++] = (uint8_t) v;
      hex += 2;
    }
  return n;
}

/* The ML-DSA tests need a GnuTLS with an ML-DSA backend (leancrypto), which
   most builds lack.  Where one is expected, the CI job that builds it sets
   GQ_EXPECT_MLDSA, and then a missing backend is a failure: a test that
   skipped itself must not look like one that passed.  AVAILABLE is whether
   the backend works; the result is whether the caller may go on to run
   WHAT.  */
static inline int
tst_mldsa_ready (int available, const char *what)
{
  const char *e = getenv ("GQ_EXPECT_MLDSA");

  if (available)
    return 1;
  if (e != NULL && *e != '\0' && strcmp (e, "0") != 0)
    {
      fprintf (stderr, "%s: GQ_EXPECT_MLDSA is set but this GnuTLS cannot do "
               "the ML-DSA that needs\n", what);
      tst_failures++;
      return 0;
    }
  fprintf (stderr, "note: this GnuTLS cannot do the ML-DSA that %s needs; "
           "skipped\n", what);
  return 0;
}

/* Decode a NULL-terminated list of hex pieces (see vectors-mlkem.h) into
   OUT, one after the other; returns the byte count.  */
static inline size_t
tst_unhex_parts (const char *const *parts, uint8_t *out, size_t cap)
{
  size_t n = 0;

  for (; *parts; parts++)
    n += tst_unhex (*parts, out + n, cap - n);
  return n;
}

/* Base64 (white space and armor ignored, no checking) of TEXT into OUT;
   returns the number of bytes.  */
static inline size_t
tst_b64_decode (const char *text, uint8_t *out, size_t cap)
{
  uint32_t acc = 0;
  int bits = 0;
  size_t n = 0;

  for (; *text; text++)
    {
      int v;
      char c = *text;

      if (c >= 'A' && c <= 'Z') v = c - 'A';
      else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
      else if (c >= '0' && c <= '9') v = c - '0' + 52;
      else if (c == '+') v = 62;
      else if (c == '/') v = 63;
      else continue;
      acc = (acc << 6) | (uint32_t) v;
      bits += 6;
      if (bits >= 8)
        {
          bits -= 8;
          if (n < cap)
            out[n++] = (uint8_t) (acc >> bits);
          acc &= (1u << bits) - 1;
        }
    }
  return n;
}

/* The DER in the PEM block TEXT (between its armor lines); returns its
   size, or 0.  */
static inline size_t
tst_pem_der (const char *text, uint8_t *out, size_t cap)
{
  const char *b = strstr (text, "-----\n"), *e = strstr (text, "\n-----END");
  char *tmp;
  size_t n;

  if (b == NULL || e == NULL || e < b)
    return 0;
  b += 6;
  tmp = malloc ((size_t) (e - b) + 1);
  memcpy (tmp, b, (size_t) (e - b));
  tmp[e - b] = '\0';
  n = tst_b64_decode (tmp, out, cap);
  free (tmp);
  return n;
}

/* Join a NULL-terminated list of text pieces (see vectors-mldsa.h) into OUT,
   NUL-terminated; returns the length.  */
static inline size_t
tst_cat_parts (const char *const *parts, char *out, size_t cap)
{
  size_t n = 0;

  for (; *parts; parts++)
    {
      size_t l = strlen (*parts);

      if (n + l + 1 > cap)
        break;
      memcpy (out + n, *parts, l);
      n += l;
    }
  out[n] = '\0';
  return n;
}

/* Compare BUF (LEN bytes) with the hex string HEX.  */
static inline int
tst_eq_hex (const uint8_t *buf, size_t len, const char *hex)
{
  uint8_t tmp[4096];
  size_t n = tst_unhex (hex, tmp, sizeof tmp);

  return n == len && memcmp (tmp, buf, len) == 0;
}

#define TST_DONE() \
  do { \
    if (tst_failures) \
      fprintf (stderr, "%d failure(s)\n", tst_failures); \
    return tst_failures ? 1 : 0; \
  } while (0)

#endif
