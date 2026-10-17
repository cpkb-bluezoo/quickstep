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

/* A reader of the qlog line format (<quickstep/qlog.h>) for the tests: it
   splits fields on spaces and each on its first '=', as an awk script would,
   and is strict about what the format promises (key characters, no stray
   spaces, only well-formed %XX escapes, printable ASCII only).  */

#ifndef GQ_TST_QKV_H
#define GQ_TST_QKV_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define QL_MAX_FIELDS 1024

/* Not every test program uses every helper.  */
#if defined __GNUC__
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wunused-function"
#endif

typedef struct qline
{
  size_t n;
  char *key[QL_MAX_FIELDS];
  char *val[QL_MAX_FIELDS];	/* Decoded.  */
  char *copy;
} qline;

static void
qline_free (qline *q)
{
  size_t i;

  for (i = 0; i < q->n; i++)
    {
      free (q->key[i]);
      free (q->val[i]);
    }
  free (q->copy);
  memset (q, 0, sizeof *q);
}

static int
qhex (char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

/* Parse FIELDS (N bytes).  Returns 1, or 0 if it breaks the format.  */
static int
qline_parse (const char *fields, size_t n, qline *q)
{
  size_t i = 0;

  memset (q, 0, sizeof *q);
  q->copy = malloc (n + 1);
  memcpy (q->copy, fields, n);
  q->copy[n] = '\0';
  if (n == 0)
    return 1;
  if (strlen (q->copy) != n)
    return 0;			/* An embedded NUL.  */
  for (;;)
    {
      size_t ks = i, ke, vs, ve, k;
      char *val;
      size_t vn = 0;

      while (i < n && fields[i] != '=' && fields[i] != ' ')
        i++;
      if (i >= n || fields[i] != '=' || i == ks)
        goto bad;
      ke = i;
      for (k = ks; k < ke; k++)
        {
          char c = fields[k];

          if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
                || c == '.'))
            goto bad;
        }
      i++;
      vs = i;
      while (i < n && fields[i] != ' ')
        i++;
      ve = i;
      val = malloc (ve - vs + 1);
      for (k = vs; k < ve; k++)
        {
          unsigned char c = (unsigned char) fields[k];

          if (c == '%')
            {
              int h1, h2;

              if (k + 2 >= ve)
                {
                  free (val);
                  goto bad;
                }
              h1 = qhex (fields[k + 1]);
              h2 = qhex (fields[k + 2]);
              if (h1 < 0 || h2 < 0)
                {
                  free (val);
                  goto bad;
                }
              val[vn++] = (char) (h1 * 16 + h2);
              k += 2;
            }
          else if (c <= 0x20 || c >= 0x7f)
            {
              free (val);
              goto bad;
            }
          else
            val[vn++] = (char) c;
        }
      val[vn] = '\0';
      if (q->n == QL_MAX_FIELDS)
        {
          free (val);
          goto bad;
        }
      q->key[q->n] = malloc (ke - ks + 1);
      memcpy (q->key[q->n], fields + ks, ke - ks);
      q->key[q->n][ke - ks] = '\0';
      q->val[q->n] = val;
      q->n++;
      if (i >= n)
        return 1;
      i++;			/* The space.  */
      if (i >= n)
        goto bad;		/* A trailing space.  */
    }
bad:
  qline_free (q);
  return 0;
}

static const char *
qline_get (const qline *q, const char *key)
{
  size_t i;

  for (i = 0; i < q->n; i++)
    if (!strcmp (q->key[i], key))
      return q->val[i];
  return NULL;
}

static int
qline_is (const qline *q, const char *key, const char *val)
{
  const char *v = qline_get (q, key);

  return v && !strcmp (v, val);
}

static int
qline_is_u (const qline *q, const char *key, uint64_t val)
{
  const char *v = qline_get (q, key);
  char *end;

  if (!v || !*v)
    return 0;
  return strtoull (v, &end, 10) == val && *end == '\0';
}

/* The number of fields whose key starts with PREFIX.  */
static size_t
qline_count (const qline *q, const char *prefix)
{
  size_t i, c = 0, n = strlen (prefix);

  for (i = 0; i < q->n; i++)
    if (!strncmp (q->key[i], prefix, n))
      c++;
  return c;
}

#if defined __GNUC__
# pragma GCC diagnostic pop
#endif

#endif /* GQ_TST_QKV_H */
