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

/* libgcrypt's own generator keeps counts of what it is asked for, and logs
   them on request:

     random usage: poolsize=600 mixed=3 polls=1/412 added=...
                   outmix=1 getlvl1=5/160 getlvl2=0/0

   A test catches the log, asks for the statistics (tst_rnd_stat) and reads a
   counter before and after the code it asks about: "polls=" has the slow
   and fast entropy polls, "getlvl1=" and "getlvl2=" the requests for
   strong and for the strongest randomness (the first number of each pair is
   how many, the second how many bytes).  Without a deterministic clock or a
   hook into the library, this is how a test sees that code did not poll or
   did not ask for more than it needs.

   Only that generator keeps them: with another (FIPS mode, the system one)
   tst_rnd_stat says it cannot, and the test skips.  The test program needs
   libgcrypt's flags and library (LIBGCRYPT_CFLAGS, LIBGCRYPT_LIBS).  */

#ifndef GQ_TST_RNDSTATS_H
#define GQ_TST_RNDSTATS_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

static char tst_log[1024];

static void tst_log_cb (void *user, int level, const char *fmt, va_list ap)
  __attribute__ ((format (printf, 3, 0)));

static void
tst_log_cb (void *user, int level, const char *fmt, va_list ap)
{
  size_t n = strlen (tst_log);

  (void) user;
  (void) level;
  vsnprintf (tst_log + n, sizeof tst_log - n, fmt, ap);
}

/* Catch what libgcrypt logs.  */
static void
tst_catch_gcrypt_log (void)
{
  /* Deprecated, and the only way libgcrypt offers to catch what it logs.  */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  gcry_set_log_handler (tst_log_cb, NULL);
#pragma GCC diagnostic pop
}

/* The counter that follows KEY ("polls=", "getlvl2=") in the statistics, or
   if SECOND the one after the slash.  Returns 0 if there is none.  */
static int
tst_rnd_stat (const char *key, int second, unsigned long *value)
{
  const char *p;

  tst_log[0] = 0;
  gcry_control (GCRYCTL_DUMP_RANDOM_STATS);
  p = strstr (tst_log, key);
  if (p == NULL)
    return 0;
  p += strlen (key);
  if (second)
    {
      p = strchr (p, '/');
      if (p == NULL)
        return 0;
      p++;
    }
  *value = strtoul (p, NULL, 10);
  return 1;
}

#endif /* GQ_TST_RNDSTATS_H */
