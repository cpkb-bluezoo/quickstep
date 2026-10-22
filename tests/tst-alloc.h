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

/* libgcrypt's allocations, counted.  Opening a cipher context allocates, so
   the count says how many a stretch of code opened, without the library
   having to tell.  A test that includes this calls tst_count_allocs first
   thing in main, before libgcrypt is initialised (the library does it on
   first use), and reads tst_allocs before and after the code it asks about.
   The test program needs libgcrypt's flags and library (LIBGCRYPT_CFLAGS and
   LIBGCRYPT_LIBS).  */

#ifndef GQ_TST_ALLOC_H
#define GQ_TST_ALLOC_H

#include <stdlib.h>

#include <gcrypt.h>

static unsigned long tst_allocs;

static void *
tst_alloc (size_t n)
{
  tst_allocs++;
  return malloc (n);
}

static void *
tst_realloc (void *p, size_t n)
{
  tst_allocs++;
  return realloc (p, n);
}

static int
tst_not_secure (const void *p)
{
  (void) p;
  return 0;
}

static void
tst_count_allocs (void)
{
  gcry_set_allocation_handler (tst_alloc, tst_alloc, tst_not_secure,
                               tst_realloc, free);
}

#endif /* GQ_TST_ALLOC_H */
