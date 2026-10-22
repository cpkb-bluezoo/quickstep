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

/* The 0-RTT replay cache: single use, expiry, fail-closed when full, and
   that a table which has seen far more tickets than it has slots still ends
   a search for a new one early.  The last needs the table's layout, so the
   module is included rather than linked.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "../src/replay.c"

#include "tst-util.h"

static void
make_id (uint8_t id[32], unsigned n)
{
  memset (id, 0, 32);
  /* The cache indexes by the first bytes, as for a digest: spread n.  */
  unsigned h = n * 2654435761u, g = (n + 12345) * 2246822519u;

  id[0] = (uint8_t) (h >> 24);
  id[1] = (uint8_t) (h >> 16);
  id[2] = (uint8_t) (h >> 8);
  id[3] = (uint8_t) h;
  id[4] = (uint8_t) (g >> 24);
  id[5] = (uint8_t) (g >> 16);
  id[6] = (uint8_t) (g >> 8);
  id[7] = (uint8_t) g;		/* The low byte is what picks the slot.  */
  id[8] = (uint8_t) n;
  id[9] = (uint8_t) (n >> 8);
  id[10] = (uint8_t) (n >> 16);
}

static size_t
empty_slots (const gq_replay_cache *c)
{
  size_t i, k = 0;

  for (i = 0; i < c->n; i++)
    k += c->slot[i].expires == 0;
  return k;
}

static void
test_single_use_and_expiry (void)
{
  gq_replay_cache *c;
  uint8_t a[32], b[32];

  make_id (a, 1);
  make_id (b, 2);
  CHECK_EQ (gq_replay_cache_new (&c, 8), GQ_OK);
  CHECK_EQ (gq_replay_cache_check (c, a, 1000, 100), 1);
  CHECK_EQ (gq_replay_cache_check (c, a, 1000, 100), 0);	/* Replay.  */
  CHECK_EQ (gq_replay_cache_check (c, b, 1000, 100), 1);
  CHECK_EQ (gq_replay_cache_size (c), 2);
  /* Already expired tickets carry no early data.  */
  CHECK_EQ (gq_replay_cache_check (c, a, 100, 100), 0);
  CHECK_EQ (gq_replay_cache_check (c, a, 50, 100), 0);
  /* Once expired, the entry is no longer a replay of anything live.  */
  CHECK_EQ (gq_replay_cache_check (c, a, 3000, 2000), 1);
  CHECK_EQ (gq_replay_cache_check (c, a, 3000, 2001), 0);
  CHECK_EQ (gq_replay_cache_check (NULL, a, 3000, 2001), 0);
  CHECK_EQ (gq_replay_cache_check (c, NULL, 3000, 2001), 0);
  gq_replay_cache_free (c);
}

static void
test_fails_closed_when_full (void)
{
  gq_replay_cache *c;
  uint8_t id[32];
  unsigned i, taken = 0;

  CHECK_EQ (gq_replay_cache_new (&c, 8), GQ_OK);
  for (i = 0; i < 40; i++)
    {
      make_id (id, i);
      taken += gq_replay_cache_check (c, id, 1000000, 10);
    }
  /* It holds what it promised and refuses the rest rather than forget.  */
  CHECK (taken >= 8 && taken <= 16);
  make_id (id, 0);
  CHECK_EQ (gq_replay_cache_check (c, id, 1000000, 11), 0);
  /* The expiry of the lot makes room again.  */
  make_id (id, 1000);
  CHECK_EQ (gq_replay_cache_check (c, id, 3000000, 2000000), 1);
  gq_replay_cache_free (c);
}

/* Tickets come and go for as long as the server runs.  Entries that expired
   are reused as they are met, but a slot that has been used is never empty
   again, so unless the table is rebuilt now and then it ends up with no
   empty slot at all: every lookup of a ticket not seen before then walks the
   whole table, an attacker's cost being one handshake for each such scan.  */
static void
test_churn_keeps_empty_slots (void)
{
  gq_replay_cache *c;
  uint8_t id[32];
  unsigned i;
  uint64_t now = 1000;
  size_t fewest;

  CHECK_EQ (gq_replay_cache_new (&c, 8), GQ_OK);
  fewest = c->n;
  for (i = 0; i < 5000; i++)
    {
      size_t e;

      make_id (id, i);
      /* Each ticket lives for 25 ms, a new one every 10: a few are live.  */
      CHECK_EQ (gq_replay_cache_check (c, id, now + 25, now), 1);
      /* And while live, it is a replay.  */
      CHECK_EQ (gq_replay_cache_check (c, id, now + 25, now), 0);
      e = empty_slots (c);
      if (e < fewest)
        fewest = e;
      now += 10;
    }
  /* A quarter of the table, at least, still ends a search.  */
  CHECK (fewest >= c->n / 4);
  gq_replay_cache_free (c);
}

int
main (void)
{
  test_single_use_and_expiry ();
  test_fails_closed_when_full ();
  test_churn_keeps_empty_slots ();
  TST_DONE ();
}
