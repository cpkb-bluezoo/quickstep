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

/* qlog-lint: check files of qlog lines (what the interop endpoint writes
   when QLOGDIR is set, see <quickstep/qlog.h>) against the event
   definitions of draft-ietf-quic-qlog-quic-events: the line, the name of
   the event, the fields it must and may have, and the values they take.

     qlog-lint [-v] FILE...

   Exits 0 if every line of every file is as the draft says, 1 if not (after
   telling what and where), 2 if a file cannot be read.  -v counts the
   events by name.  A file of a connection must begin with its
   connection_started; one called endpoint_* holds the events of no
   connection.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tst-qlogcheck.h"

static unsigned long seen[64];

/* Check one file.  Returns the number of faults, or -1 if it cannot be read.  */
static long
lint_file (const char *path, int verbose, unsigned long *events)
{
  FILE *f = fopen (path, "r");
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  unsigned long lineno = 0, faults = 0, got = 0;
  unsigned long long last = 0;
  const char *base = strrchr (path, '/');
  int endpoint_file;

  if (f == NULL)
    {
      fprintf (stderr, "%s: cannot read\n", path);
      return -1;
    }
  base = base ? base + 1 : path;
  endpoint_file = strncmp (base, "endpoint_", 9) == 0;
  while ((n = getline (&line, &cap, f)) > 0)
    {
      char *p = line, *end, *name, *fields, where[200];
      const char *err;
      unsigned long long t;
      size_t i;

      lineno++;
      if (line[n - 1] == '\n')
        line[--n] = '\0';
      if (line[0] == '#')
        continue;
      t = strtoull (p, &end, 10);
      if (end == p || *end != ' ')
        {
          fprintf (stderr, "%s:%lu: no time\n", path, lineno);
          faults++;
          continue;
        }
      name = end + 1;
      fields = strchr (name, ' ');
      if (fields)
        *fields++ = '\0';
      else
        fields = name + strlen (name);
      if (t < last)
        {
          fprintf (stderr, "%s:%lu: time goes back\n", path, lineno);
          faults++;
        }
      last = t;
      if (got++ == 0 && !endpoint_file
          && strcmp (name, "quic:connection_started") != 0)
        {
          fprintf (stderr, "%s:%lu: begins with %s, not connection_started\n",
                   path, lineno, name);
          faults++;
        }
      err = qc_check (name, fields, strlen (fields), where, sizeof where);
      if (err)
        {
          fprintf (stderr, "%s:%lu: %s%s%s (%s)\n", path, lineno, err,
                   where[0] ? ": " : "", where, name);
          faults++;
        }
      if (strncmp (name, "quic:", 5) == 0)
        for (i = 0; qc_events[i]; i++)
          if (!strcmp (name + 5, qc_events[i]))
            seen[i]++;
    }
  free (line);
  fclose (f);
  *events += got;
  if (verbose)
    fprintf (stderr, "%s: %lu events, %lu faults\n", path, got, faults);
  return (long) faults;
}

int
main (int argc, char **argv)
{
  int i, verbose = 0, status = 0;
  unsigned long events = 0, faults = 0, files = 0;

  if (argc > 1 && !strcmp (argv[1], "-v"))
    {
      verbose = 1;
      argc--;
      argv++;
    }
  if (argc < 2)
    {
      fprintf (stderr, "usage: qlog-lint [-v] FILE...\n");
      return 2;
    }
  for (i = 1; i < argc; i++)
    {
      long r = lint_file (argv[i], verbose, &events);

      files++;
      if (r < 0)
        status = 2;
      else
        faults += (unsigned long) r;
    }
  if (verbose)
    {
      size_t k;

      for (k = 0; qc_events[k]; k++)
        if (seen[k])
          fprintf (stderr, "  %-36s %lu\n", qc_events[k], seen[k]);
    }
  fprintf (stderr, "%lu files, %lu events, %lu faults\n", files, events, faults);
  if (status == 0 && faults)
    status = 1;
  return status;
}
