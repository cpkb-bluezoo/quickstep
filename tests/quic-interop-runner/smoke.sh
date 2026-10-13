#!/bin/sh
# The quic-interop-runner endpoint (quic-interop-endpoint) against itself, over
# loopback, once for each test case it implements: it speaks the runner's
# environment contract, so this checks everything but the other
# implementations and the simulator.  Skipped (exit 77) without openssl, or
# if GQ_NO_INTEROP is set.  GQ_INTEROP_FILTER=text runs only the cases whose
# names contain it.
#
# Copyright (C) 2026 Chris Burdess <dog@gnu.org>
#
# This file is part of quickstep.
#
# quickstep is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

[ -n "$GQ_NO_INTEROP" ] && exit 77

EP=${QUIC_INTEROP_ENDPOINT:-./quic-interop-endpoint}
[ -x "$EP" ] || exit 77
case $EP in /*) ;; *) EP=$(pwd)/$EP ;; esac
OPENSSL=${OPENSSL:-$(command -v openssl)}
[ -n "$OPENSSL" ] || exit 77

T=$(mktemp -d "${TMPDIR:-/tmp}/gq-runner.XXXXXX") || exit 77
PID=
cleanup ()
{
  [ -n "$PID" ] && kill $PID 2>/dev/null
  wait 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT INT TERM
cd "$T" || exit 77

# The runner's certificates: a root CA and a leaf for the host names it uses.
mkdir certs
"$OPENSSL" ecparam -name prime256v1 -genkey -out ca.key 2>/dev/null &&
"$OPENSSL" req -x509 -sha256 -nodes -days 2 -key ca.key -out certs/ca.pem \
  -subj "/O=interop runner Root Certificate Authority/" \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign >/dev/null 2>&1 &&
"$OPENSSL" ecparam -name prime256v1 -genkey -out certs/priv.key 2>/dev/null &&
"$OPENSSL" req -new -key certs/priv.key -nodes -subj "/O=interop runner leaf/" \
  -out leaf.csr >/dev/null 2>&1 &&
printf 'subjectAltName=DNS:server,DNS:server4,DNS:server6,DNS:server46,DNS:localhost,IP:127.0.0.1,IP:::1\n' > leaf.ext &&
"$OPENSSL" x509 -req -sha256 -days 2 -in leaf.csr -CA certs/ca.pem \
  -CAkey ca.key -CAcreateserial -extfile leaf.ext -out certs/cert.pem \
  >/dev/null 2>&1 || exit 77

mkdir www
head -c 1000 /dev/urandom > www/small
head -c 3000000 /dev/urandom > www/big
head -c 40 /dev/urandom > www/tiny
n=0
while [ $n -lt 300 ]; do
  head -c 32 /dev/urandom > "www/f$n"
  n=$((n + 1))
done

# The runner's 0-RTT case: forty files with 250 character names.
long=$(head -c 240 /dev/zero | tr '\0' 'a')
n=0
longs=
while [ $n -lt 40 ]; do
  name=$(printf '%s%010d' "$long" $n)
  head -c 32 /dev/urandom > "www/$name"
  longs="$longs $name"
  n=$((n + 1))
done

fails=0
runs=0
port=$((20000 + $$ % 20000))

want ()
{
  [ -z "$GQ_INTEROP_FILTER" ] || case $1 in *"$GQ_INTEROP_FILTER"*) return 0 ;; *) return 1 ;; esac
}

report ()
{
  runs=$((runs + 1))
  if [ "$1" = 0 ]; then echo "ok   $2"; else echo "FAIL $2"; fails=$((fails + 1)); fi
}

# case NAME TESTCASE HOST FILE... : a server for the test case, a client
# fetching the files, the files compared, then what that test case should
# have left in the logs.
case_ ()
{
  name=$1; tc=$2; host=$3; shift 3
  want "$name" || return 0
  port=$((port + 1))
  mkdir "dl-$name"
  : > "keys-$name.srv"
  : > "keys-$name.cli"
  ROLE=server TESTCASE=$tc INTEROP_PORT=$port INTEROP_WWW=www \
    INTEROP_CERTS=certs SSLKEYLOGFILE="keys-$name.srv" \
    "$EP" > "$name.srv.log" 2>&1 &
  PID=$!
  i=0
  while ! grep -q LISTENING "$name.srv.log" 2>/dev/null && [ $i -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
  done
  reqs=
  for f in "$@"; do reqs="$reqs https://$host:$port/$f"; done
  ROLE=client TESTCASE=$tc INTEROP_DOWNLOADS="dl-$name" INTEROP_CERTS=certs \
    REQUESTS="$reqs" SSLKEYLOGFILE="keys-$name.cli" \
    "$EP" > "$name.cli.log" 2>&1
  rc=$?
  kill $PID 2>/dev/null
  wait $PID 2>/dev/null
  PID=
  for f in "$@"; do
    cmp -s "dl-$name/$f" "www/$f" || { echo "     $f differs"; rc=1; }
  done
  # Each side logged the secrets of the handshake, and the same ones.
  grep -q '^SERVER_HANDSHAKE_TRAFFIC_SECRET ' "keys-$name.cli" || rc=1
  grep -q '^CLIENT_TRAFFIC_SECRET_0 ' "keys-$name.srv" || rc=1
  sort -u "keys-$name.cli" > "keys-$name.c"
  sort -u "keys-$name.srv" > "keys-$name.s"
  cmp -s "keys-$name.c" "keys-$name.s" || { echo "     key logs differ"; rc=1; }
  case $tc in
    v2) grep -q 'CONNECTED version=0x6b3343cf' "$name.cli.log" || rc=1 ;;
    resumption|zerortt)
      grep -q 'CONNECTED.* resumed' "$name.cli.log" || rc=1 ;;
    *) grep -q 'CONNECTED version=0x00000001' "$name.cli.log" || rc=1 ;;
  esac
  case $tc in
    keyupdate) grep -q '^KEY_UPDATE' "$name.cli.log" || rc=1 ;;
    zerortt)
      grep -q 'EARLY_DATA accepted=1' "$name.cli.log" || rc=1
      grep -q '^CLIENT_EARLY_TRAFFIC_SECRET ' "keys-$name.cli" || rc=1
      grep -q '^CLIENT_EARLY_TRAFFIC_SECRET ' "keys-$name.srv" || rc=1 ;;
  esac
  report $rc "$name"
}

case_ handshake handshake localhost small
case_ transfer transfer localhost small tiny big
case_ chacha20 chacha20 localhost small tiny
case_ retry retry localhost small tiny
case_ v2 v2 localhost small tiny
case_ keyupdate keyupdate localhost big
case_ zerortt-names zerortt localhost small $longs
case_ multiconnect multiconnect localhost small tiny f1 f2 f3
case_ resumption resumption localhost small tiny f1
case_ zerortt zerortt localhost small f1 f2 f3 f4 f5 f6 f7 f8
# Many requests over one connection, past the server's initial stream limit.
case_ multiplexing transfer localhost $(n=0; while [ $n -lt 300 ]; do echo f$n; n=$((n + 1)); done)
case_ ipv4 handshake 127.0.0.1 small
case_ ipv6 ipv6 '[::1]' small tiny

# What the endpoint does not implement is reported as such (exit 127), which
# the runner reads as "unsupported"; so is any name it does not know.
for tc in http3 ecn connectionmigration no-such-case; do
  want "unsupported-$tc" || continue
  ROLE=client TESTCASE=$tc REQUESTS=https://localhost:1/x "$EP" >/dev/null 2>&1
  [ $? = 127 ] && rc=0 || rc=1
  ROLE=server TESTCASE=$tc "$EP" >/dev/null 2>&1
  [ $? = 127 ] || rc=1
  report $rc "unsupported-$tc"
done

echo "$runs cases, $fails failed"
[ $fails = 0 ]
