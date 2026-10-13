#!/bin/bash
#
# Entrypoint of quickstep's quic-interop-runner endpoint image. The runner
# drives the container entirely through the environment: ROLE (client or
# server), TESTCASE, REQUESTS (client: the URLs to fetch), SSLKEYLOGFILE, and
# the mounts /www (server: files to serve), /downloads (client: where to
# store them), /certs (priv.key, cert.pem, ca.pem) and /logs.
#
# Unknown test cases exit 127, which the runner reads as "unsupported";
# that decision is made by the endpoint, so there is a single list of cases.

set -e

# Routes and checksum offload for the ns-3 simulator network.
/setup.sh

echo "quickstep interop endpoint: ROLE=$ROLE TESTCASE=$TESTCASE"

if [ "$ROLE" = "client" ]; then
    # The simulator opens this port once its network is up.
    /wait-for-it.sh sim:57832 -s -t 30
    echo "REQUESTS=$REQUESTS"
fi

# The endpoint copies its console to INTEROP_LOG, which the runner keeps with
# the traces and the key log; exec keeps its exit status, which the runner
# reads (127: unsupported).
export INTEROP_LOG=/logs/endpoint.log
exec /quickstep/quickstep-interop
