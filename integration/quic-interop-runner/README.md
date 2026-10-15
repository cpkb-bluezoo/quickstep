# quic-interop-runner endpoint

quickstep's endpoint for the
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner),
the test harness behind the public QUIC interop matrix at
[interop.seemann.io](https://interop.seemann.io/). The runner puts a
client and a server from two implementations on either side of an ns-3
network simulator, drives each through environment variables, and checks
the downloaded files and the packet captures. This directory holds
everything needed to be one of those implementations:

| Path | Purpose |
|------|---------|
| `endpoint.c` | The client and the server in one program, `quic-interop-endpoint`; the role comes from the environment |
| `Dockerfile` | Builds libgcrypt, quickstep and the endpoint with gcc (warnings are errors), then puts them on the simulator's endpoint base image |
| `run_endpoint.sh` | Container entrypoint: simulator routing, then the endpoint |
| `ack_stats.py`, `dump_frames.py` | Read the runner's packet captures: ACK-only packet counts, and a packet-by-packet decode (see below) |
| `smoke.sh` | The endpoint against itself over loopback, once per test case; part of `make check-integration` |

The matrix is run by the `QUIC interop` GitHub Actions workflow
(`.github/workflows/quic-interop.yml`), on demand only. It is not part of
the `CI` workflow, which builds quickstep with gcc and runs the unit and
integration tests.

## The runner's contract

The runner knows nothing about quickstep; it only runs the image.

- `ROLE` is `server` or `client`; `TESTCASE` names the test case.
- **Server:** serve the files in `/www` on UDP port 443, with
  `/certs/priv.key` and `/certs/cert.pem`, on IPv4 and IPv6 (one dual-stack
  socket).
- **Client:** download every URL in `REQUESTS` (space separated, such as
  `https://server4:443/xyz`) into `/downloads`, verifying the server
  against `/certs/ca.pem`, then exit 0 (or 1 on failure).
- Exit **127** for a `TESTCASE` the endpoint does not implement. The
  runner probes each image with a random case name first and refuses
  images that do not answer 127.
- Every case speaks HTTP/0.9 over ALPN `hq-interop`: `GET /path\r\n` on a
  client-initiated bidirectional stream, the raw file bytes back, FIN.
- `SSLKEYLOGFILE` names a file the endpoint writes TLS secrets to in NSS
  key log format (`gq_tls_config.keylog`). Several checks (resumption,
  multiplexing, key update, rebinding) are only evaluated when the runner
  can decrypt the traces with it.

## Test case coverage

| `TESTCASE` | Server | Client | Notes |
|------------|--------|--------|-------|
| `handshake`, `transfer`, `ipv6` | yes | yes | `transfer` also serves the runner's multiplexing, blackhole, loss, corruption, rebinding, amplification limit and goodput cases; `multiconnect` serves the handshake loss and corruption cases |
| `multiconnect` | yes | yes | The client makes one connection, and so one handshake, per file |
| `retry` | yes | yes | The server requires Retry address validation |
| `chacha20` | yes | yes | Only `TLS_CHACHA20_POLY1305_SHA256` offered and accepted |
| `resumption` | yes | yes | The first file on one connection, the rest on a second that resumes its session ticket |
| `zerortt` | yes | yes | As `resumption`, with the requests of the second connection sent in 0-RTT |
| `v2` | yes | yes | Compatible version negotiation to QUIC v2 (RFC 9368, RFC 9369): the client opens in v1 and lists v2 first; the server moves it there. Every other case stays in v1 |
| `keyupdate` | yes | yes | The client updates its keys after the first 100 KiB; the server follows a peer's update in every case |
| `http3` | 127 | 127 | No HTTP/3 in quickstep |
| `ecn` | 127 | 127 | The library neither reads nor sets the ECN codepoints |
| `connectionmigration` | 127 | - | The library does not use the server's `preferred_address` |

There is no qlog: `QLOGDIR` is ignored. The endpoint's own console log, the
packet captures and the analyses below take its place.

## Building the image

From the repository root (the Dockerfile needs the sources):

```bash
docker build -f integration/quic-interop-runner/Dockerfile -t quickstep-interop .
```

Podman works the same way (`podman build ...`). The public runner needs a
`linux/amd64` image; on Apple silicon add `--platform linux/amd64`, or build
both with `docker buildx build --platform linux/amd64,linux/arm64`.

The image is built on Ubuntu 24.04, the simulator's own base, so what is
compiled there runs there. Ubuntu 24.04 has libgcrypt 1.10 and quickstep
needs 1.11 or newer, so the Dockerfile builds libgpg-error and libgcrypt
from source first (the tarballs are pinned by SHA-256). The compiler is
`gcc`, and quickstep and the endpoint are built with `-Werror` on top of
the warnings `configure` adds, so a warning gcc finds fails the build.

## Running the runner locally

The runner needs Linux-style Docker networking (static dual-stack
addresses, `NET_ADMIN` for the simulator), Python 3.10 or newer, Docker
Compose and Wireshark 4.5 or newer (`tshark`, `editcap`). A Linux host is
the dependable choice; the GitHub Actions workflow is the reference setup.

```bash
git clone https://github.com/quic-interop/quic-interop-runner
cd quic-interop-runner
pip3 install -r requirements.txt
# register the local image under the name "quickstep" (role: both)
jq '. + {"quickstep": {"image": "quickstep-interop", "url": "https://github.com/cpkb-bluezoo/quickstep", "role": "both"}}' \
    implementations_quic.json > tmp.json && mv tmp.json implementations_quic.json
python3 run.py -s quickstep -c quic-go -t handshake,transfer,retry
python3 run.py -s quic-go -c quickstep -t handshake,transfer,retry
```

Logs land in `logs/<server>_<client>/<testcase>/` with the runner's
verdict in `output.txt`, the endpoint consoles under `server/` and
`client/`, and the simulator's pcaps under `sim/`.

## Running the endpoint without Docker

`make check-integration` builds the endpoint
(`integration/quic-interop-endpoint`) and runs `smoke.sh`, which starts a server and a client of it on loopback for
each test case with a certificate pair it makes with openssl. To run one
by hand, the same `INTEROP_*` variables replace the fixed container paths
and port:

```bash
ROLE=server TESTCASE=handshake INTEROP_PORT=4433 INTEROP_WWW=/tmp/www INTEROP_CERTS=/tmp/certs \
    tests/quic-interop-endpoint &
ROLE=client TESTCASE=handshake INTEROP_DOWNLOADS=/tmp/downloads INTEROP_CERTS=/tmp/certs \
    REQUESTS="https://localhost:4433/file1 https://localhost:4433/file2" \
    tests/quic-interop-endpoint
```

The certificate needs a subject alternative name for the host the client
connects to. `GQ_INTEROP_FILTER=text smoke.sh` runs only the cases whose
names contain `text`.

## The workflow

`.github/workflows/quic-interop.yml` builds the image once, then for each
peer implementation runs the whole suite twice, with quickstep as server
and as client, and appends the runner's result matrices to the job
summary. Logs and the runner's JSON results are uploaded as artifacts
named `quic-interop-<peer>`. Run it from the Actions tab; the `peers` and
`tests` inputs narrow it down, and `ref` builds the endpoint from another
quickstep commit, branch or tag (a full commit SHA, not `sha^`) while the
workflow itself stays at the commit it was dispatched from.

## What gets logged

Each direction of each peer leaves, in the uploaded `quic-interop-<peer>`
artifact, under `logs/quickstep-server/` or `logs/quickstep-client/`:

- the runner's verdict per case (`output.txt`) and the simulator's captures
  (`sim/`);
- `endpoint.log` in the `server/` or `client/` directory, quickstep's console:
  its connection events, requests, and a `STATS` line per connection with the
  library's own counters: duration, packets and bytes sent and received,
  packets lost, smoothed and minimum RTT, congestion window, slow-start
  threshold, congestion events, PTO count, key updates, and (client)
  application bytes and goodput in kbit/s. It is the quick way to see loss,
  stalls and rough performance without opening a capture;
- `frames.tsv` in each case directory (`dump_frames.py`): one row per QUIC
  packet on quickstep's side of the simulator, with time, source, packet
  number, frame types, ACK ranges and delay, and STREAM and flow control
  fields. It is what shows what a peer really received when a transfer
  stalls;
- the job summary and job log also carry a table from `ack_stats.py`: per
  case, how many 1-RTT packets quickstep sent, how many of those held only
  ACK frames, how many data packets the peer sent, and the ACK-only to data
  ratio, which is where ACKs going wild shows up. The ACK_FREQUENCY and
  IMMEDIATE_ACK columns are for the extension frames; quickstep does not
  send them, so they read 0 unless a peer does. Both scripts need `tshark`
  and the key logs the endpoints write, and `ack_stats.py --self-test`
  checks the counting on sample `tshark` output.

The runner itself reports goodput for the `goodput` and `crosstraffic`
measurements in the result matrix.
