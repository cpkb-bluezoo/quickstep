# syntax=docker/dockerfile:1
#
# quickstep endpoint for the quic-interop-runner, and the build the CI workflow
# uses (the check and integration targets below)
# (https://github.com/quic-interop/quic-interop-runner). Build from the
# repository root, so that the sources are in the context:
#
#   docker build -f integration/quic-interop-runner/Dockerfile -t quickstep-interop .
#
# The public runner needs linux/amd64; on Apple silicon add
# --platform linux/amd64, or use buildx for a multi-platform image.

# ---- Build: quickstep and the endpoint, with gcc ---------------------------
# The same Ubuntu as the simulator's endpoint base below, so that what is
# built here runs there.
FROM ubuntu:24.04 AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         autoconf autopoint automake build-essential ca-certificates curl \
         bzip2 gettext libgnutls28-dev libtool gnutls-bin openssl pkg-config \
         texinfo \
    && rm -rf /var/lib/apt/lists/*

# quickstep needs libgcrypt 1.12 or newer (the final ML-KEM), and that needs a newer
# libgpg-error than Ubuntu 24.04 has: both are built here.
ARG GPGERROR_VERSION=1.61
ARG GPGERROR_SHA256=7a85413f2bc354f4f8aa832b718af122e48965e9e0eb9012ee659c13c6385c93
ARG LIBGCRYPT_VERSION=1.12.4
ARG LIBGCRYPT_SHA256=d77f68f48879510e79a2f65977ccc68981781ea0923e5bdffac2a193ea3d660e
RUN curl -fsSL -o gpgrt.tar.bz2 \
         https://gnupg.org/ftp/gcrypt/gpgrt/libgpg-error-${GPGERROR_VERSION}.tar.bz2 \
    && echo "${GPGERROR_SHA256}  gpgrt.tar.bz2" | sha256sum -c - \
    && tar xjf gpgrt.tar.bz2 \
    && cd libgpg-error-${GPGERROR_VERSION} \
    && ./configure --prefix=/usr/local --disable-static --disable-doc \
         --disable-tests \
    && make -j"$(nproc)" \
    && make install \
    && cd .. && rm -rf gpgrt.tar.bz2 libgpg-error-${GPGERROR_VERSION} \
    && ldconfig
# The linker must find these, not the older libgpg-error that Ubuntu's own
# packages pull in, when it resolves libgcrypt's dependencies.
ENV LD_LIBRARY_PATH=/usr/local/lib
RUN curl -fsSL -o libgcrypt.tar.bz2 \
         https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-${LIBGCRYPT_VERSION}.tar.bz2 \
    && echo "${LIBGCRYPT_SHA256}  libgcrypt.tar.bz2" | sha256sum -c - \
    && tar xjf libgcrypt.tar.bz2 \
    && cd libgcrypt-${LIBGCRYPT_VERSION} \
    && ./configure --prefix=/usr/local --disable-static --disable-doc \
    && make -j"$(nproc)" \
    && make install \
    && cd .. && rm -rf libgcrypt.tar.bz2 libgcrypt-${LIBGCRYPT_VERSION} \
    && ldconfig

WORKDIR /src
COPY . .

# quickstep itself is linked statically into the endpoint. Warnings are
# errors: the tree is expected to build cleanly with gcc.
ENV CC=gcc PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
RUN ./autogen.sh \
    && ./configure --disable-shared --without-wolfssl \
    && make -C src -j"$(nproc)" CFLAGS="-g -O2 -Werror" \
    && make -C integration quic-interop-endpoint qlog-lint \
         CFLAGS="-g -O2 -Werror" \
    && strip -o /quickstep-interop integration/quic-interop-endpoint \
    && strip -o /qlog-lint integration/qlog-lint

# ---- Check: the unit tests, for the CI workflow ---------------------------
# Not part of the image; "docker build --target check" runs it.
FROM build AS check
RUN make -j"$(nproc)" -C tests check CFLAGS="-g -O2 -Werror"

# ---- Integration: the integration suite, for the CI workflow ---------------
# "docker build --target integration".  The interop scripts that need quiche
# or wolfSSL skip themselves.  One at a time: they use fixed port ranges.
FROM build AS integration
RUN make check-integration CFLAGS="-g -O2 -Werror"

# ---- GnuTLS with an ML-DSA backend, for the check-mldsa target ------------
# GnuTLS signs and verifies with ML-DSA (FIPS 204) only through leancrypto
# (./configure --with-leancrypto, which needs leancrypto 1.2.0 or newer): the
# distribution's GnuTLS has no ML-DSA at all, and a GnuTLS built without
# leancrypto declares the algorithms but cannot generate or import a key.
# GnuTLS 3.8.10 is the first to use ML-DSA in the TLS handshake and to take
# all three private key encodings of RFC 9881 (seed, expandedKey and both),
# and 3.8.13 can derive the public key of an expandedKey-only one; 3.8.13 is
# pinned.  It and its libraries go to their own prefix, so that the rest of
# the image keeps the distribution's GnuTLS.  Nothing here depends on the
# sources, so the layers are cached from one push to the next.
FROM ubuntu:24.04 AS gnutls-mldsa

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         build-essential ca-certificates curl git meson ninja-build \
         m4 pkg-config xz-utils libgmp-dev libidn2-dev libp11-kit-dev \
         libtasn1-6-dev libunistring-dev \
    && rm -rf /var/lib/apt/lists/*

# The commit is the one tag v1.9.1 points at; fetching a commit by its hash
# checks the content, which a tarball's checksum would only do until the
# host recompresses it.  GnuTLS uses only ML-DSA, ML-KEM and the random
# number generator; the key encapsulation families nothing else refers to
# are left out to keep the build short (the SPHINCS+ ones cannot be: the
# library's own ASN.1 code uses them).
ARG LEANCRYPTO_COMMIT=65eb4e7e84e3a5499460a66b1623ccf6c59628b1
RUN git init -q leancrypto \
    && cd leancrypto \
    && git fetch -q --depth 1 https://github.com/smuellerDD/leancrypto.git \
         ${LEANCRYPTO_COMMIT} \
    && git checkout -q FETCH_HEAD \
    && meson setup build --prefix=/opt/gnutls-mldsa --libdir=lib \
         -Dtests=disabled -Dapps=disabled \
         -Dbike_1=disabled -Dbike_3=disabled -Dbike_5=disabled \
         -Dhqc_128=disabled -Dhqc_192=disabled -Dhqc_256=disabled \
         -Dsntrup_761=disabled -Dsntrup_857=disabled -Dsntrup_953=disabled \
         -Dsntrup_1013=disabled -Dsntrup_1277=disabled \
    && meson compile -C build \
    && meson install -C build \
    && cd .. && rm -rf leancrypto

# GnuTLS 3.8.13 wants Nettle 3.10, and Ubuntu 24.04 has 3.9.1.
ARG NETTLE_VERSION=3.10.2
ARG NETTLE_SHA256=fe9ff51cb1f2abb5e65a6b8c10a92da0ab5ab6eaf26e7fc2b675c45f1fb519b5
RUN curl -fsSL -o nettle.tar.gz \
         https://ftp.gnu.org/gnu/nettle/nettle-${NETTLE_VERSION}.tar.gz \
    && echo "${NETTLE_SHA256}  nettle.tar.gz" | sha256sum -c - \
    && tar xzf nettle.tar.gz \
    && cd nettle-${NETTLE_VERSION} \
    && ./configure --prefix=/opt/gnutls-mldsa --libdir=/opt/gnutls-mldsa/lib \
         --disable-static --disable-documentation \
    && make -j"$(nproc)" \
    && make install \
    && cd .. && rm -rf nettle.tar.gz nettle-${NETTLE_VERSION}

ARG GNUTLS_VERSION=3.8.13
ARG GNUTLS_SHA256=ffed8ec1bf09c2426d4f14aae377de4753b53e537d685e604e99a8b16ca9c97e
RUN curl -fsSL -o gnutls.tar.xz \
         https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-${GNUTLS_VERSION}.tar.xz \
    && echo "${GNUTLS_SHA256}  gnutls.tar.xz" | sha256sum -c - \
    && tar xJf gnutls.tar.xz \
    && cd gnutls-${GNUTLS_VERSION} \
    && PKG_CONFIG_PATH=/opt/gnutls-mldsa/lib/pkgconfig \
       LD_LIBRARY_PATH=/opt/gnutls-mldsa/lib ./configure \
         --prefix=/opt/gnutls-mldsa --libdir=/opt/gnutls-mldsa/lib \
         --with-leancrypto --disable-static --disable-doc --disable-tests \
         --disable-guile --disable-cxx --disable-libdane \
         --disable-openssl-compatibility --without-tpm --without-tpm2 \
    && LD_LIBRARY_PATH=/opt/gnutls-mldsa/lib make -j"$(nproc)" \
    && make install \
    && cd .. && rm -rf gnutls.tar.xz gnutls-${GNUTLS_VERSION}

# ---- OpenSSL with ML-DSA, for the interop scenarios of check-mldsa ---------
# OpenSSL has ML-DSA (keys, certificates and the TLS 1.3 signature schemes)
# from 3.5; Ubuntu 24.04 has 3.0.  It goes to its own prefix with its own
# run path, so that nothing else in the image is affected.
FROM ubuntu:24.04 AS openssl-mldsa

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         build-essential ca-certificates curl perl \
    && rm -rf /var/lib/apt/lists/*

ARG OPENSSL_VERSION=3.6.4
ARG OPENSSL_SHA256=9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef
RUN curl -fsSL -o openssl.tar.gz \
         https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz \
    && echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum -c - \
    && tar xzf openssl.tar.gz \
    && cd openssl-${OPENSSL_VERSION} \
    && ./Configure --prefix=/opt/openssl-mldsa --openssldir=/opt/openssl-mldsa/ssl \
         --libdir=lib no-docs no-tests -Wl,-rpath,/opt/openssl-mldsa/lib \
    && make -j"$(nproc)" \
    && make install_sw install_ssldirs \
    && cd .. && rm -rf openssl.tar.gz openssl-${OPENSSL_VERSION}

# ---- wolfSSL with ML-DSA and DTLS 1.3, for the DTLS scenarios of check-mldsa -
# The DTLS 1.3 peer of interop-dtls.sh.  Nothing else in the image uses it.
# The commit is the one tag v5.9.2-stable points at.
FROM ubuntu:24.04 AS wolfssl-mldsa

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         build-essential ca-certificates git autoconf automake libtool \
         pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG WOLFSSL_COMMIT=ac01707f552c611fbd135cc723b2682b3e7f80f2
RUN git init -q wolfssl \
    && cd wolfssl \
    && git fetch -q --depth 1 https://github.com/wolfSSL/wolfssl.git \
         ${WOLFSSL_COMMIT} \
    && git checkout -q FETCH_HEAD \
    && ./autogen.sh \
    && ./configure --prefix=/opt/wolfssl-mldsa --enable-all --enable-dilithium \
         --disable-examples --disable-crypttests \
    && make -j"$(nproc)" \
    && make install \
    && cd .. && rm -rf wolfssl

# ---- Check with ML-DSA: the unit tests against that GnuTLS -----------------
# "docker build --target check-mldsa".  GQ_EXPECT_MLDSA makes the ML-DSA
# tests fail instead of skipping when the GnuTLS in use has no backend, so
# that a build which quietly lost it does not look like a pass.  The ML-DSA
# interop scenarios (integration/interop.sh) then run against the OpenSSL
# above, for the same reason with the same variable: all of them, none
# skipped, the ones under an ML-DSA CA included.  So do the DTLS 1.3
# scenarios (interop-dtls.sh), against the wolfSSL above.  The scripts are
# run directly, since a test that exits 77 would count as skipped, and be
# passed over.
FROM build AS check-mldsa
# What that GnuTLS is linked against besides Nettle, for the linker: the
# development files, which the distribution's GnuTLS does not need here.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         libgmp-dev libidn2-dev libp11-kit-dev libtasn1-6-dev \
         libunistring-dev netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
COPY --from=gnutls-mldsa /opt/gnutls-mldsa /opt/gnutls-mldsa
COPY --from=openssl-mldsa /opt/openssl-mldsa /opt/openssl-mldsa
COPY --from=wolfssl-mldsa /opt/wolfssl-mldsa /opt/wolfssl-mldsa
ENV GQ_EXPECT_MLDSA=1 \
    PKG_CONFIG_PATH=/opt/gnutls-mldsa/lib/pkgconfig:/opt/wolfssl-mldsa/lib/pkgconfig:/usr/local/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/gnutls-mldsa/lib:/usr/local/lib
RUN make distclean \
    && ./configure --disable-shared \
    && make -j"$(nproc)" check CFLAGS="-g -O2 -Werror" \
    && make -C integration interop-client interop-server interop-dtls \
         interop-probe wolf-dtls CFLAGS="-g -O2 -Werror" \
    && cd integration \
    && OPENSSL=/opt/openssl-mldsa/bin/openssl GQ_INTEROP_FILTER=ML-DSA \
       INTEROP_CLIENT=./interop-client INTEROP_SERVER=./interop-server \
       INTEROP_PROBE=./interop-probe sh ./interop.sh \
    && LD_LIBRARY_PATH=/opt/wolfssl-mldsa/lib:$LD_LIBRARY_PATH \
       OPENSSL=/opt/openssl-mldsa/bin/openssl GQ_INTEROP_FILTER=ML-DSA \
       INTEROP_DTLS=./interop-dtls WOLF_DTLS=./wolf-dtls sh ./interop-dtls.sh

# ---- Runtime: the simulator's endpoint base plus quickstep's libraries ----
FROM martenseemann/quic-network-simulator-endpoint:latest

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgnutls30t64 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/lib/libgcrypt.so.* /usr/local/lib/libgpg-error.so.* \
     /usr/local/lib/
RUN ldconfig
# Ubuntu's own, older libgcrypt and libgpg-error sit under the same names;
# ours must win.
ENV LD_LIBRARY_PATH=/usr/local/lib

# The congestion controller the endpoint runs: cubic, newreno, or empty for the
# library's default (CUBIC).  The runner gives the container only its own
# variables, so the choice is made when the image is built:
#   docker build --build-arg CONGESTION_CONTROL=newreno ...
# It goes in a file that run_endpoint.sh reads, not in an ENV: a layer that only
# expands an ARG is reused from a cache (podman does) even when the ARG has
# changed, and a comparison run would silently test the wrong controller.
ARG CONGESTION_CONTROL=
RUN printf '%s' "$CONGESTION_CONTROL" > /congestion_control

WORKDIR /quickstep
COPY --from=build /quickstep-interop ./quickstep-interop
# Checks the qlogs the endpoint writes (QLOGDIR) against the qlog draft; the
# workflow runs it over what each run left in the logs.
COPY --from=build /qlog-lint ./qlog-lint
COPY integration/quic-interop-runner/run_endpoint.sh ./
RUN chmod +x run_endpoint.sh

ENTRYPOINT ["./run_endpoint.sh"]
