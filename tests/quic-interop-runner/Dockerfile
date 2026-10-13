# syntax=docker/dockerfile:1
#
# quickstep endpoint for the quic-interop-runner
# (https://github.com/quic-interop/quic-interop-runner). Build from the
# repository root, so that the sources are in the context:
#
#   docker build -f tests/quic-interop-runner/Dockerfile -t quickstep-interop .
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
         bzip2 gettext libgnutls28-dev libtool openssl pkg-config \
         texinfo \
    && rm -rf /var/lib/apt/lists/*

# quickstep needs libgcrypt 1.11 or newer (ML-KEM), and that needs a newer
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
    && make -C tests quic-interop-endpoint CFLAGS="-g -O2 -Werror" \
    && strip -o /quickstep-interop tests/quic-interop-endpoint

# ---- Check: the whole test suite, for the CI workflow ----------------------
# Not part of the image; "docker build --target check" runs it. It needs the
# build stage's tree, so the endpoint above is built in the same pass.
FROM build AS check
# Compile the tests in parallel, then run them one at a time: several of
# them use fixed port ranges.
RUN make -j"$(nproc)" -C tests check TESTS= CFLAGS="-g -O2 -Werror" \
    && make -C tests check CFLAGS="-g -O2 -Werror"

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

WORKDIR /quickstep
COPY --from=build /quickstep-interop ./quickstep-interop
COPY tests/quic-interop-runner/run_endpoint.sh ./
RUN chmod +x run_endpoint.sh

ENTRYPOINT ["./run_endpoint.sh"]
