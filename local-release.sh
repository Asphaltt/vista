#!/bin/sh

set -uex

OS=linux

for ARCH in ${ARCHS}; do
    if [ "$ARCH" = "arm64" ]; then
        LIBPCAP_ARCH=aarch64-unknown-linux-gnu
        CC=aarch64-linux-gnu-gcc
    else
        LIBPCAP_ARCH=x86_64-unknown-linux-gnu
        CC=gcc
    fi

    make clean
    echo "Building release binary for ${OS}/${ARCH}..."
    make vista TARGET_GOARCH=${ARCH} LIBPCAP_ARCH=${LIBPCAP_ARCH} CC=${CC}

    test -d release/${OS}/${ARCH} || mkdir -p release/${OS}/${ARCH}
    tar -czf release/vista-${OS}-${ARCH}.tar.gz vista
    (cd release && sha256sum vista-${OS}-${ARCH}.tar.gz >vista-${OS}-${ARCH}.tar.gz.sha256sum)
    rm -r release/${OS}
done
