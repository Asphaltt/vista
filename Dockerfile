FROM ubuntu:22.04 AS build

ENV PATH $PATH:/usr/local/go/bin

RUN apt update -y -q &&
    DEBIAN_FRONTEND=noninteractive apt install --no-install-recommends -y -q \
        curl \
        build-essential \
        ca-certificates \
        wget \
        gnupg2 \
        git \
        llvm \
        clang \
        gcc flex bison gcc-aarch64* libc6-dev-arm64-cross &&
    curl -s https://storage.googleapis.com/golang/go1.20.5.linux-amd64.tar.gz | tar -v -C /usr/local -xz

WORKDIR /vista
COPY . .
RUN make &&
    chmod a+x /vista

FROM busybox
COPY --from=build /vista/vista /usr/local/bin/
