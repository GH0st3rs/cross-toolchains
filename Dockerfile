FROM ubuntu:bionic
MAINTAINER GH0st3rs
ARG ARCH=mipsel

# ENV

ARG TARGET=""
ENV TARGET="${TARGET}"

ARG CFLAGS_FOR_TARGET=""
ENV CFLAGS_FOR_TARGET="${CFLAGS_FOR_TARGET}"

ARG GCC_PARAMS=""
ENV GCC_PARAMS="${GCC_PARAMS}"

ARG GLIBC_EX_FLAGS=""
ENV GLIBC_EX_FLAGS="${GLIBC_EX_FLAGS}"

ARG SSL_MARCH=""
ENV SSL_MARCH="${SSL_MARCH}"

WORKDIR /tmp

RUN apt-get update && apt-get -y upgrade && apt-get install -y g++ make gawk autoconf libtool bison wget texinfo

ADD deb_toolchain.sh /tmp/deb_toolchain.sh
RUN /tmp/deb_toolchain.sh ${ARCH}

# Pre-install zlib, openssl and libevent
ADD tools.sh /tmp/tools.sh
RUN /tmp/tools.sh -i -v -a ${ARCH} -l 'zlib openssl libevent'

ENTRYPOINT service distcc start && /bin/bash
