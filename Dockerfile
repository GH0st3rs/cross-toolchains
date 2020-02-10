FROM ubuntu:latest
MAINTAINER GH0st3rs
ARG ARCH=mipsel

WORKDIR /tmp

RUN apt-get update && apt-get -y upgrade && apt-get install -y g++ make gawk autoconf libtool bison wget texinfo

ADD deb_toolchain.sh /tmp/deb_toolchain.sh
RUN /tmp/deb_toolchain.sh ${ARCH}

ADD tools.sh /tmp/tools.sh
RUN /tmp/tools.sh -a ${ARCH} -l 'zlib openssl libevent'
