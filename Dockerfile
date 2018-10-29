FROM ubuntu:latest
MAINTAINER GH0st3rs
ARG ARCH=mipsel

ADD deb_toolchain.sh /tmp/deb_toolchain.sh
ADD tools.sh /mnt/tools.sh

WORKDIR /tmp

RUN /tmp/deb_toolchain.sh ${ARCH}