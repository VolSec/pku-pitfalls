FROM debian:jessie

# apt install dependencies
RUN apt-get update
RUN apt-get install -y build-essential libunwind-dev nasm vim

COPY erim/ /root/erim
COPY pku-exploits /root/pku-exploits

WORKDIR /root/erim/src/erim
RUN make

WORKDIR /root/erim/src/tem/ptrace
RUN make

WORKDIR /root/erim/src/tem/libtem
RUN make


WORKDIR /root/pku-exploits
RUN sed -i 's:ERIM_ROOT=.*:ERIM_ROOT=/root/erim:g' common.mk
RUN make


