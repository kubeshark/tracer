FROM golang:1.19-alpine

ENV CGO_ENABLED=1 GOOS=linux
RUN apt-get update
RUN apt-get install -y -q \
    build-essential \
    binutils-gold \
    bash \
    clang \
    llvm \
    libbpf-dev 


WORKDIR /kubeshark
