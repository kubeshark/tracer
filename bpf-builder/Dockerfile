FROM golang:1.19-bullseye

ENV CGO_ENABLED=1 GOOS=linux
RUN apt-get update
RUN apt-get install -y -q \
    build-essential \
    binutils-gold \
    bash \
    clang \
    llvm \
    libbpf-dev 

#RUN apk --no-cache update && apk --no-cache add clang llvm libbpf-dev linux-headers

WORKDIR /kubeshark
