SHELL=/bin/bash

.PHONY: help bpf
.DEFAULT_GOAL := build
.ONESHELL:

ARCH=$(shell uname -m)
ifeq ($(ARCH),$(filter $(ARCH),aarch64 arm64))
	BPF_TARGET=arm64
	BPF_ARCH_SUFFIX=arm64
else
	BPF_TARGET=amd64
	BPF_ARCH_SUFFIX=x86
endif

GOCMD := go
GOBUILD := $(GOCMD) build
GOGENERATE := $(GOCMD) generate
GOTEST := $(GOCMD) test
GOTOOL := $(GOCMD) tool
CLANG := clang

help: ## Print this help message.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the program.
	$(GOBUILD) -ldflags="-extldflags=-s -w" -o tracer .

build-debug: ## Build the program without optimizations.
	$(GOBUILD) -gcflags=all="-N -l" -o tracer .

build-race: ## Build the program with -race flag.
	$(GOBUILD) -race -ldflags="-extldflags=-s -w" -o tracer .

bpf: ## Compile the object files for eBPF
	BPF_TARGET="$(BPF_TARGET)" BPF_CFLAGS="-O2 -g -D__TARGET_ARCH_$(BPF_ARCH_SUFFIX)" $(GOGENERATE) tracer.go

lint: ## Lint the source code.
	golangci-lint run

setcap:
	sudo setcap cap_net_raw,cap_net_admin,cap_sys_admin,cap_sys_ptrace,cap_dac_override,cap_sys_resource,cap_sys_module=eip ./tracer

run: setcap ## Run the program. Requires Hub being available on port 8898
	./tracer -debug

run-pcap: setcap ## Run the program with a PCAP file. Requires Hub being available on port 8898
	./tracer -f ./import -port 8897 -debug

run-race: setcap ## -race flag requires the GODEBUG=netdns=go
	GODEBUG=netdns=go ./tracer -debug

run-tls: setcap ## Run the program with TLS capture enabled. Requires Hub being available on port 8898
	KUBESHARK_GLOBAL_LIBSSL_PID=$(shell ps -ef | awk '$$8=="python3" && $$9=="tls.py" {print $$2}') \
		./tracer -debug

test:
	$(GOTEST) ./... -coverpkg=./... -race -coverprofile=coverage.out -covermode=atomic -v
