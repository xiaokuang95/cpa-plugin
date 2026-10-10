.PHONY: build test clean

GO ?= go
VERSION ?= $(shell cat VERSION 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

build:
	CGO_ENABLED=1 GOTOOLCHAIN=auto $(GO) build -buildmode=c-shared -ldflags "$(LDFLAGS)" -o tokenharbor.so .

test:
	CGO_ENABLED=1 GOTOOLCHAIN=auto $(GO) test -count=1 .

clean:
	rm -f tokenharbor.so tokenharbor.h
