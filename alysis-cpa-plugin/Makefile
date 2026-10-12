.PHONY: build test clean

GO ?= go
VERSION ?= $(shell cat VERSION 2>/dev/null || echo dev)
-include build.env
SOLVER_URL ?=
TURNSTILE_SITEKEY ?=
LDFLAGS := -X main.version=$(VERSION) -X main.solverBase=$(SOLVER_URL) -X main.turnstileSiteKey=$(TURNSTILE_SITEKEY)

build:
	CGO_ENABLED=1 GOTOOLCHAIN=auto $(GO) build -buildmode=c-shared -ldflags "$(LDFLAGS)" -o alysis.so .

test:
	CGO_ENABLED=1 GOTOOLCHAIN=auto $(GO) test -count=1 .

clean:
	rm -f alysis.so alysis.h
