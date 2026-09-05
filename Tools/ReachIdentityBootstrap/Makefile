SHELL := /bin/sh
.PHONY: build test vet static

# Keep generated output, Go caches and temporary files outside the checkout.
build:
	./scripts/build.sh linux "$(OUTPUT)"

test:
	GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off go test -count=1 ./...

vet:
	GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off go vet ./...

static:
	./scripts/static-test.sh
