.PHONY: test vet

test:
	go test -count=1 ./...
	./scripts/static_test.sh

vet:
	go vet ./...
