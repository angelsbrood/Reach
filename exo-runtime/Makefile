.PHONY: test vet linux-connector linux-connector-package

test:
	go test -count=1 ./...
	./scripts/static_test.sh
	./scripts/linux-connector-static-test.sh

vet:
	go vet ./...

linux-connector:
	./scripts/build-linux-connector.sh "$(OUTPUT_DIR)"

linux-connector-package:
	./scripts/package-linux-connector.sh "$(BUILD_DIR)" "$(OUTPUT_DIR)"
