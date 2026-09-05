.PHONY: test vet bootstrap bootstrap-static-test linux-connector linux-connector-package

test:
	go test -count=1 ./...
	./scripts/static_test.sh
	./scripts/linux-connector-static-test.sh
	./scripts/bootstrap-static-test.sh

vet:
	go vet ./...

bootstrap:
	./scripts/build-bootstrap.sh "$(TARGET_OS)" "$(OUTPUT_DIR)"

bootstrap-static-test:
	./scripts/bootstrap-static-test.sh

linux-connector:
	./scripts/build-linux-connector.sh "$(OUTPUT_DIR)"

linux-connector-package:
	./scripts/package-linux-connector.sh "$(BUILD_DIR)" "$(OUTPUT_DIR)"
