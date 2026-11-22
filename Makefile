GO ?= go
NODE ?= node
BENCHTIME ?= 5x
GOPATH ?= $(shell $(GO) env GOPATH)
GOLANGCI_LINT_VERSION=latest
BUILD_DIR=dist

.PHONY: format
format:
	$(GO) fmt ./...

.PHONY: download
download: ## download all the dependencies
	$(GO) mod download
	$(GO) mod tidy
	$(GO) vet -tags production ./...

.PHONY: run
run:
	$(GO) run -tags production ./cmd/vulman

.PHONY: test
test:
	$(GO) test -race -tags production ./...

.PHONY: test-ui benchmark benchmark-ui
test-ui:
	$(NODE) --test scripts/test-ui*.cjs

benchmark:
	$(GO) test -run '^$$' -bench '^BenchmarkWorkspace$$' -benchmem -benchtime=$(BENCHTIME) ./internal/store

benchmark-ui:
	$(NODE) scripts/benchmark-ui.cjs

.PHONY: check
check:
	$(GO) vet -tags production ./...

.PHONY: build
build:
	mkdir -p $(BUILD_DIR)
	$(GO) build -tags production -buildvcs=false -trimpath -o $(BUILD_DIR)/vulman$$($(GO) env GOEXE) ./cmd/vulman

.PHONY: build-scan
build-scan:
	mkdir -p $(BUILD_DIR)
	$(GO) build -buildvcs=false -trimpath -o $(BUILD_DIR)/vulman-scan$$($(GO) env GOEXE) ./cmd/vulman-scan

.PHONY: build-race
build-race: ## build with race detector
	mkdir -p $(BUILD_DIR)
	$(GO) build -race -tags production -buildvcs=false -trimpath -o $(BUILD_DIR)/vulman$$($(GO) env GOEXE) ./cmd/vulman

.PHONY: clean
clean: ## remove the output binary from go build, as well as go install and build cache
	$(GO) clean -i -r -cache
	rm -rf $(BUILD_DIR)/*

.PHONY: lint
lint: ## run all the lint tools, install golangci-lint if not exist
ifeq (,$(wildcard $(GOPATH)/bin/golangci-lint))
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) > /dev/null
	GOFLAGS="-tags=production -buildvcs=false" $(GOPATH)/bin/golangci-lint run -v --timeout 180s
else
	GOFLAGS="-tags=production -buildvcs=false" $(GOPATH)/bin/golangci-lint run  -v --timeout 180s
endif

.PHONY: lint-sec
lint-sec: ## run all the lint tools, install golangci-lint if not exist
ifeq (,$(wildcard $(GOPATH)/bin/golangci-lint))
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) > /dev/null
	GOFLAGS="-tags=production -buildvcs=false" $(GOPATH)/bin/golangci-lint run -v --timeout 180s -E gosec
else
	GOFLAGS="-tags=production -buildvcs=false" $(GOPATH)/bin/golangci-lint run  -v --timeout 180s -E gosec
endif

.PHONY: release release-linux release-windows release-macos
release: release-linux release-windows

release-linux:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -tags production,purego -buildvcs=false -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/vulman-linux-amd64 ./cmd/vulman
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -tags production,purego -buildvcs=false -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/vulman-linux-arm64 ./cmd/vulman
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -buildvcs=false -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/vulman-scan-linux-amd64 ./cmd/vulman-scan
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -buildvcs=false -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/vulman-scan-linux-arm64 ./cmd/vulman-scan
	cp packaging/linux/com.vulman.app.desktop $(BUILD_DIR)/com.vulman.app.desktop
	cp cmd/vulman/ui/icon.svg $(BUILD_DIR)/com.vulman.app.svg

release-windows:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -tags production -buildvcs=false -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/vulman-windows-amd64.exe ./cmd/vulman
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 $(GO) build -tags production -buildvcs=false -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/vulman-windows-arm64.exe ./cmd/vulman
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -buildvcs=false -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/vulman-scan-windows-amd64.exe ./cmd/vulman-scan
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 $(GO) build -buildvcs=false -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/vulman-scan-windows-arm64.exe ./cmd/vulman-scan

ifeq ($(shell uname -s),Darwin)
release: release-macos

release-macos:
	mkdir -p "$(BUILD_DIR)"
	@set -eu; \
		work=$$(mktemp -d "$(BUILD_DIR)/.vulman-macos.XXXXXX"); \
		trap 'rm -rf "$$work"' EXIT; \
		bundle="$$work/Vulman.app"; \
		mkdir -p "$$bundle/Contents/MacOS" "$$bundle/Contents/Resources" "$$work/Vulman.iconset"; \
		cp packaging/macos/Info.plist "$$bundle/Contents/Info.plist"; \
		swift packaging/macos/render-icon.swift cmd/vulman/ui/icon.svg "$$work/Vulman.iconset"; \
		iconutil -c icns -o "$$bundle/Contents/Resources/Vulman.icns" "$$work/Vulman.iconset"; \
		minimum=$$(/usr/bin/plutil -extract LSMinimumSystemVersion raw "$$bundle/Contents/Info.plist"); \
		for arch in arm64 amd64; do \
			printf 'Building Vulman for macOS (%s)\n' "$$arch"; \
			CGO_ENABLED=1 GOOS=darwin GOARCH="$$arch" MACOSX_DEPLOYMENT_TARGET="$$minimum" \
				CGO_CFLAGS="-O2 -g -mmacosx-version-min=$$minimum" CGO_LDFLAGS="-mmacosx-version-min=$$minimum" \
				$(GO) build -tags production -buildvcs=false -trimpath \
				-ldflags="-s -w -extldflags=-mmacosx-version-min=$$minimum" -o "$$work/vulman-$$arch" ./cmd/vulman; \
			CGO_ENABLED=0 GOOS=darwin GOARCH="$$arch" $(GO) build -buildvcs=false -trimpath \
			-ldflags="-s -w" -o "$$work/vulman-scan-$$arch" ./cmd/vulman-scan; \
		done; \
		xcrun lipo -create "$$work/vulman-arm64" "$$work/vulman-amd64" -output "$$bundle/Contents/MacOS/vulman"; \
		xcrun lipo -create "$$work/vulman-scan-arm64" "$$work/vulman-scan-amd64" -output "$$work/vulman-scan-macos"; \
		codesign --force --sign - "$$bundle"; \
		codesign --verify --strict "$$bundle"; \
		codesign --force --sign - "$$work/vulman-scan-macos"; \
		codesign --verify --strict "$$work/vulman-scan-macos"; \
		rm -rf "$(BUILD_DIR)/Vulman.app"; \
		mv "$$bundle" "$(BUILD_DIR)/Vulman.app"; \
		mv "$$work/vulman-scan-macos" "$(BUILD_DIR)/vulman-scan-macos"; \
		printf 'Created %s\n' "$(BUILD_DIR)/Vulman.app" "$(BUILD_DIR)/vulman-scan-macos"
else
release-macos:
	@printf '%s\n' 'Run make release-macos on macOS with the Xcode Command Line Tools installed.' >&2
	@exit 1
endif
