# SPDX-License-Identifier: AGPL-3.0-or-later

GO            ?= go
GOBIN         ?= $(shell $(GO) env GOPATH)/bin
# staticcheck 2026.2.1 cannot read Go 1.27 export data yet.
LINT_TOOLCHAIN ?= go1.26.9
STATICCHECK_VERSION ?= v0.8.1
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT        ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS       := -s -w \
  -X github.com/nebula-operation-station/nebula-operation-station/internal/version.Version=$(VERSION) \
  -X github.com/nebula-operation-station/nebula-operation-station/internal/version.Commit=$(COMMIT)

.PHONY: all build test test-deploy test-privileged test-integration test-browser lint fmt fmt-check generate generate-check vuln fuzz check hooks clean release-stage

all: check build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/ ./cmd/...

test:
	$(GO) test -race -timeout 40m ./...

# Deployment policy tests for the systemd units and nftables files, the
# install script's unit list (deploy/install_test.sh), and for the shared
# quickstart binary list (deploy/quickstart/quickstart_test.sh).
# python3 is required; the systemd-analyze and kernel nft checks skip
# themselves when their tools are unavailable.
test-deploy:
	@command -v python3 >/dev/null 2>&1 || { echo "test-deploy: python3 is required" >&2; exit 1; }
	python3 deploy/systemd/nebula-iconfetch_test.py
	bash deploy/install_test.sh
	bash deploy/quickstart/quickstart_test.sh

# Needs root: helper processes drop to other UIDs.
test-privileged:
	$(GO) test -tags privileged -run 'Privileged' -count=1 ./test/security/...

# Needs the SSH test VMs (spec 08, H05); configuration in test/integration.
test-integration:
	$(GO) test -tags integration -count=1 -v ./test/integration/...

# Needs Node.js with Playwright and Chromium; see test/browser/run.sh.
test-browser:
	test/browser/run.sh

fmt:
	gofmt -w $$(git ls-files '*.go')

fmt-check:
	@out=$$(gofmt -l $$(git ls-files '*.go')); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint: fmt-check
	$(GO) vet ./...
	$(GO) vet -tags privileged ./test/security/...
	$(GO) vet -tags integration ./test/integration/...
	GOTOOLCHAIN=$(LINT_TOOLCHAIN) $(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...
	GOTOOLCHAIN=$(LINT_TOOLCHAIN) $(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) -tags privileged ./test/security/...
	GOTOOLCHAIN=$(LINT_TOOLCHAIN) $(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) -tags integration ./test/integration/...
	buf lint

generate:
	buf generate

generate-check: generate
	@git diff --exit-code -- internal/rpc || (echo "generated code is out of date: run make generate" && exit 1)

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

fuzz:
	$(GO) test -run='^$$' -fuzz=FuzzHashParameters -fuzztime=20s ./internal/canonical/
	$(GO) test -run='^$$' -fuzz=FuzzVerifyNeverPanics -fuzztime=20s ./internal/webauthnverify/
	$(GO) test -run='^$$' -fuzz=FuzzScan -fuzztime=20s ./internal/scanner/
	$(GO) test -run='^$$' -fuzz=FuzzParse -fuzztime=20s ./internal/sshsig/
	$(GO) test -run='^$$' -fuzz='^FuzzParseNmapXML$$' -fuzztime=20s ./internal/discoveryjob/
	$(GO) test -run='^$$' -fuzz='^FuzzJobArgs$$' -fuzztime=20s ./internal/discoveryjob/
	$(GO) test -run='^$$' -fuzz='^FuzzParse$$' -fuzztime=20s ./internal/modulelock/
	$(GO) test -run='^$$' -fuzz='^FuzzParsers$$' -fuzztime=20s ./internal/executions/dockerhost/
	$(GO) test -run='^$$' -fuzz='^FuzzParsers$$' -fuzztime=20s ./internal/executions/osdebian/
	$(GO) test -run='^$$' -fuzz='^FuzzOneJSONDocument$$' -fuzztime=20s ./internal/hostrun/
	$(GO) test -run='^$$' -fuzz='^FuzzRead$$' -fuzztime=20s ./internal/backup/
	$(GO) test -run='^$$' -fuzz='^FuzzUnpack$$' -fuzztime=20s ./internal/modules/
	$(GO) test -run='^$$' -fuzz='^FuzzParse$$' -fuzztime=20s ./internal/inventory/csvimport/

check: lint generate-check test test-deploy vuln

hooks:
	git config core.hooksPath .githooks

# Unsigned staging for offline release signing (docs/admin/release-signing.md):
# goreleaser builds at the pinned VERSION without publishing (release.disable
# and skip_push in .goreleaser.yaml; --skip=publish,announce here, --skip=validate
# because the tag need not exist yet), the container image is exported as a flat
# filesystem tar for its installed-files flavour, and nebula-release-stage
# writes payloads/, module-bytes/, installed/ and SHA256SUMS to RELEASE_STAGE.
# Nothing is signed. Needs goreleaser and docker.
#   make release-stage VERSION=0.1.0
GORELEASER    ?= goreleaser
DOCKER        ?= docker
RELEASE_STAGE ?= dist/stage
RELEASE_IMAGE  = ghcr.io/nebula-operation-station/nebula:$(VERSION)

release-stage:
	@if [ "$(origin VERSION)" != "command line" ]; then echo "release-stage: pass the release version: make release-stage VERSION=X.Y.Z" >&2; exit 1; fi
	GORELEASER_CURRENT_TAG='v$(VERSION)' $(GORELEASER) release --clean --skip=publish,announce,validate
	cid=$$($(DOCKER) create '$(RELEASE_IMAGE)' /usr/bin/nebula) && \
	  { $(DOCKER) export -o 'dist/nebula_$(VERSION)_container_linux_amd64.tar' "$$cid"; rc=$$?; $(DOCKER) rm "$$cid" >/dev/null; exit $$rc; }
	$(GO) run ./cmd/nebula-release-stage --version '$(VERSION)' --dist dist --out '$(RELEASE_STAGE)' --modules modules

clean:
	rm -rf bin/
