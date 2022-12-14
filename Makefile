TEMPDIR = ./.tmp
LINTCMD = $(TEMPDIR)/golangci-lint run --tests=false --timeout 5m --config .golangci.yaml
GOIMPORTS_CMD = $(TEMPDIR)/gosimports -local github.com/anchore
VERSION=$(shell git describe --dirty --always --tags)

# formatting variables
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

# ci dependency versions
GOLANG_CI_VERSION = v1.50.1
GOSIMPORTS_VERSION = v0.3.4

## Build variables
ifeq "$(strip $(VERSION))" ""
 override VERSION = $(shell git describe --always --tags --dirty)
endif

## Variable assertions

ifndef TEMPDIR
	$(error TEMPDIR is not set)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef

$(RESULTSDIR):
	mkdir -p $(RESULTSDIR)

$(TEMPDIR):
	mkdir -p $(TEMPDIR)

.PHONY: all
all: static-analysis ## Run all checks (linting)
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

.PHONY: bootstrap-go
bootstrap-go:
	$(call title,Boostrapping dependencies)
	go mod download

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMPDIR)
	$(call title,Boostrapping tools)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMPDIR)/ $(GOLANG_CI_VERSION)
	GOBIN="$(realpath $(TEMPDIR))" go install github.com/rinchsan/gosimports/cmd/gosimports@$(GOSIMPORTS_VERSION)

.PHONY: bootstrap
bootstrap: bootstrap-go bootstrap-tools ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)

.PHONY: static-analysis
static-analysis: lint

.PHONY: lint
lint: ## Run gofmt + golangci lint checks
	$(call title,Running linters)
	# ensure there are no go fmt differences
	@printf "files with gofmt issues: [$(shell gofmt -l -s .)]\n"
	@test -z "$(shell gofmt -l -s .)"

	# run all golangci-lint rules
	$(LINTCMD)
	@[ -z "$(shell $(GOIMPORTS_CMD) -d .)" ] || (echo "goimports needs to be fixed" && false)

	# go tooling does not play well with certain filename characters, ensure the common cases don't result in future "go get" failures
	$(eval MALFORMED_FILENAMES := $(shell find . | grep -e ':'))
	@bash -c "[[ '$(MALFORMED_FILENAMES)' == '' ]] || (printf '\nfound unsupported filename characters:\n$(MALFORMED_FILENAMES)\n\n' && false)"

.PHONY: lint-fix
lint-fix: ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	gofmt -w -s .
	$(GOIMPORTS_CMD) -w .
	$(LINTCMD) --fix
	go mod tidy
