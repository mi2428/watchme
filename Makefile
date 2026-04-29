SHELL         := /bin/bash
.SHELLFLAGS   := -eu -o pipefail -c
.DEFAULT_GOAL := help

SWIFT       ?= swift
SWIFTFORMAT ?= swiftformat
SWIFTLINT   ?= swiftlint

CONFIG          ?= debug
HELP_NAME_WIDTH := 18
SWIFT_PATHS     := Package.swift Sources Tests

##@ Development

.PHONY: build
build: ## Build the watchme executable
	@$(SWIFT) build -c $(CONFIG)

.PHONY: fmt
fmt: ## Format and modernize Swift sources
	@$(SWIFTFORMAT) $(SWIFT_PATHS) --config .swiftformat

.PHONY: lint
lint: ## Run Swift formatting and lint checks
	@$(SWIFTFORMAT) $(SWIFT_PATHS) --config .swiftformat --lint
	@$(SWIFTLINT) lint --strict --config .swiftlint.yml

.PHONY: test
test: ## Run unit tests
	@$(SWIFT) test

.PHONY: quality
quality: fmt lint test ## Format, lint, and test

.PHONY: clean
clean: ## Remove SwiftPM build artifacts
	@rm -rf .build

##@ Help

.PHONY: help
help: ## Show this help message
	@awk -v width="$(HELP_NAME_WIDTH)" 'BEGIN {FS = ":.*##"} \
		{ lines[NR] = $$0 } \
		END { \
			section = ""; \
			for (i = 1; i <= NR; i++) { \
				$$0 = lines[i]; \
				if ($$0 ~ /^##@/) { \
					section = substr($$0, 5); \
				} else if ($$0 ~ /^[a-zA-Z0-9_.-]+:.*##/) { \
					split($$0, parts, ":.*##"); \
					sub(/^[[:space:]]+/, "", parts[2]); \
					if (section != "") printf "\n\033[1m%s\033[0m\n", section; \
					section = ""; \
					printf "  \033[36m%-*s\033[0m%s\n", width, parts[1], parts[2]; \
				} \
			} \
		}' $(MAKEFILE_LIST)
	@printf "\n\033[1mVariables:\033[0m\n"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "CONFIG" "SwiftPM build configuration, defaults to $(CONFIG)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "SWIFT" "Swift executable, defaults to $(SWIFT)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "SWIFTFORMAT" "SwiftFormat executable, defaults to $(SWIFTFORMAT)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "SWIFTLINT" "SwiftLint executable, defaults to $(SWIFTLINT)"
	@printf "\n\033[1mExamples:\033[0m\n"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "make build" "Build the debug executable"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "make fmt" "Format Swift sources"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "make lint" "Check formatting and SwiftLint"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "make test" "Run unit tests"
