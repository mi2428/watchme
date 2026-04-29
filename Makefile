SHELL         := /bin/bash
.SHELLFLAGS   := -eu -o pipefail -c
.DEFAULT_GOAL := help

SWIFT       ?= swift
SWIFTFORMAT ?= swiftformat
SWIFTLINT   ?= swiftlint

CONFIG          ?= debug
DOC_OUTPUT      ?= .build/docc
DOC_TARGET      ?= WatchmeWiFi
PREVIEW         ?= 0
HELP_NAME_WIDTH := 15
SWIFT_PATHS     := Package.swift Sources Tests

##@ Development

.PHONY: build
build: ## Build the WatchMe executable
	@$(SWIFT) build -c $(CONFIG)

.PHONY: app
app: ## Build WatchMe.app for Location authorization
	@scripts/build-app -c $(CONFIG)

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

.PHONY: doc
doc: ## Generate DocC documentation; set PREVIEW=1 to serve a local preview
	@if [[ "$(PREVIEW)" == "1" ]]; then \
		$(SWIFT) package --disable-sandbox preview-documentation --target $(DOC_TARGET); \
	else \
		$(SWIFT) package --allow-writing-to-directory $(DOC_OUTPUT) generate-documentation --target $(DOC_TARGET) --output-path $(DOC_OUTPUT); \
	fi

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
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "DOC_OUTPUT" "DocC output directory, defaults to $(DOC_OUTPUT)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "DOC_TARGET" "DocC target, defaults to $(DOC_TARGET)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "PREVIEW" "Set to 1 to preview DocC documentation, defaults to $(PREVIEW)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "SWIFT" "Swift executable, defaults to $(SWIFT)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "SWIFTFORMAT" "SwiftFormat executable, defaults to $(SWIFTFORMAT)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "SWIFTLINT" "SwiftLint executable, defaults to $(SWIFTLINT)"
