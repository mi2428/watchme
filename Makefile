SHELL         := /bin/bash
.SHELLFLAGS   := -eu -o pipefail -c
.DEFAULT_GOAL := help

SWIFT       ?= swift
SWIFTFORMAT ?= swiftformat
SWIFTLINT   ?= swiftlint
HDIUTIL     ?= hdiutil
PLUTIL      ?= plutil

CONFIG          ?= debug
DMG_CONFIG      ?= release
DOC_OUTPUT      ?= .build/docc
DOC_TARGET      ?= WatchmeWiFi
PREVIEW         ?= 0
HELP_NAME_WIDTH := 28
SWIFT_PATHS     := Package.swift Sources Tests
APP             := WatchMe
PRODUCT_NAME    := WatchMe
DISTDIR         := dist
APP_DIR         := $(DISTDIR)/$(APP).app
WATCHME_APP_BUNDLE ?= .build/watchme-app/$(APP).app
GIT_REMOTE      ?= origin
GH_REPO         ?=
RELEASE_MAKE    ?= $(MAKE)
TAG             ?=

WATCHME_PACKAGE_NAME    ?= watchme
WATCHME_GIT_DESCRIBE    ?= $(shell git describe --tags --always --dirty=-dirty 2>/dev/null || printf unknown)
WATCHME_VERSION_FROM_GIT = $(shell \
	tag="$(TAG)"; \
	if [ -n "$$tag" ]; then \
		printf '%s' "$$tag" | sed 's/^v//'; \
	else \
		describe=`git describe --tags --always --dirty=-dirty 2>/dev/null || printf unknown`; \
		printf '%s' "$$describe" | sed 's/^v//'; \
	fi)
WATCHME_VERSION         ?= $(WATCHME_VERSION_FROM_GIT)
WATCHME_BUNDLE_VERSION  ?= $(shell \
	version="$(WATCHME_VERSION)"; \
	numeric=`printf '%s' "$$version" | cut -d- -f1 | cut -d+ -f1`; \
	if printf '%s' "$$numeric" | grep -Eq '^[0-9]+[.][0-9]+[.][0-9]+$$'; then \
		printf '%s' "$$numeric"; \
	else \
		printf '0.0.0'; \
	fi)
WATCHME_GIT_COMMIT      ?= $(shell git rev-parse HEAD 2>/dev/null || printf unknown)
WATCHME_GIT_COMMIT_DATE ?= $(shell git show -s --format=%cI HEAD 2>/dev/null || printf unknown)
WATCHME_BUNDLE_BUILD    ?= $(shell git rev-list --count HEAD 2>/dev/null || date +%Y%m%d%H%M%S)
WATCHME_BUILD_DATE      ?= $(shell \
	if [ -n "$${SOURCE_DATE_EPOCH:-}" ]; then \
		if date -u -r "$${SOURCE_DATE_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ' >/dev/null 2>&1; then \
			date -u -r "$${SOURCE_DATE_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ'; \
		else \
			date -u -d "@$${SOURCE_DATE_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ'; \
		fi; \
	else \
		date -u '+%Y-%m-%dT%H:%M:%SZ'; \
	fi)
DETECTED_SWIFT_TARGET   := $(shell \
	$(SWIFT) -print-target-info 2>/dev/null | \
		sed -n 's/.*"triple"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | \
		head -n 1)
WATCHME_BUILD_TARGET    ?= $(or $(DETECTED_SWIFT_TARGET),unknown)
WATCHME_BUILD_HOST      ?= $(WATCHME_BUILD_TARGET)
WATCHME_BUILD_PROFILE   ?= $(CONFIG)
SWIFT_BUILD_ENV         := \
	WATCHME_PACKAGE_NAME="$(WATCHME_PACKAGE_NAME)" \
	WATCHME_VERSION="$(WATCHME_VERSION)" \
	WATCHME_GIT_DESCRIBE="$(WATCHME_GIT_DESCRIBE)" \
	WATCHME_GIT_COMMIT="$(WATCHME_GIT_COMMIT)" \
	WATCHME_GIT_COMMIT_DATE="$(WATCHME_GIT_COMMIT_DATE)" \
	WATCHME_BUILD_DATE="$(WATCHME_BUILD_DATE)" \
	WATCHME_BUILD_HOST="$(WATCHME_BUILD_HOST)" \
	WATCHME_BUILD_TARGET="$(WATCHME_BUILD_TARGET)" \
	WATCHME_BUILD_PROFILE="$(WATCHME_BUILD_PROFILE)"

##@ Development

.PHONY: build
build: ## Build the WatchMe executable
	@$(SWIFT_BUILD_ENV) $(SWIFT) build -c $(CONFIG)

.PHONY: app
app: ## Build WatchMe.app for Location authorization
	@$(SWIFT_BUILD_ENV) \
		WATCHME_APP_BUNDLE="$(WATCHME_APP_BUNDLE)" \
		WATCHME_BUNDLE_VERSION="$(WATCHME_BUNDLE_VERSION)" \
		WATCHME_BUNDLE_BUILD="$(WATCHME_BUNDLE_BUILD)" \
		scripts/build-app -c $(CONFIG)

.PHONY: fmt
fmt: ## Format and modernize Swift sources
	@$(SWIFTFORMAT) $(SWIFT_PATHS) --config .swiftformat

.PHONY: lint
lint: ## Run Swift formatting and lint checks
	@$(SWIFTFORMAT) $(SWIFT_PATHS) --config .swiftformat --lint
	@$(SWIFTLINT) lint --strict --config .swiftlint.yml

.PHONY: test
test: ## Run unit tests
	@$(SWIFT_BUILD_ENV) $(SWIFT) test

.PHONY: doc
doc: ## Generate DocC documentation; set PREVIEW=1 to serve a local preview
	@if [[ "$(PREVIEW)" == "1" ]]; then \
		$(SWIFT_BUILD_ENV) $(SWIFT) package --disable-sandbox preview-documentation --target $(DOC_TARGET); \
	else \
		$(SWIFT_BUILD_ENV) $(SWIFT) package \
			--allow-writing-to-directory $(DOC_OUTPUT) \
			generate-documentation \
			--target $(DOC_TARGET) \
			--output-path $(DOC_OUTPUT); \
	fi

.PHONY: quality
quality: fmt lint test ## Format, lint, and test

.PHONY: clean
clean: ## Remove local build artifacts
	@rm -rf .build $(DISTDIR)

##@ Distribution

.PHONY: dmg
dmg: ## Build an installable DMG into dist/
	@set -Eeuo pipefail; \
	die() { printf 'make dmg: %s\n' "$$*" >&2; exit 1; }; \
	need() { command -v "$$1" >/dev/null 2>&1 || die "$$1 is required"; }; \
	run() { printf '+'; printf ' %q' "$$@"; printf '\n'; "$$@"; }; \
	app="$(APP)"; \
	product_name="$(PRODUCT_NAME)"; \
	tag="$(TAG)"; \
	distdir="$(DISTDIR)"; \
	config="$(DMG_CONFIG)"; \
	watchme_version="$(WATCHME_VERSION)"; \
	build_number="$(WATCHME_BUNDLE_BUILD)"; \
	make_cmd="$(RELEASE_MAKE)"; \
	hdiutil="$(HDIUTIL)"; \
	plutil="$(PLUTIL)"; \
	semver='^v[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?([+][0-9A-Za-z][0-9A-Za-z.-]*)?$$'; \
	stage_dir=; \
	cleanup() { [[ -z "$$stage_dir" ]] || rm -rf "$$stage_dir"; }; \
	trap cleanup EXIT; \
	for tool in git "$$make_cmd" "$$hdiutil" "$$plutil" shasum; do need "$$tool"; done; \
	if [[ -n "$$tag" ]]; then \
		[[ "$$tag" =~ $$semver ]] || die "TAG must look like vMAJOR.MINOR.PATCH"; \
		app_version="$${tag#v}"; \
	elif [[ -n "$$watchme_version" ]]; then \
		app_version="$$watchme_version"; \
	else \
		die "WATCHME_VERSION could not be inferred from git"; \
	fi; \
	if [[ -z "$$build_number" ]]; then \
		build_number="$$(git rev-list --count HEAD 2>/dev/null || date +%Y%m%d%H%M%S)"; \
	fi; \
	app_dir="$${distdir}/$${app}.app"; \
	dmg="$${distdir}/$${app}-$${tag:-v$${app_version}}.dmg"; \
	run rm -rf "$$app_dir" "$$dmg"; \
	run mkdir -p "$$distdir"; \
	run "$$make_cmd" --no-print-directory app \
		"CONFIG=$$config" \
		"WATCHME_VERSION=$$app_version" \
		"WATCHME_APP_BUNDLE=$$app_dir" \
		"WATCHME_BUNDLE_BUILD=$$build_number"; \
	[[ -x "$$app_dir/Contents/MacOS/watchme" ]] || die "missing executable $$app_dir/Contents/MacOS/watchme"; \
	plist_version="$$("$$plutil" -extract CFBundleShortVersionString raw -o - "$$app_dir/Contents/Info.plist")"; \
	[[ "$$plist_version" == "$$app_version" ]] || die "bundle version $$plist_version does not match $$app_version"; \
	stage_dir="$$(mktemp -d "$${TMPDIR:-/tmp}/$${app}-dmg.XXXXXX")"; \
	run cp -R "$$app_dir" "$$stage_dir/$$app.app"; \
	run ln -s /Applications "$$stage_dir/Applications"; \
	run "$$hdiutil" create \
		-volname "$$product_name" \
		-srcfolder "$$stage_dir" \
		-ov \
		-format UDZO \
		"$$dmg"; \
	run "$$hdiutil" verify "$$dmg"; \
	(cd "$$distdir" && shasum -a 256 "$${dmg##*/}" > checksums.txt); \
	printf 'Wrote %s\n' "$$dmg"; \
	printf 'Wrote %s\n' "$$distdir/checksums.txt"

.PHONY: release
release: ## Build a DMG locally and publish it to GitHub Releases. Requires TAG=vX.Y.Z
	@set -Eeuo pipefail; \
	die() { printf 'make release: %s\n' "$$*" >&2; exit 1; }; \
	need() { command -v "$$1" >/dev/null 2>&1 || die "$$1 is required"; }; \
	run() { printf '+'; printf ' %q' "$$@"; printf '\n'; "$$@"; }; \
	app="$(APP)"; \
	product_name="$(PRODUCT_NAME)"; \
	tag="$(TAG)"; \
	distdir="$(DISTDIR)"; \
	config="$(DMG_CONFIG)"; \
	watchme_version="$(WATCHME_VERSION)"; \
	git_remote="$(GIT_REMOTE)"; \
	gh_repo="$(GH_REPO)"; \
	make_cmd="$(RELEASE_MAKE)"; \
	hdiutil="$(HDIUTIL)"; \
	plutil="$(PLUTIL)"; \
	semver='^v[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?([+][0-9A-Za-z][0-9A-Za-z.-]*)?$$'; \
	created_tag=; \
	pushed_tag=; \
	cleanup() { \
		if [[ -n "$$created_tag" && -z "$$pushed_tag" ]]; then \
			git tag -d "$$created_tag" >/dev/null 2>&1 || true; \
		fi; \
	}; \
	trap cleanup EXIT; \
	[[ -n "$$tag" ]] || die "TAG is required, for example: make release TAG=vX.Y.Z"; \
	[[ "$$tag" =~ $$semver ]] || die "TAG must look like vMAJOR.MINOR.PATCH"; \
	for tool in git gh "$$make_cmd" "$$plutil"; do need "$$tool"; done; \
	if [[ -n "$$(git status --porcelain)" ]]; then \
		git status --short >&2; \
		die "working tree must be clean before release"; \
	fi; \
	if [[ -n "$$watchme_version" && "$$watchme_version" != "$${tag#v}" ]]; then \
		die "WATCHME_VERSION $$watchme_version does not match $$tag"; \
	fi; \
	repository="$$gh_repo"; \
	if [[ -z "$$repository" ]]; then \
		repository="$${GITHUB_REPOSITORY:-}"; \
	fi; \
	if [[ -z "$$repository" ]]; then \
		url="$$(git config --get "remote.$${git_remote}.url" || true)"; \
		case "$$url" in \
			git@github.com:*) repository="$${url#git@github.com:}" ;; \
			https://github.com/*) repository="$${url#https://github.com/}" ;; \
			ssh://git@github.com/*) repository="$${url#ssh://git@github.com/}" ;; \
			*) die "could not infer GitHub repository from $$git_remote; set GH_REPO=owner/repo" ;; \
		esac; \
	fi; \
	repository="$${repository#https://github.com/}"; \
	repository="$${repository%.git}"; \
	[[ "$$repository" == */* ]] || die "GitHub repository must look like owner/repo, got $$repository"; \
	remote_line="$$(git ls-remote --tags "$$git_remote" "refs/tags/$$tag")"; \
	remote_oid="$${remote_line%%[[:space:]]*}"; \
	if git rev-parse -q --verify "refs/tags/$$tag" >/dev/null; then \
		local_oid="$$(git rev-parse "refs/tags/$$tag")"; \
		[[ -z "$$remote_oid" || "$$remote_oid" == "$$local_oid" ]] || die "local tag $$tag does not match $$git_remote/tags/$$tag"; \
		printf 'Using existing tag %s at %s\n' "$$tag" "$$(git rev-list -n 1 "$$tag")"; \
	elif [[ -n "$$remote_oid" ]]; then \
		run git fetch "$$git_remote" "refs/tags/$$tag:refs/tags/$$tag"; \
		printf 'Using fetched tag %s at %s\n' "$$tag" "$$(git rev-list -n 1 "$$tag")"; \
	else \
		run git tag "$$tag"; \
		created_tag="$$tag"; \
		printf 'Created tag %s at %s\n' "$$tag" "$$(git rev-parse HEAD)"; \
	fi; \
	release_commit="$$(git rev-list -n 1 "$$tag")"; \
	head_commit="$$(git rev-parse HEAD)"; \
	[[ "$$release_commit" == "$$head_commit" ]] || die "$$tag points to $$release_commit, but HEAD is $$head_commit; checkout the release commit first"; \
	run "$$make_cmd" dmg \
		"TAG=$$tag" \
		"APP=$$app" \
		"PRODUCT_NAME=$$product_name" \
		"DISTDIR=$$distdir" \
		"DMG_CONFIG=$$config" \
		"WATCHME_VERSION=$${tag#v}" \
		"HDIUTIL=$$hdiutil" \
		"PLUTIL=$$plutil"; \
	assets=("$${distdir}/$${app}-$${tag}.dmg" "$${distdir}/checksums.txt"); \
	for asset in "$${assets[@]}"; do \
		[[ -f "$$asset" ]] || die "missing release asset $$asset"; \
	done; \
	run git push "$$git_remote" "refs/tags/$$tag"; \
	pushed_tag=1; \
	prerelease=(); \
	[[ "$$tag" == *-* ]] && prerelease=(--prerelease); \
	if gh release view "$$tag" --repo "$$repository" >/dev/null 2>&1; then \
		run gh release upload "$$tag" "$${assets[@]}" --clobber --repo "$$repository"; \
	else \
		run gh release create "$$tag" \
			--repo "$$repository" \
			--target "$$release_commit" \
			--title "$$tag" \
			--generate-notes \
			"$${prerelease[@]}" \
			"$${assets[@]}"; \
	fi; \
	printf 'Published %s from local SwiftPM-built DMG.\n' "$$tag"

.PHONY: releae
releae: release ## Alias for release

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
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "TAG" "Release tag for make release, for example vX.Y.Z"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "GIT_REMOTE" "Release git remote, defaults to $(GIT_REMOTE)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "GH_REPO" "GitHub repo override for release, for example owner/repo"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "CONFIG" "SwiftPM build configuration, defaults to $(CONFIG)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "DMG_CONFIG" "SwiftPM build configuration for DMGs, defaults to $(DMG_CONFIG)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "DOC_OUTPUT" "DocC output directory, defaults to $(DOC_OUTPUT)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "DOC_TARGET" "DocC target, defaults to $(DOC_TARGET)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "PREVIEW" "Set to 1 to preview DocC documentation, defaults to $(PREVIEW)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "SWIFT" "Swift executable, defaults to $(SWIFT)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "WATCHME_VERSION" "Embedded package version, defaults to $(WATCHME_VERSION)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "WATCHME_BUNDLE_VERSION" "App bundle version, defaults to $(WATCHME_BUNDLE_VERSION)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "SWIFTFORMAT" "SwiftFormat executable, defaults to $(SWIFTFORMAT)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "SWIFTLINT" "SwiftLint executable, defaults to $(SWIFTLINT)"
	@printf "\n\033[1mExamples:\033[0m\n"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "make dmg TAG=vX.Y.Z" "Build an installable DMG"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "make release TAG=vX.Y.Z" "Publish the DMG to GitHub Releases"
