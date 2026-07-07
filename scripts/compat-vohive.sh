#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
	cat <<'USAGE'
Usage: VOHIVE_DIR=/path/to/vohive scripts/compat-vohive.sh

Runs VoHive compatibility checks from an isolated temporary copy of the VoHive
checkout. The source checkout is not modified.

Environment:
  VOHIVE_DIR                    path to a local VoHive checkout
  GO_BIN                        path to go binary
  VOWIFI_MODULE                 module path for this repository
  VOWIFI_COMPAT_LEGACY_BASE     legacy module owner/base to rewrite
  VOHIVE_COMPAT_PACKAGES        package list for go test
  VOHIVE_COMPAT_RUN             go test -run pattern
  VOHIVE_COMPAT_BUILD_PACKAGES  optional package list for go build
  VOHIVE_COMPAT_TMPDIR          parent directory for temporary compatibility work
  VOHIVE_COMPAT_KEEP_TMP=1      keep the temporary compatibility workdir
USAGE
}

find_go() {
	if [[ -n "${GO_BIN:-}" ]]; then
		printf '%s\n' "$GO_BIN"
		return
	fi
	if command -v go >/dev/null 2>&1; then
		command -v go
		return
	fi
	if [[ -x /usr/local/go/bin/go ]]; then
		printf '%s\n' /usr/local/go/bin/go
		return
	fi
	printf 'go not found; set GO_BIN=/path/to/go\n' >&2
	return 127
}

run() {
	printf '\n==> %s\n' "$*"
	"$@"
}

find_module_refs() {
	local module_path="$1"
	grep -RIl --exclude-dir=.git -- "$module_path" . 2>/dev/null || true
}

find_local_go_module_refs() {
	local module_path="$1"
	(
		cd "$ROOT"
		grep -RIn --include='*.go' --include='go.mod' --include='go.work' \
			--exclude-dir=.git -- "$module_path" . 2>/dev/null || true
	)
}

verify_local_module() {
	local module_path
	local local_legacy_refs=()

	if ! module_path="$(
		cd "$ROOT"
		env GOWORK=off TMPDIR="$tmpdir/go-tmp" GOTMPDIR="$tmpdir/go-tmp" "$GO_BIN" list -m -f '{{.Path}}'
	)"; then
		printf 'failed to read local vowifi-go module path\n' >&2
		return 1
	fi
	if [[ "$module_path" != "$VOWIFI_MODULE" ]]; then
		printf 'local vowifi-go module path mismatch: expected %s, got %s\n' "$VOWIFI_MODULE" "$module_path" >&2
		return 1
	fi
	printf '\n==> verified local vowifi-go module path: %s\n' "$module_path"

	if [[ "$LEGACY_MODULE" != "$VOWIFI_MODULE" ]]; then
		mapfile -t local_legacy_refs < <(find_local_go_module_refs "$LEGACY_MODULE")
		if [[ ${#local_legacy_refs[@]} -gt 0 ]]; then
			printf 'legacy vowifi-go module references found in local Go module/source files:\n' >&2
			printf '  %s\n' "${local_legacy_refs[@]}" >&2
			return 1
		fi
	fi
	printf '\n==> verified local Go module/source references do not use %s\n' "$LEGACY_MODULE"
}

verify_rewritten_modules() {
	local remaining_legacy=()
	local current_refs=()

	if [[ "$LEGACY_MODULE" != "$VOWIFI_MODULE" ]]; then
		mapfile -t remaining_legacy < <(find_module_refs "$LEGACY_MODULE")
		if [[ ${#remaining_legacy[@]} -gt 0 ]]; then
			printf 'legacy vowifi-go module references remain after rewrite:\n' >&2
			printf '  %s\n' "${remaining_legacy[@]}" >&2
			return 1
		fi
	fi

	mapfile -t current_refs < <(find_module_refs "$VOWIFI_MODULE")
	if [[ ${#current_refs[@]} -eq 0 ]]; then
		printf 'temporary VoHive copy does not reference %s after module rewrite\n' "$VOWIFI_MODULE" >&2
		return 1
	fi
	printf '\n==> verified temporary VoHive module references use %s\n' "$VOWIFI_MODULE"
}

verify_vowifi_replace() {
	local replace_path
	if ! replace_path="$(
		env GOWORK=off TMPDIR="$tmpdir/go-tmp" GOTMPDIR="$tmpdir/go-tmp" \
			"$GO_BIN" list -m -f '{{with .Replace}}{{.Path}}{{end}}' "$VOWIFI_MODULE"
	)"; then
		printf 'VoHive does not resolve %s after module rewrite and tidy\n' "$VOWIFI_MODULE" >&2
		return 1
	fi
	if [[ "$replace_path" != "$ROOT" ]]; then
		printf 'VoHive resolves %s via unexpected replace path: %s\n' "$VOWIFI_MODULE" "${replace_path:-<none>}" >&2
		return 1
	fi
	printf '\n==> verified VoHive resolves %s through this checkout\n' "$VOWIFI_MODULE"
}

VOHIVE_DIR="${VOHIVE_DIR:-${1:-}}"
if [[ -z "$VOHIVE_DIR" ]]; then
	usage >&2
	exit 2
fi
if [[ ! -d "$VOHIVE_DIR" ]]; then
	printf 'VOHIVE_DIR does not exist or is not a directory: %s\n' "$VOHIVE_DIR" >&2
	exit 2
fi

GO_BIN="$(find_go)"
VOWIFI_MODULE="${VOWIFI_MODULE:-github.com/boa-z/vowifi-go}"
legacy_base="${VOWIFI_COMPAT_LEGACY_BASE:-github.com/iniwex5}"
legacy_base="${legacy_base%/}"
LEGACY_MODULE="${legacy_base}/vowifi-go"
VOHIVE_COMPAT_PACKAGES="${VOHIVE_COMPAT_PACKAGES:-./cmd/vohive ./internal/api ./internal/cscall ./internal/device ./internal/e911 ./internal/notify ./internal/sim ./internal/vowifihost}"
VOHIVE_COMPAT_RUN="${VOHIVE_COMPAT_RUN:-VoWiFi|RuntimeStart|StartRuntime|Tunnel|MOBIKE|Dataplane|IMS|Voice|USSD|E911|Emergency|Websheet}"
VOHIVE_COMPAT_BUILD_PACKAGES="${VOHIVE_COMPAT_BUILD_PACKAGES:-./cmd/vohive}"
VOHIVE_COMPAT_TMPDIR="${VOHIVE_COMPAT_TMPDIR:-${TMPDIR:-/tmp}}"
VOHIVE_COMPAT_KEEP_TMP="${VOHIVE_COMPAT_KEEP_TMP:-0}"

mkdir -p "$VOHIVE_COMPAT_TMPDIR"
tmpdir="$(mktemp -d -p "$VOHIVE_COMPAT_TMPDIR" vowifi-go-vohive-compat-XXXXXX)"
workdir="$tmpdir/vohive"
cleanup() {
	local status=$?
	if [[ "$status" -ne 0 ]]; then
		printf '\ncompat-vohive failed.\n' >&2
		printf '  VoHive source: %s\n' "$VOHIVE_DIR" >&2
		printf '  temporary copy: %s\n' "$workdir" >&2
		printf '  test packages: %s\n' "${VOHIVE_COMPAT_PACKAGES:-<none>}" >&2
		printf '  test run pattern: %s\n' "${VOHIVE_COMPAT_RUN:-<none>}" >&2
		printf '  build packages: %s\n' "${VOHIVE_COMPAT_BUILD_PACKAGES:-<none>}" >&2
		printf 'Set VOHIVE_COMPAT_KEEP_TMP=1 to preserve the temporary workdir for inspection.\n' >&2
	fi
	if [[ "$VOHIVE_COMPAT_KEEP_TMP" == "1" ]]; then
		printf '\n==> preserving temporary compatibility workdir: %s\n' "$tmpdir" >&2
	else
		rm -rf "$tmpdir"
	fi
}
trap cleanup EXIT

if [[ -d "$VOHIVE_DIR/.git" ]]; then
	run git clone --quiet --shared "$VOHIVE_DIR" "$workdir"
else
	mkdir -p "$workdir"
	(
		cd "$VOHIVE_DIR"
		tar --exclude .git -cf - .
	) | (
		cd "$workdir"
		tar -xf -
	)
fi

cd "$workdir"
mkdir -p "$tmpdir/go-tmp"

verify_local_module

mapfile -t legacy_files < <(grep -RIl --exclude-dir=.git -- "$LEGACY_MODULE" . 2>/dev/null || true)
if [[ ${#legacy_files[@]} -gt 0 ]]; then
	printf '\n==> rewriting legacy vowifi-go imports in temporary VoHive copy\n'
	LEGACY_MODULE="$LEGACY_MODULE" VOWIFI_MODULE="$VOWIFI_MODULE" \
	perl -0pi -e 's/\Q$ENV{LEGACY_MODULE}\E/$ENV{VOWIFI_MODULE}/g' "${legacy_files[@]}"
fi
verify_rewritten_modules

run env GOWORK=off TMPDIR="$tmpdir/go-tmp" GOTMPDIR="$tmpdir/go-tmp" "$GO_BIN" mod edit -replace "${VOWIFI_MODULE}=${ROOT}"
run env GOWORK=off TMPDIR="$tmpdir/go-tmp" GOTMPDIR="$tmpdir/go-tmp" "$GO_BIN" mod tidy
verify_vowifi_replace

read -r -a test_packages <<< "$VOHIVE_COMPAT_PACKAGES"
if [[ ${#test_packages[@]} -gt 0 ]]; then
	run env GOWORK=off TMPDIR="$tmpdir/go-tmp" GOTMPDIR="$tmpdir/go-tmp" "$GO_BIN" test "${test_packages[@]}" -run "$VOHIVE_COMPAT_RUN"
fi

read -r -a build_packages <<< "$VOHIVE_COMPAT_BUILD_PACKAGES"
if [[ ${#build_packages[@]} -gt 0 ]]; then
	run env GOWORK=off TMPDIR="$tmpdir/go-tmp" GOTMPDIR="$tmpdir/go-tmp" "$GO_BIN" build "${build_packages[@]}"
fi
