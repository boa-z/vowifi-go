# Development

## Local Validation

Run the unit test suite:

```sh
go test ./...
```

Run the same local CI entry point as GitHub Actions:

```sh
make ci
```

Useful focused targets are:

- `make go-version`
- `make module-path`
- `make privacy-check`
- `make fmt-check`
- `make tidy-check`
- `make vet`
- `make smoke`
- `make compat-vohive-selftest`
- `make test`
- `make race`
- `make coverage`
- `make download`
- `make compat-vohive`

The default `make ci` path stays lightweight: it checks the Go version required
by `go.mod`, verifies the canonical module path and Go import roots, downloads
modules, scans tracked content for personal emails, local home paths, and
legacy module references, verifies formatting and module tidiness, runs
`go vet`, compiles packages/tests with a zero-test smoke pass, runs the local
VoHive compatibility self-test, then runs the unit suite. Race and coverage
runs are opt-in:

```sh
make race
make coverage
```

If Go or gofmt is installed outside `PATH`, pass them explicitly:

```sh
GO=/usr/local/go/bin/go GOFMT=/usr/local/go/bin/gofmt make ci
```

## GitHub Actions

GitHub Actions runs `.github/workflows/ci.yml` on Ubuntu against both the
minimum Go patch required by `go.mod` and the latest patch in that Go minor
line, calling `make ci` so local validation and the default CI job share the
same entry point, including the canonical
`github.com/boa-z/vowifi-go` module-path guard. The workflow can also be
started manually with optional race and coverage inputs, matching `make race`
and `make coverage`.

The manual `.github/workflows/vohive-compat.yml` workflow checks this module
against an older VoHive consumer checkout. It asks for the VoHive repository
and an optional ref, then runs the same compatibility script used locally.
Optional inputs can override the VoHive test package list, `go test -run`
pattern, and added `go build` package list for broader compatibility coverage.

The current test suite uses loopback networking and mock command boundaries. It
does not require a modem, root privileges, or a real TUN device in CI.

## VoHive Workspace Usage

VoHive can use this repository through its workspace:

```go
replace github.com/boa-z/vowifi-go v1.1.2 => ../vowifi-go
```

## VoHive Compatibility Check

Run the compatibility guard against a local VoHive checkout:

```sh
VOHIVE_DIR=/path/to/vohive GO=/usr/local/go/bin/go GOFMT=/usr/local/go/bin/gofmt make compat-vohive
```

The script clones or copies the VoHive checkout into a temporary directory,
first verifies this checkout still declares `github.com/boa-z/vowifi-go` and
does not use the legacy module path in Go module/source files, rewrites legacy
`vowifi-go` module references there to `github.com/boa-z/vowifi-go` when
needed, verifies no legacy module references remain, confirms the temporary
VoHive module resolves
`github.com/boa-z/vowifi-go` through a `replace` pointing at this repository,
then runs the focused VoHive test set. The source VoHive checkout is not
modified.

Useful overrides:

- `VOHIVE_COMPAT_PACKAGES` changes the tested package list.
- `VOHIVE_COMPAT_RUN` changes the `go test -run` pattern.
- `VOHIVE_COMPAT_BUILD_PACKAGES` optionally adds `go build` package checks.
- `VOHIVE_COMPAT_TMPDIR` chooses the parent directory for temporary clones and
  Go build work.
- `VOWIFI_MODULE` changes the expected current module path; leave it unset for
  the canonical `github.com/boa-z/vowifi-go` check.
- `VOWIFI_COMPAT_LEGACY_BASE` changes the legacy import owner/base rewritten
  inside the temporary VoHive copy.
