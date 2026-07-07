# vowifi-go

An independent, open Go implementation of the VoHive VoWiFi runtime boundary.

This repository focuses on the public runtime APIs and protocol layers that
VoHive consumes for SIM/ISIM AKA, SWu/ePDG tunneling, IMS registration,
messaging, voice bridging, and userspace dataplane experiments.

## Status

vowifi-go is still under active development. It is not affiliated with,
endorsed by, or a drop-in replacement for any vendor, operator, or official
closed-source VoWiFi implementation.

The project does **not** yet implement the complete feature set of the official
closed-source implementation. Full SIP transaction timer state machines,
advanced IMS feature interworking, carrier-specific behavior, production
hardening, and real-world compatibility work are still being implemented
incrementally behind the current APIs.

## Quick Start

Run the test suite:

```sh
go test ./...
```

Run the same local CI entry point used by GitHub Actions:

```sh
make ci
```

When developing VoHive and vowifi-go side by side, VoHive can point at this
checkout with a workspace replace:

```go
replace github.com/boa-z/vowifi-go v1.1.2 => ../vowifi-go
```

## Documentation

- [Features](docs/FEATURES.md) - current implementation inventory and known
  gaps.
- [VoHive readiness](docs/VOHIVE_READINESS.md) - remaining work before this
  module should be treated as usable inside VoHive.
- [Architecture](docs/ARCHITECTURE.md) - package layout, runtime boundaries,
  and high-level flow.
- [Development](docs/DEVELOPMENT.md) - CI targets, local validation, and
  workspace usage.
- [Disclaimer](docs/DISCLAIMER.md) - legal, compliance, warranty, and
  operational-risk notice.
- [Chinese README](README.zh-CN.md) and
  [Chinese disclaimer](docs/DISCLAIMER.zh-CN.md).

## Disclaimer Summary

vowifi-go is provided for personal learning, technical research, and functional
testing. Users are responsible for complying with local laws, telecom operator
terms, device requirements, and network policies. The software is provided
"as is", without warranties, and the authors and contributors are not liable
for losses caused by use, misuse, deployment, or inability to use this project.

Read the full [Disclaimer](docs/DISCLAIMER.md) before using the project.
