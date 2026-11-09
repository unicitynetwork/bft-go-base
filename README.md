## This project provides Unicity BFT layer base types, abstractions and utilities for Go.

The Go Base provides higher level abstractions that
simplify application integration with the blockchain.

The `types` package includes V2 trust-base entries and complete history bundles for verifying authority changes from a pinned genesis. See the [API reference](docs/api-reference.md#trust-base-entries-and-bundles) for decoding and authentication.

## Upgrading

The signature verification rules are stricter than in earlier versions, and the current binaries have no activation
gate. The conservative baseline is a stop-all upgrade; a coordinated validator cutover followed by rolling aggregator
upgrades is the documented gentler procedure. See [docs/UPGRADING.md](docs/UPGRADING.md).
