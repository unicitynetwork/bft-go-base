## This project provides Unicity BFT layer base types, abstractions and utilities for Go.

The Go Base provides higher level abstractions that
simplify application integration with the blockchain.

## Upgrading

The signature verification rules are stricter than in earlier versions, and the current binaries have no activation
gate. The conservative baseline is a stop-all upgrade; a coordinated validator cutover followed by rolling aggregator
upgrades is the documented gentler procedure. See [docs/UPGRADING.md](docs/UPGRADING.md).
