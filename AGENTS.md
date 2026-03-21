# AGENTS.md

This file provides guidance to coding agents when working with code in this repository.

## Common Development Commands

### Build
```bash
make build          # Build all binaries
make install        # Build and install binaries to $GOPATH/bin
make buildsrc       # Build main source (faster than full build)
```

### Testing
```bash
make test           # Run unit tests
make fulltest       # Run unit tests with race detection
make shorttest      # Run short tests with race detection
make integration    # Run integration tests
make testall        # Run all tests (unit + integration)
```

### Code Quality
```bash
make sanity         # Run all checks (fmt, lint, fix, tidy)
make fmt            # Format code and check licenses
make lint           # Run linter (requires deps)
make fix            # Run algofix tool
make vet            # Run go vet
make tidy           # Clean up go.mod files
```

### Code Generation

Some code must be re-generated after changes. Run the following to regenerate auto-generated code if changes are made to relevant files.

```
make rebuild_kmd_swagger                       # Rebuild swagger.json files
make generate                                  # Regenerate for stringer et al.
make expectlint                                # Run expect linter
touch data/transactions/logic/fields_string.go # Ensure rebuild of teal specs
make -C data/transactions/logic                # Update TEAL Specs
touch daemon/algod/api/algod.oas2.json         # Ensure rebuild of API spec
make -C daemon/algod/api generate              # Regenerate REST server
make msgp                                      # Regenerate msgp files
```

To verify that this wasn't missed, we run verification steps, which can be found in `scripts/travis/codegen_verification.sh`. If code is not clean, it will fail CI checks.

### Single Test Execution
```bash
go test -v -run TestName ./path/to/package    # Run specific test
go test -v ./agreement/...                    # Run tests in package tree rooted at agreement
go test -v ./agreement/                       # Run tests for just the agreement package
```

### Running E2E tests
E2E tests use live algod processes. Logs are in `$TESTDIR/<TestName>/<NodeName>/node.log`.
```bash
export NODEBINDIR=~/go/bin
export TESTDATADIR=`pwd`/test/testdata
export TESTDIR=/tmp
go test ./test/e2e-go/features/transactions -run TestAssetSend -v -timeout=0
```

## Architecture Overview

### Main Binaries
- **`algod`**: Core blockchain node daemon (consensus, networking, REST API)
- **`kmd`**: Key Management Daemon (secure wallet operations, isolated process)
- **`goal`**: Primary CLI tool for node interaction and account management
- **`algokey`**: Standalone key generation and management utility

### Core Components
- **`node/`** — Central orchestrator (`AlgorandFullNode`): ledger, networking, consensus, catchup
- **`agreement/`** — Byzantine Agreement protocol (consensus rounds, votes, proposals)
- **`ledger/`** — Blockchain state via tracker-based architecture (see `ledger/AGENTS.md` for details)
- **`network/`** — Networking: WebSocket relay, libp2p P2P, or hybrid
- **`data/`** — Transaction pool, transaction handling, participation keys, core types
- **`crypto/`** — Ed25519, VRF, state proofs, Merkle trees

### Key Patterns
- **Interface-based boundaries**: `GossipNode`, `BlockValidator`, `Ledger`, `KeyManager`
- **Tracker pattern**: Independent state machines in `ledger/` that rebuild from block events
- **Security isolation**: KMD in separate process; verification separated from consensus
