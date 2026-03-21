# Ledger Package Guide

## Tracker Architecture
The ledger uses independent state-machine trackers that consume blockchain events:
- `accountUpdates`: Account balances, resources, KV store, and application state
- `onlineAccounts` (`acctsOnline`): Online account tracking for consensus
- `catchpointTracker`: Catchpoint generation for fast sync
- `txTail`: Recent transaction and duplicate detection
- `spVerificationTracker`: State proof verification contexts
- `votersTracker`: Merkle trees of online accounts for state proofs
- `bulletin` / `bulletinMem`: Round-completion notification
- `blockNotifier`: Block listener dispatch
- `blockQueue`: In-memory block buffer before DB flush

Trackers rebuild from blockchain events, enabling stateless logic with optional persistent caching.

## Locking Conventions
Each mutable field in ledger structs is annotated with `// protected by xMu` on its declaration line. When adding new mutable fields, add the same annotation. When accessing a field marked `protected by xMu`, ensure the lock is held.

Key locks and their roles:
- **`Ledger.trackerMu`** — guards access to tracker objects from Ledger's public API. Every Ledger method that calls into a tracker (e.g. `LookupAccount`, `LookupAssets`, `LatestTotals`) must hold `RLock`; `reloadLedger` holds `Lock`.
- **`accountUpdates.accountsMu`** / **`onlineAccounts.accountsMu`** — protects in-memory deltas, caches, and `cachedDBRound` that sit on top of the committed database round. Lookup methods acquire `RLock`; `postCommit`/`newBlock` acquire `Lock`. The associated `accountsReadCond` is signaled when `cachedDBRound` advances.
- **`trackerRegistry.mu`** — protects `dbRound` and `lastFlushTime`. Distinct from `Ledger.trackerMu`.
- **`catchpointTracker.catchpointsMu`**, **`txTail.tailMu`**, **`blockQueue.mu`**, **`votersTracker.votersMu`**, **`spVerificationTracker.mu`**, **`bulletin.mu`**, **`blockNotifier.mu`** — each protects the mutable state within its struct; see inline annotations on the fields.

## Paginated Resource Lookups (`acctupdates.go`)
The `lookupAssetResources`, `lookupApplicationResources`, and `lookupBoxResources` functions follow the same pattern: walk in-memory deltas backwards, query the DB, then merge the two result sets. These functions must stay closely aligned — a bug fix or structural change in one almost certainly requires the same change in the others.

Their corresponding `Ledger`-level wrappers in `ledger.go` (`LookupAssets`, `LookupApplications`, `LookupBoxes`) must each hold `trackerMu.RLock()`, matching every other method that accesses tracker state.
