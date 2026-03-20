# Ledger Package Lock Inventory

This document catalogs every mutex in the `ledger/` package (top-level only, not
sub-packages), describes what each lock guards, and records the locking
conventions that callers must follow.

---

## 1. `Ledger.trackerMu` — `deadlock.RWMutex`

**File:** `ledger/ledger.go`

**Guards:** Access to all tracker subsystems from the `Ledger` public API.
Every public `Ledger` method that reads tracker state (account lookups,
totals, catchpoint labels, voter trees, state-proof verification contexts,
etc.) acquires `trackerMu.RLock()`. Methods that mutate tracker state
(`AddValidatedBlock`, `Close`, `reloadLedger`, `notifyCommit`) acquire the
full write lock.

**Convention:**
- `trackerMu.RLock()` + `defer trackerMu.RUnlock()` for read-only access.
- `trackerMu.Lock()` + deferred unlock (sometimes wrapped in a closure) for
  write access.
- Several `Ledger` methods intentionally skip `trackerMu` because the
  called tracker method uses its own internal lock:
  - `CheckDup`, `CheckConfirmedTail`, `BlockHdr` → `txTail.tailMu`
  - `FlushCaches` → `accountUpdates.accountsMu`
  - `LatestTrackerCommitted`, `IsBehindCommittingDeltas` → `trackerRegistry.mu`

**Lock ordering:** `trackerMu` must be acquired *before* any individual
tracker lock when both are needed.

---

## 2. `accountUpdates.accountsMu` — `deadlock.RWMutex`

**File:** `ledger/acctupdates.go`

**Guards:** All mutable, non-static fields of `accountUpdates`: `deltas`,
`accounts`, `resources`, `kvStore`, `creatables`, `versions`, `roundTotals`,
`deltasAccum`, `baseAccounts`, `baseResources`, `baseKVs`, `cachedDBRound`.

**Convention:**
- Simple read-only methods (`LatestTotals`, `Totals`, `committedUpTo`,
  `lookupStateDelta`) use `RLock` + `defer RUnlock`.
- Lookup methods that may need to fall back to the database
  (`lookupWithoutRewards`, `lookupResource`, `lookupLatest`,
  `lookupAssetResources`, `lookupApplicationResources`,
  `lookupBoxResources`, `lookupKvPair`, `lookupKeysByPrefix`) use a
  manual lock/unlock pattern: they acquire `RLock`, read in-memory
  deltas, release the lock before querying the DB, then re-acquire the
  lock to merge results. A `needUnlock` boolean tracks whether the lock
  is currently held, with a deferred closure ensuring cleanup.
- Write methods (`loadFromDisk`, `newBlock`, `postCommit`, `flushCaches`)
  use the full `Lock`.
- `accountsReadCond` (a `sync.Cond` derived from `accountsMu`) is used to
  wait for new blocks in lookup retry loops.

---

## 3. `onlineAccounts.accountsMu` — `deadlock.RWMutex`

**File:** `ledger/acctonline.go`

**Guards:** All mutable, non-static fields of `onlineAccounts`: `deltas`,
`accounts`, `onlineRoundParamsData`, `deltasAccum`,
`baseOnlineAccounts`, `onlineAccountsCache`, `cachedDBRoundOnline`.

**Convention:** Mirrors `accountUpdates.accountsMu` exactly — simple
reads use `RLock` + defer, database-fallback lookups use the manual
`needUnlock` pattern, writes use `Lock`. `accountsReadCond` is similarly
used for retry waits.

---

## 4. `catchpointTracker.catchpointsMu` — `deadlock.RWMutex`

**File:** `ledger/catchpointtracker.go`

**Guards:** `roundDigest`, `reenableCatchpointsRound`, `cachedDBRound`,
`lastCatchpointLabel`, `balancesTrie`.

**Convention:**
- Read-only accesses (`GetLastCatchpointLabel`, `committedUpTo`,
  `prepareCommit`, `isCatchpointRound`, `IsWritingCatchpointDataFile`)
  use `RLock` + `defer RUnlock`.
- Write accesses (`newBlock`, `postCommit`, `commitRound`,
  `handleCatchpointRound`) use `Lock`. Some write paths use
  `Lock`/`Unlock` without `defer` due to multi-step logic (e.g.,
  `commitRound` acquires the lock, creates a trie if needed, then
  releases before proceeding with I/O).

---

## 5. `txTail.tailMu` — `deadlock.RWMutex`

**File:** `ledger/txtail.go`

**Guards:** `lastValid`, `recent`, `lowWaterMark`, `roundTailHashes`,
`roundTailSerializedDeltas`, `blockHeaderData`, `lowestBlockHeaderRound`.

**Convention:**
- Read-only accesses (`checkDup`, `checkConfirmed`, `blockHeader`,
  `hashRoundTailSerializedDeltas`) use `RLock` + `defer RUnlock`.
- Write accesses (`loadFromDisk`, `newBlock`, `committedUpTo`,
  `postCommit`) use `Lock` + `defer Unlock`.
- `prepareCommit` uses manual `RLock`/`RUnlock` (no defer) because it
  reads a range of data and then releases before further processing.
- `txTail` methods are called directly from `Ledger` without
  `trackerMu` because `tailMu` provides sufficient self-contained
  synchronization (documented in a comment at `checkDup`).

---

## 6. `votersTracker.votersMu` — `deadlock.RWMutex`

**File:** `ledger/voters.go`

**Guards:** `votersForRoundCache` (map of `VotersForRound` entries keyed
by round).

**Convention:**
- Read-only accesses (`getVoters`, `LatestCompletedVotersUpTo`,
  `LookupVotersByRound`) use `RLock` + `defer RUnlock`.
- Write accesses (`loadFromDisk`, `postCommit`, `setVoters`) use `Lock`
  + `defer Unlock` (except `loadFromDisk` which uses manual
  `Lock`/`Unlock`).

---

## 7. `votersTracker.commitListenerMu` — `deadlock.RWMutex`

**File:** `ledger/voters.go`

**Guards:** `commitListener` (a `VotersCommitListener` callback).

**Convention:**
- `prepareCommit` acquires `RLock` to invoke the listener callback.
- `registerPrepareCommitListener` and `unregisterPrepareCommitListener`
  acquire `Lock` to set/clear the listener.
- All use `defer` for unlock.

---

## 8. `trackerRegistry.mu` — `deadlock.RWMutex`

**File:** `ledger/tracker.go`

**Guards:** `dbRound`, `lastFlushTime`, and coordination of the commit
syncer goroutine.

**Convention:**
- `initialize` acquires `Lock` + `defer Unlock`.
- `getDbRound`, `isBehindCommittingDeltas`, and parts of `commitRound`
  use `RLock`/`RUnlock` (without defer, inline pairs) to snapshot
  `dbRound`.
- `commitRound` end-of-function uses `Lock` to update `dbRound` after a
  successful commit.

---

## 9. `spVerificationTracker.mu` — `deadlock.RWMutex`

**File:** `ledger/spverificationtracker.go`

**Guards:** `pendingCommitContexts`, `pendingDeleteContexts`,
`lastLookedUpVerificationContext`.

**Convention:**
- Read-only accesses (`prepareCommit`, `retrieveFromCache`,
  `lookupVerificationContext`) use `RLock` + `defer RUnlock`.
- Write accesses (`loadFromDisk`, `postCommit`, `appendCommitContext`,
  `appendDeleteContext`) use `Lock` + `defer Unlock`.
- One-off cache update in `LookupSPContext` uses `Lock`/`Unlock`
  without defer (single assignment, immediately released).

---

## 10. `bulletin.mu` — `deadlock.Mutex`

**File:** `ledger/bulletin.go`

**Guards:** `pendingNotificationRequests` (map of round → notifier) and
`latestRound`.

**Convention:** Plain `Mutex` (not RWMutex). All accesses (`Wait`,
`WaitWithCancel`, `OnNewBlock`) use `Lock` + `defer Unlock`.
`bulletinMem` embeds `bulletin` and inherits its lock.

---

## 11. `blockQueue.mu` — `deadlock.Mutex`

**File:** `ledger/blockqueue.go`

**Guards:** `lastCommitted`, `q` (block queue slice), `running`.
Used as the underlying mutex for `blockQueue.cond` (`sync.Cond`).

**Convention:** Plain `Mutex`. Most methods (`start`, `latest`,
`latestCommitted`, `getBlock`, `getBlockHdr`, `getEncodedBlockCert`,
`putBlock`) use `Lock` + `defer Unlock`. The write-to-disk goroutine
holds the lock during queue processing and uses `cond.Wait()` /
`cond.Signal()` for synchronization.

---

## 12. `blockNotifier.mu` — `deadlock.Mutex`

**File:** `ledger/notifier.go`

**Guards:** `listeners`, `pendingBlocks`, `running`.
Used as the underlying mutex for `blockNotifier.cond` (`sync.Cond`).

**Convention:** Plain `Mutex`. The worker goroutine holds the lock while
checking for pending blocks, releases it during listener callbacks, then
re-acquires. `loadFromDisk`, `newBlock`, and `close` all use `Lock` with
appropriate `cond.Broadcast()` calls.

---

## 13. `expiredCirculationCache.mu` — `deadlock.RWMutex`

**File:** `ledger/acctonlineexp.go`

**Guards:** `cur` and `prev` maps caching expired online circulation
stake computations.

**Convention:**
- `get` uses `RLock` + `defer RUnlock`.
- `put` uses `Lock` + `defer Unlock`.
- Cache eviction (promoting `cur` → `prev`) happens under the write
  lock in `put`.

---

## Lock Ordering

When multiple locks from this list must be held simultaneously, the
following order must be observed to prevent deadlocks:

1. `Ledger.trackerMu` (outermost)
2. Individual tracker locks (`accountsMu`, `catchpointsMu`, `votersMu`,
   `tailMu`, `trackerRegistry.mu`, `spVerificationTracker.mu`)
3. `bulletin.mu`, `blockQueue.mu`, `blockNotifier.mu` (infrastructure locks)

In practice, `trackerMu` and individual tracker locks are rarely held at
the same time — `trackerMu` guards entry from the Ledger API, and each
tracker's own lock guards internal state. The trackers that bypass
`trackerMu` (`txTail`, `trackerRegistry`) rely entirely on their own
locks.

## Notes on `deadlock` Package

All mutexes use `github.com/sasha-s/go-deadlock` variants (`deadlock.Mutex`
and `deadlock.RWMutex`) rather than `sync.Mutex`/`sync.RWMutex`. This
provides runtime deadlock detection during development and testing. The
`deadlock` types are API-compatible with their `sync` counterparts.
