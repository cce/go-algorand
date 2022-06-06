// Copyright (C) 2019-2022 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package ledger

import (
	"archive/tar"
	"compress/gzip"
	"compress/zlib"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/algorand/go-deadlock"
	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// trieCachedNodesCount defines how many balances trie nodes we would like to keep around in memory.
// value was calibrated using BenchmarkCalibrateCacheNodeSize
var trieCachedNodesCount = 9000

// merkleCommitterNodesPerPage controls how many nodes will be stored in a single page
// value was calibrated using BenchmarkCalibrateNodesPerPage
var merkleCommitterNodesPerPage = int64(116)

const (
	// trieRebuildAccountChunkSize defines the number of accounts that would get read at a single chunk
	// before added to the trie during trie construction
	trieRebuildAccountChunkSize = 16384
	// trieRebuildCommitFrequency defines the number of accounts that would get added before we call evict to commit the changes and adjust the memory cache.
	trieRebuildCommitFrequency = 65536
	// trieAccumulatedChangesFlush defines the number of pending changes that would be applied to the merkle trie before
	// we attempt to commit them to disk while writing a batch of rounds balances to disk.
	trieAccumulatedChangesFlush = 256
	// CatchpointDirName represents the directory name in which all the catchpoints files are stored
	CatchpointDirName = "catchpoints"

	// CatchpointFileVersionV5 is the catchpoint file version that was used when the database schema was V0-V5.
	CatchpointFileVersionV5 = uint64(0200)
	// CatchpointFileVersionV6 is the catchpoint file version that is matching database schema V6.
	// This version introduced accounts and resources separation. The first catchpoint
	// round of this version is >= `accountDataResourceSeparationRound`.
	CatchpointFileVersionV6 = uint64(0201)
)

// TrieMemoryConfig is the memory configuration setup used for the merkle trie.
var TrieMemoryConfig = merkletrie.MemoryConfig{
	NodesCountPerPage:         merkleCommitterNodesPerPage,
	CachedNodesCount:          trieCachedNodesCount,
	PageFillFactor:            0.95,
	MaxChildrenPagesThreshold: 64,
}

type nopWriteCloser struct {
	w io.Writer
}

func (c nopWriteCloser) Write(p []byte) (n int, err error) { return c.w.Write(p) }
func (c nopWriteCloser) Close() error                      { return nil }

func catchpointStage1Encoder(w io.Writer) (io.WriteCloser, error) {
	switch strings.ToLower(os.Getenv("CATCHPOINT_COMPRESS")) {
	case "snappy":
		fmt.Println("using Snappy")
		return snappy.NewBufferedWriter(w), nil
	case "zlib":
		fmt.Println("using ZLib BestSpeed")
		return zlib.NewWriterLevel(w, zlib.BestSpeed)
	case "zstd":
		fmt.Println("using Zstd")
		return zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedFastest))
	default:
		fmt.Println("using Noop compression writer")
		return nopWriteCloser{w}, nil
	}
}

type snappyReadCloser struct {
	*snappy.Reader
}

func (snappyReadCloser) Close() error { return nil }

func catchpointStage1Decoder(r io.Reader) (io.ReadCloser, error) {
	switch strings.ToLower(os.Getenv("CATCHPOINT_COMPRESS")) {
	case "snappy":
		return snappyReadCloser{snappy.NewReader(r)}, nil
	case "zlib":
		return zlib.NewReader(r)
	case "zstd":
		ret, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		return ret.IOReadCloser(), nil
	default:
		return io.NopCloser(r), nil
	}
}

type catchpointTracker struct {
	// dbDirectory is the directory where the ledger and block sql file resides as well as the parent directory for the catchup files to be generated
	dbDirectory string

	// catchpointInterval is the configured interval at which the catchpointTracker would generate catchpoint labels and catchpoint files.
	catchpointInterval uint64

	// catchpointFileHistoryLength defines how many catchpoint files we want to store back.
	// 0 means don't store any, -1 mean unlimited and positive number suggest the number of most recent catchpoint files.
	catchpointFileHistoryLength int

	// enableGeneratingCatchpointFiles determines whether catchpoints files should be generated by the trackers.
	enableGeneratingCatchpointFiles bool

	// Prepared SQL statements for fast accounts DB lookups.
	accountsq *accountsDbQueries

	// log copied from ledger
	log logging.Logger

	// Connection to the database.
	dbs db.Pair

	// The last catchpoint label that was written to the database. Should always align with what's in the database.
	// note that this is the last catchpoint *label* and not the catchpoint file.
	lastCatchpointLabel string

	// catchpointDataSlowWriting suggests to the accounts writer that it should finish
	// writing up the (first stage) catchpoint data file ASAP. When this channel is
	// closed, the accounts writer would try and complete the writing as soon as possible.
	// Otherwise, it would take its time and perform periodic sleeps between chunks
	// processing.
	catchpointDataSlowWriting chan struct{}

	// catchpointDataWriting helps to synchronize the (first stage) catchpoint data file
	// writing. When this atomic variable is 0, no writing is going on.
	// Any non-zero value indicates a catchpoint being written, or scheduled to be written.
	catchpointDataWriting int32

	// The Trie tracking the current account balances. Always matches the balances that were
	// written to the database.
	balancesTrie *merkletrie.Trie

	// roundDigest stores the digest of the block for every round starting with dbRound+1 and every round after it.
	roundDigest []crypto.Digest

	// accountDataResourceSeparationRound is a round where the EnableAccountDataResourceSeparation feature was enabled via the consensus.
	// we avoid generating catchpoints before that round in order to ensure the network remain consistent in the catchpoint
	// label being produced. This variable could be "wrong" in two cases -
	// 1. It's zero, meaning that the EnableAccountDataResourceSeparation has yet to be seen.
	// 2. It's non-zero meaning that it the given round is after the EnableAccountDataResourceSeparation was enabled ( it might be exact round
	//    but that's only if newBlock was called with that round ), plus the lookback.
	accountDataResourceSeparationRound basics.Round

	// catchpointsMu protects `roundDigest`, `accountDataResourceSeparationRound` and
	// `lastCatchpointLabel`.
	catchpointsMu deadlock.RWMutex
}

// initialize initializes the catchpointTracker structure
func (ct *catchpointTracker) initialize(cfg config.Local, dbPathPrefix string) {
	ct.dbDirectory = filepath.Dir(dbPathPrefix)

	switch cfg.CatchpointTracking {
	case -1:
		// No catchpoints.
	default:
		// Give a warning, then fall through to case 0.
		logging.Base().Warnf("catchpointTracker: the CatchpointTracking field in the config.json file contains an invalid value (%d). The default value of 0 would be used instead.", cfg.CatchpointTracking)
		fallthrough
	case 0:
		if cfg.Archival && (cfg.CatchpointInterval > 0) {
			ct.catchpointInterval = cfg.CatchpointInterval
			ct.enableGeneratingCatchpointFiles = true
		}
	case 1:
		if cfg.CatchpointInterval > 0 {
			ct.catchpointInterval = cfg.CatchpointInterval
			ct.enableGeneratingCatchpointFiles = cfg.Archival
		}
	case 2:
		if cfg.CatchpointInterval > 0 {
			ct.catchpointInterval = cfg.CatchpointInterval
			ct.enableGeneratingCatchpointFiles = true
		}
	}

	ct.catchpointFileHistoryLength = cfg.CatchpointFileHistoryLength
	if cfg.CatchpointFileHistoryLength < -1 {
		ct.catchpointFileHistoryLength = -1
	}
}

// GetLastCatchpointLabel retrieves the last catchpoint label that was stored to the database.
func (ct *catchpointTracker) GetLastCatchpointLabel() string {
	ct.catchpointsMu.RLock()
	defer ct.catchpointsMu.RUnlock()
	return ct.lastCatchpointLabel
}

// loadFromDisk loads the state of a tracker from persistent
// storage.  The ledger argument allows loadFromDisk to load
// blocks from the database, or access its own state.  The
// ledgerForTracker interface abstracts away the details of
// ledger internals so that individual trackers can be tested
// in isolation.
func (ct *catchpointTracker) loadFromDisk(l ledgerForTracker, lastBalancesRound basics.Round) (err error) {
	ct.log = l.trackerLog()
	ct.dbs = l.trackerDB()

	ct.roundDigest = nil
	ct.catchpointDataWriting = 0
	// keep these channel closed if we're not generating catchpoint
	ct.catchpointDataSlowWriting = make(chan struct{}, 1)
	close(ct.catchpointDataSlowWriting)

	err = ct.dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		err0 := ct.accountsInitializeHashes(ctx, tx, lastBalancesRound)
		if err0 != nil {
			return err0
		}
		return nil
	})
	if err != nil {
		return err
	}

	ct.accountsq, err = accountsInitDbQueries(ct.dbs.Rdb.Handle, ct.dbs.Wdb.Handle)
	if err != nil {
		return
	}

	ct.lastCatchpointLabel, _, err = ct.accountsq.readCatchpointStateString(context.Background(), catchpointStateLastCatchpoint)
	if err != nil {
		return
	}

	// TODO: prune data, restart generating catchpoint data file or catchpoint file.
	/*
		writingCatchpointDataFileRound, _, err := ct.accountsq.readCatchpointStateUint64(context.Background(), catchpointStateWritingCatchpoint)
		if err != nil {
			return err
		}
		if writingCatchpointDataFileRound == 0 || !ct.catchpointEnabled() {
			return nil
		}

		// make sure that the database is at the desired round.
		dbRound, err := accountsRound(ct.dbs.Rdb.Handle)
		if err != nil {
			return err
		}
		if dbRound != basics.Round(writingCatchpointDataFileRound) {
			return nil
		}

		ct.generateCatchpointData(context.Background(), basics.Round(writingCatchpointDataFileRound), time.Duration(0))
	*/
	return nil
}

// newBlock informs the tracker of a new block from round
// rnd and a given ledgercore.StateDelta as produced by BlockEvaluator.
func (ct *catchpointTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	ct.catchpointsMu.Lock()
	defer ct.catchpointsMu.Unlock()

	ct.roundDigest = append(ct.roundDigest, blk.Digest())

	if config.Consensus[blk.CurrentProtocol].EnableAccountDataResourceSeparation && ct.accountDataResourceSeparationRound == 0 {
		catchpointLookback := config.Consensus[blk.CurrentProtocol].CatchpointLookback
		if catchpointLookback == 0 {
			catchpointLookback = config.Consensus[blk.CurrentProtocol].MaxBalLookback
		}
		ct.accountDataResourceSeparationRound = blk.BlockHeader.Round + basics.Round(catchpointLookback)
	}
}

// committedUpTo implements the ledgerTracker interface for catchpointTracker.
// The method informs the tracker that committedRound and all it's previous rounds have
// been committed to the block database. The method returns what is the oldest round
// number that can be removed from the blocks database as well as the lookback that this
// tracker maintains.
func (ct *catchpointTracker) committedUpTo(rnd basics.Round) (retRound, lookback basics.Round) {
	return rnd, basics.Round(0)
}

// Calculate whether we have intermediate first stage catchpoint rounds and the
// new offset.
func calculateFirstStageRounds(oldBase basics.Round, offset uint64, accountDataResourceSeparationRound basics.Round, catchpointInterval uint64, catchpointLookback uint64) (hasIntermediateFirstStageRound bool, hasMultipleIntermediateFirstStageRounds bool, newOffset uint64) {
	newOffset = offset

	if accountDataResourceSeparationRound > 0 {
		minFirstStageRound := oldBase + 1
		if (accountDataResourceSeparationRound > basics.Round(catchpointLookback)) &&
			(accountDataResourceSeparationRound-basics.Round(catchpointLookback) >
				minFirstStageRound) {
			minFirstStageRound =
				accountDataResourceSeparationRound - basics.Round(catchpointLookback)
		}

		// The smallest integer r >= dcr.minFirstStageRound such that
		// (r + catchpointLookback) % ct.catchpointInterval == 0.
		first := (int64(minFirstStageRound)+int64(catchpointLookback)+
			int64(catchpointInterval)-1)/
			int64(catchpointInterval)*int64(catchpointInterval) -
			int64(catchpointLookback)
		// The largest integer r <= dcr.oldBase + dcr.offset such that
		// (r + catchpointLookback) % ct.catchpointInterval == 0.
		last := (int64(oldBase)+int64(offset)+int64(catchpointLookback))/
			int64(catchpointInterval)*int64(catchpointInterval) - int64(catchpointLookback)

		if first <= last {
			hasIntermediateFirstStageRound = true
			// We skip earlier catchpoints if there is more than one to generate.
			newOffset = uint64(last) - uint64(oldBase)

			if first < last {
				hasMultipleIntermediateFirstStageRounds = true
			}
		}
	}

	return
}

func (ct *catchpointTracker) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	if ct.catchpointInterval == 0 {
		return dcr
	}

	ct.catchpointsMu.Lock()
	accountDataResourceSeparationRound := ct.accountDataResourceSeparationRound
	ct.catchpointsMu.Unlock()

	// Check if we need to do the first stage of catchpoint generation.
	var hasIntermediateFirstStageRound bool
	var hasMultipleIntermediateFirstStageRounds bool
	hasIntermediateFirstStageRound, hasMultipleIntermediateFirstStageRounds, dcr.offset =
		calculateFirstStageRounds(
			dcr.oldBase, dcr.offset, accountDataResourceSeparationRound,
			ct.catchpointInterval, dcr.catchpointLookback)

	// if we're still writing the previous balances, we can't move forward yet.
	if ct.IsWritingCatchpointDataFile() {
		// if we hit this path, it means that we're still writing a catchpoint.
		// see if the new delta range contains another catchpoint.
		if hasIntermediateFirstStageRound {
			// check if we're already attempting to perform fast-writing.
			select {
			case <-ct.catchpointDataSlowWriting:
				// yes, we're already doing fast-writing.
			default:
				// no, we're not yet doing fast writing, make it so.
				close(ct.catchpointDataSlowWriting)
			}
		}
		return nil
	}

	if hasIntermediateFirstStageRound {
		dcr.catchpointFirstStage = true

		if ct.enableGeneratingCatchpointFiles {
			// store non-zero ( all ones ) into the catchpointWriting atomic variable to indicate that a catchpoint is being written ( or, queued to be written )
			atomic.StoreInt32(&ct.catchpointDataWriting, int32(-1))
			ct.catchpointDataSlowWriting = make(chan struct{}, 1)
			if hasMultipleIntermediateFirstStageRounds {
				close(ct.catchpointDataSlowWriting)
			}
		}
	}

	dcr.catchpointDataWriting = &ct.catchpointDataWriting
	dcr.enableGeneratingCatchpointFiles = ct.enableGeneratingCatchpointFiles

	{
		rounds := calculateCatchpointRounds(
			dcr.oldBase+1, dcr.oldBase+basics.Round(dcr.offset), ct.catchpointInterval)
		dcr.catchpointSecondStage = (len(rounds) > 0)
	}

	return dcr
}

// prepareCommit, commitRound and postCommit are called when it is time to commit tracker's data.
// If an error returned the process is aborted.
func (ct *catchpointTracker) prepareCommit(dcc *deferredCommitContext) error {
	ct.catchpointsMu.RLock()
	defer ct.catchpointsMu.RUnlock()

	dcc.committedRoundDigests = make([]crypto.Digest, dcc.offset)
	copy(dcc.committedRoundDigests, ct.roundDigest[:dcc.offset])

	return nil
}

func (ct *catchpointTracker) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) (err error) {
	treeTargetRound := basics.Round(0)
	offset := dcc.offset
	dbRound := dcc.oldBase

	defer func() {
		if err != nil && dcc.catchpointFirstStage &&
			ct.enableGeneratingCatchpointFiles {
			atomic.StoreInt32(&ct.catchpointDataWriting, 0)
		}
	}()

	if ct.catchpointEnabled() {
		var mc *MerkleCommitter
		mc, err = MakeMerkleCommitter(tx, false)
		if err != nil {
			return
		}

		var trie *merkletrie.Trie
		if ct.balancesTrie == nil {
			trie, err = merkletrie.MakeTrie(mc, TrieMemoryConfig)
			if err != nil {
				ct.log.Warnf("unable to create merkle trie during committedUpTo: %v", err)
				return err
			}
			ct.balancesTrie = trie
		} else {
			ct.balancesTrie.SetCommitter(mc)
		}
		treeTargetRound = dbRound + basics.Round(offset)
	}

	if dcc.updateStats {
		dcc.stats.MerkleTrieUpdateDuration = time.Duration(time.Now().UnixNano())
	}

	err = ct.accountsUpdateBalances(dcc.compactAccountDeltas, dcc.compactResourcesDeltas)
	if err != nil {
		return err
	}

	if dcc.updateStats {
		now := time.Duration(time.Now().UnixNano())
		dcc.stats.MerkleTrieUpdateDuration = now - dcc.stats.MerkleTrieUpdateDuration
	}

	err = updateAccountsHashRound(tx, treeTargetRound)
	if err != nil {
		return err
	}

	return nil
}

func (ct *catchpointTracker) postCommit(ctx context.Context, dcc *deferredCommitContext) {
	if ct.balancesTrie != nil {
		_, err := ct.balancesTrie.Evict(false)
		if err != nil {
			ct.log.Warnf("merkle trie failed to evict: %v", err)
		}
	}

	ct.catchpointsMu.Lock()
	ct.roundDigest = ct.roundDigest[dcc.offset:]
	ct.catchpointsMu.Unlock()

	dcc.updatingBalancesDuration = time.Since(dcc.flushTime)

	if dcc.updateStats {
		dcc.stats.MemoryUpdatesDuration = time.Duration(time.Now().UnixNano())
	}
}

func doRepackCatchpoint(header CatchpointFileHeader, biggestChunkLen uint64, in *tar.Reader, out *tar.Writer) error {
	{
		bytes := protocol.Encode(&header)

		err := out.WriteHeader(&tar.Header{
			Name: "content.msgpack",
			Mode: 0600,
			Size: int64(len(bytes)),
		})
		if err != nil {
			return err
		}

		_, err = out.Write(bytes)
		if err != nil {
			return err
		}
	}

	// make buffer for re-use that can fit biggest chunk
	buf := make([]byte, biggestChunkLen)
	for {
		header, err := in.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		n, err := io.ReadAtLeast(in, buf, int(header.Size))
		if (err != nil) && (err != io.EOF) {
			return err
		}
		if int64(n) != header.Size { // should not happen
			return fmt.Errorf("read too many bytes from chunk %+v", header)
		}

		err = out.WriteHeader(header)
		if err != nil {
			return err
		}

		_, err = out.Write(buf[:header.Size])
		if err != nil {
			return err
		}
	}
}

func repackCatchpoint(header CatchpointFileHeader, biggestChunkLen uint64, dataPath string, outPath string) error {
	// Initialize streams.
	fin, err := os.OpenFile(dataPath, os.O_RDONLY, 0666)
	if err != nil {
		return err
	}
	defer fin.Close()

	compressorIn, err := catchpointStage1Decoder(fin)
	if err != nil {
		return err
	}
	defer compressorIn.Close()

	tarIn := tar.NewReader(compressorIn)

	fout, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer fout.Close()

	gzipOut, err := gzip.NewWriterLevel(fout, gzip.BestSpeed)
	if err != nil {
		return err
	}
	defer gzipOut.Close()

	tarOut := tar.NewWriter(gzipOut)
	defer tarOut.Close()

	// Repack.
	err = doRepackCatchpoint(header, biggestChunkLen, tarIn, tarOut)
	if err != nil {
		return err
	}

	// Close streams.
	err = tarOut.Close()
	if err != nil {
		return err
	}

	err = gzipOut.Close()
	if err != nil {
		return err
	}

	err = fout.Close()
	if err != nil {
		return err
	}

	err = compressorIn.Close()
	if err != nil {
		return err
	}

	err = fin.Close()
	if err != nil {
		return err
	}

	return nil
}

// Create a catchpoint (a label and possibly a file with db record).
func (ct *catchpointTracker) createCatchpoint(accountsRound basics.Round, round basics.Round, dataInfo catchpointFirstStageInfo, blockHash crypto.Digest) error {
	startTime := time.Now()
	label := ledgercore.MakeCatchpointLabel(
		round, blockHash, dataInfo.TrieBalancesHash, dataInfo.Totals).String()

	ct.catchpointsMu.Lock()
	ct.lastCatchpointLabel = label
	ct.catchpointsMu.Unlock()

	_, err := ct.accountsq.writeCatchpointStateString(
		context.Background(), catchpointStateLastCatchpoint, label)
	if err != nil {
		return err
	}

	if !ct.enableGeneratingCatchpointFiles {
		return nil
	}

	catchpointDataFilePath := filepath.Join(ct.dbDirectory, CatchpointDirName)
	catchpointDataFilePath =
		filepath.Join(catchpointDataFilePath, makeCatchpointDataFilePath(accountsRound))

	// Check if the data file exists.
	_, err = os.Stat(catchpointDataFilePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	// Make a catchpoint file.
	header := CatchpointFileHeader{
		Version:           CatchpointFileVersionV6,
		BalancesRound:     accountsRound,
		BlocksRound:       round,
		Totals:            dataInfo.Totals,
		TotalAccounts:     dataInfo.TotalAccounts,
		TotalChunks:       dataInfo.TotalChunks,
		Catchpoint:        label,
		BlockHeaderDigest: blockHash,
	}

	relCatchpointFilePath :=
		filepath.Join(CatchpointDirName, makeCatchpointFilePath(round))
	absCatchpointFilePath := filepath.Join(ct.dbDirectory, relCatchpointFilePath)

	err = os.MkdirAll(filepath.Dir(absCatchpointFilePath), 0700)
	if err != nil {
		return err
	}

	err = repackCatchpoint(header, dataInfo.BiggestChunkLen, catchpointDataFilePath, absCatchpointFilePath)
	if err != nil {
		return err
	}

	fileInfo, err := os.Stat(absCatchpointFilePath)
	if err != nil {
		return err
	}

	err = ct.recordCatchpointFile(
		round, relCatchpointFilePath, fileInfo.Size())
	if err != nil {
		return err
	}

	ct.log.With("accountsRound", accountsRound).
		With("writingDuration", uint64(time.Since(startTime).Nanoseconds())).
		With("accountsCount", dataInfo.TotalAccounts).
		With("fileSize", fileInfo.Size()).
		With("catchpointLabel", label).
		Infof("Catchpoint file was created")

	return nil
}

// Calculate catchpoint round numbers in [min, max]. `catchpointInterval` must be
// non-zero.
func calculateCatchpointRounds(min basics.Round, max basics.Round, catchpointInterval uint64) []basics.Round {
	var res []basics.Round

	// The smallest integer i such that i * ct.catchpointInterval >= first.
	l := (uint64(min) + catchpointInterval - 1) / catchpointInterval
	// The largest integer i such that i * ct.catchpointInterval <= last.
	r := uint64(max) / catchpointInterval

	for i := l; i <= r; i++ {
		round := basics.Round(i * catchpointInterval)
		res = append(res, round)
	}

	return res
}

// Generate catchpoints (labels and possibly files with db records) for rounds in
// [first, last]. `blockHashes` must contain block digests for rounds [first, last].
// `ct.catchpointInterval` must be non-zero.
func (ct *catchpointTracker) createCatchpoints(first basics.Round, last basics.Round, blockHashes []crypto.Digest, catchpointLookback uint64) error {
	if catchpointLookback+1 > uint64(first) {
		first = basics.Round(catchpointLookback) + 1
	}
	rounds := calculateCatchpointRounds(first, last, ct.catchpointInterval)

	for _, round := range rounds {
		accountsRound := round - basics.Round(catchpointLookback)

		dataInfo, exists, err :=
			selectCatchpointFirstStageInfo(ct.dbs.Rdb.Handle, accountsRound)
		if err != nil {
			return err
		}

		if exists {
			err := ct.createCatchpoint(accountsRound, round, dataInfo, blockHashes[round-first])
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// Delete old first stage catchpoint records and data files.
func (ct *catchpointTracker) pruneFirstStageRecordsData(maxRoundToDelete basics.Round) error {
	rounds, err := selectOldCatchpointFirstStageInfoRounds(
		ct.dbs.Rdb.Handle, maxRoundToDelete)
	if err != nil {
		return err
	}

	for _, round := range rounds {
		catchpointDataFilePath := filepath.Join(ct.dbDirectory, CatchpointDirName)
		catchpointDataFilePath =
			filepath.Join(catchpointDataFilePath, makeCatchpointDataFilePath(round))

		err = os.Remove(catchpointDataFilePath)
		if (err != nil) && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return deleteOldCatchpointFirstStageInfo(ct.dbs.Rdb.Handle, maxRoundToDelete)
}

func (ct *catchpointTracker) postCommitUnlocked(ctx context.Context, dcc *deferredCommitContext) {
	if dcc.catchpointFirstStage {
		var totalAccounts, totalChunks, biggestChunkLen uint64

		if ct.enableGeneratingCatchpointFiles {
			// Generate the catchpoint file. This need to be done inline so that it will
			// block any new accounts that from being written. generateCatchpointData()
			// expects that the accounts data would not be modified in the background during
			// it's execution.
			var err error
			totalAccounts, totalChunks, biggestChunkLen, err = ct.generateCatchpointData(
				ctx, dcc.newBase, dcc.updatingBalancesDuration)
			atomic.StoreInt32(dcc.catchpointDataWriting, 0)
			if err != nil {
				ct.log.Warnf(
					"error creating a catchpoint data file dcc.newBase: %d err: %v",
					dcc.newBase, err)
			}
		}

		err := ct.recordFirstStageInfo(dcc.newBase, totalAccounts, totalChunks, biggestChunkLen)
		if err != nil {
			ct.log.Warnf(
				"error recording first stage catchpoint info dcc.newBase: %d err: %v",
				accountsRound, err)
		}
	}

	if ct.catchpointInterval != 0 {
		// Generate catchpoints for rounds in (dcc.oldBase, dcc.newBase].
		err := ct.createCatchpoints(
			dcc.oldBase+1, dcc.newBase, dcc.committedRoundDigests, dcc.catchpointLookback)
		if err != nil {
			ct.log.Warnf(
				"error creating catchpoints dcc.oldBase: %d dcc.newBase: %d err: %v",
				dcc.oldBase, dcc.newBase, err)
		}
	}

	// Prune first stage catchpoint records from the database.
	if uint64(dcc.newBase) >= dcc.catchpointLookback {
		err := ct.pruneFirstStageRecordsData(
			dcc.newBase - basics.Round(dcc.catchpointLookback))
		if err != nil {
			ct.log.Warnf(
				"error pruning first stage records and data dcc.newBase: %d err: %v",
				dcc.newBase, err)
		}
	}
}

// handleUnorderedCommit is a special method for handling deferred commits that are out of order.
// Tracker might update own state in this case. For example, account updates tracker cancels
// scheduled catchpoint writing that deferred commit.
func (ct *catchpointTracker) handleUnorderedCommit(dcc *deferredCommitContext) {
	// if the node is configured to generate catchpoint files, we might need to update the catchpointWriting variable.
	if ct.enableGeneratingCatchpointFiles {
		// determine if this was a catchpoint round
		if dcc.catchpointFirstStage {
			// it was a catchpoint round, so update the catchpointWriting to indicate that we're done.
			atomic.StoreInt32(&ct.catchpointDataWriting, 0)
		}
	}
}

// close terminates the tracker, reclaiming any resources
// like open database connections or goroutines.  close may
// be called even if loadFromDisk() is not called or does
// not succeed.
func (ct *catchpointTracker) close() {
}

// accountsUpdateBalances applies the given compactAccountDeltas to the merkle trie
func (ct *catchpointTracker) accountsUpdateBalances(accountsDeltas compactAccountDeltas, resourcesDeltas compactResourcesDeltas) (err error) {
	if !ct.catchpointEnabled() {
		return nil
	}
	var added, deleted bool
	accumulatedChanges := 0

	for i := 0; i < accountsDeltas.len(); i++ {
		delta := accountsDeltas.getByIdx(i)
		if !delta.oldAcct.accountData.IsEmpty() {
			deleteHash := accountHashBuilderV6(delta.address, &delta.oldAcct.accountData, protocol.Encode(&delta.oldAcct.accountData))
			deleted, err = ct.balancesTrie.Delete(deleteHash)
			if err != nil {
				return fmt.Errorf("failed to delete hash '%s' from merkle trie for account %v: %w", hex.EncodeToString(deleteHash), delta.address, err)
			}
			if !deleted {
				ct.log.Warnf("failed to delete hash '%s' from merkle trie for account %v", hex.EncodeToString(deleteHash), delta.address)
			} else {
				accumulatedChanges++
			}
		}

		if !delta.newAcct.IsEmpty() {
			addHash := accountHashBuilderV6(delta.address, &delta.newAcct, protocol.Encode(&delta.newAcct))
			added, err = ct.balancesTrie.Add(addHash)
			if err != nil {
				return fmt.Errorf("attempted to add duplicate hash '%s' to merkle trie for account %v: %w", hex.EncodeToString(addHash), delta.address, err)
			}
			if !added {
				ct.log.Warnf("attempted to add duplicate hash '%s' to merkle trie for account %v", hex.EncodeToString(addHash), delta.address)
			} else {
				accumulatedChanges++
			}
		}
	}

	for i := 0; i < resourcesDeltas.len(); i++ {
		resDelta := resourcesDeltas.getByIdx(i)
		addr := resDelta.address
		if !resDelta.oldResource.data.IsEmpty() {
			var ctype basics.CreatableType
			if resDelta.oldResource.data.IsAsset() {
				ctype = basics.AssetCreatable
			} else if resDelta.oldResource.data.IsApp() {
				ctype = basics.AppCreatable
			} else {
				return fmt.Errorf("unknown old creatable for addr %s (%d), aidx %d, data %v", addr.String(), resDelta.oldResource.addrid, resDelta.oldResource.aidx, resDelta.oldResource.data)
			}
			deleteHash := resourcesHashBuilderV6(addr, resDelta.oldResource.aidx, ctype, uint64(resDelta.oldResource.data.UpdateRound), protocol.Encode(&resDelta.oldResource.data))
			deleted, err = ct.balancesTrie.Delete(deleteHash)
			if err != nil {
				return fmt.Errorf("failed to delete resource hash '%s' from merkle trie for account %v: %w", hex.EncodeToString(deleteHash), addr, err)
			}
			if !deleted {
				ct.log.Warnf("failed to delete resource hash '%s' from merkle trie for account %v", hex.EncodeToString(deleteHash), addr)
			} else {
				accumulatedChanges++
			}
		}

		if !resDelta.newResource.IsEmpty() {
			var ctype basics.CreatableType
			if resDelta.newResource.IsAsset() {
				ctype = basics.AssetCreatable
			} else if resDelta.newResource.IsApp() {
				ctype = basics.AppCreatable
			} else {
				return fmt.Errorf("unknown new creatable for addr %s, aidx %d, data %v", addr.String(), resDelta.oldResource.aidx, resDelta.newResource)
			}
			addHash := resourcesHashBuilderV6(addr, resDelta.oldResource.aidx, ctype, uint64(resDelta.newResource.UpdateRound), protocol.Encode(&resDelta.newResource))
			added, err = ct.balancesTrie.Add(addHash)
			if err != nil {
				return fmt.Errorf("attempted to add duplicate resource hash '%s' to merkle trie for account %v: %w", hex.EncodeToString(addHash), addr, err)
			}
			if !added {
				ct.log.Warnf("attempted to add duplicate resource hash '%s' to merkle trie for account %v", hex.EncodeToString(addHash), addr)
			} else {
				accumulatedChanges++
			}
		}
	}

	if accumulatedChanges >= trieAccumulatedChangesFlush {
		accumulatedChanges = 0
		_, err = ct.balancesTrie.Commit()
		if err != nil {
			return
		}
	}

	// write it all to disk.
	if accumulatedChanges > 0 {
		_, err = ct.balancesTrie.Commit()
	}

	return
}

// IsWritingCatchpointDataFile returns true iff a (first stage) catchpoint data file
// is being generated.
func (ct *catchpointTracker) IsWritingCatchpointDataFile() bool {
	return atomic.LoadInt32(&ct.catchpointDataWriting) != 0
}

// Generates a (first stage) catchpoint data file.
func (ct *catchpointTracker) generateCatchpointData(ctx context.Context, accountsRound basics.Round, updatingBalancesDuration time.Duration) (uint64 /*totalAccounts*/, uint64 /*totalChunks*/, uint64 /*biggestChunkLen*/, error) {
	startTime := time.Now()
	catchpointGenerationStats := telemetryspec.CatchpointGenerationEventDetails{
		BalancesWriteTime: uint64(updatingBalancesDuration.Nanoseconds()),
	}

	// TODO: ensure catchpoint data generation is restarted after a crash.
	// the retryCatchpointCreation is used to repeat the catchpoint file generation in case the node crashed / aborted during startup
	// before the catchpoint file generation could be completed.
	//retryCatchpointCreation := false
	ct.log.Debugf("catchpointTracker.generateCatchpointData() writing catchpoint accounts for round %d", accountsRound)
	/*
		defer func() {
			if !retryCatchpointCreation {
				// clear the writingCatchpoint flag
				_, err := ct.accountsq.writeCatchpointStateUint64(context.Background(), catchpointStateWritingCatchpoint, uint64(0))
				if err != nil {
					ct.log.Warnf("catchpointTracker.generateCatchpointData() unable to clear catchpoint state '%s' for round %d: %v", catchpointStateWritingCatchpoint, accountsRound, err)
				}
			}
		}()

		_, err := ct.accountsq.writeCatchpointStateUint64(context.Background(), catchpointStateWritingCatchpoint, uint64(accountsRound))
		if err != nil {
			return 0, 0, err
		}
	*/

	catchpointDataFilePath := filepath.Join(ct.dbDirectory, CatchpointDirName)
	catchpointDataFilePath =
		filepath.Join(catchpointDataFilePath, makeCatchpointDataFilePath(accountsRound))

	more := true
	const shortChunkExecutionDuration = 50 * time.Millisecond
	const longChunkExecutionDuration = 1 * time.Second
	var chunkExecutionDuration time.Duration
	select {
	case <-ct.catchpointDataSlowWriting:
		chunkExecutionDuration = longChunkExecutionDuration
	default:
		chunkExecutionDuration = shortChunkExecutionDuration
	}

	var catchpointWriter *catchpointWriter
	start := time.Now()
	ledgerGeneratecatchpointCount.Inc(nil)
	err := ct.dbs.Rdb.Atomic(func(dbCtx context.Context, tx *sql.Tx) (err error) {
		catchpointWriter, err = makeCatchpointWriter(ctx, catchpointDataFilePath, tx)
		if err != nil {
			return
		}
		for more {
			stepCtx, stepCancelFunction := context.WithTimeout(ctx, chunkExecutionDuration)
			writeStepStartTime := time.Now()
			more, err = catchpointWriter.WriteStep(stepCtx)
			// accumulate the actual time we've spent writing in this step.
			catchpointGenerationStats.CPUTime += uint64(time.Since(writeStepStartTime).Nanoseconds())
			stepCancelFunction()
			if more && err == nil {
				// we just wrote some data, but there is more to be written.
				// go to sleep for while.
				// before going to sleep, extend the transaction timeout so that we won't get warnings:
				_, err0 := db.ResetTransactionWarnDeadline(dbCtx, tx, time.Now().Add(1*time.Second))
				if err0 != nil {
					ct.log.Warnf("catchpointTracker: generateCatchpoint: failed to reset transaction warn deadline : %v", err0)
				}
				select {
				case <-time.After(100 * time.Millisecond):
					// increase the time slot allocated for writing the catchpoint, but stop when we get to the longChunkExecutionDuration limit.
					// this would allow the catchpoint writing speed to ramp up while still leaving some cpu available.
					chunkExecutionDuration *= 2
					if chunkExecutionDuration > longChunkExecutionDuration {
						chunkExecutionDuration = longChunkExecutionDuration
					}
				case <-ctx.Done():
					//retryCatchpointCreation = true
					err2 := catchpointWriter.Abort()
					if err2 != nil {
						return fmt.Errorf("error removing catchpoint file : %v", err2)
					}
					return nil
				case <-ct.catchpointDataSlowWriting:
					chunkExecutionDuration = longChunkExecutionDuration
				}
			}
			if err != nil {
				err = fmt.Errorf(
					"unable to create catchpoint data file for round %d: %v",
					accountsRound, err)
				err2 := catchpointWriter.Abort()
				if err2 != nil {
					ct.log.Warnf("catchpointTracker.generateCatchpointData() error removing catchpoint file : %v", err2)
				}
				return
			}
		}
		return
	})
	ledgerGeneratecatchpointMicros.AddMicrosecondsSince(start, nil)
	if err != nil {
		ct.log.Warnf("catchpointTracker.generateCatchpointData() %v", err)
		return 0, 0, 0, err
	}

	catchpointGenerationStats.FileSize = uint64(catchpointWriter.GetSize())
	catchpointGenerationStats.WritingDuration = uint64(time.Since(startTime).Nanoseconds())
	catchpointGenerationStats.AccountsCount = catchpointWriter.GetTotalAccounts()
	ct.log.EventWithDetails(telemetryspec.Accounts, telemetryspec.CatchpointGenerationEvent, catchpointGenerationStats)
	ct.log.With("accountsRound", accountsRound).
		With("writingDuration", catchpointGenerationStats.WritingDuration).
		With("CPUTime", catchpointGenerationStats.CPUTime).
		With("balancesWriteTime", catchpointGenerationStats.BalancesWriteTime).
		With("accountsCount", catchpointGenerationStats.AccountsCount).
		With("fileSize", catchpointGenerationStats.FileSize).
		With("catchpointLabel", catchpointGenerationStats.CatchpointLabel).
		Infof("Catchpoint data file was generated")

	return catchpointWriter.GetTotalAccounts(), catchpointWriter.GetTotalChunks(), catchpointWriter.GetBiggestChunkLen(), nil
}

func (ct *catchpointTracker) recordFirstStageInfo(accountsRound basics.Round, totalAccounts, totalChunks, biggestChunkLen uint64) error {
	accountTotals, err := accountsTotals(ct.dbs.Rdb.Handle, false)
	if err != nil {
		return err
	}

	var trieBalancesHash crypto.Digest
	err = ct.dbs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		mc, err := MakeMerkleCommitter(tx, false)
		if err != nil {
			return err
		}

		var trie *merkletrie.Trie
		if ct.balancesTrie == nil {
			trie, err = merkletrie.MakeTrie(mc, TrieMemoryConfig)
			if err != nil {
				return err
			}
			ct.balancesTrie = trie
		} else {
			ct.balancesTrie.SetCommitter(mc)
		}

		trieBalancesHash, err = ct.balancesTrie.RootHash()
		return err
	})
	if err != nil {
		return err
	}

	info := catchpointFirstStageInfo{
		Totals:           accountTotals,
		TotalAccounts:    totalAccounts,
		TotalChunks:      totalChunks,
		BiggestChunkLen:  biggestChunkLen,
		TrieBalancesHash: trieBalancesHash,
	}
	return insertCatchpointFirstStageInfo(ct.dbs.Wdb.Handle, accountsRound, &info)
}

func makeCatchpointDataFilePath(accountsRound basics.Round) string {
	return strconv.FormatInt(int64(accountsRound), 10) + ".data"
}

func makeCatchpointFilePath(round basics.Round) string {
	irnd := int64(round) / 256
	outStr := ""
	for irnd > 0 {
		outStr = filepath.Join(outStr, fmt.Sprintf("%02x", irnd%256))
		irnd = irnd / 256
	}
	outStr = filepath.Join(outStr, strconv.FormatInt(int64(round), 10)+".catchpoint")
	return outStr
}

// recordCatchpointFile stores the provided fileName as the stored catchpoint for the given round.
// after a successful insert operation to the database, it would delete up to 2 old entries, as needed.
// deleting 2 entries while inserting single entry allow us to adjust the size of the backing storage and have the
// database and storage realign.
func (ct *catchpointTracker) recordCatchpointFile(round basics.Round, relCatchpointFilePath string, fileSize int64) (err error) {
	if ct.catchpointFileHistoryLength != 0 {
		err = ct.accountsq.storeCatchpoint(context.Background(), round, relCatchpointFilePath, "", fileSize)
		if err != nil {
			ct.log.Warnf("catchpointTracker.recordCatchpointFile() unable to save catchpoint: %v", err)
			return
		}
	} else {
		err = os.Remove(relCatchpointFilePath)
		if err != nil {
			ct.log.Warnf("catchpointTracker.recordCatchpointFile() unable to remove file (%s): %v", relCatchpointFilePath, err)
			return
		}
	}
	if ct.catchpointFileHistoryLength == -1 {
		return
	}
	var filesToDelete map[basics.Round]string
	filesToDelete, err = ct.accountsq.getOldestCatchpointFiles(context.Background(), 2, ct.catchpointFileHistoryLength)
	if err != nil {
		return fmt.Errorf("unable to delete catchpoint file, getOldestCatchpointFiles failed : %v", err)
	}
	for round, fileToDelete := range filesToDelete {
		err = removeSingleCatchpointFileFromDisk(ct.dbDirectory, fileToDelete)
		if err != nil {
			return err
		}
		err = ct.accountsq.storeCatchpoint(context.Background(), round, "", "", 0)
		if err != nil {
			return fmt.Errorf("unable to delete old catchpoint entry '%s' : %v", fileToDelete, err)
		}
	}
	return
}

// GetCatchpointStream returns a ReadCloseSizer to the catchpoint file associated with the provided round
func (ct *catchpointTracker) GetCatchpointStream(round basics.Round) (ReadCloseSizer, error) {
	dbFileName := ""
	fileSize := int64(0)
	start := time.Now()
	ledgerGetcatchpointCount.Inc(nil)
	err := ct.dbs.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		dbFileName, _, fileSize, err = getCatchpoint(tx, round)
		return
	})
	ledgerGetcatchpointMicros.AddMicrosecondsSince(start, nil)
	if err != nil && err != sql.ErrNoRows {
		// we had some sql error.
		return nil, fmt.Errorf("catchpointTracker.GetCatchpointStream() unable to lookup catchpoint %d: %v", round, err)
	}
	if dbFileName != "" {
		catchpointPath := filepath.Join(ct.dbDirectory, dbFileName)
		file, err := os.OpenFile(catchpointPath, os.O_RDONLY, 0666)
		if err == nil && file != nil {
			return &readCloseSizer{ReadCloser: file, size: fileSize}, nil
		}
		// else, see if this is a file-not-found error
		if os.IsNotExist(err) {
			// the database told us that we have this file.. but we couldn't find it.
			// delete it from the database.
			err := ct.recordCatchpointFile(round, "", 0)
			if err != nil {
				ct.log.Warnf("catchpointTracker.GetCatchpointStream() unable to delete missing catchpoint entry: %v", err)
				return nil, err
			}

			return nil, ledgercore.ErrNoEntry{}
		}
		// it's some other error.
		return nil, fmt.Errorf("catchpointTracker.GetCatchpointStream() unable to open catchpoint file '%s' %v", catchpointPath, err)
	}

	// if the database doesn't know about that round, see if we have that file anyway:
	relCatchpointFilePath :=
		filepath.Join(CatchpointDirName, makeCatchpointFilePath(round))
	absCatchpointFilePath := filepath.Join(ct.dbDirectory, relCatchpointFilePath)
	file, err := os.OpenFile(absCatchpointFilePath, os.O_RDONLY, 0666)
	if err == nil && file != nil {
		// great, if found that we should have had this in the database.. add this one now :
		fileInfo, err := file.Stat()
		if err != nil {
			// we couldn't get the stat, so just return with the file.
			return &readCloseSizer{ReadCloser: file, size: -1}, nil
		}

		err = ct.recordCatchpointFile(round, relCatchpointFilePath, fileInfo.Size())
		if err != nil {
			ct.log.Warnf("catchpointTracker.GetCatchpointStream() unable to save missing catchpoint entry: %v", err)
		}
		return &readCloseSizer{ReadCloser: file, size: fileInfo.Size()}, nil
	}
	return nil, ledgercore.ErrNoEntry{}
}

// deleteStoredCatchpoints iterates over the storedcatchpoints table and deletes all the files stored on disk.
// once all the files have been deleted, it would go ahead and remove the entries from the table.
func deleteStoredCatchpoints(ctx context.Context, dbQueries *accountsDbQueries, dbDirectory string) (err error) {
	catchpointsFilesChunkSize := 50
	for {
		fileNames, err := dbQueries.getOldestCatchpointFiles(ctx, catchpointsFilesChunkSize, 0)
		if err != nil {
			return err
		}
		if len(fileNames) == 0 {
			break
		}

		for round, fileName := range fileNames {
			err = removeSingleCatchpointFileFromDisk(dbDirectory, fileName)
			if err != nil {
				return err
			}
			// clear the entry from the database
			err = dbQueries.storeCatchpoint(ctx, round, "", "", 0)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// This function remove a single catchpoint file from the disk. this function does not leave empty directories
func removeSingleCatchpointFileFromDisk(dbDirectory, fileToDelete string) (err error) {
	absCatchpointFileName := filepath.Join(dbDirectory, fileToDelete)
	err = os.Remove(absCatchpointFileName)
	if err == nil || os.IsNotExist(err) {
		// it's ok if the file doesn't exist.
		err = nil
	} else {
		// we can't delete the file, abort -
		return fmt.Errorf("unable to delete old catchpoint file '%s' : %v", absCatchpointFileName, err)
	}
	splitedDirName := strings.Split(fileToDelete, string(os.PathSeparator))

	var subDirectoriesToScan []string
	//build a list of all the subdirs
	currentSubDir := ""
	for _, element := range splitedDirName {
		currentSubDir = filepath.Join(currentSubDir, element)
		subDirectoriesToScan = append(subDirectoriesToScan, currentSubDir)
	}

	// iterating over the list of directories. starting from the sub dirs and moving up.
	// skipping the file itself.
	for i := len(subDirectoriesToScan) - 2; i >= 0; i-- {
		absSubdir := filepath.Join(dbDirectory, subDirectoriesToScan[i])
		if _, err := os.Stat(absSubdir); os.IsNotExist(err) {
			continue
		}

		isEmpty, err := isDirEmpty(absSubdir)
		if err != nil {
			return fmt.Errorf("unable to read old catchpoint directory '%s' : %v", subDirectoriesToScan[i], err)
		}
		if isEmpty {
			err = os.Remove(absSubdir)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return fmt.Errorf("unable to delete old catchpoint directory '%s' : %v", subDirectoriesToScan[i], err)
			}
		}
	}

	return nil
}

// accountHashBuilderV6 calculates the hash key used for the trie by combining the account address and the account data
func accountHashBuilderV6(addr basics.Address, accountData *baseAccountData, encodedAccountData []byte) []byte {
	hash := make([]byte, 4+crypto.DigestSize)
	hashIntPrefix := accountData.UpdateRound
	if hashIntPrefix == 0 {
		hashIntPrefix = accountData.RewardsBase
	}
	// write out the lowest 32 bits of the reward base. This should improve the caching of the trie by allowing
	// recent updated to be in-cache, and "older" nodes will be left alone.
	for i, prefix := 3, hashIntPrefix; i >= 0; i, prefix = i-1, prefix>>8 {
		// the following takes the prefix & 255 -> hash[i]
		hash[i] = byte(prefix)
	}
	hash[4] = 0 // set the 5th byte to zero to indicate it's a account base record hash

	prehash := make([]byte, crypto.DigestSize+len(encodedAccountData))
	copy(prehash[:], addr[:])
	copy(prehash[crypto.DigestSize:], encodedAccountData[:])
	entryHash := crypto.Hash(prehash)
	copy(hash[5:], entryHash[1:])
	return hash[:]
}

// accountHashBuilderV6 calculates the hash key used for the trie by combining the account address and the account data
func resourcesHashBuilderV6(addr basics.Address, cidx basics.CreatableIndex, ctype basics.CreatableType, updateRound uint64, encodedResourceData []byte) []byte {
	hash := make([]byte, 4+crypto.DigestSize)
	// write out the lowest 32 bits of the reward base. This should improve the caching of the trie by allowing
	// recent updated to be in-cache, and "older" nodes will be left alone.
	for i, prefix := 3, updateRound; i >= 0; i, prefix = i-1, prefix>>8 {
		// the following takes the prefix & 255 -> hash[i]
		hash[i] = byte(prefix)
	}
	hash[4] = byte(ctype + 1) // set the 5th byte to one or two ( asset / application ) so we could differentiate the hashes.

	prehash := make([]byte, 8+crypto.DigestSize+len(encodedResourceData))
	copy(prehash[:], addr[:])
	binary.LittleEndian.PutUint64(prehash[crypto.DigestSize:], uint64(cidx))
	copy(prehash[crypto.DigestSize+8:], encodedResourceData[:])
	entryHash := crypto.Hash(prehash)
	copy(hash[5:], entryHash[1:])
	return hash[:]
}

// accountHashBuilder calculates the hash key used for the trie by combining the account address and the account data
func accountHashBuilder(addr basics.Address, accountData basics.AccountData, encodedAccountData []byte) []byte {
	hash := make([]byte, 4+crypto.DigestSize)
	// write out the lowest 32 bits of the reward base. This should improve the caching of the trie by allowing
	// recent updated to be in-cache, and "older" nodes will be left alone.
	for i, rewards := 3, accountData.RewardsBase; i >= 0; i, rewards = i-1, rewards>>8 {
		// the following takes the rewards & 255 -> hash[i]
		hash[i] = byte(rewards)
	}
	entryHash := crypto.Hash(append(addr[:], encodedAccountData[:]...))
	copy(hash[4:], entryHash[:])
	return hash[:]
}

func (ct *catchpointTracker) catchpointEnabled() bool {
	return ct.catchpointInterval != 0
}

// accountsInitializeHashes initializes account hashes.
// as part of the initialization, it tests if a hash table matches to account base and updates the former.
func (ct *catchpointTracker) accountsInitializeHashes(ctx context.Context, tx *sql.Tx, rnd basics.Round) error {
	hashRound, err := accountsHashRound(tx)
	if err != nil {
		return err
	}

	if hashRound != rnd {
		// if the hashed round is different then the base round, something was modified, and the accounts aren't in sync
		// with the hashes.
		err = resetAccountHashes(tx)
		if err != nil {
			return err
		}
		// if catchpoint is disabled on this node, we could complete the initialization right here.
		if !ct.catchpointEnabled() {
			return nil
		}
	}

	// create the merkle trie for the balances
	committer, err := MakeMerkleCommitter(tx, false)
	if err != nil {
		return fmt.Errorf("accountsInitialize was unable to makeMerkleCommitter: %v", err)
	}

	trie, err := merkletrie.MakeTrie(committer, TrieMemoryConfig)
	if err != nil {
		return fmt.Errorf("accountsInitialize was unable to MakeTrie: %v", err)
	}

	// we might have a database that was previously initialized, and now we're adding the balances trie. In that case, we need to add all the existing balances to this trie.
	// we can figure this out by examining the hash of the root:
	rootHash, err := trie.RootHash()
	if err != nil {
		return fmt.Errorf("accountsInitialize was unable to retrieve trie root hash: %v", err)
	}

	if rootHash.IsZero() {
		ct.log.Infof("accountsInitialize rebuilding merkle trie for round %d", rnd)
		accountBuilderIt := makeOrderedAccountsIter(tx, trieRebuildAccountChunkSize)
		defer accountBuilderIt.Close(ctx)
		startTrieBuildTime := time.Now()
		trieHashCount := 0
		lastRebuildTime := startTrieBuildTime
		pendingTrieHashes := 0
		totalOrderedAccounts := 0
		for {
			accts, processedRows, err := accountBuilderIt.Next(ctx)
			if err == sql.ErrNoRows {
				// the account builder would return sql.ErrNoRows when no more data is available.
				break
			} else if err != nil {
				return err
			}

			if len(accts) > 0 {
				trieHashCount += len(accts)
				pendingTrieHashes += len(accts)
				for _, acct := range accts {
					added, err := trie.Add(acct.digest)
					if err != nil {
						return fmt.Errorf("accountsInitialize was unable to add changes to trie: %v", err)
					}
					if !added {
						// we need to transalate the "addrid" into actual account address so that
						// we can report the failure.
						addr, err := lookupAccountAddressFromAddressID(ctx, tx, acct.addrid)
						if err != nil {
							ct.log.Warnf("accountsInitialize attempted to add duplicate hash '%s' to merkle trie for account id %d : %v", hex.EncodeToString(acct.digest), acct.addrid, err)
						} else {
							ct.log.Warnf("accountsInitialize attempted to add duplicate hash '%s' to merkle trie for account %v", hex.EncodeToString(acct.digest), addr)
						}
					}
				}

				if pendingTrieHashes >= trieRebuildCommitFrequency {
					// this trie Evict will commit using the current transaction.
					// if anything goes wrong, it will still get rolled back.
					_, err = trie.Evict(true)
					if err != nil {
						return fmt.Errorf("accountsInitialize was unable to commit changes to trie: %v", err)
					}
					pendingTrieHashes = 0
				}

				if time.Since(lastRebuildTime) > 5*time.Second {
					// let the user know that the trie is still being rebuilt.
					ct.log.Infof("accountsInitialize still building the trie, and processed so far %d trie entries", trieHashCount)
					lastRebuildTime = time.Now()
				}
			} else if processedRows > 0 {
				totalOrderedAccounts += processedRows
				// if it's not ordered, we can ignore it for now; we'll just increase the counters and emit logs periodically.
				if time.Since(lastRebuildTime) > 5*time.Second {
					// let the user know that the trie is still being rebuilt.
					ct.log.Infof("accountsInitialize still building the trie, and hashed so far %d accounts", totalOrderedAccounts)
					lastRebuildTime = time.Now()
				}
			}
		}

		// this trie Evict will commit using the current transaction.
		// if anything goes wrong, it will still get rolled back.
		_, err = trie.Evict(true)
		if err != nil {
			return fmt.Errorf("accountsInitialize was unable to commit changes to trie: %v", err)
		}

		// we've just updated the merkle trie, update the hashRound to reflect that.
		err = updateAccountsHashRound(tx, rnd)
		if err != nil {
			return fmt.Errorf("accountsInitialize was unable to update the account hash round to %d: %v", rnd, err)
		}

		ct.log.Infof("accountsInitialize rebuilt the merkle trie with %d entries in %v", trieHashCount, time.Since(startTrieBuildTime))
	}
	ct.balancesTrie = trie
	return nil
}
