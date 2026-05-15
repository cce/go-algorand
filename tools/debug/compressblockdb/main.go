// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

// compressblockdb reads an existing ledger.block.sqlite and writes a new
// copy whose blkdata/certdata columns are encoded with windowed-zstd
// compression at the given window size N. Useful for measuring the on-disk
// savings the compression produces on a real DB without modifying the
// original file.
//
// The source DB may itself be uncompressed, fully compressed, partially
// compressed, or contain rows from multiple historical window sizes:
// blockdb.BlockGetCert auto-detects the per-row format on read.
//
// Sources that do not start at round 0 are handled the same way catchpoint
// catchup seeds a fresh node: the lowest source round is staged through
// BlockStartCatchupStaging + BlockCompleteCatchup so the dest's blocks
// table starts populated, and the rest of the rounds are appended via
// BlockPut, which carries the streaming encoder state forward across
// rounds the way the production blockqueue syncer does.
package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/store/blockdb"
	"github.com/algorand/go-algorand/protocol"
)

var (
	batchSize   = flag.Int("batch", 10000, "Commit destination transaction every this many rounds")
	parallelism = flag.Int("p", 1, "Number of parallel encoder workers (1 = single-threaded; 0 = runtime.NumCPU())")
	resumeFlag  = flag.Bool("resume", false, "Resume an existing dst from MAX(rnd)+1 instead of refusing to overwrite. The dst's blocks table must already be populated; schema setup and the stageFirst seed are skipped, and a fresh zstd frame begins at the resume round.")
)

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: compressblockdb [flags] <src.sqlite> <dst.sqlite> <window>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Reads <src.sqlite> (an existing ledger.block.sqlite) and writes a new")
	fmt.Fprintln(os.Stderr, "copy to <dst.sqlite> whose rows are encoded with the windowed-zstd")
	fmt.Fprintln(os.Stderr, "compression at window size <window>. Use window=0 to write an uncompressed")
	fmt.Fprintln(os.Stderr, "copy and window=1 for an independent zstd frame per row. The source")
	fmt.Fprintln(os.Stderr, "may itself be raw, windowed, or mixed; the lowest stored round does")
	fmt.Fprintln(os.Stderr, "not have to be 0.")
	fmt.Fprintln(os.Stderr, "")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) != 3 {
		usage()
	}
	src, dst := args[0], args[1]
	n, err := strconv.ParseUint(args[2], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad window value %q: %v\n", args[2], err)
		os.Exit(1)
	}
	if !strings.HasSuffix(src, ".sqlite") || !strings.HasSuffix(dst, ".sqlite") {
		fmt.Fprintln(os.Stderr, "both filenames must end in .sqlite")
		os.Exit(1)
	}
	if !slices.Contains([]uint64{0, 1, 2, 4, 8, 16, 32}, n) {
		fmt.Fprintf(os.Stderr, "window %d is not a supported value (must be one of 0,1,2,4,8,16,32)\n", n)
		os.Exit(1)
	}
	if _, err := os.Stat(dst); err == nil {
		if !*resumeFlag {
			fmt.Fprintf(os.Stderr, "destination %s already exists; refusing to overwrite (pass -resume to continue from MAX(rnd)+1)\n", dst)
			os.Exit(1)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "stat %s: %v\n", dst, err)
		os.Exit(1)
	} else if *resumeFlag {
		fmt.Fprintf(os.Stderr, "destination %s does not exist; cannot resume\n", dst)
		os.Exit(1)
	}

	if *batchSize <= 0 {
		fmt.Fprintf(os.Stderr, "batch must be positive, got %d\n", *batchSize)
		os.Exit(1)
	}

	p := *parallelism
	if p < 0 {
		fmt.Fprintf(os.Stderr, "p must be >= 0, got %d\n", p)
		os.Exit(1)
	}
	if p == 0 {
		p = runtime.NumCPU()
	}

	if err := run(src, dst, n, *batchSize, p, *resumeFlag); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(srcPath, dstPath string, n uint64, batch, p int, resume bool) error {
	srcDB, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro&_journal_mode=wal", srcPath))
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer srcDB.Close()
	if perr := srcDB.Ping(); perr != nil {
		return fmt.Errorf("open source: %w", perr)
	}

	dstDB, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?_journal_mode=wal", dstPath))
	if err != nil {
		return fmt.Errorf("open dest: %w", err)
	}
	dstClosed := false
	defer func() {
		if !dstClosed {
			_ = dstDB.Close()
		}
	}()

	minR, maxR, err := sourceRange(srcDB)
	if err != nil {
		return err
	}
	nrounds := uint64(maxR-minR) + 1
	fmt.Printf("source %s: rounds %d..%d (%d rounds)\n", srcPath, minR, maxR, nrounds)
	fmt.Printf("dest   %s: window N=%d\n", dstPath, n)

	var (
		batchStart   basics.Round
		startWritten uint64
	)
	var dstMax basics.Round
	if resume {
		dstMax, err = destMax(dstDB)
		if err != nil {
			return fmt.Errorf("read dest max: %w", err)
		}
		if dstMax < minR {
			return fmt.Errorf("dest tip round %d is below source min %d; refusing to resume", dstMax, minR)
		}
		if dstMax > maxR {
			return fmt.Errorf("dest tip round %d exceeds source max %d; this is not a resume of the named source", dstMax, maxR)
		}
		batchStart = dstMax + 1
		startWritten = uint64(dstMax-minR) + 1
		if dstMax == maxR {
			fmt.Printf("resume: dest already at source max round %d; verifying tip and finalizing\n", dstMax)
		} else {
			fmt.Printf("resume: dest tip=%d, continuing from round %d (%d/%d already done)\n",
				dstMax, batchStart, startWritten, nrounds)
		}
	} else {
		if ierr := initDest(dstDB, n); ierr != nil {
			return ierr
		}
	}

	srcReader, err := openReader(srcDB)
	if err != nil {
		return fmt.Errorf("open src reader: %w", err)
	}

	dstStore, err := openStore(dstDB, n)
	if err != nil {
		return fmt.Errorf("open dst store: %w", err)
	}
	defer dstStore.Close()

	if resume {
		if verr := verifyResumeTip(srcDB, dstDB, dstMax, srcReader, dstStore); verr != nil {
			return verr
		}
	} else {
		if serr := stageFirst(srcDB, dstDB, minR, srcReader); serr != nil {
			return serr
		}
		batchStart = minR + 1
		startWritten = 1
	}

	start := time.Now()
	written := startWritten
	// Parallel mode only helps when there is per-row zstd work to spread
	// across cores: with n=0 the rows are raw msgp passthrough and a single
	// writer thread saturates the disk on its own.
	if p > 1 && n > 0 {
		w, perr := parallelCopy(srcDB, dstDB, srcReader, dstStore, batchStart, maxR, n, p, batch, start, nrounds, startWritten)
		if perr != nil {
			return perr
		}
		written += w
	} else {
		c := &copier{srcReader: srcReader, dstStore: dstStore, written: startWritten}
		for batchLo := batchStart; batchLo <= maxR; batchLo += basics.Round(batch) {
			batchHi := min(batchLo+basics.Round(batch)-1, maxR)
			if berr := c.copyBatch(srcDB, dstDB, batchLo, batchHi); berr != nil {
				return fmt.Errorf("batch [%d,%d]: %w", batchLo, batchHi, berr)
			}
			fmt.Printf("  %d/%d (%.1f%%) in %s\n",
				c.written, nrounds,
				float64(c.written)*100/float64(nrounds),
				time.Since(start).Round(time.Second),
			)
		}
		written = c.written
	}

	// Truncate the WAL and close the destination connection before
	// measuring file size so the dest file fully reflects committed pages
	// (otherwise recent commits can still be sitting in dst.sqlite-wal and
	// the reported ratio is misleadingly small).
	if _, cerr := dstDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); cerr != nil {
		return fmt.Errorf("checkpoint dest: %w", cerr)
	}
	if cerr := dstDB.Close(); cerr != nil {
		return fmt.Errorf("close dest: %w", cerr)
	}
	dstClosed = true

	srcSize, err := sqliteOnDiskSize(srcPath)
	if err != nil {
		return err
	}
	dstSize, err := sqliteOnDiskSize(dstPath)
	if err != nil {
		return err
	}
	fmt.Printf("done: %d rounds in %s\n", written, time.Since(start).Round(time.Second))
	fmt.Printf("  source file: %.2f MB\n", float64(srcSize)/(1<<20))
	fmt.Printf("  dest file:   %.2f MB (%.2f%% of source)\n",
		float64(dstSize)/(1<<20),
		float64(dstSize)*100/float64(srcSize))
	return nil
}

// openReader opens a Reader on a short read-only transaction; the Reader
// survives the rollback because NewReader captures schema detection without
// retaining the tx. The source side of the copy is read-only and never
// allocates writer state.
func openReader(db *sql.DB) (*blockdb.Reader, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	return blockdb.NewReader(tx)
}

// openStore opens a Store on a short read-only transaction; the Store
// survives the rollback because NewStore captures schema detection without
// retaining the tx. window is the compression window the Store's writer
// will encode at.
func openStore(db *sql.DB, window uint64) (*blockdb.Store, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	return blockdb.NewStore(tx, window)
}

// sqliteOnDiskSize sums the .sqlite file with any -wal / -shm sidecars so
// the reported size reflects everything the DB occupies on disk. A pre-WAL
// or already-checkpointed DB has the sidecars missing or empty; their
// absence is not an error.
func sqliteOnDiskSize(path string) (int64, error) {
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}

// sourceRange returns (min, max) of the rnd column. The two aggregates are
// queried separately on purpose: SQLite's min/max-via-index optimization
// only applies when MIN or MAX appears alone in the SELECT list. Combining
// them ("SELECT MIN(rnd), MAX(rnd) FROM blocks") forces a full table scan,
// which is fine on a small DB but catastrophic on multi-TB archival nodes.
func sourceRange(db *sql.DB) (basics.Round, basics.Round, error) {
	var minNull, maxNull sql.NullInt64
	if err := db.QueryRow("SELECT MIN(rnd) FROM blocks").Scan(&minNull); err != nil {
		return 0, 0, fmt.Errorf("query source min: %w", err)
	}
	if !minNull.Valid {
		return 0, 0, fmt.Errorf("source has no rows")
	}
	if err := db.QueryRow("SELECT MAX(rnd) FROM blocks").Scan(&maxNull); err != nil {
		return 0, 0, fmt.Errorf("query source max: %w", err)
	}
	return basics.Round(minNull.Int64), basics.Round(maxNull.Int64), nil
}

// destMax returns the highest round already present in the dest blocks
// table. Errors if the table is missing or empty, since both states are
// resume-incompatible: a missing table means the dst was never initialized,
// and an empty table can't be told apart from a single row at round 0 by
// MAX() alone (mainnet starts at round 0). The caller should restart from
// scratch in either case.
func destMax(db *sql.DB) (basics.Round, error) {
	var n sql.NullInt64
	if err := db.QueryRow("SELECT MAX(rnd) FROM blocks").Scan(&n); err != nil {
		return 0, err
	}
	if !n.Valid {
		return 0, fmt.Errorf("dest blocks table is empty")
	}
	return basics.Round(n.Int64), nil
}

func initDest(db *sql.DB, window uint64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if err := blockdb.BlockInit(tx, nil, window); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("init dest schema: %w", err)
	}
	return tx.Commit()
}

// stageFirst seeds the dest blocks table with the source's lowest stored
// round using the same BlockStartCatchupStaging + BlockCompleteCatchup pair
// the catchpoint catchup path uses for its first block. After this returns,
// dest's blocks table holds exactly the row at firstRound, and BlockPut can
// be used contiguously for every subsequent round.
//
// Staging writes the row verbatim (window_start = NULL); cross-row
// compression begins with the first BlockPut call.
func stageFirst(srcDB, dstDB *sql.DB, firstRound basics.Round, srcReader *blockdb.Reader) error {
	srcTx, err := srcDB.Begin()
	if err != nil {
		return err
	}
	blk, cert, err := srcReader.BlockGetCert(srcTx, firstRound)
	_ = srcTx.Rollback()
	if err != nil {
		return fmt.Errorf("read round %d: %w", firstRound, err)
	}

	dstTx, err := dstDB.Begin()
	if err != nil {
		return err
	}
	if err := blockdb.BlockStartCatchupStaging(dstTx, blk, cert); err != nil {
		_ = dstTx.Rollback()
		return fmt.Errorf("stage first round %d: %w", firstRound, err)
	}
	if err := blockdb.BlockCompleteCatchup(dstTx); err != nil {
		_ = dstTx.Rollback()
		return fmt.Errorf("complete catchup at round %d: %w", firstRound, err)
	}
	return dstTx.Commit()
}

// verifyResumeTip confirms the row already present in dst at tipRound holds
// the same cert as the source at the same round. This catches the realistic
// operator typo of resuming the wrong (src, dst) pair: without this check
// the tool would silently extend an unrelated DB and quietly contaminate a
// multi-day run. The cert is compared rather than the block because it is
// smaller and equally identity-bearing; both are logical (decoded) values
// so the comparison works across mixed compression formats.
func verifyResumeTip(srcDB, dstDB *sql.DB, tipRound basics.Round, srcReader *blockdb.Reader, dstStore *blockdb.Store) error {
	srcTx, err := srcDB.Begin()
	if err != nil {
		return err
	}
	_, srcCert, err := srcReader.BlockGetCert(srcTx, tipRound)
	_ = srcTx.Rollback()
	if err != nil {
		return fmt.Errorf("read src tip round %d: %w", tipRound, err)
	}

	dstTx, err := dstDB.Begin()
	if err != nil {
		return err
	}
	_, dstCert, err := dstStore.BlockGetCert(dstTx, tipRound)
	_ = dstTx.Rollback()
	if err != nil {
		return fmt.Errorf("read dst tip round %d: %w", tipRound, err)
	}

	if !bytes.Equal(protocol.Encode(&srcCert), protocol.Encode(&dstCert)) {
		return fmt.Errorf("tip round %d cert in dst does not match source; refusing to resume into a different chain", tipRound)
	}
	return nil
}

// copier carries cross-batch encoder state via dstStore. BlockPut on the
// dest preserves the writer's in-flight zstd frame across consecutive
// successful Put calls, so the LZ77 window spans every round in [firstRound+1, hi].
type copier struct {
	srcReader *blockdb.Reader
	dstStore  *blockdb.Store
	written   uint64
}

func (c *copier) copyBatch(srcDB, dstDB *sql.DB, lo, hi basics.Round) error {
	srcTx, err := srcDB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = srcTx.Rollback() }()

	dstTx, err := dstDB.Begin()
	if err != nil {
		return err
	}

	for r := lo; r <= hi; r++ {
		var (
			blk  bookkeeping.Block
			cert agreement.Certificate
		)
		blk, cert, err = c.srcReader.BlockGetCert(srcTx, r)
		if err != nil {
			_ = dstTx.Rollback()
			c.dstStore.Reset()
			return fmt.Errorf("read round %d: %w", r, err)
		}
		if err = c.dstStore.BlockPut(dstTx, &blk, &cert); err != nil {
			_ = dstTx.Rollback()
			c.dstStore.Reset()
			return fmt.Errorf("put round %d: %w", r, err)
		}
		c.written++
	}
	if err := dstTx.Commit(); err != nil {
		c.dstStore.Reset()
		return err
	}
	return nil
}

// windowJob is one unit of parallel work: a contiguous range of rounds that
// fits inside a single zstd frame (so the worker's encoder produces a
// self-contained chunk for it). idx is monotonic in dispatch order so the
// writer goroutine can reorder out-of-order completions.
type windowJob struct {
	idx    int
	lo, hi basics.Round
}

// encodedRow carries the bytes a single InsertEncodedAppend call needs. proto and
// hdrBlob are caller-extracted from the source block so the writer
// goroutine never has to touch a decoded Block.
type encodedRow struct {
	rnd      basics.Round
	proto    protocol.ConsensusVersion
	hdrBlob  []byte
	blkBlob  []byte
	certBlob []byte
	anchor   basics.Round
}

// windowResult is one completed windowJob, ready for in-order INSERT.
type windowResult struct {
	idx  int
	rows []encodedRow
}

// makeWindowJobs partitions [lo, hi] into chunks aligned to the natural
// zstd-frame boundaries the single-threaded encoder would Reset on, so the
// parallel output is bit-identical to the single-threaded output for the
// same source range. The first chunk extends from lo to the next
// N-aligned boundary (lo may not itself be N-aligned because stageFirst
// consumed one earlier round); every subsequent chunk is exactly N rounds.
// Returns nil when lo > hi (empty range, e.g. a one-row source).
func makeWindowJobs(lo, hi basics.Round, n uint64) []windowJob {
	if lo > hi {
		return nil
	}
	jobs := make([]windowJob, 0, (uint64(hi-lo)/n)+2)
	cur := lo
	for cur <= hi {
		nextBoundary := basics.Round((uint64(cur)/n + 1) * n)
		end := min(nextBoundary-1, hi)
		jobs = append(jobs, windowJob{idx: len(jobs), lo: cur, hi: end})
		cur = end + 1
	}
	return jobs
}

// parallelCopy runs the encode-and-insert pipeline with p workers feeding a
// single writer goroutine. Workers each hold their own *blockdb.Store
// (= their own zstd encoder) and read from the source via per-job
// transactions; a counting semaphore caps the number of jobs dispatched
// but not yet flushed so the writer-side reorder map and the workers'
// in-flight buffers all stay bounded under disk backpressure. The writer
// goroutine drains results, reorders by job index, and inserts rounds in
// ascending order to keep the dest b-tree append-only. parallelCopy
// joins every goroutine (workers, dispatcher, resCh closer) before
// returning, so the caller can immediately close DBs without races.
// Returns the count of rounds inserted in [lo, hi] (stageFirst owns lo-1).
//
// staged is the number of rounds the caller has already written to dest
// before parallelCopy started (typically the count returned by
// stageFirst); it is used only to offset the periodic progress print so
// the percentage matches the single-threaded code path.
func parallelCopy(
	srcDB, dstDB *sql.DB,
	srcReader *blockdb.Reader,
	dstStore *blockdb.Store,
	lo, hi basics.Round,
	n uint64,
	p, batch int,
	start time.Time,
	nrounds, staged uint64,
) (uint64, error) {
	jobs := makeWindowJobs(lo, hi, n)
	if len(jobs) == 0 {
		return 0, nil
	}

	// slots is the dispatched-but-not-yet-flushed counting semaphore.
	// The dispatcher MUST acquire one slot before sending a job; the
	// writer releases one slot after InsertEncodedAppend has inserted every row
	// of the corresponding window. This caps the total memory held in
	// (workers' in-progress encode) + (resCh) + (writer's pending map)
	// at roughly maxInFlight * N * (avg compressed row size) bytes.
	// resCh by itself is not sufficient: the writer drains resCh into an
	// unbounded pending map while it waits for the next in-order window,
	// so a slow early job would otherwise let later windows pile up in
	// memory.
	//
	// The hard cap at 64 keeps the worst-case in-flight memory bounded
	// even when p scales to many cores: at N=32 and ~1 MiB/row that is
	// on the order of 2 GiB, comfortably below any practical RAM limit
	// while still leaving each worker enough slack (~p*4) to absorb
	// per-job latency variance before throttling the dispatcher.
	maxInFlight := min(max(p*4, 4), 64)
	slots := make(chan struct{}, maxInFlight)

	jobCh := make(chan windowJob, p)
	resCh := make(chan windowResult, p)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// firstErr captures the earliest error from any goroutine. sync.Once
	// avoids the type-uniformity trap of atomic.Value, where storing two
	// different concrete error types (e.g. a worker's wrapped error and
	// the writer's ctx.Err()) would panic on the second CompareAndSwap.
	var (
		firstErrOnce sync.Once
		firstErr     error
	)
	reportErr := func(err error) {
		if err == nil {
			return
		}
		firstErrOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}

	var workerWg sync.WaitGroup
	for range p {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			reportErr(encoderWorker(ctx, srcDB, srcReader, dstDB, n, jobCh, resCh, slots))
		}()
	}

	var dispatcherWg sync.WaitGroup
	dispatcherWg.Add(1)
	go func() {
		defer dispatcherWg.Done()
		defer close(jobCh)
		for _, j := range jobs {
			// Acquire a slot first so the in-flight count is bounded
			// before any worker can pick the job up.
			select {
			case <-ctx.Done():
				return
			case slots <- struct{}{}:
			}
			select {
			case <-ctx.Done():
				// Return the slot we just took; nobody else will.
				<-slots
				return
			case jobCh <- j:
			}
		}
	}()

	// resCh closer: blocks until every worker has returned (either via
	// jobCh close on success, or via ctx cancellation on error), then
	// closes resCh so writerLoop can recognize end-of-stream.
	closerDone := make(chan struct{})
	go func() {
		defer close(closerDone)
		workerWg.Wait()
		close(resCh)
	}()

	written, werr := writerLoop(ctx, dstDB, dstStore, resCh, slots, len(jobs), batch, start, nrounds, staged)
	reportErr(werr) // cancels ctx via firstErrOnce iff err != nil

	// Join every background goroutine before returning. We must NOT call
	// cancel() here on the success path: at this point workers may still
	// be in their select between <-ctx.Done() and <-jobCh (with jobCh
	// already closed by the dispatcher). A late cancellation races those
	// workers — Go picks select cases uniformly when both are ready, so
	// roughly half the time a worker would pick the ctx.Done case and
	// return ctx.Err(), which firstErrOnce would then record as the run's
	// first error on an otherwise successful copy. reportErr above is the
	// only path that cancels; success drains naturally via the closed
	// jobCh. The deferred cancel() at the top still fires after these
	// Waits as a final cleanup.
	workerWg.Wait()
	dispatcherWg.Wait()
	<-closerDone

	return written, firstErr
}

// encoderWorker pulls windowJobs off jobCh, reads each round from the
// source via a per-job read transaction (short-lived so a long-running
// import does not pin a single source-WAL snapshot for hours), encodes
// blk+cert with its own per-worker zstd encoder, and ships the completed
// window to resCh. The encoder is Reset between jobs so each job stands
// alone (a fresh worker, or one that just finished an unrelated window,
// treats the job's first round as its frame anchor). srcDB connections
// come from sql.DB's pool and are not shared across workers.
//
// The slots semaphore is passed in so encoderWorker can release a slot
// for any job that has been dequeued but cannot complete (encode error,
// ctx cancellation between dequeue and successful send). Because every
// dispatched job is acquired with exactly one slot send, and every
// dequeued job is owned by exactly one worker, this release is a
// blocking <-slots: if it ever blocks, it points to an accounting bug
// upstream. Jobs that the dispatcher cancels before sending, or jobs
// still sitting in jobCh when cancellation begins, never reach a worker
// and naturally retain their slot until the slots channel is GC'd; the
// dispatcher's <-ctx.Done() path keeps it from ever blocking on
// slots <- struct{}{} for those.
func encoderWorker(
	ctx context.Context,
	srcDB *sql.DB,
	srcReader *blockdb.Reader,
	dstDB *sql.DB,
	n uint64,
	jobCh <-chan windowJob,
	resCh chan<- windowResult,
	slots <-chan struct{},
) error {
	// openStore against dstDB just to allocate a Writer at the right
	// codec; the schema-detection tx is short and rolled back.
	store, err := openStore(dstDB, n)
	if err != nil {
		return fmt.Errorf("open worker store: %w", err)
	}
	defer store.Close()

	for {
		var job windowJob
		var ok bool
		select {
		case <-ctx.Done():
			return ctx.Err()
		case job, ok = <-jobCh:
			if !ok {
				return nil
			}
		}

		res, perr := processJob(ctx, srcDB, srcReader, store, job)
		if perr != nil {
			// We dequeued this job, so a slot was acquired for it.
			// Block on release: if this ever blocks it means the
			// dispatcher's acquire and our release are out of sync.
			<-slots
			return perr
		}
		select {
		case <-ctx.Done():
			<-slots
			return ctx.Err()
		case resCh <- res:
		}
	}
}

// processJob does the per-job source read + encode work. It opens a
// short-lived source transaction, resets the encoder so the job's first
// round becomes a fresh frame anchor, encodes every round in the window,
// and returns the result.
func processJob(
	ctx context.Context,
	srcDB *sql.DB,
	srcReader *blockdb.Reader,
	store *blockdb.Store,
	job windowJob,
) (windowResult, error) {
	srcTx, err := srcDB.Begin()
	if err != nil {
		return windowResult{}, fmt.Errorf("begin src tx for window [%d,%d]: %w", job.lo, job.hi, err)
	}
	defer func() { _ = srcTx.Rollback() }()

	// Drop any in-flight frame state from the previous job so the next
	// job's first round becomes its own frame anchor.
	store.Reset()

	rows := make([]encodedRow, 0, job.hi-job.lo+1)
	for r := job.lo; r <= job.hi; r++ {
		// Honor cancellation between rows so a long window does not
		// keep a doomed worker alive past the first error.
		if cerr := ctx.Err(); cerr != nil {
			return windowResult{}, cerr
		}
		blk, cert, gerr := srcReader.BlockGetCert(srcTx, r)
		if gerr != nil {
			return windowResult{}, fmt.Errorf("read round %d: %w", r, gerr)
		}
		blkBlob, certBlob, anchor, eerr := store.EncodeBlockCert(&blk, &cert)
		if eerr != nil {
			return windowResult{}, fmt.Errorf("encode round %d: %w", r, eerr)
		}
		rows = append(rows, encodedRow{
			rnd:      r,
			proto:    blk.CurrentProtocol,
			hdrBlob:  protocol.Encode(&blk.BlockHeader),
			blkBlob:  blkBlob,
			certBlob: certBlob,
			anchor:   anchor,
		})
	}
	return windowResult{idx: job.idx, rows: rows}, nil
}

// writerLoop drains resCh, buffers out-of-order completions in a pending
// map, and INSERTs windows in strict idx order so dest stays append-only.
// It commits dstTx whenever an in-tx batch crosses the batch threshold,
// matching the single-threaded copier's commit cadence. Each flushed
// window releases one slot on the dispatcher semaphore as soon as its
// rows have been INSERTed into the current dstTx (the slot is not held
// until COMMIT — the slots channel bounds memory in flight, not durable
// progress). Returns the count of rounds inserted.
//
// When resCh closes before totalJobs windows have been flushed it means
// workers exited early; in that case ctx.Err() (if any) is the original
// cause and is preferred over the symptomatic "workers exited" message.
func writerLoop(
	ctx context.Context,
	dstDB *sql.DB,
	dstStore *blockdb.Store,
	resCh <-chan windowResult,
	slots <-chan struct{},
	totalJobs, batch int,
	start time.Time,
	nrounds, staged uint64,
) (uint64, error) {
	pending := make(map[int]windowResult)
	next := 0
	var written uint64
	insertedInTx := 0

	dstTx, err := dstDB.Begin()
	if err != nil {
		return 0, err
	}
	rollback := func() {
		if dstTx != nil {
			_ = dstTx.Rollback()
			dstTx = nil
		}
	}
	defer rollback()

	flush := func(r windowResult) error {
		for _, row := range r.rows {
			if perr := dstStore.InsertEncodedAppend(dstTx, row.rnd, row.proto, row.hdrBlob, row.blkBlob, row.certBlob, row.anchor); perr != nil {
				return fmt.Errorf("InsertEncodedAppend round %d: %w", row.rnd, perr)
			}
			insertedInTx++
			written++
		}
		// Release the dispatcher's slot for this window now that every
		// row has been INSERTed. The receive is guaranteed not to block:
		// every job in resCh was dispatched with exactly one acquire, so
		// there is always a slot to release when we flush it.
		<-slots
		return nil
	}

	for next < totalJobs {
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		case r, ok := <-resCh:
			if !ok {
				if cerr := ctx.Err(); cerr != nil {
					return written, cerr
				}
				return written, fmt.Errorf("workers exited before completing all jobs (next=%d/%d)", next, totalJobs)
			}
			pending[r.idx] = r
		}
		// Drain consecutive in-order completions.
		for {
			r, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			if ferr := flush(r); ferr != nil {
				return written, ferr
			}
			next++
			if insertedInTx >= batch {
				if cerr := dstTx.Commit(); cerr != nil {
					dstTx = nil
					return written, fmt.Errorf("commit: %w", cerr)
				}
				dstTx, err = dstDB.Begin()
				if err != nil {
					return written, fmt.Errorf("begin: %w", err)
				}
				insertedInTx = 0
				fmt.Printf("  %d/%d (%.1f%%) in %s\n",
					written+staged, nrounds,
					float64(written+staged)*100/float64(nrounds),
					time.Since(start).Round(time.Second),
				)
			}
		}
	}
	// Final partial-batch commit.
	if insertedInTx > 0 {
		if cerr := dstTx.Commit(); cerr != nil {
			dstTx = nil
			return written, fmt.Errorf("final commit: %w", cerr)
		}
		dstTx = nil
	}
	return written, nil
}
