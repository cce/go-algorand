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

package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/store/blockdb"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestMakeWindowJobs(t *testing.T) {
	partitiontest.PartitionTest(t)

	type want struct {
		lo, hi basics.Round
	}
	cases := []struct {
		name   string
		lo, hi basics.Round
		n      uint64
		want   []want
	}{
		// Empty range produced by parallelCopy when stageFirst consumed
		// the only source row. Must NOT panic from a uint64 underflow on
		// (hi-lo) being used as a slice capacity.
		{"empty (lo>hi)", 5, 4, 16, nil},
		{"empty (lo>hi, n=1)", 1, 0, 1, nil},

		// stageFirst path: lo == minR+1 is rarely N-aligned, so the
		// first chunk runs to the next N boundary minus 1, then
		// subsequent chunks are full N-round windows.
		{
			"misaligned start, n=16",
			1, 47, 16,
			[]want{{1, 15}, {16, 31}, {32, 47}},
		},
		{
			"misaligned start, partial tail, n=16",
			1, 40, 16,
			[]want{{1, 15}, {16, 31}, {32, 40}},
		},

		// Aligned start: first chunk is a full window.
		{
			"aligned start, n=16",
			16, 63, 16,
			[]want{{16, 31}, {32, 47}, {48, 63}},
		},

		// N=1 makes every round its own chunk; first chunk is one round
		// long regardless of alignment.
		{
			"n=1 produces one chunk per round",
			5, 7, 1,
			[]want{{5, 5}, {6, 6}, {7, 7}},
		},

		// Single-round range covers one job.
		{"single round, n=16", 10, 10, 16, []want{{10, 10}}},
		{"single round at boundary, n=16", 16, 16, 16, []want{{16, 16}}},

		// N=32 with misaligned start at round 5: first frame is 5..31.
		{
			"n=32 misaligned",
			5, 95, 32,
			[]want{{5, 31}, {32, 63}, {64, 95}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jobs := makeWindowJobs(tc.lo, tc.hi, tc.n)
			require.Equal(t, len(tc.want), len(jobs))
			for i, w := range tc.want {
				require.Equal(t, i, jobs[i].idx)
				require.Equal(t, w.lo, jobs[i].lo, "job %d lo", i)
				require.Equal(t, w.hi, jobs[i].hi, "job %d hi", i)
			}
		})
	}
}

// makeSourceDB writes a tiny uncompressed block DB with `nblocks` rows
// (rounds 0..nblocks-1) using random blocks. It returns the file path.
// The DB is closed before returning so the caller can reopen it
// read-only via compressblockdb's run().
func makeSourceDB(t *testing.T, dir string, nblocks int) string {
	t.Helper()
	path := filepath.Join(dir, "src.sqlite")
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?_journal_mode=wal", path))
	require.NoError(t, err)
	tx, err := db.Begin()
	require.NoError(t, err)
	require.NoError(t, blockdb.BlockInit(tx, nil, 0))
	require.NoError(t, tx.Commit())

	tx, err = db.Begin()
	require.NoError(t, err)
	store, err := blockdb.NewStore(tx, 0)
	require.NoError(t, err)

	for i := range nblocks {
		b := bookkeeping.Block{}
		b.BlockHeader.Round = basics.Round(i)
		b.BlockHeader.TimeStamp = int64(crypto.RandUint64())
		b.CurrentProtocol = protocol.ConsensusCurrentVersion
		cert := agreement.Certificate{Round: basics.Round(i)}
		require.NoError(t, store.BlockPut(tx, &b, &cert))
	}
	store.Close()
	require.NoError(t, tx.Commit())
	_, err = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	require.NoError(t, err)
	require.NoError(t, db.Close())
	return path
}

// allRows reads every (rnd, proto, hdrdata, blkdata, certdata, window_start)
// row from path, ordered by rnd. It is used to compare two destination DBs
// for bit-identical content without depending on SQLite's exact on-disk
// page layout.
type rowDump struct {
	rnd, windowStart   sql.NullInt64
	proto              string
	hdr, blkd, certd   []byte
}

func dumpRows(t *testing.T, path string) []rowDump {
	t.Helper()
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro", path))
	require.NoError(t, err)
	defer db.Close()
	rows, err := db.Query("SELECT rnd, proto, hdrdata, blkdata, certdata, window_start FROM blocks ORDER BY rnd")
	require.NoError(t, err)
	defer rows.Close()
	var out []rowDump
	for rows.Next() {
		var r rowDump
		require.NoError(t, rows.Scan(&r.rnd, &r.proto, &r.hdr, &r.blkd, &r.certd, &r.windowStart))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

// TestParallelCopyMatchesSingle drives run() at p=1 and p=4 against the
// same source DB and asserts the destination rows have byte-identical
// blkdata, certdata, hdrdata, proto, and window_start values for every
// rnd. That is the per-row byte-identity the read path actually consumes
// (BlockGet only sees the row columns, never the SQLite page layout);
// the on-disk file may still differ in page allocation order, free-list
// state, or other internal SQLite bookkeeping, and that is intentional.
//
// The alignment between the parallel windows and the single-threaded
// encoder's natural Reset boundaries is what makes the column blobs
// match; the test covers an N that does not divide nblocks evenly so
// the first and last windows are partial.
func TestParallelCopyMatchesSingle(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, n := range []uint64{1, 4, 16} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			dir := t.TempDir()
			src := makeSourceDB(t, dir, 50)
			dst1 := filepath.Join(dir, "p1.sqlite")
			dstP := filepath.Join(dir, "pN.sqlite")

			require.NoError(t, run(src, dst1, n, 8, 1, false))
			require.NoError(t, run(src, dstP, n, 8, 4, false))

			r1 := dumpRows(t, dst1)
			rP := dumpRows(t, dstP)
			require.Equal(t, r1, rP, "n=%d: parallel output differs from single-threaded", n)
		})
	}
}

// TestParallelCopyOneRow exercises the empty-job fast path through run()
// (not just makeWindowJobs): with a single-row source, stageFirst owns the
// only round and parallelCopy is invoked with lo > hi. The previous code
// would panic on a uint64 underflow when sizing the jobs slice; the
// current version short-circuits before allocating.
func TestParallelCopyOneRow(t *testing.T) {
	partitiontest.PartitionTest(t)
	dir := t.TempDir()
	src := makeSourceDB(t, dir, 1)
	dst := filepath.Join(dir, "p4.sqlite")
	require.NoError(t, run(src, dst, 16, 8, 4, false))
	require.Len(t, dumpRows(t, dst), 1)
}

// TestParallelCopyWorkerErrorJoins introduces a gap in the source DB (a
// round between minR and maxR that no longer exists) so a worker fails
// when it tries to read it. The test verifies that parallelCopy reports
// the original read error (not a downstream context.Canceled symptom of
// it) and returns without hanging — proving the lifecycle joins and the
// firstErrOnce error preference work on the error path.
func TestParallelCopyWorkerErrorJoins(t *testing.T) {
	partitiontest.PartitionTest(t)
	dir := t.TempDir()
	src := makeSourceDB(t, dir, 50)

	// Punch a hole at round 25. sourceRange uses MIN/MAX so it will
	// still see [0, 49]; the worker will hit ErrNoEntry on round 25.
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?_journal_mode=wal", src))
	require.NoError(t, err)
	_, err = db.Exec("DELETE FROM blocks WHERE rnd = 25")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	dst := filepath.Join(dir, "broken.sqlite")
	done := make(chan error, 1)
	go func() {
		done <- run(src, dst, 16, 8, 4, false)
	}()
	select {
	case err := <-done:
		require.Error(t, err)
		require.Contains(t, err.Error(), "round 25")
	case <-time.After(30 * time.Second):
		t.Fatal("parallelCopy hung after worker error (lifecycle join broken)")
	}
}
