// Copyright (C) 2019-2021 Algorand, Inc.
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
	"database/sql"
	"fmt"
	"strings"

	"github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// 2019-12-15: removed column 'auxdata blob' from 'CREATE TABLE' statement. It was not explicitly removed from databases and may continue to exist with empty entries in some old databases.
var blockSchema = []string{
	`CREATE TABLE IF NOT EXISTS blocks (
		rnd integer primary key,
		proto text,
		hdrdata blob,
		blkdata blob,
		certdata blob)`,
}

var blockResetExprs = []string{
	`DROP TABLE IF EXISTS blocks`,
}

func blockInit(kvRead kvRead, kvWrite kvWrite, initBlocks []bookkeeping.Block) error {
	next, err := blockNext(kvRead)
	if err != nil {
		return err
	}

	if next == 0 {
		curRound := sql.NullInt64{}
		for _, blk := range initBlocks {
			curRound, err = blockPut(kvRead, kvWrite, blk, agreement.Certificate{}, curRound)
			if err != nil {
				serr, ok := err.(sqlite3.Error)
				if ok && serr.Code == sqlite3.ErrConstraint {
					continue
				}
				return err
			}
		}
	}

	return nil
}

func blockResetDB(kv kvWrite) error {
	kvBlockReset(kv)
	return nil
}

func blockGet(kv kvRead, rnd basics.Round) (blk bookkeeping.Block, err error) {
	var buf []byte
	//err = tx.QueryRow("SELECT blkdata FROM blocks WHERE rnd=?", rnd).Scan(&buf)
	buf, _, err = kvBlockGet(kv, rnd)
	if err != nil {
		if err == sql.ErrNoRows {
			err = ledgercore.ErrNoEntry{Round: rnd}
		}

		return
	}

	err = protocol.Decode(buf, &blk)
	return
}

func blockGetHdr(kv kvRead, rnd basics.Round) (hdr bookkeeping.BlockHeader, err error) {
	var buf []byte
	//err = tx.QueryRow("SELECT hdrdata FROM blocks WHERE rnd=?", rnd).Scan(&buf)
	buf, err = kvBlockHeaderGet(kv, rnd)
	if err != nil {
		if err == sql.ErrNoRows {
			err = ledgercore.ErrNoEntry{Round: rnd}
		}

		return
	}

	err = protocol.Decode(buf, &hdr)
	return
}

func blockGetEncodedCert(kv kvRead, rnd basics.Round) (blk []byte, cert []byte, err error) {
	//err = tx.QueryRow("SELECT blkdata, certdata FROM blocks WHERE rnd=?", rnd).Scan(&blk, &cert)
	blk, cert, err = kvBlockGet(kv, rnd)
	if err != nil {
		if err == sql.ErrNoRows {
			err = ledgercore.ErrNoEntry{Round: rnd}
		}

		return
	}
	return
}

func blockGetCert(kv kvRead, rnd basics.Round) (blk bookkeeping.Block, cert agreement.Certificate, err error) {
	blkbuf, certbuf, err := blockGetEncodedCert(kv, rnd)
	if err != nil {
		return
	}
	err = protocol.Decode(blkbuf, &blk)
	if err != nil {
		return
	}

	if certbuf != nil {
		err = protocol.Decode(certbuf, &cert)
		if err != nil {
			return
		}
	}

	return
}

func blockPut(kvR kvRead, kvW kvWrite, blk bookkeeping.Block, cert agreement.Certificate, curRound sql.NullInt64) (sql.NullInt64, error) {
	var max sql.NullInt64
	var err error
	if !curRound.Valid {
		//err := tx.QueryRow("SELECT MAX(rnd) FROM blocks").Scan(&max)
		max, err = kvBlockMaxRound(kvR)
		if err != nil {
			return sql.NullInt64{}, err
		}
	} else {
		max = curRound
	}

	if max.Valid {
		if blk.Round() != basics.Round(max.Int64+1) {
			err = fmt.Errorf("inserting block %d but expected %d", blk.Round(), max.Int64+1)
			return sql.NullInt64{}, err
		}
	} else {
		if blk.Round() != 0 {
			err = fmt.Errorf("inserting block %d but expected 0", blk.Round())
			return sql.NullInt64{}, err
		}
	}

	// _, err = tx.Exec("INSERT INTO blocks (rnd, proto, hdrdata, blkdata, certdata) VALUES (?, ?, ?, ?, ?)",
	err = kvBlockInsert(kvW,
		blk.Round(),
		blk.CurrentProtocol,
		protocol.Encode(&blk.BlockHeader),
		protocol.Encode(&blk),
		protocol.Encode(&cert),
	)
	return sql.NullInt64{Int64: int64(blk.Round()), Valid: true}, err
}

func blockNext(kv kvRead) (basics.Round, error) {
	// var max sql.NullInt64
	// err := tx.QueryRow("SELECT MAX(rnd) FROM blocks").Scan(&max)
	max, err := kvBlockMaxRound(kv)
	if err != nil {
		return 0, err
	}

	if max.Valid {
		return basics.Round(max.Int64 + 1), nil
	}

	return 0, nil
}

func blockLatest(kv kvRead) (basics.Round, error) {
	// var max sql.NullInt64
	// err := tx.QueryRow("SELECT MAX(rnd) FROM blocks").Scan(&max)
	max, err := kvBlockMaxRound(kv)
	if err != nil {
		return 0, err
	}

	if max.Valid {
		return basics.Round(max.Int64), nil
	}

	return 0, fmt.Errorf("no blocks present")
}

func blockEarliest(kv kvRead) (basics.Round, error) {
	// var min sql.NullInt64
	// err := tx.QueryRow("SELECT MIN(rnd) FROM blocks").Scan(&min)
	min, err := kvBlockMinRound(kv)
	if err != nil {
		return 0, err
	}

	if min.Valid {
		return basics.Round(min.Int64), nil
	}

	return 0, fmt.Errorf("no blocks present")
}

func blockForgetBefore(kvR kvRead, kvW kvWrite, rnd basics.Round) error {
	next, err := blockNext(kvR)
	if err != nil {
		return err
	}

	if rnd >= next {
		return fmt.Errorf("forgetting too much: rnd %d >= next %d", rnd, next)
	}

	//_, err = tx.Exec("DELETE FROM blocks WHERE rnd<?", rnd)
	err = kvBlockDeleteBefore(kvW, rnd)
	return err
}

func blockStartCatchupStaging(tx *sql.Tx, blk bookkeeping.Block) error {
	// delete the old catchpointblocks table, if there is such.
	for _, stmt := range blockResetExprs {
		stmt = strings.Replace(stmt, "blocks", "catchpointblocks", 1)
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}

	// create the catchpointblocks table
	for _, stmt := range blockSchema {
		stmt = strings.Replace(stmt, "blocks", "catchpointblocks", 1)
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}

	// insert the top entry to the blocks table.
	_, err := tx.Exec("INSERT INTO catchpointblocks (rnd, proto, hdrdata, blkdata) VALUES (?, ?, ?, ?)",
		blk.Round(),
		blk.CurrentProtocol,
		protocol.Encode(&blk.BlockHeader),
		protocol.Encode(&blk),
	)
	if err != nil {
		return err
	}
	return nil
}

func blockCompleteCatchup(tx *sql.Tx) (err error) {
	_, err = tx.Exec("ALTER TABLE blocks RENAME TO blocks_old")
	if err != nil {
		return err
	}
	_, err = tx.Exec("ALTER TABLE catchpointblocks RENAME TO blocks")
	if err != nil {
		return err
	}
	_, err = tx.Exec("DROP TABLE IF EXISTS blocks_old")
	if err != nil {
		return err
	}
	return nil
}

// TODO: unused, either actually implement cleanup on catchpoint failure, or delete this
func blockAbortCatchup(tx *sql.Tx) error {
	// delete the old catchpointblocks table, if there is such.
	for _, stmt := range blockResetExprs {
		stmt = strings.Replace(stmt, "blocks", "catchpointblocks", 1)
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}
	return nil
}

func blockPutStaging(tx *sql.Tx, blk bookkeeping.Block) (err error) {
	// insert the new entry
	_, err = tx.Exec("INSERT INTO catchpointblocks (rnd, proto, hdrdata, blkdata) VALUES (?, ?, ?, ?)",
		blk.Round(),
		blk.CurrentProtocol,
		protocol.Encode(&blk.BlockHeader),
		protocol.Encode(&blk),
	)
	if err != nil {
		return err
	}
	return nil
}

func blockEnsureSingleBlock(tx *sql.Tx) (blk bookkeeping.Block, err error) {
	// delete all the blocks that aren't the latest one.
	var max sql.NullInt64
	err = tx.QueryRow("SELECT MAX(rnd) FROM catchpointblocks").Scan(&max)
	if err != nil {
		if err == sql.ErrNoRows {
			err = ledgercore.ErrNoEntry{}
		}
		return bookkeeping.Block{}, err
	}
	if !max.Valid {
		return bookkeeping.Block{}, ledgercore.ErrNoEntry{}
	}
	round := basics.Round(max.Int64)

	_, err = tx.Exec("DELETE FROM catchpointblocks WHERE rnd<?", round)

	if err != nil {
		return bookkeeping.Block{}, err
	}

	var buf []byte
	err = tx.QueryRow("SELECT blkdata FROM catchpointblocks WHERE rnd=?", round).Scan(&buf)
	if err != nil {
		if err == sql.ErrNoRows {
			err = ledgercore.ErrNoEntry{Round: round}
		}
		return
	}

	err = protocol.Decode(buf, &blk)

	return blk, err
}
