// Copyright (C) 2019-2024 Algorand, Inc.
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

package sqlitedriver

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/encoded"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

type kvsIter struct {
	q    db.Queryable
	rows *sql.Rows
}

// MakeKVsIter creates a KV iterator.
func MakeKVsIter(ctx context.Context, q db.Queryable) (*kvsIter, error) {
	rows, err := q.QueryContext(ctx, "SELECT key, value FROM kvstore")
	if err != nil {
		return nil, err
	}

	return &kvsIter{
		q:    q,
		rows: rows,
	}, nil
}

func (iter *kvsIter) Next() bool {
	return iter.rows.Next()
}

func (iter *kvsIter) KeyValue() (k []byte, v []byte, err error) {
	err = iter.rows.Scan(&k, &v)
	return k, v, err
}

func (iter *kvsIter) Close() {
	iter.rows.Close()
}

type onlineAccountsIter struct {
	q    db.Queryable
	rows *sql.Rows
}

// MakeOnlineAccountsIter creates an onlineAccounts iterator.
func MakeOnlineAccountsIter(ctx context.Context, q db.Queryable) (*onlineAccountsIter, error) {
	rows, err := q.QueryContext(ctx, "SELECT address, updround, normalizedonlinebalance, votelastvalid, data FROM onlineaccounts")
	if err != nil {
		return nil, err
	}

	return &onlineAccountsIter{q: q, rows: rows}, nil
}

func (iter *onlineAccountsIter) Next() bool { return iter.rows.Next() }
func (iter *onlineAccountsIter) Close()     { iter.rows.Close() }

func (iter *onlineAccountsIter) OnlineAccount() (*encoded.OnlineAccountRecordV6, error) {
	var ret encoded.OnlineAccountRecordV6
	var updRound, normBal, lastValid sql.NullInt64
	var addr, data []byte

	err := iter.rows.Scan(&addr, &updRound, &normBal, &lastValid, &data)
	if err != nil {
		return nil, err
	}
	if len(addr) != len(ret.Address) {
		err = fmt.Errorf("onlineaccounts DB address length mismatch: %d != %d", len(addr), len(ret.Address))
		return nil, err
	}
	copy(ret.Address[:], addr)

	if !updRound.Valid || updRound.Int64 < 0 {
		return nil, fmt.Errorf("invalid updateRound (%v) for online account %s", updRound, ret.Address.String())
	}
	ret.UpdateRound = basics.Round(updRound.Int64)

	if !normBal.Valid || normBal.Int64 < 0 {
		return nil, fmt.Errorf("invalid norm balance (%v) for online account %s", normBal, ret.Address.String())
	}
	ret.NormalizedOnlineBalance = uint64(normBal.Int64)

	if !lastValid.Valid || lastValid.Int64 < 0 {
		return nil, fmt.Errorf("invalid lastValid (%v) for online account %s", lastValid, ret.Address)
	}
	ret.VoteLastValid = basics.Round(lastValid.Int64)

	var oaData trackerdb.BaseOnlineAccountData
	err = protocol.Decode(data, &oaData)
	if err != nil {
		return nil, fmt.Errorf("encoding error for online account %s: %v", ret.Address, err)
	}

	// check consistency of the decoded data against row data
	// skip checking NormalizedOnlineBalance, requires proto
	if ret.VoteLastValid != oaData.VoteLastValid {
		return nil, fmt.Errorf("decoded voteLastValid %d does not match row voteLastValid %d", oaData.VoteLastValid, ret.VoteLastValid)
	}

	// return original encoded column value
	ret.Data = data

	return &ret, nil
}

type onlineRoundParamsIter struct {
	q    db.Queryable
	rows *sql.Rows
}

// MakeOnlineRoundParamsIter creates an onlineRoundParams iterator.
func MakeOnlineRoundParamsIter(ctx context.Context, q db.Queryable) (*onlineRoundParamsIter, error) {
	rows, err := q.QueryContext(ctx, "SELECT rnd, data FROM onlineroundparamstail")
	if err != nil {
		return nil, err
	}

	return &onlineRoundParamsIter{q: q, rows: rows}, nil
}

func (iter *onlineRoundParamsIter) Next() bool { return iter.rows.Next() }
func (iter *onlineRoundParamsIter) Close()     { iter.rows.Close() }

func (iter *onlineRoundParamsIter) OnlineRoundParams() (*encoded.OnlineRoundParamsRecordV6, error) {
	var ret encoded.OnlineRoundParamsRecordV6
	var rnd sql.NullInt64
	var data []byte

	err := iter.rows.Scan(&rnd, &data)
	if err != nil {
		return nil, err
	}

	if !rnd.Valid || rnd.Int64 < 0 {
		return nil, fmt.Errorf("invalid round (%v) for online round params", rnd)
	}
	ret.Round = basics.Round(rnd.Int64)

	// test decode
	var orpData ledgercore.OnlineRoundParamsData
	err = protocol.Decode(data, &orpData)
	if err != nil {
		return nil, fmt.Errorf("encoding error for online round params round %v: %v", ret.Round, err)
	}

	// return original encoded column value
	ret.Data = data

	return &ret, nil
}
