package ledger

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/kvstore"
)

const (
	kvPrefixBlocks         = "\x00\x00\x01\x01"
	kvPrefixBlocksEndRange = "\x00\x00\x01\x02"

	kvPrefixBlockHeaders         = "\x00\x00\x01\x02"
	kvPrefixBlockHeadersEndRange = "\x00\x00\x01\x03"
)

// kvBlocksKey: 4-byte prefix + 8-byte big-endian round number
func kvBlocksKey(round basics.Round) []byte {
	ret := []byte(kvPrefixBlocks)
	ret = append(ret, bigEndianUint64(uint64(round))...)
	return ret
}

// kvBlockHeadersKey: 4-byte prefix + 8-byte big-endian round number
func kvBlockHeadersKey(round basics.Round) []byte {
	ret := []byte(kvPrefixBlockHeaders)
	ret = append(ret, bigEndianUint64(uint64(round))...)
	return ret
}

func splitBlockKey(key []byte) (round uint64, err error) {
	if len(key) != 12 {
		err = fmt.Errorf("block DB key not correct length")
		return
	}
	round = binary.BigEndian.Uint64(key[4:12])
	return
}

type kvBlockValue struct {
	_struct struct{}                  `codec:",omitempty,omitemptyarray"`
	Proto   protocol.ConsensusVersion `codec:"p"`
	Block   []byte                    `codec:"b"`
	Cert    []byte                    `codec:"c"`
}

type kvBlockHeaderValue struct {
	_struct struct{}                  `codec:",omitempty,omitemptyarray"`
	Proto   protocol.ConsensusVersion `codec:"p"`
	Header  []byte                    `codec:"h"`
}

func kvBlockMaxRound(kv kvRead) (sql.NullInt64, error) { return kvBlockFirstRound(kv, true) }  // reverse iterate over round numbers
func kvBlockMinRound(kv kvRead) (sql.NullInt64, error) { return kvBlockFirstRound(kv, false) } // forward iterate over round numbers

func kvBlockFirstRound(kv kvRead, reverse bool) (sql.NullInt64, error) {
	iter := kv.NewIterator([]byte(kvPrefixBlocks), []byte(kvPrefixBlocksEndRange), reverse)
	if !iter.Valid() {
		return sql.NullInt64{}, nil
	}
	rnd, err := splitBlockKey(iter.Key())
	if err != nil {
		return sql.NullInt64{}, err
	}
	return sql.NullInt64{Int64: int64(rnd), Valid: true}, nil
}

func kvBlockInsert(kv kvWrite, rnd basics.Round, proto protocol.ConsensusVersion, hdr, block, cert []byte) error {
	kvb := kvBlockValue{Proto: proto, Block: block, Cert: cert}
	kvh := kvBlockHeaderValue{Proto: proto, Header: hdr}
	err := kv.Set(kvBlocksKey(rnd), protocol.Encode(&kvb))
	if err != nil {
		return err
	}
	err = kv.Set(kvBlockHeadersKey(rnd), protocol.Encode(&kvh))
	if err != nil {
		return err
	}
	return nil
}

func kvBlockDeleteBefore(kv kvWrite, rnd basics.Round) error {
	err := kv.DeleteRange([]byte(kvPrefixBlocks), kvBlocksKey(rnd))
	if err != nil {
		return err
	}
	return kv.DeleteRange([]byte(kvPrefixBlockHeaders), kvBlockHeadersKey(rnd))
}

func kvBlockReset(kv kvWrite) error {
	err := kv.DeleteRange([]byte(kvPrefixBlocks), []byte(kvPrefixBlocksEndRange))
	if err != nil {
		return err
	}
	return kv.DeleteRange([]byte(kvPrefixBlockHeaders), []byte(kvPrefixBlockHeadersEndRange))
}

func kvBlockGet(kv kvRead, rnd basics.Round) (blk []byte, cert []byte, err error) {
	var val []byte
	val, err = kv.Get(kvBlocksKey(rnd))
	if err != nil {
		if errors.Is(err, kvstore.ErrKeyNotFound) {
			err = sql.ErrNoRows
			return nil, nil, err
		}
		return nil, nil, err
	}
	kvb := kvBlockValue{}
	err = protocol.Decode(val, &kvb)
	if err != nil {
		return nil, nil, err
	}
	return kvb.Block, kvb.Cert, nil
}

func kvBlockHeaderGet(kv kvRead, rnd basics.Round) (hdr []byte, err error) {
	var val []byte
	val, err = kv.Get(kvBlockHeadersKey(rnd))
	if err != nil {
		if errors.Is(err, kvstore.ErrKeyNotFound) {
			err = sql.ErrNoRows
			return nil, err
		}
		return nil, err
	}
	kvh := kvBlockHeaderValue{}
	err = protocol.Decode(val, &kvh)
	if err != nil {
		return nil, err
	}
	return kvh.Header, nil
}
