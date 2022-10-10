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
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

var boxAppSource = main(`
		txn ApplicationArgs 0
        byte "create"			// create box named arg[1]
        ==
		txn ApplicationArgs 0
		byte "recreate"
		==
		||
        bz del
		txn ApplicationArgs 1
		int 24
        txn NumAppArgs
        int 2
        ==
        bnz default
        pop						// get rid of 24
        txn ApplicationArgs 2
        btoi
     default:
		txn ApplicationArgs 0
		byte "recreate"
		==
		bz first
		box_create
		!
		assert
		b end
	 first:
	    box_create
        assert
        b end
     del:						// delete box arg[1]
		txn ApplicationArgs 0
        byte "delete"
        ==
        bz set
		txn ApplicationArgs 1
		box_del
        assert
        b end
     set:						// put arg[1] at start of box arg[0]
		txn ApplicationArgs 0
        byte "set"
        ==
        bz test
		txn ApplicationArgs 1
        int 0
		txn ApplicationArgs 2
		box_replace
        b end
     test:						// fail unless arg[2] is the prefix of box arg[1]
		txn ApplicationArgs 0
        byte "check"
        ==
        bz bad
		txn ApplicationArgs 1
        int 0
		txn ApplicationArgs 2
        len
		box_extract
		txn ApplicationArgs 2
        ==
        assert
        b end
     bad:
        err
`)

const boxVersion = 35

// TestBoxCreate tests MBR changes around allocation, deallocation
func TestBoxCreate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, boxVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion) {
		dl := NewDoubleLedger(t, genBalances, cv)
		defer dl.Close()

		// increment for a size 24 box with 4 letter name
		const mbr = 2500 + 28*400

		appIndex := dl.fundedApp(addrs[0], 100_000+3*mbr, boxAppSource)

		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appIndex,
		}

		adam := call.Args("create", "adam")
		dl.txn(adam, "invalid Box reference adam")
		adam.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("adam")}}
		dl.txn(adam)
		dl.txn(adam.Args("check", "adam", "\x00\x00"))
		dl.txgroup("box_create\nassert", adam.Noted("one"), adam.Noted("two"))
		bobo := call.Args("create", "bobo")
		dl.txn(bobo, "invalid Box reference bobo")
		bobo.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("bobo")}}
		dl.txn(bobo)
		dl.txgroup("box_create\nassert", bobo.Noted("one"), bobo.Noted("two"))

		dl.beginBlock()
		chaz := call.Args("create", "chaz")
		chaz.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("chaz")}}
		dl.txn(chaz)
		dl.txn(chaz.Noted("again"), "box_create\nassert")
		dl.endBlock()

		// new block
		dl.txn(chaz.Noted("again"), "box_create\nassert")
		dogg := call.Args("create", "dogg")
		dogg.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("dogg")}}
		dl.txn(dogg, "below min")
		dl.txn(chaz.Args("delete", "chaz"))
		dl.txn(chaz.Args("delete", "chaz").Noted("again"), "box_del\nassert")
		dl.txn(dogg)
		dl.txn(bobo.Args("delete", "bobo"))

		// empty name is illegal
		empty := call.Args("create", "")
		dl.txn(empty, "box names may not be zero")
		// and, of course, that's true even if there's a box ref with the empty name
		empty.Boxes = []transactions.BoxRef{{}}
		dl.txn(empty, "box names may not be zero")
	})
}

// TestBoxRecreate tests behavior when box_create is called for a box that already exists
func TestBoxRecreate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, boxVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion) {
		dl := NewDoubleLedger(t, genBalances, cv)
		defer dl.Close()

		// increment for a size 4 box with 4 letter name
		const mbr = 2500 + 8*400

		appIndex := dl.fundedApp(addrs[0], 100_000+mbr, boxAppSource)

		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appIndex,
			Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("adam")}},
		}

		create := call.Args("create", "adam", "\x04") // box value size is 4 bytes
		recreate := call.Args("recreate", "adam", "\x04")

		dl.txn(recreate, "box_create\n!\nassert")
		dl.txn(create)
		dl.txn(recreate)
		dl.txn(call.Args("set", "adam", "\x01\x02\x03\x04"))
		dl.txn(call.Args("check", "adam", "\x01\x02\x03\x04"))
		dl.txn(recreate.Noted("again"))
		// a recreate does not change the value
		dl.txn(call.Args("check", "adam", "\x01\x02\x03\x04").Noted("after recreate"))
		// recreating with a smaller size fails
		dl.txn(call.Args("recreate", "adam", "\x03"), "box size mismatch 4 3")
		// recreating with a larger size fails
		dl.txn(call.Args("recreate", "adam", "\x05"), "box size mismatch 4 5")
		dl.txn(call.Args("check", "adam", "\x01\x02\x03\x04").Noted("after failed recreates"))

		// delete and actually create again
		dl.txn(call.Args("delete", "adam"))
		dl.txn(call.Args("create", "adam", "\x03"))

		dl.txn(call.Args("set", "adam", "\x03\x02\x01"))
		dl.txn(call.Args("check", "adam", "\x03\x02\x01"))
		dl.txn(recreate.Noted("after delete"), "box size mismatch 3 4")
		dl.txn(call.Args("recreate", "adam", "\x03"))
		dl.txn(call.Args("check", "adam", "\x03\x02\x01").Noted("after delete and recreate"))
	})
}

func TestBoxCreateAvailability(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, boxVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion) {
		dl := NewDoubleLedger(t, genBalances, cv)
		defer dl.Close()

		accessInCreate := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: 0, // This is a create
			Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("hello")}},
			ApprovalProgram: `
              byte "hello"
              int 10
              box_create
`,
		}

		// We know box_create worked because we finished and checked MBR
		dl.txn(&accessInCreate, "balance 0 below min")

		// But let's fund it and be sure. This is "psychic". We're going to fund
		// the app address that we know the app will get. So this is a nice
		// test, but unrealistic way to actual create a box.
		psychic := basics.AppIndex(2)
		dl.txn(&txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: psychic.Address(),
			Amount:   100_000 + 2500 + 15*400,
		})
		dl.txn(&accessInCreate)

		// Now, a more realistic, though tricky, way to get a box created during
		// the app's first txgroup in existence is to create it in tx0, and then
		// in tx1 fund it using an inner tx, then invoke it with an inner
		// transaction. During that invocation, the app will have access to the
		// boxes supplied as "0 refs", since they were resolved to the app ID
		// during creation.

		accessWhenCalled := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: 0, // This is a create
			Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("hello")}},
			// Note that main() wraps the program so it does not run at creation time.
			ApprovalProgram: main(`
              byte "hello"
              int 10
              box_create
              assert
              byte "we did it"
              log
`),
		}

		trampoline := dl.fundedApp(addrs[0], 1_000_000, main(`
            // Fund the app created in the txn behind me.
			txn GroupIndex
            int 1
            -
            gtxns CreatedApplicationID
            dup					// copy for use when calling
            dup					// test copy
            assert
            app_params_get AppAddress
            assert

            itxn_begin
             itxn_field Receiver
             int 500000
             itxn_field Amount
             int pay
             itxn_field TypeEnum
            itxn_submit

            // Now invoke it, so it can intialize (and create the "hello" box)
            itxn_begin
             itxn_field ApplicationID
             int appl
             itxn_field TypeEnum
            itxn_submit
`))

		call := txntest.Txn{
			Sender:        addrs[0],
			Type:          "appl",
			ApplicationID: trampoline,
		}

		dl.beginBlock()
		dl.txgroup("", &accessWhenCalled, &call)
		vb := dl.endBlock()

		// Make sure that we actually did it.
		require.Equal(t, "we did it", vb.Block().Payset[1].ApplyData.EvalDelta.InnerTxns[1].EvalDelta.Logs[0])
	})
}

// TestBoxRW tests reading writing boxes in consecutive transactions
func TestBoxRW(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, boxVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion) {
		dl := NewDoubleLedger(t, genBalances, cv)
		defer dl.Close()

		var bufNewLogger bytes.Buffer
		log := logging.NewLogger()
		log.SetOutput(&bufNewLogger)

		appIndex := dl.fundedApp(addrs[0], 1_000_000, boxAppSource)
		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appIndex,
			Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("x")}},
		}

		dl.txn(call.Args("create", "x", "\x10"))    // 16
		dl.txn(call.Args("set", "x", "ABCDEFGHIJ")) // 10 long
		dl.txn(call.Args("check", "x", "ABCDE"))
		dl.txn(call.Args("check", "x", "ABCDEFGHIJ"))
		dl.txn(call.Args("check", "x", "ABCDEFGHIJ\x00"))

		dl.txn(call.Args("delete", "x"))
		dl.txn(call.Args("check", "x", "ABC"), "no such box")
		dl.txn(call.Args("create", "x", "\x08"))
		dl.txn(call.Args("check", "x", "\x00")) // it was cleared
		dl.txn(call.Args("set", "x", "ABCDEFGHIJ"), "replacement end 10")
		dl.txn(call.Args("check", "x", "\x00")) // still clear
		dl.txn(call.Args("set", "x", "ABCDEFGH"))
		dl.txn(call.Args("check", "x", "ABCDEFGH\x00"), "extraction end 9")
		dl.txn(call.Args("check", "x", "ABCDEFGH"))
		dl.txn(call.Args("set", "x", "ABCDEFGHI"), "replacement end 9")

		// Advance more than 320 rounds, ensure box is still there
		for i := 0; i < 330; i++ {
			dl.fullBlock()
		}
		time.Sleep(5 * time.Second) // balancesFlushInterval, so commit happens
		dl.fullBlock(call.Args("check", "x", "ABCDEFGH"))
		time.Sleep(100 * time.Millisecond) // give commit time to run, and prune au caches
		dl.fullBlock(call.Args("check", "x", "ABCDEFGH"))

		dl.txn(call.Args("create", "yy"), "invalid Box reference yy")
		withBr := call.Args("create", "yy")
		withBr.Boxes = append(withBr.Boxes, transactions.BoxRef{Index: 1, Name: []byte("yy")})
		require.Error(dl.t, withBr.Txn().WellFormed(transactions.SpecialAddresses{}, dl.generator.GenesisProto()))
		withBr.Boxes[1].Index = 0
		dl.txn(withBr)
	})
}

// TestBoxAccountData tests that an account's data changes when boxes are created
func TestBoxAccountData(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	uint64ToArgStr := func(i uint64) string {
		encoded := make([]byte, 8)
		binary.BigEndian.PutUint64(encoded, i)
		return string(encoded)
	}

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, boxVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion) {
		dl := NewDoubleLedger(t, genBalances, cv)
		defer dl.Close()

		proto := config.Consensus[cv]

		var bufNewLogger bytes.Buffer
		log := logging.NewLogger()
		log.SetOutput(&bufNewLogger)

		appIndex := dl.fundedApp(addrs[0], 1_000_000, boxAppSource)
		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appIndex,
			Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("x")}, {Index: 0, Name: []byte("y")}},
		}

		verifyAppSrc := main(`
txn ApplicationArgs 0
btoi
txn Accounts 1
acct_params_get AcctMinBalance
assert
==
assert

txn ApplicationArgs 1
btoi
txn Accounts 1
acct_params_get AcctTotalBoxes
assert
==
assert

txn ApplicationArgs 2
btoi
txn Accounts 1
acct_params_get AcctTotalBoxBytes
assert
==
assert
`)
		verifyAppIndex := dl.fundedApp(addrs[0], 0, verifyAppSrc)
		verifyAppCall := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: verifyAppIndex,
			Accounts:      []basics.Address{appIndex.Address()},
		}

		// The app account has no box data initially
		dl.txn(verifyAppCall.Args(uint64ToArgStr(proto.MinBalance), "\x00", "\x00"))

		dl.txn(call.Args("create", "x", "\x10")) // 16

		// It gets updated when a new box is created
		dl.txn(verifyAppCall.Args(uint64ToArgStr(proto.MinBalance+proto.BoxFlatMinBalance+17*proto.BoxByteMinBalance), "\x01", "\x11"))

		dl.txn(call.Args("create", "y", "\x05"))

		// And again
		dl.txn(verifyAppCall.Args(uint64ToArgStr(proto.MinBalance+2*proto.BoxFlatMinBalance+23*proto.BoxByteMinBalance), "\x02", "\x17"))

		// Advance more than 320 rounds, ensure box is still there
		for i := 0; i < 330; i++ {
			dl.fullBlock()
		}
		time.Sleep(5 * time.Second) // balancesFlushInterval, so commit happens
		dl.fullBlock(call.Args("check", "x", string(make([]byte, 16))))
		time.Sleep(100 * time.Millisecond) // give commit time to run, and prune au caches
		dl.fullBlock(call.Args("check", "x", string(make([]byte, 16))))

		// Still the same after caches are flushed
		dl.txn(verifyAppCall.Args(uint64ToArgStr(proto.MinBalance+2*proto.BoxFlatMinBalance+23*proto.BoxByteMinBalance), "\x02", "\x17"))

		dl.txns(call.Args("delete", "x"), call.Args("delete", "y"))

		// Data gets removed after boxes are deleted
		dl.txn(verifyAppCall.Args(uint64ToArgStr(proto.MinBalance), "\x00", "\x00"))
	})
}

func TestBoxIOBudgets(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	ledgertesting.TestConsensusRange(t, boxVersion, 0, func(t *testing.T, ver int, cv protocol.ConsensusVersion) {
		dl := NewDoubleLedger(t, genBalances, cv)
		defer dl.Close()

		appIndex := dl.fundedApp(addrs[0], 1_000_000, boxAppSource)
		call := txntest.Txn{
			Type:          "appl",
			Sender:        addrs[0],
			ApplicationID: appIndex,
			Boxes:         []transactions.BoxRef{{Index: 0, Name: []byte("x")}},
		}
		dl.txn(call.Args("create", "x", "\x10\x00"), // 4096
			"write budget (1024) exceeded")
		call.Boxes = append(call.Boxes, transactions.BoxRef{})
		dl.txn(call.Args("create", "x", "\x10\x00"), // 4096
			"write budget (2048) exceeded")
		call.Boxes = append(call.Boxes, transactions.BoxRef{})
		dl.txn(call.Args("create", "x", "\x10\x00"), // 4096
			"write budget (3072) exceeded")
		call.Boxes = append(call.Boxes, transactions.BoxRef{})
		dl.txn(call.Args("create", "x", "\x10\x00"), // now there are 4 box refs
			"below min") // big box would need more balance
		dl.txn(call.Args("create", "x", "\x10\x01"), // 4097
			"write budget (4096) exceeded")

		var needed uint64 = 100_000 + 2500 + 400*(4096+1) // remember key len!
		dl.txn(&txntest.Txn{
			Type:     "pay",
			Sender:   addrs[0],
			Receiver: appIndex.Address(),
			Amount:   needed - 1_000_000,
		})
		dl.txn(call.Args("create", "x", "\x10\x00"))

		// Now that we've created a 4,096 byte box, test READ budget
		// It works at the start, because call still has 4 brs.
		dl.txn(call.Args("check", "x", "\x00"))
		call.Boxes = call.Boxes[:3]
		dl.txn(call.Args("check", "x", "\x00"),
			"box read budget (3072) exceeded")

		// Give a budget over 32768, confirm failure anyway
		empties := [32]transactions.BoxRef{}
		// These tests skip WellFormed, so the huge Boxes is ok
		call.Boxes = append(call.Boxes, empties[:]...)
		dl.txn(call.Args("create", "x", "\x80\x01"), "box size too large") // 32769
	})
}
