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

package ledger

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/avm-abi/apps"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger/encoded"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/msgp/msgp"
)

type decodedCatchpointChunkData struct {
	headerName string
	data       []byte
}

func readCatchpointContent(t *testing.T, tarReader *tar.Reader) []decodedCatchpointChunkData {
	result := make([]decodedCatchpointChunkData, 0)
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			break
		}
		data := make([]byte, header.Size)
		readComplete := int64(0)

		for readComplete < header.Size {
			bytesRead, err := tarReader.Read(data[readComplete:])
			readComplete += int64(bytesRead)
			if err != nil {
				if err == io.EOF {
					if readComplete == header.Size {
						break
					}
					require.NoError(t, err)
				}
				break
			}
		}

		result = append(result, decodedCatchpointChunkData{headerName: header.Name, data: data})
	}

	return result
}

func readCatchpointDataFile(t *testing.T, catchpointDataPath string) []decodedCatchpointChunkData {
	fileContent, err := os.ReadFile(catchpointDataPath)
	require.NoError(t, err)

	compressorReader, err := catchpointStage1Decoder(bytes.NewBuffer(fileContent))
	require.NoError(t, err)

	tarReader := tar.NewReader(compressorReader)
	return readCatchpointContent(t, tarReader)
}

func readCatchpointFile(t *testing.T, catchpointPath string) []decodedCatchpointChunkData {
	fileContent, err := os.ReadFile(catchpointPath)
	require.NoError(t, err)

	gzipReader, err := gzip.NewReader(bytes.NewBuffer(fileContent))
	require.NoError(t, err)
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	return readCatchpointContent(t, tarReader)
}

func verifyStateProofVerificationContextWrite(t *testing.T, data []ledgercore.StateProofVerificationContext) {
	// create new protocol version, which has lower lookback
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestBasicCatchpointWriter")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	config.Consensus[testProtocolVersion] = protoParams
	temporaryDirectory := t.TempDir()
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()
	accts := ledgertesting.RandomAccounts(300, false)

	ml := makeMockLedgerForTracker(t, true, 10, testProtocolVersion, []map[basics.Address]basics.AccountData{accts})
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au, _ := newAcctUpdates(t, ml, conf)
	err := au.loadFromDisk(ml, 0)
	require.NoError(t, err)
	au.close() // it is OK to close it here - no data race since commitSyncer is not active
	fileName := filepath.Join(temporaryDirectory, "15.data")

	mockCommitData := make([]verificationCommitContext, 0)
	for _, element := range data {
		mockCommitData = append(mockCommitData, verificationCommitContext{verificationContext: element})
	}

	err = ml.dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error {
		return commitSPContexts(ctx, tx, mockCommitData)
	})

	require.NoError(t, err)

	err = ml.trackerDB().Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		writer, err := makeCatchpointFileWriter(context.Background(), protoParams, fileName, tx, ResourcesPerCatchpointFileChunk, 0)
		if err != nil {
			return err
		}
		rawData, err := tx.MakeSpVerificationCtxReader().GetAllSPContexts(ctx)
		if err != nil {
			return err
		}
		_, encodedData := crypto.EncodeAndHash(catchpointStateProofVerificationContext{Data: rawData})

		err = writer.FileWriteSPVerificationContext(encodedData)
		if err != nil {
			return err
		}
		for {
			more, err := writer.FileWriteStep(context.Background())
			require.NoError(t, err)
			if !more {
				break
			}
		}
		return
	})

	catchpointData := readCatchpointDataFile(t, fileName)
	require.Equal(t, catchpointSPVerificationFileName, catchpointData[0].headerName)
	var wrappedData catchpointStateProofVerificationContext
	err = protocol.Decode(catchpointData[0].data, &wrappedData)
	require.NoError(t, err)

	for index, verificationContext := range wrappedData.Data {
		require.Equal(t, data[index], verificationContext)
	}
}

func TestCatchpointFileBalancesChunkEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// check a low number of balances/kvs/resources
	// otherwise it would take forever to serialize/deserialize
	const numChunkEntries = BalancesPerCatchpointFileChunk / 50
	require.Greater(t, numChunkEntries, 1)

	const numResources = ResourcesPerCatchpointFileChunk / 10000
	require.Greater(t, numResources, 1)

	baseAD := randomBaseAccountData()
	encodedBaseAD := baseAD.MarshalMsg(nil)

	resources := make(map[uint64]msgp.Raw, numResources/10)
	rdApp := randomAppResourceData()
	encodedResourceData := rdApp.MarshalMsg(nil)
	for i := uint64(0); i < numResources; i++ {
		resources[i] = encodedResourceData
	}
	balance := encoded.BalanceRecordV6{
		Address:     ledgertesting.RandomAddress(),
		AccountData: encodedBaseAD,
		Resources:   resources,
	}
	balances := make([]encoded.BalanceRecordV6, numChunkEntries)
	kv := encoded.KVRecordV6{
		Key:   make([]byte, encoded.KVRecordV6MaxKeyLength),
		Value: make([]byte, encoded.KVRecordV6MaxValueLength),
	}
	crypto.RandBytes(kv.Key[:])
	crypto.RandBytes(kv.Value[:])
	kvs := make([]encoded.KVRecordV6, numChunkEntries)

	for i := 0; i < numChunkEntries; i++ {
		balances[i] = balance
		kvs[i] = kv
	}

	chunk1 := catchpointFileChunkV6{}
	chunk1.Balances = balances
	chunk1.KVs = kvs
	encodedChunk := chunk1.MarshalMsg(nil)

	var chunk2 catchpointFileChunkV6
	_, err := chunk2.UnmarshalMsg(encodedChunk)
	require.NoError(t, err)

	require.Equal(t, chunk1, chunk2)
}

func TestBasicCatchpointWriter(t *testing.T) {
	partitiontest.PartitionTest(t)
	// t.Parallel() NO! config.Consensus is modified

	// create new protocol version, which has lower lookback
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestBasicCatchpointWriter")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	config.Consensus[testProtocolVersion] = protoParams
	temporaryDirectory := t.TempDir()
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()
	accts := ledgertesting.RandomAccounts(300, false)

	ml := makeMockLedgerForTracker(t, true, 10, testProtocolVersion, []map[basics.Address]basics.AccountData{accts})
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au, _ := newAcctUpdates(t, ml, conf)
	err := au.loadFromDisk(ml, 0)
	require.NoError(t, err)
	au.close() // it is OK to close it here - no data race since commitSyncer is not active
	fileName := filepath.Join(temporaryDirectory, "15.data")

	err = ml.trackerDB().Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		writer, err := makeCatchpointFileWriter(context.Background(), protoParams, fileName, tx, ResourcesPerCatchpointFileChunk, 0)
		if err != nil {
			return err
		}
		rawData, err := tx.MakeSpVerificationCtxReader().GetAllSPContexts(ctx)
		if err != nil {
			return err
		}
		_, encodedData := crypto.EncodeAndHash(catchpointStateProofVerificationContext{Data: rawData})
		err = writer.FileWriteSPVerificationContext(encodedData)
		if err != nil {
			return err
		}
		for {
			more, err := writer.FileWriteStep(context.Background())
			require.NoError(t, err)
			if !more {
				break
			}
		}
		return
	})

	catchpointContent := readCatchpointDataFile(t, fileName)
	balanceFileName := fmt.Sprintf(catchpointBalancesFileNameTemplate, 1)
	require.Equal(t, balanceFileName, catchpointContent[1].headerName)

	var chunk catchpointFileChunkV6
	err = protocol.Decode(catchpointContent[1].data, &chunk)
	require.NoError(t, err)
	require.Equal(t, uint64(len(accts)), uint64(len(chunk.Balances)))
}

func testWriteCatchpoint(t *testing.T, params config.ConsensusParams, rdb trackerdb.Store, datapath string, filepath string, maxResourcesPerChunk int) CatchpointFileHeader {
	var totalAccounts, totalKVs, totalOnlineAccounts, totalOnlineRoundParams, totalChunks uint64
	var biggestChunkLen uint64
	var accountsRnd basics.Round
	var totals ledgercore.AccountTotals
	if maxResourcesPerChunk <= 0 {
		maxResourcesPerChunk = ResourcesPerCatchpointFileChunk
	}

	err := rdb.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		writer, err := makeCatchpointFileWriter(context.Background(), params, datapath, tx, maxResourcesPerChunk, 0)
		if err != nil {
			return err
		}

		ar, err := tx.MakeAccountsReader()
		if err != nil {
			return err
		}
		rawData, err := tx.MakeSpVerificationCtxReader().GetAllSPContexts(ctx)
		if err != nil {
			return err
		}
		_, encodedData := crypto.EncodeAndHash(catchpointStateProofVerificationContext{Data: rawData})
		err = writer.FileWriteSPVerificationContext(encodedData)
		if err != nil {
			return err
		}
		for {
			more, err := writer.FileWriteStep(context.Background())
			require.NoError(t, err)
			if !more {
				break
			}
		}
		totalAccounts = writer.totalAccounts
		totalKVs = writer.totalKVs
		totalOnlineAccounts = writer.totalOnlineAccounts
		totalOnlineRoundParams = writer.totalOnlineRoundParams
		totalChunks = writer.chunkNum
		biggestChunkLen = writer.biggestChunkLen
		accountsRnd, err = ar.AccountsRound()
		if err != nil {
			return
		}
		totals, err = ar.AccountsTotals(ctx, false)
		return
	})
	require.NoError(t, err)
	blocksRound := accountsRnd + 1
	blockHeaderDigest := crypto.Hash([]byte{1, 2, 3})
	catchpointLabel := fmt.Sprintf("%d#%v", blocksRound, blockHeaderDigest) // this is not a correct way to create a label, but it's good enough for this unit test
	catchpointFileHeader := CatchpointFileHeader{
		Version:                CatchpointFileVersionV8,
		BalancesRound:          accountsRnd,
		BlocksRound:            blocksRound,
		Totals:                 totals,
		TotalAccounts:          totalAccounts,
		TotalKVs:               totalKVs,
		TotalOnlineAccounts:    totalOnlineAccounts,
		TotalOnlineRoundParams: totalOnlineRoundParams,
		TotalChunks:            totalChunks,
		Catchpoint:             catchpointLabel,
		BlockHeaderDigest:      blockHeaderDigest,
	}
	err = repackCatchpoint(
		context.Background(), catchpointFileHeader, biggestChunkLen,
		datapath, filepath)
	require.NoError(t, err)

	l := testNewLedgerFromCatchpoint(t, rdb, filepath)
	defer l.Close()

	return catchpointFileHeader
}

func TestStateProofVerificationContextWrite(t *testing.T) {
	partitiontest.PartitionTest(t)
	//t.Parallel() verifyStateProofVerificationContextWrite changes consensus

	verificationContext := ledgercore.StateProofVerificationContext{
		LastAttestedRound: 120,
		VotersCommitment:  nil,
		OnlineTotalWeight: basics.MicroAlgos{Raw: 100},
	}

	verifyStateProofVerificationContextWrite(t, []ledgercore.StateProofVerificationContext{verificationContext})
}

func TestEmptyStateProofVerificationContextWrite(t *testing.T) {
	partitiontest.PartitionTest(t)
	//t.Parallel() verifyStateProofVerificationContextWrite changes consensus

	verifyStateProofVerificationContextWrite(t, []ledgercore.StateProofVerificationContext{})
}

func TestCatchpointReadDatabaseOverflowSingleAccount(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestFullCatchpointWriter")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	config.Consensus[testProtocolVersion] = protoParams
	temporaryDirectory := t.TempDir()
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	maxResourcesPerChunk := 5

	accts := ledgertesting.RandomAccounts(1, false)
	// force acct to have overflowing number of resources
	assetIndex := 1000
	for addr, acct := range accts {
		if acct.AssetParams == nil {
			acct.AssetParams = make(map[basics.AssetIndex]basics.AssetParams, 0)
			accts[addr] = acct
		}
		for i := uint64(0); i < 20; i++ {
			ap := ledgertesting.RandomAssetParams()
			acct.AssetParams[basics.AssetIndex(assetIndex)] = ap
			assetIndex++
		}
	}

	ml := makeMockLedgerForTracker(t, true, 10, testProtocolVersion, []map[basics.Address]basics.AccountData{accts})
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au, _ := newAcctUpdates(t, ml, conf)
	err := au.loadFromDisk(ml, 0)
	require.NoError(t, err)
	au.close() // it is OK to close it here - no data race since commitSyncer is not active
	catchpointDataFilePath := filepath.Join(temporaryDirectory, "15.data")

	err = ml.trackerDB().Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		expectedTotalAccounts := uint64(1)
		totalAccountsWritten := uint64(0)
		totalResources := 0
		totalChunks := 0
		cw, err := makeCatchpointFileWriter(context.Background(), protoParams, catchpointDataFilePath, tx, maxResourcesPerChunk, 0)
		require.NoError(t, err)

		ar, err := tx.MakeAccountsReader()
		if err != nil {
			return err
		}

		expectedTotalResources, err := ar.TotalResources(ctx)
		if err != nil {
			return err
		}

		// repeat this until read all accts
		for totalAccountsWritten < expectedTotalAccounts {
			cw.chunk.Balances = nil
			err := cw.readDatabaseStep(cw.ctx)
			if err != nil {
				return err
			}
			totalAccountsWritten += cw.chunk.numAccounts
			numResources := 0
			for _, balance := range cw.chunk.Balances {
				numResources += len(balance.Resources)
			}
			if numResources > maxResourcesPerChunk {
				return fmt.Errorf("too many resources in this chunk: found %d resources, maximum %d resources", numResources, maxResourcesPerChunk)
			}
			totalResources += numResources
			totalChunks++
		}

		if totalChunks <= 1 {
			return fmt.Errorf("expected more than one chunk due to overflow")
		}

		if expectedTotalResources != uint64(totalResources) {
			return fmt.Errorf("total resources did not match: expected %d, actual %d", expectedTotalResources, totalResources)
		}

		return
	})

	require.NoError(t, err)
}

func TestCatchpointReadDatabaseOverflowAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestFullCatchpointWriter")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	config.Consensus[testProtocolVersion] = protoParams
	temporaryDirectory := t.TempDir()
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	const maxResourcesPerChunk = 5

	accts := ledgertesting.RandomAccounts(5, false)
	// force each acct to have overflowing number of resources
	assetIndex := 1000
	for addr, acct := range accts {
		if acct.AssetParams == nil {
			acct.AssetParams = make(map[basics.AssetIndex]basics.AssetParams, 0)
			accts[addr] = acct
		}
		for i := uint64(0); i < 20; i++ {
			ap := ledgertesting.RandomAssetParams()
			acct.AssetParams[basics.AssetIndex(assetIndex)] = ap
			assetIndex++
		}
	}

	ml := makeMockLedgerForTracker(t, true, 10, testProtocolVersion, []map[basics.Address]basics.AccountData{accts})
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au, _ := newAcctUpdates(t, ml, conf)
	err := au.loadFromDisk(ml, 0)
	require.NoError(t, err)
	au.close()
	catchpointDataFilePath := filepath.Join(temporaryDirectory, "15.data")

	err = ml.trackerDB().Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		ar, err := tx.MakeAccountsReader()
		if err != nil {
			return err
		}

		expectedTotalAccounts, err := ar.TotalAccounts(ctx)
		if err != nil {
			return err
		}

		expectedTotalResources, err := ar.TotalResources(ctx)
		if err != nil {
			return err
		}

		totalAccountsWritten := uint64(0)
		totalResources := 0
		cw, err := makeCatchpointFileWriter(context.Background(), protoParams, catchpointDataFilePath, tx, maxResourcesPerChunk, 0)
		require.NoError(t, err)

		// repeat this until read all accts
		for totalAccountsWritten < expectedTotalAccounts {
			cw.chunk.Balances = nil
			err := cw.readDatabaseStep(cw.ctx)
			if err != nil {
				return err
			}
			totalAccountsWritten += cw.chunk.numAccounts
			numResources := 0
			for _, balance := range cw.chunk.Balances {
				numResources += len(balance.Resources)
			}
			if numResources > maxResourcesPerChunk {
				return fmt.Errorf("too many resources in this chunk: found %d resources, maximum %d resources", numResources, maxResourcesPerChunk)
			}
			totalResources += numResources
		}

		if expectedTotalResources != uint64(totalResources) {
			return fmt.Errorf("total resources did not match: expected %d, actual %d", expectedTotalResources, totalResources)
		}

		return
	})

	require.NoError(t, err)
}

func TestFullCatchpointWriterOverflowAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create new protocol version, which has lower lookback
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestFullCatchpointWriter")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	config.Consensus[testProtocolVersion] = protoParams
	temporaryDirectory := t.TempDir()
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	accts := ledgertesting.RandomAccounts(BalancesPerCatchpointFileChunk*3, false)
	ml := makeMockLedgerForTracker(t, true, 10, testProtocolVersion, []map[basics.Address]basics.AccountData{accts})
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au, _ := newAcctUpdates(t, ml, conf)
	err := au.loadFromDisk(ml, 0)
	require.NoError(t, err)
	au.close()
	catchpointDataFilePath := filepath.Join(temporaryDirectory, "15.data")
	catchpointFilePath := filepath.Join(temporaryDirectory, "15.catchpoint")
	const maxResourcesPerChunk = 5
	testWriteCatchpoint(t, protoParams, ml.trackerDB(), catchpointDataFilePath, catchpointFilePath, maxResourcesPerChunk)

	l := testNewLedgerFromCatchpoint(t, ml.trackerDB(), catchpointFilePath)
	defer l.Close()

	// verify that the account data aligns with what we originally stored :
	for addr, acct := range accts {
		acctData, validThrough, _, err := l.LookupLatest(addr)
		require.NoErrorf(t, err, "failed to lookup for account %v after restoring from catchpoint", addr)
		require.Equal(t, acct, acctData)
		require.Equal(t, basics.Round(0), validThrough)
	}

	// TODO: uncomment if we want to test re-initializing the ledger fully
	// currently this doesn't work, because reloadLedger runs migrations like txtail that require a working block DB
	//err = l.reloadLedger()
	//require.NoError(t, err)

	// now manually construct the MT and ensure the reading makeOrderedAccountsIter works as expected:
	// no errors on read, hashes match
	ctx := context.Background()

	err = l.trackerDBs.TransactionContext(ctx, func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		aw, err := tx.MakeAccountsWriter()
		if err != nil {
			return nil
		}

		// save the existing hash
		committer, err := tx.MakeMerkleCommitter(false)
		require.NoError(t, err)
		trie, err := merkletrie.MakeTrie(committer, trackerdb.TrieMemoryConfig)
		require.NoError(t, err)

		h1, err := trie.RootHash()
		require.NoError(t, err)
		require.NotEmpty(t, h1)

		// reset hashes
		err = aw.ResetAccountHashes(ctx)
		require.NoError(t, err)

		// rebuild the MT
		committer, err = tx.MakeMerkleCommitter(false)
		require.NoError(t, err)
		trie, err = merkletrie.MakeTrie(committer, trackerdb.TrieMemoryConfig)
		require.NoError(t, err)

		h, err := trie.RootHash()
		require.NoError(t, err)
		require.Zero(t, h)

		iter := tx.MakeOrderedAccountsIter(trieRebuildAccountChunkSize)
		defer iter.Close(ctx)
		for {
			accts, _, err := iter.Next(ctx)
			if err == sql.ErrNoRows {
				// the account builder would return sql.ErrNoRows when no more data is available.
				err = nil
				break
			} else if err != nil {
				require.NoError(t, err)
			}

			if len(accts) > 0 {
				for _, acct := range accts {
					added, err := trie.Add(acct.Digest)
					require.NoError(t, err)
					require.True(t, added)
				}
			}
		}

		require.NoError(t, err)
		h2, err := trie.RootHash()
		require.NoError(t, err)
		require.NotEmpty(t, h2)

		require.Equal(t, h1, h2)

		return nil
	})
	require.NoError(t, err)
}

func testNewLedgerFromCatchpoint(t *testing.T, catchpointWriterReadAccess trackerdb.Store, filepath string) *Ledger {
	// create a ledger.
	var initState ledgercore.InitState
	initState.Block.CurrentProtocol = protocol.ConsensusCurrentVersion
	conf := config.GetDefaultLocal()
	dbName := fmt.Sprintf("%s.%d", t.Name()+"FromCatchpoint", crypto.RandUint64())
	dbName = strings.Replace(dbName, "/", "_", -1)
	l, err := OpenLedger(logging.TestingLog(t), dbName, true, initState, conf)
	require.NoError(t, err)
	accessor := MakeCatchpointCatchupAccessor(l, l.log)

	err = accessor.ResetStagingBalances(context.Background(), true)
	require.NoError(t, err)

	var catchupProgress CatchpointCatchupAccessorProgress
	catchpointContent := readCatchpointFile(t, filepath)
	var balancesRound basics.Round
	for _, catchpointData := range catchpointContent {
		// get BalancesRound from header and use it to set the DB round
		if catchpointData.headerName == CatchpointContentFileName {
			var fileheader CatchpointFileHeader
			err = protocol.Decode(catchpointData.data, &fileheader)
			require.NoError(t, err)
			balancesRound = fileheader.BalancesRound
		}
		err = accessor.ProcessStagingBalances(context.Background(), catchpointData.headerName, catchpointData.data, &catchupProgress)
		require.NoError(t, err)
	}
	require.NotZero(t, balancesRound, "no balances round found in test catchpoint file")

	// TODO: uncomment if we want to test re-initializing the ledger fully, by setting the balances round (DB round)
	// for use by the trackers and migrations. However the txtail migration requires a working block DB, which most
	// of these catchpoint tests don't copy over when saving/restoring.
	//
	// // Manually set the balances round. In regular catchpoint restore, this is set by StoreBalancesRound
	// // when the first block is downloaded.
	// err = l.trackerDB().Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
	// 	crw, err := tx.MakeCatchpointWriter()
	// 	require.NoError(t, err)

	// 	err = crw.WriteCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupBalancesRound, uint64(balancesRound))
	// 	require.NoError(t, err)
	// 	return nil
	// })
	// require.NoError(t, err)

	err = accessor.BuildMerkleTrie(context.Background(), nil)
	require.NoError(t, err)

	// Initializes DB, runs migrations, runs ApplyCatchpointStagingBalances
	err = accessor.(*catchpointCatchupAccessorImpl).finishBalances(context.Background())
	require.NoError(t, err)

	balanceTrieStats := func(db trackerdb.Store) merkletrie.Stats {
		var stats merkletrie.Stats
		err = db.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
			committer, err := tx.MakeMerkleCommitter(false)
			if err != nil {
				return err
			}
			trie, err := merkletrie.MakeTrie(committer, trackerdb.TrieMemoryConfig)
			if err != nil {
				return err
			}
			stats, err = trie.GetStats()
			if err != nil {
				return err
			}
			return nil
		})

		require.NoError(t, err)
		return stats
	}

	ws := balanceTrieStats(catchpointWriterReadAccess)
	// Skip invariant check for tests using mocks that do _not_ update
	// balancesTrie by checking for zero value stats.
	if ws != (merkletrie.Stats{}) {
		require.Equal(t, ws, balanceTrieStats(l.trackerDBs), "Invariant broken - Catchpoint writer and reader merkle tries should _always_ agree")
	}

	return l
}

func TestFullCatchpointWriter(t *testing.T) {
	partitiontest.PartitionTest(t)
	// t.Parallel() NO! config.Consensus is modified

	// create new protocol version, which has lower lookback
	testProtocolVersion := protocol.ConsensusVersion("test-protocol-TestFullCatchpointWriter")
	protoParams := config.Consensus[protocol.ConsensusCurrentVersion]
	protoParams.CatchpointLookback = 32
	config.Consensus[testProtocolVersion] = protoParams
	temporaryDirectory := t.TempDir()
	defer func() {
		delete(config.Consensus, testProtocolVersion)
	}()

	accts := ledgertesting.RandomAccounts(BalancesPerCatchpointFileChunk*3, false)
	ml := makeMockLedgerForTracker(t, true, 10, testProtocolVersion, []map[basics.Address]basics.AccountData{accts})
	defer ml.Close()

	conf := config.GetDefaultLocal()
	conf.CatchpointInterval = 1
	conf.Archival = true
	au, _ := newAcctUpdates(t, ml, conf)
	err := au.loadFromDisk(ml, 0)
	require.NoError(t, err)
	au.close()

	catchpointDataFilePath := filepath.Join(temporaryDirectory, "15.data")
	catchpointFilePath := filepath.Join(temporaryDirectory, "15.catchpoint")
	testWriteCatchpoint(t, protoParams, ml.trackerDB(), catchpointDataFilePath, catchpointFilePath, 0)

	l := testNewLedgerFromCatchpoint(t, ml.trackerDB(), catchpointFilePath)
	defer l.Close()
	// verify that the account data aligns with what we originally stored :
	for addr, acct := range accts {
		acctData, validThrough, _, err := l.LookupLatest(addr)
		require.NoErrorf(t, err, "failed to lookup for account %v after restoring from catchpoint", addr)
		require.Equal(t, acct, acctData)
		require.Equal(t, basics.Round(0), validThrough)
	}
}

// ensure both committed all pending changes before taking a catchpoint
// another approach is to modify the test and craft round numbers,
// and make the ledger to generate catchpoint itself when it is time
func testCatchpointFlushRound(l *Ledger) basics.Round {
	// Clear the timer to ensure a flush
	l.trackers.mu.Lock()
	l.trackers.lastFlushTime = time.Time{}
	l.trackers.mu.Unlock()

	r, _ := l.LatestCommitted()
	l.trackers.committedUpTo(r)
	l.trackers.waitAccountsWriting()
	return r
}

func TestExactAccountChunk(t *testing.T) {
	partitiontest.PartitionTest(t)
	// t.Parallel() // probably not good to parallelize catchpoint file save/load

	t.Run("v39", func(t *testing.T) { testExactAccountChunk(t, protocol.ConsensusV39) })
	t.Run("v40", func(t *testing.T) { testExactAccountChunk(t, protocol.ConsensusV40) })
	t.Run("future", func(t *testing.T) { testExactAccountChunk(t, protocol.ConsensusFuture) })
}

func testExactAccountChunk(t *testing.T, proto protocol.ConsensusVersion) {
	genBalances, addrs, _ := ledgertesting.NewTestGenesis(func(c *ledgertesting.GenesisCfg) {
		c.OnlineCount = 1 // addrs[0] is online
	}, ledgertesting.TurnOffRewards)
	cfg := config.GetDefaultLocal()

	dl := NewDoubleLedger(t, genBalances, proto, cfg)
	defer dl.Close()

	payFrom := addrs[1] // offline account sends pays
	pay := txntest.Txn{
		Type:   "pay",
		Sender: payFrom,
		Amount: 1_000_000,
	}
	// There are 12 accounts in the NewTestGenesis, so we create more so that we
	// have exactly one chunk's worth, to make sure that works without an empty
	// chunk between accounts and kvstore.
	for i := 0; i < (BalancesPerCatchpointFileChunk - 12); i++ {
		newacctpay := pay
		newacctpay.Receiver = ledgertesting.RandomAddress()
		dl.fullBlock(&newacctpay)
	}

	// At least 32 more blocks so that we catchpoint after the accounts exist
	for i := 0; i < 40; i++ {
		selfpay := pay
		selfpay.Receiver = payFrom
		selfpay.Note = ledgertesting.RandomNote()
		dl.fullBlock(&selfpay)
	}

	genR := testCatchpointFlushRound(dl.generator)
	valR := testCatchpointFlushRound(dl.validator)
	require.Equal(t, genR, valR)
	require.EqualValues(t, BalancesPerCatchpointFileChunk-12+40, genR) // 540 (512-12+40)

	require.Eventually(t, func() bool {
		dl.generator.accts.accountsMu.RLock()
		dlg := len(dl.generator.accts.deltas)
		dl.generator.accts.accountsMu.RUnlock()

		dl.validator.accts.accountsMu.RLock()
		dlv := len(dl.validator.accts.deltas)
		dl.validator.accts.accountsMu.RUnlock()
		return dlg == dlv && dl.generator.Latest() == dl.validator.Latest()
	}, 10*time.Second, 100*time.Millisecond)

	tempDir := t.TempDir()

	catchpointDataFilePath := filepath.Join(tempDir, t.Name()+".data")
	catchpointFilePath := filepath.Join(tempDir, t.Name()+".catchpoint.tar.gz")

	cph := testWriteCatchpoint(t, config.Consensus[proto], dl.validator.trackerDB(), catchpointDataFilePath, catchpointFilePath, 0)

	decodedData := readCatchpointFile(t, catchpointFilePath)

	// decode and verify some stats about balances chunk contents
	var chunks []catchpointFileChunkV6
	for i, d := range decodedData {
		t.Logf("section %d: %s", i, d.headerName)
		if strings.HasPrefix(d.headerName, "balances.") {
			var chunk catchpointFileChunkV6
			err := protocol.Decode(d.data, &chunk)
			require.NoError(t, err)
			t.Logf("chunk %d balances: %d, kvs: %d, onlineaccounts: %d, onlineroundparams: %d", i, len(chunk.Balances), len(chunk.KVs), len(chunk.OnlineAccounts), len(chunk.OnlineRoundParams))
			chunks = append(chunks, chunk)
		}
	}
	if config.Consensus[proto].EnableCatchpointsWithOnlineAccounts {
		require.Len(t, chunks, 3)
	} else {
		require.Len(t, chunks, 1)
	}
	require.Len(t, chunks, int(cph.TotalChunks))

	// first chunk is maxed out (512 accounts)
	require.Len(t, chunks[0].Balances, BalancesPerCatchpointFileChunk)

	if config.Consensus[proto].EnableCatchpointsWithOnlineAccounts {
		// second and third chunks are onlinaccounts and onlineroundparams
		require.Len(t, chunks[1].OnlineAccounts, 1)
		require.Len(t, chunks[2].OnlineRoundParams, 320)
	}

	l := testNewLedgerFromCatchpoint(t, dl.generator.trackerDB(), catchpointFilePath)
	defer l.Close()
}

// Exercises interactions between transaction evaluation and catchpoint
// generation to confirm catchpoints include expected transactions.
func TestCatchpointAfterTxns(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	cfg := config.GetDefaultLocal()
	proto := protocol.ConsensusFuture
	dl := NewDoubleLedger(t, genBalances, proto, cfg)
	defer dl.Close()

	boxApp := dl.fundedApp(addrs[1], 1_000_000, boxAppSource)
	callBox := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[2],
		ApplicationID: boxApp,
	}

	makeBox := callBox.Args("create", "xxx")
	makeBox.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("xxx")}}
	dl.txn(makeBox)

	pay := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: addrs[1],
		Amount:   100000,
	}
	// There are 12 accounts in the NewTestGenesis, plus 1 app account, so we
	// create more so that we have exactly one chunk's worth, to make sure that
	// works without an empty chunk between accounts and kvstore.
	for i := 0; i < (BalancesPerCatchpointFileChunk - 13); i++ {
		newacctpay := pay
		newacctpay.Receiver = ledgertesting.RandomAddress()
		dl.fullBlock(&newacctpay)
	}
	for i := 0; i < 40; i++ {
		dl.fullBlock(pay.Noted(strconv.Itoa(i)))
	}

	tempDir := t.TempDir()

	catchpointDataFilePath := filepath.Join(tempDir, t.Name()+".data")
	catchpointFilePath := filepath.Join(tempDir, t.Name()+".catchpoint.tar.gz")

	cph := testWriteCatchpoint(t, config.Consensus[proto], dl.validator.trackerDB(), catchpointDataFilePath, catchpointFilePath, 0)
	require.EqualValues(t, 3, cph.TotalChunks)

	l := testNewLedgerFromCatchpoint(t, dl.validator.trackerDB(), catchpointFilePath)
	defer l.Close()
	values, err := l.LookupKeysByPrefix(l.Latest(), "bx:", 10)
	require.NoError(t, err)
	require.Len(t, values, 1)

	// Add one more account
	newacctpay := pay
	last := ledgertesting.RandomAddress()
	newacctpay.Receiver = last
	dl.fullBlock(&newacctpay)

	// Write and read back in, and ensure even the last effect exists.
	cph = testWriteCatchpoint(t, config.Consensus[proto], dl.validator.trackerDB(), catchpointDataFilePath, catchpointFilePath, 0)
	require.EqualValues(t, cph.TotalChunks, 3) // Still only 3 chunks, as last was in a recent block

	// Drive home the point that `last` is _not_ included in the catchpoint by inspecting balance read from catchpoint.
	{
		l = testNewLedgerFromCatchpoint(t, dl.validator.trackerDB(), catchpointFilePath)
		defer l.Close()
		_, _, algos, err := l.LookupLatest(last)
		require.NoError(t, err)
		require.Equal(t, basics.MicroAlgos{}, algos)
	}

	for i := 0; i < 40; i++ { // Advance so catchpoint sees the txns
		dl.fullBlock(pay.Noted(strconv.Itoa(i)))
	}

	cph = testWriteCatchpoint(t, config.Consensus[proto], dl.validator.trackerDB(), catchpointDataFilePath, catchpointFilePath, 0)
	require.EqualValues(t, cph.TotalChunks, 4)

	l = testNewLedgerFromCatchpoint(t, dl.validator.trackerDB(), catchpointFilePath)
	defer l.Close()
	values, err = l.LookupKeysByPrefix(l.Latest(), "bx:", 10)
	require.NoError(t, err)
	require.Len(t, values, 1)
	v, err := l.LookupKv(l.Latest(), apps.MakeBoxKey(uint64(boxApp), "xxx"))
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("\x00", 24), string(v))

	// Confirm `last` balance is now available in the catchpoint.
	{
		// Since fast catchup consists of multiple steps and the test only performs catchpoint reads, the resulting ledger is incomplete.
		// That's why the assertion ignores rewards and does _not_ use `LookupLatest`.
		ad, _, err := l.LookupWithoutRewards(0, last)
		require.NoError(t, err)
		require.Equal(t, basics.MicroAlgos{Raw: 100_000}, ad.MicroAlgos)
	}
}

func TestCatchpointAfterStakeLookupTxns(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis(func(cfg *ledgertesting.GenesisCfg) {
		cfg.OnlineCount = 1
		ledgertesting.TurnOffRewards(cfg)
	})
	cfg := config.GetDefaultLocal()
	proto := protocol.ConsensusFuture
	dl := NewDoubleLedger(t, genBalances, proto, cfg, simpleLedgerOnDisk())
	defer dl.Close()

	initialStake := uint64(833333333333333)
	expectedStake := initialStake
	stakeAppSource := main(`
// ensure total online stake matches arg 0
txn ApplicationArgs 0
btoi
online_stake
==
assert
// ensure stake for accounts 1 (the only online account) matches arg 0
txn Accounts 1
voter_params_get VoterBalance
pop
txn ApplicationArgs 0
btoi
==
assert
`)
	// uses block 1 and 2
	stakeApp := dl.fundedApp(addrs[1], 1_000_000, stakeAppSource)

	// starting with block 3, make an app call and a pay in each block
	callStakeApp := func(assertStake uint64) []*txntest.Txn {
		stakebuf := make([]byte, 8)
		binary.BigEndian.PutUint64(stakebuf, assertStake)
		return []*txntest.Txn{
			// assert stake from 320 rounds ago
			txntest.Txn{
				Type:          "appl",
				Sender:        addrs[2],
				ApplicationID: stakeApp,
				Note:          ledgertesting.RandomNote(),
				Accounts:      []basics.Address{addrs[0]},
			}.Args(string(stakebuf)),
			// pay 1 microalgo to the only online account (takes effect in 320 rounds)
			{
				Type:     "pay",
				Sender:   addrs[1],
				Receiver: addrs[0],
				Amount:   1,
			}}
	}

	// adds block 3
	vb := dl.fullBlock(callStakeApp(expectedStake)...)
	require.Equal(t, vb.Block().Round(), basics.Round(3))
	require.Empty(t, vb.Block().ExpiredParticipationAccounts)
	require.Empty(t, vb.Block().AbsentParticipationAccounts)

	// add blocks until round 322, after which stake will go up by 1 each round
	for ; vb.Block().Round() < 322; vb = dl.fullBlock(callStakeApp(expectedStake)...) {
		require.Empty(t, vb.Block().ExpiredParticipationAccounts)
		require.Empty(t, vb.Block().AbsentParticipationAccounts)

		nextRnd := vb.Block().Round() + 1
		stake, err := dl.generator.OnlineCirculation(nextRnd.SubSaturate(320), nextRnd)
		require.NoError(t, err)
		require.Equal(t, expectedStake, stake.Raw)
	}
	require.Equal(t, vb.Block().Round(), basics.Round(322))

	for vb.Block().Round() <= 1500 {
		expectedStake++ // add 1 microalgo to the expected stake for the next block

		// the online_stake opcode in block 323 will look up OnlineCirculation(3, 323).
		nextRnd := vb.Block().Round() + 1
		stake, err := dl.generator.OnlineCirculation(nextRnd.SubSaturate(320), nextRnd)
		require.NoError(t, err)
		require.Equal(t, expectedStake, stake.Raw)

		// build a new block for nextRnd, asserting online stake for nextRnd-320
		vb = dl.fullBlock(callStakeApp(expectedStake)...)
		require.Empty(t, vb.Block().ExpiredParticipationAccounts)
		require.Empty(t, vb.Block().AbsentParticipationAccounts)
	}

	// wait for tracker to flush
	testCatchpointFlushRound(dl.generator)
	testCatchpointFlushRound(dl.validator)

	// ensure flush and latest round all were OK
	genDBRound := dl.generator.LatestTrackerCommitted()
	valDBRound := dl.validator.LatestTrackerCommitted()
	require.NotZero(t, genDBRound)
	require.NotZero(t, valDBRound)
	require.Equal(t, genDBRound, valDBRound)
	require.Equal(t, 1497, int(genDBRound))
	genLatestRound := dl.generator.Latest()
	valLatestRound := dl.validator.Latest()
	require.NotZero(t, genLatestRound)
	require.NotZero(t, valLatestRound)
	require.Equal(t, genLatestRound, valLatestRound)
	// latest should be 4 rounds ahead of DB round
	require.Equal(t, genDBRound+basics.Round(cfg.MaxAcctLookback), genLatestRound)

	t.Log("DB round generator", genDBRound, "validator", valDBRound)
	t.Log("Latest round generator", genLatestRound, "validator", valLatestRound)

	genOAHash, genOARows, err := calculateVerificationHash(context.Background(), dl.generator.trackerDB().MakeOnlineAccountsIter, 0, false)
	require.NoError(t, err)
	valOAHash, valOARows, err := calculateVerificationHash(context.Background(), dl.validator.trackerDB().MakeOnlineAccountsIter, 0, false)
	require.NoError(t, err)
	require.Equal(t, genOAHash, valOAHash)
	require.NotZero(t, genOAHash)
	require.Equal(t, genOARows, valOARows)
	require.NotZero(t, genOARows)

	genORPHash, genORPRows, err := calculateVerificationHash(context.Background(), dl.generator.trackerDB().MakeOnlineRoundParamsIter, 0, false)
	require.NoError(t, err)
	valORPHash, valORPRows, err := calculateVerificationHash(context.Background(), dl.validator.trackerDB().MakeOnlineRoundParamsIter, 0, false)
	require.NoError(t, err)
	require.Equal(t, genORPHash, valORPHash)
	require.NotZero(t, genORPHash)
	require.Equal(t, genORPRows, valORPRows)
	require.NotZero(t, genORPRows)

	tempDir := t.TempDir()
	catchpointDataFilePath := filepath.Join(tempDir, t.Name()+".data")
	catchpointFilePath := filepath.Join(tempDir, t.Name()+".catchpoint.tar.gz")

	cph := testWriteCatchpoint(t, config.Consensus[proto], dl.generator.trackerDB(), catchpointDataFilePath, catchpointFilePath, 0)
	require.EqualValues(t, 7, cph.TotalChunks)

	l := testNewLedgerFromCatchpoint(t, dl.generator.trackerDB(), catchpointFilePath)
	defer l.Close()

	catchpointOAHash, catchpointOARows, err := calculateVerificationHash(context.Background(), l.trackerDBs.MakeOnlineAccountsIter, 0, false)
	require.NoError(t, err)
	require.Equal(t, genOAHash, catchpointOAHash)
	t.Log("catchpoint onlineaccounts hash", catchpointOAHash, "matches")
	require.Equal(t, genOARows, catchpointOARows)

	catchpointORPHash, catchpointORPRows, err := calculateVerificationHash(context.Background(), l.trackerDBs.MakeOnlineRoundParamsIter, 0, false)
	require.NoError(t, err)
	require.Equal(t, genORPHash, catchpointORPHash)
	t.Log("catchpoint onlineroundparams hash", catchpointORPHash, "matches")
	require.Equal(t, genORPRows, catchpointORPRows)

	oar, err := l.trackerDBs.MakeOnlineAccountsOptimizedReader()
	require.NoError(t, err)

	for i := genDBRound; i >= (genDBRound - 1000); i-- {
		oad, err := oar.LookupOnline(addrs[0], basics.Round(i))
		require.NoError(t, err)
		// block 3 started paying 1 microalgo to addrs[0] per round
		expected := initialStake + uint64(i) - 2
		require.Equal(t, expected, oad.AccountData.MicroAlgos.Raw)
	}

}

// Exercises a sequence of box modifications that caused a bug in
// catchpoint writes.
//
// The problematic sequence of values is:  v1 -> v2 -> v1.  Where each
// box value is:
// * Part of a transaction that does _not_ modify global/local state.
// * Written to `balancesTrie`.
func TestCatchpointAfterBoxTxns(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis()
	cfg := config.GetDefaultLocal()
	proto := protocol.ConsensusFuture
	dl := NewDoubleLedger(t, genBalances, proto, cfg)
	defer dl.Close()

	boxApp := dl.fundedApp(addrs[1], 1_000_000, boxAppSource)
	callBox := txntest.Txn{
		Type:          "appl",
		Sender:        addrs[2],
		ApplicationID: boxApp,
	}

	makeBox := callBox.Args("create", "xxx")
	makeBox.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("xxx")}}
	dl.fullBlock(makeBox)

	setBox := callBox.Args("set", "xxx", strings.Repeat("f", 24))
	setBox.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("xxx")}}
	dl.fullBlock(setBox)

	pay := txntest.Txn{
		Type:     "pay",
		Sender:   addrs[0],
		Receiver: addrs[1],
		Amount:   100000,
	}

	// There are 12 accounts in the NewTestGenesis, plus 1 app account, so we
	// create more so that we have exactly one chunk's worth, to make sure that
	// works without an empty chunk between accounts and kvstore.
	for i := 0; i < (BalancesPerCatchpointFileChunk - 13); i++ {
		newacctpay := pay
		newacctpay.Receiver = ledgertesting.RandomAddress()
		dl.fullBlock(&newacctpay)
	}
	for i := 0; i < 40; i++ {
		dl.fullBlock(pay.Noted(strconv.Itoa(i)))
	}

	resetBox := callBox.Args("set", "xxx", strings.Repeat("z", 24))
	resetBox.Boxes = []transactions.BoxRef{{Index: 0, Name: []byte("xxx")}}
	dl.fullBlock(resetBox)

	for i := 0; i < 40; i++ {
		dl.fullBlock(pay.Noted(strconv.Itoa(i)))
	}

	dl.fullBlock(setBox.Noted("reset back to f's"))
	for i := 0; i < 40; i++ {
		dl.fullBlock(pay.Noted(strconv.Itoa(i)))
	}

	tempDir := t.TempDir()

	catchpointDataFilePath := filepath.Join(tempDir, t.Name()+".data")
	catchpointFilePath := filepath.Join(tempDir, t.Name()+".catchpoint.tar.gz")

	cph := testWriteCatchpoint(t, config.Consensus[proto], dl.generator.trackerDB(), catchpointDataFilePath, catchpointFilePath, 0)
	require.EqualValues(t, 3, cph.TotalChunks)

	l := testNewLedgerFromCatchpoint(t, dl.generator.trackerDB(), catchpointFilePath)
	defer l.Close()

	values, err := l.LookupKeysByPrefix(l.Latest(), "bx:", 10)
	require.NoError(t, err)
	require.Len(t, values, 1)
	v, err := l.LookupKv(l.Latest(), apps.MakeBoxKey(uint64(boxApp), "xxx"))
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("f", 24), string(v))
}
