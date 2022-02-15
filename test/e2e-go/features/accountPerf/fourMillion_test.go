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

package fataccount

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

const numberOfThreads = 256
const printFreequency = 200
const groupTransactions = true
const channelDepth = 100

var maxTxGroupSize int

type psKey struct {
	sk *crypto.SignatureSecrets
	pk basics.Address
}

type txnKey struct {
	sk *crypto.SignatureSecrets
	tx transactions.Transaction
}

func broadcastTransactions(queueWg *sync.WaitGroup, c libgoal.Client, sigTxnChan <-chan *transactions.SignedTxn, errChan chan<- error) {
	for stxn := range sigTxnChan {
		if stxn == nil {
			break
		}
		var err error
		for x := 0; x < 100; x++ { // retry only 50 times
			_, err = c.BroadcastTransaction(*stxn)
			if err == nil {
				break
			}
			fmt.Printf("broadcastTransactions[%d]: %s", x, err)
			time.Sleep(time.Millisecond * 256)
		}
		if err != nil {
			handleError(err, "Error broadcastTransactions", errChan)
		}
	}
	queueWg.Done()
}

func broadcastTransactionGroups(queueWg *sync.WaitGroup, c libgoal.Client, sigTxnGrpChan <-chan []transactions.SignedTxn, errChan chan<- error) {
	for stxns := range sigTxnGrpChan {
		if stxns == nil {
			break
		}
		var err error
		for x := 0; x < 20; x++ { // retry only 20 times
			err = c.BroadcastTransactionGroup(stxns)
			if err == nil {
				break
			}
			fmt.Printf("broadcastTransactionGroups[%d]: %s", x, err)
			time.Sleep(time.Millisecond * 256)
		}
		if err != nil {
			handleError(err, "Error broadcastTransactionGroups", errChan)
		}
	}
	queueWg.Done()
}

func signer(
	sigWg *sync.WaitGroup,
	client libgoal.Client,
	txnChan <-chan *txnKey,
	sigTxnChan chan<- *transactions.SignedTxn,
	errChan chan<- error) {

	for tk := range txnChan {
		if tk == nil {
			continue
		}
		stxn := tk.tx.Sign(tk.sk)
		sigTxnChan <- &stxn
	}
	sigWg.Done()
}

func signerGrpTxn(
	sigWg *sync.WaitGroup,
	client libgoal.Client,
	txnGrpChan <-chan []txnKey,
	sigTxnGrpChan chan<- []transactions.SignedTxn,
	errChan chan<- error) {

	for tGroup := range txnGrpChan {

		// prepare the array of transactions for the group id
		sendTransactions := make([]transactions.Transaction, len(tGroup))
		for i, tk := range tGroup {
			sendTransactions[i] = tk.tx
		}
		// get the group id
		gid, err := client.GroupID(sendTransactions)
		handleError(err, "Error GroupID", errChan)

		// set the group id to each transaction
		for i, _ := range tGroup {
			sendTransactions[i].Group = gid
		}

		// sign the transactions
		stxns := make([]transactions.SignedTxn, len(tGroup))
		for i, tk := range tGroup {
			stxns[i] = sendTransactions[i].Sign(tk.sk)
		}

		sigTxnGrpChan <- stxns
	}
	sigWg.Done()
}

func Test5MAssetsScenario1(t *testing.T) {
	test5MAssets(t, 1)
}

func Test5MAssetsScenario2(t *testing.T) {
	test5MAssets(t, 2)
}

func Test5MAssetsScenario4(t *testing.T) {
	test5MAssets(t, 4)
}

func test5MAssets(t *testing.T, scenario int) {
	partitiontest.PartitionTest(t)

	var fixture fixtures.RestClientFixture
	var sigWg sync.WaitGroup
	var queueWg sync.WaitGroup
	var hkWg sync.WaitGroup
	var errWatcherWg sync.WaitGroup

	maxTxGroupSize = config.Consensus[protocol.ConsensusFuture].MaxTxGroupSize
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "DevModeOneWalletFuture.json"))

	for _, nodeDir := range fixture.NodeDataDirs() {
		cfg, err := config.LoadConfigFromDisk(nodeDir)
		require.NoError(t, err)
		cfg.MaxAccountsAPIResults = 7000000
		cfg.SaveToDisk(nodeDir)
	}
	fixture.Start()

	defer func() {
		hkWg.Wait()
		fixture.Shutdown()
	}()
	client := fixture.LibGoalClient

	accountList, err := fixture.GetWalletsSortedByBalance()
	require.NoError(t, err)
	// get the wallet account
	wAcct := accountList[0].Address

	suggestedParams, err := client.SuggestedParams()
	require.NoError(t, err)
	var genesisHash crypto.Digest
	copy(genesisHash[:], suggestedParams.GenesisHash)
	tLife := config.Consensus[protocol.ConsensusVersion(suggestedParams.ConsensusVersion)].MaxTxnLife

	// fund the non-wallet base account
	ba := generateKeys(1)
	baseAcct := ba[0]
	sender, err := basics.UnmarshalChecksumAddress(wAcct)
	satxn := sendAlgoTransaction(t, 0, sender, baseAcct.pk, 1000000000000000, 1, genesisHash)
	err = signAndBroadcastTransaction(0, &satxn, client, &fixture)
	require.NoError(t, err)

	txnChan := make(chan *txnKey, channelDepth)
	txnGrpChan := make(chan []txnKey, channelDepth)
	sigTxnChan := make(chan *transactions.SignedTxn, channelDepth)
	sigTxnGrpChan := make(chan []transactions.SignedTxn, channelDepth)
	errChan := make(chan error, channelDepth)
	stopChan := make(chan struct{}, 1)

	for nthread := 0; nthread < numberOfThreads; nthread++ {
		sigWg.Add(1)
		if groupTransactions {
			go signerGrpTxn(&sigWg, client, txnGrpChan, sigTxnGrpChan, errChan)
		} else {
			go signer(&sigWg, client, txnChan, sigTxnChan, errChan)
		}
	}

	for nthread := 0; nthread < numberOfThreads; nthread++ {
		queueWg.Add(1)
		if groupTransactions {
			go broadcastTransactionGroups(&queueWg, client, sigTxnGrpChan, errChan)
		} else {
			go broadcastTransactions(&queueWg, client, sigTxnChan, errChan)
		}
	}

	// error handling
	errWatcherWg.Add(1)
	go func() {
		errCount := 0
		for range errChan {
			errCount++
			if errCount > 1000 {
				fmt.Println("Too many errors!")
				stopChan <- struct{}{}
				break
			}
		}
		close(stopChan)
		errWatcherWg.Done()
	}()

	// some housekeeping
	hkWg.Add(1)
	go func() {
		sigWg.Wait()
		close(sigTxnChan)
		close(sigTxnGrpChan)
		queueWg.Wait()
		close(errChan)
		errWatcherWg.Wait()
		hkWg.Done()
	}()

	// Call different scenarios
	switch scenario {
	case 1:
		scenarioA(t, &fixture, baseAcct, genesisHash, txnChan, txnGrpChan, tLife, stopChan)
	case 2:
		scenarioB(t, &fixture, baseAcct, genesisHash, txnChan, txnGrpChan, tLife, stopChan)
	case 4:
		scenarioD(t, &fixture, baseAcct, genesisHash, txnChan, txnGrpChan, tLife, stopChan)

	}
}

func generateKeys(numAccounts int) (keys []psKey) {
	keys = make([]psKey, 0, numAccounts)
	var seed crypto.Seed
	for a := 0; a < numAccounts; a++ {
		crypto.RandBytes(seed[:])
		privateKey := crypto.GenerateSignatureSecrets(seed)
		publicKey := basics.Address(privateKey.SignatureVerifier)
		keys = append(keys, psKey{pk: publicKey, sk: privateKey})
	}
	return
}

func sendAlgoTransaction(
	t *testing.T,
	round uint64,
	sender basics.Address,
	receiver basics.Address,
	amount uint64,
	tLife uint64,
	genesisHash crypto.Digest) (txn transactions.Transaction) {

	txn = transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(round),
			LastValid:   basics.Round(round + tLife),
			GenesisHash: genesisHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: amount},
		},
	}
	return
}

func createAssetTransaction(
	t *testing.T,
	round uint64,
	sender basics.Address,
	tLife uint64,
	amount uint64,
	genesisHash crypto.Digest) (assetTx transactions.Transaction) {

	assetTx = transactions.Transaction{
		Type: protocol.AssetConfigTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(round),
			LastValid:   basics.Round(round + tLife),
			GenesisHash: genesisHash,
		},
		AssetConfigTxnFields: transactions.AssetConfigTxnFields{
			AssetParams: basics.AssetParams{
				Total:         amount,
				DefaultFrozen: false,
				Manager:       sender,
			},
		},
	}
	return
}

func sendAssetTransaction(
	t *testing.T,
	round uint64,
	sender basics.Address,
	tLife uint64,
	genesisHash crypto.Digest,
	assetID basics.AssetIndex,
	receiver basics.Address,
	amount uint64) (tx transactions.Transaction) {

	tx = transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(round),
			LastValid:   basics.Round(round + tLife),
			GenesisHash: genesisHash,
		},
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     assetID,
			AssetAmount:   amount,
			AssetReceiver: receiver,
		},
	}
	return
}

// create 6M unique assets by a different 6,000 accounts, and have a single account opted in, and owning all of them
func scenarioA(
	t *testing.T,
	fixture *fixtures.RestClientFixture,
	baseAcct psKey,
	genesisHash crypto.Digest,
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	tLife uint64,
	stopChan <-chan struct{}) {

	client := fixture.LibGoalClient

	numberOfAccounts := uint64(6000) // 6K
	numberOfAssets := uint64(2000000)     // 6M

	assetsPerAccount := numberOfAssets / numberOfAccounts

	balance := uint64(200000000) // 100300000 for (1002 assets)  99363206259 below min 99363300000 (993632 assets)

	totalAssetAmount := uint64(0)

	defer func() {
		close(txnChan)
		close(txnGrpChan)
	}()

	firstValid := uint64(2)
	counter := uint64(0)
	txnGroup := make([]txnKey, 0, maxTxGroupSize)
	var err error

	fmt.Println("Creating accounts...")

	// create 6K accounts
	keys := generateKeys(int(numberOfAccounts))
	for i, key := range keys {
		select {
		case <-stopChan:
			require.Fail(t, "Test errored")
		default:
		}
		if i%printFreequency == 0 {
			fmt.Println("account create txn: ", i)
		}
		txn := sendAlgoTransaction(t, firstValid, baseAcct.pk, key.pk, balance, tLife, genesisHash)
		counter, txnGroup = queueTransaction(baseAcct.sk, txn, txnChan, txnGrpChan, counter, txnGroup)

		counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
		require.NoError(t, err)
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)

	fmt.Println("Creating assets...")

	// create 6M unique assets by a different 6,000 accounts
	assetAmount := uint64(100)
	for nai, na := range keys {
		for asi := uint64(0); asi < assetsPerAccount; asi++ {
			select {
			case <-stopChan:
				require.Fail(t, "Test errored")
			default:
			}

			if nai%printFreequency == 0 && int(asi)%printFreequency == 0 {
				fmt.Printf("create asset for acct: %d asset %d\n", nai, asi)
			}
			atx := createAssetTransaction(t, firstValid, na.pk, tLife, uint64(600000000)+assetAmount, genesisHash)
			totalAssetAmount += uint64(600000000) + assetAmount
			assetAmount++

			counter, txnGroup = queueTransaction(na.sk, atx, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)

	fmt.Println("Opt-in assets...")

	// have a single account opted in all of them
	ownAllAccount := keys[numberOfAccounts-1]
	// make ownAllAccount very rich
	sendAlgoTx := sendAlgoTransaction(t, firstValid, baseAcct.pk, ownAllAccount.pk, 10000000000000, tLife, genesisHash)
	counter, txnGroup = queueTransaction(baseAcct.sk, sendAlgoTx, txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)

	for acci, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		info, err := client.AccountInformationV2(nacc.pk.String())
		require.NoError(t, err)
		for assi, asset := range *info.Assets {
			select {
			case <-stopChan:
				require.Fail(t, "Test errored")
			default:
			}

			if assi%printFreequency == 0 && acci%printFreequency == 0 {
				fmt.Printf("Accepting assets acct: %d asset %d\n", acci, assi)
			}
			optInT := sendAssetTransaction(
				t,
				firstValid,
				ownAllAccount.pk,
				tLife,
				genesisHash,
				basics.AssetIndex(asset.AssetId),
				ownAllAccount.pk,
				uint64(0))

			counter, txnGroup = queueTransaction(ownAllAccount.sk, optInT, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)

	fmt.Println("Transfer assets...")

	// and owning all of them
	for acci, nacc := range keys {
		if nacc == ownAllAccount {
			continue
		}
		info, err := client.AccountInformationV2(nacc.pk.String())
		require.NoError(t, err)
		for assi, asset := range *info.Assets {
			select {
			case <-stopChan:
				require.False(t, true, "Test interrupted")
			default:
			}

			if assi%printFreequency == 0 && acci%printFreequency == 0 {
				fmt.Printf("Sending assets acct: %d asset %d\n", acci, assi)
			}
			assSend := sendAssetTransaction(
				t,
				firstValid,
				nacc.pk,
				tLife,
				genesisHash,
				basics.AssetIndex(asset.AssetId),
				ownAllAccount.pk,
				asset.Amount)
			counter, txnGroup = queueTransaction(nacc.sk, assSend, txnChan, txnGrpChan, counter, txnGroup)

			counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
			require.NoError(t, err)
		}
	}
	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)
	/*
		// Verify the assets are transfered here
		t0 := time.Now()
		info, err := client.AccountInformationV2(ownAllAccount.pk.String())
		fmt.Printf("AccountInformationV2 retrieval time: %s\n", time.Since(t0).String())
		require.NoError(t, err)
		require.Equal(t, int(numberOfAssets), len(*info.Assets))
		tAssetAmt := uint64(0)
		for _, asset := range *info.Assets {
			tAssetAmt += asset.Amount
		}
		if totalAssetAmount != tAssetAmt {
			fmt.Printf("%d != %d\n", totalAssetAmount, tAssetAmt)
		}
		require.Equal(t, totalAssetAmount, tAssetAmt)
	*/
}

// create 6M unique assets, all created by a single account.
func scenarioB(
	t *testing.T,
	fixture *fixtures.RestClientFixture,
	baseAcct psKey,
	genesisHash crypto.Digest,
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	tLife uint64,
	stopChan <-chan struct{}) {

	//	client := fixture.LibGoalClient

	numberOfAssets := uint64(6000000) // 6M
	totalAssetAmount := uint64(0)

	defer func() {
		close(txnChan)
		close(txnGrpChan)
	}()

	firstValid := uint64(2)
	counter := uint64(0)
	txnGroup := make([]txnKey, 0, maxTxGroupSize)
	var err error

	fmt.Println("Creating accounts...")

	// create 6M unique assets by a single account
	assetAmount := uint64(100)

	for asi := uint64(0); asi < numberOfAssets; asi++ {
		select {
		case <-stopChan:
			require.Fail(t, "Test errored")
		default:
		}

		if int(asi)%printFreequency == 0 {
			fmt.Printf("create asset %d / %d\n", asi, numberOfAssets)
		}
		atx := createAssetTransaction(t, firstValid, baseAcct.pk, tLife, uint64(600000000)+assetAmount, genesisHash)
		totalAssetAmount += uint64(600000000) + assetAmount
		assetAmount++

		counter, txnGroup = queueTransaction(baseAcct.sk, atx, txnChan, txnGrpChan, counter, txnGroup)

		counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
		require.NoError(t, err)
	}

	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)
	/*
		// Verify the assets are transfered here
		t0 := time.Now()
		info, err := client.AccountInformationV2(baseAcct.pk.String())
		fmt.Printf("AccountInformationV2 retrieval time: %s\n", time.Since(t0).String())
		require.NoError(t, err)
		require.Equal(t, int(numberOfAssets), len(*info.Assets))
		tAssetAmt := uint64(0)
		for _, asset := range *info.Assets {
			tAssetAmt += asset.Amount
		}
		if totalAssetAmount != tAssetAmt {
			fmt.Printf("%d != %d\n", totalAssetAmount, tAssetAmt)
		}
		require.Equal(t, totalAssetAmount, tAssetAmt)
	*/
}

// create 6M unique apps by a different 6,000 accounts, and have a single account opted-in all of them. Make an app call to each of them, and make sure the app store some information into the local storage.
//func scenarioC(
// create 6M unique apps by a single account. Opt-into all the applications and make sure the app stores information to both the local and global storage.
func scenarioD(
	t *testing.T,
	fixture *fixtures.RestClientFixture,
	baseAcct psKey,
	genesisHash crypto.Digest,
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	tLife uint64,
	stopChan <-chan struct{}) {

	client := fixture.LibGoalClient

	numberOfApps := uint64(200) // 6M
	defer func() {
		close(txnChan)
		close(txnGrpChan)
	}()

	firstValid := uint64(2)
	counter := uint64(0)
	txnGroup := make([]txnKey, 0, maxTxGroupSize)
	var err error

	globalStateCheck := make([]bool, numberOfApps)
	
	fmt.Println("Creating accounts...")

	// create 6M apps
	for asi := uint64(0); asi < numberOfApps; asi++ {
		select {
		case <-stopChan:
			require.Fail(t, "Test errored")
		default:
		}

		if int(asi)%printFreequency == 0 {
			fmt.Printf("create app %d / %d\n", asi, numberOfApps)
		}
		atx := makeAppTransaction(t, client, asi, firstValid, baseAcct.pk, tLife, genesisHash)
		counter, txnGroup = queueTransaction(baseAcct.sk, atx, txnChan, txnGrpChan, counter, txnGroup)

		counter, firstValid, err = checkPoint(counter, firstValid, tLife, false, fixture)
		require.NoError(t, err)
	}

	counter, txnGroup = flushQueue(txnChan, txnGrpChan, counter, txnGroup)
	counter, firstValid, err = checkPoint(counter, firstValid, tLife, true, fixture)
	require.NoError(t, err)

	// check creator's balance record for the app entry and the state changes
	ad, err := client.AccountData(baseAcct.pk.String())
	require.NoError(t, err)

	appCounter := 0
	a := require.New(t)
	schema := basics.StateSchema{
		NumUint: 1,
	}

	for appIdx, params := range ad.AppParams {
		select {
		case <-stopChan:
			require.Fail(t, "Test errored")
		default:
		}

		if int(appCounter)%printFreequency == 0 {
			fmt.Printf("check app params %d / %d\n", appCounter, numberOfApps)
		}

		a.Equal(schema, params.LocalStateSchema)
		a.Equal(schema, params.GlobalStateSchema)
		a.Equal(1, len(params.GlobalState))
		value, ok := params.GlobalState["counter"]
		a.True(ok)
		a.False(globalStateCheck[value.Uint])
		globalStateCheck[value.Uint] = true

		state, ok := ad.AppLocalStates[appIdx]
		a.True(ok)
		a.Equal(schema, state.Schema)
		a.Equal(1, len(state.KeyValue))
		value, ok = state.KeyValue["counter"]
		a.True(ok)
		a.Equal(uint64(1), value.Uint)
		appCounter++
	}
}

func handleError(err error, message string, errChan chan<- error) {
	if err != nil {
		fmt.Printf("%s: %v\n", message, err)
		select {
		// use select to avoid blocking when the errChan is not interested in messages.
		case errChan <- err:
		default:
		}
	}
}

func checkPoint(counter, firstValid, tLife uint64, force bool, fixture *fixtures.RestClientFixture) (newCounter, nextFirstValid uint64, err error) {
	waitBlock := 5
	lastRound := firstValid + counter - 1
	if force || counter+100 == tLife {
		fmt.Printf("Waiting for round %d...", int(lastRound))
		for x := 0; x < 1000; x++ {
			err := fixture.WaitForRound(lastRound, time.Duration(waitBlock)*time.Second)
			if err == nil {
				fmt.Printf(" waited %d sec, done.\n", (x+1)*waitBlock)
				status, err := fixture.AlgodClient.Status()
				if err != nil {
					return 0, lastRound + 1, nil
				}
				return 0, status.LastRound + 1, nil
			} else {
				fmt.Printf(" waited %d sec, continue waiting...\n", (x+1)*waitBlock)
			}
		}
		fmt.Println("Giving up!")
		return 0, 0, fmt.Errorf("Waited for round %d for %d seconds. Giving up!", firstValid+counter, 1000*waitBlock)
	}
	return counter, firstValid, nil
}

func signAndBroadcastTransaction(
	round uint64,
	txn *transactions.Transaction,
	client libgoal.Client,
	fixture *fixtures.RestClientFixture) error {

	walletHandle, err := client.GetUnencryptedWalletHandle()
	if err != nil {
		return err
	}
	stxn, err := client.SignTransactionWithWallet(walletHandle, nil, *txn)
	if err != nil {
		return err
	}
	_, err = client.BroadcastTransaction(stxn)
	if err != nil {
		return err
	}
	err = fixture.WaitForRound(round, time.Millisecond*2000)
	return err
}

func queueTransaction(
	sk *crypto.SignatureSecrets,
	tx transactions.Transaction,
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	counter uint64,
	txnGroup []txnKey) (uint64, []txnKey) {
	tk := txnKey{tx: tx, sk: sk}

	if !groupTransactions {
		txnChan <- &tk
		return counter + 1, txnGroup
	}
	txnGroup = append(txnGroup, tk)
	if len(txnGroup) == maxTxGroupSize {
		sendTransactions := make([]txnKey, len(txnGroup))
		for i, t := range txnGroup {
			sendTransactions[i] = t
		}

		txnGrpChan <- sendTransactions
		txnGroup = txnGroup[:0]
		return counter + 1, txnGroup
	}
	return counter, txnGroup
}

func flushQueue(
	txnChan chan<- *txnKey,
	txnGrpChan chan<- []txnKey,
	counter uint64,
	txnGroup []txnKey) (uint64, []txnKey) {

	if len(txnGroup) == 0 {
		return counter, txnGroup
	}
	sendTransactions := make([]txnKey, len(txnGroup))
	for i, t := range txnGroup {
		sendTransactions[i] = t
	}
	txnGrpChan <- sendTransactions
	txnGroup = txnGroup[:0]
	return counter + 1, txnGroup
}

func makeAppTransaction(
	t *testing.T,
	client libgoal.Client,
	counter uint64,
	round uint64,
	sender basics.Address,
	tLife uint64,
	genesisHash crypto.Digest) (appTx transactions.Transaction) {

	prog := fmt.Sprintf(`#pragma version 2
// a simple global and local calls counter app
byte b64 Y291bnRlcg== // counter
dup
app_global_get
int %d
+
app_global_put  // update the counter
int 0
int 0
app_opted_in
bnz opted_in
err
opted_in:
int 0  // account idx for app_local_put
byte b64 Y291bnRlcg== // counter
int 0
byte b64 Y291bnRlcg==
app_local_get
int 1  // increment
+
app_local_put
int 1
`, counter)

	approvalOps, err := logic.AssembleString(prog)
	require.NoError(t, err)
	clearstateOps, err := logic.AssembleString("#pragma version 2\nint 1")
	require.NoError(t, err)
	schema := basics.StateSchema{
		NumUint: 1,
	}

	// create the app
	appTx, err = client.MakeUnsignedAppCreateTx(
		transactions.OptInOC, approvalOps.Program, clearstateOps.Program, schema, schema, nil, nil, nil, nil, 0)
	require.NoError(t, err)

	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, counter)

	appTx.Header = transactions.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
		FirstValid:  basics.Round(round),
		LastValid:   basics.Round(round + tLife),
		GenesisHash: genesisHash,
		Note:        note,
	}
	return
}

func makeOptInApp(
	t *testing.T,
	client libgoal.Client,
	appIdx basics.AppIndex,
	round uint64,
	sender basics.Address,
	tLife uint64,
	genesisHash crypto.Digest) (appTx transactions.Transaction) {

	appTx, err := client.MakeUnsignedAppOptInTx(uint64(appIdx), nil, nil, nil, nil)
	require.NoError(t, err)

	appTx.Header = transactions.Header{
		Sender:      sender,
		Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
		FirstValid:  basics.Round(round),
		LastValid:   basics.Round(round + tLife),
		GenesisHash: genesisHash,
	}

	return
}

