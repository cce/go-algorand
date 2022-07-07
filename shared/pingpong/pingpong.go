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

package pingpong

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	v1 "github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util"
)

// CreatablesInfo has information about created assets, apps and opting in
type CreatablesInfo struct {
	AssetParams map[uint64]v1.AssetParams
	AppParams   map[uint64]v1.AppParams
	OptIns      map[uint64][]string
}

// pingPongAccount represents the account state for each account in the pingpong application
// This includes the current balance and public/private keys tied to the account
type pingPongAccount struct {
	deadlock.Mutex
	sk *crypto.SignatureSecrets
	pk basics.Address

	balance      uint64
	balanceRound uint64
}

func (ppa *pingPongAccount) getBalance() uint64 {
	ppa.Lock()
	defer ppa.Unlock()
	return ppa.balance
}

func (ppa *pingPongAccount) setBalance(balance uint64) {
	ppa.Lock()
	defer ppa.Unlock()
	ppa.balance = balance
}

func (ppa *pingPongAccount) addBalance(offset int64) {
	ppa.Lock()
	defer ppa.Unlock()
	ppa.balance = uint64(int64(ppa.balance) + offset)
}

// WorkerState object holds a running pingpong worker
type WorkerState struct {
	cfg        PpConfig
	accounts   map[string]*pingPongAccount
	accountsMu deadlock.RWMutex
	cinfo      CreatablesInfo

	nftStartTime       int64
	localNftIndex      uint64
	nftHolders         map[string]int
	incTransactionSalt uint64

	muSuggestedParams deadlock.Mutex
	suggestedParams   v1.TransactionParams
	pendingTxns       v1.PendingTransactions
}

// PrepareAccounts to set up accounts and asset accounts required for Ping Pong run
func (pps *WorkerState) PrepareAccounts(ac libgoal.Client) (err error) {
	pps.accounts, pps.cfg, err = pps.ensureAccounts(ac, pps.cfg)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ensure accounts failed %v\n", err)
		return
	}
	cfg := pps.cfg

	if cfg.NumAsset > 0 {
		// zero out max amount for asset transactions
		cfg.MaxAmt = 0

		var assetAccounts map[string]*pingPongAccount
		assetAccounts, err = pps.prepareNewAccounts(ac)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "prepare new accounts failed: %v\n", err)
			return
		}

		pps.cinfo.AssetParams, pps.cinfo.OptIns, err = pps.prepareAssets(assetAccounts, ac)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "prepare assets failed %v\n", err)
			return
		}

		if !cfg.Quiet {
			for addr := range assetAccounts {
				if addr != pps.cfg.SrcAccount {
					fmt.Printf("final prepareAccounts, account addr: %s, balance: %d\n", addr, pps.accounts[addr].getBalance())
				}
			}
		}
	} else if cfg.NumApp > 0 {
		var appAccounts map[string]*pingPongAccount
		appAccounts, err = pps.prepareNewAccounts(ac)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "prepare new accounts failed: %v\n", err)
			return
		}
		pps.cinfo.AppParams, pps.cinfo.OptIns, err = pps.prepareApps(appAccounts, ac, cfg)
		if err != nil {
			return
		}
		if !cfg.Quiet {
			for addr := range appAccounts {
				if addr != pps.cfg.SrcAccount {
					fmt.Printf("final prepareAccounts, account addr: %s, balance: %d\n", addr, pps.accounts[addr].getBalance())
				}
			}
		}
	} else {
		// If we have more accounts than requested, pick the top N (not including src)
		if len(pps.accounts) > int(cfg.NumPartAccounts+1) {
			fmt.Printf("Finding the richest %d accounts to use for transacting\n", cfg.NumPartAccounts)
			pps.accounts = takeTopAccounts(pps.accounts, cfg.NumPartAccounts, cfg.SrcAccount)
		} else {
			// Not enough accounts yet (or just enough).  Create more if needed
			fmt.Printf("Not enough accounts - creating %d more\n", int(cfg.NumPartAccounts+1)-len(pps.accounts))
			generateAccounts(pps.accounts, cfg.NumPartAccounts)
		}

		err = pps.fundAccounts(pps.accounts, ac, cfg)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "fund accounts failed %v\n", err)
			return
		}
		go pps.roundMonitor(ac)
	}

	pps.cfg = cfg
	return
}

func (pps *WorkerState) prepareNewAccounts(client libgoal.Client) (newAccounts map[string]*pingPongAccount, err error) {
	// create new accounts for testing
	newAccounts = make(map[string]*pingPongAccount)
	generateAccounts(newAccounts, pps.cfg.NumPartAccounts)
	// copy the source account, as needed.
	if srcAcct, has := pps.accounts[pps.cfg.SrcAccount]; has {
		newAccounts[pps.cfg.SrcAccount] = srcAcct
	}
	pps.accounts = newAccounts

	err = pps.fundAccounts(newAccounts, client, pps.cfg)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "fund accounts failed %v\n", err)
		return
	}

	go pps.roundMonitor(client)
	return
}

// determine the min balance per participant account
func computeAccountMinBalance(client libgoal.Client, cfg PpConfig) (fundingRequiredBalance uint64, runningRequiredBalance uint64, err error) {
	proto, err := getProto(client)
	if err != nil {
		return
	}

	minActiveAccountBalance := proto.MinBalance

	var fee uint64
	if cfg.MaxFee != 0 {
		fee = cfg.MaxFee
	} else {
		// follow the same logic as constructTxn
		fee, err = client.SuggestedFee()
		if err != nil {
			return
		}
		fee *= uint64(cfg.GroupSize)
	}

	if cfg.NumApp > 0 {
		amount := uint64(0)

		runningRequiredBalance = (amount + fee) * 10 * 2
		setupCost := uint64(proto.MaxTxGroupSize) * (uint64(proto.AppFlatParamsMinBalance*2) + fee)
		// todo: add the cfg.NumAppOptIn to the setup cost.
		fundingRequiredBalance = proto.MinBalance + cfg.MinAccountFunds + (amount+fee)*10*2*cfg.TxnPerSec*uint64(math.Ceil(cfg.RefreshTime.Seconds())) + setupCost
		fmt.Printf("required min balance for app accounts: %d\n", fundingRequiredBalance)
		return
	}

	fundingRequiredBalance = minActiveAccountBalance
	runningRequiredBalance = minActiveAccountBalance

	// add cost of assets
	if cfg.NumAsset > 0 {
		assetCost := minActiveAccountBalance*uint64(cfg.NumAsset)*uint64(cfg.NumPartAccounts) + // assets*accounts
			(fee)*uint64(cfg.NumAsset) + // asset creations
			(fee)*uint64(cfg.NumAsset)*uint64(cfg.NumPartAccounts) + // asset opt-ins
			(fee)*uint64(cfg.NumAsset)*uint64(cfg.NumPartAccounts) // asset distributions
		fundingRequiredBalance += assetCost
		runningRequiredBalance += assetCost
	}
	if cfg.NumApp > 0 {
		maxAppsCreated := proto.MaxAppsCreated
		maxAppsOptedIn := proto.MaxAppsOptedIn
		// TODO : given that we've added unlimited app support, we should revise this
		// code so that we'll have control on how many app/account we want to create.
		// for now, I'm going to keep the previous max values until we have refactored this code.
		if maxAppsCreated == 0 {
			maxAppsCreated = config.Consensus[protocol.ConsensusV30].MaxAppsCreated
		}
		if maxAppsOptedIn == 0 {
			maxAppsOptedIn = config.Consensus[protocol.ConsensusV30].MaxAppsOptedIn
		}

		creationCost := uint64(cfg.NumApp) * proto.AppFlatParamsMinBalance * uint64(maxAppsCreated)
		optInCost := uint64(cfg.NumApp) * proto.AppFlatOptInMinBalance * uint64(maxAppsOptedIn)
		maxGlobalSchema := basics.StateSchema{NumUint: proto.MaxGlobalSchemaEntries, NumByteSlice: proto.MaxGlobalSchemaEntries}
		maxLocalSchema := basics.StateSchema{NumUint: proto.MaxLocalSchemaEntries, NumByteSlice: proto.MaxLocalSchemaEntries}
		schemaCost := uint64(cfg.NumApp) * (maxGlobalSchema.MinBalance(&proto).Raw*uint64(maxAppsCreated) +
			maxLocalSchema.MinBalance(&proto).Raw*uint64(maxAppsOptedIn))
		fundingRequiredBalance += creationCost + optInCost + schemaCost
		runningRequiredBalance += creationCost + optInCost + schemaCost
	}
	// add cost of transactions
	fundingRequiredBalance += (cfg.MaxAmt + fee) * 2 * cfg.TxnPerSec * uint64(math.Ceil(cfg.RefreshTime.Seconds()))

	// override computed value if less than configured value
	if cfg.MinAccountFunds > fundingRequiredBalance {
		fundingRequiredBalance = cfg.MinAccountFunds
	}

	return
}

// Wait for `*nextSendTime` and update it afterwards.
func schedule(tps uint64, nextSendTime *time.Time) {
	dur := time.Until(*nextSendTime)
	if dur > 0 {
		time.Sleep(dur)
	}

	*nextSendTime = nextSendTime.Add(time.Second / time.Duration(tps))
}

func (pps *WorkerState) fundAccounts(accounts map[string]*pingPongAccount, client libgoal.Client, cfg PpConfig) error {
	var srcFunds, minFund uint64
	var err error
	var tx transactions.Transaction
	srcFunds, err = client.GetBalance(cfg.SrcAccount)

	if err != nil {
		return err
	}

	var totalSent uint64

	// Fee of 0 will make cause the function to use the suggested one by network
	fee := uint64(0)

	minFund, _, err = computeAccountMinBalance(client, cfg)
	if err != nil {
		return err
	}
	fmt.Printf("adjusting account balance to %d\n", minFund)

	srcAcct := accounts[cfg.SrcAccount]

	nextSendTime := time.Now()
	for {
		accountsAdjusted := 0
		adjStart := time.Now()
		for addr, acct := range accounts {
			if addr == pps.cfg.SrcAccount {
				continue
			}
		repeat:
			if acct.getBalance() >= minFund {
				continue
			}
			if !cfg.Quiet {
				fmt.Printf("adjusting balance of account %v\n", addr)
			}
			toSend := minFund - acct.getBalance()
			if srcFunds <= toSend {
				return fmt.Errorf("source account %s has insufficient funds %d - needs %d", cfg.SrcAccount, srcFunds, toSend)
			}
			srcFunds -= toSend
			if !cfg.Quiet {
				fmt.Printf("adjusting balance of account %v by %d\n ", addr, toSend)
			}

			schedule(cfg.TxnPerSec, &nextSendTime)
			tx, err = pps.sendPaymentFromSourceAccount(client, addr, fee, toSend, srcAcct)
			if err != nil {
				if strings.Contains(err.Error(), "broadcast queue full") {
					fmt.Printf("failed to send payment, broadcast queue full. sleeping & retrying.\n")
					waitForNextRoundOrSleep(client, 500*time.Millisecond)
					goto repeat
				}
				return err
			}
			srcFunds -= tx.Fee.Raw
			accountsAdjusted++
			if !cfg.Quiet {
				fmt.Printf("account balance for key %s will be %d\n", addr, minFund)
			}
			acct.setBalance(minFund)
			totalSent++
		}
		accounts[cfg.SrcAccount].setBalance(srcFunds)
		waitStart := time.Now()
		// wait until all the above transactions are sent, or that we have no more transactions
		// in our pending transaction pool coming from the source account.
		err = waitPendingTransactions([]string{cfg.SrcAccount}, client)
		if err != nil {
			return err
		}
		waitStop := time.Now()
		if !cfg.Quiet {
			fmt.Printf("%d sent (%s); waited %s\n", accountsAdjusted, waitStart.Sub(adjStart).String(), waitStop.Sub(waitStart).String())
		}
		if accountsAdjusted == 0 {
			break
		}
	}
	return err
}

func (pps *WorkerState) sendPaymentFromSourceAccount(client libgoal.Client, to string, fee, amount uint64, srcAcct *pingPongAccount) (transactions.Transaction, error) {
	// generate a unique note to avoid duplicate transaction failures
	note := pps.makeNextUniqueNoteField()

	var txn transactions.Transaction
	var stxn transactions.SignedTxn
	var err error
	txn, err = client.ConstructPayment(srcAcct.pk.String(), to, fee, amount, note, "", [32]byte{}, 0, 0)

	if err != nil {
		return transactions.Transaction{}, err
	}

	stxn, err = signTxn(srcAcct, txn, pps.cfg)

	if err != nil {
		return transactions.Transaction{}, err
	}

	_, err = client.BroadcastTransaction(stxn)
	if err != nil {
		return transactions.Transaction{}, err
	}

	return txn, nil
}

// waitPendingTransactions waits until all the pending transactions coming from the given
// accounts map have been cleared out of the transaction pool. A prerequesite for this is that
// there is no other source who might be generating transactions that would come from these account
// addresses.
func waitPendingTransactions(accounts []string, client libgoal.Client) error {
	for _, from := range accounts {
	repeat:
		pendingTxns, err := client.GetPendingTransactionsByAddress(from, 0)
		if err != nil {
			fmt.Printf("failed to check pending transaction pool status : %v\n", err)
			return err
		}
		for _, txn := range pendingTxns.TruncatedTxns.Transactions {
			if txn.From != from {
				// we found a transaction where the receiver was the given account. We don't
				// care about these.
				continue
			}
			// the transaction is still in the transaction pool.
			// this would wait for the next round, when we will perform the check again.
			waitForNextRoundOrSleep(client, 500*time.Millisecond)
			goto repeat
		}
	}
	return nil
}

func (pps *WorkerState) refreshAccounts(client libgoal.Client, cfg PpConfig) error {
	pps.accountsMu.Lock()
	addrs := make([]string, 0, len(pps.accounts))
	for addr := range pps.accounts {
		addrs = append(addrs, addr)
	}
	pps.accountsMu.Unlock()
	// wait until all the pending transactions have been sent; otherwise, getting the balance
	// is pretty much meaningless.
	fmt.Printf("waiting for all transactions to be accepted before refreshing accounts.\n")
	err := waitPendingTransactions(addrs, client)
	if err != nil {
		return err
	}

	balanceUpdates := make(map[string]uint64, len(addrs))
	for _, addr := range addrs {
		amount, err := client.GetBalance(addr)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error refreshAccounts: %v\n", err)
			return err
		}
		balanceUpdates[addr] = amount
	}

	pps.accountsMu.Lock()
	defer pps.accountsMu.Unlock()
	for addr, amount := range balanceUpdates {
		pps.accounts[addr].setBalance(amount)
	}

	return pps.fundAccounts(pps.accounts, client, cfg)
}

// return a shuffled list of accounts with some minimum balance
func listSufficientAccounts(accounts map[string]*pingPongAccount, minimumAmount uint64, except string) []string {
	out := make([]string, 0, len(accounts))
	for key, value := range accounts {
		if key == except {
			continue
		}
		if value.getBalance() >= minimumAmount {
			out = append(out, key)
		}
	}
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

var logPeriod = 5 * time.Second

// RunPingPong starts ping pong process
func (pps *WorkerState) RunPingPong(ctx context.Context, ac libgoal.Client) {
	// Infinite loop given:
	//  - accounts -> map of accounts to include in transfers (including src account, which we don't want to use)
	//  - cfg      -> configuration for how to proceed
	// LOOP {
	// 		for time.Now() < StopRunTime
	//			FromList = Randomize list of accounts
	//			ToList = Randomize list of accounts
	//			for i, from := range FromList
	//				Send(from, ToList[i], CalcAmount, CalcFee)
	//			If DelayBetween != 0 { sleep(delay) }
	//		If RestTime > 0 { sleep(RestTime) }
	//		If time-to-refresh
	//			accounts, cfg, err = PrepareAccounts()
	//			error = fundAccounts()
	//  }

	cfg := pps.cfg
	var runTime time.Duration
	if cfg.RunTime > 0 {
		runTime = cfg.RunTime
	} else {
		runTime = 10000 * time.Hour // Effectively 'forever'
	}
	var endTime time.Time
	if cfg.MaxRuntime > 0 {
		endTime = time.Now().Add(cfg.MaxRuntime)
	}
	refreshTime := time.Now().Add(cfg.RefreshTime)

	var nftThrottler *throttler
	if pps.cfg.NftAsaPerSecond > 0 {
		nftThrottler = newThrottler(20, float64(pps.cfg.NftAsaPerSecond))
	}

	lastLog := time.Now()
	nextLog := lastLog.Add(logPeriod)

	nextSendTime := time.Now()
	for {
		if ctx.Err() != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error bad context in RunPingPong: %v\n", ctx.Err())
			break
		}
		startTime := time.Now()
		stopTime := startTime.Add(runTime)

		var totalSent, totalSucceeded, lastTotalSent uint64
		for {
			now := time.Now()
			if now.After(stopTime) {
				break
			}
			if now.After(nextLog) {
				dt := now.Sub(lastLog)
				fmt.Printf("%d sent, %0.2f/s (%d total)\n", totalSent-lastTotalSent, float64(totalSent-lastTotalSent)/dt.Seconds(), totalSent)
				lastTotalSent = totalSent
				for now.After(nextLog) {
					nextLog = nextLog.Add(logPeriod)
				}
				lastLog = now
			}

			if cfg.MaxRuntime > 0 && time.Now().After(endTime) {
				fmt.Printf("Terminating after max run time of %.f seconds\n", cfg.MaxRuntime.Seconds())
				return
			}

			if pps.cfg.NftAsaPerSecond > 0 {
				sent, err := pps.makeNftTraffic(ac)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error sending nft transactions: %v\n", err)
				}
				nftThrottler.maybeSleep(int(sent))
				totalSent += sent
				continue
			}

			minimumAmount := cfg.MinAccountFunds + (cfg.MaxAmt+cfg.MaxFee)*2
			pps.accountsMu.RLock()
			fromList := listSufficientAccounts(pps.accounts, minimumAmount, cfg.SrcAccount)
			pps.accountsMu.RUnlock()
			// in group tests txns are sent back and forth, so both parties need funds
			var toList []string
			if cfg.GroupSize == 1 {
				minimumAmount = 0
				pps.accountsMu.RLock()
				toList = listSufficientAccounts(pps.accounts, minimumAmount, cfg.SrcAccount)
				pps.accountsMu.RUnlock()
			} else {
				// same selection with another shuffle
				toList = make([]string, len(fromList))
				copy(toList, fromList)
				rand.Shuffle(len(toList), func(i, j int) { toList[i], toList[j] = toList[j], toList[i] })
			}

			sent, succeeded, err := pps.sendFromTo(fromList, toList, ac, &nextSendTime)
			totalSent += sent
			totalSucceeded += succeeded
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "error sending transactions: %v\n", err)
			}

			if cfg.RefreshTime > 0 && time.Now().After(refreshTime) {
				err = pps.refreshAccounts(ac, cfg)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "error refreshing: %v\n", err)
				}

				refreshTime = refreshTime.Add(cfg.RefreshTime)
			}
		}

		timeDelta := time.Since(startTime)
		_, _ = fmt.Fprintf(os.Stdout, "Sent %d transactions (%d attempted) in %d seconds\n", totalSucceeded, totalSent, int(math.Round(timeDelta.Seconds())))
	}
}

// NewPingpong creates a new pingpong WorkerState
func NewPingpong(cfg PpConfig) *WorkerState {
	return &WorkerState{cfg: cfg, nftHolders: make(map[string]int)}
}

func randomizeCreatableID(cfg PpConfig, cinfo CreatablesInfo) (aidx uint64) {
	if cfg.NumAsset > 0 {
		rindex := rand.Intn(len(cinfo.AssetParams))
		i := 0
		for k := range cinfo.AssetParams {
			if i == rindex {
				aidx = k
				break
			}
			i++
		}
	} else if cfg.NumApp > 0 {
		rindex := rand.Intn(len(cinfo.AppParams))
		i := 0
		for k := range cinfo.AppParams {
			if i == rindex {
				aidx = k
				break
			}
			i++
		}
	}
	return
}

func (pps *WorkerState) fee() uint64 {
	cfg := pps.cfg
	fee := cfg.MaxFee
	if cfg.RandomizeFee {
		fee = rand.Uint64()%(cfg.MaxFee-cfg.MinFee) + cfg.MinFee
	}
	return fee
}

func (pps *WorkerState) makeNftTraffic(client libgoal.Client) (sentCount uint64, err error) {
	fee := pps.fee()
	var srcCost uint64
	if (len(pps.nftHolders) == 0) || ((float64(int(pps.cfg.NftAsaAccountInFlight)-len(pps.nftHolders)) / float64(pps.cfg.NftAsaAccountInFlight)) >= rand.Float64()) {
		var addr string

		var seed [32]byte
		crypto.RandBytes(seed[:])
		privateKey := crypto.GenerateSignatureSecrets(seed)
		publicKey := basics.Address(privateKey.SignatureVerifier)

		pps.accountsMu.Lock()
		pps.accounts[publicKey.String()] = &pingPongAccount{
			sk: privateKey,
			pk: publicKey,
		}
		pps.accountsMu.Unlock()
		addr = publicKey.String()

		fmt.Printf("new NFT holder %s\n", addr)
		var proto config.ConsensusParams
		proto, err = getProto(client)
		if err != nil {
			return
		}
		// enough for the per-asa minbalance and more than enough for the txns to create them
		toSend := proto.MinBalance * uint64(pps.cfg.NftAsaPerAccount+1) * 2
		pps.nftHolders[addr] = 0
		var tx transactions.Transaction
		srcAcct := pps.acct(pps.cfg.SrcAccount)
		tx, err = pps.sendPaymentFromSourceAccount(client, addr, fee, toSend, srcAcct)
		if err != nil {
			return
		}
		srcCost += tx.Fee.Raw + toSend
		sentCount++
		// we ran one txn above already to fund the new addr,
		// we'll run a second txn below
	}
	pps.accountsMu.Lock()
	pps.accounts[pps.cfg.SrcAccount].addBalance(-int64(srcCost))
	pps.accountsMu.Unlock()
	// pick a random sender from nft holder sub accounts
	pick := rand.Intn(len(pps.nftHolders))
	pos := 0
	var sender string
	var senderNftCount int
	for addr, nftCount := range pps.nftHolders {
		sender = addr
		senderNftCount = nftCount
		if pos == pick {
			break
		}
		pos++

	}
	var meta [32]byte
	rand.Read(meta[:])
	assetName := pps.nftSpamAssetName()
	const totalSupply = 1
	txn, err := client.MakeUnsignedAssetCreateTx(totalSupply, false, sender, sender, sender, sender, "ping", assetName, "", meta[:], 0)
	if err != nil {
		fmt.Printf("Cannot make asset create txn with meta %v\n", meta)
		return
	}
	txn, err = client.FillUnsignedTxTemplate(sender, 0, 0, pps.cfg.MaxFee, txn)
	if err != nil {
		fmt.Printf("Cannot fill asset creation txn\n")
		return
	}
	if senderNftCount+1 >= int(pps.cfg.NftAsaPerAccount) {
		delete(pps.nftHolders, sender)
	} else {
		pps.nftHolders[sender] = senderNftCount + 1
	}
	signer := pps.acct(sender)
	stxn, err := signTxn(signer, txn, pps.cfg)
	if err != nil {
		return
	}

	_, err = client.BroadcastTransaction(stxn)
	if err != nil {
		return
	}
	sentCount++
	return
}

func (pps *WorkerState) acct(from string) *pingPongAccount {
	pps.accountsMu.RLock()
	defer pps.accountsMu.RUnlock()
	return pps.accounts[from]
}

func (pps *WorkerState) sendFromTo(
	fromList, toList []string,
	client libgoal.Client, nextSendTime *time.Time,
) (sentCount, successCount uint64, err error) {
	cinfo := pps.cinfo
	cfg := pps.cfg

	amt := cfg.MaxAmt
	var minAccountRunningBalance uint64
	_, minAccountRunningBalance, err = computeAccountMinBalance(client, cfg)
	if err != nil {
		return 0, 0, err
	}
	belowMinBalanceAccounts := make(map[string] /*basics.Address*/ bool)

	assetsByCreator := make(map[string][]*v1.AssetParams)
	for _, p := range cinfo.AssetParams {
		c := p.Creator
		ap := &v1.AssetParams{}
		*ap = p
		assetsByCreator[c] = append(assetsByCreator[c], ap)
	}
	for i, from := range fromList {

		// keep going until the balances of at least 20% of the accounts is too low.
		if len(belowMinBalanceAccounts)*5 > len(fromList) {
			fmt.Printf("quitting sendFromTo: too many accounts below threshold")
			return
		}

		if belowMinBalanceAccounts[from] {
			continue
		}

		if cfg.RandomizeAmt {
			amt = ((rand.Uint64() % cfg.MaxAmt) + 1) % cfg.MaxAmt
		}

		fee := pps.fee()

		to := toList[i]
		if cfg.RandomizeDst {
			var addr basics.Address
			crypto.RandBytes(addr[:])
			to = addr.String()
		} else if len(belowMinBalanceAccounts) > 0 && (crypto.RandUint64()%100 < 50) {
			// make 50% of the calls attempt to refund low-balanced accounts.
			// ( if there is any )
			// pick the first low balance account
			for acct := range belowMinBalanceAccounts {
				to = acct
				break
			}
		}

		// Broadcast transaction
		var sendErr error
		fromBalanceChange := int64(0)
		toBalanceChange := int64(0)
		if cfg.NumAsset > 0 {
			amt = 1
		} else if cfg.NumApp > 0 {
			amt = 0
		}

		fromAcct := pps.acct(from)
		if cfg.GroupSize == 1 {
			// generate random assetID or appId if we send asset/app txns
			aidx := randomizeCreatableID(cfg, cinfo)
			var txn transactions.Transaction
			var consErr error
			// Construct single txn
			txn, from, consErr = pps.constructTxn(from, to, fee, amt, aidx, client)
			if consErr != nil {
				err = consErr
				_, _ = fmt.Fprintf(os.Stderr, "constructTxn failed: %v\n", err)
				return
			}

			// would we have enough money after taking into account the current updated fees ?
			if fromAcct.getBalance() <= (txn.Fee.Raw + amt + minAccountRunningBalance) {
				_, _ = fmt.Fprintf(os.Stdout, "Skipping sending %d: %s -> %s; Current cost too high(%d <= %d + %d  + %d).\n", amt, from, to, fromAcct.getBalance(), txn.Fee.Raw, amt, minAccountRunningBalance)
				belowMinBalanceAccounts[from] = true
				continue
			}

			fromBalanceChange = -int64(txn.Fee.Raw + amt)
			toBalanceChange = int64(amt)

			// Sign txn
			signer := pps.acct(from)
			stxn, signErr := signTxn(signer, txn, cfg)
			if signErr != nil {
				err = signErr
				_, _ = fmt.Fprintf(os.Stderr, "signTxn failed: %v\n", err)
				return
			}

			schedule(cfg.TxnPerSec, nextSendTime)
			sentCount++
			_, sendErr = client.BroadcastTransaction(stxn)
		} else {
			// Generate txn group

			// In rekeying test there are two txns sent in a group
			// the first is  from -> to with RekeyTo=to
			// the second is from -> to with RekeyTo=from and AuthAddr=to
			// So that rekeying test only supports groups of two

			var txGroup []transactions.Transaction
			var txSigners []string
			for j := 0; j < int(cfg.GroupSize); j++ {
				var txn transactions.Transaction
				var signer string
				if j%2 == 0 {
					txn, signer, err = pps.constructTxn(from, to, fee, amt, 0, client)
					fromBalanceChange -= int64(txn.Fee.Raw + amt)
					toBalanceChange += int64(amt)
				} else if cfg.GroupSize == 2 && cfg.Rekey {
					txn, _, err = pps.constructTxn(from, to, fee, amt, 0, client)
					fromBalanceChange -= int64(txn.Fee.Raw + amt)
					toBalanceChange += int64(amt)
					signer = to
				} else {
					txn, signer, err = pps.constructTxn(to, from, fee, amt, 0, client)
					toBalanceChange -= int64(txn.Fee.Raw + amt)
					fromBalanceChange += int64(amt)
				}
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "group tx failed: %v\n", err)
					return
				}
				if cfg.RandomizeAmt && j%2 == 1 {
					amt = rand.Uint64()%cfg.MaxAmt + 1
				}
				if cfg.Rekey {
					if from == signer {
						// rekey to the receiver the first txn of the rekeying pair
						txn.RekeyTo, err = basics.UnmarshalChecksumAddress(to)
					} else {
						// rekey to the sender the second txn of the rekeying pair
						txn.RekeyTo, err = basics.UnmarshalChecksumAddress(from)
					}
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "Address unmarshalling failed: %v\n", err)
						return
					}
				}
				txGroup = append(txGroup, txn)
				txSigners = append(txSigners, signer)
			}

			// would we have enough money after taking into account the current updated fees ?
			if int64(fromAcct.getBalance())+fromBalanceChange <= int64(cfg.MinAccountFunds) {
				_, _ = fmt.Fprintf(os.Stdout, "Skipping sending %d : %s -> %s; Current cost too high.\n", amt, from, to)
				continue
			}
			toAcct := pps.acct(to)
			if int64(toAcct.getBalance())+toBalanceChange <= int64(cfg.MinAccountFunds) {
				_, _ = fmt.Fprintf(os.Stdout, "Skipping sending back %d : %s -> %s; Current cost too high.\n", amt, to, from)
				continue
			}

			// Generate group ID
			gid, gidErr := client.GroupID(txGroup)
			if gidErr != nil {
				err = gidErr
				return
			}

			if !cfg.Quiet {
				_, _ = fmt.Fprintf(os.Stdout, "Sending TxnGroup: ID %v, size %v \n", gid, len(txGroup))
			}

			// Sign each transaction
			stxGroup := make([]transactions.SignedTxn, len(txGroup))
			var signErr error
			for j, txn := range txGroup {
				txn.Group = gid
				signer := pps.acct(txSigners[j])
				stxGroup[j], signErr = signTxn(signer, txn, cfg)
				if signErr != nil {
					err = signErr
					return
				}
			}

			schedule(cfg.TxnPerSec, nextSendTime)
			sentCount++
			sendErr = client.BroadcastTransactionGroup(stxGroup)
		}

		if sendErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error sending Transaction, sleeping .5 seconds: %v\n", sendErr)
			err = sendErr
			time.Sleep(500 * time.Millisecond)
			return
		}

		successCount++
		fromAcct.addBalance(fromBalanceChange)
		// avoid updating the "to" account.

	}
	return
}

func (pps *WorkerState) nftSpamAssetName() string {
	if pps.nftStartTime == 0 {
		pps.nftStartTime = time.Now().Unix()
	}
	pps.localNftIndex++
	return fmt.Sprintf("nft%d_%d", pps.nftStartTime, pps.localNftIndex)
}
func (pps *WorkerState) makeNextUniqueNoteField() []byte {
	noteField := make([]byte, binary.MaxVarintLen64)
	usedBytes := binary.PutUvarint(noteField, pps.incTransactionSalt)
	pps.incTransactionSalt++
	return noteField[:usedBytes]
}

func (pps *WorkerState) roundMonitor(client libgoal.Client) {
	var minFund uint64
	var err error
	for {
		minFund, _, err = computeAccountMinBalance(client, pps.cfg)
		if err == nil {
			break
		}
	}
	var newBalance uint64
	for {
		paramsResp, err := client.SuggestedParams()
		if err != nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		pendingTxns, err := client.GetPendingTransactions(0)
		if err != nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		pps.muSuggestedParams.Lock()
		pps.suggestedParams = paramsResp
		pps.pendingTxns = pendingTxns
		pps.muSuggestedParams.Unlock()

		// take a quick snapshot of accounts to decrease mutex shadow
		pps.accountsMu.Lock()
		accountsSnapshot := make([]*pingPongAccount, 0, len(pps.accounts))
		for _, acct := range pps.accounts {
			accountsSnapshot = append(accountsSnapshot, acct)
		}
		pps.accountsMu.Unlock()

		for _, acct := range accountsSnapshot {
			acct.Lock()
			needRefresh := acct.balance < minFund && acct.balanceRound < paramsResp.LastRound
			acct.Unlock()
			if needRefresh {
				newBalance, err = client.GetBalance(acct.pk.String())
				if err == nil {
					acct.Lock()
					acct.balanceRound, acct.balance = paramsResp.LastRound, newBalance
					acct.Unlock()
				}
			}
		}

		// wait for the next round.
		waitForNextRoundOrSleep(client, 200*time.Millisecond)
	}
}

func (pps *WorkerState) getSuggestedParams() v1.TransactionParams {
	pps.muSuggestedParams.Lock()
	defer pps.muSuggestedParams.Unlock()
	return pps.suggestedParams
}

func (pps *WorkerState) constructTxn(from, to string, fee, amt, aidx uint64, client libgoal.Client) (txn transactions.Transaction, sender string, err error) {
	cfg := pps.cfg
	cinfo := pps.cinfo
	sender = from
	var noteField []byte
	const pingpongTag = "pingpong"
	const tagLen = len(pingpongTag)
	// if random note flag set, then append a random number of additional bytes
	if cfg.RandomNote {
		const maxNoteFieldLen = 1024
		noteLength := tagLen + int(rand.Uint32())%(maxNoteFieldLen-tagLen)
		noteField = make([]byte, noteLength)
		copy(noteField, pingpongTag)
		crypto.RandBytes(noteField[tagLen:])
	} else {
		noteField = pps.makeNextUniqueNoteField()
	}

	// if random lease flag set, fill the lease field with random bytes
	var lease [32]byte
	if cfg.RandomLease {
		crypto.RandBytes(lease[:])
	}

	if cfg.NumApp > 0 { // Construct app transaction
		// select opted-in accounts for Txn.Accounts field
		var accounts []string
		assetOptIns := cinfo.OptIns[aidx]
		if len(assetOptIns) > 0 {
			indices := rand.Perm(len(assetOptIns))
			limit := 5
			if len(indices) < limit {
				limit = len(indices)
			}
			for i := 0; i < limit; i++ {
				idx := indices[i]
				accounts = append(accounts, assetOptIns[idx])
			}
			if cinfo.AssetParams[aidx].Creator == from {
				// if the application was created by the "from" account, then we don't need to worry about it being opted-in.
			} else {
				fromIsOptedIn := false
				for i := 0; i < len(assetOptIns); i++ {
					if assetOptIns[i] == from {
						fromIsOptedIn = true
						break
					}
				}
				if !fromIsOptedIn {
					sender = accounts[0]
					from = sender
				}
			}
			accounts = accounts[1:]
		}
		txn, err = client.MakeUnsignedAppNoOpTx(aidx, nil, accounts, nil, nil)
		if err != nil {
			return
		}
		txn.Note = noteField[:]
		txn.Lease = lease
		txn, err = client.FillUnsignedTxTemplate(from, 0, 0, cfg.MaxFee, txn)
		if !cfg.Quiet {
			_, _ = fmt.Fprintf(os.Stdout, "Calling app %d : %s\n", aidx, from)
		}
	} else if cfg.NumAsset > 0 { // Construct asset transaction
		// select a pair of random opted-in accounts by aidx
		// use them as from/to addresses
		if from != to {
			if len(cinfo.OptIns[aidx]) > 0 {
				indices := rand.Perm(len(cinfo.OptIns[aidx]))
				from = cinfo.OptIns[aidx][indices[0]]
				to = cinfo.OptIns[aidx][indices[1]]
				sender = from
			} else {
				err = fmt.Errorf("asset %d has not been opted in by any account", aidx)
				_, _ = fmt.Fprintf(os.Stdout, "error constructing transaction - %v\n", err)
				return
			}
		}
		txn, err = client.MakeUnsignedAssetSendTx(aidx, amt, to, "", "")
		if err != nil {
			_, _ = fmt.Fprintf(os.Stdout, "error making unsigned asset send tx %v\n", err)
			return
		}
		txn.Note = noteField[:]
		txn.Lease = lease
		txn, err = client.FillUnsignedTxTemplate(sender, 0, 0, cfg.MaxFee, txn)
		if !cfg.Quiet {
			_, _ = fmt.Fprintf(os.Stdout, "Sending %d asset %d: %s -> %s\n", amt, aidx, sender, to)
		}
	} else {
		txn, err = client.ConstructPayment(from, to, fee, amt, noteField, "", lease, 0, 0)
		if !cfg.Quiet {
			_, _ = fmt.Fprintf(os.Stdout, "Sending %d : %s -> %s\n", amt, from, to)
		}
	}

	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "error constructing transaction %v\n", err)
		return
	}
	// adjust transaction duration for 5 rounds. That would prevent it from getting stuck in the transaction pool for too long.
	txn.LastValid = txn.FirstValid + 5

	// if cfg.MaxFee == 0, automatically adjust the fee amount to required min fee
	if cfg.MaxFee == 0 {
		var suggestedFee uint64
		suggestedFee, err = client.SuggestedFee()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stdout, "error retrieving suggestedFee: %v\n", err)
			return
		}
		if suggestedFee > txn.Fee.Raw {
			txn.Fee.Raw = suggestedFee
		}
	}
	return
}

func signTxn(signer *pingPongAccount, txn transactions.Transaction, cfg PpConfig) (stxn transactions.SignedTxn, err error) {

	var psig crypto.Signature

	if cfg.Rekey {
		stxn, err = txn.Sign(signer.sk), nil

	} else if len(cfg.Program) > 0 {
		// If there's a program, sign it and use that in a lsig
		progb := logic.Program(cfg.Program)
		psig = signer.sk.Sign(&progb)

		// Fill in signed transaction
		stxn.Txn = txn
		stxn.Lsig.Logic = cfg.Program
		stxn.Lsig.Sig = psig
		stxn.Lsig.Args = cfg.LogicArgs
	} else {

		// Otherwise, just sign the transaction like normal
		stxn, err = txn.Sign(signer.sk), nil
	}
	return
}

type timeCount struct {
	when  time.Time
	count int
}

type throttler struct {
	times []timeCount

	next int

	// target x per-second
	xps float64

	// rough proportional + integral control
	iterm float64
}

func newThrottler(windowSize int, targetPerSecond float64) *throttler {
	return &throttler{times: make([]timeCount, windowSize), xps: targetPerSecond, iterm: 0.0}
}

func (t *throttler) maybeSleep(count int) {
	now := time.Now()
	t.times[t.next].when = now
	t.times[t.next].count = count
	nn := (t.next + 1) % len(t.times)
	t.next = nn
	if t.times[nn].when.IsZero() {
		return
	}
	dt := now.Sub(t.times[nn].when)
	countsum := 0
	for i, tc := range t.times {
		if i != nn {
			countsum += tc.count
		}
	}
	rate := float64(countsum) / dt.Seconds()
	if rate > t.xps {
		// rate too high, slow down
		desiredSeconds := float64(countsum) / t.xps
		extraSeconds := desiredSeconds - dt.Seconds()
		t.iterm += 0.1 * extraSeconds / float64(len(t.times))
		util.NanoSleep(time.Duration(1000000000.0 * (extraSeconds + t.iterm) / float64(len(t.times))))

	} else {
		t.iterm *= 0.95
	}
}
