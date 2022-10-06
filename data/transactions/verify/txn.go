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

package verify

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
	"github.com/algorand/go-algorand/util/metrics"
)

var logicGoodTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_ledger_logic_ok", Description: "Total transaction scripts executed and accepted"})
var logicRejTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_ledger_logic_rej", Description: "Total transaction scripts executed and rejected"})
var logicErrTotal = metrics.MakeCounter(metrics.MetricName{Name: "algod_ledger_logic_err", Description: "Total transaction scripts executed and errored"})

// ErrInvalidSignature is the error returned to report that at least one signature is invalid
var ErrInvalidSignature = errors.New("At least one signature didn't pass verification")

// The PaysetGroups is taking large set of transaction groups and attempt to verify their validity using multiple go-routines.
// When doing so, it attempts to break these into smaller "worksets" where each workset takes about 2ms of execution time in order
// to avoid context switching overhead while providing good validation cancelation responsiveness. Each one of these worksets is
// "populated" with roughly txnPerWorksetThreshold transactions. ( note that the real evaluation time is unknown, but benchmarks
// show that these are realistic numbers )
const txnPerWorksetThreshold = 32

// When the PaysetGroups is generating worksets, it enqueues up to concurrentWorksets entries to the execution pool. This serves several
// purposes :
// - if the verification task need to be aborted, there are only concurrentWorksets entries that are currently redundant on the execution pool queue.
// - that number of concurrent tasks would not get beyond the capacity of the execution pool back buffer.
// - if we were to "redundantly" execute all these during context cancelation, we would spent at most 2ms * 16 = 32ms time.
// - it allows us to linearly scan the input, and process elements only once we're going to queue them into the pool.
const concurrentWorksets = 16

// GroupContext is the set of parameters external to a transaction which
// stateless checks are performed against.
//
// For efficient caching, these parameters should either be constant
// or change slowly over time.
//
// Group data are omitted because they are committed to in the
// transaction and its ID.
type GroupContext struct {
	specAddrs        transactions.SpecialAddresses
	consensusVersion protocol.ConsensusVersion
	consensusParams  config.ConsensusParams
	minAvmVersion    uint64
	signedGroupTxns  []transactions.SignedTxn
	ledger           logic.LedgerForSignature
}

// PrepareGroupContext prepares a verification group parameter object for a given transaction
// group.
func PrepareGroupContext(group []transactions.SignedTxn, contextHdr bookkeeping.BlockHeader, ledger logic.LedgerForSignature) (*GroupContext, error) {
	if len(group) == 0 {
		return nil, nil
	}
	consensusParams, ok := config.Consensus[contextHdr.CurrentProtocol]
	if !ok {
		return nil, protocol.Error(contextHdr.CurrentProtocol)
		//		return nil, fmt.Errorf("Unsupported protocol: %w", protocol.Error(contextHdr.CurrentProtocol))
	}
	return &GroupContext{
		specAddrs: transactions.SpecialAddresses{
			FeeSink:     contextHdr.FeeSink,
			RewardsPool: contextHdr.RewardsPool,
		},
		consensusVersion: contextHdr.CurrentProtocol,
		consensusParams:  consensusParams,
		minAvmVersion:    logic.ComputeMinAvmVersion(transactions.WrapSignedTxnsWithAD(group)),
		signedGroupTxns:  group,
		ledger:           ledger,
	}, nil
}

// Equal compares two group contexts to see if they would represent the same verification context for a given transaction.
func (g *GroupContext) Equal(other *GroupContext) bool {
	return g.specAddrs == other.specAddrs &&
		g.consensusVersion == other.consensusVersion &&
		g.minAvmVersion == other.minAvmVersion
}

// txnBatchPrep verifies a SignedTxn having no obviously inconsistent data.
// Block-assembly time checks of LogicSig and accounting rules may still block the txn.
// it is the caller responsibility to call batchVerifier.Verify()
func txnBatchPrep(s *transactions.SignedTxn, txnIdx int, groupCtx *GroupContext, verifier *crypto.BatchVerifier) error {
	if !groupCtx.consensusParams.SupportRekeying && (s.AuthAddr != basics.Address{}) {
		return errors.New("nonempty AuthAddr but rekeying is not supported")
	}

	if err := s.Txn.WellFormed(groupCtx.specAddrs, groupCtx.consensusParams); err != nil {
		return err
	}

	return stxnCoreChecks(s, txnIdx, groupCtx, verifier)
}

// TxnGroup verifies a []SignedTxn as being signed and having no obviously inconsistent data.
func TxnGroup(stxs []transactions.SignedTxn, contextHdr bookkeeping.BlockHeader, cache VerifiedTransactionCache, ledger logic.LedgerForSignature) (groupCtx *GroupContext, err error) {
	batchVerifier := crypto.MakeBatchVerifier()

	if groupCtx, err = txnGroupBatchPrep(stxs, contextHdr, ledger, batchVerifier); err != nil {
		return nil, err
	}

	if err := batchVerifier.Verify(); err != nil {
		return nil, err
	}

	if cache != nil {
		cache.Add(stxs, groupCtx)
	}

	return
}

// txnGroupBatchPrep verifies a []SignedTxn having no obviously inconsistent data.
// it is the caller responsibility to call batchVerifier.Verify()
func txnGroupBatchPrep(stxs []transactions.SignedTxn, contextHdr bookkeeping.BlockHeader, ledger logic.LedgerForSignature, verifier *crypto.BatchVerifier) (groupCtx *GroupContext, err error) {
	groupCtx, err = PrepareGroupContext(stxs, contextHdr, ledger)
	if err != nil {
		return nil, err
	}

	minFeeCount := uint64(0)
	feesPaid := uint64(0)
	for i, stxn := range stxs {
		err = txnBatchPrep(&stxn, i, groupCtx, verifier)
		if err != nil {
			err = fmt.Errorf("transaction %+v invalid : %w", stxn, err)
			return
		}
		if stxn.Txn.Type != protocol.StateProofTx {
			minFeeCount++
		}
		feesPaid = basics.AddSaturate(feesPaid, stxn.Txn.Fee.Raw)
	}
	feeNeeded, overflow := basics.OMul(groupCtx.consensusParams.MinTxnFee, minFeeCount)
	if overflow {
		err = fmt.Errorf("txgroup fee requirement overflow")
		return
	}
	// feesPaid may have saturated. That's ok. Since we know
	// feeNeeded did not overflow, simple comparison tells us
	// feesPaid was enough.
	if feesPaid < feeNeeded {
		err = fmt.Errorf("txgroup had %d in fees, which is less than the minimum %d * %d",
			feesPaid, minFeeCount, groupCtx.consensusParams.MinTxnFee)
		return
	}

	return
}

func stxnCoreChecks(s *transactions.SignedTxn, txnIdx int, groupCtx *GroupContext, batchVerifier *crypto.BatchVerifier) error {
	numSigs := 0
	hasSig := false
	hasMsig := false
	hasLogicSig := false
	if s.Sig != (crypto.Signature{}) {
		numSigs++
		hasSig = true
	}
	if !s.Msig.Blank() {
		numSigs++
		hasMsig = true
	}
	if !s.Lsig.Blank() {
		numSigs++
		hasLogicSig = true
	}
	if numSigs == 0 {
		// Special case: special sender address can issue special transaction
		// types (state proof txn) without any signature.  The well-formed
		// check ensures that this transaction cannot pay any fee, and
		// cannot have any other interesting fields, except for the state proof payload.
		if s.Txn.Sender == transactions.StateProofSender && s.Txn.Type == protocol.StateProofTx {
			return nil
		}

		return errors.New("signedtxn has no sig")
	}
	if numSigs > 1 {
		return errors.New("signedtxn should only have one of Sig or Msig or LogicSig")
	}

	if hasSig {
		batchVerifier.EnqueueSignature(crypto.SignatureVerifier(s.Authorizer()), s.Txn, s.Sig)
		return nil
	}
	if hasMsig {
		if err := crypto.MultisigBatchPrep(s.Txn, crypto.Digest(s.Authorizer()), s.Msig, batchVerifier); err != nil {
			return fmt.Errorf("multisig validation failed: %w", err)
		}
		return nil
	}
	if hasLogicSig {
		return logicSigVerify(s, txnIdx, groupCtx)
	}
	return errors.New("has one mystery sig. WAT?")
}

// LogicSigSanityCheck checks that the signature is valid and that the program is basically well formed.
// It does not evaluate the logic.
func LogicSigSanityCheck(txn *transactions.SignedTxn, groupIndex int, groupCtx *GroupContext) error {
	batchVerifier := crypto.MakeBatchVerifier()

	if err := logicSigSanityCheckBatchPrep(txn, groupIndex, groupCtx, batchVerifier); err != nil {
		return err
	}
	return batchVerifier.Verify()
}

// logicSigSanityCheckBatchPrep checks that the signature is valid and that the program is basically well formed.
// It does not evaluate the logic.
// it is the caller responsibility to call batchVerifier.Verify()
func logicSigSanityCheckBatchPrep(txn *transactions.SignedTxn, groupIndex int, groupCtx *GroupContext, batchVerifier *crypto.BatchVerifier) error {
	lsig := txn.Lsig

	if groupCtx.consensusParams.LogicSigVersion == 0 {
		return errors.New("LogicSig not enabled")
	}
	if len(lsig.Logic) == 0 {
		return errors.New("LogicSig.Logic empty")
	}
	version, vlen := binary.Uvarint(lsig.Logic)
	if vlen <= 0 {
		return errors.New("LogicSig.Logic bad version")
	}
	if version > groupCtx.consensusParams.LogicSigVersion {
		return errors.New("LogicSig.Logic version too new")
	}
	if uint64(lsig.Len()) > groupCtx.consensusParams.LogicSigMaxSize {
		return errors.New("LogicSig.Logic too long")
	}

	if groupIndex < 0 {
		return errors.New("Negative groupIndex")
	}
	txngroup := transactions.WrapSignedTxnsWithAD(groupCtx.signedGroupTxns)
	ep := logic.EvalParams{
		Proto:         &groupCtx.consensusParams,
		TxnGroup:      txngroup,
		MinAvmVersion: &groupCtx.minAvmVersion,
		SigLedger:     groupCtx.ledger, // won't be needed for CheckSignature
	}
	err := logic.CheckSignature(groupIndex, &ep)
	if err != nil {
		return err
	}

	hasMsig := false
	numSigs := 0
	if lsig.Sig != (crypto.Signature{}) {
		numSigs++
	}
	if !lsig.Msig.Blank() {
		hasMsig = true
		numSigs++
	}
	if numSigs == 0 {
		// if the txn.Authorizer() == hash(Logic) then this is a (potentially) valid operation on a contract-only account
		program := logic.Program(lsig.Logic)
		lhash := crypto.HashObj(&program)
		if crypto.Digest(txn.Authorizer()) == lhash {
			return nil
		}
		return errors.New("LogicNot signed and not a Logic-only account")
	}
	if numSigs > 1 {
		return errors.New("LogicSig should only have one of Sig or Msig but has more than one")
	}

	if !hasMsig {
		program := logic.Program(lsig.Logic)
		batchVerifier.EnqueueSignature(crypto.PublicKey(txn.Authorizer()), &program, lsig.Sig)
	} else {
		program := logic.Program(lsig.Logic)
		if err := crypto.MultisigBatchPrep(&program, crypto.Digest(txn.Authorizer()), lsig.Msig, batchVerifier); err != nil {
			return fmt.Errorf("logic multisig validation failed: %w", err)
		}
	}
	return nil
}

// logicSigVerify checks that the signature is valid, executing the program.
func logicSigVerify(txn *transactions.SignedTxn, groupIndex int, groupCtx *GroupContext) error {
	err := LogicSigSanityCheck(txn, groupIndex, groupCtx)
	if err != nil {
		return err
	}

	if groupIndex < 0 {
		return errors.New("Negative groupIndex")
	}
	ep := logic.EvalParams{
		Proto:         &groupCtx.consensusParams,
		TxnGroup:      transactions.WrapSignedTxnsWithAD(groupCtx.signedGroupTxns),
		MinAvmVersion: &groupCtx.minAvmVersion,
		SigLedger:     groupCtx.ledger,
	}
	pass, err := logic.EvalSignature(groupIndex, &ep)
	if err != nil {
		logicErrTotal.Inc(nil)
		return fmt.Errorf("transaction %v: rejected by logic err=%v", txn.ID(), err)
	}
	if !pass {
		logicRejTotal.Inc(nil)
		return fmt.Errorf("transaction %v: rejected by logic", txn.ID())
	}
	logicGoodTotal.Inc(nil)
	return nil

}

// PaysetGroups verifies that the payset have a good signature and that the underlying
// transactions are properly constructed.
// Note that this does not check whether a payset is valid against the ledger:
// a PaysetGroups may be well-formed, but a payset might contain an overspend.
//
// This version of verify is performing the verification over the provided execution pool.
func PaysetGroups(ctx context.Context, payset [][]transactions.SignedTxn, blkHeader bookkeeping.BlockHeader, verificationPool execpool.BacklogPool, cache VerifiedTransactionCache, ledger logic.LedgerForSignature) (err error) {
	if len(payset) == 0 {
		return nil
	}

	// prepare up to 16 concurrent worksets.
	worksets := make(chan struct{}, concurrentWorksets)
	worksDoneCh := make(chan interface{}, concurrentWorksets)
	processing := 0

	tasksCtx, cancelTasksCtx := context.WithCancel(ctx)
	defer cancelTasksCtx()
	builder := worksetBuilder{payset: payset}
	var nextWorkset [][]transactions.SignedTxn
	for processing >= 0 {
		// see if we need to get another workset
		if len(nextWorkset) == 0 && !builder.completed() {
			nextWorkset = builder.next()
		}

		select {
		case <-tasksCtx.Done():
			return tasksCtx.Err()
		case worksets <- struct{}{}:
			if len(nextWorkset) > 0 {
				err := verificationPool.EnqueueBacklog(ctx, func(arg interface{}) interface{} {
					var grpErr error
					// check if we've canceled the request while this was in the queue.
					if tasksCtx.Err() != nil {
						return tasksCtx.Err()
					}

					txnGroups := arg.([][]transactions.SignedTxn)
					groupCtxs := make([]*GroupContext, len(txnGroups))

					batchVerifier := crypto.MakeBatchVerifierWithHint(len(payset))
					for i, signTxnsGrp := range txnGroups {
						groupCtxs[i], grpErr = txnGroupBatchPrep(signTxnsGrp, blkHeader, ledger, batchVerifier)
						// abort only if it's a non-cache error.
						if grpErr != nil {
							return grpErr
						}
					}
					verifyErr := batchVerifier.Verify()
					if verifyErr != nil {
						return verifyErr
					}
					cache.AddPayset(txnGroups, groupCtxs)
					return nil
				}, nextWorkset, worksDoneCh)
				if err != nil {
					return err
				}
				processing++
				nextWorkset = nil
			}
		case processingResult := <-worksDoneCh:
			processing--
			<-worksets
			// if there is nothing in the queue, the nextWorkset doesn't contain any work and the builder has no more entries, then we're done.
			if processing == 0 && builder.completed() && len(nextWorkset) == 0 {
				// we're done.
				processing = -1
			}
			if processingResult != nil {
				err = processingResult.(error)
				if err != nil {
					return err
				}
			}
		}

	}
	return err
}

// worksetBuilder is a helper struct used to construct well sized worksets for the execution pool to process
type worksetBuilder struct {
	payset [][]transactions.SignedTxn
	idx    int
}

func (w *worksetBuilder) next() (txnGroups [][]transactions.SignedTxn) {
	txnCounter := 0 // how many transaction we already included in the current workset.
	// scan starting from the current position until we filled up the workset.
	for i := w.idx; i < len(w.payset); i++ {
		if txnCounter+len(w.payset[i]) > txnPerWorksetThreshold {
			if i == w.idx {
				i++
			}
			txnGroups = w.payset[w.idx:i]
			w.idx = i
			return
		}
		if i == len(w.payset)-1 {
			txnGroups = w.payset[w.idx:]
			w.idx = len(w.payset)
			return
		}
		txnCounter += len(w.payset[i])
	}
	// we can reach here only if w.idx >= len(w.payset). This is not really a usecase, but just
	// for code-completeness, we'll return an empty array here.
	return nil
}

// test to see if we have any more worksets we can extract from our payset.
func (w *worksetBuilder) completed() bool {
	return w.idx >= len(w.payset)
}

// VerificationElement is the element passed the Stream verifier
// Context is a reference associated with the txn group which is passed
// with the result
type VerificationElement struct {
	TxnGroup []transactions.SignedTxn
	Context  interface{}
}

// VerificationResult is the result of the txn group verification
// Context is a reference associated with the txn group which was
// initially passed to the stream verifier
type VerificationResult struct {
	TxnGroup []transactions.SignedTxn
	Context  interface{}
	Err      error
}

type streamManager struct {
	seatReturnChan   chan interface{}
	resultChan       chan<- VerificationResult
	verificationPool execpool.BacklogPool
	ctx              context.Context
	cache            VerifiedTransactionCache
}

type batchLoad struct {
	batchVerifier  *crypto.BatchVerifier
	txnGroups      [][]transactions.SignedTxn
	groupCtxs      []*GroupContext
	elementContext []interface{}
	messagesForTxn []int
}

// NewBlockWatcher is a struct used to provide a new block header to the
// stream verifier
type NewBlockWatcher struct {
	blkHeader bookkeeping.BlockHeader
	mu        deadlock.RWMutex
}

// MakeNewBlockWatcher construct a new block watcher with the initial blkHdr
func MakeNewBlockWatcher(blkHdr bookkeeping.BlockHeader) (nbw *NewBlockWatcher) {
	nbw = &NewBlockWatcher{
		blkHeader: blkHdr,
	}
	return nbw
}

// OnNewBlock implements the interface to subscribe to new block notifications from the ledger
func (nbw *NewBlockWatcher) OnNewBlock(block bookkeeping.Block, delta ledgercore.StateDelta) {
	if nbw.blkHeader.Round >= block.BlockHeader.Round {
		return
	}
	nbw.mu.Lock()
	defer nbw.mu.Unlock()
	nbw.blkHeader = block.BlockHeader
}

func (nbw *NewBlockWatcher) getBlockHeader() (bh bookkeeping.BlockHeader) {
	nbw.mu.RLock()
	defer nbw.mu.RUnlock()
	return nbw.blkHeader
}

func makeBatchLoad() batchLoad {
	bl := batchLoad{}
	bl.batchVerifier = crypto.MakeBatchVerifier()
	bl.groupCtxs = make([]*GroupContext, 0)
	bl.txnGroups = make([][]transactions.SignedTxn, 0)
	bl.messagesForTxn = make([]int, 0)
	return bl
}

// wait time for another txn should satisfy the following inequality:
// [validation time added to the group by one more txn] + [wait time] <= [validation time of a single txn]
// since these are difficult to estimate, the simplified version could be to assume:
// [validation time added to the group by one more txn] = [validation time of a single txn] / 2
// This gives us:
// [wait time] <= [validation time of a single txn] / 2
const singelTxnValidationTime = 100 * time.Millisecond
const numberOfExecPoolSeats = 8

// internalBufferSize is the size of the chan that will hold the arriving stxns before they get pre-processed
const internalBufferSize = 25000

//const txnPerWorksetThreshold = 32

// MakeStream creates a new stream verifier and returns the chans used to send txn groups
// to it and obtain the txn signature verification result from
func MakeStream(ctx context.Context, ledger logic.LedgerForSignature, nbw *NewBlockWatcher,
	verificationPool execpool.BacklogPool, cache VerifiedTransactionCache) (
	stxnInput chan<- VerificationElement, resultOtput <-chan VerificationResult) {

	stxnChan := make(chan VerificationElement, internalBufferSize)
	resultChan := make(chan VerificationResult)

	sm := streamManager{
		seatReturnChan:   make(chan interface{}, numberOfExecPoolSeats),
		resultChan:       resultChan,
		verificationPool: verificationPool,
		ctx:              ctx,
		cache:            cache,
	}

	go func() {
		for x := 0; x < numberOfExecPoolSeats; x++ {
			sm.seatReturnChan <- struct{}{}
		}

		bl := makeBatchLoad()
		timer := time.NewTicker(singelTxnValidationTime / 2)
		var added bool
		for {
			select {
			case stx := <-stxnChan:
				timer = time.NewTicker(singelTxnValidationTime / 2)
				// TODO: separate operations here, and get the sig verification inside LogicSig outside
				groupCtx, err := txnGroupBatchPrep(stx.TxnGroup, nbw.getBlockHeader(), ledger, bl.batchVerifier)
				//TODO: report the error ctx.Err()

				if err != nil {
					continue
				}
				bl.groupCtxs = append(bl.groupCtxs, groupCtx)
				bl.txnGroups = append(bl.txnGroups, stx.TxnGroup)
				bl.elementContext = append(bl.elementContext, stx.Context)
				bl.messagesForTxn = append(bl.messagesForTxn, bl.batchVerifier.GetNumberOfEnqueuedSignatures())
				if len(bl.groupCtxs) >= txnPerWorksetThreshold {
					// TODO: the limit of 32 should not pass
					timer, added = sm.processBatch(bl)
					if added {
						bl = makeBatchLoad()
					}
				}
			case <-timer.C:
				if len(bl.groupCtxs) == 0 {
					// nothing yet... wait some more
					timer = time.NewTicker(singelTxnValidationTime / 2)
					continue
				}
				timer, added = sm.processBatch(bl)
				if added {
					bl = makeBatchLoad()
				}
			case <-ctx.Done():
				return //TODO: report the error ctx.Err()
			}
		}
	}()
	return stxnChan, resultChan
}

func (sm *streamManager) processBatch(bl batchLoad) (timer *time.Ticker, added bool) {
	if bl.batchVerifier.GetNumberOfEnqueuedSignatures() >= txnPerWorksetThreshold {
		// Should not allow addition of more txns to the batch
		// the varifier might be saturated.
		// block and wait for a free seat
		<-sm.seatReturnChan
		err := sm.addVerificationTaskToThePool(bl)
		if err != nil {
			// TODO: report the error
			fmt.Println(err)
		}
		timer = time.NewTicker(singelTxnValidationTime / 2)
		added = true
		return
	}
	// Otherwise, if cannot find a seat, can go back and collect
	// more signatures instead of waiting here
	select {
	case <-sm.seatReturnChan:
		err := sm.addVerificationTaskToThePool(bl)
		timer = time.NewTicker(singelTxnValidationTime / 2)
		added = true
		if err != nil {
			// TODO: report the error
			fmt.Println(err)
		}
		// TODO: queue to the pool.
		//				fmt.Println(err)
	default:
		// if no free seats, wait some more for more txns
		timer = time.NewTicker(singelTxnValidationTime / 2)
	}
	return
}

// send the result out the chan
func (sm *streamManager) sendOut(vr VerificationResult) {
	// send the txn result out the pipe
	sm.resultChan <- vr
	/*
		select {
		case sm.resultChan <- vr:

				// if the channel is not accepting, should not block here
				// report dropped txn. caching is fine, if it comes back in the block
				default:
					fmt.Println("skipped!!")
					//TODO: report this

		}
	*/
}

func (sm *streamManager) addVerificationTaskToThePool(bl batchLoad) error {

	function := func(arg interface{}) interface{} {
		bl = arg.(batchLoad)
		//		var grpErr error
		// check if we've canceled the request while this was in the queue.
		if sm.ctx.Err() != nil {
			return sm.ctx.Err()
		}
		failed, err := bl.batchVerifier.VerifyWithFeedback()
		if err != nil && err != crypto.ErrBatchHasFailedSigs {
			fmt.Println(err)
			// something bad happened
			// TODO:  report error and discard the batch
		}

		verifiedTxnGroups := make([][]transactions.SignedTxn, len(bl.txnGroups))
		verifiedGroupCtxs := make([]*GroupContext, len(bl.groupCtxs))
		failedSigIdx := 0
		for txgIdx := range bl.txnGroups {
			txGroupSigFailed := false
			// if err == nil, means all sigs are verified, no need to check for the failed
			for err != nil && failedSigIdx < bl.messagesForTxn[txgIdx] {
				if failed[failedSigIdx] {
					// if there is a failed sig check, then no need to check the rest of the
					// sigs for this txnGroup
					failedSigIdx = bl.messagesForTxn[txgIdx]
					txGroupSigFailed = true
				} else {
					// proceed to check the next sig belonging to this txnGroup
					failedSigIdx++
				}
			}
			var result error
			if !txGroupSigFailed {
				verifiedTxnGroups = append(verifiedTxnGroups, bl.txnGroups[txgIdx])
				verifiedGroupCtxs = append(verifiedGroupCtxs, bl.groupCtxs[txgIdx])
			} else {
				result = ErrInvalidSignature
			}
			vr := VerificationResult{
				TxnGroup: bl.txnGroups[txgIdx],
				Context:  bl.elementContext[txgIdx],
				Err:      result,
			}
			sm.sendOut(vr)
		}
		// loading them all at once to lock the cache once
		err = sm.cache.AddPayset(verifiedTxnGroups, verifiedGroupCtxs)
		if err != nil {
			// TODO: handle the error
			fmt.Println(err)
		}
		return struct{}{}
	}
	err := sm.verificationPool.EnqueueBacklog(sm.ctx, function, bl, sm.seatReturnChan)
	return err
}
