// Copyright (C) 2019-2023 Algorand, Inc.
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
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/execpool"
)

// ErrShuttingDownError is the error returned when a job is not processed because the service is shutting down
var ErrShuttingDownError = errors.New("not processed, execpool service is shutting down")

// batchSizeBlockLimit is the limit when the batch exceeds, will be added to the exec pool, even if the pool is saturated
// and the stream  will be blocked until the exec pool accepts the batch
const batchSizeBlockLimit = 1024

// waitForNextJobDuration is the time to wait before sending the batch to the exec pool
// If the incoming rate is low, an input job in the batch may wait no less than
// waitForNextJobDuration before it is sent for processing.
// This can introduce a latency to the propagation in the network (e.g. sigs in txn or vote),
// since every relay will go through this wait time before broadcasting the result.
// However, when the incoming rate is high, the batch will fill up quickly and will send
// for processing before waitForNextJobDuration.
const waitForNextJobDuration = 2 * time.Millisecond

// UnverifiedTxnSigJob is the sig verification job passed to the Stream verifier
// It represents an unverified txn whose signatures will be verified
// BacklogMessage is a *txBacklogMsg from data/txHandler.go which needs to be
// passed back to that context
// Implements UnverifiedSigJob
type UnverifiedTxnSigJob struct {
	TxnGroup       []transactions.SignedTxn
	BacklogMessage interface{}
}

// VerificationResult is the result of the txn group verification
// BacklogMessage is the reference associated with the txn group which was
// initially passed to the stream verifier
type VerificationResult struct {
	TxnGroup       []transactions.SignedTxn
	BacklogMessage interface{}
	Err            error
}

// StreamToBatch makes batches from incoming stream of jobs, and submits the batches to the exec pool
type StreamToBatch struct {
	inputChan      <-chan InputJob
	executionPool  execpool.BacklogPool
	ctx            context.Context
	activeLoopWg   sync.WaitGroup
	batchProcessor BatchProcessor
}

type txnSigBatchProcessor struct {
	cache       VerifiedTransactionCache
	nbw         *NewBlockWatcher
	ledger      logic.LedgerForSignature
	resultChan  chan<- *VerificationResult
	droppedChan chan<- *UnverifiedTxnSigJob
}

// InputJob is the interface the incoming jobs need to implement
type InputJob interface {
	GetNumberOfBatchableItems() (count uint64, err error)
}

// BatchProcessor is the interface of the functions needed to prepare a batch from the stream,
// process and return the results
type BatchProcessor interface {
	// ProcessBatch processes a batch packed from the stream in the execpool
	ProcessBatch(jobs []InputJob)
	// GetErredUnprocessed returns an unprocessed jobs because of an err
	GetErredUnprocessed(ue InputJob, err error)
	// Cleanup called on the unprocessed jobs when the service shuts down
	Cleanup(ue []InputJob, err error)
}

// NewBlockWatcher is a struct used to provide a new block header to the
// stream verifier
type NewBlockWatcher struct {
	blkHeader atomic.Value
}

// MakeNewBlockWatcher construct a new block watcher with the initial blkHdr
func MakeNewBlockWatcher(blkHdr bookkeeping.BlockHeader) (nbw *NewBlockWatcher) {
	nbw = &NewBlockWatcher{}
	nbw.blkHeader.Store(&blkHdr)
	return nbw
}

// OnNewBlock implements the interface to subscribe to new block notifications from the ledger
func (nbw *NewBlockWatcher) OnNewBlock(block bookkeeping.Block, delta ledgercore.StateDelta) {
	bh := nbw.blkHeader.Load().(*bookkeeping.BlockHeader)
	if bh.Round >= block.BlockHeader.Round {
		return
	}
	nbw.blkHeader.Store(&block.BlockHeader)
}

func (nbw *NewBlockWatcher) getBlockHeader() (bh *bookkeeping.BlockHeader) {
	return nbw.blkHeader.Load().(*bookkeeping.BlockHeader)
}

type batchLoad struct {
	txnGroups      [][]transactions.SignedTxn
	groupCtxs      []*GroupContext
	backlogMessage []interface{}
	messagesForTxn []int
}

func makeBatchLoad(l int) (bl *batchLoad) {
	return &batchLoad{
		txnGroups:      make([][]transactions.SignedTxn, 0, l),
		groupCtxs:      make([]*GroupContext, 0, l),
		backlogMessage: make([]interface{}, 0, l),
		messagesForTxn: make([]int, 0, l),
	}
}

func (bl *batchLoad) addLoad(txngrp []transactions.SignedTxn, gctx *GroupContext, backlogMsg interface{}, numBatchableSigs int) {
	bl.txnGroups = append(bl.txnGroups, txngrp)
	bl.groupCtxs = append(bl.groupCtxs, gctx)
	bl.backlogMessage = append(bl.backlogMessage, backlogMsg)
	bl.messagesForTxn = append(bl.messagesForTxn, numBatchableSigs)

}

// LedgerForStreamVerifier defines the ledger methods used by the StreamVerifier.
type LedgerForStreamVerifier interface {
	logic.LedgerForSignature
	RegisterBlockListeners([]ledgercore.BlockListener)
	Latest() basics.Round
	BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error)
}

// MakeSigVerifyJobProcessor returns the object implementing the stream verifier Helper interface
func MakeSigVerifyJobProcessor(ledger LedgerForStreamVerifier, cache VerifiedTransactionCache,
	resultChan chan<- *VerificationResult, droppedChan chan<- *UnverifiedTxnSigJob) (svp BatchProcessor, err error) {
	latest := ledger.Latest()
	latestHdr, err := ledger.BlockHdr(latest)
	if err != nil {
		return nil, errors.New("MakeStreamVerifier: Could not get header for previous block")
	}

	nbw := MakeNewBlockWatcher(latestHdr)
	ledger.RegisterBlockListeners([]ledgercore.BlockListener{nbw})

	return &txnSigBatchProcessor{
		cache:       cache,
		nbw:         nbw,
		ledger:      ledger,
		droppedChan: droppedChan,
		resultChan:  resultChan,
	}, nil
}

// MakeStreamToBatch creates a new stream to batch converter
func MakeStreamToBatch(inputChan <-chan InputJob, execPool execpool.BacklogPool,
	batchProcessor BatchProcessor) *StreamToBatch {

	return &StreamToBatch{
		inputChan:      inputChan,
		executionPool:  execPool,
		batchProcessor: batchProcessor,
	}
}

// Start is called when the StreamToBatch is created and whenever it needs to restart after
// the ctx is canceled
func (sv *StreamToBatch) Start(ctx context.Context) {
	sv.ctx = ctx
	sv.activeLoopWg.Add(1)
	go sv.batchingLoop()
}

// WaitForStop waits until the batching loop terminates afer the ctx is canceled
func (sv *StreamToBatch) WaitForStop() {
	sv.activeLoopWg.Wait()
}

func (tbp *txnSigBatchProcessor) Cleanup(pending []InputJob, err error) {
	// report an error for the unchecked txns
	// drop the messages without reporting if the receiver does not consume
	for _, ue := range pending {
		uelt := ue.(*UnverifiedTxnSigJob)
		tbp.sendResult(uelt.TxnGroup, uelt.BacklogMessage, err)
	}
}

func (sv *StreamToBatch) batchingLoop() {
	defer sv.activeLoopWg.Done()
	timer := time.NewTicker(waitForNextJobDuration)
	defer timer.Stop()
	var added bool
	var numberOfJobsInCurrent uint64
	var numberOfBatchAttempts uint64
	uJobs := make([]InputJob, 0, 8)
	defer func() { sv.batchProcessor.Cleanup(uJobs, ErrShuttingDownError) }()
	for {
		select {
		case job := <-sv.inputChan:
			numberOfBatchable, err := job.GetNumberOfBatchableItems()
			if err != nil {
				sv.batchProcessor.GetErredUnprocessed(job, err)
				continue
			}

			// if no batchable items here, send this as a task of its own
			if numberOfBatchable == 0 {
				err := sv.addBatchToThePoolNow([]InputJob{job})
				if err != nil {
					return
				}
				continue // job is handled, continue
			}

			// add this job to the list of batchable jobs
			numberOfJobsInCurrent = numberOfJobsInCurrent + numberOfBatchable
			uJobs = append(uJobs, job)
			if numberOfJobsInCurrent > txnPerWorksetThreshold {
				// enough jobs in the batch to efficiently process

				if numberOfJobsInCurrent > batchSizeBlockLimit {
					// do not consider adding more jobs to this batch.
					// bypass the exec pool situation and queue anyway
					// this is to prevent creation of very large batches
					err := sv.addBatchToThePoolNow(uJobs)
					if err != nil {
						return
					}
					added = true
				} else {
					added, err = sv.tryAddBatchToThePool(uJobs)
					if err != nil {
						return
					}
				}
				if added {
					numberOfJobsInCurrent = 0
					uJobs = make([]InputJob, 0, 8)
					numberOfBatchAttempts = 0
				} else {
					// was not added because of the exec pool buffer length
					numberOfBatchAttempts++
				}
			}
		case <-timer.C:
			// timer ticked. it is time to send the batch even if it is not full
			if numberOfJobsInCurrent == 0 {
				// nothing batched yet... wait some more
				continue
			}
			var err error
			if numberOfBatchAttempts > 1 {
				// bypass the exec pool situation and queue anyway
				// this is to prevent long delays in the propagation (sigs txn/vote)
				// at least one job has waited 3 x waitForNextJobDuration
				err = sv.addBatchToThePoolNow(uJobs)
				added = true
			} else {
				added, err = sv.tryAddBatchToThePool(uJobs)
			}
			if err != nil {
				return
			}
			if added {
				numberOfJobsInCurrent = 0
				uJobs = make([]InputJob, 0, 8)
				numberOfBatchAttempts = 0
			} else {
				// was not added because of the exec pool buffer length. wait for some more
				numberOfBatchAttempts++
			}
		case <-sv.ctx.Done():
			return
		}
	}
}

func (tbp txnSigBatchProcessor) sendResult(veTxnGroup []transactions.SignedTxn, veBacklogMessage interface{}, err error) {
	// send the txn result out the pipe
	select {
	case tbp.resultChan <- &VerificationResult{
		TxnGroup:       veTxnGroup,
		BacklogMessage: veBacklogMessage,
		Err:            err,
	}:
	default:
		// we failed to write to the output queue, since the queue was full.
		tbp.droppedChan <- &UnverifiedTxnSigJob{veTxnGroup, veBacklogMessage}
	}
}

func (sv *StreamToBatch) tryAddBatchToThePool(uJobs []InputJob) (added bool, err error) {
	// if the exec pool buffer is full, can go back and collect
	// more jobs instead of waiting in the exec pool buffer
	// e.g. more signatures to the batch do not harm performance but introduce latency when delayed (see crypto.BenchmarkBatchVerifierBig)

	// if the buffer is full
	if l, c := sv.executionPool.BufferSize(); l == c {
		return false, nil
	}
	err = sv.addBatchToThePoolNow(uJobs)
	if err != nil {
		// An error is returned when the context of the pool expires
		return false, err
	}
	return true, nil
}

func (sv *StreamToBatch) addBatchToThePoolNow(unprocessed []InputJob) error {
	// if the context is canceled when the task is in the queue, it should be canceled
	// copy the ctx here so that when the StreamToBatch is started again, and a new context
	// is created, this task still gets canceled due to the ctx at the time of this task
	taskCtx := sv.ctx
	function := func(arg interface{}) interface{} {
		uJobs := arg.([]InputJob)
		if taskCtx.Err() != nil {
			// ctx is canceled. the results will be returned
			sv.batchProcessor.Cleanup(uJobs, ErrShuttingDownError)
			return nil
		}

		sv.batchProcessor.ProcessBatch(uJobs)
		return nil
	}

	// EnqueueBacklog returns an error when the context is canceled
	err := sv.executionPool.EnqueueBacklog(sv.ctx, function, unprocessed, nil)
	if err != nil {
		logging.Base().Infof("addBatchToThePoolNow: EnqueueBacklog returned an error and StreamToBatch will stop: %v", err)
	}
	return err
}

func (tbp *txnSigBatchProcessor) preProcessUnverifiedTxns(uTxns []InputJob) (batchVerifier *crypto.BatchVerifier, ctx interface{}) {
	batchVerifier = crypto.MakeBatchVerifier()
	bl := makeBatchLoad(len(uTxns))
	// TODO: separate operations here, and get the sig verification inside the LogicSig to the batch here
	blockHeader := tbp.nbw.getBlockHeader()

	for _, uTxn := range uTxns {
		ut := uTxn.(*UnverifiedTxnSigJob)
		groupCtx, err := txnGroupBatchPrep(ut.TxnGroup, blockHeader, tbp.ledger, batchVerifier, nil)
		if err != nil {
			// verification failed, no need to add the sig to the batch, report the error
			tbp.sendResult(ut.TxnGroup, ut.BacklogMessage, err)
			continue
		}
		totalBatchCount := batchVerifier.GetNumberOfEnqueuedSignatures()
		bl.addLoad(ut.TxnGroup, groupCtx, ut.BacklogMessage, totalBatchCount)
	}
	return batchVerifier, bl
}

func (tbp *txnSigBatchProcessor) ProcessBatch(txns []InputJob) {
	batchVerifier, ctx := tbp.preProcessUnverifiedTxns(txns)
	failed, err := batchVerifier.VerifyWithFeedback()
	// this error can only be crypto.ErrBatchHasFailedSigs
	tbp.postProcessVerifiedJobs(ctx, failed, err)
}

func (tbp *txnSigBatchProcessor) postProcessVerifiedJobs(ctx interface{}, failed []bool, err error) {
	bl := ctx.(*batchLoad)
	if err == nil { // success, all signatures verified
		for i := range bl.txnGroups {
			tbp.sendResult(bl.txnGroups[i], bl.backlogMessage[i], nil)
		}
		tbp.cache.AddPayset(bl.txnGroups, bl.groupCtxs)
		return
	}

	verifiedTxnGroups := make([][]transactions.SignedTxn, 0, len(bl.txnGroups))
	verifiedGroupCtxs := make([]*GroupContext, 0, len(bl.groupCtxs))
	failedSigIdx := 0
	for txgIdx := range bl.txnGroups {
		txGroupSigFailed := false
		for failedSigIdx < bl.messagesForTxn[txgIdx] {
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
			result = err
		}
		tbp.sendResult(bl.txnGroups[txgIdx], bl.backlogMessage[txgIdx], result)
	}
	// loading them all at once by locking the cache once
	tbp.cache.AddPayset(verifiedTxnGroups, verifiedGroupCtxs)
}

// GetNumberOfBatchableItems returns the number of batchable signatures in the txn group
func (ue UnverifiedTxnSigJob) GetNumberOfBatchableItems() (batchSigs uint64, err error) {
	batchSigs = 0
	for i := range ue.TxnGroup {
		count, err := getNumberOfBatchableSigsInTxn(&ue.TxnGroup[i])
		if err != nil {
			return 0, err
		}
		batchSigs = batchSigs + count
	}
	return
}

func getNumberOfBatchableSigsInTxn(stx *transactions.SignedTxn) (uint64, error) {
	sigType, err := checkTxnSigTypeCounts(stx)
	if err != nil {
		return 0, err
	}
	switch sigType {
	case regularSig:
		return 1, nil
	case multiSig:
		sig := stx.Msig
		batchSigs := uint64(0)
		for _, subsigi := range sig.Subsigs {
			if (subsigi.Sig != crypto.Signature{}) {
				batchSigs++
			}
		}
		return batchSigs, nil
	case logicSig:
		// Currently the sigs in here are not batched. Something to consider later.
		return 0, nil
	case stateProofTxn:
		return 0, nil
	default:
		// this case is impossible
		return 0, nil
	}
}
