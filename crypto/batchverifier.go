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

package crypto

// #cgo CFLAGS: -Wall -std=c99
// #cgo darwin,amd64 CFLAGS: -I${SRCDIR}/libs/darwin/amd64/include
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/libs/darwin/amd64/lib/libsodium.a
// #cgo darwin,arm64 CFLAGS: -I${SRCDIR}/libs/darwin/arm64/include
// #cgo darwin,arm64 LDFLAGS: ${SRCDIR}/libs/darwin/arm64/lib/libsodium.a
// #cgo linux,amd64 CFLAGS: -I${SRCDIR}/libs/linux/amd64/include
// #cgo linux,amd64 LDFLAGS: ${SRCDIR}/libs/linux/amd64/lib/libsodium.a
// #cgo linux,arm64 CFLAGS: -I${SRCDIR}/libs/linux/arm64/include
// #cgo linux,arm64 LDFLAGS: ${SRCDIR}/libs/linux/arm64/lib/libsodium.a
// #cgo linux,arm CFLAGS: -I${SRCDIR}/libs/linux/arm/include
// #cgo linux,arm LDFLAGS: ${SRCDIR}/libs/linux/arm/lib/libsodium.a
// #cgo windows,amd64 CFLAGS: -I${SRCDIR}/libs/windows/amd64/include
// #cgo windows,amd64 LDFLAGS: ${SRCDIR}/libs/windows/amd64/lib/libsodium.a
// #include <stdint.h>
// #include "sodium.h"
// enum {
//	sizeofPtr = sizeof(void*),
//	sizeofULongLong = sizeof(unsigned long long),
// };
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

// BatchSignatureID is an identifier used for tracking which signatures belonged to which ID.
// A caller might want to provide a value such as a txn group index to be able to verify
// which transactions failed, or dequeue signatures matching a given ID from the batch.
type BatchSignatureID int

// BatchVerifier enqueues signatures to be validated in batch.
type BatchVerifier struct {
	messages   []Hashable          // contains a slice of messages to be hashed. Each message is varible length
	publicKeys []SignatureVerifier // contains a slice of public keys. Each individual public key is 32 bytes.
	signatures []Signature         // contains a slice of signatures keys. Each individual signature is 64 bytes.

	sigIdentifierMap map[BatchSignatureID][]int // map of BatchSignatureID to messages/publicKeys/signatures indexes
	indexMap         map[int]BatchSignatureID   // map of messages/publicKeys/signatures indexes to BatchSignatureID
}

const minBatchVerifierAlloc = 16

// Batch verifications errors
var (
	ErrBatchVerificationFailed = errors.New("At least one signature didn't pass verification")
	ErrSignatureIDNotInBatch   = errors.New("SignatureID not found in batch")
)

//export ed25519_randombytes_unsafe
func ed25519_randombytes_unsafe(p unsafe.Pointer, len C.size_t) {
	randBuf := (*[1 << 30]byte)(p)[:len:len]
	RandBytes(randBuf)
}

// MakeBatchVerifier creates a BatchVerifier instance.
func MakeBatchVerifier() *BatchVerifier {
	return MakeBatchVerifierWithHint(minBatchVerifierAlloc)
}

// MakeBatchVerifierWithHint creates a BatchVerifier instance. This function pre-allocates
// amount of free space to enqueue signatures without expanding
func MakeBatchVerifierWithHint(hint int) *BatchVerifier {
	// preallocate enough storage for the expected usage. We will reallocate as needed.
	if hint < minBatchVerifierAlloc {
		hint = minBatchVerifierAlloc
	}
	return &BatchVerifier{
		messages:   make([]Hashable, 0, hint),
		publicKeys: make([]SignatureVerifier, 0, hint),
		signatures: make([]Signature, 0, hint),
	}
}

// EnqueueSignature enqueues a signature to be enqueued
func (b *BatchVerifier) EnqueueSignature(sigVerifier SignatureVerifier, message Hashable, sig Signature) {
	// do we need to reallocate ?
	if len(b.messages) == cap(b.messages) {
		b.expand()
	}
	b.messages = append(b.messages, message)
	b.publicKeys = append(b.publicKeys, sigVerifier)
	b.signatures = append(b.signatures, sig)
}

// EnqueueSignatureWithID enqueues a signature to be enqueued, using a provided signature identifier.
// Multiple calls to EnqueueSignatureWithID may use the same BatchSignatureID. The BatchSignatureID can be
// used with DequeueSignature to remove any signature(s) that were enqueued using the same ID.
// The BatchSignatureID can also be used to identify transactions that did not verify in the batch.
func (b *BatchVerifier) EnqueueSignatureWithID(sigID BatchSignatureID, sigVerifier SignatureVerifier, message Hashable, sig Signature) {
	// allocate maps on first use
	if b.sigIdentifierMap == nil {
		b.sigIdentifierMap = make(map[BatchSignatureID][]int)
		b.indexMap = make(map[int]BatchSignatureID)
	}
	// store the slice index of the next signature to be enqueued, then enqueue the signature
	nextIndex := len(b.messages)
	b.sigIdentifierMap[sigID] = append(b.sigIdentifierMap[sigID], nextIndex)
	b.indexMap[nextIndex] = sigID
	b.EnqueueSignature(sigVerifier, message, sig)
}

// DequeueSignature remove signatures matching a provided BatchSignatureID from the batch. There may be multiple signatures
// that were enqueued using the same sigID. If the BatchSignatureID was not found, an ErrSignatureIDNotInBatch is returned.
func (b *BatchVerifier) DequeueSignature(sigID BatchSignatureID) error {
	if b.sigIdentifierMap == nil {
		return fmt.Errorf("DequeueSignature: no BatchSignatureIDs have been enqueued: %w", ErrSignatureIDNotInBatch)
	}
	batchIndexes, ok := b.sigIdentifierMap[sigID]
	if !ok {
		return fmt.Errorf("DequeueSignature: BatchSignatureID %d not found: %w", sigID, ErrSignatureIDNotInBatch)
	}
	// remove each of the signatures matching this sigID
	for _, idx := range batchIndexes {
		b.messages = append(b.messages[0:idx], b.messages[idx+1:]...)
		b.publicKeys = append(b.publicKeys[0:idx], b.publicKeys[idx+1:]...)
		b.signatures = append(b.signatures[0:idx], b.signatures[idx+1:]...)
		delete(b.indexMap, idx)
	}
	// forget this sigID
	delete(b.sigIdentifierMap, sigID)
	return nil
}

func (b *BatchVerifier) expand() {
	messages := make([]Hashable, len(b.messages), len(b.messages)*2)
	publicKeys := make([]SignatureVerifier, len(b.publicKeys), len(b.publicKeys)*2)
	signatures := make([]Signature, len(b.signatures), len(b.signatures)*2)
	copy(messages, b.messages)
	copy(publicKeys, b.publicKeys)
	copy(signatures, b.signatures)
	b.messages = messages
	b.publicKeys = publicKeys
	b.signatures = signatures
}

// getNumberOfEnqueuedSignatures returns the number of signatures current enqueue onto the bacth verifier object
func (b *BatchVerifier) getNumberOfEnqueuedSignatures() int {
	return len(b.messages)
}

// Verify verifies that all the signatures are valid, in that case nil is returned
// if the batch is zero an appropriate error is return.
func (b *BatchVerifier) Verify() error {
	if b.getNumberOfEnqueuedSignatures() == 0 {
		return nil
	}

	var messages = make([][]byte, b.getNumberOfEnqueuedSignatures())
	for i, m := range b.messages {
		messages[i] = HashRep(m)
	}
	if batchVerificationImpl(messages, b.publicKeys, b.signatures) {
		return nil
	}
	return ErrBatchVerificationFailed
}

// VerifyWithIDs verifies that all the signatures are valid, on success returning
// nil, nil.
// On failure, it returns a non-nil error and a slice of BatchSignatureIDs that were
// assigned to signatures that failed, if any BatchSignatureIDs were provided.
func (b *BatchVerifier) VerifyWithIDs() ([]BatchSignatureID, error) {
	if b.getNumberOfEnqueuedSignatures() == 0 {
		return nil, nil
	}

	var messages = make([][]byte, b.getNumberOfEnqueuedSignatures())
	for i, m := range b.messages {
		messages[i] = HashRep(m)
	}

	failed := batchVerificationIdentifyValid(messages, b.publicKeys, b.signatures)
	// success: no failed signatures
	if len(failed) == 0 {
		return nil, nil
	}

	// failed, and no BatchSignatureIDs were used when enqueueing
	if len(failed) != 0 && b.sigIdentifierMap == nil {
		return nil, ErrBatchVerificationFailed
	}

	// failed, and BatchSignatureIDs were used
	// go through failed indexes, looking up associated BatchSignatureIDs
	failedSigIDs := make(map[BatchSignatureID]bool)
	for _, idx := range failed {
		sigID := b.indexMap[idx]
		failedSigIDs[sigID] = true
	}
	// remove duplicate BatchSignatureIDs in returned list
	ret := make([]BatchSignatureID, len(failedSigIDs))
	for sigID := range failedSigIDs {
		ret = append(ret, sigID)
	}

	return ret, ErrBatchVerificationFailed
}

// batchVerificationImpl invokes the ed25519 batch verification algorithm.
// it returns true if all the signatures were authentically signed by the owners
func batchVerificationImpl(messages [][]byte, publicKeys []SignatureVerifier, signatures []Signature) bool {
	ret, _ := batchVerificationValidImpl(messages, publicKeys, signatures)
	return ret
}

// batchVerificationValidImpl invokes the ed25519 batch verification algorithm.
// it returns true if all the signatures were authentically signed by the owners,
// and a pointer to the "valid" output array identifying which signatures were valid.
func batchVerificationValidImpl(messages [][]byte, publicKeys []SignatureVerifier, signatures []Signature) (bool, unsafe.Pointer) {
	numberOfSignatures := len(messages)

	messagesAllocation := C.malloc(C.size_t(C.sizeofPtr * numberOfSignatures))
	messagesLenAllocation := C.malloc(C.size_t(C.sizeofULongLong * numberOfSignatures))
	publicKeysAllocation := C.malloc(C.size_t(C.sizeofPtr * numberOfSignatures))
	signaturesAllocation := C.malloc(C.size_t(C.sizeofPtr * numberOfSignatures))
	valid := C.malloc(C.size_t(C.sizeof_int * numberOfSignatures))

	defer func() {
		// release staging memory
		C.free(messagesAllocation)
		C.free(messagesLenAllocation)
		C.free(publicKeysAllocation)
		C.free(signaturesAllocation)
		C.free(valid)
	}()

	// load all the data pointers into the array pointers.
	for i := 0; i < numberOfSignatures; i++ {
		*(*uintptr)(unsafe.Pointer(uintptr(messagesAllocation) + uintptr(i*C.sizeofPtr))) = uintptr(unsafe.Pointer(&messages[i][0]))
		*(*C.ulonglong)(unsafe.Pointer(uintptr(messagesLenAllocation) + uintptr(i*C.sizeofULongLong))) = C.ulonglong(len(messages[i]))
		*(*uintptr)(unsafe.Pointer(uintptr(publicKeysAllocation) + uintptr(i*C.sizeofPtr))) = uintptr(unsafe.Pointer(&publicKeys[i][0]))
		*(*uintptr)(unsafe.Pointer(uintptr(signaturesAllocation) + uintptr(i*C.sizeofPtr))) = uintptr(unsafe.Pointer(&signatures[i][0]))
	}

	// call the batch verifier
	allValid := C.crypto_sign_ed25519_open_batch(
		(**C.uchar)(unsafe.Pointer(messagesAllocation)),
		(*C.ulonglong)(unsafe.Pointer(messagesLenAllocation)),
		(**C.uchar)(unsafe.Pointer(publicKeysAllocation)),
		(**C.uchar)(unsafe.Pointer(signaturesAllocation)),
		C.size_t(len(messages)),
		(*C.int)(unsafe.Pointer(valid)))

	return allValid == 0, valid
}

// batchVerificationIdentifyValid invokes the ed25519 batch verification algorithm.
// it returns true if all the signatures were authentically signed by the owners,
// and an array of indexes to the messages that were invalid.
func batchVerificationIdentifyValid(messages [][]byte, publicKeys []SignatureVerifier, signatures []Signature) (failedIndexes []int) {
	ok, valid := batchVerificationValidImpl(messages, publicKeys, signatures)
	if ok {
		return nil
	}

	// some signatures failed: prepare list of failed signature indexes
	for i := 0; i < len(messages); i++ {
		isValid := *(*C.int)(unsafe.Pointer(uintptr(valid) + uintptr(i*C.sizeof_int)))
		if isValid == 0 {
			failedIndexes = append(failedIndexes, i)
		}
	}
	return failedIndexes
}
