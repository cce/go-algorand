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

package crypto

import (
	"filippo.io/edwards25519"
	"github.com/hdevalence/ed25519consensus"
)

type ed25519ConsensusBatchVerifier struct {
	messages   []Hashable          // contains a slice of messages to be hashed. Each message is varible length
	publicKeys []SignatureVerifier // contains a slice of public keys. Each individual public key is 32 bytes.
	signatures []Signature         // contains a slice of signatures keys. Each individual signature is 64 bytes.
	good       []bool
}

func (b *ed25519ConsensusBatchVerifier) EnqueueSignature(sigVerifier SignatureVerifier, message Hashable, sig Signature) {
	b.messages = append(b.messages, message)
	b.publicKeys = append(b.publicKeys, sigVerifier)
	b.signatures = append(b.signatures, sig)
}

func (b *ed25519ConsensusBatchVerifier) GetNumberOfEnqueuedSignatures() int {
	return len(b.messages)
}

func (b *ed25519ConsensusBatchVerifier) Verify() error {
	bv := ed25519consensus.NewBatchVerifier()
	for i := range b.signatures {
		bv.Add(b.publicKeys[i][:], HashRep(b.messages[i]), b.signatures[i][:])
	}
	if ok := bv.Verify(); !ok {
		return ErrBatchHasFailedSigs
	}
	return nil
}

func (b *ed25519ConsensusBatchVerifier) VerifyWithFeedback() (failed []bool, err error) {
	if err := b.Verify(); err == nil {
		// no failures
		return nil, nil
	}

	// one or more signatures failed, identify which ones
	failed = make([]bool, len(b.messages))
	for i := range b.messages {
		//failed[i] = !ed25519Verify(ed25519PublicKey(b.publicKeys[i]), HashRep(b.messages[i]), ed25519Signature(b.signatures[i]))
		failed[i] = !ed25519consensus.Verify(b.publicKeys[i][:], HashRep(b.messages[i]), b.signatures[i][:])
	}
	return failed, ErrBatchHasFailedSigs
}

// isSmallOrder returns true if p is in the torsion subgroup `E[8]`.
func isSmallOrder(p *edwards25519.Point) bool {
	var check edwards25519.Point
	return check.MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1
}
