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

package network

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

type identityChallenge struct {
	Key       crypto.PublicKey `codec:"pk"`
	Challenge [32]byte         `codec:"c"`
	Address   string           `codec:"a"`
	Signature crypto.Signature `codec:"s"`
}

type identityChallengeResponse struct {
	Key               crypto.PublicKey `codec:"pk"`
	Challenge         [32]byte         `codec:"c"`
	ResponseChallenge [32]byte         `codec:"rc"`
	Signature         crypto.Signature `codec:"s"`
}

// The identityTracker allows for ensuring there's only one peer for a given
// public key, to prevent duplicate connections between a pair of peers.
// The data structure is not thread-safe and is protected by wn.peersLock.
type identityTracker struct {
	// If a peer has successfully verified its identity it will be present
	// in this map by its public key.
	peersByID map[crypto.PublicKey]*wsPeer
}

func newIdentityTracker() *identityTracker {
	return &identityTracker{
		peersByID: make(map[crypto.PublicKey]*wsPeer),
	}
}

// setIdentity returns true if a peer by this identity already exists
func (it *identityTracker) setIdentity(peer *wsPeer) bool {
	// if the identity is verified, check for an existing connection before initializing and adding
	if peer.identity != [32]byte{} && atomic.LoadUint32(&peer.identityVerified) == 1 {
		if _, exists := it.peersByID[peer.identity]; exists {
			return true
		}
		it.peersByID[peer.identity] = peer
	}
	return false
}

func (it *identityTracker) removePeer(peer *wsPeer) {
	// remove this peer from the identity map if it is there
	if it.peersByID[peer.identity] == peer {
		delete(it.peersByID, peer.identity)
	}
}

// NewIdentityChallengeAndHeader will create an identityChallenge, and will return the underlying 32 byte challenge itself,
// and the Signed and B64 encoded header of the challenge object
func NewIdentityChallengeAndHeader(keys *crypto.SignatureSecrets, addr string) ([32]byte, string) {
	c := identityChallenge{
		Key:       keys.SignatureVerifier,
		Challenge: [32]byte{},
		Address:   addr,
	}
	crypto.RandBytes(c.Challenge[:])
	return c.Challenge, c.signAndEncodeB64(keys)
}

func (i *identityChallenge) signAndEncodeB64(s *crypto.SignatureSecrets) string {
	i.Signature = s.SignBytes(i.signableBytes())
	enc := protocol.EncodeReflect(i)
	b64enc := base64.StdEncoding.EncodeToString(enc)
	return b64enc
}

func (i identityChallenge) signableBytes() []byte {
	return bytes.Join([][]byte{
		[]byte("IC"),
		i.Challenge[:],
		i.Key[:],
		[]byte(i.Address),
	},
		[]byte(":"))
}

// IdentityChallengeFromB64 will decode a B64 string (from a HTTP request header) and will build an IdentityChallenge from it
func IdentityChallengeFromB64(i string) identityChallenge {
	msg, err := base64.StdEncoding.DecodeString(i)
	if err != nil {
		return identityChallenge{}
	}
	ret := identityChallenge{}
	err = protocol.DecodeReflect(msg, &ret)
	if err != nil {
		return identityChallenge{}
	}
	return ret
}

// Verify checks that the signature included in the identityChallenge was indeed created by the included Key
func (i identityChallenge) Verify() bool {
	return i.Key.VerifyBytes(i.signableBytes(), i.Signature)
}

// NewIdentityResponseChallengeAndHeader will generate an Identity Challenge Response from the given Identity Challenge,
// and will return the "Response Challenge" (a novel challenge) and the signed and b64 encoded header for response
func NewIdentityResponseChallengeAndHeader(keys *crypto.SignatureSecrets, c identityChallenge) ([32]byte, string) {
	r := identityChallengeResponse{
		Key:               keys.SignatureVerifier,
		Challenge:         c.Challenge,
		ResponseChallenge: [32]byte{},
	}
	crypto.RandBytes(r.ResponseChallenge[:])
	return r.ResponseChallenge, r.signAndEncodeB64(keys)
}

func (i *identityChallengeResponse) signAndEncodeB64(s *crypto.SignatureSecrets) string {
	i.Signature = s.SignBytes(i.signableBytes())
	enc := protocol.EncodeReflect(i)
	b64enc := base64.StdEncoding.EncodeToString(enc)
	return b64enc
}

func (i identityChallengeResponse) signableBytes() []byte {
	return bytes.Join([][]byte{
		[]byte("ICR"),
		i.Challenge[:],
		i.ResponseChallenge[:],
		i.Key[:],
	},
		[]byte(":"))
}

// IdentityChallengeResponseFromB64 will return an Identity Challenge Response from the B64 header string
func IdentityChallengeResponseFromB64(i string) identityChallengeResponse {
	msg, err := base64.StdEncoding.DecodeString(i)
	if err != nil {
		return identityChallengeResponse{}
	}
	ret := identityChallengeResponse{}
	err = protocol.DecodeReflect(msg, &ret)
	if err != nil {
		return identityChallengeResponse{}
	}
	return ret
}

// Verify checks that the signature included in the identityChallengeResponse was indeed created by the included Key
func (i identityChallengeResponse) Verify() bool {
	return i.Key.VerifyBytes(i.signableBytes(), i.Signature)
}

// SendIdentityChallengeVerification sends the 3rd (final) message for signature handshake between two peers.
// it simply sends across a signature of a challenge which the potential peer has given it to sign.
// at this stage in the peering process, the peer hasn't had an opportunity to verify our supposed identity
func SendIdentityChallengeVerification(wp *wsPeer, sig crypto.Signature) error {
	mbytes := append([]byte(protocol.NetIDVerificationTag), sig[:]...)
	sent := wp.writeNonBlock(context.Background(), mbytes, true, crypto.Digest{}, time.Now())
	if !sent {
		return fmt.Errorf("could not send identity challenge verification")
	}
	return nil
}

// identityVerificationHandler receives a signature over websocket, and confirms it matches the
// sender's claimed identity and the challenge that was assigned to it. If it verifies, the network will mark it verified,
// and will do any related record keeping it needs
func identityVerificationHandler(message IncomingMessage) OutgoingMessage {
	peer := message.Sender.(*wsPeer)
	// avoid doing work (crypto and potentially taking a lock) if the peer is already verified
	if atomic.LoadUint32(&peer.identityVerified) == 1 {
		return OutgoingMessage{}
	}
	sig := crypto.Signature{}
	copy(sig[:], message.Data[:64])
	if peer.identity.VerifyBytes(peer.identityChallenge[:], sig) {
		peer.IdentityVerified()
		if peer.net != nil {
			peer.net.MarkVerified(peer)
		}
	}
	return OutgoingMessage{}
}

var identityHandlers = []TaggedMessageHandler{
	{protocol.NetIDVerificationTag, HandlerFunc(identityVerificationHandler)},
}
