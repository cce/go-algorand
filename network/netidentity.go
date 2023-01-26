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
	"encoding/base64"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

// netidentity holds the functionality to participate in "Identity Challenge Exchange"
// with the purpose of identitfying redundant and bidirectional connections and prevent them.
// the identity challenge exchange protocol is a 3 way handshake that exchanges signed messages.
// Message 1 (Identity Challenge): when a peering request is made, an identityChallenge is attached with:
// - a 32 byte random challenge
// - the requester's "identity" PublicKey
// - the PublicAddress of the intended recipient
// - a Nonce "IC"
// - Signature of the above by the requester's PublicKey
// Message 2 (Identity Challenge Response): when responding to a peering request,
// if the identity challenge is correct, an identityChallengeResponse is attached with:
// - the original 32 byte random challenge
// - a new "response" 32 byte random challenge
// - the responder's "identity" PublicKey
// - a Nonce "ICR"
// - Signature of the above by the responder's PublicKey
// Message 3 (Identity Verification): if the identityChallengeResponse is correct,
// the requester sends a message "NI" over websocket to verify its identity PublicKey, with:
// - Signature of the resposne challenge by the requester's PublicKey
//
// Upon receipt of Message 2, the requester has enough data to consider the peer's Identity "verified"
// Upon receipt of Message 3, the responder has enough data to consider the peer's Identity "verified"
// at each of these steps, if the peer's identity is verified, wsNetwork will attempt to add it to the
// identityTracker, which maintains a single peer per identity PublicKey. If the identity is already in use
// by another peer, we know this connection is duplicate and can be closed or disconnected
//
// Protocol Enablement:
// Identity Challenge Exchange is optional for peers, and is enabled by setting PublicAddress in the node's config
// to either the address used in Foundation DNS, or to "auto" to attempt to load the PublicAddress after the listener starts.
//
// Protocol Error Handling:
// Message 1
// - If the Message is not included, assume the peer does not use identity exchange, and peer without attaching an identityChallengeResponse
// - If the Address included in the challenge is not this node's PublicAddress, peering continues without identity exchange.
//   this is so that if an operator misconfigures PublicAddress, it does not decline well meaning peering attempts
// - If the Message is malformed or cannot be decoded, the peering attempt is stopped
// - If the Signature in the challenge does not verify to the included key, the peering attempt is stopped
// Message 2
// - If the Message is not included, assume the peer does not use identity exchange, and do not send Message 3
// - If the Message is malformed or cannot be decoded, the peering attempt is stopped
// - If the original 32 Byte challenge does not match the one sent in Message 1, the peering attempt is stopped
// - If the Signature in the challenge does not verify to the included key, the peering attempt is stopped
// Message 3
// - If the Message is malformed or cannot be decoded, the peer is disconnected
// - If the Signature in the challenge does not verify peer's assumed PublicKey and assigned Challenge Bytes, the peer is disconnected
// - If the Message is expected (if the requester used identity challenge), wsNetwork will check that the peer verified within 5 seconds, or will disconnect

const maxAddressLen = 256 + 32 // Max DNS (255) + margin for port specification

// identityChallengeValue is 32 random bytes used for identity challenge exchange
type identityChallengeValue [32]byte

func newIdentityChallengeValue() identityChallengeValue {
	var ret identityChallengeValue
	crypto.RandBytes(ret[:])
	return ret
}

type identityChallengeScheme interface {
	AttachChallenge(attach http.Header, addr string) identityChallengeValue
	VerifyAndAttachResponse(attach http.Header, h http.Header) (identityChallengeValue, crypto.PublicKey, error)
	VerifyResponse(h http.Header, c identityChallengeValue) (crypto.PublicKey, []byte, error)
}

// identityChallengePublicKeyScheme implements IdentityChallengeScheme by
// exchanging and verifying public key challenges and attaching them to headers,
// or returning the message payload to be sent
type identityChallengePublicKeyScheme struct {
	dedupName    string
	identityKeys *crypto.SignatureSecrets
}

// NewIdentityChallengeScheme will create a default Identification Scheme
func NewIdentityChallengeScheme(dn string) *identityChallengePublicKeyScheme {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])

	return &identityChallengePublicKeyScheme{
		dedupName:    dn,
		identityKeys: crypto.GenerateSignatureSecrets(seed),
	}
}

// AttachChallenge will generate a new identity challenge
// and will encode and attach the challenge as a header.
// returns the identityChallengeValue used for this challenge so the network can confirm it later
// or returns an empty challenge if dedupName is not set
func (i identityChallengePublicKeyScheme) AttachChallenge(attach http.Header, addr string) identityChallengeValue {
	if i.dedupName == "" {
		return identityChallengeValue{}
	}
	c := identityChallenge{
		Key:       i.identityKeys.SignatureVerifier,
		Challenge: newIdentityChallengeValue(),
		Address:   []byte(addr),
	}

	attach.Add(IdentityChallengeHeader, c.signAndEncodeB64(i.identityKeys))
	return c.Challenge
}

// VerifyAndAttachResponse  headers for an Identity Challenge, and verifies:
// * the provided challenge bytes matches the one encoded in the header
// * the identity challenge verifies against the included key
// * the "Address" field matches what this scheme expects
// once verified, it will attach the header to the "attach" header
// and will return the challenge and identity of the peer for recording
// or returns empty values if the header did not end up getting set
func (i identityChallengePublicKeyScheme) VerifyAndAttachResponse(attach http.Header, h http.Header) (identityChallengeValue, crypto.PublicKey, error) {
	// if dedupName is not set, this scheme is not configured to exchange identity
	if i.dedupName == "" {
		return identityChallengeValue{}, crypto.PublicKey{}, nil
	}
	// if the headerString is not populated, the peer isn't participating in identity exchange
	headerString := h.Get(IdentityChallengeHeader)
	if headerString == "" {
		return identityChallengeValue{}, crypto.PublicKey{}, nil
	}
	// decode the header to an identityChallenge
	msg, err := base64.StdEncoding.DecodeString(headerString)
	if err != nil {
		return identityChallengeValue{}, crypto.PublicKey{}, err
	}
	idChal := identityChallenge{}
	err = protocol.Decode(msg, &idChal)
	if err != nil {
		return identityChallengeValue{}, crypto.PublicKey{}, err
	}
	if !idChal.Verify() {
		return identityChallengeValue{}, crypto.PublicKey{}, fmt.Errorf("identity challenge incorrectly signed")
	}
	// if the address is not meant for this host, return without attaching headers,
	// but also do not emit an error. This is because if an operator were to incorrectly
	// specify their dedupName, it could result in inappropriate disconnections from valid peers
	if string(idChal.Address) != i.dedupName {
		return identityChallengeValue{}, crypto.PublicKey{}, nil
	}
	// make the response object, encode it and attach it to the header
	r := identityChallengeResponse{
		Key:               i.identityKeys.SignatureVerifier,
		Challenge:         idChal.Challenge,
		ResponseChallenge: newIdentityChallengeValue(),
	}
	attach.Add(IdentityChallengeHeader, r.signAndEncodeB64(i.identityKeys))
	return r.ResponseChallenge, idChal.Key, nil
}

// VerifyResponse will decode the identity challenge header and confirm it self-verifies,
// and that the provided challenge matches the encoded one
// if the response can be verified, it returns the identity of the peer and a final Verification Message to send to the peer
// otherwise, returns empty values
func (i identityChallengePublicKeyScheme) VerifyResponse(h http.Header, c identityChallengeValue) (crypto.PublicKey, []byte, error) {
	headerString := h.Get(IdentityChallengeHeader)
	// if the header is not populated, assume the peer is not participating in identity exchange
	if headerString == "" {
		return crypto.PublicKey{}, []byte{}, nil
	}
	msg, err := base64.StdEncoding.DecodeString(headerString)
	if err != nil {
		return crypto.PublicKey{}, []byte{}, err
	}
	resp := identityChallengeResponse{}
	err = protocol.Decode(msg, &resp)
	if err != nil {
		return crypto.PublicKey{}, []byte{}, err
	}
	if resp.Challenge != c {
		return crypto.PublicKey{}, []byte{}, fmt.Errorf("challenge response did not contain originally issued challenge value")
	}
	if !resp.Verify() {
		return crypto.PublicKey{}, []byte{}, fmt.Errorf("challenge response incorrectly signed ")
	}
	return resp.Key, i.identityVerificationMessage(resp.ResponseChallenge), nil
}

// IdentityVerificationMessage generates the 3rd message of the challenge exchange,
// which a wsNetwork can then send to a peer in order to verify their own identity.
// It is prefixed with the ID Verification tag and returned ready-to-send
func (i *identityChallengePublicKeyScheme) identityVerificationMessage(c identityChallengeValue) []byte {
	msg := identityVerificationMessage{
		Signature: i.identityKeys.SignBytes(c[:]),
	}
	return append([]byte(protocol.NetIDVerificationTag), protocol.Encode(&msg)[:]...)
}

// The initial challenge object, giving the peer a challenge to return (Challenge),
// the presumed identity of this node (Key), the intended recipient (Address), all Signed.
type identityChallenge struct {
	_struct   struct{}               `codec:",omitempty,omitemptyarray"`
	Key       crypto.PublicKey       `codec:"pk"`
	Challenge identityChallengeValue `codec:"c"`
	Address   []byte                 `codec:"a,allocbound=maxAddressLen"`
	Signature crypto.Signature       `codec:"s"`
}

type identityChallengeResponse struct {
	_struct           struct{}               `codec:",omitempty,omitemptyarray"`
	Key               crypto.PublicKey       `codec:"pk"`
	Challenge         identityChallengeValue `codec:"c"`
	ResponseChallenge identityChallengeValue `codec:"rc"`
	Signature         crypto.Signature       `codec:"s"`
}

type identityVerificationMessage struct {
	_struct   struct{}         `codec:",omitempty,omitemptyarray"`
	Signature crypto.Signature `codec:"s"`
}

func (i *identityChallenge) signAndEncodeB64(s *crypto.SignatureSecrets) string {
	i.Signature = s.SignBytes(i.signableBytes())
	enc := protocol.Encode(i)
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

// Verify checks that the signature included in the identityChallenge was indeed created by the included Key
func (i identityChallenge) Verify() bool {
	return i.Key.VerifyBytes(i.signableBytes(), i.Signature)
}

func (i *identityChallengeResponse) signAndEncodeB64(s *crypto.SignatureSecrets) string {
	i.Signature = s.SignBytes(i.signableBytes())
	enc := protocol.Encode(i)
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

// Verify checks that the signature included in the identityChallengeResponse was indeed created by the included Key
func (i identityChallengeResponse) Verify() bool {
	return i.Key.VerifyBytes(i.signableBytes(), i.Signature)
}

// identityVerificationHandler receives a signature over websocket, and confirms it matches the
// sender's claimed identity and the challenge that was assigned to it. If the identity is available,
// the peer is loaded into the identity tracker. Otherwise, we ask the network to disconnect the peer
func identityVerificationHandler(message IncomingMessage) OutgoingMessage {
	peer := message.Sender.(*wsPeer)
	// avoid doing work (crypto and potentially taking a lock) if the peer is already verified
	if atomic.LoadUint32(&peer.identityVerified) == 1 {
		return OutgoingMessage{}
	}
	msg := identityVerificationMessage{}
	err := protocol.Decode(message.Data, &msg)
	if err != nil {
		peer.net.Disconnect(peer)
		return OutgoingMessage{}
	}
	if !peer.identity.VerifyBytes(peer.identityChallenge[:], msg.Signature) {
		peer.net.Disconnect(peer)
		return OutgoingMessage{}
	}
	atomic.StoreUint32(&peer.identityVerified, 1)
	// if the identity could not be claimed by this peer, it means the identity is in use
	peer.net.peersLock.Lock()
	ok := peer.net.identityTracker.setIdentity(peer)
	peer.net.peersLock.Unlock()
	if !ok {
		networkPeerDisconnectDupeIdentity.Inc(nil)
		peer.net.Disconnect(peer)
	}
	return OutgoingMessage{}
}

var identityHandlers = []TaggedMessageHandler{
	{protocol.NetIDVerificationTag, HandlerFunc(identityVerificationHandler)},
}

// identityTracker is used by wsNetwork to manage peer identities for connection deduplication
type identityTracker interface {
	removeIdentity(p *wsPeer)
	setIdentity(p *wsPeer) bool
}

// publicKeyIdentTracker implements identityTracker by
// mapping from PublicKeys exchanged in identity challenges to a peer
// this structure is not thread-safe; it is protected by wn.peersLock.
type publicKeyIdentTracker struct {
	peersByID map[crypto.PublicKey]*wsPeer
}

// NewIdentityTracker returns a new publicKeyIdentTracker
func NewIdentityTracker() *publicKeyIdentTracker {
	return &publicKeyIdentTracker{
		peersByID: make(map[crypto.PublicKey]*wsPeer),
	}
}

// setIdentity attempts to store a peer at its identity.
// returns false if it was unable to load the peer into the given identity
// or true otherwise (if the peer was already there, or if it was added)
func (t *publicKeyIdentTracker) setIdentity(p *wsPeer) bool {
	existingPeer, exists := t.peersByID[p.identity]
	if !exists {
		// the identity is not occupied, so set it and return true
		t.peersByID[p.identity] = p
		return true
	}
	// the identity is occupied, so return false if it is occupied by some *other* peer
	// or true if it is occupied by this peer
	return existingPeer == p
}

// removeIdentity removes the entry in the peersByID map if it exists
// and is occupied by the given peer
func (t *publicKeyIdentTracker) removeIdentity(p *wsPeer) {
	if t.peersByID[p.identity] == p {
		delete(t.peersByID, p.identity)
	}
}
