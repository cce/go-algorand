// Copyright (C) 2019-2025 Algorand, Inc.
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
	"fmt"
	"io"

	"github.com/DataDog/zstd"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/network/vpack"
	"github.com/algorand/go-algorand/protocol"
)

var zstdCompressionMagic = [4]byte{0x28, 0xb5, 0x2f, 0xfd}

const zstdCompressionLevel = zstd.BestSpeed

// zstdCompressMsg returns a concatenation of a tag and compressed data
func zstdCompressMsg(tbytes []byte, d []byte) ([]byte, string) {
	bound := max(zstd.CompressBound(len(d)),
		// although CompressBound allocated more than the src size, this is an implementation detail.
		// increase the buffer size to always have enough space for the raw data if compression fails.
		len(d))
	mbytesComp := make([]byte, len(tbytes)+bound)
	copy(mbytesComp, tbytes)
	comp, err := zstd.CompressLevel(mbytesComp[len(tbytes):], d, zstdCompressionLevel)
	if err != nil {
		// fallback and reuse non-compressed original data
		logMsg := fmt.Sprintf("failed to compress into buffer of len %d: %v", len(d), err)
		copied := copy(mbytesComp[len(tbytes):], d)
		return mbytesComp[:len(tbytes)+copied], logMsg
	}
	mbytesComp = mbytesComp[:len(tbytes)+len(comp)]
	return mbytesComp, ""
}

func vpackCompressVote(tbytes []byte, d []byte) ([]byte, string) {
	var enc vpack.StatelessEncoder
	bound := vpack.MaxCompressedVoteSize
	// Pre-allocate buffer for tag bytes and compressed data
	mbytesComp := make([]byte, len(tbytes)+bound)
	copy(mbytesComp, tbytes)
	comp, err := enc.CompressVote(mbytesComp[len(tbytes):], d)
	if err != nil {
		// fallback and reuse non-compressed original data
		logMsg := fmt.Sprintf("failed to compress vote into buffer of len %d: %v", len(d), err)
		copied := copy(mbytesComp[len(tbytes):], d)
		return mbytesComp[:len(tbytes)+copied], logMsg
	}

	result := mbytesComp[:len(tbytes)+len(comp)]
	return result, ""
}

// MaxDecompressedMessageSize defines a maximum decompressed data size
// to prevent zip bombs. This depends on MaxTxnBytesPerBlock consensus parameter
// and should be larger.
const MaxDecompressedMessageSize = 20 * 1024 * 1024 // some large enough value

// wsPeerMsgCodec performs optional message compression/decompression.
// It handles:
// - zstd compression for proposals (outgoing not implemented)
// - stateless vpack compression for votes (outgoing not implemented)
// - stateful vpack compression for votes (both directions)
type wsPeerMsgCodec struct {
	log    logging.Logger
	origin string

	// decompressors
	ppdec zstdProposalDecompressor
	avdec vpackVoteDecompressor

	// stateful vote compression (if enabled)
	statefulVoteEnabled bool
	statefulVoteEnc     *vpack.StatefulEncoder
	statefulVoteDec     *vpack.StatefulDecoder
}

type zstdProposalDecompressor struct{}

func (dec zstdProposalDecompressor) accept(data []byte) bool {
	return len(data) > 4 && bytes.Equal(data[:4], zstdCompressionMagic[:])
}

type vpackVoteDecompressor struct {
	enabled bool
	dec     *vpack.StatelessDecoder
}

func (dec vpackVoteDecompressor) convert(data []byte) ([]byte, error) {
	return dec.dec.DecompressVote(nil, data)
}

func (dec zstdProposalDecompressor) convert(data []byte) ([]byte, error) {
	r := zstd.NewReader(bytes.NewReader(data))
	defer r.Close()
	b := make([]byte, 0, 3*len(data))
	for {
		if len(b) == cap(b) {
			// grow capacity, retain length
			b = append(b, 0)[:len(b)]
		}
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err != nil {
			if err == io.EOF {
				return b, nil
			}
			return nil, err
		}
		if len(b) > MaxDecompressedMessageSize {
			return nil, fmt.Errorf("proposal data is too large: %d", len(b))
		}
	}
}

// decompress handles incoming message decompression based on tag type
func (c *wsPeerMsgCodec) decompress(tag protocol.Tag, data []byte) ([]byte, error) {
	switch tag {
	case protocol.ProposalPayloadTag:
		// sender might support compressed payload but fail to compress for whatever reason,
		// in this case it sends non-compressed payload - the receiver decompress only if it is compressed.
		if c.ppdec.accept(data) {
			res, err := c.ppdec.convert(data)
			if err != nil {
				return nil, fmt.Errorf("peer %s: %w", c.origin, err)
			}
			return res, nil
		}
		c.log.Warnf("peer %s supported zstd but sent non-compressed data", c.origin)

	case protocol.AgreementVoteTag:
		if c.avdec.enabled {
			res, err := c.avdec.convert(data)
			if err != nil {
				c.log.Warnf("peer %s vote decompress error: %v", c.origin, err)
				// fall back to original data
				return data, nil
			}
			return res, nil
		}

	case protocol.VotePackedTag:
		if c.statefulVoteEnabled && c.statefulVoteDec != nil {
			// The data parameter does not include tag bytes
			c.log.Debugf("Decompressing VP vote: %d bytes", len(data))
			// First decompress to stateless form
			statelessCompressed, err := c.statefulVoteDec.Decompress(make([]byte, 0, vpack.MaxCompressedVoteSize), data)
			if err != nil {
				c.log.Warnf("stateful vote decompression failed: %v, compressed len=%d", err, len(data))
				return nil, err
			}

			// Then decompress stateless form into the original vote body
			var statelessDec vpack.StatelessDecoder
			voteBody, err := statelessDec.DecompressVote(make([]byte, 0, vpack.MaxMsgpackVoteSize), statelessCompressed)
			if err != nil {
				c.log.Warnf("stateless vote decompression failed: %v", err)
				return nil, err
			}

			c.log.Debugf("Decompressed vote: %d -> %d -> %d bytes", len(data), len(statelessCompressed), len(voteBody))
			return voteBody, nil
		}
		return nil, fmt.Errorf("received VP message but stateful compression not enabled")
	}

	return data, nil
}

// compress attempts to compress an outgoing message.
// Currently only supports stateful vote compression.
// Returns compressed data or nil if compression is not applicable/fails.
func (c *wsPeerMsgCodec) compress(tag protocol.Tag, data []byte) []byte {
	if tag == protocol.AgreementVoteTag && c.statefulVoteEnabled && c.statefulVoteEnc != nil {
		// Skip the tag bytes (first 2 bytes are the AV tag)
		if len(data) < 2 {
			return nil
		}
		voteData := data[2:]

		// Note: We don't need to check if the vote is already compressed because
		// stateless compression is handled at the broadcast level and those messages
		// are sent directly to peers that support compression, bypassing this codec

		// First apply stateless compression
		var statelessEnc vpack.StatelessEncoder
		statelessBuf := make([]byte, vpack.MaxCompressedVoteSize)
		statelessCompressed, err := statelessEnc.CompressVote(statelessBuf, voteData)
		if err != nil {
			c.log.Debugf("stateless vote compression failed: %v", err)
			return nil
		}

		// Prepare output buffer: VP tag + compressed data
		vpTag := []byte(protocol.VotePackedTag)
		bound := vpack.MaxCompressedVoteSize
		result := make([]byte, len(vpTag)+bound)
		copy(result, vpTag)

		// Apply stateful compression on top of stateless
		compressed, err := c.statefulVoteEnc.Compress(result[len(vpTag):], statelessCompressed)
		if err != nil {
			c.log.Debugf("stateful vote compression failed: %v", err)
			return nil
		}

		// Return the final message: VP tag + compressed data
		c.log.Debugf("Compressed vote: %d -> %d -> %d bytes", len(voteData), len(statelessCompressed), len(compressed))
		return result[:len(vpTag)+len(compressed)]
	}
	return nil
}

func makeWsPeerMsgCodec(wp *wsPeer) *wsPeerMsgCodec {
	c := wsPeerMsgCodec{
		log:    wp.log,
		origin: wp.originAddress,
	}

	c.ppdec = zstdProposalDecompressor{}
	// have both ends advertised support for compression?
	if wp.enableVoteCompression && wp.vpackVoteCompressionSupported() {
		c.avdec = vpackVoteDecompressor{
			enabled: true,
			dec:     vpack.NewStatelessDecoder(),
		}
	}

	// Initialize stateful compression if both nodes support it and have non-zero table sizes
	if wp.enableVoteCompression && wp.voteCompressionDynamicTableSize > 0 && wp.vpackDynamicCompressionSupported() {
		tableSize := wp.getBestVpackTableSize()
		// Use the minimum of our configured size and the negotiated size
		if tableSize > wp.voteCompressionDynamicTableSize {
			tableSize = wp.voteCompressionDynamicTableSize
		}
		wp.log.Debugf("Initializing stateful compression with table size %d (our max: %d)", tableSize, wp.voteCompressionDynamicTableSize)
		if tableSize > 0 {
			enc, err := vpack.NewStatefulEncoder(tableSize)
			if err != nil {
				wp.log.Warnf("failed to initialize stateful encoder: %v", err)
			} else {
				dec, err := vpack.NewStatefulDecoder(tableSize)
				if err != nil {
					wp.log.Warnf("failed to initialize stateful decoder: %v", err)
				} else {
					c.statefulVoteEnabled = true
					c.statefulVoteEnc = enc
					c.statefulVoteDec = dec
					wp.log.Debugf("Stateful compression enabled")
				}
			}
		}
	}

	return &c
}
