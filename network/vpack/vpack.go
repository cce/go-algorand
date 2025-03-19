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

package vpack

import (
	"fmt"
	"io"
)

type compressWriter interface {
	writeStatic(idx uint8)
	writeDynamicVaruint(b []byte) error
	writeDynamicBin32(b [32]byte)
	writeLiteralBin64(b [64]byte)
	writeLiteralBin80(b [80]byte)
}

// CompressVoteBound estimates the maximum size needed for compressed vote data
func CompressVoteBound(srcSize int) int {
	// Vote messages typically get ~80% smaller, but we will use
	// the input size as the worst case. If this is too small, CompressVote
	// will return ErrBufferTooSmall (and the caller will send the uncompressed
	// message instead).
	return srcSize
}

// ErrBufferTooSmall is returned when the destination buffer is too small
var ErrBufferTooSmall = fmt.Errorf("destination buffer too small")

// CompressVote compresses a vote in src and writes it to dst.
// If the provided buffer dst is nil or too small, a new slice is allocated.
func (s *StaticEncoder) CompressVote(dst, src []byte) ([]byte, error) {
	bound := CompressVoteBound(len(src))
	// Reuse dst if it's big enough, otherwise allocate a new buffer
	if cap(dst) >= bound {
		dst = dst[0:bound] // Reuse dst buffer with its full capacity
	} else {
		dst = make([]byte, bound)
	}

	// Reset our position to the beginning
	s.cur = dst
	s.pos = 0

	// Compress the data
	err := parseVote(src, s)
	if err != nil {
		return nil, err
	}

	// Check if we overflowed the buffer
	if s.pos > len(dst) {
		return nil, ErrBufferTooSmall
	}

	// Return only the portion that was used
	return dst[:s.pos], nil
}

// StaticEncoder uses a static table to shorten vote messages.
// It is not thread-safe.
type StaticEncoder struct {
	cur []byte // Current buffer we're writing to
	pos int    // Current position in the buffer
}

// NewStaticEncoder returns a new StaticEncoder.
func NewStaticEncoder() *StaticEncoder { return &StaticEncoder{} }

// writeByte writes a single byte to the current buffer
func (s *StaticEncoder) writeByte(b byte) {
	if s.pos < len(s.cur) {
		s.cur[s.pos] = b
	}
	// Always increment pos, so CompressVote can return ErrBufferTooSmall
	s.pos++
}

// writeBytes writes multiple bytes to the current buffer
// This is optimized to avoid per-byte bounds checking when possible
func (s *StaticEncoder) writeBytes(bytes []byte) {
	// If we have enough room in the buffer, use direct copy
	if s.pos+len(bytes) <= len(s.cur) {
		copy(s.cur[s.pos:], bytes)
	}
	// Always increment pos, so CompressVote will return ErrBufferTooSmall
	s.pos += len(bytes)
}

func (s *StaticEncoder) writeStatic(idx uint8) {
	s.writeByte(idx)
}

// writeDynamicVaruint writes a dynamic varuint to the writer.
// It expects readUintBytes to provide a non-empty byte slice containing
// a msgpack varuint encoding of 1, 2, 3, 5, or 9 byte length.
func (s *StaticEncoder) writeDynamicVaruint(b []byte) error {
	var expectedLength int
	switch b[0] {
	case uint8tag:
		expectedLength = 2
		s.writeByte(markerDynamicUint8)
	case uint16tag:
		expectedLength = 3
		s.writeByte(markerDynamicUint16)
	case uint32tag:
		expectedLength = 5
		s.writeByte(markerDynamicUint32)
	case uint64tag:
		expectedLength = 9
		s.writeByte(markerDynamicUint64)
	default:
		if isfixint(b[0]) {
			if len(b) != 1 {
				return fmt.Errorf("unexpected dynamic fixint length %d", len(b))
			}
			// prefix with fixuint marker, so 0x00-0x7f isn't used by fixint
			// this is slightly inefficient, but we have low-numbered period & step fields in the static table
			s.writeByte(markerDynamicFixuint)
			s.writeByte(b[0])
			return nil
		} else {
			return fmt.Errorf("unexpected dynamic varuint marker %x", b[0])
		}
	}
	if len(b) != expectedLength {
		return fmt.Errorf("unexpected dynamic varuint length %d", len(b))
	}
	s.writeBytes(b[1:])
	return nil
}

func (s *StaticEncoder) writeDynamicBin32(b [32]byte) {
	s.writeByte(markerDynamicBin32)
	s.writeBytes(b[:])
}

func (s *StaticEncoder) writeLiteralBin64(b [64]byte) {
	s.writeByte(markerLiteralBin64)
	s.writeBytes(b[:])
}

func (s *StaticEncoder) writeLiteralBin80(b [80]byte) {
	s.writeByte(markerLiteralBin80)
	s.writeBytes(b[:])
}

// StaticDecoder decodes votes encoded by StaticEncoder using a static table.
type StaticDecoder struct{}

// NewStaticDecoder returns a new StaticDecoder.
func NewStaticDecoder() *StaticDecoder { return &StaticDecoder{} }

// DecompressVote decodes a compressed vote in src and appends it to dst.
// To re-use dst, run like: dst = dec.DecompressVote(dst[:0], src)
func (d *StaticDecoder) DecompressVote(dst, src []byte) ([]byte, error) {
	return decompressStatic(dst, src)
}

func decompressStatic(dst, src []byte) ([]byte, error) {
	if dst == nil {
		// typical compression ratio is 1.253
		dst = make([]byte, 0, len(src)*13/10)
	}

	lenb := len(src)
	for pos := 0; pos < lenb; {
		marker := src[pos] // read control byte
		pos++

		switch marker {
		case markerDynamicFixuint:
			if pos >= lenb { // Needs one more byte beyond marker
				// Loses a byte here vs msgpack, because vpack codes 0x00-0x7F are not assigned to fixuint.
				// However only only period and step use fixuint, and we have assigned static indexes for
				// name+value pairs "step":1, "step":2, "step":3, which should save even more.
				return nil, io.ErrUnexpectedEOF
			}
			dst = append(dst, src[pos])
			pos++
		case markerDynamicUint8:
			if pos >= lenb { // Needs one more byte
				return nil, io.ErrUnexpectedEOF
			}
			dst = append(dst, uint8tag, src[pos])
			pos++
		case markerDynamicUint16:
			if pos+1 >= lenb { // Needs two more bytes
				return nil, io.ErrUnexpectedEOF
			}
			dst = append(dst, uint16tag, src[pos], src[pos+1])
			pos += 2
		case markerDynamicUint32:
			if pos+3 >= lenb { // Needs four more bytes
				return nil, io.ErrUnexpectedEOF
			}
			dst = append(dst, uint32tag, src[pos], src[pos+1], src[pos+2], src[pos+3])
			pos += 4
		case markerDynamicUint64:
			if pos+7 >= lenb { // Needs eight more bytes
				return nil, io.ErrUnexpectedEOF
			}
			dst = append(dst, uint64tag, src[pos], src[pos+1], src[pos+2], src[pos+3], src[pos+4], src[pos+5], src[pos+6], src[pos+7])
			pos += 8
		case markerLiteralBin64:
			if pos+63 >= lenb { // Needs 64 more bytes
				return nil, io.ErrUnexpectedEOF
			}
			dst = append(dst, msgpBin8Len64...)
			dst = append(dst, src[pos:pos+64]...)
			pos += 64
		case markerLiteralBin80:
			if pos+79 >= lenb { // Needs 80 more bytes
				return nil, io.ErrUnexpectedEOF
			}
			dst = append(dst, msgpBin8Len80...)
			dst = append(dst, src[pos:pos+80]...)
			pos += 80
		case markerDynamicBin32:
			if pos+31 >= lenb { // Needs 32 more bytes
				return nil, io.ErrUnexpectedEOF
			}
			dst = append(dst, msgpBin8Len32...)
			dst = append(dst, src[pos:pos+32]...)
			pos += 32
		default:
			// assume static table index
			if isStaticIdx(marker) {
				if staticTable[marker] == nil {
					return nil, fmt.Errorf("unexpected static marker: 0x%02x", marker)
				}
				dst = append(dst, staticTable[marker]...)
			} else {
				return nil, fmt.Errorf("unexpected marker: 0x%02x", marker)
			}
		}
	}
	return dst, nil
}
