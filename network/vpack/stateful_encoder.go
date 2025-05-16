// stateful_encoder.go
package vpack

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// StatefulEncoder compresses votes by using references to previously seen values
// from earlier votes.
type StatefulEncoder struct {
	// 2-way tables
	sndTab lruTable[[32]byte]
	pkTab  lruTable[pkBundle]
	pk2Tab lruTable[pk2Bundle]

	// proposal 8-slot window
	propWin propWindow

	// last round number
	lastRnd uint64
}

func encodeDynamicRef(id uint16, dst *[]byte) {
	*dst = binary.BigEndian.AppendUint16(*dst, id)
}

// Compress takes stateless-encoded vote (canonical order) and
// returns stateful-compressed buffer.
func (e *StatefulEncoder) Compress(dst, src []byte) ([]byte, error) {
	if len(src) < 2 {
		return nil, errors.New("src too short")
	}
	maskP := src[0] // header[0] from stateless encoder
	pos := 2        // reader cursor

	// prepare output, leave room for 2-byte header
	out := dst[:0]
	out = append(out, 0, 0) // placeholder

	var hdr1 byte

	// cred.pf
	out = append(out, src[pos:pos+80]...)
	pos += 80

	// r.per
	if (maskP & bitPer) != 0 {
		n := msgpVaruintLen(src[pos])
		out = append(out, src[pos:pos+n]...)
		pos += n
	}

	// r.prop
	// copy proposal fields for table lookup
	var prop proposalBundle
	prop.maskP = maskP & propFieldsMask
	if (maskP & bitDig) != 0 {
		copy(prop.dig[:], src[pos:pos+32])
		pos += 32
	}
	if (maskP & bitEncDig) != 0 {
		copy(prop.encdig[:], src[pos:pos+32])
		pos += 32
	}
	if (maskP & bitOper) != 0 {
		n := msgpVaruintLen(src[pos])
		copy(prop.operEnc[:], src[pos:pos+n])
		prop.operLen = uint8(n)
		pos += n
	}
	if (maskP & bitOprop) != 0 {
		copy(prop.oprop[:], src[pos:pos+32])
		pos += 32
	}

	// look up in sliding window
	if idx, ok := e.propWin.indexOf(prop); ok {
		// reference
		hdr1 |= byte(idx+1) << 2 // 001..111  (000 will mean literal)
		e.propWin.pushFront(prop, e.propWin.slotAt(idx))
	} else {
		// literal
		hdr1 |= 0 << 2 // 000
		phys := e.propWin.lruSlot()
		e.propWin.pushFront(prop, phys)

		// write the literal bytes exactly as in stateless stream
		if (maskP & bitDig) != 0 {
			out = append(out, prop.dig[:]...)
		}
		if (maskP & bitEncDig) != 0 {
			out = append(out, prop.encdig[:]...)
		}
		if (maskP & bitOper) != 0 {
			out = append(out, prop.operEnc[:prop.operLen]...)
		}
		if (maskP & bitOprop) != 0 {
			out = append(out, prop.oprop[:]...)
		}
	}

	// r.rnd
	rndStart := pos
	n := msgpVaruintLen(src[pos])
	rnd := decodeMsgpVaruint(src[pos : pos+n])
	pos += n

	switch {
	case rnd == e.lastRnd:
		hdr1 |= 0b11 // rndOp = same
	case rnd == e.lastRnd+1:
		hdr1 |= 0b01
	case rnd == e.lastRnd-1:
		hdr1 |= 0b10
	default:
		// literal
		hdr1 |= 0b00
		out = append(out, src[rndStart:pos]...)
	}
	e.lastRnd = rnd

	// r.snd
	var snd [32]byte
	copy(snd[:], src[pos:pos+32])
	pos += 32
	if id, ok := e.sndTab.lookup(snd, hash32(&snd)); ok {
		hdr1 |= 1 << 5 // sndRef
		encodeDynamicRef(id, &out)
	} else {
		out = append(out, snd[:]...)
		id := e.sndTab.insert(snd, hash32(&snd))
		_ = id
	}

	// r.step
	if (maskP & bitStep) != 0 {
		n := msgpVaruintLen(src[pos])
		out = append(out, src[pos:pos+n]...)
		pos += n
	}

	// sig.p + sig.p1s
	var pk pkBundle
	copy(pk.pk[:], src[pos:pos+32])
	pos += 32
	copy(pk.sig[:], src[pos:pos+64])
	pos += 64

	if id, ok := e.pkTab.lookup(pk, hashPK(pk)); ok {
		hdr1 |= 1 << 6 // pkRef
		encodeDynamicRef(id, &out)
	} else {
		out = append(out, pk.pk[:]...)
		out = append(out, pk.sig[:]...)
		_ = e.pkTab.insert(pk, hashPK(pk))
	}

	// sig.p2 + sig.p2s
	var pk2 pk2Bundle
	copy(pk2.pk2[:], src[pos:pos+32])
	pos += 32
	copy(pk2.sig2[:], src[pos:pos+64])
	pos += 64

	if id, ok := e.pk2Tab.lookup(pk2, hashPK2(pk2)); ok {
		hdr1 |= 1 << 7 // pk2Ref
		encodeDynamicRef(id, &out)
	} else {
		out = append(out, pk2.pk2[:]...)
		out = append(out, pk2.sig2[:]...)
		_ = e.pk2Tab.insert(pk2, hashPK2(pk2))
	}

	// sig.s
	out = append(out, src[pos:pos+64]...)
	pos += 64

	if pos != len(src) {
		return nil, fmt.Errorf("length mismatch: expected %d, got %d", len(src), pos)
	}

	// fill in headers
	out[0] = maskP
	out[1] = hdr1
	return out, nil
}
