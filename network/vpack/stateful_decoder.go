// stateful_decoder.go
package vpack

import (
	"encoding/binary"
	"errors"
)

type StatefulDecoder struct {
	// 2-way caches holding FULL VALUES (not handles) – must mirror encoder
	sndTab lruTable[[32]byte]
	pkTab  lruTable[pkBundle]
	pk2Tab lruTable[pk2Bundle]

	propWin propWindow
	lastRnd uint64
}

func decodeDynamicRef(src []byte, pos *int) (uint16, error) {
	if *pos+2 > len(src) {
		return 0, errors.New("truncated ref id")
	}
	id := binary.BigEndian.Uint16(src[*pos : *pos+2])
	*pos += 2
	return id, nil
}

// Decompress reverses StatefulEncoder and *writes* a valid stateless-vpack
// buffer into dst.  Caller can then pass it to StatelessDecoder.
func (d *StatefulDecoder) Decompress(dst, src []byte) ([]byte, error) {
	if len(src) < 2 {
		return nil, errors.New("input shorter than header")
	}
	maskP := src[0]
	hdr1 := src[1]
	pos := 2 // read cursor in src

	// prepare out; stateless size ≤ original
	out := dst[:0]
	out = append(out, maskP, 0) // second byte reserved = 0

	// cred.pf
	if pos+80 > len(src) {
		return nil, errors.New("truncated pf")
	}
	out = append(out, src[pos:pos+80]...)
	pos += 80

	// r.per
	if maskP&bitPer != 0 {
		n := msgpVaruintLen(src[pos])
		out = append(out, src[pos:pos+n]...)
		pos += n
	}

	// r.prop
	propOp := (hdr1 >> 2) & 0x7
	var prop proposalBundle

	switch propOp {
	case 0: // literal follows
		prop.maskP = maskP & propFieldsMask
		if prop.maskP&bitDig != 0 {
			copy(prop.dig[:], src[pos:pos+32])
			pos += 32
		}
		if prop.maskP&bitEncDig != 0 {
			copy(prop.encdig[:], src[pos:pos+32])
			pos += 32
		}
		if prop.maskP&bitOper != 0 {
			n := msgpVaruintLen(src[pos])
			copy(prop.operEnc[:], src[pos:pos+n])
			prop.operLen = uint8(n)
			pos += n
		}
		if prop.maskP&bitOprop != 0 {
			copy(prop.oprop[:], src[pos:pos+32])
			pos += 32
		}
		phys := d.propWin.lruSlot()
		d.propWin.pushFront(prop, phys)

		// emit literal bytes exactly as stateless order
		if prop.maskP&bitDig != 0 {
			out = append(out, prop.dig[:]...)
		}
		if prop.maskP&bitEncDig != 0 {
			out = append(out, prop.encdig[:]...)
		}
		if prop.maskP&bitOper != 0 {
			out = append(out, prop.operEnc[:prop.operLen]...)
		}
		if prop.maskP&bitOprop != 0 {
			out = append(out, prop.oprop[:]...)
		}
	default: // reference 1-7 => slot (op-1)
		idx := int(propOp) - 1
		if idx >= d.propWin.size {
			return nil, errors.New("bad proposal ref")
		}
		phys := d.propWin.slotAt(idx)
		prop = d.propWin.key[phys]
		d.propWin.pushFront(prop, phys)

		// write referenced bundle fields
		if prop.maskP&bitDig != 0 {
			out = append(out, prop.dig[:]...)
		}
		if prop.maskP&bitEncDig != 0 {
			out = append(out, prop.encdig[:]...)
		}
		if prop.maskP&bitOper != 0 {
			out = append(out, prop.operEnc[:prop.operLen]...)
		}
		if prop.maskP&bitOprop != 0 {
			out = append(out, prop.oprop[:]...)
		}
	}

	// r.rnd
	rndOp := hdr1 & 0x3
	var rnd uint64
	switch rndOp {
	case 0b11: // same
		rnd = d.lastRnd
	case 0b01: // +1
		rnd = d.lastRnd + 1
	case 0b10: // −1
		rnd = d.lastRnd - 1
	case 0b00: // literal follows
		n := msgpVaruintLen(src[pos])
		rnd = decodeMsgpVaruint(src[pos : pos+n])
		out = append(out, src[pos:pos+n]...)
		pos += n
	}
	if rndOp != 0b00 {
		out = appendMsgpVaruint(out, rnd)
	}
	d.lastRnd = rnd

	// r.snd
	if hdr1&(1<<5) != 0 { // reference
		id, err := decodeDynamicRef(src, &pos)
		if err != nil {
			return nil, err
		}
		addr, ok := d.sndTab.fetch(id)
		if !ok {
			return nil, errors.New("bad sender ref")
		}
		out = append(out, addr[:]...)
	} else { // literal
		if pos+32 > len(src) {
			return nil, errors.New("truncated sender")
		}
		var addr [32]byte
		copy(addr[:], src[pos:pos+32])
		out = append(out, addr[:]...)
		_ = d.sndTab.insert(addr, hash32(&addr))
		pos += 32
	}

	// r.step
	if maskP&bitStep != 0 {
		n := msgpVaruintLen(src[pos])
		out = append(out, src[pos:pos+n]...)
		pos += n
	}

	// sig.p + p1s
	if hdr1&(1<<6) != 0 { // reference
		id, err := decodeDynamicRef(src, &pos)
		if err != nil {
			return nil, err
		}
		pkb, ok := d.pkTab.fetch(id)
		if !ok {
			return nil, errors.New("bad pk ref")
		}
		out = append(out, pkb.pk[:]...)
		out = append(out, pkb.sig[:]...)
	} else {
		if pos+96 > len(src) {
			return nil, errors.New("truncated pk bundle")
		}
		var pkb pkBundle
		copy(pkb.pk[:], src[pos:pos+32])
		copy(pkb.sig[:], src[pos+32:pos+96])
		out = append(out, pkb.pk[:]...)
		out = append(out, pkb.sig[:]...)
		_ = d.pkTab.insert(pkb, hashPK(pkb))
		pos += 96
	}

	// sig.p2 + p2s
	if hdr1&(1<<7) != 0 { // reference
		id, err := decodeDynamicRef(src, &pos)
		if err != nil {
			return nil, err
		}
		pk2b, ok := d.pk2Tab.fetch(id)
		if !ok {
			return nil, errors.New("bad pk2 ref")
		}
		out = append(out, pk2b.pk2[:]...)
		out = append(out, pk2b.sig2[:]...)
	} else {
		if pos+96 > len(src) {
			return nil, errors.New("truncated pk2 bundle")
		}
		var pk2b pk2Bundle
		copy(pk2b.pk2[:], src[pos:pos+32])
		copy(pk2b.sig2[:], src[pos+32:pos+96])
		out = append(out, pk2b.pk2[:]...)
		out = append(out, pk2b.sig2[:]...)
		_ = d.pk2Tab.insert(pk2b, hashPK2(pk2b))
		pos += 96
	}

	// sig.s
	if pos+64 > len(src) {
		return nil, errors.New("truncated sig.s")
	}
	out = append(out, src[pos:pos+64]...)
	pos += 64

	if pos != len(src) {
		return nil, errors.New("trailing bytes in stateful frame")
	}
	return out, nil
}
