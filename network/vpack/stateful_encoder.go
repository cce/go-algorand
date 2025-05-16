// stateful_encoder.go
package vpack

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
)

// ─────────────────────────────────────────────────────────────────────────────
// 0 · Key bundles and hashing helpers
// ─────────────────────────────────────────────────────────────────────────────

// pk bundle = 32-byte pk + 64-byte signature
type pkBundle struct {
	pk  [32]byte
	sig [64]byte
}
type pk2Bundle struct {
	pk2  [32]byte
	sig2 [64]byte
}
type proposalBundle struct {
	dig, encdig, oprop [32]byte
	operEnc            [9]byte // msgp varuint encoding of oper
	operLen            uint8   // length of operEnc
	maskP              uint8   // which digests/oper/oprop were present
}

// very cheap 64-bit mix good enough for in-process tables
func mix64(x uint64) uint64 {
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	x *= 0xc4ceb9fe1a85ec53
	x ^= x >> 33
	return x
}
func hash32(x *[32]byte) uint64 {
	return mix64(binary.LittleEndian.Uint64(x[:8]) ^ binary.LittleEndian.Uint64(x[24:]))
}
func hashPK(pb pkBundle) uint64 {
	return mix64(hash32(&pb.pk) ^ binary.LittleEndian.Uint64(pb.sig[:8]))
}
func hashPK2(pb pk2Bundle) uint64 {
	return mix64(hash32(&pb.pk2) ^ binary.LittleEndian.Uint64(pb.sig2[:8]))
}
func hashProp(pb proposalBundle) uint64 {
	return mix64(
		hash32(&pb.dig) ^
			hash32(&pb.encdig) ^
			hash32(&pb.oprop) ^
			binary.LittleEndian.Uint64(pb.operEnc[:8]),
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1 · Generic 1024-bucket 2-way table  (zero alloc)
// ─────────────────────────────────────────────────────────────────────────────

const buckets1024 = 1024
const bucketMask = buckets1024 - 1

type bucket2[K comparable] struct{ key [2]K }

type table2[K comparable] struct {
	bkt [buckets1024]bucket2[K]
	mru [buckets1024 / 8]byte // 1 bit / bucket
}

func (t *table2[K]) mruSlot(b uint32) uint32 {
	if (t.mru[b>>3]>>(b&7))&1 == 0 {
		return 1
	}
	return 0
}
func (t *table2[K]) setMRU(b, slot uint32) {
	byteIdx := b >> 3
	mask := byte(1 << (b & 7))
	if slot == 0 {
		t.mru[byteIdx] &^= mask
	} else {
		t.mru[byteIdx] |= mask
	}
}
func (t *table2[K]) lookup(k K, h uint64) (id uint16, ok bool) {
	b := uint32(h) & bucketMask
	bk := &t.bkt[b]
	if bk.key[0] == k {
		t.setMRU(b, 0)
		return uint16(b<<1 | 0), true
	}
	if bk.key[1] == k {
		t.setMRU(b, 1)
		return uint16(b<<1 | 1), true
	}
	return 0, false
}
func (t *table2[K]) insert(k K, h uint64) uint16 {
	b := uint32(h) & bucketMask
	evict := t.mruSlot(b) // LRU slot
	t.bkt[b].key[evict] = k
	t.setMRU(b, evict^1) // new key → MRU
	return uint16(b<<1 | evict)
}
func (t *table2[K]) key(id uint16) (K, bool) {
	b := id >> 1
	slot := id & 1
	if b >= buckets1024 {
		var zero K
		return zero, false
	}
	return t.bkt[b].key[slot], true
}

// ─────────────────────────────────────────────────────────────────────────────
// 2 · 8-slot MRU window (24-bit order = 3 bits / logical slot)
// ─────────────────────────────────────────────────────────────────────────────

type propWindow struct {
	order uint32 // 24 bits: [lsb] slot0 slot1 … slot7 [msb]
	size  int
	key   [8]proposalBundle
}

func (w *propWindow) slotAt(pos int) uint8 { return uint8(w.order >> (pos * 3) & 7) }
func (w *propWindow) setSlot(pos int, s uint8) {
	shift := pos * 3
	w.order &^= 7 << shift
	w.order |= uint32(s) << shift
}

func (w *propWindow) indexOf(pb proposalBundle) (int, bool) {
	for i := 0; i < w.size; i++ {
		if w.key[w.slotAt(i)] == pb {
			return i, true
		}
	}
	return -1, false
}

func (w *propWindow) pushFront(pb proposalBundle, phys uint8) {
	if w.size < 8 {
		w.size++
	}
	// shift logical order right by 3 bits (slot7 ← slot6 ← … ← slot0)
	w.order <<= 3
	w.order |= uint32(phys)
	w.key[phys] = pb
}

// get physical slot to overwrite (LRU = logical 7)
func (w *propWindow) lruSlot() uint8 { return w.slotAt(7) }

// ─────────────────────────────────────────────────────────────────────────────
// 3 · Stateful encoder
// ─────────────────────────────────────────────────────────────────────────────

type StatefulEncoder struct {
	// 2-way tables
	sndTab table2[[32]byte]
	pkTab  table2[pkBundle]
	pk2Tab table2[pk2Bundle]

	// proposal 8-slot window
	propWin propWindow

	// last round number
	lastRnd uint64

	// Optional metrics collector
	metrics *CompressionMetrics
}

func encodeDynamicRef(id uint16, dst *[]byte) {
	// use binary AppendUint16
	*dst = binary.BigEndian.AppendUint16(*dst, id)
}

// SetMetrics assigns a metrics collection object to the encoder
func (e *StatefulEncoder) SetMetrics(metrics *CompressionMetrics) {
	e.metrics = metrics
}

// compress takes stateless-encoded vote (canonical order) and
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

	// Collect metrics if enabled
	if e.metrics != nil {
		atomic.AddUint64(&e.metrics.TotalOps, 1)
	}

	// ---- cred.pf  ----------------------------------------------------
	out = append(out, src[pos:pos+80]...)
	pos += 80

	// ---- optional r.per ---------------------------------------------
	if (maskP & bitPer) != 0 {
		n := msgpVaruintLen(src[pos])
		out = append(out, src[pos:pos+n]...)
		pos += n
	}

	// ---- proposal fields --------------------------------------------
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

	// look-up in 8-slot window
	if idx, ok := e.propWin.indexOf(prop); ok {
		// reference
		hdr1 |= byte(idx+1) << 2 // 001..111  (000 will mean literal)
		e.propWin.pushFront(prop, e.propWin.slotAt(idx))
		// Metrics: proposal hit
		if e.metrics != nil {
			atomic.AddUint64(&e.metrics.PropHits, 1)
			var bytesSaved uint64
			if (maskP & bitDig) != 0 {
				bytesSaved += 32
			}
			if (maskP & bitEncDig) != 0 {
				bytesSaved += 32
			}
			if (maskP & bitOper) != 0 {
				bytesSaved += uint64(prop.operLen)
			}
			if (maskP & bitOprop) != 0 {
				bytesSaved += 32
			}
			atomic.AddUint64(&e.metrics.PropBytesSaved, bytesSaved)
		}
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
		// Metrics: proposal miss
		if e.metrics != nil {
			atomic.AddUint64(&e.metrics.PropMiss, 1)
		}
	}

	// ---- r.rnd -------------------------------------------------------
	rndStart := pos
	n := msgpVaruintLen(src[pos])
	rnd := decodeMsgpVaruint(src[pos : pos+n])
	pos += n

	switch {
	case rnd == e.lastRnd:
		hdr1 |= 0b11 // rndOp = same
		if e.metrics != nil {
			atomic.AddUint64(&e.metrics.RoundSame, 1)
			atomic.AddUint64(&e.metrics.RoundBytesSaved, uint64(n))
		}
	case rnd == e.lastRnd+1:
		hdr1 |= 0b01
		if e.metrics != nil {
			atomic.AddUint64(&e.metrics.RoundPlus1, 1)
			atomic.AddUint64(&e.metrics.RoundBytesSaved, uint64(n))
		}
	case rnd == e.lastRnd-1:
		hdr1 |= 0b10
		if e.metrics != nil {
			atomic.AddUint64(&e.metrics.RoundMinus1, 1)
			atomic.AddUint64(&e.metrics.RoundBytesSaved, uint64(n))
		}
	default:
		// literal
		hdr1 |= 0b00
		out = append(out, src[rndStart:pos]...)
		if e.metrics != nil {
			atomic.AddUint64(&e.metrics.RoundLiteral, 1)
		}
	}
	e.lastRnd = rnd

	// ---- r.snd  (sender address) ------------------------------------
	var snd [32]byte
	copy(snd[:], src[pos:pos+32])
	pos += 32
	if id, ok := e.sndTab.lookup(snd, hash32(&snd)); ok {
		hdr1 |= 1 << 5 // sndRef
		encodeDynamicRef(id, &out)
		if e.metrics != nil {
			atomic.AddUint64(&e.metrics.SenderHits, 1)
			atomic.AddUint64(&e.metrics.SenderBytesSaved, 32-2)
		}
	} else {
		out = append(out, snd[:]...)
		id := e.sndTab.insert(snd, hash32(&snd))
		_ = id
		if e.metrics != nil {
			atomic.AddUint64(&e.metrics.SenderMiss, 1)
		}
	}

	// ---- optional r.step --------------------------------------------
	if (maskP & bitStep) != 0 {
		n := msgpVaruintLen(src[pos])
		out = append(out, src[pos:pos+n]...)
		pos += n
	}

	// ---- sig.p + sig.p1s  (pk bundle) -------------------------------
	var pk pkBundle
	copy(pk.pk[:], src[pos:pos+32])
	pos += 32
	copy(pk.sig[:], src[pos:pos+64])
	pos += 64

	// if id, ok := e.pkTab.lookup(pk, hashPK(pk)); ok {
	// 	hdr1 |= 1 << 6 // pkRef
	// 	encodeDynamicRef(id, &out)
	// 	if e.metrics != nil {
	// 		atomic.AddUint64(&e.metrics.PKHits, 1)
	// 		atomic.AddUint64(&e.metrics.PKBytesSaved, 96-2)
	// 	}
	// } else {
	out = append(out, pk.pk[:]...)
	out = append(out, pk.sig[:]...)
	_ = e.pkTab.insert(pk, hashPK(pk))
	if e.metrics != nil {
		atomic.AddUint64(&e.metrics.PKMiss, 1)
	}
	// }

	// ---- sig.p2 + sig.p2s (pk2 bundle) ------------------------------
	var pk2 pk2Bundle
	copy(pk2.pk2[:], src[pos:pos+32])
	pos += 32
	copy(pk2.sig2[:], src[pos:pos+64])
	pos += 64

	if id, ok := e.pk2Tab.lookup(pk2, hashPK2(pk2)); ok {
		hdr1 |= 1 << 7 // pk2Ref
		encodeDynamicRef(id, &out)
		if e.metrics != nil {
			atomic.AddUint64(&e.metrics.PK2Hits, 1)
			atomic.AddUint64(&e.metrics.PK2BytesSaved, 96-2)
		}
	} else {
		out = append(out, pk2.pk2[:]...)
		out = append(out, pk2.sig2[:]...)
		_ = e.pk2Tab.insert(pk2, hashPK2(pk2))
		if e.metrics != nil {
			atomic.AddUint64(&e.metrics.PK2Miss, 1)
		}
	}

	// ---- sig.s -------------------------------------------------------
	out = append(out, src[pos:pos+64]...)
	pos += 64

	if pos != len(src) {
		return nil, errors.New("stateless parse mismatch")
	}

	// fill in headers
	out[0] = maskP
	out[1] = hdr1
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// 4 · Small helpers
// ─────────────────────────────────────────────────────────────────────────────

func msgpVaruintLen(first byte) int {
	switch first {
	case 0xcc:
		return 2
	case 0xcd:
		return 3
	case 0xce:
		return 5
	case 0xcf:
		return 9
	default: // fixint
		return 1
	}
}
func decodeMsgpVaruint(buf []byte) uint64 {
	switch buf[0] {
	case 0xcc:
		return uint64(buf[1])
	case 0xcd:
		return uint64(binary.BigEndian.Uint16(buf[1:]))
	case 0xce:
		return uint64(binary.BigEndian.Uint32(buf[1:]))
	case 0xcf:
		return binary.BigEndian.Uint64(buf[1:])
	default:
		return uint64(buf[0])
	}
}
