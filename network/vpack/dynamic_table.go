package vpack

import "encoding/binary"

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

// very cheap 64-bit hash function good enough for in-process tables
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

const lruTableBuckets = 1024
const lruTableBucketMask = lruTableBuckets - 1

type bucket2way[K comparable] struct{ key [2]K }

// lruTable is a generic 1024-bucket 2-way table (zero alloc)
type lruTable[K comparable] struct {
	bkt [lruTableBuckets]bucket2way[K]
	mru [lruTableBuckets / 8]byte // 1 bit / bucket
}

func (t *lruTable[K]) mruSlot(b uint32) uint32 {
	if (t.mru[b>>3]>>(b&7))&1 == 0 {
		return 1
	}
	return 0
}

func (t *lruTable[K]) setMRU(b, slot uint32) {
	byteIdx := b >> 3
	mask := byte(1 << (b & 7))
	if slot == 0 {
		t.mru[byteIdx] &^= mask
	} else {
		t.mru[byteIdx] |= mask
	}
}

func (t *lruTable[K]) lookup(k K, h uint64) (id uint16, ok bool) {
	b := uint32(h) & lruTableBucketMask
	bk := &t.bkt[b]
	if bk.key[0] == k {
		t.setMRU(b, 0)
		return uint16(b << 1), true
	}
	if bk.key[1] == k {
		t.setMRU(b, 1)
		return uint16(b<<1 | 1), true
	}
	return 0, false
}

func (t *lruTable[K]) insert(k K, h uint64) uint16 {
	b := uint32(h) & lruTableBucketMask
	evict := t.mruSlot(b) // LRU slot
	t.bkt[b].key[evict] = k
	t.setMRU(b, evict^1) // new key -> MRU
	return uint16(b<<1 | evict)
}

func (t *lruTable[K]) key(id uint16) (K, bool) {
	b := id >> 1
	slot := id & 1
	if b >= lruTableBuckets {
		var zero K
		return zero, false
	}
	return t.bkt[b].key[slot], true
}

// fetch by id and set MRU
func (t *lruTable[K]) fetch(id uint16) (K, bool) {
	b := id >> 1
	slot := id & 1
	if b >= lruTableBuckets {
		var zero K
		return zero, false
	}
	// touch MRU bit
	t.setMRU(uint32(b), uint32(slot)^1)
	return t.bkt[b].key[slot], true
}

// propWindow is an 8-slot MRU window for proposal values
type propWindow struct {
	order uint32 // 24 bits: [lsb] slot0 slot1 ... slot7 [msb]
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
	// shift logical order right by 3 bits (slot7 <- slot6 <- ... <- slot0)
	w.order <<= 3
	w.order |= uint32(phys)
	w.key[phys] = pb
}

// get physical slot to overwrite (LRU = logical 7)
func (w *propWindow) lruSlot() uint8 { return w.slotAt(7) }
