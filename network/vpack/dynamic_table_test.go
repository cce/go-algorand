package vpack

import (
	"bytes"
	"math/rand"
	"testing"
	"testing/quick"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLRUTableInsertLookupFetch(t *testing.T) {
	var tab lruTable[int]

	const bucketHash = 42          // deterministic hash for test
	const baseID = bucketHash << 1 // slot-bit is OR-ed below

	// 1) first insert → slot 1 (bit was 0 ⇒ slot1 LRU)
	id1 := tab.insert(100, bucketHash)
	require.EqualValues(t, baseID|1, id1)

	// lookup flips MRU bit to 1
	id, ok := tab.lookup(100, bucketHash)
	require.True(t, ok)
	require.EqualValues(t, id1, id)

	// 2) second insert → slot 0 (bit=1 ⇒ slot0 LRU)
	id2 := tab.insert(200, bucketHash)
	require.EqualValues(t, baseID, id2)

	// old key (100) is still in slot 1
	_, ok = tab.lookup(100, bucketHash)
	require.True(t, ok)

	// touch key 200 (slot 0) → bit flips to 0
	_, _ = tab.lookup(200, bucketHash)

	// 3) third insert → slot 1 again (bit=0 ⇒ slot1 LRU)
	id3 := tab.insert(300, bucketHash)
	require.EqualValues(t, baseID|1, id3)

	// fetch(id3) returns the value and flips bit to 1→0
	val, ok := tab.fetch(id3)
	require.True(t, ok)
	require.Equal(t, 300, val)

	// 4) after fetch, bit is 0 again, so next insert evicts slot 1
	id4 := tab.insert(400, bucketHash)
	require.EqualValues(t, baseID|1, id4)
}

func TestLRUTableQuick(t *testing.T) {
	cfg := &quick.Config{MaxCount: 5_000, Rand: rand.New(rand.NewSource(time.Now().UnixNano()))}
	f := func(keys []uint32) bool {
		var tab lruTable[uint32]
		for _, k := range keys {
			h := uint16(k & 0x3ff) // confine to existing bucket range
			tab.insert(k, uint64(h))
			id, ok := tab.lookup(k, uint64(h))
			if !ok {
				return false
			}
			if k2, ok := tab.key(id); !ok || k2 != k {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, cfg); err != nil {
		t.Fatalf("quick-check failed: %v", err)
	}
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

func makeTestPropBundle(seed byte) proposalBundle {
	var p proposalBundle
	for i := range p.dig {
		p.dig[i] = seed
	}
	p.operLen = 1
	p.operEnc[0] = seed
	p.maskP = bitDig | bitOper
	return p
}

func (w *propWindow) setSlot(pos int, s uint8) {
	shift := pos * 3
	w.order &^= 7 << shift
	w.order |= uint32(s) << shift
}

func TestPropWindowOrderAndLRU(t *testing.T) {
	var w propWindow

	// fill with 8 unique entries
	for i := 0; i < 8; i++ {
		p := makeTestPropBundle(byte(i))
		w.pushFront(p, uint8(i)) // physical == seed for ease
		if w.size != i+1 {
			t.Fatalf("size incorrect after pushFront")
		}
		// newest should be accessible at logical 0
		if idx, ok := w.indexOf(p); !ok || idx != 0 {
			t.Fatalf("indexOf failed just after insertion")
		}
	}

	// Check logical -> physical mapping
	got := bytes.Buffer{}
	for i := 0; i < 8; i++ {
		got.WriteByte(w.slotAt(i))
	}
	want := []byte{7, 6, 5, 4, 3, 2, 1, 0}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("order wrong: got %v want %v", got.Bytes(), want)
	}

	// LRU should be physical slot of oldest (seed 0)
	if lru := w.lruSlot(); lru != 0 {
		t.Fatalf("lruSlot=%d want 0", lru)
	}

	// insert duplicate of existing entry (seed 3) – should move to front
	p3 := makeTestPropBundle(3)
	if idx, ok := w.indexOf(p3); !ok || idx == 0 {
		t.Fatalf("pre-condition failed; dup not found")
	} else {
		prevPhys := w.slotAt(idx)
		w.pushFront(p3, prevPhys)
	}

	if idx, ok := w.indexOf(p3); !ok || idx != 0 {
		t.Fatalf("duplicate insert did not promote to front")
	}
}
