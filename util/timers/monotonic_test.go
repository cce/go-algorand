// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package timers

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func polled(ch <-chan time.Time) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestMonotonicDelta(t *testing.T) {
	partitiontest.PartitionTest(t)

	var m Monotonic[int]
	var c Clock[int]
	var ch <-chan time.Time

	d := time.Millisecond * 100

	c = m.Zero()
	ch = c.TimeoutAt(d, 0)
	if polled(ch) {
		t.Errorf("channel fired ~100ms early")
	}

	<-time.After(d * 2)
	if !polled(ch) {
		t.Errorf("channel failed to fire at 100ms")
	}

	ch = c.TimeoutAt(d/2, 0)
	if !polled(ch) {
		t.Errorf("channel failed to fire at 50ms")
	}
}

func TestMonotonicZeroDelta(t *testing.T) {
	partitiontest.PartitionTest(t)

	var m Monotonic[int]
	var c Clock[int]
	var ch <-chan time.Time

	c = m.Zero()
	ch = c.TimeoutAt(0, 0)
	if !polled(ch) {
		t.Errorf("read failed on channel at zero timeout")
	}
}

func TestMonotonicNegativeDelta(t *testing.T) {
	partitiontest.PartitionTest(t)

	var m Monotonic[int]
	var c Clock[int]
	var ch <-chan time.Time

	c = m.Zero()
	ch = c.TimeoutAt(-time.Second, 0)
	if !polled(ch) {
		t.Errorf("read failed on channel at negative timeout")
	}
}

func TestMonotonicZeroTwice(t *testing.T) {
	partitiontest.PartitionTest(t)

	var m Monotonic[int]
	var c Clock[int]
	var ch <-chan time.Time

	d := time.Millisecond * 100

	c = m.Zero()
	ch = c.TimeoutAt(d, 0)
	if polled(ch) {
		t.Errorf("channel fired ~100ms early")
	}

	<-time.After(d * 2)
	if !polled(ch) {
		t.Errorf("channel failed to fire at 100ms")
	}

	c = c.Zero()
	ch = c.TimeoutAt(d, 0)
	if polled(ch) {
		t.Errorf("channel fired ~100ms early after call to Zero")
	}

	<-time.After(d * 2)
	if !polled(ch) {
		t.Errorf("channel failed to fire at 100ms after call to Zero")
	}
}

func TestMonotonicEncodeDecode(t *testing.T) {
	partitiontest.PartitionTest(t)

	singleTest := func(c Clock[int], descr string) {
		data := c.Encode()
		c0, err := c.Decode(data)
		if err != nil {
			t.Errorf("decoding error: %v", err)
		}
		if !time.Time(c.(*Monotonic[int]).zero).Equal(time.Time(c0.(*Monotonic[int]).zero)) {
			t.Errorf("%v clock not encoded properly: %v != %v", descr, c, c0)
		}
	}

	var c Clock[int]
	var m Monotonic[int]

	c = Clock[int](&m)
	singleTest(c, "empty")

	c = c.Zero()
	singleTest(c, "Zero()'ed")

	now := time.Now()
	for i := 0; i < 100; i++ {
		r := time.Duration(rand.Int63())
		c = Clock[int](
			&Monotonic[int]{
				zero: now.Add(r),
			},
		)
		singleTest(c, "random")
	}
}

func TestTimeoutTypes(t *testing.T) {
	partitiontest.PartitionTest(t)

	var m Monotonic[int]
	var c Clock[int]

	d := time.Millisecond * 100

	c = m.Zero()
	ch1 := c.TimeoutAt(d, 0)
	ch2 := c.TimeoutAt(d, 1)
	if polled(ch1) {
		t.Errorf("channel fired ~100ms early")
	}
	if polled(ch2) {
		t.Errorf("channel fired ~100ms early")
	}

	if ch1 == ch2 {
		t.Errorf("equal channels for different timeout types")
	}

	<-time.After(d * 2)
	if !polled(ch1) {
		t.Errorf("channel failed to fire at 100ms")
	}
	if !polled(ch2) {
		t.Errorf("channel failed to fire at 100ms")
	}

	ch1 = c.TimeoutAt(d/2, 0)
	if !polled(ch1) {
		t.Errorf("channel failed to fire at 50ms")
	}
	ch2 = c.TimeoutAt(d/2, 0)
	if !polled(ch2) {
		t.Errorf("channel failed to fire at 50ms")
	}
}

// TestClockZeroTimeEncodingCompat pins encodeTime/decodeTime to the go-codec
// reflection encoding that earlier releases wrote to the agreement crash
// database, exercising the msgpack nil, fixext4, fixext8, and ext8 forms.
func TestClockZeroTimeEncodingCompat(t *testing.T) {
	partitiontest.PartitionTest(t)

	cases := []time.Time{
		{},                               // zero -> msgpack nil
		time.Unix(0, 0),                  // epoch
		time.Unix(1751990400, 0),         // whole seconds -> fixext4
		time.Unix(1751990400, 123456789), // seconds + nanoseconds -> fixext8
		time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC),
		time.Unix(-5, 500), // negative seconds -> ext8 (12 bytes)
		// non-UTC zones must encode identically to their UTC instant, since
		// both encoders normalize to UTC before serializing.
		time.Date(2020, 6, 15, 12, 30, 45, 500, time.FixedZone("UTC-5", -5*3600)),
		time.Unix(1751990400, 123456789).In(time.FixedZone("UTC+9", 9*3600)),
		time.Now(),
	}
	for _, tc := range cases {
		// encodeTime must match go-codec byte-for-byte...
		want := protocol.EncodeReflect(tc)
		got := encodeTime(tc)
		require.Equalf(t, want, got, "encodeTime differs from go-codec for %v", tc)

		// ...and decodeTime must recover the same instant.
		back, err := decodeTime(got)
		require.NoErrorf(t, err, "decodeTime(%v)", tc)
		require.Truef(t, tc.UTC().Equal(back), "round-trip mismatch: %v != %v", tc.UTC(), back)
	}
}
