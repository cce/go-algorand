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
	"encoding/binary"
	"fmt"
	"time"

	"github.com/algorand/go-algorand/logging"
)

type timeout struct {
	delta time.Duration
	ch    <-chan time.Time
}

// Monotonic uses the system's monotonic clock to emit timeouts.
type Monotonic[TimeoutType comparable] struct {
	zero     time.Time
	timeouts map[TimeoutType]timeout
}

// MakeMonotonicClock creates a new monotonic clock with a given zero point.
func MakeMonotonicClock[TimeoutType comparable](zero time.Time) Clock[TimeoutType] {
	return &Monotonic[TimeoutType]{
		zero: zero,
	}
}

// Zero returns a new Clock reset to the current time.
func (m *Monotonic[TimeoutType]) Zero() Clock[TimeoutType] {
	z := time.Now()
	logging.Base().Debugf("Clock zeroed to %v", z)
	return MakeMonotonicClock[TimeoutType](z)
}

// TimeoutAt returns a channel that will signal when the duration has elapsed.
func (m *Monotonic[TimeoutType]) TimeoutAt(delta time.Duration, timeoutType TimeoutType) <-chan time.Time {
	if m.timeouts == nil {
		m.timeouts = make(map[TimeoutType]timeout)
	}

	tmt, ok := m.timeouts[timeoutType]
	if ok && tmt.delta == delta {
		// if the new timeout is the same as the current one for that type,
		// return the existing channel.
		return tmt.ch
	}

	tmt = timeout{delta: delta}

	target := m.zero.Add(delta)
	left := time.Until(target)
	if left < 0 {
		ch := make(chan time.Time)
		close(ch)
		tmt.ch = ch
	} else {
		tmt.ch = time.After(left)
	}
	m.timeouts[timeoutType] = tmt
	return tmt.ch
}

// Encode implements Clock.Encode.
func (m *Monotonic[TimeoutType]) Encode() []byte {
	return encodeTime(m.zero)
}

// Decode implements Clock.Decode.
func (m *Monotonic[TimeoutType]) Decode(data []byte) (Clock[TimeoutType], error) {
	zero, err := decodeTime(data)
	if err == nil {
		logging.Base().Debugf("Clock decoded with zero at %v", zero)
	} else {
		logging.Base().Errorf("Clock decoded with zero at %v (err: %v)", zero, err)
	}
	return MakeMonotonicClock[TimeoutType](zero), err
}

// The agreement crash-recovery state stores the monotonic clock's zero point,
// historically written with protocol.EncodeReflect(time.Time) -- that is,
// go-codec's built-in msgpack timestamp extension. encodeTime/decodeTime
// reproduce that exact wire format so state written by an earlier release still
// decodes, while dropping the reflection codec from this path.
const (
	// msgpack lead bytes emitted by go-codec's timestamp encoding.
	mpNil     = 0xc0 // a zero time is encoded as msgpack nil
	mpFixExt4 = 0xd6 // whole seconds that fit in 32 bits
	mpFixExt8 = 0xd7 // seconds (<=34 bits) with nanoseconds packed into the high bits
	mpExt8    = 0xc7 // full 12-byte form for negative or large seconds

	// go-codec tags its msgpack timestamp with ext type -1 (0xff unsigned).
	timeExtTag = 0xff
)

// encodeTime serializes t exactly as go-codec's msgpack encoder does with
// WriteExt enabled. The width selection (4, 8, or 12 payload bytes) mirrors
// go-codec: the 8-byte form packs nanoseconds into the top 30 bits and the
// seconds into the low 34 bits.
func encodeTime(t time.Time) []byte {
	if t.IsZero() {
		return []byte{mpNil}
	}
	t = t.UTC()
	sec, nsec := t.Unix(), uint64(t.Nanosecond())
	var data64 uint64
	l := 4
	if sec >= 0 && sec>>34 == 0 {
		data64 = (nsec << 34) | uint64(sec)
		if data64&0xffffffff00000000 != 0 {
			l = 8
		}
	} else {
		l = 12
	}
	switch l {
	case 4:
		b := make([]byte, 2+4)
		b[0] = mpFixExt4
		b[1] = timeExtTag
		binary.BigEndian.PutUint32(b[2:], uint32(data64))
		return b
	case 8:
		b := make([]byte, 2+8)
		b[0] = mpFixExt8
		b[1] = timeExtTag
		binary.BigEndian.PutUint64(b[2:], data64)
		return b
	default: // 12
		b := make([]byte, 3+12)
		b[0] = mpExt8
		b[1] = 12
		b[2] = timeExtTag
		binary.BigEndian.PutUint32(b[3:], uint32(nsec))
		binary.BigEndian.PutUint64(b[7:], uint64(sec))
		return b
	}
}

// decodeTime inverts encodeTime, accepting the msgpack nil and timestamp
// extension forms that go-codec (with WriteExt) and encodeTime can produce.
func decodeTime(data []byte) (time.Time, error) {
	if len(data) == 0 {
		return time.Time{}, fmt.Errorf("decodeTime: empty input")
	}
	switch data[0] {
	case mpNil:
		return time.Time{}, nil
	case mpFixExt4:
		if len(data) < 2+4 || data[1] != timeExtTag {
			return time.Time{}, fmt.Errorf("decodeTime: malformed fixext4 timestamp")
		}
		sec := binary.BigEndian.Uint32(data[2:6])
		return time.Unix(int64(sec), 0).UTC(), nil
	case mpFixExt8:
		if len(data) < 2+8 || data[1] != timeExtTag {
			return time.Time{}, fmt.Errorf("decodeTime: malformed fixext8 timestamp")
		}
		tv := binary.BigEndian.Uint64(data[2:10])
		return time.Unix(int64(tv&0x00000003ffffffff), int64(tv>>34)).UTC(), nil
	case mpExt8:
		if len(data) < 3+12 || data[1] != 12 || data[2] != timeExtTag {
			return time.Time{}, fmt.Errorf("decodeTime: malformed ext8 timestamp")
		}
		nsec := binary.BigEndian.Uint32(data[3:7])
		sec := binary.BigEndian.Uint64(data[7:15])
		return time.Unix(int64(sec), int64(nsec)).UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("decodeTime: unexpected lead byte 0x%02x", data[0])
	}
}

func (m *Monotonic[TimeoutType]) String() string {
	return time.Time(m.zero).String()
}

// Since returns the time that has passed between the time the clock was last zeroed out and now
func (m *Monotonic[TimeoutType]) Since() time.Duration {
	return time.Since(m.zero)
}
