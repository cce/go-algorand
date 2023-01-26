package network

// Code generated by github.com/algorand/msgp DO NOT EDIT.

import (
	"github.com/algorand/msgp/msgp"
)

// The following msgp objects are implemented in this file:
// disconnectReason
//         |-----> MarshalMsg
//         |-----> CanMarshalMsg
//         |-----> (*) UnmarshalMsg
//         |-----> (*) CanUnmarshalMsg
//         |-----> Msgsize
//         |-----> MsgIsZero
//
// identityChallenge
//         |-----> (*) MarshalMsg
//         |-----> (*) CanMarshalMsg
//         |-----> (*) UnmarshalMsg
//         |-----> (*) CanUnmarshalMsg
//         |-----> (*) Msgsize
//         |-----> (*) MsgIsZero
//
// identityChallengeResponse
//             |-----> (*) MarshalMsg
//             |-----> (*) CanMarshalMsg
//             |-----> (*) UnmarshalMsg
//             |-----> (*) CanUnmarshalMsg
//             |-----> (*) Msgsize
//             |-----> (*) MsgIsZero
//
// identityChallengeValue
//            |-----> (*) MarshalMsg
//            |-----> (*) CanMarshalMsg
//            |-----> (*) UnmarshalMsg
//            |-----> (*) CanUnmarshalMsg
//            |-----> (*) Msgsize
//            |-----> (*) MsgIsZero
//
// identityVerificationMessage
//              |-----> (*) MarshalMsg
//              |-----> (*) CanMarshalMsg
//              |-----> (*) UnmarshalMsg
//              |-----> (*) CanUnmarshalMsg
//              |-----> (*) Msgsize
//              |-----> (*) MsgIsZero
//

// MarshalMsg implements msgp.Marshaler
func (z disconnectReason) MarshalMsg(b []byte) (o []byte) {
	o = msgp.Require(b, z.Msgsize())
	o = msgp.AppendString(o, string(z))
	return
}

func (_ disconnectReason) CanMarshalMsg(z interface{}) bool {
	_, ok := (z).(disconnectReason)
	if !ok {
		_, ok = (z).(*disconnectReason)
	}
	return ok
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *disconnectReason) UnmarshalMsg(bts []byte) (o []byte, err error) {
	{
		var zb0001 string
		zb0001, bts, err = msgp.ReadStringBytes(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		(*z) = disconnectReason(zb0001)
	}
	o = bts
	return
}

func (_ *disconnectReason) CanUnmarshalMsg(z interface{}) bool {
	_, ok := (z).(*disconnectReason)
	return ok
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z disconnectReason) Msgsize() (s int) {
	s = msgp.StringPrefixSize + len(string(z))
	return
}

// MsgIsZero returns whether this is a zero value
func (z disconnectReason) MsgIsZero() bool {
	return z == ""
}

// MarshalMsg implements msgp.Marshaler
func (z *identityChallenge) MarshalMsg(b []byte) (o []byte) {
	o = msgp.Require(b, z.Msgsize())
	// omitempty: check for empty values
	zb0002Len := uint32(4)
	var zb0002Mask uint8 /* 5 bits */
	if len((*z).Address) == 0 {
		zb0002Len--
		zb0002Mask |= 0x2
	}
	if (*z).Challenge == (identityChallengeValue{}) {
		zb0002Len--
		zb0002Mask |= 0x4
	}
	if (*z).Key.MsgIsZero() {
		zb0002Len--
		zb0002Mask |= 0x8
	}
	if (*z).Signature.MsgIsZero() {
		zb0002Len--
		zb0002Mask |= 0x10
	}
	// variable map header, size zb0002Len
	o = append(o, 0x80|uint8(zb0002Len))
	if zb0002Len != 0 {
		if (zb0002Mask & 0x2) == 0 { // if not empty
			// string "a"
			o = append(o, 0xa1, 0x61)
			o = msgp.AppendBytes(o, (*z).Address)
		}
		if (zb0002Mask & 0x4) == 0 { // if not empty
			// string "c"
			o = append(o, 0xa1, 0x63)
			o = msgp.AppendBytes(o, ((*z).Challenge)[:])
		}
		if (zb0002Mask & 0x8) == 0 { // if not empty
			// string "pk"
			o = append(o, 0xa2, 0x70, 0x6b)
			o = (*z).Key.MarshalMsg(o)
		}
		if (zb0002Mask & 0x10) == 0 { // if not empty
			// string "s"
			o = append(o, 0xa1, 0x73)
			o = (*z).Signature.MarshalMsg(o)
		}
	}
	return
}

func (_ *identityChallenge) CanMarshalMsg(z interface{}) bool {
	_, ok := (z).(*identityChallenge)
	return ok
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *identityChallenge) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zb0002 int
	var zb0003 bool
	zb0002, zb0003, bts, err = msgp.ReadMapHeaderBytes(bts)
	if _, ok := err.(msgp.TypeError); ok {
		zb0002, zb0003, bts, err = msgp.ReadArrayHeaderBytes(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		if zb0002 > 0 {
			zb0002--
			bts, err = (*z).Key.UnmarshalMsg(bts)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array", "Key")
				return
			}
		}
		if zb0002 > 0 {
			zb0002--
			bts, err = msgp.ReadExactBytes(bts, ((*z).Challenge)[:])
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array", "Challenge")
				return
			}
		}
		if zb0002 > 0 {
			zb0002--
			var zb0004 int
			zb0004, err = msgp.ReadBytesBytesHeader(bts)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array", "Address")
				return
			}
			if zb0004 > maxAddressLen {
				err = msgp.ErrOverflow(uint64(zb0004), uint64(maxAddressLen))
				return
			}
			(*z).Address, bts, err = msgp.ReadBytesBytes(bts, (*z).Address)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array", "Address")
				return
			}
		}
		if zb0002 > 0 {
			zb0002--
			bts, err = (*z).Signature.UnmarshalMsg(bts)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array", "Signature")
				return
			}
		}
		if zb0002 > 0 {
			err = msgp.ErrTooManyArrayFields(zb0002)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array")
				return
			}
		}
	} else {
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		if zb0003 {
			(*z) = identityChallenge{}
		}
		for zb0002 > 0 {
			zb0002--
			field, bts, err = msgp.ReadMapKeyZC(bts)
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
			switch string(field) {
			case "pk":
				bts, err = (*z).Key.UnmarshalMsg(bts)
				if err != nil {
					err = msgp.WrapError(err, "Key")
					return
				}
			case "c":
				bts, err = msgp.ReadExactBytes(bts, ((*z).Challenge)[:])
				if err != nil {
					err = msgp.WrapError(err, "Challenge")
					return
				}
			case "a":
				var zb0005 int
				zb0005, err = msgp.ReadBytesBytesHeader(bts)
				if err != nil {
					err = msgp.WrapError(err, "Address")
					return
				}
				if zb0005 > maxAddressLen {
					err = msgp.ErrOverflow(uint64(zb0005), uint64(maxAddressLen))
					return
				}
				(*z).Address, bts, err = msgp.ReadBytesBytes(bts, (*z).Address)
				if err != nil {
					err = msgp.WrapError(err, "Address")
					return
				}
			case "s":
				bts, err = (*z).Signature.UnmarshalMsg(bts)
				if err != nil {
					err = msgp.WrapError(err, "Signature")
					return
				}
			default:
				err = msgp.ErrNoField(string(field))
				if err != nil {
					err = msgp.WrapError(err)
					return
				}
			}
		}
	}
	o = bts
	return
}

func (_ *identityChallenge) CanUnmarshalMsg(z interface{}) bool {
	_, ok := (z).(*identityChallenge)
	return ok
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *identityChallenge) Msgsize() (s int) {
	s = 1 + 3 + (*z).Key.Msgsize() + 2 + msgp.ArrayHeaderSize + (32 * (msgp.ByteSize)) + 2 + msgp.BytesPrefixSize + len((*z).Address) + 2 + (*z).Signature.Msgsize()
	return
}

// MsgIsZero returns whether this is a zero value
func (z *identityChallenge) MsgIsZero() bool {
	return ((*z).Key.MsgIsZero()) && ((*z).Challenge == (identityChallengeValue{})) && (len((*z).Address) == 0) && ((*z).Signature.MsgIsZero())
}

// MarshalMsg implements msgp.Marshaler
func (z *identityChallengeResponse) MarshalMsg(b []byte) (o []byte) {
	o = msgp.Require(b, z.Msgsize())
	// omitempty: check for empty values
	zb0003Len := uint32(4)
	var zb0003Mask uint8 /* 5 bits */
	if (*z).Challenge == (identityChallengeValue{}) {
		zb0003Len--
		zb0003Mask |= 0x2
	}
	if (*z).Key.MsgIsZero() {
		zb0003Len--
		zb0003Mask |= 0x4
	}
	if (*z).ResponseChallenge == (identityChallengeValue{}) {
		zb0003Len--
		zb0003Mask |= 0x8
	}
	if (*z).Signature.MsgIsZero() {
		zb0003Len--
		zb0003Mask |= 0x10
	}
	// variable map header, size zb0003Len
	o = append(o, 0x80|uint8(zb0003Len))
	if zb0003Len != 0 {
		if (zb0003Mask & 0x2) == 0 { // if not empty
			// string "c"
			o = append(o, 0xa1, 0x63)
			o = msgp.AppendBytes(o, ((*z).Challenge)[:])
		}
		if (zb0003Mask & 0x4) == 0 { // if not empty
			// string "pk"
			o = append(o, 0xa2, 0x70, 0x6b)
			o = (*z).Key.MarshalMsg(o)
		}
		if (zb0003Mask & 0x8) == 0 { // if not empty
			// string "rc"
			o = append(o, 0xa2, 0x72, 0x63)
			o = msgp.AppendBytes(o, ((*z).ResponseChallenge)[:])
		}
		if (zb0003Mask & 0x10) == 0 { // if not empty
			// string "s"
			o = append(o, 0xa1, 0x73)
			o = (*z).Signature.MarshalMsg(o)
		}
	}
	return
}

func (_ *identityChallengeResponse) CanMarshalMsg(z interface{}) bool {
	_, ok := (z).(*identityChallengeResponse)
	return ok
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *identityChallengeResponse) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zb0003 int
	var zb0004 bool
	zb0003, zb0004, bts, err = msgp.ReadMapHeaderBytes(bts)
	if _, ok := err.(msgp.TypeError); ok {
		zb0003, zb0004, bts, err = msgp.ReadArrayHeaderBytes(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		if zb0003 > 0 {
			zb0003--
			bts, err = (*z).Key.UnmarshalMsg(bts)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array", "Key")
				return
			}
		}
		if zb0003 > 0 {
			zb0003--
			bts, err = msgp.ReadExactBytes(bts, ((*z).Challenge)[:])
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array", "Challenge")
				return
			}
		}
		if zb0003 > 0 {
			zb0003--
			bts, err = msgp.ReadExactBytes(bts, ((*z).ResponseChallenge)[:])
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array", "ResponseChallenge")
				return
			}
		}
		if zb0003 > 0 {
			zb0003--
			bts, err = (*z).Signature.UnmarshalMsg(bts)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array", "Signature")
				return
			}
		}
		if zb0003 > 0 {
			err = msgp.ErrTooManyArrayFields(zb0003)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array")
				return
			}
		}
	} else {
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		if zb0004 {
			(*z) = identityChallengeResponse{}
		}
		for zb0003 > 0 {
			zb0003--
			field, bts, err = msgp.ReadMapKeyZC(bts)
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
			switch string(field) {
			case "pk":
				bts, err = (*z).Key.UnmarshalMsg(bts)
				if err != nil {
					err = msgp.WrapError(err, "Key")
					return
				}
			case "c":
				bts, err = msgp.ReadExactBytes(bts, ((*z).Challenge)[:])
				if err != nil {
					err = msgp.WrapError(err, "Challenge")
					return
				}
			case "rc":
				bts, err = msgp.ReadExactBytes(bts, ((*z).ResponseChallenge)[:])
				if err != nil {
					err = msgp.WrapError(err, "ResponseChallenge")
					return
				}
			case "s":
				bts, err = (*z).Signature.UnmarshalMsg(bts)
				if err != nil {
					err = msgp.WrapError(err, "Signature")
					return
				}
			default:
				err = msgp.ErrNoField(string(field))
				if err != nil {
					err = msgp.WrapError(err)
					return
				}
			}
		}
	}
	o = bts
	return
}

func (_ *identityChallengeResponse) CanUnmarshalMsg(z interface{}) bool {
	_, ok := (z).(*identityChallengeResponse)
	return ok
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *identityChallengeResponse) Msgsize() (s int) {
	s = 1 + 3 + (*z).Key.Msgsize() + 2 + msgp.ArrayHeaderSize + (32 * (msgp.ByteSize)) + 3 + msgp.ArrayHeaderSize + (32 * (msgp.ByteSize)) + 2 + (*z).Signature.Msgsize()
	return
}

// MsgIsZero returns whether this is a zero value
func (z *identityChallengeResponse) MsgIsZero() bool {
	return ((*z).Key.MsgIsZero()) && ((*z).Challenge == (identityChallengeValue{})) && ((*z).ResponseChallenge == (identityChallengeValue{})) && ((*z).Signature.MsgIsZero())
}

// MarshalMsg implements msgp.Marshaler
func (z *identityChallengeValue) MarshalMsg(b []byte) (o []byte) {
	o = msgp.Require(b, z.Msgsize())
	o = msgp.AppendBytes(o, (*z)[:])
	return
}

func (_ *identityChallengeValue) CanMarshalMsg(z interface{}) bool {
	_, ok := (z).(*identityChallengeValue)
	return ok
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *identityChallengeValue) UnmarshalMsg(bts []byte) (o []byte, err error) {
	bts, err = msgp.ReadExactBytes(bts, (*z)[:])
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	o = bts
	return
}

func (_ *identityChallengeValue) CanUnmarshalMsg(z interface{}) bool {
	_, ok := (z).(*identityChallengeValue)
	return ok
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *identityChallengeValue) Msgsize() (s int) {
	s = msgp.ArrayHeaderSize + (32 * (msgp.ByteSize))
	return
}

// MsgIsZero returns whether this is a zero value
func (z *identityChallengeValue) MsgIsZero() bool {
	return (*z) == (identityChallengeValue{})
}

// MarshalMsg implements msgp.Marshaler
func (z *identityVerificationMessage) MarshalMsg(b []byte) (o []byte) {
	o = msgp.Require(b, z.Msgsize())
	// omitempty: check for empty values
	zb0001Len := uint32(1)
	var zb0001Mask uint8 /* 2 bits */
	if (*z).Signature.MsgIsZero() {
		zb0001Len--
		zb0001Mask |= 0x2
	}
	// variable map header, size zb0001Len
	o = append(o, 0x80|uint8(zb0001Len))
	if zb0001Len != 0 {
		if (zb0001Mask & 0x2) == 0 { // if not empty
			// string "s"
			o = append(o, 0xa1, 0x73)
			o = (*z).Signature.MarshalMsg(o)
		}
	}
	return
}

func (_ *identityVerificationMessage) CanMarshalMsg(z interface{}) bool {
	_, ok := (z).(*identityVerificationMessage)
	return ok
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *identityVerificationMessage) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zb0001 int
	var zb0002 bool
	zb0001, zb0002, bts, err = msgp.ReadMapHeaderBytes(bts)
	if _, ok := err.(msgp.TypeError); ok {
		zb0001, zb0002, bts, err = msgp.ReadArrayHeaderBytes(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		if zb0001 > 0 {
			zb0001--
			bts, err = (*z).Signature.UnmarshalMsg(bts)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array", "Signature")
				return
			}
		}
		if zb0001 > 0 {
			err = msgp.ErrTooManyArrayFields(zb0001)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array")
				return
			}
		}
	} else {
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		if zb0002 {
			(*z) = identityVerificationMessage{}
		}
		for zb0001 > 0 {
			zb0001--
			field, bts, err = msgp.ReadMapKeyZC(bts)
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
			switch string(field) {
			case "s":
				bts, err = (*z).Signature.UnmarshalMsg(bts)
				if err != nil {
					err = msgp.WrapError(err, "Signature")
					return
				}
			default:
				err = msgp.ErrNoField(string(field))
				if err != nil {
					err = msgp.WrapError(err)
					return
				}
			}
		}
	}
	o = bts
	return
}

func (_ *identityVerificationMessage) CanUnmarshalMsg(z interface{}) bool {
	_, ok := (z).(*identityVerificationMessage)
	return ok
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *identityVerificationMessage) Msgsize() (s int) {
	s = 1 + 2 + (*z).Signature.Msgsize()
	return
}

// MsgIsZero returns whether this is a zero value
func (z *identityVerificationMessage) MsgIsZero() bool {
	return ((*z).Signature.MsgIsZero())
}
