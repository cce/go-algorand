// Copyright (C) 2019-2022 Algorand, Inc.
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

package logic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"
	mrand "math/rand"
	"strconv"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/secp256k1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestKeccak256(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	/*
		pip install sha3
		import sha3
		blob=b'fnord'
		sha3.keccak_256(blob).hexdigest()
	*/
	progText := `byte 0x666E6F7264
keccak256
byte 0xc195eca25a6f4c82bfba0287082ddb0d602ae9230f9cf1f1a40b68f8e2c41567
==`
	testAccepts(t, progText, 1)
}

func TestSHA3_256(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	/*
		pip install hashlib
		import hashlib
		hashlib.sha3_256(b"fnord").hexdigest()
	*/
	progText := `byte 0x666E6F7264
sha3_256
byte 0xd757297405c5c89f7ceca368ee76c2f1893ee24f654e60032e65fb53b01aae10
==`
	testAccepts(t, progText, 7)
}

func TestSHA512_256(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	/*
		pip cryptography
		from cryptography.hazmat.backends import default_backend
		from cryptography.hazmat.primitives import hashes
		import base64
		digest = hashes.Hash(hashes.SHA512_256(), backend=default_backend())
		digest.update(b'fnord')
		base64.b16encode(digest.finalize())
	*/
	progText := `byte 0x666E6F7264
sha512_256

byte 0x98D2C31612EA500279B6753E5F6E780CA63EBA8274049664DAD66A2565ED1D2A
==`
	testAccepts(t, progText, 1)
}

// This is patterned off vrf_test.go, but we don't create proofs here, we only
// check that the output is correct, given the proof.
func testVrfApp(pubkey, proof, data string, output string) string {
	source := `
byte 0x%s
byte 0x%s
byte 0x%s
vrf_verify VrfAlgorand
assert
byte 0x%s
==
`
	return fmt.Sprintf(source, data, proof, pubkey, output)
}

func TestVrfVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	ep, _, _ := makeSampleEnv()
	testApp(t, notrack("int 1; int 2; int 3; vrf_verify VrfAlgorand"), ep, "arg 0 wanted")
	testApp(t, notrack("byte 0x1122; int 2; int 3; vrf_verify VrfAlgorand"), ep, "arg 1 wanted")
	testApp(t, notrack("byte 0x1122; byte 0x2233; int 3; vrf_verify VrfAlgorand"), ep, "arg 2 wanted")
	testLogic(t, "byte 0x1122; byte 0x2233; byte 0x3344; vrf_verify VrfAlgorand", LogicVersion, ep, "vrf proof wrong size")
	// 80 byte proof
	testLogic(t, "byte 0x1122; int 80; bzero; byte 0x3344; vrf_verify VrfAlgorand", LogicVersion, ep, "vrf pubkey wrong size")
	// 32 byte pubkey
	testLogic(t, "byte 0x3344; int 80; bzero; int 32; bzero; vrf_verify VrfAlgorand", LogicVersion, ep, "stack len is 2")

	// working app, but the verify itself fails
	testLogic(t, "byte 0x3344; int 80; bzero; int 32; bzero; vrf_verify VrfAlgorand; !; assert; int 64; bzero; ==", LogicVersion, ep)

	source := testVrfApp(
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",                                                                                                 //pubkey
		"b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900", // proof
		"", // data
		"5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc", // output
	)
	testLogic(t, source, LogicVersion, ep)

	source = testVrfApp(
		"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",                                                                                                 //pk
		"ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07", // pi
		"72", // alpha
		"94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8", // beta
	)
	testLogic(t, source, LogicVersion, ep)
}

// BenchMarkVerify is useful to see relative speeds of various crypto verify functions
func BenchmarkVerify(b *testing.B) {
	benches := [][]string{
		{"pop", "", "int 1234576; int 6712; pop; pop", "int 1"},
		{"add", "", "int 1234576; int 6712; +; pop", "int 1"},
		/*
					{"ed25519verify_bare", "", `byte 0x
			byte 0x
			addr
			ed25519verify_bare
			assert`, "int 1"},*/
		{"ecdsa_verify", "", `byte 0x71a5910445820f57989c027bdf9391c80097874d249e0f38bf90834fdec2877f
byte 0x5eb27782eb1a5df8de9a5d51613ad5ca730840ddf4af919c6feb15cde14f9978
byte 0x0cb3c0d636ed991ee030d09c295de3121eb166cb9e1552cf0ef0fb2358f35f0f
byte 0x79de0699673571df1de8486718d06a3e7838f6831ec4ef3fb963788fbfb773b7
byte 0xd76446a3393af3e2eefada16df80cc6a881a56f4cf41fa2ab4769c5708ce878d
ecdsa_verify Secp256k1
assert`, "int 1"},
		{"vrf_verify", "", `byte 0x72
byte 0xae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07
byte 0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
vrf_verify VrfAlgorand
assert							// make sure we're testing success
pop								// output`, "int 1"},
	}
	for _, bench := range benches {
		b.Run(bench[0], func(b *testing.B) {
			benchmarkOperation(b, bench[1], bench[2], bench[3])
		})
	}
}

func TestEd25519verify(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var s crypto.Seed
	crypto.RandBytes(s[:])
	c := crypto.GenerateSignatureSecrets(s)
	msg := "62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
	data, err := hex.DecodeString(msg)
	require.NoError(t, err)
	pk := basics.Address(c.SignatureVerifier)
	pkStr := pk.String()

	for v := uint64(1); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, fmt.Sprintf(`arg 0
arg 1
addr %s
ed25519verify`, pkStr), v)
			sig := c.Sign(Msg{
				ProgramHash: crypto.HashObj(Program(ops.Program)),
				Data:        data[:],
			})
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = [][]byte{data[:], sig[:]}
			testLogicBytes(t, ops.Program, defaultEvalParams(txn))

			// short sig will fail
			txn.Lsig.Args[1] = sig[1:]
			testLogicBytes(t, ops.Program, defaultEvalParams(txn), "invalid signature")

			// flip a bit and it should not pass
			msg1 := "52fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
			data1, err := hex.DecodeString(msg1)
			require.NoError(t, err)
			txn.Lsig.Args = [][]byte{data1, sig[:]}
			testLogicBytes(t, ops.Program, defaultEvalParams(txn), "REJECT")
		})
	}
}

func TestEd25519VerifyBare(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var s crypto.Seed
	crypto.RandBytes(s[:])
	c := crypto.GenerateSignatureSecrets(s)
	msg := "62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
	data, err := hex.DecodeString(msg)
	require.NoError(t, err)
	pk := basics.Address(c.SignatureVerifier)
	pkStr := pk.String()

	for v := uint64(7); v <= AssemblerMaxVersion; v++ {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			ops := testProg(t, fmt.Sprintf(`arg 0
arg 1
addr %s
ed25519verify_bare`, pkStr), v)
			require.NoError(t, err)
			sig := c.SignBytes(data)
			var txn transactions.SignedTxn
			txn.Lsig.Logic = ops.Program
			txn.Lsig.Args = [][]byte{data[:], sig[:]}
			testLogicBytes(t, ops.Program, defaultEvalParams(txn))

			// short sig will fail
			txn.Lsig.Args[1] = sig[1:]
			testLogicBytes(t, ops.Program, defaultEvalParams(txn), "invalid signature")

			// flip a bit and it should not pass
			msg1 := "52fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
			data1, err := hex.DecodeString(msg1)
			require.NoError(t, err)
			txn.Lsig.Args = [][]byte{data1, sig[:]}
			testLogicBytes(t, ops.Program, defaultEvalParams(txn), "REJECT")
		})
	}
}

func keyToByte(tb testing.TB, b *big.Int) []byte {
	k := make([]byte, 32)
	require.NotPanics(tb, func() {
		b.FillBytes(k)
	})
	return k
}

func TestLeadingZeros(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	b := big.NewInt(0x100)
	r, err := leadingZeros(1, b)
	require.Error(t, err)
	require.Nil(t, r)

	b = big.NewInt(100)
	r, err = leadingZeros(1, b)
	require.NoError(t, err)
	require.Equal(t, []byte{100}, r)

	b = big.NewInt(100)
	r, err = leadingZeros(2, b)
	require.NoError(t, err)
	require.Equal(t, []byte{0, 100}, r)

	v32, err := hex.DecodeString("71a5910445820f57989c027bdf9391c80097874d249e0f38bf90834fdec2877f")
	require.NoError(t, err)
	b = new(big.Int).SetBytes(v32)
	r, err = leadingZeros(32, b)
	require.NoError(t, err)
	require.Equal(t, v32, r)

	v31 := v32[1:]
	b = new(big.Int).SetBytes(v31)
	r, err = leadingZeros(32, b)
	require.NoError(t, err)
	v31z := append([]byte{0}, v31...)
	require.Equal(t, v31z, r)

	require.Equal(t, v31z, keyToByte(t, b))
}

func TestEcdsaWithSecp256k1(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	require.NoError(t, err)
	pk := secp256k1.CompressPubkey(key.PublicKey.X, key.PublicKey.Y)
	sk := keyToByte(t, key.D)
	x := keyToByte(t, key.PublicKey.X)
	y := keyToByte(t, key.PublicKey.Y)

	// ecdsa decompress tests
	source := `
byte 0x%s
ecdsa_pk_decompress Secp256k1
store 0
byte 0x%s
==
load 0
byte 0x%s
==
&&`
	pkTampered1 := make([]byte, len(pk))
	copy(pkTampered1, pk)
	pkTampered1[0] = 0                     // first byte is a prefix of either 0x02 or 0x03
	pkTampered2 := make([]byte, len(pk)-1) // must be 33 bytes length
	copy(pkTampered2, pk)

	var decompressTests = []struct {
		key  []byte
		pass bool
	}{
		{pk, true},
		{pkTampered1, false},
		{pkTampered2, false},
	}
	for i, test := range decompressTests {
		t.Run(fmt.Sprintf("decompress/pass=%v", test.pass), func(t *testing.T) {
			t.Log("decompressTests i", i)
			src := fmt.Sprintf(source, hex.EncodeToString(test.key), hex.EncodeToString(x), hex.EncodeToString(y))
			if test.pass {
				testAccepts(t, src, 5)
			} else {
				testPanics(t, src, 5)
			}
		})
	}

	// ecdsa verify tests
	source = `
byte "%s"
sha512_256
byte 0x%s
byte 0x%s
byte 0x%s
byte 0x%s
ecdsa_verify Secp256k1
`
	data := []byte("testdata")
	msg := sha512.Sum512_256(data)

	sign, err := secp256k1.Sign(msg[:], sk)
	require.NoError(t, err)
	r := sign[:32]
	s := sign[32:64]
	v := int(sign[64])

	rTampered := make([]byte, len(r))
	copy(rTampered, r)
	rTampered[0] += byte(1) // intentional overflow

	var verifyTests = []struct {
		data string
		r    []byte
		pass bool
	}{
		{"testdata", r, true},
		{"testdata", rTampered, false},
		{"testdata1", r, false},
	}
	for _, test := range verifyTests {
		t.Run(fmt.Sprintf("verify/pass=%v", test.pass), func(t *testing.T) {
			src := fmt.Sprintf(source, test.data, hex.EncodeToString(test.r), hex.EncodeToString(s), hex.EncodeToString(x), hex.EncodeToString(y))
			if test.pass {
				testAccepts(t, src, 5)
			} else {
				testRejects(t, src, 5)
			}
		})
	}

	// ecdsa recover tests
	source = `
byte 0x%s
int %d
byte 0x%s
byte 0x%s
ecdsa_pk_recover Secp256k1
dup2
store 0
byte 0x%s
==
load 0
byte 0x%s
==
&&
store 1
concat // X + Y
byte 0x04
swap
concat // 0x04 + X + Y
byte 0x%s
==
load 1
&&`
	var recoverTests = []struct {
		v       int
		checker func(t *testing.T, program string, introduced uint64)
	}{
		{v, testAccepts},
		{v ^ 1, testRejects},
		{3, func(t *testing.T, program string, introduced uint64) {
			testPanics(t, program, introduced)
		}},
	}
	pkExpanded := secp256k1.S256().Marshal(key.PublicKey.X, key.PublicKey.Y)

	for i, test := range recoverTests {
		t.Run(fmt.Sprintf("recover/%d", i), func(t *testing.T) {
			src := fmt.Sprintf(source, hex.EncodeToString(msg[:]), test.v, hex.EncodeToString(r), hex.EncodeToString(s), hex.EncodeToString(x), hex.EncodeToString(y), hex.EncodeToString(pkExpanded))
			test.checker(t, src, 5)
		})
	}

	// sample sequencing: decompress + verify
	source = fmt.Sprintf(`#pragma version 5
byte "testdata"
sha512_256
byte 0x%s
byte 0x%s
byte 0x%s
ecdsa_pk_decompress Secp256k1
ecdsa_verify Secp256k1`, hex.EncodeToString(r), hex.EncodeToString(s), hex.EncodeToString(pk))
	ops := testProg(t, source, 5)
	var txn transactions.SignedTxn
	txn.Lsig.Logic = ops.Program
	pass, err := EvalSignature(0, defaultEvalParamsWithVersion(5, txn))
	require.NoError(t, err)
	require.True(t, pass)
}

func TestEcdsaWithSecp256r1(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pk := elliptic.MarshalCompressed(elliptic.P256(), key.X, key.Y)
	x := keyToByte(t, key.PublicKey.X)
	y := keyToByte(t, key.PublicKey.Y)

	// ecdsa decompress tests
	source := `
byte 0x%s
ecdsa_pk_decompress Secp256r1
store 0
byte 0x%s
==
load 0
byte 0x%s
==
&&`
	pkTampered1 := make([]byte, len(pk))
	copy(pkTampered1, pk)
	pkTampered1[0] = 0                     // first byte is a prefix of either 0x02 or 0x03
	pkTampered2 := make([]byte, len(pk)-1) // must be 33 bytes length
	copy(pkTampered2, pk)

	var decompressTests = []struct {
		key  []byte
		pass bool
	}{
		{pk, true},
		{pkTampered1, false},
		{pkTampered2, false},
	}
	for i, test := range decompressTests {
		t.Run(fmt.Sprintf("decompress/pass=%v", test.pass), func(t *testing.T) {
			t.Log("decompressTests i", i)
			src := fmt.Sprintf(source, hex.EncodeToString(test.key), hex.EncodeToString(x), hex.EncodeToString(y))
			if test.pass {
				testAccepts(t, src, fidoVersion)
			} else {
				testPanics(t, src, fidoVersion)
			}
		})
	}

	// ecdsa verify tests
	source = `
byte "%s"
sha512_256
byte 0x%s
byte 0x%s
byte 0x%s
byte 0x%s
ecdsa_verify Secp256r1
`
	data := []byte("testdata")
	msg := sha512.Sum512_256(data)

	ri, si, err := ecdsa.Sign(rand.Reader, key, msg[:])
	require.NoError(t, err)
	r := ri.Bytes()
	s := si.Bytes()

	rTampered := make([]byte, len(r))
	copy(rTampered, r)
	rTampered[0] += byte(1) // intentional overflow

	var verifyTests = []struct {
		data string
		r    []byte
		pass bool
	}{
		{"testdata", r, true},
		{"testdata", rTampered, false},
		{"testdata1", r, false},
	}
	for _, test := range verifyTests {
		t.Run(fmt.Sprintf("verify/pass=%v", test.pass), func(t *testing.T) {
			src := fmt.Sprintf(source, test.data, hex.EncodeToString(test.r), hex.EncodeToString(s), hex.EncodeToString(x), hex.EncodeToString(y))
			if test.pass {
				testAccepts(t, src, fidoVersion)
			} else {
				testRejects(t, src, fidoVersion)
			}
		})
	}

	// sample sequencing: decompress + verify
	source = fmt.Sprintf(`#pragma version `+strconv.Itoa(fidoVersion)+`
byte "testdata"
sha512_256
byte 0x%s
byte 0x%s
byte 0x%s
ecdsa_pk_decompress Secp256r1
ecdsa_verify Secp256r1`, hex.EncodeToString(r), hex.EncodeToString(s), hex.EncodeToString(pk))
	ops := testProg(t, source, fidoVersion)
	var txn transactions.SignedTxn
	txn.Lsig.Logic = ops.Program
	pass, err := EvalSignature(0, defaultEvalParamsWithVersion(fidoVersion, txn))
	require.NoError(t, err)
	require.True(t, pass)
}

// test compatibility with ethereum signatures
func TestEcdsaEthAddress(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	/*
		pip install eth-keys pycryptodome
		from eth_keys import keys
		pk = keys.PrivateKey(b"\xb2\\}\xb3\x1f\xee\xd9\x12''\xbf\t9\xdcv\x9a\x96VK-\xe4\xc4rm\x03[6\xec\xf1\xe5\xb3d")
		msg=b"hello from ethereum"
		print("msg: '{}'".format(msg.decode()))
		signature = pk.sign_msg(msg)
		print("v:", signature.v)
		print("r:", signature.r.to_bytes(32, byteorder="big").hex())
		print("s:", signature.s.to_bytes(32, byteorder="big").hex())
		print("addr:", pk.public_key.to_address())
	*/
	progText := `byte "hello from ethereum" // msg
keccak256
int 0 // v
byte 0x745e8f55ac6189ee89ed707c36694868e3903988fbf776c8096c45da2e60c638 // r
byte 0x30c8e4a9b5d2eb53ddc6294587dd00bed8afe2c45dd72f6b4cf752e46d5ba681 // s
ecdsa_pk_recover Secp256k1
concat // convert public key X and Y to ethereum addr
keccak256
substring 12 32
byte 0x5ce9454909639d2d17a3f753ce7d93fa0b9ab12e // addr
==`
	testAccepts(t, progText, 5)
}

func TestEcdsaCostVariation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Doesn't matter if the actual verify returns true or false. Just confirm the cost depends on curve.
	source := `
global ZeroAddress				// need 32 bytes
byte "signature r"
byte "signature s"
byte "PK x"
byte "PK y"
ecdsa_verify Secp256k1
!
assert
global OpcodeBudget
int ` + fmt.Sprintf("%d", 20_000-1700-8) + `
==
`
	testAccepts(t, source, 6) // Secp256k1 was 5, but OpcodeBudget is 6

	source = `
global ZeroAddress				// need 32 bytes
byte "signature r"
byte "signature s"
byte "PK x"
byte "PK y"
ecdsa_verify Secp256r1
!
assert
global OpcodeBudget
int ` + fmt.Sprintf("%d", 20_000-2500-8) + `
==
`
	testAccepts(t, source, fidoVersion)
}

func BenchmarkHash(b *testing.B) {
	for _, hash := range []string{"sha256", "keccak256", "sha512_256"} {
		b.Run(hash+"-0w", func(b *testing.B) { // hash 0 bytes
			benchmarkOperation(b, "", "byte 0x; "+hash+"; pop", "int 1")
		})
		b.Run(hash+"-32", func(b *testing.B) { // hash 32 bytes
			benchmarkOperation(b, "int 32; bzero", hash, "pop; int 1")
		})
		b.Run(hash+"-128", func(b *testing.B) { // hash 128 bytes
			benchmarkOperation(b, "int 32; bzero",
				"dup; concat; dup; concat;"+hash, "pop; int 1")
		})
		b.Run(hash+"-512", func(b *testing.B) { // hash 512 bytes
			benchmarkOperation(b, "int 32; bzero",
				"dup; concat; dup; concat; dup; concat; dup; concat;"+hash, "pop; int 1")
		})
		b.Run(hash+"-4096", func(b *testing.B) { // hash 4k bytes
			benchmarkOperation(b, "int 32; bzero",
				"dup; concat; dup; concat; dup; concat; dup; concat; dup; concat; dup; concat; dup; concat;"+hash, "pop; int 1")
		})
	}
}

func BenchmarkSha256Raw(b *testing.B) {
	addr, _ := basics.UnmarshalChecksumAddress("OC6IROKUJ7YCU5NV76AZJEDKYQG33V2CJ7HAPVQ4ENTAGMLIOINSQ6EKGE")
	a := addr[:]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t := sha256.Sum256(a)
		a = t[:]
	}
}

func BenchmarkEd25519Verifyx1(b *testing.B) {
	//benchmark setup
	var data [][32]byte
	var programs [][]byte
	var signatures []crypto.Signature

	for i := 0; i < b.N; i++ {
		var buffer [32]byte //generate data to be signed
		crypto.RandBytes(buffer[:])
		data = append(data, buffer)

		var s crypto.Seed //generate programs and signatures
		crypto.RandBytes(s[:])
		secret := crypto.GenerateSignatureSecrets(s)
		pk := basics.Address(secret.SignatureVerifier)
		pkStr := pk.String()
		ops, err := AssembleStringWithVersion(fmt.Sprintf(`arg 0
arg 1
addr %s
ed25519verify`, pkStr), AssemblerMaxVersion)
		require.NoError(b, err)
		programs = append(programs, ops.Program)
		sig := secret.Sign(Msg{
			ProgramHash: crypto.HashObj(Program(ops.Program)),
			Data:        buffer[:],
		})
		signatures = append(signatures, sig)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = programs[i]
		txn.Lsig.Args = [][]byte{data[i][:], signatures[i][:]}
		ep := defaultEvalParams(txn)
		pass, err := EvalSignature(0, ep)
		if !pass {
			b.Log(hex.EncodeToString(programs[i]))
			b.Log(ep.Trace.String())
		}
		if err != nil {
			require.NoError(b, err)
		}
		if !pass {
			require.True(b, pass)
		}
	}
}

type benchmarkEcdsaData struct {
	x        []byte
	y        []byte
	pk       []byte
	msg      [32]byte
	r        []byte
	s        []byte
	v        int
	programs []byte
}

func benchmarkEcdsaGenData(b *testing.B, curve EcdsaCurve) (data []benchmarkEcdsaData) {
	data = make([]benchmarkEcdsaData, b.N)
	for i := 0; i < b.N; i++ {
		var key *ecdsa.PrivateKey
		if curve == Secp256k1 {
			var err error
			key, err = ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
			require.NoError(b, err)
		} else if curve == Secp256r1 {
			var err error
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(b, err)
		}
		sk := keyToByte(b, key.D)
		data[i].x = keyToByte(b, key.PublicKey.X)
		data[i].y = keyToByte(b, key.PublicKey.Y)
		if curve == Secp256k1 {
			data[i].pk = secp256k1.CompressPubkey(key.PublicKey.X, key.PublicKey.Y)
		} else if curve == Secp256r1 {
			data[i].pk = elliptic.MarshalCompressed(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
		}

		d := []byte("testdata")
		data[i].msg = sha512.Sum512_256(d)

		if curve == Secp256k1 {
			sign, err := secp256k1.Sign(data[i].msg[:], sk)
			require.NoError(b, err)
			data[i].r = sign[:32]
			data[i].s = sign[32:64]
			data[i].v = int(sign[64])
		} else if curve == Secp256r1 {
			r, s, err := ecdsa.Sign(rand.Reader, key, data[i].msg[:])
			require.NoError(b, err)
			data[i].r = r.Bytes()
			data[i].s = s.Bytes()
		}
	}
	return data
}

func benchmarkEcdsa(b *testing.B, source string, curve EcdsaCurve) {
	data := benchmarkEcdsaGenData(b, curve)
	var version uint64
	if curve == Secp256k1 {
		version = 5
	} else if curve == Secp256r1 {
		version = fidoVersion
	}
	ops := testProg(b, source, version)
	for i := 0; i < b.N; i++ {
		data[i].programs = ops.Program
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = data[i].programs
		txn.Lsig.Args = [][]byte{data[i].msg[:], data[i].r, data[i].s, data[i].x, data[i].y, data[i].pk, {uint8(data[i].v)}}
		ep := defaultEvalParams(txn)
		pass, err := EvalSignature(0, ep)
		if !pass {
			b.Log(hex.EncodeToString(data[i].programs))
			b.Log(ep.Trace.String())
		}
		if err != nil {
			require.NoError(b, err)
		}
		if !pass {
			require.True(b, pass)
		}
	}
}

func BenchmarkEcdsa(b *testing.B) {
	b.Run("ecdsa_verify secp256k1", func(b *testing.B) {
		source := `#pragma version 5
arg 0
arg 1
arg 2
arg 3
arg 4
ecdsa_verify Secp256k1`
		benchmarkEcdsa(b, source, Secp256k1)
	})

	if LogicVersion >= fidoVersion {
		b.Run("ecdsa_verify secp256r1", func(b *testing.B) {
			source := `#pragma version ` + strconv.Itoa(fidoVersion) + `
	arg 0
	arg 1
	arg 2
	arg 3
	arg 4
	ecdsa_verify Secp256r1`
			benchmarkEcdsa(b, source, Secp256r1)
		})
	}

	b.Run("ecdsa_pk_decompress Secp256k1", func(b *testing.B) {
		source := `#pragma version 5
arg 5
ecdsa_pk_decompress Secp256k1
pop
pop
int 1`
		benchmarkEcdsa(b, source, Secp256k1)
	})

	if LogicVersion >= fidoVersion {
		b.Run("ecdsa_pk_decompress Secp256r1", func(b *testing.B) {
			source := `#pragma version ` + strconv.Itoa(fidoVersion) + `
	arg 5
	ecdsa_pk_decompress Secp256r1
	pop
	pop
	int 1`
			benchmarkEcdsa(b, source, Secp256r1)
		})
	}

	b.Run("ecdsa_pk_recover Secp256k1", func(b *testing.B) {
		source := `#pragma version 5
arg 0
arg 6
btoi
arg 1
arg 2
ecdsa_pk_recover Secp256k1
pop
pop
int 1`
		benchmarkEcdsa(b, source, Secp256k1)
	})
}

type benchmarkBn256Data struct {
	a        []byte
	k        []byte
	g1       []byte
	g2       []byte
	programs []byte
}

func benchmarkBn256DataGenData(b *testing.B) (data []benchmarkBn256Data) {
	data = make([]benchmarkBn256Data, b.N)
	var g1Gen bn254.G1Jac
	var g1GenAff bn254.G1Affine
	g1Gen.X.SetString("1")
	g1Gen.Y.SetString("2")
	g1Gen.Z.SetString("1")
	g1GenAff.FromJacobian(&g1Gen)
	var a bn254.G1Affine
	a.ScalarMultiplication(&g1GenAff, new(big.Int).SetUint64(mrand.Uint64()))

	for i := 0; i < b.N; i++ {
		var a bn254.G1Affine
		a.ScalarMultiplication(&g1GenAff, new(big.Int).SetUint64(mrand.Uint64()))

		data[i].a = bN254G1ToBytes(&a)
		data[i].k = new(big.Int).SetUint64(mrand.Uint64()).Bytes()

		// Pair one g1 and one g2
		data[i].g1, _ = hex.DecodeString("0ebc9fc712b13340c800793386a88385e40912a21bacad2cc7db17d36e54c802238449426931975cced7200f08681ab9a86a2e5c2336cf625451cf2413318e32")
		data[i].g2, _ = hex.DecodeString("217fbd9a9db5719cfbe3580e3d8750cada058fdfffe95c440a0528ffc608f36e05d6a67604658d40b3e4cac3c46150f2702d87739b7774d79a8147f7271773b420f9429ee13c1843404bfd70e75efa886c173e57dde32970274d8bc53dfd562403f6276318990d053785b4ca342ebc4581a23a39285804bb74e079aa2ef3ba66")
	}
	return data
}

func benchmarkBn256(b *testing.B, source string) {
	data := benchmarkBn256DataGenData(b)
	ops, err := AssembleStringWithVersion(source, pairingVersion)
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		data[i].programs = ops.Program
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = data[i].programs
		txn.Lsig.Args = [][]byte{data[i].a, data[i].k, data[i].g1, data[i].g2}
		ep := defaultEvalParams(txn)
		pass, err := EvalSignature(0, ep)
		if !pass {
			b.Log(hex.EncodeToString(data[i].programs))
			b.Log(ep.Trace.String())
		}
		if err != nil {
			require.NoError(b, err)
		}
		if !pass {
			require.True(b, pass)
		}
	}
}

func BenchmarkBn256AddRaw(b *testing.B) {
	data := benchmarkBn256DataGenData(b)
	a1 := bytesToBN254G1(data[0].g1)
	a2 := bytesToBN254G1(data[0].g1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = new(bn254.G1Affine).Add(&a1, &a2)
	}
}

func BenchmarkBn256AddWithMarshal(b *testing.B) {
	b.ResetTimer()
	var v [][]byte
	v = make([][]byte, b.N)
	g1, _ := hex.DecodeString("0ebc9fc712b13340c800793386a88385e40912a21bacad2cc7db17d36e54c802238449426931975cced7200f08681ab9a86a2e5c2336cf625451cf2413318e32")

	for i := 0; i < b.N; i++ {
		a1 := bytesToBN254G1(g1)
		a2 := bytesToBN254G1(g1)
		r := new(bn254.G1Affine).Add(&a1, &a2)
		v[i] = r.Marshal()
	}
}

func BenchmarkBn256PairingRaw(b *testing.B) {
	data := benchmarkBn256DataGenData(b)
	g1s := bytesToBN254G1s(data[0].g1)
	g2s := bytesToBN254G2s(data[0].g2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, _ := bn254.PairingCheck(g1s, g2s)
		require.False(b, ok)
	}
}

func BenchmarkBn256(b *testing.B) {
	if pairingVersion > LogicVersion {
		b.Skip()
	}
	b.Run("bn256 add", func(b *testing.B) {
		benchmarkOperation(b, "byte 0x0ebc9fc712b13340c800793386a88385e40912a21bacad2cc7db17d36e54c802238449426931975cced7200f08681ab9a86a2e5c2336cf625451cf2413318e32", "dup; bn256_add", "pop; int 1")
	})

	b.Run("bn256 scalar mul", func(b *testing.B) {
		source := `
arg 0
arg 1
bn256_scalar_mul
pop
int 1
`
		benchmarkBn256(b, source)
	})

	b.Run("bn256 pairing", func(b *testing.B) {
		source := `
arg 2
arg 3
bn256_pairing
pop
int 1
`
		benchmarkBn256(b, source)
	})
}

func TestEcdsaVectors(t *testing.T) {
	message := "Hello"
	curve := "secp256r1"
	PubX, success := new(big.Int).SetString("33903964965861532023650245008903090201819051686264021958530366090984128098564", 10)
	require.True(t, success)
	PubY, success := new(big.Int).SetString("113542129898393725739068316260085522189065290079050903091108740065052129055287", 10)
	require.True(t, success)

	// Valid signatures for MESSAGE
	validSignatures := []string{
		"3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
	}

	/**
	 * The following test vectors contain a valid signature that use alternative BER encoding. Whether
	 * such signatures are accepted as valid or rejected depends on the implementation. Allowing
	 * alternative BER encodings is in many cases benign. However, there are cases where this kind of
	 * signature malleability was a problem. See for example
	 * https://en.bitcoin.it/wiki/Transaction_Malleability
	 */
	// NOTE(bleichen): The following test vectors were generated with some python code.
	//   New test vectors should best be done by extending this code. Some of the signatures
	//   can be moved to INVALID_SIGNATURES, when b/31572415 is fixed.
	modifiedSignatures := []string{
		// BER:long form encoding of length
		"308145022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		"304602812100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		"3046022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f028120747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// BER:length contains leading 0
		"30820045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		"30470282002100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		"3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f02820020747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// BER:prepending 0's to integer
		"30470223000000b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		"3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f02220000747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// NOTE (bleichen): belongs into INVALID_SIGNATURES. We only keep these
		//  sigantures here because of b/31572415.
		// length = 2**31 - 1
		"30847fffffff022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		"304902847fffffff00b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		"3049022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f02847fffffff747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
	}

	/**
	 * Test vectors with invalid signatures. The motivation for these test vectors are previously
	 * broken implementations. E.g.
	 *
	 * <ul>
	 *   <li>The implementation of DSA in gpg4browsers accepted signatures with r=1 and s=q as valid.
	 *       Similar bugs in ECDSA are thinkable, hence the test vectors contain a number of tests
	 *       with edge case integers.
	 *   <li>CVE-2013-2944: strongSwan 5.0.4 accepts invalid ECDSA signatures when openssl is used.
	 *       (Not sure if the following interpretation is correct, because of missing details).
	 *       OpenSSLs error codes are easy to misinterpret. For many functions the result can be 0
	 *       (verification failed), 1 (verification succeded) or -1 (invalid format). A simple <code>
	 *       if (result) { ... }</code> will be incorrect in such situations. The test vectors below
	 *       contain incorrectly encoded signatures.
	 * </ul>
	 *
	 * <p>{@link java.security.Signature#verify(byte[])} should either return false or throw a
	 * SignatureException. Other behaviour such as throwing a RuntimeException might allow a denial of
	 * service attack:
	 *
	 * <ul>
	 *   <li>CVE-2016-5546: OpenJDK8 throwed an OutOfmemoryError on some signatures.
	 * </ul>
	 *
	 * Some of the test vectors were derived from a valid signature by corrupting the DER encoding. If
	 * providers accepts such modified signatures for legacy purpose, then these signatures should be
	 * moved to MODIFIED_SIGNATURES.
	 */
	// NOTE(bleichen): The following test vectors were generated with some python code. New test
	// vectors should best be done by extending the python code.
	invalidSignatures := []string{
		// // wrong length
		// "3046022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3044022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3045022200b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3045022000b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0221747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f021f747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // uint32 overflow in length
		// "30850100000045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304a0285010000002100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304a022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f02850100000020747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // uint64 overflow in length
		// "3089010000000000000045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304e028901000000000000002100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304e022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0289010000000000000020747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // length = 2**32 - 1
		// "3084ffffffff022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "30490284ffffffff00b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3049022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0284ffffffff747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // length = 2**64 - 1
		// "3088ffffffffffffffff022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304d0288ffffffffffffffff00b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304d022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0288ffffffffffffffff747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // removing sequence
		// "",
		// // appending 0's to sequence
		// "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0000",
		// // prepending 0's to sequence
		// "30470000022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // appending unused 0's
		// "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0000",
		// "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f00000220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // appending null value
		// "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0500",
		// "3047022300b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f05000220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0222747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0500",
		// // including garbage
		// "304949803045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304925003045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "30473045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0004deadbeef",
		// "304922254980022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304922252500022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304d2223022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0004deadbeef0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3049022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f222449800220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3049022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f222425000220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304d022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f22220220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0004deadbeef",
		// // including undefined tags
		// "304daa00bb00cd003045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304baa02aabb3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304d2229aa00bb00cd00022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304b2227aa02aabb022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304d022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f2228aa00bb00cd000220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304b022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f2226aa02aabb0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // changing tag value
		// "2e45022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3245022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "ff45022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3045002100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3045042100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3045ff2100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0020747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0420747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3fff20747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // dropping value of sequence
		// "3000",
		// // using composition
		// "304930010230442100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "304922250201000220b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3049022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f2224020174021f7291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // truncate sequence
		// "3044022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ec",
		// "30442100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // prepend empty sequence
		// "30473000022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // append empty sequence
		// "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce3000",
		// // sequence of sequence
		// "30473045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // truncated sequence
		// "3023022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f",
		// // repeat element in sequence
		// "3067022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // removing integer
		// "30220220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // appending 0's to integer
		// "3047022300b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f00000220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0222747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0000",
		// // dropping value of integer
		// "302402000220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3025022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0200",
		// // modify first byte of integer
		// "3045022101b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220757291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // modify last byte of integer
		// "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3e0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260eccf",
		// // truncate integer
		// "3044022000b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "30440220b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3044022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f021f747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ec",
		// "3044022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f021f7291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // leading ff in integer
		// "30460222ff00b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3046022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0221ff747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// // infinity
		// "30250901800220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		// "3026022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f090180",
		// Vectors where r or s have been modified e.g. by adding or subtracting the order of the
		// group or field and hence violate the range check for r and s required by ECDSA.
		"30450221ff48454516ccd4ab475c5fa48ffba867de57785e4deb9a082475c2b6e4c602d3c10220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		"3045022101b7babae8332b54b9a3a05b7004579821656e9c5fbb7d96607df713de366051900220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		"3044022048454515ccd4ab485c5fa48ffba867de145f58fb92b1a6a9697c81a7c265f9120220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		"3045022101b7babae8332b54b9a3a05b7004579821a887a1b31465f7db8a3d491b39fd2c3e0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
		"3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f02208b8d6e22d0c0bb5085319715ccbce2906b1be73ef959189d7a32a60bcd9f1332",
		"3046022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f022101747291dc2f3f44b07ace68ea33431d6f51cb136eadbe85e7798724b72ec4121f",
		"3046022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f022101747291dc2f3f44b07ace68ea33431d6f94e418c206a6e76285cd59f43260eccd",
		// Signatures with special case values for r and s (such as 0 and 1). Such values often
		// uncover implementation errors.
		"3006020100020100",
		"3006020100020101",
		"30060201000201ff",
		"3026020100022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		"3026020100022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
		"3026020100022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
		"3026020100022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
		"3026020100022100ffffffff00000001000000000000000000000001000000000000000000000000",
		"3008020100090380fe01",
		"3006020101020100",
		"3006020101020101",
		"30060201010201ff",
		"3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		"3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
		"3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
		"3026020101022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
		"3026020101022100ffffffff00000001000000000000000000000001000000000000000000000000",
		"3008020101090380fe01",
		"30060201ff020100",
		"30060201ff020101",
		"30060201ff0201ff",
		"30260201ff022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		"30260201ff022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
		"30260201ff022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
		"30260201ff022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
		"30260201ff022100ffffffff00000001000000000000000000000001000000000000000000000000",
		"30080201ff090380fe01",
		"3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020100",
		"3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101",
		"3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510201ff",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551022100ffffffff00000001000000000000000000000001000000000000000000000000",
		"3028022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551090380fe01",
		"3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550020100",
		"3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550020101",
		"3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325500201ff",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550022100ffffffff00000001000000000000000000000001000000000000000000000000",
		"3028022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550090380fe01",
		"3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552020100",
		"3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552020101",
		"3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325520201ff",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
		"3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552022100ffffffff00000001000000000000000000000001000000000000000000000000",
		"3028022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552090380fe01",
		"3026022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff020100",
		"3026022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff020101",
		"3026022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff0201ff",
		"3046022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		"3046022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
		"3046022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
		"3046022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
		"3046022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff022100ffffffff00000001000000000000000000000001000000000000000000000000",
		"3028022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff090380fe01",
		"3026022100ffffffff00000001000000000000000000000001000000000000000000000000020100",
		"3026022100ffffffff00000001000000000000000000000001000000000000000000000000020101",
		"3026022100ffffffff000000010000000000000000000000010000000000000000000000000201ff",
		"3046022100ffffffff00000001000000000000000000000001000000000000000000000000022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		"3046022100ffffffff00000001000000000000000000000001000000000000000000000000022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
		"3046022100ffffffff00000001000000000000000000000001000000000000000000000000022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
		"3046022100ffffffff00000001000000000000000000000001000000000000000000000000022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
		"3046022100ffffffff00000001000000000000000000000001000000000000000000000000022100ffffffff00000001000000000000000000000001000000000000000000000000",
		"3028022100ffffffff00000001000000000000000000000001000000000000000000000000090380fe01",
	}

	/**
	 * Extract the integer r from an ECDSA signature. This method implicitely assumes that the ECDSA
	 * signature is DER encoded. and that the order of the curve is smaller than 2^1024.
	 */
	extractR := func(signature []byte) *big.Int {
		var startR int
		// if (signature[1] & 0x80) != 0 {
		// 	startR = 3
		// } else {
		startR = 2
		//}
		lengthR := int(signature[startR+1])
		return new(big.Int).SetBytes(signature[startR+2 : startR+2+lengthR])
	}

	extractS := func(signature []byte) *big.Int {
		var startR int
		// if (signature[1] & 0x80) != 0 {
		// 	startR = 3
		// } else {
		startR = 2
		//		}
		lengthR := int(signature[startR+1])
		startS := startR + 2 + lengthR
		lengthS := int(signature[startS+1])
		return new(big.Int).SetBytes(signature[startS+2 : startS+2+lengthS])
	}

	t.Run("valid", func(t *testing.T) {
		for _, sig := range validSignatures {
			sigBytes, err := hex.DecodeString(sig)
			require.NoError(t, err)
			r := extractR(sigBytes)
			s := extractS(sigBytes)
			pubkey := ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     PubX,
				Y:     PubY,
			}
			h := sha256.Sum256([]byte(message))
			result := ecdsa.Verify(&pubkey, h[:], r, s)
			require.True(t, result)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for i, sig := range invalidSignatures {
			sigBytes, err := hex.DecodeString(sig)
			require.NoError(t, err)
			r := extractR(sigBytes)
			s := extractS(sigBytes)
			pubkey := ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     PubX,
				Y:     PubY,
			}
			t.Log("r", r)
			t.Log("s", s)
			h := sha256.Sum256([]byte(message))
			result := ecdsa.Verify(&pubkey, h[:], r, s)
			require.False(t, result, "should be invalid: %d", i)
		}
	})

	_ = modifiedSignatures
	_ = invalidSignatures
	_ = curve
	// public ECPublicKeySpec publicKey1() throws Exception {
	//   ECParameterSpec params = EcUtil.getNistP256Params();
	//   ECPoint w = new ECPoint(PubX, PubY);
	//   return new ECPublicKeySpec(w, params);
	// }

	// public void testVectors(
	//     String[] signatures,
	//     ECPublicKeySpec pubSpec,
	//     String message,
	//     String algorithm,
	//     String signatureType,
	//     boolean isValidDER,
	//     boolean isValidBER)
	//     throws Exception {
	//   byte[] messageBytes = message.getBytes("UTF-8");
	//   Signature verifier = Signature.getInstance(algorithm);
	//   KeyFactory kf = KeyFactory.getInstance("EC");
	//   ECPublicKey pub = (ECPublicKey) kf.generatePublic(pubSpec);
	//   int errors = 0;
	//   for (String signature : signatures) {
	//     byte[] signatureBytes = TestUtil.hexToBytes(signature);
	//     verifier.initVerify(pub);
	//     verifier.update(messageBytes);
	//     boolean verified = false;
	//     try {
	//       verified = verifier.verify(signatureBytes);
	//     } catch (SignatureException ex) {
	//       // verify can throw SignatureExceptions if the signature is malformed.
	//       // We don't flag these cases and simply consider the signature as invalid.
	//       verified = false;
	//     }
	//     if (!verified && isValidDER) {
	//       System.out.println(signatureType + " was not verified:" + signature);
	//       errors++;
	//     }
	//     if (verified && !isValidBER) {
	//       System.out.println(signatureType + " was verified:" + signature);
	//       errors++;
	//     }
	//   }
	//   assertEquals(0, errors);
	// }

	// @Test
	// public void testValidSignatures() throws Exception {
	//   testVectors(
	//       VALID_SIGNATURES,
	//       publicKey1(),
	//       "Hello",
	//       "SHA256WithECDSA",
	//       "Valid ECDSA signature",
	//       true,
	//       true);
	// }

	// @Test
	// public void testModifiedSignatures() throws Exception {
	//   testVectors(
	//       MODIFIED_SIGNATURES,
	//       publicKey1(),
	//       "Hello",
	//       "SHA256WithECDSA",
	//       "Modified ECDSA signature",
	//       false,
	//       true);
	// }

	// @Test
	// public void testInvalidSignatures() throws Exception {
	//   testVectors(
	//       INVALID_SIGNATURES,
	//       publicKey1(),
	//       "Hello",
	//       "SHA256WithECDSA",
	//       "Invalid ECDSA signature",
	//       false,
	//       false);
	// }
}
