package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEd25519ConsensusBatchVerifierTypes(t *testing.T) {
	partitiontest.PartitionTest(t)

	// ensure internal ed25519 types match the expected []byte lengths used by ed25519consensus package
	require.Len(t, ed25519PublicKey{}, ed25519.PublicKeySize)
	require.Len(t, ed25519Signature{}, ed25519.SignatureSize)
}

// Test vector according to "Taming the many EdDSAs" white paper
const edgeCasesSize = 12

var edgeCasesSignatures = [edgeCasesSize][3]string{
	{"8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000"},
	{"9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"},
	{"aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
		"f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e"},
	{"9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
		"cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
		"9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009"},
	{"e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
		"cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
		"160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09"},
	{"e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
		"cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
		"21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405"},
	{"85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
		"442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
		"e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514"},
	{"85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
		"442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
		"8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a4734e74f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c2"},
	{"9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
		"f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f"},
	{"9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
		"f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908"},
	{"e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"},
	{"39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"},
}

var edgeCasesExpectedResults = [edgeCasesSize]int{0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0}

//nolint:paralleltest
func TestBatchVerifierLibsodiumEdgeCases(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Run("cgoSingle", func(t *testing.T) {
		bv := MakeBatchVerifier()
		bv.(*cgoBatchVerifier).useSingle = true
		testEdgeCases(t, bv)
	})
	t.Run("cgoBatch", func(t *testing.T) {
		bv := MakeBatchVerifier()
		bv.(*cgoBatchVerifier).useSingle = false
		testEdgeCases(t, bv)
	})
	t.Run("ed25519consensus", func(t *testing.T) {
		bv := &ed25519ConsensusBatchVerifier{}
		testEdgeCases(t, bv)
	})
}

// noHashID implements Hashable but returns an empty protocol.HashID for use with the test vectors, which should not be prefixed
type noHashID []byte

func (n noHashID) ToBeHashed() (protocol.HashID, []byte) { return "", n }

// port of test_edge_cases from libsodium-fork/test/default/batch.c
func testEdgeCases(t *testing.T, bv BatchVerifier) {
	for i := 0; i < edgeCasesSize; i++ {
		msg, err := hex.DecodeString(edgeCasesSignatures[i][0])
		require.NoError(t, err)
		require.Len(t, msg, ed25519.PublicKeySize)

		pk, err := hex.DecodeString(edgeCasesSignatures[i][1])
		require.NoError(t, err)
		require.Len(t, pk, ed25519.PublicKeySize)

		sig, err := hex.DecodeString(edgeCasesSignatures[i][2])
		require.NoError(t, err)
		require.Len(t, sig, ed25519.SignatureSize)

		bv.EnqueueSignature(SignatureVerifier(pk), noHashID(msg), Signature(sig))
	}

	failed, err := bv.VerifyWithFeedback()
	require.Error(t, err, "batch passed - should have failed!")
	require.NotNil(t, failed, "failed should not be nil")
	require.Len(t, failed, edgeCasesSize)
	for i := range failed {
		assert.Equal(t, edgeCasesExpectedResults[i] == 0, failed[i], "failed[%d] should be %v", i, edgeCasesExpectedResults[i] == 0)
	}
}
