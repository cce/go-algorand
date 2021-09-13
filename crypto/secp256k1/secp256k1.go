package secp256k1

import (
	"math/big"

	geth256k1 "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// A BitCurve represents a Koblitz Curve with a=0.
type BitCurve struct {
	P       *big.Int // the order of the underlying field
	N       *big.Int // the order of the base point
	B       *big.Int // the constant of the BitCurve equation
	Gx, Gy  *big.Int // (x,y) of the base point
	BitSize int      // the size of the underlying field
}

func S256() *BitCurve {
	bc := geth256k1.S256()
	return &BitCurve{P: bc.P, N: bc.N, B: bc.B, Gx: bc.Gx, Gy: bc.Gy, BitSize: bc.BitSize}
}

func VerifySignature(pubkey, msg, signature []byte) bool {
	return geth256k1.VerifySignature(pubkey, msg, signature)
}

func DecompressPubkey(pubkey []byte) (x, y *big.Int) {
	return geth256k1.DecompressPubkey(pubkey)
}
func RecoverPubkey(msg, signature []byte) ([]byte, error) {
	return geth256k1.RecoverPubkey(msg, signature)
}

func (bc *BitCurve) Unmarshal(data []byte) (x, y *big.Int) {
	gbc := geth256k1.BitCurve{P: bc.P, N: bc.N, B: bc.B, Gx: bc.Gx, Gy: bc.Gy, BitSize: bc.BitSize}
	return gbc.Unmarshal(data)
}

func CompressPubkey(x, y *big.Int) []byte {
	return geth256k1.CompressPubkey(x, y)
}

func Sign(msg, seckey []byte) ([]byte, error) {
	return geth256k1.Sign(msg, seckey)
}
