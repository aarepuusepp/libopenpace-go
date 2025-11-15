package crypto

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

// brainpoolP256r1 implements the brainpoolP256r1 curve as defined in RFC 5639.
// This curve is commonly used in European smart card applications.
type brainpoolP256r1Curve struct {
	*elliptic.CurveParams
}

var (
	brainpoolP256r1Once sync.Once
	brainpoolP256r1Inst *brainpoolP256r1Curve
)

// BrainpoolP256r1 returns the brainpoolP256r1 curve.
func BrainpoolP256r1() elliptic.Curve {
	brainpoolP256r1Once.Do(func() {
		brainpoolP256r1Inst = &brainpoolP256r1Curve{CurveParams: &elliptic.CurveParams{Name: "brainpoolP256r1"}}
		
		// RFC 5639 brainpoolP256r1 parameters
		brainpoolP256r1Inst.P, _ = new(big.Int).SetString("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16)
		brainpoolP256r1Inst.N, _ = new(big.Int).SetString("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16)
		brainpoolP256r1Inst.B, _ = new(big.Int).SetString("662C61C430D84EA4FE66A7733D0B76B7BF93EBC4AF2F49256AE58101FEE92B04", 16)
		brainpoolP256r1Inst.Gx, _ = new(big.Int).SetString("A3E8EB3CC1CFE7B7732213B23A656149AFA142C47AAFBC2B79A191562E1305F4", 16)
		brainpoolP256r1Inst.Gy, _ = new(big.Int).SetString("2D996C823439C56D7F7B22E14644417E69BCB6DE39D027001DABE8F35B25C9BE", 16)
		brainpoolP256r1Inst.BitSize = 256
	})
	return brainpoolP256r1Inst
}

// BrainpoolP256r1Name returns the name identifier for brainpoolP256r1
func BrainpoolP256r1Name() string {
	return "brainpoolP256r1"
}

