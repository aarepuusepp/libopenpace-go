package pace

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	gndbp "go.gnd.pw/crypto/brainpool"
)

// EC is an interface for elliptic curves (both NIST and brainpool)
type EC interface {
	elliptic.Curve
}

// nistP256 returns NIST P-256 curve
func nistP256() EC { return elliptic.P256() }

// nistP384 returns NIST P-384 curve
func nistP384() EC { return elliptic.P384() }

// nistP521 returns NIST P-521 curve
func nistP521() EC { return elliptic.P521() }

// brainpoolP256r1 returns brainpoolP256r1 curve (RFC 5639)
func brainpoolP256r1() EC { return gndbp.P256r1() }

// ChooseCurve picks the EC domain from ParamID (from EF.CardAccess PACEInfo)
func ChooseCurve(paramID byte) (EC, error) {
	switch paramID {
	case 0x08: // NIST P-256 (secp256r1)
		return nistP256(), nil
	case 0x09: // NIST P-384 (secp384r1)
		return nistP384(), nil
	case 0x0A: // NIST P-521 (secp521r1)
		return nistP521(), nil
	case 0x0C: // brainpoolP256r1 (older spec / Idemia cards)
		return brainpoolP256r1(), nil
	case 0x10: // brainpoolP256r1 (newer spec / Thales cards)
		return brainpoolP256r1(), nil
	default:
		return nil, errors.New("unsupported PACE ParamID")
	}
}

// GenerateECKey generates a keypair for an elliptic curve
func GenerateECKey(c EC) (priv []byte, pubX, pubY *big.Int, err error) {
	priv, x, y, err := elliptic.GenerateKey(c, rand.Reader)
	return priv, x, y, err
}

// ECDH computes ECDH shared secret for elliptic curves
func ECDH(c EC, priv []byte, peerX, peerY *big.Int) []byte {
	sx, _ := c.ScalarMult(peerX, peerY, priv)
	return sx.Bytes() // x-coordinate as shared secret
}

// EncodePoint encodes an EC point in uncompressed format (04 || X || Y)
func EncodePoint(c EC, x, y *big.Int) []byte {
	return elliptic.Marshal(c, x, y)
}

// DecodePoint decodes an EC point from uncompressed format
func DecodePoint(c EC, b []byte) (x, y *big.Int, err error) {
	x, y = elliptic.Unmarshal(c, b)
	if x == nil {
		return nil, nil, errors.New("invalid EC point")
	}
	return x, y, nil
}

// SelfTestBrainpool performs a sanity check on brainpool curve operations
func SelfTestBrainpool() error {
	c := brainpoolP256r1()

	// Alice
	privA, Ax, Ay, err := GenerateECKey(c)
	if err != nil {
		return err
	}

	// Bob
	privB, Bx, By, err := GenerateECKey(c)
	if err != nil {
		return err
	}

	// Compute shared secrets
	sA := ECDH(c, privA, Bx, By)
	sB := ECDH(c, privB, Ax, Ay)

	// Verify they match
	if new(big.Int).SetBytes(sA).Cmp(new(big.Int).SetBytes(sB)) != 0 {
		return errors.New("ECDH mismatch - brainpool curve test failed")
	}

	return nil
}

