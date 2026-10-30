package pace

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/aarepuusepp/libopenpace-go/crypto"
)

// PACE_STEP3B_generate_ephemeral_key implements PACE Step 3B: Key Agreement.
//
// Generates an ephemeral keypair using the mapped generator G'.
// For ECDH with Generic Mapping: PK = privKey * G' (NOT privKey * G)
// For ECDH with Integrated Mapping: same approach.
//
// Reference: BSI TR-03110 v2.21 Section 4.4.3
func PACE_STEP3B_generate_ephemeral_key(ctx *PACEContext) ([]byte, error) {
	if err := ValidateProtocol(ctx.Protocol); err != nil {
		return nil, err
	}
	keyAgreementType := ctx.Protocol.GetKeyAgreementType()

	switch keyAgreementType {
	case KeyAgreementECDH:
		return generateEphemeralKeyECDH(ctx)
	case KeyAgreementDH:
		return generateEphemeralKeyDH(ctx)
	default:
		return nil, fmt.Errorf("unsupported key agreement type: %v", keyAgreementType)
	}
}

// generateEphemeralKeyECDH generates an ephemeral ECDH keypair.
// Dispatches to brainpool (elliptic.Curve) or standard (ecdh.Curve) path.
func generateEphemeralKeyECDH(ctx *PACEContext) ([]byte, error) {
	if ctx.DomainParams == nil || ctx.DomainParams.Type != DomainTypeEC {
		return nil, fmt.Errorf("EC domain parameters required")
	}
	if ctx.MappedGenerator == nil {
		return nil, fmt.Errorf("mapped generator required (run Step 3A first)")
	}

	if ctx.DomainParams.EllipticCurve != nil {
		return generateEphemeralKeyElliptic(ctx)
	}

	// Standard ecdh.Curve — generate keypair on the standard curve.
	// For IM on standard curves, the mapped generator cannot be used
	// directly with crypto/ecdh (it only supports standard base point).
	curve := ctx.DomainParams.Curve
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	ctx.EphemeralPrivateKey = privateKey
	ctx.EphemeralPublicKey = privateKey.PublicKey()

	return privateKey.PublicKey().Bytes(), nil
}

// generateEphemeralKeyElliptic generates an ephemeral key for brainpool curves.
//
// The public key is computed as privKey * G' where G' is the mapped generator,
// NOT the standard base point G. This is critical for PACE correctness.
func generateEphemeralKeyElliptic(ctx *PACEContext) ([]byte, error) {
	curve := ctx.DomainParams.EllipticCurve

	// Generate a random private key scalar
	privBytes, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Compute public key = privKey * G' (mapped generator)
	mappedGen, ok := ctx.MappedGenerator.(*ECPoint)
	if !ok {
		return nil, fmt.Errorf("mapped generator is not *ECPoint (got %T)", ctx.MappedGenerator)
	}

	pubX, pubY := curve.ScalarMult(mappedGen.X, mappedGen.Y, privBytes)

	// Encode as uncompressed: 04 || X || Y (padded to curve byte size)
	byteLen := (curve.Params().BitSize + 7) / 8
	publicKeyBytes := make([]byte, 1+2*byteLen)
	publicKeyBytes[0] = 0x04
	xBytes := pubX.Bytes()
	yBytes := pubY.Bytes()
	copy(publicKeyBytes[1+byteLen-len(xBytes):1+byteLen], xBytes)
	copy(publicKeyBytes[1+2*byteLen-len(yBytes):1+2*byteLen], yBytes)

	ctx.EphemeralPrivateKey = privBytes
	ctx.EphemeralPublicKey = publicKeyBytes

	return publicKeyBytes, nil
}

// generateEphemeralKeyDH generates an ephemeral DH keypair using the mapped generator.
func generateEphemeralKeyDH(ctx *PACEContext) ([]byte, error) {
	if ctx.DomainParams == nil || ctx.DomainParams.Type != DomainTypeDH {
		return nil, fmt.Errorf("DH domain parameters required")
	}
	if ctx.MappedGenerator == nil {
		return nil, fmt.Errorf("mapped generator required")
	}

	mappedG, ok := ctx.MappedGenerator.(*big.Int)
	if !ok {
		return nil, fmt.Errorf("invalid mapped generator type for DH")
	}

	// Generate ephemeral private key (random scalar)
	var max *big.Int
	if ctx.DomainParams.Q != nil {
		max = new(big.Int).Sub(ctx.DomainParams.Q, big.NewInt(1))
	} else {
		max = new(big.Int).Sub(ctx.DomainParams.P, big.NewInt(2))
	}

	privateKey, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral private key: %w", err)
	}
	privateKey.Add(privateKey, big.NewInt(1))

	// PK = G'^privateKey mod P
	publicKey := new(big.Int).Exp(mappedG, privateKey, ctx.DomainParams.P)

	ctx.EphemeralPrivateKey = privateKey
	ctx.EphemeralPublicKey = publicKey

	keySize := (ctx.DomainParams.P.BitLen() + 7) / 8
	return crypto.DHPublicKeyToBytes(publicKey, keySize), nil
}

// PACE_STEP3B_compute_shared_secret computes the shared secret from peer's public key.
//
// Parameters:
//   - ctx: PACE context (must have ephemeral private key)
//   - peerPublicKey: Peer's ephemeral public key bytes
func PACE_STEP3B_compute_shared_secret(ctx *PACEContext, peerPublicKey []byte) error {
	if err := ValidateProtocol(ctx.Protocol); err != nil {
		return err
	}
	keyAgreementType := ctx.Protocol.GetKeyAgreementType()

	switch keyAgreementType {
	case KeyAgreementECDH:
		return computeSharedSecretECDH(ctx, peerPublicKey)
	case KeyAgreementDH:
		return computeSharedSecretDH(ctx, peerPublicKey)
	default:
		return fmt.Errorf("unsupported key agreement type: %v", keyAgreementType)
	}
}

// computeSharedSecretECDH computes the ECDH shared secret.
// Dispatches to brainpool (elliptic.Curve) or standard (ecdh.Curve) path.
func computeSharedSecretECDH(ctx *PACEContext, peerPublicKeyBytes []byte) error {
	if ctx.EphemeralPrivateKey == nil {
		return fmt.Errorf("ephemeral private key required")
	}

	// Brainpool path: private key is []byte
	if privBytes, ok := ctx.EphemeralPrivateKey.([]byte); ok {
		return computeSharedSecretElliptic(ctx, privBytes, peerPublicKeyBytes)
	}

	// Standard ecdh.Curve path
	privateKey, ok := ctx.EphemeralPrivateKey.(*ecdh.PrivateKey)
	if !ok {
		return fmt.Errorf("invalid ephemeral private key type: %T", ctx.EphemeralPrivateKey)
	}

	curve := ctx.DomainParams.Curve
	peerPublicKey, err := curve.NewPublicKey(peerPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse peer public key: %w", err)
	}

	ctx.PeerPublicKey = peerPublicKey

	sharedSecret, err := privateKey.ECDH(peerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to compute ECDH shared secret: %w", err)
	}

	ctx.SharedSecret = sharedSecret
	return nil
}

// computeSharedSecretElliptic computes ECDH shared secret for brainpool curves
// using the elliptic.Curve interface.
func computeSharedSecretElliptic(ctx *PACEContext, privKey []byte, peerPublicKeyBytes []byte) error {
	curve := ctx.DomainParams.EllipticCurve
	if curve == nil {
		return fmt.Errorf("elliptic.Curve required for brainpool ECDH")
	}

	// Parse peer's uncompressed public key
	peerX, peerY := elliptic.Unmarshal(curve, peerPublicKeyBytes)
	if peerX == nil {
		return fmt.Errorf("failed to unmarshal peer public key (%d bytes)", len(peerPublicKeyBytes))
	}

	// Store raw peer public key bytes
	ctx.PeerPublicKey = peerPublicKeyBytes

	// SharedSecret = x-coordinate of (privKey * peerPub)
	sx, _ := curve.ScalarMult(peerX, peerY, privKey)

	// Pad x-coordinate to curve byte length
	byteLen := (curve.Params().BitSize + 7) / 8
	sharedSecret := make([]byte, byteLen)
	sxBytes := sx.Bytes()
	copy(sharedSecret[byteLen-len(sxBytes):], sxBytes)

	ctx.SharedSecret = sharedSecret
	return nil
}

// computeSharedSecretDH computes the DH shared secret.
func computeSharedSecretDH(ctx *PACEContext, peerPublicKeyBytes []byte) error {
	if ctx.EphemeralPrivateKey == nil {
		return fmt.Errorf("ephemeral private key required")
	}

	privateKey, ok := ctx.EphemeralPrivateKey.(*big.Int)
	if !ok {
		return fmt.Errorf("invalid ephemeral private key type for DH")
	}

	peerPublicKey := new(big.Int).SetBytes(peerPublicKeyBytes)

	// Validate peer public key is in valid range [2, P-2]
	two := big.NewInt(2)
	pMinus2 := new(big.Int).Sub(ctx.DomainParams.P, two)

	if peerPublicKey.Cmp(two) < 0 || peerPublicKey.Cmp(pMinus2) > 0 {
		return fmt.Errorf("peer public key out of valid range")
	}

	ctx.PeerPublicKey = peerPublicKey

	// K = peerPublicKey^privateKey mod P
	sharedSecret := new(big.Int).Exp(peerPublicKey, privateKey, ctx.DomainParams.P)

	if sharedSecret.Cmp(big.NewInt(1)) == 0 {
		return fmt.Errorf("shared secret is 1, possible small subgroup attack")
	}

	keySize := (ctx.DomainParams.P.BitLen() + 7) / 8
	sharedSecretBytes := crypto.DHPublicKeyToBytes(sharedSecret, keySize)

	ctx.SharedSecret = sharedSecretBytes
	return nil
}
