package pace

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"math/big"
	
	"github.com/aarepuusepp/libopenpace-go/crypto"
)

// PACE_STEP3B_key_agreement implements PACE Step 3B: Key Agreement.
//
// This step performs ephemeral key agreement using the mapped generator.
//
// Process:
//  1. Generate ephemeral keypair using mapped generator G'
//  2. Send ephemeral public key to peer
//  3. Receive peer's ephemeral public key
//  4. Compute shared secret
//
// Parameters:
//   - ctx: PACE context (must have mapped generator)
//
// Returns the ephemeral public key to send to the peer.
//
// Reference: BSI TR-03110 v2.21 Section 4.4.3
func PACE_STEP3B_generate_ephemeral_key(ctx *PACEContext) ([]byte, error) {
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
func generateEphemeralKeyECDH(ctx *PACEContext) ([]byte, error) {
	if ctx.DomainParams == nil || ctx.DomainParams.Type != DomainTypeEC {
		return nil, fmt.Errorf("EC domain parameters required")
	}
	
	if ctx.MappedGenerator == nil {
		return nil, fmt.Errorf("mapped generator required")
	}
	
	// Check if we're using brainpool (elliptic.Curve) or standard (ecdh.Curve)
	if ctx.DomainParams.EllipticCurve != nil {
		// Brainpool curve - use elliptic package
		return generateEphemeralKeyElliptic(ctx)
	}
	
	// Generate ephemeral keypair using ecdh.Curve
	curve := ctx.DomainParams.Curve
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	
	publicKey := privateKey.PublicKey()
	
	// Store keys in context
	ctx.EphemeralPrivateKey = privateKey
	ctx.EphemeralPublicKey = publicKey
	
	// Return public key bytes
	return publicKey.Bytes(), nil
}

// generateEphemeralKeyElliptic generates an ephemeral key for brainpool curves.
func generateEphemeralKeyElliptic(ctx *PACEContext) ([]byte, error) {
	curve := ctx.DomainParams.EllipticCurve
	
	// Generate random private key
	privateKey, x, y, err := crypto.GenerateEllipticKey(curve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	
	// Build uncompressed public key: 04 || X || Y
	publicKeyBytes := []byte{0x04}
	publicKeyBytes = append(publicKeyBytes, x.Bytes()...)
	publicKeyBytes = append(publicKeyBytes, y.Bytes()...)
	
	// Store keys in context
	ctx.EphemeralPrivateKey = privateKey
	ctx.EphemeralPublicKey = publicKeyBytes
	
	// Return public key bytes (uncompressed format: 04 || X || Y)
	return publicKeyBytes, nil
}

// generateEphemeralKeyDH generates an ephemeral DH keypair.
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
	
	// Compute ephemeral public key: PK = G'^privateKey mod P
	publicKey := new(big.Int).Exp(mappedG, privateKey, ctx.DomainParams.P)
	
	// Store keys in context
	ctx.EphemeralPrivateKey = privateKey
	ctx.EphemeralPublicKey = publicKey
	
	// Return public key bytes (big-endian)
	keySize := (ctx.DomainParams.P.BitLen() + 7) / 8
	return crypto.DHPublicKeyToBytes(publicKey, keySize), nil
}

// PACE_STEP3B_compute_shared_secret computes the shared secret from peer's public key.
//
// Parameters:
//   - ctx: PACE context (must have ephemeral private key)
//   - peerPublicKey: Peer's ephemeral public key bytes
//
// Returns an error if computation fails.
func PACE_STEP3B_compute_shared_secret(ctx *PACEContext, peerPublicKey []byte) error {
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
func computeSharedSecretECDH(ctx *PACEContext, peerPublicKeyBytes []byte) error {
	if ctx.EphemeralPrivateKey == nil {
		return fmt.Errorf("ephemeral private key required")
	}
	
	privateKey, ok := ctx.EphemeralPrivateKey.(*ecdh.PrivateKey)
	if !ok {
		return fmt.Errorf("invalid ephemeral private key type for ECDH")
	}
	
	// Parse peer's public key
	curve := ctx.DomainParams.Curve
	peerPublicKey, err := curve.NewPublicKey(peerPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse peer public key: %w", err)
	}
	
	// Store peer's public key
	ctx.PeerPublicKey = peerPublicKey
	
	// Compute shared secret
	sharedSecret, err := privateKey.ECDH(peerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to compute ECDH shared secret: %w", err)
	}
	
	// Store shared secret
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
	
	// Parse peer's public key
	peerPublicKey := new(big.Int).SetBytes(peerPublicKeyBytes)
	
	// Validate peer public key is in valid range [2, P-2]
	two := big.NewInt(2)
	pMinus2 := new(big.Int).Sub(ctx.DomainParams.P, two)
	
	if peerPublicKey.Cmp(two) < 0 || peerPublicKey.Cmp(pMinus2) > 0 {
		return fmt.Errorf("peer public key out of valid range")
	}
	
	// Store peer's public key
	ctx.PeerPublicKey = peerPublicKey
	
	// Compute shared secret: K = peerPublicKey^privateKey mod P
	sharedSecret := new(big.Int).Exp(peerPublicKey, privateKey, ctx.DomainParams.P)
	
	// Verify shared secret is not 1 (small subgroup attack prevention)
	if sharedSecret.Cmp(big.NewInt(1)) == 0 {
		return fmt.Errorf("shared secret is 1, possible small subgroup attack")
	}
	
	// Convert to bytes
	keySize := (ctx.DomainParams.P.BitLen() + 7) / 8
	sharedSecretBytes := crypto.DHPublicKeyToBytes(sharedSecret, keySize)
	
	// Store shared secret
	ctx.SharedSecret = sharedSecretBytes
	
	return nil
}

