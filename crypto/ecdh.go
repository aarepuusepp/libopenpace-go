package crypto

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

// ECDHGenerateKey generates a new ECDH keypair for the specified curve.
//
// Parameters:
//   - curve: The elliptic curve to use (P256, P384, P521, X25519)
//
// Returns the private key and public key.
func ECDHGenerateKey(curve ecdh.Curve) (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDH key: %w", err)
	}
	
	return privateKey, privateKey.PublicKey(), nil
}

// ECDHComputeSharedSecret computes the ECDH shared secret.
//
// Parameters:
//   - privateKey: Our private key
//   - peerPublicKey: Peer's public key
//
// Returns the shared secret.
func ECDHComputeSharedSecret(privateKey *ecdh.PrivateKey, peerPublicKey *ecdh.PublicKey) ([]byte, error) {
	sharedSecret, err := privateKey.ECDH(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute ECDH shared secret: %w", err)
	}
	
	return sharedSecret, nil
}

// ECDHPublicKeyFromBytes creates an ECDH public key from bytes.
//
// Parameters:
//   - curve: The elliptic curve
//   - data: Public key bytes (uncompressed format: 0x04 || x || y)
//
// Returns the public key.
func ECDHPublicKeyFromBytes(curve ecdh.Curve, data []byte) (*ecdh.PublicKey, error) {
	publicKey, err := curve.NewPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDH public key: %w", err)
	}
	
	return publicKey, nil
}

// ECDHPrivateKeyFromBytes creates an ECDH private key from bytes.
//
// Parameters:
//   - curve: The elliptic curve
//   - data: Private key bytes (scalar value)
//
// Returns the private key.
func ECDHPrivateKeyFromBytes(curve ecdh.Curve, data []byte) (*ecdh.PrivateKey, error) {
	privateKey, err := curve.NewPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDH private key: %w", err)
	}
	
	return privateKey, nil
}

// GetCurveByName returns an ECDH curve by name.
//
// Supported curves:
//   - "P-256", "P256", "secp256r1"
//   - "P-384", "P384", "secp384r1"
//   - "P-521", "P521", "secp521r1"
//   - "X25519"
func GetCurveByName(name string) (ecdh.Curve, error) {
	switch name {
	case "P-256", "P256", "secp256r1":
		return ecdh.P256(), nil
	case "P-384", "P384", "secp384r1":
		return ecdh.P384(), nil
	case "P-521", "P521", "secp521r1":
		return ecdh.P521(), nil
	case "X25519":
		return ecdh.X25519(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}

// GenerateEllipticKey generates a keypair for an elliptic curve (brainpool, etc.).
// Returns private key scalar and public key coordinates (x, y).
func GenerateEllipticKey(curve elliptic.Curve) ([]byte, *big.Int, *big.Int, error) {
	// Generate random private key
	privateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}
	
	return privateKey, x, y, nil
}

// ComputeEllipticSharedSecret computes ECDH shared secret for elliptic curves.
func ComputeEllipticSharedSecret(curve elliptic.Curve, privateKey []byte, peerX, peerY *big.Int) ([]byte, error) {
	// Compute shared secret: privateKey * peerPublicKey
	x, _ := curve.ScalarMult(peerX, peerY, privateKey)
	
	// Return x-coordinate as shared secret
	return x.Bytes(), nil
}

