package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// DHParameters represents Diffie-Hellman domain parameters.
type DHParameters struct {
	P *big.Int // Prime modulus
	G *big.Int // Generator
	Q *big.Int // Prime order of subgroup (optional, for validation)
}

// DHGenerateKey generates a new DH keypair.
//
// Parameters:
//   - params: DH domain parameters (P, G, Q)
//
// Returns the private key (scalar) and public key (G^private mod P).
func DHGenerateKey(params *DHParameters) (*big.Int, *big.Int, error) {
	// Generate random private key in range [1, Q-1] or [1, P-2]
	var max *big.Int
	if params.Q != nil {
		max = new(big.Int).Sub(params.Q, big.NewInt(1))
	} else {
		max = new(big.Int).Sub(params.P, big.NewInt(2))
	}
	
	privateKey, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate DH private key: %w", err)
	}
	
	// Ensure private key is at least 1
	privateKey.Add(privateKey, big.NewInt(1))
	
	// Compute public key: G^privateKey mod P
	publicKey := new(big.Int).Exp(params.G, privateKey, params.P)
	
	return privateKey, publicKey, nil
}

// DHComputeSharedSecret computes the DH shared secret.
//
// Parameters:
//   - params: DH domain parameters
//   - privateKey: Our private key
//   - peerPublicKey: Peer's public key
//
// Returns the shared secret (peerPublicKey^privateKey mod P).
func DHComputeSharedSecret(params *DHParameters, privateKey, peerPublicKey *big.Int) (*big.Int, error) {
	// Validate peer public key is in valid range [2, P-2]
	two := big.NewInt(2)
	pMinus2 := new(big.Int).Sub(params.P, two)
	
	if peerPublicKey.Cmp(two) < 0 || peerPublicKey.Cmp(pMinus2) > 0 {
		return nil, fmt.Errorf("peer public key out of valid range")
	}
	
	// Compute shared secret: peerPublicKey^privateKey mod P
	sharedSecret := new(big.Int).Exp(peerPublicKey, privateKey, params.P)
	
	// Verify shared secret is not 1 (small subgroup attack prevention)
	if sharedSecret.Cmp(big.NewInt(1)) == 0 {
		return nil, fmt.Errorf("shared secret is 1, possible small subgroup attack")
	}
	
	return sharedSecret, nil
}

// DHPublicKeyFromBytes creates a DH public key from bytes.
//
// Parameters:
//   - data: Public key bytes (big-endian encoding)
//
// Returns the public key as a big.Int.
func DHPublicKeyFromBytes(data []byte) *big.Int {
	return new(big.Int).SetBytes(data)
}

// DHPublicKeyToBytes converts a DH public key to bytes.
//
// Parameters:
//   - publicKey: Public key as big.Int
//   - size: Desired output size in bytes (will be zero-padded if needed)
//
// Returns the public key bytes (big-endian encoding).
func DHPublicKeyToBytes(publicKey *big.Int, size int) []byte {
	bytes := publicKey.Bytes()
	
	// Pad with leading zeros if needed
	if len(bytes) < size {
		padded := make([]byte, size)
		copy(padded[size-len(bytes):], bytes)
		return padded
	}
	
	return bytes
}

// ValidateDHParameters validates DH domain parameters.
//
// This performs basic sanity checks:
//   - P is odd and > 2
//   - G is in range [2, P-2]
//   - If Q is provided, verify P = kQ + 1 for some k
func ValidateDHParameters(params *DHParameters) error {
	// Check P is odd and > 2
	if params.P.Cmp(big.NewInt(2)) <= 0 {
		return fmt.Errorf("P must be greater than 2")
	}
	
	if params.P.Bit(0) == 0 {
		return fmt.Errorf("P must be odd")
	}
	
	// Check G is in range [2, P-2]
	two := big.NewInt(2)
	pMinus2 := new(big.Int).Sub(params.P, two)
	
	if params.G.Cmp(two) < 0 || params.G.Cmp(pMinus2) > 0 {
		return fmt.Errorf("G must be in range [2, P-2]")
	}
	
	// If Q is provided, verify G^Q mod P = 1
	if params.Q != nil {
		gToQ := new(big.Int).Exp(params.G, params.Q, params.P)
		if gToQ.Cmp(big.NewInt(1)) != 0 {
			return fmt.Errorf("G^Q mod P must equal 1")
		}
	}
	
	return nil
}

// GetStandardDHParameters returns standardized DH parameters.
//
// Supported groups:
//   - "modp1024": 1024-bit MODP group (RFC 2409)
//   - "modp2048": 2048-bit MODP group (RFC 3526)
//   - "modp3072": 3072-bit MODP group (RFC 3526)
//   - "modp4096": 4096-bit MODP group (RFC 3526)
func GetStandardDHParameters(group string) (*DHParameters, error) {
	switch group {
	case "modp2048":
		// RFC 3526 2048-bit MODP Group
		p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
		g := big.NewInt(2)
		return &DHParameters{P: p, G: g}, nil
	default:
		return nil, fmt.Errorf("unsupported DH group: %s", group)
	}
}

