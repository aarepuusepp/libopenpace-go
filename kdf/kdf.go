package kdf

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
)

// HashAlgorithm identifies the hash function used in KDF.
type HashAlgorithm int

const (
	HashSHA256 HashAlgorithm = iota // SHA-256
	HashSHA512                       // SHA-512
)

// KDF_PI derives a key from a password/secret using the BSI TR-03110 KDF_PI function.
// This is used in PACE Step 1 to derive the encryption key from the shared secret (CAN/PIN).
//
// Parameters:
//   - secret: The shared secret (e.g., CAN, PIN)
//   - nonce: Optional nonce/salt
//   - keyLength: Desired key length in bytes
//   - hashAlg: Hash algorithm to use (SHA-256 or SHA-512)
//
// Returns the derived key.
//
// Reference: BSI TR-03110 v2.21 Section 4.3.1
func KDF_PI(secret, nonce []byte, keyLength int, hashAlg HashAlgorithm) []byte {
	return kdf(secret, nonce, keyLength, hashAlg, 3) // Counter starts at 3 for KDF_PI
}

// KDF_Enc derives an encryption key from shared secret and nonce.
// This is used in PACE Step 3C to derive K_enc for secure messaging.
//
// Parameters:
//   - sharedSecret: The shared secret from key agreement
//   - nonce: Nonce from PACE protocol
//   - keyLength: Desired key length in bytes
//   - hashAlg: Hash algorithm to use
//
// Returns the derived encryption key.
//
// Reference: BSI TR-03110 v2.21 Section 4.3.2
func KDF_Enc(sharedSecret, nonce []byte, keyLength int, hashAlg HashAlgorithm) []byte {
	return kdf(sharedSecret, nonce, keyLength, hashAlg, 1) // Counter starts at 1 for KDF_Enc
}

// KDF_MAC derives a MAC key from shared secret and nonce.
// This is used in PACE Step 3C to derive K_mac for secure messaging.
//
// Parameters:
//   - sharedSecret: The shared secret from key agreement
//   - nonce: Nonce from PACE protocol
//   - keyLength: Desired key length in bytes
//   - hashAlg: Hash algorithm to use
//
// Returns the derived MAC key.
//
// Reference: BSI TR-03110 v2.21 Section 4.3.2
func KDF_MAC(sharedSecret, nonce []byte, keyLength int, hashAlg HashAlgorithm) []byte {
	return kdf(sharedSecret, nonce, keyLength, hashAlg, 2) // Counter starts at 2 for KDF_MAC
}

// kdf implements the generic KDF function as specified in BSI TR-03110.
//
// The KDF uses a counter mode construction:
//   K = H(K_in || c || nonce) || H(K_in || c+1 || nonce) || ...
//
// where:
//   - K_in is the input key material
//   - c is a 4-byte counter starting at counterStart
//   - nonce is optional additional data
//   - H is the hash function (SHA-256 or SHA-512)
//
// The output is truncated to keyLength bytes.
func kdf(keyMaterial, nonce []byte, keyLength int, hashAlg HashAlgorithm, counterStart uint32) []byte {
	var h hash.Hash
	switch hashAlg {
	case HashSHA256:
		h = sha256.New()
	case HashSHA512:
		h = sha512.New()
	default:
		h = sha256.New() // Default to SHA-256
	}
	
	result := make([]byte, 0, keyLength)
	counter := counterStart
	
	// Generate key material in blocks until we have enough
	for len(result) < keyLength {
		h.Reset()
		
		// H(K_in || counter || nonce)
		h.Write(keyMaterial)
		
		// Write counter as 4-byte big-endian
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		h.Write(counterBytes)
		
		if len(nonce) > 0 {
			h.Write(nonce)
		}
		
		block := h.Sum(nil)
		result = append(result, block...)
		counter++
	}
	
	// Truncate to desired length
	return result[:keyLength]
}

// AdjustKeyParity adjusts DES key parity bits.
// This is required for 3DES keys where each byte must have odd parity.
//
// For each byte, the least significant bit is set to make the total
// number of 1-bits odd.
func AdjustKeyParity(key []byte) []byte {
	adjusted := make([]byte, len(key))
	copy(adjusted, key)
	
	for i := range adjusted {
		// Count number of 1-bits in the upper 7 bits
		b := adjusted[i] & 0xFE // Clear LSB
		ones := 0
		for j := 0; j < 8; j++ {
			if (b & (1 << j)) != 0 {
				ones++
			}
		}
		
		// Set LSB to make total number of 1-bits odd
		if ones%2 == 0 {
			adjusted[i] |= 0x01
		} else {
			adjusted[i] &= 0xFE
		}
	}
	
	return adjusted
}

// GetHashAlgorithm returns the appropriate hash algorithm for a given key length.
// Per BSI TR-03110 Part 3, Appendix A.2.1.2, Table A.1:
//   - SHA-1 for 3DES and AES-128 (≤16 bytes) — we use SHA-256 as SHA-1 is not available
//   - SHA-256 for AES-192 and AES-256 (≤32 bytes)
//   - SHA-512 for key sizes >32 bytes
func GetHashAlgorithm(keyLength int) HashAlgorithm {
	if keyLength <= 32 {
		return HashSHA256
	}
	return HashSHA512
}

