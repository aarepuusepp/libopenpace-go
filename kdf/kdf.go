package kdf

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
)

// HashAlgorithm identifies the hash function used in KDF.
type HashAlgorithm int

const (
	HashSHA256 HashAlgorithm = iota // SHA-256
	HashSHA512                      // SHA-512
	HashSHA1                        // SHA-1 (PACE AES-128 protocol requirement)
)

// KDF_PI derives a key from a password/secret using the BSI TR-03110 KDF_PI function.
// This is used in PACE Step 1 to derive the encryption key from the shared secret (CAN/PIN).
//
// Parameters:
//   - secret: The shared secret (e.g., CAN, PIN)
//   - nonce: Optional nonce/salt
//   - keyLength: Desired key length in bytes
//   - hashAlg: Hash algorithm to use (SHA-1, SHA-256 or SHA-512)
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

// kdf derives one digest H(secret || nonce || counter), truncated to keyLength.
// The counter is a four-byte big-endian purpose identifier, not an expansion
// counter. Invalid algorithms or lengths return nil (the public API has no error
// return). SHA-1 is required for the PACE AES-128 KDF, not used for signatures.
func kdf(keyMaterial, nonce []byte, keyLength int, hashAlg HashAlgorithm, counter uint32) []byte {
	var h hash.Hash
	switch hashAlg {
	case HashSHA1:
		h = sha1.New()
	case HashSHA256:
		h = sha256.New()
	case HashSHA512:
		h = sha512.New()
	default:
		return nil
	}
	if keyLength <= 0 || keyLength > h.Size() {
		return nil
	}
	h.Write(keyMaterial)
	h.Write(nonce)
	var purpose [4]byte
	binary.BigEndian.PutUint32(purpose[:], counter)
	h.Write(purpose[:])
	return h.Sum(nil)[:keyLength]
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

// GetHashAlgorithm returns the digest for AES key lengths: SHA-1 for
// AES-128 and SHA-256 for AES-192/256 (BSI TR-03110 Part 3, A.2.2).
// SHA-512 is retained for legacy callers requesting longer digest output.
// This helper does not select or enable a DES/3DES protocol.
func GetHashAlgorithm(keyLength int) HashAlgorithm {
	if keyLength <= 16 {
		return HashSHA1
	}
	if keyLength <= 32 {
		return HashSHA256
	}
	return HashSHA512
}
