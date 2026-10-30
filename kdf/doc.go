// Package kdf implements Key Derivation Functions as specified in BSI TR-03110.
//
// This package provides the cryptographic key derivation functions required
// for the PACE protocol:
//   - KDF_PI: Derives a key from a password/CAN
//   - KDF_Enc: Derives encryption keys
//   - KDF_MAC: Derives MAC keys
//
// AES-128 uses SHA-1; AES-192/256 use SHA-256. Each KDF hashes
// secret || optional nonce || purpose counter and truncates one digest.
//
// Example usage:
//
//	key := kdf.KDF_PI(password, nil, 16, kdf.HashSHA1)
//	encKey := kdf.KDF_Enc(sharedSecret, nil, 16, kdf.HashSHA1)
//	macKey := kdf.KDF_MAC(sharedSecret, nil, 16, kdf.HashSHA1)
//
// References:
//   - BSI TR-03110 v2.21 Section 4.3: Key Derivation Functions
package kdf
