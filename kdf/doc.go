// Package kdf implements Key Derivation Functions as specified in BSI TR-03110.
//
// This package provides the cryptographic key derivation functions required
// for the PACE protocol:
//   - KDF_PI: Derives a key from a password/CAN
//   - KDF_Enc: Derives encryption keys
//   - KDF_MAC: Derives MAC keys
//
// All KDFs follow the BSI TR-03110 specification and use SHA-256 or SHA-512
// as the underlying hash function.
//
// Example usage:
//
//	key := kdf.KDF_PI(password, salt, keyLength)
//	encKey := kdf.KDF_Enc(sharedSecret, nonce)
//	macKey := kdf.KDF_MAC(sharedSecret, nonce)
//
// References:
//   - BSI TR-03110 v2.21 Section 4.3: Key Derivation Functions
package kdf

