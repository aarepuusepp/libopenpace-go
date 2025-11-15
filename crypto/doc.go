// Package crypto provides cryptographic primitives for the PACE protocol.
//
// This package implements:
//   - AES encryption/decryption (CBC, ECB modes)
//   - 3DES encryption/decryption
//   - CMAC (Cipher-based Message Authentication Code)
//   - ISO 9797-1 Method 2 padding
//   - ECDH (Elliptic Curve Diffie-Hellman)
//   - DH (Diffie-Hellman)
//   - Point encoding/decoding utilities
//
// All implementations follow relevant standards (NIST, ISO, BSI) and use
// Go's standard library crypto packages where possible.
//
// Example usage:
//
//	ciphertext, err := crypto.AESEncrypt(key, plaintext)
//	mac := crypto.CMAC(key, data)
//	sharedSecret, err := crypto.ECDH(privateKey, publicKey)
//
// References:
//   - NIST SP 800-38A: Block Cipher Modes
//   - NIST SP 800-38B: CMAC
//   - ISO 9797-1: MAC algorithms
package crypto

