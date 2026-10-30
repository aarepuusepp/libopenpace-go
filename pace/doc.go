// Package pace implements the PACE (Password Authenticated Connection Establishment)
// protocol as specified in BSI TR-03110.
//
// PACE is a cryptographic protocol used to establish a secure channel between
// a smart card and a terminal. It provides mutual authentication and establishes
// session keys for secure messaging.
//
// The protocol consists of several steps:
//  1. Nonce encryption/decryption
//  2. Domain parameter mapping (GM; IM/CAM are disabled)
//  3. Key agreement (DH/ECDH)
//  4. Key derivation
//  5. Mutual authentication
//
// Example usage:
//
//	session, err := pace.PerformPACE(card, secret, pace.OID_PACE_ECDH_GM_AES256, 12)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// References:
//   - BSI TR-03110 v2.21: Advanced Security Mechanisms for Machine Readable Travel Documents
package pace
