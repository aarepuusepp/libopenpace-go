> Historical investigation/development record. Commands, versions and completion claims describe that record, not the current release. Use [current README](../README.md) for supported setup and API boundaries.

# brainpoolP256r1 and AES-256 Support

## Status: ✅ IMPLEMENTED

All brainpool curve and AES-256 requirements have been resolved as of v1.1.0.

## Implementation Details

### Brainpool Curves

Brainpool curve support was added using the `go.gnd.pw/crypto/brainpool` package, which implements the `elliptic.Curve` interface:

- **brainpoolP256r1** (ParamID 13)
- **brainpoolP320r1** (ParamID 14)
- **brainpoolP384r1** (ParamID 16)
- **brainpoolP512r1** (ParamID 17)

Since Go's `crypto/ecdh` only supports NIST curves, brainpool operations use the `crypto/elliptic.Curve` interface directly. Key operations (`ScalarMult`, `ScalarBaseMult`, `Add`) work through this interface with private keys as `[]byte` and public keys as uncompressed `04||X||Y` format.

### AES-256 Support

AES-256 is fully supported throughout the protocol:

- **KDF**: SHA-256 hash for key lengths ≤ 32 bytes (per BSI TR-03110)
- **Nonce**: 32-byte nonce for AES-256, decrypted with AES-CBC (zero IV)
- **SM**: AES-256 encryption with 16-byte SSC, correct IV computation

### Estonian Card Parameters

- **IDEMIA cards**: ECDH-GM-AES256, secp256r1 (ParamID 12)
- **Thales cards**: ECDH-GM-AES256, brainpoolP384r1 (ParamID 16), 16-byte nonce

Parameters are automatically detected via EF.CardAccess parsing.

## Original Issue

The Thales test card required brainpoolP256r1/AES-256, but v1.0.0 only supported NIST P-256/AES-128. This resulted in `SW=6985` (Conditions of use not satisfied) from MSE:Set AT.

## Resolution

- ✅ brainpoolP256r1 implemented via `go.gnd.pw/crypto/brainpool`
- ✅ AES-256 support in KDF, PACE, and SM
- ✅ Dynamic cipher suite selection from EF.CardAccess OID
- ✅ ParamID-to-curve mapping corrected per BSI TR-03110 Part 3, Table D.1
- ✅ Tested successfully with both IDEMIA and Thales Estonian ID cards

## References

- RFC 5639: Elliptic Curve Cryptography (ECC) Brainpool Standard Curves
- BSI TR-03110 v2.21: Advanced Security Mechanisms
- ISO/IEC 15946-5: Cryptographic techniques based on elliptic curves
