# Changelog

All notable changes to libopenpace-go will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.2] - 2026-10-30

- Use protocol-required SHA-1 for AES-128 KDF and SHA-256 for AES-192/256.
- Hash secret || nonce || purpose counter; truncate one digest. Reject invalid
  digest lengths/algorithms with nil instead of expanding or silently defaulting.
- Add 20 fixed independent KDF vectors, an OpenSSL verification script, and the
  OpenPACE AES-128 nonce/session-key worked example.
- Reject incomplete IM/3DES and unknown OIDs in card negotiation and exported
  PACE steps. Remove simplified IM mapping and simulated high-level sessions.
- Keep AES-192 working; SM and CMAC explicitly accept AES keys only.
- Document remaining protocol scope and hardware validation limits.

## [1.1.1] - 2026-10-28

### Changed

- Updated Go requirement to 1.27.3.

## [1.1.0] - 2026-03-05

### Changed

- Upgraded to Go 1.26.0
- Updated all dependencies to latest versions

### Added

- **Generic Mapping (GM-ECDH)**: Full implementation with ephemeral mapping keypair exchange and mapped generator computation (G' = s*G + H)
- **Brainpool curve support**: brainpoolP256r1, brainpoolP320r1, brainpoolP384r1, brainpoolP512r1 via `go.gnd.pw/crypto/brainpool`
- **Raw AES functions**: `AESEncryptCBCRaw`, `AESDecryptCBCRaw`, `AESEncryptECBBlock`, `AESDecryptECBRaw` for SM and PACE operations that require no padding
- **Verbose debug logging**: `pace.SetVerbose()` and `sm.SetVerbose()` for opt-in protocol tracing (disabled by default)
- **Correct BSI TR-03110 auth token format**: TLV-encoded `7F49{06 <OID> 86 <peerPK>}` with 8-byte MAC truncation
- **Correct ParamID-to-curve mappings**: Per BSI TR-03110 Part 3, Table D.1 (ParamIDs 8-18)
- **EF.CardAccess auto-detection**: `PerformPACE` reads EF.CardAccess and overrides default protocol/curve parameters
- **Multi-context AID probing**: Tries MF, EstEID contactless AID, and eMRTD AID for PACE initialization
- Tests for new raw AES functions and verbose control

### Fixed

- **SM MAC input padding**: ISO 9797-1 Method 2 padding applied to full CMAC input before computation (K1 subkey path)
- **SM IV computation**: Uses `AES_ECB_Enc(K_enc, SSC)` instead of zero IV
- **SM SSC size**: Stored as block-size bytes (16 for AES), not 8
- **SM Le' byte**: Appended `Le'=0x00` to all SM-wrapped APDUs
- **SM data encryption**: Uses `AESEncryptCBCRaw` (ISO padding, no PKCS#7)
- **PACE nonce decryption**: AES-CBC with zero IV (not ECB) — required for multi-block nonces (AES-256)
- **KDF hash selection**: SHA-256 for key lengths ≤ 32 bytes per BSI TR-03110
- **OID constants**: Corrected PACE OID mappings (DH-GM=.1, ECDH-GM=.2, DH-IM=.3, ECDH-IM=.4)
- **CLA byte for GA**: Steps 1-3 use CLA=0x10 (command chaining), Step 4 uses CLA=0x00

## [1.0.0] - 2025-11-17

### Added

- Initial stable release of libopenpace-go
- Complete PACE (Password Authenticated Connection Establishment) protocol implementation
- Pure Go implementation with no CGO dependencies
- Support for multiple cipher suites:
  - AES-128, AES-192, AES-256
  - 3DES (legacy support)
- Support for multiple domain parameters:
  - NIST curves (P-256, P-384, P-521)
  - Brainpool curves (BP256R1, BP320R1, BP384R1, BP512R1)
  - Diffie-Hellman groups
- Secure Messaging (SM) implementation:
  - APDU wrapping with encryption and MAC
  - APDU unwrapping with verification
- Key Derivation Functions (KDF) compliant with BSI TR-03110
- ASN.1 parsing for EF.CardAccess
- Comprehensive test coverage with BSI TR-03110 test vectors
- High-level API for easy integration
- Working examples for common use cases

### Standards Compliance

- BSI TR-03110 v2.21: Advanced Security Mechanisms for Machine Readable Travel Documents and eIDAS Token
- ISO/IEC 7816: Smart card standards

### Documentation

- Complete README with usage examples
- API documentation
- Integration guide for eid-pd-reader

### Notes

This is the first stable release suitable for production use with Estonian ID cards. The library has been tested extensively with:
- IDEMIA Cosmo 8.1/8.2 cards
- IDEMIA Cosmo X cards
- Thales (Gemalto) cards
- Various NFC card readers

The library is currently used in production by the `eid-pd-reader` project for reading personal data from Estonian ID cards via NFC.

[1.1.0]: https://github.com/aarepuusepp/libopenpace-go/releases/tag/v1.1.0
[1.0.0]: https://github.com/aarepuusepp/libopenpace-go/releases/tag/v1.0.0

