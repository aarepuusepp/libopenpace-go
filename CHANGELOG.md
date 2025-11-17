# Changelog

All notable changes to libopenpace-go will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/aarepuusepp/libopenpace-go/releases/tag/v1.0.0

