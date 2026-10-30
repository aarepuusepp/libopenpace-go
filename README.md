# libopenpace-go

**Version 1.1.2**

Pure Go implementation of the PACE (Password Authenticated Connection Establishment) protocol for Estonian ID card NFC reading.

Based on the OpenPACE C library specification that is available at https://github.com/frankmorgner/openpace.

## Overview

`libopenpace-go` is a native Go implementation of the OpenPACE protocol, providing PACE and Secure Messaging functionality without CGO dependencies. This library enables secure communication with smart cards via NFC readers, specifically targeting Estonian ID cards.

## Features

- **Pure Go**: No CGO dependencies, fully cross-platform
- **PACE Protocol**: Generic Mapping with AES; IM, CAM and 3DES are not enabled
- **Secure Messaging**: APDU wrapping/unwrapping with encryption and MAC
- **Multiple Cipher Suites**: Support for AES-128/192/256 only
- **Domain Parameters**: Standardized curves (P-256, P-384, P-521, brainpool) and DH groups
- **Well-Tested**: Unit tests and independent KDF reference vectors (see kdf/testdata)

## Requirements

- Go 1.27.3 or later
- PC/SC compatible smart card reader (for hardware testing)

## Installation

```bash
# Latest version
go get github.com/aarepuusepp/libopenpace-go@v1.1.2

# Or use in go.mod
require github.com/aarepuusepp/libopenpace-go v1.1.2
```

## Usage

```go
import (
    "github.com/aarepuusepp/libopenpace-go/pace"
)

// Establish PACE session
secret := &pace.PACESecret{Type: pace.SecretTypeCAN, Value: []byte(can)}
session, err := pace.PerformPACE(card, secret, pace.OID_PACE_ECDH_GM_AES256, 12)
if err != nil {
    log.Fatal(err)
}

// Wrap APDU for secure messaging
wrappedAPDU, err := session.WrapCommand(0x00, 0xB0, 0x00, 0x00, nil, 256)
if err != nil {
    log.Fatal(err)
}

// Send wrapped APDU and unwrap response
response, err := card.Transmit(wrappedAPDU)
if err != nil {
    log.Fatal(err)
}

data, sw, err := session.UnwrapResponse(response)
```

## Project Structure

- `pace/` - PACE protocol implementation
- `sm/` - Secure Messaging (APDU wrap/unwrap)
- `kdf/` - Key Derivation Functions (BSI TR-03110)
- `crypto/` - Cryptographic helpers (AES, CMAC, ECDH/DH)
- `asn1/` - ASN.1 parsing for EF.CardAccess
- `apdu/` - APDU utilities
- `examples/` - Usage examples
- `docs/` - Additional documentation

## Standards Compliance

This implementation follows:
- **BSI TR-03110 v2.21**: Advanced Security Mechanisms for Machine Readable Travel Documents and eIDAS Token
- **ISO/IEC 7816**: Smart card standards

## Development Status

The real card exchange uses Generic Mapping and AES secure messaging.
Version 1.1.2 corrects the AES-128 KDF and optional nonce ordering.
IM, 3DES and unknown protocol OIDs fail with pace.ErrUnsupportedProtocol before
authentication. CardAccess-selected protocols and individual exported PACE steps
are checked too. EstablishPACE is an alias for the real PerformPACE exchange.

SM NewContext and crypto.CMAC are AES-only: a 24-byte key means AES-192.
Raw TripleDES helpers remain available as standalone primitives; they do not
provide PACE 3DES or Retail MAC support. DH helpers exist, but the full card
exchange currently generates EC mapping keys; do not assume DH interoperability.
CA/TA/CVC and IM/CAM are not implemented.

Validation for this patch includes fixed OpenPACE worked-example values and
independently calculated AES-128/192/256 KDF vectors, protocol rejection tests
and reader integration tests. It does not certify every protocol variant or
replace a real NFC/card interoperability test. Previous contact-card reading
and PKCS#11 decryption tests do not exercise NFC PACE.

## Version History

See [CHANGELOG.md](CHANGELOG.md) for detailed version history and release notes.

Current stable version: **1.1.2**

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Related Projects

- [web-eid-pd](https://github.com/aarepuusepp/web-eid-pd) - Estonian ID card personal data reader (uses this library)

## Acknowledgments

- Based on the [OpenPACE](https://github.com/frankmorgner/openpace) C library specification
- Implements BSI TR-03110 standards

## Contact

Aare Puusepp - aare.puusepp@gmail.com

