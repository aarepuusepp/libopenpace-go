# libopenpace-go

Pure Go implementation of the PACE (Password Authenticated Connection Establishment) protocol for Estonian ID card NFC reading.

## Overview

`libopenpace-go` is a native Go implementation of the OpenPACE protocol, providing PACE and Secure Messaging functionality without CGO dependencies. This library enables secure communication with smart cards via NFC readers, specifically targeting Estonian ID cards.

## Features

- **Pure Go**: No CGO dependencies, fully cross-platform
- **PACE Protocol**: Complete implementation of BSI TR-03110 PACE protocol
- **Secure Messaging**: APDU wrapping/unwrapping with encryption and MAC
- **Multiple Cipher Suites**: Support for AES-128/192/256 and 3DES
- **Domain Parameters**: Standardized curves (P-256, P-384, P-521, brainpool) and DH groups
- **Well-Tested**: Comprehensive test coverage with BSI TR-03110 test vectors

## Requirements

- Go 1.25.4 or later
- PC/SC compatible smart card reader (for hardware testing)

## Installation

```bash
go get github.com/aarepuusepp/libopenpace-go
```

## Usage

```go
import (
    "github.com/aarepuusepp/libopenpace-go/pace"
)

// Establish PACE session
session, err := pace.EstablishPACE(card, can, cardAccess)
if err != nil {
    log.Fatal(err)
}

// Wrap APDU for secure messaging
wrappedAPDU, err := session.WrapAPDU(plainAPDU)
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

🚧 **Under Active Development** 🚧

This library is currently being implemented. See the project plan for details.

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

