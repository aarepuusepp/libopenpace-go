# libopenpace-go Implementation Notes

## Overview

`libopenpace-go` is a pure Go implementation of the PACE (Password Authenticated Connection Establishment) protocol as specified in BSI TR-03110 v2.21. This document provides detailed implementation notes for developers.

## Architecture

### Package Structure

```
libopenpace-go/
├── pace/          # PACE protocol implementation
│   ├── types.go   # Core data structures
│   ├── step1.go   # Nonce encryption
│   ├── step2.go   # Nonce decryption
│   ├── step3a.go  # Generator mapping
│   ├── step3b.go  # Key agreement
│   ├── step3cd.go # Key derivation and authentication
│   └── api.go     # High-level API
├── sm/            # Secure Messaging
│   └── sm.go      # APDU wrap/unwrap
├── kdf/           # Key Derivation Functions
│   └── kdf.go     # KDF_PI, KDF_Enc, KDF_MAC
├── crypto/        # Cryptographic primitives
│   ├── aes.go     # AES encryption
│   ├── des.go     # 3DES encryption
│   ├── cmac.go    # CMAC computation
│   ├── padding.go # Padding schemes
│   ├── ecdh.go    # ECDH operations
│   └── dh.go      # DH operations
├── asn1/          # ASN.1 parsing
│   └── cardaccess.go # EF.CardAccess parsing
└── examples/      # Usage examples
    └── basic_usage.go
```

## PACE Protocol Flow

### Step 1: Encrypt Nonce (Terminal)

1. Terminal generates random nonce (16 bytes for AES, 8 bytes for 3DES)
2. Derives encryption key from shared secret using KDF_PI
3. Encrypts nonce using AES-ECB or 3DES-ECB
4. Sends encrypted nonce to card

**Implementation**: `pace/step1.go`

### Step 2: Decrypt Nonce (Card)

1. Card receives encrypted nonce
2. Derives decryption key from shared secret using KDF_PI
3. Decrypts nonce
4. Re-encrypts with card's key and sends back

**Implementation**: `pace/step2.go`

### Step 3A: Map Generator

Two mapping methods are supported:

#### Generic Mapping (GM)
- Terminal and card exchange mapping data
- Compute H = s * PCD_Map_PK
- New generator: G' = G + H (EC) or G' = G * H mod P (DH)

#### Integrated Mapping (IM)
- Uses nonce directly for mapping
- G' = nonce * G (EC) or G' = G^nonce mod P (DH)
- No additional data exchange required

**Implementation**: `pace/step3a.go`

**Note**: Current implementation uses a simplified approach for ECDH IM due to Go's crypto/ecdh package limitations. A production implementation would need proper EC point arithmetic.

### Step 3B: Key Agreement

1. Both parties generate ephemeral keypairs using mapped generator G'
2. Exchange ephemeral public keys
3. Compute shared secret using ECDH or DH

**Implementation**: `pace/step3b.go`

### Step 3C: Derive Session Keys

1. K_enc = KDF_Enc(shared_secret, nonce)
2. K_mac = KDF_MAC(shared_secret, nonce)

**Implementation**: `pace/step3cd.go`

### Step 3D: Mutual Authentication

1. Terminal computes: T_terminal = MAC(K_mac, PK_terminal || PK_card)
2. Card computes: T_card = MAC(K_mac, PK_card || PK_terminal)
3. Exchange and verify authentication tokens

**Implementation**: `pace/step3cd.go`

## Secure Messaging

After PACE establishment, all communication is protected using Secure Messaging:

### Command Wrapping

1. Increment Send Sequence Counter (SSC)
2. Encrypt command data (if present) → DO87
3. Add expected response length (if present) → DO97
4. Compute MAC over SSC || header || data objects → DO8E
5. Build protected APDU with SM bits set in CLA

### Response Unwrapping

1. Increment SSC
2. Parse data objects (DO87, DO99, DO8E)
3. Verify MAC
4. Decrypt data (if present)
5. Return plaintext data and status word

**Implementation**: `sm/sm.go`

## Cryptographic Primitives

### Key Derivation Functions

All KDFs follow BSI TR-03110 specification:

```
KDF(K, c, nonce) = H(K || c || nonce) || H(K || c+1 || nonce) || ...
```

Where:
- K: Input key material
- c: Counter (starts at 3 for KDF_PI, 1 for KDF_Enc, 2 for KDF_MAC)
- H: Hash function (SHA-256 or SHA-512)

**Implementation**: `kdf/kdf.go`

### Symmetric Encryption

- **AES**: CBC and ECB modes with PKCS#7 padding
- **3DES**: CBC and ECB modes with PKCS#7 padding
- **CMAC**: Cipher-based MAC following NIST SP 800-38B

**Implementation**: `crypto/aes.go`, `crypto/des.go`, `crypto/cmac.go`

### Asymmetric Cryptography

- **ECDH**: Using Go's crypto/ecdh package (P-256, P-384, P-521)
- **DH**: Custom implementation with big.Int (MODP groups)

**Implementation**: `crypto/ecdh.go`, `crypto/dh.go`

## Protocol OIDs

PACE protocol variants are identified by OIDs:

```
0.4.0.127.0.7.2.2.4.X.Y

Where:
X = 1: ECDH + Generic Mapping
X = 2: ECDH + Integrated Mapping
X = 3: DH + Generic Mapping
X = 4: DH + Integrated Mapping

Y = 1: 3DES
Y = 2: AES-128
Y = 3: AES-192
Y = 4: AES-256
```

**Implementation**: `pace/types.go`

## Domain Parameters

Standardized parameter IDs:

- **8**: NIST P-256 (secp256r1)
- **9**: BrainpoolP256r1
- **10**: NIST P-384 (secp384r1)
- **11**: BrainpoolP384r1
- **12**: NIST P-521 (secp521r1)
- **13**: BrainpoolP512r1

**Implementation**: `pace/api.go` (setupDomainParameters)

## Limitations and Future Work

### Current Limitations

1. **Integrated Mapping (ECDH)**: Uses simplified approach instead of proper scalar multiplication
2. **Generic Mapping**: Not fully implemented (requires card interaction)
3. **EF.CardAccess Parsing**: Simplified implementation, doesn't parse all SecurityInfo types
4. **Test Vectors**: Limited BSI TR-03110 test vectors
5. **Card Communication**: Requires external PC/SC implementation

### Future Enhancements

1. Implement proper EC point arithmetic for IM
2. Complete Generic Mapping implementation
3. Add comprehensive BSI TR-03110 test vectors
4. Implement CAM (Chip Authentication Mapping)
5. Add support for more domain parameters (Brainpool curves)
6. Optimize performance (reduce allocations, use sync.Pool)
7. Add hardware security module (HSM) support
8. Implement full EF.CardAccess parsing

## Testing

### Unit Tests

Each package includes comprehensive unit tests:

```bash
go test ./...
```

### Test Coverage

```bash
go test -cover ./...
```

### Benchmarks

```bash
go test -bench=. ./...
```

## Performance Considerations

1. **Memory Allocations**: Most operations allocate new byte slices
2. **Cryptographic Operations**: CMAC and encryption are the bottlenecks
3. **Big Integer Operations**: DH operations are slower than ECDH
4. **SSC Increment**: Very fast, no allocations

## Security Considerations

1. **Constant-Time Operations**: Authentication token verification uses constant-time comparison
2. **Random Number Generation**: Uses crypto/rand for all random values
3. **Key Zeroization**: Keys are not explicitly zeroized (Go GC handles this)
4. **Side-Channel Attacks**: No specific mitigations implemented
5. **Timing Attacks**: MAC verification is constant-time

## References

- **BSI TR-03110 v2.21**: Advanced Security Mechanisms for Machine Readable Travel Documents and eIDAS Token
- **NIST SP 800-38A**: Block Cipher Modes of Operation
- **NIST SP 800-38B**: CMAC: The CMAC Mode for Authentication
- **RFC 3526**: More Modular Exponential (MODP) Diffie-Hellman groups
- **ISO/IEC 7816-4**: Identification cards - Integrated circuit cards - Part 4: Organization, security and commands for interchange

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please ensure:
1. All tests pass
2. Code follows Go conventions
3. Documentation is updated
4. Commit messages are descriptive

## Contact

Aare Puusepp - aare.puusepp@gmail.com

GitHub: https://github.com/aarepuusepp/libopenpace-go

