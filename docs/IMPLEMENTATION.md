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
3. Decrypts nonce using AES-CBC with zero IV (not ECB, as CBC chaining is required for multi-block nonces with AES-256)

**Implementation**: `pace/step2.go`

### Step 3A: Map Generator

Two mapping methods are supported:

#### Generic Mapping (GM)
- Terminal generates ephemeral mapping keypair
- GA Step 2 exchanges mapping public keys (Tag 0x81/0x82)
- Compute H = ECDH(mapping_priv, card_mapping_pub) — a point on the curve
- New generator: G' = s*G + H (EC addition of nonce*basepoint with ECDH result)

#### Integrated Mapping (IM)
- Uses nonce directly for mapping
- G' = nonce * G (EC) or G' = G^nonce mod P (DH)
- No additional data exchange required

**Implementation**: `pace/step3a.go`, `pace/protocol.go`

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

1. Terminal computes: T_terminal = MAC_8(K_mac, 7F49{06 <OID> 86 <cardPK>}) — TLV-encoded per BSI TR-03110
2. Card computes: T_card = MAC_8(K_mac, 7F49{06 <OID> 86 <terminalPK>})
3. Exchange and verify 8-byte truncated authentication tokens via GA Step 4

**Implementation**: `pace/step3cd.go`

## Secure Messaging

After PACE establishment, all communication is protected using Secure Messaging:

### Command Wrapping

1. Increment Send Sequence Counter (SSC) — stored as block-size bytes (16 for AES)
2. Compute IV = AES_ECB_Enc(K_enc, SSC)
3. Encrypt command data with AES-CBC-Raw using computed IV and ISO 9797-1 Method 2 padded data → DO87
4. Add expected response length (if present) → DO97
5. Compute MAC = CMAC(K_mac, ISO_pad(SSC || ISO_pad(header) || DO87 || DO97)) → DO8E
6. Build protected APDU with SM bits set in CLA, append Le'=0x00

### Response Unwrapping

1. Increment SSC
2. Parse data objects (DO87, DO99, DO8E)
3. Verify MAC = CMAC(K_mac, ISO_pad(SSC || DOs_except_DO8E))
4. Decrypt data with AES-CBC-Raw using computed IV (if present)
5. Remove ISO 9797-1 Method 2 padding
6. Return plaintext data and status word

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

- **AES**: CBC and ECB modes with PKCS#7 padding (standard) and raw modes (no padding) for SM/PACE
  - `AESEncryptCBCRaw` / `AESDecryptCBCRaw`: For SM data encryption and PACE nonce decryption
  - `AESEncryptECBBlock`: For SM IV computation (IV = AES_ECB_Enc(K_enc, SSC))
  - `AESDecryptECBRaw`: For raw ECB decryption without unpadding
- **3DES**: CBC and ECB modes with PKCS#7 padding
- **CMAC**: Cipher-based MAC following NIST SP 800-38B
- **Padding**: PKCS#7 and ISO 9797-1 Method 2

**Implementation**: `crypto/aes.go`, `crypto/des.go`, `crypto/cmac.go`, `crypto/padding.go`

### Asymmetric Cryptography

- **ECDH**: Using Go's crypto/ecdh package (P-256, P-384, P-521) and elliptic.Curve interface for Brainpool curves
- **DH**: Custom implementation with big.Int (MODP groups)
- **Brainpool curves**: brainpoolP256r1, brainpoolP320r1, brainpoolP384r1, brainpoolP512r1 via `go.gnd.pw/crypto/brainpool`

**Implementation**: `crypto/ecdh.go`, `crypto/dh.go`

## Protocol OIDs

PACE protocol variants are identified by OIDs:

```
0.4.0.127.0.7.2.2.4.X.Y

Where:
X = 1: DH + Generic Mapping
X = 2: ECDH + Generic Mapping
X = 3: DH + Integrated Mapping
X = 4: ECDH + Integrated Mapping

Y = 1: 3DES
Y = 2: AES-128
Y = 3: AES-192
Y = 4: AES-256
```

**Implementation**: `pace/types.go`

## Domain Parameters

Standardized parameter IDs per BSI TR-03110 Part 3, Table D.1:

- **8**: secp192r1
- **9**: brainpoolP192r1
- **10**: secp224r1
- **11**: brainpoolP224r1
- **12**: secp256r1 (NIST P-256)
- **13**: brainpoolP256r1
- **14**: brainpoolP320r1
- **15**: secp384r1 (NIST P-384)
- **16**: brainpoolP384r1
- **17**: brainpoolP512r1
- **18**: secp521r1 (NIST P-521)

**Implementation**: `pace/api.go` (setupDomainParameters)

## Limitations and Future Work

### Current Limitations

1. **Integrated Mapping (ECDH)**: Uses simplified approach instead of proper scalar multiplication
2. **EF.CardAccess Parsing**: Simplified implementation, extracts single PACEInfo
3. **Card Communication**: Requires external PC/SC implementation
4. **Key Zeroization**: Relies on Go GC (no explicit memory wiping)

### Resolved Limitations (v1.1.0)

- ✅ Generic Mapping (GM-ECDH) fully implemented with card interaction
- ✅ Brainpool curve support added
- ✅ SM wrapping/unwrapping production-grade
- ✅ PACE nonce decryption uses correct AES-CBC mode

### Future Enhancements

1. Implement proper EC point arithmetic for IM
2. Add comprehensive BSI TR-03110 test vectors
3. Implement CAM (Chip Authentication Mapping)
4. Optimize performance (reduce allocations, use sync.Pool)
5. Add hardware security module (HSM) support
6. Implement full EF.CardAccess parsing (multiple SecurityInfos)

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

