# brainpoolP256r1 Implementation Required

## Current Status

The Thales test card requires **brainpoolP256r1** (ParamID=16) with **AES-256**, but our implementation currently uses **P-256** with **AES-128**.

### Test Results

All password references tested return **SW=6985**:
- `83 01 01` (MRZ) → SW=6985
- `83 01 02` (CAN) → SW=6985  
- `83 01 03` (CAN alternate) → SW=6985

This confirms the issue is **NOT** the password reference - it's the **cryptographic suite**.

### Why P-256 Substitute Doesn't Work

The card can detect that we're using P-256 instead of brainpoolP256r1 because:
1. Different curve equations
2. Different point coordinates
3. Different order and cofactor
4. PACE protocol exchanges public keys that reveal the curve being used

## What's Needed

### 1. Full brainpoolP256r1 Implementation

Go's `crypto/ecdh` package doesn't include brainpool curves. We need to implement:

#### Option A: Use Third-Party Library
```go
// Example using github.com/ebfe/brainpool
import "github.com/ebfe/brainpool"

curve := brainpool.P256r1()
```

**Pros**: Battle-tested, maintained
**Cons**: External dependency

#### Option B: Implement Ourselves
```go
// Implement elliptic.Curve interface for brainpoolP256r1
type brainpoolP256r1Curve struct {
    *elliptic.CurveParams
}

func (curve *brainpoolP256r1Curve) Params() *elliptic.CurveParams {
    return curve.CurveParams
}
```

**Pros**: No external dependencies
**Cons**: More work, needs thorough testing

### 2. AES-256 Support

Current implementation uses AES-128. Need to add AES-256:

```go
// In KDF functions
switch cipherSuite {
case AES128:
    keyLen = 16
case AES256:
    keyLen = 32
}

// In SM (Secure Messaging)
// AES-256 uses 32-byte keys but same CMAC truncation (8 bytes)
```

### 3. Dynamic Cipher Suite Selection

Parse OID to determine cipher suite:
```
OID: 0.4.0.127.0.7.2.2.4.2.X
                          ^
                          2 = AES-128
                          4 = AES-256
```

## RFC 5639 brainpoolP256r1 Parameters

```
p = A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
a = 7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
b = 26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6
x = 8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262
y = 547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997
n = A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
h = 1
```

## Implementation Plan

### Phase 1: Add brainpool Support
1. Choose implementation approach (library vs custom)
2. Implement brainpoolP256r1 curve
3. Add to `setupDomainParameters()` for ParamID=16
4. Test basic ECDH operations

### Phase 2: Add AES-256 Support
1. Update KDF functions for 32-byte keys
2. Update SM encryption for AES-256
3. Keep CMAC truncation at 8 bytes
4. Parse OID to detect AES-256 vs AES-128

### Phase 3: Integration
1. Update `PerformPACE()` to use correct suite
2. Test with Thales card
3. Verify MSE:Set AT returns SW=9000
4. Complete PACE protocol with real card

### Phase 4: Testing
1. Verify all PACE steps work
2. Test SM-protected commands
3. Read personal data successfully
4. Document results

## Estimated Effort

- **brainpool implementation**: 4-8 hours
- **AES-256 support**: 2-4 hours
- **Integration & testing**: 2-4 hours
- **Total**: 8-16 hours

## Alternative: Test with Real Estonian ID Card

If a real Estonian ID card uses AES-128 + P-256, the current implementation should work immediately without any changes!

Recommended: **Test with real card first** before implementing brainpool.

## References

- RFC 5639: Elliptic Curve Cryptography (ECC) Brainpool Standard Curves
- BSI TR-03110 v2.21: Advanced Security Mechanisms
- ISO/IEC 15946-5: Cryptographic techniques based on elliptic curves

## Current Workaround

For now, the implementation:
- ✅ Accepts ParamID=16
- ✅ Tries all password references
- ✅ Builds correct MSE:Set AT command
- ❌ Uses P-256 instead of brainpoolP256r1
- ❌ Uses AES-128 instead of AES-256

Result: **SW=6985** (correct format, wrong crypto parameters)

Once brainpool + AES-256 are added: **SW=9000** expected!

