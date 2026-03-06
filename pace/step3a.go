package pace

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// PACE_STEP3A_map_generator implements PACE Step 3A: Map Generator.
//
// Two mapping methods are supported:
//   - Generic Mapping (GM): G' = s*G + H, where H = ECDH(mappingPriv, cardMappingPub)
//   - Integrated Mapping (IM): G' = f(nonce, G) — hash-to-curve variant
//
// Parameters:
//   - ctx: PACE context (must have nonce, domain params, and MappingPrivateKey for GM)
//   - cardMappingPub: Card's mapping public key bytes (for GM) or nil (for IM)
//
// Reference: BSI TR-03110 v2.21 Section 4.4.1
func PACE_STEP3A_map_generator(ctx *PACEContext, cardMappingPub []byte) error {
	mappingType := ctx.Protocol.GetMappingType()
	keyAgreementType := ctx.Protocol.GetKeyAgreementType()

	switch mappingType {
	case MappingGeneric:
		return mapGeneratorGM(ctx, cardMappingPub, keyAgreementType)
	case MappingIntegrated:
		return mapGeneratorIM(ctx, keyAgreementType)
	case MappingCAM:
		return fmt.Errorf("CAM (Chip Authentication Mapping) not yet implemented")
	default:
		return fmt.Errorf("unsupported mapping type: %v", mappingType)
	}
}

// mapGeneratorGM implements Generic Mapping (GM).
//
// Per BSI TR-03110 Section 4.4.1:
//  1. Both sides exchange ephemeral mapping public keys (done in GA Step 2)
//  2. Compute shared point H = ECDH(terminal_mapping_priv, card_mapping_pub)
//  3. Compute new generator G' = s*G + H (point addition on the curve)
//
// For DH: G' = G^s * H mod p (modular multiplication)
func mapGeneratorGM(ctx *PACEContext, cardMappingPub []byte, keyAgreementType KeyAgreementType) error {
	if len(cardMappingPub) == 0 {
		return fmt.Errorf("card mapping public key required for Generic Mapping")
	}
	if len(ctx.Nonce) == 0 {
		return fmt.Errorf("nonce required for mapping")
	}
	if len(ctx.MappingPrivateKey) == 0 {
		return fmt.Errorf("mapping private key required for Generic Mapping")
	}

	switch keyAgreementType {
	case KeyAgreementECDH:
		return mapGeneratorGM_ECDH(ctx, cardMappingPub)
	case KeyAgreementDH:
		return mapGeneratorGM_DH(ctx, cardMappingPub)
	default:
		return fmt.Errorf("unsupported key agreement type: %v", keyAgreementType)
	}
}

// mapGeneratorGM_ECDH implements Generic Mapping for ECDH (brainpool and NIST curves).
//
// Algorithm:
//  1. Parse card's mapping public key as EC point
//  2. H = mappingPriv * cardMappingPub (scalar multiplication)
//  3. sG = nonce * G (scalar-basemult with the nonce)
//  4. G' = sG + H (point addition)
//
// The mapped generator G' is stored as *ECPoint in ctx.MappedGenerator.
func mapGeneratorGM_ECDH(ctx *PACEContext, cardMappingPubBytes []byte) error {
	curve := ctx.DomainParams.EllipticCurve
	if curve == nil {
		return fmt.Errorf("elliptic.Curve required for Generic Mapping ECDH")
	}

	// Parse card's mapping public key (uncompressed: 04 || X || Y)
	cardX, cardY := elliptic.Unmarshal(curve, cardMappingPubBytes)
	if cardX == nil {
		return fmt.Errorf("failed to unmarshal card mapping public key (%d bytes)", len(cardMappingPubBytes))
	}

	// H = mappingPriv * cardMappingPub (ECDH shared point, using BOTH coordinates)
	hx, hy := curve.ScalarMult(cardX, cardY, ctx.MappingPrivateKey)

	// sG = nonce * G (scalar multiplication with the standard base point)
	sgx, sgy := curve.ScalarBaseMult(ctx.Nonce)

	// G' = sG + H (point addition on the curve)
	gPrimeX, gPrimeY := curve.Add(sgx, sgy, hx, hy)

	logVerbose("[PACE] Mapped generator G' computed (GM-ECDH)\n")

	ctx.MappedGenerator = &ECPoint{X: gPrimeX, Y: gPrimeY}
	return nil
}

// mapGeneratorGM_DH implements Generic Mapping for DH.
//
// G' = G^s * H mod p, where H = cardMappingPub^mappingPriv mod p
func mapGeneratorGM_DH(ctx *PACEContext, cardMappingPubBytes []byte) error {
	if ctx.DomainParams == nil || ctx.DomainParams.Type != DomainTypeDH {
		return fmt.Errorf("DH domain parameters required")
	}

	cardPubVal := new(big.Int).SetBytes(cardMappingPubBytes)

	// H = cardPubVal^mappingPriv mod P
	mappingPriv := new(big.Int).SetBytes(ctx.MappingPrivateKey)
	H := new(big.Int).Exp(cardPubVal, mappingPriv, ctx.DomainParams.P)

	// sG = G^s mod P (nonce as exponent)
	s := new(big.Int).SetBytes(ctx.Nonce)
	sG := new(big.Int).Exp(ctx.DomainParams.G, s, ctx.DomainParams.P)

	// G' = sG * H mod P
	gPrime := new(big.Int).Mul(sG, H)
	gPrime.Mod(gPrime, ctx.DomainParams.P)

	ctx.MappedGenerator = gPrime
	return nil
}

// mapGeneratorIM implements Integrated Mapping (IM).
//
// For ECDH: The nonce is used to derive a new generator via deterministic
// point generation. Since Go's standard library doesn't expose hash-to-curve,
// we use a simplified approach: generate a deterministic keypair seeded
// from the nonce, and use its public key as the mapped generator.
//
// For DH: G' = G^nonce mod P
func mapGeneratorIM(ctx *PACEContext, keyAgreementType KeyAgreementType) error {
	if len(ctx.Nonce) == 0 {
		return fmt.Errorf("nonce required for Integrated Mapping")
	}

	switch keyAgreementType {
	case KeyAgreementECDH:
		return mapGeneratorIM_ECDH(ctx)
	case KeyAgreementDH:
		return mapGeneratorIM_DH(ctx)
	default:
		return fmt.Errorf("unsupported key agreement type: %v", keyAgreementType)
	}
}

// mapGeneratorIM_ECDH implements Integrated Mapping for ECDH.
//
// Per BSI TR-03110 Annex A.3.4, Integrated Mapping uses the ICART algorithm
// or Shallue-van de Woestijne for hash-to-curve. For practical purposes with
// Estonian ID cards (which use Generic Mapping), this is a simplified version.
func mapGeneratorIM_ECDH(ctx *PACEContext) error {
	curve := ctx.DomainParams.EllipticCurve
	if curve == nil {
		return fmt.Errorf("elliptic.Curve required for Integrated Mapping ECDH")
	}

	// G' = nonce * G (scalar multiplication)
	gPrimeX, gPrimeY := curve.ScalarBaseMult(ctx.Nonce)

	ctx.MappedGenerator = &ECPoint{X: gPrimeX, Y: gPrimeY}
	return nil
}

// mapGeneratorIM_DH implements Integrated Mapping for DH.
func mapGeneratorIM_DH(ctx *PACEContext) error {
	if ctx.DomainParams == nil || ctx.DomainParams.Type != DomainTypeDH {
		return fmt.Errorf("DH domain parameters required")
	}

	nonce := new(big.Int).SetBytes(ctx.Nonce)
	mappedG := new(big.Int).Exp(ctx.DomainParams.G, nonce, ctx.DomainParams.P)

	ctx.MappedGenerator = mappedG
	return nil
}
