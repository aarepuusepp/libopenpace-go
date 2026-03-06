package pace

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"

	"github.com/aarepuusepp/libopenpace-go/sm"
)

// PerformPACE executes the full PACE protocol with a smart card.
//
// This function implements the complete PACE protocol as specified in BSI TR-03110:
//  1. MSE:Set AT (set authentication template with OID and parameter ID)
//  2. General Authenticate - Encrypted Nonce
//  3. General Authenticate - Mapping Data
//  4. General Authenticate - Ephemeral Public Key
//  5. General Authenticate - Authentication Token
//
// Parameters:
//   - card: Smart card interface for APDU communication
//   - secret: Shared secret (CAN, PIN, etc.)
//   - protocol: PACE protocol OID
//   - parameterID: Standardized domain parameter ID (8 for P-256, etc.)
//
// Returns a Secure Messaging context ready for protected communication.
//
// Reference: BSI TR-03110 v2.21 Section 4.4
func PerformPACE(card CardInterface, secret *PACESecret, protocol ProtocolOID, parameterID int) (*sm.Context, error) {
	// Initialize PACE context
	ctx := &PACEContext{
		Protocol:    protocol,
		ParameterID: parameterID,
	}
	
	// Set up domain parameters
	err := setupDomainParameters(ctx, parameterID)
	if err != nil {
		return nil, fmt.Errorf("failed to setup domain parameters: %w", err)
	}
	
	// Step 0a: Select MF first, then try to read EF.CardAccess
	logVerbose("[PACE] Selecting MF...\n")
	selectMF := []byte{0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00}
	resp, err2 := card.Transmit(selectMF)
	if err2 == nil && len(resp) >= 2 {
		sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
		if sw == 0x9000 {
			logVerbose("[PACE] MF selected\n")
		}
	}
	
	// Now try to read EF.CardAccess from MF
	logVerbose("[PACE] Reading EF.CardAccess from MF...\n")
	selectCmd := []byte{0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1C}
	resp, err2 = card.Transmit(selectCmd)
	var mfCardAccess []byte
	if err2 == nil && len(resp) >= 2 {
		sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
		if sw == 0x9000 {
			readCmd := []byte{0x00, 0xB0, 0x00, 0x00, 0x00}
			resp, err2 = card.Transmit(readCmd)
			if err2 == nil && len(resp) > 2 {
				mfCardAccess = resp[:len(resp)-2]
				logVerbose("[PACE] EF.CardAccess from MF: %d bytes: %X\n", len(mfCardAccess), mfCardAccess)
			}
		}
	}
	
	// Step 0b: Probe contexts and try MSE:Set AT for PACE.
	// Order matters: try MF first (PACE is typically in MF context),
	// then specific AIDs. Re-select MF before each attempt to reset card state.
	aids := []struct {
		name string
		aid  []byte
	}{
		{"MF (no AID)", nil},
		{"EstEID (contactless)", []byte{0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00}},
		{"eMRTD", []byte{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01}},
	}

	var paceSuccess bool
	for _, aidInfo := range aids {
		logVerbose("[PACE] Trying context: %s\n", aidInfo.name)

		// Always re-select MF to reset card state before each attempt
		selectMFCmd := []byte{0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00}
		card.Transmit(selectMFCmd)

		if aidInfo.aid != nil {
			err = selectApplication(card, aidInfo.aid)
			if err != nil {
				logVerbose("[PACE] SELECT AID failed: %v, trying next...\n", err)
				continue
			}
			logVerbose("[PACE] AID selected: %s\n", aidInfo.name)

			// Try to read EF.CardAccess from this application context
			selectEFCmd := []byte{0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1C}
			resp, err2 := card.Transmit(selectEFCmd)
			if err2 == nil && len(resp) >= 2 {
				sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
				if sw == 0x9000 {
					readCmd := []byte{0x00, 0xB0, 0x00, 0x00, 0x00}
					resp, err2 = card.Transmit(readCmd)
					if err2 == nil && len(resp) > 2 {
						aidCardAccess := resp[:len(resp)-2]
						logVerbose("[PACE] EF.CardAccess from AID: %d bytes: %X\n", len(aidCardAccess), aidCardAccess)
						mfCardAccess = aidCardAccess
					}
				}
			}
		}

		cardAccessData := mfCardAccess
		if len(cardAccessData) == 0 {
			logVerbose("[PACE] No CardAccess available, trying next...\n")
			continue
		}

		paceInfos := parseCardAccessPACEInfos(cardAccessData)
		if len(paceInfos) == 0 {
			logVerbose("[PACE] No PACEInfo found in CardAccess, trying next...\n")
			continue
		}

		for i, paceInfo := range paceInfos {
			logVerbose("[PACE] Trying PACEInfo %d: OID=%X, ParamID=%d\n", i+1, paceInfo.oidDER, paceInfo.paramID)

			ctx.CardAccessOID = paceInfo.oidDER
			ctx.ParameterID = int(paceInfo.paramID)

			err = setupDomainParameters(ctx, int(paceInfo.paramID))
			if err != nil {
				logVerbose("[PACE] Failed to setup domain params for ParamID=%d: %v\n", paceInfo.paramID, err)
				continue
			}

			// Password references to try: 0x02=CAN, 0x03=CAN(alt), 0xFF=omit Tag 83
			pwRefs := []byte{0x02, 0xFF, 0x03}

			for _, pwRef := range pwRefs {
				pwRefName := "CAN"
				if pwRef == 0xFF {
					pwRefName = "OMIT"
				}
				logVerbose("[PACE] MSE:Set AT PWRef=0x%02X (%s)\n", pwRef, pwRefName)

				err = mseSetATPACE(card, paceInfo.oidDER, pwRef, paceInfo.paramID)
				if err != nil {
					logVerbose("[PACE] MSE:Set AT failed: %v\n", err)
					continue
				}

				logVerbose("[PACE] MSE:Set AT succeeded!\n")
				paceSuccess = true
				break
			}

			if paceSuccess {
				break
			}
		}

		if paceSuccess {
			break
		}
	}

	if !paceSuccess {
		return nil, fmt.Errorf("all contexts and PACEInfos failed - card may require vendor-specific initialization")
	}

	// Resolve the actual protocol from CardAccess OID
	if len(ctx.CardAccessOID) > 0 {
		oidStr := oidBytesToString(ctx.CardAccessOID)
		resolved := ProtocolOID(oidStr)
		logVerbose("[PACE] Resolved OID from CardAccess: %s\n", oidStr)
		ctx.Protocol = resolved
		protocol = resolved
	}

	// Step 1: Request encrypted nonce from card (GA Step 1, CLA=0x10)
	cardEncryptedNonce, err := generalAuthenticateStep1(card)
	if err != nil {
		return nil, fmt.Errorf("General Authenticate Step 1 failed: %w", err)
	}
	logVerbose("[PACE] GA Step 1 - Received encrypted nonce: %d bytes: %X\n", len(cardEncryptedNonce), cardEncryptedNonce)

	// Step 2: Decrypt card's encrypted nonce
	err = PACE_STEP2_dec_nonce(ctx, secret, cardEncryptedNonce)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 2 failed: %w", err)
	}

	// Step 3A: Map generator
	mappingType := protocol.GetMappingType()
	logVerbose("[PACE] Mapping type: %v (protocol=%s)\n", mappingType, protocol)

	if mappingType == MappingGeneric {
		// Generate mapping keypair for Generic Mapping
		mappingPubBytes, err := generateMappingKeypair(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to generate mapping keypair: %w", err)
		}
		logVerbose("[PACE] Generated mapping public key: %d bytes\n", len(mappingPubBytes))

		// Exchange mapping data with card (GA Step 2, CLA=0x10)
		cardMappingPub, err := generalAuthenticateStep2(card, mappingPubBytes)
		if err != nil {
			return nil, fmt.Errorf("General Authenticate Step 2 (mapping) failed: %w", err)
		}
		logVerbose("[PACE] Card mapping public key: %d bytes\n", len(cardMappingPub))

		// Compute mapped generator G' = s*G + H
		err = PACE_STEP3A_map_generator(ctx, cardMappingPub)
		if err != nil {
			return nil, fmt.Errorf("PACE Step 3A (map generator) failed: %w", err)
		}
	} else {
		// Integrated Mapping — no data exchange, map from nonce only
		err = PACE_STEP3A_map_generator(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("PACE Step 3A (map generator) failed: %w", err)
		}
	}

	// Step 3B: Generate ephemeral keypair using mapped generator G'
	ourPublicKey, err := PACE_STEP3B_generate_ephemeral_key(ctx)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3B (generate key) failed: %w", err)
	}
	logVerbose("[PACE] Our ephemeral public key: %d bytes\n", len(ourPublicKey))

	// Exchange ephemeral public keys (GA Step 3, CLA=0x10)
	cardPublicKey, err := generalAuthenticateStep3(card, ourPublicKey)
	if err != nil {
		return nil, fmt.Errorf("General Authenticate Step 3 (key exchange) failed: %w", err)
	}
	logVerbose("[PACE] Card ephemeral public key: %d bytes\n", len(cardPublicKey))

	// Compute shared secret from card's ephemeral public key
	err = PACE_STEP3B_compute_shared_secret(ctx, cardPublicKey)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3B (compute secret) failed: %w", err)
	}

	// Step 3C: Derive session keys
	err = PACE_STEP3C_derive_keys(ctx)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3C failed: %w", err)
	}

	// Step 3D: Mutual authentication
	ourAuthToken, err := PACE_STEP3D_compute_auth_token(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3D (compute token) failed: %w", err)
	}
	logVerbose("[PACE] Our auth token: %X\n", ourAuthToken)

	// Exchange authentication tokens (GA Step 4, CLA=0x00 — final command)
	cardAuthToken, err := generalAuthenticateStep4(card, ourAuthToken)
	if err != nil {
		return nil, fmt.Errorf("General Authenticate Step 4 (auth) failed: %w", err)
	}
	logVerbose("[PACE] Card auth token: %X\n", cardAuthToken)

	// Verify card's authentication token
	err = PACE_STEP3D_verify_auth_token(ctx, cardAuthToken, true)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3D (verify token) failed: %w", err)
	}

	// Initialize SSC to zero (BSI TR-03110)
	initialSSC := make([]byte, 8)

	// Create Secure Messaging context
	smCtx, err := sm.NewContext(ctx.EncryptionKey, ctx.MACKey, initialSSC)
	if err != nil {
		return nil, fmt.Errorf("failed to create SM context: %w", err)
	}

	return smCtx, nil
}

// selectApplication selects an application by AID.
//
// Command: 00 A4 04 00 <AID> (plain SELECT, no P2=0C for PACE context)
func selectApplication(card CardInterface, aid []byte) error {
	// Use P2=00 for plain SELECT (not P2=0C which is for file selection)
	cmd := []byte{0x00, 0xA4, 0x04, 0x00, byte(len(aid))}
	cmd = append(cmd, aid...)
	
	resp, err := card.Transmit(cmd)
	if err != nil {
		return fmt.Errorf("SELECT AID transmission failed: %w", err)
	}
	
	if len(resp) < 2 {
		return fmt.Errorf("SELECT AID response too short")
	}
	
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	if sw != 0x9000 {
		return fmt.Errorf("SELECT AID failed: SW=%04X", sw)
	}
	
	// Log FCI (File Control Information) if present
	if len(resp) > 2 {
		fci := resp[:len(resp)-2]
		logVerbose("[PACE] FCI from SELECT AID: %d bytes: %X\n", len(fci), fci)
	}
	
	return nil
}

// paceInfo holds parsed PACE information from EF.CardAccess
type paceInfo struct {
	oidDER  []byte // DER-encoded OID (including 06 <len> prefix)
	pwType  byte   // Password type from CardAccess
	paramID byte   // Parameter ID
}

// parseCardAccessPACEInfos parses EF.CardAccess and extracts all PACEInfo structures
func parseCardAccessPACEInfos(cardAccess []byte) []paceInfo {
	var infos []paceInfo
	
	// Format: 31 <len> 30 <len> 06 <oidlen> <oid> 02 01 <pwtype> 02 01 <paramid>
	if len(cardAccess) < 22 || cardAccess[0] != 0x31 {
		return infos
	}
	
	// For now, parse single PACEInfo (most cards have one)
	// TODO: Support multiple PACEInfos in SET
	if cardAccess[2] != 0x30 || cardAccess[4] != 0x06 {
		return infos
	}
	
	oidLen := int(cardAccess[5])
	if len(cardAccess) < 6+oidLen+6 {
		return infos
	}
	
	actualOID := cardAccess[6 : 6+oidLen]
	pwTypePos := 6 + oidLen
	
	if cardAccess[pwTypePos] != 0x02 || cardAccess[pwTypePos+1] != 0x01 {
		return infos
	}
	
	pwType := cardAccess[pwTypePos+2]
	paramIDPos := pwTypePos + 3
	
	if cardAccess[paramIDPos] != 0x02 || cardAccess[paramIDPos+1] != 0x01 {
		return infos
	}
	
	paramID := cardAccess[paramIDPos+2]
	
	// For MSE:Set AT, some cards want just the OID bytes (no 06 <len> prefix)
	// Others want the full DER encoding. We'll store just the OID bytes
	// and let mseSetATPACE decide based on card behavior.
	oidDER := actualOID // Just the OID bytes, no DER wrapper
	
	infos = append(infos, paceInfo{
		oidDER:  oidDER,
		pwType:  pwType,
		paramID: paramID,
	})
	
	return infos
}

// mseSetATPACE sends MSE:Set AT command with explicit OID, PWRef, and ParamID
func mseSetATPACE(card CardInterface, oidDER []byte, pwRef byte, paramID byte) error {
	// Build MSE:Set AT data with three TLVs:
	// Tag 80: OID (algorithm) - DER encoded
	// Tag 83: Password Reference (optional - some AIDs derive from policy)
	// Tag 84: Parameter ID
	
	data := []byte{0x80, byte(len(oidDER))}
	data = append(data, oidDER...)
	
	// Include PWRef if not 0xFF (0xFF = omit tag 83)
	if pwRef != 0xFF {
		data = append(data, 0x83, 0x01, pwRef)
	}
	
	data = append(data, 0x84, 0x01, paramID)
	
	logVerbose("[PACE] MSE:Set AT data: %X\n", data)
	
	// MSE:Set AT command (plain, CLA=00)
	cmd := []byte{0x00, 0x22, 0xC1, 0xA4, byte(len(data))}
	cmd = append(cmd, data...)
	
	logVerbose("[PACE] MSE:Set AT command: %X\n", cmd)
	
	resp, err := card.Transmit(cmd)
	if err != nil {
		return fmt.Errorf("MSE:Set AT transmission failed: %w", err)
	}
	
	if len(resp) < 2 {
		return fmt.Errorf("MSE:Set AT response too short")
	}
	
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	if sw != 0x9000 {
		return fmt.Errorf("MSE:Set AT failed: SW=%04X", sw)
	}
	
	return nil
}

// mseSetAT sends MSE:Set AT command to set up PACE parameters.
//
// Command: 00 22 C1 A4 <data>
// Data: TLV with OID and parameter ID
func mseSetAT(card CardInterface, protocol ProtocolOID, parameterID int, ctx *PACEContext) error {
	// Build MSE:Set AT data
	// Tag 80: OID
	// Tag 84: Parameter ID (optional)
	
	var oidBytes []byte
	if len(ctx.CardAccessOID) > 0 {
		// Use OID from CardAccess (already DER encoded)
		oidBytes = ctx.CardAccessOID
		logVerbose("[PACE] MSE:Set AT - Using OID from CardAccess: %X\n", oidBytes)
	} else {
		// Fallback to protocol OID
		oidSlice := protocol.ToOIDSlice()
		var err error
		oidBytes, err = asn1.Marshal(asn1.ObjectIdentifier(oidSlice))
		if err != nil {
			return fmt.Errorf("failed to marshal OID: %w", err)
		}
		logVerbose("[PACE] MSE:Set AT - OID: %v, OID bytes: %X\n", oidSlice, oidBytes)
	}
	
	// Build MSE:Set AT data with three TLVs:
	// Tag 80: OID (algorithm)
	// Tag 83: Password Reference (0x03 for CAN, 0x02 as fallback)
	// Tag 84: Parameter ID
	
	data := []byte{0x80, byte(len(oidBytes))}
	data = append(data, oidBytes...)
	
	// Tag 83: Password Reference for CAN
	// Try 0x02 for CAN (some Thales/CosmoX cards use 0x02 instead of 0x03)
	data = append(data, 0x83, 0x01, 0x02)
	
	if parameterID > 0 {
		data = append(data, 0x84, 0x01, byte(parameterID))
	}
	
	logVerbose("[PACE] MSE:Set AT data (with PW ref 0x02): %X\n", data)
	
	// MSE:Set AT command
	cmd := []byte{0x00, 0x22, 0xC1, 0xA4, byte(len(data))}
	cmd = append(cmd, data...)
	
	logVerbose("[PACE] MSE:Set AT command: %X\n", cmd)
	
	resp, err := card.Transmit(cmd)
	if err != nil {
		return fmt.Errorf("MSE:Set AT transmission failed: %w", err)
	}
	
	if len(resp) < 2 {
		return fmt.Errorf("MSE:Set AT response too short")
	}
	
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	if sw != 0x9000 {
		return fmt.Errorf("MSE:Set AT failed: SW=%04X", sw)
	}
	
	return nil
}

// generalAuthenticateStep1 requests the encrypted nonce from the card.
//
// BSI TR-03110: CLA=0x10 (command chaining), INS=0x86, P1=00, P2=00
// Data: 7C 00 (empty Dynamic Authentication Data template)
// Le: 00
// Response: 7C { 80 <encrypted_nonce> }
func generalAuthenticateStep1(card CardInterface) ([]byte, error) {
	// CLA=0x10 for command chaining (GA Steps 1-3 are chained)
	cmd := []byte{0x10, 0x86, 0x00, 0x00, 0x02, 0x7C, 0x00, 0x00}
	logVerbose("[PACE] GA Step 1 - Command: %X\n", cmd)

	resp, err := card.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("transmission failed: %w", err)
	}

	if len(resp) < 2 {
		return nil, fmt.Errorf("response too short")
	}

	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	logVerbose("[PACE] GA Step 1 - SW=%04X\n", sw)
	if sw != 0x9000 {
		return nil, fmt.Errorf("SW=%04X", sw)
	}

	respData := resp[:len(resp)-2]
	logVerbose("[PACE] GA Step 1 - Response data: %X\n", respData)

	nonce, err := parseTLVResponse(respData, 0x80)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nonce: %w", err)
	}

	return nonce, nil
}

// generalAuthenticateStep2 exchanges mapping data (Generic Mapping).
//
// BSI TR-03110: CLA=0x10 (chaining), INS=0x86
// Send: 7C { 81 <terminal_mapping_pub_key> }
// Recv: 7C { 82 <card_mapping_pub_key> }
func generalAuthenticateStep2(card CardInterface, terminalMappingPub []byte) ([]byte, error) {
	innerData := buildTLV(0x81, terminalMappingPub)
	data := buildTLV(0x7C, innerData)

	cmd := []byte{0x10, 0x86, 0x00, 0x00}
	cmd = appendLc(cmd, data)
	cmd = append(cmd, data...)
	cmd = append(cmd, 0x00) // Le

	logVerbose("[PACE] GA Step 2 - Command: %X\n", cmd)

	resp, err := card.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("transmission failed: %w", err)
	}

	if len(resp) < 2 {
		return nil, fmt.Errorf("response too short")
	}

	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	logVerbose("[PACE] GA Step 2 - SW=%04X\n", sw)
	if sw != 0x9000 {
		return nil, fmt.Errorf("SW=%04X", sw)
	}

	respData := resp[:len(resp)-2]
	logVerbose("[PACE] GA Step 2 - Response data: %X\n", respData)

	cardMappingPub, err := parseTLVResponse(respData, 0x82)
	if err != nil {
		return nil, fmt.Errorf("failed to parse card mapping key: %w", err)
	}

	return cardMappingPub, nil
}

// generalAuthenticateStep3 exchanges ephemeral public keys.
//
// BSI TR-03110: CLA=0x10 (chaining), INS=0x86
// Send: 7C { 83 <terminal_ephemeral_pub> }
// Recv: 7C { 84 <card_ephemeral_pub> }
func generalAuthenticateStep3(card CardInterface, ourPublicKey []byte) ([]byte, error) {
	innerData := buildTLV(0x83, ourPublicKey)
	data := buildTLV(0x7C, innerData)

	cmd := []byte{0x10, 0x86, 0x00, 0x00}
	cmd = appendLc(cmd, data)
	cmd = append(cmd, data...)
	cmd = append(cmd, 0x00) // Le

	logVerbose("[PACE] GA Step 3 - Command: %X\n", cmd)

	resp, err := card.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("transmission failed: %w", err)
	}

	if len(resp) < 2 {
		return nil, fmt.Errorf("response too short")
	}

	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	logVerbose("[PACE] GA Step 3 - SW=%04X\n", sw)
	if sw != 0x9000 {
		return nil, fmt.Errorf("SW=%04X", sw)
	}

	respData := resp[:len(resp)-2]
	logVerbose("[PACE] GA Step 3 - Response data: %X\n", respData)

	cardPub, err := parseTLVResponse(respData, 0x84)
	if err != nil {
		return nil, fmt.Errorf("failed to parse card public key: %w", err)
	}

	return cardPub, nil
}

// generalAuthenticateStep4 exchanges authentication tokens.
//
// BSI TR-03110: CLA=0x00 (final command, no chaining), INS=0x86
// Send: 7C { 85 <terminal_auth_token> }
// Recv: 7C { 86 <card_auth_token> }
func generalAuthenticateStep4(card CardInterface, ourAuthToken []byte) ([]byte, error) {
	innerData := buildTLV(0x85, ourAuthToken)
	data := buildTLV(0x7C, innerData)

	// CLA=0x00 — this is the LAST GA command (no chaining)
	cmd := []byte{0x00, 0x86, 0x00, 0x00}
	cmd = appendLc(cmd, data)
	cmd = append(cmd, data...)
	cmd = append(cmd, 0x00) // Le

	logVerbose("[PACE] GA Step 4 - Command: %X\n", cmd)

	resp, err := card.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("transmission failed: %w", err)
	}

	if len(resp) < 2 {
		return nil, fmt.Errorf("response too short")
	}

	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	logVerbose("[PACE] GA Step 4 - SW=%04X\n", sw)
	if sw != 0x9000 {
		return nil, fmt.Errorf("SW=%04X", sw)
	}

	respData := resp[:len(resp)-2]
	logVerbose("[PACE] GA Step 4 - Response data: %X\n", respData)

	cardToken, err := parseTLVResponse(respData, 0x86)
	if err != nil {
		return nil, fmt.Errorf("failed to parse card auth token: %w", err)
	}

	return cardToken, nil
}

// --- TLV and OID helpers ---

// buildTLV constructs a TLV (Tag-Length-Value) byte sequence.
// Handles both short-form (length < 128) and long-form length encoding.
func buildTLV(tag byte, value []byte) []byte {
	result := []byte{tag}
	vLen := len(value)
	if vLen < 0x80 {
		result = append(result, byte(vLen))
	} else if vLen <= 0xFF {
		result = append(result, 0x81, byte(vLen))
	} else {
		result = append(result, 0x82, byte(vLen>>8), byte(vLen))
	}
	result = append(result, value...)
	return result
}

// appendLc appends the Lc byte for an APDU command.
func appendLc(cmd []byte, data []byte) []byte {
	return append(cmd, byte(len(data)))
}

// parseTLVResponse extracts a value from a 7C { expectedTag <value> } response.
func parseTLVResponse(data []byte, expectedTag byte) ([]byte, error) {
	if len(data) < 2 || data[0] != 0x7C {
		return nil, fmt.Errorf("expected 7C wrapper, got: %X", data)
	}

	// Parse 7C outer length
	innerStart, _, err := parseTLVLength(data, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to parse 7C length: %w", err)
	}

	inner := data[innerStart:]
	if len(inner) < 2 || inner[0] != expectedTag {
		return nil, fmt.Errorf("expected tag %02X, got: %X", expectedTag, inner)
	}

	// Parse inner tag length
	valueStart, valueLen, err := parseTLVLength(inner, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tag %02X length: %w", expectedTag, err)
	}

	if len(inner) < valueStart+valueLen {
		return nil, fmt.Errorf("tag %02X value truncated: need %d, have %d",
			expectedTag, valueLen, len(inner)-valueStart)
	}

	return inner[valueStart : valueStart+valueLen], nil
}

// parseTLVLength parses a BER-TLV length field starting at offset.
// Returns (start of value, length of value, error).
func parseTLVLength(data []byte, offset int) (int, int, error) {
	if offset >= len(data) {
		return 0, 0, fmt.Errorf("offset %d beyond data length %d", offset, len(data))
	}

	b := data[offset]
	if b < 0x80 {
		return offset + 1, int(b), nil
	}
	if b == 0x81 {
		if offset+1 >= len(data) {
			return 0, 0, fmt.Errorf("truncated long-form length")
		}
		return offset + 2, int(data[offset+1]), nil
	}
	if b == 0x82 {
		if offset+2 >= len(data) {
			return 0, 0, fmt.Errorf("truncated long-form length")
		}
		return offset + 3, int(data[offset+1])<<8 | int(data[offset+2]), nil
	}
	return 0, 0, fmt.Errorf("unsupported length encoding: %02X", b)
}

// oidBytesToString converts DER-encoded OID bytes to dotted-decimal string.
// Example: {04 00 7F 00 07 02 02 04 02 04} → "0.4.0.127.0.7.2.2.4.2.4"
func oidBytesToString(oidBytes []byte) string {
	if len(oidBytes) == 0 {
		return ""
	}
	// First byte encodes first two components: first*40 + second
	components := []int{int(oidBytes[0]) / 40, int(oidBytes[0]) % 40}
	value := 0
	for i := 1; i < len(oidBytes); i++ {
		value = (value << 7) | int(oidBytes[i]&0x7F)
		if oidBytes[i]&0x80 == 0 {
			components = append(components, value)
			value = 0
		}
	}
	result := ""
	for i, c := range components {
		if i > 0 {
			result += "."
		}
		result += fmt.Sprintf("%d", c)
	}
	return result
}

// generateMappingKeypair creates an ephemeral keypair for Generic Mapping
// and stores the private key in ctx.MappingPrivateKey.
// Returns the uncompressed public key bytes to send to the card.
func generateMappingKeypair(ctx *PACEContext) ([]byte, error) {
	if ctx.DomainParams == nil {
		return nil, fmt.Errorf("domain parameters not set")
	}

	if ctx.DomainParams.EllipticCurve != nil {
		// Brainpool or standard elliptic curve via elliptic.Curve interface
		curve := ctx.DomainParams.EllipticCurve
		privBytes, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("key generation failed: %w", err)
		}
		ctx.MappingPrivateKey = privBytes
		pubBytes := elliptic.Marshal(curve, x, y)
		return pubBytes, nil
	}

	if ctx.DomainParams.Curve != nil {
		// Standard curve via ecdh.Curve
		privKey, err := ctx.DomainParams.Curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("key generation failed: %w", err)
		}
		ctx.MappingPrivateKey = privKey.Bytes()
		return privKey.PublicKey().Bytes(), nil
	}

	return nil, fmt.Errorf("no EC curve configured for mapping keypair generation")
}

