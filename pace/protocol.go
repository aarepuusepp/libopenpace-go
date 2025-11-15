package pace

import (
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
	fmt.Printf("[PACE] Selecting MF...\n")
	selectMF := []byte{0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00}
	resp, err2 := card.Transmit(selectMF)
	if err2 == nil && len(resp) >= 2 {
		sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
		if sw == 0x9000 {
			fmt.Printf("[PACE] MF selected\n")
		}
	}
	
	// Now try to read EF.CardAccess from MF
	fmt.Printf("[PACE] Reading EF.CardAccess from MF...\n")
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
				fmt.Printf("[PACE] EF.CardAccess from MF: %d bytes: %X\n", len(mfCardAccess), mfCardAccess)
			}
		}
	}
	
	// Step 0b: Probe AIDs and try PACE with each
	// Try multiple AIDs in order
	aids := []struct {
		name string
		aid  []byte
	}{
		{"EstEID (contactless)", []byte{0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00}},
		{"PKCS-15", []byte{0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35}},
		{"eMRTD", []byte{0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01}},
		{"No AID (MF)", nil}, // Try without selecting any AID
	}
	
	var paceSuccess bool
	for _, aidInfo := range aids {
		fmt.Printf("[PACE] Trying context: %s\n", aidInfo.name)
		
		// SELECT AID if specified (plain, no SM)
		if aidInfo.aid != nil {
			err = selectApplication(card, aidInfo.aid)
			if err != nil {
				fmt.Printf("[PACE] SELECT AID failed: %v, trying next...\n", err)
				continue
			}
			fmt.Printf("[PACE] AID selected: %s\n", aidInfo.name)
			
			// Try to read EF.CardAccess from this application
			fmt.Printf("[PACE] Reading EF.CardAccess for this AID...\n")
			selectCmd := []byte{0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1C}
			resp, err2 := card.Transmit(selectCmd)
			if err2 == nil && len(resp) >= 2 {
				sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
				if sw == 0x9000 {
					readCmd := []byte{0x00, 0xB0, 0x00, 0x00, 0x00}
					resp, err2 = card.Transmit(readCmd)
					if err2 == nil && len(resp) > 2 {
						mfCardAccess = resp[:len(resp)-2]
						fmt.Printf("[PACE] EF.CardAccess from AID: %d bytes: %X\n", len(mfCardAccess), mfCardAccess)
					}
				}
			}
		}
		
		// Use CardAccess (either from MF or from this AID)
		cardAccessData := mfCardAccess
		if len(cardAccessData) == 0 {
			fmt.Printf("[PACE] No CardAccess available, trying next...\n")
			continue
		}
		
		fmt.Printf("[PACE] Using CardAccess: %d bytes\n", len(cardAccessData))
		
		// Parse CardAccess to get PACEInfo(s)
		paceInfos := parseCardAccessPACEInfos(cardAccessData)
		if len(paceInfos) == 0 {
			fmt.Printf("[PACE] No PACEInfo found in CardAccess, trying next AID...\n")
			continue
		}
		
		// Try each PACEInfo with both password references (0x02 and 0x03)
		for i, paceInfo := range paceInfos {
			fmt.Printf("[PACE] Trying PACEInfo %d: OID=%X, ParamID=%d\n", i+1, paceInfo.oidDER, paceInfo.paramID)
			
			// Update context with this PACEInfo
			ctx.CardAccessOID = paceInfo.oidDER
			ctx.ParameterID = int(paceInfo.paramID)
			
			// Try multiple password references
			// 0x01 = MRZ (for eMRTD), 0x02 = CAN, 0x03 = CAN (alternate)
			pwRefs := []byte{0x02, 0x03}
			if aidInfo.name == "eMRTD" {
				// For eMRTD, try MRZ first, then CAN
				pwRefs = []byte{0x01, 0x02, 0x03}
			}
			
			for _, pwRef := range pwRefs {
				pwRefName := "CAN"
				if pwRef == 0x01 {
					pwRefName = "MRZ"
				}
				fmt.Printf("[PACE] Trying MSE:Set AT with PWRef=0x%02X (%s)\n", pwRef, pwRefName)
				
				// Some cards require VERIFY CAN before MSE:Set AT
				// Try VERIFY command with the CAN
				fmt.Printf("[PACE] Trying VERIFY CAN...\n")
				verifyCmd := []byte{0x00, 0x20, 0x00, pwRef, byte(len(secret.Value))}
				verifyCmd = append(verifyCmd, secret.Value...)
				resp, err3 := card.Transmit(verifyCmd)
				if err3 == nil && len(resp) >= 2 {
					sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
					if sw == 0x9000 {
						fmt.Printf("[PACE] VERIFY CAN succeeded\n")
					} else {
						fmt.Printf("[PACE] VERIFY CAN returned SW=%04X (may not be required)\n", sw)
					}
				}
				
				// Step 0c: MSE:Set AT (plain, no SM)
				err = mseSetATPACE(card, paceInfo.oidDER, pwRef, paceInfo.paramID)
				if err != nil {
					fmt.Printf("[PACE] MSE:Set AT failed: %v\n", err)
					continue
				}
				
				fmt.Printf("[PACE] MSE:Set AT succeeded! Proceeding with PACE...\n")
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
		return nil, fmt.Errorf("all AIDs and PACEInfos failed - card may require vendor-specific initialization")
	}
	
	// Step 1: Encrypt nonce and send to card
	encryptedNonce, err := PACE_STEP1_enc_nonce(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 1 failed: %w", err)
	}
	
	// Send encrypted nonce to card via General Authenticate
	cardEncryptedNonce, err := generalAuthenticateStep1(card, encryptedNonce)
	if err != nil {
		return nil, fmt.Errorf("General Authenticate Step 1 failed: %w", err)
	}
	
	// Step 2: Decrypt card's encrypted nonce
	err = PACE_STEP2_dec_nonce(ctx, secret, cardEncryptedNonce)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 2 failed: %w", err)
	}
	
	// Step 3A: Map generator (if needed)
	mappingType := protocol.GetMappingType()
	var mappingData []byte
	
	if mappingType == MappingGeneric {
		// For Generic Mapping, exchange mapping data with card
		mappingData, err = generalAuthenticateStep2(card, nil)
		if err != nil {
			return nil, fmt.Errorf("General Authenticate Step 2 (mapping) failed: %w", err)
		}
	}
	
	err = PACE_STEP3A_map_generator(ctx, mappingData)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3A failed: %w", err)
	}
	
	// Step 3B: Generate ephemeral keypair and exchange with card
	ourPublicKey, err := PACE_STEP3B_generate_ephemeral_key(ctx)
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3B (generate key) failed: %w", err)
	}
	
	// Exchange ephemeral public keys
	cardPublicKey, err := generalAuthenticateStep3(card, ourPublicKey)
	if err != nil {
		return nil, fmt.Errorf("General Authenticate Step 3 (key exchange) failed: %w", err)
	}
	
	// Compute shared secret from card's public key
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
	ourAuthToken, err := PACE_STEP3D_compute_auth_token(ctx, true) // true = we are terminal
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3D (compute token) failed: %w", err)
	}
	
	// Exchange authentication tokens
	cardAuthToken, err := generalAuthenticateStep4(card, ourAuthToken)
	if err != nil {
		return nil, fmt.Errorf("General Authenticate Step 4 (auth) failed: %w", err)
	}
	
	// Verify card's authentication token
	err = PACE_STEP3D_verify_auth_token(ctx, cardAuthToken, false) // false = card is not terminal
	if err != nil {
		return nil, fmt.Errorf("PACE Step 3D (verify token) failed: %w", err)
	}
	
	// Initialize SSC to zero (as per OpenPACE and BSI TR-03110)
	initialSSC := make([]byte, 8) // All zeros
	
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
	
	// Build DER-encoded OID (06 <len> <oid>)
	oidDER := append([]byte{0x06, byte(len(actualOID))}, actualOID...)
	
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
	// Tag 83: Password Reference
	// Tag 84: Parameter ID
	
	data := []byte{0x80, byte(len(oidDER))}
	data = append(data, oidDER...)
	data = append(data, 0x83, 0x01, pwRef)
	data = append(data, 0x84, 0x01, paramID)
	
	fmt.Printf("[PACE] MSE:Set AT data: %X\n", data)
	
	// MSE:Set AT command (plain, CLA=00)
	cmd := []byte{0x00, 0x22, 0xC1, 0xA4, byte(len(data))}
	cmd = append(cmd, data...)
	
	fmt.Printf("[PACE] MSE:Set AT command: %X\n", cmd)
	
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
		fmt.Printf("[PACE] MSE:Set AT - Using OID from CardAccess: %X\n", oidBytes)
	} else {
		// Fallback to protocol OID
		oidSlice := protocol.ToOIDSlice()
		var err error
		oidBytes, err = asn1.Marshal(asn1.ObjectIdentifier(oidSlice))
		if err != nil {
			return fmt.Errorf("failed to marshal OID: %w", err)
		}
		fmt.Printf("[PACE] MSE:Set AT - OID: %v, OID bytes: %X\n", oidSlice, oidBytes)
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
	
	fmt.Printf("[PACE] MSE:Set AT data (with PW ref 0x02): %X\n", data)
	
	// MSE:Set AT command
	cmd := []byte{0x00, 0x22, 0xC1, 0xA4, byte(len(data))}
	cmd = append(cmd, data...)
	
	fmt.Printf("[PACE] MSE:Set AT command: %X\n", cmd)
	
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

// generalAuthenticateStep1 sends the encrypted nonce to the card.
//
// Command: 00 86 00 00 <data> 00
// Data: Tag 7C { Tag 80 <encrypted_nonce> }
func generalAuthenticateStep1(card CardInterface, encryptedNonce []byte) ([]byte, error) {
	// Build General Authenticate data
	// Tag 7C: Dynamic Authentication Data
	//   Tag 80: Encrypted Nonce
	
	data := []byte{0x7C}
	innerData := []byte{0x80, byte(len(encryptedNonce))}
	innerData = append(innerData, encryptedNonce...)
	data = append(data, byte(len(innerData)))
	data = append(data, innerData...)
	
	// General Authenticate command
	cmd := []byte{0x00, 0x86, 0x00, 0x00, byte(len(data))}
	cmd = append(cmd, data...)
	cmd = append(cmd, 0x00) // Le=0 (expect response)
	
	resp, err2 := card.Transmit(cmd)
	if err2 != nil {
		return nil, fmt.Errorf("General Authenticate Step 1 transmission failed: %w", err2)
	}
	
	if len(resp) < 2 {
		return nil, fmt.Errorf("General Authenticate Step 1 response too short")
	}
	
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	if sw != 0x9000 {
		return nil, fmt.Errorf("General Authenticate Step 1 failed: SW=%04X", sw)
	}
	
	// Parse response: Tag 7C { Tag 80 <card_encrypted_nonce> }
	respData := resp[:len(resp)-2]
	if len(respData) < 4 || respData[0] != 0x7C {
		return nil, fmt.Errorf("invalid response format")
	}
	
	// Extract encrypted nonce from Tag 80
	innerResp := respData[2:]
	if len(innerResp) < 2 || innerResp[0] != 0x80 {
		return nil, fmt.Errorf("missing Tag 80 in response")
	}
	
	nonceLen := int(innerResp[1])
	if len(innerResp) < 2+nonceLen {
		return nil, fmt.Errorf("incomplete encrypted nonce")
	}
	
	return innerResp[2 : 2+nonceLen], nil
}

// generalAuthenticateStep2 exchanges mapping data (for Generic Mapping only).
func generalAuthenticateStep2(card CardInterface, mappingData []byte) ([]byte, error) {
	// Build General Authenticate data
	// Tag 7C: Dynamic Authentication Data
	//   Tag 81: Mapping Data (optional)
	
	var data []byte
	if mappingData != nil {
		data = []byte{0x7C}
		innerData := []byte{0x81, byte(len(mappingData))}
		innerData = append(innerData, mappingData...)
		data = append(data, byte(len(innerData)))
		data = append(data, innerData...)
	} else {
		data = []byte{0x7C, 0x00}
	}
	
	// General Authenticate command
	cmd := []byte{0x00, 0x86, 0x00, 0x00, byte(len(data))}
	cmd = append(cmd, data...)
	cmd = append(cmd, 0x00) // Le=0
	
	resp, err2 := card.Transmit(cmd)
	if err2 != nil {
		return nil, fmt.Errorf("General Authenticate Step 2 transmission failed: %w", err2)
	}
	
	if len(resp) < 2 {
		return nil, fmt.Errorf("General Authenticate Step 2 response too short")
	}
	
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	if sw != 0x9000 {
		return nil, fmt.Errorf("General Authenticate Step 2 failed: SW=%04X", sw)
	}
	
	// Parse response for mapping data if present
	respData := resp[:len(resp)-2]
	if len(respData) > 0 && respData[0] == 0x7C {
		// Extract mapping data from Tag 81
		innerResp := respData[2:]
		if len(innerResp) >= 2 && innerResp[0] == 0x81 {
			dataLen := int(innerResp[1])
			if len(innerResp) >= 2+dataLen {
				return innerResp[2 : 2+dataLen], nil
			}
		}
	}
	
	return nil, nil
}

// generalAuthenticateStep3 exchanges ephemeral public keys.
//
// Command: 00 86 00 00 <data> 00
// Data: Tag 7C { Tag 83 <our_public_key> }
// Response: Tag 7C { Tag 84 <card_public_key> }
func generalAuthenticateStep3(card CardInterface, ourPublicKey []byte) ([]byte, error) {
	// Build General Authenticate data
	// Tag 7C: Dynamic Authentication Data
	//   Tag 83: Terminal Public Key
	
	data := []byte{0x7C}
	innerData := []byte{0x83, byte(len(ourPublicKey))}
	innerData = append(innerData, ourPublicKey...)
	data = append(data, byte(len(innerData)))
	data = append(data, innerData...)
	
	// General Authenticate command
	cmd := []byte{0x00, 0x86, 0x00, 0x00, byte(len(data))}
	cmd = append(cmd, data...)
	cmd = append(cmd, 0x00) // Le=0
	
	resp, err3 := card.Transmit(cmd)
	if err3 != nil {
		return nil, fmt.Errorf("General Authenticate Step 3 transmission failed: %w", err3)
	}
	
	if len(resp) < 2 {
		return nil, fmt.Errorf("General Authenticate Step 3 response too short")
	}
	
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	if sw != 0x9000 {
		return nil, fmt.Errorf("General Authenticate Step 3 failed: SW=%04X", sw)
	}
	
	// Parse response: Tag 7C { Tag 84 <card_public_key> }
	respData := resp[:len(resp)-2]
	if len(respData) < 4 || respData[0] != 0x7C {
		return nil, fmt.Errorf("invalid response format")
	}
	
	// Extract public key from Tag 84
	innerResp := respData[2:]
	if len(innerResp) < 2 || innerResp[0] != 0x84 {
		return nil, fmt.Errorf("missing Tag 84 in response")
	}
	
	keyLen := int(innerResp[1])
	if len(innerResp) < 2+keyLen {
		return nil, fmt.Errorf("incomplete public key")
	}
	
	return innerResp[2 : 2+keyLen], nil
}

// generalAuthenticateStep4 exchanges authentication tokens.
//
// Command: 00 86 00 00 <data> 00
// Data: Tag 7C { Tag 85 <our_auth_token> }
// Response: Tag 7C { Tag 86 <card_auth_token> }
func generalAuthenticateStep4(card CardInterface, ourAuthToken []byte) ([]byte, error) {
	// Build General Authenticate data
	// Tag 7C: Dynamic Authentication Data
	//   Tag 85: Terminal Authentication Token
	
	data := []byte{0x7C}
	innerData := []byte{0x85, byte(len(ourAuthToken))}
	innerData = append(innerData, ourAuthToken...)
	data = append(data, byte(len(innerData)))
	data = append(data, innerData...)
	
	// General Authenticate command
	cmd := []byte{0x00, 0x86, 0x00, 0x00, byte(len(data))}
	cmd = append(cmd, data...)
	cmd = append(cmd, 0x00) // Le=0
	
	resp, err4 := card.Transmit(cmd)
	if err4 != nil {
		return nil, fmt.Errorf("General Authenticate Step 4 transmission failed: %w", err4)
	}
	
	if len(resp) < 2 {
		return nil, fmt.Errorf("General Authenticate Step 4 response too short")
	}
	
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	if sw != 0x9000 {
		return nil, fmt.Errorf("General Authenticate Step 4 failed: SW=%04X", sw)
	}
	
	// Parse response: Tag 7C { Tag 86 <card_auth_token> }
	respData := resp[:len(resp)-2]
	if len(respData) < 4 || respData[0] != 0x7C {
		return nil, fmt.Errorf("invalid response format")
	}
	
	// Extract auth token from Tag 86
	innerResp := respData[2:]
	if len(innerResp) < 2 || innerResp[0] != 0x86 {
		return nil, fmt.Errorf("missing Tag 86 in response")
	}
	
	tokenLen := int(innerResp[1])
	if len(innerResp) < 2+tokenLen {
		return nil, fmt.Errorf("incomplete auth token")
	}
	
	return innerResp[2 : 2+tokenLen], nil
}

