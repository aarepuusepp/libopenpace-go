package asn1

import (
	"testing"
)

func TestCreateDefaultCardAccess(t *testing.T) {
	ca := CreateDefaultCardAccess()
	
	if ca == nil {
		t.Fatal("CreateDefaultCardAccess returned nil")
	}
	
	if len(ca.SecurityInfos) == 0 {
		t.Error("CardAccess has no SecurityInfos")
	}
	
	// Verify the OID is correct for PACE ECDH GM AES-128
	expectedOID := "0.4.0.127.0.7.2.2.4.1.2"
	actualOID := ca.SecurityInfos[0].Protocol.String()
	
	if actualOID != expectedOID {
		t.Errorf("Protocol OID = %s, expected %s", actualOID, expectedOID)
	}
}

func TestGetPACEInfo(t *testing.T) {
	ca := CreateDefaultCardAccess()
	
	paceInfo := ca.GetPACEInfo()
	if paceInfo == nil {
		t.Fatal("GetPACEInfo returned nil")
	}
	
	if paceInfo.Protocol != "0.4.0.127.0.7.2.2.4.1.2" {
		t.Errorf("PACE protocol = %s, expected 0.4.0.127.0.7.2.2.4.1.2", paceInfo.Protocol)
	}
}

func TestPACEInfo_GetProtocolOID(t *testing.T) {
	pi := &PACEInfo{
		Protocol: "0.4.0.127.0.7.2.2.4.1.2",
	}
	
	oid := pi.GetProtocolOID()
	if oid != "0.4.0.127.0.7.2.2.4.1.2" {
		t.Errorf("GetProtocolOID = %s, expected 0.4.0.127.0.7.2.2.4.1.2", oid)
	}
}

func TestPACEInfo_ParameterID(t *testing.T) {
	pi := &PACEInfo{}
	
	// Test default
	if pi.GetParameterID() != 0 {
		t.Errorf("Default ParameterID = %d, expected 0", pi.GetParameterID())
	}
	
	// Test set/get
	pi.SetParameterID(8) // P-256
	if pi.GetParameterID() != 8 {
		t.Errorf("ParameterID = %d, expected 8", pi.GetParameterID())
	}
}

func TestParseCardAccess_Empty(t *testing.T) {
	_, err := ParseCardAccess([]byte{})
	if err == nil {
		t.Error("ParseCardAccess should fail with empty data")
	}
}

