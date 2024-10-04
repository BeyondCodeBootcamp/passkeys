package passkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// RawURLBase64 is a newtype of string for base64 encoding
type RawURLBase64 []byte

// MarshalJSON encodes the Base64 as a base64 byte array
func (b RawURLBase64) MarshalJSON() ([]byte, error) {
	encoded := base64.RawURLEncoding.EncodeToString(b)
	return json.Marshal(encoded)
}

// UnmarshalJSON decodes a base64 byte array into the Base64
func (b *RawURLBase64) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	*b = RawURLBase64(decoded)
	return nil
}

// Registration is the CredentialCreationResponse containing the Attestation Object
// and PublicKey
type Registration struct {
	ID       string
	Response struct {
		AttestationCBOR       RawURLBase64       `json:"attestationObject"`
		AuthenticatorDataRaw  RawURLBase64       `json:"authenticatorData"`
		AuthenticatorData     *AuthenticatorData `json:"-"`
		ClientDataJSON        RawURLBase64       `json:"clientDataJSON"`
		ClientData            ClientData         `json:"-"`
		PublicKeyAlgorithmInt int                `json:"publicKeyAlgorithm"`
		PublicKeyAlgorithm    string             `json:"publicKeyAlgorithmName"`
		PublicKeyDER          RawURLBase64       `json:"publicKey"`
		PublicKeyECDSA        *ecdsa.PublicKey   `json:"-"`
		Transports            []string           `json:"transports"`
	} `json:"response"`
}

func ParseRegistration(credentialCreationResponse []byte) (*Registration, error) {
	credCreation := &Registration{}
	if err := json.Unmarshal(credentialCreationResponse, credCreation); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(credCreation.Response.ClientDataJSON, &credCreation.Response.ClientData); err != nil {
		return nil, err
	}

	var err error
	credCreation.Response.PublicKeyECDSA, err = parseECDSAPublicKey(credCreation.Response.PublicKeyDER)
	if err != nil {
		return nil, err
	}

	credCreation.Response.AuthenticatorData, err = ParseAuthenticatorData(credCreation.Response.AuthenticatorDataRaw)
	if err != nil {
		return nil, err
	}

	return credCreation, nil
}

func parseECDSAPublicKey(derBytes []byte) (*ecdsa.PublicKey, error) {
	publicKey, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: %w", err)
	}

	// Type assert to *ecdsa.PublicKey
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return ecdsaPublicKey, nil
}

// Assertion is the CredentialRequestResponse containing the Authenticator Data
type Assertion struct {
	ID       string
	Response struct {
		AuthenticatorDataRaw RawURLBase64       `json:"authenticatorData"`
		AuthenticatorData    *AuthenticatorData `json:"-"`
		ClientDataJSON       RawURLBase64       `json:"clientDataJSON"`
		ClientData           ClientData         `json:"-"`
		Signature            RawURLBase64       `json:"signature"`
		AttToBeSigned        []byte             `json:"-"`
	} `json:"response"`
}

func ParseAssertion(credentialRequestResponse []byte) (*Assertion, error) {
	credReq := &Assertion{}
	if err := json.Unmarshal(credentialRequestResponse, credReq); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(credReq.Response.ClientDataJSON, &credReq.Response.ClientData); err != nil {
		return nil, err
	}

	clientDataHash := sha256.Sum256(credReq.Response.ClientDataJSON)
	attToBeSigned := append(credReq.Response.AuthenticatorDataRaw, clientDataHash[:]...)

	var err error
	credReq.Response.AuthenticatorData, err = ParseAuthenticatorData(credReq.Response.AuthenticatorDataRaw)
	if err != nil {
		return nil, err
	}

	credReq.Response.AttToBeSigned = attToBeSigned

	return credReq, nil
}

// AuthenticatorData represents the authenticator device or service
type AuthenticatorData struct {
	RPIDHash               []byte
	Flags                  Flags
	SignCount              uint32
	AttestedCredentialData *AttestedCredentialData
	Extensions             []byte
}

// ParseAuthenticatorData parses the AuthenticatorData from decoded base64
func ParseAuthenticatorData(authData []byte) (*AuthenticatorData, error) {
	if len(authData) < 37 {
		return nil, errors.New("authenticatorData too short")
	}

	reader := bytes.NewReader(authData)

	// Parse RP ID Hash (32 bytes)
	rpIDHash := make([]byte, 32)
	if _, err := reader.Read(rpIDHash); err != nil {
		return nil, err
	}

	// Parse Flags (1 byte)
	var flags Flags
	if err := binary.Read(reader, binary.BigEndian, &flags); err != nil {
		return nil, err
	}

	// Parse Sign Count (4 bytes)
	var signCount uint32
	if err := binary.Read(reader, binary.BigEndian, &signCount); err != nil {
		return nil, err
	}

	authDataObj := &AuthenticatorData{
		RPIDHash:  rpIDHash,
		Flags:     flags,
		SignCount: signCount,
	}

	// Check if Attested Credential Data (AT flag) is present
	if flags&0x40 != 0 {
		attestedCredentialData, err := ParseAttestedCredentialData(reader)
		if err != nil {
			return nil, err
		}
		authDataObj.AttestedCredentialData = attestedCredentialData
	}

	// Check if Extensions Data (ED flag) is present
	if flags&0x80 != 0 {
		// Remaining bytes are for extensions (if present)
		extensions := make([]byte, reader.Len())
		if _, err := reader.Read(extensions); err != nil {
			return nil, err
		}
		authDataObj.Extensions = extensions
	}

	return authDataObj, nil
}

type ClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// AttestedCredentialData represents the structure of attested credential data
type AttestedCredentialData struct {
	AAGUID        []byte
	CredentialID  []byte
	PublicKeyCBOR []byte
}

// ParseAttestedCredentialData parses the attested credential data from the reader
func ParseAttestedCredentialData(reader *bytes.Reader) (*AttestedCredentialData, error) {
	if reader.Len() < 18 {
		return nil, errors.New("insufficient bytes for attested credential data")
	}

	// Parse AAGUID (16 bytes)
	aaguid := make([]byte, 16)
	if _, err := reader.Read(aaguid); err != nil {
		return nil, err
	}

	// Parse Credential ID length (2 bytes)
	var credentialIDLen uint16
	if err := binary.Read(reader, binary.BigEndian, &credentialIDLen); err != nil {
		return nil, err
	}

	// Parse Credential ID (variable length)
	credentialID := make([]byte, credentialIDLen)
	if _, err := reader.Read(credentialID); err != nil {
		return nil, err
	}

	// The rest should be the public key in CBOR format (we'll assume it's raw bytes for now)
	publicKey := make([]byte, reader.Len())
	if _, err := reader.Read(publicKey); err != nil {
		return nil, err
	}

	return &AttestedCredentialData{
		AAGUID:        aaguid,
		CredentialID:  credentialID,
		PublicKeyCBOR: publicKey,
	}, nil
}

// Flags represents the flags byte in the authenticatorData
type Flags byte

const (
	FlagUP Flags = 1 << 0 // User presence tested
	flagR1 Flags = 1 << 1 // Reserved 1
	FlagUV Flags = 1 << 2 // User verification performed
	FlagBE Flags = 1 << 3 // Backup Eligible (Multi Device)
	FlagBS Flags = 1 << 4 // Backup State (e.g. saved to iCloud)
	flagR2 Flags = 1 << 5 // Reserved 2
	FlagAT Flags = 1 << 6 // Attested credential data included
	FlagED Flags = 1 << 7 // Extension data included
)

// IsUserPresent (0:UP) is true if the user is physically detected (NFC, Touch, BLE, etc)
func (f Flags) IsUserPresent() bool {
	return f&FlagUP != 0
}

func (f Flags) hasReserved1Bit() bool {
	return f&flagR1 != 0
}

// UserVerified (2:UV) is true when the user verified via password, PIN, Touch, Face, etc
func (f Flags) UserVerified() bool {
	return f&FlagUV != 0
}

// IsMultiDeviceCredential (3:BE) true for Browser Sync, iCloud, etc - "Backup Eligible"
func (f Flags) IsMultiDeviceCredential() bool {
	return f&FlagBE != 0
}

// IsBackedUp (4:BS) true if Browser Sync, iCloud, etc is active "Backup State"
func (f Flags) IsBackedUp() bool {
	return f&FlagBE != 0
}

func (f Flags) hasReserved2Bit() bool {
	return f&flagR2 != 0
}

// HasAttestedCredentialData (6:AT) is true when additional data is attached
func (f Flags) HasAttestedCredentialData() bool {
	return f&FlagAT != 0
}

// HasExtensionData (7:ED) is true when data about extensions is present
func (f Flags) HasExtensionData() bool {
	return f&FlagED != 0
}

// String returns a string representation of the Flags with human-readable status
func (f Flags) String() string {
	return fmt.Sprintf(
		"\n\t[0:UP] %t %s\n\t[1:R1] %t %s\n\t[2:UV] %t %s\n\t[3:BE] %t %s\n\t[4:BS] %t %s\n\t[5:R2] %t %s\n\t[6:AT] %t %s\n\t[7:ED] %t %s",
		f.IsUserPresent(),
		"\tUser Was Present?",
		f.hasReserved1Bit(),
		"\t-",
		f.UserVerified(),
		"\tUser Verified?",
		f.IsMultiDeviceCredential(),
		"\tMulti-Device?",
		f.IsBackedUp(),
		"\tBacked up / Synced?",
		f.hasReserved2Bit(),
		"\t-",
		f.HasAttestedCredentialData(),
		"\tHas Attested Credential Data?",
		f.HasExtensionData(),
		"\tHas Extended Data?",
	)
}
