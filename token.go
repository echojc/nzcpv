package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type Token struct {
	KeyID     string
	Algorithm int
	Issuer    string
	NotBefore time.Time
	Expires   time.Time
	JTI       string
	Claims    Claims

	Signature []byte
	digest    []byte
}

type Claims struct {
	Context           []string `cbor:"@context"`
	Version           string   `cbor:"version"`
	Type              []string `cbor:"type"`
	CredentialSubject Subject  `cbor:"credentialSubject"`
}

type Subject struct {
	GivenName  string `cbor:"givenName"`
	FamilyName string `cbor:"familyName"`
	DOB        string `cbor:"dob"`
}

func NewToken(qr string) (*Token, error) {
	if !strings.HasPrefix(qr, "NZCP:/") {
		return nil, errors.New("Missing prefix 'NZCP:/'")
	}

	parts := strings.Split(qr, "/")
	if len(parts) < 1 {
		return nil, errors.New("Missing version number")
	}

	version, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("Bad version: %v", err)
	}

	switch version {
	case 1:
		if len(parts) < 2 {
			return nil, errors.New("Missing QR payload")
		}

		decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
		data, err := decoder.DecodeString(parts[2])
		if err != nil {
			return nil, fmt.Errorf("Could not decode QR payload: %v", err)
		}

		t, err := unmarshalTokenV1(data)
		if err != nil {
			return nil, err
		}
		return t, validateTokenV1(t)

	default:
		return nil, fmt.Errorf("Bad version: expected '1', got '%d'", version)
	}
}

func unmarshalTokenV1(data []byte) (*Token, error) {
	type signedCWT struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected cbor.RawMessage
		Payload     []byte
		Signature   []byte
	}

	// TODO
	tags := cbor.NewTagSet()
	tags.Add(
		cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired},
		reflect.TypeOf(signedCWT{}), 18)
	d, _ := cbor.DecOptions{}.DecModeWithTags(tags)

	var raw signedCWT
	if err := d.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("Payload not COSE_Sign1: %v", err)
	}

	var h struct {
		Kid []byte `cbor:"4,keyasint"` // spec says Major Type 3 string
		Alg int    `cbor:"1,keyasint"`
	}
	if err := cbor.Unmarshal(raw.Protected, &h); err != nil {
		return nil, fmt.Errorf("Could not unmarshal header: %v", err)
	}

	var p struct {
		Issuer    string `cbor:"1,keyasint"`
		NotBefore int64  `cbor:"5,keyasint"`
		Expires   int64  `cbor:"4,keyasint"`
		CTI       []byte `cbor:"7,keyasint"`
		Claims    Claims `cbor:"vc"`
	}
	if err := cbor.Unmarshal(raw.Payload, &p); err != nil {
		return nil, fmt.Errorf("Could not unmarshal body: %v", err)
	}
	// any non-zero uuid is valid
	nilUUID := [16]byte{}
	if len(p.CTI) != 16 || bytes.Equal(p.CTI, nilUUID[:]) {
		return nil, fmt.Errorf("Invalid CTI '%x'", p.CTI)
	}

	// build signature digest
	ss := []interface{}{
		"Signature1",
		raw.Protected,
		[]byte{},
		raw.Payload,
	}
	ssb, err := cbor.Marshal(ss)
	if err != nil {
		return nil, fmt.Errorf("Could not build message digest: %v", err)
	}
	digest := sha256.Sum256(ssb)

	return &Token{
		KeyID:     string(h.Kid),
		Algorithm: h.Alg,
		Issuer:    p.Issuer,
		NotBefore: time.Unix(p.NotBefore, 0),
		Expires:   time.Unix(p.Expires, 0),
		JTI: fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x",
			p.CTI[0:4], p.CTI[4:6], p.CTI[6:8], p.CTI[8:10], p.CTI[10:16]),
		Claims: p.Claims,

		Signature: raw.Signature,
		digest:    digest[:],
	}, nil
}

func validateTokenV1(t *Token) error {
	if t.Algorithm != -7 {
		return fmt.Errorf("Invalid algorithm: expected -7, got %d", t.Algorithm)
	}

	if _, ok := trustedIssuers[t.Issuer]; !ok {
		return fmt.Errorf("Untrusted issuer '%s'", t.Issuer)
	}

	// verify signature
	keyID := t.Issuer + "#" + t.KeyID
	if _, ok := keys[keyID]; !ok {
		// TODO retrieve?
		return fmt.Errorf("Unknown public key '%s'", keyID)
	}
	if !ecdsa.Verify(
		keys[keyID],
		t.digest,
		big.NewInt(0).SetBytes(t.Signature[:32]),
		big.NewInt(0).SetBytes(t.Signature[32:])) {
		return errors.New("Signature failed to verify")
	}

	// timestamps
	now := time.Now()
	if now.Before(t.NotBefore) {
		return fmt.Errorf("Token not yet active (nbf: %v)", t.NotBefore)
	}
	if now.After(t.Expires) {
		return fmt.Errorf("Token expired (exp: %v)", t.Expires)
	}

	// claims
	if len(t.Claims.Context) < 1 ||
		t.Claims.Context[0] != "https://www.w3.org/2018/credentials/v1" {
		return fmt.Errorf("Claims @context[0] must be '%s' (got: %v)",
			"https://www.w3.org/2018/credentials/v1",
			t.Claims.Context[0])
	}
	containsNZCPContext := false
	for _, c := range t.Claims.Context {
		if c == "https://nzcp.covid19.health.nz/contexts/v1" {
			containsNZCPContext = true
			break
		}
	}
	if !containsNZCPContext {
		return fmt.Errorf("Missing NZCP context '%s'",
			"https://nzcp.covid19.health.nz/contexts/v1")
	}

	// pass type
	if len(t.Claims.Type) != 2 ||
		t.Claims.Type[0] != "VerifiableCredential" ||
		t.Claims.Type[1] != "PublicCovidPass" {
		return fmt.Errorf("VC type must be %v (got: %v)",
			[]string{"VerifiableCredential", "PublicCovidPass"},
			t.Claims.Type)
	}

	// version
	if t.Claims.Version != "1.0.0" {
		return fmt.Errorf("VC version must be 1.0.0 (got: '%s')", t.Claims.Version)
	}

	return nil
}
