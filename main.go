package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// https://nzcp.covid19.health.nz

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

var keys = map[string]*ecdsa.PublicKey{
	"did:web:nzcp.covid19.health.nz#key-1": &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X: big.NewInt(0).SetBytes([]byte{
			0xcd, 0x14, 0x7e, 0x5c, 0x6b, 0x02, 0xa7, 0x5d,
			0x95, 0xbd, 0xb8, 0x2e, 0x8b, 0x80, 0xc3, 0xe8,
			0xee, 0x9c, 0xaa, 0x68, 0x5f, 0x3e, 0xe5, 0xcc,
			0x86, 0x2d, 0x4e, 0xc4, 0xf9, 0x7c, 0xef, 0xad,
		}),
		Y: big.NewInt(0).SetBytes([]byte{
			0x22, 0xfe, 0x52, 0x53, 0xa1, 0x6e, 0x5b, 0xe4,
			0xd1, 0x62, 0x1e, 0x7f, 0x18, 0xea, 0xc9, 0x95,
			0xc5, 0x7f, 0x82, 0x91, 0x7f, 0x1a, 0x91, 0x50,
			0x84, 0x23, 0x83, 0xf0, 0xb4, 0xa4, 0xdd, 0x3d,
		}),
	},
	"did:web:nzcp.identity.health.nz#z12Kf7UQ": &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X: big.NewInt(0).SetBytes([]byte{
			0x0d, 0x00, 0x8a, 0x26, 0xeb, 0x2a, 0x32, 0xc4,
			0xf4, 0xbb, 0xb0, 0xa3, 0xa6, 0x68, 0x63, 0x54,
			0x69, 0x07, 0x96, 0x7d, 0xc0, 0xdd, 0xf4, 0xbe,
			0x6b, 0x27, 0x87, 0xe0, 0xdb, 0xb9, 0xda, 0xd7,
		}),
		Y: big.NewInt(0).SetBytes([]byte{
			0x97, 0x18, 0x16, 0xce, 0xc2, 0xed, 0x54, 0x8f,
			0x1f, 0xa9, 0x99, 0x93, 0x3c, 0xfa, 0x3d, 0x9d,
			0x9f, 0xa4, 0xcc, 0x6b, 0x3b, 0xc3, 0xb5, 0xce,
			0xf3, 0xea, 0xd4, 0x53, 0xaf, 0x0e, 0xc6, 0x62,
		}),
	},
}

var trustedIssuers = map[string]struct{}{
	"did:web:nzcp.identity.health.nz": struct{}{},
	"did:web:nzcp.covid19.health.nz":  struct{}{},
}

func main() {
	q := "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX"

	t, err := NewToken(q)
	if err != nil {
		log.Fatal(err)
	}

	s, _ := json.MarshalIndent(t, "", "  ")
	fmt.Println(string(s))
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
