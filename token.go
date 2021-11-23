package nzcpv

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type Token struct {
	KeyID                string
	Algorithm            int
	Issuer               string
	NotBefore            time.Time
	Expires              time.Time
	JTI                  string
	VerifiableCredential VerifiableCredential
	Signature            []byte

	cti    []byte
	digest []byte
}

type VerifiableCredential struct {
	Context           []string          `cbor:"@context"`
	Version           string            `cbor:"version"`
	Type              []string          `cbor:"type"`
	CredentialSubject CredentialSubject `cbor:"credentialSubject"`
}

type CredentialSubject struct {
	GivenName  string `cbor:"givenName"`
	FamilyName string `cbor:"familyName"`
	DOB        string `cbor:"dob"`
}

var (
	ErrMissingNZCPPrefix  = errors.New("Missing prefix 'NZCP:/'")
	ErrMissingNZCPVersion = errors.New("Missing NZCP version")
	ErrBadNZCPVersion     = errors.New("Bad NZCP version")
	ErrMissingNZCPPayload = errors.New("Missing NZCP payload")
	ErrBadNZCPPayload     = errors.New("Bad NZCP payload")
	ErrInvalidTokenFormat = errors.New("Invalid token format")
	ErrInvalidTokenHeader = errors.New("Invalid token header")
	ErrInvalidTokenBody   = errors.New("Invalid token body")
)

// NewToken parses an encoded NZCP from the QR code data. If err is nil, the
// token has been successfully unmarshalled, but it has not been validated.
// This is so that the data in the QR code can be displayed whether the token
// is valid or not. Use t.Valid() to validate.
func NewToken(qr string) (*Token, error) {
	if !strings.HasPrefix(qr, "NZCP:/") {
		return nil, ErrMissingNZCPPrefix
	}

	parts := strings.Split(qr, "/")
	if len(parts) < 1 {
		return nil, ErrMissingNZCPVersion
	}

	version, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadNZCPVersion, err)
	}

	switch version {
	case 1:
		if len(parts) < 2 {
			return nil, ErrMissingNZCPPayload
		}

		decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
		data, err := decoder.DecodeString(parts[2])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadNZCPPayload, err)
		}

		return unmarshalTokenV1(data)

	default:
		return nil, fmt.Errorf("%w: expected '1', got '%d'",
			ErrBadNZCPVersion, version)
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
		return nil, fmt.Errorf("%w: expected COSE_Sign1: %v",
			ErrInvalidTokenFormat, err)
	}

	var h struct {
		Kid []byte `cbor:"4,keyasint"` // spec says Major Type 3 string
		Alg int    `cbor:"1,keyasint"`
	}
	if err := cbor.Unmarshal(raw.Protected, &h); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTokenHeader, err)
	}

	var p struct {
		Issuer    string               `cbor:"1,keyasint"`
		NotBefore int64                `cbor:"5,keyasint"`
		Expires   int64                `cbor:"4,keyasint"`
		CTI       []byte               `cbor:"7,keyasint"`
		Claims    VerifiableCredential `cbor:"vc"`
	}
	if err := cbor.Unmarshal(raw.Payload, &p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTokenBody, err)
	}
	var jti string
	if len(p.CTI) == 16 {
		jti = fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x",
			p.CTI[0:4], p.CTI[4:6], p.CTI[6:8], p.CTI[8:10], p.CTI[10:16])
	} else {
		jti = fmt.Sprintf("urn:uuid:%x", p.CTI)
	}

	// build signature digest
	ss, err := cbor.Marshal([]interface{}{
		"Signature1",
		raw.Protected,
		[]byte{},
		raw.Payload,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: could not build message digest: %v",
			ErrBadSignature, err)
	}
	digest := sha256.Sum256(ss)

	return &Token{
		KeyID:                string(h.Kid),
		Algorithm:            h.Alg,
		Issuer:               p.Issuer,
		NotBefore:            time.Unix(p.NotBefore, 0),
		Expires:              time.Unix(p.Expires, 0),
		JTI:                  jti,
		VerifiableCredential: p.Claims,
		Signature:            raw.Signature,

		cti:    p.CTI,
		digest: digest[:],
	}, nil
}
