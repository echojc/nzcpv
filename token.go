package nzcpv

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

	cti    []byte
	digest []byte

	validated bool
	errs      []error
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

var (
	ErrMissingNZCPPrefix  = errors.New("Missing prefix 'NZCP:/'")
	ErrMissingNZCPVersion = errors.New("Missing NZCP version")
	ErrBadNZCPVersion     = errors.New("Bad NZCP version")
	ErrMissingNZCPPayload = errors.New("Missing NZCP payload")
	ErrBadNZCPPayload     = errors.New("Bad NZCP payload")
	ErrInvalidTokenFormat = errors.New("Invalid token format")
	ErrInvalidTokenHeader = errors.New("Invalid token header")
	ErrInvalidTokenBody   = errors.New("Invalid token body")

	ErrBadSignature            = errors.New("Bad signature")
	ErrInvalidSigningAlgorithm = errors.New("Invalid signing algorithm")
	ErrUntrustedIssuer         = errors.New("Untrusted issuer")
	ErrUnknownPublicKey        = errors.New("Unknown public key")

	ErrTokenNotActive       = errors.New("Token not yet active")
	ErrTokenExpired         = errors.New("Token has expired")
	ErrInvalidCTI           = errors.New("Invalid CTI")
	ErrInvalidClaimsContext = errors.New("Claims context is invalid")
	ErrInvalidClaimsType    = errors.New("Claims type is invalid")
	ErrInvalidTokenVersion  = errors.New("Token version is invalid")
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

// Valid validates the token according to the specification and returns whether
// it is valid.
func (t *Token) Valid() bool {
	if !t.validated {
		t.validateTokenV1()
	}
	return len(t.errs) == 0
}

// Errs returns all the validation errors encountered while validating this
// token. If the token is valid, this will be nil.
func (t *Token) Errs() []error {
	if !t.validated {
		t.validateTokenV1()
	}
	return t.errs
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
		Issuer    string `cbor:"1,keyasint"`
		NotBefore int64  `cbor:"5,keyasint"`
		Expires   int64  `cbor:"4,keyasint"`
		CTI       []byte `cbor:"7,keyasint"`
		Claims    Claims `cbor:"vc"`
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
		KeyID:     string(h.Kid),
		Algorithm: h.Alg,
		Issuer:    p.Issuer,
		NotBefore: time.Unix(p.NotBefore, 0),
		Expires:   time.Unix(p.Expires, 0),
		JTI:       jti,
		Claims:    p.Claims,
		Signature: raw.Signature,

		cti:    p.CTI,
		digest: digest[:],
	}, nil
}

func (t *Token) validateTokenV1() {
	if t.Algorithm != -7 {
		t.errs = append(t.errs,
			fmt.Errorf("%w: expected -7, got %d", ErrInvalidSigningAlgorithm, t.Algorithm))
	}

	if _, ok := trustedIssuers[t.Issuer]; !ok {
		t.errs = append(t.errs,
			fmt.Errorf("%w: got '%s'", ErrUntrustedIssuer, t.Issuer))
	}

	// verify signature
	keyID := t.Issuer + "#" + t.KeyID
	key, ok := keys[keyID]
	if !ok {
		// TODO retrieve?
		t.errs = append(t.errs,
			fmt.Errorf("%w: got '%s'", ErrUnknownPublicKey, keyID))
	} else if key != nil {
		if !ecdsa.Verify(
			keys[keyID],
			t.digest,
			big.NewInt(0).SetBytes(t.Signature[:32]),
			big.NewInt(0).SetBytes(t.Signature[32:])) {
			t.errs = append(t.errs,
				fmt.Errorf("%w: did not verify", ErrBadSignature))
		}
	}

	// timestamps
	now := time.Now()
	if now.Before(t.NotBefore) {
		t.errs = append(t.errs,
			fmt.Errorf("%w (nbf: %v)", ErrTokenNotActive, t.NotBefore))
	}
	if now.After(t.Expires) {
		t.errs = append(t.errs,
			fmt.Errorf("%w (exp: %v)", ErrTokenExpired, t.Expires))
	}

	// cti/jti: any non-zero uuid is valid
	nilUUID := [16]byte{}
	if len(t.cti) != 16 || bytes.Equal(t.cti, nilUUID[:]) {
		t.errs = append(t.errs,
			fmt.Errorf("%w: got '%x'", ErrInvalidCTI, t.cti))
	}

	// claims
	if len(t.Claims.Context) < 1 ||
		t.Claims.Context[0] != "https://www.w3.org/2018/credentials/v1" {
		t.errs = append(t.errs,
			fmt.Errorf("%w: @context[0] must be '%s' (got: %s)",
				ErrInvalidClaimsContext,
				"https://www.w3.org/2018/credentials/v1",
				t.Claims.Context[0]))
	}
	containsNZCPContext := false
	for _, c := range t.Claims.Context {
		if c == "https://nzcp.covid19.health.nz/contexts/v1" {
			containsNZCPContext = true
			break
		}
	}
	if !containsNZCPContext {
		t.errs = append(t.errs,
			fmt.Errorf("%w: missing NZCP context '%s'",
				ErrInvalidClaimsContext,
				"https://nzcp.covid19.health.nz/contexts/v1"))
	}

	// pass type
	if len(t.Claims.Type) != 2 ||
		t.Claims.Type[0] != "VerifiableCredential" ||
		t.Claims.Type[1] != "PublicCovidPass" {
		t.errs = append(t.errs,
			fmt.Errorf("%w: type must be %v (got: %v)",
				ErrInvalidClaimsType,
				[]string{"VerifiableCredential", "PublicCovidPass"},
				t.Claims.Type))
	}

	// version
	if t.Claims.Version != "1.0.0" {
		t.errs = append(t.errs,
			fmt.Errorf("%w: token version must be 1.0.0 (got: '%s')",
				ErrInvalidTokenVersion,
				t.Claims.Version))
	}

	t.validated = true
}
