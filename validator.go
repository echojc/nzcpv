package nzcpv

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	defaultKeys = map[string]*ecdsa.PublicKey{
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

	defaultTrustedIssuers = map[string]struct{}{
		"did:web:nzcp.identity.health.nz": struct{}{},
	}
)

var (
	defaultValidator = NewValidator()
)

var (
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

// Validator is a struct that holds a list of trusted issuers and keys for
// validating tokens. The zero-value is NOT usable. Use NewValidator() instead.
type Validator struct {
	keys           map[string]*ecdsa.PublicKey
	trustedIssuers map[string]struct{}
}

// NewValidator creates a token validator to which non-trusted issuers and
// public keys can be added. This is intended for testing purposes only. To
// ensure compliance to the specification, the default validator should be
// used instead via the ValidateToken() function.
func NewValidator() *Validator {
	v := &Validator{
		keys:           map[string]*ecdsa.PublicKey{},
		trustedIssuers: map[string]struct{}{},
	}
	for id, key := range defaultKeys {
		v.keys[id] = key
	}
	for iss := range defaultTrustedIssuers {
		v.trustedIssuers[iss] = struct{}{}
	}
	return v
}

// ValidateToken validates token t only accepting the trusted issuers in the
// official specification. If the token is invalid, a slice of all validation
// errors is returned. Otherwise, nil is returned.
func ValidateToken(t *Token) []error {
	return defaultValidator.validateTokenV1(t)
}

// ValidateToken validates token t according to the configuration of the
// Validator. If the token is invalid, a slice of all validation errors is
// returned. Otherwise, nil is returned.
func (v *Validator) ValidateToken(t *Token) []error {
	return v.validateTokenV1(t)
}

func (v *Validator) validateTokenV1(t *Token) (errs []error) {
	if t.Algorithm != -7 {
		errs = append(errs,
			fmt.Errorf("%w: expected -7, got %d",
				ErrInvalidSigningAlgorithm, t.Algorithm))
	}

	if _, ok := v.trustedIssuers[t.Issuer]; !ok {
		errs = append(errs,
			fmt.Errorf("%w: got '%s'", ErrUntrustedIssuer, t.Issuer))
	}

	// verify signature
	keyID := t.Issuer + "#" + t.KeyID
	key, ok := v.keys[keyID]
	if !ok {
		// TODO retrieve?
		errs = append(errs,
			fmt.Errorf("%w: got '%s'", ErrUnknownPublicKey, keyID))
	} else if key != nil {
		if !ecdsa.Verify(
			key,
			t.digest,
			big.NewInt(0).SetBytes(t.Signature[:32]),
			big.NewInt(0).SetBytes(t.Signature[32:])) {
			errs = append(errs,
				fmt.Errorf("%w: did not verify", ErrBadSignature))
		}
	}

	// timestamps
	now := time.Now()
	if now.Before(t.NotBefore) {
		errs = append(errs,
			fmt.Errorf("%w (nbf: %v)", ErrTokenNotActive, t.NotBefore))
	}
	if now.After(t.Expires) {
		errs = append(errs,
			fmt.Errorf("%w (exp: %v)", ErrTokenExpired, t.Expires))
	}

	// cti/jti: any non-zero uuid is valid
	nilUUID := [16]byte{}
	if len(t.cti) != 16 || bytes.Equal(t.cti, nilUUID[:]) {
		errs = append(errs,
			fmt.Errorf("%w: got '%x'", ErrInvalidCTI, t.cti))
	}

	// claims
	vcContext := "https://www.w3.org/2018/credentials/v1"
	if len(t.VerifiableCredential.Context) < 1 ||
		t.VerifiableCredential.Context[0] != vcContext {
		errs = append(errs,
			fmt.Errorf("%w: @context[0] must be '%s' (got: %s)",
				ErrInvalidClaimsContext, vcContext,
				t.VerifiableCredential.Context[0]))
	}
	nzcpContext := "https://nzcp.covid19.health.nz/contexts/v1"
	containsNZCPContext := false
	for _, c := range t.VerifiableCredential.Context {
		if c == nzcpContext {
			containsNZCPContext = true
			break
		}
	}
	if !containsNZCPContext {
		errs = append(errs,
			fmt.Errorf("%w: missing NZCP context '%s'",
				ErrInvalidClaimsContext, nzcpContext))
	}

	// pass type
	if len(t.VerifiableCredential.Type) != 2 ||
		t.VerifiableCredential.Type[0] != "VerifiableCredential" ||
		t.VerifiableCredential.Type[1] != "PublicCovidPass" {
		errs = append(errs,
			fmt.Errorf("%w: type must be %v (got: %v)",
				ErrInvalidClaimsType,
				[]string{"VerifiableCredential", "PublicCovidPass"},
				t.VerifiableCredential.Type))
	}

	// version
	if t.VerifiableCredential.Version != "1.0.0" {
		errs = append(errs,
			fmt.Errorf("%w: token version must be 1.0.0 (got: '%s')",
				ErrInvalidTokenVersion,
				t.VerifiableCredential.Version))
	}

	return errs
}

// RegisterIssuer instructs the validator to treat iss as a valid issuer for
// NZCPs. This is intended for testing purposes only.
func (v *Validator) RegisterIssuer(iss string) {
	v.trustedIssuers[iss] = struct{}{}
}

// RegisterPublicKey instructs the validator to treat id and its associated
// public key as valid for NZCPs. This is intended for testing purposes only.
func (v *Validator) RegisterPublicKey(id string, pub *ecdsa.PublicKey) error {
	if _, ok := v.keys[id]; ok {
		return errors.New("Cannot overwrite existing public key; " +
			"use a new instance instead.")
	}
	v.keys[id] = pub
	return nil
}
