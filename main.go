package main

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/fxamacker/cbor"
)

type Token struct {
	Header    Header
	Payload   Payload
	Signature []byte
}

type Header struct {
	KeyID     string
	Algorithm int
}

type Payload struct {
	Issuer    string
	NotBefore time.Time
	Expires   time.Time
	JTI       string
	Claims    Claims
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

func main() {
	q := "2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX"

	data, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(q)
	if err != nil {
		log.Fatal(err)
	}

	t, err := Decode(data)
	if err != nil {
		log.Fatal(err)
	}

	s, _ := json.MarshalIndent(t, "", "  ")
	fmt.Println(string(s))
}

func Decode(data []byte) (Token, error) {

	var raw struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected cbor.RawMessage
		Payload     []byte
		Signature   []byte
	}
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return Token{}, err
	}

	var ph struct {
		Kid []byte `cbor:"4,keyasint"`
		Alg int    `cbor:"1,keyasint"`
	}
	if err := cbor.Unmarshal(raw.Protected, &ph); err != nil {
		return Token{}, err
	}

	var p struct {
		Issuer    string `cbor:"1,keyasint"`
		NotBefore int64  `cbor:"5,keyasint"`
		Expires   int64  `cbor:"4,keyasint"`
		JTI       []byte `cbor:"7,keyasint"`
		Claims    Claims `cbor:"vc"`
	}
	if err := cbor.Unmarshal(raw.Payload, &p); err != nil {
		return Token{}, err
	}

	return Token{
		Header: Header{
			KeyID:     string(ph.Kid),
			Algorithm: ph.Alg,
		},
		Payload: Payload{
			Issuer:    p.Issuer,
			NotBefore: time.Unix(p.NotBefore, 0),
			Expires:   time.Unix(p.Expires, 0),
			JTI:       fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", p.JTI[0:4], p.JTI[4:6], p.JTI[6:8], p.JTI[8:10], p.JTI[10:16]),
			Claims:    p.Claims,
		},
		Signature: raw.Signature,
	}, nil
}
