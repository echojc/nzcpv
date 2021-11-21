package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/fxamacker/cbor"
)

// https://nzcp.covid19.health.nz

type Token struct {
	Header    Header
	Payload   Payload
	Signature []byte

	sig_structure []byte
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

var keys = map[string]*ecdsa.PublicKey{
	"did:web:nzcp.covid19.health.nz#key-1": &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X: big.NewInt(0).SetBytes([]byte{
			205, 20, 126, 92, 107, 2, 167, 93,
			149, 189, 184, 46, 139, 128, 195, 232,
			238, 156, 170, 104, 95, 62, 229, 204,
			134, 45, 78, 196, 249, 124, 239, 173,
		}),
		Y: big.NewInt(0).SetBytes([]byte{
			34, 254, 82, 83, 161, 110, 91, 228,
			209, 98, 30, 127, 24, 234, 201, 149,
			197, 127, 130, 145, 127, 26, 145, 80,
			132, 35, 131, 240, 180, 164, 221, 61,
		}),
	},
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

	fmt.Println(t.Verify())
}

func (t *Token) Verify() bool {
	key := t.Payload.Issuer + "#" + t.Header.KeyID
	digest := sha256.Sum256(t.sig_structure)

	return ecdsa.Verify(
		keys[key],
		digest[:],
		big.NewInt(0).SetBytes(t.Signature[:32]),
		big.NewInt(0).SetBytes(t.Signature[32:]))
}

func Decode(data []byte) (*Token, error) {

	var raw struct {
		_           struct{} `cbor:",toarray"`
		Protected   cbor.RawMessage
		Unprotected cbor.RawMessage
		Payload     cbor.RawMessage
		Signature   []byte
	}
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	ss := bytes.Buffer{}
	ss.Write([]byte{0x84, 0x6a})
	ss.WriteString("Signature1")
	ss.Write(raw.Protected)
	ss.WriteByte(0x40)
	ss.Write(raw.Payload)

	var ph_b []byte
	if err := cbor.Unmarshal(raw.Protected, &ph_b); err != nil {
		return nil, err
	}
	var ph struct {
		Kid []byte `cbor:"4,keyasint"`
		Alg int    `cbor:"1,keyasint"`
	}
	if err := cbor.Unmarshal(ph_b, &ph); err != nil {
		return nil, err
	}

	var p_b []byte
	if err := cbor.Unmarshal(raw.Payload, &p_b); err != nil {
		return nil, err
	}
	var p struct {
		Issuer    string `cbor:"1,keyasint"`
		NotBefore int64  `cbor:"5,keyasint"`
		Expires   int64  `cbor:"4,keyasint"`
		JTI       []byte `cbor:"7,keyasint"`
		Claims    Claims `cbor:"vc"`
	}
	if err := cbor.Unmarshal(p_b, &p); err != nil {
		return nil, err
	}

	return &Token{
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
		Signature:     raw.Signature,
		sig_structure: ss.Bytes(),
	}, nil
}

//func main() {
//	_x := "zRR-XGsCp12Vvbgui4DD6O6cqmhfPuXMhi1OxPl8760"
//	_y := "Iv5SU6FuW-TRYh5_GOrJlcV_gpF_GpFQhCOD8LSk3T0"
//
//	xb := make([]byte, 32)
//	yb := make([]byte, 32)
//	_, err := base64.URLEncoding.WithPadding(base64.NoPadding).Decode(xb, []byte(_x))
//	if err != nil {
//		log.Fatal(err)
//	}
//	_, err = base64.URLEncoding.WithPadding(base64.NoPadding).Decode(yb, []byte(_y))
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	x := big.Int{}
//	x.SetBytes(xb)
//	fmt.Printf("%v\n", xb)
//
//	y := big.Int{}
//	y.SetBytes(yb)
//	fmt.Printf("%v\n", yb)
//
//	pub := ecdsa.PublicKey{}
//	pub.Curve = elliptic.P256()
//	pub.X = &x
//	pub.Y = &y
//
//	fmt.Printf("%+v\n", pub)
//
//	//msg, err := hex.DecodeString("a2012603004054546869732069732074686520636f6e74656e742e")
//	//if err != nil {
//	//	log.Fatal(err)
//	//}
//	//fmt.Printf("[% x]\n", msg)
//
//	//tohash := append([]byte("Signature1"), msg...)
//	tohash, err := hex.DecodeString("846A5369676E6174757265314AA204456B65792D3101264059011FA501781E6469643A7765623A6E7A63702E636F76696431392E6865616C74682E6E7A051A61819A0A041A7450400A627663A46840636F6E7465787482782668747470733A2F2F7777772E77332E6F72672F323031382F63726564656E7469616C732F7631782A68747470733A2F2F6E7A63702E636F76696431392E6865616C74682E6E7A2F636F6E74657874732F76316776657273696F6E65312E302E306474797065827456657269666961626C6543726564656E7469616C6F5075626C6963436F766964506173737163726564656E7469616C5375626A656374A369676976656E4E616D65644A61636B6A66616D696C794E616D656753706172726F7763646F626A313936302D30342D3136075060A4F54D4E304332BE33AD78B1EAFA4B")
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("[% x]\n", tohash)
//
//	//sha := sha256.New()
//	//sha.Write(tohash)
//	sum := sha256.Sum256(tohash)
//	fmt.Printf("[% x]\n", sum)
//
//	sig, err := hex.DecodeString("d2e07b1dd7263d833166bdbb4f1a093837a905d7eca2ee836b6b2ada23c23154fba88a529f675d6686ee632b09ec581ab08f72b458904bb3396d10fa66d11477")
//	fmt.Printf("[% x]\n", sig)
//
//	r := big.NewInt(0).SetBytes(sig[:32])
//	s := big.NewInt(0).SetBytes(sig[32:])
//	fmt.Println(ecdsa.Verify(&pub, sum[:], r, s))
//}
