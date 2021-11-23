package nzcpv_test

import (
	"testing"

	"github.com/echojc/nzcpv"
)

func TestValidatorRejectsUntrustedToken(t *testing.T) {
	tkn := tokenUntrusted(t)
	expected := []error{nzcpv.ErrUntrustedIssuer, nzcpv.ErrUnknownPublicKey}
	if errs := nzcpv.ValidateToken(tkn); !checkErrors(expected, errs) {
		t.Errorf("Expected %v but got %v", expected, errs)
	}
}

func TestValidatorRejectsUnknownKey(t *testing.T) {
	tkn := tokenUntrusted(t)
	v := nzcpv.NewValidator()
	v.RegisterIssuer(tkn.Issuer)

	expected := []error{nzcpv.ErrUnknownPublicKey}
	if errs := v.ValidateToken(tkn); !checkErrors(expected, errs) {
		t.Errorf("Expected %v but got %v", expected, errs)
	}
}

func TestValidatorRejectsUntrustedIssuer(t *testing.T) {
	tkn := tokenUntrusted(t)
	v := nzcpv.NewValidator()
	err := v.RegisterPublicKey("did:web:nzcp.covid19.health.nz#key-1", testKey1)
	if err != nil {
		t.Errorf("Could not register test key for validator: %v\n", err)
		t.FailNow()
	}

	expected := []error{nzcpv.ErrUntrustedIssuer}
	if errs := v.ValidateToken(tkn); !checkErrors(expected, errs) {
		t.Errorf("Expected %v but got %v", expected, errs)
	}
}

func tokenUntrusted(t *testing.T) *nzcpv.Token {
	qr := "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX"
	tkn, err := nzcpv.NewToken(qr)
	if err != nil {
		t.Errorf("Could not create test token: %v\n", err)
		t.FailNow()
	}
	return tkn
}
