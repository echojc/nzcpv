package nzcpv_test

import (
	"encoding/json"
	"fmt"

	"github.com/echojc/nzcpv"
)

func ExampleNewToken() {
	q := "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX"

	t, err := nzcpv.NewToken(q)
	if err != nil {
		fmt.Println(err)
		return
	}

	// pretty print
	s, _ := json.MarshalIndent(t, "", "  ")
	fmt.Println(string(s))
	// Output:
	// {
	//   "KeyID": "key-1",
	//   "Algorithm": -7,
	//   "Issuer": "did:web:nzcp.covid19.health.nz",
	//   "NotBefore": "2021-11-03T09:05:30+13:00",
	//   "Expires": "2031-11-03T09:05:30+13:00",
	//   "JTI": "urn:uuid:60a4f54d-4e30-4332-be33-ad78b1eafa4b",
	//   "VerifiableCredential": {
	//     "Context": [
	//       "https://www.w3.org/2018/credentials/v1",
	//       "https://nzcp.covid19.health.nz/contexts/v1"
	//     ],
	//     "Version": "1.0.0",
	//     "Type": [
	//       "VerifiableCredential",
	//       "PublicCovidPass"
	//     ],
	//     "CredentialSubject": {
	//       "GivenName": "Jack",
	//       "FamilyName": "Sparrow",
	//       "DOB": "1960-04-16"
	//     }
	//   },
	//   "Signature": "0uB7HdcmPYMxZr27TxoJODepBdfsou6Da2sq2iPCMVT7qIpSn2ddZobuYysJ7FgasI9ytFiQS7M5bRD6ZtEUdw=="
	// }
}
