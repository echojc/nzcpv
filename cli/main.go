package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/echojc/nzcpv"
)

func main() {
	r := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Scan QR code> ")
		qr, err := r.ReadString('\n')
		if err != nil {
			log.Fatal("Failed to read input.")
		}

		tkn, err := nzcpv.NewToken(qr)
		if err != nil {
			fmt.Println("Failed to read QR code:")
			fmt.Printf("> %v\n", err)
			continue
		}

		fmt.Println()
		fmt.Printf("Given name:    %s\n",
			tkn.VerifiableCredential.CredentialSubject.GivenName)
		fmt.Printf("Family name:   %s\n",
			tkn.VerifiableCredential.CredentialSubject.FamilyName)
		fmt.Printf("Date of birth: %v\n",
			tkn.VerifiableCredential.CredentialSubject.DOB)
		fmt.Printf("Valid between: %s to %s\n",
			tkn.NotBefore.Format("2006-01-02"), tkn.Expires.Format("2006-01-02"))

		fmt.Println()
		fmt.Printf("Pass ID:     %s\n", tkn.JTI)
		fmt.Printf("Signing key: %s#%s\n", tkn.Issuer, tkn.KeyID)
		fmt.Printf("Signature:   %s\n",
			base64.RawStdEncoding.EncodeToString(tkn.Signature))

		fmt.Println()
		fmt.Printf("Validation: ")

		errs := nzcpv.ValidateToken(tkn)
		if errs == nil {
			fmt.Println("PASS")
		} else {
			fmt.Println("FAIL")
			for _, err := range errs {
				fmt.Printf("> %v\n", err)
			}
		}

		fmt.Println()
	}
}
