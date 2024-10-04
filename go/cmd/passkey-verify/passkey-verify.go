package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/BeyondCodeBootcamp/vanilla-webauthn/go/passkey"
)

func getPreviouslyStoredChallenge(assertionResp *passkey.Assertion) (string, error) {
	// for the demo we just use the requests own challenge
	return assertionResp.Response.ClientData.Challenge, nil
}

type CredentialIDString = string
type ChallengeString = string

func main() {
	challengeDB := map[CredentialIDString]bool{}
	regDB := map[ChallengeString]*passkey.Registration{}

	var debug bool
	flag.BoolVar(&debug, "debug", false, "show fully parsed credential request")
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 {
		log.Fatalf("Usage: %s <./fixtures/01-create.json> <./fixtures/01-request.json>", os.Args[0])
	}

	attestationFile := args[0]
	assertionFile := args[1]

	fmt.Println()
	{
		// CHALLENGE would be created BEFORE getting the registration response

		fmt.Printf(
			"[Registration] Credential Creation Fixture (01): \n\t\t%s\n",
			filepath.Base(attestationFile),
		)

		credentialCreationResponse, err := os.ReadFile(attestationFile)
		if err != nil {
			log.Fatalf("Failed to read attestation file: %v", err)
		}
		registration, err := passkey.ParseRegistration(credentialCreationResponse)
		if err != nil {
			log.Fatalf("Could not decode Credential Registraiton: %v", err)
		}

		fmt.Println("[Registration] Credential ID:", registration.ID)
		if debug {
			fmt.Printf("\n%#+v\n", registration)
		}

		challengeWeWouldCreateAbove := registration.Response.ClientData.Challenge
		challengeDB[challengeWeWouldCreateAbove] = true

		if _, ok := challengeDB[registration.Response.ClientData.Challenge]; !ok {
			log.Fatalf("Challenge was not found in db, Registration rejected")
		}
		delete(challengeDB, challengeWeWouldCreateAbove)

		regDB[registration.ID] = registration
	}

	var assertion *passkey.Assertion
	fmt.Println()
	{
		// CHALLENGE would be created BEFORE getting the authenticator response

		fmt.Printf(
			"[Assertion] Credential Request Fixture (02): \n\t\t%s\n",
			filepath.Base(assertionFile),
		)

		credentialRequestResponse, err := os.ReadFile(assertionFile)
		if err != nil {
			log.Fatalf("Failed to read assertion file: %v", err)
		}
		assertion, err = passkey.ParseAssertion(credentialRequestResponse)
		if err != nil {
			log.Fatalf("Could not decode Credential Request: %v", err)
		}

		fmt.Println("[Assertion] Credential ID:", assertion.ID)
		if debug {
			fmt.Printf("\n%#+v\n", assertion)
		}

		challengeWeWouldCreateAbove := assertion.Response.ClientData.Challenge
		challengeDB[challengeWeWouldCreateAbove] = true
	}

	{
		originalChallenge := assertion.Response.ClientData.Challenge
		if _, ok := challengeDB[originalChallenge]; !ok {
			log.Fatalf("Challenge was not found in db, Assertion rejected")
		}
		delete(challengeDB, originalChallenge)

		registration, ok := regDB[assertion.ID]
		if !ok {
			log.Fatalf("passkey has been deleted from user's account")
		}

		trustedOrigin := "https://local.pocketid.app"
		fmt.Println()
		fmt.Println("Origin:", assertion.Response.ClientData.Origin)
		if assertion.Response.ClientData.Origin != trustedOrigin {
			log.Fatalf("assertion origin expected to be %q but got %q", trustedOrigin, assertion.Response.ClientData.Origin)
		}

		fmt.Println("Count:", assertion.Response.AuthenticatorData.SignCount)
		fmt.Println("Flags:", assertion.Response.AuthenticatorData.Flags)

		// TODO decode CBOR data

		message := sha256.Sum256(assertion.Response.AttToBeSigned)
		verified := ecdsa.VerifyASN1(
			registration.Response.PublicKeyECDSA,
			message[:],
			assertion.Response.Signature,
		)
		if !verified {
			log.Fatalf("Could not verify signature bytes")
		}
		fmt.Println()
		fmt.Println("Verified:", verified)
	}

	fmt.Println()
}
