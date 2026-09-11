package saml_test

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/BaesBlockchainLabs/logalsend-go/saml"
)

// Signing an existing user in to the portal: build the assertion, then post it
// to the portal's SAML endpoint.
func ExampleGenerator_Login() {
	keystore, err := saml.LoadKeystoreFile("/etc/logalty/client.pfx", "keystore-password")
	if err != nil {
		log.Fatal(err)
	}

	assertion, err := saml.NewGenerator(keystore).Login("www.example.com", "jsmith")
	if err != nil {
		log.Fatal(err)
	}

	// The portal takes the assertion by POST, in a form field, not in a query
	// string. Serve this page to the user's browser and it carries them in.
	fmt.Println(saml.SignInFormHTML("https://www.demo.logalty.es/lgt/frontendweb", assertion))
}

// Provisioning a user on their first sign-in: the extra attributes create the
// account if it does not exist yet.
func ExampleGenerator_Generate() {
	keystore, err := saml.LoadKeystoreFile("/etc/logalty/client.pfx", "keystore-password")
	if err != nil {
		log.Fatal(err)
	}

	assertion, err := saml.NewGenerator(keystore).GenerateEncoded(saml.Config{
		ClientURL: "www.example.com",
		Login:     "jsmith",
		FullName:  "J. Smith",
		Mail:      "jsmith@example.com",
		Password:  "initial-password",
		Role:      saml.RoleManager,
		Group:     saml.Int(1),
		Companies: []int{311},

		// Validate makes the generator insist that every provisioning field
		// above is present, instead of quietly emitting a partial assertion.
		Validate: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// To sign in from code rather than from a browser, post the form yourself.
	// The assertion keeps Logalty's own percent-encoding and the form encoding
	// goes on top; the portal unwraps both.
	target, body := saml.SignInForm("https://www.demo.logalty.es/lgt/frontendweb", assertion)
	resp, err := http.Post(target, "application/x-www-form-urlencoded", strings.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)
}
