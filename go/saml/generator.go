package saml

import (
	"fmt"
	"time"

	"github.com/BaesBlockchainLabs/logalsend-go/xmldsig"
)

// Generator builds signed SAML assertions with a fixed keystore.
//
// The zero value is not usable; construct one with NewGenerator.
type Generator struct {
	keystore Keystore

	// now is overridable so tests can pin the assertion's timestamps.
	now func() time.Time
}

// NewGenerator returns a Generator that signs with the given keystore.
func NewGenerator(keystore Keystore) *Generator {
	return &Generator{keystore: keystore, now: time.Now}
}

// Generate returns the signed assertion as XML, without URL encoding. Use it
// when you are embedding the assertion somewhere that is not a URL, such as a
// form field you encode yourself.
func (g *Generator) Generate(c Config) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}

	signer := xmldsig.EnvelopedSigner{
		Key:         g.keystore.Key,
		Certificate: g.keystore.Certificate,
	}
	signed, err := signer.Sign([]byte(renderAssertion(c, g.now())))
	if err != nil {
		return "", fmt.Errorf("saml: sign assertion: %w", err)
	}
	return string(signed), nil
}

// GenerateEncoded returns the signed assertion URL-encoded, ready to be used as
// a query-string value. This is what the Java SDK's
// SamlGenerator.buildSamlDocument returns by default.
func (g *Generator) GenerateEncoded(c Config) (string, error) {
	xml, err := g.Generate(c)
	if err != nil {
		return "", err
	}
	return urlEncode(xml), nil
}

// Login builds the minimal assertion that signs an existing user in. It is the
// equivalent of the Java SamlGenerator.buildLoginSaml.
func (g *Generator) Login(clientURL, login string) (string, error) {
	return g.GenerateEncoded(Config{ClientURL: clientURL, Login: login})
}
