package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BaesBlockchainLabs/logalsend-go/xmldsig"
	"github.com/beevik/etree"
)

// fixedTime pins the assertion timestamps so generated documents are
// byte-for-byte reproducible across runs.
var fixedTime = time.Date(2026, 9, 11, 18, 33, 2, 552_000_000, time.FixedZone("CEST", 2*60*60))

func testGenerator(t *testing.T) *Generator {
	t.Helper()
	keystore, err := LoadKeystoreFile("testdata/test-logalty-private.pfx", "111111")
	if err != nil {
		t.Fatalf("load keystore: %v", err)
	}
	g := NewGenerator(keystore)
	g.now = func() time.Time { return fixedTime }
	return g
}

// fullConfig mirrors the configuration the Java reference harness uses, so the
// two implementations can be diffed directly.
func fullConfig() Config {
	return Config{
		ClientURL:    "www.logalty.es",
		Login:        "jaumepallares",
		FullName:     "Jaume Pallares",
		Password:     "1a35d9##",
		Mail:         "example@logalty.com",
		Role:         RoleAdmin,
		Group:        Int(1),
		Companies:    []int{311},
		Position:     "position",
		EmailAlerts:  Bool(true),
		ReadersGroup: []int{1, 2},
	}
}

// TestSignatureVerifies is the end-to-end check: take the generated document,
// re-parse it the way the portal would, and confirm both that the reference
// digest covers the assertion and that the signature covers SignedInfo.
func TestSignatureVerifies(t *testing.T) {
	xml, err := testGenerator(t).Generate(fullConfig())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	doc, err := xmldsig.ParseDocument([]byte(xml))
	if err != nil {
		t.Fatalf("generated document does not parse: %v\n%s", err, xml)
	}
	root := doc.Root()

	digest := sha1.Sum(xmldsig.Canonicalize(root, xmldsig.IsSignature))
	wantDigest := text(t, root, "Signature/SignedInfo/Reference/DigestValue")
	if got := base64.StdEncoding.EncodeToString(digest[:]); got != wantDigest {
		t.Errorf("DigestValue does not cover the assertion\n got: %s\nwant: %s", got, wantDigest)
	}

	signedInfo := find(root, "Signature/SignedInfo")
	if signedInfo == nil {
		t.Fatal("no SignedInfo in generated document")
	}
	signedInfoDigest := sha1.Sum(xmldsig.Canonicalize(signedInfo, nil))

	cert, err := x509.ParseCertificate(unbase64(t, text(t, root, "Signature/KeyInfo/X509Data/X509Certificate")))
	if err != nil {
		t.Fatalf("parse embedded certificate: %v", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("embedded certificate holds a %T", cert.PublicKey)
	}

	sig := unbase64(t, text(t, root, "Signature/SignatureValue"))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, signedInfoDigest[:], sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

// TestSignatureCoversContent confirms the digest is not vacuous: tampering with
// any attribute value must break verification.
func TestSignatureCoversContent(t *testing.T) {
	xml, err := testGenerator(t).Generate(fullConfig())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	tampered := strings.Replace(xml, "Administrator", "ReadOnly___", 1)
	if tampered == xml {
		t.Fatal("test is not tampering with anything")
	}

	doc, err := xmldsig.ParseDocument([]byte(tampered))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	digest := sha1.Sum(xmldsig.Canonicalize(doc.Root(), xmldsig.IsSignature))
	got := base64.StdEncoding.EncodeToString(digest[:])
	if want := text(t, doc.Root(), "Signature/SignedInfo/Reference/DigestValue"); got == want {
		t.Error("digest still matches after the role was changed")
	}
}

// TestStructureMatchesJava pins the document shape against the Java SDK's
// output, including the quirks that were kept on purpose.
func TestStructureMatchesJava(t *testing.T) {
	xml, err := testGenerator(t).Generate(fullConfig())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	for _, want := range []string{
		`ID="ass00000000002"`,
		`IssueInstant="2026-09-11T18:33:02.552+02:00"`,
		`NotOnOrAfter="2026-09-11T19:03:02.552+02:00"`,
		// AuthnContextClassRef beside, not inside, an empty AuthnContext.
		"<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\n    <saml:AuthnContext/>",
		// The mixed-prefix signature block.
		`<Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns="http://www.w3.org/2000/09/xmldsig#">`,
		"<SignedInfo>",
		`<ds:Reference URI="">`,
		"<ds:KeyInfo>",
		// Integer lists are semicolon-separated.
		"<saml:AttributeValue>1;2</saml:AttributeValue>",
	} {
		if !strings.Contains(xml, want) {
			t.Errorf("generated document is missing:\n%s", want)
		}
	}

	if strings.HasPrefix(xml, "<?xml") {
		t.Error("generated document must not carry an XML declaration")
	}
}

// TestLoginAssertionOmitsOptionalAttributes checks that a bare login assertion
// carries only the login attribute.
func TestLoginAssertionOmitsOptionalAttributes(t *testing.T) {
	g := testGenerator(t)
	xml, err := g.Generate(Config{ClientURL: "www.logalty.es", Login: "someone"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if got := strings.Count(xml, "<saml:Attribute "); got != 1 {
		t.Errorf("got %d attributes, want only the login one", got)
	}
	for _, absent := range []string{"attributes:password", "attributes:group", "attributes:companies"} {
		if strings.Contains(xml, absent) {
			t.Errorf("login assertion should not carry %s", absent)
		}
	}
}

// TestCarriageReturnSurvivesRoundTrip is a regression guard. A CR written
// literally would be folded into a LF by the portal's parser and the digest
// would no longer match, so it must be escaped as a character reference.
func TestCarriageReturnSurvivesRoundTrip(t *testing.T) {
	g := testGenerator(t)
	xml, err := g.Generate(Config{
		ClientURL: "www.logalty.es",
		Login:     "someone",
		FullName:  "Line\r\nBreak",
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if strings.Contains(xml, "Line\r\n") {
		t.Error("carriage return was emitted literally")
	}

	doc, err := xmldsig.ParseDocument([]byte(xml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	digest := sha1.Sum(xmldsig.Canonicalize(doc.Root(), xmldsig.IsSignature))
	got := base64.StdEncoding.EncodeToString(digest[:])
	if want := text(t, doc.Root(), "Signature/SignedInfo/Reference/DigestValue"); got != want {
		t.Errorf("digest breaks on a value containing CRLF\n got: %s\nwant: %s", got, want)
	}
}

func TestValidation(t *testing.T) {
	g := testGenerator(t)

	tests := []struct {
		name   string
		config Config
		ok     bool
	}{
		{"login only", Config{ClientURL: "u", Login: "l"}, true},
		{"no login", Config{ClientURL: "u"}, false},
		{"blank login", Config{ClientURL: "u", Login: "   "}, false},
		{"no client url", Config{Login: "l"}, false},
		{"strict, incomplete", Config{ClientURL: "u", Login: "l", Validate: true}, false},
		{"strict, complete", func() Config {
			c := fullConfig()
			c.Validate = true
			return c
		}(), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := g.Generate(tt.config)
			if tt.ok && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Error("expected a validation error")
			}
		})
	}
}

func TestURLEncode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"abcXYZ019", "abcXYZ019"},
		{"a b", "a+b"},
		{"-_.!~*'()", "-_.!~*'()"},
		{"<saml:Assertion>", "%3Csaml%3AAssertion%3E"},
		{`a="b"`, "a%3D%22b%22"},
		{"\n", "%0A"},
		// Latin-1 goes out as a single byte, not as UTF-8 percent pairs.
		{"á", "%E1"},
		// Anything above U+00FF is dropped, exactly as the Java encoder does.
		{"a€b", "ab"},
		{"a😀b", "ab"},
	}
	for _, tt := range tests {
		if got := urlEncode(tt.in); got != tt.want {
			t.Errorf("urlEncode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestGenerateEncodedIsDecodable checks the encoded form round-trips back to
// the XML for the ASCII documents this SDK actually produces.
func TestGenerateEncodedIsDecodable(t *testing.T) {
	g := testGenerator(t)
	config := fullConfig()

	xml, err := g.Generate(config)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	encoded, err := g.GenerateEncoded(config)
	if err != nil {
		t.Fatalf("generate encoded: %v", err)
	}

	decoded := strings.Builder{}
	for i := 0; i < len(encoded); i++ {
		switch encoded[i] {
		case '+':
			decoded.WriteByte(' ')
		case '%':
			b, err := strconv.ParseUint(encoded[i+1:i+3], 16, 8)
			if err != nil {
				t.Fatalf("bad escape at %d: %v", i, err)
			}
			decoded.WriteByte(byte(b))
			i += 2
		default:
			decoded.WriteByte(encoded[i])
		}
	}
	if decoded.String() != xml {
		t.Error("encoded form does not decode back to the generated XML")
	}
}

// writeGoldenForJava dumps a generated assertion for the Java verifier used by
// the cross-check script. It is skipped unless LOGALTY_WRITE_GOLDEN is set.
func TestWriteGoldenForJava(t *testing.T) {
	path := os.Getenv("LOGALTY_WRITE_GOLDEN")
	if path == "" {
		t.Skip("set LOGALTY_WRITE_GOLDEN to a path to dump a Go-signed assertion")
	}
	xml, err := testGenerator(t).Generate(fullConfig())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := os.WriteFile(path, []byte(xml), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func find(el *etree.Element, path string) *etree.Element {
	for _, name := range strings.Split(path, "/") {
		var next *etree.Element
		for _, child := range el.ChildElements() {
			if child.Tag == name {
				next = child
				break
			}
		}
		if next == nil {
			return nil
		}
		el = next
	}
	return el
}

func text(t *testing.T, root *etree.Element, path string) string {
	t.Helper()
	el := find(root, path)
	if el == nil {
		t.Fatalf("no %s in document", path)
	}
	return el.Text()
}

func unbase64(t *testing.T, s string) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(regexp.MustCompile(`\s`).ReplaceAllString(s, ""))
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return out
}
