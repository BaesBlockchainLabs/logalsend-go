package xmldsig

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

// The golden file is a signed SAML assertion produced by the original Java SDK
// (lgtweb-sdk 3.9.0) against the bundled test certificate. Its DigestValue and
// SignatureValue were computed by Apache Santuario, so reproducing them proves
// this canonicalizer agrees with the implementation the Logalty servers expect.
const goldenPath = "testdata/java-reference-signed.xml"

func loadGolden(t *testing.T) *etree.Document {
	t.Helper()
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	doc, err := ParseDocument(data)
	if err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	return doc
}

// findLocal walks a slash-separated path of local names, ignoring prefixes.
// The golden file mixes prefixed and unprefixed XMLDSig elements, so matching
// on etree's prefix-sensitive paths would be needlessly fragile here.
func findLocal(el *etree.Element, path string) *etree.Element {
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

func textOf(t *testing.T, root *etree.Element, path string) string {
	t.Helper()
	el := findLocal(root, path)
	if el == nil {
		t.Fatalf("golden file has no %s", path)
	}
	return el.Text()
}

// TestDigestMatchesJava canonicalizes the assertion with the Signature element
// removed — the enveloped-signature transform — and checks the SHA-1 digest
// against the DigestValue Santuario wrote.
func TestDigestMatchesJava(t *testing.T) {
	doc := loadGolden(t)
	root := doc.Root()

	canonical := Canonicalize(root, IsSignature)
	sum := sha1.Sum(canonical)
	got := base64.StdEncoding.EncodeToString(sum[:])

	want := textOf(t, root, "Signature/SignedInfo/Reference/DigestValue")
	if got != want {
		t.Errorf("digest mismatch\n got: %s\nwant: %s\ncanonical form was:\n%s", got, want, canonical)
	}
}

// TestSignedInfoCanonicalizationMatchesJava verifies the RSA-SHA1 signature
// over the canonicalized SignedInfo. This is the stricter of the two checks:
// SignedInfo is a subtree, so it only verifies if the apex element picks up
// every namespace inherited from its ancestors, as inclusive c14n requires.
func TestSignedInfoCanonicalizationMatchesJava(t *testing.T) {
	doc := loadGolden(t)
	root := doc.Root()

	signedInfo := findLocal(root, "Signature/SignedInfo")
	if signedInfo == nil {
		t.Fatal("golden file has no SignedInfo")
	}

	canonical := Canonicalize(signedInfo, nil)

	// Inclusive canonicalization must pull saml and xsi down from the
	// assertion root even though SignedInfo never mentions them.
	for _, want := range []string{
		`xmlns="http://www.w3.org/2000/09/xmldsig#"`,
		`xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`,
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`,
		`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`,
	} {
		if !strings.Contains(string(canonical), want) {
			t.Errorf("canonical SignedInfo is missing %s\ngot:\n%s", want, canonical)
		}
	}

	certDER := decodeB64(t, textOf(t, root, "Signature/KeyInfo/X509Data/X509Certificate"))
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("certificate holds a %T, want *rsa.PublicKey", cert.PublicKey)
	}

	sum := sha1.Sum(canonical)
	sig := decodeB64(t, textOf(t, root, "Signature/SignatureValue"))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, sum[:], sig); err != nil {
		t.Errorf("Java signature does not verify over our canonical SignedInfo: %v\ncanonical form was:\n%s", err, canonical)
	}
}

// TestCanonicalizeExpandsEmptyElements guards the rule that canonical XML never
// uses the empty-element shorthand, which is easy to lose to a serializer.
func TestCanonicalizeExpandsEmptyElements(t *testing.T) {
	doc, err := ParseDocument([]byte(`<a><b/><c x="1"/></a>`))
	if err != nil {
		t.Fatal(err)
	}
	got := string(Canonicalize(doc.Root(), nil))
	want := `<a><b></b><c x="1"></c></a>`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// TestCanonicalizeSortsAxes checks the two orderings canonical XML mandates:
// namespace declarations by prefix, attributes by namespace URI then local name.
func TestCanonicalizeSortsAxes(t *testing.T) {
	doc, err := ParseDocument([]byte(
		`<r xmlns:z="urn:z" xmlns:a="urn:a" xmlns="urn:d" z:two="2" b="b" a:one="1" a="a"/>`))
	if err != nil {
		t.Fatal(err)
	}
	got := string(Canonicalize(doc.Root(), nil))
	want := `<r xmlns="urn:d" xmlns:a="urn:a" xmlns:z="urn:z" a="a" b="b" a:one="1" z:two="2"></r>`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// TestCanonicalizeEscaping covers the asymmetry between text and attribute
// escaping: '>' is escaped in text but not in attributes, '"' the other way
// round, and whitespace becomes character references only inside attributes.
func TestCanonicalizeEscaping(t *testing.T) {
	doc, err := ParseDocument([]byte(
		"<r a=\"&lt;&amp;&#34;&gt;&#9;&#10;&#13;\">&lt;&amp;&gt;&#34;&#13;\n</r>"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(Canonicalize(doc.Root(), nil))
	want := `<r a="&lt;&amp;&quot;>&#x9;&#xA;&#xD;">&lt;&amp;&gt;"&#xD;` + "\n" + `</r>`
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// TestCanonicalizeSuppressesRedundantDeclarations checks that a namespace is
// only re-declared when it actually changes, and that a reset to no default
// namespace is emitted only when a default was in scope.
func TestCanonicalizeSuppressesRedundantDeclarations(t *testing.T) {
	doc, err := ParseDocument([]byte(
		`<r xmlns:p="urn:p"><a xmlns:p="urn:p"><b xmlns:p="urn:q"/></a><c xmlns=""/></r>`))
	if err != nil {
		t.Fatal(err)
	}
	got := string(Canonicalize(doc.Root(), nil))
	want := `<r xmlns:p="urn:p"><a><b xmlns:p="urn:q"></b></a><c></c></r>`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	stripped := regexp.MustCompile(`\s`).ReplaceAllString(s, "")
	out, err := base64.StdEncoding.DecodeString(stripped)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return out
}
