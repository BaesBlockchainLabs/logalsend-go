package xmldsig

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/beevik/etree"
)

// Digest and signature algorithms this package recognises.
//
// The Logalty portal signs its own XML certificates with RSA-SHA256, while the
// assertions it accepts are RSA-SHA1, so both are needed.
const (
	algDigestSHA256    = "http://www.w3.org/2001/04/xmlenc#sha256"
	algSignatureRSA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
)

// Verified describes a signature that checked out.
type Verified struct {
	// Certificate is the signer's certificate, taken from KeyInfo. Verify
	// proves the document was signed by its private key; it says nothing about
	// whether you should trust that certificate — check the issuer and the
	// validity dates yourself.
	Certificate *x509.Certificate

	// SignatureAlgorithm and DigestAlgorithm are the URIs the document
	// declared, so a caller can reject one it considers too weak.
	SignatureAlgorithm string
	DigestAlgorithm    string
}

// Verify checks the enveloped signature on an XML document.
//
// It is the counterpart of EnvelopedSigner, and it is what lets you confirm
// offline that an XML certificate the portal handed you is authentic and
// unaltered: Logalty signs those with RSA-SHA256 over the same inclusive
// Canonical XML 1.0 that this package already implements.
//
// Both halves are checked, and both matter. The reference digest proves the
// document's content is the content that was signed; the signature proves
// SignedInfo — and therefore that digest — came from the certificate's holder.
// Checking only the signature would leave the content unverified.
//
// Limitations, each reported as an error rather than passed over: only
// inclusive c14n, only a single reference covering the whole document
// (URI="") with the enveloped-signature transform, and only RSA keys.
func Verify(doc []byte) (*Verified, error) {
	parsed, err := ParseDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("xmldsig: parse document: %w", err)
	}
	root := parsed.Root()
	if root == nil {
		return nil, errors.New("xmldsig: document has no root element")
	}

	signature := findSignature(root)
	if signature == nil {
		return nil, errors.New("xmldsig: document carries no signature")
	}
	signedInfo := findChild(signature, "SignedInfo")
	if signedInfo == nil {
		return nil, errors.New("xmldsig: signature has no SignedInfo")
	}

	c14nAlg := algorithmOf(findChild(signedInfo, "CanonicalizationMethod"))
	if c14nAlg != C14NAlgorithm {
		return nil, fmt.Errorf("xmldsig: unsupported canonicalization %q", c14nAlg)
	}
	signatureAlg := algorithmOf(findChild(signedInfo, "SignatureMethod"))
	signatureHash, err := hashFor(signatureAlg, map[string]crypto.Hash{
		algSignatureRSASHA1: crypto.SHA1,
		algSignatureRSA256:  crypto.SHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("xmldsig: signature method: %w", err)
	}

	reference := findChild(signedInfo, "Reference")
	if reference == nil {
		return nil, errors.New("xmldsig: SignedInfo has no Reference")
	}
	if uri := reference.SelectAttrValue("URI", ""); uri != "" {
		return nil, fmt.Errorf("xmldsig: only a whole-document reference is supported, got URI=%q", uri)
	}
	if transform := findChild(findChild(reference, "Transforms"), "Transform"); algorithmOf(transform) != algEnveloped {
		return nil, fmt.Errorf("xmldsig: expected the enveloped-signature transform, got %q", algorithmOf(transform))
	}

	digestAlg := algorithmOf(findChild(reference, "DigestMethod"))
	digestHash, err := hashFor(digestAlg, map[string]crypto.Hash{
		algDigestSHA1:   crypto.SHA1,
		algDigestSHA256: crypto.SHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("xmldsig: digest method: %w", err)
	}

	// The reference digest: the whole document with the signature removed.
	declared, err := decodeBase64(elementText(findChild(reference, "DigestValue")))
	if err != nil {
		return nil, fmt.Errorf("xmldsig: DigestValue: %w", err)
	}
	computed := sum(digestHash, Canonicalize(root, IsSignature))
	if !equal(declared, computed) {
		return nil, errors.New("xmldsig: the document does not match its reference digest — " +
			"it was altered after signing")
	}

	certificate, err := signerCertificate(signature)
	if err != nil {
		return nil, err
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("xmldsig: signer holds a %T, only RSA is supported", certificate.PublicKey)
	}

	signatureValue, err := decodeBase64(elementText(findChild(signature, "SignatureValue")))
	if err != nil {
		return nil, fmt.Errorf("xmldsig: SignatureValue: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(publicKey, signatureHash,
		sum(signatureHash, Canonicalize(signedInfo, nil)), signatureValue); err != nil {
		return nil, fmt.Errorf("xmldsig: signature does not verify: %w", err)
	}

	return &Verified{
		Certificate:        certificate,
		SignatureAlgorithm: signatureAlg,
		DigestAlgorithm:    digestAlg,
	}, nil
}

// findSignature looks for the signature among the root's children, which is
// where an enveloped signature lives.
func findSignature(root *etree.Element) *etree.Element {
	for _, child := range root.ChildElements() {
		if IsSignature(child) {
			return child
		}
	}
	return nil
}

func signerCertificate(signature *etree.Element) (*x509.Certificate, error) {
	element := findChild(findChild(findChild(signature, "KeyInfo"), "X509Data"), "X509Certificate")
	if element == nil {
		return nil, errors.New("xmldsig: no X509Certificate in KeyInfo")
	}
	der, err := decodeBase64(element.Text())
	if err != nil {
		return nil, fmt.Errorf("xmldsig: X509Certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("xmldsig: parse signer certificate: %w", err)
	}
	return certificate, nil
}

func algorithmOf(element *etree.Element) string {
	if element == nil {
		return ""
	}
	return element.SelectAttrValue("Algorithm", "")
}

func elementText(element *etree.Element) string {
	if element == nil {
		return ""
	}
	return element.Text()
}

func hashFor(algorithm string, known map[string]crypto.Hash) (crypto.Hash, error) {
	if h, ok := known[algorithm]; ok {
		return h, nil
	}
	if algorithm == "" {
		return 0, errors.New("not declared")
	}
	return 0, fmt.Errorf("unsupported algorithm %q", algorithm)
}

func sum(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA1:
		digest := sha1.Sum(data)
		return digest[:]
	default:
		digest := sha256.Sum256(data)
		return digest[:]
	}
}

var whitespace = regexp.MustCompile(`\s`)

// decodeBase64 tolerates the line breaks XMLDSig implementations wrap base64
// content in.
func decodeBase64(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(whitespace.ReplaceAllString(strings.TrimSpace(value), ""))
}

// equal compares two digests. They are public values, so a timing-safe
// comparison would buy nothing.
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
