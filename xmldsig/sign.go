package xmldsig

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// NamespaceDSig is the XML Signature namespace.
const NamespaceDSig = "http://www.w3.org/2000/09/xmldsig#"

const (
	algSignatureRSASHA1 = NamespaceDSig + "rsa-sha1"
	algDigestSHA1       = NamespaceDSig + "sha1"
	algEnveloped        = NamespaceDSig + "enveloped-signature"
)

// EnvelopedSigner produces the exact <Signature> block the Logalty portal
// expects: an enveloped RSA-SHA1 signature over the whole document, digested
// with SHA-1 and canonicalized with inclusive Canonical XML 1.0.
//
// The output deliberately reproduces one quirk of the Java SDK. Santuario
// builds the signature with a "ds" prefix throughout, and the SDK then strips
// the prefix from whichever elements exist at that moment — Signature,
// SignedInfo, CanonicalizationMethod, SignatureMethod and SignatureValue.
// Reference and KeyInfo are created afterwards and keep theirs. The result is a
// block that mixes prefixed and unprefixed XMLDSig elements. It is valid XML
// either way, but it is what Logalty has always received, so it is reproduced
// rather than tidied up.
type EnvelopedSigner struct {
	Key         *rsa.PrivateKey
	Certificate *x509.Certificate
}

// Sign appends an enveloped signature to the document in doc, immediately
// before the root element's closing tag, and returns the signed document.
//
// doc must be a serialized XML document whose root element's closing tag is the
// final thing in it, with no trailing content or XML declaration.
func (s EnvelopedSigner) Sign(doc []byte) ([]byte, error) {
	if s.Key == nil {
		return nil, errors.New("xmldsig: no private key")
	}
	if s.Certificate == nil {
		return nil, errors.New("xmldsig: no certificate")
	}

	parsed, err := ParseDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("xmldsig: parse document: %w", err)
	}
	root := parsed.Root()
	if root == nil {
		return nil, errors.New("xmldsig: document has no root element")
	}

	closingTag := "</" + qualifiedName(root.Space, root.Tag) + ">"
	prefix, ok := strings.CutSuffix(string(doc), closingTag)
	if !ok {
		return nil, fmt.Errorf("xmldsig: document does not end with %s", closingTag)
	}

	// The reference covers the whole document; the enveloped-signature
	// transform takes the Signature element itself back out.
	digest := sha1.Sum(Canonicalize(root, IsSignature))
	digestValue := base64.StdEncoding.EncodeToString(digest[:])

	// SignedInfo has to be canonicalized in place, because inclusive c14n
	// pulls in every namespace the surrounding document has in scope. So
	// assemble the document once with an empty SignatureValue, canonicalize,
	// then assemble it again with the real one.
	draft := prefix + signatureBlock(digestValue, "", nil) + closingTag
	draftDoc, err := ParseDocument([]byte(draft))
	if err != nil {
		return nil, fmt.Errorf("xmldsig: parse draft: %w", err)
	}
	signedInfo := findChild(findChild(draftDoc.Root(), "Signature"), "SignedInfo")
	if signedInfo == nil {
		return nil, errors.New("xmldsig: draft is missing SignedInfo")
	}

	signedInfoDigest := sha1.Sum(Canonicalize(signedInfo, nil))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.Key, crypto.SHA1, signedInfoDigest[:])
	if err != nil {
		return nil, fmt.Errorf("xmldsig: sign: %w", err)
	}

	block := signatureBlock(digestValue, base64.StdEncoding.EncodeToString(signature), s.Certificate)
	return []byte(prefix + block + closingTag), nil
}

// signatureBlock renders the <Signature> element. Passing an empty
// signatureValue and a nil certificate yields the draft used to canonicalize
// SignedInfo, which neither of those two values is part of.
func signatureBlock(digestValue, signatureValue string, cert *x509.Certificate) string {
	var b strings.Builder

	fmt.Fprintf(&b, "<Signature xmlns:ds=%q xmlns=%q>\n", NamespaceDSig, NamespaceDSig)
	b.WriteString("<SignedInfo>\n")
	fmt.Fprintf(&b, "<CanonicalizationMethod Algorithm=%q/>\n", C14NAlgorithm)
	fmt.Fprintf(&b, "<SignatureMethod Algorithm=%q/>\n", algSignatureRSASHA1)
	b.WriteString("<ds:Reference URI=\"\">\n")
	b.WriteString("<ds:Transforms>\n")
	fmt.Fprintf(&b, "<ds:Transform Algorithm=%q/>\n", algEnveloped)
	b.WriteString("</ds:Transforms>\n")
	fmt.Fprintf(&b, "<ds:DigestMethod Algorithm=%q/>\n", algDigestSHA1)
	fmt.Fprintf(&b, "<ds:DigestValue>%s</ds:DigestValue>\n", digestValue)
	b.WriteString("</ds:Reference>\n")
	b.WriteString("</SignedInfo>\n")
	fmt.Fprintf(&b, "<SignatureValue>\n%s\n</SignatureValue>\n", wrapBase64(signatureValue))

	if cert != nil {
		b.WriteString("<ds:KeyInfo>\n")
		b.WriteString("<ds:X509Data>\n")
		fmt.Fprintf(&b, "<ds:X509Certificate>\n%s\n</ds:X509Certificate>\n",
			wrapBase64(base64.StdEncoding.EncodeToString(cert.Raw)))
		b.WriteString("</ds:X509Data>\n")
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			b.WriteString("<ds:KeyValue>\n<ds:RSAKeyValue>\n")
			fmt.Fprintf(&b, "<ds:Modulus>%s</ds:Modulus>\n",
				wrapBase64(base64.StdEncoding.EncodeToString(pub.N.Bytes())))
			fmt.Fprintf(&b, "<ds:Exponent>%s</ds:Exponent>\n",
				base64.StdEncoding.EncodeToString(bigEndianExponent(pub.E)))
			b.WriteString("</ds:RSAKeyValue>\n</ds:KeyValue>\n")
		}
		b.WriteString("</ds:KeyInfo>\n")
	}

	b.WriteString("</Signature>")
	return b.String()
}

// wrapBase64 breaks base64 into 76-character lines the way Java's MIME encoder
// does. The CRLF separator is written as a character reference, matching how
// the Java SDK's serializer emits it; XMLDSig implementations ignore whitespace
// inside base64 content, so this is presentation only.
func wrapBase64(s string) string {
	const lineLength = 76
	if len(s) <= lineLength {
		return s
	}
	var b strings.Builder
	for start := 0; start < len(s); start += lineLength {
		if start > 0 {
			b.WriteString("&#13;\n")
		}
		b.WriteString(s[start:min(start+lineLength, len(s))])
	}
	return b.String()
}

// bigEndianExponent renders an RSA public exponent as the minimal big-endian
// byte string XMLDSig's CryptoBinary type calls for.
func bigEndianExponent(e int) []byte {
	var buf bytes.Buffer
	for shift := 24; shift >= 0; shift -= 8 {
		b := byte(e >> shift)
		if buf.Len() == 0 && b == 0 {
			continue
		}
		buf.WriteByte(b)
	}
	if buf.Len() == 0 {
		buf.WriteByte(0)
	}
	return buf.Bytes()
}
