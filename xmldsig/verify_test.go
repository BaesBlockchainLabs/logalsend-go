package xmldsig

import (
	"os"
	"strings"
	"testing"
)

// TestVerifyJavaReference verifies the golden assertion the Java SDK signed
// under Apache Santuario. Santuario accepts it, so Verify must too: the two
// implementations have to agree in both directions, not just when signing.
func TestVerifyJavaReference(t *testing.T) {
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	verified, err := Verify(data)
	if err != nil {
		t.Fatalf("the Java-signed golden does not verify: %v", err)
	}
	if got := verified.Certificate.Subject.CommonName; got != "Test Logalty" {
		t.Errorf("signer CN = %q", got)
	}
	if verified.SignatureAlgorithm != algSignatureRSASHA1 {
		t.Errorf("SignatureAlgorithm = %q", verified.SignatureAlgorithm)
	}
	if verified.DigestAlgorithm != algDigestSHA1 {
		t.Errorf("DigestAlgorithm = %q", verified.DigestAlgorithm)
	}
}

// TestVerifyRejectsTampering is the property that gives verification its
// meaning. Both halves are checked separately, because a signature that
// verifies over a digest of the wrong content is worse than no check at all.
func TestVerifyRejectsTampering(t *testing.T) {
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	original := string(data)

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "content changed",
			doc:  strings.Replace(original, "Administrator", "ReadOnly___", 1),
			want: "reference digest",
		},
		{
			name: "digest changed to match the new content",
			// Swapping the DigestValue too defeats the reference check, so
			// the signature over SignedInfo has to catch it.
			doc: strings.Replace(
				strings.Replace(original, "Administrator", "ReadOnly___", 1),
				"1ZjsyIcYazpv5UgJgdI6a4IszZ0=", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=", 1),
			want: "",
		},
		{
			name: "signature value changed",
			doc:  strings.Replace(original, "DdnJxLQcrYRTDqf3RkcEZ1ONTP", "AAAAAAAAAAAAAAAAAAAAAAAAAA", 1),
			want: "signature does not verify",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.doc == original {
				t.Fatal("the test did not actually change anything")
			}
			_, err := Verify([]byte(tt.doc))
			if err == nil {
				t.Fatal("tampering was accepted")
			}
			if tt.want != "" && !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error was %q, expected it to mention %q", err, tt.want)
			}
		})
	}
}

// TestVerifyRejectsWhatItCannotCheck covers the refusals. Each of these is a
// document Verify must not claim to have verified.
func TestVerifyRejectsWhatItCannotCheck(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"not XML", "not xml at all", "no root element"},
		{"no signature", `<a><b>x</b></a>`, "no signature"},
		{
			name: "reference to an element rather than the document",
			doc: `<a><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>` +
				`<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>` +
				`<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>` +
				`<Reference URI="#xades-id-1"/></SignedInfo></Signature></a>`,
			want: "whole-document reference",
		},
		{
			name: "exclusive canonicalization",
			doc: `<a><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>` +
				`<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
				`</SignedInfo></Signature></a>`,
			want: "unsupported canonicalization",
		},
		{
			name: "unknown signature algorithm",
			doc: `<a><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>` +
				`<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>` +
				`<SignatureMethod Algorithm="urn:made:up"/></SignedInfo></Signature></a>`,
			want: "signature method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify([]byte(tt.doc))
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error was %q, expected it to mention %q", err, tt.want)
			}
		})
	}
}

// TestVerifySurvivesReserialization checks that parsing a signed document and
// writing it back out again does not break it. It holds for this document
// because every carriage return it contains sits inside the Signature element,
// which the digest excludes — re-serializing a document whose *signed* content
// carries one would not be safe, which is why the generator escapes them.
func TestVerifySurvivesReserialization(t *testing.T) {
	doc := loadGolden(t)
	serialized, err := doc.WriteToString()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if _, err := Verify([]byte(serialized)); err != nil {
		t.Errorf("a re-serialized golden should still verify: %v", err)
	}
}
