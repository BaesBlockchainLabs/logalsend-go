package wsdatachannel

import (
	"os"
	"strings"
	"testing"
)

// The fixture is synthetic. It reproduces the structure of a real
// identity-validation certificate — the element names, the two attribute
// quoting styles, the code/value triples and the two hash conventions — with
// invented personal data, because a real certificate carries a real person's
// name, document number, date of birth and home address.
func loadCertificate(t *testing.T) *IdentityCertificate {
	t.Helper()
	data, err := os.ReadFile("testdata/identity-certificate.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	cert, err := ParseIdentityCertificate(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}

func TestParseIdentityCertificateState(t *testing.T) {
	cert := loadCertificate(t)

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"ResultCode", cert.ResultCode, "0000"},
		{"Reason", cert.Reason, "Operation processed successfully"},
		{"OCRResult", cert.OCRResult, "OK"},
		{"TokenID", cert.TokenID, "001002-0000-000000000000001.par"},
		{"ExternalID", cert.ExternalID, "ENROLL-0001"},
		{"Result", cert.Result, 7},
		{"Substate", cert.Substate, 12},
		{"Locked", cert.Locked, false},
		{"ConsentStatus", cert.ConsentStatus, "CONSENT_ACCEPTED"},
		{"DataMinimization", cert.DataMinimization, "NORMAL"},
		{"Method", cert.Method, "NFC"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}

	if got := cert.ResultDate.Format("2006-01-02 15:04:05.000"); got != "2026-09-11 20:23:50.820" {
		t.Errorf("ResultDate = %s", got)
	}
}

func TestParseIdentityAttributes(t *testing.T) {
	a := loadCertificate(t).Attributes

	checks := []struct{ name, got, want string }{
		{"DocumentType", a.DocumentType, "DNI"},
		{"IDNumber", a.IDNumber, "00000000T"},
		{"DocumentNumber", a.DocumentNumber, "ABC000000"},
		{"Name", a.Name, "NOMBRE"},
		{"Surname1", a.Surname1, "APELLIDOUNO"},
		{"Surname2", a.Surname2, "APELLIDODOS"},
		{"Sex", a.Sex, "Mujer"},
		{"StreetAddress", a.StreetAddress, "CALLE FALSA 1-CIUDAD-PROVINCIA"},
		{"BirthMunicipality", a.BirthMunicipality, "CIUDAD"},
		{"Nationality", a.Nationality, "España"},
		{"SelectedDocumentType", a.SelectedDocumentType, "ES_IDCard_2021"},
		{"Method", a.Method, "NFC"},
		{"NFCCountryCode", a.NFCCountryCode, "ES"},
		{"AuthIssuingAuthority", a.AuthIssuingAuthority, "AUTORIDAD DE PRUEBA"},
		{"FullName", a.FullName(), "NOMBRE APELLIDOUNO APELLIDODOS"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}

	// Dates arrive as plain YYYY-MM-DD and must come out as real dates, not
	// as strings the caller has to parse again.
	dates := []struct {
		name string
		got  Time
		want string
	}{
		{"BirthDate", a.BirthDate, "1980-03-04"},
		{"ExpeditionDate", a.ExpeditionDate, "2020-01-02"},
		{"ExpiryDate", a.ExpiryDate, "2030-01-02"},
	}
	for _, d := range dates {
		if got := d.got.Format("2006-01-02"); got != d.want {
			t.Errorf("%s = %s, want %s", d.name, got, d.want)
		}
	}
}

func TestParseIdentityVerification(t *testing.T) {
	v := loadCertificate(t).Verification

	if !v.GlobalResult || !v.LegalAge || !v.DocumentNotExpired || !v.CARootTrusted ||
		!v.NFCChipPresent || !v.NFCReadSuccessful {
		t.Errorf("boolean checks decoded wrong: %+v", v)
	}
	// "1"/"0" booleans and a genuine integer share the same attribute shape,
	// so the retry count must not be flattened into a boolean.
	if v.NFCErrorRetries != 2 {
		t.Errorf("NFCErrorRetries = %d, want 2", v.NFCErrorRetries)
	}

	if !v.AuthCertificate.Status || !v.AuthCertificate.IDNumberMatches ||
		!v.SignCertificate.NotExpired || !v.SignCertificate.SurnameMatches {
		t.Errorf("certificate checks decoded wrong: %+v", v)
	}

	// The PDF prints these as percentages; the XML carries fractions.
	scores := []struct {
		name string
		got  float64
		want float64
	}{
		{"FaceMatch", v.FaceMatch, 0.998737774164915},
		{"SelfieAuthenticity", v.SelfieAuthenticity, 0.8595648096042146},
		{"SelfieSimilarity", v.SelfieSimilarity, 0.9997344017028809},
		{"Liveness", v.Liveness, 0.8698338237148047},
	}
	for _, s := range scores {
		if s.got != s.want {
			t.Errorf("%s = %v, want %v", s.name, s.got, s.want)
		}
	}
}

func TestParseIdentityChecks(t *testing.T) {
	cert := loadCertificate(t)

	if len(cert.Checks) != 3 {
		t.Fatalf("got %d checks, want 3", len(cert.Checks))
	}
	first := cert.Checks[0]
	if first.Code != "TEST_LIFE_RECOGNITION_RATIO" || first.Threshold != "0.6" || !first.Blocking {
		t.Errorf("first check decoded wrong: %+v", first)
	}
	if !first.Passed() {
		t.Error("an OK check should report as passed")
	}

	// The fixture's failing check is deliberately non-blocking, so the
	// certificate as a whole still passes.
	if !cert.Passed() {
		t.Errorf("certificate should pass: failed = %+v", cert.FailedChecks())
	}
	if len(cert.FailedChecks()) != 0 {
		t.Errorf("a non-blocking failure must not appear in FailedChecks: %+v", cert.FailedChecks())
	}
}

// TestPassedRequiresBlockingChecks is the safety property that matters: a
// blocking failure, or a negative global verdict, must not read as success.
func TestPassedRequiresBlockingChecks(t *testing.T) {
	cert := loadCertificate(t)

	cert.Checks[2].Blocking = true // the KO check
	if cert.Passed() {
		t.Error("a failed blocking check must fail the certificate")
	}
	if got := cert.FailedChecks(); len(got) != 1 || got[0].Code != "TEST_NFC_CHIP_PRESENCE" {
		t.Errorf("FailedChecks = %+v", got)
	}

	cert.Checks[2].Blocking = false
	cert.Verification.GlobalResult = false
	if cert.Passed() {
		t.Error("a negative global result must fail the certificate")
	}
}

func TestParseIdentityConsents(t *testing.T) {
	consents := loadCertificate(t).Consents

	if len(consents) != 2 {
		t.Fatalf("got %d consents, want 2", len(consents))
	}
	// These attributes are wrapped in literal single quotes in the document,
	// unlike the state attributes, which are not.
	if consents[0].ID != "nfc_data_consent_check" || !consents[0].Given || consents[0].Mandatory {
		t.Errorf("first consent decoded wrong: %+v", consents[0])
	}
	if consents[1].ID != "nfc_sepblac_consent_check" || consents[1].Given || !consents[1].Mandatory {
		t.Errorf("second consent decoded wrong: %+v", consents[1])
	}
	if consents[0].Step != "IDCARD_CONSENT" || consents[0].Locale != "es-ES" {
		t.Errorf("consent context not carried over: %+v", consents[0])
	}
}

// TestIdentityArtifactHashes covers the quirk that the two embedded artefacts
// declare their digests over different things: the signed result over its
// decoded bytes, the attributes declaration over its base64 text. Both were
// confirmed against a live certificate.
func TestIdentityArtifactHashes(t *testing.T) {
	artifacts := loadCertificate(t).Artifacts

	if len(artifacts) != 2 {
		t.Fatalf("got %d artifacts, want 2", len(artifacts))
	}

	signed := artifacts[0]
	if signed.Kind != "nfc-signed-result" || signed.Extension != "xml" || !signed.Signed {
		t.Errorf("signed artifact decoded wrong: kind=%q ext=%q signed=%v",
			signed.Kind, signed.Extension, signed.Signed)
	}
	declaration := artifacts[1]
	if declaration.Kind != "nfc-attributes-declaration" || declaration.Extension != "pdf" {
		t.Errorf("declaration decoded wrong: kind=%q ext=%q", declaration.Kind, declaration.Extension)
	}
	if declaration.Signed {
		t.Error("the declaration carries no signed flag and must not report one")
	}

	for _, a := range artifacts {
		if err := a.VerifyHash(); err != nil {
			t.Errorf("%s: %v", a.Kind, err)
		}
		data, err := a.Decode()
		if err != nil {
			t.Errorf("%s: decode: %v", a.Kind, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("%s: decoded to nothing", a.Kind)
		}
	}

	if got := mustDecode(t, artifacts[1]); !strings.HasPrefix(string(got), "%PDF") {
		t.Errorf("the declaration should decode to a PDF, got %q", got[:min(8, len(got))])
	}

	// A tampered artefact must be rejected under both conventions, not
	// silently accepted by the one that happens not to apply.
	tampered := artifacts[0]
	tampered.Hash = strings.Repeat("0", 64)
	if err := tampered.VerifyHash(); err == nil {
		t.Error("a wrong hash must be reported")
	}
	missing := artifacts[0]
	missing.Hash = ""
	if err := missing.VerifyHash(); err == nil {
		t.Error("a missing hash must be reported")
	}
}

// TestRawKeepsUnmodelledCodes checks that a code this SDK has never seen still
// reaches the caller, so a portal upgrade cannot quietly drop data.
func TestRawKeepsUnmodelledCodes(t *testing.T) {
	cert := loadCertificate(t)

	if got := cert.Raw["A_CODE_THIS_SDK_DOES_NOT_MODEL"]; got != "surprise" {
		t.Errorf("unmodelled code = %q, want %q", got, "surprise")
	}
	if got := cert.Raw["ID_NUMBER"]; got != "00000000T" {
		t.Errorf("Raw should also carry modelled codes, got %q", got)
	}
	if len(cert.Raw) != 44 {
		t.Errorf("Raw has %d codes, want 44", len(cert.Raw))
	}
}

func TestParseIdentityCertificateRejectsGarbage(t *testing.T) {
	if _, err := ParseIdentityCertificate([]byte("not xml at all")); err == nil {
		t.Error("expected an error for non-XML input")
	}
}

// TestUnquote pins the quoting rule, which differs between attribute families
// in the same document.
func TestUnquote(t *testing.T) {
	tests := []struct{ in, want string }{
		{"'xml'", "xml"},
		{"''", ""},
		{"plain", "plain"},
		{"", ""},
		{"'", "'"},
		{"'unbalanced", "'unbalanced"},
		{"unbalanced'", "unbalanced'"},
		{"  'padded'  ", "padded"},
	}
	for _, tt := range tests {
		if got := unquote(tt.in); got != tt.want {
			t.Errorf("unquote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func mustDecode(t *testing.T, a IdentityArtifact) []byte {
	t.Helper()
	data, err := a.Decode()
	if err != nil {
		t.Fatalf("decode %s: %v", a.Kind, err)
	}
	return data
}
