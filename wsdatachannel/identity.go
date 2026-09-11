package wsdatachannel

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// IdentityCertificate is the decoded XML certificate of an identity-validation
// shipment — what DownloadDocument returns for DocumentIdentificationOCRXML.
//
// It is the machine-readable twin of the PDF certificate: the same attributes,
// checks and biometric scores, plus the consents the subject gave and the
// signed artefacts, none of which the PDF exposes in a parseable form. Parse
// this rather than the PDF.
//
// Note that the certificate carries personal data — full name, document
// number, date of birth, home address and biometric scores. Handle the decoded
// value, and anything you log, accordingly.
type IdentityCertificate struct {
	// ResultCode is the operation's own code, "0000" on success, and Reason
	// its description. They describe the *request*, not the verification; a
	// well-formed request for a failed verification still reports "0000".
	ResultCode string
	Reason     string

	// OCRResult is the overall outcome of reading the document, "OK" when the
	// portal could read it.
	OCRResult string

	// TokenID is the shipment's GUID. ExternalID echoes back whatever you set
	// on the Receiver, and is empty when you set nothing.
	TokenID      string
	ExternalID   string
	ValidationID string

	// Result and Substate are the same codes shippingStatus reports; Result 7
	// has been observed on a successfully completed verification.
	Result        int
	Substate      int
	ResultComment string
	ResultDate    Time

	Locked       bool
	CancelCode   string
	CancelReason string

	// ConsentStatus is the subject's overall consent state, e.g.
	// "CONSENT_ACCEPTED". DataMinimization is the level applied, e.g.
	// "NORMAL". Method is how they identified themselves, e.g. "NFC".
	ConsentStatus    string
	DataMinimization string
	Method           string

	// Attributes holds the identity data read from the document.
	Attributes IdentityAttributes

	// Verification holds the checks the portal ran, decoded into the types
	// they actually are.
	Verification IdentityVerification

	// Checks is the same list of checks as the PDF's "validaciones de la
	// petición" table, each with the threshold that was applied to it.
	Checks []IdentityCheck

	// Consents are the consent-form answers the subject gave.
	Consents []Consent

	// Artifacts are the files embedded in the certificate: a signed XML
	// declaration and the PDF certificate itself.
	Artifacts []IdentityArtifact

	// Raw is every code/value pair in the certificate, including any this
	// package does not model. Reach for it when a portal upgrade adds a code
	// before this struct grows a field for it.
	Raw map[string]string
}

// IdentityAttributes is the identity data read from the subject's document.
type IdentityAttributes struct {
	DocumentType   string // TYPE, e.g. "DNI"
	IDNumber       string // ID_NUMBER — the NIF/DNI itself
	DocumentNumber string // DOC_NUMBER — the physical card's serial number

	Name     string // NAME
	Surname  string // SURNAME, both surnames as printed on the document
	Surname1 string // SURNAME1
	Surname2 string // SURNAME2
	Sex      string // SEX, in the document's own wording

	BirthDate         Time   // BIRTHDATE
	BirthPlace        string // BIRTHPLACE
	BirthMunicipality string // BIRTHPLACE_MUNICIPALITY
	StreetAddress     string // STREET_ADDRESS
	Nationality       string // NATIONALITY

	Issuer         string // ISSUER
	ExpeditionDate Time   // EXPEDITION_DATE
	ExpiryDate     Time   // EXPIRY

	// SelectedDocumentType is the document model the portal matched, e.g.
	// "ES_IDCard_2021"; Method is how it was read, e.g. "NFC".
	SelectedDocumentType string // SELECTED_DOCUMENT_TYPE
	Method               string // SELECTED_ID_METHOD_TYPE

	// NFCCountryCode and ChipSignedHashes come from the chip's security
	// object, and are what lets a third party prove the data came off the
	// chip rather than from a photograph of the card.
	NFCCountryCode   string // NFC_SOD_COUNTRY_CODE
	ChipSignedHashes string // CHIP_SIGNED_HASHES_LIST

	// AuthIssuingAuthority and SignIssuingAuthority are the authorities
	// behind the chip's two certificates.
	AuthIssuingAuthority string // AUTH_ISSUING_AUTHORITY
	SignIssuingAuthority string // SIGN_ISSUING_AUTHORITY
}

// FullName assembles the subject's name in the Spanish order, skipping any part
// the document did not carry.
func (a IdentityAttributes) FullName() string {
	parts := make([]string, 0, 3)
	for _, part := range []string{a.Name, a.Surname1, a.Surname2} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, " ")
}

// IdentityVerification is the outcome of each check, decoded. The portal
// reports booleans as "1"/"0" and scores as fractions of one.
type IdentityVerification struct {
	// GlobalResult is TEST_GLOBAL_RESULT, the portal's own verdict.
	GlobalResult bool

	LegalAge           bool // TEST_LEGAL_AGE
	DocumentNotExpired bool // TEST_DOCUMENT_EXPIRY_DATE
	CARootTrusted      bool // TEST_DOCUMENT_CERTIFICATE_CA_ROOT
	NFCChipPresent     bool // TEST_NFC_CHIP_PRESENCE
	NFCReadSuccessful  bool // TEST_NFC_SUCCESSFUL_READING
	NFCErrorRetries    int  // TEST_NFC_ERROR_RETRIES

	// AuthCertificate and SignCertificate are the chip's authentication and
	// signature certificates, checked independently.
	AuthCertificate CertificateChecks
	SignCertificate CertificateChecks

	// The biometric scores run from 0 to 1. The PDF certificate shows them as
	// percentages, so 0.9987 here is the 99.87% printed there.
	FaceMatch          float64 // TEST_BIOMETRIC_VALIDATION_CORRESPONDENCE
	SelfieAuthenticity float64 // TEST_ANTISPOOFING_SELFIE_VALIDATION_CORRESPONDENCE
	SelfieSimilarity   float64 // TEST_ANTISPOOFING_SELFIE_SIMILARITY_CORRESPONDENCE
	Liveness           float64 // TEST_LIFE_RECOGNITION_RATIO
}

// CertificateChecks is one of the chip's certificates, verified against the
// document's printed data.
type CertificateChecks struct {
	Status          bool
	NotExpired      bool
	IDNumberMatches bool
	NameMatches     bool
	SurnameMatches  bool
}

// IdentityCheck is one row of the certificate's validation table.
type IdentityCheck struct {
	Code string
	// Result is the portal's verdict, "OK" when the check passed.
	Result string
	// Threshold is the filter applied to the check: "1" for a boolean, or the
	// minimum score for a biometric one.
	Threshold string
	// Blocking reports whether failing this check fails the verification.
	Blocking  bool
	Condition string
	Message   string
}

// Passed reports whether the check succeeded.
func (c IdentityCheck) Passed() bool { return strings.EqualFold(c.Result, "OK") }

// Consent is one answer on the consent form the subject filled in.
type Consent struct {
	// ID identifies the question, e.g. "nfc_data_consent_check".
	ID string
	// Step and Locale say where in the flow it was asked, and in which
	// language.
	Step   string
	Locale string
	// Given is the answer. Mandatory reports whether it had to be given for
	// the flow to continue.
	Given     bool
	Mandatory bool
	// Original is the value the form started with, before the subject
	// answered.
	Original string
}

// IdentityArtifact is a file embedded in the certificate.
type IdentityArtifact struct {
	// Kind is the element the artefact came from.
	Kind string
	// Extension is the file type, "xml" or "pdf".
	Extension string
	// Hash is the digest the portal declares. See VerifyHash for the two
	// conventions it can follow.
	Hash string
	// Signed reports whether the portal says it signed this artefact. Only
	// the signed-result artefact carries the flag.
	Signed bool

	// Base64 is the artefact as it appears in the certificate.
	Base64 string
}

// Decode returns the artefact's bytes.
func (a IdentityArtifact) Decode() ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(stripWhitespace(a.Base64))
	if err != nil {
		return nil, fmt.Errorf("wsdatachannel: decode %s artifact: %w", a.Kind, err)
	}
	return data, nil
}

// VerifyHash checks the artefact against the digest the portal declared.
//
// The two artefacts in a certificate use different conventions, which is why
// this accepts either: the signed result's hash is SHA-256 over the decoded
// bytes, while the attributes declaration's is SHA-256 over the base64 text.
// Both were confirmed against a live certificate. A mismatch on both is
// reported as an error.
func (a IdentityArtifact) VerifyHash() error {
	if a.Hash == "" {
		return fmt.Errorf("wsdatachannel: %s artifact declares no hash", a.Kind)
	}

	declared := strings.ToLower(strings.TrimSpace(a.Hash))

	overText := sha256.Sum256([]byte(a.Base64))
	if hex.EncodeToString(overText[:]) == declared {
		return nil
	}

	decoded, err := a.Decode()
	if err != nil {
		return err
	}
	overBytes := sha256.Sum256(decoded)
	if hex.EncodeToString(overBytes[:]) == declared {
		return nil
	}

	return fmt.Errorf("wsdatachannel: %s artifact does not match its declared hash %s "+
		"(sha256 of bytes %s, of base64 %s)",
		a.Kind, declared, hex.EncodeToString(overBytes[:]), hex.EncodeToString(overText[:]))
}

// Passed reports whether the certificate attests a successful verification:
// the portal's own verdict is positive and no blocking check failed.
//
// Check this rather than the shipment's status code. A shipment reaches its
// final status whether the subject verified successfully or not.
func (c IdentityCertificate) Passed() bool {
	if !c.Verification.GlobalResult {
		return false
	}
	for _, check := range c.Checks {
		if check.Blocking && !check.Passed() {
			return false
		}
	}
	return true
}

// FailedChecks returns the blocking checks that did not pass, which is what to
// report when Passed is false.
func (c IdentityCertificate) FailedChecks() []IdentityCheck {
	var failed []IdentityCheck
	for _, check := range c.Checks {
		if check.Blocking && !check.Passed() {
			failed = append(failed, check)
		}
	}
	return failed
}

// identityXML mirrors the certificate's element structure.
//
// The element names carry a "urn" prefix that the document never binds to a
// namespace. The tags below deliberately omit any namespace so they match on
// local name, which keeps this working whether or not the portal starts
// declaring one.
type identityXML struct {
	Main   string `xml:"main"`
	Reason string `xml:"reason"`

	State struct {
		CancelCode       string `xml:"cancel_code,attr"`
		CancelReason     string `xml:"cancel_reason,attr"`
		ConsentStatus    string `xml:"consent_status,attr"`
		DataMinimization string `xml:"data_minimization_level,attr"`
		ExternalID       string `xml:"external_id,attr"`
		Locked           string `xml:"locked,attr"`
		Method           string `xml:"nfc_step_identification_method,attr"`
		ResultComment    string `xml:"result_comment,attr"`
		ResultDate       Time   `xml:"result_date,attr"`
		ResultValue      string `xml:"result_value,attr"`
		SubstateValue    string `xml:"substate_value,attr"`
		TokenID          string `xml:"token_id,attr"`
		ValidationID     string `xml:"validation_id,attr"`

		OCRValidationResult string `xml:"ocr_validation_result"`

		Results []struct {
			Code  string `xml:"code,attr"`
			Type  string `xml:"type,attr"`
			Value string `xml:"value,attr"`
		} `xml:"idcard_state_ocr_result"`

		Checks []struct {
			Blocker   string `xml:"blocker,attr"`
			Code      string `xml:"code,attr"`
			Condition string `xml:"condition,attr"`
			Message   string `xml:"message,attr"`
			Result    string `xml:"result,attr"`
			Value     string `xml:"value,attr"`
		} `xml:"idcard_state_ocr_validation_result"`

		Forms []struct {
			ID        string `xml:"id,attr"`
			Locale    string `xml:"locale,attr"`
			Placement string `xml:"placement,attr"`
			Step      string `xml:"step,attr"`
		} `xml:"xforms_data"`

		Items []struct {
			ID            string `xml:"id,attr"`
			Mandatory     string `xml:"mandatory,attr"`
			Modifiable    string `xml:"modifiable,attr"`
			OriginalValue string `xml:"originalValue,attr"`
			Value         string `xml:"value,attr"`
		} `xml:"xforms_items"`

		NFCSigned *struct {
			Base64    string `xml:"base64,attr"`
			Extension string `xml:"extension,attr"`
			Hash      string `xml:"hash,attr"`
			Signed    string `xml:"signed,attr"`
		} `xml:"idcard_nfcsigned_result"`

		NFCDeclaration *struct {
			Base64    string `xml:"base64,attr"`
			Extension string `xml:"extension,attr"`
			Hash      string `xml:"hash,attr"`
		} `xml:"idcard_nfcattributes_declaration"`
	} `xml:"idcard_state"`
}

// ParseIdentityCertificate decodes the XML certificate of an
// identity-validation shipment.
//
//	doc, err := client.DownloadDocument(ctx,
//	    wsdatachannel.DocumentIdentificationOCRXML,
//	    wsdatachannel.IdentifyByGUID, guid)
//	raw, err := wsdatachannel.DecodeBinary(doc.Binary)
//	cert, err := wsdatachannel.ParseIdentityCertificate(raw)
//
// Unknown codes are not an error: they land in Raw so a portal upgrade cannot
// break a working integration.
func ParseIdentityCertificate(data []byte) (*IdentityCertificate, error) {
	var doc identityXML
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("wsdatachannel: parse identity certificate: %w", err)
	}
	state := doc.State

	cert := &IdentityCertificate{
		ResultCode:       strings.TrimSpace(doc.Main),
		Reason:           strings.TrimSpace(doc.Reason),
		OCRResult:        strings.TrimSpace(state.OCRValidationResult),
		TokenID:          unquote(state.TokenID),
		ExternalID:       unquote(state.ExternalID),
		ValidationID:     unquote(state.ValidationID),
		Result:           atoi(state.ResultValue),
		Substate:         atoi(state.SubstateValue),
		ResultComment:    unquote(state.ResultComment),
		ResultDate:       state.ResultDate,
		Locked:           isTrue(state.Locked),
		CancelCode:       unquote(state.CancelCode),
		CancelReason:     unquote(state.CancelReason),
		ConsentStatus:    unquote(state.ConsentStatus),
		DataMinimization: unquote(state.DataMinimization),
		Method:           unquote(state.Method),
		Raw:              make(map[string]string, len(state.Results)),
	}

	for _, result := range state.Results {
		cert.Raw[unquote(result.Code)] = unquote(result.Value)
	}
	cert.Attributes = identityAttributesFrom(cert.Raw)
	cert.Verification = identityVerificationFrom(cert.Raw)

	for _, check := range state.Checks {
		cert.Checks = append(cert.Checks, IdentityCheck{
			Code:      unquote(check.Code),
			Result:    unquote(check.Result),
			Threshold: unquote(check.Value),
			Blocking:  isTrue(check.Blocker),
			Condition: unquote(check.Condition),
			Message:   unquote(check.Message),
		})
	}

	// The consent questions and the form they belong to are siblings rather
	// than nested, so the step and locale are taken from the single form when
	// the certificate has one. Certificates seen so far have exactly one step.
	step, locale := "", ""
	if len(state.Forms) > 0 {
		step, locale = unquote(state.Forms[0].Step), unquote(state.Forms[0].Locale)
	}
	for _, item := range state.Items {
		cert.Consents = append(cert.Consents, Consent{
			ID:        unquote(item.ID),
			Step:      step,
			Locale:    locale,
			Given:     isTrue(unquote(item.Value)),
			Mandatory: isTrue(unquote(item.Mandatory)),
			Original:  unquote(item.OriginalValue),
		})
	}

	if a := state.NFCSigned; a != nil {
		cert.Artifacts = append(cert.Artifacts, IdentityArtifact{
			Kind:      "nfc-signed-result",
			Extension: unquote(a.Extension),
			Hash:      unquote(a.Hash),
			Signed:    isTrue(unquote(a.Signed)),
			Base64:    unquote(a.Base64),
		})
	}
	if a := state.NFCDeclaration; a != nil {
		cert.Artifacts = append(cert.Artifacts, IdentityArtifact{
			Kind:      "nfc-attributes-declaration",
			Extension: unquote(a.Extension),
			Hash:      unquote(a.Hash),
			Base64:    unquote(a.Base64),
		})
	}

	return cert, nil
}

func identityAttributesFrom(raw map[string]string) IdentityAttributes {
	return IdentityAttributes{
		DocumentType:   raw["TYPE"],
		IDNumber:       raw["ID_NUMBER"],
		DocumentNumber: raw["DOC_NUMBER"],

		Name:     raw["NAME"],
		Surname:  raw["SURNAME"],
		Surname1: raw["SURNAME1"],
		Surname2: raw["SURNAME2"],
		Sex:      raw["SEX"],

		BirthDate:         date(raw["BIRTHDATE"]),
		BirthPlace:        raw["BIRTHPLACE"],
		BirthMunicipality: raw["BIRTHPLACE_MUNICIPALITY"],
		StreetAddress:     raw["STREET_ADDRESS"],
		Nationality:       raw["NATIONALITY"],

		Issuer:         raw["ISSUER"],
		ExpeditionDate: date(raw["EXPEDITION_DATE"]),
		ExpiryDate:     date(raw["EXPIRY"]),

		SelectedDocumentType: raw["SELECTED_DOCUMENT_TYPE"],
		Method:               raw["SELECTED_ID_METHOD_TYPE"],

		NFCCountryCode:   raw["NFC_SOD_COUNTRY_CODE"],
		ChipSignedHashes: raw["CHIP_SIGNED_HASHES_LIST"],

		AuthIssuingAuthority: raw["AUTH_ISSUING_AUTHORITY"],
		SignIssuingAuthority: raw["SIGN_ISSUING_AUTHORITY"],
	}
}

func identityVerificationFrom(raw map[string]string) IdentityVerification {
	return IdentityVerification{
		GlobalResult: isTrue(raw["TEST_GLOBAL_RESULT"]),

		LegalAge:           isTrue(raw["TEST_LEGAL_AGE"]),
		DocumentNotExpired: isTrue(raw["TEST_DOCUMENT_EXPIRY_DATE"]),
		CARootTrusted:      isTrue(raw["TEST_DOCUMENT_CERTIFICATE_CA_ROOT"]),
		NFCChipPresent:     isTrue(raw["TEST_NFC_CHIP_PRESENCE"]),
		NFCReadSuccessful:  isTrue(raw["TEST_NFC_SUCCESSFUL_READING"]),
		NFCErrorRetries:    atoi(raw["TEST_NFC_ERROR_RETRIES"]),

		AuthCertificate: CertificateChecks{
			Status:          isTrue(raw["TEST_DOCUMENT_AUTH_CERTIFICATE_STATUS"]),
			NotExpired:      isTrue(raw["TEST_DOCUMENT_AUTH_CERTIFICATE_EXPIRATION"]),
			IDNumberMatches: isTrue(raw["TEST_DOCUMENT_AUTH_CERTIFICATE_IDNUMBER_CORRESPONDENCE"]),
			NameMatches:     isTrue(raw["TEST_DOCUMENT_AUTH_CERTIFICATE_NAME_CORRESPONDENCE"]),
			SurnameMatches:  isTrue(raw["TEST_DOCUMENT_AUTH_CERTIFICATE_SURNAME_CORRESPONDENCE"]),
		},
		SignCertificate: CertificateChecks{
			Status:          isTrue(raw["TEST_DOCUMENT_SIGN_CERTIFICATE_STATUS"]),
			NotExpired:      isTrue(raw["TEST_DOCUMENT_SIGN_CERTIFICATE_EXPIRATION"]),
			IDNumberMatches: isTrue(raw["TEST_DOCUMENT_SIGN_CERTIFICATE_IDNUMBER_CORRESPONDENCE"]),
			NameMatches:     isTrue(raw["TEST_DOCUMENT_SIGN_CERTIFICATE_NAME_CORRESPONDENCE"]),
			SurnameMatches:  isTrue(raw["TEST_DOCUMENT_SIGN_CERTIFICATE_SURNAME_CORRESPONDENCE"]),
		},

		FaceMatch:          atof(raw["TEST_BIOMETRIC_VALIDATION_CORRESPONDENCE"]),
		SelfieAuthenticity: atof(raw["TEST_ANTISPOOFING_SELFIE_VALIDATION_CORRESPONDENCE"]),
		SelfieSimilarity:   atof(raw["TEST_ANTISPOOFING_SELFIE_SIMILARITY_CORRESPONDENCE"]),
		Liveness:           atof(raw["TEST_LIFE_RECOGNITION_RATIO"]),
	}
}

// unquote strips the literal single quotes the portal wraps some attribute
// values in. It leaves everything else alone, including a value that merely
// starts or ends with a quote.
func unquote(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		return value[1 : len(value)-1]
	}
	return value
}

// isTrue accepts every spelling of "yes" the certificate uses: "1" for the
// numeric test results, "true" for the XML flags.
func isTrue(value string) bool {
	switch strings.ToLower(unquote(value)) {
	case "1", "true", "yes", "ok":
		return true
	default:
		return false
	}
}

func atoi(value string) int {
	n, err := strconv.Atoi(unquote(value))
	if err != nil {
		return 0
	}
	return n
}

func atof(value string) float64 {
	f, err := strconv.ParseFloat(unquote(value), 64)
	if err != nil {
		return 0
	}
	return f
}

func date(value string) Time {
	var t Time
	// A malformed date is left as the zero time rather than failing the whole
	// certificate: one unreadable field should not cost you the other forty.
	_ = t.parse(unquote(value))
	return t
}
