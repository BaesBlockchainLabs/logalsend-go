package wsdatachannel

import "encoding/base64"

// DocumentType selects which artefact DownloadDocument returns.
type DocumentType string

const (
	DocumentOriginal                     DocumentType = "dwn_orig"
	DocumentStamped                      DocumentType = "dwn_sent"
	DocumentSigned                       DocumentType = "dwn_signed"
	DocumentPostalNoticeReport           DocumentType = "dwn_nrep"
	DocumentPostalCourierCertificate     DocumentType = "dwn_dvn"
	DocumentLogaltyCertificate           DocumentType = "dwn_cert"
	DocumentLogaltyCertificateXML        DocumentType = "dwn_cert_xml"
	DocumentEvidencePack                 DocumentType = "dwn_pack"
	DocumentIdentificationImages         DocumentType = "dwn_idcard_images"
	DocumentIdentificationOCRCertificate DocumentType = "dwn_idcard_ocr"
	DocumentIdentificationOCRXML         DocumentType = "dwn_idcard_xml_cert"
	DocumentVideoCertificate             DocumentType = "dwn_video_cert"
)

// IdentificationType says how the id passed to DownloadDocument should be
// interpreted.
type IdentificationType string

const (
	IdentifyByRequestID  IdentificationType = "requestcid"
	IdentifyByGUID       IdentificationType = "guid"
	IdentifyByExternalID IdentificationType = "externalid"
)

// ShippingListDateFilter picks which date ShippingRequestList filters on.
type ShippingListDateFilter string

const (
	FilterByCreated ShippingListDateFilter = "created"
	FilterBySent    ShippingListDateFilter = "sent"
	FilterByUpdated ShippingListDateFilter = "updated"
)

// ShippingListResultType is the export format. CSV is the only one the portal
// offers.
type ShippingListResultType string

const ShippingListCSV ShippingListResultType = "CSV"

// CancelReason explains why a shipment is being cancelled.
type CancelReason string

const (
	CancelInvalidRemmitance CancelReason = "INVALID_REMMITANCE"
	CancelInvalidReceiver   CancelReason = "INVALID_RECEIVER"
	CancelInvalidContent    CancelReason = "INVALID_CONTENT"
	CancelInvalidData       CancelReason = "INVALID_DATA"
	CancelTechnicalProblems CancelReason = "TECHNICAL_PROBLEMS"
	// CancelOtherProblems is spelled OPTION_ZERO on the wire; the Java SDK
	// exposes it as OTHER_PROBLEMS.
	CancelOtherProblems CancelReason = "OPTION_ZERO"
)

// EncodeContent base64-encodes a file for sending.
func EncodeContent(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBinary decodes a base64 payload returned by the portal — the Binary
// field of DocumentDoc and DocumentStateUTC, or the Data field of
// DocumentExport.
func DecodeBinary(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(stripWhitespace(encoded))
}

func stripWhitespace(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}
