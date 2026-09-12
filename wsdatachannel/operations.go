package wsdatachannel

import "context"

// --- Sending -----------------------------------------------------------------

// SendRequest is a single-file shipment to one or more receivers.
type SendRequest struct {
	// CompanyID and TypeID identify the sending company and the shipment type
	// configured for it in the portal.
	CompanyID string
	TypeID    string

	Receivers []Receiver

	// FileType is the document's MIME type — "application/pdf" in the Java
	// SDK's own examples, not the bare extension.
	FileType string
	// FileName is the file name shown to the receiver, with extension.
	FileName string
	// FileContent is the document, base64-encoded. Use EncodeContent.
	//
	// A PDF must not be an AcroForm — the portal rejects those.
	FileContent string

	// Language selects the portal's UI language for the signer, as a full
	// locale such as "es-ES". It is only read by the synchronous variant.
	Language string
}

func (r SendRequest) params(includeLanguage bool) []param {
	params := []param{
		{"companyId", r.CompanyID},
		{"typeId", r.TypeID},
		{"receiver", r.Receivers},
		{"FileType", r.FileType},
		{"FileContent", r.FileContent},
		{"FileName", r.FileName},
	}
	if includeLanguage {
		params = append(params, param{"language", r.Language})
	}
	return params
}

// ShippingSend queues a shipment and returns as soon as the portal has accepted
// it. The receivers are notified by the portal; poll ShippingStatusUTC to
// follow what happens next.
//
// Deprecated: the integration guide marks shippingSend as deprecated and says
// it may be withdrawn. Use ShippingSendMultiReceiver, which covers the
// single-receiver case too.
func (c *Client) ShippingSend(ctx context.Context, req SendRequest) (RemmitanceResult, error) {
	var out resultEnvelope[RemmitanceResult]
	err := c.call(ctx, "shippingSend", req.params(false), &out)
	return out.Value, err
}

// ShippingSynchronousSend creates a shipment for a single receiver and returns
// the URL to redirect them to immediately, rather than having the portal notify
// them. Exactly one receiver is expected; only the first is sent.
//
// Deprecated: the integration guide marks shippingSynchronousSend as
// deprecated and says using ShippingSynchronousSendMultiReceiver is mandatory,
// since it covers every case.
func (c *Client) ShippingSynchronousSend(ctx context.Context, req SendRequest) (SRemmitanceResult, error) {
	var receiver any
	if len(req.Receivers) > 0 {
		receiver = req.Receivers[0]
	}

	params := req.params(true)
	for i := range params {
		if params[i].name == "receiver" {
			params[i].value = receiver
		}
	}

	var out resultEnvelope[SRemmitanceResult]
	err := c.call(ctx, "shippingSynchronousSend", params, &out)
	return out.Value, err
}

// MultiReceiverSendRequest is a shipment of several files to several receivers,
// who may be required to sign in a given order via Receiver.SignatureOrder.
type MultiReceiverSendRequest struct {
	CompanyID string
	TypeID    string

	Receivers []Receiver

	// Files are the documents to sign. A PDF must not be an AcroForm.
	Files []BinaryContentItem

	// SenderName fills the "Enviado por" line of the notification email. It
	// only applies when the shipment type notifies by email; left empty, the
	// portal uses the company name.
	SenderName string
	// ExternalID is your own identifier for the whole shipment — a customer
	// reference, a case number, whatever you poll by later. For a multi-signer
	// shipment this is the only place the portal reads it from; one set on a
	// Receiver is ignored.
	ExternalID string

	// Subject is the subject line of the certified email. Used by
	// ShippingSendMultiReceiver only.
	Subject string
	// Language selects the signer's UI language. Used by
	// ShippingSynchronousSendMultiReceiver only.
	Language string
}

// ShippingSendMultiReceiver queues a multi-receiver shipment. The portal
// notifies each receiver itself.
func (c *Client) ShippingSendMultiReceiver(ctx context.Context, req MultiReceiverSendRequest) ([]RemmitanceResult, error) {
	var out resultEnvelope[[]RemmitanceResult]
	err := c.call(ctx, "shippingSendMultiReceiver", []param{
		{"companyId", req.CompanyID},
		{"typeId", req.TypeID},
		{"receiver", req.Receivers},
		{"file", req.Files},
		{"senderName", req.SenderName},
		{"externalId", req.ExternalID},
		{"subjectEmailCertificate", req.Subject},
	}, &out)
	return out.Value, err
}

// ShippingSynchronousSendMultiReceiver creates a shipment and returns a sign-in
// URL per receiver instead of having the portal notify them. This is the
// operation to reach for: it handles one receiver or many, and the
// single-receiver variants are deprecated.
//
// It works **only** with a contract (contratación) shipment type. Any other
// type is rejected with RetCodeTypeNotContract.
func (c *Client) ShippingSynchronousSendMultiReceiver(ctx context.Context, req MultiReceiverSendRequest) ([]SMultiRemmitanceResult, error) {
	var out resultEnvelope[[]SMultiRemmitanceResult]
	err := c.call(ctx, "shippingSynchronousSendMultiReceiver", []param{
		{"companyId", req.CompanyID},
		{"typeId", req.TypeID},
		{"receiver", req.Receivers},
		{"file", req.Files},
		{"senderName", req.SenderName},
		{"externalId", req.ExternalID},
		{"language", req.Language},
	}, &out)
	return out.Value, err
}

// ShippingSendWTemplate queues one shipment per TemplateReceiver, each built
// from a template held in the portal.
func (c *Client) ShippingSendWTemplate(ctx context.Context, receivers []TemplateReceiver) ([]RemmitanceResult, error) {
	var out resultsEnvelope[[]RemmitanceResult]
	err := c.call(ctx, "shippingSendWTemplate", []param{
		{"templateReceivers", receivers},
	}, &out)
	return out.Value, err
}

// ShippingSynchronousSendWTemplate builds a shipment from a template and
// returns the sign-in URL immediately.
func (c *Client) ShippingSynchronousSendWTemplate(ctx context.Context, receiver TemplateReceiver) (SRemmitanceResult, error) {
	var out resultEnvelope[SRemmitanceResult]
	err := c.call(ctx, "shippingSynchronousSendWTemplate", []param{
		{"templateReceivers", receiver},
	}, &out)
	return out.Value, err
}

// --- Status ------------------------------------------------------------------

// StatusQuery selects which shipments to report on. The three lists are
// alternative ways of naming shipments; fill in whichever you have. Leaving all
// three empty asks the portal for everything it considers pending, which can be
// a large response.
type StatusQuery struct {
	GUIDs       []string
	IDs         []string
	ExternalIDs []string
}

// ShippingStatus reports the state of the selected shipments, with dates as the
// portal's local-time strings. Prefer ShippingStatusUTC for new code.
func (c *Client) ShippingStatus(ctx context.Context, query StatusQuery) ([]DocumentState, error) {
	var out documentEnvelope[[]DocumentState]
	err := c.call(ctx, "shippingStatus", []param{
		{"guid", query.GUIDs},
		{"id", query.IDs},
		{"externalId", query.ExternalIDs},
	}, &out)
	return out.Value, err
}

// ShippingStatusUTC reports the state of the selected shipments with parsed
// timestamps.
func (c *Client) ShippingStatusUTC(ctx context.Context, query StatusQuery) ([]DocumentStateUTC, error) {
	var out documentEnvelope[[]DocumentStateUTC]
	err := c.call(ctx, "shippingStatusUTC", []param{
		{"guid", query.GUIDs},
		{"id", query.IDs},
		{"externalId", query.ExternalIDs},
	}, &out)
	return out.Value, err
}

// MultiReceiverStatusQuery selects multi-receiver shipments. Unlike
// StatusQuery, the portal takes numeric ids here.
type MultiReceiverStatusQuery struct {
	GUIDs       []string
	IDs         []int
	ExternalIDs []string
}

// ShippingStatusMultiReceiver reports the per-group, per-signature state of
// multi-receiver shipments.
func (c *Client) ShippingStatusMultiReceiver(ctx context.Context, query MultiReceiverStatusQuery) ([]DocumentStateMultiReceiver, error) {
	var out documentEnvelope[[]DocumentStateMultiReceiver]
	err := c.call(ctx, "shippingStatusMultiReceiver", []param{
		{"guid", query.GUIDs},
		{"id", query.IDs},
		{"externalId", query.ExternalIDs},
	}, &out)
	return out.Value, err
}

// --- Sign-in URLs ------------------------------------------------------------

// BuildSamlURL returns the URL that signs a given receiver in to an
// already-created shipment. receiverIdentity is the receiver's identity
// document number, as sent in Receiver.ReceiverIdentityID.
func (c *Client) BuildSamlURL(ctx context.Context, guid, receiverIdentity string) (DocumentSamlResult, error) {
	var out documentEnvelope[DocumentSamlResult]
	err := c.call(ctx, "buildSamlUrl", []param{
		{"guid", guid},
		{"receiverIdentity", receiverIdentity},
	}, &out)
	return out.Value, err
}

// BuildSamlURLMultiReceiver returns one sign-in URL per receiver of a
// multi-receiver shipment.
func (c *Client) BuildSamlURLMultiReceiver(ctx context.Context, guid string) ([]DocumentSamlResult, error) {
	var out documentEnvelope[[]DocumentSamlResult]
	err := c.call(ctx, "buildSamlUrlMultiReceiver", []param{
		{"guid", guid},
	}, &out)
	return out.Value, err
}

// --- Downloads ---------------------------------------------------------------

// byGUID runs the many download operations that differ only in name.
func (c *Client) byGUID(ctx context.Context, operation, guid string) (DocumentDoc, error) {
	var out documentEnvelope[DocumentDoc]
	err := c.call(ctx, operation, []param{{"guid", guid}}, &out)
	return out.Value, err
}

// ShippingDocumentSent downloads the document as it was sent, stamped by the
// portal.
func (c *Client) ShippingDocumentSent(ctx context.Context, guid string) (DocumentDoc, error) {
	return c.byGUID(ctx, "shippingDocumentSent", guid)
}

// ShippingDocumentSigned downloads the signed document.
func (c *Client) ShippingDocumentSigned(ctx context.Context, guid string) (DocumentDoc, error) {
	return c.byGUID(ctx, "shippingDocumentSigned", guid)
}

// ShippingCertificate downloads the Logalty certificate of the transaction.
func (c *Client) ShippingCertificate(ctx context.Context, guid string) (DocumentDoc, error) {
	return c.byGUID(ctx, "shippingCertificate", guid)
}

// ShippingXmlCertificate downloads the machine-readable certificate.
func (c *Client) ShippingXmlCertificate(ctx context.Context, guid string) (DocumentDoc, error) {
	return c.byGUID(ctx, "shippingXmlCertificate", guid)
}

// ShippingDeliveryNote downloads the postal courier's delivery note.
func (c *Client) ShippingDeliveryNote(ctx context.Context, guid string) (DocumentDoc, error) {
	return c.byGUID(ctx, "shippingDeliveryNote", guid)
}

// ShippingNoticeReport downloads the postal notice report.
func (c *Client) ShippingNoticeReport(ctx context.Context, guid string) (DocumentDoc, error) {
	return c.byGUID(ctx, "shippingNoticeReport", guid)
}

// ShippingDossier downloads the full evidence pack.
func (c *Client) ShippingDossier(ctx context.Context, guid string) (DocumentDoc, error) {
	return c.byGUID(ctx, "shippingDossier", guid)
}

// ShippingIdCardCertificate downloads the identity-verification certificate.
func (c *Client) ShippingIdCardCertificate(ctx context.Context, guid string) (DocumentDoc, error) {
	return c.byGUID(ctx, "shippingIdCardCertificate", guid)
}

// ShippingIdCardXmlCertificate downloads the machine-readable
// identity-verification certificate.
func (c *Client) ShippingIdCardXmlCertificate(ctx context.Context, guid string) (DocumentDoc, error) {
	return c.byGUID(ctx, "shippingIdCardXmlCertificate", guid)
}

// ShippingIdCardImages downloads the captured identity-document images.
func (c *Client) ShippingIdCardImages(ctx context.Context, guid string) (DocumentDoc, error) {
	return c.byGUID(ctx, "shippingIdCardImages", guid)
}

// ShippingVideoCertificate downloads the video-identification certificate.
func (c *Client) ShippingVideoCertificate(ctx context.Context, guid string) (DocumentDoc, error) {
	return c.byGUID(ctx, "shippingVideoCertificate", guid)
}

// DownloadDocument is the general download operation: it can fetch any
// DocumentType and identify the shipment by request id, GUID or your own
// external id. It supersedes the per-artefact operations above, which remain
// because the Java SDK exposes them.
func (c *Client) DownloadDocument(ctx context.Context, document DocumentType, idType IdentificationType, id string) (DocumentDoc, error) {
	var out documentEnvelope[DocumentDoc]
	err := c.call(ctx, "downloadDocument", []param{
		{"document", string(document)},
		{"idType", string(idType)},
		{"id", id},
	}, &out)
	return out.Value, err
}

// --- Listing and cancellation ------------------------------------------------

// ShippingListRequest asks for an export of the shipments in a date range.
type ShippingListRequest struct {
	// ResponseType is the export format; CSV is the only one available.
	ResponseType ShippingListResultType
	// DateFrom and DateTo bound the range, formatted as the portal expects
	// (dd/MM/yyyy).
	DateFrom string
	DateTo   string
	// DateType picks which of the shipment's dates the range applies to.
	DateType ShippingListDateFilter
	// CompanyIDs restricts the export to these companies.
	CompanyIDs []int
}

// ShippingRequestList exports the matching shipments. The payload comes back
// base64-encoded in DocumentExport.Data.
func (c *Client) ShippingRequestList(ctx context.Context, req ShippingListRequest) (DocumentExport, error) {
	var out documentEnvelope[DocumentExport]
	err := c.call(ctx, "shippingRequestList", []param{
		{"responsetype", string(req.ResponseType)},
		{"datefrom", req.DateFrom},
		{"dateto", req.DateTo},
		{"datetype", string(req.DateType)},
		{"companyids", req.CompanyIDs},
	}, &out)
	return out.Value, err
}

// CancelShipping cancels a shipment that has not yet been completed.
// stateCode is the portal-defined cancellation state; reason explains why.
func (c *Client) CancelShipping(ctx context.Context, guid, stateCode string, reason CancelReason) (RemmitanceResult, error) {
	var out resultEnvelope[RemmitanceResult]
	err := c.call(ctx, "cancelShipping", []param{
		{"guid", guid},
		{"stateCode", stateCode},
		{"situation", string(reason)},
	}, &out)
	return out.Value, err
}
