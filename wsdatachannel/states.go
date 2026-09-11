package wsdatachannel

import "fmt"

// Shipment states, table TE1 of the LogalSend integration guide (4.1.0).
//
// A shipment's Status says where it is in the pipeline; its Result says how it
// ended. Only StatusFinished carries a meaningful Result — everything earlier
// reports ResultPending.
const (
	StatusPendingSend            = 1  // Pendiente de Enviar
	StatusSending                = 2  // Enviando
	StatusInProgress             = 3  // En Curso
	StatusFinished               = 4  // Finalizada
	StatusSendError              = 5  // Error en el envío
	StatusPendingCertificates    = 6  // Pendiente de Certificados
	StatusPendingPostalCert      = 7  // Pendiente de Certificado Postal
	StatusPendingAuthorization   = 10 // Pendiente de Autorización
	StatusAuthorizationsRejected = 11 // Autorizaciones Rechazadas
)

// Shipment results, table TR1 of the same guide.
//
// ResultAccepted is the only unambiguously successful outcome. Note that the
// codes are not contiguous and jump into the 99000s for failures, so test for
// the specific value rather than for a range.
const (
	ResultPending            = 0     // Pendiente
	ResultAccepted           = 7     // Aceptada
	ResultRejected           = 8     // Rechazada
	ResultNFCConsentAccepted = 21    // Consentimiento de datos NFC aceptado
	ResultNFCConsentRejected = 22    // Consentimiento de datos NFC rechazado
	ResultSignatureNotDone   = 10006 // Firma no realizada

	ResultReceiverDataError   = 99901 // Error por incidencia en los datos del destinatario
	ResultReceiverNoticeError = 99903 // Error al avisar al receptor
	ResultPinError            = 99904 // Error en el Pin
	ResultExpired             = 99906 // Tiempo Expirado
	ResultOCRAttemptsExceeded = 99908 // Intentos OCR excedido
	ResultNFCChipUnreadable   = 99910 // Chip NFC ilegible
	ResultValidationsFailed   = 99915 // Validaciones no superadas
	ResultCancelledBySender   = 99932 // Cancelada por el Emisor
)

var statusNames = map[int]string{
	StatusPendingSend:            "Pendiente de Enviar",
	StatusSending:                "Enviando",
	StatusInProgress:             "En Curso",
	StatusFinished:               "Finalizada",
	StatusSendError:              "Error en el envío",
	StatusPendingCertificates:    "Pendiente de Certificados",
	StatusPendingPostalCert:      "Pendiente de Certificado Postal",
	StatusPendingAuthorization:   "Pendiente de Autorización",
	StatusAuthorizationsRejected: "Autorizaciones Rechazadas",
}

var resultNames = map[int]string{
	ResultPending:             "Pendiente",
	ResultAccepted:            "Aceptada",
	ResultRejected:            "Rechazada",
	ResultNFCConsentAccepted:  "Consentimiento de datos NFC aceptado",
	ResultNFCConsentRejected:  "Consentimiento de datos NFC rechazado",
	ResultSignatureNotDone:    "Firma no realizada",
	ResultReceiverDataError:   "Error por incidencia en los datos del destinatario",
	ResultReceiverNoticeError: "Error al avisar al receptor",
	ResultPinError:            "Error en el Pin",
	ResultExpired:             "Tiempo Expirado",
	ResultOCRAttemptsExceeded: "Intentos OCR excedido",
	ResultNFCChipUnreadable:   "Chip NFC ilegible",
	ResultValidationsFailed:   "Validaciones no superadas",
	ResultCancelledBySender:   "Cancelada por el Emisor",
}

// StatusName returns the portal's own wording for a status code, in Spanish as
// the integration guide gives it. Unknown codes are reported as such rather
// than guessed at.
func StatusName(status int) string {
	if name, ok := statusNames[status]; ok {
		return name
	}
	return fmt.Sprintf("estado desconocido (%d)", status)
}

// ResultName returns the portal's own wording for a result code.
func ResultName(result int) string {
	if name, ok := resultNames[result]; ok {
		return name
	}
	return fmt.Sprintf("resultado desconocido (%d)", result)
}

// Settled reports whether a shipment has stopped moving — either it finished or
// it failed outright. A settled shipment is worth acting on; an unsettled one
// is worth polling again.
func (d DocumentState) Settled() bool { return settled(d.Status) }

// Settled reports whether the shipment has stopped moving.
func (d DocumentStateUTC) Settled() bool { return settled(d.Status) }

func settled(status int) bool {
	switch status {
	case StatusFinished, StatusSendError, StatusAuthorizationsRejected:
		return true
	default:
		return false
	}
}

// Accepted reports whether the shipment finished with the receiver accepting.
// This is the check to make before downloading a signed document or an
// identity certificate.
func (d DocumentState) Accepted() bool {
	return d.Status == StatusFinished && d.Result == ResultAccepted
}

// Accepted reports whether the shipment finished with the receiver accepting.
func (d DocumentStateUTC) Accepted() bool {
	return d.Status == StatusFinished && d.Result == ResultAccepted
}

// Describe renders a shipment's state in the portal's own words, for logs and
// operator-facing output.
func (d DocumentState) Describe() string {
	return fmt.Sprintf("%s / %s", StatusName(d.Status), ResultName(d.Result))
}

// Describe renders a shipment's state in the portal's own words.
func (d DocumentStateUTC) Describe() string {
	return fmt.Sprintf("%s / %s", StatusName(d.Status), ResultName(d.Result))
}
