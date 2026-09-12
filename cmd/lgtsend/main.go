// Command lgtsend submits a document to Logalty LGT Portal for signature and
// polls its state, using the Go port of the lgtweb SDK.
//
// It exists to exercise the SDK against a real endpoint. Sending is an
// irreversible, outward-facing action — the portal notifies the receiver — so
// nothing is sent unless -send is given. By default the request is printed and
// the command stops.
//
//	# See exactly what would go on the wire, without sending
//	lgtsend -name Ana -lastname1 García -id 12345678Z -idtype NIF \
//	    -email ana@example.com -mobile +34600000000 -file contract.pdf
//
//	# Actually send
//	lgtsend ... -send
//
//	# Poll a shipment afterwards, then build a sign-in URL for its signer
//	lgtsend -status GUID-OR-EXTERNAL-ID
//	lgtsend -saml GUID -id 12345678Z
//
// The endpoint, credentials and sending company come from LOGALTY_ENDPOINT,
// LOGALTY_USER, LOGALTY_PASSWORD, LOGALTY_COMPANY and LOGALTY_TYPE, which are
// read from a .env file in the repository root if they are not already set.
// Flags override both.
//
// Prefer the file or the environment over -user and -password: command-line
// arguments are visible to every other process on the machine.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BaesBlockchainLabs/logalsend-go/wsdatachannel"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lgtsend:", err)
		os.Exit(1)
	}
}

type options struct {
	endpoint string
	user     string
	password string

	company string
	typeID  string

	name      string
	midName   string
	lastName1 string
	lastName2 string
	identity  string
	idType    string
	email     string
	mobile    string

	externalID string
	senderName string
	subject    string
	file       string
	fileName   string
	mimeType   string
	language   string

	send      bool
	sync      bool
	debug     bool
	status    string
	samlFor   string
	download  string
	attrsFor  string
	outDir    string
	timeout   time.Duration
	pollEvery time.Duration
	pollFor   time.Duration
}

func run() error {
	var o options

	// Load .env before the flags are declared, so its values can serve as
	// their defaults. A variable already present in the real environment wins,
	// which keeps CI and one-off overrides working.
	loadDotEnv()

	flag.StringVar(&o.endpoint, "endpoint", os.Getenv("LOGALTY_ENDPOINT"),
		"WsDataChannel SOAP endpoint URL (default $LOGALTY_ENDPOINT)")
	flag.StringVar(&o.user, "user", os.Getenv("LOGALTY_USER"), "username (default $LOGALTY_USER)")
	flag.StringVar(&o.password, "password", os.Getenv("LOGALTY_PASSWORD"), "password (default $LOGALTY_PASSWORD)")

	flag.StringVar(&o.company, "company", os.Getenv("LOGALTY_COMPANY"),
		"companyId (default $LOGALTY_COMPANY)")
	flag.StringVar(&o.typeID, "type", os.Getenv("LOGALTY_TYPE"),
		"typeId, the shipment type configured for the company (default $LOGALTY_TYPE)")

	flag.StringVar(&o.name, "name", "", "receiver's first name")
	flag.StringVar(&o.midName, "midname", "", "receiver's middle name")
	flag.StringVar(&o.lastName1, "lastname1", "", "receiver's first surname")
	flag.StringVar(&o.lastName2, "lastname2", "", "receiver's second surname")
	flag.StringVar(&o.identity, "id", "", "receiver's identity document number")
	flag.StringVar(&o.idType, "idtype", "NIF", "receiver's identity document type")
	flag.StringVar(&o.email, "email", "", "receiver's email address")
	flag.StringVar(&o.mobile, "mobile", "", "receiver's mobile, in +34... form")

	flag.StringVar(&o.externalID, "external-id", "", "your own identifier for this shipment")
	flag.StringVar(&o.senderName, "sender", "",
		"name shown in the notification's \"Enviado por\" line (email shipment types only)")
	flag.StringVar(&o.subject, "subject", "", "subject line of the certified email")
	flag.StringVar(&o.file, "file", "", "path to the document to send")
	flag.StringVar(&o.fileName, "file-name", "", "file name shown to the receiver (default: the file's base name)")
	flag.StringVar(&o.mimeType, "mime", "application/pdf", "document MIME type")
	flag.StringVar(&o.language, "language", "es-ES", "signer's UI language, synchronous send only")

	flag.BoolVar(&o.send, "send", false, "actually send; without it the request is printed and nothing leaves the machine")
	flag.BoolVar(&o.sync, "sync", false, "use the synchronous send, which returns a sign-in URL instead of notifying the receiver")
	flag.StringVar(&o.status, "status", "", "poll this GUID or external id instead of sending")
	flag.StringVar(&o.samlFor, "saml", "", "build a sign-in URL for this GUID instead of sending; needs -id for the receiver")
	flag.StringVar(&o.download, "download", "",
		"download artefacts for this GUID instead of sending; see -kinds")
	flag.StringVar(&o.attrsFor, "attrs", "",
		"print the identity attributes verified for this GUID instead of sending")
	flag.StringVar(&o.outDir, "out", ".", "directory to write downloads into")
	flag.BoolVar(&o.debug, "debug", false, "dump the raw SOAP request and response, with the password redacted")
	flag.DurationVar(&o.timeout, "timeout", 2*time.Minute, "HTTP timeout")
	flag.DurationVar(&o.pollEvery, "poll-every", 15*time.Second, "interval between status checks")
	flag.DurationVar(&o.pollFor, "poll-for", 0, "keep polling the new shipment for this long after sending")

	flag.Parse()

	if o.endpoint == "" {
		return errors.New("-endpoint is required (or set LOGALTY_ENDPOINT, or put it in .env)")
	}

	var httpClient *http.Client
	if o.debug {
		httpClient = &http.Client{
			Timeout:   o.timeout + o.pollFor,
			Transport: &debugTransport{next: http.DefaultTransport},
		}
	}
	client, err := wsdatachannel.NewClient(o.endpoint, o.user, o.password, httpClient)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout+o.pollFor)
	defer cancel()

	if o.status != "" {
		return showStatus(ctx, client, o.status)
	}
	if o.samlFor != "" {
		return showSamlURL(ctx, client, o.samlFor, o.identity)
	}
	if o.download != "" {
		return download(ctx, client, o.download, o.outDir)
	}
	if o.attrsFor != "" {
		return showAttributes(ctx, client, o.attrsFor)
	}
	return send(ctx, client, o)
}

// showAttributes fetches and decodes the identity certificate for a completed
// identity-validation shipment.
//
// Everything it prints is personal data about the subject, so it goes to
// stdout and nowhere else — do not wire this into a log.
func showAttributes(ctx context.Context, client *wsdatachannel.Client, guid string) error {
	doc, err := client.DownloadDocument(ctx,
		wsdatachannel.DocumentIdentificationOCRXML, wsdatachannel.IdentifyByGUID, guid)
	if err != nil {
		return err
	}
	if doc.Binary == "" {
		return errors.New("no identity certificate for this shipment — it may not be an " +
			"identity-validation type, or the subject may not have finished")
	}
	raw, err := wsdatachannel.DecodeBinary(doc.Binary)
	if err != nil {
		return err
	}
	cert, err := wsdatachannel.ParseIdentityCertificate(raw)
	if err != nil {
		return err
	}

	a, v := cert.Attributes, cert.Verification
	fmt.Printf("%-22s %s\n", "Verificación", verdict(cert))
	fmt.Printf("%-22s %s (%s)\n", "Resultado", cert.Reason, cert.ResultDate.Format("2006-01-02 15:04:05"))
	fmt.Println()
	for _, f := range [][2]string{
		{"Documento", a.DocumentType + " " + a.IDNumber},
		{"Nº de soporte", a.DocumentNumber},
		{"Nombre", a.FullName()},
		{"Sexo", a.Sex},
		{"Nacimiento", a.BirthDate.Format("2006-01-02") + "  " + a.BirthPlace},
		{"Domicilio", a.StreetAddress},
		{"Nacionalidad", a.Nationality},
		{"Expedición", a.ExpeditionDate.Format("2006-01-02")},
		{"Caducidad", a.ExpiryDate.Format("2006-01-02")},
		{"Emisor", a.Issuer},
		{"Método", a.Method + " (" + a.SelectedDocumentType + ")"},
	} {
		fmt.Printf("  %-20s %s\n", f[0], f[1])
	}

	fmt.Printf("\n  %-20s %.2f%% coincidencia, %.2f%% prueba de vida\n",
		"Biometría", v.FaceMatch*100, v.Liveness*100)
	fmt.Printf("  %-20s %.2f%% autenticidad, %.2f%% semejanza\n",
		"Selfie", v.SelfieAuthenticity*100, v.SelfieSimilarity*100)
	fmt.Printf("  %-20s chip %v, lectura %v, %d reintentos\n",
		"NFC", v.NFCChipPresent, v.NFCReadSuccessful, v.NFCErrorRetries)

	fmt.Println("\n  Consentimientos")
	for _, c := range cert.Consents {
		fmt.Printf("    %-38s %v\n", c.ID, c.Given)
	}

	fmt.Println("\n  Artefactos firmados")
	for _, art := range cert.Artifacts {
		status := "hash verificado"
		if err := art.VerifyHash(); err != nil {
			status = "HASH NO COINCIDE"
		}
		fmt.Printf("    %-30s %-4s %s\n", art.Kind, art.Extension, status)
	}
	return nil
}

func verdict(cert *wsdatachannel.IdentityCertificate) string {
	if cert.Passed() {
		return "SUPERADA"
	}
	failed := cert.FailedChecks()
	codes := make([]string, len(failed))
	for i, f := range failed {
		codes[i] = f.Code
	}
	if len(codes) == 0 {
		return "NO SUPERADA (resultado global negativo)"
	}
	return "NO SUPERADA: " + strings.Join(codes, ", ")
}

// downloadable lists the artefacts worth trying for a finished shipment, in
// the order they are most likely to exist. Which ones a shipment actually has
// depends on its type and on how far it got, so failures are reported and
// skipped rather than treated as fatal.
var downloadable = []struct {
	kind wsdatachannel.DocumentType
	name string
}{
	{wsdatachannel.DocumentSigned, "signed"},
	{wsdatachannel.DocumentStamped, "stamped"},
	{wsdatachannel.DocumentOriginal, "original"},
	{wsdatachannel.DocumentLogaltyCertificate, "certificate"},
	{wsdatachannel.DocumentLogaltyCertificateXML, "certificate-xml"},
	{wsdatachannel.DocumentEvidencePack, "evidence-pack"},
	{wsdatachannel.DocumentPostalNoticeReport, "notice-report"},
	{wsdatachannel.DocumentPostalCourierCertificate, "delivery-note"},
	{wsdatachannel.DocumentIdentificationOCRCertificate, "idcard-ocr"},
	{wsdatachannel.DocumentIdentificationOCRXML, "idcard-ocr-xml"},
	{wsdatachannel.DocumentIdentificationImages, "idcard-images"},
	{wsdatachannel.DocumentVideoCertificate, "video-certificate"},
}

// download fetches every artefact the portal will part with, which is the
// empirical way to find out how far a shipment actually got: a signed document
// exists only if it was signed.
func download(ctx context.Context, client *wsdatachannel.Client, guid, outDir string) error {
	found := 0
	for _, item := range downloadable {
		doc, err := client.DownloadDocument(ctx, item.kind, wsdatachannel.IdentifyByGUID, guid)
		if err != nil {
			fmt.Printf("  %-16s unavailable: %v\n", item.name, err)
			continue
		}
		if doc.Binary == "" {
			fmt.Printf("  %-16s empty\n", item.name)
			continue
		}
		data, err := wsdatachannel.DecodeBinary(doc.Binary)
		if err != nil {
			fmt.Printf("  %-16s undecodable: %v\n", item.name, err)
			continue
		}
		path := filepath.Join(outDir, fmt.Sprintf("%s-%s%s", sanitize(guid), item.name, extensionFor(data)))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return err
		}
		fmt.Printf("  %-16s %7d bytes -> %s\n", item.name, len(data), path)
		found++
	}
	if found == 0 {
		return errors.New("the portal returned no artefacts for this shipment")
	}
	return nil
}

// extensionFor guesses from the payload's magic bytes, since the portal does
// not say what it just handed over.
func extensionFor(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte("%PDF")):
		return ".pdf"
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		return ".zip"
	case bytes.HasPrefix(bytes.TrimSpace(data), []byte("<")):
		return ".xml"
	default:
		return ".bin"
	}
}

// sanitize makes a GUID safe to use in a file name.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(`/\:*?"<>|`, r) {
			return '-'
		}
		return r
	}, s)
}

// debugTransport prints each exchange so the portal's own words can be read
// rather than inferred from the decoded structs. The password is redacted; the
// document payload is elided.
type debugTransport struct {
	next http.RoundTripper
}

func (t *debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		fmt.Fprintln(os.Stderr, "--- request ---")
		fmt.Fprintln(os.Stderr, indentXML(redactPassword(elideBase64(string(body)))))
	}

	response, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(body))

	fmt.Fprintf(os.Stderr, "--- response (HTTP %d) ---\n", response.StatusCode)
	fmt.Fprintln(os.Stderr, indentXML(elideBase64(string(body))))
	fmt.Fprintln(os.Stderr, "---")
	return response, nil
}

// loadDotEnv reads KEY=VALUE pairs from a .env file into the environment.
//
// It looks in the working directory and then walks up, so the command works
// from anywhere inside the repository. Variables already set are left alone:
// the real environment always beats the file.
//
// This is a deliberately small parser — comments, blank lines, optional quotes
// and nothing else. It is not a shell, so no expansion or substitution happens.
func loadDotEnv() {
	path, ok := findUp(".env", 5)
	if !ok {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if key == "" {
			continue
		}
		if _, set := os.LookupEnv(key); set {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return
		}
	}
}

// findUp looks for name in the working directory and its ancestors.
func findUp(name string, levels int) (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for i := 0; i < levels; i++ {
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", false
}

func send(ctx context.Context, client *wsdatachannel.Client, o options) error {
	request, err := buildRequest(o)
	if err != nil {
		return err
	}

	if !o.send {
		describe(o, request)
		fmt.Println()
		fmt.Println("Nothing was sent. Re-run with -send to submit this shipment.")
		return nil
	}

	describe(o, request)
	fmt.Println()

	outcome, err := dispatch(ctx, client, o, multiRequest(o, request))
	if err != nil {
		return err
	}

	var guid string
	for _, result := range outcome.results {
		report(result)
		if err := result.Err(); err != nil {
			return err
		}
		if guid == "" {
			guid = firstGUID(result)
		}
	}
	if len(outcome.links) > 0 {
		fmt.Println("\nSign-in URLs:")
		for _, link := range outcome.links {
			fmt.Printf("  %-14s %s\n", link.Receiver, link.URL)
		}
	}

	if guid != "" && o.pollFor > 0 {
		return poll(ctx, client, guid, o.pollEvery, o.pollFor)
	}
	return nil
}

func buildRequest(o options) (wsdatachannel.SendRequest, error) {
	if o.company == "" || o.typeID == "" {
		return wsdatachannel.SendRequest{}, errors.New("-company and -type are required")
	}
	if o.name == "" || o.identity == "" {
		return wsdatachannel.SendRequest{}, errors.New("-name and -id are required")
	}
	if o.email == "" && o.mobile == "" {
		return wsdatachannel.SendRequest{}, errors.New("the receiver needs an -email or a -mobile to be reachable")
	}

	// The document is optional. An identity-verification type carries no
	// document at all, and the three file parameters are simply left out —
	// which is what the Axis stubs do for a null argument.
	var content, fileName, mimeType string
	if o.file != "" {
		document, err := os.ReadFile(o.file)
		if err != nil {
			return wsdatachannel.SendRequest{}, fmt.Errorf("read document: %w", err)
		}
		content = wsdatachannel.EncodeContent(document)
		mimeType = o.mimeType
		fileName = o.fileName
		if fileName == "" {
			fileName = baseName(o.file)
		}
	}

	return wsdatachannel.SendRequest{
		CompanyID: o.company,
		TypeID:    o.typeID,
		Receivers: []wsdatachannel.Receiver{{
			ExternalID:           o.externalID,
			ReceiverName:         o.name,
			ReceiverMidName:      o.midName,
			ReceiverLastName1:    o.lastName1,
			ReceiverLastName2:    o.lastName2,
			ReceiverIdentityID:   o.identity,
			ReceiverIdentityType: o.idType,
			ReceiverEmail:        o.email,
			ReceiverMobile:       o.mobile,
		}},
		FileType:    mimeType,
		FileName:    fileName,
		FileContent: content,
		Language:    o.language,
	}, nil
}

// describe prints what is about to happen in human terms, then the request
// itself with the document body elided — a base64 PDF is unreadable and would
// bury everything else.
func describe(o options, request wsdatachannel.SendRequest) {
	mode := "asynchronous (the portal notifies the receiver)"
	if o.sync {
		mode = "synchronous (returns a sign-in URL; the receiver is not notified)"
	}

	fmt.Println("Endpoint: ", o.endpoint)
	fmt.Println("User:     ", o.user)
	fmt.Println("Company:  ", request.CompanyID, " Type:", request.TypeID)
	fmt.Println("Mode:     ", mode)

	r := request.Receivers[0]
	fmt.Printf("Receiver:  %s %s %s (%s %s)\n",
		r.ReceiverName, r.ReceiverLastName1, r.ReceiverLastName2, r.ReceiverIdentityType, r.ReceiverIdentityID)
	if r.ReceiverEmail != "" {
		fmt.Println("  email:  ", r.ReceiverEmail)
	}
	if r.ReceiverMobile != "" {
		fmt.Println("  mobile: ", r.ReceiverMobile)
	}
	if r.ExternalID != "" {
		fmt.Println("  ref:    ", r.ExternalID)
	}
	if request.FileContent == "" {
		fmt.Println("Document:  none — the request carries no document")
	} else {
		fmt.Printf("Document:  %s (%s, %d bytes before encoding)\n",
			request.FileName, request.FileType, decodedSize(request.FileContent))
	}

	envelope, err := captureEnvelope(o, request)
	if err != nil {
		fmt.Println("\n(could not render the request:", err, ")")
		return
	}
	fmt.Println("\nSOAP request:")
	fmt.Println(indentXML(redactPassword(elideBase64(envelope))))
}

// multiRequest turns the flags into the request both send variants take.
//
// Only the MultiReceiver operations are used. The single-receiver ones are
// deprecated — the integration guide calls using
// shippingSynchronousSendMultiReceiver mandatory — and these cover one
// receiver just as well.
func multiRequest(o options, request wsdatachannel.SendRequest) wsdatachannel.MultiReceiverSendRequest {
	multi := wsdatachannel.MultiReceiverSendRequest{
		CompanyID:  request.CompanyID,
		TypeID:     request.TypeID,
		Receivers:  request.Receivers,
		SenderName: o.senderName,
		ExternalID: o.externalID,
		Subject:    o.subject,
		Language:   request.Language,
	}
	if request.FileContent != "" {
		multi.Files = []wsdatachannel.BinaryContentItem{{
			Name:    request.FileName,
			Type:    request.FileType,
			Content: request.FileContent,
		}}
	}
	return multi
}

// sendOutcome flattens what the two send variants return, so the rest of the
// command does not care which one ran.
type sendOutcome struct {
	results []wsdatachannel.RemmitanceResult
	links   []wsdatachannel.ReceiverURL
}

// dispatch performs the send.
//
// Both the preview and the real send go through here. They used to build the
// call separately, and drifted: the preview kept showing the deprecated
// single-receiver operation after the send moved to the MultiReceiver one, so
// the request it printed was not the request that would be sent. Routing both
// through one function makes that impossible rather than merely fixed.
func dispatch(ctx context.Context, client *wsdatachannel.Client, o options,
	multi wsdatachannel.MultiReceiverSendRequest) (sendOutcome, error) {

	var outcome sendOutcome

	if o.sync {
		results, err := client.ShippingSynchronousSendMultiReceiver(ctx, multi)
		if err != nil {
			return outcome, err
		}
		for _, r := range results {
			outcome.results = append(outcome.results, r.RemmitanceResult)
			outcome.links = append(outcome.links, r.Link...)
		}
		return outcome, nil
	}

	results, err := client.ShippingSendMultiReceiver(ctx, multi)
	if err != nil {
		return outcome, err
	}
	outcome.results = append(outcome.results, results...)
	return outcome, nil
}

// captureEnvelope runs the real send through a transport that records the
// request and answers locally, so the bytes shown are the bytes that would go
// out — not a second rendering that might disagree with the first.
func captureEnvelope(o options, request wsdatachannel.SendRequest) (string, error) {
	capture := &captureTransport{}
	client, err := wsdatachannel.NewClient(o.endpoint, o.user, o.password,
		&http.Client{Transport: capture})
	if err != nil {
		return "", err
	}

	if _, err := dispatch(context.Background(), client, o, multiRequest(o, request)); err != nil {
		return "", err
	}
	return capture.body, nil
}

// captureTransport records the request body and replies with an empty SOAP
// envelope without opening a connection.
type captureTransport struct {
	body string
}

func (t *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		t.body = string(body)
	}
	const empty = `<?xml version="1.0" encoding="UTF-8"?>` +
		`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<soapenv:Body/></soapenv:Envelope>`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/xml; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(empty)),
		Request:    req,
	}, nil
}

// elideBase64 replaces long base64 payloads with a placeholder. A document is
// thousands of unreadable characters that would bury everything worth checking.
//
// It works on any element rather than a named one: the payload lives in
// <FileContent> for the single-receiver operations and in <content> for the
// MultiReceiver ones, and hunting for one name meant the other went through
// unelided.
func elideBase64(envelope string) string {
	const threshold = 200

	var b strings.Builder
	for i := 0; i < len(envelope); {
		open := strings.IndexByte(envelope[i:], '>')
		if open < 0 {
			b.WriteString(envelope[i:])
			break
		}
		open += i
		b.WriteString(envelope[i : open+1])

		close := strings.IndexByte(envelope[open+1:], '<')
		if close < 0 {
			b.WriteString(envelope[open+1:])
			break
		}
		close += open + 1

		text := envelope[open+1 : close]
		if len(text) >= threshold && isBase64(text) {
			fmt.Fprintf(&b, "[%d base64 chars elided]", len(text))
		} else {
			b.WriteString(text)
		}
		i = close
	}
	return b.String()
}

// isBase64 reports whether every byte could belong to base64 content,
// whitespace included.
func isBase64(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+', c == '/', c == '=', c == '\n', c == '\r':
		default:
			return false
		}
	}
	return true
}

// redactPassword keeps the credential out of the terminal, and out of whatever
// log or bug report the output gets pasted into.
func redactPassword(envelope string) string {
	return replaceElement(envelope, "password", "[redacted]")
}

// replaceElement swaps the text content of the first <name xmlns=""> element.
func replaceElement(document, name, replacement string) string {
	open := "<" + name + ` xmlns="">`
	closing := "</" + name + ">"
	start := strings.Index(document, open)
	if start < 0 {
		return document
	}
	end := strings.Index(document[start:], closing)
	if end < 0 {
		return document
	}
	end += start
	return document[:start+len(open)] + replacement + document[end:]
}

// indentXML lays the envelope out over several lines so it can be read.
//
// It works on the text rather than re-encoding through encoding/xml, which
// would rewrite the namespace declarations — the very thing this SDK writes by
// hand to keep them correct. Only whitespace between tags is added; every other
// byte is the byte that would be sent. Elements with text content stay on one
// line, so a value is never confused with indentation.
func indentXML(document string) string {
	var out strings.Builder
	depth := 0

	for i := 0; i < len(document); {
		if document[i] != '<' {
			next := strings.IndexByte(document[i:], '<')
			if next < 0 {
				out.WriteString(document[i:])
				break
			}
			out.WriteString(document[i : i+next])
			i += next
			continue
		}

		end := strings.IndexByte(document[i:], '>')
		if end < 0 {
			out.WriteString(document[i:])
			break
		}
		tag := document[i : i+end+1]

		closing := strings.HasPrefix(tag, "</")
		selfClosing := strings.HasSuffix(tag, "/>")
		declaration := strings.HasPrefix(tag, "<?")

		if closing {
			depth--
		}
		// Break the line only where one tag directly abuts another, so text
		// content keeps its element on a single line.
		if i > 0 && document[i-1] == '>' {
			out.WriteString("\n")
			out.WriteString(strings.Repeat("  ", max(depth, 0)))
		}
		out.WriteString(tag)
		if !closing && !selfClosing && !declaration {
			depth++
		}
		i += end + 1
	}
	return out.String()
}

func report(result wsdatachannel.RemmitanceResult) {
	if result.RetCode == 0 {
		fmt.Println("Accepted by the portal.")
	} else {
		fmt.Printf("Rejected: retCode %d — %s\n", result.RetCode, result.Message)
	}
	for _, doc := range result.Documents {
		fmt.Printf("  request id %d, guid %s, status %d %s\n",
			doc.ID, doc.GUID, doc.Status, doc.StatusComment)
		if doc.ResultComment != "" {
			fmt.Println("    ", doc.ResultComment)
		}
	}
}

func firstGUID(result wsdatachannel.RemmitanceResult) string {
	for _, doc := range result.Documents {
		if doc.GUID != "" {
			return doc.GUID
		}
	}
	return ""
}

func showStatus(ctx context.Context, client *wsdatachannel.Client, reference string) error {
	// A GUID and an external id are told apart by shape here: the portal's
	// GUIDs are long hex-ish strings, so anything shorter is assumed to be
	// the caller's own reference. Both are queried regardless, and the portal
	// ignores the one that does not match.
	query := wsdatachannel.StatusQuery{
		GUIDs:       []string{reference},
		ExternalIDs: []string{reference},
	}
	states, err := client.ShippingStatus(ctx, query)
	if err != nil {
		return err
	}
	if len(states) == 0 {
		fmt.Println("No shipment matched", reference)
		return nil
	}
	for _, state := range states {
		fmt.Printf("guid %s (id %d, ref %q)\n", state.GUID, state.ID, state.ExternalID)
		fmt.Printf("  status %d %s\n", state.Status, state.StatusComment)
		fmt.Printf("  result %d %s\n", state.Result, state.ResultComment)
		fmt.Printf("  sent %s, updated %s\n", state.SendDate, state.LastUpdate)
	}
	return nil
}

// showSamlURL asks the portal for the URL that signs a receiver in to an
// existing shipment, so they can be redirected straight there instead of
// waiting for the portal's own notification.
func showSamlURL(ctx context.Context, client *wsdatachannel.Client, guid, receiverIdentity string) error {
	if receiverIdentity == "" {
		return errors.New("-saml needs -id, the receiver's identity document")
	}
	result, err := client.BuildSamlURL(ctx, guid, receiverIdentity)
	if err != nil {
		return err
	}
	if result.URL == "" {
		return fmt.Errorf("the portal returned no URL (result %d) for receiver %q",
			result.Result, result.Receiver)
	}
	fmt.Println(result.URL)
	return nil
}

func poll(ctx context.Context, client *wsdatachannel.Client, guid string, every, total time.Duration) error {
	fmt.Printf("\nPolling %s every %s for %s...\n", guid, every, total)
	deadline := time.Now().Add(total)
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		states, err := client.ShippingStatus(ctx, wsdatachannel.StatusQuery{GUIDs: []string{guid}})
		if err != nil {
			return err
		}
		for _, state := range states {
			fmt.Printf("  [%s] status %d %s\n",
				time.Now().Format("15:04:05"), state.Status, state.StatusComment)
		}
	}
	return nil
}

func baseName(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[i+1:]
	}
	return path
}

// decodedSize reports the original byte count of a base64 payload without
// decoding it.
func decodedSize(encoded string) int {
	size := len(encoded) / 4 * 3
	for i := len(encoded) - 1; i >= 0 && encoded[i] == '='; i-- {
		size--
	}
	return size
}
