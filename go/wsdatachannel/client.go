package wsdatachannel

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Namespace is the WsDataChannel service namespace. Operation wrappers live in
// it; their parameters do not, which is why they are written unqualified.
const Namespace = "https://sender.logalty.net/lgtportal/wsDataChannel"

// Endpoints Logalty publishes. Your production endpoint comes from them
// directly; there is no constant for it here.
const (
	// EndpointDemo is the demo environment. Its portal — where the same
	// shipments can be seen in a browser — is at
	// https://www.demo.logalty.es/lgt/frontendweb.
	EndpointDemo = "https://www.demo.logalty.es/lgt/lgtweb/wsDataChannel"

	// EndpointDevelopment is what the Java SDK's service locator defaults to.
	// It is not the demo environment, and it is not reachable from everywhere.
	EndpointDevelopment = "https://desarrollo.logalty.com/lgtportal/wsDataChannel"
)

const (
	namespaceSOAPEnvelope = "http://schemas.xmlsoap.org/soap/envelope/"
	namespaceXSD          = "http://www.w3.org/2001/XMLSchema"
	namespaceXSI          = "http://www.w3.org/2001/XMLSchema-instance"
)

// maxResponseBytes caps how much of a response is read. Downloads of evidence
// packs are legitimately large, so this is generous; it exists only to stop a
// misbehaving endpoint from exhausting memory.
const maxResponseBytes = 256 << 20

// Client calls the WsDataChannel service.
//
// The username and password every operation takes are held here rather than
// repeated in each call, which is the one place this port deliberately departs
// from the Java stubs' signatures.
//
// A Client is safe for concurrent use.
type Client struct {
	endpoint string
	username string
	password string
	http     *http.Client
}

// NewClient returns a Client for the given endpoint and credentials.
//
// Pass nil for httpClient to get one with a 5-minute timeout, which suits the
// synchronous send and bulk download operations. Supply your own when you need
// different timeouts, a proxy, or client certificates.
func NewClient(endpoint, username, password string, httpClient *http.Client) (*Client, error) {
	if endpoint == "" {
		return nil, errors.New("wsdatachannel: endpoint is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Minute}
	}
	return &Client{
		endpoint: endpoint,
		username: username,
		password: password,
		http:     httpClient,
	}, nil
}

// param is one child element of an operation wrapper. Values are marshalled by
// encoding/xml, so a nil pointer or an empty slice contributes nothing —
// matching how the Axis stubs omit absent parameters.
type param struct {
	name  string
	value any
}

// Fault is a SOAP 1.1 fault returned by the service.
type Fault struct {
	Code   string `xml:"faultcode"`
	String string `xml:"faultstring"`
	Actor  string `xml:"faultactor"`
	Detail struct {
		Raw string `xml:",innerxml"`
	} `xml:"detail"`
}

func (f *Fault) Error() string {
	message := f.String
	if message == "" {
		message = "(no faultstring)"
	}
	if f.Code != "" {
		return fmt.Sprintf("wsdatachannel: SOAP fault %s: %s", f.Code, message)
	}
	return "wsdatachannel: SOAP fault: " + message
}

// HTTPError is returned when the endpoint answers with a non-200 status and no
// parseable SOAP fault.
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	body := strings.TrimSpace(e.Body)
	if len(body) > 512 {
		body = body[:512] + "..."
	}
	return fmt.Sprintf("wsdatachannel: HTTP %d: %s", e.StatusCode, body)
}

// call performs one document/literal wrapped SOAP 1.1 request. Credentials are
// prepended to params, since every operation takes them first.
func (c *Client) call(ctx context.Context, operation string, params []param, result any) error {
	body, err := c.buildRequest(operation, params)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("wsdatachannel: build request: %w", err)
	}
	request.Header.Set("Content-Type", "text/xml; charset=utf-8")
	// Axis sets an empty SOAPAction but still sends the header; some
	// dispatchers reject the request when it is missing altogether.
	request.Header.Set("SOAPAction", `""`)

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("wsdatachannel: %s: %w", operation, err)
	}
	defer response.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("wsdatachannel: %s: read response: %w", operation, err)
	}

	return c.decodeResponse(operation, response.StatusCode, raw, result)
}

// buildRequest writes the SOAP envelope, reproducing what the Axis 1.4 stubs
// put on the wire. The element structure is identical; the serialization
// differs only where XML says it cannot matter, in attribute order and in
// whether non-ASCII text is escaped as character references.
//
// The shape is worth spelling out, because it looks redundant and is not. The
// operation wrapper declares the service namespace as the *default* namespace,
// and then every parameter resets it with xmlns="". Parameters are unqualified
// in this service's schema, so without the reset they would be dragged into the
// service namespace and the server would not recognize them.
func (c *Client) buildRequest(operation string, params []param) ([]byte, error) {
	var buf bytes.Buffer
	// Written by hand rather than with xml.Header, which adds a newline Axis
	// does not send.
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)

	encoder := xml.NewEncoder(&buf)

	envelope := xml.StartElement{
		Name: xml.Name{Local: "soapenv:Envelope"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns:soapenv"}, Value: namespaceSOAPEnvelope},
			{Name: xml.Name{Local: "xmlns:xsd"}, Value: namespaceXSD},
			{Name: xml.Name{Local: "xmlns:xsi"}, Value: namespaceXSI},
		},
	}
	bodyElement := xml.StartElement{Name: xml.Name{Local: "soapenv:Body"}}
	wrapper := xml.StartElement{
		Name: xml.Name{Local: operation},
		Attr: []xml.Attr{{Name: xml.Name{Local: "xmlns"}, Value: Namespace}},
	}

	for _, token := range []xml.Token{envelope, bodyElement, wrapper} {
		if err := encoder.EncodeToken(token); err != nil {
			return nil, fmt.Errorf("wsdatachannel: encode envelope: %w", err)
		}
	}

	// Credentials always go out, even when blank, so that an unauthenticated
	// call fails with the service's own error rather than a malformed request.
	all := append([]param{
		{"username", c.username},
		{"password", c.password},
	}, params...)

	for i, p := range all {
		if i >= 2 && omitted(p.value) {
			continue
		}
		start := xml.StartElement{
			Name: xml.Name{Local: p.name},
			Attr: append([]xml.Attr{{Name: xml.Name{Local: "xmlns"}, Value: ""}}, xsiTypeAttrs(p.value)...),
		}
		if err := encoder.EncodeElement(p.value, start); err != nil {
			return nil, fmt.Errorf("wsdatachannel: encode %s: %w", p.name, err)
		}
	}

	for _, token := range []xml.Token{wrapper.End(), bodyElement.End(), envelope.End()} {
		if err := encoder.EncodeToken(token); err != nil {
			return nil, fmt.Errorf("wsdatachannel: encode envelope: %w", err)
		}
	}
	if err := encoder.Flush(); err != nil {
		return nil, fmt.Errorf("wsdatachannel: encode envelope: %w", err)
	}
	return buf.Bytes(), nil
}

// omitted reports whether a parameter should be left out of the request. Axis
// omits null parameters, and Go has no null string, so an empty string is
// treated as absent. Empty slices encode to nothing on their own.
func omitted(value any) bool {
	s, ok := value.(string)
	return ok && s == ""
}

// xsiTypeAttrs reproduces an Axis quirk that shows up on exactly two
// parameters.
//
// Axis tags an element with an explicit xsi:type whenever the schema type named
// in the parameter descriptor differs from the one its class is registered
// under. Two descriptors in the Java stub disagree with their registrations:
// the "file" parameter is declared as type "file" while BinaryContentItem is
// registered as "binaryContentItem", and the singular "templateReceivers"
// parameter is declared as type "templateReceivers" while TemplateReceiver is
// registered as "templateReceiver". The plural template parameter names the
// type correctly and gets no xsi:type — hence the asymmetry below between the
// slice and non-slice cases.
//
// The attribute is redundant for a document/literal service, but it is what the
// portal has been receiving for years, so it is reproduced rather than tidied.
func xsiTypeAttrs(value any) []xml.Attr {
	var xsdType string
	switch value.(type) {
	case BinaryContentItem, []BinaryContentItem:
		xsdType = "binaryContentItem"
	case TemplateReceiver:
		xsdType = "templateReceiver"
	default:
		return nil
	}
	return []xml.Attr{
		{Name: xml.Name{Local: "xmlns:ns1"}, Value: Namespace},
		{Name: xml.Name{Local: "xsi:type"}, Value: "ns1:" + xsdType},
	}
}

// soapEnvelope captures just enough of the response to separate a fault from a
// result. The body is kept raw so each operation can decode its own payload.
type soapEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		Fault *Fault `xml:"Fault"`
		Inner string `xml:",innerxml"`
	} `xml:"Body"`
}

func (c *Client) decodeResponse(operation string, statusCode int, raw []byte, result any) error {
	var envelope soapEnvelope
	parseErr := xml.Unmarshal(raw, &envelope)

	// A fault is the meaningful error even when it arrives with HTTP 500,
	// which is what SOAP 1.1 prescribes, so check it before the status code.
	if parseErr == nil && envelope.Body.Fault != nil {
		return envelope.Body.Fault
	}
	if statusCode != http.StatusOK {
		return &HTTPError{StatusCode: statusCode, Body: string(raw)}
	}
	if parseErr != nil {
		return fmt.Errorf("wsdatachannel: %s: parse response: %w", operation, parseErr)
	}
	if result == nil {
		return nil
	}

	// An empty body carries no payload — the portal answers this way for
	// operations that found nothing. Leave the result at its zero value.
	if strings.TrimSpace(envelope.Body.Inner) == "" {
		return nil
	}

	// Body.Inner holds the operation's response wrapper. Namespace prefixes
	// declared on the envelope are not carried into it, but the response
	// structs match on local names only, so decoding is unaffected.
	if err := xml.Unmarshal([]byte(envelope.Body.Inner), result); err != nil {
		return fmt.Errorf("wsdatachannel: %s: decode result: %w", operation, err)
	}
	return nil
}

// The three envelope shapes cover every operation: Axis names the response
// payload "result", "results" or "document" depending on the operation.

type resultEnvelope[T any] struct {
	Value T `xml:"result"`
}

type resultsEnvelope[T any] struct {
	Value T `xml:"results"`
}

type documentEnvelope[T any] struct {
	Value T `xml:"document"`
}
