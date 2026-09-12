package wsdatachannel

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/BaesBlockchainLabs/logalsend-go/xmldsig"
)

// The golden files in testdata are real requests captured off the wire from the
// Apache Axis 1.4 stubs in the Java SDK, driven against a local recorder. They
// are the reference for what this client must send.
func golden(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	return string(data)
}

// recorder stands in for the portal, capturing the request and replying with a
// canned response.
type recorder struct {
	server   *httptest.Server
	request  string
	headers  http.Header
	response string
}

func newRecorder(t *testing.T, response string) *recorder {
	t.Helper()
	r := &recorder{response: response}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body := make([]byte, req.ContentLength)
		if _, err := io.ReadFull(req.Body, body); err != nil {
			t.Errorf("read request: %v", err)
		}
		r.request = string(body)
		r.headers = req.Header.Clone()
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		if _, err := w.Write([]byte(r.response)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *recorder) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(r.server.URL, "user", "pass", r.server.Client())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

const emptyResponse = `<?xml version="1.0" encoding="UTF-8"?>` +
	`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">` +
	`<soapenv:Body/></soapenv:Envelope>`

// sampleReceiver matches the receiver the Java capture harness built.
func sampleReceiver() Receiver {
	order := 1
	return Receiver{
		ReceiverName:         "Ana",
		ReceiverLastName1:    "García",
		ReceiverEmail:        "ana@example.com",
		ReceiverIdentityID:   "12345678Z",
		ReceiverIdentityType: "NIF",
		SignatureOrder:       &order,
	}
}

// sampleTemplate matches the template receiver the Java capture harness built.
func sampleTemplate() TemplateReceiver {
	return TemplateReceiver{
		Receiver: Receiver{
			ExternalID:    "EXT-T1",
			ReceiverName:  "Ana",
			ReceiverEmail: "ana@example.com",
		},
		CompanyID:   "311",
		TypeID:      "TYPE1",
		TemplateID:  "TPL-7",
		PDFFileName: "out.pdf",
		Field1:      "one",
		Field2:      "two",
		Field10:     "ten",
	}
}

// TestRequestsMatchAxis is the core wire-compatibility check: for each request
// captured from the Java stubs, make the equivalent call and compare.
func TestRequestsMatchAxis(t *testing.T) {
	tests := []struct {
		golden string
		call   func(*Client) error
	}{
		{
			golden: "axis-shippingCertificate.xml",
			call: func(c *Client) error {
				_, err := c.ShippingCertificate(context.Background(), "GUID-0001")
				return err
			},
		},
		{
			golden: "axis-shippingSend.xml",
			call: func(c *Client) error {
				_, err := c.ShippingSend(context.Background(), SendRequest{
					CompanyID:   "311",
					TypeID:      "TYPE1",
					Receivers:   []Receiver{sampleReceiver()},
					FileType:    "pdf",
					FileContent: "SGVsbG8=",
					FileName:    "contract.pdf",
				})
				return err
			},
		},
		{
			golden: "axis-shippingStatus.xml",
			call: func(c *Client) error {
				_, err := c.ShippingStatus(context.Background(), StatusQuery{
					GUIDs:       []string{"GUID-1", "GUID-2"},
					ExternalIDs: []string{"EXT-1"},
				})
				return err
			},
		},
		{
			golden: "axis-shippingRequestList.xml",
			call: func(c *Client) error {
				_, err := c.ShippingRequestList(context.Background(), ShippingListRequest{
					ResponseType: ShippingListCSV,
					DateFrom:     "01/01/2026",
					DateTo:       "31/01/2026",
					DateType:     FilterByCreated,
					CompanyIDs:   []int{311, 312},
				})
				return err
			},
		},
		{
			golden: "axis-shippingSendMultiReceiver.xml",
			call: func(c *Client) error {
				_, err := c.ShippingSendMultiReceiver(context.Background(), MultiReceiverSendRequest{
					CompanyID:  "311",
					TypeID:     "TYPE1",
					Receivers:  []Receiver{sampleReceiver()},
					Files:      []BinaryContentItem{{Name: "doc.pdf", Type: "pdf", Content: "SGVsbG8="}},
					SenderName: "Acme",
					ExternalID: "EXT-99",
					Subject:    "Please sign",
				})
				return err
			},
		},
		{
			golden: "axis-shippingSynchronousSend.xml",
			call: func(c *Client) error {
				_, err := c.ShippingSynchronousSend(context.Background(), SendRequest{
					CompanyID:   "311",
					TypeID:      "TYPE1",
					Receivers:   []Receiver{sampleReceiver()},
					FileType:    "pdf",
					FileContent: "SGVsbG8=",
					FileName:    "contract.pdf",
					Language:    "es",
				})
				return err
			},
		},
		{
			golden: "axis-shippingSendWTemplate.xml",
			call: func(c *Client) error {
				_, err := c.ShippingSendWTemplate(context.Background(), []TemplateReceiver{sampleTemplate()})
				return err
			},
		},
		{
			golden: "axis-shippingSynchronousSendWTemplate.xml",
			call: func(c *Client) error {
				_, err := c.ShippingSynchronousSendWTemplate(context.Background(), sampleTemplate())
				return err
			},
		},
		{
			golden: "axis-shippingStatusMultiReceiver.xml",
			call: func(c *Client) error {
				_, err := c.ShippingStatusMultiReceiver(context.Background(), MultiReceiverStatusQuery{
					GUIDs: []string{"GUID-9"},
					IDs:   []int{1, 2},
				})
				return err
			},
		},
		{
			golden: "axis-buildSamlUrl.xml",
			call: func(c *Client) error {
				_, err := c.BuildSamlURL(context.Background(), "GUID-3", "12345678Z")
				return err
			},
		},
		{
			golden: "axis-downloadDocument.xml",
			call: func(c *Client) error {
				_, err := c.DownloadDocument(context.Background(), DocumentSigned, IdentifyByGUID, "GUID-4")
				return err
			},
		},
		{
			golden: "axis-cancelShipping.xml",
			call: func(c *Client) error {
				_, err := c.CancelShipping(context.Background(), "GUID-5", "99", CancelInvalidData)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.golden, func(t *testing.T) {
			r := newRecorder(t, emptyResponse)
			if err := tt.call(r.client(t)); err != nil {
				t.Fatalf("call: %v", err)
			}

			got, want := canonical(t, r.request), canonical(t, golden(t, tt.golden))
			if got != want {
				t.Errorf("request differs from the Axis capture\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// canonical reduces a request to Canonical XML, which is the level at which
// "the same request" is actually defined.
//
// Two differences from the Axis captures survive byte comparison but are
// meaningless to a parser, so they are normalized away here rather than
// imitated in the client: Axis escapes non-ASCII text as numeric character
// references where Go writes UTF-8, and it happens to order the attributes of
// the <file> element differently. Canonicalization settles both.
func canonical(t *testing.T, document string) string {
	t.Helper()
	doc, err := xmldsig.ParseDocument([]byte(document))
	if err != nil {
		t.Fatalf("parse request: %v\n%s", err, document)
	}
	return string(xmldsig.Canonicalize(doc.Root(), nil))
}

// TestSOAPActionHeader pins the header Axis sends. An absent SOAPAction is a
// common reason for a dispatcher to reject an otherwise valid SOAP 1.1 request.
func TestSOAPActionHeader(t *testing.T) {
	r := newRecorder(t, emptyResponse)
	if _, err := r.client(t).ShippingCertificate(context.Background(), "G"); err != nil {
		t.Fatalf("call: %v", err)
	}
	if got := r.headers.Get("SOAPAction"); got != `""` {
		t.Errorf("SOAPAction = %q, want %q", got, `""`)
	}
	if got := r.headers.Get("Content-Type"); !strings.HasPrefix(got, "text/xml") {
		t.Errorf("Content-Type = %q, want text/xml", got)
	}
}

// TestOmitsAbsentParameters checks that empty parameters are dropped rather
// than sent as empty elements, matching how Axis omits nulls.
func TestOmitsAbsentParameters(t *testing.T) {
	r := newRecorder(t, emptyResponse)
	if _, err := r.client(t).ShippingStatus(context.Background(), StatusQuery{
		GUIDs: []string{"G1"},
	}); err != nil {
		t.Fatalf("call: %v", err)
	}
	for _, absent := range []string{"<id", "<externalId"} {
		if strings.Contains(r.request, absent) {
			t.Errorf("request should not contain %s:\n%s", absent, r.request)
		}
	}
	if !strings.Contains(r.request, `<guid xmlns="">G1</guid>`) {
		t.Errorf("request is missing the guid:\n%s", r.request)
	}
}

// TestDecodeResult exercises the response path against a realistic payload,
// including attribute-carried fields and a repeated child element.
func TestDecodeResult(t *testing.T) {
	response := `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <ns:shippingStatusResponse xmlns:ns="https://sender.logalty.net/lgtportal/wsDataChannel">
   <document guid="G-1" id="42" externalId="EXT-1" typeid="7" status="3"
             statusComment="Signed" result="0" resultComment="OK"
             sendate="01/02/2026 10:00:00" resultdate="01/02/2026 11:00:00"
             lastupdate="01/02/2026 11:00:01"/>
   <document guid="G-2" id="43" status="1" statusComment="Pending"/>
  </ns:shippingStatusResponse>
 </soapenv:Body>
</soapenv:Envelope>`

	r := newRecorder(t, response)
	states, err := r.client(t).ShippingStatus(context.Background(), StatusQuery{GUIDs: []string{"G-1", "G-2"}})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if len(states) != 2 {
		t.Fatalf("got %d states, want 2", len(states))
	}
	if states[0].GUID != "G-1" || states[0].ID != 42 || states[0].StatusComment != "Signed" {
		t.Errorf("first state decoded wrong: %+v", states[0])
	}
	if states[0].SendDate != "01/02/2026 10:00:00" {
		t.Errorf("SendDate = %q", states[0].SendDate)
	}
	if states[1].GUID != "G-2" || states[1].Status != 1 {
		t.Errorf("second state decoded wrong: %+v", states[1])
	}
}

// TestDecodeUTCTimestamps covers the dateTime handling, including the
// offset-less form the portal sometimes emits.
func TestDecodeUTCTimestamps(t *testing.T) {
	response := `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body><shippingStatusUTCResponse>
  <document guid="G-1" sendate="2026-02-01T10:00:00Z" resultdate="2026-02-01T11:30:00"/>
 </shippingStatusUTCResponse></soapenv:Body>
</soapenv:Envelope>`

	r := newRecorder(t, response)
	states, err := r.client(t).ShippingStatusUTC(context.Background(), StatusQuery{GUIDs: []string{"G-1"}})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("got %d states, want 1", len(states))
	}
	if got := states[0].SendDate.UTC().Format("2006-01-02 15:04:05"); got != "2026-02-01 10:00:00" {
		t.Errorf("SendDate = %s", got)
	}
	if got := states[0].ResultDate.Format("2006-01-02 15:04:05"); got != "2026-02-01 11:30:00" {
		t.Errorf("ResultDate = %s", got)
	}
	if !states[0].LastUpdate.IsZero() {
		t.Error("a missing dateTime attribute should decode to the zero time")
	}
}

// TestFault checks that a SOAP fault becomes a typed error even though it
// arrives with HTTP 500, as SOAP 1.1 prescribes.
func TestFault(t *testing.T) {
	response := `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <soapenv:Fault>
   <faultcode>soapenv:Server.userException</faultcode>
   <faultstring>Invalid credentials</faultstring>
   <detail><ns:hostname xmlns:ns="http://xml.apache.org/axis/">lgt01</ns:hostname></detail>
  </soapenv:Fault>
 </soapenv:Body>
</soapenv:Envelope>`

	r := &recorder{response: response}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte(response)); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(r.server.Close)

	_, err := r.client(t).ShippingCertificate(context.Background(), "G")
	if err == nil {
		t.Fatal("expected an error")
	}
	fault, ok := err.(*Fault)
	if !ok {
		t.Fatalf("got %T, want *Fault: %v", err, err)
	}
	if fault.String != "Invalid credentials" {
		t.Errorf("faultstring = %q", fault.String)
	}
	if !strings.Contains(fault.Detail.Raw, "lgt01") {
		t.Errorf("detail was not captured: %q", fault.Detail.Raw)
	}
}

// TestHTTPErrorWithoutFault covers a gateway or proxy answering with something
// that is not SOAP at all.
func TestHTTPErrorWithoutFault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		if _, err := w.Write([]byte("<html>gateway down</html>")); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	c, err := NewClient(server.URL, "u", "p", server.Client())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	_, err = c.ShippingCertificate(context.Background(), "G")
	httpErr, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("got %T, want *HTTPError: %v", err, err)
	}
	if httpErr.StatusCode != http.StatusBadGateway {
		t.Errorf("StatusCode = %d", httpErr.StatusCode)
	}
}

// TestRemmitanceResultErr checks the convenience wrapper over the portal's
// business-level return code.
func TestRemmitanceResultErr(t *testing.T) {
	if err := (RemmitanceResult{RetCode: 0}).Err(); err != nil {
		t.Errorf("RetCode 0 should not be an error: %v", err)
	}
	err := (RemmitanceResult{RetCode: -7, Message: "unknown company"}).Err()
	if err == nil {
		t.Fatal("expected an error for a non-zero RetCode")
	}
	if !strings.Contains(err.Error(), "unknown company") {
		t.Errorf("error should carry the message: %v", err)
	}
}

func TestNewClientRequiresEndpoint(t *testing.T) {
	if _, err := NewClient("", "u", "p", nil); err == nil {
		t.Error("expected an error for an empty endpoint")
	}
}

func TestDecodeBinary(t *testing.T) {
	// Portal payloads arrive wrapped across lines; the decoder must tolerate it.
	data, err := DecodeBinary("SGVsbG8s\r\nIHdvcmxk\n")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(data) != "Hello, world" {
		t.Errorf("got %q", data)
	}
	if got := EncodeContent([]byte("Hello, world")); got != "SGVsbG8sIHdvcmxk" {
		t.Errorf("encode = %q", got)
	}
}

// TestSynchronousSendWithoutReceiver guards the one place a parameter can be a
// nil interface rather than a zero value: the synchronous send takes a single
// receiver, and the caller may have supplied none.
func TestSynchronousSendWithoutReceiver(t *testing.T) {
	r := newRecorder(t, emptyResponse)
	if _, err := r.client(t).ShippingSynchronousSend(context.Background(), SendRequest{
		CompanyID: "311",
		TypeID:    "TYPE1",
		FileType:  "pdf",
		FileName:  "x.pdf",
	}); err != nil {
		t.Fatalf("call: %v", err)
	}
	if strings.Contains(r.request, "<receiver") {
		t.Errorf("an absent receiver should be omitted:\n%s", r.request)
	}
}

// TestSynchronousResultCarriesOutcome guards a type relationship that is easy
// to miss when porting: sRemmitanceResult extends remmitanceResult, so a
// synchronous send reports retCode and message alongside the sign-in URL. A
// port that only modelled urlSaml would silently drop the outcome and treat
// every rejected shipment as a success.
func TestSynchronousResultCarriesOutcome(t *testing.T) {
	response := `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body><shippingSynchronousSendResponse>
  <result>
   <documents guid="G-77" id="77" status="1" statusComment="Created"/>
   <message>OK</message>
   <retCode>0</retCode>
   <urlSaml>https://portal.example/sign?x=1</urlSaml>
  </result>
 </shippingSynchronousSendResponse></soapenv:Body>
</soapenv:Envelope>`

	r := newRecorder(t, response)
	result, err := r.client(t).ShippingSynchronousSend(context.Background(), SendRequest{
		CompanyID: "311",
		TypeID:    "TYPE1",
		Receivers: []Receiver{sampleReceiver()},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if result.URLSaml != "https://portal.example/sign?x=1" {
		t.Errorf("URLSaml = %q", result.URLSaml)
	}
	if result.RetCode != 0 || result.Message != "OK" {
		t.Errorf("outcome fields not decoded: retCode=%d message=%q", result.RetCode, result.Message)
	}
	if err := result.Err(); err != nil {
		t.Errorf("Err() should be nil for retCode 0: %v", err)
	}
	if len(result.Documents) != 1 || result.Documents[0].GUID != "G-77" {
		t.Errorf("documents not decoded: %+v", result.Documents)
	}
}

// TestMultiReceiverStateCarriesShipmentFields covers the other inherited type:
// documentStateMultiReceiver extends documentState.
func TestMultiReceiverStateCarriesShipmentFields(t *testing.T) {
	response := `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body><shippingStatusMultiReceiverResponse>
  <document guid="G-88" id="88" status="2" statusComment="In progress">
   <groups group-id="1" status="2" result="0">
    <signatures receiver-id="5" receiverIdentityId="12345678Z" status="1" statusCom="Pending"/>
   </groups>
  </document>
 </shippingStatusMultiReceiverResponse></soapenv:Body>
</soapenv:Envelope>`

	r := newRecorder(t, response)
	states, err := r.client(t).ShippingStatusMultiReceiver(context.Background(), MultiReceiverStatusQuery{
		GUIDs: []string{"G-88"},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("got %d states, want 1", len(states))
	}
	if states[0].GUID != "G-88" || states[0].Status != 2 {
		t.Errorf("inherited shipment fields not decoded: %+v", states[0].DocumentState)
	}
	if len(states[0].Groups) != 1 || len(states[0].Groups[0].Signatures) != 1 {
		t.Fatalf("groups not decoded: %+v", states[0].Groups)
	}
	if got := states[0].Groups[0].Signatures[0].ReceiverIdentityID; got != "12345678Z" {
		t.Errorf("signature identity = %q", got)
	}
}

// TestTimeLayouts pins the dateTime shapes the portal has actually been seen to
// emit. The space-separated ones are not valid xsd:dateTime, but shippingStatus
// returns them, so the parser has to cope.
func TestTimeLayouts(t *testing.T) {
	tests := []struct {
		in   string
		want string // as UTC, or "" for the zero time
	}{
		{"2026-09-11T19:47:12.503+02:00", "2026-09-11 17:47:12"},
		{"2026-09-11T17:47:12Z", "2026-09-11 17:47:12"},
		{"2026-09-11T17:47:12", "2026-09-11 17:47:12"},
		{"2026-09-11 19:47:12.503", "2026-09-11 19:47:12"},
		{"2026-09-11 19:47:12", "2026-09-11 19:47:12"},
		{"2026-09-11", "2026-09-11 00:00:00"},
		{"", ""},
		{"   ", ""},
	}

	for _, tt := range tests {
		var parsed Time
		if err := parsed.parse(tt.in); err != nil {
			t.Errorf("parse(%q): %v", tt.in, err)
			continue
		}
		if tt.want == "" {
			if !parsed.IsZero() {
				t.Errorf("parse(%q) = %v, want the zero time", tt.in, parsed)
			}
			continue
		}
		if got := parsed.UTC().Format("2006-01-02 15:04:05"); got != tt.want {
			t.Errorf("parse(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}

	var parsed Time
	if err := parsed.parse("not a date"); err == nil {
		t.Error("an unparseable value should report an error, not pass silently")
	}
}

// TestDecodeDocumentedSyncMultiResponse decodes the response printed in section
// 5.5 of the integration guide, verbatim. It guards the type relationships that
// a synchronous contract send depends on: the outcome fields come from the
// embedded remmitanceResult, and one result carries a link per signer.
func TestDecodeDocumentedSyncMultiResponse(t *testing.T) {
	const response = `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
   <soap:Body>
      <ns2:shippingSynchronousSendMultiReceiverResponse xmlns:ns2="https://sender.logalty.net/lgtportal/wsDataChannel">
         <result>
            <documents externalId="1111" guid="001001-9996-000000001323970.par" id="83610" result="0" resultComment="" status="1" statusComment="Saved" typeid="12777"/>
            <retCode>0</retCode>
            <link>
               <receiver>11111111H</receiver>
               <url>https://example/a</url>
            </link>
            <link>
               <receiver>22222222H</receiver>
               <url>https://example/b</url>
            </link>
         </result>
      </ns2:shippingSynchronousSendMultiReceiverResponse>
   </soap:Body>
</soap:Envelope>`

	r := newRecorder(t, response)
	results, err := r.client(t).ShippingSynchronousSendMultiReceiver(
		context.Background(), MultiReceiverSendRequest{CompanyID: "1", TypeID: "1"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	got := results[0]
	if got.RetCode != RetCodeOK {
		t.Errorf("RetCode = %d", got.RetCode)
	}
	if err := got.Err(); err != nil {
		t.Errorf("Err() = %v, want nil", err)
	}
	if len(got.Documents) != 1 || got.Documents[0].GUID != "001001-9996-000000001323970.par" {
		t.Errorf("documents decoded wrong: %+v", got.Documents)
	}
	if got.Documents[0].Status != StatusPendingSend {
		t.Errorf("status = %d, want %d", got.Documents[0].Status, StatusPendingSend)
	}
	if len(got.Link) != 2 || got.Link[1].Receiver != "22222222H" {
		t.Errorf("links decoded wrong: %+v", got.Link)
	}
}
