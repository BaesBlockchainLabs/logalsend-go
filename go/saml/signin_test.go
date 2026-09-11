package saml

import (
	"net/url"
	"strings"
	"testing"
)

// The endpoint, method and field name below come from the portal's own SAML
// tester page, linked from the LogalSend integration guide: a POST form whose
// action is <frontend>/saml/samllogin.pg with a single hidden field called
// saml_assertion. They are not guesses.
func TestSignInURL(t *testing.T) {
	const want = "https://www.demo.logalty.es/lgt/frontendweb/saml/samllogin.pg"
	for _, base := range []string{
		"https://www.demo.logalty.es/lgt/frontendweb",
		"https://www.demo.logalty.es/lgt/frontendweb/",
		"https://www.demo.logalty.es/lgt/frontendweb///",
	} {
		if got := SignInURL(base); got != want {
			t.Errorf("SignInURL(%q) = %q, want %q", base, got, want)
		}
	}
}

// TestSignInFormRoundTrips is the property that matters: whatever percent
// encoding Logalty's scheme put in the assertion has to survive form encoding
// and come back byte for byte.
func TestSignInFormRoundTrips(t *testing.T) {
	// A realistic encoded assertion: Logalty's encoder emits upper-case hex,
	// '+' for spaces, and leaves "-_.!~*'()" alone.
	const assertion = "%3Csaml%3AAssertion+ID%3D%22ass00000000002%22%3E-_.!~*'()%3C%2Fsaml%3AAssertion%3E"

	target, body := SignInForm("https://portal.example/lgt/frontendweb", assertion)
	if target != "https://portal.example/lgt/frontendweb/saml/samllogin.pg" {
		t.Errorf("target = %q", target)
	}

	values, err := url.ParseQuery(body)
	if err != nil {
		t.Fatalf("form body does not parse: %v", err)
	}
	if got := values.Get(SignInField); got != assertion {
		t.Errorf("assertion did not survive form encoding\n got: %s\nwant: %s", got, assertion)
	}
	if len(values) != 1 {
		t.Errorf("form should carry exactly one field, got %v", values)
	}
	// The percent signs must be escaped in the body, or the portal would
	// decode the assertion one step too far.
	if strings.Contains(body, "%3C") {
		t.Error("the body should carry %253C, not %3C — the form encoding is missing")
	}
}

func TestSignInFormHTML(t *testing.T) {
	const assertion = `%3Cx%3E"quote"&amp;`

	page := SignInFormHTML("https://portal.example/lgt/frontendweb", assertion)

	for _, want := range []string{
		`<form method="POST" action="https://portal.example/lgt/frontendweb/saml/samllogin.pg">`,
		`name="saml_assertion"`,
		`onload="document.forms[0].submit()"`,
		"<noscript>",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page is missing %s\n%s", want, page)
		}
	}

	// The quote in the value must be escaped, or it would close the attribute
	// and break the form — and with it the signature.
	if strings.Contains(page, `value="%3Cx%3E"quote"`) {
		t.Error("the assertion was not HTML-escaped into the attribute")
	}
	if !strings.Contains(page, "&#34;quote&#34;") {
		t.Errorf("expected the quotes to be escaped:\n%s", page)
	}
	// Escaping must not mangle the percent encoding Logalty applied.
	if !strings.Contains(page, "%3Cx%3E") {
		t.Error("the assertion's percent encoding was altered")
	}
}

// TestSignInFormUsesEncodedAssertion documents, executably, which generator
// output belongs in the form. Passing raw XML would leave the portal decoding
// an assertion that was never encoded.
func TestSignInFormUsesEncodedAssertion(t *testing.T) {
	g := testGenerator(t)
	config := fullConfig()

	encoded, err := g.GenerateEncoded(config)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	_, body := SignInForm("https://portal.example/lgt/frontendweb", encoded)

	values, err := url.ParseQuery(body)
	if err != nil {
		t.Fatalf("parse body: %v", err)
	}
	got := values.Get(SignInField)
	if got != encoded {
		t.Error("the encoded assertion did not survive the form body")
	}
	if strings.HasPrefix(got, "<") {
		t.Error("the form should carry the encoded assertion, not raw XML")
	}
	if !strings.HasPrefix(got, "%3Csaml%3AAssertion") {
		t.Errorf("unexpected start: %s", got[:min(40, len(got))])
	}
}
