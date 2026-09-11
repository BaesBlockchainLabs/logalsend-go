package saml

import (
	"html"
	"net/url"
	"strings"
)

// SignInPath is the portal path that consumes a SAML assertion, relative to
// the front-end base URL. Note that it is a real server path, not one of the
// single-page app's hash routes.
const SignInPath = "/saml/samllogin.pg"

// SignInField is the form field the assertion travels in.
const SignInField = "saml_assertion"

// SignInURL joins a portal front-end base URL with the sign-in path.
//
//	SignInURL("https://www.demo.logalty.es/lgt/frontendweb")
//	  → "https://www.demo.logalty.es/lgt/frontendweb/saml/samllogin.pg"
func SignInURL(portalBase string) string {
	return strings.TrimRight(portalBase, "/") + SignInPath
}

// SignInForm returns the target URL and form body for signing a user in.
//
// The assertion is delivered by an HTTP POST with a
// application/x-www-form-urlencoded body, not as a query parameter. Pass the
// output of GenerateEncoded (or Login): the portal expects the assertion to
// carry Logalty's own percent-encoding, and the form encoding then goes on top
// of that. This double encoding looks wrong and is not — it is what the
// portal's own SAML tester does, which percent-encodes the assertion in the
// browser before submitting the form.
//
// Handing this to an http.Client is enough to sign in programmatically:
//
//	target, body := saml.SignInForm(portal, assertion)
//	resp, err := http.Post(target, "application/x-www-form-urlencoded",
//	    strings.NewReader(body))
//
// To sign a *person* in, serve them SignInFormHTML instead so their own
// browser makes the request and keeps the resulting session.
func SignInForm(portalBase, encodedAssertion string) (target, body string) {
	form := url.Values{SignInField: {encodedAssertion}}
	return SignInURL(portalBase), form.Encode()
}

// SignInFormHTML returns a self-submitting HTML page that posts the assertion
// to the portal, which is the usual way to sign a user in: serve this from your
// own site and the user's browser carries them into Logalty with a session of
// their own.
//
// Pass the output of GenerateEncoded or Login. The assertion is HTML-escaped
// into the form value, so it survives the round trip unchanged.
func SignInFormHTML(portalBase, encodedAssertion string) string {
	var b strings.Builder

	b.WriteString("<!doctype html>\n<html>\n<head>\n")
	b.WriteString(`<meta charset="utf-8">` + "\n")
	b.WriteString("<title>Redirecting…</title>\n</head>\n")
	// The visible body only shows if scripting is off, in which case the
	// button is the way through.
	b.WriteString(`<body onload="document.forms[0].submit()">` + "\n")
	// Attributes are quoted by hand with HTML escaping. %q would layer Go's
	// string escaping on top, which is a different and wrong encoding.
	b.WriteString(`<form method="POST" action="` + html.EscapeString(SignInURL(portalBase)) + "\">\n")
	b.WriteString(`  <input type="hidden" name="` + SignInField +
		`" value="` + html.EscapeString(encodedAssertion) + "\">\n")
	b.WriteString("  <noscript><button type=\"submit\">Continue</button></noscript>\n")
	b.WriteString("</form>\n</body>\n</html>\n")
	return b.String()
}
