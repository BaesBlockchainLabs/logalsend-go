package saml

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	namespaceAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	namespaceXSI       = "http://www.w3.org/2001/XMLSchema-instance"

	attributePrefix     = "urn:logalty:schemas:core:1.0:attributes:"
	attributeNameFormat = "urn:oasis:names:tc:SAML:2.0:attrnameformat:basic"

	// assertionID is the fixed ID the Java SDK hard-codes. The portal does not
	// require it to be unique, and changing it would be a behaviour change
	// rather than a port, so it is kept.
	assertionID = "ass00000000002"

	// validity is how long SubjectConfirmationData stays acceptable.
	validity = 30 * time.Minute

	// timeLayout is the xsd:dateTime format the Java SDK emits: milliseconds
	// and a numeric offset with a colon.
	timeLayout = "2006-01-02T15:04:05.000-07:00"
)

// renderAssertion serializes the unsigned assertion.
//
// The document is written directly rather than through an XML library so that
// the exact bytes handed to Logalty stay under this package's control: the
// two-space layout matches what the Java SDK's XMLBeans serializer produced,
// and carriage returns in caller-supplied values are escaped rather than
// emitted literally. That last part matters for correctness, not looks — a
// literal CR would be normalized to LF when the portal re-parsed the document,
// and the signature would no longer verify.
func renderAssertion(c Config, now time.Time) string {
	var b strings.Builder

	issue := now.Format(timeLayout)

	fmt.Fprintf(&b, "<saml:Assertion xmlns:saml=%q xmlns:xsi=%q ID=%q IssueInstant=%q Version=\"2.0\">\n",
		namespaceAssertion, namespaceXSI, assertionID, issue)

	fmt.Fprintf(&b, "  <saml:Issuer>%s</saml:Issuer>\n", escapeText(c.ClientURL))

	b.WriteString("  <saml:Subject>\n")
	b.WriteString("    <saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\"/>\n")
	b.WriteString("    <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n")
	// Recipient is caller-supplied, so it is quoted by hand: %q would apply
	// Go's own string escaping on top of the XML escaping.
	fmt.Fprintf(&b, "      <saml:SubjectConfirmationData NotOnOrAfter=%q Recipient=\"%s\"/>\n",
		now.Add(validity).Format(timeLayout), escapeAttr(c.ClientURL))
	b.WriteString("    </saml:SubjectConfirmation>\n")
	b.WriteString("  </saml:Subject>\n")

	b.WriteString("  <saml:Conditions>\n")
	b.WriteString("    <saml:AudienceRestriction>\n")
	fmt.Fprintf(&b, "      <saml:Audience>%s</saml:Audience>\n", escapeText(c.ClientURL))
	b.WriteString("    </saml:AudienceRestriction>\n")
	b.WriteString("  </saml:Conditions>\n")

	// AuthnContextClassRef sits beside an empty AuthnContext rather than
	// inside it. That is what the Java SDK produces — its XMLBeans cursor
	// inserts the element before the one it was opened on — and the portal
	// accepts it, so the shape is preserved.
	fmt.Fprintf(&b, "  <saml:AuthnStatement AuthnInstant=%q>\n", issue)
	b.WriteString("    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\n")
	b.WriteString("    <saml:AuthnContext/>\n")
	b.WriteString("  </saml:AuthnStatement>\n")

	b.WriteString("  <saml:AttributeStatement>\n")
	for _, attr := range attributesOf(c) {
		fmt.Fprintf(&b, "    <saml:Attribute Name=%q NameFormat=%q>\n",
			attributePrefix+attr.name, attributeNameFormat)
		fmt.Fprintf(&b, "      <saml:AttributeValue>%s</saml:AttributeValue>\n", escapeText(attr.value))
		b.WriteString("    </saml:Attribute>\n")
	}
	b.WriteString("  </saml:AttributeStatement>\n")

	b.WriteString("</saml:Assertion>")
	return b.String()
}

type attribute struct{ name, value string }

// attributesOf lists the Logalty attributes to emit, in the order the Java SDK
// emits them. Order is not semantically meaningful to the portal, but keeping
// it makes Go and Java output directly comparable.
func attributesOf(c Config) []attribute {
	attrs := []attribute{{"login", c.Login}}

	optional := func(name, value string) {
		if value != "" {
			attrs = append(attrs, attribute{name, value})
		}
	}

	optional("password", c.Password)
	optional("email", c.Mail)
	optional("fullname", c.FullName)
	optional("rol", string(c.Role))
	if c.Group != nil {
		attrs = append(attrs, attribute{"group", strconv.Itoa(*c.Group)})
	}
	if c.Companies != nil {
		attrs = append(attrs, attribute{"companies", joinInts(c.Companies)})
	}
	optional("position", c.Position)
	if c.EmailAlerts != nil {
		attrs = append(attrs, attribute{"emailsAlerts", strconv.FormatBool(*c.EmailAlerts)})
	}
	if c.ReadersGroup != nil {
		attrs = append(attrs, attribute{"readersGroup", joinInts(c.ReadersGroup)})
	}
	return attrs
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ";")
}

// escapeText escapes a text node. The carriage return must become a character
// reference: left literal it would be silently turned into a line feed by the
// portal's parser, changing the digest.
var escapeText = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	"\r", "&#13;",
).Replace

// escapeAttr escapes an attribute value. Beyond the text rules, the quote
// delimiter and every whitespace character need escaping, since attribute-value
// normalization would otherwise collapse tabs and newlines into spaces.
var escapeAttr = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"\t", "&#9;",
	"\n", "&#10;",
	"\r", "&#13;",
).Replace
