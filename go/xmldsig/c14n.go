// Package xmldsig implements the slice of XML Signature (XMLDSig) that the
// Logalty SAML integration relies on: Canonical XML 1.0 (inclusive, comments
// omitted) plus enveloped RSA-SHA1 signing.
//
// The Java SDK gets this from Apache Santuario; Go has no equivalent in the
// standard library, so the canonicalization is implemented here. It is
// deliberately scoped to the documents this SDK produces and consumes:
// namespace-aware elements, attributes, text and CDATA. Comments and
// processing instructions are dropped, which matches the
// REC-xml-c14n-20010315 "omit comments" variant that the SDK requests.
package xmldsig

import (
	"bytes"
	"sort"

	"github.com/beevik/etree"
)

// C14NAlgorithm is the canonicalization method the Logalty SDK signs with.
const C14NAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"

// nsScope tracks which namespace declarations are currently rendered, so a
// declaration is only emitted when it differs from the nearest output ancestor.
type nsScope struct {
	parent *nsScope
	decls  map[string]string // prefix ("" = default) -> URI
}

func (s *nsScope) lookup(prefix string) (string, bool) {
	for scope := s; scope != nil; scope = scope.parent {
		if uri, ok := scope.decls[prefix]; ok {
			return uri, true
		}
	}
	return "", false
}

// Canonicalize serializes el and its descendants in Canonical XML 1.0
// (inclusive, comments omitted) form.
//
// Because inclusive canonicalization gives the apex element every namespace
// that is in scope for it — not just the ones declared on it — el must still be
// attached to its document when this is called. Namespaces inherited from
// ancestors are picked up automatically.
//
// If exclude is non-nil, every element for which it reports true is omitted
// along with its entire subtree. That is how the enveloped-signature transform
// drops the <Signature> element before the document is digested.
func Canonicalize(el *etree.Element, exclude func(*etree.Element) bool) []byte {
	var buf bytes.Buffer

	// The apex inherits its ancestors' namespaces but re-declares them itself,
	// so it starts out with nothing rendered above it.
	rendered := &nsScope{decls: map[string]string{}}

	writeElement(&buf, el, inheritedScope(el), rendered, exclude)
	return buf.Bytes()
}

// inheritedScope collects the namespace declarations in force on el's
// ancestors, nearest ancestor winning.
func inheritedScope(el *etree.Element) map[string]string {
	var chain []*etree.Element
	for parent := el.Parent(); parent != nil; parent = parent.Parent() {
		chain = append(chain, parent)
	}
	out := map[string]string{}
	for i := len(chain) - 1; i >= 0; i-- {
		for prefix, uri := range declarationsOn(chain[i]) {
			out[prefix] = uri
		}
	}
	return out
}

// declarationsOn returns the xmlns declarations written directly on el.
func declarationsOn(el *etree.Element) map[string]string {
	out := map[string]string{}
	for _, attr := range el.Attr {
		switch {
		case attr.Space == "xmlns":
			out[attr.Key] = attr.Value
		case attr.Space == "" && attr.Key == "xmlns":
			out[""] = attr.Value
		}
	}
	return out
}

func writeElement(buf *bytes.Buffer, el *etree.Element, inherited map[string]string, rendered *nsScope, exclude func(*etree.Element) bool) {
	// The namespaces visible on this element: what it declares itself, layered
	// over whatever the apex inherited (only non-empty for the apex itself).
	visible := map[string]string{}
	for prefix, uri := range inherited {
		visible[prefix] = uri
	}
	for prefix, uri := range declarationsOn(el) {
		visible[prefix] = uri
	}

	// Emit only the declarations that differ from the nearest output ancestor.
	// A default namespace reset (xmlns="") is emitted only when some ancestor
	// actually put a default namespace in scope.
	emit := map[string]string{}
	for prefix, uri := range visible {
		previous, seen := rendered.lookup(prefix)
		if seen && previous == uri {
			continue
		}
		if uri == "" && (!seen || previous == "") {
			continue
		}
		emit[prefix] = uri
	}

	scope := &nsScope{parent: rendered, decls: emit}

	name := qualifiedName(el.Space, el.Tag)
	buf.WriteByte('<')
	buf.WriteString(name)

	// Namespace axis: default declaration first, then by prefix, ascending.
	prefixes := make([]string, 0, len(emit))
	for prefix := range emit {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	for _, prefix := range prefixes {
		buf.WriteByte(' ')
		if prefix == "" {
			buf.WriteString("xmlns")
		} else {
			buf.WriteString("xmlns:")
			buf.WriteString(prefix)
		}
		buf.WriteString(`="`)
		writeAttrValue(buf, emit[prefix])
		buf.WriteByte('"')
	}

	// Attribute axis: sorted by namespace URI then local name, with
	// unprefixed (no-namespace) attributes first.
	type sortedAttr struct {
		uri   string
		local string
		name  string
		value string
	}
	var attrs []sortedAttr
	for _, attr := range el.Attr {
		if attr.Space == "xmlns" || (attr.Space == "" && attr.Key == "xmlns") {
			continue
		}
		uri := ""
		if attr.Space != "" {
			if resolved, ok := scope.lookup(attr.Space); ok {
				uri = resolved
			} else if resolved, ok := visible[attr.Space]; ok {
				uri = resolved
			} else if attr.Space == "xml" {
				uri = "http://www.w3.org/XML/1998/namespace"
			}
		}
		attrs = append(attrs, sortedAttr{
			uri:   uri,
			local: attr.Key,
			name:  qualifiedName(attr.Space, attr.Key),
			value: attr.Value,
		})
	}
	sort.SliceStable(attrs, func(i, j int) bool {
		if attrs[i].uri != attrs[j].uri {
			return attrs[i].uri < attrs[j].uri
		}
		return attrs[i].local < attrs[j].local
	})
	for _, attr := range attrs {
		buf.WriteByte(' ')
		buf.WriteString(attr.name)
		buf.WriteString(`="`)
		writeAttrValue(buf, attr.value)
		buf.WriteByte('"')
	}

	// Canonical form never uses the empty-element shorthand.
	buf.WriteByte('>')

	for _, child := range el.Child {
		switch node := child.(type) {
		case *etree.Element:
			if exclude != nil && exclude(node) {
				continue
			}
			writeElement(buf, node, nil, scope, exclude)
		case *etree.CharData:
			writeText(buf, node.Data)
		}
		// Comments and processing instructions are dropped.
	}

	buf.WriteString("</")
	buf.WriteString(name)
	buf.WriteByte('>')
}

func qualifiedName(space, local string) string {
	if space == "" {
		return local
	}
	return space + ":" + local
}

// writeText escapes a text node per canonical XML: &, < and > are escaped, and
// a literal carriage return becomes a character reference so that XML line-end
// normalization cannot alter it.
func writeText(buf *bytes.Buffer, s string) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '&':
			buf.WriteString("&amp;")
		case '<':
			buf.WriteString("&lt;")
		case '>':
			buf.WriteString("&gt;")
		case '\r':
			buf.WriteString("&#xD;")
		default:
			buf.WriteByte(c)
		}
	}
}

// writeAttrValue escapes an attribute value per canonical XML: &, < and the
// delimiter are escaped, and tab, newline and carriage return become character
// references so attribute-value normalization cannot collapse them.
func writeAttrValue(buf *bytes.Buffer, s string) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '&':
			buf.WriteString("&amp;")
		case '<':
			buf.WriteString("&lt;")
		case '"':
			buf.WriteString("&quot;")
		case '\t':
			buf.WriteString("&#x9;")
		case '\n':
			buf.WriteString("&#xA;")
		case '\r':
			buf.WriteString("&#xD;")
		default:
			buf.WriteByte(c)
		}
	}
}

// ParseDocument reads XML into an etree document with the settings the
// canonicalizer expects: whitespace preserved and entities left decoded.
func ParseDocument(data []byte) (*etree.Document, error) {
	doc := etree.NewDocument()
	doc.ReadSettings.Permissive = false
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, err
	}
	return doc, nil
}

// IsSignature reports whether el is an XMLDSig <Signature> element, whatever
// prefix it happens to carry. It is the exclusion predicate that implements the
// enveloped-signature transform.
func IsSignature(el *etree.Element) bool {
	return el.Tag == "Signature" && namespaceOf(el) == NamespaceDSig
}

// namespaceOf resolves an element's namespace URI from the declarations in
// scope on it and its ancestors.
func namespaceOf(el *etree.Element) string {
	for scope := el; scope != nil; scope = scope.Parent() {
		if uri, ok := declarationsOn(scope)[el.Space]; ok {
			return uri
		}
	}
	if el.Space == "xml" {
		return "http://www.w3.org/XML/1998/namespace"
	}
	return ""
}

// findChild returns el's first child element with the given local name,
// ignoring prefixes. It tolerates a nil receiver so lookups can be chained.
func findChild(el *etree.Element, localName string) *etree.Element {
	if el == nil {
		return nil
	}
	for _, child := range el.ChildElements() {
		if child.Tag == localName {
			return child
		}
	}
	return nil
}
