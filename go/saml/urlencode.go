package saml

import (
	"strconv"
	"strings"
)

// urlEncode reproduces the Java SDK's own URL encoder rather than delegating to
// net/url. The two disagree in ways the portal would notice:
//
//   - the safe set here is "-_.!~*'()", so '(' and ')' and '!' are left alone
//     where url.QueryEscape would percent-encode them;
//   - hex digits are upper-case;
//   - a space becomes '+';
//   - the input is walked by rune and any rune above U+00FF is dropped
//     entirely, and the rest are encoded as a single byte from their code
//     point — this is not UTF-8 percent-encoding, it is latin-1.
//
// That last rule silently mangles non-latin-1 text, but it is what the portal
// has always been sent, so it is reproduced exactly.
func urlEncode(text string) string {
	const safe = "-_.!~*'()"

	var b strings.Builder
	for _, r := range text {
		switch {
		case r == ' ':
			b.WriteByte('+')
		case r >= '0' && r <= '9', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case strings.ContainsRune(safe, r):
			b.WriteRune(r)
		case r <= 0xFF:
			b.WriteByte('%')
			hex := strings.ToUpper(strconv.FormatInt(int64(r), 16))
			if len(hex) == 1 {
				b.WriteByte('0')
			}
			b.WriteString(hex)
		}
	}
	return b.String()
}
