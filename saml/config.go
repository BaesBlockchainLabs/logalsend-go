// Package saml generates the signed SAML 2.0 assertions that authenticate a
// user against the Logalty LGT Portal. It is a Go port of the
// com.logalty.generation.saml package of the lgtweb Java SDK.
package saml

import (
	"errors"
	"fmt"
	"strings"
)

// Role is the portal role granted to the user the assertion describes.
type Role string

const (
	RoleAdmin             Role = "Administrator"
	RoleManager           Role = "Manager"
	RoleUser              Role = "User"
	RoleReadOnlyUser      Role = "ReadOnly"
	RoleAuthorizeOnlyUser Role = "AuthorizeOnly"
	RoleTemplatesOnlyUser Role = "TemplatesOnly"
	RoleWSIntegrationUser Role = "WsIntegration"
)

// Config describes the assertion to generate. Only ClientURL and Login are
// always required; the remaining user fields are what turn a plain login
// assertion into a user-provisioning one, and are emitted only when set.
//
// Optional scalar fields are pointers so that "not set" stays distinct from the
// zero value — the Java SDK relies on the same distinction via boxed types, and
// emitting group 0 or emailAlerts=false when the caller said nothing would
// change what the portal does.
type Config struct {
	// ClientURL identifies the integrating site. It becomes the assertion's
	// Issuer, its Audience and the SubjectConfirmationData recipient.
	ClientURL string

	// Login is the portal username. Always emitted.
	Login string

	// Password, Mail, FullName, Role, Group and Companies provision the user
	// on first sign-in. Leave them unset for a pure login assertion.
	Password  string
	Mail      string
	FullName  string
	Role      Role
	Group     *int
	Companies []int

	// Position, EmailAlerts and ReadersGroup are further optional user
	// attributes.
	Position     string
	EmailAlerts  *bool
	ReadersGroup []int

	// Validate turns on the stricter check that every user-provisioning field
	// is present. It mirrors the Java SamlConfig.validate flag, which is off
	// by default.
	Validate bool
}

// Int is a helper for setting Config.Group.
func Int(v int) *int { return &v }

// Bool is a helper for setting Config.EmailAlerts.
func Bool(v bool) *bool { return &v }

// ErrValidation reports a Config that cannot produce a usable assertion. It
// corresponds to the Java SDK's ValidationException.
var ErrValidation = errors.New("saml: invalid configuration")

func (c Config) validate() error {
	var missing []string

	require := func(name, value string) {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}

	require("Login", c.Login)
	require("ClientURL", c.ClientURL)

	if c.Validate {
		require("Password", c.Password)
		require("FullName", c.FullName)
		require("Mail", c.Mail)
		require("Role", string(c.Role))
		if c.Group == nil {
			missing = append(missing, "Group")
		}
		if len(c.Companies) == 0 {
			missing = append(missing, "Companies")
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("%w: %s must be set", ErrValidation, strings.Join(missing, ", "))
	}
	return nil
}
