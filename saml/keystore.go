package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// Keystore is the signing material: the RSA private key that signs assertions
// and the certificate the portal uses to verify them.
type Keystore struct {
	Key         *rsa.PrivateKey
	Certificate *x509.Certificate
}

// LoadKeystoreFile reads a PKCS#12 (.pfx/.p12) file.
func LoadKeystoreFile(path, password string) (Keystore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Keystore{}, fmt.Errorf("saml: read keystore: %w", err)
	}
	return LoadKeystore(data, password)
}

// LoadKeystore reads a PKCS#12 keystore from memory, which is usually the
// better option when the key comes from a secret manager rather than disk.
//
// The Java SDK obfuscates the keystore password with a fixed-key character
// shift before handing it to SignXml, which promptly reverses it. The round
// trip is the identity function, so there is nothing to port: pass the real
// password.
func LoadKeystore(pfx []byte, password string) (Keystore, error) {
	key, cert, err := pkcs12.Decode(pfx, password)
	if err != nil {
		return Keystore{}, fmt.Errorf("saml: decode keystore: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return Keystore{}, fmt.Errorf("saml: keystore holds a %T, want an RSA private key", key)
	}
	if cert == nil {
		return Keystore{}, errors.New("saml: keystore has no certificate")
	}

	return Keystore{Key: rsaKey, Certificate: cert}, nil
}
