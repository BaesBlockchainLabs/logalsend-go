# Test keystore

`test-logalty-private.pfx` (password `111111`) is the throwaway certificate that
Logalty ships inside its own `lgtweb-sdk-full-dependencies` distribution, in
`src/test/resources/certs/`. It is committed here so the golden tests can run
from a fresh clone.

It is **not a credential**. It expired in December 2022, it never had any
authority beyond Logalty's own unit tests, and anyone holding the vendor's SDK
zip already has it. If a secret scanner flags it, that is the reason.

`java-reference-signed.xml` in `../../xmldsig/testdata` is a SAML assertion this
same certificate signed, produced by the Java SDK under Apache Santuario. Its
`DigestValue` and `SignatureValue` are what the canonicalizer is tested against,
so the file must not be regenerated casually — see `oracle/run.sh`.
