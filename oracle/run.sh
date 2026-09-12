#!/usr/bin/env bash
#
# Rebuilds the Java reference harness and regenerates the golden files the Go
# port is tested against.
#
# Everything here runs against the original lgtweb SDK 3.9.0 and its bundled
# jars, so the goldens are what the Java implementation actually produces rather
# than what a reading of its source suggests it produces.
#
# Usage: oracle/run.sh    (from the repository root)

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

sdk="java-sdk"
classes="oracle/classes"
captured="oracle/captured"

if [[ ! -d "$sdk/lib" || ! -d "$sdk/src" ]]; then
    echo "error: $sdk not populated — unzip lgtweb-sdk-full-dependencies-3.9.0.zip into $sdk first." >&2
    echo "       It is not committed: Logalty ships it without a licence to redistribute." >&2
    exit 1
fi

mkdir -p "$classes" "$captured"
cp="$(find "$sdk/lib" -name '*.jar' | tr '\n' ':')$classes"

echo "==> compiling the Java SDK"
javac -nowarn -encoding UTF-8 -cp "$cp" -d "$classes" \
    $(find "$sdk/src/main/java" -name '*.java' -not -path '*/example/*')

echo "==> compiling the reference harness"
javac -nowarn -encoding UTF-8 -cp "$cp" -d "$classes" \
    oracle/SamlRef.java oracle/SamlVerify.java oracle/SoapCapture.java

# --- SAML -------------------------------------------------------------------
# The signed assertion is regenerated but NOT copied over the frozen golden in
# xmldsig/testdata: its timestamps change on every run, and the golden's
# value is that its DigestValue and SignatureValue were computed by Santuario
# for that exact document.
echo "==> generating a reference SAML assertion"
java -cp "$cp" SamlRef \
    "$sdk/src/test/resources/certs/test-logalty-private.pfx" 111111 raw \
    > oracle/ref-raw.xml 2>/dev/null
echo "    wrote oracle/ref-raw.xml"

echo "==> verifying the Go-generated assertion with Apache Santuario"
LOGALTY_WRITE_GOLDEN="$root/oracle/go-signed.xml" \
    go test ./saml/ -run TestWriteGoldenForJava -count=1 >/dev/null
java -cp "$cp" SamlVerify oracle/go-signed.xml 2>/dev/null

# --- SOAP -------------------------------------------------------------------
echo "==> capturing SOAP requests from the Axis stubs"
java -cp "$cp" SoapCapture "$captured" 2>/dev/null | sed 's/^/    /'
cp "$captured"/*.xml wsdatachannel/testdata/

echo "==> running the Go test suite"
go test ./...
