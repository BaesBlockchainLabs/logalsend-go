import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.FileInputStream;
import java.security.cert.X509Certificate;

/**
 * Verifies an enveloped XMLDSig signature with Apache Santuario — the same
 * stack the Logalty portal runs — so a Go-generated assertion can be checked
 * against the implementation that actually has to accept it.
 *
 * Args: <file.xml>
 */
public class SamlVerify {

    public static void main(String[] args) throws Exception {
        org.apache.xml.security.Init.init();

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        Document doc;
        try (FileInputStream in = new FileInputStream(args[0])) {
            doc = factory.newDocumentBuilder().parse(in);
        }

        NodeList signatures =
                doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
        if (signatures.getLength() == 0) {
            System.out.println("FAIL: no Signature element");
            System.exit(1);
        }

        XMLSignature signature = new XMLSignature((Element) signatures.item(0), "");
        X509Certificate cert = signature.getKeyInfo().getX509Certificate();
        if (cert == null) {
            System.out.println("FAIL: no certificate in KeyInfo");
            System.exit(1);
        }

        boolean valid = signature.checkSignatureValue(cert);
        System.out.println((valid ? "VALID" : "INVALID")
                + " signature, signed by " + cert.getSubjectX500Principal());

        // Report the reference digest separately: a signature can verify while
        // the reference it covers does not, which is the failure mode that
        // matters when porting a canonicalizer.
        boolean refValid = signature.getSignedInfo().verify(false);
        System.out.println("reference digest: " + (refValid ? "OK" : "MISMATCH"));

        System.exit(valid && refValid ? 0 : 1);
    }
}
