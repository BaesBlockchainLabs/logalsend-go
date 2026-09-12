import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.cert.X509Certificate;

/**
 * Dumps what Apache Santuario considers the canonical form of a signed
 * document's reference — the whole document with the signature removed — so a
 * Go implementation can be diffed against it byte for byte.
 *
 * Also reports whether Santuario itself accepts the signature, which
 * distinguishes "our canonicalizer is wrong" from "the document is broken".
 *
 * Args: <file.xml> <output.c14n>
 */
public class C14NDump {

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
            System.out.println("no Signature element");
            System.exit(1);
        }
        Element signatureElement = (Element) signatures.item(0);

        XMLSignature signature = new XMLSignature(signatureElement, "");
        X509Certificate cert = signature.getKeyInfo().getX509Certificate();
        System.out.println("Santuario: signature " +
                (cert != null && signature.checkSignatureValue(cert) ? "VALID" : "INVALID"));
        System.out.println("Santuario: reference " +
                (signature.getSignedInfo().verify(false) ? "OK" : "MISMATCH"));

        // Detach the signature, then canonicalize what is left. That is what
        // the enveloped-signature transform amounts to.
        Node parent = signatureElement.getParentNode();
        parent.removeChild(signatureElement);

        Canonicalizer c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        try (FileOutputStream out = new FileOutputStream(args[1])) {
            c14n.canonicalizeSubtree(doc.getDocumentElement(), out);
        }
        System.out.println("wrote " + args[1] + " (" + new java.io.File(args[1]).length() + " bytes)");
    }
}
