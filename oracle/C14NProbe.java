import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Tries every canonicalization algorithm Santuario offers against a signed
 * document's declared DigestValue, to find out which one — if any — the signer
 * actually used. A signature that declares inclusive c14n but was computed
 * with exclusive is a real and common implementation bug, and this tells them
 * apart instead of guessing.
 *
 * Args: <file.xml>
 */
public class C14NProbe {

    private static final String[] ALGORITHMS = {
        Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS,
        Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS,
        Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS,
        Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS,
        Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS,
        Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS,
    };

    public static void main(String[] args) throws Exception {
        org.apache.xml.security.Init.init();

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);

        String declared = null;
        for (String withSignature : new String[] { "detached", "kept" }) {
            Document doc;
            try (FileInputStream in = new FileInputStream(args[0])) {
                doc = factory.newDocumentBuilder().parse(in);
            }
            NodeList sigs = doc.getElementsByTagNameNS(
                    javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
            Element sig = (Element) sigs.item(0);

            if (declared == null) {
                NodeList dv = doc.getElementsByTagNameNS(
                        javax.xml.crypto.dsig.XMLSignature.XMLNS, "DigestValue");
                declared = dv.item(0).getTextContent().trim();
                System.out.println("declared DigestValue: " + declared);
            }
            if (withSignature.equals("detached")) {
                sig.getParentNode().removeChild(sig);
            }

            System.out.println("\n-- signature " + withSignature + " --");
            for (String alg : ALGORITHMS) {
                try {
                    Canonicalizer c = Canonicalizer.getInstance(alg);
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    c.canonicalizeSubtree(doc.getDocumentElement(), out);
                    byte[] digest = MessageDigest.getInstance("SHA-256").digest(out.toByteArray());
                    String got = Base64.getEncoder().encodeToString(digest);
                    System.out.printf("   %-62s %s%s%n",
                            alg.replace("http://www.w3.org/", "").replace("http://www.w3.org/2001/10/", ""),
                            got, got.equals(declared) ? "   <<< MATCH" : "");
                } catch (Exception e) {
                    System.out.printf("   %-62s error: %s%n", alg, e.getMessage());
                }
            }
        }
    }
}
