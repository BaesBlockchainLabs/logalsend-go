import net.logalty.sender.lgtportal.wsDataChannel.BinaryContentItem;
import net.logalty.sender.lgtportal.wsDataChannel.Receiver;
import net.logalty.sender.lgtportal.wsDataChannel.TemplateReceiver;
import net.logalty.sender.lgtportal.wsDataChannel.WsDataChannelPortBindingStub;
import net.logalty.sender.lgtportal.wsDataChannel.WsDataChannel_ServiceLocator;

import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Captures the SOAP requests Axis actually puts on the wire, so the Go port can
 * be diffed against them instead of against a reading of the stubs.
 *
 * Starts a local HTTP server that records each request body and answers with a
 * canned response, then drives the generated stub through a few operations.
 *
 * Args: <outputDirectory>
 */
public class SoapCapture {

    private static final List<byte[]> captured = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        String outDir = args[0];

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            try (InputStream in = exchange.getRequestBody()) {
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                in.transferTo(buffer);
                captured.add(buffer.toByteArray());
            }
            byte[] body = RESPONSE.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/xml; charset=utf-8");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();

        URL endpoint = new URL("http://127.0.0.1:" + server.getAddress().getPort() + "/ws");
        WsDataChannelPortBindingStub stub =
                new WsDataChannelPortBindingStub(endpoint, new WsDataChannel_ServiceLocator());

        // 1. A simple GUID-only download.
        quietly(() -> stub.shippingCertificate("user", "pass", "GUID-0001"));

        // 2. A send carrying a complex type and an array.
        Receiver receiver = new Receiver();
        receiver.setReceiverName("Ana");
        receiver.setReceiverLastName1("García");
        receiver.setReceiverEmail("ana@example.com");
        receiver.setReceiverIdentityId("12345678Z");
        receiver.setReceiverIdentityType("NIF");
        receiver.setSignatureOrder(1);
        quietly(() -> stub.shippingSend("user", "pass", "311", "TYPE1",
                new Receiver[] { receiver }, "pdf", "SGVsbG8=", "contract.pdf"));

        // 3. String arrays.
        quietly(() -> stub.shippingStatus("user", "pass",
                new String[] { "GUID-1", "GUID-2" }, null, new String[] { "EXT-1" }));

        // 4. An int array plus a nested array of complex types.
        quietly(() -> stub.shippingRequestList("user", "pass", "CSV",
                "01/01/2026", "31/01/2026", "created", new int[] { 311, 312 }));

        BinaryContentItem file = new BinaryContentItem("doc.pdf", "pdf", "SGVsbG8=");
        quietly(() -> stub.shippingSendMultiReceiver("user", "pass", "311", "TYPE1",
                new Receiver[] { receiver }, new BinaryContentItem[] { file },
                "Acme", "EXT-99", "Please sign"));

        // 5. A single complex parameter rather than an array, plus a trailing
        //    parameter the asynchronous variant does not have.
        quietly(() -> stub.shippingSynchronousSend("user", "pass", "311", "TYPE1",
                receiver, "pdf", "SGVsbG8=", "contract.pdf", "es"));

        // 6. Templates: an array and a single value of the same type.
        TemplateReceiver template = new TemplateReceiver();
        template.setCompanyId("311");
        template.setTypeId("TYPE1");
        template.setTemplateId("TPL-7");
        template.setPdfFileName("out.pdf");
        template.setField1("one");
        template.setField10("ten");
        template.setField2("two");
        // TemplateReceiver extends Receiver in the schema; set inherited
        // fields too, so the capture shows where they land in the sequence.
        template.setReceiverName("Ana");
        template.setReceiverEmail("ana@example.com");
        template.setExternalId("EXT-T1");
        quietly(() -> stub.shippingSendWTemplate("user", "pass",
                new TemplateReceiver[] { template }));
        quietly(() -> stub.shippingSynchronousSendWTemplate("user", "pass", template));

        // 7. An int array in a status query.
        quietly(() -> stub.shippingStatusMultiReceiver("user", "pass",
                new String[] { "GUID-9" }, new int[] { 1, 2 }, null));

        // 8. Plain string parameters on the remaining shapes.
        quietly(() -> stub.buildSamlUrl("user", "pass", "GUID-3", "12345678Z"));
        quietly(() -> stub.downloadDocument("user", "pass", "dwn_signed", "guid", "GUID-4"));
        quietly(() -> stub.cancelShipping("user", "pass", "GUID-5", "99", "INVALID_DATA"));

        server.stop(0);

        String[] names = {
            "axis-shippingCertificate.xml",
            "axis-shippingSend.xml",
            "axis-shippingStatus.xml",
            "axis-shippingRequestList.xml",
            "axis-shippingSendMultiReceiver.xml",
            "axis-shippingSynchronousSend.xml",
            "axis-shippingSendWTemplate.xml",
            "axis-shippingSynchronousSendWTemplate.xml",
            "axis-shippingStatusMultiReceiver.xml",
            "axis-buildSamlUrl.xml",
            "axis-downloadDocument.xml",
            "axis-cancelShipping.xml",
        };
        for (int i = 0; i < captured.size() && i < names.length; i++) {
            Files.write(Paths.get(outDir, names[i]), captured.get(i));
            System.out.println("wrote " + names[i] + " (" + captured.get(i).length + " bytes)");
        }
    }

    /** The canned response only has to be well-formed; we are capturing requests. */
    private static final String RESPONSE =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">"
            + "<soapenv:Body/></soapenv:Envelope>";

    private interface Call {
        void run() throws Exception;
    }

    /** Response decoding is irrelevant here, so failures after send are ignored. */
    private static void quietly(Call call) {
        try {
            call.run();
        } catch (Exception e) {
            // expected: the canned response carries no result
        }
    }
}
