package wsdatachannel_test

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/BaesBlockchainLabs/logalsend-go/wsdatachannel"
)

// Sending a document for signature and following it through to the signed copy.
func Example() {
	ctx := context.Background()

	client, err := wsdatachannel.NewClient(
		wsdatachannel.EndpointDemo,
		os.Getenv("LOGALTY_USER"),
		os.Getenv("LOGALTY_PASSWORD"),
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}

	pdf, err := os.ReadFile("contract.pdf")
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.ShippingSend(ctx, wsdatachannel.SendRequest{
		CompanyID: "311",
		TypeID:    "SIGNATURE",
		Receivers: []wsdatachannel.Receiver{{
			ExternalID:           "order-4711",
			ReceiverName:         "Ana",
			ReceiverLastName1:    "García",
			ReceiverEmail:        "ana@example.com",
			ReceiverIdentityID:   "12345678Z",
			ReceiverIdentityType: "NIF",
			ReceiverMobile:       "+34600000000",
		}},
		FileType:    "application/pdf",
		FileName:    "contract.pdf",
		FileContent: wsdatachannel.EncodeContent(pdf),
	})
	if err != nil {
		log.Fatal(err)
	}

	// The transport succeeded, but the portal may still have rejected the
	// shipment on business grounds. That shows up as a non-zero RetCode.
	if err := result.Err(); err != nil {
		log.Fatal(err)
	}

	guid := result.Documents[0].GUID
	fmt.Println("sent:", guid)

	// Later, once the receiver has signed, fetch the signed document.
	signed, err := client.ShippingDocumentSigned(ctx, guid)
	if err != nil {
		log.Fatal(err)
	}
	data, err := wsdatachannel.DecodeBinary(signed.Binary)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("contract-signed.pdf", data, 0o600); err != nil {
		log.Fatal(err)
	}
}

// Polling the state of shipments you have already sent.
func ExampleClient_ShippingStatusUTC() {
	client, err := wsdatachannel.NewClient(wsdatachannel.EndpointDemo, "user", "password", nil)
	if err != nil {
		log.Fatal(err)
	}

	states, err := client.ShippingStatusUTC(context.Background(), wsdatachannel.StatusQuery{
		ExternalIDs: []string{"order-4711", "order-4712"},
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, state := range states {
		fmt.Printf("%s: status %d (%s), last updated %s\n",
			state.ExternalID, state.Status, state.StatusComment, state.LastUpdate)
	}
}

// Redirecting a signer straight into the portal instead of letting it email
// them, using the synchronous send.
func ExampleClient_ShippingSynchronousSend() {
	client, err := wsdatachannel.NewClient(wsdatachannel.EndpointDemo, "user", "password", nil)
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.ShippingSynchronousSend(context.Background(), wsdatachannel.SendRequest{
		CompanyID: "311",
		TypeID:    "SIGNATURE",
		Receivers: []wsdatachannel.Receiver{{
			ReceiverName:         "Ana",
			ReceiverIdentityID:   "12345678Z",
			ReceiverIdentityType: "NIF",
			ReceiverMobile:       "+34600000000",
		}},
		FileType:    "application/pdf",
		FileName:    "contract.pdf",
		FileContent: wsdatachannel.EncodeContent([]byte("...")),
		Language:    "es-ES",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Redirect the signer's browser here.
	fmt.Println(result.URLSaml)
}
