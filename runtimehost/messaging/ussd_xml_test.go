package messaging

import (
	"strings"
	"testing"
)

func TestIMSUSSDXMLRoundTripRequest(t *testing.T) {
	body, err := BuildIMSUSSDXML(IMSUSSDPayload{
		Language:  "en",
		Text:      "*100#",
		Operation: IMSUSSDOperationRequest,
	})
	if err != nil {
		t.Fatalf("BuildIMSUSSDXML() error = %v", err)
	}
	if !strings.Contains(string(body), "UnstructuredSS-Request") {
		t.Fatalf("body=%s", body)
	}
	payload, err := ParseIMSUSSDXML(body)
	if err != nil {
		t.Fatalf("ParseIMSUSSDXML() error = %v", err)
	}
	if payload.Language != "en" || payload.Text != "*100#" || payload.Operation != IMSUSSDOperationRequest {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestParseIMSUSSDXMLNotifyWithError(t *testing.T) {
	payload, err := ParseIMSUSSDXML([]byte(`<ussd-data><language>en</language><ussd-string>failed</ussd-string><UnstructuredSS-Notify/><error-code>17</error-code></ussd-data>`))
	if err != nil {
		t.Fatalf("ParseIMSUSSDXML() error = %v", err)
	}
	if payload.Operation != IMSUSSDOperationNotify || payload.Text != "failed" || !payload.HasError || payload.ErrorCode != 17 {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestDecodeIMSUSSDDocumentFromMultipart(t *testing.T) {
	xmlBody, err := BuildIMSUSSDXML(IMSUSSDPayload{Text: "Balance: 10", Operation: IMSUSSDOperationNotify})
	if err != nil {
		t.Fatalf("BuildIMSUSSDXML() error = %v", err)
	}
	body := buildIMSUSSDMultipartBody("192.0.2.10", "b1", xmlBody)
	payload, ok, err := DecodeIMSUSSDDocument(`multipart/mixed; boundary="b1"`, body)
	if err != nil {
		t.Fatalf("DecodeIMSUSSDDocument() error = %v", err)
	}
	if !ok || payload.Text != "Balance: 10" || payload.Operation != IMSUSSDOperationNotify {
		t.Fatalf("ok=%v payload=%+v", ok, payload)
	}
}
