package messaging

import (
	"bytes"
	"context"
	"encoding/base64"
	"mime/multipart"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/runtimehost/eventhost"
)

func TestHandleIMSMessageAcceptsCPIMIMDNDeliveryReport(t *testing.T) {
	store := &fakeDeliveryStore{match: DeliveryPartMatch{MessageID: "msg-123", PartNo: 1, State: "delivered"}}
	svc := NewService("dev-1", "310280233641503", store, nil)
	payload := strings.Join([]string{
		`<imdn xmlns="urn:ietf:params:xml:ns:imdn">`,
		`<message-id>msg-123-1@vowifi-go</message-id>`,
		`<datetime>2026-07-07T02:03:04Z</datetime>`,
		`<recipient-uri>tel:+18005551212</recipient-uri>`,
		`<delivery-notification><status><delivered/></status></delivery-notification>`,
		`</imdn>`,
	}, "")
	body, err := BuildIMSCPIMMessageWithHeaders(map[string][]string{
		"From":            {"<sip:smsc@ims.example>"},
		"To":              {"<sip:user@ims.example>"},
		"NS":              {"imdn <urn:ietf:params:imdn>"},
		"imdn.Message-ID": {"header-message-id"},
	}, map[string][]string{
		"Content-Type":        {"message/imdn+xml; charset=UTF-8"},
		"Content-Disposition": {"notification"},
	}, []byte(payload))
	if err != nil {
		t.Fatalf("BuildIMSCPIMMessageWithHeaders() error = %v", err)
	}

	result, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		CallID:      "imdn-report-call",
		ContentType: IMSCPIMContentType,
		Body:        body,
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage() error = %v", err)
	}
	if result.StatusCode != 200 || result.DeliveryReport == nil || result.ReplyContentType != "" || len(result.ReplyBody) != 0 {
		t.Fatalf("result=%+v", result)
	}
	report := result.DeliveryReport
	if report.InReplyTo != "msg-123-1@vowifi-go" || report.CallID != "imdn-report-call" || report.State != "delivered" {
		t.Fatalf("report=%+v", report)
	}
	if report.Recipient != "tel:+18005551212" || report.ErrorText != "" || report.SIPCode != 200 {
		t.Fatalf("report fields=%+v", report)
	}
	wantAt := time.Date(2026, 7, 7, 2, 3, 4, 0, time.UTC)
	if !report.ReportAt.Equal(wantAt) {
		t.Fatalf("ReportAt=%s want %s", report.ReportAt, wantAt)
	}
	if store.reportInReplyTo != "msg-123-1@vowifi-go" || store.reportCallID != "imdn-report-call" || store.reportState != "delivered" {
		t.Fatalf("store=%+v", store)
	}
	if store.recomputedMessageID != "msg-123" {
		t.Fatalf("recomputedMessageID=%q", store.recomputedMessageID)
	}
}

func TestHandleIMSMessageAcceptsMultipartCPIM3GPPSMS(t *testing.T) {
	dispatch := &fakeDispatcher{}
	svc := NewService("dev-1", "310280233641503", nil, dispatch)
	tpdu := mustHex(t, "0005810180F600006270502143650005E8329BFD06")
	rpdu := imsRPDataBody(0x34, tpdu)
	cpimBody, err := BuildIMSCPIMMessage("<sip:smsc@ims.example>", "<sip:user@ims.example>", IMS3GPPSMSContentType, rpdu)
	if err != nil {
		t.Fatalf("BuildIMSCPIMMessage() error = %v", err)
	}
	boundary := "ims-message-mixed"
	body := buildIMSMultipartTestBody(t, boundary, []imsMultipartTestPart{
		{
			headers: map[string][]string{"Content-Type": {"application/sdp"}},
			body:    []byte("v=0\r\n"),
		},
		{
			headers: map[string][]string{"Content-Type": {IMSCPIMContentType}},
			body:    cpimBody,
		},
	})

	result, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		CallID:      "sms-downlink-multipart-cpim",
		ContentType: `multipart/mixed; boundary="` + boundary + `"`,
		Body:        body,
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage() error = %v", err)
	}
	if result.StatusCode != 200 || result.ReplyContentType != IMSCPIMContentType || result.Incoming == nil || result.Incoming.Content != "hello" {
		t.Fatalf("result=%+v", result)
	}
	reply, err := ParseIMSCPIMMessage(result.ReplyBody)
	if err != nil {
		t.Fatalf("ParseIMSCPIMMessage(reply) error = %v body=%x", err, result.ReplyBody)
	}
	if reply.ContentType != IMS3GPPSMSContentType || string(reply.Body) != string(BuildSMSRPAck(0x34)) {
		t.Fatalf("reply=%+v body=%x", reply, reply.Body)
	}
	if len(dispatch.events) != 1 {
		t.Fatalf("events=%d", len(dispatch.events))
	}
	got, ok := dispatch.events[0].(eventhost.SMSReceived)
	if !ok || got.Sender != "10086" || got.Content != "hello" {
		t.Fatalf("event=%+v", dispatch.events[0])
	}
}

func TestHandleIMSMessageAcceptsMultipartBase64TransferEncoded3GPPSMS(t *testing.T) {
	dispatch := &fakeDispatcher{}
	svc := NewService("dev-1", "310280233641503", nil, dispatch)
	tpdu := mustHex(t, "0005810180F600006270502143650005E8329BFD06")
	rpdu := imsRPDataBody(0x36, tpdu)
	boundary := "ims-message-base64-sms"
	body := buildIMSMultipartTestBody(t, boundary, []imsMultipartTestPart{
		{
			headers: map[string][]string{"Content-Type": {"application/sdp"}},
			body:    []byte("v=0\r\n"),
		},
		{
			headers: map[string][]string{
				"Content-Type":              {IMS3GPPSMSContentType},
				"Content-Transfer-Encoding": {"base64"},
			},
			body: []byte(base64.StdEncoding.EncodeToString(rpdu)),
		},
	})

	result, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		CallID:      "sms-downlink-multipart-base64",
		ContentType: `multipart/mixed; boundary="` + boundary + `"`,
		Body:        body,
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage() error = %v", err)
	}
	if result.StatusCode != 200 || result.ReplyContentType != IMS3GPPSMSContentType || string(result.ReplyBody) != string(BuildSMSRPAck(0x36)) {
		t.Fatalf("result=%+v", result)
	}
	if result.Incoming == nil || result.Incoming.Sender != "10086" || result.Incoming.Content != "hello" {
		t.Fatalf("incoming=%+v", result.Incoming)
	}
	if len(dispatch.events) != 1 {
		t.Fatalf("events=%d", len(dispatch.events))
	}
	got, ok := dispatch.events[0].(eventhost.SMSReceived)
	if !ok || got.Sender != "10086" || got.Content != "hello" {
		t.Fatalf("event=%+v", dispatch.events[0])
	}
}

func TestHandleIMSMessageAcceptsMultipartIMDNDeliveryReport(t *testing.T) {
	store := &fakeDeliveryStore{match: DeliveryPartMatch{MessageID: "msg-789", PartNo: 1, State: "displayed"}}
	svc := NewService("dev-1", "310280233641503", store, nil)
	payload := strings.Join([]string{
		`<imdn xmlns="urn:ietf:params:xml:ns:imdn">`,
		`<message-id>msg-789-1@vowifi-go</message-id>`,
		`<datetime>2026-07-07T03:04:05Z</datetime>`,
		`<recipient-uri>tel:+18005550123</recipient-uri>`,
		`<display-notification><status><displayed/></status></display-notification>`,
		`</imdn>`,
	}, "")
	boundary := "ims-message-imdn"
	body := buildIMSMultipartTestBody(t, boundary, []imsMultipartTestPart{
		{
			headers: map[string][]string{"Content-Type": {"application/sdp"}},
			body:    []byte("v=0\r\n"),
		},
		{
			headers: map[string][]string{
				"Content-Type":        {`message/imdn+xml; charset=UTF-8`},
				"Content-Disposition": {"notification"},
			},
			body: []byte(payload),
		},
	})

	result, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		CallID:      "imdn-multipart-call",
		ContentType: `multipart/related; boundary="` + boundary + `"`,
		Body:        body,
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage() error = %v", err)
	}
	if result.StatusCode != 200 || result.DeliveryReport == nil {
		t.Fatalf("result=%+v", result)
	}
	report := result.DeliveryReport
	if report.InReplyTo != "msg-789-1@vowifi-go" || report.CallID != "imdn-multipart-call" || report.State != "delivered" {
		t.Fatalf("report=%+v", report)
	}
	if report.Recipient != "tel:+18005550123" || report.ErrorText != "" {
		t.Fatalf("report fields=%+v", report)
	}
	if store.reportInReplyTo != "msg-789-1@vowifi-go" || store.recomputedMessageID != "msg-789" {
		t.Fatalf("store=%+v", store)
	}
}

func TestHandleIMSMessageAcceptsRPACKStatusReportBuiltFromStruct(t *testing.T) {
	store := &fakeDeliveryStore{match: DeliveryPartMatch{MessageID: "msg-456", PartNo: 1, State: "failed"}}
	svc := NewService("dev-1", "310280233641503", store, nil)
	sentAt := time.Date(2026, 7, 5, 12, 34, 56, 0, time.FixedZone("", 0))
	doneAt := time.Date(2026, 7, 5, 12, 44, 0, 0, time.FixedZone("", 0))
	tpdu, err := BuildSMSStatusReportTPDU(SMSStatusReport{
		FirstOctet: 0x02,
		Reference:  7,
		Recipient:  "+18005551212",
		Timestamp:  sentAt,
		DoneAt:     doneAt,
		Status:     0x46,
	})
	if err != nil {
		t.Fatalf("BuildSMSStatusReportTPDU() error = %v", err)
	}
	body, err := BuildSMSRPAckWithTPDU(0x55, tpdu)
	if err != nil {
		t.Fatalf("BuildSMSRPAckWithTPDU() error = %v", err)
	}

	result, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		CallID:      "status-report-call",
		ContentType: IMS3GPPSMSContentType,
		Body:        body,
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage() error = %v", err)
	}
	if result.StatusCode != 200 || result.DeliveryReport == nil || result.RPDU.Kind != SMSRPDUKindAck {
		t.Fatalf("result=%+v", result)
	}
	report := result.DeliveryReport
	if report.CallID != "status-report-call" || report.RPMR != 7 || report.State != "failed" || report.RPCause != 0x46 {
		t.Fatalf("report=%+v", report)
	}
	if report.Recipient != "+18005551212" || !report.SentAt.Equal(sentAt) || !report.ReportAt.Equal(doneAt) || !strings.Contains(report.ErrorText, "validity period expired") {
		t.Fatalf("report fields=%+v", report)
	}
	if store.reportCallID != "status-report-call" || store.reportRPMR != 7 || store.reportState != "failed" || store.reportRPCause != 0x46 {
		t.Fatalf("store report=%+v", store)
	}
	if store.recomputedMessageID != "msg-456" {
		t.Fatalf("recomputedMessageID=%q", store.recomputedMessageID)
	}
}

type imsMultipartTestPart struct {
	headers map[string][]string
	body    []byte
}

func buildIMSMultipartTestBody(t *testing.T, boundary string, parts []imsMultipartTestPart) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	if err := writer.SetBoundary(boundary); err != nil {
		t.Fatalf("SetBoundary() error = %v", err)
	}
	for _, part := range parts {
		header := textproto.MIMEHeader{}
		for key, values := range part.headers {
			for _, value := range values {
				header.Add(key, value)
			}
		}
		partWriter, err := writer.CreatePart(header)
		if err != nil {
			t.Fatalf("CreatePart() error = %v", err)
		}
		if _, err := partWriter.Write(part.body); err != nil {
			t.Fatalf("Write(part) error = %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return buf.Bytes()
}
