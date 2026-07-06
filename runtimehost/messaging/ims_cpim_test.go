package messaging

import (
	"bytes"
	"encoding/base64"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIMSCPIMMessageHeaderRoundTrip(t *testing.T) {
	body := []byte(`<imdn><message-id>msg-123</message-id></imdn>`)
	messageHeaders := map[string][]string{
		"From":            {"<sip:alice@example.com>;tag=from-tag"},
		"To":              {"<sip:bob@example.com>"},
		"DateTime":        {"2026-07-07T02:03:04Z"},
		"NS":              {"imdn <urn:ietf:params:imdn>"},
		"Require":         {"imdn.Delivery-Notification"},
		"imdn.Message-ID": {"msg-123"},
	}
	contentHeaders := map[string][]string{
		"Content-Type":        {`message/imdn+xml; charset=UTF-8`},
		"Content-Disposition": {"notification"},
		"Content-Length":      {"999"},
	}

	encoded, err := BuildIMSCPIMMessageWithHeaders(messageHeaders, contentHeaders, body)
	if err != nil {
		t.Fatalf("BuildIMSCPIMMessageWithHeaders() error = %v", err)
	}
	if bytes.Contains(encoded, []byte("Content-Length: 999")) {
		t.Fatalf("encoded CPIM kept stale Content-Length:\n%s", encoded)
	}
	parsed, err := ParseIMSCPIMMessage(encoded)
	if err != nil {
		t.Fatalf("ParseIMSCPIMMessage() error = %v body=%s", err, encoded)
	}

	headers := textproto.MIMEHeader(parsed.Headers)
	if got := headers.Get("From"); got != "<sip:alice@example.com>;tag=from-tag" {
		t.Fatalf("From=%q", got)
	}
	if got := headers.Get("To"); got != "<sip:bob@example.com>" {
		t.Fatalf("To=%q", got)
	}
	if got := headers.Get("DateTime"); got != "2026-07-07T02:03:04Z" {
		t.Fatalf("DateTime=%q", got)
	}
	if got := headers.Get("NS"); got != "imdn <urn:ietf:params:imdn>" {
		t.Fatalf("NS=%q", got)
	}
	if got := headers.Get("Require"); got != "imdn.Delivery-Notification" {
		t.Fatalf("Require=%q", got)
	}
	if got := imsHeaderValue(parsed.Headers, "imdn.Message-ID"); got != "msg-123" {
		t.Fatalf("imdn.Message-ID=%q", got)
	}

	content := textproto.MIMEHeader(parsed.ContentHeaders)
	if parsed.ContentType != "message/imdn+xml" {
		t.Fatalf("ContentType=%q", parsed.ContentType)
	}
	if got := content.Get("Content-Type"); got != `message/imdn+xml; charset=UTF-8` {
		t.Fatalf("Content-Type=%q", got)
	}
	if got := content.Get("Content-Disposition"); got != "notification" {
		t.Fatalf("Content-Disposition=%q", got)
	}
	if got := content.Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length=%q want %d", got, len(body))
	}
	if string(parsed.Body) != string(body) {
		t.Fatalf("Body=%q want %q", parsed.Body, body)
	}

	if got := contentHeaders["Content-Length"][0]; got != "999" {
		t.Fatalf("caller content headers mutated: Content-Length=%q", got)
	}
}

func TestBuildIMSCPIMMessageWithHeadersDeduplicatesContentLength(t *testing.T) {
	body := []byte("hello")
	encoded, err := BuildIMSCPIMMessageWithHeaders(map[string][]string{
		"From": {"<sip:alice@example.com>"},
	}, map[string][]string{
		"Content-Type":   {"text/plain"},
		"Content-Length": {"999"},
		"content-length": {"888"},
	}, body)
	if err != nil {
		t.Fatalf("BuildIMSCPIMMessageWithHeaders() error = %v", err)
	}
	if count := bytes.Count(encoded, []byte("Content-Length:")); count != 1 {
		t.Fatalf("Content-Length count=%d body=\n%s", count, encoded)
	}
	if strings.Contains(string(encoded), "999") || strings.Contains(string(encoded), "888") {
		t.Fatalf("encoded CPIM kept stale duplicate length:\n%s", encoded)
	}
	parsed, err := ParseIMSCPIMMessage(encoded)
	if err != nil {
		t.Fatalf("ParseIMSCPIMMessage() error = %v body=%s", err, encoded)
	}
	content := textproto.MIMEHeader(parsed.ContentHeaders)
	if got := content.Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length=%q want %d", got, len(body))
	}
}

func TestParseIMSCPIMMessageDecodesContentTransferEncoding(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		encoding    string
		wireBody    []byte
		wantBody    []byte
	}{
		{
			name:        "base64 3gpp sms",
			contentType: IMS3GPPSMSContentType,
			encoding:    "base64",
			wantBody:    []byte{0x00, 0x34, 0x00, 0x05, 0x05, 0x01, 0x80, 0xf6, 0x00, 0x00, 0x01, 0x62, 0x72, 0x6f, 0x6b, 0x65, 0x6e},
		},
		{
			name:        "quoted printable text",
			contentType: "text/plain",
			encoding:    "quoted-printable",
			wireBody:    []byte("hello=3Dworld=0A"),
			wantBody:    []byte("hello=world\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wireBody := tt.wireBody
			if tt.encoding == "base64" {
				wireBody = []byte(base64.StdEncoding.EncodeToString(tt.wantBody))
			}
			body := []byte(strings.Join([]string{
				"From: <sip:alice@example.com>",
				"To: <sip:bob@example.com>",
				"",
				"Content-Type: " + tt.contentType,
				"Content-Transfer-Encoding: " + tt.encoding,
				"Content-Length: " + strconv.Itoa(len(wireBody)),
				"",
				string(wireBody),
			}, "\r\n"))

			parsed, err := ParseIMSCPIMMessage(body)
			if err != nil {
				t.Fatalf("ParseIMSCPIMMessage() error = %v body=%s", err, body)
			}
			if parsed.ContentType != normalizedIMSMessageContentType(tt.contentType) || string(parsed.Body) != string(tt.wantBody) {
				t.Fatalf("parsed contentType=%q body=%x want %q/%x", parsed.ContentType, parsed.Body, normalizedIMSMessageContentType(tt.contentType), tt.wantBody)
			}
		})
	}
}

func TestParseIMSCPIMMessageDecodesWrappedBase64ContentTransferEncoding(t *testing.T) {
	wantBody := []byte{0x00, 0x34, 0x00, 0x05, 0x05, 0x01, 0x80, 0xf6, 0x00, 0x00, 0x01}
	encoded := base64.StdEncoding.EncodeToString(wantBody)
	wireBody := []byte(encoded[:8] + "\r\n\t" + encoded[8:])
	body := []byte(strings.Join([]string{
		"From: <sip:alice@example.com>",
		"To: <sip:bob@example.com>",
		"",
		"Content-Type: " + IMS3GPPSMSContentType,
		"Content-Transfer-Encoding: base64",
		"Content-Length: " + strconv.Itoa(len(wireBody)),
		"",
		string(wireBody),
	}, "\r\n"))

	parsed, err := ParseIMSCPIMMessage(body)
	if err != nil {
		t.Fatalf("ParseIMSCPIMMessage() error = %v", err)
	}
	if string(parsed.Body) != string(wantBody) {
		t.Fatalf("body=%x want %x", parsed.Body, wantBody)
	}
}

func TestParseIMSCPIMMessageNormalizesIMDNNamespaceAlias(t *testing.T) {
	payload := "<imdn><message-id>msg-aliased</message-id></imdn>"
	body := []byte(strings.Join([]string{
		"From: <sip:alice@example.com>",
		"NS: MsgState <URN:IETF:PARAMS:IMDN>",
		"MsgState.Message-Id: msg-aliased",
		"MsgState.Disposition-Notification: positive-delivery, display",
		"",
		"Content-Type: message/imdn+xml",
		"Content-Length: " + strconv.Itoa(len(payload)),
		"",
		payload,
	}, "\r\n"))

	parsed, err := ParseIMSCPIMMessage(body)
	if err != nil {
		t.Fatalf("ParseIMSCPIMMessage() error = %v", err)
	}

	if got := imsHeaderValue(parsed.Headers, "imdn.Message-ID"); got != "msg-aliased" {
		t.Fatalf("imdn.Message-ID=%q", got)
	}
	if got := imsHeaderValue(parsed.Headers, "imdn.Disposition-Notification"); got != "positive-delivery, display" {
		t.Fatalf("imdn.Disposition-Notification=%q", got)
	}
	if got := imsHeaderValue(parsed.Headers, "MsgState.Message-ID"); got != "" {
		t.Fatalf("aliased MsgState.Message-ID still present as %q", got)
	}
	if values := parsed.Headers["imdn.Message-ID"]; len(values) != 1 || values[0] != "msg-aliased" {
		t.Fatalf("normalized Message-ID header=%+v", parsed.Headers)
	}
}

func TestParseIMSCPIMMessageMergesCanonicalAndAliasedIMDNHeaders(t *testing.T) {
	payload := "<imdn/>"
	body := []byte(strings.Join([]string{
		"From: <sip:alice@example.com>",
		"NS: x <urn:ietf:params:imdn>",
		"imdn.Message-ID: canonical",
		"x.Message-ID: aliased",
		"",
		"Content-Type: message/imdn+xml",
		"Content-Length: " + strconv.Itoa(len(payload)),
		"",
		payload,
	}, "\r\n"))

	parsed, err := ParseIMSCPIMMessage(body)
	if err != nil {
		t.Fatalf("ParseIMSCPIMMessage() error = %v", err)
	}
	values := parsed.Headers["imdn.Message-ID"]
	if len(values) != 2 || !cpimTestHasValue(values, "canonical") || !cpimTestHasValue(values, "aliased") {
		t.Fatalf("merged imdn.Message-ID values=%+v headers=%+v", values, parsed.Headers)
	}
	if got := parsed.Headers["x.Message-ID"]; len(got) != 0 {
		t.Fatalf("alias key still present: %+v", got)
	}
}

func TestParseIMSCPIMIMDNReportDeliveryFailure(t *testing.T) {
	payload := strings.Join([]string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		`<imdn xmlns="urn:ietf:params:xml:ns:imdn">`,
		`  <message-id>msg-123-1@vowifi-go</message-id>`,
		`  <datetime>2026-07-07T02:03:04.123Z</datetime>`,
		`  <recipient-uri>tel:+18005551212</recipient-uri>`,
		`  <original-recipient-uri>tel:+18005550000</original-recipient-uri>`,
		`  <delivery-notification><status><failed/></status></delivery-notification>`,
		`</imdn>`,
	}, "")
	body := []byte(strings.Join([]string{
		"From: <sip:smsc@ims.example>",
		"To: <sip:user@ims.example>",
		"NS: x <urn:ietf:params:imdn>",
		"x.Message-ID: header-message-id",
		"x.Original-To: tel:+18005559999",
		"",
		"Content-Type: message/imdn+xml; charset=UTF-8",
		"Content-Disposition: notification",
		"Content-Length: " + strconv.Itoa(len(payload)),
		"",
		payload,
	}, "\r\n"))

	cpim, err := ParseIMSCPIMMessage(body)
	if err != nil {
		t.Fatalf("ParseIMSCPIMMessage() error = %v", err)
	}
	report, err := parseIMSCPIMIMDNReport(cpim)
	if err != nil {
		t.Fatalf("parseIMSCPIMIMDNReport() error = %v", err)
	}

	if report.MessageID != "msg-123-1@vowifi-go" || report.Notification != "delivery" || report.Status != "failed" || report.State != "failed" {
		t.Fatalf("report=%+v", report)
	}
	if report.RecipientURI != "tel:+18005551212" || report.OriginalRecipientURI != "tel:+18005550000" {
		t.Fatalf("report recipients=%+v", report)
	}
	wantAt := time.Date(2026, 7, 7, 2, 3, 4, 123000000, time.UTC)
	if !report.DateTime.Equal(wantAt) {
		t.Fatalf("DateTime=%s want %s", report.DateTime, wantAt)
	}
	if !strings.Contains(report.ErrorText, "failed") {
		t.Fatalf("ErrorText=%q", report.ErrorText)
	}
}

func TestParseIMSCPIMIMDNReportTextStatusAndLooseDateTime(t *testing.T) {
	payload := strings.Join([]string{
		`<imdn xmlns="urn:ietf:params:xml:ns:imdn">`,
		`  <recipient-uri>tel:+18005551212</recipient-uri>`,
		`  <delivery-notification><status><error>carrier timeout</error></status></delivery-notification>`,
		`</imdn>`,
	}, "")
	body := []byte(strings.Join([]string{
		"From: <sip:smsc@ims.example>",
		"To: <sip:user@ims.example>",
		"NS: x <urn:ietf:params:imdn>",
		"x.Message-ID: header-message-id",
		"x.DateTime: 2026-07-07T10:03:04+0800",
		"",
		"Content-Type: message/imdn+xml; charset=UTF-8",
		"Content-Length: " + strconv.Itoa(len(payload)),
		"",
		payload,
	}, "\r\n"))

	cpim, err := ParseIMSCPIMMessage(body)
	if err != nil {
		t.Fatalf("ParseIMSCPIMMessage() error = %v", err)
	}
	report, err := parseIMSCPIMIMDNReport(cpim)
	if err != nil {
		t.Fatalf("parseIMSCPIMIMDNReport() error = %v", err)
	}

	if report.MessageID != "header-message-id" || report.Notification != "delivery" || report.Status != "error" || report.State != "failed" {
		t.Fatalf("report=%+v", report)
	}
	if report.StatusText != "carrier timeout" || !strings.Contains(report.ErrorText, "carrier timeout") {
		t.Fatalf("status text/error=%q/%q", report.StatusText, report.ErrorText)
	}
	wantAt := time.Date(2026, 7, 7, 10, 3, 4, 0, time.FixedZone("", 8*3600))
	if !report.DateTime.Equal(wantAt) {
		t.Fatalf("DateTime=%s want %s", report.DateTime, wantAt)
	}
}

func TestParseIMSCPIMIMDNReportStatusCharacterData(t *testing.T) {
	payload := strings.Join([]string{
		`<imdn xmlns="urn:ietf:params:xml:ns:imdn">`,
		`  <message-id>msg-displayed</message-id>`,
		`  <display-notification><status>displayed</status></display-notification>`,
		`</imdn>`,
	}, "")
	body, err := BuildIMSCPIMMessageWithHeaders(map[string][]string{"From": {"<sip:smsc@ims.example>"}}, map[string][]string{"Content-Type": {imsIMDNContentType}}, []byte(payload))
	if err != nil {
		t.Fatalf("BuildIMSCPIMMessageWithHeaders() error = %v", err)
	}
	cpim, err := ParseIMSCPIMMessage(body)
	if err != nil {
		t.Fatalf("ParseIMSCPIMMessage() error = %v", err)
	}
	report, err := parseIMSCPIMIMDNReport(cpim)
	if err != nil {
		t.Fatalf("parseIMSCPIMIMDNReport() error = %v", err)
	}
	if report.Notification != "display" || report.Status != "displayed" || report.State != "delivered" || report.ErrorText != "" {
		t.Fatalf("report=%+v", report)
	}
}

func cpimTestHasValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestBuildIMSCPIMMessageWithHeadersRejectsInvalidHeaders(t *testing.T) {
	_, err := BuildIMSCPIMMessageWithHeaders(nil, map[string][]string{"Content-Type": {"text/plain"}}, []byte("hello"))
	if err != nil {
		t.Fatalf("BuildIMSCPIMMessageWithHeaders(valid) error = %v", err)
	}

	tests := []struct {
		name           string
		messageHeaders map[string][]string
		contentHeaders map[string][]string
		want           string
	}{
		{
			name:           "missing content type",
			contentHeaders: map[string][]string{},
			want:           "content type is empty",
		},
		{
			name:           "bad message header name",
			messageHeaders: map[string][]string{"Bad: Name": {"value"}},
			contentHeaders: map[string][]string{"Content-Type": {"text/plain"}},
			want:           "invalid CPIM header name",
		},
		{
			name:           "bad content header value",
			messageHeaders: map[string][]string{"From": {"<sip:alice@example.com>"}},
			contentHeaders: map[string][]string{"Content-Type": {"text/plain\r\nInjected: yes"}},
			want:           "line break",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildIMSCPIMMessageWithHeaders(tt.messageHeaders, tt.contentHeaders, []byte("hello"))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("BuildIMSCPIMMessageWithHeaders() err=%v, want %q", err, tt.want)
			}
		})
	}
}
