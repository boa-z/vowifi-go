package messaging

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/runtimehost/eventhost"
)

func TestSegmentSMSGSM7(t *testing.T) {
	parts := SegmentSMS(strings.Repeat("a", 161), "")
	if len(parts) != 2 {
		t.Fatalf("parts=%d, want 2", len(parts))
	}
	if parts[0].Encoding != "gsm7" || len([]rune(parts[0].Text)) != 153 || len(parts[0].UDH) == 0 {
		t.Fatalf("first part=%+v", parts[0])
	}
	if parts[1].PartNo != 2 || parts[1].TotalParts != 2 {
		t.Fatalf("second part=%+v", parts[1])
	}
}

func TestSegmentSMSUsesFreshConcatReferences(t *testing.T) {
	first := SegmentSMS(strings.Repeat("a", 161), "")
	second := SegmentSMS(strings.Repeat("b", 161), "")
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("parts first=%d second=%d", len(first), len(second))
	}
	if first[0].ConcatRefBits != 8 || second[0].ConcatRefBits != 8 {
		t.Fatalf("concat bits first=%+v second=%+v", first[0], second[0])
	}
	if first[0].ConcatRef == 0 || second[0].ConcatRef == 0 || first[0].ConcatRef == second[0].ConcatRef {
		t.Fatalf("concat refs first=%d second=%d", first[0].ConcatRef, second[0].ConcatRef)
	}
	if first[0].UDH[3] != byte(first[0].ConcatRef) || second[0].UDH[3] != byte(second[0].ConcatRef) {
		t.Fatalf("UDH refs first=%x second=%x", first[0].UDH, second[0].UDH)
	}
}

func TestSegmentSMSWithExplicit16BitConcatReference(t *testing.T) {
	parts := SegmentSMSWithOptions(strings.Repeat("a", 306), SendOptions{ConcatRef: 0x1234, ConcatRefBits: 16})
	if len(parts) != 3 {
		t.Fatalf("parts=%d, want 3", len(parts))
	}
	if parts[0].ConcatRef != 0x1234 || parts[0].ConcatRefBits != 16 {
		t.Fatalf("first part=%+v", parts[0])
	}
	wantUDH := []byte{0x06, 0x08, 0x04, 0x12, 0x34, 0x03, 0x01}
	if string(parts[0].UDH) != string(wantUDH) {
		t.Fatalf("UDH=%x want %x", parts[0].UDH, wantUDH)
	}
	if messageLen(parts[0].Text, "gsm7") != 152 {
		t.Fatalf("first part septets=%d want 152", messageLen(parts[0].Text, "gsm7"))
	}
}

func TestSegmentSMSGSM7ExtendedCharacters(t *testing.T) {
	single := SegmentSMS(strings.Repeat("^", 80), "")
	if len(single) != 1 || single[0].Encoding != "gsm7" || single[0].UDH != nil || messageLen(single[0].Text, single[0].Encoding) != 160 {
		t.Fatalf("single extended parts=%+v", single)
	}

	parts := SegmentSMS(strings.Repeat("^", 81), "")
	if len(parts) != 2 {
		t.Fatalf("parts=%d, want 2", len(parts))
	}
	if parts[0].Encoding != "gsm7" || messageLen(parts[0].Text, "gsm7") > 153 || len([]rune(parts[0].Text)) != 76 || len(parts[0].UDH) == 0 {
		t.Fatalf("first extended part=%+v septets=%d", parts[0], messageLen(parts[0].Text, "gsm7"))
	}
	if parts[1].PartNo != 2 || parts[1].TotalParts != 2 || messageLen(parts[1].Text, "gsm7") != 10 {
		t.Fatalf("second extended part=%+v septets=%d", parts[1], messageLen(parts[1].Text, "gsm7"))
	}
}

func TestSegmentSMSUCS2(t *testing.T) {
	parts := SegmentSMS(strings.Repeat("你", 71), "")
	if len(parts) != 2 {
		t.Fatalf("parts=%d, want 2", len(parts))
	}
	if parts[0].Encoding != "ucs2" || len([]rune(parts[0].Text)) != 67 {
		t.Fatalf("first part=%+v", parts[0])
	}
}

func TestSendSMSWithTransportStoresEveryPart(t *testing.T) {
	store := &fakeDeliveryStore{}
	dispatch := &fakeDispatcher{}
	transport := &fakeSMSTransport{}
	svc := NewService("dev-1", "310280233641503", store, dispatch)
	svc.SetSMSTransport(transport)

	out, err := svc.SendSMSWithOptions(context.Background(), "+18005551212", strings.Repeat("a", 161), SendOptions{})
	if err != nil {
		t.Fatalf("SendSMSWithOptions() error = %v", err)
	}
	if out.Parts != 2 || out.PartsTotal != 2 || out.State != "sent" {
		t.Fatalf("outcome=%+v", out)
	}
	if len(transport.requests) != 2 || transport.requests[0].Part.PartNo != 1 || transport.requests[1].Part.PartNo != 2 {
		t.Fatalf("transport requests=%+v", transport.requests)
	}
	if store.createdPartsTotal != 2 || len(store.parts) != 2 || store.state != "sent" || store.acks != 2 {
		t.Fatalf("store=%+v parts=%+v", store, store.parts)
	}
	if len(dispatch.events) != 1 {
		t.Fatalf("events=%d", len(dispatch.events))
	}
	sent, ok := dispatch.events[0].(eventhost.SMSSent)
	if !ok || sent.TotalParts != 2 {
		t.Fatalf("event=%+v", dispatch.events[0])
	}
}

func TestSendSMSWithOptionsPropagatesValidityPeriod(t *testing.T) {
	transport := &fakeSMSTransport{}
	svc := NewService("dev-1", "310280233641503", nil, nil)
	svc.SetSMSTransport(transport)

	out, err := svc.SendSMSWithOptions(context.Background(), "+18005551212", strings.Repeat("a", 161), SendOptions{
		ValidityPeriod: 6 * time.Hour,
	})
	if err != nil {
		t.Fatalf("SendSMSWithOptions() error = %v", err)
	}
	if out.PartsTotal != 2 || len(transport.requests) != 2 {
		t.Fatalf("out=%+v requests=%+v", out, transport.requests)
	}
	for _, req := range transport.requests {
		if req.Part.ValidityPeriod != 6*time.Hour {
			t.Fatalf("part validity=%s want 6h part=%+v", req.Part.ValidityPeriod, req.Part)
		}
	}
}

func TestSendSMSWithTransportFailureMarksDeliveryFailed(t *testing.T) {
	store := &fakeDeliveryStore{}
	transport := &fakeSMSTransport{failPart: 2}
	svc := NewService("dev-1", "310280233641503", store, nil)
	svc.SetSMSTransport(transport)

	out, err := svc.SendSMSWithOptions(context.Background(), "+18005551212", strings.Repeat("a", 161), SendOptions{})
	if err == nil {
		t.Fatal("SendSMSWithOptions() err=nil, want failure")
	}
	if out.State != "failed" || out.Parts != 1 || store.state != "failed" || store.acks != 1 {
		t.Fatalf("outcome=%+v store=%+v", out, store)
	}
	if !strings.Contains(store.lastError, "part failed") {
		t.Fatalf("lastError=%q", store.lastError)
	}
}

func TestSendSMSWithOptionsRejectsInvalidConcatReference(t *testing.T) {
	svc := NewService("dev-1", "310280233641503", nil, nil)
	_, err := svc.SendSMSWithOptions(context.Background(), "+18005551212", strings.Repeat("a", 161), SendOptions{
		ConcatRef:     0x1ff,
		ConcatRefBits: 8,
	})
	if err == nil || !strings.Contains(err.Error(), "8-bit concat reference") {
		t.Fatalf("SendSMSWithOptions() err=%v, want 8-bit concat reference error", err)
	}
}

func TestSendSMSWithOptionsRejectsInvalidValidityPeriod(t *testing.T) {
	svc := NewService("dev-1", "310280233641503", nil, nil)
	_, err := svc.SendSMSWithOptions(context.Background(), "+18005551212", "hello", SendOptions{
		ValidityPeriod: 64 * 7 * 24 * time.Hour,
	})
	if err == nil || !strings.Contains(err.Error(), "validity period") {
		t.Fatalf("SendSMSWithOptions() err=%v, want validity period error", err)
	}
}

func TestUSSDTransportSessionLifecycle(t *testing.T) {
	transport := &fakeUSSDTransport{
		executeResult:  USSDResult{Text: "1. Balance\n2. Data", RawText: "menu", Status: 1, DCS: 15, Done: false},
		continueResult: USSDResult{Text: "Balance: 10", Status: 0, DCS: 15, Done: true},
	}
	dispatch := &fakeDispatcher{}
	svc := NewService("dev-1", "310280233641503", nil, dispatch)
	svc.SetUSSDTransport(transport)

	first, err := svc.SendUSSD(context.Background(), "*100#")
	if err != nil {
		t.Fatalf("SendUSSD() error = %v", err)
	}
	if first.Done || first.SessionID == "" || first.Text != "1. Balance\n2. Data" {
		t.Fatalf("first=%+v", first)
	}
	if len(transport.executeRequests) != 1 || transport.executeRequests[0].Command != "*100#" {
		t.Fatalf("execute requests=%+v", transport.executeRequests)
	}
	if len(dispatch.events) != 1 {
		t.Fatalf("events=%d", len(dispatch.events))
	}
	firstEvent, ok := dispatch.events[0].(eventhost.USSDUpdated)
	if !ok || firstEvent.DevID != "dev-1" || firstEvent.SessionID != first.SessionID || firstEvent.Text != "1. Balance\n2. Data" || firstEvent.RawText != "menu" || firstEvent.Status != 1 || firstEvent.DCS != 15 || firstEvent.Done || firstEvent.Time.IsZero() {
		t.Fatalf("event=%+v", dispatch.events[0])
	}

	next, err := svc.ContinueUSSD(context.Background(), first.SessionID, "1")
	if err != nil {
		t.Fatalf("ContinueUSSD() error = %v", err)
	}
	if !next.Done || next.Text != "Balance: 10" {
		t.Fatalf("next=%+v", next)
	}
	if len(transport.continueRequests) != 1 || transport.continueRequests[0].Input != "1" {
		t.Fatalf("continue requests=%+v", transport.continueRequests)
	}
	if len(dispatch.events) != 2 {
		t.Fatalf("events=%d", len(dispatch.events))
	}
	nextEvent, ok := dispatch.events[1].(eventhost.USSDUpdated)
	if !ok || nextEvent.SessionID != first.SessionID || nextEvent.Text != "Balance: 10" || nextEvent.Status != 0 || nextEvent.DCS != 15 || !nextEvent.Done || nextEvent.Time.IsZero() {
		t.Fatalf("event=%+v", dispatch.events[1])
	}
	if _, err := svc.ContinueUSSD(context.Background(), first.SessionID, "1"); err == nil {
		t.Fatal("ContinueUSSD() err=nil after session completion, want inactive session error")
	}
}

func TestUSSDCancelDelegatesAndClearsSession(t *testing.T) {
	transport := &fakeUSSDTransport{executeResult: USSDResult{Text: "menu", Done: false}}
	svc := NewService("dev-1", "310280233641503", nil, nil)
	svc.SetUSSDTransport(transport)

	first, err := svc.SendUSSD(context.Background(), "*100#")
	if err != nil {
		t.Fatalf("SendUSSD() error = %v", err)
	}
	if err := svc.CancelUSSD(context.Background(), first.SessionID); err != nil {
		t.Fatalf("CancelUSSD() error = %v", err)
	}
	if len(transport.cancelRequests) != 1 || transport.cancelRequests[0].SessionID != first.SessionID {
		t.Fatalf("cancel requests=%+v", transport.cancelRequests)
	}
	if _, err := svc.ContinueUSSD(context.Background(), first.SessionID, "1"); err == nil {
		t.Fatal("ContinueUSSD() err=nil after cancel, want inactive session error")
	}
}

func TestHandleSMSDeliveryReportMarksAndRecomputes(t *testing.T) {
	store := &fakeDeliveryStore{match: DeliveryPartMatch{MessageID: "msg-1", PartNo: 1, State: "delivered"}}
	svc := NewService("dev-1", "310280233641503", store, nil)

	match, err := svc.HandleSMSDeliveryReport(context.Background(), SMSDeliveryReport{
		InReplyTo: "sip-message-1",
		CallID:    "call-1",
		RPMR:      7,
		SIPCode:   202,
	})
	if err != nil {
		t.Fatalf("HandleSMSDeliveryReport() error = %v", err)
	}
	if match.MessageID != "msg-1" || store.reportState != "delivered" || store.reportSIPCode != 202 || store.reportRPMR != 7 {
		t.Fatalf("match=%+v store=%+v", match, store)
	}
	if store.recomputedMessageID != "msg-1" {
		t.Fatalf("recomputedMessageID=%q", store.recomputedMessageID)
	}
}

func TestHandleSMSDeliveryReportFailureCause(t *testing.T) {
	store := &fakeDeliveryStore{match: DeliveryPartMatch{MessageID: "msg-1", PartNo: 1, State: "failed"}}
	svc := NewService("dev-1", "310280233641503", store, nil)

	_, err := svc.HandleSMSDeliveryReport(context.Background(), SMSDeliveryReport{
		InReplyTo: "sip-message-1",
		RPCause:   42,
	})
	if err != nil {
		t.Fatalf("HandleSMSDeliveryReport() error = %v", err)
	}
	if store.reportState != "failed" || !strings.Contains(store.reportErrText, "42") {
		t.Fatalf("store=%+v", store)
	}
}

func TestHandleSMSDeliveryReportUsesMappedRPCauseText(t *testing.T) {
	store := &fakeDeliveryStore{match: DeliveryPartMatch{MessageID: "msg-1", PartNo: 1, State: "failed"}}
	svc := NewService("dev-1", "310280233641503", store, nil)

	_, err := svc.HandleSMSDeliveryReport(context.Background(), SMSDeliveryReport{
		CallID:  "call-1",
		RPCause: int(SMSRPCauseTemporaryFailure),
	})
	if err != nil {
		t.Fatalf("HandleSMSDeliveryReport() error = %v", err)
	}
	if store.reportErrText != "RP cause 41: temporary failure" {
		t.Fatalf("reportErrText=%q", store.reportErrText)
	}
}

func TestHandleIncomingSMSDispatchesEvent(t *testing.T) {
	dispatch := &fakeDispatcher{}
	svc := NewService("dev-1", "310280233641503", nil, dispatch)

	err := svc.HandleIncomingSMS(context.Background(), IncomingSMS{Sender: "+10086", Content: "hello"})
	if err != nil {
		t.Fatalf("HandleIncomingSMS() error = %v", err)
	}
	if len(dispatch.events) != 1 {
		t.Fatalf("events=%d", len(dispatch.events))
	}
	got, ok := dispatch.events[0].(eventhost.SMSReceived)
	if !ok || got.DevID != "dev-1" || got.Sender != "+10086" || got.Content != "hello" || got.Time.IsZero() {
		t.Fatalf("event=%+v", dispatch.events[0])
	}
}

func TestHandleIMSMessageDispatchesRPDataAndReturnsAck(t *testing.T) {
	dispatch := &fakeDispatcher{}
	svc := NewService("dev-1", "310280233641503", nil, dispatch)
	tpdu := mustHex(t, "0005810180F600006270502143650005E8329BFD06")

	result, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		FromURI:     "sip:smsc@ims.example",
		ToURI:       "sip:user@ims.example",
		CallID:      "sms-downlink-1",
		ContentType: IMS3GPPSMSContentType,
		Body:        imsRPDataBody(0x33, tpdu),
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage() error = %v", err)
	}
	if result.StatusCode != 200 || result.ReplyContentType != IMS3GPPSMSContentType || string(result.ReplyBody) != string(BuildSMSRPAck(0x33)) {
		t.Fatalf("result=%+v", result)
	}
	if len(dispatch.events) != 1 {
		t.Fatalf("events=%d", len(dispatch.events))
	}
	got, ok := dispatch.events[0].(eventhost.SMSReceived)
	if !ok || got.Sender != "10086" || got.Content != "hello" {
		t.Fatalf("event=%+v", dispatch.events[0])
	}
}

func TestHandleIMSMessageReassemblesConcatSMSBeforeDispatch(t *testing.T) {
	dispatch := &fakeDispatcher{}
	svc := NewService("dev-1", "310280233641503", nil, dispatch)
	part1 := mustHex(t, "4005810180F6000862705021436500080500037A02014F60")
	part2 := mustHex(t, "4005810180F6000862705021436500080500037A0202597D")

	result, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		FromURI:     "sip:smsc@ims.example",
		ToURI:       "sip:user@ims.example",
		CallID:      "sms-downlink-2",
		ContentType: IMS3GPPSMSContentType,
		Body:        imsRPDataBody(0x34, part2),
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage(part2) error = %v", err)
	}
	if result.StatusCode != 200 || result.Incoming != nil || string(result.ReplyBody) != string(BuildSMSRPAck(0x34)) {
		t.Fatalf("part2 result=%+v", result)
	}
	if len(dispatch.events) != 0 {
		t.Fatalf("events after partial=%d", len(dispatch.events))
	}

	result, err = svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		FromURI:     "sip:smsc@ims.example",
		ToURI:       "sip:user@ims.example",
		CallID:      "sms-downlink-1",
		ContentType: IMS3GPPSMSContentType,
		Body:        imsRPDataBody(0x33, part1),
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage(part1) error = %v", err)
	}
	if result.StatusCode != 200 || result.Incoming == nil || result.Incoming.Content != "你好" || string(result.ReplyBody) != string(BuildSMSRPAck(0x33)) {
		t.Fatalf("part1 result=%+v", result)
	}
	if len(dispatch.events) != 1 {
		t.Fatalf("events after complete=%d", len(dispatch.events))
	}
	got, ok := dispatch.events[0].(eventhost.SMSReceived)
	if !ok || got.Sender != "10086" || got.Content != "你好" {
		t.Fatalf("event=%+v", dispatch.events[0])
	}
}

func TestHandleIMSMessageIgnoresDuplicateConcatPartUntilComplete(t *testing.T) {
	dispatch := &fakeDispatcher{}
	svc := NewService("dev-1", "310280233641503", nil, dispatch)
	part1 := mustHex(t, "4005810180F6000862705021436500080500037A02014F60")
	part2 := mustHex(t, "4005810180F6000862705021436500080500037A0202597D")

	for i := 0; i < 2; i++ {
		result, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
			FromURI:     "sip:smsc@ims.example",
			ToURI:       "sip:user@ims.example",
			ContentType: IMS3GPPSMSContentType,
			Body:        imsRPDataBody(byte(0x40+i), part2),
		})
		if err != nil {
			t.Fatalf("HandleIMSMessage(part2 duplicate %d) error = %v", i, err)
		}
		if result.Incoming != nil || len(dispatch.events) != 0 {
			t.Fatalf("duplicate result=%+v events=%d", result, len(dispatch.events))
		}
	}

	result, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		FromURI:     "sip:smsc@ims.example",
		ToURI:       "sip:user@ims.example",
		ContentType: IMS3GPPSMSContentType,
		Body:        imsRPDataBody(0x42, part1),
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage(part1) error = %v", err)
	}
	if result.Incoming == nil || result.Incoming.Content != "你好" || len(dispatch.events) != 1 {
		t.Fatalf("complete result=%+v events=%d", result, len(dispatch.events))
	}
}

func TestHandleIMSMessageMalformedConcatFallsBackToSingleSMS(t *testing.T) {
	dispatch := &fakeDispatcher{}
	svc := NewService("dev-1", "310280233641503", nil, dispatch)
	tpdu := mustHex(t, "4005810180F6000862705021436500080500037A02004F60")

	result, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		FromURI:     "sip:smsc@ims.example",
		ToURI:       "sip:user@ims.example",
		ContentType: IMS3GPPSMSContentType,
		Body:        imsRPDataBody(0x35, tpdu),
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage() error = %v", err)
	}
	if result.Incoming == nil || result.Incoming.Content != "你" || string(result.ReplyBody) != string(BuildSMSRPAck(0x35)) {
		t.Fatalf("result=%+v", result)
	}
	if len(dispatch.events) != 1 {
		t.Fatalf("events=%d", len(dispatch.events))
	}
}

func TestHandleIMSMessageMarksRPErrorDeliveryReport(t *testing.T) {
	store := &fakeDeliveryStore{match: DeliveryPartMatch{MessageID: "msg-1", PartNo: 1, State: "failed"}}
	svc := NewService("dev-1", "310280233641503", store, nil)

	result, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		CallID:      "call-1",
		ContentType: IMS3GPPSMSContentType,
		Body:        BuildSMSRPError(7, SMSRPCauseTemporaryFailure),
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage() error = %v", err)
	}
	if result.StatusCode != 200 || result.DeliveryReport == nil {
		t.Fatalf("result=%+v", result)
	}
	if store.reportCallID != "call-1" || store.reportRPMR != 7 || store.reportState != "failed" || store.reportRPCause != int(SMSRPCauseTemporaryFailure) {
		t.Fatalf("store=%+v", store)
	}
	if store.reportErrText != "RP cause 41: temporary failure" {
		t.Fatalf("reportErrText=%q", store.reportErrText)
	}
}

func TestHandleIMSMessageMarksStatusReportFailureText(t *testing.T) {
	store := &fakeDeliveryStore{match: DeliveryPartMatch{MessageID: "msg-1", PartNo: 1, State: "failed"}}
	svc := NewService("dev-1", "310280233641503", store, nil)
	tpdu := mustHex(t, "02070B918100551512F2627050214365006270502144000046")

	result, err := svc.HandleIMSMessage(context.Background(), IMSMessageRequest{
		CallID:      "status-report-failed",
		ContentType: IMS3GPPSMSContentType,
		Body:        imsRPDataBody(0x44, tpdu),
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage() error = %v", err)
	}
	if result.StatusCode != 200 || result.DeliveryReport == nil {
		t.Fatalf("result=%+v", result)
	}
	if store.reportCallID != "status-report-failed" || store.reportRPMR != 7 || store.reportState != "failed" || store.reportRPCause != 0x46 {
		t.Fatalf("store=%+v", store)
	}
	if !strings.Contains(store.reportErrText, "validity period expired") {
		t.Fatalf("reportErrText=%q", store.reportErrText)
	}
}

type fakeSMSTransport struct {
	requests []SMSSendRequest
	failPart int
}

type fakeUSSDTransport struct {
	executeRequests  []USSDRequest
	continueRequests []USSDRequest
	cancelRequests   []USSDRequest
	executeResult    USSDResult
	continueResult   USSDResult
}

func (t *fakeUSSDTransport) ExecuteUSSD(ctx context.Context, req USSDRequest) (USSDResult, error) {
	t.executeRequests = append(t.executeRequests, req)
	return t.executeResult, nil
}

func (t *fakeUSSDTransport) ContinueUSSD(ctx context.Context, req USSDRequest) (USSDResult, error) {
	t.continueRequests = append(t.continueRequests, req)
	return t.continueResult, nil
}

func (t *fakeUSSDTransport) CancelUSSD(ctx context.Context, req USSDRequest) error {
	t.cancelRequests = append(t.cancelRequests, req)
	return nil
}

func (t *fakeSMSTransport) SendSMSPart(ctx context.Context, req SMSSendRequest) (SMSSendResult, error) {
	t.requests = append(t.requests, req)
	if req.Part.PartNo == t.failPart {
		return SMSSendResult{State: "failed", ErrorText: "part failed"}, errors.New("part failed")
	}
	return SMSSendResult{CallID: "call", RPMR: req.Part.PartNo, State: "sent"}, nil
}

type fakeDispatcher struct {
	events []eventhost.Event
}

func (d *fakeDispatcher) Dispatch(ctx context.Context, ev eventhost.Event) {
	d.events = append(d.events, ev)
}

type fakeDeliveryStore struct {
	createdPartsTotal   int
	parts               []DeliveryPartStatus
	state               string
	lastError           string
	acks                int
	match               DeliveryPartMatch
	reportInReplyTo     string
	reportCallID        string
	reportDeviceID      string
	reportRPMR          int
	reportState         string
	reportSIPCode       int
	reportRPCause       int
	reportErrText       string
	recomputedMessageID string
}

func (s *fakeDeliveryStore) CreateSMSDelivery(messageID, imsi, deviceID, peer, content string, partsTotal int, at time.Time) error {
	s.createdPartsTotal = partsTotal
	return nil
}

func (s *fakeDeliveryStore) UpsertSMSDeliveryPart(messageID string, partNo int, callID string, rpMR int, state string, sentAt time.Time) error {
	s.parts = append(s.parts, DeliveryPartStatus{PartNo: partNo, CallID: callID, RPMR: rpMR, State: state, SentAt: sentAt})
	return nil
}

func (s *fakeDeliveryStore) MarkSMSDeliveryPartReport(inReplyTo, callID, deviceID string, rpMR int, state string, sipCode int, rpCause int, errText string, at time.Time) (DeliveryPartMatch, error) {
	s.reportInReplyTo = inReplyTo
	s.reportCallID = callID
	s.reportDeviceID = deviceID
	s.reportRPMR = rpMR
	s.reportState = state
	s.reportSIPCode = sipCode
	s.reportRPCause = rpCause
	s.reportErrText = errText
	return s.match, nil
}

func (s *fakeDeliveryStore) RecomputeSMSDelivery(messageID string, at time.Time) error {
	s.recomputedMessageID = messageID
	return nil
}

func (s *fakeDeliveryStore) UpdateSMSDeliveryState(messageID, state, lastError string, acks int, at time.Time) error {
	s.state = state
	s.lastError = lastError
	s.acks = acks
	return nil
}

func (s *fakeDeliveryStore) GetSMSDeliveryStatus(messageID string) (*DeliveryStatus, error) {
	return nil, ErrDeliveryNotFound
}

func imsRPDataBody(rpMR byte, tpdu []byte) []byte {
	body := make([]byte, 0, 5+len(tpdu))
	body = append(body, 0x01, rpMR, 0x00, 0x00, byte(len(tpdu)))
	body = append(body, tpdu...)
	return body
}
