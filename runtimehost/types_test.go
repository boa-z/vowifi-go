package runtimehost

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu"
	"github.com/iniwex5/vowifi-go/runtimehost/eventhost"
	"github.com/iniwex5/vowifi-go/runtimehost/identity"
	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
	"github.com/iniwex5/vowifi-go/runtimehost/voicehost"
)

type testModem struct{}

func (testModem) DeviceID() string                           { return "dev-1" }
func (testModem) IsHealthy() bool                            { return true }
func (testModem) IsSimInserted() bool                        { return true }
func (testModem) QuerySIMInserted() (bool, error)            { return true, nil }
func (testModem) GetRegStatus() (int, string)                { return 1, "registered" }
func (testModem) GetNetworkMode() string                     { return "LTE" }
func (testModem) Stop()                                      {}
func (testModem) OpenLogicalChannel(aid string) (int, error) { return 1, nil }
func (testModem) CloseLogicalChannel(channel int) error      { return nil }
func (testModem) TransmitAPDU(channel int, hexAPDU string) (string, error) {
	return "9000", nil
}

type testIMSRegistrar struct {
	result IMSRegistrationResult
	err    error
	config IMSRegistrationConfig
}

func (r *testIMSRegistrar) RegisterIMS(ctx context.Context, cfg IMSRegistrationConfig) (IMSRegistrationResult, error) {
	r.config = cfg
	if r.err != nil {
		return IMSRegistrationResult{}, r.err
	}
	return r.result, nil
}

func TestStartUsesIMSRegistrarResult(t *testing.T) {
	registrar := &testIMSRegistrar{result: IMSRegistrationResult{
		Registered: true,
		StatusCode: 200,
		Reason:     "ims registered",
		Server:     "pcscf",
	}}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID:     "dev-1",
		TraceID:      "trace-1",
		Access:       NewModemAccessAdapter(testModem{}),
		IMSRegistrar: registrar,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	st := inst.State()
	if !st.IMSReady || st.LastReason != "ims registered" {
		t.Fatalf("state=%+v", st)
	}
	if registrar.config.DeviceID != "dev-1" || registrar.config.TraceID != "trace-1" || registrar.config.Access == nil {
		t.Fatalf("registrar config=%+v", registrar.config)
	}
}

func TestStartRegistersRuntimeIMSVoiceAgent(t *testing.T) {
	transport := &runtimeVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:+18005551212@ims.example>;tag=remote"},
				"Contact": {"<sip:remote@pcscf.ims.example>"},
			},
			Body: runtimeSDP("198.51.100.22", 49170),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	gw := voicehost.NewGateway()
	registrar := &testIMSRegistrar{result: IMSRegistrationResult{
		Registered: true,
		StatusCode: 200,
		Reason:     "ims registered",
		Profile: voiceclient.IMSProfile{
			IMPI:   "user@ims.example",
			IMPU:   "sip:user@ims.example",
			Domain: "ims.example",
		},
		Binding: voiceclient.RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
			ServiceRoutes:  []string{"<sip:pcscf.ims.example;lr>"},
		},
		VoiceTransport: transport,
	}}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID:     "dev-voice",
		TraceID:      "trace-voice",
		IMSRegistrar: registrar,
		VoiceGateway: gw,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	agent, ok := gw.GetAgent("dev-voice").(voicehost.OutboundCallAgent)
	if !ok || agent == nil || agent != inst {
		t.Fatalf("gateway agent=%T, want runtime outbound agent", gw.GetAgent("dev-voice"))
	}
	res, err := agent.StartOutboundCall(context.Background(), voicehost.OutboundCallRequest{
		DeviceID: "dev-voice",
		CallID:   "call-runtime-voice",
		Callee:   "+18005551212",
		RemoteSDP: voicehost.SDPInfo{
			ConnectionIP: "192.0.2.44",
			MediaPort:    4000,
			Payloads:     []int{0, 8},
			Direction:    "sendrecv",
		},
		RawSDP: runtimeSDP("192.0.2.44", 4000),
	})
	if err != nil || !res.Accepted {
		t.Fatalf("StartOutboundCall() res=%+v err=%v", res, err)
	}
	if len(transport.requests) != 1 || transport.requests[0].Method != "INVITE" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	if transport.requests[0].Headers["Route"] != "<sip:pcscf.ims.example;lr>" {
		t.Fatalf("INVITE Route=%q", transport.requests[0].Headers["Route"])
	}
	if len(transport.writes) != 1 || transport.writes[0].Method != "ACK" {
		t.Fatalf("writes=%+v", transport.writes)
	}
	terminator, ok := gw.GetAgent("dev-voice").(voicehost.DialogTerminator)
	if !ok {
		t.Fatalf("gateway agent=%T, want dialog terminator", gw.GetAgent("dev-voice"))
	}
	canceller, ok := gw.GetAgent("dev-voice").(voicehost.DialogCanceller)
	if !ok {
		t.Fatalf("gateway agent=%T, want dialog canceller", gw.GetAgent("dev-voice"))
	}
	if err := canceller.CancelVoiceCall(context.Background(), voicehost.DialogInfo{CallID: "unknown-call"}); err != nil {
		t.Fatalf("CancelVoiceCall(unknown) error = %v", err)
	}
	if err := terminator.EndVoiceCall(context.Background(), voicehost.DialogInfo{CallID: "call-runtime-voice"}); err != nil {
		t.Fatalf("EndVoiceCall() error = %v", err)
	}
	if len(transport.requests) != 2 || transport.requests[1].Method != "BYE" {
		t.Fatalf("requests after BYE=%+v", transport.requests)
	}
}

func TestStartRejectsIMSRegistrationFailure(t *testing.T) {
	registrar := &testIMSRegistrar{err: errors.New("401 after AKA")}
	_, err := Start(context.Background(), StartRequest{
		DeviceID:     "dev-1",
		Access:       NewModemAccessAdapter(testModem{}),
		IMSRegistrar: registrar,
	})
	if err == nil || !strings.Contains(err.Error(), "IMS registration failed") {
		t.Fatalf("Start() err=%v, want IMS registration failure", err)
	}
}

func TestStartRejectsUnregisteredIMSResult(t *testing.T) {
	registrar := &testIMSRegistrar{result: IMSRegistrationResult{Registered: false, StatusCode: 403, Reason: "Forbidden"}}
	_, err := Start(context.Background(), StartRequest{
		DeviceID:     "dev-1",
		Access:       NewModemAccessAdapter(testModem{}),
		IMSRegistrar: registrar,
	})
	if err == nil || !strings.Contains(err.Error(), "IMS registration rejected") {
		t.Fatalf("Start() err=%v, want rejected IMS registration", err)
	}
}

func TestStartWithoutIMSRegistrarKeepsCompatibilityReady(t *testing.T) {
	inst, err := Start(context.Background(), StartRequest{
		DeviceID: "dev-1",
		Access:   NewModemAccessAdapter(testModem{}),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !inst.State().IMSReady {
		t.Fatalf("IMSReady=false without explicit registrar")
	}
	if inst.State().TunnelReady {
		t.Fatalf("TunnelReady=true without explicit tunnel manager")
	}
}

func TestStartEstablishesTunnelWhenManagerProvided(t *testing.T) {
	manager := &runtimeTunnelManager{session: &runtimeTunnelSession{result: swu.TunnelResult{
		Ready:            true,
		Mode:             swu.DataplaneModeUserspace,
		EPDGAddress:      "epdg.example",
		IKEEstablished:   true,
		IPsecEstablished: true,
		MOBIKESupported:  true,
		Reason:           "ike ipsec ready",
	}}}
	prepared := identity.PreparedSession{
		Profile:    identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280", IMEI: "356789012345678"},
		EPDGAddr:   "epdg.example",
		EPDGSource: "redirect",
		IMSIdentity: identity.IMSIdentityResolution{
			IMPI:   "310280233641503@private.att.net",
			IMPU:   "sip:310280233641503@one.att.net",
			Domain: "one.att.net",
		},
	}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID:      "dev-1",
		TraceID:       "trace-1",
		Profile:       prepared.Profile,
		Prepared:      &prepared,
		Access:        NewModemAccessAdapter(testModem{}),
		Dataplane:     DataplanePolicy{Mode: swu.DataplaneModeUserspace},
		TunnelManager: manager,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	st := inst.State()
	if !st.TunnelReady || st.LastReason != "ike ipsec ready" {
		t.Fatalf("state=%+v", st)
	}
	if manager.config.EPDGAddress != "epdg.example" || manager.config.Identity.Domain != "one.att.net" {
		t.Fatalf("tunnel config=%+v", manager.config)
	}
}

func TestStartRejectsIncompleteTunnel(t *testing.T) {
	manager := &runtimeTunnelManager{session: &runtimeTunnelSession{result: swu.TunnelResult{
		Ready:          true,
		IKEEstablished: true,
		Reason:         "child sa missing",
	}}}
	_, err := Start(context.Background(), StartRequest{
		DeviceID:      "dev-1",
		Profile:       identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
		Dataplane:     DataplanePolicy{Mode: swu.DataplaneModeUserspace},
		TunnelManager: manager,
	})
	if err == nil || !strings.Contains(err.Error(), "SWU tunnel establishment incomplete") {
		t.Fatalf("Start() err=%v, want incomplete tunnel", err)
	}
	if !manager.session.closed {
		t.Fatalf("incomplete tunnel was not closed")
	}
}

func TestStopClosesTunnel(t *testing.T) {
	session := &runtimeTunnelSession{result: swu.TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true}}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID:      "dev-1",
		Profile:       identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
		Dataplane:     DataplanePolicy{Mode: swu.DataplaneModeUserspace},
		TunnelManager: &runtimeTunnelManager{session: session},
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := inst.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if !session.closed || inst.State().TunnelReady {
		t.Fatalf("closed=%t state=%+v", session.closed, inst.State())
	}
}

func TestTriggerMOBIKEDelegatesToTunnel(t *testing.T) {
	session := &runtimeTunnelSession{
		result: swu.TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true},
		mobikeResult: swu.MOBIKEResult{
			Rekeyed:          true,
			IKEEstablished:   true,
			IPsecEstablished: true,
			Reason:           "mobike rekeyed",
		},
	}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID:      "dev-1",
		Profile:       identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
		Dataplane:     DataplanePolicy{Mode: swu.DataplaneModeUserspace},
		TunnelManager: &runtimeTunnelManager{session: session},
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := inst.TriggerMOBIKE("198.51.100.1", "198.51.100.2"); err != nil {
		t.Fatalf("TriggerMOBIKE() error = %v", err)
	}
	if session.mobikeRequest.OldIP != "198.51.100.1" || session.mobikeRequest.NewIP != "198.51.100.2" {
		t.Fatalf("mobike request=%+v", session.mobikeRequest)
	}
	if inst.State().LastReason != "mobike rekeyed" {
		t.Fatalf("state=%+v", inst.State())
	}
}

func TestStartWiresSMSTransport(t *testing.T) {
	transport := &runtimeSMSTransport{}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID:     "dev-1",
		Profile:      identity.Profile{IMSI: "310280233641503"},
		SMSTransport: transport,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	out, err := inst.SendSMSWithOptions(context.Background(), "+18005551212", strings.Repeat("a", 161), messaging.SendOptions{})
	if err != nil {
		t.Fatalf("SendSMSWithOptions() error = %v", err)
	}
	if out.PartsTotal != 2 || len(transport.requests) != 2 {
		t.Fatalf("outcome=%+v requests=%+v", out, transport.requests)
	}
}

func TestStartUsesIMSRegistrarSMSTransport(t *testing.T) {
	smsTransport := &runtimeSMSTransport{}
	ussdTransport := &runtimeUSSDTransport{}
	registrar := &testIMSRegistrar{result: IMSRegistrationResult{
		Registered:    true,
		StatusCode:    200,
		Reason:        "OK",
		SMSTransport:  smsTransport,
		USSDTransport: ussdTransport,
	}}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID:     "dev-ims-sms",
		Profile:      identity.Profile{IMSI: "310280233641503"},
		IMSRegistrar: registrar,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	out, err := inst.SendSMSWithOptions(context.Background(), "+18005551212", "hello", messaging.SendOptions{})
	if err != nil {
		t.Fatalf("SendSMSWithOptions() error = %v", err)
	}
	if out.PartsTotal != 1 || len(smsTransport.requests) != 1 || smsTransport.requests[0].Peer != "+18005551212" {
		t.Fatalf("outcome=%+v requests=%+v", out, smsTransport.requests)
	}
	ussd, err := inst.Service().SendUSSD(context.Background(), "*100#")
	if err != nil {
		t.Fatalf("SendUSSD() error = %v", err)
	}
	if ussd.Text != "ok" || len(ussdTransport.executeRequests) != 1 || ussdTransport.executeRequests[0].Command != "*100#" {
		t.Fatalf("ussd=%+v requests=%+v", ussd, ussdTransport.executeRequests)
	}
}

func TestStartWiresUSSDTransport(t *testing.T) {
	transport := &runtimeUSSDTransport{}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID:      "dev-1",
		Profile:       identity.Profile{IMSI: "310280233641503"},
		USSDTransport: transport,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	res, err := inst.Service().SendUSSD(context.Background(), "*100#")
	if err != nil {
		t.Fatalf("SendUSSD() error = %v", err)
	}
	if res.Text != "ok" || len(transport.executeRequests) != 1 {
		t.Fatalf("res=%+v requests=%+v", res, transport.executeRequests)
	}
}

func TestInstanceHandlesIncomingSMSAndDeliveryReport(t *testing.T) {
	store := &runtimeDeliveryStore{match: messaging.DeliveryPartMatch{MessageID: "msg-1", PartNo: 1, State: "delivered"}}
	dispatch := &runtimeDispatcher{}
	inst, err := Start(context.Background(), StartRequest{
		DeviceID:      "dev-1",
		Profile:       identity.Profile{IMSI: "310280233641503"},
		DeliveryStore: store,
		Dispatch:      dispatch,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := inst.HandleIncomingSMS(context.Background(), messaging.IncomingSMS{Sender: "+10086", Content: "hi"}); err != nil {
		t.Fatalf("HandleIncomingSMS() error = %v", err)
	}
	if len(dispatch.events) != 1 {
		t.Fatalf("events=%d", len(dispatch.events))
	}
	match, err := inst.HandleSMSDeliveryReport(context.Background(), messaging.SMSDeliveryReport{InReplyTo: "sip-1", SIPCode: 200})
	if err != nil {
		t.Fatalf("HandleSMSDeliveryReport() error = %v", err)
	}
	if match.MessageID != "msg-1" || store.reportState != "delivered" || store.recomputed != "msg-1" {
		t.Fatalf("match=%+v store=%+v", match, store)
	}
	tpdu, err := hex.DecodeString("0005810180F600006270502143650005E8329BFD06")
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	body := append([]byte{0x01, 0x33, 0x00, 0x00, byte(len(tpdu))}, tpdu...)
	imsResult, err := inst.HandleIMSMessage(context.Background(), voicehost.IMSMessageRequest{
		FromURI:     "sip:smsc@ims.example",
		ToURI:       "sip:user@ims.example",
		CallID:      "sms-downlink-1",
		ContentType: messaging.IMS3GPPSMSContentType,
		Body:        body,
	})
	if err != nil {
		t.Fatalf("HandleIMSMessage() error = %v", err)
	}
	if imsResult.StatusCode != 200 || imsResult.ContentType != messaging.IMS3GPPSMSContentType || string(imsResult.Body) != string(messaging.BuildSMSRPAck(0x33)) {
		t.Fatalf("imsResult=%+v", imsResult)
	}
	if len(dispatch.events) != 2 {
		t.Fatalf("events=%d", len(dispatch.events))
	}
	got, ok := dispatch.events[1].(eventhost.SMSReceived)
	if !ok || got.Sender != "10086" || got.Content != "hello" {
		t.Fatalf("event=%+v", dispatch.events[1])
	}
}

type runtimeSMSTransport struct {
	requests []messaging.SMSSendRequest
}

type runtimeVoiceTransport struct {
	requests  []voiceclient.SIPRequestMessage
	writes    []voiceclient.SIPRequestMessage
	responses []voiceclient.SIPResponse
}

func (t *runtimeVoiceTransport) RoundTripRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	t.requests = append(t.requests, msg)
	if len(t.responses) == 0 {
		return voiceclient.SIPResponse{StatusCode: 500, Reason: "empty"}, nil
	}
	resp := t.responses[0]
	t.responses = t.responses[1:]
	return resp, nil
}

func (t *runtimeVoiceTransport) WriteRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) error {
	t.writes = append(t.writes, msg)
	return nil
}

func runtimeSDP(ip string, port int) []byte {
	return []byte("v=0\r\n" +
		"o=- 0 0 IN IP4 " + ip + "\r\n" +
		"s=VoWiFi\r\n" +
		"c=IN IP4 " + ip + "\r\n" +
		"t=0 0\r\n" +
		"m=audio " + strconv.Itoa(port) + " RTP/AVP 0 8 101\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:8 PCMA/8000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=sendrecv\r\n")
}

type runtimeTunnelManager struct {
	session *runtimeTunnelSession
	err     error
	config  swu.TunnelConfig
}

func (m *runtimeTunnelManager) EstablishTunnel(ctx context.Context, cfg swu.TunnelConfig) (swu.TunnelSession, error) {
	m.config = cfg
	if m.err != nil {
		return nil, m.err
	}
	return m.session, nil
}

type runtimeTunnelSession struct {
	result        swu.TunnelResult
	mobikeResult  swu.MOBIKEResult
	mobikeErr     error
	mobikeRequest swu.MOBIKERequest
	closed        bool
}

func (s *runtimeTunnelSession) Result() swu.TunnelResult {
	return s.result
}

func (s *runtimeTunnelSession) MOBIKE(ctx context.Context, req swu.MOBIKERequest) (swu.MOBIKEResult, error) {
	s.mobikeRequest = req
	if s.mobikeErr != nil {
		return swu.MOBIKEResult{}, s.mobikeErr
	}
	return s.mobikeResult, nil
}

func (s *runtimeTunnelSession) Close(ctx context.Context) error {
	s.closed = true
	return nil
}

type runtimeUSSDTransport struct {
	executeRequests []messaging.USSDRequest
}

type runtimeDispatcher struct {
	events []eventhost.Event
}

func (d *runtimeDispatcher) Dispatch(ctx context.Context, ev eventhost.Event) {
	d.events = append(d.events, ev)
}

type runtimeDeliveryStore struct {
	match       messaging.DeliveryPartMatch
	reportState string
	recomputed  string
}

func (s *runtimeDeliveryStore) CreateSMSDelivery(messageID, imsi, deviceID, peer, content string, partsTotal int, at time.Time) error {
	return nil
}

func (s *runtimeDeliveryStore) UpsertSMSDeliveryPart(messageID string, partNo int, callID string, rpMR int, state string, sentAt time.Time) error {
	return nil
}

func (s *runtimeDeliveryStore) MarkSMSDeliveryPartReport(inReplyTo, callID, deviceID string, rpMR int, state string, sipCode int, rpCause int, errText string, at time.Time) (messaging.DeliveryPartMatch, error) {
	s.reportState = state
	return s.match, nil
}

func (s *runtimeDeliveryStore) RecomputeSMSDelivery(messageID string, at time.Time) error {
	s.recomputed = messageID
	return nil
}

func (s *runtimeDeliveryStore) UpdateSMSDeliveryState(messageID, state, lastError string, acks int, at time.Time) error {
	return nil
}

func (s *runtimeDeliveryStore) GetSMSDeliveryStatus(messageID string) (*messaging.DeliveryStatus, error) {
	return nil, messaging.ErrDeliveryNotFound
}

func (t *runtimeUSSDTransport) ExecuteUSSD(ctx context.Context, req messaging.USSDRequest) (messaging.USSDResult, error) {
	t.executeRequests = append(t.executeRequests, req)
	return messaging.USSDResult{Text: "ok", Done: true}, nil
}

func (t *runtimeUSSDTransport) ContinueUSSD(ctx context.Context, req messaging.USSDRequest) (messaging.USSDResult, error) {
	return messaging.USSDResult{Text: "continued", Done: true}, nil
}

func (t *runtimeUSSDTransport) CancelUSSD(ctx context.Context, req messaging.USSDRequest) error {
	return nil
}

func (t *runtimeSMSTransport) SendSMSPart(ctx context.Context, req messaging.SMSSendRequest) (messaging.SMSSendResult, error) {
	t.requests = append(t.requests, req)
	return messaging.SMSSendResult{State: "sent"}, nil
}
