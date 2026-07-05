package voicehost

import (
	"context"
	"strings"
	"testing"

	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

func TestIMSOutboundAgentInviteAckAndBye(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:+18005551212@ims.example>;tag=remote-tag"},
				"Contact": {"<sip:carrier@198.51.100.1:5060>"},
			},
			Body: []byte(sampleSDP("203.0.113.10", 49170)),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSOutboundAgent{
		Transport: transport,
		Profile: voiceclient.IMSProfile{
			IMPI:      "impi@example",
			IMPU:      "sip:user@ims.example",
			Domain:    "ims.example",
			UserAgent: "VoHive",
		},
		Registration: voiceclient.RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
			ServiceRoutes:  []string{"<sip:pcscf.ims.example;lr>"},
		},
		LocalTag: "local-tag",
	}

	result, err := agent.StartOutboundCall(context.Background(), OutboundCallRequest{
		DeviceID:  "dev-1",
		CallID:    "call-1",
		Callee:    "+18005551212",
		RawSDP:    []byte(sampleSDP("192.0.2.50", 4002)),
		RemoteSDP: SDPInfo{ConnectionIP: "192.0.2.50", MediaPort: 4002},
	})
	if err != nil {
		t.Fatalf("StartOutboundCall() error = %v", err)
	}
	if !result.Accepted || result.LocalSDP.ConnectionIP != "203.0.113.10" || result.LocalSDP.MediaPort != 49170 {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 1 || transport.requests[0].Method != "INVITE" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	invite := transport.requests[0]
	if invite.URI != "sip:+18005551212@ims.example" || invite.Headers["Route"] != "<sip:pcscf.ims.example;lr>" {
		t.Fatalf("INVITE=%+v", invite)
	}
	if !strings.Contains(string(invite.Body), "m=audio 4002 RTP/AVP") {
		t.Fatalf("INVITE body=%q", invite.Body)
	}
	if len(transport.writes) != 1 || transport.writes[0].Method != "ACK" {
		t.Fatalf("writes=%+v", transport.writes)
	}
	if transport.writes[0].URI != "sip:carrier@198.51.100.1:5060" || !strings.Contains(transport.writes[0].Headers["To"], "remote-tag") {
		t.Fatalf("ACK=%+v", transport.writes[0])
	}

	if err := agent.EndVoiceCall(context.Background(), DialogInfo{CallID: "call-1"}); err != nil {
		t.Fatalf("EndVoiceCall() error = %v", err)
	}
	if len(transport.requests) != 2 || transport.requests[1].Method != "BYE" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	bye := transport.requests[1]
	if bye.URI != "sip:carrier@198.51.100.1:5060" || bye.Headers["CSeq"] != "2 BYE" {
		t.Fatalf("BYE=%+v", bye)
	}
}

func TestIMSOutboundAgentRejectedInviteDoesNotAck(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{{StatusCode: 486, Reason: "Busy Here"}}}
	agent := &IMSOutboundAgent{
		Transport: transport,
		Profile:   voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration: voiceclient.RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
		},
	}
	result, err := agent.StartOutboundCall(context.Background(), OutboundCallRequest{
		CallID: "call-2",
		Callee: "+18005551212",
		RawSDP: []byte(sampleSDP("192.0.2.50", 4002)),
	})
	if err != nil {
		t.Fatalf("StartOutboundCall() error = %v", err)
	}
	if result.Accepted || result.Reason != "Busy Here" {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.writes) != 0 {
		t.Fatalf("ACK writes=%+v, want none", transport.writes)
	}
}

func TestIMSOutboundAgentKeepsDialogWhenByeFails(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers:    map[string][]string{"To": {"<sip:+18005551212@ims.example>;tag=remote-tag"}},
			Body:       []byte(sampleSDP("203.0.113.10", 49170)),
		},
		{StatusCode: 503, Reason: "Try Later"},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSOutboundAgent{
		Transport: transport,
		Profile:   voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration: voiceclient.RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
		},
	}
	if _, err := agent.StartOutboundCall(context.Background(), OutboundCallRequest{
		CallID: "call-3",
		Callee: "+18005551212",
		RawSDP: []byte(sampleSDP("192.0.2.50", 4002)),
	}); err != nil {
		t.Fatalf("StartOutboundCall() error = %v", err)
	}
	if err := agent.EndVoiceCall(context.Background(), DialogInfo{CallID: "call-3"}); err == nil {
		t.Fatal("EndVoiceCall() err=nil, want failed BYE")
	}
	if err := agent.EndVoiceCall(context.Background(), DialogInfo{CallID: "call-3"}); err != nil {
		t.Fatalf("EndVoiceCall() retry error = %v", err)
	}
	if len(transport.requests) != 3 || transport.requests[1].Method != "BYE" || transport.requests[2].Method != "BYE" {
		t.Fatalf("requests=%+v", transport.requests)
	}
}

func TestIMSOutboundAgentUsesRTPRelayWhenConfigured(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers:    map[string][]string{"To": {"<sip:+18005551212@ims.example>;tag=remote-tag"}},
			Body:       []byte(sampleSDP("203.0.113.10", 49170)),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSOutboundAgent{
		Transport: transport,
		Profile:   voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration: voiceclient.RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
		},
		MediaRelay: &RTPRelayConfig{
			ClientListenIP:    "127.0.0.1",
			ClientAdvertiseIP: "127.0.0.1",
			IMSListenIP:       "127.0.0.1",
			IMSAdvertiseIP:    "127.0.0.1",
		},
	}
	result, err := agent.StartOutboundCall(context.Background(), OutboundCallRequest{
		CallID:    "call-relay",
		Callee:    "+18005551212",
		RemoteSDP: SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 4002, Payloads: []int{0, 101}, Direction: "sendrecv"},
		RawSDP:    []byte(sampleSDP("127.0.0.1", 4002)),
	})
	if err != nil {
		t.Fatalf("StartOutboundCall() error = %v", err)
	}
	if len(transport.requests) != 1 || transport.requests[0].Method != "INVITE" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	imsOffer, err := ParseSDP(transport.requests[0].Body)
	if err != nil {
		t.Fatalf("ParseSDP(IMS offer) error = %v", err)
	}
	if imsOffer.ConnectionIP != "127.0.0.1" || imsOffer.MediaPort == 4002 || imsOffer.MediaPort <= 0 {
		t.Fatalf("IMS offer=%+v", imsOffer)
	}
	if result.LocalSDP.ConnectionIP != "127.0.0.1" || result.LocalSDP.MediaPort == 49170 || result.LocalSDP.MediaPort <= 0 {
		t.Fatalf("client answer=%+v", result.LocalSDP)
	}
	if answer := string(result.RawSDP); !strings.Contains(answer, "c=IN IP4 127.0.0.1") || strings.Contains(answer, "m=audio 49170") {
		t.Fatalf("client answer body=%q", answer)
	}
	if err := agent.EndVoiceCall(context.Background(), DialogInfo{CallID: "call-relay"}); err != nil {
		t.Fatalf("EndVoiceCall() error = %v", err)
	}
}

type fakeIMSVoiceTransport struct {
	requests  []voiceclient.SIPRequestMessage
	writes    []voiceclient.SIPRequestMessage
	responses []voiceclient.SIPResponse
}

func (t *fakeIMSVoiceTransport) RoundTripRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	t.requests = append(t.requests, msg)
	if len(t.responses) == 0 {
		return voiceclient.SIPResponse{StatusCode: 500, Reason: "empty"}, nil
	}
	resp := t.responses[0]
	t.responses = t.responses[1:]
	return resp, nil
}

func (t *fakeIMSVoiceTransport) WriteRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) error {
	t.writes = append(t.writes, msg)
	return nil
}
