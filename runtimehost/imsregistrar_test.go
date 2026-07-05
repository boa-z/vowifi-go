package runtimehost

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/runtimehost/identity"
	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

func TestWireIMSRegistrarUsesPreparedIdentity(t *testing.T) {
	transport := &wireIMSRegistrarTransport{responses: []voiceclient.RegisterResponse{{
		StatusCode: 200,
		Reason:     "OK",
		Headers: map[string][]string{
			"P-Associated-URI": {"<sip:user@ims.example>"},
			"Service-Route":    {"<sip:pcscf.ims.example;lr>"},
		},
	}}}
	voiceTransport := &runtimeVoiceTransport{responses: []voiceclient.SIPResponse{
		{StatusCode: 202, Reason: "Accepted"},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:*100%23@ims.example;user=dialstring>;tag=as-tag"},
				"Contact": {"<sip:ussd-as@ims.example>"},
			},
		},
	}}
	res, err := WireIMSRegistrar{
		Transport:      transport,
		VoiceTransport: voiceTransport,
		ContactHost:    "192.0.2.10",
		ContactPort:    5062,
		UserAgent:      "VoHive",
		Expires:        600,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-1",
		TraceID:  "trace-1",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
		Prepared: &identity.PreparedSession{
			IMSIdentity: identity.IMSIdentityResolution{
				IMPI:   "impi@private.example",
				IMPU:   "sip:user@ims.example",
				Domain: "ims.example",
			},
		},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	if !res.Registered || res.Server != "sip:user@ims.example" {
		t.Fatalf("result=%+v", res)
	}
	if res.Profile.IMPU != "sip:user@ims.example" || res.Binding.ContactURI != "sip:user@192.0.2.10:5062" {
		t.Fatalf("voice registration profile/binding=%+v/%+v", res.Profile, res.Binding)
	}
	if len(res.Binding.ServiceRoutes) != 1 || res.Binding.ServiceRoutes[0] != "<sip:pcscf.ims.example;lr>" {
		t.Fatalf("service routes=%+v", res.Binding.ServiceRoutes)
	}
	if res.VoiceTransport == nil {
		t.Fatal("VoiceTransport=nil, want SIP request transport for IMS voice")
	}
	if res.SMSTransport == nil {
		t.Fatal("SMSTransport=nil, want IMS SIP MESSAGE transport")
	}
	if res.USSDTransport == nil {
		t.Fatal("USSDTransport=nil, want IMS USSI transport")
	}
	smsResult, err := res.SMSTransport.SendSMSPart(context.Background(), messaging.SMSSendRequest{
		Peer:      "+18005551212",
		MessageID: "msg-1",
		Part:      messaging.SMSPart{PartNo: 1, TotalParts: 1, Text: "hello"},
	})
	if err != nil || smsResult.State != "accepted" {
		t.Fatalf("SendSMSPart() result=%+v err=%v", smsResult, err)
	}
	if len(voiceTransport.requests) != 1 || voiceTransport.requests[0].Method != "MESSAGE" || voiceTransport.requests[0].Headers["Route"] != "<sip:pcscf.ims.example;lr>" {
		t.Fatalf("SMS request=%+v", voiceTransport.requests)
	}
	ussdResult, err := res.USSDTransport.ExecuteUSSD(context.Background(), messaging.USSDRequest{SessionID: "ussd-1", Command: "*100#"})
	if err != nil {
		t.Fatalf("ExecuteUSSD() result=%+v err=%v", ussdResult, err)
	}
	if ussdResult.Done || len(voiceTransport.requests) != 2 || voiceTransport.requests[1].Method != "INVITE" || voiceTransport.requests[1].Headers["Recv-Info"] != messaging.IMSUSSDInfoPackage {
		t.Fatalf("USSD result=%+v request=%+v", ussdResult, voiceTransport.requests)
	}
	if len(voiceTransport.writes) != 1 || voiceTransport.writes[0].Method != "ACK" {
		t.Fatalf("USSD ACK writes=%+v", voiceTransport.writes)
	}
	if len(transport.requests) != 1 {
		t.Fatalf("requests=%d", len(transport.requests))
	}
	req := transport.requests[0]
	if req.URI != "sip:ims.example" || req.Headers["Expires"] != "600" {
		t.Fatalf("request=%+v", req)
	}
	if !strings.Contains(req.Headers["Contact"], "<sip:user@192.0.2.10:5062>") {
		t.Fatalf("Contact=%q", req.Headers["Contact"])
	}
	if req.Headers["User-Agent"] != "VoHive" || !strings.Contains(req.Headers["To"], "sip:user@ims.example") {
		t.Fatalf("headers=%+v", req.Headers)
	}
}

func TestWireIMSRegistrarHandlesAKADigestChallenge(t *testing.T) {
	rawNonce := append(runtimeBytesFrom(0x10, 16), runtimeBytesFrom(0x40, 16)...)
	transport := &wireIMSRegistrarTransport{responses: []voiceclient.RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`},
				"Security-Server":  {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=101;spi-s=202`},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"P-Associated-URI": {"<sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org>"},
			},
		},
	}}
	simAdapter := &wireIMSRegistrarSIM{}
	res, err := WireIMSRegistrar{
		Transport:   transport,
		ContactHost: "192.0.2.10",
		CNonce:      "cnonce",
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-1",
		TraceID:  "trace-1",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
		SIM:      simAdapter,
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	if !res.Registered || len(transport.requests) != 2 {
		t.Fatalf("result=%+v requests=%d", res, len(transport.requests))
	}
	second := transport.requests[1]
	if !strings.Contains(second.Headers["Authorization"], `username="310280233641503@ims.mnc280.mcc310.3gppnetwork.org"`) {
		t.Fatalf("Authorization=%q", second.Headers["Authorization"])
	}
	if !strings.Contains(second.Headers["Security-Verify"], "spi-c=101") {
		t.Fatalf("Security-Verify=%q", second.Headers["Security-Verify"])
	}
	if got := strings.ToUpper(hex.EncodeToString(simAdapter.rand)); got != strings.ToUpper(hex.EncodeToString(runtimeBytesFrom(0x10, 16))) {
		t.Fatalf("RAND=%s", got)
	}
}

func TestWireIMSRegistrarRequiresContactURI(t *testing.T) {
	_, err := WireIMSRegistrar{Transport: &wireIMSRegistrarTransport{}}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		Profile: identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
	})
	if err == nil || !strings.Contains(err.Error(), "contact URI") {
		t.Fatalf("err=%v, want contact URI error", err)
	}
}

func TestWireIMSRegistrarFormatsIPv6ContactHost(t *testing.T) {
	profile := voiceclient.IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"}
	got := WireIMSRegistrar{ContactHost: "2001:db8::10", ContactPort: 5070}.contactURIForProfile(profile)
	if got != "sip:user@[2001:db8::10]:5070" {
		t.Fatalf("contact URI=%q", got)
	}
}

type wireIMSRegistrarTransport struct {
	requests  []voiceclient.RegisterMessage
	responses []voiceclient.RegisterResponse
}

func (t *wireIMSRegistrarTransport) RoundTripRegister(ctx context.Context, msg voiceclient.RegisterMessage) (voiceclient.RegisterResponse, error) {
	t.requests = append(t.requests, msg)
	if len(t.responses) == 0 {
		return voiceclient.RegisterResponse{StatusCode: 500, Reason: "empty"}, nil
	}
	resp := t.responses[0]
	t.responses = t.responses[1:]
	return resp, nil
}

type wireIMSRegistrarSIM struct {
	rand []byte
	autn []byte
}

func (s *wireIMSRegistrarSIM) GetIMSI() (string, error) { return "310280233641503", nil }

func (s *wireIMSRegistrarSIM) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	s.rand = append([]byte(nil), rand16...)
	s.autn = append([]byte(nil), autn16...)
	return sim.AKAResult{RES: []byte{0x11, 0x22, 0x33, 0x44}, CK: runtimeBytesFrom(0xA0, 16), IK: runtimeBytesFrom(0xB0, 16)}, nil
}

func (s *wireIMSRegistrarSIM) Close() error { return nil }

func runtimeBytesFrom(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}
