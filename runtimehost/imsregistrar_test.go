package runtimehost

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/engine/sim"
	"github.com/boa-z/vowifi-go/engine/swu"
	"github.com/boa-z/vowifi-go/runtimehost/identity"
	"github.com/boa-z/vowifi-go/runtimehost/messaging"
	"github.com/boa-z/vowifi-go/runtimehost/voiceclient"
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

func TestWireIMSRegistrarReportsRegistrationRefreshSchedule(t *testing.T) {
	transport := &wireIMSRegistrarTransport{responses: []voiceclient.RegisterResponse{{
		StatusCode: 200,
		Reason:     "OK",
		Headers: map[string][]string{
			"P-Associated-URI": {"<sip:user@ims.example>"},
			"Contact":          {"<sip:310280233641503@192.0.2.10:5060>;expires=1200"},
		},
	}}}
	res, err := WireIMSRegistrar{
		Transport:        transport,
		ContactHost:      "192.0.2.10",
		ContactPort:      5060,
		Expires:          3600,
		RefreshLead:      2 * time.Minute,
		DisableKeepalive: true,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-1",
		TraceID:  "trace-refresh-schedule",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	if !res.Registered || res.RegisteredAt.IsZero() {
		t.Fatalf("result registration timestamps=%+v", res)
	}
	if res.Binding.Expires != 1200 {
		t.Fatalf("binding expires=%d, want granted Contact expires 1200", res.Binding.Expires)
	}
	if got, want := res.ExpiresAt.Sub(res.RegisteredAt), 20*time.Minute; got != want {
		t.Fatalf("ExpiresAt-RegisteredAt=%v, want %v", got, want)
	}
	if res.RefreshDelay != 18*time.Minute {
		t.Fatalf("RefreshDelay=%v, want 18m", res.RefreshDelay)
	}
	if got, want := res.NextRefreshAt.Sub(res.RegisteredAt), res.RefreshDelay; got != want {
		t.Fatalf("NextRefreshAt-RegisteredAt=%v, want %v", got, want)
	}
}

func TestWireIMSRegistrarRefreshScheduleHonorsDisableRefresh(t *testing.T) {
	transport := &wireIMSRegistrarTransport{responses: []voiceclient.RegisterResponse{{
		StatusCode: 200,
		Reason:     "OK",
		Headers: map[string][]string{
			"P-Associated-URI": {"<sip:user@ims.example>"},
			"Contact":          {"<sip:310280233641503@192.0.2.10:5060>;expires=600"},
		},
	}}}
	res, err := WireIMSRegistrar{
		Transport:      transport,
		ContactHost:    "192.0.2.10",
		ContactPort:    5060,
		DisableRefresh: true,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-1",
		TraceID:  "trace-no-refresh-schedule",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	if res.RegisteredAt.IsZero() || res.ExpiresAt.Sub(res.RegisteredAt) != 10*time.Minute {
		t.Fatalf("expiry metadata=%+v", res)
	}
	if res.RefreshDelay != 0 || !res.NextRefreshAt.IsZero() {
		t.Fatalf("refresh schedule delay=%v next=%s, want disabled", res.RefreshDelay, res.NextRefreshAt)
	}
}

func TestIMSRegistrationMaintenanceReportsUpdatedRefreshSchedule(t *testing.T) {
	base := time.Date(2026, 7, 7, 8, 0, 0, 0, time.UTC)
	m := &imsRegistrationMaintenance{
		session: voiceclient.RegisterSession{Expires: 3600},
		config:  WireIMSRegistrar{RefreshLead: time.Minute},
		profile: voiceclient.IMSProfile{
			Domain: "ims.example",
		},
		registered:   true,
		statusCode:   200,
		reason:       "OK",
		registeredAt: base,
		binding: voiceclient.RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
			Expires:        900,
		},
	}
	res := m.result("registered")
	if got, want := res.ExpiresAt.Sub(res.RegisteredAt), 15*time.Minute; got != want {
		t.Fatalf("ExpiresAt-RegisteredAt=%v, want %v", got, want)
	}
	if res.RefreshDelay != 14*time.Minute {
		t.Fatalf("RefreshDelay=%v, want 14m", res.RefreshDelay)
	}
	if got, want := res.NextRefreshAt, base.Add(14*time.Minute); !got.Equal(want) {
		t.Fatalf("NextRefreshAt=%s, want %s", got, want)
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

func TestWireIMSRegistrarPassesSecurityPlanInstallerRequest(t *testing.T) {
	rawNonce := append(runtimeBytesFrom(0x10, 16), runtimeBytesFrom(0x40, 16)...)
	transport := &wireIMSRegistrarTransport{responses: []voiceclient.RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`},
				"Security-Server":  {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=301;spi-s=302;port-c=5062;port-s=5063;q=0.7`},
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
	installer := &wireIMSRegistrarSecurityInstaller{}
	res, err := WireIMSRegistrar{
		Transport:             transport,
		ContactHost:           "192.0.2.10",
		ContactPort:           5060,
		ServerAddr:            "198.51.100.10:5060",
		CNonce:                "cnonce",
		SecurityPlanInstaller: installer,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-1",
		TraceID:  "trace-1",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
		SIM:      &wireIMSRegistrarSIM{},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	if !res.Registered || len(transport.requests) != 2 {
		t.Fatalf("result=%+v requests=%d", res, len(transport.requests))
	}
	if len(installer.requests) != 1 || len(installer.legacyCalls) != 0 {
		t.Fatalf("installer requests=%+v legacy=%+v", installer.requests, installer.legacyCalls)
	}
	req := installer.requests[0]
	if req.Plan.SPIClient != 301 || req.Plan.SPIServer != 302 || req.SelectedParameters["q"] != "0.7" {
		t.Fatalf("install request plan=%+v selected=%+v", req.Plan, req.SelectedParameters)
	}
	if req.LocalEndpoint.Address != "192.0.2.10" || req.LocalEndpoint.Port != 5062 ||
		req.RemoteEndpoint.Address != "198.51.100.10" || req.RemoteEndpoint.Port != 5063 {
		t.Fatalf("install request endpoints local=%+v remote=%+v", req.LocalEndpoint, req.RemoteEndpoint)
	}
	if hex.EncodeToString(req.AKA.CK) != hex.EncodeToString(runtimeBytesFrom(0xA0, 16)) ||
		hex.EncodeToString(req.AKA.IK) != hex.EncodeToString(runtimeBytesFrom(0xB0, 16)) {
		t.Fatalf("install request AKA CK=%x IK=%x", req.AKA.CK, req.AKA.IK)
	}
}

func TestWireIMSRegistrarUsesTunnelInnerIPForContact(t *testing.T) {
	transport := &wireIMSRegistrarTransport{responses: []voiceclient.RegisterResponse{{
		StatusCode: 200,
		Reason:     "OK",
		Headers: map[string][]string{
			"P-Associated-URI": {"<sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org>"},
		},
	}}}
	res, err := WireIMSRegistrar{
		Transport:   transport,
		ContactPort: 5064,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-1",
		TraceID:  "trace-1",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
		Tunnel:   swu.TunnelResult{LocalInnerIP: "10.0.0.2"},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	if !res.Registered || res.Profile.LocalIP != "10.0.0.2" {
		t.Fatalf("result=%+v", res)
	}
	if len(transport.requests) != 1 {
		t.Fatalf("requests=%d", len(transport.requests))
	}
	contact := transport.requests[0].Headers["Contact"]
	if !strings.Contains(contact, "<sip:310280233641503@10.0.0.2:5064>") {
		t.Fatalf("Contact=%q", contact)
	}
}

func TestWireIMSRegistrarProfileFromPreparedCarrierFallbacks(t *testing.T) {
	tests := []struct {
		name     string
		prepared identity.PreparedSession
		wantIMPI string
	}{
		{
			name: "effective carrier",
			prepared: identity.PreparedSession{
				Profile:          identity.Profile{IMSI: "001010123456789"},
				EffectiveCarrier: identity.EffectiveCarrier{MCC: "001", MNC: "010"},
			},
			wantIMPI: "001010123456789@ims.mnc010.mcc001.3gppnetwork.org",
		},
		{
			name: "prepared IMSI",
			prepared: identity.PreparedSession{
				Profile: identity.Profile{IMSI: "310280233641503"},
			},
			wantIMPI: "310280233641503@ims.mnc280.mcc310.3gppnetwork.org",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := WireIMSRegistrar{}.profileFromConfig(IMSRegistrationConfig{Prepared: &tc.prepared})
			if err != nil {
				t.Fatalf("profileFromConfig() error = %v", err)
			}
			if profile.IMPI != tc.wantIMPI || profile.IMPU != "sip:"+tc.wantIMPI {
				t.Fatalf("profile identities=%+v, want IMPI=%q", profile, tc.wantIMPI)
			}
			if profile.Domain == "" {
				t.Fatalf("profile domain empty: %+v", profile)
			}
		})
	}
}

func TestWireIMSRegistrarDefaultResolverUsesTunnelDNS(t *testing.T) {
	dnsServers := []string{"10.0.0.53", "2001:db8::53"}
	flow := WireIMSRegistrar{Timeout: 2 * time.Second}.defaultSIPFlow(IMSRegistrationConfig{
		Tunnel: swu.TunnelResult{DNSServers: dnsServers},
	})
	dnsServers[0] = "198.51.100.53"
	resolver, ok := flow.Resolver.(voiceclient.NetSIPResolver)
	if !ok {
		t.Fatalf("resolver=%T, want NetSIPResolver", flow.Resolver)
	}
	if len(resolver.DNSServers) != 2 || resolver.DNSServers[0] != "10.0.0.53" || resolver.DNSServers[1] != "2001:db8::53" || resolver.Timeout != 2*time.Second {
		t.Fatalf("resolver=%+v", resolver)
	}
	custom := voiceclient.SIPServerResolverFunc(func(context.Context, string, string) (string, error) {
		return "127.0.0.1:5060", nil
	})
	customFlow := WireIMSRegistrar{Resolver: custom}.defaultSIPFlow(IMSRegistrationConfig{
		Tunnel: swu.TunnelResult{DNSServers: []string{"10.0.0.53"}},
	})
	if customFlow.Resolver == nil {
		t.Fatal("custom resolver not retained")
	}
	if _, ok := customFlow.Resolver.(voiceclient.NetSIPResolver); ok {
		t.Fatalf("custom resolver was overwritten: %T", customFlow.Resolver)
	}
}

func TestWireIMSRegistrarUsesPreparedPCSCFFallbackCandidates(t *testing.T) {
	first, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(first) error = %v", err)
	}
	defer first.Close()
	second, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(second) error = %v", err)
	}
	defer second.Close()

	readOne := func(pc net.PacketConn, response string, ch chan<- string) {
		buf := make([]byte, 65535)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			ch <- "read error: " + err.Error()
			return
		}
		wire := string(append([]byte(nil), buf[:n]...))
		_, _ = pc.WriteTo([]byte(response), addr)
		ch <- wire
	}
	firstSeen := make(chan string, 1)
	secondSeen := make(chan string, 1)
	go readOne(first, "SIP/2.0 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n", firstSeen)
	go readOne(second, "SIP/2.0 200 OK\r\nP-Associated-URI: <sip:user@ims.example>\r\nContact: <sip:user@192.0.2.10:5060>;expires=600\r\nContent-Length: 0\r\n\r\n", secondSeen)

	res, err := WireIMSRegistrar{
		ContactHost:           "192.0.2.10",
		ContactPort:           5060,
		Timeout:               time.Second,
		MaxRetransmits:        1,
		RetransmitInterval:    20 * time.Millisecond,
		MaxRetransmitInterval: 20 * time.Millisecond,
		DisableRefresh:        true,
		DisableKeepalive:      true,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-prepared-pcscf",
		TraceID:  "trace-prepared-pcscf",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
		Prepared: &identity.PreparedSession{
			Profile:    identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
			PCSCFFQDNs: []string{first.LocalAddr().String(), second.LocalAddr().String()},
			IMSIdentity: identity.IMSIdentityResolution{
				IMPI:   "impi@example",
				IMPU:   "sip:user@ims.example",
				Domain: "ims.example",
			},
		},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	if !res.Registered || res.StatusCode != 200 {
		t.Fatalf("result=%+v", res)
	}
	if flow, ok := res.VoiceTransport.(*voiceclient.WireSIPFlow); ok {
		defer flow.Close()
	}

	firstWire := waitWire(t, firstSeen)
	secondWire := waitWire(t, secondSeen)
	if !strings.Contains(firstWire, "REGISTER sip:ims.example SIP/2.0") ||
		!strings.Contains(firstWire, "Call-ID: trace-prepared-pcscf\r\n") {
		t.Fatalf("first P-CSCF wire=%q", firstWire)
	}
	if !strings.Contains(secondWire, "REGISTER sip:ims.example SIP/2.0") ||
		!strings.Contains(secondWire, "Call-ID: trace-prepared-pcscf\r\n") {
		t.Fatalf("second P-CSCF wire=%q", secondWire)
	}
}

func TestWireIMSRegistrarDefaultFlowReusesRegisterSocketForSMS(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	type seenRequest struct {
		addr string
		wire string
	}
	seen := make(chan []seenRequest, 1)
	go func() {
		var requests []seenRequest
		buf := make([]byte, 65535)
		for i := 0; i < 2; i++ {
			_ = pc.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				seen <- append(requests, seenRequest{wire: "read error: " + err.Error()})
				return
			}
			wire := string(append([]byte(nil), buf[:n]...))
			requests = append(requests, seenRequest{addr: addr.String(), wire: wire})
			resp := "SIP/2.0 200 OK\r\n" +
				"P-Associated-URI: <sip:310280233641503@ims.mnc280.mcc310.3gppnetwork.org>\r\n" +
				"Service-Route: <sip:pcscf.example;lr>\r\n" +
				"Content-Length: 0\r\n\r\n"
			if i == 1 {
				resp = "SIP/2.0 202 Accepted\r\nContent-Length: 0\r\n\r\n"
			}
			_, _ = pc.WriteTo([]byte(resp), addr)
		}
		seen <- requests
	}()

	res, err := WireIMSRegistrar{
		ServerAddr:       pc.LocalAddr().String(),
		ContactHost:      "192.0.2.10",
		ContactPort:      5060,
		Timeout:          time.Second,
		MaxRetransmits:   1,
		DisableRefresh:   true,
		DisableKeepalive: true,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-1",
		TraceID:  "trace-1",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	flow, ok := res.VoiceTransport.(*voiceclient.WireSIPFlow)
	if !ok {
		t.Fatalf("VoiceTransport=%T, want *WireSIPFlow", res.VoiceTransport)
	}
	defer flow.Close()
	smsResult, err := res.SMSTransport.SendSMSPart(context.Background(), messaging.SMSSendRequest{
		Peer:      "+18005551212",
		MessageID: "flow-sms",
		Part:      messaging.SMSPart{PartNo: 1, TotalParts: 1, Text: "hello"},
	})
	if err != nil || smsResult.State != "accepted" {
		t.Fatalf("SendSMSPart() result=%+v err=%v", smsResult, err)
	}
	requests := <-seen
	if len(requests) != 2 {
		t.Fatalf("requests=%d %+v", len(requests), requests)
	}
	if requests[0].addr == "" || requests[0].addr != requests[1].addr {
		t.Fatalf("REGISTER and MESSAGE used different flows: %+v", requests)
	}
	if !strings.Contains(requests[0].wire, "REGISTER sip:ims.mnc280.mcc310.3gppnetwork.org SIP/2.0") ||
		!strings.Contains(requests[1].wire, "MESSAGE sip:+18005551212@ims.mnc280.mcc310.3gppnetwork.org SIP/2.0") {
		t.Fatalf("unexpected wires: %+v", requests)
	}
}

func TestWireIMSRegistrarRecoverReturnsUpdatedBinding(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	type seenRequest struct {
		addr string
		wire string
	}
	seen := make(chan []seenRequest, 1)
	go func() {
		var requests []seenRequest
		buf := make([]byte, 65535)
		registers := 0
		for i := 0; i < 3; i++ {
			_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				seen <- append(requests, seenRequest{wire: "read error: " + err.Error()})
				return
			}
			wire := string(append([]byte(nil), buf[:n]...))
			requests = append(requests, seenRequest{addr: addr.String(), wire: wire})
			registers++
			serviceRoute := "<sip:pcscf1.ims.example;lr>"
			if registers >= 2 {
				serviceRoute = "<sip:pcscf2.ims.example;lr>"
			}
			resp := "SIP/2.0 200 OK\r\n" +
				"P-Associated-URI: <sip:user@ims.example>\r\n" +
				"Service-Route: " + serviceRoute + "\r\n" +
				"Contact: <sip:user@192.0.2.10:5060>;expires=60\r\n" +
				"Content-Length: 0\r\n\r\n"
			_, _ = pc.WriteTo([]byte(resp), addr)
			if strings.Contains(wire, "Expires: 0\r\n") {
				seen <- requests
				return
			}
		}
		seen <- requests
	}()

	res, err := WireIMSRegistrar{
		ServerAddr:       pc.LocalAddr().String(),
		ContactHost:      "192.0.2.10",
		ContactPort:      5060,
		Expires:          60,
		Timeout:          time.Second,
		MaxRetransmits:   1,
		DisableRefresh:   true,
		DisableKeepalive: true,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-1",
		TraceID:  "trace-manual-recover",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	if res.Recover == nil {
		t.Fatal("Recover=nil, want default flow recovery hook")
	}
	recovered, err := res.Recover(context.Background())
	if err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if !recovered.Registered || recovered.StatusCode != 200 || recovered.VoiceTransport == nil || recovered.SMSTransport == nil || recovered.USSDTransport == nil {
		t.Fatalf("recovered result=%+v", recovered)
	}
	if len(recovered.Binding.ServiceRoutes) != 1 || recovered.Binding.ServiceRoutes[0] != "<sip:pcscf2.ims.example;lr>" {
		t.Fatalf("recovered service routes=%+v", recovered.Binding.ServiceRoutes)
	}
	if recovered.Recover == nil || recovered.Close == nil {
		t.Fatalf("recovered lifecycle hooks missing: close=%v recover=%v", recovered.Close != nil, recovered.Recover != nil)
	}
	if recovered.RecoveryState.Attempts != 1 || recovered.RecoveryState.ConsecutiveFailures != 0 ||
		recovered.RecoveryState.LastAttemptAt.IsZero() || recovered.RecoveryState.LastSucceededAt.IsZero() ||
		!recovered.RecoveryState.NextAttemptAt.IsZero() {
		t.Fatalf("recovered state=%+v", recovered.RecoveryState)
	}
	if err := recovered.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	requests := <-seen
	if len(requests) != 3 {
		t.Fatalf("requests=%d %+v", len(requests), requests)
	}
	if !strings.Contains(requests[1].wire, "Call-ID: trace-manual-recover-recovery-1\r\n") ||
		!strings.Contains(requests[1].wire, "CSeq: 1 REGISTER\r\n") {
		t.Fatalf("recovery REGISTER wire=%q", requests[1].wire)
	}
	if !strings.Contains(requests[2].wire, "Expires: 0\r\n") {
		t.Fatalf("deregister wire=%q", requests[2].wire)
	}
}

func TestWireIMSRegistrarRecoveryBackoffDelaysRepeatedRecover(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	type seenRequest struct {
		addr string
		wire string
	}
	seen := make(chan []seenRequest, 1)
	noImmediateRetry := make(chan bool, 1)
	go func() {
		var requests []seenRequest
		buf := make([]byte, 65535)
		for i := 0; i < 2; i++ {
			_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				seen <- append(requests, seenRequest{wire: "read error: " + err.Error()})
				return
			}
			wire := string(append([]byte(nil), buf[:n]...))
			requests = append(requests, seenRequest{addr: addr.String(), wire: wire})
			resp := "SIP/2.0 200 OK\r\n" +
				"P-Associated-URI: <sip:user@ims.example>\r\n" +
				"Contact: <sip:user@192.0.2.10:5060>;expires=600\r\n" +
				"Content-Length: 0\r\n\r\n"
			if i == 1 {
				resp = "SIP/2.0 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
			}
			_, _ = pc.WriteTo([]byte(resp), addr)
		}
		_ = pc.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			noImmediateRetry <- true
			seen <- requests
			return
		}
		requests = append(requests, seenRequest{addr: addr.String(), wire: string(append([]byte(nil), buf[:n]...))})
		noImmediateRetry <- false
		seen <- requests
	}()

	res, err := WireIMSRegistrar{
		ServerAddr:             pc.LocalAddr().String(),
		ContactHost:            "192.0.2.10",
		ContactPort:            5060,
		Expires:                600,
		DisableRefresh:         true,
		DisableKeepalive:       true,
		RecoveryBackoffInitial: 200 * time.Millisecond,
		RecoveryBackoffMax:     200 * time.Millisecond,
		Timeout:                time.Second,
		MaxRetransmits:         1,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-1",
		TraceID:  "trace-recovery-backoff",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	if _, err := res.Recover(context.Background()); err == nil {
		t.Fatal("first Recover() err=nil, want failed recovery")
	}
	retryCtx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := res.Recover(retryCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second Recover() err=%v, want context deadline from backoff wait", err)
	}
	select {
	case ok := <-noImmediateRetry:
		if !ok {
			t.Fatal("second recovery sent REGISTER before backoff elapsed")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for immediate retry check")
	}
	requests := <-seen
	if len(requests) != 2 {
		t.Fatalf("requests=%d %+v", len(requests), requests)
	}
	if !strings.Contains(requests[1].wire, "Call-ID: trace-recovery-backoff-recovery-1\r\n") {
		t.Fatalf("first recovery wire=%q", requests[1].wire)
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer closeCancel()
	_ = res.Close(closeCtx)
}

func TestIMSRegistrationRecoveryHonorsRetryAfterOnCurrentPCSCF(t *testing.T) {
	tests := []struct {
		name       string
		retryAfter time.Duration
		waitOK     bool
		wantErr    error
		wantWrites int
	}{
		{
			name:       "waits before retrying same target",
			retryAfter: 3 * time.Second,
			waitOK:     true,
			wantWrites: 1,
		},
		{
			name:       "keeps scheduled retry visible when wait is canceled",
			retryAfter: 4 * time.Second,
			waitOK:     false,
			wantErr:    context.Canceled,
			wantWrites: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var waits []time.Duration
			transport := &wireIMSRegistrarTransport{responses: []voiceclient.RegisterResponse{{
				StatusCode: 200,
				Reason:     "OK",
				Headers: map[string][]string{
					"P-Associated-URI": {"<sip:user@ims.example>"},
					"Contact":          {"<sip:user@192.0.2.10:5060>;expires=600"},
				},
			}}}
			session := voiceclient.RegisterSession{
				Transport:    transport,
				Profile:      voiceclient.IMSProfile{IMPI: "impi@example", IMPU: "sip:user@ims.example", Domain: "ims.example"},
				RegistrarURI: "sip:ims.example",
				ContactURI:   "sip:user@192.0.2.10:5060",
				CallID:       "trace-retry-after",
				Expires:      600,
			}
			m := newIMSRegistrationMaintenance(&voiceclient.WireSIPFlow{Network: "udp", ServerAddr: "127.0.0.1:9"}, session, voiceclient.RegisterResult{
				Registered: true,
				StatusCode: 200,
				Reason:     "OK",
				Binding: voiceclient.RegistrationBinding{
					ContactURI:     "sip:user@192.0.2.10:5060",
					PublicIdentity: "sip:user@ims.example",
					Expires:        600,
				},
				NextCSeq: 2,
			}, WireIMSRegistrar{
				DisableRefresh:   true,
				DisableKeepalive: true,
			}, IMSRegistrationConfig{}, voiceclient.IMSProfile{Domain: "ims.example"}, time.Date(2026, 7, 7, 8, 0, 0, 0, time.UTC))
			m.waitFunc = func(ctx context.Context, delay time.Duration) bool {
				waits = append(waits, delay)
				return tc.waitOK
			}
			defer m.flow.Close()

			err := m.recoverRegistration(context.Background(), errors.New("refresh 503 Service Unavailable"), tc.retryAfter)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("recoverRegistration() err=%v, want %v", err, tc.wantErr)
			}
			if len(waits) != 1 || waits[0] != tc.retryAfter {
				t.Fatalf("waits=%v, want [%v]", waits, tc.retryAfter)
			}
			if len(transport.requests) != tc.wantWrites {
				t.Fatalf("requests=%d %+v, want %d", len(transport.requests), transport.requests, tc.wantWrites)
			}
			state := m.result("retry-after recovery").RecoveryState
			if tc.waitOK {
				if state.Attempts != 1 || state.LastSwitchedTarget || state.LastSucceededAt.IsZero() || !state.NextAttemptAt.IsZero() {
					t.Fatalf("successful recovery state=%+v", state)
				}
				request := transport.requests[0]
				if request.Headers["Call-ID"] != "trace-retry-after-recovery-1" ||
					request.Headers["CSeq"] != "1 REGISTER" ||
					request.Headers["Expires"] != "600" {
					t.Fatalf("recovery REGISTER headers=%+v", request.Headers)
				}
				return
			}
			if state.NextAttemptAt.IsZero() || state.LastReason != "refresh 503 Service Unavailable" {
				t.Fatalf("canceled recovery state=%+v", state)
			}
		})
	}
}

func TestWireIMSRegistrarMaintainsDefaultFlowWithCRLFKeepalive(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	type seenRequest struct {
		addr string
		wire string
	}
	seen := make(chan []seenRequest, 1)
	keepaliveSeen := make(chan struct{}, 1)
	go func() {
		var requests []seenRequest
		buf := make([]byte, 65535)
		for i := 0; i < 5; i++ {
			_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				seen <- append(requests, seenRequest{wire: "read error: " + err.Error()})
				return
			}
			wire := string(append([]byte(nil), buf[:n]...))
			requests = append(requests, seenRequest{addr: addr.String(), wire: wire})
			if wire == "\r\n\r\n" {
				select {
				case keepaliveSeen <- struct{}{}:
				default:
				}
				continue
			}
			_, _ = pc.WriteTo([]byte("SIP/2.0 200 OK\r\nP-Associated-URI: <sip:user@ims.example>\r\nContent-Length: 0\r\n\r\n"), addr)
			if strings.Contains(wire, "Expires: 0\r\n") {
				seen <- requests
				return
			}
		}
		seen <- requests
	}()

	res, err := WireIMSRegistrar{
		ServerAddr:        pc.LocalAddr().String(),
		ContactHost:       "192.0.2.10",
		Timeout:           time.Second,
		MaxRetransmits:    1,
		DisableRefresh:    true,
		KeepaliveInterval: 50 * time.Millisecond,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-1",
		TraceID:  "trace-keepalive",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	if res.Close == nil {
		t.Fatal("Close=nil, want default flow cleanup")
	}
	select {
	case <-keepaliveSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for CRLF keepalive")
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := res.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	requests := <-seen
	if len(requests) < 3 {
		t.Fatalf("requests=%d %+v", len(requests), requests)
	}
	for i := range requests {
		if requests[i].addr == "" || requests[i].addr != requests[0].addr {
			t.Fatalf("REGISTER, keepalive, and deregister used different flows: %+v", requests)
		}
	}
	if !strings.Contains(requests[0].wire, "REGISTER sip:ims.mnc280.mcc310.3gppnetwork.org SIP/2.0") ||
		!strings.Contains(requests[0].wire, "CSeq: 1 REGISTER\r\n") {
		t.Fatalf("register wire=%q", requests[0].wire)
	}
	if requests[1].wire != "\r\n\r\n" {
		t.Fatalf("keepalive wire=%q", requests[1].wire)
	}
	last := requests[len(requests)-1]
	if !strings.Contains(last.wire, "Expires: 0\r\n") ||
		!strings.Contains(last.wire, "CSeq: 2 REGISTER\r\n") {
		t.Fatalf("deregister wire=%q", last.wire)
	}
}

func TestWireIMSRegistrarRefreshesRegistrationAndCloseUsesLatestCSeq(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	type seenRequest struct {
		addr string
		wire string
	}
	seen := make(chan []seenRequest, 1)
	refreshed := make(chan struct{}, 1)
	go func() {
		var requests []seenRequest
		buf := make([]byte, 65535)
		for i := 0; i < 6; i++ {
			_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				seen <- append(requests, seenRequest{wire: "read error: " + err.Error()})
				return
			}
			wire := string(append([]byte(nil), buf[:n]...))
			requests = append(requests, seenRequest{addr: addr.String(), wire: wire})
			resp := "SIP/2.0 200 OK\r\n" +
				"P-Associated-URI: <sip:user@ims.example>\r\n" +
				"Contact: <sip:user@192.0.2.10:5060>;expires=60\r\n" +
				"Content-Length: 0\r\n\r\n"
			_, _ = pc.WriteTo([]byte(resp), addr)
			if i == 1 {
				refreshed <- struct{}{}
			}
			if strings.Contains(wire, "Expires: 0\r\n") {
				seen <- requests
				return
			}
		}
		seen <- requests
	}()

	res, err := WireIMSRegistrar{
		ServerAddr:            pc.LocalAddr().String(),
		ContactHost:           "192.0.2.10",
		ContactPort:           5060,
		Expires:               60,
		RefreshInterval:       100 * time.Millisecond,
		RefreshRetryInterval:  100 * time.Millisecond,
		Timeout:               time.Second,
		MaxRetransmits:        1,
		RetransmitInterval:    20 * time.Millisecond,
		MaxRetransmitInterval: 20 * time.Millisecond,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-1",
		TraceID:  "trace-refresh",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	if res.Close == nil {
		t.Fatal("Close=nil, want default flow cleanup")
	}
	select {
	case <-refreshed:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for refresh REGISTER")
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := res.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	requests := <-seen
	if len(requests) < 3 {
		t.Fatalf("requests=%d %+v", len(requests), requests)
	}
	for i := range requests {
		if requests[i].addr == "" || requests[i].addr != requests[0].addr {
			t.Fatalf("REGISTER lifecycle used different flows: %+v", requests)
		}
		wantCSeq := "CSeq: " + strconv.Itoa(i+1) + " REGISTER\r\n"
		if !strings.Contains(requests[i].wire, wantCSeq) {
			t.Fatalf("request %d missing %q: %q", i, wantCSeq, requests[i].wire)
		}
	}
	if !strings.Contains(requests[0].wire, "Expires: 60\r\n") ||
		!strings.Contains(requests[1].wire, "Expires: 60\r\n") {
		t.Fatalf("register/refresh wires=%q\n%q", requests[0].wire, requests[1].wire)
	}
	last := requests[len(requests)-1]
	if !strings.Contains(last.wire, "Expires: 0\r\n") || !strings.Contains(last.wire, "expires=0") {
		t.Fatalf("deregister wire=%q", last.wire)
	}
}

func TestWireIMSRegistrarRecoversRegistrationAfterRefresh503(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	type seenRequest struct {
		addr string
		wire string
	}
	seen := make(chan []seenRequest, 1)
	recovered := make(chan struct{}, 1)
	go func() {
		var requests []seenRequest
		buf := make([]byte, 65535)
		registers := 0
		for i := 0; i < 6; i++ {
			_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				seen <- append(requests, seenRequest{wire: "read error: " + err.Error()})
				return
			}
			wire := string(append([]byte(nil), buf[:n]...))
			requests = append(requests, seenRequest{addr: addr.String(), wire: wire})
			if wire == "\r\n\r\n" {
				continue
			}
			registers++
			switch registers {
			case 2:
				_, _ = pc.WriteTo([]byte("SIP/2.0 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n"), addr)
			default:
				resp := "SIP/2.0 200 OK\r\n" +
					"P-Associated-URI: <sip:user@ims.example>\r\n" +
					"Contact: <sip:user@192.0.2.10:5060>;expires=60\r\n" +
					"Content-Length: 0\r\n\r\n"
				_, _ = pc.WriteTo([]byte(resp), addr)
				if registers == 3 {
					recovered <- struct{}{}
				}
				if strings.Contains(wire, "Expires: 0\r\n") {
					seen <- requests
					return
				}
			}
		}
		seen <- requests
	}()

	res, err := WireIMSRegistrar{
		ServerAddr:            pc.LocalAddr().String(),
		ContactHost:           "192.0.2.10",
		ContactPort:           5060,
		Expires:               60,
		RefreshInterval:       100 * time.Millisecond,
		RefreshRetryInterval:  100 * time.Millisecond,
		Timeout:               time.Second,
		MaxRetransmits:        1,
		RetransmitInterval:    20 * time.Millisecond,
		MaxRetransmitInterval: 20 * time.Millisecond,
		DisableKeepalive:      true,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-1",
		TraceID:  "trace-recover",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	if res.Close == nil {
		t.Fatal("Close=nil, want default flow cleanup")
	}
	select {
	case <-recovered:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for recovery REGISTER")
	}
	time.Sleep(20 * time.Millisecond)
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := res.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	requests := <-seen
	if len(requests) < 4 {
		t.Fatalf("requests=%d %+v", len(requests), requests)
	}
	if !strings.Contains(requests[0].wire, "Call-ID: trace-recover\r\n") ||
		!strings.Contains(requests[0].wire, "CSeq: 1 REGISTER\r\n") {
		t.Fatalf("initial REGISTER wire=%q", requests[0].wire)
	}
	if !strings.Contains(requests[1].wire, "Call-ID: trace-recover\r\n") ||
		!strings.Contains(requests[1].wire, "CSeq: 2 REGISTER\r\n") {
		t.Fatalf("refresh wire=%q", requests[1].wire)
	}
	if !strings.Contains(requests[2].wire, "Call-ID: trace-recover-recovery-1\r\n") ||
		!strings.Contains(requests[2].wire, "CSeq: 1 REGISTER\r\n") ||
		!strings.Contains(requests[2].wire, "Expires: 60\r\n") {
		t.Fatalf("recovery REGISTER wire=%q", requests[2].wire)
	}
	last := requests[len(requests)-1]
	if !strings.Contains(last.wire, "Call-ID: trace-recover-recovery-1\r\n") ||
		!strings.Contains(last.wire, "CSeq: 2 REGISTER\r\n") ||
		!strings.Contains(last.wire, "Expires: 0\r\n") {
		t.Fatalf("deregister wire=%q", last.wire)
	}
}

func TestWireIMSRegistrarRefreshFailsOverToNextPCSCF(t *testing.T) {
	first, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(first) error = %v", err)
	}
	defer first.Close()
	second, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(second) error = %v", err)
	}
	defer second.Close()

	type seenRequest struct {
		addr string
		wire string
	}
	firstSeen := make(chan []seenRequest, 1)
	go func() {
		var requests []seenRequest
		buf := make([]byte, 65535)
		for i := 0; i < 2; i++ {
			_ = first.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, err := first.ReadFrom(buf)
			if err != nil {
				firstSeen <- append(requests, seenRequest{wire: "read error: " + err.Error()})
				return
			}
			wire := string(append([]byte(nil), buf[:n]...))
			requests = append(requests, seenRequest{addr: addr.String(), wire: wire})
			if i == 0 {
				resp := "SIP/2.0 200 OK\r\n" +
					"P-Associated-URI: <sip:user@ims.example>\r\n" +
					"Contact: <sip:user@192.0.2.10:5060>;expires=60\r\n" +
					"Content-Length: 0\r\n\r\n"
				_, _ = first.WriteTo([]byte(resp), addr)
				continue
			}
			_, _ = first.WriteTo([]byte("SIP/2.0 503 Service Unavailable\r\nRetry-After: 30\r\nContent-Length: 0\r\n\r\n"), addr)
			firstSeen <- requests
			return
		}
		firstSeen <- requests
	}()

	secondSeen := make(chan []seenRequest, 1)
	refreshed := make(chan struct{}, 1)
	go func() {
		var requests []seenRequest
		buf := make([]byte, 65535)
		for i := 0; i < 4; i++ {
			_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, err := second.ReadFrom(buf)
			if err != nil {
				secondSeen <- append(requests, seenRequest{wire: "read error: " + err.Error()})
				return
			}
			wire := string(append([]byte(nil), buf[:n]...))
			requests = append(requests, seenRequest{addr: addr.String(), wire: wire})
			resp := "SIP/2.0 200 OK\r\n" +
				"P-Associated-URI: <sip:user@ims.example>\r\n" +
				"Contact: <sip:user@192.0.2.10:5060>;expires=60\r\n" +
				"Content-Length: 0\r\n\r\n"
			_, _ = second.WriteTo([]byte(resp), addr)
			if strings.Contains(wire, "Call-ID: trace-pcscf-failover\r\n") &&
				strings.Contains(wire, "CSeq: 2 REGISTER\r\n") {
				refreshed <- struct{}{}
			}
			if strings.Contains(wire, "Expires: 0\r\n") {
				secondSeen <- requests
				return
			}
		}
		secondSeen <- requests
	}()

	resolver := voiceclient.SIPServerCandidateResolverFunc(func(ctx context.Context, network, uri string) ([]string, error) {
		if network != "udp" || uri != "sip:ims.mnc280.mcc310.3gppnetwork.org" {
			t.Fatalf("resolver network=%q uri=%q", network, uri)
		}
		return []string{first.LocalAddr().String(), second.LocalAddr().String()}, nil
	})
	res, err := WireIMSRegistrar{
		Resolver:              resolver,
		ContactHost:           "192.0.2.10",
		ContactPort:           5060,
		Expires:               60,
		RefreshInterval:       60 * time.Millisecond,
		RefreshRetryInterval:  60 * time.Millisecond,
		Timeout:               time.Second,
		MaxRetransmits:        1,
		RetransmitInterval:    20 * time.Millisecond,
		MaxRetransmitInterval: 20 * time.Millisecond,
		DisableKeepalive:      true,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-pcscf-failover",
		TraceID:  "trace-pcscf-failover",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	select {
	case <-refreshed:
	case <-time.After(time.Second):
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = res.Close(closeCtx)
		t.Fatal("timed out waiting for refresh REGISTER on second P-CSCF")
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := res.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	firstRequests := <-firstSeen
	secondRequests := <-secondSeen
	if len(firstRequests) != 2 {
		t.Fatalf("first requests=%d %+v", len(firstRequests), firstRequests)
	}
	if !strings.Contains(firstRequests[0].wire, "Call-ID: trace-pcscf-failover\r\n") ||
		!strings.Contains(firstRequests[1].wire, "CSeq: 2 REGISTER\r\n") {
		t.Fatalf("first P-CSCF requests=%+v", firstRequests)
	}
	if len(secondRequests) < 1 ||
		!strings.Contains(secondRequests[0].wire, "Call-ID: trace-pcscf-failover\r\n") ||
		!strings.Contains(secondRequests[0].wire, "CSeq: 2 REGISTER\r\n") {
		t.Fatalf("second P-CSCF requests=%+v", secondRequests)
	}
	if strings.Contains(secondRequests[0].wire, "Expires: 0\r\n") {
		t.Fatalf("first second-P-CSCF request was deregister, want refresh REGISTER: %q", secondRequests[0].wire)
	}
}

func TestWireIMSRegistrarRefreshAndCloseAdvanceDigestNonceCount(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	rawNonce := append(runtimeBytesFrom(0x10, 16), runtimeBytesFrom(0x40, 16)...)
	challenge := `Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`
	type seenRequest struct {
		addr string
		wire string
	}
	seen := make(chan []seenRequest, 1)
	refreshed := make(chan struct{}, 1)
	go func() {
		var requests []seenRequest
		buf := make([]byte, 65535)
		for i := 0; i < 5; i++ {
			_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				seen <- append(requests, seenRequest{wire: "read error: " + err.Error()})
				return
			}
			wire := string(append([]byte(nil), buf[:n]...))
			requests = append(requests, seenRequest{addr: addr.String(), wire: wire})
			if i == 0 {
				resp := "SIP/2.0 401 Unauthorized\r\n" +
					"WWW-Authenticate: " + challenge + "\r\n" +
					"Security-Server: ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=101;spi-s=202;port-c=5062;port-s=5063\r\n" +
					"Content-Length: 0\r\n\r\n"
				_, _ = pc.WriteTo([]byte(resp), addr)
				continue
			}
			resp := "SIP/2.0 200 OK\r\n" +
				"P-Associated-URI: <sip:user@ims.example>\r\n" +
				"Contact: <sip:user@192.0.2.10:5060>;expires=60\r\n" +
				"Content-Length: 0\r\n\r\n"
			_, _ = pc.WriteTo([]byte(resp), addr)
			if i == 2 {
				refreshed <- struct{}{}
			}
			if strings.Contains(wire, "Expires: 0\r\n") {
				seen <- requests
				return
			}
		}
		seen <- requests
	}()

	res, err := WireIMSRegistrar{
		ServerAddr:            pc.LocalAddr().String(),
		ContactHost:           "192.0.2.10",
		ContactPort:           5060,
		Expires:               60,
		RefreshInterval:       100 * time.Millisecond,
		RefreshRetryInterval:  100 * time.Millisecond,
		Timeout:               time.Second,
		MaxRetransmits:        1,
		RetransmitInterval:    20 * time.Millisecond,
		MaxRetransmitInterval: 20 * time.Millisecond,
		DisableKeepalive:      true,
		CNonce:                "cnonce",
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-1",
		TraceID:  "trace-refresh-auth",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
		SIM:      &wireIMSRegistrarSIM{},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	if res.Close == nil {
		t.Fatal("Close=nil, want default flow cleanup")
	}
	select {
	case <-refreshed:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for authenticated refresh REGISTER")
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := res.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	requests := <-seen
	if len(requests) < 4 {
		t.Fatalf("requests=%d %+v", len(requests), requests)
	}
	for i := range requests {
		if requests[i].addr == "" || requests[i].addr != requests[0].addr {
			t.Fatalf("REGISTER lifecycle used different flows: %+v", requests)
		}
	}
	if strings.Contains(requests[0].wire, "Authorization:") {
		t.Fatalf("initial REGISTER unexpectedly authenticated: %q", requests[0].wire)
	}
	if !strings.Contains(requests[1].wire, "Authorization: Digest") || !strings.Contains(requests[1].wire, "nc=00000001") ||
		!strings.Contains(requests[1].wire, "CSeq: 2 REGISTER\r\n") {
		t.Fatalf("authenticated REGISTER wire=%q", requests[1].wire)
	}
	if !strings.Contains(requests[2].wire, "nc=00000002") || !strings.Contains(requests[2].wire, "CSeq: 3 REGISTER\r\n") ||
		!strings.Contains(requests[2].wire, "Expires: 60\r\n") {
		t.Fatalf("refresh wire=%q", requests[2].wire)
	}
	last := requests[len(requests)-1]
	if !strings.Contains(last.wire, "nc=00000003") || !strings.Contains(last.wire, "CSeq: 4 REGISTER\r\n") ||
		!strings.Contains(last.wire, "Expires: 0\r\n") {
		t.Fatalf("deregister wire=%q", last.wire)
	}
}

func TestWireIMSRegistrarCloseDeregistersDefaultFlow(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	type seenRequest struct {
		addr string
		wire string
	}
	seen := make(chan []seenRequest, 1)
	go func() {
		var requests []seenRequest
		buf := make([]byte, 65535)
		for i := 0; i < 2; i++ {
			_ = pc.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				seen <- append(requests, seenRequest{wire: "read error: " + err.Error()})
				return
			}
			requests = append(requests, seenRequest{addr: addr.String(), wire: string(append([]byte(nil), buf[:n]...))})
			_, _ = pc.WriteTo([]byte("SIP/2.0 200 OK\r\nP-Associated-URI: <sip:user@ims.example>\r\nContent-Length: 0\r\n\r\n"), addr)
		}
		seen <- requests
	}()

	res, err := WireIMSRegistrar{
		ServerAddr:     pc.LocalAddr().String(),
		ContactHost:    "192.0.2.10",
		Timeout:        time.Second,
		MaxRetransmits: 1,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-1",
		TraceID:  "trace-close",
		Profile:  identity.Profile{IMSI: "310280233641503", MCC: "310", MNC: "280"},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	if res.Close == nil {
		t.Fatal("Close=nil, want default flow cleanup")
	}
	if err := res.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	requests := <-seen
	if len(requests) != 2 {
		t.Fatalf("requests=%d %+v", len(requests), requests)
	}
	if requests[0].addr == "" || requests[0].addr != requests[1].addr {
		t.Fatalf("REGISTER and deregister used different flows: %+v", requests)
	}
	if !strings.Contains(requests[0].wire, "REGISTER sip:ims.mnc280.mcc310.3gppnetwork.org SIP/2.0") ||
		!strings.Contains(requests[0].wire, "Expires: 3600\r\n") {
		t.Fatalf("register wire=%q", requests[0].wire)
	}
	if !strings.Contains(requests[1].wire, "REGISTER sip:ims.mnc280.mcc310.3gppnetwork.org SIP/2.0") ||
		!strings.Contains(requests[1].wire, "Expires: 0\r\n") ||
		!strings.Contains(requests[1].wire, "expires=0") ||
		!strings.Contains(requests[1].wire, "CSeq: 2 REGISTER\r\n") {
		t.Fatalf("deregister wire=%q", requests[1].wire)
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

type wireIMSRegistrarSecurityInstaller struct {
	requests    []voiceclient.IMSSecurityAssociationInstallRequest
	legacyCalls []voiceclient.IMSSecurityAssociationPlan
}

func (i *wireIMSRegistrarSecurityInstaller) InstallSecurityPlan(ctx context.Context, plan voiceclient.IMSSecurityAssociationPlan) error {
	i.legacyCalls = append(i.legacyCalls, plan)
	return nil
}

func (i *wireIMSRegistrarSecurityInstaller) InstallSecurityPlanRequest(ctx context.Context, req voiceclient.IMSSecurityAssociationInstallRequest) error {
	req.AKA.CK = append([]byte(nil), req.AKA.CK...)
	req.AKA.IK = append([]byte(nil), req.AKA.IK...)
	if len(req.SelectedParameters) > 0 {
		selected := make(map[string]string, len(req.SelectedParameters))
		for k, v := range req.SelectedParameters {
			selected[k] = v
		}
		req.SelectedParameters = selected
	}
	i.requests = append(i.requests, req)
	return nil
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

func waitWire(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case wire := <-ch:
		return wire
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SIP wire")
	}
	return ""
}

func runtimeBytesFrom(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}
