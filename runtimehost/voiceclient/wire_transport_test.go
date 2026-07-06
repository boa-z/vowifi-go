package voiceclient

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseSIPResponseWithFoldedAndCompactHeaders(t *testing.T) {
	raw := strings.Join([]string{
		"SIP/2.0 200 OK",
		"P-Associated-URI: <sip:user@example>,",
		" <tel:+18005551212>",
		"k: path, sec-agree",
		"a: *;+g.3gpp.smsip",
		"e: gzip",
		"l: 5",
		"",
		"hello ignored",
	}, "\r\n")
	resp, err := ParseSIPResponse([]byte(raw))
	if err != nil {
		t.Fatalf("ParseSIPResponse() error = %v", err)
	}
	if resp.StatusCode != 200 || resp.Reason != "OK" || string(resp.Body) != "hello" {
		t.Fatalf("response=%+v body=%q", resp, resp.Body)
	}
	if got := resp.Headers["Supported"]; len(got) != 1 || got[0] != "path, sec-agree" {
		t.Fatalf("Supported=%+v", got)
	}
	if got := resp.Headers["Accept-Contact"]; len(got) != 1 || got[0] != "*;+g.3gpp.smsip" {
		t.Fatalf("Accept-Contact=%+v", got)
	}
	if got := resp.Headers["Content-Encoding"]; len(got) != 1 || got[0] != "gzip" {
		t.Fatalf("Content-Encoding=%+v", got)
	}
	binding := BuildRegistrationBinding(IMSProfile{}, "sip:user@192.0.2.10:5060", resp, 3600)
	if len(binding.AssociatedURIs) != 2 || binding.AssociatedURIs[0] != "sip:user@example" || binding.AssociatedURIs[1] != "tel:+18005551212" {
		t.Fatalf("binding=%+v", binding)
	}
}

func TestSIPRetryAfterDelayParsesDeltaSeconds(t *testing.T) {
	resp, err := ParseSIPResponse([]byte(strings.Join([]string{
		"SIP/2.0 503 Service Unavailable",
		"Retry-After: 2 (maintenance);duration=60",
		"Retry-After: 5",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")))
	if err != nil {
		t.Fatalf("ParseSIPResponse() error = %v", err)
	}
	if resp.RetryAfter != 5*time.Second || SIPResponseRetryAfter(resp) != 5*time.Second {
		t.Fatalf("RetryAfter=%v helper=%v, want 5s", resp.RetryAfter, SIPResponseRetryAfter(resp))
	}
	if got := SIPRetryAfterDelay(map[string][]string{"Retry-After": {"invalid", "3;duration=10"}}); got != 3*time.Second {
		t.Fatalf("SIPRetryAfterDelay()=%v, want 3s", got)
	}
}

func TestParseSIPResponseRejectsInvalidStatusCode(t *testing.T) {
	for _, status := range []string{"99", "700", "0200", "2xx"} {
		_, err := ParseSIPResponse([]byte(strings.Join([]string{
			"SIP/2.0 " + status + " Invalid",
			"Content-Length: 0",
			"",
			"",
		}, "\r\n")))
		if !errors.Is(err, ErrInvalidSIPMessage) {
			t.Fatalf("ParseSIPResponse(%s) error=%v, want ErrInvalidSIPMessage", status, err)
		}
	}
}

func TestParseSIPRequestAndBuildResponseWire(t *testing.T) {
	raw := strings.Join([]string{
		"INVITE sip:user@example SIP/2.0",
		"v: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-a",
		"t: <sip:user@example>",
		"f: <sip:caller@example>;tag=remote",
		"i: call-1",
		"CSeq: 7 INVITE",
		"s: hello",
		" world",
		"u: presence",
		"o: reg",
		"r: <sip:refer@example>",
		"b: <sip:referrer@example>",
		"d: no-fork",
		"j: *;audio",
		"x: 1800;refresher=uac",
		"l: 5",
		"",
		"abcde ignored",
	}, "\r\n")
	req, err := ParseSIPRequest([]byte(raw))
	if err != nil {
		t.Fatalf("ParseSIPRequest() error = %v", err)
	}
	if req.Method != "INVITE" || req.URI != "sip:user@example" || string(req.Body) != "abcde" {
		t.Fatalf("request=%+v body=%q", req, req.Body)
	}
	for name, want := range map[string]string{
		"Via":                 "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-a",
		"To":                  "<sip:user@example>",
		"From":                "<sip:caller@example>;tag=remote",
		"Call-ID":             "call-1",
		"Subject":             "hello world",
		"Allow-Events":        "presence",
		"Event":               "reg",
		"Refer-To":            "<sip:refer@example>",
		"Referred-By":         "<sip:referrer@example>",
		"Request-Disposition": "no-fork",
		"Reject-Contact":      "*;audio",
		"Session-Expires":     "1800;refresher=uac",
	} {
		if got := req.Headers[name]; len(got) != 1 || got[0] != want {
			t.Fatalf("%s=%+v, want %q", name, got, want)
		}
	}
	wire, err := BuildSIPResponseWire(req, 200, "OK", map[string]string{
		"Contact":      "<sip:user@192.0.2.10:5060>",
		"Content-Type": "application/sdp",
	}, []byte("answer"))
	if err != nil {
		t.Fatalf("BuildSIPResponseWire() error = %v", err)
	}
	text := string(wire)
	for _, want := range []string{
		"SIP/2.0 200 OK\r\n",
		"Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-a\r\n",
		"To: <sip:user@example>\r\n",
		"From: <sip:caller@example>;tag=remote\r\n",
		"Call-ID: call-1\r\n",
		"CSeq: 7 INVITE\r\n",
		"Contact: <sip:user@192.0.2.10:5060>\r\n",
		"Content-Length: 6\r\n\r\nanswer",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("response wire missing %q in %q", want, text)
		}
	}
}

func TestBuildSIPResponseWireRejectsInvalidStatusCode(t *testing.T) {
	req := SIPIncomingRequest{
		Method: "OPTIONS",
		URI:    "sip:user@example",
		Headers: map[string][]string{
			"Via":     {"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-a"},
			"To":      {"<sip:user@example>"},
			"From":    {"<sip:caller@example>;tag=remote"},
			"Call-ID": {"bad-status-builder"},
			"CSeq":    {"1 OPTIONS"},
		},
	}
	for _, status := range []int{99, 700} {
		_, err := BuildSIPResponseWire(req, status, "Invalid", nil, nil)
		if !errors.Is(err, ErrInvalidSIPMessage) {
			t.Fatalf("BuildSIPResponseWire(%d) error=%v, want ErrInvalidSIPMessage", status, err)
		}
	}
}

func TestParseSIPMessageRejectsInvalidContentLength(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		parse func([]byte) error
	}{
		{
			name: "request_short_body",
			raw: strings.Join([]string{
				"MESSAGE sip:user@example SIP/2.0",
				"Call-ID: short-request",
				"CSeq: 1 MESSAGE",
				"Content-Length: 5",
				"",
				"abc",
			}, "\r\n"),
			parse: func(raw []byte) error {
				_, err := ParseSIPRequest(raw)
				return err
			},
		},
		{
			name: "response_short_body",
			raw: strings.Join([]string{
				"SIP/2.0 200 OK",
				"Content-Length: 5",
				"",
				"abc",
			}, "\r\n"),
			parse: func(raw []byte) error {
				_, err := ParseSIPResponse(raw)
				return err
			},
		},
		{
			name: "request_negative_length",
			raw: strings.Join([]string{
				"OPTIONS sip:user@example SIP/2.0",
				"Call-ID: bad-length",
				"CSeq: 1 OPTIONS",
				"Content-Length: -1",
				"",
				"",
			}, "\r\n"),
			parse: func(raw []byte) error {
				_, err := ParseSIPRequest(raw)
				return err
			},
		},
		{
			name: "response_nonnumeric_length",
			raw: strings.Join([]string{
				"SIP/2.0 200 OK",
				"Content-Length: many",
				"",
				"",
			}, "\r\n"),
			parse: func(raw []byte) error {
				_, err := ParseSIPResponse(raw)
				return err
			},
		},
		{
			name: "request_conflicting_lengths",
			raw: strings.Join([]string{
				"MESSAGE sip:user@example SIP/2.0",
				"Call-ID: conflicting-length",
				"CSeq: 1 MESSAGE",
				"Content-Length: 5",
				"l: 3",
				"",
				"abcde",
			}, "\r\n"),
			parse: func(raw []byte) error {
				_, err := ParseSIPRequest(raw)
				return err
			},
		},
	}
	for _, tc := range tests {
		err := tc.parse([]byte(tc.raw))
		if !errors.Is(err, ErrInvalidSIPMessage) {
			t.Fatalf("%s error=%v, want ErrInvalidSIPMessage", tc.name, err)
		}
	}
}

func TestParseSIPMessageAllowsMatchingContentLength(t *testing.T) {
	resp, err := ParseSIPResponse([]byte(strings.Join([]string{
		"SIP/2.0 200 OK",
		"Content-Length: 5",
		"l: 5",
		"",
		"hello ignored",
	}, "\r\n")))
	if err != nil {
		t.Fatalf("ParseSIPResponse() error = %v", err)
	}
	if string(resp.Body) != "hello" {
		t.Fatalf("body=%q, want hello", resp.Body)
	}
}

func TestReadSIPStreamMessageSkipsCRLFKeepalive(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("\r\n\r\n\r\nSIP/2.0 200 OK\r\nContent-Length: 5\r\n\r\nreadytrailing"))
	raw, err := readSIPStreamMessage(reader)
	if err != nil {
		t.Fatalf("readSIPStreamMessage() error = %v", err)
	}
	resp, err := ParseSIPResponse(raw)
	if err != nil {
		t.Fatalf("ParseSIPResponse() error = %v raw=%q", err, raw)
	}
	if resp.StatusCode != 200 || string(resp.Body) != "ready" {
		t.Fatalf("response=%+v body=%q raw=%q", resp, resp.Body, raw)
	}
}

func TestReadSIPStreamMessageRejectsConflictingContentLength(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("SIP/2.0 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nabc"))
	_, err := readSIPStreamMessage(reader)
	if !errors.Is(err, ErrInvalidSIPMessage) {
		t.Fatalf("readSIPStreamMessage() error = %v, want ErrInvalidSIPMessage", err)
	}
}

func TestSIPURIAddrParsesHostPortAndIPv6(t *testing.T) {
	cases := map[string]string{
		"sip:ims.example":                  "ims.example:5060",
		"sip:user@ims.example:5070;lr":     "ims.example:5070",
		"sips:user@[2001:db8::1]:5071;lr":  "[2001:db8::1]:5071",
		"sip:user@[2001:db8::2];transport": "[2001:db8::2]:5060",
	}
	for uri, want := range cases {
		got, err := sipURIAddr(uri)
		if err != nil {
			t.Fatalf("sipURIAddr(%q) error = %v", uri, err)
		}
		if got != want {
			t.Fatalf("sipURIAddr(%q)=%q, want %q", uri, got, want)
		}
	}
}

func TestWireRegisterTransportIgnoresUDPKeepaliveBeforeResponse(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	requestCh := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			requestCh <- "read error: " + err.Error()
			return
		}
		requestCh <- string(append([]byte(nil), buf[:n]...))
		_, _ = pc.WriteTo([]byte("\r\n\r\n"), addr)
		_, _ = pc.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), addr)
	}()

	resp, err := WireRegisterTransport{
		Network:    "udp",
		ServerAddr: pc.LocalAddr().String(),
		Timeout:    time.Second,
	}.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "keepalive-register",
			"CSeq":         "1 REGISTER",
			"Max-Forwards": "70",
		},
	})
	if err != nil {
		t.Fatalf("RoundTripRegister() error = %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("response=%+v", resp)
	}
	if req := <-requestCh; !strings.Contains(req, "REGISTER sip:ims.example SIP/2.0") {
		t.Fatalf("REGISTER wire=%q", req)
	}
}

func TestWireRegisterTransportRoundTripRegisterOverUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	rawNonce := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	requests := make(chan []string, 1)
	go func() {
		var seen []string
		buf := make([]byte, 65535)
		for i := 0; i < 2; i++ {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				requests <- append(seen, "read error: "+err.Error())
				return
			}
			req := string(append([]byte(nil), buf[:n]...))
			seen = append(seen, req)
			var resp string
			if i == 0 {
				resp = "SIP/2.0 401 Unauthorized\r\n" +
					"WWW-Authenticate: Digest realm=\"ims.example\", nonce=\"" + base64.StdEncoding.EncodeToString(rawNonce) + "\", algorithm=AKAv1-MD5, qop=\"auth\"\r\n" +
					"Security-Server: ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=111;spi-s=222;port-c=5062;port-s=5063\r\n" +
					"Content-Length: 0\r\n\r\n"
			} else {
				resp = "SIP/2.0 200 OK\r\n" +
					"P-Associated-URI: <sip:user@example>\r\n" +
					"Service-Route: <sip:pcscf.example;lr>\r\n" +
					"Contact: <sip:user@192.0.2.10:5060>;expires=1800\r\n" +
					"Content-Length: 0\r\n\r\n"
			}
			_, _ = pc.WriteTo([]byte(resp), addr)
		}
		requests <- seen
	}()

	result, err := RegisterSession{
		Transport: WireRegisterTransport{
			Network:    "udp",
			ServerAddr: pc.LocalAddr().String(),
			Timeout:    time.Second,
		},
		AKAProvider:  &registerAKAProvider{},
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "wire-call",
		CNonce:       "wire-cnonce",
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !result.Registered || result.Binding.PublicIdentity != "sip:user@example" || len(result.Binding.ServiceRoutes) != 1 {
		t.Fatalf("result=%+v", result)
	}
	seen := <-requests
	if len(seen) != 2 {
		t.Fatalf("requests=%d %v", len(seen), seen)
	}
	if !strings.Contains(seen[0], "REGISTER sip:ims.example SIP/2.0\r\n") || !strings.Contains(seen[0], "Via: SIP/2.0/UDP") {
		t.Fatalf("first REGISTER wire=%q", seen[0])
	}
	if !strings.Contains(seen[1], "Authorization: Digest") || !strings.Contains(seen[1], "Security-Verify: ipsec-3gpp") {
		t.Fatalf("second REGISTER wire=%q", seen[1])
	}
}

func TestWireRegisterTransportRetransmitsUDPRegister(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	seen := make(chan []string, 1)
	go func() {
		var requests []string
		buf := make([]byte, 65535)
		for i := 0; i < 2; i++ {
			_ = pc.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				seen <- append(requests, "read error: "+err.Error())
				return
			}
			requests = append(requests, string(append([]byte(nil), buf[:n]...)))
			if i == 1 {
				_, _ = pc.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), addr)
			}
		}
		seen <- requests
	}()

	resp, err := WireRegisterTransport{
		Network:               "udp",
		ServerAddr:            pc.LocalAddr().String(),
		Timeout:               time.Second,
		RetransmitInterval:    20 * time.Millisecond,
		MaxRetransmitInterval: 20 * time.Millisecond,
		MaxRetransmits:        2,
	}.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "retransmit-register",
			"CSeq":         "1 REGISTER",
			"Max-Forwards": "70",
		},
	})
	if err != nil {
		t.Fatalf("RoundTripRegister() error = %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("response=%+v", resp)
	}
	requests := <-seen
	if len(requests) != 2 || !strings.Contains(requests[0], "REGISTER sip:ims.example") || requests[0] != requests[1] {
		t.Fatalf("requests=%d %v", len(requests), requests)
	}
}

func TestWireRegisterTransportWaitsForFinalAfterProvisional(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	serverErr := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			serverErr <- "read error: " + err.Error()
			return
		}
		req, err := ParseSIPRequest(buf[:n])
		if err != nil {
			serverErr <- "parse request error: " + err.Error()
			return
		}
		trying, err := BuildSIPResponseWire(req, 100, "Trying", nil, nil)
		if err != nil {
			serverErr <- "build trying error: " + err.Error()
			return
		}
		if _, err := pc.WriteTo(trying, addr); err != nil {
			serverErr <- "write trying error: " + err.Error()
			return
		}
		_ = pc.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
		n, _, err = pc.ReadFrom(buf)
		if err == nil {
			serverErr <- "unexpected retransmit after 100 Trying: " + string(append([]byte(nil), buf[:n]...))
			return
		}
		ok, err := BuildSIPResponseWire(req, 200, "OK", nil, nil)
		if err != nil {
			serverErr <- "build ok error: " + err.Error()
			return
		}
		if _, err := pc.WriteTo(ok, addr); err != nil {
			serverErr <- "write ok error: " + err.Error()
			return
		}
		serverErr <- ""
	}()

	resp, err := WireRegisterTransport{
		Network:               "udp",
		ServerAddr:            pc.LocalAddr().String(),
		Timeout:               time.Second,
		RetransmitInterval:    20 * time.Millisecond,
		MaxRetransmitInterval: 20 * time.Millisecond,
	}.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "provisional-register",
			"CSeq":         "1 REGISTER",
			"Max-Forwards": "70",
		},
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRegister() response=%+v err=%v", resp, err)
	}
	if msg := <-serverErr; msg != "" {
		t.Fatal(msg)
	}
}

func TestWireRegisterTransportIgnoresMismatchedUDPResponse(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 65535)
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := ParseSIPRequest(buf[:n])
		if err != nil {
			return
		}
		via := firstHeader(req.Headers, "Via")
		cseq := firstHeader(req.Headers, "CSeq")
		bad := strings.Join([]string{
			"SIP/2.0 503 Service Unavailable",
			"Via: " + via,
			"Call-ID: unrelated-register",
			"CSeq: " + cseq,
			"Content-Length: 0",
			"",
			"",
		}, "\r\n")
		good := strings.Join([]string{
			"SIP/2.0 200 OK",
			"Via: " + via,
			"Call-ID: " + firstHeader(req.Headers, "Call-ID"),
			"CSeq: " + cseq,
			"Content-Length: 0",
			"",
			"",
		}, "\r\n")
		_, _ = pc.WriteTo([]byte(bad), addr)
		_, _ = pc.WriteTo([]byte(good), addr)
	}()

	resp, err := WireRegisterTransport{
		Network:    "udp",
		ServerAddr: pc.LocalAddr().String(),
		Timeout:    time.Second,
	}.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "matched-register",
			"CSeq":         "1 REGISTER",
			"Max-Forwards": "70",
		},
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRegister() response=%+v err=%v", resp, err)
	}
}

func TestWireRegisterTransportFailsOverResolvedUDPTargets(t *testing.T) {
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(dead) error = %v", err)
	}
	defer dead.Close()
	live, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(live) error = %v", err)
	}
	defer live.Close()

	deadSeen := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = dead.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := dead.ReadFrom(buf)
		if err != nil {
			deadSeen <- "read error: " + err.Error()
			return
		}
		deadSeen <- string(append([]byte(nil), buf[:n]...))
	}()
	liveSeen := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = live.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := live.ReadFrom(buf)
		if err != nil {
			liveSeen <- "read error: " + err.Error()
			return
		}
		liveSeen <- string(append([]byte(nil), buf[:n]...))
		_, _ = live.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), addr)
	}()

	resolver := SIPServerCandidateResolverFunc(func(ctx context.Context, network, uri string) ([]string, error) {
		if network != "udp" || uri != "sip:ims.example" {
			t.Fatalf("resolver network=%q uri=%q", network, uri)
		}
		return []string{dead.LocalAddr().String(), live.LocalAddr().String()}, nil
	})
	resp, err := WireRegisterTransport{
		Network:               "udp",
		Resolver:              resolver,
		Timeout:               80 * time.Millisecond,
		RetransmitInterval:    20 * time.Millisecond,
		MaxRetransmitInterval: 20 * time.Millisecond,
		MaxRetransmits:        1,
	}.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "failover-register",
			"CSeq":         "1 REGISTER",
			"Max-Forwards": "70",
		},
	})
	if err != nil {
		t.Fatalf("RoundTripRegister() error = %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("response=%+v", resp)
	}
	if wire := <-deadSeen; !strings.Contains(wire, "REGISTER sip:ims.example") {
		t.Fatalf("dead target wire=%q", wire)
	}
	if wire := <-liveSeen; !strings.Contains(wire, "REGISTER sip:ims.example") {
		t.Fatalf("live target wire=%q", wire)
	}
}

func TestWireRegisterTransportFailsOverRecoverableResponse(t *testing.T) {
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

	firstSeen := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = first.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := first.ReadFrom(buf)
		if err != nil {
			firstSeen <- "read error: " + err.Error()
			return
		}
		firstSeen <- string(append([]byte(nil), buf[:n]...))
		_, _ = first.WriteTo([]byte("SIP/2.0 503 Service Unavailable\r\nRetry-After: 30\r\nContent-Length: 0\r\n\r\n"), addr)
	}()
	secondSeen := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = second.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := second.ReadFrom(buf)
		if err != nil {
			secondSeen <- "read error: " + err.Error()
			return
		}
		secondSeen <- string(append([]byte(nil), buf[:n]...))
		_, _ = second.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), addr)
	}()

	resp, err := WireRegisterTransport{
		Network: "udp",
		Resolver: SIPServerCandidateResolverFunc(func(ctx context.Context, network, uri string) ([]string, error) {
			return []string{first.LocalAddr().String(), second.LocalAddr().String()}, nil
		}),
		Timeout: time.Second,
	}.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "failover-response-register",
			"CSeq":         "1 REGISTER",
			"Max-Forwards": "70",
		},
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRegister() response=%+v err=%v", resp, err)
	}
	if wire := <-firstSeen; !strings.Contains(wire, "REGISTER sip:ims.example") {
		t.Fatalf("first target wire=%q", wire)
	}
	if wire := <-secondSeen; !strings.Contains(wire, "REGISTER sip:ims.example") {
		t.Fatalf("second target wire=%q", wire)
	}
}

func TestWireRegisterTransportFollowsRedirectContactTarget(t *testing.T) {
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

	firstSeen := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = first.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := first.ReadFrom(buf)
		if err != nil {
			firstSeen <- "read error: " + err.Error()
			return
		}
		firstSeen <- string(append([]byte(nil), buf[:n]...))
		_, _ = first.WriteTo([]byte("SIP/2.0 302 Moved Temporarily\r\nContact: <sip:pcscf@"+second.LocalAddr().String()+">\r\nContent-Length: 0\r\n\r\n"), addr)
	}()
	secondSeen := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = second.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := second.ReadFrom(buf)
		if err != nil {
			secondSeen <- "read error: " + err.Error()
			return
		}
		secondSeen <- string(append([]byte(nil), buf[:n]...))
		_, _ = second.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), addr)
	}()

	resp, err := WireRegisterTransport{
		Network:    "udp",
		ServerAddr: first.LocalAddr().String(),
		Timeout:    time.Second,
	}.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "register-redirect",
			"CSeq":         "1 REGISTER",
			"Max-Forwards": "70",
		},
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRegister() response=%+v err=%v", resp, err)
	}
	if wire := <-firstSeen; !strings.Contains(wire, "REGISTER sip:ims.example") {
		t.Fatalf("first target wire=%q", wire)
	}
	if wire := <-secondSeen; !strings.Contains(wire, "REGISTER sip:ims.example") {
		t.Fatalf("redirect target wire=%q", wire)
	}
}

func TestWireSIPTransportFailsOverRecoverableDialogResponse(t *testing.T) {
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

	firstSeen := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = first.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := first.ReadFrom(buf)
		if err != nil {
			firstSeen <- "read error: " + err.Error()
			return
		}
		firstSeen <- string(append([]byte(nil), buf[:n]...))
		_, _ = first.WriteTo([]byte("SIP/2.0 503 Service Unavailable\r\nRetry-After: 10\r\nContent-Length: 0\r\n\r\n"), addr)
	}()
	secondSeen := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = second.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := second.ReadFrom(buf)
		if err != nil {
			secondSeen <- "read error: " + err.Error()
			return
		}
		secondSeen <- string(append([]byte(nil), buf[:n]...))
		_, _ = second.WriteTo([]byte("SIP/2.0 202 Accepted\r\nContent-Length: 0\r\n\r\n"), addr)
	}()

	resp, err := WireSIPTransport{
		Network: "udp",
		Resolver: SIPServerCandidateResolverFunc(func(ctx context.Context, network, uri string) ([]string, error) {
			return []string{first.LocalAddr().String(), second.LocalAddr().String()}, nil
		}),
		Timeout: time.Second,
	}.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "MESSAGE",
		URI:    "sip:+18005551212@example",
		Headers: map[string]string{
			"To":           "<sip:+18005551212@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "failover-dialog-message",
			"CSeq":         "1 MESSAGE",
			"Max-Forwards": "70",
		},
		Body: []byte("hello"),
	})
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("RoundTripRequest() response=%+v err=%v", resp, err)
	}
	if wire := <-firstSeen; !strings.Contains(wire, "MESSAGE sip:+18005551212@example") {
		t.Fatalf("first target wire=%q", wire)
	}
	if wire := <-secondSeen; !strings.Contains(wire, "MESSAGE sip:+18005551212@example") {
		t.Fatalf("second target wire=%q", wire)
	}
}

func TestWireSIPTransportFollowsRedirectContactTarget(t *testing.T) {
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

	firstSeen := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = first.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := first.ReadFrom(buf)
		if err != nil {
			firstSeen <- "read error: " + err.Error()
			return
		}
		firstSeen <- string(append([]byte(nil), buf[:n]...))
		_, _ = first.WriteTo([]byte("SIP/2.0 380 Alternative Service\r\nContact: <sip:pcscf@"+second.LocalAddr().String()+";transport=udp>\r\nContent-Length: 0\r\n\r\n"), addr)
	}()
	secondSeen := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = second.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := second.ReadFrom(buf)
		if err != nil {
			secondSeen <- "read error: " + err.Error()
			return
		}
		secondSeen <- string(append([]byte(nil), buf[:n]...))
		_, _ = second.WriteTo([]byte("SIP/2.0 202 Accepted\r\nContent-Length: 0\r\n\r\n"), addr)
	}()

	resp, err := WireSIPTransport{
		Network:    "udp",
		ServerAddr: first.LocalAddr().String(),
		Timeout:    time.Second,
	}.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "MESSAGE",
		URI:    "sip:+18005551212@example",
		Headers: map[string]string{
			"To":           "<sip:+18005551212@example>",
			"From":         "<sip:user@example>;tag=sms",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "dialog-redirect",
			"CSeq":         "1 MESSAGE",
			"Max-Forwards": "70",
		},
		Body: []byte("hello"),
	})
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("RoundTripRequest() response=%+v err=%v", resp, err)
	}
	if wire := <-firstSeen; !strings.Contains(wire, "MESSAGE sip:+18005551212@example") {
		t.Fatalf("first target wire=%q", wire)
	}
	if wire := <-secondSeen; !strings.Contains(wire, "MESSAGE sip:+18005551212@example") {
		t.Fatalf("redirect target wire=%q", wire)
	}
}

func TestWireRegisterTransportRoundTripOverTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()
	requestCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			requestCh <- "accept error: " + err.Error()
			return
		}
		defer conn.Close()
		raw, err := readSIPStreamMessage(bufio.NewReader(conn))
		if err != nil {
			requestCh <- "read error: " + err.Error()
			return
		}
		requestCh <- string(raw)
		body := "ready"
		resp := "SIP/2.0 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
		_, _ = conn.Write([]byte(resp))
	}()

	resp, err := WireRegisterTransport{
		Network:    "tcp",
		ServerAddr: ln.Addr().String(),
		Timeout:    time.Second,
	}.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "tcp-call",
			"CSeq":         "1 REGISTER",
			"Max-Forwards": "70",
		},
	})
	if err != nil {
		t.Fatalf("RoundTripRegister() error = %v", err)
	}
	if resp.StatusCode != 200 || string(resp.Body) != "ready" {
		t.Fatalf("response=%+v body=%q", resp, resp.Body)
	}
	req := <-requestCh
	if !strings.Contains(req, "Via: SIP/2.0/TCP") || !strings.Contains(req, "Content-Length: 0") {
		t.Fatalf("TCP request=%q", req)
	}
}

func TestWireSIPTransportIgnoresUDPKeepaliveBeforeResponse(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 65535)
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		_, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo([]byte("\r\n\r\n"), addr)
		_, _ = pc.WriteTo([]byte("SIP/2.0 202 Accepted\r\nContent-Length: 0\r\n\r\n"), addr)
	}()

	resp, err := WireSIPTransport{
		Network:    "udp",
		ServerAddr: pc.LocalAddr().String(),
		Timeout:    time.Second,
	}.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "MESSAGE",
		URI:    "sip:callee@example",
		Headers: map[string]string{
			"To":           "<sip:callee@example>",
			"From":         "<sip:user@example>;tag=t",
			"Call-ID":      "keepalive-message",
			"CSeq":         "1 MESSAGE",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Max-Forwards": "70",
		},
	})
	if err != nil {
		t.Fatalf("RoundTripRequest() error = %v", err)
	}
	if resp.StatusCode != 202 {
		t.Fatalf("response=%+v", resp)
	}
}

func TestWireSIPTransportWaitsForNonInviteFinalAfterProvisional(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	serverErr := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			serverErr <- "read error: " + err.Error()
			return
		}
		req, err := ParseSIPRequest(buf[:n])
		if err != nil {
			serverErr <- "parse request error: " + err.Error()
			return
		}
		trying, err := BuildSIPResponseWire(req, 100, "Trying", nil, nil)
		if err != nil {
			serverErr <- "build trying error: " + err.Error()
			return
		}
		if _, err := pc.WriteTo(trying, addr); err != nil {
			serverErr <- "write trying error: " + err.Error()
			return
		}
		_ = pc.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
		n, _, err = pc.ReadFrom(buf)
		if err == nil {
			serverErr <- "unexpected retransmit after 100 Trying: " + string(append([]byte(nil), buf[:n]...))
			return
		}
		accepted, err := BuildSIPResponseWire(req, 202, "Accepted", nil, nil)
		if err != nil {
			serverErr <- "build accepted error: " + err.Error()
			return
		}
		if _, err := pc.WriteTo(accepted, addr); err != nil {
			serverErr <- "write accepted error: " + err.Error()
			return
		}
		serverErr <- ""
	}()

	resp, err := WireSIPTransport{
		Network:               "udp",
		ServerAddr:            pc.LocalAddr().String(),
		Timeout:               time.Second,
		RetransmitInterval:    20 * time.Millisecond,
		MaxRetransmitInterval: 20 * time.Millisecond,
	}.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "MESSAGE",
		URI:    "sip:callee@example",
		Headers: map[string]string{
			"To":           "<sip:callee@example>",
			"From":         "<sip:user@example>;tag=t",
			"Call-ID":      "provisional-message",
			"CSeq":         "1 MESSAGE",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Max-Forwards": "70",
		},
	})
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("RoundTripRequest() response=%+v err=%v", resp, err)
	}
	if msg := <-serverErr; msg != "" {
		t.Fatal(msg)
	}
}

func TestWireSIPTransportRetransmitsUDPInvite(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	seen := make(chan []string, 1)
	go func() {
		var requests []string
		buf := make([]byte, 65535)
		for i := 0; i < 2; i++ {
			_ = pc.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				seen <- append(requests, "read error: "+err.Error())
				return
			}
			requests = append(requests, string(append([]byte(nil), buf[:n]...)))
			if i == 1 {
				_, _ = pc.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), addr)
			}
		}
		seen <- requests
	}()

	resp, err := WireSIPTransport{
		Network:               "udp",
		ServerAddr:            pc.LocalAddr().String(),
		Timeout:               time.Second,
		RetransmitInterval:    20 * time.Millisecond,
		MaxRetransmitInterval: 20 * time.Millisecond,
		MaxRetransmits:        2,
	}.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "INVITE",
		URI:    "sip:callee@example",
		Headers: map[string]string{
			"To":           "<sip:callee@example>",
			"From":         "<sip:user@example>;tag=t",
			"Call-ID":      "retransmit-invite",
			"CSeq":         "1 INVITE",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Max-Forwards": "70",
		},
	})
	if err != nil {
		t.Fatalf("RoundTripRequest() error = %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("response=%+v", resp)
	}
	requests := <-seen
	if len(requests) != 2 || !strings.Contains(requests[0], "INVITE sip:callee@example") || requests[0] != requests[1] {
		t.Fatalf("requests=%d %v", len(requests), requests)
	}
}

func TestWireSIPTransportIgnoresMismatchedUDPResponse(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 65535)
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := ParseSIPRequest(buf[:n])
		if err != nil {
			return
		}
		via := firstHeader(req.Headers, "Via")
		cseq := firstHeader(req.Headers, "CSeq")
		bad := strings.Join([]string{
			"SIP/2.0 486 Busy Here",
			"Via: " + via,
			"Call-ID: unrelated-message",
			"CSeq: " + cseq,
			"Content-Length: 0",
			"",
			"",
		}, "\r\n")
		good := strings.Join([]string{
			"SIP/2.0 202 Accepted",
			"Via: " + via,
			"Call-ID: " + firstHeader(req.Headers, "Call-ID"),
			"CSeq: " + cseq,
			"Content-Length: 0",
			"",
			"",
		}, "\r\n")
		_, _ = pc.WriteTo([]byte(bad), addr)
		_, _ = pc.WriteTo([]byte(good), addr)
	}()

	resp, err := WireSIPTransport{
		Network:    "udp",
		ServerAddr: pc.LocalAddr().String(),
		Timeout:    time.Second,
	}.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "MESSAGE",
		URI:    "sip:callee@example",
		Headers: map[string]string{
			"To":           "<sip:callee@example>",
			"From":         "<sip:user@example>;tag=t",
			"Call-ID":      "matched-message",
			"CSeq":         "1 MESSAGE",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Max-Forwards": "70",
		},
	})
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("RoundTripRequest() response=%+v err=%v", resp, err)
	}
}

func TestWireSIPTransportStopsInviteRetransmitAfterProvisional(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	seen := make(chan []string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			seen <- []string{"read error: " + err.Error()}
			return
		}
		first := string(append([]byte(nil), buf[:n]...))
		_, _ = pc.WriteTo([]byte("SIP/2.0 180 Ringing\r\nContent-Length: 0\r\n\r\n"), addr)
		_ = pc.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
		n, _, err = pc.ReadFrom(buf)
		if err == nil {
			seen <- []string{first, "unexpected retransmit: " + string(append([]byte(nil), buf[:n]...))}
			return
		}
		_, _ = pc.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), addr)
		seen <- []string{first}
	}()

	resp, err := WireSIPTransport{
		Network:               "udp",
		ServerAddr:            pc.LocalAddr().String(),
		Timeout:               time.Second,
		RetransmitInterval:    20 * time.Millisecond,
		MaxRetransmitInterval: 20 * time.Millisecond,
	}.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "INVITE",
		URI:    "sip:callee@example",
		Headers: map[string]string{
			"To":           "<sip:callee@example>",
			"From":         "<sip:user@example>;tag=t",
			"Call-ID":      "provisional-invite",
			"CSeq":         "1 INVITE",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Max-Forwards": "70",
		},
	})
	if err != nil {
		t.Fatalf("RoundTripRequest() error = %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("response=%+v", resp)
	}
	requests := <-seen
	if len(requests) != 1 || !strings.Contains(requests[0], "INVITE sip:callee@example") {
		t.Fatalf("requests=%d %v", len(requests), requests)
	}
}

func TestWireSIPTransportReportsReliableProvisional(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 65535)
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		_, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo([]byte("SIP/2.0 183 Session Progress\r\nRequire: 100rel\r\nRSeq: 7\r\nContent-Length: 0\r\n\r\n"), addr)
		_, _ = pc.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), addr)
	}()

	var provisionals []SIPResponse
	resp, err := WireSIPTransport{
		Network:    "udp",
		ServerAddr: pc.LocalAddr().String(),
		Timeout:    time.Second,
	}.RoundTripInvite(context.Background(), SIPRequestMessage{
		Method: "INVITE",
		URI:    "sip:callee@example",
		Headers: map[string]string{
			"To":           "<sip:callee@example>",
			"From":         "<sip:user@example>;tag=t",
			"Call-ID":      "provisional-callback",
			"CSeq":         "1 INVITE",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Max-Forwards": "70",
		},
	}, func(ctx context.Context, req SIPRequestMessage, resp SIPResponse) error {
		provisionals = append(provisionals, resp)
		return nil
	})
	if err != nil {
		t.Fatalf("RoundTripInvite() error = %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("response=%+v", resp)
	}
	if len(provisionals) != 1 || provisionals[0].StatusCode != 183 || firstHeader(provisionals[0].Headers, "RSeq") != "7" {
		t.Fatalf("provisionals=%+v", provisionals)
	}
}

func TestWireSIPTransportWritesGeneratedViaBackToRequest(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	seen := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			seen <- "read error: " + err.Error()
			return
		}
		seen <- string(append([]byte(nil), buf[:n]...))
		_, _ = pc.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), addr)
	}()

	msg := SIPRequestMessage{
		Method: "INVITE",
		URI:    "sip:callee@example",
		Headers: map[string]string{
			"To":           "<sip:callee@example>",
			"From":         "<sip:user@example>;tag=t",
			"Call-ID":      "via-writeback",
			"CSeq":         "1 INVITE",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Max-Forwards": "70",
		},
	}
	resp, err := WireSIPTransport{
		Network:    "udp",
		ServerAddr: pc.LocalAddr().String(),
		Timeout:    time.Second,
	}.RoundTripInvite(context.Background(), msg, nil)
	if err != nil {
		t.Fatalf("RoundTripInvite() error = %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("response=%+v", resp)
	}
	wire := <-seen
	via := msg.Headers["Via"]
	if via == "" || !strings.Contains(via, ";branch=z9hG4bK") || !strings.Contains(wire, "Via: "+via+"\r\n") {
		t.Fatalf("Via writeback=%q wire=%q", via, wire)
	}
}

func TestWireSIPTransportInviteWaitsForFinalResponseAndWritesAck(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	requests := make(chan []string, 1)
	go func() {
		var seen []string
		buf := make([]byte, 65535)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			requests <- []string{"read invite error: " + err.Error()}
			return
		}
		seen = append(seen, string(append([]byte(nil), buf[:n]...)))
		_, _ = pc.WriteTo([]byte("SIP/2.0 180 Ringing\r\nContent-Length: 0\r\n\r\n"), addr)
		_, _ = pc.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Type: application/sdp\r\nContent-Length: 9\r\n\r\nanswer=ok"), addr)

		n, _, err = pc.ReadFrom(buf)
		if err != nil {
			requests <- append(seen, "read ack error: "+err.Error())
			return
		}
		seen = append(seen, string(append([]byte(nil), buf[:n]...)))
		requests <- seen
	}()

	transport := WireSIPTransport{Network: "udp", ServerAddr: pc.LocalAddr().String(), Timeout: time.Second}
	resp, err := transport.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "INVITE",
		URI:    "sip:callee@example",
		Headers: map[string]string{
			"To":           "<sip:callee@example>",
			"From":         "<sip:user@example>;tag=t",
			"Call-ID":      "call-1",
			"CSeq":         "1 INVITE",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Max-Forwards": "70",
		},
		Body: []byte("offer=ok"),
	})
	if err != nil {
		t.Fatalf("RoundTripRequest() error = %v", err)
	}
	if resp.StatusCode != 200 || string(resp.Body) != "answer=ok" {
		t.Fatalf("response=%+v body=%q", resp, resp.Body)
	}
	if err := transport.WriteRequest(context.Background(), SIPRequestMessage{
		Method: "ACK",
		URI:    "sip:callee@example",
		Headers: map[string]string{
			"To":           "<sip:callee@example>;tag=remote",
			"From":         "<sip:user@example>;tag=t",
			"Call-ID":      "call-1",
			"CSeq":         "1 ACK",
			"Max-Forwards": "70",
		},
	}); err != nil {
		t.Fatalf("WriteRequest() error = %v", err)
	}
	seen := <-requests
	if len(seen) != 2 {
		t.Fatalf("requests=%d %v", len(seen), seen)
	}
	if !strings.Contains(seen[0], "INVITE sip:callee@example SIP/2.0") || !strings.Contains(seen[0], "Content-Length: 8") {
		t.Fatalf("INVITE wire=%q", seen[0])
	}
	if !strings.Contains(seen[1], "ACK sip:callee@example SIP/2.0") || !strings.Contains(seen[1], "Via: SIP/2.0/UDP") {
		t.Fatalf("ACK wire=%q", seen[1])
	}
}
