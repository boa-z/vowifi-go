package voiceclient

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestWireSIPFlowReusesUDPFlowForRegisterAndDialog(t *testing.T) {
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
			requests = append(requests, seenRequest{
				addr: addr.String(),
				wire: string(append([]byte(nil), buf[:n]...)),
			})
			_, _ = pc.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), addr)
		}
		seen <- requests
	}()

	flow := &WireSIPFlow{Network: "udp", ServerAddr: pc.LocalAddr().String(), Timeout: time.Second}
	defer flow.Close()
	resp, err := flow.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-register",
			"CSeq":         "1 REGISTER",
			"Max-Forwards": "70",
		},
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRegister() response=%+v err=%v", resp, err)
	}
	resp, err = flow.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "MESSAGE",
		URI:    "sip:+18005551212@example",
		Headers: map[string]string{
			"To":           "<sip:+18005551212@example>",
			"From":         "<sip:user@example>;tag=sms",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-message",
			"CSeq":         "1 MESSAGE",
			"Max-Forwards": "70",
		},
		Body: []byte("hello"),
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRequest() response=%+v err=%v", resp, err)
	}
	requests := <-seen
	if len(requests) != 2 {
		t.Fatalf("requests=%d %+v", len(requests), requests)
	}
	if requests[0].addr == "" || requests[0].addr != requests[1].addr {
		t.Fatalf("flow used different local addresses: %+v", requests)
	}
	if !strings.Contains(requests[0].wire, "REGISTER sip:ims.example SIP/2.0") || !strings.Contains(requests[1].wire, "MESSAGE sip:+18005551212@example SIP/2.0") {
		t.Fatalf("unexpected wires: %+v", requests)
	}
}

func TestWireSIPFlowSendsCRLFKeepaliveOnEstablishedUDPFlow(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	seen := make(chan []string, 1)
	go func() {
		var requests []string
		buf := make([]byte, 65535)
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			seen <- []string{"read register error: " + err.Error()}
			return
		}
		requests = append(requests, string(append([]byte(nil), buf[:n]...)), addr.String())
		_, _ = pc.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), addr)
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, keepaliveAddr, err := pc.ReadFrom(buf)
		if err != nil {
			seen <- append(requests, "read keepalive error: "+err.Error())
			return
		}
		requests = append(requests, string(append([]byte(nil), buf[:n]...)), keepaliveAddr.String())
		seen <- requests
	}()

	flow := &WireSIPFlow{Network: "udp", ServerAddr: pc.LocalAddr().String(), Timeout: time.Second}
	defer flow.Close()
	resp, err := flow.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-keepalive",
			"CSeq":         "1 REGISTER",
			"Max-Forwards": "70",
		},
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRegister() response=%+v err=%v", resp, err)
	}
	if err := flow.SendCRLFKeepalive(context.Background()); err != nil {
		t.Fatalf("SendCRLFKeepalive() error = %v", err)
	}
	requests := <-seen
	if len(requests) != 4 {
		t.Fatalf("requests=%d %+v", len(requests), requests)
	}
	if requests[2] != "\r\n\r\n" || requests[1] != requests[3] {
		t.Fatalf("keepalive=%q addrs=%q/%q", requests[2], requests[1], requests[3])
	}
}

func TestWireSIPFlowUsesResolverForRegisterTarget(t *testing.T) {
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

	var resolvedNetwork, resolvedURI string
	flow := &WireSIPFlow{
		Network: "udp",
		Resolver: SIPServerResolverFunc(func(ctx context.Context, network, uri string) (string, error) {
			resolvedNetwork = network
			resolvedURI = uri
			return pc.LocalAddr().String(), nil
		}),
		Timeout: time.Second,
	}
	defer flow.Close()
	resp, err := flow.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-resolver",
			"CSeq":         "1 REGISTER",
			"Max-Forwards": "70",
		},
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRegister() response=%+v err=%v", resp, err)
	}
	if resolvedNetwork != "udp" || resolvedURI != "sip:ims.example" {
		t.Fatalf("resolver saw network=%q uri=%q", resolvedNetwork, resolvedURI)
	}
	if wire := <-seen; !strings.Contains(wire, "REGISTER sip:ims.example SIP/2.0") {
		t.Fatalf("wire=%q", wire)
	}
}

func TestWireSIPFlowFailsOverAndReusesResolvedTarget(t *testing.T) {
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
	type seenRequest struct {
		addr string
		wire string
	}
	liveSeen := make(chan []seenRequest, 1)
	go func() {
		var requests []seenRequest
		buf := make([]byte, 65535)
		for i := 0; i < 2; i++ {
			_ = live.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := live.ReadFrom(buf)
			if err != nil {
				liveSeen <- append(requests, seenRequest{wire: "read error: " + err.Error()})
				return
			}
			requests = append(requests, seenRequest{
				addr: addr.String(),
				wire: string(append([]byte(nil), buf[:n]...)),
			})
			_, _ = live.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), addr)
		}
		liveSeen <- requests
	}()

	resolverCalls := 0
	flow := &WireSIPFlow{
		Network: "udp",
		Resolver: SIPServerCandidateResolverFunc(func(ctx context.Context, network, uri string) ([]string, error) {
			resolverCalls++
			if network != "udp" || uri != "sip:ims.example" {
				t.Fatalf("resolver network=%q uri=%q", network, uri)
			}
			return []string{dead.LocalAddr().String(), live.LocalAddr().String()}, nil
		}),
		Timeout:               80 * time.Millisecond,
		RetransmitInterval:    20 * time.Millisecond,
		MaxRetransmitInterval: 20 * time.Millisecond,
		MaxRetransmits:        1,
	}
	defer flow.Close()
	resp, err := flow.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-failover-register",
			"CSeq":         "1 REGISTER",
			"Max-Forwards": "70",
		},
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRegister() response=%+v err=%v", resp, err)
	}
	resp, err = flow.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "MESSAGE",
		URI:    "sip:+18005551212@example",
		Headers: map[string]string{
			"To":           "<sip:+18005551212@example>",
			"From":         "<sip:user@example>;tag=sms",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-failover-message",
			"CSeq":         "1 MESSAGE",
			"Max-Forwards": "70",
		},
		Body: []byte("hello"),
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRequest() response=%+v err=%v", resp, err)
	}
	if wire := <-deadSeen; !strings.Contains(wire, "REGISTER sip:ims.example") {
		t.Fatalf("dead target wire=%q", wire)
	}
	requests := <-liveSeen
	if len(requests) != 2 {
		t.Fatalf("live requests=%d %+v", len(requests), requests)
	}
	if requests[0].addr == "" || requests[0].addr != requests[1].addr {
		t.Fatalf("flow did not reuse live target/local address: %+v", requests)
	}
	if !strings.Contains(requests[0].wire, "REGISTER sip:ims.example") ||
		!strings.Contains(requests[1].wire, "MESSAGE sip:+18005551212@example") {
		t.Fatalf("live wires=%+v", requests)
	}
	if resolverCalls != 1 {
		t.Fatalf("resolver calls=%d, want 1", resolverCalls)
	}
}

func TestWireSIPFlowRegisterFailsOverRecoverableResponse(t *testing.T) {
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

	resolverCalls := 0
	flow := &WireSIPFlow{
		Network: "udp",
		Resolver: SIPServerCandidateResolverFunc(func(ctx context.Context, network, uri string) ([]string, error) {
			resolverCalls++
			return []string{first.LocalAddr().String(), second.LocalAddr().String()}, nil
		}),
		Timeout: time.Second,
	}
	defer flow.Close()
	resp, err := flow.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-failover-response",
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
	if resolverCalls != 1 {
		t.Fatalf("resolver calls=%d, want 1", resolverCalls)
	}
}

func TestWireSIPFlowDialogFailsOverRecoverableResponse(t *testing.T) {
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
		_, _ = first.WriteTo([]byte("SIP/2.0 503 Service Unavailable\r\nRetry-After: 20\r\nContent-Length: 0\r\n\r\n"), addr)
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

	resolverCalls := 0
	flow := &WireSIPFlow{
		Network: "udp",
		Resolver: SIPServerCandidateResolverFunc(func(ctx context.Context, network, uri string) ([]string, error) {
			resolverCalls++
			return []string{first.LocalAddr().String(), second.LocalAddr().String()}, nil
		}),
		Timeout: time.Second,
	}
	defer flow.Close()
	resp, err := flow.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "MESSAGE",
		URI:    "sip:+18005551212@example",
		Headers: map[string]string{
			"To":           "<sip:+18005551212@example>",
			"From":         "<sip:user@example>;tag=sms",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-dialog-failover",
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
	if resolverCalls != 1 {
		t.Fatalf("resolver calls=%d, want 1", resolverCalls)
	}
}

func TestWireSIPFlowRegisterFollowsRedirectContactTarget(t *testing.T) {
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

	flow := &WireSIPFlow{Network: "udp", ServerAddr: first.LocalAddr().String(), Timeout: time.Second}
	defer flow.Close()
	resp, err := flow.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-register-redirect",
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
	if flow.target != second.LocalAddr().String() {
		t.Fatalf("flow target=%q, want redirect target %q", flow.target, second.LocalAddr().String())
	}
}

func TestWireSIPFlowDialogFollowsRedirectContactTarget(t *testing.T) {
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
		_, _ = first.WriteTo([]byte("SIP/2.0 302 Moved Temporarily\r\nContact: <sip:pcscf@"+second.LocalAddr().String()+";transport=udp>\r\nContent-Length: 0\r\n\r\n"), addr)
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

	flow := &WireSIPFlow{Network: "udp", ServerAddr: first.LocalAddr().String(), Timeout: time.Second}
	defer flow.Close()
	resp, err := flow.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "MESSAGE",
		URI:    "sip:+18005551212@example",
		Headers: map[string]string{
			"To":           "<sip:+18005551212@example>",
			"From":         "<sip:user@example>;tag=sms",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-dialog-redirect",
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

func TestWireSIPFlowWaitsForNonInviteFinalAfterProvisional(t *testing.T) {
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

	flow := &WireSIPFlow{
		Network:               "udp",
		ServerAddr:            pc.LocalAddr().String(),
		Timeout:               time.Second,
		RetransmitInterval:    20 * time.Millisecond,
		MaxRetransmitInterval: 20 * time.Millisecond,
	}
	defer flow.Close()
	resp, err := flow.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "MESSAGE",
		URI:    "sip:+18005551212@example",
		Headers: map[string]string{
			"To":           "<sip:+18005551212@example>",
			"From":         "<sip:user@example>;tag=sms",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-provisional-message",
			"CSeq":         "1 MESSAGE",
			"Max-Forwards": "70",
		},
		Body: []byte("hello"),
	})
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("RoundTripRequest() response=%+v err=%v", resp, err)
	}
	if msg := <-serverErr; msg != "" {
		t.Fatal(msg)
	}
}

func TestWireSIPFlowIgnoresStaleMatchedHeadersOnReusedUDPFlow(t *testing.T) {
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
		firstReq, err := ParseSIPRequest(buf[:n])
		if err != nil {
			return
		}
		firstOK := strings.Join([]string{
			"SIP/2.0 200 OK",
			"Via: " + firstHeader(firstReq.Headers, "Via"),
			"Call-ID: " + firstHeader(firstReq.Headers, "Call-ID"),
			"CSeq: " + firstHeader(firstReq.Headers, "CSeq"),
			"Content-Length: 0",
			"",
			"",
		}, "\r\n")
		_, _ = pc.WriteTo([]byte(firstOK), addr)

		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err = pc.ReadFrom(buf)
		if err != nil {
			return
		}
		secondReq, err := ParseSIPRequest(buf[:n])
		if err != nil {
			return
		}
		stale := strings.Join([]string{
			"SIP/2.0 486 Busy Here",
			"Via: " + firstHeader(firstReq.Headers, "Via"),
			"Call-ID: " + firstHeader(firstReq.Headers, "Call-ID"),
			"CSeq: " + firstHeader(firstReq.Headers, "CSeq"),
			"Content-Length: 0",
			"",
			"",
		}, "\r\n")
		matched := strings.Join([]string{
			"SIP/2.0 202 Accepted",
			"Via: " + firstHeader(secondReq.Headers, "Via"),
			"Call-ID: " + firstHeader(secondReq.Headers, "Call-ID"),
			"CSeq: " + firstHeader(secondReq.Headers, "CSeq"),
			"Content-Length: 0",
			"",
			"",
		}, "\r\n")
		_, _ = pc.WriteTo([]byte(stale), addr)
		_, _ = pc.WriteTo([]byte(matched), addr)
	}()

	flow := &WireSIPFlow{Network: "udp", ServerAddr: pc.LocalAddr().String(), Timeout: time.Second}
	defer flow.Close()
	resp, err := flow.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-stale-register",
			"CSeq":         "1 REGISTER",
			"Max-Forwards": "70",
		},
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRegister() response=%+v err=%v", resp, err)
	}
	resp, err = flow.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "MESSAGE",
		URI:    "sip:+18005551212@example",
		Headers: map[string]string{
			"To":           "<sip:+18005551212@example>",
			"From":         "<sip:user@example>;tag=sms",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-stale-message",
			"CSeq":         "1 MESSAGE",
			"Max-Forwards": "70",
		},
		Body: []byte("hello"),
	})
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("RoundTripRequest() response=%+v err=%v", resp, err)
	}
}

func TestWireSIPFlowResetToNextTargetPreservesCandidates(t *testing.T) {
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
		_, _ = first.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), addr)
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

	resolverCalls := 0
	flow := &WireSIPFlow{
		Network: "udp",
		Resolver: SIPServerCandidateResolverFunc(func(ctx context.Context, network, uri string) ([]string, error) {
			resolverCalls++
			return []string{first.LocalAddr().String(), second.LocalAddr().String()}, nil
		}),
		Timeout: time.Second,
	}
	defer flow.Close()
	if resp, err := flow.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-reset-target",
			"CSeq":         "1 REGISTER",
			"Max-Forwards": "70",
		},
	}); err != nil || resp.StatusCode != 200 {
		t.Fatalf("first RoundTripRegister() response=%+v err=%v", resp, err)
	}
	switched, err := flow.ResetToNextTarget()
	if err != nil || !switched {
		t.Fatalf("ResetToNextTarget() switched=%t err=%v, want switched", switched, err)
	}
	if resp, err := flow.RoundTripRegister(context.Background(), RegisterMessage{
		URI: "sip:ims.example",
		Headers: map[string]string{
			"To":           "<sip:user@example>",
			"From":         "<sip:user@example>;tag=t",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-reset-target",
			"CSeq":         "2 REGISTER",
			"Max-Forwards": "70",
		},
	}); err != nil || resp.StatusCode != 200 {
		t.Fatalf("second RoundTripRegister() response=%+v err=%v", resp, err)
	}
	if wire := <-firstSeen; !strings.Contains(wire, "CSeq: 1 REGISTER") {
		t.Fatalf("first target wire=%q", wire)
	}
	if wire := <-secondSeen; !strings.Contains(wire, "CSeq: 2 REGISTER") {
		t.Fatalf("second target wire=%q", wire)
	}
	if resolverCalls != 1 {
		t.Fatalf("resolver calls=%d, want 1", resolverCalls)
	}
}
