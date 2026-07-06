package voiceclient

import (
	"bufio"
	"context"
	"errors"
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

func TestWireSIPFlowFailsOverTCPResetAndReusesResolvedTarget(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(first) error = %v", err)
	}
	defer first.Close()
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(second) error = %v", err)
	}
	defer second.Close()

	firstSeen := make(chan string, 1)
	go func() {
		conn, err := first.Accept()
		if err != nil {
			firstSeen <- "accept error: " + err.Error()
			return
		}
		raw, err := readSIPStreamMessage(bufio.NewReader(conn))
		if err != nil {
			firstSeen <- "read error: " + err.Error()
			_ = conn.Close()
			return
		}
		firstSeen <- string(raw)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = conn.Close()
	}()
	secondSeen := make(chan []string, 1)
	go func() {
		conn, err := second.Accept()
		if err != nil {
			secondSeen <- []string{"accept error: " + err.Error()}
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		var requests []string
		for i := 0; i < 2; i++ {
			raw, err := readSIPStreamMessage(reader)
			if err != nil {
				secondSeen <- append(requests, "read error: "+err.Error())
				return
			}
			requests = append(requests, string(raw))
			status := "SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"
			if i == 1 {
				status = "SIP/2.0 202 Accepted\r\nContent-Length: 0\r\n\r\n"
			}
			_, _ = conn.Write([]byte(status))
		}
		secondSeen <- requests
	}()

	resolverCalls := 0
	flow := &WireSIPFlow{
		Network: "tcp",
		Resolver: SIPServerCandidateResolverFunc(func(ctx context.Context, network, uri string) ([]string, error) {
			resolverCalls++
			return []string{first.Addr().String(), second.Addr().String()}, nil
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
			"Call-ID":      "flow-tcp-reset-register",
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
			"Call-ID":      "flow-tcp-reset-message",
			"CSeq":         "1 MESSAGE",
			"Max-Forwards": "70",
		},
		Body: []byte("hello"),
	})
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("RoundTripRequest() response=%+v err=%v", resp, err)
	}
	if wire := <-firstSeen; !strings.Contains(wire, "REGISTER sip:ims.example") {
		t.Fatalf("first target wire=%q", wire)
	}
	requests := <-secondSeen
	if len(requests) != 2 ||
		!strings.Contains(requests[0], "REGISTER sip:ims.example") ||
		!strings.Contains(requests[1], "MESSAGE sip:+18005551212@example") {
		t.Fatalf("second target requests=%+v", requests)
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

func TestWireSIPFlowFinalResponseTimeoutAfterProvisionalDoesNotFailOver(t *testing.T) {
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
		requestWire := string(append([]byte(nil), buf[:n]...))
		req, err := ParseSIPRequest(buf[:n])
		if err != nil {
			firstSeen <- "parse request error: " + err.Error()
			return
		}
		trying, err := BuildSIPResponseWire(req, 100, "Trying", nil, nil)
		if err != nil {
			firstSeen <- "build trying error: " + err.Error()
			return
		}
		if _, err := first.WriteTo(trying, addr); err != nil {
			firstSeen <- "write trying error: " + err.Error()
			return
		}
		_ = first.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
		n, _, err = first.ReadFrom(buf)
		if err == nil {
			firstSeen <- "unexpected retransmit after 100 Trying: " + string(append([]byte(nil), buf[:n]...))
			return
		}
		firstSeen <- requestWire
	}()

	secondSeen := make(chan string, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = second.SetReadDeadline(time.Now().Add(380 * time.Millisecond))
		n, _, err := second.ReadFrom(buf)
		if err != nil {
			secondSeen <- ""
			return
		}
		secondSeen <- string(append([]byte(nil), buf[:n]...))
	}()

	resolverCalls := 0
	flow := &WireSIPFlow{
		Network: "udp",
		Resolver: SIPServerCandidateResolverFunc(func(ctx context.Context, network, uri string) ([]string, error) {
			resolverCalls++
			return []string{first.LocalAddr().String(), second.LocalAddr().String()}, nil
		}),
		Timeout:               250 * time.Millisecond,
		RetransmitInterval:    20 * time.Millisecond,
		MaxRetransmitInterval: 20 * time.Millisecond,
		MaxRetransmits:        1,
	}
	defer flow.Close()
	resp, err := flow.RoundTripRequest(context.Background(), SIPRequestMessage{
		Method: "MESSAGE",
		URI:    "sip:+18005551212@example",
		Headers: map[string]string{
			"To":           "<sip:+18005551212@example>",
			"From":         "<sip:user@example>;tag=sms",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-final-timeout-message",
			"CSeq":         "1 MESSAGE",
			"Max-Forwards": "70",
		},
		Body: []byte("hello"),
	})
	firstWire := <-firstSeen
	if err == nil || !errors.Is(err, ErrSIPFinalResponseTimeout) {
		t.Fatalf("RoundTripRequest() response=%+v err=%v, first=%q, want final response timeout", resp, err, firstWire)
	}
	if !strings.Contains(firstWire, "MESSAGE sip:+18005551212@example") {
		t.Fatalf("first target wire=%q", firstWire)
	}
	if wire := <-secondSeen; wire != "" {
		t.Fatalf("unexpected failover request to second target: %q", wire)
	}
	if resolverCalls != 1 {
		t.Fatalf("resolver calls=%d, want 1", resolverCalls)
	}
}

func TestWireSIPFlowTCPFinalResponseTimeoutAfterProvisional(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	serverErr := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- "accept error: " + err.Error()
			return
		}
		defer conn.Close()
		raw, err := readSIPStreamMessage(bufio.NewReader(conn))
		if err != nil {
			serverErr <- "read error: " + err.Error()
			return
		}
		req, err := ParseSIPRequest(raw)
		if err != nil {
			serverErr <- "parse request error: " + err.Error()
			return
		}
		ringing, err := BuildSIPResponseWire(req, 180, "Ringing", nil, nil)
		if err != nil {
			serverErr <- "build ringing error: " + err.Error()
			return
		}
		if _, err := conn.Write(ringing); err != nil {
			serverErr <- "write ringing error: " + err.Error()
			return
		}
		time.Sleep(320 * time.Millisecond)
		serverErr <- ""
	}()

	flow := &WireSIPFlow{
		Network:    "tcp",
		ServerAddr: ln.Addr().String(),
		Timeout:    200 * time.Millisecond,
	}
	defer flow.Close()
	resp, err := flow.RoundTripInvite(context.Background(), SIPRequestMessage{
		Method: "INVITE",
		URI:    "sip:+18005551212@example",
		Headers: map[string]string{
			"To":           "<sip:+18005551212@example>",
			"From":         "<sip:user@example>;tag=call",
			"Contact":      "<sip:user@192.0.2.10:5060>",
			"Call-ID":      "flow-tcp-final-timeout-invite",
			"CSeq":         "1 INVITE",
			"Max-Forwards": "70",
		},
	}, nil)
	if err == nil || !errors.Is(err, ErrSIPFinalResponseTimeout) {
		t.Fatalf("RoundTripInvite() response=%+v err=%v, want final response timeout", resp, err)
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

func TestWireSIPFlowBranchesCallerViaAndIgnoresLateTCPFinal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	seen := make(chan []string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			seen <- []string{"accept error: " + err.Error()}
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		firstRaw, err := readSIPStreamMessage(reader)
		if err != nil {
			seen <- []string{"read first error: " + err.Error()}
			return
		}
		firstReq, err := ParseSIPRequest(firstRaw)
		if err != nil {
			seen <- []string{"parse first error: " + err.Error()}
			return
		}
		firstOK, err := BuildSIPResponseWire(firstReq, 200, "OK", nil, nil)
		if err != nil {
			seen <- []string{"build first ok error: " + err.Error()}
			return
		}
		if _, err := conn.Write(firstOK); err != nil {
			seen <- []string{"write first ok error: " + err.Error()}
			return
		}

		secondRaw, err := readSIPStreamMessage(reader)
		if err != nil {
			seen <- []string{string(firstRaw), "read second error: " + err.Error()}
			return
		}
		secondReq, err := ParseSIPRequest(secondRaw)
		if err != nil {
			seen <- []string{string(firstRaw), "parse second error: " + err.Error()}
			return
		}
		stale, err := BuildSIPResponseWire(firstReq, 486, "Busy Here", nil, nil)
		if err != nil {
			seen <- []string{string(firstRaw), string(secondRaw), "build stale error: " + err.Error()}
			return
		}
		secondOK, err := BuildSIPResponseWire(secondReq, 200, "OK", nil, nil)
		if err != nil {
			seen <- []string{string(firstRaw), string(secondRaw), "build second ok error: " + err.Error()}
			return
		}
		_, _ = conn.Write(stale)
		_, _ = conn.Write(secondOK)
		seen <- []string{string(firstRaw), string(secondRaw)}
	}()

	headers := map[string]string{
		"Via":          "SIP/2.0/TCP 192.0.2.10:5060",
		"To":           "<sip:user@example>",
		"From":         "<sip:user@example>;tag=t",
		"Contact":      "<sip:user@192.0.2.10:5060>",
		"Call-ID":      "flow-late-tcp-branch",
		"CSeq":         "1 REGISTER",
		"Max-Forwards": "70",
	}
	flow := &WireSIPFlow{Network: "tcp", ServerAddr: ln.Addr().String(), Timeout: time.Second}
	defer flow.Close()
	resp, err := flow.RoundTripRegister(context.Background(), RegisterMessage{
		URI:     "sip:ims.example",
		Headers: headers,
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("first RoundTripRegister() response=%+v err=%v", resp, err)
	}
	resp, err = flow.RoundTripRegister(context.Background(), RegisterMessage{
		URI:     "sip:ims.example",
		Headers: headers,
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("second RoundTripRegister() response=%+v err=%v, want stale final ignored", resp, err)
	}

	requests := <-seen
	if len(requests) != 2 {
		t.Fatalf("requests=%d %+v", len(requests), requests)
	}
	firstReq, err := ParseSIPRequest([]byte(requests[0]))
	if err != nil {
		t.Fatalf("ParseSIPRequest(first) error = %v", err)
	}
	secondReq, err := ParseSIPRequest([]byte(requests[1]))
	if err != nil {
		t.Fatalf("ParseSIPRequest(second) error = %v", err)
	}
	firstVia := firstHeader(firstReq.Headers, "Via")
	secondVia := firstHeader(secondReq.Headers, "Via")
	if sipViaBranch(firstVia) == "" || sipViaBranch(secondVia) == "" || sipViaBranch(firstVia) == sipViaBranch(secondVia) {
		t.Fatalf("Via branches first=%q second=%q", firstVia, secondVia)
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
