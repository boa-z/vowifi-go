package voiceclient

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var ErrSIPFlowClosed = errors.New("SIP flow is closed")

type WireSIPFlow struct {
	Network               string
	ServerAddr            string
	LocalAddr             string
	Timeout               time.Duration
	RetransmitInterval    time.Duration
	MaxRetransmitInterval time.Duration
	MaxRetransmits        int

	mu      sync.Mutex
	conn    net.Conn
	reader  *bufio.Reader
	network string
	target  string
	closed  bool
}

var _ SIPRegisterTransport = (*WireSIPFlow)(nil)
var _ SIPRequestTransport = (*WireSIPFlow)(nil)
var _ SIPInviteTransport = (*WireSIPFlow)(nil)

func (f *WireSIPFlow) RoundTripRegister(ctx context.Context, msg RegisterMessage) (RegisterResponse, error) {
	return f.roundTrip(ctx, SIPRequestMessage{
		Method:  "REGISTER",
		URI:     msg.URI,
		Headers: cloneStringMap(msg.Headers),
		Body:    append([]byte(nil), msg.Body...),
	}, nil)
}

func (f *WireSIPFlow) RoundTripRequest(ctx context.Context, msg SIPRequestMessage) (SIPResponse, error) {
	return f.roundTrip(ctx, msg, nil)
}

func (f *WireSIPFlow) RoundTripInvite(ctx context.Context, msg SIPRequestMessage, onProvisional ProvisionalResponseHandler) (SIPResponse, error) {
	return f.roundTrip(ctx, msg, onProvisional)
}

func (f *WireSIPFlow) WriteRequest(ctx context.Context, msg SIPRequestMessage) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if f == nil {
		return errors.New("nil SIP flow")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	conn, network, timeout, err := f.ensureConnLocked(ctx, msg)
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		f.closeConnLocked()
		return err
	}
	ensureSIPRequestVia(&msg, transportName(network), conn.LocalAddr())
	wire, err := buildSIPRequestWire(msg, transportName(network), conn.LocalAddr())
	if err != nil {
		return err
	}
	if _, err := conn.Write(wire); err != nil {
		f.closeConnLocked()
		return err
	}
	return nil
}

func (f *WireSIPFlow) SendCRLFKeepalive(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if f == nil {
		return errors.New("nil SIP flow")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrSIPFlowClosed
	}
	conn := f.conn
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if conn == nil {
		target := strings.TrimSpace(f.ServerAddr)
		if target == "" {
			return errors.New("SIP flow has no connected remote for keepalive")
		}
		var err error
		conn, _, timeout, err = f.ensureConnLocked(ctx, SIPRequestMessage{URI: "sip:" + target})
		if err != nil {
			return err
		}
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		f.closeConnLocked()
		return err
	}
	if _, err := conn.Write([]byte("\r\n\r\n")); err != nil {
		f.closeConnLocked()
		return err
	}
	return nil
}

func (f *WireSIPFlow) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return f.closeConnLocked()
}

func (f *WireSIPFlow) roundTrip(ctx context.Context, msg SIPRequestMessage, onProvisional ProvisionalResponseHandler) (SIPResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if f == nil {
		return SIPResponse{}, errors.New("nil SIP flow")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	conn, network, timeout, err := f.ensureConnLocked(ctx, msg)
	if err != nil {
		return SIPResponse{}, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		f.closeConnLocked()
		return SIPResponse{}, err
	}
	ensureSIPRequestVia(&msg, transportName(network), conn.LocalAddr())
	wire, err := buildSIPRequestWire(msg, transportName(network), conn.LocalAddr())
	if err != nil {
		return SIPResponse{}, err
	}
	if _, err := conn.Write(wire); err != nil {
		f.closeConnLocked()
		return SIPResponse{}, err
	}
	if strings.HasPrefix(network, "tcp") {
		resp, err := readFinalSIPResponse(ctx, f.reader, msg, onProvisional)
		if err != nil {
			f.closeConnLocked()
		}
		return resp, err
	}
	resp, err := f.readUDPResponseLocked(ctx, conn, timeout, wire, msg, onProvisional)
	if err != nil {
		f.closeConnLocked()
	}
	return resp, err
}

func (f *WireSIPFlow) readUDPResponseLocked(ctx context.Context, conn net.Conn, timeout time.Duration, wire []byte, msg SIPRequestMessage, onProvisional ProvisionalResponseHandler) (SIPResponse, error) {
	buf := make([]byte, 65535)
	interval := sipRetransmitInterval(timeout, f.RetransmitInterval)
	maxInterval := sipMaxRetransmitInterval(timeout, f.MaxRetransmitInterval)
	deadline := time.Now().Add(timeout)
	retransmits := 0
	gotResponse := false
	retransmitExhausted := false
	for {
		readInterval := interval
		if gotResponse || retransmitExhausted {
			readInterval = time.Until(deadline)
		}
		if err := conn.SetReadDeadline(nextSIPReadDeadline(deadline, readInterval)); err != nil {
			return SIPResponse{}, err
		}
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return SIPResponse{}, ctx.Err()
			}
			if !isSIPTimeout(err) || !time.Now().Before(deadline) {
				return SIPResponse{}, err
			}
			if !gotResponse && !retransmitExhausted && shouldSIPRetransmit(retransmits, f.MaxRetransmits) {
				if _, writeErr := conn.Write(wire); writeErr != nil {
					return SIPResponse{}, writeErr
				}
				retransmits++
				interval = nextSIPRetransmitInterval(interval, maxInterval)
				continue
			}
			if !gotResponse {
				retransmitExhausted = true
				continue
			}
			return SIPResponse{}, err
		}
		if !bytes.HasPrefix(buf[:n], []byte("SIP/2.0")) {
			continue
		}
		resp, err := ParseSIPResponse(buf[:n])
		if err != nil {
			return SIPResponse{}, err
		}
		if !isProvisionalResponse(resp.StatusCode, msg.Method) {
			return resp, nil
		}
		if onProvisional != nil {
			if err := onProvisional(ctx, msg, resp); err != nil {
				return SIPResponse{}, err
			}
		}
		gotResponse = true
	}
}

func (f *WireSIPFlow) ensureConnLocked(ctx context.Context, msg SIPRequestMessage) (net.Conn, string, time.Duration, error) {
	if f.closed {
		return nil, "", 0, ErrSIPFlowClosed
	}
	network := strings.ToLower(strings.TrimSpace(f.Network))
	if network == "" {
		network = "udp"
	}
	target := strings.TrimSpace(f.ServerAddr)
	if target == "" {
		addr, err := sipURIAddr(msg.URI)
		if err != nil {
			return nil, "", 0, err
		}
		target = addr
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if f.conn != nil && f.network == network && f.target == target {
		return f.conn, network, timeout, nil
	}
	_ = f.closeConnLocked()
	dialer := net.Dialer{Timeout: timeout}
	switch network {
	case "udp", "udp4", "udp6":
		if strings.TrimSpace(f.LocalAddr) != "" {
			addr, err := net.ResolveUDPAddr(network, f.LocalAddr)
			if err != nil {
				return nil, "", 0, err
			}
			dialer.LocalAddr = addr
		}
	case "tcp", "tcp4", "tcp6":
		if strings.TrimSpace(f.LocalAddr) != "" {
			addr, err := net.ResolveTCPAddr(network, f.LocalAddr)
			if err != nil {
				return nil, "", 0, err
			}
			dialer.LocalAddr = addr
		}
	default:
		return nil, "", 0, fmt.Errorf("unsupported SIP network %q", network)
	}
	conn, err := dialer.DialContext(ctx, network, target)
	if err != nil {
		return nil, "", 0, err
	}
	f.conn = conn
	f.network = network
	f.target = target
	if strings.HasPrefix(network, "tcp") {
		f.reader = bufio.NewReader(conn)
	} else {
		f.reader = nil
	}
	return conn, network, timeout, nil
}

func (f *WireSIPFlow) closeConnLocked() error {
	if f.conn == nil {
		f.reader = nil
		f.network = ""
		f.target = ""
		return nil
	}
	err := f.conn.Close()
	f.conn = nil
	f.reader = nil
	f.network = ""
	f.target = ""
	return err
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
