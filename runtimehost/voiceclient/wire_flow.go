package voiceclient

import (
	"bufio"
	"context"
	"errors"
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
	Resolver              SIPServerResolver
	Timeout               time.Duration
	RetransmitInterval    time.Duration
	MaxRetransmitInterval time.Duration
	MaxRetransmits        int

	mu          sync.Mutex
	conn        net.Conn
	reader      *bufio.Reader
	network     string
	target      string
	targets     []string
	targetIndex int
	closed      bool
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
	}, nil, sipRegisterTargetFailoverStatus)
}

func (f *WireSIPFlow) RoundTripRequest(ctx context.Context, msg SIPRequestMessage) (SIPResponse, error) {
	return f.roundTrip(ctx, msg, nil, sipDialogTargetFailoverStatus)
}

func (f *WireSIPFlow) RoundTripInvite(ctx context.Context, msg SIPRequestMessage, onProvisional ProvisionalResponseHandler) (SIPResponse, error) {
	return f.roundTrip(ctx, msg, onProvisional, sipDialogTargetFailoverStatus)
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
	attempts := 0
	shouldRetry := func(err error) bool {
		if ctx.Err() != nil || !isSIPRetryableTransportError(err) {
			return false
		}
		attempts++
		if attempts >= f.targetCountLocked() {
			return false
		}
		return f.advanceTargetLocked()
	}
	for {
		conn, network, timeout, err := f.ensureConnLocked(ctx, msg)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !shouldRetry(err) {
				return err
			}
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			f.closeConnLocked()
			if !shouldRetry(err) {
				return err
			}
			continue
		}
		attempt := cloneSIPRequestMessage(msg)
		ensureSIPRequestVia(&attempt, transportName(network), conn.LocalAddr())
		wire, err := buildSIPRequestWire(attempt, transportName(network), conn.LocalAddr())
		if err != nil {
			return err
		}
		if _, err := conn.Write(wire); err != nil {
			f.closeConnLocked()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !shouldRetry(err) {
				return err
			}
			continue
		}
		return nil
	}
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
		if target == "" && len(f.targets) > 0 && f.targetIndex >= 0 && f.targetIndex < len(f.targets) {
			target = f.targets[f.targetIndex]
		}
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

func (f *WireSIPFlow) Reset() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrSIPFlowClosed
	}
	err := f.closeConnLocked()
	f.targets = nil
	f.targetIndex = 0
	return err
}

func (f *WireSIPFlow) ResetToNextTarget() (bool, error) {
	if f == nil {
		return false, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false, ErrSIPFlowClosed
	}
	err := f.closeConnLocked()
	if strings.TrimSpace(f.ServerAddr) != "" {
		return false, err
	}
	if len(f.targets) <= 1 {
		f.targets = nil
		f.targetIndex = 0
		return false, err
	}
	old := f.targetIndex
	switched := f.advanceTargetLocked() && f.targetIndex != old
	return switched, err
}

func (f *WireSIPFlow) roundTrip(ctx context.Context, msg SIPRequestMessage, onProvisional ProvisionalResponseHandler, retryStatus func(int) bool) (SIPResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if f == nil {
		return SIPResponse{}, errors.New("nil SIP flow")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	attempts := 0
	redirects := 0
	shouldRetry := func(err error) bool {
		if ctx.Err() != nil || !isSIPRetryableTransportError(err) {
			return false
		}
		attempts++
		if attempts >= f.targetCountLocked() {
			return false
		}
		return f.advanceTargetLocked()
	}
	shouldRetryResponse := func(resp SIPResponse) bool {
		if ctx.Err() != nil || retryStatus == nil || !retryStatus(resp.StatusCode) {
			return false
		}
		attempts++
		if attempts >= f.targetCountLocked() {
			return false
		}
		f.closeConnLocked()
		return f.advanceTargetLocked()
	}
	shouldRedirectResponse := func(resp SIPResponse) bool {
		if ctx.Err() != nil || redirects >= maxSIPRedirectTargets || !sipRedirectStatus(resp.StatusCode) ||
			strings.EqualFold(strings.TrimSpace(msg.Method), "INVITE") {
			return false
		}
		if !f.redirectToResponseTargetsLocked(resp) {
			return false
		}
		redirects++
		f.closeConnLocked()
		return true
	}
	for {
		conn, network, timeout, err := f.ensureConnLocked(ctx, msg)
		if err != nil {
			if ctx.Err() != nil {
				return SIPResponse{}, ctx.Err()
			}
			if !shouldRetry(err) {
				return SIPResponse{}, err
			}
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			f.closeConnLocked()
			if !shouldRetry(err) {
				return SIPResponse{}, err
			}
			continue
		}
		attempt := cloneSIPRequestMessage(msg)
		ensureSIPRequestVia(&attempt, transportName(network), conn.LocalAddr())
		wire, err := buildSIPRequestWire(attempt, transportName(network), conn.LocalAddr())
		if err != nil {
			return SIPResponse{}, err
		}
		if _, err := conn.Write(wire); err != nil {
			f.closeConnLocked()
			if ctx.Err() != nil {
				return SIPResponse{}, ctx.Err()
			}
			if !shouldRetry(err) {
				return SIPResponse{}, err
			}
			continue
		}
		if strings.HasPrefix(network, "tcp") {
			resp, err := readFinalSIPResponse(ctx, f.reader, attempt, onProvisional)
			if err != nil {
				f.closeConnLocked()
				if ctx.Err() != nil {
					return SIPResponse{}, ctx.Err()
				}
				if !shouldRetry(err) {
					return SIPResponse{}, err
				}
				continue
			}
			if shouldRedirectResponse(resp) {
				continue
			}
			if shouldRetryResponse(resp) {
				continue
			}
			return resp, nil
		}
		resp, err := f.readUDPResponseLocked(ctx, conn, timeout, wire, attempt, onProvisional)
		if err != nil {
			f.closeConnLocked()
			if ctx.Err() != nil {
				return SIPResponse{}, ctx.Err()
			}
			if !shouldRetry(err) {
				return SIPResponse{}, err
			}
			continue
		}
		if shouldRedirectResponse(resp) {
			continue
		}
		if shouldRetryResponse(resp) {
			continue
		}
		return resp, nil
	}
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
		if !isSIPResponseWire(buf[:n]) {
			continue
		}
		resp, err := ParseSIPResponse(buf[:n])
		if err != nil {
			return SIPResponse{}, err
		}
		if !sipResponseMatchesRequest(resp, msg) {
			continue
		}
		if !isSIPProvisionalResponse(resp.StatusCode) {
			return resp, nil
		}
		if onProvisional != nil && shouldReportSIPProvisionalResponse(msg.Method) {
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
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if f.conn != nil && f.network == network && (strings.TrimSpace(f.ServerAddr) == "" || f.target == strings.TrimSpace(f.ServerAddr)) {
		return f.conn, network, timeout, nil
	}
	targets, err := f.ensureTargetsLocked(ctx, network, msg.URI)
	if err != nil {
		return nil, "", 0, err
	}
	if len(targets) == 0 {
		return nil, "", 0, errSIPDNSResolverEmpty()
	}
	target := targets[f.targetIndex]
	if f.conn != nil && f.network == network && f.target == target {
		return f.conn, network, timeout, nil
	}
	_ = f.closeConnLocked()
	conn, err := dialSIPConn(ctx, network, target, f.LocalAddr, timeout)
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

func (f *WireSIPFlow) ensureTargetsLocked(ctx context.Context, network, uri string) ([]string, error) {
	if target := strings.TrimSpace(f.ServerAddr); target != "" {
		if len(f.targets) == 0 || f.targets[0] != target {
			f.targets = []string{target}
			f.targetIndex = 0
		}
		if f.targetIndex < 0 || f.targetIndex >= len(f.targets) {
			f.targetIndex = 0
		}
		return f.targets, nil
	}
	if len(f.targets) == 0 {
		targets, err := resolveSIPServerAddrs(ctx, f.Resolver, network, uri)
		if err != nil {
			return nil, err
		}
		f.targets = appendSIPTargets(nil, targets...)
		f.targetIndex = 0
	}
	if f.targetIndex < 0 || f.targetIndex >= len(f.targets) {
		f.targetIndex = 0
	}
	return f.targets, nil
}

func (f *WireSIPFlow) redirectToResponseTargetsLocked(resp SIPResponse) bool {
	targets, nextIndex, ok := sipTargetsWithRedirects(f.targets, f.targetIndex, sipRedirectTargets(resp))
	if !ok {
		return false
	}
	f.targets = targets
	f.targetIndex = nextIndex
	return true
}

func (f *WireSIPFlow) advanceTargetLocked() bool {
	if len(f.targets) <= 1 {
		return false
	}
	f.targetIndex = (f.targetIndex + 1) % len(f.targets)
	return true
}

func (f *WireSIPFlow) targetCountLocked() int {
	if len(f.targets) == 0 {
		return 1
	}
	return len(f.targets)
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

func cloneSIPRequestMessage(msg SIPRequestMessage) SIPRequestMessage {
	msg.Headers = cloneStringMap(msg.Headers)
	msg.Body = append([]byte(nil), msg.Body...)
	return msg
}
