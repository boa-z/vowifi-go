package voiceclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

var ErrInvalidSIPMessage = errors.New("invalid SIP message")

type WireRegisterTransport struct {
	Network               string
	ServerAddr            string
	LocalAddr             string
	Resolver              SIPServerResolver
	Timeout               time.Duration
	RetransmitInterval    time.Duration
	MaxRetransmitInterval time.Duration
	MaxRetransmits        int
}

func (t WireRegisterTransport) RoundTripRegister(ctx context.Context, msg RegisterMessage) (RegisterResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	network := strings.ToLower(strings.TrimSpace(t.Network))
	if network == "" {
		network = "udp"
	}
	targets, err := sipTargetsForRequest(ctx, t.Resolver, network, t.ServerAddr, msg.URI)
	if err != nil {
		return RegisterResponse{}, err
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	var lastErr error
	redirects := 0
	for idx := 0; idx < len(targets); idx++ {
		target := targets[idx]
		var resp RegisterResponse
		var err error
		switch network {
		case "udp", "udp4", "udp6":
			resp, err = t.roundTripUDP(ctx, network, target, timeout, msg)
		case "tcp", "tcp4", "tcp6":
			resp, err = t.roundTripTCP(ctx, network, target, timeout, msg)
		default:
			return RegisterResponse{}, fmt.Errorf("unsupported SIP register network %q", network)
		}
		if err == nil {
			if redirects < maxSIPRedirectTargets && sipRedirectStatus(resp.StatusCode) {
				if nextTargets, nextIndex, ok := sipTargetsWithRedirects(targets, idx, sipRedirectTargets(resp)); ok {
					targets = nextTargets
					idx = nextIndex - 1
					redirects++
					continue
				}
			}
			if sipRegisterTargetFailoverStatus(resp.StatusCode) && idx+1 < len(targets) {
				continue
			}
			return resp, nil
		}
		if ctx.Err() != nil {
			return RegisterResponse{}, ctx.Err()
		}
		lastErr = err
		if !isSIPRetryableTransportError(err) {
			break
		}
	}
	if lastErr != nil {
		return RegisterResponse{}, lastErr
	}
	return RegisterResponse{}, errSIPDNSResolverEmpty()
}

func sipTargetsForRequest(ctx context.Context, resolver SIPServerResolver, network, serverAddr, uri string) ([]string, error) {
	target := strings.TrimSpace(serverAddr)
	if target != "" {
		return []string{target}, nil
	}
	targets, err := resolveSIPServerAddrs(ctx, resolver, network, uri)
	if err != nil {
		return nil, err
	}
	targets = appendSIPTargets(nil, targets...)
	if len(targets) == 0 {
		return nil, errSIPDNSResolverEmpty()
	}
	return targets, nil
}

func dialSIPConn(ctx context.Context, network, target, localAddr string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	switch network {
	case "udp", "udp4", "udp6":
		if strings.TrimSpace(localAddr) != "" {
			addr, err := net.ResolveUDPAddr(network, localAddr)
			if err != nil {
				return nil, err
			}
			dialer.LocalAddr = addr
		}
	case "tcp", "tcp4", "tcp6":
		if strings.TrimSpace(localAddr) != "" {
			addr, err := net.ResolveTCPAddr(network, localAddr)
			if err != nil {
				return nil, err
			}
			dialer.LocalAddr = addr
		}
	default:
		return nil, fmt.Errorf("unsupported SIP network %q", network)
	}
	return dialer.DialContext(ctx, network, target)
}

func (t WireRegisterTransport) roundTripUDP(ctx context.Context, network, target string, timeout time.Duration, msg RegisterMessage) (RegisterResponse, error) {
	conn, err := dialSIPConn(ctx, network, target, t.LocalAddr, timeout)
	if err != nil {
		return RegisterResponse{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return RegisterResponse{}, err
	}
	attempt := SIPRequestMessage{
		Method:  "REGISTER",
		URI:     msg.URI,
		Headers: cloneStringMap(msg.Headers),
		Body:    append([]byte(nil), msg.Body...),
	}
	ensureSIPRequestVia(&attempt, "UDP", conn.LocalAddr())
	wire, err := buildSIPRequestWire(attempt, "UDP", conn.LocalAddr())
	if err != nil {
		return RegisterResponse{}, err
	}
	if _, err := conn.Write(wire); err != nil {
		return RegisterResponse{}, err
	}
	buf := make([]byte, 65535)
	interval := sipRetransmitInterval(timeout, t.RetransmitInterval)
	maxInterval := sipMaxRetransmitInterval(timeout, t.MaxRetransmitInterval)
	deadline := time.Now().Add(timeout)
	retransmits := 0
	gotResponse := false
	for {
		readInterval := interval
		if gotResponse {
			readInterval = time.Until(deadline)
		}
		if err := conn.SetReadDeadline(nextSIPReadDeadline(deadline, readInterval)); err != nil {
			return RegisterResponse{}, err
		}
		n, err := conn.Read(buf)
		if err == nil {
			if !isSIPResponseWire(buf[:n]) {
				continue
			}
			resp, err := ParseSIPResponse(buf[:n])
			if err != nil {
				return RegisterResponse{}, err
			}
			if !sipResponseMatchesRequest(resp, attempt) {
				continue
			}
			if isSIPProvisionalResponse(resp.StatusCode) {
				gotResponse = true
				continue
			}
			return resp, nil
		}
		if ctx.Err() != nil {
			return RegisterResponse{}, ctx.Err()
		}
		if !isSIPTimeout(err) || !time.Now().Before(deadline) {
			return RegisterResponse{}, err
		}
		if !gotResponse && shouldSIPRetransmit(retransmits, t.MaxRetransmits) {
			if _, writeErr := conn.Write(wire); writeErr != nil {
				return RegisterResponse{}, writeErr
			}
			retransmits++
			interval = nextSIPRetransmitInterval(interval, maxInterval)
			continue
		}
		interval = time.Until(deadline)
	}
}

func (t WireRegisterTransport) roundTripTCP(ctx context.Context, network, target string, timeout time.Duration, msg RegisterMessage) (RegisterResponse, error) {
	conn, err := dialSIPConn(ctx, network, target, t.LocalAddr, timeout)
	if err != nil {
		return RegisterResponse{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return RegisterResponse{}, err
	}
	attempt := SIPRequestMessage{
		Method:  "REGISTER",
		URI:     msg.URI,
		Headers: cloneStringMap(msg.Headers),
		Body:    append([]byte(nil), msg.Body...),
	}
	ensureSIPRequestVia(&attempt, "TCP", conn.LocalAddr())
	wire, err := buildSIPRequestWire(attempt, "TCP", conn.LocalAddr())
	if err != nil {
		return RegisterResponse{}, err
	}
	if _, err := conn.Write(wire); err != nil {
		return RegisterResponse{}, err
	}
	reader := bufio.NewReader(conn)
	for {
		raw, err := readSIPStreamMessage(reader)
		if err != nil {
			return RegisterResponse{}, err
		}
		resp, err := ParseSIPResponse(raw)
		if err != nil {
			return RegisterResponse{}, err
		}
		if sipResponseMatchesRequest(resp, attempt) {
			if isSIPProvisionalResponse(resp.StatusCode) {
				continue
			}
			return resp, nil
		}
	}
}

func buildSIPRequestWire(msg SIPRequestMessage, transport string, localAddr net.Addr) ([]byte, error) {
	method := strings.ToUpper(strings.TrimSpace(msg.Method))
	if method == "" {
		return nil, errors.New("SIP method is empty")
	}
	uri := strings.TrimSpace(msg.URI)
	if uri == "" {
		return nil, errors.New("SIP request URI is empty")
	}
	headers := make(map[string]string, len(msg.Headers)+4)
	for k, v := range msg.Headers {
		if strings.TrimSpace(k) != "" {
			headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if firstHeaderValue(headers, "Via") == "" {
		headers["Via"] = buildViaHeader(transport, localAddr)
	}
	if firstHeaderValue(headers, "Content-Length") == "" {
		headers["Content-Length"] = strconv.Itoa(len(msg.Body))
	}
	var out bytes.Buffer
	out.WriteString(method)
	out.WriteString(" ")
	out.WriteString(uri)
	out.WriteString(" SIP/2.0\r\n")
	writeOrderedHeaders(&out, headers)
	out.WriteString("\r\n")
	out.Write(msg.Body)
	return out.Bytes(), nil
}

func ensureSIPRequestVia(msg *SIPRequestMessage, transport string, localAddr net.Addr) {
	if msg == nil {
		return
	}
	if msg.Headers == nil {
		msg.Headers = make(map[string]string)
	}
	if firstHeaderValue(msg.Headers, "Via") == "" {
		msg.Headers["Via"] = buildViaHeader(transport, localAddr)
	}
}

func writeOrderedHeaders(out *bytes.Buffer, headers map[string]string) {
	order := []string{
		"Via", "Route", "Max-Forwards", "To", "From", "Call-ID", "CSeq", "Contact",
		"Expires", "P-Preferred-Identity", "User-Agent", "Allow", "Supported", "Require",
		"P-Preferred-Service", "Accept-Contact",
		"P-Access-Network-Info", "Security-Client", "Security-Verify", "Authorization",
		"Proxy-Authorization", "Session-Expires", "Min-SE", "Event", "Subscription-State",
		"Allow-Events", "Content-Type", "Accept",
	}
	written := make(map[string]bool, len(order))
	contentLength := ""
	for _, name := range order {
		for key, value := range headers {
			if strings.EqualFold(key, name) && strings.TrimSpace(value) != "" {
				out.WriteString(name)
				out.WriteString(": ")
				out.WriteString(value)
				out.WriteString("\r\n")
				written[strings.ToLower(key)] = true
			}
		}
	}
	for key, value := range headers {
		if strings.EqualFold(key, "Content-Length") {
			contentLength = strings.TrimSpace(value)
			written[strings.ToLower(key)] = true
			continue
		}
		if written[strings.ToLower(key)] || strings.TrimSpace(value) == "" {
			continue
		}
		out.WriteString(key)
		out.WriteString(": ")
		out.WriteString(value)
		out.WriteString("\r\n")
	}
	if contentLength != "" {
		out.WriteString("Content-Length: ")
		out.WriteString(contentLength)
		out.WriteString("\r\n")
	}
}

func buildViaHeader(transport string, addr net.Addr) string {
	host, port := localHostPort(addr)
	if host == "" {
		host = "0.0.0.0"
	}
	if port == 0 {
		port = 5060
	}
	return "SIP/2.0/" + strings.ToUpper(strings.TrimSpace(transport)) + " " + host + ":" + strconv.Itoa(port) + ";branch=" + newBranch() + ";rport"
}

func localHostPort(addr net.Addr) (string, int) {
	if addr == nil {
		return "", 0
	}
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0
	}
	port, _ := strconv.Atoi(portText)
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host, port
}

func newBranch() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "z9hG4bKvowifigo"
	}
	return "z9hG4bK" + hex.EncodeToString(b[:])
}

func ParseSIPResponse(raw []byte) (RegisterResponse, error) {
	head, body, err := splitSIPMessage(raw)
	if err != nil {
		return RegisterResponse{}, err
	}
	lines := splitHeaderLines(head)
	if len(lines) == 0 {
		return RegisterResponse{}, ErrInvalidSIPMessage
	}
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 || !strings.EqualFold(parts[0], "SIP/2.0") {
		return RegisterResponse{}, fmt.Errorf("%w: invalid status line", ErrInvalidSIPMessage)
	}
	statusToken := strings.TrimSpace(parts[1])
	if !validSIPStatusToken(statusToken) {
		return RegisterResponse{}, fmt.Errorf("%w: invalid status code", ErrInvalidSIPMessage)
	}
	code, _ := strconv.Atoi(statusToken)
	if !validSIPStatusCode(code) {
		return RegisterResponse{}, fmt.Errorf("%w: invalid status code", ErrInvalidSIPMessage)
	}
	reason := ""
	if len(parts) == 3 {
		reason = strings.TrimSpace(parts[2])
	}
	headers, err := parseSIPHeaders(lines[1:])
	if err != nil {
		return RegisterResponse{}, err
	}
	body, err = sipBodyByContentLength(headers, body)
	if err != nil {
		return RegisterResponse{}, err
	}
	return RegisterResponse{
		StatusCode: code,
		Reason:     reason,
		Headers:    headers,
		Body:       append([]byte(nil), body...),
		RetryAfter: SIPRetryAfterDelay(headers),
	}, nil
}

func SIPResponseRetryAfter(resp RegisterResponse) time.Duration {
	if resp.RetryAfter > 0 {
		return resp.RetryAfter
	}
	return SIPRetryAfterDelay(resp.Headers)
}

func sipRegisterTargetFailoverStatus(code int) bool {
	switch code {
	case 408, 430, 480, 500, 502, 503, 504, 580:
		return true
	default:
		return code >= 500 && code < 600
	}
}

func sipDialogTargetFailoverStatus(code int) bool {
	switch code {
	case 408, 430, 500, 502, 503, 504, 580:
		return true
	default:
		return code >= 500 && code < 600
	}
}

const maxSIPRedirectTargets = 4

func sipRedirectStatus(code int) bool {
	return code >= 300 && code < 400
}

func sipRedirectTargets(resp SIPResponse) []string {
	var targets []string
	for _, contact := range headerListValues(resp.Headers, "Contact") {
		uri := extractAddressURI(contact)
		if uri == "" || uri == "*" {
			continue
		}
		target, err := sipURIAddr(uri)
		if err != nil {
			continue
		}
		targets = appendSIPTargets(targets, target)
	}
	return targets
}

func sipTargetsWithRedirects(targets []string, currentIndex int, redirects []string) ([]string, int, bool) {
	if len(redirects) == 0 {
		return targets, currentIndex, false
	}
	if currentIndex < 0 {
		currentIndex = 0
	}
	if currentIndex >= len(targets) {
		currentIndex = len(targets) - 1
	}
	if currentIndex < 0 {
		targets = appendSIPTargets(nil, redirects...)
		return targets, 0, len(targets) > 0
	}
	out := appendSIPTargets(nil, targets[:currentIndex+1]...)
	out = appendSIPTargets(out, redirects...)
	out = appendSIPTargets(out, targets[currentIndex+1:]...)
	for _, redirect := range redirects {
		redirect = strings.TrimSpace(redirect)
		if redirect == "" {
			continue
		}
		for idx, target := range out {
			if target == redirect && idx != currentIndex {
				return out, idx, true
			}
		}
	}
	return out, currentIndex, false
}

func SIPRetryAfterDelay(headers map[string][]string) time.Duration {
	var delay time.Duration
	for _, value := range rawHeaderValues(headers, "Retry-After") {
		parsed, ok := parseSIPRetryAfterValue(value)
		if !ok {
			continue
		}
		if parsed > delay {
			delay = parsed
		}
	}
	return delay
}

func parseSIPRetryAfterValue(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	end := 0
	for end < len(value) {
		switch value[end] {
		case ' ', '\t', ';', '(', ',':
			goto parse
		default:
			end++
		}
	}
parse:
	token := strings.TrimSpace(value[:end])
	if token == "" {
		return 0, false
	}
	seconds, err := strconv.Atoi(token)
	if err != nil || seconds < 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func validSIPStatusCode(code int) bool {
	return code >= 100 && code <= 699
}

func validSIPStatusToken(token string) bool {
	if len(token) != 3 {
		return false
	}
	for _, r := range token {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func sipResponseMatchesRequest(resp RegisterResponse, req SIPRequestMessage) bool {
	if !sipResponseHeaderMatchesRequest(resp.Headers, req.Headers, "Call-ID") {
		return false
	}
	if !sipResponseCSeqMatchesRequest(resp, req) {
		return false
	}
	if !sipResponseViaMatchesRequest(resp, req) {
		return false
	}
	return true
}

func sipResponseHeaderMatchesRequest(respHeaders map[string][]string, reqHeaders map[string]string, name string) bool {
	respValue := firstHeader(respHeaders, name)
	if respValue == "" {
		return true
	}
	reqValue := firstHeaderValue(reqHeaders, name)
	return reqValue != "" && strings.TrimSpace(respValue) == strings.TrimSpace(reqValue)
}

func sipResponseCSeqMatchesRequest(resp RegisterResponse, req SIPRequestMessage) bool {
	respValue := firstHeader(resp.Headers, "CSeq")
	if respValue == "" {
		return true
	}
	respSeq, respMethod, ok := sipCSeqParts(respValue)
	if !ok {
		return false
	}
	reqSeq, reqMethod, ok := sipCSeqParts(firstHeaderValue(req.Headers, "CSeq"))
	if !ok {
		return false
	}
	return respSeq == reqSeq && strings.EqualFold(respMethod, reqMethod)
}

func sipCSeqParts(value string) (int, string, bool) {
	fields := strings.Fields(value)
	if len(fields) < 2 {
		return 0, "", false
	}
	seq, err := strconv.Atoi(fields[0])
	if err != nil || seq <= 0 {
		return 0, "", false
	}
	method := strings.ToUpper(strings.TrimSpace(fields[1]))
	if method == "" {
		return 0, "", false
	}
	return seq, method, true
}

func sipResponseViaMatchesRequest(resp RegisterResponse, req SIPRequestMessage) bool {
	respVia := firstHeader(resp.Headers, "Via")
	if respVia == "" {
		return true
	}
	reqVia := firstHeaderValue(req.Headers, "Via")
	if reqVia == "" {
		return false
	}
	respBranch := sipViaBranch(respVia)
	reqBranch := sipViaBranch(reqVia)
	if respBranch != "" || reqBranch != "" {
		return respBranch != "" && reqBranch != "" && respBranch == reqBranch
	}
	return true
}

func sipViaBranch(via string) string {
	for _, part := range strings.Split(via, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "branch") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func ParseSIPRequest(raw []byte) (SIPIncomingRequest, error) {
	head, body, err := splitSIPMessage(raw)
	if err != nil {
		return SIPIncomingRequest{}, err
	}
	lines := splitHeaderLines(head)
	if len(lines) == 0 {
		return SIPIncomingRequest{}, ErrInvalidSIPMessage
	}
	parts := strings.Fields(lines[0])
	if len(parts) != 3 || !strings.EqualFold(parts[2], "SIP/2.0") {
		return SIPIncomingRequest{}, fmt.Errorf("%w: invalid request line", ErrInvalidSIPMessage)
	}
	method := strings.ToUpper(strings.TrimSpace(parts[0]))
	uri := strings.TrimSpace(parts[1])
	if method == "" || uri == "" {
		return SIPIncomingRequest{}, fmt.Errorf("%w: empty method or URI", ErrInvalidSIPMessage)
	}
	headers, err := parseSIPHeaders(lines[1:])
	if err != nil {
		return SIPIncomingRequest{}, err
	}
	body, err = sipBodyByContentLength(headers, body)
	if err != nil {
		return SIPIncomingRequest{}, err
	}
	return SIPIncomingRequest{
		Method:  method,
		URI:     uri,
		Headers: headers,
		Body:    append([]byte(nil), body...),
	}, nil
}

func BuildSIPResponseWire(req SIPIncomingRequest, statusCode int, reason string, headers map[string]string, body []byte) ([]byte, error) {
	if !validSIPStatusCode(statusCode) {
		return nil, fmt.Errorf("%w: invalid response status", ErrInvalidSIPMessage)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = defaultSIPReason(statusCode)
	}
	outHeaders := make(map[string][]string, len(headers)+6)
	copyIncomingHeader(outHeaders, req.Headers, "Via")
	copyIncomingHeader(outHeaders, req.Headers, "To")
	copyIncomingHeader(outHeaders, req.Headers, "From")
	copyIncomingHeader(outHeaders, req.Headers, "Call-ID")
	copyIncomingHeader(outHeaders, req.Headers, "CSeq")
	for key, value := range headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || strings.EqualFold(key, "Content-Length") {
			continue
		}
		canonical := canonicalHeaderName(key)
		outHeaders[canonical] = append(outHeaders[canonical], value)
	}
	outHeaders["Content-Length"] = []string{strconv.Itoa(len(body))}
	var out bytes.Buffer
	out.WriteString("SIP/2.0 ")
	out.WriteString(strconv.Itoa(statusCode))
	out.WriteString(" ")
	out.WriteString(reason)
	out.WriteString("\r\n")
	writeOrderedHeaderValues(&out, outHeaders)
	out.WriteString("\r\n")
	out.Write(body)
	return out.Bytes(), nil
}

func ReadSIPStreamMessage(r *bufio.Reader) ([]byte, error) {
	return readSIPStreamMessage(r)
}

func splitSIPMessage(raw []byte) (string, []byte, error) {
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		return string(raw[:idx]), raw[idx+4:], nil
	}
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		return string(raw[:idx]), raw[idx+2:], nil
	}
	return "", nil, fmt.Errorf("%w: missing header terminator", ErrInvalidSIPMessage)
}

func writeOrderedHeaderValues(out *bytes.Buffer, headers map[string][]string) {
	order := []string{
		"Via", "Record-Route", "Route", "Max-Forwards", "To", "From", "Call-ID",
		"CSeq", "Contact", "Expires", "P-Associated-URI", "Service-Route", "Path",
		"P-Preferred-Identity", "User-Agent", "Allow", "Supported", "Require",
		"P-Access-Network-Info", "Security-Client", "Security-Verify",
		"Authorization", "Proxy-Authorization", "WWW-Authenticate",
		"Proxy-Authenticate", "Session-Expires", "Min-SE", "Event", "Subscription-State",
		"Allow-Events", "Content-Type", "Accept",
	}
	written := make(map[string]bool, len(order))
	for _, name := range order {
		for key, values := range headers {
			if !strings.EqualFold(key, name) {
				continue
			}
			for _, value := range values {
				if strings.TrimSpace(value) == "" {
					continue
				}
				out.WriteString(name)
				out.WriteString(": ")
				out.WriteString(strings.TrimSpace(value))
				out.WriteString("\r\n")
			}
			written[strings.ToLower(key)] = true
		}
	}
	for key, values := range headers {
		if written[strings.ToLower(key)] {
			continue
		}
		for _, value := range values {
			if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
				continue
			}
			out.WriteString(key)
			out.WriteString(": ")
			out.WriteString(strings.TrimSpace(value))
			out.WriteString("\r\n")
		}
	}
}

func copyIncomingHeader(dst map[string][]string, src map[string][]string, name string) {
	for key, values := range src {
		if strings.EqualFold(key, name) && len(values) > 0 {
			dst[name] = append(dst[name], trimHeaderValues(values)...)
		}
	}
}

func defaultSIPReason(code int) string {
	switch code {
	case 100:
		return "Trying"
	case 180:
		return "Ringing"
	case 200:
		return "OK"
	case 400:
		return "Bad Request"
	case 481:
		return "Call/Transaction Does Not Exist"
	case 486:
		return "Busy Here"
	case 488:
		return "Not Acceptable Here"
	case 500:
		return "Server Internal Error"
	case 503:
		return "Service Unavailable"
	default:
		return "Status"
	}
}

func splitHeaderLines(head string) []string {
	raw := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		if line == "" {
			continue
		}
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && len(out) > 0 {
			out[len(out)-1] += " " + strings.TrimSpace(line)
			continue
		}
		out = append(out, strings.TrimSpace(line))
	}
	return out
}

func parseSIPHeaders(lines []string) (map[string][]string, error) {
	headers := make(map[string][]string)
	for _, line := range lines {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("%w: malformed header %q", ErrInvalidSIPMessage, line)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" {
			return nil, fmt.Errorf("%w: empty header name", ErrInvalidSIPMessage)
		}
		canonical := canonicalHeaderName(name)
		headers[canonical] = append(headers[canonical], value)
	}
	return headers, nil
}

func readSIPStreamMessage(r *bufio.Reader) ([]byte, error) {
	var raw []byte
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		if len(raw) == 0 && isSIPBlankLine(line) {
			continue
		}
		raw = append(raw, line...)
		if bytes.HasSuffix(raw, []byte("\r\n\r\n")) || bytes.HasSuffix(raw, []byte("\n\n")) {
			break
		}
	}
	headers, _, err := splitSIPMessage(raw)
	if err != nil {
		return nil, err
	}
	parsed, err := parseSIPHeaders(splitHeaderLines(headers)[1:])
	if err != nil {
		return nil, err
	}
	n, ok, err := strictContentLength(parsed)
	if err != nil {
		return nil, err
	}
	if ok && n > 0 {
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		raw = append(raw, body...)
	}
	return raw, nil
}

func isSIPBlankLine(line []byte) bool {
	return len(bytes.TrimSpace(line)) == 0
}

func isSIPResponseWire(raw []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(raw, "\r\n\t "), []byte("SIP/2.0"))
}

func sipBodyByContentLength(headers map[string][]string, body []byte) ([]byte, error) {
	n, ok, err := strictContentLength(headers)
	if err != nil {
		return nil, err
	}
	if !ok {
		return body, nil
	}
	if n > len(body) {
		return nil, fmt.Errorf("%w: content length %d exceeds body length %d", ErrInvalidSIPMessage, n, len(body))
	}
	return body[:n], nil
}

func strictContentLength(headers map[string][]string) (int, bool, error) {
	var length int
	seen := false
	for key, values := range headers {
		if !strings.EqualFold(key, "Content-Length") && !strings.EqualFold(key, "l") {
			continue
		}
		if len(values) == 0 {
			return 0, false, fmt.Errorf("%w: invalid content length", ErrInvalidSIPMessage)
		}
		for _, value := range values {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || n < 0 {
				return 0, false, fmt.Errorf("%w: invalid content length", ErrInvalidSIPMessage)
			}
			if seen && n != length {
				return 0, false, fmt.Errorf("%w: conflicting content length", ErrInvalidSIPMessage)
			}
			length = n
			seen = true
		}
	}
	return length, seen, nil
}

func sipRetransmitInterval(timeout, configured time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}
	if timeout > 0 && timeout < 500*time.Millisecond {
		return timeout
	}
	return 500 * time.Millisecond
}

func sipMaxRetransmitInterval(timeout, configured time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}
	if timeout > 0 && timeout < 4*time.Second {
		return timeout
	}
	return 4 * time.Second
}

func nextSIPReadDeadline(deadline time.Time, interval time.Duration) time.Time {
	if interval <= 0 {
		return deadline
	}
	next := time.Now().Add(interval)
	if deadline.IsZero() || next.Before(deadline) {
		return next
	}
	return deadline
}

func nextSIPRetransmitInterval(interval, maxInterval time.Duration) time.Duration {
	if interval <= 0 {
		return maxInterval
	}
	next := interval * 2
	if maxInterval > 0 && next > maxInterval {
		return maxInterval
	}
	return next
}

func shouldSIPRetransmit(done, max int) bool {
	return max <= 0 || done < max
}

func isSIPTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isSIPRetryableTransportError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if isSIPTimeout(err) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr)
}

func sipURIAddr(uri string) (string, error) {
	endpoint, err := parseSIPURIEndpoint(uri)
	if err != nil {
		return "", err
	}
	return endpoint.addr(), nil
}

func canonicalHeaderName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "a":
		return "Accept-Contact"
	case "accept-contact":
		return "Accept-Contact"
	case "b":
		return "Referred-By"
	case "referred-by":
		return "Referred-By"
	case "d":
		return "Request-Disposition"
	case "request-disposition":
		return "Request-Disposition"
	case "e":
		return "Content-Encoding"
	case "content-encoding":
		return "Content-Encoding"
	case "i":
		return "Call-ID"
	case "call-id":
		return "Call-ID"
	case "j":
		return "Reject-Contact"
	case "reject-contact":
		return "Reject-Contact"
	case "k":
		return "Supported"
	case "supported":
		return "Supported"
	case "m":
		return "Contact"
	case "contact":
		return "Contact"
	case "o":
		return "Event"
	case "event":
		return "Event"
	case "r":
		return "Refer-To"
	case "refer-to":
		return "Refer-To"
	case "s":
		return "Subject"
	case "subject":
		return "Subject"
	case "u":
		return "Allow-Events"
	case "allow-events":
		return "Allow-Events"
	case "subscription-state":
		return "Subscription-State"
	case "x":
		return "Session-Expires"
	case "session-expires":
		return "Session-Expires"
	case "l":
		return "Content-Length"
	case "content-length":
		return "Content-Length"
	case "c":
		return "Content-Type"
	case "content-type":
		return "Content-Type"
	case "min-se":
		return "Min-SE"
	case "f":
		return "From"
	case "t":
		return "To"
	case "v":
		return "Via"
	case "www-authenticate":
		return "WWW-Authenticate"
	case "proxy-authenticate":
		return "Proxy-Authenticate"
	case "p-associated-uri":
		return "P-Associated-URI"
	case "p-preferred-identity":
		return "P-Preferred-Identity"
	case "p-access-network-info":
		return "P-Access-Network-Info"
	case "service-route":
		return "Service-Route"
	case "security-server":
		return "Security-Server"
	case "security-client":
		return "Security-Client"
	case "security-verify":
		return "Security-Verify"
	default:
		parts := strings.Split(name, "-")
		for i, part := range parts {
			if part == "" {
				continue
			}
			parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
		}
		return strings.Join(parts, "-")
	}
}

func firstHeaderValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
