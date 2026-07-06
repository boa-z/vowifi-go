package voiceclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type SIPServerResolver interface {
	ResolveSIPServer(context.Context, string, string) (string, error)
}

type SIPServerResolverFunc func(context.Context, string, string) (string, error)

func (f SIPServerResolverFunc) ResolveSIPServer(ctx context.Context, network, uri string) (string, error) {
	return f(ctx, network, uri)
}

type SIPServerCandidateResolver interface {
	ResolveSIPServers(context.Context, string, string) ([]string, error)
}

type SIPServerCandidateResolverFunc func(context.Context, string, string) ([]string, error)

func (f SIPServerCandidateResolverFunc) ResolveSIPServers(ctx context.Context, network, uri string) ([]string, error) {
	return f(ctx, network, uri)
}

func (f SIPServerCandidateResolverFunc) ResolveSIPServer(ctx context.Context, network, uri string) (string, error) {
	addrs, err := f.ResolveSIPServers(ctx, network, uri)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", errSIPDNSResolverEmpty()
	}
	return strings.TrimSpace(addrs[0]), nil
}

type NetSIPResolver struct {
	Resolver   *net.Resolver
	DNSServers []string
	Timeout    time.Duration
}

func (r NetSIPResolver) ResolveSIPServer(ctx context.Context, network, uri string) (string, error) {
	addrs, err := r.ResolveSIPServers(ctx, network, uri)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", errSIPDNSResolverEmpty()
	}
	return addrs[0], nil
}

func (r NetSIPResolver) ResolveSIPServers(ctx context.Context, network, uri string) ([]string, error) {
	endpoint, err := parseSIPURIEndpoint(uri)
	if err != nil {
		return nil, err
	}
	if endpoint.ExplicitPort || net.ParseIP(strings.Trim(endpoint.Host, "[]")) != nil {
		return []string{endpoint.addr()}, nil
	}
	resolver := r.Resolver
	if resolver == nil {
		resolver = DNSResolverForServers(r.DNSServers, r.Timeout)
	}
	service := "sip"
	if endpoint.Secure {
		service = "sips"
	}
	var out []string
	_, records, err := resolver.LookupSRV(ctx, service, sipResolverProto(network, endpoint.Secure), endpoint.Host)
	if err == nil && len(records) > 0 {
		for _, record := range records {
			target := strings.TrimSuffix(strings.TrimSpace(record.Target), ".")
			if target == "" {
				continue
			}
			port := strconv.Itoa(int(record.Port))
			if addrs := resolveSIPHostAddrs(ctx, resolver, network, target, port); len(addrs) > 0 {
				out = appendSIPTargets(out, addrs...)
				continue
			}
			out = appendSIPTargets(out, net.JoinHostPort(strings.Trim(target, "[]"), port))
		}
	}
	if addrs := resolveSIPHostAddrs(ctx, resolver, network, endpoint.Host, endpoint.Port); len(addrs) > 0 {
		out = appendSIPTargets(out, addrs...)
	}
	if len(out) == 0 {
		out = appendSIPTargets(out, endpoint.addr())
	}
	return out, nil
}

func ResolveSIPServer(ctx context.Context, network, uri string) (string, error) {
	return NetSIPResolver{}.ResolveSIPServer(ctx, network, uri)
}

func ResolveSIPServers(ctx context.Context, network, uri string) ([]string, error) {
	return NetSIPResolver{}.ResolveSIPServers(ctx, network, uri)
}

func DNSResolverForServers(servers []string, timeout time.Duration) *net.Resolver {
	addrs := normalizeDNSServerAddrs(servers)
	if len(addrs) == 0 {
		return net.DefaultResolver
	}
	var next uint64
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			_ = address
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
			start := int(atomic.AddUint64(&next, 1)-1) % len(addrs)
			var lastErr error
			dialer := net.Dialer{}
			for i := 0; i < len(addrs); i++ {
				addr := addrs[(start+i)%len(addrs)]
				conn, err := dialer.DialContext(ctx, network, addr)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, errSIPDNSResolverEmpty()
		},
	}
}

func appendSIPTargets(out []string, targets ...string) []string {
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target != "" {
			duplicate := false
			for _, existing := range out {
				if existing == target {
					duplicate = true
					break
				}
			}
			if !duplicate {
				out = append(out, target)
			}
		}
	}
	return out
}

func normalizeDNSServerAddrs(servers []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, server := range servers {
		addr := normalizeDNSServerAddr(server)
		if addr == "" || seen[addr] {
			continue
		}
		out = append(out, addr)
		seen[addr] = true
	}
	return out
}

func normalizeDNSServerAddr(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	if host, port, err := net.SplitHostPort(server); err == nil {
		if strings.TrimSpace(port) == "" {
			port = "53"
		}
		return net.JoinHostPort(strings.Trim(host, "[] "), port)
	}
	if strings.HasPrefix(server, "[") {
		end := strings.IndexByte(server, ']')
		if end < 0 {
			return ""
		}
		host := strings.TrimSpace(server[1:end])
		rest := strings.TrimSpace(server[end+1:])
		if strings.HasPrefix(rest, ":") {
			port := strings.TrimSpace(rest[1:])
			if port == "" {
				port = "53"
			}
			return net.JoinHostPort(host, port)
		}
		return net.JoinHostPort(host, "53")
	}
	if ip := net.ParseIP(server); ip != nil {
		return net.JoinHostPort(ip.String(), "53")
	}
	if idx := strings.LastIndex(server, ":"); idx > 0 && !strings.Contains(server[idx+1:], ":") {
		host := strings.TrimSpace(server[:idx])
		port := strings.TrimSpace(server[idx+1:])
		if host == "" {
			return ""
		}
		if port == "" {
			port = "53"
		}
		return net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	return net.JoinHostPort(strings.Trim(server, "[]"), "53")
}

func resolveSIPServerAddr(ctx context.Context, resolver SIPServerResolver, network, uri string) (string, error) {
	addrs, err := resolveSIPServerAddrs(ctx, resolver, network, uri)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", errSIPDNSResolverEmpty()
	}
	return addrs[0], nil
}

func resolveSIPServerAddrs(ctx context.Context, resolver SIPServerResolver, network, uri string) ([]string, error) {
	if resolver == nil {
		return NetSIPResolver{}.ResolveSIPServers(ctx, network, uri)
	}
	if candidateResolver, ok := resolver.(SIPServerCandidateResolver); ok {
		addrs, err := candidateResolver.ResolveSIPServers(ctx, network, uri)
		if err != nil {
			return nil, err
		}
		return appendSIPTargets(nil, addrs...), nil
	}
	addr, err := resolver.ResolveSIPServer(ctx, network, uri)
	if err != nil {
		return nil, err
	}
	return appendSIPTargets(nil, addr), nil
}

type sipURIEndpoint struct {
	Host         string
	Port         string
	Secure       bool
	ExplicitPort bool
}

func (e sipURIEndpoint) addr() string {
	return net.JoinHostPort(strings.Trim(e.Host, "[]"), e.Port)
}

func parseSIPURIEndpoint(uri string) (sipURIEndpoint, error) {
	original := strings.TrimSpace(uri)
	uri = extractSIPURIForEndpoint(original)
	if uri == "" {
		return sipURIEndpoint{}, errSIPURIEmpty()
	}
	lower := strings.ToLower(uri)
	secure := false
	if strings.HasPrefix(lower, "sip:") {
		uri = uri[4:]
	} else if strings.HasPrefix(lower, "sips:") {
		uri = uri[5:]
		secure = true
	} else {
		return sipURIEndpoint{}, errUnsupportedSIPURI(uri)
	}
	if q := strings.IndexByte(uri, '?'); q >= 0 {
		uri = uri[:q]
	}
	if at := strings.LastIndexByte(uri, '@'); at >= 0 {
		uri = uri[at+1:]
	}
	if semi := strings.IndexByte(uri, ';'); semi >= 0 {
		uri = uri[:semi]
	}
	rawHostPort := strings.TrimSpace(uri)
	defaultPort := "5060"
	if secure {
		defaultPort = "5061"
	}
	host := strings.Trim(rawHostPort, "[] ")
	port := defaultPort
	explicitPort := false
	if strings.HasPrefix(rawHostPort, "[") {
		end := strings.IndexByte(rawHostPort, ']')
		if end < 0 {
			return sipURIEndpoint{}, errInvalidSIPURIHost(rawHostPort)
		}
		host = strings.TrimSpace(rawHostPort[1:end])
		if rest := strings.TrimSpace(rawHostPort[end+1:]); strings.HasPrefix(rest, ":") {
			port = strings.TrimSpace(rest[1:])
			explicitPort = true
		} else if rest != "" {
			return sipURIEndpoint{}, errInvalidSIPURIHost(rawHostPort)
		}
	} else if h, p, err := net.SplitHostPort(rawHostPort); err == nil {
		host = strings.Trim(h, "[]")
		port = p
		explicitPort = true
	} else if ip := net.ParseIP(rawHostPort); ip != nil {
		host = ip.String()
	} else if idx := strings.LastIndex(rawHostPort, ":"); idx > 0 && strings.Count(rawHostPort, ":") == 1 {
		host = strings.Trim(rawHostPort[:idx], "[] ")
		port = strings.TrimSpace(rawHostPort[idx+1:])
		explicitPort = true
	}
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		return sipURIEndpoint{}, errSIPURIHostEmpty(rawHostPort)
	}
	if port == "" {
		port = defaultPort
	}
	return sipURIEndpoint{Host: host, Port: port, Secure: secure, ExplicitPort: explicitPort}, nil
}

func extractSIPURIForEndpoint(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := splitSIPHeaderValues(value)
	if len(parts) == 0 {
		parts = []string{value}
	}
	var first string
	for _, part := range parts {
		uri, sip := sipURIFromHeaderPart(part)
		if uri == "" {
			continue
		}
		if first == "" {
			first = uri
		}
		if sip {
			return uri
		}
	}
	return first
}

func sipURIFromHeaderPart(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	if hasSIPURIScheme(value) {
		return trimSIPURIHeaderTail(value), true
	}
	if start := strings.IndexByte(value, '<'); start >= 0 {
		if end := strings.IndexByte(value[start+1:], '>'); end >= 0 {
			uri := trimSIPURIHeaderTail(value[start+1 : start+1+end])
			return uri, hasSIPURIScheme(uri)
		}
		uri := trimSIPURIHeaderTail(value[start+1:])
		return uri, hasSIPURIScheme(uri)
	}
	value = strings.Trim(strings.TrimSpace(value), "\"'")
	if hasSIPURIScheme(value) {
		return trimSIPURIHeaderTail(value), true
	}
	if idx := sipURISchemeIndex(value); idx >= 0 {
		uri := trimSIPURIHeaderTail(value[idx:])
		return uri, true
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return "", false
	}
	uri := trimSIPURIHeaderTail(fields[0])
	return uri, hasSIPURIScheme(uri)
}

func trimSIPURIHeaderTail(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "<>\"'")
	if end := strings.IndexByte(value, '>'); end >= 0 {
		value = value[:end]
	}
	if fields := strings.Fields(value); len(fields) > 0 {
		value = fields[0]
	}
	return strings.Trim(strings.TrimSpace(value), "<>\"'")
}

func hasSIPURIScheme(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:")
}

func sipURISchemeIndex(value string) int {
	lower := strings.ToLower(value)
	best := -1
	for _, scheme := range []string{"sips:", "sip:"} {
		for offset := 0; offset < len(lower); {
			idx := strings.Index(lower[offset:], scheme)
			if idx < 0 {
				break
			}
			idx += offset
			if sipSchemeBoundary(value, idx) && (best < 0 || idx < best) {
				best = idx
				break
			}
			offset = idx + 1
		}
	}
	return best
}

func sipSchemeBoundary(value string, idx int) bool {
	if idx <= 0 {
		return true
	}
	switch value[idx-1] {
	case '<', '"', '\'', ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}

func sipResolverProto(network string, secure bool) string {
	if secure {
		return "tcp"
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(network)), "tcp") {
		return "tcp"
	}
	return "udp"
}

func resolveSIPHostAddr(ctx context.Context, resolver *net.Resolver, network, host, port string) string {
	addrs := resolveSIPHostAddrs(ctx, resolver, network, host, port)
	if len(addrs) == 0 {
		return ""
	}
	return addrs[0]
}

func resolveSIPHostAddrs(ctx context.Context, resolver *net.Resolver, network, host, port string) []string {
	if resolver == nil {
		return nil
	}
	addrs, err := resolver.LookupIPAddr(ctx, strings.Trim(host, "[]"))
	if err != nil {
		return nil
	}
	prefer6 := strings.HasSuffix(strings.ToLower(strings.TrimSpace(network)), "6")
	prefer4 := strings.HasSuffix(strings.ToLower(strings.TrimSpace(network)), "4")
	var preferred []string
	var fallback []string
	for _, addr := range addrs {
		ip := addr.IP
		if ip == nil {
			continue
		}
		target := net.JoinHostPort(ip.String(), port)
		if prefer4 && ip.To4() != nil {
			preferred = appendSIPTargets(preferred, target)
			continue
		}
		if prefer6 && ip.To4() == nil {
			preferred = appendSIPTargets(preferred, target)
			continue
		}
		fallback = appendSIPTargets(fallback, target)
	}
	return appendSIPTargets(preferred, fallback...)
}

func errSIPURIEmpty() error {
	return errors.New("SIP URI is empty")
}

func errUnsupportedSIPURI(uri string) error {
	return fmt.Errorf("unsupported SIP URI %q", uri)
}

func errInvalidSIPURIHost(uri string) error {
	return fmt.Errorf("invalid SIP URI host %q", uri)
}

func errSIPURIHostEmpty(uri string) error {
	return fmt.Errorf("SIP URI host is empty: %q", uri)
}

func errSIPDNSResolverEmpty() error {
	return errors.New("SIP DNS resolver has no servers")
}
