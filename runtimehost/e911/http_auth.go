package e911

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// HTTPAuthenticationChallenge is a parsed WWW-Authenticate or Proxy-Authenticate value.
type HTTPAuthenticationChallenge struct {
	Header string
	Scheme string
	Params map[string]string
	Raw    string
}

// HTTPAuthenticationChallengeError reports an E911 HTTP auth challenge that has
// been parsed but not answered yet.
type HTTPAuthenticationChallengeError struct {
	StatusCode int
	Challenges []HTTPAuthenticationChallenge
}

func (e *HTTPAuthenticationChallengeError) Error() string {
	if e == nil {
		return ErrChallengeNotImplemented.Error()
	}
	schemes := httpAuthenticationChallengeSchemes(e.Challenges)
	if len(schemes) == 0 {
		return fmt.Sprintf("e911 HTTP status %d authentication challenge not implemented", e.StatusCode)
	}
	return fmt.Sprintf("e911 HTTP status %d authentication challenge not implemented (%s)", e.StatusCode, strings.Join(schemes, ", "))
}

func (e *HTTPAuthenticationChallengeError) Unwrap() error {
	return ErrChallengeNotImplemented
}

func httpAuthenticationChallengeError(resp *HTTPResponse) error {
	if resp == nil || !httpStatusCanCarryAuthenticationChallenge(resp.StatusCode) {
		return nil
	}
	challenges := httpAuthenticationChallenges(resp.StatusCode, resp.Headers)
	if len(challenges) == 0 {
		return nil
	}
	return &HTTPAuthenticationChallengeError{
		StatusCode: resp.StatusCode,
		Challenges: challenges,
	}
}

func httpStatusCanCarryAuthenticationChallenge(statusCode int) bool {
	return statusCode == http.StatusUnauthorized || statusCode == http.StatusProxyAuthRequired
}

func httpAuthenticationChallenges(statusCode int, headers []HeaderPair) []HTTPAuthenticationChallenge {
	var out []HTTPAuthenticationChallenge
	for _, header := range headers {
		if !isHTTPAuthenticationChallengeHeader(statusCode, header.Key) {
			continue
		}
		for _, raw := range splitHTTPAuthenticateChallenges(header.Value) {
			if challenge, ok := parseHTTPAuthenticationChallenge(header.Key, raw); ok {
				out = append(out, challenge)
			}
		}
	}
	return out
}

func isHTTPAuthenticationChallengeHeader(statusCode int, name string) bool {
	switch http.CanonicalHeaderKey(strings.TrimSpace(name)) {
	case "Www-Authenticate":
		return statusCode == http.StatusUnauthorized
	case "Proxy-Authenticate":
		return statusCode == http.StatusProxyAuthRequired
	default:
		return false
	}
}

func parseHTTPAuthenticationChallenge(headerName, raw string) (HTTPAuthenticationChallenge, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return HTTPAuthenticationChallenge{}, false
	}
	scheme := raw
	rest := ""
	for i := 0; i < len(raw); i++ {
		if raw[i] == ' ' || raw[i] == '\t' {
			scheme = strings.TrimSpace(raw[:i])
			rest = strings.TrimSpace(raw[i+1:])
			break
		}
	}
	if scheme == "" {
		return HTTPAuthenticationChallenge{}, false
	}
	challenge := HTTPAuthenticationChallenge{
		Header: http.CanonicalHeaderKey(strings.TrimSpace(headerName)),
		Scheme: scheme,
		Raw:    raw,
	}
	if params := parseHTTPAuthParams(rest); len(params) > 0 {
		challenge.Params = params
	}
	return challenge, true
}

func parseHTTPAuthParams(s string) map[string]string {
	params := make(map[string]string)
	for _, part := range splitHTTPAuthParams(s) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		setHTTPAuthParam(params, key, unquoteHTTPAuthValue(value))
	}
	if len(params) == 0 {
		return nil
	}
	return params
}

func setHTTPAuthParam(params map[string]string, key, value string) {
	if params == nil || key == "" {
		return
	}
	if previous, ok := params[key]; ok {
		params[key] = mergeHTTPAuthParam(key, previous, value)
		return
	}
	params[key] = value
}

func mergeHTTPAuthParam(key, previous, value string) string {
	if strings.TrimSpace(value) == "" {
		return previous
	}
	switch key {
	case "qop":
		return mergeHTTPAuthTokenList(previous, value)
	case "stale":
		if strings.EqualFold(previous, "true") || strings.EqualFold(value, "true") {
			return "true"
		}
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return value
	}
}

func mergeHTTPAuthTokenList(values ...string) string {
	var out []string
	seen := make(map[string]bool)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			token := strings.TrimSpace(part)
			key := strings.ToLower(token)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, token)
		}
	}
	return strings.Join(out, ",")
}

func splitHTTPAuthParams(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			cur.WriteRune(r)
			escaped = true
		case r == '"':
			cur.WriteRune(r)
			inQuote = !inQuote
		case r == ',' && !inQuote:
			if part := strings.TrimSpace(cur.String()); part != "" {
				out = append(out, part)
			}
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if part := strings.TrimSpace(cur.String()); part != "" {
		out = append(out, part)
	}
	return out
}

func splitHTTPAuthenticateChallenges(header string) []string {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil
	}
	var out []string
	start := 0
	inQuote := false
	escaped := false
	for i := 0; i < len(header); i++ {
		switch header[i] {
		case '\\':
			if inQuote && !escaped {
				escaped = true
				continue
			}
			escaped = false
		case '"':
			if !escaped {
				inQuote = !inQuote
			}
			escaped = false
		case ',':
			if !inQuote && httpAuthChallengeStarts(header[i+1:]) {
				if part := strings.TrimSpace(header[start:i]); part != "" {
					out = append(out, part)
				}
				start = i + 1
			}
			escaped = false
		default:
			escaped = false
		}
	}
	if part := strings.TrimSpace(header[start:]); part != "" {
		out = append(out, part)
	}
	return out
}

func httpAuthChallengeStarts(s string) bool {
	s = strings.TrimLeft(s, " \t")
	end := 0
	for end < len(s) && isHTTPAuthTokenChar(s[end]) {
		end++
	}
	if end == 0 || end >= len(s) {
		return false
	}
	if s[end] != ' ' && s[end] != '\t' {
		return false
	}
	rest := strings.TrimLeft(s[end:], " \t")
	return rest != "" && rest[0] != '='
}

func isHTTPAuthTokenChar(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func unquoteHTTPAuthValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return value
	}
	var out strings.Builder
	escaped := false
	for _, r := range value[1 : len(value)-1] {
		if escaped {
			out.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		out.WriteRune(r)
	}
	if escaped {
		out.WriteRune('\\')
	}
	return out.String()
}

func quoteHTTPAuthValue(value string) string {
	var out strings.Builder
	for _, r := range value {
		if r == '\\' || r == '"' {
			out.WriteRune('\\')
		}
		out.WriteRune(r)
	}
	return out.String()
}

func httpAuthenticationChallengeSchemes(challenges []HTTPAuthenticationChallenge) []string {
	seen := make(map[string]string)
	for _, challenge := range challenges {
		scheme := strings.TrimSpace(challenge.Scheme)
		if scheme == "" {
			continue
		}
		key := strings.ToLower(scheme)
		if _, ok := seen[key]; !ok {
			seen[key] = scheme
		}
	}
	out := make([]string, 0, len(seen))
	for _, scheme := range seen {
		out = append(out, scheme)
	}
	sort.Strings(out)
	return out
}

func responseHeaderPairs(headers http.Header) []HeaderPair {
	if len(headers) == 0 {
		return nil
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []HeaderPair
	for _, name := range names {
		for _, value := range headers[name] {
			out = append(out, HeaderPair{Key: name, Value: value})
		}
	}
	return out
}
