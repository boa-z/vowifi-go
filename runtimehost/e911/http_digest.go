package e911

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/boa-z/vowifi-go/engine/sim"
	"github.com/boa-z/vowifi-go/runtimehost/voiceclient"
)

const maxEntitlementHTTPDigestRetries = 2

func doEntitlementWithHTTPDigest(ctx context.Context, client HTTPClient, trace TraceSink, httpReq *HTTPRequest, req Request) (*HTTPResponse, error) {
	current := cloneHTTPRequest(httpReq)
	for attempt := 0; ; attempt++ {
		resp, err := doEntitlement(ctx, client, trace, current)
		if err == nil {
			return resp, nil
		}
		var challengeErr *HTTPAuthenticationChallengeError
		if !errors.As(err, &challengeErr) || attempt >= maxEntitlementHTTPDigestRetries {
			return nil, err
		}
		auth, syncFailure, stale, buildErr := buildEntitlementHTTPDigestAuthorization(current, req, challengeErr)
		if buildErr != nil {
			if errors.Is(buildErr, ErrChallengeNotImplemented) {
				return nil, err
			}
			return nil, buildErr
		}
		current = entitlementRequestWithAuthorization(current, auth)
		if !syncFailure && !stale {
			resp, err = doEntitlement(ctx, client, trace, current)
			if err == nil {
				return resp, nil
			}
			return nil, err
		}
	}
}

type entitlementHTTPDigestAuthorization struct {
	HeaderName string
	Value      string
}

func buildEntitlementHTTPDigestAuthorization(httpReq *HTTPRequest, req Request, challengeErr *HTTPAuthenticationChallengeError) (entitlementHTTPDigestAuthorization, bool, bool, error) {
	if challengeErr == nil {
		return entitlementHTTPDigestAuthorization{}, false, false, ErrChallengeNotImplemented
	}
	challengeHeader, authHeader := entitlementHTTPDigestHeaderNames(challengeErr.StatusCode)
	headers := entitlementHTTPDigestChallengeHeaders(challengeErr.Challenges, challengeHeader)
	challenge, err := voiceclient.SelectDigestChallenge(headers, challengeHeader)
	if err != nil {
		return entitlementHTTPDigestAuthorization{}, false, false, fmt.Errorf("%w: %v", ErrChallengeNotImplemented, err)
	}
	challenge = entitlementHTTPDigestNormalizeChallenge(challenge)
	input, syncFailure, err := entitlementHTTPDigestInput(httpReq, req, challenge)
	if err != nil {
		return entitlementHTTPDigestAuthorization{}, false, false, err
	}
	value, err := voiceclient.BuildDigestAuthorization(challenge, input)
	if err != nil {
		return entitlementHTTPDigestAuthorization{}, false, false, err
	}
	return entitlementHTTPDigestAuthorization{
		HeaderName: authHeader,
		Value:      value,
	}, syncFailure, challenge.Stale, nil
}

func entitlementHTTPDigestInput(httpReq *HTTPRequest, req Request, challenge voiceclient.DigestChallenge) (voiceclient.DigestAuthInput, bool, error) {
	input := voiceclient.DigestAuthInput{
		Method:   firstNonEmpty(httpReq.Method, http.MethodGet),
		URI:      entitlementHTTPDigestURI(httpReq.URL),
		Username: entitlementHTTPDigestUsername(req.Identity),
		NC:       1,
		Body:     append([]byte(nil), httpReq.Body...),
	}
	if strings.TrimSpace(input.Username) == "" {
		return input, false, fmt.Errorf("%w: missing E911 digest identity", ErrChallengeNotImplemented)
	}
	cnonce, err := entitlementHTTPDigestCNonce(req)
	if err != nil {
		return input, false, err
	}
	input.CNonce = cnonce
	if !entitlementHTTPDigestUsesAKA(challenge.Algorithm) {
		return input, false, fmt.Errorf("%w: E911 HTTP digest algorithm %q requires password material", ErrChallengeNotImplemented, challenge.Algorithm)
	}
	rand16, autn16, ok := voiceclient.ExtractAKAChallengeNonce(challenge.Nonce)
	if !ok {
		return input, false, fmt.Errorf("%w: invalid E911 digest AKA nonce", ErrChallengeNotImplemented)
	}
	if req.AKAProvider == nil {
		return input, false, fmt.Errorf("%w: AKA provider required for E911 HTTP digest", ErrChallengeNotImplemented)
	}
	aka, err := req.AKAProvider.CalculateAKA(rand16, autn16)
	if errors.Is(err, sim.ErrSyncFailure) {
		if len(aka.AUTS) == 0 {
			return input, false, err
		}
		input.AUTS = append([]byte(nil), aka.AUTS...)
		return input, true, nil
	}
	if err != nil {
		return input, false, err
	}
	password, err := voiceclient.BuildAKADigestPassword(challenge.Algorithm, aka)
	if err != nil {
		return input, false, err
	}
	input.Password = password
	return input, false, nil
}

func entitlementHTTPDigestHeaderNames(statusCode int) (challengeHeader, authHeader string) {
	if statusCode == http.StatusProxyAuthRequired {
		return "Proxy-Authenticate", "Proxy-Authorization"
	}
	return "WWW-Authenticate", "Authorization"
}

func entitlementHTTPDigestChallengeHeaders(challenges []HTTPAuthenticationChallenge, headerName string) map[string][]string {
	var values []string
	for _, challenge := range challenges {
		if strings.EqualFold(challenge.Header, headerName) && strings.TrimSpace(challenge.Raw) != "" {
			values = append(values, entitlementHTTPDigestChallengeValue(challenge))
		}
	}
	if len(values) == 0 {
		return nil
	}
	return map[string][]string{headerName: values}
}

func entitlementHTTPDigestChallengeValue(challenge HTTPAuthenticationChallenge) string {
	if !strings.EqualFold(strings.TrimSpace(challenge.Scheme), "Digest") {
		return challenge.Raw
	}
	if len(challenge.Params) == 0 {
		return challenge.Raw
	}
	realm := strings.TrimSpace(challenge.Params["realm"])
	nonce := strings.TrimSpace(challenge.Params["nonce"])
	if realm == "" || nonce == "" {
		return challenge.Raw
	}
	algorithm := entitlementHTTPDigestCanonicalAlgorithm(challenge.Params["algorithm"])
	qop := entitlementHTTPDigestCanonicalQOP(challenge.Params["qop"])
	parts := []string{
		`Digest realm="` + quoteHTTPAuthValue(realm) + `"`,
		`nonce="` + quoteHTTPAuthValue(nonce) + `"`,
	}
	if algorithm != "" {
		parts = append(parts, `algorithm=`+algorithm)
	}
	if qop != "" {
		parts = append(parts, `qop="`+quoteHTTPAuthValue(qop)+`"`)
	}
	if opaque := challenge.Params["opaque"]; opaque != "" {
		parts = append(parts, `opaque="`+quoteHTTPAuthValue(opaque)+`"`)
	}
	if stale := entitlementHTTPDigestCanonicalStale(challenge.Params["stale"]); stale != "" {
		parts = append(parts, `stale=`+stale)
	}
	return strings.Join(parts, ", ")
}

func entitlementHTTPDigestNormalizeChallenge(challenge voiceclient.DigestChallenge) voiceclient.DigestChallenge {
	if strings.EqualFold(strings.TrimSpace(challenge.Scheme), "Digest") || strings.TrimSpace(challenge.Scheme) == "" {
		challenge.Scheme = "Digest"
	}
	if algorithm := entitlementHTTPDigestCanonicalAlgorithm(challenge.Algorithm); algorithm != "" {
		challenge.Algorithm = algorithm
	}
	challenge.QOP = entitlementHTTPDigestCanonicalQOP(challenge.QOP)
	return challenge
}

func entitlementHTTPDigestCanonicalAlgorithm(algorithm string) string {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "":
		return ""
	case "AKAV1-MD5":
		return "AKAv1-MD5"
	case "AKAV2-MD5":
		return "AKAv2-MD5"
	case "MD5":
		return "MD5"
	case "MD5-SESS":
		return "MD5-sess"
	case "SHA-256":
		return "SHA-256"
	case "SHA-256-SESS":
		return "SHA-256-sess"
	case "SHA-512-256":
		return "SHA-512-256"
	case "SHA-512-256-SESS":
		return "SHA-512-256-sess"
	default:
		return strings.TrimSpace(algorithm)
	}
}

func entitlementHTTPDigestCanonicalQOP(qop string) string {
	for _, part := range strings.Split(qop, ",") {
		if strings.EqualFold(strings.TrimSpace(part), "auth") {
			return "auth"
		}
	}
	for _, part := range strings.Split(qop, ",") {
		if strings.EqualFold(strings.TrimSpace(part), "auth-int") {
			return "auth-int"
		}
	}
	return strings.ToLower(strings.TrimSpace(qop))
}

func entitlementHTTPDigestCanonicalStale(stale string) string {
	stale = strings.TrimSpace(stale)
	if stale == "" {
		return ""
	}
	if strings.EqualFold(stale, "true") {
		return "true"
	}
	if strings.EqualFold(stale, "false") {
		return "false"
	}
	return strings.ToLower(stale)
}

func entitlementHTTPDigestAuthenticationInfoParams(headers []HeaderPair, authHeaderName string) map[string]string {
	for _, name := range entitlementHTTPDigestAuthenticationInfoHeaderNames(authHeaderName) {
		params := make(map[string]string)
		for _, header := range headers {
			if !strings.EqualFold(header.Key, name) {
				continue
			}
			for _, part := range splitHTTPAuthParams(header.Value) {
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
		}
		if len(params) > 0 {
			return params
		}
	}
	return nil
}

func entitlementHTTPDigestNextNonce(headers []HeaderPair, authHeaderName string) string {
	return entitlementHTTPDigestAuthenticationInfoParams(headers, authHeaderName)["nextnonce"]
}

func entitlementHTTPDigestAuthenticationInfoHeaderNames(authHeaderName string) []string {
	if strings.EqualFold(strings.TrimSpace(authHeaderName), "Proxy-Authorization") {
		return []string{"Proxy-Authentication-Info", "Authentication-Info"}
	}
	return []string{"Authentication-Info", "Proxy-Authentication-Info"}
}

func entitlementHTTPDigestUsername(identity Identity) string {
	return firstNonEmpty(identity.SIPUsername, identity.IMSI)
}

func entitlementHTTPDigestUsesAKA(algorithm string) bool {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "AKAV1-MD5", "AKAV2-MD5":
		return true
	default:
		return false
	}
}

func entitlementHTTPDigestURI(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return strings.TrimSpace(rawURL)
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	return path
}

func entitlementHTTPDigestCNonce(req Request) (string, error) {
	raw, err := entitlementRandomBytes(req.Random, 16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func entitlementRequestWithAuthorization(req *HTTPRequest, auth entitlementHTTPDigestAuthorization) *HTTPRequest {
	next := cloneHTTPRequest(req)
	next.Headers = replaceHeader(next.Headers, auth.HeaderName, auth.Value)
	return next
}

func cloneHTTPRequest(req *HTTPRequest) *HTTPRequest {
	if req == nil {
		return &HTTPRequest{}
	}
	return &HTTPRequest{
		Method:  req.Method,
		URL:     req.URL,
		Headers: append([]HeaderPair(nil), req.Headers...),
		Body:    append([]byte(nil), req.Body...),
	}
}

func replaceHeader(headers []HeaderPair, name, value string) []HeaderPair {
	out := make([]HeaderPair, 0, len(headers)+1)
	for _, header := range headers {
		if strings.EqualFold(header.Key, name) {
			continue
		}
		out = append(out, header)
	}
	if strings.TrimSpace(name) != "" && strings.TrimSpace(value) != "" {
		out = append(out, HeaderPair{Key: name, Value: value})
	}
	return out
}
