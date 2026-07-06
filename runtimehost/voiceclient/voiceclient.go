package voiceclient

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/iniwex5/vowifi-go/engine/sim"
)

var ErrInvalidChallenge = errors.New("invalid SIP digest challenge")
var ErrInvalidAuthenticationInfo = errors.New("invalid SIP digest authentication-info")
var ErrRegistrationRejected = errors.New("IMS registration rejected")

type IMSProfile struct {
	IMPI      string
	IMPU      string
	Domain    string
	LocalIP   string
	UserAgent string
}

type DigestChallenge struct {
	Scheme    string
	Realm     string
	Nonce     string
	Algorithm string
	QOP       string
	Opaque    string
	Stale     bool
}

type DigestAuthInput struct {
	Method   string
	URI      string
	Username string
	Password string
	CNonce   string
	NC       int
	Body     []byte
	AUTS     []byte
}

type DigestAuthState struct {
	challenge  DigestChallenge
	input      DigestAuthInput
	headerName string
	nextNC     int
	lastHeader string
}

type RegistrationBinding struct {
	ContactURI        string
	PublicIdentity    string
	AssociatedURIs    []string
	ServiceRoutes     []string
	Paths             []string
	SecurityClient    string
	SecurityServer    []string
	SecurityVerify    []string
	SecurityAgreement SecurityAgreement
	Expires           int
	RegistrarContact  string
}

type RegisterMessage struct {
	URI     string
	Headers map[string]string
	Body    []byte
}

type RegisterResponse struct {
	StatusCode int
	Reason     string
	Headers    map[string][]string
	Body       []byte
	RetryAfter time.Duration
}

type SIPRegisterTransport interface {
	RoundTripRegister(context.Context, RegisterMessage) (RegisterResponse, error)
}

type RegisterSession struct {
	Transport      SIPRegisterTransport
	AKAProvider    sim.AKAProvider
	Profile        IMSProfile
	RegistrarURI   string
	ContactURI     string
	CallID         string
	CNonce         string
	Expires        int
	SecurityClient SecurityAgreement
	SecurityRandom io.Reader
}

type RegisterResult struct {
	Registered     bool
	StatusCode     int
	Reason         string
	Attempts       int
	RetryAfter     time.Duration
	Challenge      DigestChallenge
	Binding        RegistrationBinding
	AuthHeader     string
	AuthHeaderName string
	AuthState      DigestAuthState
	NextCSeq       int
}

type DeregisterRequest struct {
	Binding        RegistrationBinding
	CallID         string
	CSeq           int
	AuthHeader     string
	AuthHeaderName string
	AuthState      DigestAuthState
}

type DeregisterResult struct {
	Deregistered bool
	StatusCode   int
	Reason       string
	Attempts     int
	RetryAfter   time.Duration
}

type RefreshRequest struct {
	Binding        RegistrationBinding
	CallID         string
	CSeq           int
	Expires        int
	AuthHeader     string
	AuthHeaderName string
	AuthState      DigestAuthState
}

type RefreshResult struct {
	Refreshed      bool
	StatusCode     int
	Reason         string
	Attempts       int
	RetryAfter     time.Duration
	Binding        RegistrationBinding
	AuthHeader     string
	AuthHeaderName string
	AuthState      DigestAuthState
	NextCSeq       int
}

func ParseWWWAuthenticate(header string) (DigestChallenge, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return DigestChallenge{}, ErrInvalidChallenge
	}
	scheme, rest, ok := strings.Cut(header, " ")
	if !ok {
		return DigestChallenge{}, ErrInvalidChallenge
	}
	ch := DigestChallenge{Scheme: strings.TrimSpace(scheme)}
	if !strings.EqualFold(ch.Scheme, "Digest") {
		return DigestChallenge{}, ErrInvalidChallenge
	}
	for _, part := range splitAuthParams(rest) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = unquote(strings.TrimSpace(value))
		switch key {
		case "realm":
			ch.Realm = value
		case "nonce":
			ch.Nonce = value
		case "algorithm":
			ch.Algorithm = value
		case "qop":
			ch.QOP = firstQOP(value)
		case "opaque":
			ch.Opaque = value
		case "stale":
			ch.Stale = strings.EqualFold(value, "true")
		}
	}
	if ch.Realm == "" || ch.Nonce == "" {
		return DigestChallenge{}, ErrInvalidChallenge
	}
	if ch.Algorithm == "" {
		ch.Algorithm = "MD5"
	}
	return ch, nil
}

func ExtractAKAChallengeNonce(nonce string) (rand16, autn16 []byte, ok bool) {
	raw, ok := decodeNonceBytes(nonce)
	if !ok || len(raw) < 32 {
		return nil, nil, false
	}
	return append([]byte(nil), raw[:16]...), append([]byte(nil), raw[16:32]...), true
}

func BuildDigestAuthorization(ch DigestChallenge, in DigestAuthInput) (string, error) {
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	uri := strings.TrimSpace(in.URI)
	username := strings.TrimSpace(in.Username)
	if method == "" || uri == "" || username == "" || ch.Realm == "" || ch.Nonce == "" {
		return "", ErrInvalidChallenge
	}
	algorithm := strings.TrimSpace(ch.Algorithm)
	if algorithm == "" {
		algorithm = "MD5"
	}
	if !strings.EqualFold(algorithm, "MD5") && !strings.EqualFold(algorithm, "AKAv1-MD5") && !strings.EqualFold(algorithm, "AKAv2-MD5") {
		return "", fmt.Errorf("unsupported digest algorithm %q", algorithm)
	}

	password := in.Password
	if len(in.AUTS) > 0 {
		password = ""
	}
	ha1 := md5Hex(username + ":" + ch.Realm + ":" + password)
	qop := firstQOP(ch.QOP)
	ha2 := ""
	switch qop {
	case "":
		ha2 = md5Hex(method + ":" + uri)
	case "auth":
		ha2 = md5Hex(method + ":" + uri)
	case "auth-int":
		ha2 = md5Hex(method + ":" + uri + ":" + md5HexBytes(in.Body))
	default:
		return "", fmt.Errorf("unsupported digest qop %q", qop)
	}
	response := ""
	nc := in.NC
	if nc <= 0 {
		nc = 1
	}
	ncText := fmt.Sprintf("%08x", nc)
	cnonce := strings.TrimSpace(in.CNonce)
	if qop != "" {
		if cnonce == "" {
			return "", errors.New("cnonce required when qop is present")
		}
		response = md5Hex(ha1 + ":" + ch.Nonce + ":" + ncText + ":" + cnonce + ":" + qop + ":" + ha2)
	} else {
		response = md5Hex(ha1 + ":" + ch.Nonce + ":" + ha2)
	}

	parts := []string{
		`Digest username="` + quote(username) + `"`,
		`realm="` + quote(ch.Realm) + `"`,
		`nonce="` + quote(ch.Nonce) + `"`,
		`uri="` + quote(uri) + `"`,
		`response="` + response + `"`,
		`algorithm=` + algorithm,
	}
	if ch.Opaque != "" {
		parts = append(parts, `opaque="`+quote(ch.Opaque)+`"`)
	}
	if qop != "" {
		parts = append(parts, `qop=`+qop, `nc=`+ncText, `cnonce="`+quote(cnonce)+`"`)
	}
	if len(in.AUTS) > 0 {
		parts = append(parts, `auts="`+base64.StdEncoding.EncodeToString(in.AUTS)+`"`)
	}
	return strings.Join(parts, ", "), nil
}

func (s DigestAuthState) Usable() bool {
	return strings.TrimSpace(s.challenge.Realm) != "" &&
		strings.TrimSpace(s.challenge.Nonce) != "" &&
		strings.TrimSpace(s.input.Username) != "" &&
		len(s.input.AUTS) == 0
}

func (s DigestAuthState) Build(method, uri string) (string, DigestAuthState, error) {
	if !s.Usable() {
		return "", s, ErrInvalidChallenge
	}
	next := s.clone()
	input := next.input
	if strings.TrimSpace(method) != "" {
		input.Method = strings.ToUpper(strings.TrimSpace(method))
	}
	if strings.TrimSpace(uri) != "" {
		input.URI = strings.TrimSpace(uri)
	}
	nc := next.nextNC
	if nc <= 0 {
		nc = input.NC
	}
	if nc <= 0 {
		nc = 1
	}
	input.NC = nc
	authz, err := BuildDigestAuthorization(next.challenge, input)
	if err != nil {
		return "", s, err
	}
	next.input = input
	next.input.AUTS = append([]byte(nil), input.AUTS...)
	next.nextNC = nc + 1
	next.lastHeader = authz
	return authz, next, nil
}

func (s DigestAuthState) clone() DigestAuthState {
	s.input = cloneDigestAuthInput(s.input)
	return s
}

func newDigestAuthState(headerName string, ch DigestChallenge, input DigestAuthInput, authz string) DigestAuthState {
	nextNC := input.NC + 1
	if nextNC <= 1 {
		nextNC = 2
	}
	return DigestAuthState{
		challenge:  ch,
		input:      cloneDigestAuthInput(input),
		headerName: firstNonEmpty(headerName, "Authorization"),
		nextNC:     nextNC,
		lastHeader: strings.TrimSpace(authz),
	}
}

func cloneDigestAuthInput(input DigestAuthInput) DigestAuthInput {
	input.Body = append([]byte(nil), input.Body...)
	input.AUTS = append([]byte(nil), input.AUTS...)
	return input
}

func BuildAKADigestPassword(algorithm string, aka sim.AKAResult) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "AKAV1-MD5":
		if len(aka.RES) == 0 {
			return "", errors.New("AKA RES is empty")
		}
		return string(aka.RES), nil
	case "AKAV2-MD5":
		if len(aka.RES) == 0 || len(aka.CK) == 0 || len(aka.IK) == 0 {
			return "", errors.New("AKA RES/CK/IK required for AKAv2-MD5")
		}
		key := make([]byte, 0, len(aka.RES)+len(aka.IK)+len(aka.CK))
		key = append(key, aka.RES...)
		key = append(key, aka.IK...)
		key = append(key, aka.CK...)
		mac := hmac.New(md5.New, key)
		_, _ = mac.Write([]byte("http-digest-akav2-password"))
		return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
	default:
		return "", fmt.Errorf("unsupported AKA digest algorithm %q", algorithm)
	}
}

func BuildRegisterHeaders(profile IMSProfile, contactURI, callID, cseq string) map[string]string {
	domain := strings.TrimSpace(profile.Domain)
	impu := strings.TrimSpace(profile.IMPU)
	if impu == "" && domain != "" {
		impu = "sip:" + strings.TrimSpace(profile.IMPI) + "@" + domain
	}
	headers := map[string]string{
		"To":                   "<" + impu + ">",
		"From":                 "<" + impu + ">;tag=vowifi-go",
		"Contact":              "<" + strings.TrimSpace(contactURI) + ">;+sip.instance=\"<urn:uuid:vowifi-go>\"",
		"Call-ID":              strings.TrimSpace(callID),
		"CSeq":                 strings.TrimSpace(cseq) + " REGISTER",
		"Max-Forwards":         "70",
		"User-Agent":           firstNonEmpty(profile.UserAgent, "vowifi-go"),
		"Allow":                "INVITE, ACK, CANCEL, BYE, PRACK, UPDATE, INFO, MESSAGE, OPTIONS",
		"Supported":            "path, gruu, outbound, sec-agree, 100rel, timer",
		"Require":              "sec-agree",
		"P-Preferred-Identity": "<" + impu + ">",
		"Security-Client":      BuildSecurityClientHeader(DefaultSecurityClientAgreement(nil)),
	}
	return headers
}

func (s RegisterSession) Register(ctx context.Context) (RegisterResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Transport == nil {
		return RegisterResult{}, errors.New("nil SIP register transport")
	}
	registrarURI := strings.TrimSpace(s.RegistrarURI)
	contactURI := strings.TrimSpace(s.ContactURI)
	if registrarURI == "" || contactURI == "" {
		return RegisterResult{}, errors.New("registrar URI and contact URI are required")
	}
	callID := firstNonEmpty(s.CallID, "vowifi-go-register")
	expires := s.Expires
	if expires <= 0 {
		expires = 3600
	}
	securityClient := s.securityClientAgreement()
	securityClientHeader := BuildSecurityClientHeader(securityClient)

	attempts := 0
	cseq := 1
	sendRegister := func(cseq int, authHeaderName, authz string, challengeHeaders map[string][]string) (RegisterResponse, error) {
		msg := RegisterMessage{
			URI:     registrarURI,
			Headers: BuildRegisterHeaders(s.Profile, contactURI, callID, strconv.Itoa(cseq)),
		}
		msg.Headers["Expires"] = strconv.Itoa(expires)
		msg.Headers["Security-Client"] = securityClientHeader
		if strings.TrimSpace(authHeaderName) != "" && strings.TrimSpace(authz) != "" {
			msg.Headers[authHeaderName] = authz
		}
		if securityVerify := securityVerifyFromChallenge(challengeHeaders); securityVerify != "" {
			msg.Headers["Security-Verify"] = securityVerify
		}
		attempts++
		return s.Transport.RoundTripRegister(ctx, cloneRegisterMessage(msg))
	}
	retryMinExpires := func(resp RegisterResponse, authHeaderName, authz string, challengeHeaders map[string][]string, authInput *DigestAuthInput, ch DigestChallenge) (RegisterResponse, string, bool, error) {
		if resp.StatusCode != 423 {
			return resp, authz, false, nil
		}
		minExpires := minExpiresHeader(resp.Headers)
		if minExpires <= expires {
			return resp, authz, false, nil
		}
		expires = minExpires
		nextAuthz := authz
		if authInput != nil {
			authInput.NC++
			var err error
			nextAuthz, err = BuildDigestAuthorization(ch, *authInput)
			if err != nil {
				return resp, authz, true, err
			}
		}
		cseq++
		nextResp, err := sendRegister(cseq, authHeaderName, nextAuthz, challengeHeaders)
		return nextResp, nextAuthz, true, err
	}

	resp, err := sendRegister(cseq, "", "", nil)
	if err != nil {
		return RegisterResult{}, err
	}
	resp, _, _, err = retryMinExpires(resp, "", "", nil, nil, DigestChallenge{})
	if err != nil {
		return RegisterResult{Attempts: attempts}, err
	}
	if isSIPSuccess(resp.StatusCode) {
		return RegisterResult{
			Registered: true,
			StatusCode: resp.StatusCode,
			Reason:     resp.Reason,
			Attempts:   attempts,
			Binding:    buildRegistrationBinding(s.Profile, contactURI, resp, expires, securityClient, nil),
			NextCSeq:   cseq + 1,
		}, nil
	}
	if resp.StatusCode != 401 && resp.StatusCode != 407 {
		return RegisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp)}, fmt.Errorf("%w: %d %s", ErrRegistrationRejected, resp.StatusCode, resp.Reason)
	}

	headerName := "WWW-Authenticate"
	authHeader := firstHeader(resp.Headers, headerName)
	authzHeader := "Authorization"
	if authHeader == "" {
		headerName = "Proxy-Authenticate"
		authHeader = firstHeader(resp.Headers, headerName)
		authzHeader = "Proxy-Authorization"
	}
	ch, err := SelectDigestChallenge(resp.Headers, headerName)
	if err != nil {
		return RegisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp)}, err
	}
	securityHeaders := resp.Headers

	authzInput, syncFailure, err := s.digestAuthInputForChallenge(ch, registrarURI)
	if err != nil {
		return RegisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp), Challenge: ch}, err
	}
	currentAuthInput := authzInput
	authz, err := BuildDigestAuthorization(ch, authzInput)
	if err != nil {
		return RegisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp), Challenge: ch}, err
	}

	cseq++
	resp2, err := sendRegister(cseq, authzHeader, authz, resp.Headers)
	if err != nil {
		return RegisterResult{Attempts: attempts, Challenge: ch}, err
	}
	resp2, authz, _, err = retryMinExpires(resp2, authzHeader, authz, resp.Headers, &authzInput, ch)
	if err != nil {
		return RegisterResult{Attempts: attempts, Challenge: ch, AuthHeader: authz}, err
	}
	currentAuthInput = authzInput
	if syncFailure {
		if isSIPSuccess(resp2.StatusCode) {
			authState := newDigestAuthState(authzHeader, ch, currentAuthInput, authz)
			authState, err = updateDigestAuthStateFromInfo(authState, resp2.Headers, authzHeader, resp2.Body)
			result := RegisterResult{
				Registered:     true,
				StatusCode:     resp2.StatusCode,
				Reason:         resp2.Reason,
				Attempts:       attempts,
				Challenge:      ch,
				Binding:        buildRegistrationBinding(s.Profile, contactURI, resp2, expires, securityClient, securityHeaders),
				AuthHeader:     authz,
				AuthHeaderName: authzHeader,
				AuthState:      authState,
				NextCSeq:       cseq + 1,
			}
			if err != nil {
				result.Registered = false
				return result, err
			}
			return result, nil
		}
		if resp2.StatusCode != 401 && resp2.StatusCode != 407 {
			return RegisterResult{StatusCode: resp2.StatusCode, Reason: resp2.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp2), Challenge: ch, AuthHeader: authz}, fmt.Errorf("%w: %d %s", ErrRegistrationRejected, resp2.StatusCode, resp2.Reason)
		}
		nextHeaderName := "WWW-Authenticate"
		nextAuthzHeader := "Authorization"
		if firstHeader(resp2.Headers, nextHeaderName) == "" {
			nextHeaderName = "Proxy-Authenticate"
			nextAuthzHeader = "Proxy-Authorization"
		}
		nextChallenge, err := SelectDigestChallenge(resp2.Headers, nextHeaderName)
		if err != nil {
			return RegisterResult{StatusCode: resp2.StatusCode, Reason: resp2.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp2), Challenge: ch, AuthHeader: authz}, err
		}
		nextAuthInput, nextSyncFailure, err := s.digestAuthInputForChallenge(nextChallenge, registrarURI)
		if err != nil {
			return RegisterResult{StatusCode: resp2.StatusCode, Reason: resp2.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp2), Challenge: nextChallenge, AuthHeader: authz}, err
		}
		if nextSyncFailure {
			return RegisterResult{StatusCode: resp2.StatusCode, Reason: resp2.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp2), Challenge: nextChallenge, AuthHeader: authz}, sim.ErrSyncFailure
		}
		authz, err = BuildDigestAuthorization(nextChallenge, nextAuthInput)
		if err != nil {
			return RegisterResult{StatusCode: resp2.StatusCode, Reason: resp2.Reason, Attempts: attempts, Challenge: nextChallenge, AuthHeader: authz}, err
		}
		ch = nextChallenge
		authzHeader = nextAuthzHeader
		currentAuthInput = nextAuthInput
		nextChallengeHeaders := resp2.Headers
		securityHeaders = nextChallengeHeaders
		cseq++
		resp2, err = sendRegister(cseq, authzHeader, authz, nextChallengeHeaders)
		if err != nil {
			return RegisterResult{Attempts: attempts, Challenge: ch, AuthHeader: authz}, err
		}
		resp2, authz, _, err = retryMinExpires(resp2, authzHeader, authz, nextChallengeHeaders, &nextAuthInput, ch)
		if err != nil {
			return RegisterResult{Attempts: attempts, Challenge: ch, AuthHeader: authz}, err
		}
		currentAuthInput = nextAuthInput
	}
	result := RegisterResult{
		Registered:     isSIPSuccess(resp2.StatusCode),
		StatusCode:     resp2.StatusCode,
		Reason:         resp2.Reason,
		Attempts:       attempts,
		RetryAfter:     SIPResponseRetryAfter(resp2),
		Challenge:      ch,
		Binding:        buildRegistrationBinding(s.Profile, contactURI, resp2, expires, securityClient, securityHeaders),
		AuthHeader:     authz,
		AuthHeaderName: authzHeader,
		AuthState:      newDigestAuthState(authzHeader, ch, currentAuthInput, authz),
		NextCSeq:       cseq + 1,
	}
	if !result.Registered {
		return result, fmt.Errorf("%w: %d %s", ErrRegistrationRejected, resp2.StatusCode, resp2.Reason)
	}
	result.AuthState, err = updateDigestAuthStateFromInfo(result.AuthState, resp2.Headers, authzHeader, resp2.Body)
	if err != nil {
		result.Registered = false
		return result, err
	}
	return result, nil
}

func (s RegisterSession) Deregister(ctx context.Context, req DeregisterRequest) (DeregisterResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Transport == nil {
		return DeregisterResult{}, errors.New("nil SIP register transport")
	}
	registrarURI := strings.TrimSpace(s.RegistrarURI)
	contactURI := firstNonEmpty(req.Binding.ContactURI, s.ContactURI)
	if registrarURI == "" || contactURI == "" {
		return DeregisterResult{}, errors.New("registrar URI and contact URI are required")
	}
	callID := firstNonEmpty(req.CallID, s.CallID, "vowifi-go-register")
	cseq := req.CSeq
	if cseq <= 0 {
		cseq = 1
	}
	attempts := 0
	sendDeregister := func(cseq int, authHeaderName, authz string, challengeHeaders map[string][]string) (RegisterResponse, error) {
		msg := RegisterMessage{
			URI:     registrarURI,
			Headers: BuildRegisterHeaders(s.Profile, contactURI, callID, strconv.Itoa(cseq)),
		}
		msg.Headers["Expires"] = "0"
		msg.Headers["Contact"] = deregisterContactHeader(msg.Headers["Contact"])
		if securityClient := strings.TrimSpace(req.Binding.SecurityClient); securityClient != "" {
			msg.Headers["Security-Client"] = securityClient
		}
		if strings.TrimSpace(authHeaderName) != "" && strings.TrimSpace(authz) != "" {
			msg.Headers[authHeaderName] = authz
		}
		if securityVerify := securityVerifyFromChallenge(challengeHeaders); securityVerify != "" {
			msg.Headers["Security-Verify"] = securityVerify
		} else if len(req.Binding.SecurityVerify) > 0 {
			msg.Headers["Security-Verify"] = strings.Join(trimHeaderValues(req.Binding.SecurityVerify), ", ")
		}
		attempts++
		return s.Transport.RoundTripRegister(ctx, cloneRegisterMessage(msg))
	}
	authHeaderName, authz, _, err := nextDigestAuthorization(req.AuthState, "REGISTER", registrarURI, req.AuthHeaderName, req.AuthHeader)
	if err != nil {
		return DeregisterResult{Attempts: attempts}, err
	}
	resp, err := sendDeregister(cseq, authHeaderName, authz, nil)
	if err != nil {
		return DeregisterResult{Attempts: attempts}, err
	}
	if isSIPSuccess(resp.StatusCode) {
		return DeregisterResult{Deregistered: true, StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}, nil
	}
	if resp.StatusCode != 401 && resp.StatusCode != 407 {
		result := DeregisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp)}
		return result, fmt.Errorf("%w: deregister %d %s", ErrRegistrationRejected, resp.StatusCode, resp.Reason)
	}
	challengeHeader := "WWW-Authenticate"
	authHeaderName = "Authorization"
	if firstHeader(resp.Headers, challengeHeader) == "" {
		challengeHeader = "Proxy-Authenticate"
		authHeaderName = "Proxy-Authorization"
	}
	ch, err := SelectDigestChallenge(resp.Headers, challengeHeader)
	if err != nil {
		return DeregisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp)}, err
	}
	authInput, syncFailure, err := s.digestAuthInputForChallenge(ch, registrarURI)
	if err != nil {
		return DeregisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp)}, err
	}
	if syncFailure {
		return DeregisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp)}, sim.ErrSyncFailure
	}
	authz, err = BuildDigestAuthorization(ch, authInput)
	if err != nil {
		return DeregisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}, err
	}
	cseq++
	resp2, err := sendDeregister(cseq, authHeaderName, authz, resp.Headers)
	if err != nil {
		return DeregisterResult{Attempts: attempts}, err
	}
	result := DeregisterResult{Deregistered: isSIPSuccess(resp2.StatusCode), StatusCode: resp2.StatusCode, Reason: resp2.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp2)}
	if !result.Deregistered {
		return result, fmt.Errorf("%w: deregister %d %s", ErrRegistrationRejected, resp2.StatusCode, resp2.Reason)
	}
	return result, nil
}

func (s RegisterSession) Refresh(ctx context.Context, req RefreshRequest) (RefreshResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Transport == nil {
		return RefreshResult{}, errors.New("nil SIP register transport")
	}
	registrarURI := strings.TrimSpace(s.RegistrarURI)
	contactURI := firstNonEmpty(req.Binding.ContactURI, s.ContactURI)
	if registrarURI == "" || contactURI == "" {
		return RefreshResult{}, errors.New("registrar URI and contact URI are required")
	}
	callID := firstNonEmpty(req.CallID, s.CallID, "vowifi-go-register")
	cseq := req.CSeq
	if cseq <= 0 {
		cseq = 1
	}
	expires := req.Expires
	if expires <= 0 {
		expires = req.Binding.Expires
	}
	if expires <= 0 {
		expires = s.Expires
	}
	if expires <= 0 {
		expires = 3600
	}
	attempts := 0
	sendRefresh := func(cseq int, authHeaderName, authz string, challengeHeaders map[string][]string) (RegisterResponse, error) {
		msg := RegisterMessage{
			URI:     registrarURI,
			Headers: BuildRegisterHeaders(s.Profile, contactURI, callID, strconv.Itoa(cseq)),
		}
		msg.Headers["Expires"] = strconv.Itoa(expires)
		if securityClient := strings.TrimSpace(req.Binding.SecurityClient); securityClient != "" {
			msg.Headers["Security-Client"] = securityClient
		}
		if strings.TrimSpace(authHeaderName) != "" && strings.TrimSpace(authz) != "" {
			msg.Headers[authHeaderName] = authz
		}
		if securityVerify := securityVerifyFromChallenge(challengeHeaders); securityVerify != "" {
			msg.Headers["Security-Verify"] = securityVerify
		} else if len(req.Binding.SecurityVerify) > 0 {
			msg.Headers["Security-Verify"] = strings.Join(trimHeaderValues(req.Binding.SecurityVerify), ", ")
		}
		attempts++
		return s.Transport.RoundTripRegister(ctx, cloneRegisterMessage(msg))
	}
	retryMinExpires := func(resp RegisterResponse, authHeaderName, authz string, authState DigestAuthState, challengeHeaders map[string][]string) (RegisterResponse, string, string, DigestAuthState, bool, error) {
		if resp.StatusCode != 423 {
			return resp, authHeaderName, authz, authState, false, nil
		}
		minExpires := minExpiresHeader(resp.Headers)
		if minExpires <= expires {
			return resp, authHeaderName, authz, authState, false, nil
		}
		expires = minExpires
		nextAuthHeaderName := authHeaderName
		nextAuthz := authz
		nextAuthState := authState
		if authState.Usable() {
			var err error
			nextAuthHeaderName, nextAuthz, nextAuthState, err = nextDigestAuthorization(authState, "REGISTER", registrarURI, authHeaderName, "")
			if err != nil {
				return resp, authHeaderName, authz, authState, true, err
			}
		}
		cseq++
		nextResp, err := sendRefresh(cseq, nextAuthHeaderName, nextAuthz, challengeHeaders)
		return nextResp, nextAuthHeaderName, nextAuthz, nextAuthState, true, err
	}
	authHeaderName, authz, authState, err := nextDigestAuthorization(req.AuthState, "REGISTER", registrarURI, req.AuthHeaderName, req.AuthHeader)
	if err != nil {
		return RefreshResult{Attempts: attempts}, err
	}
	resp, err := sendRefresh(cseq, authHeaderName, authz, nil)
	if err != nil {
		return RefreshResult{Attempts: attempts}, err
	}
	resp, authHeaderName, authz, authState, _, err = retryMinExpires(resp, authHeaderName, authz, authState, nil)
	if err != nil {
		return RefreshResult{Attempts: attempts, AuthHeader: authz, AuthHeaderName: authHeaderName, AuthState: authState}, err
	}
	if isSIPSuccess(resp.StatusCode) {
		binding := mergeRefreshBinding(req.Binding, buildRegistrationBinding(s.Profile, contactURI, resp, expires, securityClientFromBinding(req.Binding), nil))
		authState, err = updateDigestAuthStateFromInfo(authState, resp.Headers, authHeaderName, resp.Body)
		result := RefreshResult{
			Refreshed:      true,
			StatusCode:     resp.StatusCode,
			Reason:         resp.Reason,
			Attempts:       attempts,
			Binding:        binding,
			AuthHeader:     authz,
			AuthHeaderName: authHeaderName,
			AuthState:      authState,
			NextCSeq:       cseq + 1,
		}
		if err != nil {
			result.Refreshed = false
			return result, err
		}
		return result, nil
	}
	if resp.StatusCode != 401 && resp.StatusCode != 407 {
		result := RefreshResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp)}
		return result, fmt.Errorf("%w: refresh %d %s", ErrRegistrationRejected, resp.StatusCode, resp.Reason)
	}
	challengeHeader := "WWW-Authenticate"
	authHeaderName = "Authorization"
	if firstHeader(resp.Headers, challengeHeader) == "" {
		challengeHeader = "Proxy-Authenticate"
		authHeaderName = "Proxy-Authorization"
	}
	ch, err := SelectDigestChallenge(resp.Headers, challengeHeader)
	if err != nil {
		return RefreshResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp)}, err
	}
	authInput, syncFailure, err := s.digestAuthInputForChallenge(ch, registrarURI)
	if err != nil {
		return RefreshResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp)}, err
	}
	if syncFailure {
		return RefreshResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts, RetryAfter: SIPResponseRetryAfter(resp)}, sim.ErrSyncFailure
	}
	authz, err = BuildDigestAuthorization(ch, authInput)
	if err != nil {
		return RefreshResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: attempts}, err
	}
	authState = newDigestAuthState(authHeaderName, ch, authInput, authz)
	cseq++
	resp2, err := sendRefresh(cseq, authHeaderName, authz, resp.Headers)
	if err != nil {
		return RefreshResult{Attempts: attempts}, err
	}
	resp2, authHeaderName, authz, authState, _, err = retryMinExpires(resp2, authHeaderName, authz, authState, resp.Headers)
	if err != nil {
		return RefreshResult{Attempts: attempts, AuthHeader: authz, AuthHeaderName: authHeaderName, AuthState: authState}, err
	}
	resultBinding := mergeRefreshBinding(req.Binding, buildRegistrationBinding(s.Profile, contactURI, resp2, expires, securityClientFromBinding(req.Binding), resp.Headers))
	result := RefreshResult{
		Refreshed:      isSIPSuccess(resp2.StatusCode),
		StatusCode:     resp2.StatusCode,
		Reason:         resp2.Reason,
		Attempts:       attempts,
		RetryAfter:     SIPResponseRetryAfter(resp2),
		Binding:        resultBinding,
		AuthHeader:     authz,
		AuthHeaderName: authHeaderName,
		AuthState:      authState,
		NextCSeq:       cseq + 1,
	}
	if !result.Refreshed {
		return result, fmt.Errorf("%w: refresh %d %s", ErrRegistrationRejected, resp2.StatusCode, resp2.Reason)
	}
	result.AuthState, err = updateDigestAuthStateFromInfo(result.AuthState, resp2.Headers, authHeaderName, resp2.Body)
	if err != nil {
		result.Refreshed = false
		return result, err
	}
	return result, nil
}

func (s RegisterSession) securityClientAgreement() SecurityAgreement {
	if isZeroSecurityAgreement(s.SecurityClient) {
		return DefaultSecurityClientAgreement(s.SecurityRandom)
	}
	return completeSecurityAgreement(s.SecurityClient)
}

func nextDigestAuthorization(state DigestAuthState, method, uri, fallbackName, fallbackHeader string) (string, string, DigestAuthState, error) {
	headerName := firstNonEmpty(state.headerName, fallbackName, "Authorization")
	if state.Usable() {
		authz, next, err := state.Build(method, uri)
		if err != nil {
			return headerName, "", state, err
		}
		return firstNonEmpty(next.headerName, headerName), authz, next, nil
	}
	return firstNonEmpty(fallbackName, headerName), strings.TrimSpace(fallbackHeader), state.clone(), nil
}

func updateDigestAuthStateFromInfo(state DigestAuthState, headers map[string][]string, authHeaderName string, body []byte) (DigestAuthState, error) {
	if !state.Usable() {
		return state, nil
	}
	params := digestInfoParams(headers, authHeaderName)
	if rspauth := strings.TrimSpace(params["rspauth"]); rspauth != "" {
		expected, err := digestRspauth(state, firstNonEmpty(params["qop"], state.challenge.QOP), body)
		if err != nil {
			return state, err
		}
		if !strings.EqualFold(rspauth, expected) {
			return state, fmt.Errorf("%w: rspauth mismatch", ErrInvalidAuthenticationInfo)
		}
	}
	nextNonce := strings.TrimSpace(params["nextnonce"])
	if nextNonce == "" || nextNonce == state.challenge.Nonce {
		return state, nil
	}
	next := state.clone()
	next.challenge.Nonce = nextNonce
	next.input.NC = 1
	next.nextNC = 1
	next.lastHeader = ""
	return next, nil
}

func digestInfoNextNonce(headers map[string][]string, authHeaderName string) string {
	return digestInfoParams(headers, authHeaderName)["nextnonce"]
}

func digestInfoParams(headers map[string][]string, authHeaderName string) map[string]string {
	params := make(map[string]string)
	for _, name := range digestInfoHeaderNames(authHeaderName) {
		for _, header := range rawHeaderValues(headers, name) {
			for _, part := range splitAuthParams(header) {
				key, value, ok := strings.Cut(part, "=")
				if !ok {
					continue
				}
				key = strings.ToLower(strings.TrimSpace(key))
				value = unquote(strings.TrimSpace(value))
				if key != "" && value != "" {
					params[key] = value
				}
			}
		}
		if len(params) > 0 {
			return params
		}
	}
	return params
}

func digestInfoHeaderNames(authHeaderName string) []string {
	if strings.EqualFold(strings.TrimSpace(authHeaderName), "Proxy-Authorization") {
		return []string{"Proxy-Authentication-Info", "Authentication-Info"}
	}
	return []string{"Authentication-Info", "Proxy-Authentication-Info"}
}

func digestRspauth(state DigestAuthState, qop string, body []byte) (string, error) {
	input := state.input
	qop = firstQOP(qop)
	ha1 := md5Hex(input.Username + ":" + state.challenge.Realm + ":" + input.Password)
	ha2 := ""
	switch qop {
	case "":
		ha2 = md5Hex(":" + input.URI)
	case "auth":
		ha2 = md5Hex(":" + input.URI)
	case "auth-int":
		ha2 = md5Hex(":" + input.URI + ":" + md5HexBytes(body))
	default:
		return "", fmt.Errorf("%w: unsupported rspauth qop %q", ErrInvalidAuthenticationInfo, qop)
	}
	nc := input.NC
	if nc <= 0 {
		nc = 1
	}
	if qop == "" {
		return md5Hex(ha1 + ":" + state.challenge.Nonce + ":" + ha2), nil
	}
	cnonce := strings.TrimSpace(input.CNonce)
	if cnonce == "" {
		return "", fmt.Errorf("%w: cnonce required", ErrInvalidAuthenticationInfo)
	}
	return md5Hex(ha1 + ":" + state.challenge.Nonce + ":" + fmt.Sprintf("%08x", nc) + ":" + cnonce + ":" + qop + ":" + ha2), nil
}

func securityClientFromBinding(binding RegistrationBinding) SecurityAgreement {
	if agreement, ok := parseSecurityAgreement(binding.SecurityClient); ok {
		return agreement
	}
	return SecurityAgreement{}
}

func mergeRefreshBinding(previous, next RegistrationBinding) RegistrationBinding {
	if strings.TrimSpace(next.ContactURI) == "" {
		next.ContactURI = previous.ContactURI
	}
	if strings.TrimSpace(next.PublicIdentity) == "" {
		next.PublicIdentity = previous.PublicIdentity
	}
	if len(next.AssociatedURIs) == 0 {
		next.AssociatedURIs = append([]string(nil), previous.AssociatedURIs...)
	}
	if len(next.ServiceRoutes) == 0 {
		next.ServiceRoutes = append([]string(nil), previous.ServiceRoutes...)
	}
	if len(next.Paths) == 0 {
		next.Paths = append([]string(nil), previous.Paths...)
	}
	if strings.TrimSpace(next.SecurityClient) == "" {
		next.SecurityClient = previous.SecurityClient
	}
	if len(next.SecurityServer) == 0 {
		next.SecurityServer = append([]string(nil), previous.SecurityServer...)
	}
	if len(next.SecurityVerify) == 0 {
		next.SecurityVerify = append([]string(nil), previous.SecurityVerify...)
	}
	if isZeroSecurityAgreement(next.SecurityAgreement) {
		next.SecurityAgreement = previous.SecurityAgreement
	}
	if next.Expires <= 0 {
		next.Expires = previous.Expires
	}
	if strings.TrimSpace(next.RegistrarContact) == "" {
		next.RegistrarContact = previous.RegistrarContact
	}
	return next
}

func (s RegisterSession) digestAuthInputForChallenge(ch DigestChallenge, registrarURI string) (DigestAuthInput, bool, error) {
	input := DigestAuthInput{
		Method:   "REGISTER",
		URI:      registrarURI,
		Username: firstNonEmpty(s.Profile.IMPI, s.Profile.IMPU),
		CNonce:   firstNonEmpty(s.CNonce, "vowifi-go"),
		NC:       1,
	}
	if !isAKADigestAlgorithm(ch.Algorithm) {
		return input, false, nil
	}
	rand16, autn16, ok := ExtractAKAChallengeNonce(ch.Nonce)
	if !ok {
		return input, false, ErrInvalidChallenge
	}
	if s.AKAProvider == nil {
		return input, false, errors.New("AKA provider required for IMS digest AKA")
	}
	aka, err := s.AKAProvider.CalculateAKA(rand16, autn16)
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
	password, err := BuildAKADigestPassword(ch.Algorithm, aka)
	if err != nil {
		return input, false, err
	}
	input.Password = password
	return input, false, nil
}

func SelectDigestChallenge(headers map[string][]string, name string) (DigestChallenge, error) {
	var best DigestChallenge
	bestScore := -1
	var firstErr error
	for _, header := range rawHeaderValues(headers, name) {
		ch, err := ParseWWWAuthenticate(header)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !digestChallengeSupported(ch) {
			if firstErr == nil {
				firstErr = unsupportedDigestChallengeError(ch)
			}
			continue
		}
		score := digestAlgorithmScore(ch.Algorithm)
		if score > bestScore {
			best = ch
			bestScore = score
		}
	}
	if bestScore >= 0 {
		return best, nil
	}
	if firstErr != nil {
		return DigestChallenge{}, firstErr
	}
	return DigestChallenge{}, ErrInvalidChallenge
}

func digestChallengeSupported(ch DigestChallenge) bool {
	return digestAlgorithmScore(ch.Algorithm) > 0 && digestQOPSupported(ch.QOP)
}

func digestQOPSupported(qop string) bool {
	qop = strings.TrimSpace(qop)
	if qop == "" {
		return true
	}
	switch firstQOP(qop) {
	case "auth", "auth-int":
		return true
	default:
		return false
	}
}

func unsupportedDigestChallengeError(ch DigestChallenge) error {
	if digestAlgorithmScore(ch.Algorithm) <= 0 {
		return fmt.Errorf("unsupported digest algorithm %q", ch.Algorithm)
	}
	return fmt.Errorf("unsupported digest qop %q", ch.QOP)
}

func BuildRegistrationBinding(profile IMSProfile, contactURI string, resp RegisterResponse, requestedExpires int) RegistrationBinding {
	return buildRegistrationBinding(profile, contactURI, resp, requestedExpires, SecurityAgreement{}, nil)
}

func buildRegistrationBinding(profile IMSProfile, contactURI string, resp RegisterResponse, requestedExpires int, securityClient SecurityAgreement, securityFallback map[string][]string) RegistrationBinding {
	associated := normalizeAddressValues(headerListValues(resp.Headers, "P-Associated-URI"))
	securityServer := trimHeaderValues(headerListValues(resp.Headers, "Security-Server"))
	if len(securityServer) == 0 && securityFallback != nil {
		securityServer = trimHeaderValues(headerListValues(securityFallback, "Security-Server"))
	}
	securityVerify := append([]string(nil), securityServer...)
	securityClientHeader := ""
	if !isZeroSecurityAgreement(securityClient) {
		securityClientHeader = BuildSecurityClientHeader(securityClient)
	}
	registrarContact := registrationContactHeader(resp.Headers, contactURI)
	binding := RegistrationBinding{
		ContactURI:       strings.TrimSpace(contactURI),
		PublicIdentity:   defaultPublicIdentity(profile, associated),
		AssociatedURIs:   associated,
		ServiceRoutes:    trimHeaderValues(headerListValues(resp.Headers, "Service-Route")),
		Paths:            trimHeaderValues(headerListValues(resp.Headers, "Path")),
		SecurityClient:   securityClientHeader,
		SecurityServer:   securityServer,
		SecurityVerify:   securityVerify,
		Expires:          registrationExpires(resp.Headers, contactURI, requestedExpires),
		RegistrarContact: registrarContact,
	}
	if selected, ok := SelectSecurityAgreement(binding.SecurityServer, securityClient); ok {
		binding.SecurityAgreement = selected
	}
	if len(binding.AssociatedURIs) == 0 && binding.PublicIdentity != "" {
		binding.AssociatedURIs = []string{binding.PublicIdentity}
	}
	return binding
}

func splitAuthParams(s string) []string {
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

func firstQOP(qop string) string {
	for _, part := range strings.Split(qop, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p == "auth" {
			return p
		}
	}
	for _, part := range strings.Split(qop, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p == "auth-int" {
			return p
		}
	}
	return strings.ToLower(strings.TrimSpace(qop))
}

func firstHeader(headers map[string][]string, name string) string {
	return firstTrimmed(rawHeaderValues(headers, name)...)
}

func isSIPSuccess(code int) bool {
	return code >= 200 && code < 300
}

func cloneRegisterMessage(msg RegisterMessage) RegisterMessage {
	out := RegisterMessage{
		URI:     msg.URI,
		Headers: make(map[string]string, len(msg.Headers)),
		Body:    append([]byte(nil), msg.Body...),
	}
	for k, v := range msg.Headers {
		out.Headers[k] = v
	}
	return out
}

func deregisterContactHeader(contact string) string {
	contact = strings.TrimSpace(contact)
	if contact == "" {
		return ""
	}
	parts := splitSemicolonParams(contact)
	if len(parts) == 0 {
		return contact + ";expires=0"
	}
	var out []string
	replaced := false
	for i, part := range parts {
		if i > 0 {
			key, _, ok := strings.Cut(part, "=")
			if ok && strings.EqualFold(strings.TrimSpace(key), "expires") {
				out = append(out, "expires=0")
				replaced = true
				continue
			}
		}
		out = append(out, part)
	}
	if !replaced {
		out = append(out, "expires=0")
	}
	return strings.Join(out, ";")
}

func decodeNonceBytes(nonce string) ([]byte, bool) {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return nil, false
	}
	clean := strings.NewReplacer(":", "", "-", "", " ", "").Replace(nonce)
	if raw, err := hex.DecodeString(clean); err == nil {
		return raw, true
	}
	if raw, err := base64.StdEncoding.DecodeString(nonce); err == nil {
		return raw, true
	}
	if raw, err := base64.RawStdEncoding.DecodeString(nonce); err == nil {
		return raw, true
	}
	return nil, false
}

func isAKADigestAlgorithm(algorithm string) bool {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	return alg == "AKAV1-MD5" || alg == "AKAV2-MD5"
}

func digestAlgorithmScore(algorithm string) int {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "AKAV2-MD5":
		return 30
	case "AKAV1-MD5":
		return 20
	case "MD5":
		return 10
	default:
		return 0
	}
}

func rawHeaderValues(headers map[string][]string, name string) []string {
	var out []string
	for key, values := range headers {
		if strings.EqualFold(key, name) {
			for _, value := range values {
				if strings.TrimSpace(value) != "" {
					out = append(out, strings.TrimSpace(value))
				}
			}
		}
	}
	return out
}

func headerListValues(headers map[string][]string, name string) []string {
	var out []string
	for _, value := range rawHeaderValues(headers, name) {
		out = append(out, splitSIPHeaderValues(value)...)
	}
	return out
}

func splitSIPHeaderValues(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	escaped := false
	angleDepth := 0
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
		case r == '<' && !inQuote:
			angleDepth++
			cur.WriteRune(r)
		case r == '>' && !inQuote:
			if angleDepth > 0 {
				angleDepth--
			}
			cur.WriteRune(r)
		case r == ',' && !inQuote && angleDepth == 0:
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

func normalizeAddressValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if uri := extractAddressURI(value); uri != "" {
			out = append(out, uri)
		}
	}
	return out
}

func trimHeaderValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func extractAddressURI(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if start := strings.IndexByte(value, '<'); start >= 0 {
		if end := strings.IndexByte(value[start+1:], '>'); end >= 0 {
			return strings.TrimSpace(value[start+1 : start+1+end])
		}
	}
	if fields := strings.Fields(value); len(fields) > 0 {
		value = fields[0]
	}
	return strings.TrimSpace(strings.Trim(value, "<>"))
}

func defaultPublicIdentity(profile IMSProfile, associated []string) string {
	if len(associated) > 0 {
		return associated[0]
	}
	if impu := strings.TrimSpace(profile.IMPU); impu != "" {
		return impu
	}
	if strings.TrimSpace(profile.IMPI) != "" && strings.TrimSpace(profile.Domain) != "" {
		return "sip:" + strings.TrimSpace(profile.IMPI) + "@" + strings.TrimSpace(profile.Domain)
	}
	return strings.TrimSpace(profile.IMPI)
}

func registrationExpires(headers map[string][]string, contactURI string, fallback int) int {
	if contact, ok := matchingRegistrationContactHeader(headers, contactURI); ok {
		if n, ok := headerParamInt(contact, "expires"); ok {
			return n
		}
	}
	for _, value := range rawHeaderValues(headers, "Expires") {
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			return n
		}
	}
	if fallback > 0 {
		return fallback
	}
	return 0
}

func registrationContactHeader(headers map[string][]string, contactURI string) string {
	contacts := trimHeaderValues(headerListValues(headers, "Contact"))
	if len(contacts) == 0 {
		return ""
	}
	if contact, ok := matchingRegistrationContactHeader(headers, contactURI); ok {
		return contact
	}
	return contacts[0]
}

func matchingRegistrationContactHeader(headers map[string][]string, contactURI string) (string, bool) {
	contacts := trimHeaderValues(headerListValues(headers, "Contact"))
	if len(contacts) == 0 {
		return "", false
	}
	target := normalizeSIPURIForContactMatch(contactURI)
	if target == "" {
		return contacts[0], true
	}
	for _, contact := range contacts {
		if normalizeSIPURIForContactMatch(extractAddressURI(contact)) == target {
			return contact, true
		}
	}
	return "", false
}

func normalizeSIPURIForContactMatch(uri string) string {
	uri = strings.TrimSpace(strings.Trim(uri, "<>"))
	if uri == "" || uri == "*" {
		return ""
	}
	if semi := strings.IndexByte(uri, ';'); semi >= 0 {
		uri = uri[:semi]
	}
	return strings.ToLower(strings.TrimSpace(uri))
}

func minExpiresHeader(headers map[string][]string) int {
	for _, value := range rawHeaderValues(headers, "Min-Expires") {
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

func headerParamInt(value, name string) (int, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, part := range strings.Split(value, ";") {
		key, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || strings.ToLower(strings.TrimSpace(key)) != name {
			continue
		}
		n, err := strconv.Atoi(strings.Trim(raw, `"`))
		return n, err == nil
	}
	return 0, false
}

func securityVerifyFromChallenge(headers map[string][]string) string {
	values := trimHeaderValues(headerListValues(headers, "Security-Server"))
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, ", ")
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func md5HexBytes(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if out, err := strconv.Unquote(s); err == nil {
			return out
		}
		return s[1 : len(s)-1]
	}
	return s
}

func quote(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

func firstNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}

func firstTrimmed(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}
