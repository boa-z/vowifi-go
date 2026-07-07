package voiceclient

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var ErrInvalidDialogConfig = errors.New("invalid IMS dialog config")

const (
	imsMMTelService            = "urn:urn-7:3gpp-service.ims.icsi.mmtel"
	imsMMTelContactFeature     = `+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`
	imsMMTelAcceptContact      = "*;" + imsMMTelContactFeature
	DefaultDialogMessageAccept = "text/plain, application/vnd.3gpp.sms, message/cpim"
	DefaultSubscribeExpires    = "3600"
	DefaultReferSub            = "false"
)

type SIPRequestMessage struct {
	Method      string
	URI         string
	Headers     map[string]string
	Body        []byte
	AuthSession *DigestAuthSession
}

type SIPIncomingRequest struct {
	Method  string
	URI     string
	Headers map[string][]string
	Body    []byte
}

type DialogRequestConfig struct {
	Profile           IMSProfile
	Registration      RegistrationBinding
	ContactURI        string
	LocalURI          string
	RemoteURI         string
	RemoteTargetURI   string
	CallID            string
	LocalTag          string
	RemoteTag         string
	CSeq              int
	RouteSet          []string
	UserAgent         string
	PreferredIdentity string
	AccessNetworkInfo string
	Reason            string
	CarrierHeaders    map[string]string
	SessionExpires    int
	SessionRefresher  string
	MinSE             int
	InviteHeaders     map[string]string
	AuthHeader        string
	AuthHeaderName    string
	AuthSession       *DigestAuthSession
}

type ReferRequestOptions struct {
	ReferredBy string
	ReferSub   string
}

type DialogSessionState string

const (
	DialogSessionStateIdle        DialogSessionState = "idle"
	DialogSessionStateCalling     DialogSessionState = "calling"
	DialogSessionStateEarly       DialogSessionState = "early"
	DialogSessionStateConfirmed   DialogSessionState = "confirmed"
	DialogSessionStateTerminating DialogSessionState = "terminating"
	DialogSessionStateTerminated  DialogSessionState = "terminated"
)

type ProvisionalResponseInfo struct {
	StatusCode      int
	Reason          string
	Reliable        bool
	RSeq            int
	RAck            string
	CSeq            int
	CSeqMethod      string
	EarlyMedia      bool
	ContentType     string
	SDP             []byte
	RemoteTag       string
	RemoteTargetURI string
	DialogReasons   []DialogReason
}

type DialogSessionTimerInfo struct {
	Active        bool
	Interval      int
	Refresher     string
	MinSE         int
	RefreshAfter  time.Duration
	RetryRequired bool
}

type DialogFailureInfo struct {
	StatusCode    int
	ReasonPhrase  string
	RetryAfter    time.Duration
	Warnings      []string
	Reasons       []string
	DialogReasons []DialogReason
}

type DialogReason struct {
	Raw        string
	Protocol   string
	Cause      int
	Text       string
	Parameters map[string]string
}

func BuildInviteRequest(cfg DialogRequestConfig, sdp []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("INVITE", cfg, sdp)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(sdp) > 0 {
		msg.Headers["Content-Type"] = "application/sdp"
		msg.Headers["Accept"] = "application/sdp"
	}
	setDefaultDialogRequestHeader(msg.Headers, "P-Preferred-Service", imsMMTelService)
	setDefaultDialogRequestHeader(msg.Headers, "Accept-Contact", imsMMTelAcceptContact)
	msg.Headers["Supported"] = "100rel, timer, replaces, outbound"
	applySessionIntervalHeaders(msg.Headers, cfg)
	if cfg.MinSE > 0 {
		msg.Headers["Min-SE"] = strconv.Itoa(cfg.MinSE)
	}
	applyDialogRequestHeaders(msg.Headers, cfg.InviteHeaders)
	return msg, nil
}

func BuildAckRequest(cfg DialogRequestConfig) (SIPRequestMessage, error) {
	return buildDialogRequest("ACK", cfg, nil)
}

func BuildAckRequestForInviteResponse(cfg DialogRequestConfig, resp SIPResponse) (SIPRequestMessage, bool, error) {
	if !DialogResponseRequiresAck("INVITE", resp) {
		return SIPRequestMessage{}, false, nil
	}
	cseqValue := firstHeader(resp.Headers, "CSeq")
	if cseqValue == "" {
		return SIPRequestMessage{}, false, fmt.Errorf("%w: missing INVITE response CSeq", ErrInvalidSIPMessage)
	}
	cseq, method, ok := sipCSeqParts(cseqValue)
	if !ok || !strings.EqualFold(method, "INVITE") {
		return SIPRequestMessage{}, false, fmt.Errorf("%w: invalid INVITE response CSeq", ErrInvalidSIPMessage)
	}
	cfg.CSeq = cseq
	if cfg.RemoteTag == "" {
		cfg.RemoteTag = sipHeaderTag(firstHeader(resp.Headers, "To"))
	}
	if cfg.RemoteTargetURI == "" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		cfg.RemoteTargetURI = firstContactURI(resp.Headers)
	}
	msg, err := BuildAckRequest(cfg)
	if err != nil {
		return SIPRequestMessage{}, false, err
	}
	return msg, true, nil
}

func BuildByeRequest(cfg DialogRequestConfig) (SIPRequestMessage, error) {
	return buildDialogRequest("BYE", cfg, nil)
}

func BuildByeRequestWithBody(cfg DialogRequestConfig, contentType string, body []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("BYE", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "application/octet-stream")
	}
	return msg, nil
}

func BuildCancelRequest(cfg DialogRequestConfig) (SIPRequestMessage, error) {
	return BuildCancelRequestWithBody(cfg, "", nil)
}

func BuildCancelRequestWithBody(cfg DialogRequestConfig, contentType string, body []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("CANCEL", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "application/octet-stream")
	}
	return msg, nil
}

func BuildUpdateRequest(cfg DialogRequestConfig, sdp []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("UPDATE", cfg, sdp)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	msg.Headers["Supported"] = "timer, replaces, outbound"
	applySessionIntervalHeaders(msg.Headers, cfg)
	if cfg.MinSE > 0 {
		msg.Headers["Min-SE"] = strconv.Itoa(cfg.MinSE)
	}
	if len(sdp) > 0 {
		msg.Headers["Content-Type"] = "application/sdp"
		msg.Headers["Accept"] = "application/sdp"
	}
	return msg, nil
}

func BuildPrackRequest(cfg DialogRequestConfig, rack string) (SIPRequestMessage, error) {
	return BuildPrackRequestWithBody(cfg, rack, "", nil)
}

func BuildPrackRequestWithBody(cfg DialogRequestConfig, rack, contentType string, body []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("PRACK", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if strings.TrimSpace(rack) != "" {
		msg.Headers["RAck"] = strings.TrimSpace(rack)
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "application/sdp")
	}
	return msg, nil
}

func BuildPrackRequestForProvisionalResponse(cfg DialogRequestConfig, resp SIPResponse) (SIPRequestMessage, bool, error) {
	info, err := ParseProvisionalResponseInfo(resp)
	if err != nil {
		return SIPRequestMessage{}, false, err
	}
	if !info.Reliable {
		return SIPRequestMessage{}, false, nil
	}
	if cfg.RemoteTag == "" && info.RemoteTag != "" {
		cfg.RemoteTag = info.RemoteTag
	}
	if cfg.RemoteTargetURI == "" && info.RemoteTargetURI != "" {
		cfg.RemoteTargetURI = info.RemoteTargetURI
	}
	msg, err := BuildPrackRequest(cfg, info.RAck)
	if err != nil {
		return SIPRequestMessage{}, false, err
	}
	return msg, true, nil
}

func ParseProvisionalResponseInfo(resp SIPResponse) (ProvisionalResponseInfo, error) {
	info := ProvisionalResponseInfo{
		StatusCode:      resp.StatusCode,
		Reason:          strings.TrimSpace(resp.Reason),
		ContentType:     firstHeader(resp.Headers, "Content-Type"),
		RemoteTag:       sipHeaderTag(firstHeader(resp.Headers, "To")),
		RemoteTargetURI: firstContactURI(resp.Headers),
		DialogReasons:   ParseDialogReasonHeaders(resp.Headers),
	}
	if isSIPProvisionalResponse(resp.StatusCode) && sipContentTypeMatches(info.ContentType, "application/sdp") && len(resp.Body) > 0 {
		info.EarlyMedia = true
		info.SDP = append([]byte(nil), resp.Body...)
	}
	if !isSIPProvisionalResponse(resp.StatusCode) {
		return info, nil
	}
	rseqValue := firstHeader(resp.Headers, "RSeq")
	if !sipHeaderHasToken(resp.Headers, "Require", "100rel") && strings.TrimSpace(rseqValue) == "" {
		return info, nil
	}
	info.Reliable = true
	if strings.TrimSpace(rseqValue) == "" {
		return info, fmt.Errorf("%w: reliable provisional missing RSeq", ErrInvalidSIPMessage)
	}
	rseq, err := parsePositiveSIPHeaderInt(rseqValue)
	if err != nil {
		return info, fmt.Errorf("%w: invalid RSeq", ErrInvalidSIPMessage)
	}
	cseq, method, ok := sipCSeqParts(firstHeader(resp.Headers, "CSeq"))
	if !ok {
		return info, fmt.Errorf("%w: invalid CSeq for reliable provisional", ErrInvalidSIPMessage)
	}
	info.RSeq = rseq
	info.CSeq = cseq
	info.CSeqMethod = method
	info.RAck = strconv.Itoa(rseq) + " " + strconv.Itoa(cseq) + " " + method
	return info, nil
}

func ParseDialogSessionTimerInfo(resp SIPResponse) (DialogSessionTimerInfo, error) {
	info := DialogSessionTimerInfo{
		RetryRequired: resp.StatusCode == 422,
	}
	if minSE := firstHeader(resp.Headers, "Min-SE"); strings.TrimSpace(minSE) != "" {
		value, err := parsePositiveSIPHeaderInt(minSE)
		if err != nil {
			return info, fmt.Errorf("%w: invalid Min-SE", ErrInvalidSIPMessage)
		}
		info.MinSE = value
	}
	sessionExpires := firstHeader(resp.Headers, "Session-Expires")
	if strings.TrimSpace(sessionExpires) == "" {
		return info, nil
	}
	interval, refresher, err := parseSessionExpiresHeader(sessionExpires)
	if err != nil {
		return info, err
	}
	info.Active = true
	info.Interval = interval
	info.Refresher = refresher
	info.RefreshAfter = sessionRefreshDelay(interval)
	return info, nil
}

func DialogSessionRefreshDelay(cfg DialogRequestConfig, resp SIPResponse) (time.Duration, bool, error) {
	info, err := ParseDialogSessionTimerInfo(resp)
	if err != nil || !info.Active {
		return 0, false, err
	}
	refresher := info.Refresher
	if refresher == "" {
		refresher = normalizeSessionRefresher(cfg.SessionRefresher)
	}
	if refresher == "uas" {
		return 0, false, nil
	}
	return info.RefreshAfter, true, nil
}

func DialogSessionTimerRetryConfig(cfg DialogRequestConfig, resp SIPResponse) (DialogRequestConfig, bool, error) {
	info, err := ParseDialogSessionTimerInfo(resp)
	if err != nil || !info.RetryRequired {
		return cfg, false, err
	}
	if info.MinSE <= 0 {
		return cfg, false, fmt.Errorf("%w: 422 response missing Min-SE", ErrInvalidSIPMessage)
	}
	next := cfg
	if next.MinSE < info.MinSE {
		next.MinSE = info.MinSE
	}
	if next.SessionExpires <= 0 || next.SessionExpires < next.MinSE {
		next.SessionExpires = next.MinSE
	}
	return next, true, nil
}

func ParseDialogFailureInfo(resp SIPResponse) DialogFailureInfo {
	reasons := trimHeaderValues(headerListValues(resp.Headers, "Reason"))
	return DialogFailureInfo{
		StatusCode:    resp.StatusCode,
		ReasonPhrase:  strings.TrimSpace(resp.Reason),
		RetryAfter:    SIPResponseRetryAfter(resp),
		Warnings:      trimHeaderValues(headerListValues(resp.Headers, "Warning")),
		Reasons:       reasons,
		DialogReasons: parseDialogReasonValues(reasons),
	}
}

func AdvanceDialogSessionState(state DialogSessionState, method string, resp SIPResponse) DialogSessionState {
	if state == "" {
		state = DialogSessionStateIdle
	}
	if state == DialogSessionStateTerminated {
		return state
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	switch method {
	case "INVITE":
		switch {
		case isSIPProvisionalResponse(resp.StatusCode):
			if resp.StatusCode >= 180 {
				return DialogSessionStateEarly
			}
			if state == DialogSessionStateIdle {
				return DialogSessionStateCalling
			}
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return DialogSessionStateConfirmed
		case resp.StatusCode >= 300 && resp.StatusCode < 700:
			if state == DialogSessionStateConfirmed && resp.StatusCode != 481 {
				return DialogSessionStateConfirmed
			}
			return DialogSessionStateTerminated
		}
	case "CANCEL":
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return DialogSessionStateTerminating
		}
		if resp.StatusCode == 481 {
			return DialogSessionStateTerminated
		}
	case "BYE":
		if isSIPProvisionalResponse(resp.StatusCode) {
			return DialogSessionStateTerminating
		}
		if resp.StatusCode == 481 || (resp.StatusCode >= 200 && resp.StatusCode < 300) {
			return DialogSessionStateTerminated
		}
	case "PRACK", "UPDATE":
		if resp.StatusCode == 481 {
			return DialogSessionStateTerminated
		}
	}
	return state
}

func DialogResponseRequiresAck(method string, resp SIPResponse) bool {
	return strings.EqualFold(strings.TrimSpace(method), "INVITE") && resp.StatusCode >= 200 && resp.StatusCode < 700
}

func DialogResponseIsInviteTerminated(resp SIPResponse) bool {
	return resp.StatusCode == 487
}

func DialogResponseIsRequestPending(resp SIPResponse) bool {
	return resp.StatusCode == 491
}

func FormatDialogReasonHeader(protocol string, cause int, text string) (string, error) {
	protocol = strings.TrimSpace(protocol)
	if protocol == "" {
		return "", fmt.Errorf("%w: Reason protocol is empty", ErrInvalidDialogConfig)
	}
	if strings.ContainsAny(protocol, " \t\r\n;") {
		return "", fmt.Errorf("%w: invalid Reason protocol", ErrInvalidDialogConfig)
	}
	if cause <= 0 {
		return "", fmt.Errorf("%w: invalid Reason cause", ErrInvalidDialogConfig)
	}
	value := protocol + ";cause=" + strconv.Itoa(cause)
	text = strings.TrimSpace(text)
	if strings.ContainsAny(text, "\r\n") {
		return "", fmt.Errorf("%w: invalid Reason text", ErrInvalidDialogConfig)
	}
	if text == "" && strings.EqualFold(protocol, "SIP") && validSIPStatusCode(cause) {
		text = defaultSIPReason(cause)
	}
	if text != "" {
		value += `;text="` + quote(text) + `"`
	}
	return value, nil
}

func ParseDialogReasonHeader(value string) (DialogReason, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return DialogReason{}, fmt.Errorf("%w: Reason header is empty", ErrInvalidSIPMessage)
	}
	parts := splitSIPHeaderParams(raw)
	if len(parts) == 0 {
		return DialogReason{}, fmt.Errorf("%w: invalid Reason header", ErrInvalidSIPMessage)
	}
	protocol := strings.TrimSpace(parts[0])
	if protocol == "" || strings.ContainsAny(protocol, " \t\r\n;") {
		return DialogReason{}, fmt.Errorf("%w: invalid Reason protocol", ErrInvalidSIPMessage)
	}
	reason := DialogReason{
		Raw:        raw,
		Protocol:   protocol,
		Parameters: make(map[string]string),
	}
	for _, part := range parts[1:] {
		key, rawValue, ok := strings.Cut(strings.TrimSpace(part), "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			return DialogReason{}, fmt.Errorf("%w: invalid Reason parameter", ErrInvalidSIPMessage)
		}
		value := ""
		if ok {
			parsed, err := parseDialogReasonParamValue(rawValue)
			if err != nil {
				return DialogReason{}, err
			}
			value = parsed
		}
		reason.Parameters[key] = value
		switch key {
		case "cause":
			cause, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || cause <= 0 {
				return DialogReason{}, fmt.Errorf("%w: invalid Reason cause", ErrInvalidSIPMessage)
			}
			reason.Cause = cause
		case "text":
			reason.Text = value
		}
	}
	if reason.Cause <= 0 {
		return DialogReason{}, fmt.Errorf("%w: Reason cause is missing", ErrInvalidSIPMessage)
	}
	return reason, nil
}

func ParseDialogReasonHeaders(headers map[string][]string) []DialogReason {
	return parseDialogReasonValues(trimHeaderValues(headerListValues(headers, "Reason")))
}

func parseDialogReasonValues(values []string) []DialogReason {
	out := make([]DialogReason, 0, len(values))
	for _, value := range values {
		reason, err := ParseDialogReasonHeader(value)
		if err == nil {
			out = append(out, reason)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseDialogReasonParamValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	quotedStart := strings.HasPrefix(value, `"`)
	quotedEnd := strings.HasSuffix(value, `"`)
	if quotedStart || quotedEnd {
		if !quotedStart || !quotedEnd || len(value) < 2 {
			return "", fmt.Errorf("%w: malformed Reason parameter", ErrInvalidSIPMessage)
		}
		out, err := strconv.Unquote(value)
		if err != nil {
			return "", fmt.Errorf("%w: malformed Reason parameter", ErrInvalidSIPMessage)
		}
		return out, nil
	}
	if strings.ContainsAny(value, "\"\r\n") {
		return "", fmt.Errorf("%w: malformed Reason parameter", ErrInvalidSIPMessage)
	}
	return value, nil
}

func BuildInfoRequest(cfg DialogRequestConfig, contentType string, body []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("INFO", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "application/octet-stream")
	}
	if contactURI := firstNonEmpty(cfg.ContactURI, cfg.Registration.ContactURI); contactURI != "" {
		msg.Headers["Contact"] = "<" + contactURI + ">"
	}
	return msg, nil
}

func BuildMessageRequest(cfg DialogRequestConfig, contentType string, body []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("MESSAGE", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "text/plain;charset=UTF-8")
	}
	msg.Headers["Accept"] = "text/plain, application/vnd.3gpp.sms"
	msg.Headers["P-Preferred-Service"] = "urn:urn-7:3gpp-service.ims.icsi.sms"
	msg.Headers["Accept-Contact"] = "*;+g.3gpp.smsip"
	if contactURI := firstNonEmpty(cfg.ContactURI, cfg.Registration.ContactURI); contactURI != "" {
		msg.Headers["Contact"] = "<" + contactURI + ">"
	}
	return msg, nil
}

func BuildDialogMessageRequest(cfg DialogRequestConfig, contentType string, body []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("MESSAGE", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "text/plain;charset=UTF-8")
	}
	msg.Headers["Accept"] = DefaultDialogMessageAccept
	if contactURI := firstNonEmpty(cfg.ContactURI, cfg.Registration.ContactURI); contactURI != "" {
		msg.Headers["Contact"] = "<" + contactURI + ">"
	}
	return msg, nil
}

func BuildReferRequest(cfg DialogRequestConfig, referTo, referredBy string) (SIPRequestMessage, error) {
	return BuildReferRequestWithOptions(cfg, referTo, ReferRequestOptions{ReferredBy: referredBy})
}

func BuildReferRequestWithOptions(cfg DialogRequestConfig, referTo string, opts ReferRequestOptions) (SIPRequestMessage, error) {
	referTo = strings.TrimSpace(referTo)
	if referTo == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: Refer-To is empty", ErrInvalidDialogConfig)
	}
	msg, err := buildDialogRequest("REFER", cfg, nil)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	msg.Headers["Refer-To"] = formatReferHeader(referTo)
	if referredBy := strings.TrimSpace(opts.ReferredBy); referredBy != "" {
		msg.Headers["Referred-By"] = formatReferHeader(referredBy)
	}
	referSub := strings.ToLower(strings.TrimSpace(opts.ReferSub))
	if referSub == "" {
		referSub = DefaultReferSub
	}
	if referSub != "true" && referSub != "false" {
		return SIPRequestMessage{}, fmt.Errorf("%w: Refer-Sub must be true or false", ErrInvalidDialogConfig)
	}
	msg.Headers["Refer-Sub"] = referSub
	msg.Headers["Supported"] = "replaces, norefersub, outbound"
	return msg, nil
}

func BuildNotifyRequest(cfg DialogRequestConfig, event, subscriptionState, contentType string, body []byte) (SIPRequestMessage, error) {
	event = strings.TrimSpace(event)
	if event == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: Event is empty", ErrInvalidDialogConfig)
	}
	subscriptionState = strings.TrimSpace(subscriptionState)
	if subscriptionState == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: Subscription-State is empty", ErrInvalidDialogConfig)
	}
	msg, err := buildDialogRequest("NOTIFY", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	msg.Headers["Event"] = event
	msg.Headers["Subscription-State"] = subscriptionState
	msg.Headers["Allow-Events"] = "refer"
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "message/sipfrag")
	}
	return msg, nil
}

func BuildSubscribeRequest(cfg DialogRequestConfig, event, expires, contentType string, body []byte) (SIPRequestMessage, error) {
	event = strings.TrimSpace(event)
	if event == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: Event is empty", ErrInvalidDialogConfig)
	}
	msg, err := buildDialogRequest("SUBSCRIBE", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	msg.Headers["Event"] = event
	msg.Headers["Accept"] = "message/sipfrag"
	msg.Headers["Allow-Events"] = "refer"
	if expires = strings.TrimSpace(expires); expires == "" {
		expires = DefaultSubscribeExpires
	}
	msg.Headers["Expires"] = expires
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "application/octet-stream")
	}
	return msg, nil
}

func BuildOptionsRequest(cfg DialogRequestConfig) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("OPTIONS", cfg, nil)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	msg.Headers["Accept"] = "application/sdp"
	msg.Headers["Supported"] = "100rel, timer, replaces, outbound"
	return msg, nil
}

func buildDialogRequest(method string, cfg DialogRequestConfig, body []byte) (SIPRequestMessage, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: method is empty", ErrInvalidDialogConfig)
	}
	localURI := firstNonEmpty(cfg.LocalURI, cfg.Registration.PublicIdentity, cfg.Profile.IMPU)
	remoteURI := strings.TrimSpace(cfg.RemoteURI)
	targetURI := firstNonEmpty(cfg.RemoteTargetURI, remoteURI)
	contactURI := firstNonEmpty(cfg.ContactURI, cfg.Registration.ContactURI)
	callID := strings.TrimSpace(cfg.CallID)
	if localURI == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: local URI is empty", ErrInvalidDialogConfig)
	}
	if remoteURI == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: remote URI is empty", ErrInvalidDialogConfig)
	}
	if targetURI == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: request URI is empty", ErrInvalidDialogConfig)
	}
	if contactURI == "" && method == "INVITE" {
		return SIPRequestMessage{}, fmt.Errorf("%w: contact URI is empty", ErrInvalidDialogConfig)
	}
	if callID == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: Call-ID is empty", ErrInvalidDialogConfig)
	}
	cseq := cfg.CSeq
	if cseq <= 0 {
		cseq = 1
	}
	localTag := firstNonEmpty(cfg.LocalTag, "vowifi-go")
	headers := map[string]string{
		"To":                    formatNameAddr(remoteURI, cfg.RemoteTag),
		"From":                  formatNameAddr(localURI, localTag),
		"Call-ID":               callID,
		"CSeq":                  strconv.Itoa(cseq) + " " + method,
		"Max-Forwards":          "70",
		"User-Agent":            firstNonEmpty(cfg.UserAgent, cfg.Profile.UserAgent, "vowifi-go"),
		"Allow":                 "INVITE, ACK, CANCEL, BYE, PRACK, UPDATE, INFO, MESSAGE, REFER, NOTIFY, SUBSCRIBE, OPTIONS",
		"P-Preferred-Identity":  formatPreferredIdentityHeader(localURI),
		"P-Access-Network-Info": "IEEE-802.11",
	}
	applyDialogCarrierHeaders(headers, cfg)
	if contactURI != "" && (method == "INVITE" || method == "UPDATE" || method == "INFO" || method == "REFER" || method == "NOTIFY" || method == "SUBSCRIBE") {
		headers["Contact"] = "<" + contactURI + ">"
	}
	if route := routeHeader(firstNonEmptySlice(cfg.RouteSet, cfg.Registration.ServiceRoutes)); route != "" {
		headers["Route"] = route
	}
	if securityVerify := routeHeader(cfg.Registration.SecurityVerify); securityVerify != "" {
		headers["Security-Verify"] = securityVerify
	}
	authSession := dialogDigestAuthSession(cfg)
	authHeaderName, authHeader, err := dialogDigestAuthorization(cfg, authSession, method, targetURI, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if authHeaderName != "" && authHeader != "" {
		headers[authHeaderName] = authHeader
	}
	return SIPRequestMessage{
		Method:      method,
		URI:         targetURI,
		Headers:     headers,
		Body:        append([]byte(nil), body...),
		AuthSession: authSession,
	}, nil
}

func dialogDigestAuthSession(cfg DialogRequestConfig) *DigestAuthSession {
	if cfg.AuthSession != nil {
		return cfg.AuthSession
	}
	return cfg.Registration.AuthSession
}

func dialogDigestAuthorization(cfg DialogRequestConfig, session *DigestAuthSession, method, targetURI string, body []byte) (string, string, error) {
	fallbackName := firstNonEmpty(cfg.AuthHeaderName, cfg.Registration.AuthHeaderName)
	fallbackHeader := firstNonEmpty(cfg.AuthHeader, cfg.Registration.AuthHeader)
	if session == nil {
		if fallbackHeader == "" {
			return "", "", nil
		}
		return firstNonEmpty(fallbackName, "Authorization"), fallbackHeader, nil
	}
	headerName, header, err := session.NextWithBody(method, targetURI, body)
	if err != nil {
		return "", "", err
	}
	if header == "" && fallbackHeader != "" {
		headerName = firstNonEmpty(headerName, fallbackName, "Authorization")
		header = fallbackHeader
	}
	return headerName, header, nil
}

func applyDialogCarrierHeaders(dst map[string]string, cfg DialogRequestConfig) {
	if dst == nil {
		return
	}
	if identity := formatPreferredIdentityHeader(cfg.PreferredIdentity); identity != "" {
		setDialogRequestHeader(dst, "P-Preferred-Identity", identity)
	}
	if accessNetworkInfo := strings.TrimSpace(cfg.AccessNetworkInfo); accessNetworkInfo != "" {
		setDialogRequestHeader(dst, "P-Access-Network-Info", accessNetworkInfo)
	}
	if reason := strings.TrimSpace(cfg.Reason); reason != "" {
		setDialogRequestHeader(dst, "Reason", reason)
	}
	for key, value := range cfg.CarrierHeaders {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		canonical := canonicalHeaderName(key)
		switch strings.ToLower(canonical) {
		case "p-preferred-identity":
			value = formatPreferredIdentityHeader(value)
			if value == "" {
				continue
			}
		case "p-access-network-info", "reason":
		default:
			if isProtectedDialogRequestHeader(key) || isProtectedDialogRequestHeader(canonical) {
				continue
			}
		}
		setDialogRequestHeader(dst, canonical, value)
	}
}

func applySessionIntervalHeaders(headers map[string]string, cfg DialogRequestConfig) {
	if headers == nil || cfg.SessionExpires <= 0 {
		return
	}
	value := strconv.Itoa(cfg.SessionExpires)
	if refresher := normalizeSessionRefresher(cfg.SessionRefresher); refresher != "" {
		value += ";refresher=" + refresher
	}
	headers["Session-Expires"] = value
}

func applyDialogRequestHeaders(dst map[string]string, headers map[string]string) {
	if dst == nil {
		return
	}
	for key, value := range headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogRequestHeader(key) {
			continue
		}
		setDialogRequestHeader(dst, key, value)
	}
}

func setDialogRequestHeader(headers map[string]string, name, value string) {
	for key := range headers {
		if strings.EqualFold(key, name) {
			headers[key] = value
			return
		}
	}
	headers[name] = value
}

func setDefaultDialogRequestHeader(headers map[string]string, name, value string) {
	for key, existing := range headers {
		if strings.EqualFold(key, name) {
			if strings.TrimSpace(existing) == "" {
				headers[key] = value
			}
			return
		}
	}
	headers[name] = value
}

func isProtectedDialogRequestHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "to", "from", "call-id", "cseq", "max-forwards", "route", "record-route", "via", "contact", "content-length", "content-type", "authorization", "proxy-authorization", "p-preferred-identity", "security-verify", "rack", "refer-to", "referred-by", "event", "subscription-state":
		return true
	default:
		return false
	}
}

func normalizeSessionRefresher(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "uac", "uas":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func routeHeader(routes []string) string {
	clean := trimHeaderValues(routes)
	if len(clean) == 0 {
		return ""
	}
	return strings.Join(clean, ", ")
}

func firstNonEmptySlice(items ...[]string) []string {
	for _, item := range items {
		if len(trimHeaderValues(item)) > 0 {
			return item
		}
	}
	return nil
}

func formatNameAddr(uri, tag string) string {
	out := "<" + strings.TrimSpace(uri) + ">"
	if tag = strings.TrimSpace(tag); tag != "" {
		out += ";tag=" + tag
	}
	return out
}

func formatReferHeader(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "<") {
		return value
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") || strings.HasPrefix(lower, "tel:") {
		return "<" + value + ">"
	}
	return value
}

func formatPreferredIdentityHeader(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "<") {
		return value
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") || strings.HasPrefix(lower, "tel:") {
		return "<" + value + ">"
	}
	return value
}

func sipHeaderHasToken(headers map[string][]string, name, token string) bool {
	token = strings.ToLower(strings.TrimSpace(token))
	if token == "" {
		return false
	}
	for _, value := range headerListValues(headers, name) {
		candidate := strings.TrimSpace(value)
		if semi := strings.IndexByte(candidate, ';'); semi >= 0 {
			candidate = candidate[:semi]
		}
		if strings.EqualFold(strings.TrimSpace(candidate), token) {
			return true
		}
	}
	return false
}

func sipContentTypeMatches(value, mediaType string) bool {
	value = strings.TrimSpace(value)
	if semi := strings.IndexByte(value, ';'); semi >= 0 {
		value = value[:semi]
	}
	return strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(mediaType))
}

func parsePositiveSIPHeaderInt(value string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n <= 0 {
		return 0, ErrInvalidSIPMessage
	}
	return n, nil
}

func parseSessionExpiresHeader(value string) (int, string, error) {
	parts := splitSIPHeaderParams(value)
	if len(parts) == 0 {
		return 0, "", fmt.Errorf("%w: invalid Session-Expires", ErrInvalidSIPMessage)
	}
	interval, err := parsePositiveSIPHeaderInt(parts[0])
	if err != nil {
		return 0, "", fmt.Errorf("%w: invalid Session-Expires", ErrInvalidSIPMessage)
	}
	var refresher string
	for _, part := range parts[1:] {
		key, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "refresher") {
			continue
		}
		refresher = normalizeSessionRefresher(strings.Trim(strings.TrimSpace(raw), `"`))
		if refresher == "" {
			return 0, "", fmt.Errorf("%w: invalid Session-Expires refresher", ErrInvalidSIPMessage)
		}
	}
	return interval, refresher, nil
}

func sessionRefreshDelay(interval int) time.Duration {
	if interval <= 1 {
		return time.Second
	}
	return time.Duration(interval/2) * time.Second
}

func firstContactURI(headers map[string][]string) string {
	contacts := trimHeaderValues(headerListValues(headers, "Contact"))
	if len(contacts) == 0 {
		return ""
	}
	return extractAddressURI(contacts[0])
}

func sipHeaderTag(value string) string {
	for _, part := range splitSIPHeaderParams(value) {
		key, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "tag") {
			return strings.TrimSpace(strings.Trim(raw, `"`))
		}
	}
	return ""
}

func splitSIPHeaderParams(s string) []string {
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
		case r == ';' && !inQuote && angleDepth == 0:
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
