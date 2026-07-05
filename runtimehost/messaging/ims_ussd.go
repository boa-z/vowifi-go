package messaging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

type IMSUSSDTransport struct {
	Transport       voiceclient.SIPRequestTransport
	Profile         voiceclient.IMSProfile
	Registration    voiceclient.RegistrationBinding
	Domain          string
	LocalURI        string
	ContactURI      string
	RemoteTargetURI string
	UserAgent       string
	LocalTag        string
	Language        string
	SessionExpires  int

	mu       sync.Mutex
	sessions map[string]imsUSSDSession
}

type imsUSSDSession struct {
	cfg  voiceclient.DialogRequestConfig
	cseq int
}

func (t *IMSUSSDTransport) ExecuteUSSD(ctx context.Context, req USSDRequest) (USSDResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if t == nil || t.Transport == nil {
		return USSDResult{SessionID: req.SessionID, Done: true}, ErrUSSDTransportUnavailable
	}
	command := strings.TrimSpace(req.Command)
	if command == "" {
		return USSDResult{SessionID: req.SessionID, Done: true}, errors.New("ussd command is empty")
	}
	sessionID := firstNonEmpty(req.SessionID, fmt.Sprintf("ussd-%d", len(command)))
	cfg, err := t.dialogConfig(command, sessionID, 1)
	if err != nil {
		return USSDResult{SessionID: sessionID, Done: true}, err
	}
	xmlBody, err := BuildIMSUSSDXML(IMSUSSDPayload{
		Language:  firstNonEmpty(t.Language, "en"),
		Text:      command,
		Operation: IMSUSSDOperationRequest,
	})
	if err != nil {
		return USSDResult{SessionID: sessionID, Done: true}, err
	}
	boundary := "vowifi-ussd-" + smsToken(sessionID)
	body := buildIMSUSSDMultipartBody(firstNonEmpty(t.Profile.LocalIP, "0.0.0.0"), boundary, xmlBody)
	invite, err := voiceclient.BuildInviteRequest(cfg, body)
	if err != nil {
		return USSDResult{SessionID: sessionID, Done: true}, err
	}
	prepareUSSDInvite(&invite, boundary)
	resp, err := t.Transport.RoundTripRequest(ctx, invite)
	if err != nil {
		return USSDResult{SessionID: sessionID, Done: true, Status: resp.StatusCode}, err
	}
	cfg.RemoteTag = sipHeaderTagValue(firstHeaderValue(resp.Headers, "To"))
	if contact := sipHeaderURIValue(firstHeaderValue(resp.Headers, "Contact")); contact != "" {
		cfg.RemoteTargetURI = contact
	}
	result, err := ussdResultFromSIPResponse(sessionID, resp, false)
	if err != nil {
		result.Done = true
		return result, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := t.writeUSSDACK(ctx, cfg); err != nil {
			result.Done = true
			return result, err
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Done = true
		return result, fmt.Errorf("IMS USSD INVITE rejected: %d %s", resp.StatusCode, strings.TrimSpace(resp.Reason))
	}
	if !result.Done {
		t.storeSession(sessionID, imsUSSDSession{cfg: cfg, cseq: 1})
	} else {
		t.clearSession(sessionID)
	}
	return result, nil
}

func (t *IMSUSSDTransport) ContinueUSSD(ctx context.Context, req USSDRequest) (USSDResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if t == nil || t.Transport == nil {
		return USSDResult{SessionID: req.SessionID, Done: true}, ErrUSSDTransportUnavailable
	}
	sessionID := strings.TrimSpace(req.SessionID)
	if sessionID == "" {
		return USSDResult{}, errors.New("ussd session_id is empty")
	}
	input := strings.TrimSpace(req.Input)
	if input == "" {
		return USSDResult{SessionID: sessionID}, errors.New("ussd input is empty")
	}
	state, ok := t.session(sessionID)
	if !ok {
		return USSDResult{SessionID: sessionID, Done: true}, fmt.Errorf("ussd session %s is not active", sessionID)
	}
	state.cseq++
	state.cfg.CSeq = state.cseq
	xmlBody, err := BuildIMSUSSDXML(IMSUSSDPayload{
		Language:  firstNonEmpty(t.Language, "en"),
		Text:      input,
		Operation: IMSUSSDOperationRequest,
	})
	if err != nil {
		return USSDResult{SessionID: sessionID, Done: true}, err
	}
	info, err := voiceclient.BuildInfoRequest(state.cfg, IMSUSSDContentType, xmlBody)
	if err != nil {
		return USSDResult{SessionID: sessionID, Done: true}, err
	}
	prepareUSSDInfo(&info)
	resp, err := t.Transport.RoundTripRequest(ctx, info)
	if err != nil {
		return USSDResult{SessionID: sessionID, Done: true, Status: resp.StatusCode}, err
	}
	result, parseErr := ussdResultFromSIPResponse(sessionID, resp, false)
	if parseErr != nil {
		result.Done = true
		t.clearSession(sessionID)
		return result, parseErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Done = true
		t.clearSession(sessionID)
		return result, fmt.Errorf("IMS USSD INFO rejected: %d %s", resp.StatusCode, strings.TrimSpace(resp.Reason))
	}
	if result.Done {
		t.clearSession(sessionID)
	} else {
		t.storeSession(sessionID, state)
	}
	return result, nil
}

func (t *IMSUSSDTransport) CancelUSSD(ctx context.Context, req USSDRequest) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if t == nil || t.Transport == nil {
		return ErrUSSDTransportUnavailable
	}
	sessionID := strings.TrimSpace(req.SessionID)
	if sessionID == "" {
		return errors.New("ussd session_id is empty")
	}
	state, ok := t.session(sessionID)
	if !ok {
		return nil
	}
	state.cseq++
	state.cfg.CSeq = state.cseq
	bye, err := voiceclient.BuildByeRequest(state.cfg)
	if err != nil {
		return err
	}
	resp, err := t.Transport.RoundTripRequest(ctx, bye)
	t.clearSession(sessionID)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("IMS USSD BYE rejected: %d %s", resp.StatusCode, strings.TrimSpace(resp.Reason))
	}
	return nil
}

func (t *IMSUSSDTransport) dialogConfig(command, sessionID string, cseq int) (voiceclient.DialogRequestConfig, error) {
	remoteURI := t.remoteURI(command)
	if remoteURI == "" {
		return voiceclient.DialogRequestConfig{}, errors.New("IMS USSD remote URI is empty")
	}
	localURI := firstNonEmpty(t.LocalURI, t.Registration.PublicIdentity, t.Profile.IMPU)
	if localURI == "" {
		return voiceclient.DialogRequestConfig{}, errors.New("IMS USSD local identity is empty")
	}
	return voiceclient.DialogRequestConfig{
		Profile:         t.Profile,
		Registration:    t.Registration,
		LocalURI:        localURI,
		ContactURI:      firstNonEmpty(t.ContactURI, t.Registration.ContactURI),
		RemoteURI:       remoteURI,
		RemoteTargetURI: firstNonEmpty(t.RemoteTargetURI, remoteURI),
		CallID:          "ussd-" + smsToken(sessionID) + "@vowifi-go",
		LocalTag:        firstNonEmpty(t.LocalTag, "ussd"),
		CSeq:            cseq,
		UserAgent:       firstNonEmpty(t.UserAgent, t.Profile.UserAgent, "vowifi-go"),
		SessionExpires:  t.SessionExpires,
	}, nil
}

func (t *IMSUSSDTransport) remoteURI(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	lower := strings.ToLower(command)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") || strings.HasPrefix(lower, "tel:") {
		return command
	}
	domain := firstNonEmpty(t.Domain, t.Profile.Domain, smsDomainFromURI(t.Registration.PublicIdentity), smsDomainFromURI(t.Profile.IMPU))
	encoded := encodeUSSDDialString(command)
	if domain == "" {
		return "tel:" + encoded
	}
	return "sip:" + encoded + "@" + domain + ";user=dialstring"
}

func (t *IMSUSSDTransport) writeUSSDACK(ctx context.Context, cfg voiceclient.DialogRequestConfig) error {
	ack, err := voiceclient.BuildAckRequest(cfg)
	if err != nil {
		return err
	}
	return t.Transport.WriteRequest(ctx, ack)
}

func (t *IMSUSSDTransport) session(sessionID string) (imsUSSDSession, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sessions == nil {
		return imsUSSDSession{}, false
	}
	state, ok := t.sessions[strings.TrimSpace(sessionID)]
	return state, ok
}

func (t *IMSUSSDTransport) storeSession(sessionID string, state imsUSSDSession) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sessions == nil {
		t.sessions = make(map[string]imsUSSDSession)
	}
	t.sessions[strings.TrimSpace(sessionID)] = state
}

func (t *IMSUSSDTransport) clearSession(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sessions, strings.TrimSpace(sessionID))
}

func prepareUSSDInvite(msg *voiceclient.SIPRequestMessage, boundary string) {
	if msg.Headers == nil {
		msg.Headers = make(map[string]string)
	}
	msg.Headers["Content-Type"] = `multipart/mixed;boundary="` + boundary + `"`
	msg.Headers["Accept"] = IMSUSSDContentType + ", application/sdp, multipart/mixed"
	msg.Headers["Recv-Info"] = IMSUSSDInfoPackage
	msg.Headers["P-Preferred-Service"] = "urn:urn-7:3gpp-service.ims.icsi.ussd"
	msg.Headers["Accept-Contact"] = "*;+g.3gpp.ussd"
}

func prepareUSSDInfo(msg *voiceclient.SIPRequestMessage) {
	if msg.Headers == nil {
		msg.Headers = make(map[string]string)
	}
	msg.Headers["Info-Package"] = IMSUSSDInfoPackage
	msg.Headers["Content-Disposition"] = IMSUSSDContentDisposition
	msg.Headers["Accept"] = IMSUSSDContentType
	msg.Headers["Recv-Info"] = IMSUSSDInfoPackage
}

func buildIMSUSSDMultipartBody(localIP, boundary string, ussdBody []byte) []byte {
	localIP = firstNonEmpty(localIP, "0.0.0.0")
	var out bytes.Buffer
	out.WriteString("--")
	out.WriteString(boundary)
	out.WriteString("\r\nContent-Type: application/sdp\r\n\r\n")
	out.WriteString("v=0\r\n")
	out.WriteString("o=- 0 0 IN IP4 ")
	out.WriteString(localIP)
	out.WriteString("\r\n")
	out.WriteString("s=-\r\n")
	out.WriteString("c=IN IP4 ")
	out.WriteString(localIP)
	out.WriteString("\r\n")
	out.WriteString("t=0 0\r\n")
	out.WriteString("m=message 0 TCP/MSRP *\r\n")
	out.WriteString("a=recvonly\r\n")
	out.WriteString("--")
	out.WriteString(boundary)
	out.WriteString("\r\nContent-Type: ")
	out.WriteString(IMSUSSDContentType)
	out.WriteString("\r\nContent-Disposition: ")
	out.WriteString(IMSUSSDContentDisposition)
	out.WriteString("\r\n\r\n")
	out.Write(ussdBody)
	out.WriteString("\r\n--")
	out.WriteString(boundary)
	out.WriteString("--\r\n")
	return out.Bytes()
}

func ussdResultFromSIPResponse(sessionID string, resp voiceclient.SIPResponse, doneFallback bool) (USSDResult, error) {
	contentType := firstHeaderValue(resp.Headers, "Content-Type")
	payload, ok, err := DecodeIMSUSSDDocument(contentType, resp.Body)
	if err != nil {
		return USSDResult{SessionID: sessionID, Status: resp.StatusCode, Done: true}, err
	}
	if ok {
		return ussdResultFromPayload(sessionID, payload, resp.StatusCode), nil
	}
	return USSDResult{SessionID: sessionID, Status: resp.StatusCode, Done: doneFallback}, nil
}

func encodeUSSDDialString(command string) string {
	var b strings.Builder
	const hex = "0123456789ABCDEF"
	for _, c := range []byte(command) {
		switch {
		case c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == '*':
			b.WriteByte(c)
		case c == '#':
			b.WriteString("%23")
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}

func firstHeaderValue(headers map[string][]string, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
	}
	return ""
}

func sipHeaderTagValue(value string) string {
	for _, part := range strings.Split(value, ";") {
		key, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "tag") {
			return strings.Trim(strings.TrimSpace(raw), `"`)
		}
	}
	return ""
}

func sipHeaderURIValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if start := strings.IndexByte(value, '<'); start >= 0 {
		if end := strings.IndexByte(value[start+1:], '>'); end >= 0 {
			return strings.TrimSpace(value[start+1 : start+1+end])
		}
	}
	if semi := strings.IndexByte(value, ';'); semi >= 0 {
		value = value[:semi]
	}
	return strings.TrimSpace(strings.Trim(value, "<>"))
}
