package voicehost

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

var ErrIMSVoiceAgentNotReady = errors.New("ims voice agent not ready")

type IMSOutboundAgent struct {
	Transport       voiceclient.SIPRequestTransport
	Profile         voiceclient.IMSProfile
	Registration    voiceclient.RegistrationBinding
	Domain          string
	UserAgent       string
	LocalTag        string
	SessionExpires  int
	RemoteTargetURI string
	MediaRelay      *RTPRelayConfig

	mu      sync.Mutex
	dialogs map[string]imsDialogState
}

type imsDialogState struct {
	cfg   voiceclient.DialogRequestConfig
	relay *RTPRelaySession
}

func (a *IMSOutboundAgent) StartOutboundCall(ctx context.Context, req OutboundCallRequest) (OutboundCallResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.Transport == nil {
		return OutboundCallResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
	}
	if strings.TrimSpace(req.CallID) == "" {
		return OutboundCallResult{Accepted: false, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	remoteURI := a.remoteURI(req.Callee)
	if remoteURI == "" {
		return OutboundCallResult{Accepted: false, Reason: "callee empty"}, errors.New("callee is empty")
	}
	cfg := voiceclient.DialogRequestConfig{
		Profile:         a.Profile,
		Registration:    a.Registration,
		LocalURI:        firstVoiceNonEmpty(a.Registration.PublicIdentity, a.Profile.IMPU),
		ContactURI:      a.Registration.ContactURI,
		RemoteURI:       remoteURI,
		RemoteTargetURI: firstVoiceNonEmpty(a.RemoteTargetURI, remoteURI),
		CallID:          strings.TrimSpace(req.CallID),
		LocalTag:        firstVoiceNonEmpty(a.LocalTag, "vowifi-go"),
		CSeq:            1,
		UserAgent:       firstVoiceNonEmpty(a.UserAgent, a.Profile.UserAgent, "vowifi-go"),
		SessionExpires:  a.SessionExpires,
	}
	inviteBody := append([]byte(nil), req.RawSDP...)
	var relay *RTPRelaySession
	if a.MediaRelay != nil {
		createdRelay, relayErr := NewRTPRelaySession(ctx, *a.MediaRelay, req.RemoteSDP)
		if relayErr != nil {
			return OutboundCallResult{Accepted: false, Reason: "RTP relay setup failed"}, relayErr
		}
		relay = createdRelay
		inviteBody = RewriteSDPMediaEndpoint(req.RawSDP, relay.IMSEndpoint())
	}
	closeRelayOnError := true
	defer func() {
		if closeRelayOnError && relay != nil {
			_ = relay.Close()
		}
	}()
	invite, err := voiceclient.BuildInviteRequest(cfg, inviteBody)
	if err != nil {
		return OutboundCallResult{Accepted: false, Reason: "build IMS INVITE failed"}, err
	}
	resp, err := a.Transport.RoundTripRequest(ctx, invite)
	if err != nil {
		return OutboundCallResult{Accepted: false, Reason: "IMS INVITE failed"}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return OutboundCallResult{
			Accepted: false,
			Reason:   firstVoiceNonEmpty(resp.Reason, fmt.Sprintf("IMS rejected call: %d", resp.StatusCode)),
		}, nil
	}
	cfg.RemoteTag = sipHeaderTag(firstVoiceHeader(resp.Headers, "To"))
	if contact := sipHeaderURI(firstVoiceHeader(resp.Headers, "Contact")); contact != "" {
		cfg.RemoteTargetURI = contact
	}
	ack, err := voiceclient.BuildAckRequest(cfg)
	if err != nil {
		return OutboundCallResult{Accepted: false, Reason: "build IMS ACK failed"}, err
	}
	if err := a.Transport.WriteRequest(ctx, ack); err != nil {
		return OutboundCallResult{Accepted: false, Reason: "IMS ACK failed"}, err
	}
	localSDP, err := ParseSDP(resp.Body)
	if err != nil {
		return OutboundCallResult{Accepted: false, Reason: "invalid IMS SDP answer"}, err
	}
	answerBody := append([]byte(nil), resp.Body...)
	if relay != nil {
		if err := relay.SetIMSRemote(localSDP); err != nil {
			return OutboundCallResult{Accepted: false, Reason: "RTP relay remote setup failed"}, err
		}
		answerBody = RewriteSDPMediaEndpoint(resp.Body, relay.ClientEndpoint())
		localSDP, err = ParseSDP(answerBody)
		if err != nil {
			return OutboundCallResult{Accepted: false, Reason: "invalid RTP relay SDP answer"}, err
		}
	}
	a.mu.Lock()
	if a.dialogs == nil {
		a.dialogs = make(map[string]imsDialogState)
	}
	byeCfg := cfg
	byeCfg.CSeq = 2
	a.dialogs[strings.TrimSpace(req.CallID)] = imsDialogState{cfg: byeCfg, relay: relay}
	a.mu.Unlock()
	closeRelayOnError = false
	return OutboundCallResult{
		Accepted: true,
		Reason:   firstVoiceNonEmpty(resp.Reason, "OK"),
		LocalSDP: localSDP,
		RawSDP:   answerBody,
	}, nil
}

func (a *IMSOutboundAgent) EndVoiceCall(ctx context.Context, info DialogInfo) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.Transport == nil {
		return ErrIMSVoiceAgentNotReady
	}
	callID := strings.TrimSpace(info.CallID)
	if callID == "" {
		return nil
	}
	a.mu.Lock()
	state, ok := a.dialogs[callID]
	a.mu.Unlock()
	if !ok {
		return nil
	}
	bye, err := voiceclient.BuildByeRequest(state.cfg)
	if err != nil {
		return err
	}
	resp, err := a.Transport.RoundTripRequest(ctx, bye)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("IMS BYE rejected: %d %s", resp.StatusCode, strings.TrimSpace(resp.Reason))
	}
	if state.relay != nil {
		_ = state.relay.Close()
	}
	a.mu.Lock()
	delete(a.dialogs, callID)
	a.mu.Unlock()
	return nil
}

func (a *IMSOutboundAgent) remoteURI(callee string) string {
	callee = strings.TrimSpace(callee)
	if callee == "" {
		return ""
	}
	lower := strings.ToLower(callee)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") || strings.HasPrefix(lower, "tel:") {
		return callee
	}
	domain := firstVoiceNonEmpty(a.Domain, a.Profile.Domain, domainFromURI(a.Registration.PublicIdentity))
	if domain == "" {
		return "sip:" + callee
	}
	return "sip:" + callee + "@" + domain
}

func firstVoiceHeader(headers map[string][]string, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
	}
	return ""
}

func sipHeaderURI(value string) string {
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

func sipHeaderTag(value string) string {
	for _, part := range strings.Split(value, ";") {
		key, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "tag") {
			return strings.Trim(strings.TrimSpace(raw), `"`)
		}
	}
	return ""
}

func domainFromURI(uri string) string {
	uri = strings.TrimSpace(uri)
	if strings.HasPrefix(strings.ToLower(uri), "sip:") {
		uri = uri[4:]
	}
	if _, host, ok := strings.Cut(uri, "@"); ok {
		if semi := strings.IndexByte(host, ';'); semi >= 0 {
			host = host[:semi]
		}
		return strings.Trim(strings.TrimSpace(host), "<>")
	}
	return ""
}

func firstVoiceNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}
