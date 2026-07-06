package voicehost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
)

const (
	DefaultSimulateCallHoldSeconds = 10
	MaxSimulateCallHoldSeconds     = 300
)

type ClientAdapter interface {
	GetClientContact(deviceID string) (contactURI string, contactIP string, username string, err error)
}

type Agent interface{}

type OutboundCallAgent interface {
	StartOutboundCall(context.Context, OutboundCallRequest) (OutboundCallResult, error)
}

type DialogTerminator interface {
	EndVoiceCall(context.Context, DialogInfo) error
}

type DialogTerminatorWithResult interface {
	EndVoiceCallWithResult(context.Context, DialogInfo) (DialogInfoResult, error)
}

type DialogCanceller interface {
	CancelVoiceCall(context.Context, DialogInfo) error
}

type DialogCancellerWithResult interface {
	CancelVoiceCallWithResult(context.Context, DialogInfo) (DialogInfoResult, error)
}

type DialogInfoSender interface {
	SendDialogInfo(context.Context, DialogInfoRequest) (DialogInfoResult, error)
}

type DialogMessageSender interface {
	SendDialogMessage(context.Context, DialogMessageRequest) (DialogMessageResult, error)
}

type DialogPrackSender interface {
	SendDialogPrack(context.Context, DialogPrackRequest) (DialogPrackResult, error)
}

type DialogOptionsSender interface {
	SendDialogOptions(context.Context, DialogOptionsRequest) (DialogOptionsResult, error)
}

type DialogReferSender interface {
	SendDialogRefer(context.Context, DialogReferRequest) (DialogReferResult, error)
}

type DialogNotifySender interface {
	SendDialogNotify(context.Context, DialogNotifyRequest) (DialogNotifyResult, error)
}

type DialogSubscribeSender interface {
	SendDialogSubscribe(context.Context, DialogSubscribeRequest) (DialogSubscribeResult, error)
}

type DialogUpdater interface {
	SendDialogUpdate(context.Context, DialogUpdateRequest) (DialogUpdateResult, error)
}

type DialogReinviter interface {
	SendDialogReinvite(context.Context, DialogReinviteRequest) (DialogReinviteResult, error)
}

type DialogHoldController interface {
	SendDialogHold(context.Context, DialogHoldRequest) (DialogUpdateResult, error)
	SendDialogResume(context.Context, DialogResumeRequest) (DialogUpdateResult, error)
}

type OutboundCallRequest struct {
	DeviceID   string
	CallID     string
	Callee     string
	RequestURI string
	RouteSet   []string
	RemoteSDP  SDPInfo
	RawSDP     []byte
	Headers    map[string]string
}

type OutboundCallResult struct {
	Accepted                   bool
	StatusCode                 int
	Reason                     string
	RegistrationRecoveryNeeded bool
	RetryAfter                 time.Duration
	LocalSDP                   SDPInfo
	RawSDP                     []byte
	Headers                    map[string]string
}

type DialogInfo struct {
	DeviceID    string
	CallID      string
	Callee      string
	State       DialogState
	CSeq        int
	ContentType string
	Body        []byte
	Headers     map[string]string
}

type DialogState string

const (
	DialogStateEarly       DialogState = "early"
	DialogStateEstablished DialogState = "established"
	DialogStateTerminated  DialogState = "terminated"
)

type DialogInfoRequest struct {
	DeviceID    string
	CallID      string
	ContentType string
	InfoPackage string
	Body        []byte
	Headers     map[string]string
}

type DialogInfoResult struct {
	Accepted                   bool
	StatusCode                 int
	Reason                     string
	RegistrationRecoveryNeeded bool
	RetryAfter                 time.Duration
	ContentType                string
	Body                       []byte
	Headers                    map[string]string
}

type DialogMessageRequest struct {
	DeviceID    string
	CallID      string
	ContentType string
	Body        []byte
	Headers     map[string]string
}

type DialogMessageResult = DialogInfoResult

type DialogPrackRequest struct {
	DeviceID    string
	CallID      string
	RAck        string
	ContentType string
	Body        []byte
	Headers     map[string]string
}

type DialogPrackResult = DialogInfoResult

type DialogOptionsRequest struct {
	DeviceID string
	CallID   string
	Headers  map[string]string
}

type DialogOptionsResult = DialogInfoResult

type DialogReferRequest struct {
	DeviceID   string
	CallID     string
	ReferTo    string
	ReferredBy string
	ReferSub   string
	Headers    map[string]string
}

type DialogReferResult = DialogInfoResult

type DialogNotifyRequest struct {
	DeviceID          string
	CallID            string
	Event             string
	SubscriptionState string
	ContentType       string
	Body              []byte
	Headers           map[string]string
}

type DialogNotifyResult = DialogInfoResult

type DialogSubscribeRequest struct {
	DeviceID    string
	CallID      string
	Event       string
	Expires     string
	ContentType string
	Body        []byte
	Headers     map[string]string
}

type DialogSubscribeResult = DialogInfoResult

type DialogUpdateRequest struct {
	DeviceID    string
	CallID      string
	ContentType string
	Body        []byte
	Headers     map[string]string
}

type DialogUpdateResult struct {
	Accepted                   bool
	StatusCode                 int
	Reason                     string
	RegistrationRecoveryNeeded bool
	RetryAfter                 time.Duration
	ContentType                string
	Body                       []byte
	Headers                    map[string]string
}

type DialogReinviteRequest struct {
	DeviceID    string
	CallID      string
	ContentType string
	Body        []byte
	Headers     map[string]string
}

type DialogReinviteResult struct {
	Accepted                   bool
	StatusCode                 int
	Reason                     string
	RegistrationRecoveryNeeded bool
	RetryAfter                 time.Duration
	ContentType                string
	Body                       []byte
	Headers                    map[string]string
}

type DialogHoldRequest struct {
	DeviceID    string
	CallID      string
	Direction   string
	ContentType string
	Headers     map[string]string
}

type DialogResumeRequest struct {
	DeviceID    string
	CallID      string
	ContentType string
	Headers     map[string]string
}

type Gateway struct {
	mu       sync.RWMutex
	agents   map[string]Agent
	dialogs  map[string]DialogInfo
	client   ClientAdapter
	notifier any
	started  bool
}

func NewGateway() *Gateway {
	return &Gateway{agents: make(map[string]Agent), dialogs: make(map[string]DialogInfo)}
}

func (g *Gateway) Start(ctx context.Context) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	g.started = true
	g.mu.Unlock()
	return nil
}

func (g *Gateway) Stop() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	g.started = false
	g.mu.Unlock()
	return nil
}

func (g *Gateway) SetClientAdapter(a ClientAdapter) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.client = a
	g.mu.Unlock()
}

func (g *Gateway) SetNotifier(n any) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.notifier = n
	g.mu.Unlock()
}

func (g *Gateway) RegisterAgent(deviceID string, agent Agent) {
	if g == nil || strings.TrimSpace(deviceID) == "" {
		return
	}
	g.mu.Lock()
	if g.agents == nil {
		g.agents = make(map[string]Agent)
	}
	g.agents[strings.TrimSpace(deviceID)] = agent
	g.mu.Unlock()
}

func (g *Gateway) GetAgent(deviceID string) Agent {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.agents[strings.TrimSpace(deviceID)]
}

func (g *Gateway) DeviceStatus(deviceID string) map[string]interface{} {
	dialogs := 0
	if g != nil {
		g.mu.RLock()
		for _, d := range g.dialogs {
			if d.DeviceID == strings.TrimSpace(deviceID) && d.State != DialogStateTerminated {
				dialogs++
			}
		}
		g.mu.RUnlock()
	}
	return map[string]interface{}{
		"ready":          g != nil && g.GetAgent(deviceID) != nil,
		"device":         strings.TrimSpace(deviceID),
		"active_dialogs": dialogs,
	}
}

type SimulateCallRequest struct {
	Callee      string `json:"callee"`
	HoldSeconds int    `json:"hold_seconds"`
	OnConnected func() `json:"-"`
}

type SimulateCallResult struct {
	Success    bool   `json:"success"`
	Reason     string `json:"reason,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

func (g *Gateway) SimulateCall(ctx context.Context, deviceID string, req SimulateCallRequest) (SimulateCallResult, error) {
	if g == nil || g.GetAgent(deviceID) == nil {
		return SimulateCallResult{Success: false, Reason: "agent not ready"}, errors.New("voice agent not ready")
	}
	if strings.TrimSpace(req.Callee) == "" {
		return SimulateCallResult{Success: false, Reason: "callee empty"}, errors.New("callee is empty")
	}
	hold := req.HoldSeconds
	if hold <= 0 {
		hold = DefaultSimulateCallHoldSeconds
	}
	if hold > MaxSimulateCallHoldSeconds {
		hold = MaxSimulateCallHoldSeconds
	}
	if req.OnConnected != nil {
		req.OnConnected()
	}
	timer := time.NewTimer(time.Duration(hold) * time.Second)
	select {
	case <-ctx.Done():
		timer.Stop()
		return SimulateCallResult{Success: false, Reason: ctx.Err().Error()}, ctx.Err()
	case <-timer.C:
		return SimulateCallResult{Success: true, DurationMs: int64(hold) * 1000}, nil
	}
}

func (g *Gateway) HandleClientInvite(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if tx == nil || req == nil {
		return
	}
	callID := sipCallID(req)
	if callID == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Call-ID", nil))
		return
	}
	remoteSDP, err := ParseSDP(req.Body())
	if err != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 488, "Invalid SDP", nil))
		return
	}
	if dialog := g.dialog(callID); dialog.State == DialogStateEstablished {
		g.handleClientReinvite(deviceID, req, tx, callID)
		return
	}
	agent, _ := g.GetAgent(deviceID).(OutboundCallAgent)
	if agent == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi voice bridge unavailable", nil))
		return
	}
	callee := sipCallee(req)
	if callee == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing callee", nil))
		return
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
	g.recordDialog(DialogInfo{DeviceID: deviceID, CallID: callID, Callee: callee, State: DialogStateEarly})
	result, err := agent.StartOutboundCall(context.Background(), OutboundCallRequest{
		DeviceID:  strings.TrimSpace(deviceID),
		CallID:    callID,
		Callee:    callee,
		RemoteSDP: remoteSDP,
		RawSDP:    append([]byte(nil), req.Body()...),
	})
	if err != nil {
		g.recordDialog(DialogInfo{DeviceID: deviceID, CallID: callID, Callee: callee, State: DialogStateTerminated})
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi voice setup failed", nil))
		return
	}
	if !result.Accepted {
		g.recordDialog(DialogInfo{DeviceID: deviceID, CallID: callID, Callee: callee, State: DialogStateTerminated})
		reason := strings.TrimSpace(result.Reason)
		if reason == "" {
			reason = "Busy Here"
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, localFinalStatusCode(result.StatusCode, 486), reason, nil))
		return
	}
	body := append([]byte(nil), result.RawSDP...)
	if len(body) == 0 {
		body = BuildSDPAnswer(result.LocalSDP)
	}
	res := sip.NewResponseFromRequest(req, 200, "OK", body)
	res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	for key, value := range result.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogHeader(key) {
			continue
		}
		res.AppendHeader(sip.NewHeader(key, value))
	}
	g.recordDialog(DialogInfo{DeviceID: deviceID, CallID: callID, Callee: callee, State: DialogStateEstablished})
	_ = tx.Respond(res)
}

func (g *Gateway) handleClientReinvite(deviceID string, req *sip.Request, tx sip.ServerTransaction, callID string) {
	reinviter, _ := g.GetAgent(deviceID).(DialogReinviter)
	if reinviter == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi voice bridge unavailable", nil))
		return
	}
	contentType := sipHeaderValue(req, "Content-Type")
	if strings.TrimSpace(contentType) != "" && !isSIPSDPContentType(contentType) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 415, "Unsupported Media Type", nil))
		return
	}
	result, err := reinviter.SendDialogReinvite(context.Background(), DialogReinviteRequest{
		DeviceID:    strings.TrimSpace(deviceID),
		CallID:      callID,
		ContentType: contentType,
		Body:        append([]byte(nil), req.Body()...),
		Headers:     sipRequestHeaderMap(req),
	})
	if err != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi re-INVITE failed", nil))
		return
	}
	statusCode := localFinalStatusCode(result.StatusCode, 488)
	reason := firstVoiceNonEmpty(result.Reason, "OK")
	if result.Accepted {
		statusCode = localDialogInfoStatusCode(result.StatusCode, true)
	}
	body := append([]byte(nil), result.Body...)
	res := sip.NewResponseFromRequest(req, statusCode, reason, body)
	if len(body) > 0 {
		res.AppendHeader(sip.NewHeader("Content-Type", firstVoiceNonEmpty(result.ContentType, "application/sdp")))
	}
	for key, value := range result.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogHeader(key) {
			continue
		}
		res.AppendHeader(sip.NewHeader(key, value))
	}
	_ = tx.Respond(res)
}

func (g *Gateway) HandleClientCancel(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if req == nil {
		return
	}
	callID := sipCallID(req)
	if callID == "" {
		if tx != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Call-ID", nil))
		}
		return
	}
	dialog := g.dialog(callID)
	dialog.DeviceID = firstVoiceNonEmpty(dialog.DeviceID, strings.TrimSpace(deviceID))
	dialog.ContentType = sipHeaderValue(req, "Content-Type")
	dialog.Body = append([]byte(nil), req.Body()...)
	dialog.Headers = sipRequestHeaderMap(req)
	dialog.State = DialogStateTerminated
	agent := g.GetAgent(deviceID)
	if canceller, ok := agent.(DialogCancellerWithResult); ok {
		result, err := canceller.CancelVoiceCallWithResult(context.Background(), dialog)
		if dialogResultTerminatesLocalDialog(result, err) {
			g.recordDialog(dialog)
		}
		if tx != nil {
			_ = tx.Respond(dialogInfoResultResponse(req, result, err, "VoWiFi CANCEL failed"))
		}
		return
	}
	if canceller, ok := agent.(DialogCanceller); ok {
		err := canceller.CancelVoiceCall(context.Background(), dialog)
		if err == nil {
			g.recordDialog(dialog)
		}
		if tx != nil {
			_ = tx.Respond(legacyDialogActionResponse(req, err, "VoWiFi CANCEL failed"))
		}
		return
	}
	g.recordDialog(dialog)
	if tx != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	}
}

func (g *Gateway) HandleClientPrack(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if tx == nil || req == nil {
		return
	}
	sender, _ := g.GetAgent(deviceID).(DialogPrackSender)
	if sender == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi voice bridge unavailable", nil))
		return
	}
	callID := sipCallID(req)
	if callID == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Call-ID", nil))
		return
	}
	rack := sipHeaderValue(req, "RAck")
	if strings.TrimSpace(rack) == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing RAck", nil))
		return
	}
	body := append([]byte(nil), req.Body()...)
	contentType := sipHeaderValue(req, "Content-Type")
	if len(body) > 0 {
		if strings.TrimSpace(contentType) != "" && !isSIPSDPContentType(contentType) {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 415, "Unsupported Media Type", nil))
			return
		}
		if _, err := ParseSDP(body); err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 488, "Invalid SDP", nil))
			return
		}
	}
	result, err := sender.SendDialogPrack(context.Background(), DialogPrackRequest{
		DeviceID:    strings.TrimSpace(deviceID),
		CallID:      callID,
		RAck:        rack,
		ContentType: contentType,
		Body:        body,
		Headers:     sipRequestHeaderMap(req),
	})
	if err != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi PRACK failed", nil))
		return
	}
	statusCode := localDialogInfoStatusCode(result.StatusCode, result.Accepted)
	reason := firstVoiceNonEmpty(result.Reason, "OK")
	resBody := append([]byte(nil), result.Body...)
	res := sip.NewResponseFromRequest(req, statusCode, reason, resBody)
	if len(resBody) > 0 {
		res.AppendHeader(sip.NewHeader("Content-Type", firstVoiceNonEmpty(result.ContentType, "application/sdp")))
	}
	for key, value := range result.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogHeader(key) {
			continue
		}
		res.AppendHeader(sip.NewHeader(key, value))
	}
	_ = tx.Respond(res)
}

func (g *Gateway) HandleClientOptions(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if tx == nil || req == nil {
		return
	}
	sender, _ := g.GetAgent(deviceID).(DialogOptionsSender)
	if sender == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi voice bridge unavailable", nil))
		return
	}
	callID := sipCallID(req)
	if callID == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Call-ID", nil))
		return
	}
	result, err := sender.SendDialogOptions(context.Background(), DialogOptionsRequest{
		DeviceID: strings.TrimSpace(deviceID),
		CallID:   callID,
		Headers:  sipRequestHeaderMap(req),
	})
	if err != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi OPTIONS failed", nil))
		return
	}
	statusCode := localDialogInfoStatusCode(result.StatusCode, result.Accepted)
	reason := firstVoiceNonEmpty(result.Reason, "OK")
	body := append([]byte(nil), result.Body...)
	res := sip.NewResponseFromRequest(req, statusCode, reason, body)
	if strings.TrimSpace(result.ContentType) != "" && len(body) > 0 {
		res.AppendHeader(sip.NewHeader("Content-Type", strings.TrimSpace(result.ContentType)))
	}
	for key, value := range result.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogHeader(key) {
			continue
		}
		res.AppendHeader(sip.NewHeader(key, value))
	}
	_ = tx.Respond(res)
}

func (g *Gateway) HandleClientRefer(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if tx == nil || req == nil {
		return
	}
	sender, _ := g.GetAgent(deviceID).(DialogReferSender)
	if sender == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi voice bridge unavailable", nil))
		return
	}
	callID := sipCallID(req)
	if callID == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Call-ID", nil))
		return
	}
	referTo := sipHeaderValue(req, "Refer-To")
	if strings.TrimSpace(referTo) == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Refer-To", nil))
		return
	}
	referSub := sipHeaderValue(req, "Refer-Sub")
	if _, ok := normalizeReferSub(referSub); !ok {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Invalid Refer-Sub", nil))
		return
	}
	headers := sipRequestHeaderMap(req)
	deleteSIPHeaderValue(headers, "Refer-Sub")
	result, err := sender.SendDialogRefer(context.Background(), DialogReferRequest{
		DeviceID:   strings.TrimSpace(deviceID),
		CallID:     callID,
		ReferTo:    referTo,
		ReferredBy: sipHeaderValue(req, "Referred-By"),
		ReferSub:   referSub,
		Headers:    headers,
	})
	if err != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi REFER failed", nil))
		return
	}
	statusCode := localDialogInfoStatusCode(result.StatusCode, result.Accepted)
	reason := firstVoiceNonEmpty(result.Reason, "Accepted")
	body := append([]byte(nil), result.Body...)
	res := sip.NewResponseFromRequest(req, statusCode, reason, body)
	if strings.TrimSpace(result.ContentType) != "" && len(body) > 0 {
		res.AppendHeader(sip.NewHeader("Content-Type", strings.TrimSpace(result.ContentType)))
	}
	for key, value := range result.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogHeader(key) {
			continue
		}
		res.AppendHeader(sip.NewHeader(key, value))
	}
	_ = tx.Respond(res)
}

func (g *Gateway) HandleClientNotify(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if tx == nil || req == nil {
		return
	}
	sender, _ := g.GetAgent(deviceID).(DialogNotifySender)
	if sender == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi voice bridge unavailable", nil))
		return
	}
	callID := sipCallID(req)
	if callID == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Call-ID", nil))
		return
	}
	event := sipHeaderValue(req, "Event")
	if strings.TrimSpace(event) == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Event", nil))
		return
	}
	subscriptionState := sipHeaderValue(req, "Subscription-State")
	if strings.TrimSpace(subscriptionState) == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Subscription-State", nil))
		return
	}
	result, err := sender.SendDialogNotify(context.Background(), DialogNotifyRequest{
		DeviceID:          strings.TrimSpace(deviceID),
		CallID:            callID,
		Event:             event,
		SubscriptionState: subscriptionState,
		ContentType:       sipHeaderValue(req, "Content-Type"),
		Body:              append([]byte(nil), req.Body()...),
		Headers:           sipRequestHeaderMap(req),
	})
	if err != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi NOTIFY failed", nil))
		return
	}
	statusCode := localDialogInfoStatusCode(result.StatusCode, result.Accepted)
	reason := firstVoiceNonEmpty(result.Reason, "OK")
	body := append([]byte(nil), result.Body...)
	res := sip.NewResponseFromRequest(req, statusCode, reason, body)
	if strings.TrimSpace(result.ContentType) != "" && len(body) > 0 {
		res.AppendHeader(sip.NewHeader("Content-Type", strings.TrimSpace(result.ContentType)))
	}
	for key, value := range result.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogHeader(key) {
			continue
		}
		res.AppendHeader(sip.NewHeader(key, value))
	}
	_ = tx.Respond(res)
}

func (g *Gateway) HandleClientSubscribe(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if tx == nil || req == nil {
		return
	}
	sender, _ := g.GetAgent(deviceID).(DialogSubscribeSender)
	if sender == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi voice bridge unavailable", nil))
		return
	}
	callID := sipCallID(req)
	if callID == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Call-ID", nil))
		return
	}
	event := sipHeaderValue(req, "Event")
	if strings.TrimSpace(event) == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Event", nil))
		return
	}
	headers := sipRequestHeaderMap(req)
	deleteSIPHeaderValue(headers, "Expires")
	result, err := sender.SendDialogSubscribe(context.Background(), DialogSubscribeRequest{
		DeviceID:    strings.TrimSpace(deviceID),
		CallID:      callID,
		Event:       event,
		Expires:     sipHeaderValue(req, "Expires"),
		ContentType: sipHeaderValue(req, "Content-Type"),
		Body:        append([]byte(nil), req.Body()...),
		Headers:     headers,
	})
	if err != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi SUBSCRIBE failed", nil))
		return
	}
	statusCode := localDialogInfoStatusCode(result.StatusCode, result.Accepted)
	reason := firstVoiceNonEmpty(result.Reason, "OK")
	body := append([]byte(nil), result.Body...)
	res := sip.NewResponseFromRequest(req, statusCode, reason, body)
	if strings.TrimSpace(result.ContentType) != "" && len(body) > 0 {
		res.AppendHeader(sip.NewHeader("Content-Type", strings.TrimSpace(result.ContentType)))
	}
	for key, value := range result.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogHeader(key) {
			continue
		}
		res.AppendHeader(sip.NewHeader(key, value))
	}
	_ = tx.Respond(res)
}

func (g *Gateway) HandleClientInfo(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if tx == nil || req == nil {
		return
	}
	sender, _ := g.GetAgent(deviceID).(DialogInfoSender)
	if sender == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi voice bridge unavailable", nil))
		return
	}
	callID := sipCallID(req)
	if callID == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Call-ID", nil))
		return
	}
	result, err := sender.SendDialogInfo(context.Background(), DialogInfoRequest{
		DeviceID:    strings.TrimSpace(deviceID),
		CallID:      callID,
		ContentType: sipHeaderValue(req, "Content-Type"),
		InfoPackage: sipHeaderValue(req, "Info-Package"),
		Body:        append([]byte(nil), req.Body()...),
		Headers:     sipRequestHeaderMap(req),
	})
	if err != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi INFO failed", nil))
		return
	}
	statusCode := localDialogInfoStatusCode(result.StatusCode, result.Accepted)
	reason := firstVoiceNonEmpty(result.Reason, "OK")
	body := append([]byte(nil), result.Body...)
	res := sip.NewResponseFromRequest(req, statusCode, reason, body)
	if strings.TrimSpace(result.ContentType) != "" && len(body) > 0 {
		res.AppendHeader(sip.NewHeader("Content-Type", strings.TrimSpace(result.ContentType)))
	}
	for key, value := range result.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogHeader(key) {
			continue
		}
		res.AppendHeader(sip.NewHeader(key, value))
	}
	_ = tx.Respond(res)
}

func (g *Gateway) HandleClientMessage(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if tx == nil || req == nil {
		return
	}
	sender, _ := g.GetAgent(deviceID).(DialogMessageSender)
	if sender == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi voice bridge unavailable", nil))
		return
	}
	callID := sipCallID(req)
	if callID == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Call-ID", nil))
		return
	}
	result, err := sender.SendDialogMessage(context.Background(), DialogMessageRequest{
		DeviceID:    strings.TrimSpace(deviceID),
		CallID:      callID,
		ContentType: sipHeaderValue(req, "Content-Type"),
		Body:        append([]byte(nil), req.Body()...),
		Headers:     sipRequestHeaderMap(req),
	})
	if err != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi MESSAGE failed", nil))
		return
	}
	statusCode := localDialogInfoStatusCode(result.StatusCode, result.Accepted)
	reason := firstVoiceNonEmpty(result.Reason, "OK")
	body := append([]byte(nil), result.Body...)
	res := sip.NewResponseFromRequest(req, statusCode, reason, body)
	if strings.TrimSpace(result.ContentType) != "" && len(body) > 0 {
		res.AppendHeader(sip.NewHeader("Content-Type", strings.TrimSpace(result.ContentType)))
	}
	for key, value := range result.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogHeader(key) {
			continue
		}
		res.AppendHeader(sip.NewHeader(key, value))
	}
	_ = tx.Respond(res)
}

func (g *Gateway) HandleClientUpdate(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if tx == nil || req == nil {
		return
	}
	updater, _ := g.GetAgent(deviceID).(DialogUpdater)
	if updater == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi voice bridge unavailable", nil))
		return
	}
	callID := sipCallID(req)
	if callID == "" {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Call-ID", nil))
		return
	}
	body := append([]byte(nil), req.Body()...)
	contentType := sipHeaderValue(req, "Content-Type")
	if len(body) > 0 {
		if strings.TrimSpace(contentType) != "" && !isSIPSDPContentType(contentType) {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 415, "Unsupported Media Type", nil))
			return
		}
		if _, err := ParseSDP(body); err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 488, "Invalid SDP", nil))
			return
		}
	}
	result, err := updater.SendDialogUpdate(context.Background(), DialogUpdateRequest{
		DeviceID:    strings.TrimSpace(deviceID),
		CallID:      callID,
		ContentType: contentType,
		Body:        body,
		Headers:     sipRequestHeaderMap(req),
	})
	if err != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "VoWiFi UPDATE failed", nil))
		return
	}
	statusCode := localDialogInfoStatusCode(result.StatusCode, result.Accepted)
	reason := firstVoiceNonEmpty(result.Reason, "OK")
	resBody := append([]byte(nil), result.Body...)
	res := sip.NewResponseFromRequest(req, statusCode, reason, resBody)
	if len(resBody) > 0 {
		res.AppendHeader(sip.NewHeader("Content-Type", firstVoiceNonEmpty(result.ContentType, "application/sdp")))
	}
	for key, value := range result.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogHeader(key) {
			continue
		}
		res.AppendHeader(sip.NewHeader(key, value))
	}
	_ = tx.Respond(res)
}

func (g *Gateway) HandleClientAck(deviceID string, req *sip.Request, tx sip.ServerTransaction) {}

func (g *Gateway) HandleClientBye(deviceID string, req *sip.Request, tx sip.ServerTransaction) {
	if req == nil {
		return
	}
	callID := sipCallID(req)
	if callID == "" {
		if tx != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 400, "Missing Call-ID", nil))
		}
		return
	}
	dialog := g.dialog(callID)
	dialog.DeviceID = firstVoiceNonEmpty(dialog.DeviceID, strings.TrimSpace(deviceID))
	dialog.State = DialogStateTerminated
	dialog.ContentType = sipHeaderValue(req, "Content-Type")
	dialog.Body = append([]byte(nil), req.Body()...)
	dialog.Headers = sipRequestHeaderMap(req)
	agent := g.GetAgent(deviceID)
	if terminator, ok := agent.(DialogTerminatorWithResult); ok {
		result, err := terminator.EndVoiceCallWithResult(context.Background(), dialog)
		if dialogResultTerminatesLocalDialog(result, err) {
			g.recordDialog(dialog)
		}
		if tx != nil {
			_ = tx.Respond(dialogInfoResultResponse(req, result, err, "VoWiFi BYE failed"))
		}
		return
	}
	if terminator, ok := agent.(DialogTerminator); ok {
		err := terminator.EndVoiceCall(context.Background(), dialog)
		if err == nil {
			g.recordDialog(dialog)
		}
		if tx != nil {
			_ = tx.Respond(legacyDialogActionResponse(req, err, "VoWiFi BYE failed"))
		}
		return
	}
	g.recordDialog(dialog)
	if tx != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	}
}

type SDPInfo struct {
	ConnectionIP           string
	MediaPort              int
	RTCPIP                 string
	RTCPPort               int
	Payloads               []int
	TelephoneEventPayloads map[uint8]int
	Direction              string
	PTimeMS                int
	MaxPTimeMS             int
}

var (
	sdpConnRE   = regexp.MustCompile(`(?m)^c=IN IP[46] ([^\r\n]+)`)
	sdpMediaRE  = regexp.MustCompile(`(?m)^m=audio ([0-9]+) [A-Z0-9/]+(.*)$`)
	sdpRTCPRE   = regexp.MustCompile(`(?m)^a=rtcp:([0-9]+)(?:\s+IN\s+IP[46]\s+([^\r\n]+))?`)
	sdpRTPMapRE = regexp.MustCompile(`(?mi)^a=rtpmap:([0-9]+)\s+telephone-event/([0-9]+)(?:/[0-9]+)?\s*$`)
)

func ParseSDP(body []byte) (SDPInfo, error) {
	text := string(body)
	var out SDPInfo
	if m := sdpConnRE.FindStringSubmatch(text); len(m) == 2 {
		out.ConnectionIP = strings.TrimSpace(m[1])
	}
	if out.ConnectionIP == "" {
		out.ConnectionIP = "127.0.0.1"
	}
	ip := net.ParseIP(out.ConnectionIP)
	if ip == nil {
		return SDPInfo{}, errors.New("invalid SDP connection IP")
	}
	hasAudio := false
	if m := sdpMediaRE.FindStringSubmatch(text); len(m) == 3 {
		hasAudio = true
		port, _ := strconv.Atoi(m[1])
		out.MediaPort = port
		for _, part := range strings.Fields(m[2]) {
			payload, err := strconv.Atoi(part)
			if err == nil {
				out.Payloads = append(out.Payloads, payload)
			}
		}
	}
	if !hasAudio {
		return SDPInfo{}, errors.New("missing SDP audio port")
	}
	if m := sdpRTCPRE.FindStringSubmatch(text); len(m) >= 2 {
		port, _ := strconv.Atoi(m[1])
		out.RTCPPort = port
		if len(m) >= 3 && strings.TrimSpace(m[2]) != "" {
			out.RTCPIP = strings.TrimSpace(m[2])
		}
	}
	for _, m := range sdpRTPMapRE.FindAllStringSubmatch(text, -1) {
		payload, _ := strconv.Atoi(m[1])
		clockRate, _ := strconv.Atoi(m[2])
		if payload < 0 || payload > 127 || clockRate <= 0 {
			continue
		}
		if out.TelephoneEventPayloads == nil {
			out.TelephoneEventPayloads = make(map[uint8]int)
		}
		out.TelephoneEventPayloads[uint8(payload)] = clockRate
	}
	if out.TelephoneEventPayloads == nil && sdpPayloadsContain(out.Payloads, DefaultRTPDTMFPayloadType) {
		out.TelephoneEventPayloads = map[uint8]int{DefaultRTPDTMFPayloadType: DefaultRTPDTMFClockRate}
	}
	out.PTimeMS, out.MaxPTimeMS = parseSDPAudioPacketizationTime(body)
	out.Direction = parseSDPAudioDirection(body, out.ConnectionIP, out.MediaPort)
	return out, nil
}

func BuildSDPAnswer(info SDPInfo) []byte {
	ip := strings.TrimSpace(info.ConnectionIP)
	if ip == "" {
		ip = "127.0.0.1"
	}
	ipVersion := "IP4"
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		ipVersion = "IP6"
	}
	port := info.MediaPort
	if port <= 0 {
		if normalizeSDPDirection(info.Direction) != "inactive" {
			port = 4000
		}
	}
	payloads := info.Payloads
	if len(payloads) == 0 {
		payloads = []int{0, 8, 101}
	}
	direction := strings.TrimSpace(info.Direction)
	if direction == "" {
		direction = "sendrecv"
	}
	timingLines := sdpPacketizationTimeAttributeLines(info.PTimeMS, info.MaxPTimeMS)
	var b strings.Builder
	b.WriteString("v=0\r\n")
	b.WriteString("o=vowifi-go 0 0 IN " + ipVersion + " " + ip + "\r\n")
	b.WriteString("s=VoWiFi\r\n")
	b.WriteString("c=IN " + ipVersion + " " + ip + "\r\n")
	b.WriteString("t=0 0\r\n")
	b.WriteString("m=audio " + strconv.Itoa(port) + " RTP/AVP")
	for _, payload := range payloads {
		b.WriteString(" " + strconv.Itoa(payload))
	}
	b.WriteString("\r\n")
	if info.RTCPPort > 0 {
		rtcpIP := strings.TrimSpace(info.RTCPIP)
		if rtcpIP == "" {
			rtcpIP = ip
		}
		rtcpIPVersion := "IP4"
		if parsed := net.ParseIP(rtcpIP); parsed != nil && parsed.To4() == nil {
			rtcpIPVersion = "IP6"
		}
		b.WriteString("a=rtcp:" + strconv.Itoa(info.RTCPPort) + " IN " + rtcpIPVersion + " " + rtcpIP + "\r\n")
	}
	b.WriteString("a=" + direction + "\r\n")
	for _, line := range timingLines {
		b.WriteString(line + "\r\n")
	}
	telephoneEventPayloads := info.TelephoneEventPayloads
	if telephoneEventPayloads == nil && sdpPayloadsContain(payloads, DefaultRTPDTMFPayloadType) {
		telephoneEventPayloads = map[uint8]int{DefaultRTPDTMFPayloadType: DefaultRTPDTMFClockRate}
	}
	for _, payload := range payloads {
		switch payload {
		case 0:
			b.WriteString("a=rtpmap:0 PCMU/8000\r\n")
		case 8:
			b.WriteString("a=rtpmap:8 PCMA/8000\r\n")
		}
		if payload >= 0 && payload <= 127 {
			if clockRate, ok := telephoneEventPayloads[uint8(payload)]; ok {
				if clockRate <= 0 {
					clockRate = DefaultRTPDTMFClockRate
				}
				b.WriteString("a=rtpmap:" + strconv.Itoa(payload) + " telephone-event/" + strconv.Itoa(clockRate) + "\r\n")
				b.WriteString("a=fmtp:" + strconv.Itoa(payload) + " 0-16\r\n")
			}
		}
	}
	return []byte(b.String())
}

func sdpPayloadsContain(payloads []int, want int) bool {
	for _, payload := range payloads {
		if payload == want {
			return true
		}
	}
	return false
}

func (g *Gateway) recordDialog(info DialogInfo) {
	if g == nil || strings.TrimSpace(info.CallID) == "" {
		return
	}
	g.mu.Lock()
	if g.dialogs == nil {
		g.dialogs = make(map[string]DialogInfo)
	}
	g.dialogs[strings.TrimSpace(info.CallID)] = info
	g.mu.Unlock()
}

func (g *Gateway) dialog(callID string) DialogInfo {
	if g == nil {
		return DialogInfo{CallID: strings.TrimSpace(callID)}
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if d, ok := g.dialogs[strings.TrimSpace(callID)]; ok {
		return d
	}
	return DialogInfo{CallID: strings.TrimSpace(callID)}
}

func localFinalStatusCode(code, fallback int) int {
	if code >= 300 && code <= 699 {
		return code
	}
	return fallback
}

func localDialogInfoStatusCode(code int, accepted bool) int {
	if code >= 200 && code <= 699 {
		return code
	}
	if accepted {
		return 200
	}
	return 500
}

func dialogInfoResultResponse(req *sip.Request, result DialogInfoResult, err error, failureReason string) *sip.Response {
	statusCode := localDialogInfoStatusCode(result.StatusCode, result.Accepted)
	reason := firstVoiceNonEmpty(result.Reason, "OK")
	if !result.Accepted && statusCode >= 300 {
		reason = firstVoiceNonEmpty(result.Reason, failureReason)
	}
	if err != nil && result.StatusCode <= 0 {
		statusCode = 503
		reason = firstVoiceNonEmpty(result.Reason, failureReason)
	}
	body := append([]byte(nil), result.Body...)
	res := sip.NewResponseFromRequest(req, statusCode, reason, body)
	if len(body) > 0 && strings.TrimSpace(result.ContentType) != "" {
		res.AppendHeader(sip.NewHeader("Content-Type", strings.TrimSpace(result.ContentType)))
	}
	for key, value := range result.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogHeader(key) {
			continue
		}
		res.AppendHeader(sip.NewHeader(key, value))
	}
	return res
}

func legacyDialogActionResponse(req *sip.Request, err error, failureReason string) *sip.Response {
	if err != nil {
		return sip.NewResponseFromRequest(req, 503, firstVoiceNonEmpty(failureReason, err.Error()), nil)
	}
	return sip.NewResponseFromRequest(req, 200, "OK", nil)
}

func dialogResultTerminatesLocalDialog(result DialogInfoResult, err error) bool {
	if result.Accepted || (result.StatusCode >= 200 && result.StatusCode < 300) {
		return true
	}
	if result.StatusCode == 481 {
		return true
	}
	return err == nil && result.StatusCode == 0
}

func sipHeaderValue(req *sip.Request, name string) string {
	if req == nil {
		return ""
	}
	header := req.GetHeader(name)
	if header == nil {
		return ""
	}
	return strings.TrimSpace(header.Value())
}

func deleteSIPHeaderValue(headers map[string]string, name string) {
	for key := range headers {
		if strings.EqualFold(key, name) {
			delete(headers, key)
		}
	}
}

func normalizeReferSub(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "true" || value == "false" {
		return value, true
	}
	return "", false
}

func sipRequestHeaderMap(req *sip.Request) map[string]string {
	if req == nil {
		return nil
	}
	headers := req.Headers()
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for _, header := range headers {
		if header == nil {
			continue
		}
		name := strings.TrimSpace(header.Name())
		value := strings.TrimSpace(header.Value())
		if name == "" || value == "" || isProtectedDialogHeader(name) {
			continue
		}
		out[name] = value
	}
	return out
}

func isSIPSDPContentType(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if semi := strings.IndexByte(value, ';'); semi >= 0 {
		value = value[:semi]
	}
	return strings.EqualFold(strings.TrimSpace(value), "application/sdp")
}

func sipCallID(req *sip.Request) string {
	if req == nil || req.CallID() == nil {
		return ""
	}
	return strings.TrimSpace(req.CallID().Value())
}

func sipCallee(req *sip.Request) string {
	if req == nil {
		return ""
	}
	if to := req.To(); to != nil {
		if user := strings.TrimSpace(to.Address.User); user != "" {
			return user
		}
	}
	if user := strings.TrimSpace(req.Recipient.User); user != "" {
		return user
	}
	return strings.TrimSpace(fmt.Sprint(req.Recipient))
}
