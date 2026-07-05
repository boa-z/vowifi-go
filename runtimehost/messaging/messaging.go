package messaging

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/iniwex5/vowifi-go/runtimehost/eventhost"
)

var ErrDeliveryNotFound = errors.New("delivery not found")
var ErrSMSTransportUnavailable = errors.New("sms transport unavailable")
var ErrUSSDTransportUnavailable = errors.New("ussd transport unavailable")

type suppressKey struct{}

func WithSuppressSendTGSuccess(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, suppressKey{}, true)
}

type SendOptions struct {
	Encoding string
}

type SendOutcome struct {
	MessageID     string `json:"message_id,omitempty"`
	Parts         int    `json:"parts,omitempty"`
	PartsTotal    int    `json:"parts_total,omitempty"`
	State         string `json:"state,omitempty"`
	DeliveryState string `json:"delivery_state,omitempty"`
}

type USSDResult struct {
	SessionID string `json:"session_id,omitempty"`
	Text      string `json:"text,omitempty"`
	RawText   string `json:"raw_text,omitempty"`
	Status    int    `json:"status,omitempty"`
	DCS       int    `json:"dcs,omitempty"`
	Done      bool   `json:"done"`
}

type IncomingSMS struct {
	Sender    string
	Recipient string
	Content   string
	Timestamp time.Time
}

type SMSDeliveryReport struct {
	InReplyTo string
	CallID    string
	RPMR      int
	State     string
	SIPCode   int
	RPCause   int
	ErrorText string
	ReportAt  time.Time
}

type SMSPart struct {
	PartNo     int
	TotalParts int
	Text       string
	Encoding   string
	UDH        []byte
}

type SMSSendRequest struct {
	DeviceID  string
	IMSI      string
	Peer      string
	MessageID string
	Part      SMSPart
}

type SMSSendResult struct {
	CallID    string
	RPMR      int
	State     string
	SIPCode   int
	ErrorText string
}

type SMSTransport interface {
	SendSMSPart(context.Context, SMSSendRequest) (SMSSendResult, error)
}

type USSDTransport interface {
	ExecuteUSSD(context.Context, USSDRequest) (USSDResult, error)
	ContinueUSSD(context.Context, USSDRequest) (USSDResult, error)
	CancelUSSD(context.Context, USSDRequest) error
}

type USSDRequest struct {
	DeviceID  string
	IMSI      string
	SessionID string
	Command   string
	Input     string
}

type DeliveryPartMatch struct {
	MessageID string
	PartNo    int
	State     string
}

type DeliveryPartStatus struct {
	PartNo      int
	CallID      string
	InReplyTo   string
	RPMR        int
	State       string
	SIPCode     int
	RPCause     int
	RPCauseText string
	ErrorText   string
	SentAt      time.Time
	ReportAt    *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type DeliveryStatus struct {
	MessageID  string
	IMSI       string
	DeviceID   string
	Peer       string
	Content    string
	PartsTotal int
	Acks       int
	State      string
	LastError  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Parts      []DeliveryPartStatus
}

type DeliveryStore interface {
	CreateSMSDelivery(messageID, imsi, deviceID, peer, content string, partsTotal int, at time.Time) error
	UpsertSMSDeliveryPart(messageID string, partNo int, callID string, rpMR int, state string, sentAt time.Time) error
	MarkSMSDeliveryPartReport(inReplyTo, callID, deviceID string, rpMR int, state string, sipCode int, rpCause int, errText string, at time.Time) (DeliveryPartMatch, error)
	RecomputeSMSDelivery(messageID string, at time.Time) error
	UpdateSMSDeliveryState(messageID, state, lastError string, acks int, at time.Time) error
	GetSMSDeliveryStatus(messageID string) (*DeliveryStatus, error)
}

func RPCauseText(code int) string {
	if code == 0 {
		return ""
	}
	return fmt.Sprintf("RP cause %d", code)
}

type Service struct {
	deviceID      string
	imsi          string
	store         DeliveryStore
	dispatch      eventhost.Dispatcher
	transport     SMSTransport
	ussdTransport USSDTransport
	mu            sync.Mutex
	ussdSessions  map[string]USSDResult
}

func NewService(deviceID, imsi string, store DeliveryStore, dispatch eventhost.Dispatcher) *Service {
	return &Service{deviceID: deviceID, imsi: imsi, store: store, dispatch: dispatch}
}

func (s *Service) SetSMSTransport(t SMSTransport) {
	if s == nil {
		return
	}
	s.transport = t
}

func (s *Service) SetUSSDTransport(t USSDTransport) {
	if s == nil {
		return
	}
	s.ussdTransport = t
}

func (s *Service) SendSMSWithOptions(ctx context.Context, to, text string, opts SendOptions) (SendOutcome, error) {
	to = strings.TrimSpace(to)
	if to == "" {
		return SendOutcome{}, errors.New("sms target is empty")
	}
	parts := SegmentSMS(text, opts.Encoding)
	if len(parts) == 0 {
		return SendOutcome{}, errors.New("sms content is empty")
	}
	id := fmt.Sprintf("vowifi-%d", time.Now().UnixNano())
	now := time.Now()
	if s != nil && s.store != nil {
		_ = s.store.CreateSMSDelivery(id, s.imsi, s.deviceID, to, text, len(parts), now)
	}
	acks := 0
	state := "sent"
	deliveryState := "sent"
	lastErr := ""
	for _, part := range parts {
		partNow := time.Now()
		res := SMSSendResult{State: "sent"}
		var sendErr error
		if s != nil && s.transport != nil {
			res, sendErr = s.transport.SendSMSPart(ctx, SMSSendRequest{
				DeviceID:  s.deviceID,
				IMSI:      s.imsi,
				Peer:      to,
				MessageID: id,
				Part:      part,
			})
		}
		if res.State == "" {
			res.State = "sent"
		}
		if sendErr != nil {
			res.State = "failed"
			if res.ErrorText == "" {
				res.ErrorText = sendErr.Error()
			}
		}
		if s != nil && s.store != nil {
			_ = s.store.UpsertSMSDeliveryPart(id, part.PartNo, res.CallID, res.RPMR, res.State, partNow)
		}
		if res.State == "sent" || res.State == "delivered" || res.State == "accepted" {
			acks++
		}
		if sendErr != nil {
			state = "failed"
			deliveryState = "failed"
			lastErr = res.ErrorText
			break
		}
		if res.State == "failed" {
			state = "failed"
			deliveryState = "failed"
			lastErr = res.ErrorText
			break
		}
	}
	if s != nil && s.store != nil {
		_ = s.store.UpdateSMSDeliveryState(id, state, lastErr, acks, time.Now())
	}
	if s != nil && s.dispatch != nil {
		s.dispatch.Dispatch(ctx, eventhost.SMSSent{DevID: s.deviceID, TargetURI: to, Content: text, Time: now, TotalParts: len(parts)})
	}
	out := SendOutcome{MessageID: id, Parts: acks, PartsTotal: len(parts), State: state, DeliveryState: deliveryState}
	if state == "failed" {
		return out, errors.New(firstNonEmpty(lastErr, "sms send failed"))
	}
	return out, nil
}

func (s *Service) SendUSSD(ctx context.Context, command string) (*USSDResult, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, errors.New("ussd command is empty")
	}
	sessionID := fmt.Sprintf("ussd-%d", time.Now().UnixNano())
	if s == nil || s.ussdTransport == nil {
		return &USSDResult{SessionID: sessionID, Text: "", Done: true}, nil
	}
	res, err := s.ussdTransport.ExecuteUSSD(ctx, USSDRequest{
		DeviceID:  s.deviceID,
		IMSI:      s.imsi,
		SessionID: sessionID,
		Command:   command,
	})
	if err != nil {
		return nil, err
	}
	res = normalizeUSSDResult(res, sessionID)
	s.recordUSSDSession(res)
	return &res, nil
}

func (s *Service) ContinueUSSD(ctx context.Context, sessionID, input string) (*USSDResult, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, errors.New("ussd session_id is empty")
	}
	input = strings.TrimSpace(input)
	if s == nil || s.ussdTransport == nil {
		return &USSDResult{SessionID: sessionID, Text: "", Done: true}, nil
	}
	if !s.hasUSSDSession(sessionID) {
		return nil, fmt.Errorf("ussd session %s is not active", sessionID)
	}
	res, err := s.ussdTransport.ContinueUSSD(ctx, USSDRequest{
		DeviceID:  s.deviceID,
		IMSI:      s.imsi,
		SessionID: sessionID,
		Input:     input,
	})
	if err != nil {
		return nil, err
	}
	res = normalizeUSSDResult(res, sessionID)
	s.recordUSSDSession(res)
	return &res, nil
}

func (s *Service) CancelUSSD(ctx context.Context, sessionID string) error {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return errors.New("ussd session_id is empty")
	}
	if s == nil || s.ussdTransport == nil {
		return nil
	}
	if err := s.ussdTransport.CancelUSSD(ctx, USSDRequest{
		DeviceID:  s.deviceID,
		IMSI:      s.imsi,
		SessionID: sessionID,
	}); err != nil {
		return err
	}
	s.clearUSSDSession(sessionID)
	return nil
}

func (s *Service) GetSMSDeliveryStatus(messageID string) (*DeliveryStatus, error) {
	if s == nil || s.store == nil {
		return nil, ErrDeliveryNotFound
	}
	return s.store.GetSMSDeliveryStatus(messageID)
}

func (s *Service) HandleIncomingSMS(ctx context.Context, msg IncomingSMS) error {
	sender := strings.TrimSpace(msg.Sender)
	content := msg.Content
	if sender == "" {
		return errors.New("incoming sms sender is empty")
	}
	if strings.TrimSpace(content) == "" {
		return errors.New("incoming sms content is empty")
	}
	at := msg.Timestamp
	if at.IsZero() {
		at = time.Now()
	}
	if s != nil && s.dispatch != nil {
		s.dispatch.Dispatch(ctx, eventhost.SMSReceived{
			DevID:   s.deviceID,
			Sender:  sender,
			Content: content,
			Time:    at,
		})
	}
	return nil
}

func (s *Service) HandleSMSDeliveryReport(ctx context.Context, report SMSDeliveryReport) (DeliveryPartMatch, error) {
	if s == nil || s.store == nil {
		return DeliveryPartMatch{}, ErrDeliveryNotFound
	}
	at := report.ReportAt
	if at.IsZero() {
		at = time.Now()
	}
	state := normalizeDeliveryReportState(report.State, report.SIPCode, report.RPCause)
	errText := strings.TrimSpace(report.ErrorText)
	if errText == "" && report.RPCause != 0 {
		errText = RPCauseText(report.RPCause)
	}
	match, err := s.store.MarkSMSDeliveryPartReport(
		strings.TrimSpace(report.InReplyTo),
		strings.TrimSpace(report.CallID),
		s.deviceID,
		report.RPMR,
		state,
		report.SIPCode,
		report.RPCause,
		errText,
		at,
	)
	if err != nil {
		return DeliveryPartMatch{}, err
	}
	if match.MessageID != "" {
		_ = s.store.RecomputeSMSDelivery(match.MessageID, at)
	}
	return match, nil
}

func SegmentSMS(text, encoding string) []SMSPart {
	if text == "" {
		return nil
	}
	enc := normalizeEncoding(text, encoding)
	single, concat := smsPartLimits(enc)
	if messageLen(text, enc) <= single {
		return []SMSPart{{PartNo: 1, TotalParts: 1, Text: text, Encoding: enc}}
	}
	total := int(math.Ceil(float64(messageLen(text, enc)) / float64(concat)))
	if total <= 0 {
		total = 1
	}
	out := make([]SMSPart, 0, total)
	remaining := text
	for partNo := 1; remaining != ""; partNo++ {
		chunk, rest := takeSMSChunk(remaining, enc, concat)
		out = append(out, SMSPart{PartNo: partNo, TotalParts: total, Text: chunk, Encoding: enc, UDH: concatUDH(total, partNo)})
		remaining = rest
	}
	for i := range out {
		out[i].TotalParts = len(out)
		out[i].UDH = concatUDH(len(out), out[i].PartNo)
	}
	return out
}

func normalizeEncoding(text, requested string) string {
	req := strings.ToLower(strings.TrimSpace(requested))
	switch req {
	case "gsm7", "7bit", "gsm-7":
		return "gsm7"
	case "ucs2", "utf16":
		return "ucs2"
	case "utf8":
		return "utf8"
	}
	if isGSM7Text(text) {
		return "gsm7"
	}
	return "ucs2"
}

func smsPartLimits(encoding string) (single int, concat int) {
	switch encoding {
	case "gsm7":
		return 160, 153
	case "utf8":
		return 140, 134
	default:
		return 70, 67
	}
}

func messageLen(text, encoding string) int {
	if encoding == "utf8" {
		return len([]byte(text))
	}
	if encoding == "gsm7" {
		return len([]rune(text))
	}
	return utf8.RuneCountInString(text)
}

func takeSMSChunk(text, encoding string, limit int) (string, string) {
	if encoding == "utf8" {
		if len(text) <= limit {
			return text, ""
		}
		i := 0
		for pos := range text {
			if pos > limit {
				break
			}
			i = pos
		}
		if i <= 0 {
			_, size := utf8.DecodeRuneInString(text)
			i = size
		}
		return text[:i], text[i:]
	}
	runes := []rune(text)
	if len(runes) <= limit {
		return text, ""
	}
	return string(runes[:limit]), string(runes[limit:])
}

func concatUDH(total, partNo int) []byte {
	if total <= 1 {
		return nil
	}
	return []byte{0x05, 0x00, 0x03, 0x01, byte(total), byte(partNo)}
}

func isGSM7Text(text string) bool {
	for _, r := range text {
		if gsm7Code(r) < 0 {
			return false
		}
	}
	return true
}

const gsm7Alphabet = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"

func firstNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}

func normalizeDeliveryReportState(state string, sipCode int, rpCause int) string {
	state = strings.ToLower(strings.TrimSpace(state))
	switch state {
	case "delivered", "failed", "sent", "accepted":
		return state
	}
	if rpCause != 0 {
		return "failed"
	}
	if sipCode >= 200 && sipCode < 300 {
		return "delivered"
	}
	if sipCode >= 300 {
		return "failed"
	}
	return "delivered"
}

func normalizeUSSDResult(res USSDResult, sessionID string) USSDResult {
	if strings.TrimSpace(res.SessionID) == "" {
		res.SessionID = sessionID
	}
	if res.Text == "" && res.RawText != "" {
		res.Text = res.RawText
	}
	return res
}

func (s *Service) recordUSSDSession(res USSDResult) {
	if s == nil || strings.TrimSpace(res.SessionID) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if res.Done {
		delete(s.ussdSessions, res.SessionID)
		return
	}
	if s.ussdSessions == nil {
		s.ussdSessions = make(map[string]USSDResult)
	}
	s.ussdSessions[res.SessionID] = res
}

func (s *Service) hasUSSDSession(sessionID string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.ussdSessions[sessionID]
	return ok
}

func (s *Service) clearUSSDSession(sessionID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.ussdSessions, sessionID)
	s.mu.Unlock()
}
