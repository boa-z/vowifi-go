package messaging

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
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
	Encoding       string
	ValidityPeriod time.Duration
	ConcatRef      int
	ConcatRefBits  int
}

type SendOutcome struct {
	MessageID     string `json:"message_id,omitempty"`
	Parts         int    `json:"parts,omitempty"`
	PartsTotal    int    `json:"parts_total,omitempty"`
	State         string `json:"state,omitempty"`
	DeliveryState string `json:"delivery_state,omitempty"`
}

type USSDResult struct {
	SessionID                  string        `json:"session_id,omitempty"`
	Text                       string        `json:"text,omitempty"`
	RawText                    string        `json:"raw_text,omitempty"`
	Status                     int           `json:"status,omitempty"`
	DCS                        int           `json:"dcs,omitempty"`
	Done                       bool          `json:"done"`
	RegistrationRecoveryNeeded bool          `json:"registration_recovery_needed,omitempty"`
	RetryAfter                 time.Duration `json:"retry_after,omitempty"`
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
	PartNo              int
	TotalParts          int
	Text                string
	Encoding            string
	UDH                 []byte
	ValidityPeriod      time.Duration
	ConcatRef           int
	ConcatRefBits       int
	RequestStatusReport bool
}

type SMSSendRequest struct {
	DeviceID  string
	IMSI      string
	Peer      string
	MessageID string
	Part      SMSPart
}

type SMSSendResult struct {
	CallID                     string
	RPMR                       int
	State                      string
	SIPCode                    int
	ErrorText                  string
	RegistrationRecoveryNeeded bool
	RetryAfter                 time.Duration
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
	if text := smsRPCauseText(code); text != "" {
		return text
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
	smsConcat     map[smsConcatKey]*smsConcatState
}

var smsConcatRefCounter atomic.Uint32

func NewService(deviceID, imsi string, store DeliveryStore, dispatch eventhost.Dispatcher) *Service {
	return &Service{deviceID: deviceID, imsi: imsi, store: store, dispatch: dispatch}
}

func (s *Service) SetSMSTransport(t SMSTransport) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transport = t
}

func (s *Service) SetUSSDTransport(t USSDTransport) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ussdTransport = t
}

func (s *Service) smsTransport() SMSTransport {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transport
}

func (s *Service) currentUSSDTransport() USSDTransport {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ussdTransport
}

func (s *Service) SendSMSWithOptions(ctx context.Context, to, text string, opts SendOptions) (SendOutcome, error) {
	to = strings.TrimSpace(to)
	if to == "" {
		return SendOutcome{}, errors.New("sms target is empty")
	}
	parts, err := segmentSMS(text, opts)
	if err != nil {
		return SendOutcome{}, err
	}
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
		if transport := s.smsTransport(); transport != nil {
			res, sendErr = transport.SendSMSPart(ctx, SMSSendRequest{
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
	transport := s.currentUSSDTransport()
	if transport == nil {
		return &USSDResult{SessionID: sessionID, Text: "", Done: true}, nil
	}
	res, err := transport.ExecuteUSSD(ctx, USSDRequest{
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
	s.dispatchUSSDUpdated(ctx, res)
	return &res, nil
}

func (s *Service) ContinueUSSD(ctx context.Context, sessionID, input string) (*USSDResult, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, errors.New("ussd session_id is empty")
	}
	input = strings.TrimSpace(input)
	transport := s.currentUSSDTransport()
	if transport == nil {
		return &USSDResult{SessionID: sessionID, Text: "", Done: true}, nil
	}
	if !s.hasUSSDSession(sessionID) {
		return nil, fmt.Errorf("ussd session %s is not active", sessionID)
	}
	res, err := transport.ContinueUSSD(ctx, USSDRequest{
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
	s.dispatchUSSDUpdated(ctx, res)
	return &res, nil
}

func (s *Service) CancelUSSD(ctx context.Context, sessionID string) error {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return errors.New("ussd session_id is empty")
	}
	transport := s.currentUSSDTransport()
	if transport == nil {
		return nil
	}
	if err := transport.CancelUSSD(ctx, USSDRequest{
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
	return SegmentSMSWithOptions(text, SendOptions{Encoding: encoding})
}

func SegmentSMSWithOptions(text string, opts SendOptions) []SMSPart {
	parts, _ := segmentSMS(text, opts)
	return parts
}

func segmentSMS(text string, opts SendOptions) ([]SMSPart, error) {
	if text == "" {
		return nil, nil
	}
	if _, _, err := encodeSMSRelativeValidityPeriod(opts.ValidityPeriod); err != nil {
		return nil, err
	}
	enc := normalizeEncoding(text, opts.Encoding)
	single, concat := smsPartLimitsForUDH(enc, concatUDHLength(normalizeSMSConcatRefBits(opts.ConcatRef, opts.ConcatRefBits)))
	if messageLen(text, enc) <= single {
		return []SMSPart{{PartNo: 1, TotalParts: 1, Text: text, Encoding: enc, ValidityPeriod: opts.ValidityPeriod}}, nil
	}
	refBits, err := validateSMSConcatOptions(opts.ConcatRef, opts.ConcatRefBits)
	if err != nil {
		return nil, err
	}
	ref := opts.ConcatRef
	if ref == 0 {
		ref = nextSMSConcatRef(refBits)
	}
	_, concat = smsPartLimitsForUDH(enc, concatUDHLength(refBits))
	total := int(math.Ceil(float64(messageLen(text, enc)) / float64(concat)))
	if total <= 0 {
		total = 1
	}
	if total > 255 {
		return nil, fmt.Errorf("sms message requires %d parts; maximum is 255", total)
	}
	out := make([]SMSPart, 0, total)
	remaining := text
	for partNo := 1; remaining != ""; partNo++ {
		chunk, rest := takeSMSChunk(remaining, enc, concat)
		udh, err := concatUDHWithRef(ref, refBits, total, partNo)
		if err != nil {
			return nil, err
		}
		out = append(out, SMSPart{PartNo: partNo, TotalParts: total, Text: chunk, Encoding: enc, UDH: udh, ValidityPeriod: opts.ValidityPeriod, ConcatRef: ref, ConcatRefBits: refBits})
		remaining = rest
	}
	for i := range out {
		out[i].TotalParts = len(out)
		udh, err := concatUDHWithRef(ref, refBits, len(out), out[i].PartNo)
		if err != nil {
			return nil, err
		}
		out[i].UDH = udh
	}
	return out, nil
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
	return smsPartLimitsForUDH(encoding, 6)
}

func smsPartLimitsForUDH(encoding string, udhBytes int) (single int, concat int) {
	if udhBytes <= 0 {
		udhBytes = 6
	}
	switch encoding {
	case "gsm7":
		headerSeptets := (udhBytes*8 + 6) / 7
		return 160, 160 - headerSeptets
	case "utf8":
		return 140, 140 - udhBytes
	default:
		return 70, (140 - udhBytes) / 2
	}
}

func messageLen(text, encoding string) int {
	if encoding == "utf8" {
		return len([]byte(text))
	}
	if encoding == "gsm7" {
		if septets, ok := gsm7SeptetLen(text); ok {
			return septets
		}
		return utf8.RuneCountInString(text)
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
	if encoding == "gsm7" {
		return takeGSM7Chunk(text, limit)
	}
	runes := []rune(text)
	if len(runes) <= limit {
		return text, ""
	}
	return string(runes[:limit]), string(runes[limit:])
}

func concatUDH(total, partNo int) []byte {
	udh, _ := concatUDHWithRef(1, 8, total, partNo)
	return udh
}

func concatUDHWithRef(ref, refBits, total, partNo int) ([]byte, error) {
	if total <= 1 {
		return nil, nil
	}
	if total > 255 {
		return nil, fmt.Errorf("sms concat total parts out of range: %d", total)
	}
	if partNo <= 0 || partNo > total {
		return nil, fmt.Errorf("sms concat part number %d out of range for %d parts", partNo, total)
	}
	switch refBits {
	case 8:
		if ref < 0 || ref > 0xff {
			return nil, fmt.Errorf("sms 8-bit concat reference out of range: %d", ref)
		}
		return []byte{0x05, 0x00, 0x03, byte(ref), byte(total), byte(partNo)}, nil
	case 16:
		if ref < 0 || ref > 0xffff {
			return nil, fmt.Errorf("sms 16-bit concat reference out of range: %d", ref)
		}
		return []byte{0x06, 0x08, 0x04, byte(ref >> 8), byte(ref), byte(total), byte(partNo)}, nil
	default:
		return nil, fmt.Errorf("unsupported sms concat reference size: %d", refBits)
	}
}

func concatUDHLength(refBits int) int {
	if refBits == 16 {
		return 7
	}
	return 6
}

func validateSMSConcatOptions(ref, refBits int) (int, error) {
	if ref < 0 {
		return 0, fmt.Errorf("sms concat reference out of range: %d", ref)
	}
	bits := normalizeSMSConcatRefBits(ref, refBits)
	switch bits {
	case 8:
		if ref > 0xff {
			return 0, fmt.Errorf("sms 8-bit concat reference out of range: %d", ref)
		}
	case 16:
		if ref > 0xffff {
			return 0, fmt.Errorf("sms 16-bit concat reference out of range: %d", ref)
		}
	default:
		return 0, fmt.Errorf("unsupported sms concat reference size: %d", refBits)
	}
	return bits, nil
}

func normalizeSMSConcatRefBits(ref, refBits int) int {
	switch refBits {
	case 8, 16:
		return refBits
	case 0:
		if ref > 0xff {
			return 16
		}
		return 8
	default:
		return refBits
	}
}

func nextSMSConcatRef(refBits int) int {
	n := smsConcatRefCounter.Add(1)
	if refBits == 16 {
		return int(n%0xffff) + 1
	}
	return int(n%0xff) + 1
}

func isGSM7Text(text string) bool {
	_, ok := gsm7SeptetLen(text)
	return ok
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

func (s *Service) dispatchUSSDUpdated(ctx context.Context, res USSDResult) {
	if s == nil || s.dispatch == nil || strings.TrimSpace(res.SessionID) == "" {
		return
	}
	s.dispatch.Dispatch(ctx, eventhost.USSDUpdated{
		DevID:     s.deviceID,
		SessionID: res.SessionID,
		Text:      res.Text,
		RawText:   res.RawText,
		Status:    res.Status,
		DCS:       res.DCS,
		Done:      res.Done,
		Time:      time.Now(),
	})
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
