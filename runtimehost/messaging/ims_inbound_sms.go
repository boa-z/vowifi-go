package messaging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
	"time"
)

type IMSMessageRequest struct {
	FromURI     string
	ToURI       string
	CallID      string
	CSeq        int
	ContentType string
	Body        []byte
	Headers     map[string][]string
}

type IMSMessageResult struct {
	StatusCode         int
	Reason             string
	RPDU               SMSRPDU
	Incoming           *IncomingSMS
	DeliveryReport     *SMSDeliveryReport
	ReplyContentType   string
	ReplyBody          []byte
	UnsupportedContent bool
}

const (
	smsConcatTTL         = 10 * time.Minute
	smsConcatMaxSets     = 64
	imsMultipartMaxDepth = 4
)

type smsConcatKey struct {
	sender    string
	recipient string
	ref       int
	refBits   int
	total     int
}

type smsConcatState struct {
	parts                  map[int]string
	timestamp              time.Time
	protocolID             byte
	dataCodingScheme       byte
	userDataHeader         bool
	userDataHeaderInfo     SMSUserDataHeaderInfo
	moreMessagesToSend     bool
	statusReportIndication bool
	replyPath              bool
	firstSeen              time.Time
	updatedAt              time.Time
}

func (s *Service) HandleIMSMessage(ctx context.Context, msg IMSMessageRequest) (IMSMessageResult, error) {
	body, consumedTransferEncoding, err := decodeIMSContentTransferEncoding(msg.Headers, msg.Body)
	if err != nil {
		return IMSMessageResult{StatusCode: 400, Reason: err.Error()}, err
	}
	if consumedTransferEncoding {
		msg.Body = body
		msg.Headers = omitIMSMessageHeader(msg.Headers, imsContentTransferEncodingHeader)
	}
	contentType := normalizedIMSMessageContentType(msg.ContentType)
	if strings.HasPrefix(contentType, "multipart/") {
		return s.handleIMSMultipartMessage(ctx, msg)
	}
	if contentType == IMSCPIMContentType {
		return s.handleIMSCPIMMessage(ctx, msg)
	}
	switch contentType {
	case "", "text/plain":
		incoming := IncomingSMS{
			Sender:    firstNonEmpty(msg.FromURI, "unknown"),
			Recipient: msg.ToURI,
			Content:   strings.ToValidUTF8(string(msg.Body), ""),
		}
		if err := s.HandleIncomingSMS(ctx, incoming); err != nil {
			return IMSMessageResult{StatusCode: 400, Reason: err.Error(), Incoming: &incoming}, err
		}
		return IMSMessageResult{StatusCode: 200, Reason: "OK", Incoming: &incoming}, nil
	case IMS3GPPSMSContentType:
		return s.handleIMS3GPPSMS(ctx, msg)
	case imsIMDNContentType:
		return s.handleIMSIMDNMessage(ctx, msg, IMSCPIMMessage{
			Headers:     msg.Headers,
			ContentType: contentType,
			Body:        msg.Body,
		})
	default:
		err := errors.New("unsupported IMS MESSAGE content type")
		return IMSMessageResult{StatusCode: 415, Reason: err.Error(), UnsupportedContent: true}, err
	}
}

func (s *Service) handleIMSMultipartMessage(ctx context.Context, msg IMSMessageRequest) (IMSMessageResult, error) {
	boundary, err := imsMessageMultipartBoundary(msg.ContentType)
	if err != nil {
		return IMSMessageResult{StatusCode: 400, Reason: err.Error()}, err
	}
	parts, err := readIMSMessageMultipartLeafParts(msg.Body, boundary, msg.Headers, 0)
	if err != nil {
		return IMSMessageResult{StatusCode: 400, Reason: err.Error()}, err
	}
	if part, ok := imsMessageMultipartStartPart(parts, imsMessageMultipartStartContentID(msg.ContentType)); ok {
		nested := msg
		nested.ContentType = part.ContentType
		nested.Body = part.Body
		nested.Headers = part.Headers
		return s.HandleIMSMessage(ctx, nested)
	}
	for _, priority := range imsMultipartContentPriorities() {
		for _, part := range parts {
			if normalizedIMSMessageContentType(part.ContentType) != priority {
				continue
			}
			nested := msg
			nested.ContentType = part.ContentType
			nested.Body = part.Body
			nested.Headers = part.Headers
			return s.HandleIMSMessage(ctx, nested)
		}
	}
	err = errors.New("unsupported IMS MESSAGE multipart content")
	return IMSMessageResult{StatusCode: 415, Reason: err.Error(), UnsupportedContent: true}, err
}

type imsMessageMultipartPart struct {
	ContentType string
	ContentID   string
	Headers     map[string][]string
	Body        []byte
}

func readIMSMessageMultipartParts(body []byte, boundary string) ([]imsMessageMultipartPart, error) {
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var parts []imsMessageMultipartPart
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		partBody, err := io.ReadAll(part)
		_ = part.Close()
		if err != nil {
			return nil, err
		}
		headers := mapFromMIMEHeader(part.Header)
		contentType := textproto.MIMEHeader(part.Header).Get("Content-Type")
		if strings.TrimSpace(contentType) == "" {
			contentType = "text/plain"
		}
		parts = append(parts, imsMessageMultipartPart{
			ContentType: contentType,
			ContentID:   textproto.MIMEHeader(part.Header).Get("Content-ID"),
			Headers:     headers,
			Body:        partBody,
		})
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("IMS MESSAGE multipart has no parts")
	}
	return parts, nil
}

func readIMSMessageMultipartLeafParts(body []byte, boundary string, headers map[string][]string, depth int) ([]imsMessageMultipartPart, error) {
	if depth > imsMultipartMaxDepth {
		return nil, fmt.Errorf("IMS MESSAGE multipart nesting exceeds %d levels", imsMultipartMaxDepth)
	}
	parts, err := readIMSMessageMultipartParts(body, boundary)
	if err != nil {
		return nil, err
	}
	var out []imsMessageMultipartPart
	for _, part := range parts {
		part.Headers = mergeIMSMessageHeaders(headers, part.Headers)
		if strings.HasPrefix(normalizedIMSMessageContentType(part.ContentType), "multipart/") {
			nestedBoundary, err := imsMessageMultipartBoundary(part.ContentType)
			if err != nil {
				return nil, err
			}
			nested, err := readIMSMessageMultipartLeafParts(part.Body, nestedBoundary, part.Headers, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, nested...)
			continue
		}
		out = append(out, part)
	}
	return out, nil
}

func imsMessageMultipartBoundary(contentType string) (string, error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", err
	}
	boundary := strings.TrimSpace(params["boundary"])
	if boundary == "" {
		return "", errors.New("IMS MESSAGE multipart boundary is empty")
	}
	return boundary, nil
}

func imsMessageMultipartStartContentID(contentType string) string {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	return normalizeIMSMessageMultipartContentID(params["start"])
}

func imsMessageMultipartStartPart(parts []imsMessageMultipartPart, startContentID string) (imsMessageMultipartPart, bool) {
	startContentID = normalizeIMSMessageMultipartContentID(startContentID)
	if startContentID == "" {
		return imsMessageMultipartPart{}, false
	}
	for _, part := range parts {
		if normalizeIMSMessageMultipartContentID(part.ContentID) != startContentID {
			continue
		}
		if !imsMessageMultipartSupportedContentType(part.ContentType) {
			return imsMessageMultipartPart{}, false
		}
		return part, true
	}
	return imsMessageMultipartPart{}, false
}

func normalizeIMSMessageMultipartContentID(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	value = strings.Trim(strings.TrimSpace(value), "<>")
	return strings.ToLower(value)
}

func imsMessageMultipartSupportedContentType(contentType string) bool {
	contentType = normalizedIMSMessageContentType(contentType)
	for _, priority := range imsMultipartContentPriorities() {
		if contentType == priority {
			return true
		}
	}
	return false
}

func imsMultipartContentPriorities() []string {
	return []string{
		IMSCPIMContentType,
		IMS3GPPSMSContentType,
		imsIMDNContentType,
		"text/plain",
	}
}

func mapFromMIMEHeader(headers textproto.MIMEHeader) map[string][]string {
	out := make(map[string][]string, len(headers))
	for key, values := range headers {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func mergeIMSMessageHeaders(base, overlay map[string][]string) map[string][]string {
	if len(base) == 0 && len(overlay) == 0 {
		return nil
	}
	out := make(map[string][]string, len(base)+len(overlay))
	for key, values := range base {
		out[key] = append([]string(nil), values...)
	}
	for key, values := range overlay {
		appendIMSMessageHeaderValues(out, key, values)
	}
	return out
}

func appendIMSMessageHeaderValues(headers map[string][]string, key string, values []string) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	for candidate, existing := range headers {
		if strings.EqualFold(strings.TrimSpace(candidate), key) {
			headers[candidate] = append(append([]string(nil), existing...), values...)
			return
		}
	}
	headers[key] = append([]string(nil), values...)
}

func omitIMSMessageHeader(headers map[string][]string, key string) map[string][]string {
	if len(headers) == 0 {
		return headers
	}
	out := make(map[string][]string, len(headers))
	removed := false
	for candidate, values := range headers {
		if strings.EqualFold(strings.TrimSpace(candidate), key) {
			removed = true
			continue
		}
		out[candidate] = append([]string(nil), values...)
	}
	if !removed {
		return headers
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *Service) handleIMSCPIMMessage(ctx context.Context, msg IMSMessageRequest) (IMSMessageResult, error) {
	cpim, err := ParseIMSCPIMMessage(msg.Body)
	if err != nil {
		return IMSMessageResult{StatusCode: 400, Reason: err.Error()}, err
	}
	if cpim.ContentType == imsIMDNContentType {
		return s.handleIMSIMDNMessage(ctx, msg, cpim)
	}
	nested := msg
	nested.ContentType = cpim.ContentType
	nested.Body = cpim.Body
	nested.FromURI = firstNonEmpty(msg.FromURI, imsHeaderValue(cpim.Headers, "From"))
	nested.ToURI = firstNonEmpty(msg.ToURI, imsHeaderValue(cpim.Headers, "To"))
	result, err := s.HandleIMSMessage(ctx, nested)
	if len(result.ReplyBody) > 0 && strings.TrimSpace(result.ReplyContentType) != "" {
		reply, wrapErr := BuildIMSCPIMMessage(firstNonEmpty(nested.ToURI, msg.ToURI), firstNonEmpty(nested.FromURI, msg.FromURI), result.ReplyContentType, result.ReplyBody)
		if wrapErr != nil {
			return IMSMessageResult{StatusCode: 500, Reason: wrapErr.Error()}, wrapErr
		}
		result.ReplyContentType = IMSCPIMContentType
		result.ReplyBody = reply
	}
	return result, err
}

func (s *Service) handleIMSIMDNMessage(ctx context.Context, msg IMSMessageRequest, cpim IMSCPIMMessage) (IMSMessageResult, error) {
	imdn, err := parseIMSCPIMIMDNReport(cpim)
	if err != nil {
		return IMSMessageResult{StatusCode: 400, Reason: err.Error()}, err
	}
	report := SMSDeliveryReport{
		InReplyTo: firstNonEmpty(imdn.MessageID, imsHeaderValue(msg.Headers, "In-Reply-To")),
		CallID:    firstNonEmpty(msg.CallID, imsHeaderValue(msg.Headers, "Call-ID")),
		State:     imdn.State,
		SIPCode:   200,
		ErrorText: imdn.ErrorText,
		ReportAt:  imdn.DateTime,
		Recipient: firstNonEmpty(imdn.OriginalRecipientURI, imdn.RecipientURI),
	}
	_, err = s.HandleSMSDeliveryReport(ctx, report)
	out := IMSMessageResult{StatusCode: 200, Reason: "OK", DeliveryReport: &report}
	if err != nil && !errors.Is(err, ErrDeliveryNotFound) {
		out.StatusCode = 500
		out.Reason = err.Error()
		return out, err
	}
	return out, nil
}

func imsHeaderValue(headers map[string][]string, key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	for candidate, values := range headers {
		if strings.ToLower(candidate) == key && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func (s *Service) handleIMS3GPPSMS(ctx context.Context, msg IMSMessageRequest) (IMSMessageResult, error) {
	rpdu, err := ParseSMSRPDU(msg.Body)
	if err != nil {
		return IMSMessageResult{StatusCode: 400, Reason: err.Error()}, err
	}
	out := IMSMessageResult{StatusCode: 200, Reason: "OK", RPDU: rpdu}
	switch rpdu.Kind {
	case SMSRPDUKindData:
		return s.handleIMSRPData(ctx, msg, rpdu, out)
	case SMSRPDUKindAck:
		if len(rpdu.TPDU) > 0 && rpdu.TPDU[0]&0x03 == 0x02 {
			reportTPDU, err := ParseSMSStatusReportTPDU(rpdu.TPDU)
			if err != nil {
				out.StatusCode = 400
				out.Reason = err.Error()
				return out, err
			}
			report, err := s.handleIMSSMSStatusReport(ctx, msg, reportTPDU)
			out.DeliveryReport = &report
			if err != nil && !errors.Is(err, ErrDeliveryNotFound) {
				out.StatusCode = 500
				out.Reason = err.Error()
				return out, err
			}
			return out, nil
		}
		report := SMSDeliveryReport{
			CallID:   msg.CallID,
			RPMR:     int(rpdu.MR),
			State:    "delivered",
			SIPCode:  200,
			ReportAt: time.Time{},
		}
		_, err := s.HandleSMSDeliveryReport(ctx, report)
		out.DeliveryReport = &report
		if err != nil && !errors.Is(err, ErrDeliveryNotFound) {
			out.StatusCode = 500
			out.Reason = err.Error()
			return out, err
		}
		return out, nil
	case SMSRPDUKindError:
		report := SMSDeliveryReport{
			CallID:    msg.CallID,
			RPMR:      int(rpdu.MR),
			State:     "failed",
			SIPCode:   200,
			RPCause:   rpdu.Cause,
			ErrorText: RPCauseText(rpdu.Cause),
			ReportAt:  time.Time{},
		}
		_, err := s.HandleSMSDeliveryReport(ctx, report)
		out.DeliveryReport = &report
		if err != nil && !errors.Is(err, ErrDeliveryNotFound) {
			out.StatusCode = 500
			out.Reason = err.Error()
			return out, err
		}
		return out, nil
	default:
		err := errors.New("unsupported IMS SMS RPDU kind")
		out.StatusCode = 400
		out.Reason = err.Error()
		return out, err
	}
}

func (s *Service) handleIMSRPData(ctx context.Context, msg IMSMessageRequest, rpdu SMSRPDU, out IMSMessageResult) (IMSMessageResult, error) {
	if len(rpdu.TPDU) == 0 {
		err := errors.New("IMS SMS RP-DATA has no TPDU")
		out.StatusCode = 400
		out.Reason = err.Error()
		out.ReplyContentType = IMS3GPPSMSContentType
		out.ReplyBody = BuildSMSRPError(rpdu.MR, SMSRPCauseTemporaryFailure)
		return out, err
	}
	switch rpdu.TPDU[0] & 0x03 {
	case 0x00:
		deliver, err := ParseSMSDeliverTPDU(rpdu.TPDU)
		if err != nil {
			out.StatusCode = 400
			out.Reason = err.Error()
			out.ReplyContentType = IMS3GPPSMSContentType
			out.ReplyBody = BuildSMSRPError(rpdu.MR, SMSRPCauseTemporaryFailure)
			return out, err
		}
		incoming := IncomingSMS{
			Sender:                 firstNonEmpty(deliver.Sender, rpdu.Originator, msg.FromURI),
			Recipient:              firstNonEmpty(deliver.Recipient, rpdu.Destination, msg.ToURI),
			Content:                deliver.Text,
			Timestamp:              deliver.Timestamp,
			ProtocolID:             deliver.ProtocolID,
			DataCodingScheme:       deliver.DataCodingScheme,
			DataCoding:             deliver.DataCoding,
			UserDataHeader:         deliver.UserDataHeader,
			UserDataHeaderInfo:     deliver.UserDataHeaderInfo,
			MoreMessagesToSend:     deliver.MoreMessagesToSend,
			StatusReportIndication: deliver.StatusReportIndication,
			ReplyPath:              deliver.ReplyPath,
		}
		if deliver.Concat.IsConcat {
			assembled, ready := s.collectSMSConcatPart(incoming, deliver.Concat, time.Now())
			if !ready {
				out.ReplyContentType = IMS3GPPSMSContentType
				out.ReplyBody = BuildSMSRPAck(rpdu.MR)
				return out, nil
			}
			incoming = assembled
		}
		if err := s.HandleIncomingSMS(ctx, incoming); err != nil {
			out.StatusCode = 400
			out.Reason = err.Error()
			out.Incoming = &incoming
			out.ReplyContentType = IMS3GPPSMSContentType
			out.ReplyBody = BuildSMSRPError(rpdu.MR, SMSRPCauseTemporaryFailure)
			return out, err
		}
		out.Incoming = &incoming
		out.ReplyContentType = IMS3GPPSMSContentType
		out.ReplyBody = BuildSMSRPAck(rpdu.MR)
		return out, nil
	case 0x02:
		reportTPDU, err := ParseSMSStatusReportTPDU(rpdu.TPDU)
		if err != nil {
			out.StatusCode = 400
			out.Reason = err.Error()
			out.ReplyContentType = IMS3GPPSMSContentType
			out.ReplyBody = BuildSMSRPError(rpdu.MR, SMSRPCauseTemporaryFailure)
			return out, err
		}
		report, err := s.handleIMSSMSStatusReport(ctx, msg, reportTPDU)
		out.DeliveryReport = &report
		out.ReplyContentType = IMS3GPPSMSContentType
		out.ReplyBody = BuildSMSRPAck(rpdu.MR)
		if err != nil && !errors.Is(err, ErrDeliveryNotFound) {
			out.StatusCode = 500
			out.Reason = err.Error()
			return out, err
		}
		return out, nil
	default:
		err := errors.New("unsupported IMS SMS TPDU type")
		out.StatusCode = 400
		out.Reason = err.Error()
		out.ReplyContentType = IMS3GPPSMSContentType
		out.ReplyBody = BuildSMSRPError(rpdu.MR, SMSRPCauseTemporaryFailure)
		return out, err
	}
}

func (s *Service) handleIMSSMSStatusReport(ctx context.Context, msg IMSMessageRequest, reportTPDU SMSStatusReport) (SMSDeliveryReport, error) {
	report := SMSDeliveryReport{
		CallID:                msg.CallID,
		RPMR:                  int(reportTPDU.Reference),
		State:                 reportTPDU.State,
		SIPCode:               200,
		RPCause:               int(reportTPDU.Status),
		ReportAt:              reportTPDU.DoneAt,
		ErrorText:             smsStatusReportError(reportTPDU),
		Recipient:             reportTPDU.Recipient,
		SentAt:                reportTPDU.Timestamp,
		FirstOctet:            reportTPDU.FirstOctet,
		MoreMessagesToSend:    reportTPDU.MoreMessagesToSend,
		StatusReportQualifier: reportTPDU.StatusReportQualifier,
		UserDataHeader:        reportTPDU.UserDataHeader,
		UserDataHeaderInfo:    reportTPDU.UserDataHeaderInfo,
		ParameterIndicator:    reportTPDU.ParameterIndicator,
		ProtocolID:            reportTPDU.ProtocolID,
		DataCodingScheme:      reportTPDU.DataCodingScheme,
		DataCoding:            reportTPDU.DataCoding,
		UserData:              reportTPDU.UserData,
	}
	_, err := s.HandleSMSDeliveryReport(ctx, report)
	return report, err
}

func (s *Service) collectSMSConcatPart(incoming IncomingSMS, concat SMSConcatInfo, now time.Time) (IncomingSMS, bool) {
	if s == nil || !validSMSConcatInfo(concat) {
		return incoming, true
	}
	if now.IsZero() {
		now = time.Now()
	}
	key := smsConcatKey{
		sender:    strings.TrimSpace(incoming.Sender),
		recipient: strings.TrimSpace(incoming.Recipient),
		ref:       concat.Ref,
		refBits:   concat.RefBits,
		total:     concat.Total,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupSMSConcatLocked(now)
	if s.smsConcat == nil {
		s.smsConcat = make(map[smsConcatKey]*smsConcatState)
	}
	state := s.smsConcat[key]
	if state == nil {
		if len(s.smsConcat) >= smsConcatMaxSets {
			s.evictOldestSMSConcatLocked()
		}
		state = &smsConcatState{
			parts:     make(map[int]string, concat.Total),
			firstSeen: now,
		}
		s.smsConcat[key] = state
	}
	state.updatedAt = now
	if !incoming.Timestamp.IsZero() && (state.timestamp.IsZero() || concat.Seq == 1) {
		state.timestamp = incoming.Timestamp
	}
	if concat.Seq == 1 || len(state.parts) == 0 {
		state.protocolID = incoming.ProtocolID
		state.dataCodingScheme = incoming.DataCodingScheme
		state.userDataHeader = incoming.UserDataHeader
		state.userDataHeaderInfo = incoming.UserDataHeaderInfo
		state.moreMessagesToSend = incoming.MoreMessagesToSend
		state.statusReportIndication = incoming.StatusReportIndication
		state.replyPath = incoming.ReplyPath
	}
	if _, exists := state.parts[concat.Seq]; !exists {
		state.parts[concat.Seq] = incoming.Content
	}
	if len(state.parts) < concat.Total {
		return IncomingSMS{}, false
	}

	var content strings.Builder
	for seq := 1; seq <= concat.Total; seq++ {
		part, ok := state.parts[seq]
		if !ok {
			return IncomingSMS{}, false
		}
		content.WriteString(part)
	}
	delete(s.smsConcat, key)

	incoming.Content = content.String()
	if !state.timestamp.IsZero() {
		incoming.Timestamp = state.timestamp
	}
	incoming.ProtocolID = state.protocolID
	incoming.DataCodingScheme = state.dataCodingScheme
	incoming.UserDataHeader = state.userDataHeader
	incoming.UserDataHeaderInfo = state.userDataHeaderInfo
	incoming.MoreMessagesToSend = state.moreMessagesToSend
	incoming.StatusReportIndication = state.statusReportIndication
	incoming.ReplyPath = state.replyPath
	return incoming, true
}

func validSMSConcatInfo(concat SMSConcatInfo) bool {
	return concat.IsConcat &&
		concat.Total > 1 &&
		concat.Seq >= 1 &&
		concat.Seq <= concat.Total &&
		(concat.RefBits == 8 || concat.RefBits == 16)
}

func (s *Service) cleanupSMSConcatLocked(now time.Time) {
	for key, state := range s.smsConcat {
		updatedAt := state.updatedAt
		if updatedAt.IsZero() {
			updatedAt = state.firstSeen
		}
		if updatedAt.IsZero() || now.Sub(updatedAt) > smsConcatTTL {
			delete(s.smsConcat, key)
		}
	}
}

func (s *Service) evictOldestSMSConcatLocked() {
	var oldestKey smsConcatKey
	var oldestAt time.Time
	found := false
	for key, state := range s.smsConcat {
		at := state.updatedAt
		if at.IsZero() {
			at = state.firstSeen
		}
		if !found || at.Before(oldestAt) {
			oldestKey = key
			oldestAt = at
			found = true
		}
	}
	if found {
		delete(s.smsConcat, oldestKey)
	}
}

func smsStatusReportError(report SMSStatusReport) string {
	if report.State != "failed" {
		return ""
	}
	return SMSStatusReportText(report.Status)
}

func hexByte(v byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[v>>4], digits[v&0x0f]})
}
