package voicehost

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pion/rtcp"
)

type RTCPFeedbackDirection string

const (
	RTCPFeedbackClientToIMS RTCPFeedbackDirection = "client_to_ims"
	RTCPFeedbackIMSToClient RTCPFeedbackDirection = "ims_to_client"
)

type RTCPFeedbackKind string

const (
	RTCPFeedbackSenderReport                    RTCPFeedbackKind = "sender_report"
	RTCPFeedbackReceiverReport                  RTCPFeedbackKind = "receiver_report"
	RTCPFeedbackPictureLossIndication           RTCPFeedbackKind = "picture_loss_indication"
	RTCPFeedbackFullIntraRequest                RTCPFeedbackKind = "full_intra_request"
	RTCPFeedbackRapidResynchronizationRequest   RTCPFeedbackKind = "rapid_resynchronization_request"
	RTCPFeedbackTransportLayerNack              RTCPFeedbackKind = "transport_layer_nack"
	RTCPFeedbackReceiverEstimatedMaximumBitrate RTCPFeedbackKind = "receiver_estimated_maximum_bitrate"
	RTCPFeedbackTransportLayerCongestionControl RTCPFeedbackKind = "transport_layer_congestion_control"
	RTCPFeedbackSliceLossIndication             RTCPFeedbackKind = "slice_loss_indication"
	RTCPFeedbackExtendedReport                  RTCPFeedbackKind = "extended_report"
	RTCPFeedbackSourceDescription               RTCPFeedbackKind = "source_description"
	RTCPFeedbackGoodbye                         RTCPFeedbackKind = "goodbye"
	RTCPFeedbackApplicationDefined              RTCPFeedbackKind = "application_defined"
	RTCPFeedbackUnknown                         RTCPFeedbackKind = "unknown"
)

type RTCPFeedbackHandler func(RTCPFeedbackEvent)

type RTCPFeedbackEvent struct {
	Direction        RTCPFeedbackDirection
	Kind             RTCPFeedbackKind
	PacketType       string
	SenderSSRC       uint32
	MediaSSRC        uint32
	SSRC             uint32
	NTPTime          uint64
	RTPTime          uint32
	PacketCount      uint32
	OctetCount       uint32
	DestinationSSRCs []uint32
	ReportCount      int
	NACKCount        int
	FIRCount         int
	SLICount         int
	REMBBitrate      float64
	REMBSSRCs        []uint32
	TransportCCCount int
	Reports          []RTCPReceptionReport
	Packet           rtcp.Packet
}

type RTCPReceptionReport struct {
	SSRC               uint32
	FractionLost       uint8
	TotalLost          uint32
	LastSequenceNumber uint32
	Jitter             uint32
	LastSenderReport   uint32
	Delay              uint32
}

type RTCPFeedbackSummary struct {
	Packets                          uint64
	SenderReports                    uint64
	ReceiverReports                  uint64
	PictureLossIndications           uint64
	FullIntraRequests                uint64
	RapidResynchronizationRequests   uint64
	TransportLayerNacks              uint64
	ReceiverEstimatedMaximumBitrates uint64
	TransportLayerCongestionControls uint64
	SliceLossIndications             uint64
	ExtendedReports                  uint64
	SourceDescriptions               uint64
	Goodbyes                         uint64
	ApplicationDefined               uint64
	UnknownPackets                   uint64
}

type SDPRTCPFeedbackAttribute struct {
	Payload   string
	Type      string
	Parameter string
}

func InspectRTCPFeedback(direction RTCPFeedbackDirection, packet []byte, handler RTCPFeedbackHandler) (RTCPFeedbackSummary, error) {
	var summary RTCPFeedbackSummary
	packets, err := rtcp.Unmarshal(packet)
	if err != nil {
		return summary, err
	}
	for _, packet := range packets {
		for _, event := range rtcpFeedbackEvents(direction, packet) {
			summary.add(event.Kind)
			emitRTCPFeedback(handler, event)
		}
	}
	return summary, nil
}

func ParseSDPRTCPFeedbackLine(line string) (SDPRTCPFeedbackAttribute, bool, error) {
	value, ok := cutSDPAttributeValue(line, "a=rtcp-fb:")
	if !ok {
		return SDPRTCPFeedbackAttribute{}, false, nil
	}
	payload, rest, ok := cutSDPField(value)
	if !ok || !validSDPRTCPFeedbackPayload(payload) {
		return SDPRTCPFeedbackAttribute{}, true, fmt.Errorf("%w: malformed rtcp-fb payload", ErrInvalidSDPSecurity)
	}
	feedbackType, parameter, ok := cutSDPField(rest)
	if !ok || strings.TrimSpace(feedbackType) == "" {
		return SDPRTCPFeedbackAttribute{}, true, fmt.Errorf("%w: malformed rtcp-fb attribute", ErrInvalidSDPSecurity)
	}
	attr := SDPRTCPFeedbackAttribute{
		Payload:   strings.TrimSpace(payload),
		Type:      strings.TrimSpace(feedbackType),
		Parameter: strings.TrimSpace(parameter),
	}
	if attr.SDPValue() == "" {
		return SDPRTCPFeedbackAttribute{}, true, fmt.Errorf("%w: malformed rtcp-fb attribute", ErrInvalidSDPSecurity)
	}
	return attr, true, nil
}

func (a SDPRTCPFeedbackAttribute) SDPValue() string {
	payload := strings.TrimSpace(a.Payload)
	feedbackType := strings.TrimSpace(a.Type)
	if payload == "" || feedbackType == "" || !validSDPRTCPFeedbackPayload(payload) {
		return ""
	}
	value := payload + " " + feedbackType
	if parameter := strings.TrimSpace(a.Parameter); parameter != "" {
		value += " " + parameter
	}
	return value
}

func ParseSDPRTCPFeedbackAttributes(body []byte) ([]SDPRTCPFeedbackAttribute, error) {
	lines := sdpSecurityLines(body)
	var session []SDPRTCPFeedbackAttribute
	var media []SDPRTCPFeedbackAttribute
	beforeFirstMedia := true
	inAudio := false
	sawAudio := false
	for _, line := range lines {
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "m=") {
			if inAudio {
				break
			}
			beforeFirstMedia = false
			inAudio = false
			fields := strings.Fields(line)
			if len(fields) > 0 && strings.EqualFold(fields[0], "m=audio") {
				inAudio = true
				sawAudio = true
			}
			continue
		}
		if beforeFirstMedia || inAudio {
			attr, ok, err := ParseSDPRTCPFeedbackLine(line)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			if beforeFirstMedia {
				session = append(session, attr)
				continue
			}
			media = append(media, attr)
		}
	}
	if !sawAudio {
		return nil, fmt.Errorf("%w: missing SDP audio media", ErrInvalidSDPSecurity)
	}
	if len(media) == 0 {
		media = session
	}
	return cloneSDPRTCPFeedbackAttributes(media), nil
}

func SelectSDPRTCPFeedbackAnswer(offer, local []SDPRTCPFeedbackAttribute, payloads []int) []SDPRTCPFeedbackAttribute {
	if len(offer) == 0 {
		return nil
	}
	if len(local) == 0 {
		return filterSDPRTCPFeedbackPayloads(offer, payloads)
	}
	var out []SDPRTCPFeedbackAttribute
	seen := make(map[string]bool)
	for _, offered := range offer {
		for _, allowed := range local {
			if !sdpRTCPFeedbackCompatible(offered, allowed) {
				continue
			}
			answer := offered
			if strings.TrimSpace(answer.Payload) == "*" && strings.TrimSpace(allowed.Payload) != "*" {
				answer.Payload = strings.TrimSpace(allowed.Payload)
			}
			if !sdpRTCPFeedbackPayloadAllowed(answer.Payload, payloads) {
				continue
			}
			key := strings.ToLower(answer.SDPValue())
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, answer)
		}
	}
	return out
}

func RewriteSDPRTCPFeedback(body []byte, feedback []SDPRTCPFeedbackAttribute) []byte {
	lines := sdpSecurityLines(body)
	attrs := sdpRTCPFeedbackAttributeLines(feedback)
	out := make([]string, 0, len(lines)+len(attrs))
	inAudio := false
	inserted := false
	for _, line := range lines {
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "m=") {
			if inAudio && !inserted {
				out = append(out, attrs...)
			}
			inAudio = false
			fields := strings.Fields(line)
			if len(fields) > 0 && strings.EqualFold(fields[0], "m=audio") {
				inAudio = true
				inserted = true
				out = append(out, line)
				out = append(out, attrs...)
				continue
			}
			out = append(out, line)
			continue
		}
		if inAudio && strings.HasPrefix(lower, "a=rtcp-fb:") {
			continue
		}
		out = append(out, line)
	}
	if inAudio && !inserted {
		out = append(out, attrs...)
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n")
}

func rtcpFeedbackEvents(direction RTCPFeedbackDirection, packet rtcp.Packet) []RTCPFeedbackEvent {
	if packet == nil {
		return nil
	}
	if compound, ok := packet.(*rtcp.CompoundPacket); ok && compound != nil {
		var events []RTCPFeedbackEvent
		for _, inner := range *compound {
			events = append(events, rtcpFeedbackEvents(direction, inner)...)
		}
		return events
	}
	event := RTCPFeedbackEvent{
		Direction:        direction,
		Kind:             RTCPFeedbackUnknown,
		PacketType:       rtcpPacketType(packet),
		DestinationSSRCs: append([]uint32(nil), packet.DestinationSSRC()...),
		Packet:           packet,
	}
	switch p := packet.(type) {
	case *rtcp.SenderReport:
		event.Kind = RTCPFeedbackSenderReport
		event.SSRC = p.SSRC
		event.NTPTime = p.NTPTime
		event.RTPTime = p.RTPTime
		event.PacketCount = p.PacketCount
		event.OctetCount = p.OctetCount
		event.ReportCount = len(p.Reports)
		event.Reports = rtcpReceptionReports(p.Reports)
	case *rtcp.ReceiverReport:
		event.Kind = RTCPFeedbackReceiverReport
		event.SSRC = p.SSRC
		event.ReportCount = len(p.Reports)
		event.Reports = rtcpReceptionReports(p.Reports)
	case *rtcp.PictureLossIndication:
		event.Kind = RTCPFeedbackPictureLossIndication
		event.SenderSSRC = p.SenderSSRC
		event.MediaSSRC = p.MediaSSRC
	case *rtcp.FullIntraRequest:
		event.Kind = RTCPFeedbackFullIntraRequest
		event.SenderSSRC = p.SenderSSRC
		event.MediaSSRC = p.MediaSSRC
		event.FIRCount = len(p.FIR)
	case *rtcp.RapidResynchronizationRequest:
		event.Kind = RTCPFeedbackRapidResynchronizationRequest
		event.SenderSSRC = p.SenderSSRC
		event.MediaSSRC = p.MediaSSRC
	case *rtcp.TransportLayerNack:
		event.Kind = RTCPFeedbackTransportLayerNack
		event.SenderSSRC = p.SenderSSRC
		event.MediaSSRC = p.MediaSSRC
		for _, nack := range p.Nacks {
			event.NACKCount += len(nack.PacketList())
		}
	case *rtcp.ReceiverEstimatedMaximumBitrate:
		event.Kind = RTCPFeedbackReceiverEstimatedMaximumBitrate
		event.SenderSSRC = p.SenderSSRC
		event.REMBBitrate = float64(p.Bitrate)
		event.REMBSSRCs = append([]uint32(nil), p.SSRCs...)
	case *rtcp.TransportLayerCC:
		event.Kind = RTCPFeedbackTransportLayerCongestionControl
		event.SenderSSRC = p.SenderSSRC
		event.MediaSSRC = p.MediaSSRC
		event.TransportCCCount = int(p.PacketStatusCount)
	case *rtcp.SliceLossIndication:
		event.Kind = RTCPFeedbackSliceLossIndication
		event.SenderSSRC = p.SenderSSRC
		event.MediaSSRC = p.MediaSSRC
		event.SLICount = len(p.SLI)
	case *rtcp.ExtendedReport:
		event.Kind = RTCPFeedbackExtendedReport
	case *rtcp.SourceDescription:
		event.Kind = RTCPFeedbackSourceDescription
	case *rtcp.Goodbye:
		event.Kind = RTCPFeedbackGoodbye
	case *rtcp.ApplicationDefined:
		event.Kind = RTCPFeedbackApplicationDefined
		event.SSRC = p.SSRC
	case *rtcp.RawPacket:
		event.Kind = RTCPFeedbackUnknown
	}
	return []RTCPFeedbackEvent{event}
}

func rtcpReceptionReports(in []rtcp.ReceptionReport) []RTCPReceptionReport {
	if len(in) == 0 {
		return nil
	}
	out := make([]RTCPReceptionReport, 0, len(in))
	for _, report := range in {
		out = append(out, RTCPReceptionReport{
			SSRC:               report.SSRC,
			FractionLost:       report.FractionLost,
			TotalLost:          report.TotalLost,
			LastSequenceNumber: report.LastSequenceNumber,
			Jitter:             report.Jitter,
			LastSenderReport:   report.LastSenderReport,
			Delay:              report.Delay,
		})
	}
	return out
}

func (s *RTCPFeedbackSummary) add(kind RTCPFeedbackKind) {
	if s == nil {
		return
	}
	s.Packets++
	switch kind {
	case RTCPFeedbackSenderReport:
		s.SenderReports++
	case RTCPFeedbackReceiverReport:
		s.ReceiverReports++
	case RTCPFeedbackPictureLossIndication:
		s.PictureLossIndications++
	case RTCPFeedbackFullIntraRequest:
		s.FullIntraRequests++
	case RTCPFeedbackRapidResynchronizationRequest:
		s.RapidResynchronizationRequests++
	case RTCPFeedbackTransportLayerNack:
		s.TransportLayerNacks++
	case RTCPFeedbackReceiverEstimatedMaximumBitrate:
		s.ReceiverEstimatedMaximumBitrates++
	case RTCPFeedbackTransportLayerCongestionControl:
		s.TransportLayerCongestionControls++
	case RTCPFeedbackSliceLossIndication:
		s.SliceLossIndications++
	case RTCPFeedbackExtendedReport:
		s.ExtendedReports++
	case RTCPFeedbackSourceDescription:
		s.SourceDescriptions++
	case RTCPFeedbackGoodbye:
		s.Goodbyes++
	case RTCPFeedbackApplicationDefined:
		s.ApplicationDefined++
	default:
		s.UnknownPackets++
	}
}

func emitRTCPFeedback(handler RTCPFeedbackHandler, event RTCPFeedbackEvent) {
	if handler == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	handler(event)
}

type rtcpHeaderer interface {
	Header() rtcp.Header
}

func rtcpPacketType(packet rtcp.Packet) string {
	if packet == nil {
		return ""
	}
	if headerer, ok := packet.(rtcpHeaderer); ok {
		header := headerer.Header()
		return strconv.Itoa(int(header.Type))
	}
	name := fmt.Sprintf("%T", packet)
	name = strings.TrimPrefix(name, "*")
	name = strings.TrimPrefix(name, "rtcp.")
	return name
}

func sdpRTCPFeedbackAttributeLines(feedback []SDPRTCPFeedbackAttribute) []string {
	out := make([]string, 0, len(feedback))
	seen := make(map[string]bool, len(feedback))
	for _, attr := range feedback {
		if value := attr.SDPValue(); value != "" {
			line := "a=rtcp-fb:" + value
			key := strings.ToLower(line)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, line)
		}
	}
	return out
}

func cloneSDPRTCPFeedbackAttributes(in []SDPRTCPFeedbackAttribute) []SDPRTCPFeedbackAttribute {
	if len(in) == 0 {
		return nil
	}
	out := make([]SDPRTCPFeedbackAttribute, 0, len(in))
	for _, attr := range in {
		out = append(out, SDPRTCPFeedbackAttribute{
			Payload:   strings.TrimSpace(attr.Payload),
			Type:      strings.TrimSpace(attr.Type),
			Parameter: strings.TrimSpace(attr.Parameter),
		})
	}
	return out
}

func filterSDPRTCPFeedbackPayloads(in []SDPRTCPFeedbackAttribute, payloads []int) []SDPRTCPFeedbackAttribute {
	var out []SDPRTCPFeedbackAttribute
	seen := make(map[string]bool)
	for _, attr := range in {
		if !sdpRTCPFeedbackPayloadAllowed(attr.Payload, payloads) {
			continue
		}
		key := strings.ToLower(attr.SDPValue())
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, attr)
	}
	return out
}

func sdpRTCPFeedbackCompatible(offer, local SDPRTCPFeedbackAttribute) bool {
	if offer.SDPValue() == "" || local.SDPValue() == "" {
		return false
	}
	offerPayload := strings.TrimSpace(offer.Payload)
	localPayload := strings.TrimSpace(local.Payload)
	if offerPayload != "*" && localPayload != "*" && offerPayload != localPayload {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(offer.Type), strings.TrimSpace(local.Type)) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(offer.Parameter), strings.TrimSpace(local.Parameter))
}

func sdpRTCPFeedbackPayloadAllowed(payload string, payloads []int) bool {
	payload = strings.TrimSpace(payload)
	if payload == "*" || len(payloads) == 0 {
		return true
	}
	want, err := strconv.Atoi(payload)
	if err != nil {
		return false
	}
	for _, candidate := range payloads {
		if candidate == want {
			return true
		}
	}
	return false
}

func validSDPRTCPFeedbackPayload(payload string) bool {
	payload = strings.TrimSpace(payload)
	if payload == "*" {
		return true
	}
	value, err := strconv.Atoi(payload)
	return err == nil && value >= 0 && value <= 127
}
