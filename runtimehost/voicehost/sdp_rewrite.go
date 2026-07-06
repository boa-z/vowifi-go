package voicehost

import (
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
)

var ErrInvalidSDPDirection = errors.New("invalid SDP media direction")

var ErrSDPMediaNegotiation = errors.New("invalid SDP media negotiation")

type SDPCodec struct {
	Payload      int
	EncodingName string
	ClockRate    int
	Channels     int
	FMTP         string
}

const (
	SDPCodecAMR            = "AMR"
	SDPCodecAMRWB          = "AMR-WB"
	SDPCodecTelephoneEvent = "telephone-event"
)

type SDPMediaDescription struct {
	Info         SDPInfo
	RTPProfile   string
	RTCPMux      bool
	ExplicitRTCP bool
	Codecs       []SDPCodec
}

type SDPAnswerOptions struct {
	RTPProfile string
	RTCPMux    bool
	Codecs     []SDPCodec
	Security   SDPSecurityInfo
	PTimeMS    int
	MaxPTimeMS int
}

type SDPMediaRewriteOptions struct {
	RTCPMux bool
}

func NewSDPAMRCodec(payload int, fmtp string) SDPCodec {
	return SDPCodec{
		Payload:      payload,
		EncodingName: SDPCodecAMR,
		ClockRate:    8000,
		Channels:     1,
		FMTP:         strings.TrimSpace(fmtp),
	}
}

func NewSDPAMRWBCodec(payload int, fmtp string) SDPCodec {
	return SDPCodec{
		Payload:      payload,
		EncodingName: SDPCodecAMRWB,
		ClockRate:    16000,
		Channels:     1,
		FMTP:         strings.TrimSpace(fmtp),
	}
}

func NewSDPTelephoneEventCodec(payload, clockRate int) SDPCodec {
	if clockRate <= 0 {
		clockRate = DefaultRTPDTMFClockRate
	}
	if payload < 0 {
		payload = DefaultRTPDTMFPayloadType
	}
	return SDPCodec{
		Payload:      payload,
		EncodingName: SDPCodecTelephoneEvent,
		ClockRate:    clockRate,
		Channels:     1,
		FMTP:         "0-16",
	}
}

func RewriteSDPMediaEndpoint(body []byte, endpoint SDPInfo) []byte {
	if len(body) == 0 || strings.TrimSpace(endpoint.ConnectionIP) == "" || endpoint.MediaPort <= 0 {
		return BuildSDPAnswer(endpoint)
	}
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	audioDisabled := sdpAudioPortDisabled(lines)
	ipVersion := "IP4"
	if ip := net.ParseIP(endpoint.ConnectionIP); ip != nil && ip.To4() == nil {
		ipVersion = "IP6"
	}
	rtcpIP := strings.TrimSpace(endpoint.RTCPIP)
	if rtcpIP == "" {
		rtcpIP = endpoint.ConnectionIP
	}
	rtcpIPVersion := "IP4"
	if ip := net.ParseIP(rtcpIP); ip != nil && ip.To4() == nil {
		rtcpIPVersion = "IP6"
	}
	rewroteConnection := false
	rewroteAudio := false
	rewroteRTCP := false
	out := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "c=IN IP"):
			if audioDisabled {
				out = append(out, line)
			} else {
				out = append(out, "c=IN "+ipVersion+" "+endpoint.ConnectionIP)
			}
			rewroteConnection = true
		case strings.HasPrefix(line, "m=audio "):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if fields[1] != "0" {
					fields[1] = strconv.Itoa(endpoint.MediaPort)
				}
				line = strings.Join(fields, " ")
				rewroteAudio = true
			}
			out = append(out, line)
		case strings.HasPrefix(line, "a=rtcp:") && endpoint.RTCPPort > 0:
			if audioDisabled {
				out = append(out, line)
			} else {
				out = append(out, "a=rtcp:"+strconv.Itoa(endpoint.RTCPPort)+" IN "+rtcpIPVersion+" "+rtcpIP)
			}
			rewroteRTCP = true
		default:
			out = append(out, line)
		}
	}
	if !rewroteAudio {
		return BuildSDPAnswer(endpoint)
	}
	if !rewroteConnection && !audioDisabled {
		insertAt := len(out)
		for i, line := range out {
			if strings.HasPrefix(line, "m=audio ") {
				insertAt = i
				break
			}
		}
		out = append(out, "")
		copy(out[insertAt+1:], out[insertAt:])
		out[insertAt] = "c=IN " + ipVersion + " " + endpoint.ConnectionIP
	}
	if endpoint.RTCPPort > 0 && !rewroteRTCP && !audioDisabled {
		insertAt := len(out)
		for i, line := range out {
			if strings.HasPrefix(line, "m=audio ") {
				insertAt = i + 1
				break
			}
		}
		out = append(out, "")
		copy(out[insertAt+1:], out[insertAt:])
		out[insertAt] = "a=rtcp:" + strconv.Itoa(endpoint.RTCPPort) + " IN " + rtcpIPVersion + " " + rtcpIP
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n")
}

func RewriteSDPMediaEndpointWithOptions(body []byte, endpoint SDPInfo, options SDPMediaRewriteOptions) []byte {
	if !options.RTCPMux {
		return RewriteSDPMediaEndpoint(body, endpoint)
	}
	endpoint.RTCPPort = 0
	return rewriteSDPRTCPMux(RewriteSDPMediaEndpoint(body, endpoint))
}

func ParseSDPMediaDescription(body []byte) (SDPMediaDescription, error) {
	info, err := ParseSDP(body)
	if err != nil {
		return SDPMediaDescription{}, err
	}
	out := SDPMediaDescription{Info: info}
	lines := sdpSecurityLines(body)
	inAudio := false
	sawAudio := false
	codecsByPayload := make(map[int]SDPCodec)
	payloadOrder := append([]int(nil), info.Payloads...)
	for _, line := range lines {
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "m=") {
			if inAudio {
				break
			}
			inAudio = false
			fields := strings.Fields(line)
			if len(fields) >= 3 && strings.EqualFold(fields[0], "m=audio") {
				out.RTPProfile = fields[2]
				inAudio = true
				sawAudio = true
			}
			continue
		}
		if !inAudio {
			continue
		}
		switch {
		case strings.EqualFold(strings.TrimSpace(line), "a=rtcp-mux"):
			out.RTCPMux = true
		case strings.HasPrefix(lower, "a=rtcp:"):
			out.ExplicitRTCP = true
		case strings.HasPrefix(lower, "a=rtpmap:"):
			codec, ok, err := parseSDPRTPMapCodec(line)
			if err != nil {
				return SDPMediaDescription{}, err
			}
			if ok {
				if existing, exists := codecsByPayload[codec.Payload]; exists {
					codec.FMTP = existing.FMTP
				}
				codecsByPayload[codec.Payload] = codec
			}
		case strings.HasPrefix(lower, "a=fmtp:"):
			payload, fmtp, ok, err := parseSDPFmtpLine(line)
			if err != nil {
				return SDPMediaDescription{}, err
			}
			if ok {
				codec := codecsByPayload[payload]
				codec.Payload = payload
				codec.FMTP = fmtp
				codecsByPayload[payload] = codec
			}
		}
	}
	if !sawAudio {
		return SDPMediaDescription{}, errors.New("missing SDP audio port")
	}
	out.Codecs = make([]SDPCodec, 0, len(payloadOrder))
	for _, payload := range payloadOrder {
		codec, ok := codecsByPayload[payload]
		if !ok {
			codec, _ = staticSDPCodec(payload)
		}
		codec.Payload = payload
		out.Codecs = append(out.Codecs, codec)
	}
	if out.RTCPMux && out.Info.MediaPort > 0 {
		out.Info.RTCPPort = out.Info.MediaPort
		out.Info.RTCPIP = out.Info.ConnectionIP
	}
	return out, nil
}

func SelectSDPAnswerCodecs(offer, local []SDPCodec) []SDPCodec {
	if len(offer) == 0 {
		return nil
	}
	if len(local) == 0 {
		return cloneSDPCodecs(offer)
	}
	selected := make([]SDPCodec, 0, len(local))
	used := make(map[int]bool, len(offer))
	for _, want := range local {
		want = normalizeSDPCodec(want)
		for i, offered := range offer {
			if used[i] {
				continue
			}
			answer, ok := selectSDPCodecAnswer(offered, want)
			if !ok {
				continue
			}
			selected = append(selected, answer)
			used[i] = true
			break
		}
	}
	return selected
}

func SelectSDPAnswerPacketizationTime(offer, local SDPInfo) (int, int) {
	maxptime := local.MaxPTimeMS
	if maxptime > 0 && offer.MaxPTimeMS > 0 && offer.MaxPTimeMS < maxptime {
		maxptime = offer.MaxPTimeMS
	}
	limit := maxptime
	if limit <= 0 {
		limit = offer.MaxPTimeMS
	}
	ptime := local.PTimeMS
	if ptime <= 0 {
		ptime = offer.PTimeMS
	}
	if ptime > 0 && limit > 0 && ptime > limit {
		ptime = limit
	}
	return ptime, maxptime
}

func SDPInfoWithCodecs(info SDPInfo, codecs []SDPCodec) SDPInfo {
	if len(codecs) == 0 {
		return info
	}
	out := info
	out.Payloads = nil
	out.TelephoneEventPayloads = nil
	for _, codec := range codecs {
		if codec.Payload < 0 || codec.Payload > 127 || sdpPayloadsContain(out.Payloads, codec.Payload) {
			continue
		}
		out.Payloads = append(out.Payloads, codec.Payload)
		if strings.EqualFold(strings.TrimSpace(codec.EncodingName), "telephone-event") {
			clockRate := codec.ClockRate
			if clockRate <= 0 {
				clockRate = DefaultRTPDTMFClockRate
			}
			if out.TelephoneEventPayloads == nil {
				out.TelephoneEventPayloads = make(map[uint8]int)
			}
			out.TelephoneEventPayloads[uint8(codec.Payload)] = clockRate
		}
	}
	return out
}

func BuildSDPAnswerWithOptions(info SDPInfo, options SDPAnswerOptions) []byte {
	if options.RTPProfile == "" && !options.RTCPMux && len(options.Codecs) == 0 && options.Security.IsZero() && options.PTimeMS <= 0 && options.MaxPTimeMS <= 0 {
		return BuildSDPAnswer(info)
	}
	if len(options.Codecs) > 0 {
		info = SDPInfoWithCodecs(info, options.Codecs)
	}
	ip := strings.TrimSpace(info.ConnectionIP)
	if ip == "" {
		ip = "127.0.0.1"
	}
	ipVersion := "IP4"
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		ipVersion = "IP6"
	}
	port := info.MediaPort
	if port <= 0 && normalizeSDPDirection(info.Direction) != "inactive" {
		port = 4000
	}
	payloads := info.Payloads
	if len(payloads) == 0 {
		payloads = []int{0, 8, 101}
	}
	profile := strings.TrimSpace(options.RTPProfile)
	if profile == "" {
		profile = strings.TrimSpace(options.Security.RTPProfile)
	}
	if profile == "" {
		profile = "RTP/AVP"
	}
	direction := strings.TrimSpace(info.Direction)
	if direction == "" {
		direction = "sendrecv"
	}
	ptime := info.PTimeMS
	if options.PTimeMS > 0 {
		ptime = options.PTimeMS
	}
	maxptime := info.MaxPTimeMS
	if options.MaxPTimeMS > 0 {
		maxptime = options.MaxPTimeMS
	}
	timingLines := sdpPacketizationTimeAttributeLines(ptime, maxptime)
	var b strings.Builder
	b.WriteString("v=0\r\n")
	b.WriteString("o=vowifi-go 0 0 IN " + ipVersion + " " + ip + "\r\n")
	b.WriteString("s=VoWiFi\r\n")
	b.WriteString("c=IN " + ipVersion + " " + ip + "\r\n")
	b.WriteString("t=0 0\r\n")
	b.WriteString("m=audio " + strconv.Itoa(port) + " " + profile)
	for _, payload := range payloads {
		b.WriteString(" " + strconv.Itoa(payload))
	}
	b.WriteString("\r\n")
	for _, line := range options.Security.sdpAttributeLines() {
		b.WriteString(line + "\r\n")
	}
	if options.RTCPMux {
		b.WriteString("a=rtcp-mux\r\n")
	} else if info.RTCPPort > 0 {
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
	for _, line := range sdpCodecAttributeLines(payloads, options.Codecs, info.TelephoneEventPayloads) {
		b.WriteString(line + "\r\n")
	}
	return []byte(b.String())
}

func RewriteSDPMediaDirection(body []byte, direction string) ([]byte, error) {
	direction, err := normalizeExplicitSDPDirection(direction)
	if err != nil {
		return nil, err
	}
	if _, err := ParseSDP(body); err != nil {
		return nil, err
	}
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines)+1)
	inserted := false
	inAudio := false
	sawAudio := false
	for _, line := range lines {
		if line == "" {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "m=") {
			inAudio = false
			fields := strings.Fields(line)
			if !sawAudio && len(fields) > 0 && strings.EqualFold(fields[0], "m=audio") {
				inAudio = true
				sawAudio = true
				inserted = true
				out = append(out, line, "a="+direction)
				continue
			}
			out = append(out, line)
			continue
		}
		if inAudio && isSDPDirectionLine(line) {
			continue
		}
		out = append(out, line)
	}
	if !inserted {
		out = append(out, "a="+direction)
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n"), nil
}

func SelectSDPAnswerDirection(offerDirection, localDirection string) (string, error) {
	offer, err := normalizeOptionalSDPDirection(offerDirection)
	if err != nil {
		return "", err
	}
	local, err := normalizeOptionalSDPDirection(localDirection)
	if err != nil {
		return "", err
	}
	answerSends := sdpDirectionAllowsSend(local) && sdpDirectionAllowsReceive(offer)
	answerReceives := sdpDirectionAllowsReceive(local) && sdpDirectionAllowsSend(offer)
	return sdpDirectionFromCapabilities(answerSends, answerReceives), nil
}

func normalizeExplicitSDPDirection(direction string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "sendrecv", "sendonly", "recvonly", "inactive":
		return strings.ToLower(strings.TrimSpace(direction)), nil
	default:
		return "", ErrInvalidSDPDirection
	}
}

func normalizeOptionalSDPDirection(direction string) (string, error) {
	direction = strings.TrimSpace(direction)
	if direction == "" {
		return "sendrecv", nil
	}
	return normalizeExplicitSDPDirection(direction)
}

func isSDPDirectionLine(line string) bool {
	_, ok := parseSDPDirectionLine(line)
	return ok
}

func parseSDPAudioDirection(body []byte, connectionIP string, mediaPort int) string {
	lines := sdpSecurityLines(body)
	beforeFirstMedia := true
	inFirstAudio := false
	sawAudio := false
	sessionDirection := ""
	audioDirection := ""
	for _, line := range lines {
		if line == "" {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "m=") {
			if sawAudio && inFirstAudio {
				break
			}
			beforeFirstMedia = false
			inFirstAudio = false
			fields := strings.Fields(line)
			if !sawAudio && len(fields) > 0 && strings.EqualFold(fields[0], "m=audio") {
				inFirstAudio = true
				sawAudio = true
			}
			continue
		}
		if direction, ok := parseSDPDirectionLine(line); ok {
			if beforeFirstMedia {
				sessionDirection = direction
				continue
			}
			if inFirstAudio {
				audioDirection = direction
			}
		}
	}
	if audioDirection != "" {
		return audioDirection
	}
	if sessionDirection != "" {
		return sessionDirection
	}
	if ip := net.ParseIP(strings.TrimSpace(connectionIP)); ip != nil && ip.IsUnspecified() {
		return "inactive"
	}
	if mediaPort == 0 {
		return "inactive"
	}
	return "sendrecv"
}

func parseSDPDirectionLine(line string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "a=sendrecv":
		return "sendrecv", true
	case "a=sendonly":
		return "sendonly", true
	case "a=recvonly":
		return "recvonly", true
	case "a=inactive":
		return "inactive", true
	default:
		return "", false
	}
}

func sdpDirectionFromCapabilities(send, receive bool) string {
	switch {
	case send && receive:
		return "sendrecv"
	case send:
		return "sendonly"
	case receive:
		return "recvonly"
	default:
		return "inactive"
	}
}

func sdpAudioPortDisabled(lines []string) bool {
	for _, line := range lines {
		if !strings.HasPrefix(line, "m=audio ") {
			continue
		}
		fields := strings.Fields(line)
		return len(fields) >= 2 && strings.TrimSpace(fields[1]) == "0"
	}
	return false
}

func rewriteSDPRTCPMux(body []byte) []byte {
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines)+1)
	inAudio := false
	inserted := false
	audioDisabled := false
	for _, line := range lines {
		if line == "" {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "m=") {
			inAudio = strings.HasPrefix(lower, "m=audio ")
			inserted = false
			audioDisabled = false
			if inAudio {
				fields := strings.Fields(line)
				audioDisabled = len(fields) >= 2 && fields[1] == "0"
			}
			out = append(out, line)
			if inAudio && !audioDisabled {
				out = append(out, "a=rtcp-mux")
				inserted = true
			}
			continue
		}
		if inAudio {
			if strings.HasPrefix(lower, "a=rtcp:") {
				continue
			}
			if lower == "a=rtcp-mux" {
				if inserted || audioDisabled {
					continue
				}
				inserted = true
			}
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n")
}

func parseSDPAudioPacketizationTime(body []byte) (int, int) {
	lines := sdpSecurityLines(body)
	inAudio := false
	var ptime int
	var maxptime int
	for _, line := range lines {
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "m=") {
			fields := strings.Fields(line)
			inAudio = len(fields) > 0 && strings.EqualFold(fields[0], "m=audio")
			continue
		}
		if !inAudio {
			continue
		}
		if value, ok := parseSDPPacketizationTimeAttribute(line, "a=ptime:"); ok {
			ptime = value
			continue
		}
		if value, ok := parseSDPPacketizationTimeAttribute(line, "a=maxptime:"); ok {
			maxptime = value
		}
	}
	return ptime, maxptime
}

func parseSDPPacketizationTimeAttribute(line, prefix string) (int, bool) {
	value, ok := cutSDPAttributeValue(line, prefix)
	if !ok {
		return 0, false
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, true
	}
	ms, err := strconv.Atoi(fields[0])
	if err != nil || ms <= 0 {
		return 0, true
	}
	return ms, true
}

func sdpPacketizationTimeAttributeLines(ptime, maxptime int) []string {
	out := make([]string, 0, 2)
	if ptime > 0 {
		out = append(out, "a=ptime:"+strconv.Itoa(ptime))
	}
	if maxptime > 0 {
		out = append(out, "a=maxptime:"+strconv.Itoa(maxptime))
	}
	return out
}

func parseSDPRTPMapCodec(line string) (SDPCodec, bool, error) {
	value, ok := cutSDPAttributeValue(line, "a=rtpmap:")
	if !ok {
		return SDPCodec{}, false, nil
	}
	payloadText, encoding, ok := cutSDPField(value)
	if !ok || strings.TrimSpace(encoding) == "" {
		return SDPCodec{}, true, ErrSDPMediaNegotiation
	}
	payload, err := strconv.Atoi(payloadText)
	if err != nil || payload < 0 || payload > 127 {
		return SDPCodec{}, true, ErrSDPMediaNegotiation
	}
	parts := strings.Split(strings.Fields(encoding)[0], "/")
	if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" {
		return SDPCodec{}, true, ErrSDPMediaNegotiation
	}
	clockRate, err := strconv.Atoi(parts[1])
	if err != nil || clockRate <= 0 {
		return SDPCodec{}, true, ErrSDPMediaNegotiation
	}
	channels := 1
	if len(parts) >= 3 && strings.TrimSpace(parts[2]) != "" {
		channels, err = strconv.Atoi(parts[2])
		if err != nil || channels <= 0 {
			return SDPCodec{}, true, ErrSDPMediaNegotiation
		}
	}
	return SDPCodec{
		Payload:      payload,
		EncodingName: strings.TrimSpace(parts[0]),
		ClockRate:    clockRate,
		Channels:     channels,
	}, true, nil
}

func parseSDPFmtpLine(line string) (int, string, bool, error) {
	value, ok := cutSDPAttributeValue(line, "a=fmtp:")
	if !ok {
		return 0, "", false, nil
	}
	payloadText, fmtp, ok := cutSDPField(value)
	if !ok {
		return 0, "", true, ErrSDPMediaNegotiation
	}
	payload, err := strconv.Atoi(payloadText)
	if err != nil || payload < 0 || payload > 127 {
		return 0, "", true, ErrSDPMediaNegotiation
	}
	return payload, strings.TrimSpace(fmtp), true, nil
}

func cloneSDPCodecs(in []SDPCodec) []SDPCodec {
	if len(in) == 0 {
		return nil
	}
	out := make([]SDPCodec, len(in))
	copy(out, in)
	return out
}

func normalizeSDPCodec(codec SDPCodec) SDPCodec {
	if codec.Channels <= 0 {
		codec.Channels = 1
	}
	codec.EncodingName = strings.TrimSpace(codec.EncodingName)
	codec.FMTP = strings.TrimSpace(codec.FMTP)
	if codec.EncodingName == "" {
		if static, ok := staticSDPCodec(codec.Payload); ok {
			if codec.ClockRate <= 0 {
				codec.ClockRate = static.ClockRate
			}
			codec.EncodingName = static.EncodingName
		}
	}
	return codec
}

func sdpCodecMatches(offered, want SDPCodec) bool {
	offered = normalizeSDPCodec(offered)
	want = normalizeSDPCodec(want)
	if want.EncodingName == "" {
		return want.Payload >= 0 && offered.Payload == want.Payload
	}
	if !strings.EqualFold(offered.EncodingName, want.EncodingName) {
		return false
	}
	if want.ClockRate > 0 && offered.ClockRate > 0 && want.ClockRate != offered.ClockRate {
		return false
	}
	if want.Channels > 0 && offered.Channels > 0 && want.Channels != offered.Channels {
		return false
	}
	return true
}

func selectSDPCodecAnswer(offered, want SDPCodec) (SDPCodec, bool) {
	if !sdpCodecMatches(offered, want) {
		return SDPCodec{}, false
	}
	answer := normalizeSDPCodec(offered)
	if sdpCodecIsAMR(answer) && sdpCodecIsAMR(want) {
		fmtp, ok := selectSDPAMRAnswerFMTP(answer.FMTP, want.FMTP)
		if !ok {
			return SDPCodec{}, false
		}
		answer.FMTP = fmtp
		return answer, true
	}
	if strings.TrimSpace(want.FMTP) != "" {
		answer.FMTP = strings.TrimSpace(want.FMTP)
	}
	return answer, true
}

func sdpCodecIsAMR(codec SDPCodec) bool {
	name := strings.ToUpper(strings.TrimSpace(codec.EncodingName))
	return name == SDPCodecAMR || name == SDPCodecAMRWB
}

func selectSDPAMRAnswerFMTP(offered, want string) (string, bool) {
	offered = strings.TrimSpace(offered)
	want = strings.TrimSpace(want)
	if want == "" {
		return offered, true
	}
	offeredParams := ParseSDPFmtpParameters(offered)
	wantParams := ParseSDPFmtpParameters(want)
	out := make(map[string]string, len(offeredParams)+len(wantParams))
	for key, value := range offeredParams {
		out[key] = value
	}
	for _, key := range []string{"octet-align", "crc", "robust-sorting", "interleaving"} {
		value, ok := selectSDPAMRBinaryFMTPParam(offeredParams, wantParams, key)
		if !ok {
			return "", false
		}
		if strings.TrimSpace(value) != "" {
			out[key] = value
		}
	}
	if wantModeSet, ok := wantParams["mode-set"]; ok {
		if offeredModeSet, hasOffered := offeredParams["mode-set"]; hasOffered {
			intersection, ok := intersectSDPAMRModeSet(offeredModeSet, wantModeSet)
			if !ok {
				return "", false
			}
			out["mode-set"] = intersection
		} else {
			out["mode-set"] = strings.TrimSpace(wantModeSet)
		}
	}
	for key, value := range wantParams {
		switch key {
		case "octet-align", "crc", "robust-sorting", "interleaving", "mode-set":
			continue
		default:
			if strings.TrimSpace(value) != "" {
				out[key] = value
			}
		}
	}
	return BuildSDPFmtpParameters(out), true
}

func selectSDPAMRBinaryFMTPParam(offered, want map[string]string, key string) (string, bool) {
	wantValue, hasWant := want[key]
	offerValue, hasOffer := offered[key]
	if !hasWant {
		return strings.TrimSpace(offerValue), true
	}
	wantValue = normalizeSDPAMRBinaryFMTPValue(wantValue)
	if wantValue == "" {
		return "", false
	}
	if !hasOffer {
		if wantValue == "0" {
			return wantValue, true
		}
		return "", false
	}
	offerValue = normalizeSDPAMRBinaryFMTPValue(offerValue)
	if offerValue == "" || offerValue != wantValue {
		return "", false
	}
	return wantValue, true
}

func normalizeSDPAMRBinaryFMTPValue(value string) string {
	switch strings.TrimSpace(value) {
	case "0", "1":
		return strings.TrimSpace(value)
	default:
		return ""
	}
}

func intersectSDPAMRModeSet(offered, want string) (string, bool) {
	offeredModes := parseSDPAMRModeSet(offered)
	wantModes := parseSDPAMRModeSet(want)
	if len(offeredModes) == 0 || len(wantModes) == 0 {
		return "", false
	}
	offeredSet := make(map[string]bool, len(offeredModes))
	for _, mode := range offeredModes {
		offeredSet[mode] = true
	}
	intersection := make([]string, 0, len(wantModes))
	seen := make(map[string]bool, len(wantModes))
	for _, mode := range wantModes {
		if offeredSet[mode] && !seen[mode] {
			intersection = append(intersection, mode)
			seen[mode] = true
		}
	}
	if len(intersection) == 0 {
		return "", false
	}
	return strings.Join(intersection, ","), true
}

func parseSDPAMRModeSet(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		mode := strings.TrimSpace(part)
		if mode == "" {
			continue
		}
		if _, err := strconv.Atoi(mode); err != nil {
			return nil
		}
		out = append(out, mode)
	}
	return out
}

func staticSDPCodec(payload int) (SDPCodec, bool) {
	switch payload {
	case 0:
		return SDPCodec{Payload: payload, EncodingName: "PCMU", ClockRate: 8000, Channels: 1}, true
	case 8:
		return SDPCodec{Payload: payload, EncodingName: "PCMA", ClockRate: 8000, Channels: 1}, true
	default:
		return SDPCodec{Payload: payload}, false
	}
}

func sdpCodecAttributeLines(payloads []int, codecs []SDPCodec, telephoneEventPayloads map[uint8]int) []string {
	if telephoneEventPayloads == nil && sdpPayloadsContain(payloads, DefaultRTPDTMFPayloadType) {
		telephoneEventPayloads = map[uint8]int{DefaultRTPDTMFPayloadType: DefaultRTPDTMFClockRate}
	}
	if len(codecs) == 0 {
		codecs = make([]SDPCodec, 0, len(payloads))
		for _, payload := range payloads {
			codec, _ := staticSDPCodec(payload)
			if payload >= 0 && payload <= 127 {
				if clockRate, ok := telephoneEventPayloads[uint8(payload)]; ok {
					if clockRate <= 0 {
						clockRate = DefaultRTPDTMFClockRate
					}
					codec = SDPCodec{Payload: payload, EncodingName: "telephone-event", ClockRate: clockRate, Channels: 1, FMTP: "0-16"}
				}
			}
			codecs = append(codecs, codec)
		}
	}
	byPayload := make(map[int]SDPCodec, len(codecs))
	for _, codec := range codecs {
		codec = normalizeSDPCodec(codec)
		byPayload[codec.Payload] = codec
	}
	out := make([]string, 0, len(payloads)*2)
	for _, payload := range payloads {
		codec := byPayload[payload]
		if codec.EncodingName == "" && codec.ClockRate == 0 {
			codec, _ = staticSDPCodec(payload)
		}
		codec = normalizeSDPCodec(codec)
		if codec.EncodingName != "" && codec.ClockRate > 0 {
			rtpmap := "a=rtpmap:" + strconv.Itoa(payload) + " " + codec.EncodingName + "/" + strconv.Itoa(codec.ClockRate)
			if codec.Channels > 1 {
				rtpmap += "/" + strconv.Itoa(codec.Channels)
			}
			out = append(out, rtpmap)
		}
		if fmtp := strings.TrimSpace(codec.FMTP); fmtp != "" {
			out = append(out, "a=fmtp:"+strconv.Itoa(payload)+" "+fmtp)
		}
	}
	return out
}

func ParseSDPFmtpParameters(fmtp string) map[string]string {
	parts := splitSDPFmtpParameters(fmtp)
	if len(parts) == 0 {
		return nil
	}
	out := make(map[string]string, len(parts))
	for _, part := range parts {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func BuildSDPFmtpParameters(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	normalized := make(map[string]string, len(params))
	for key, value := range params {
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			normalized[key] = value
		}
	}
	if len(normalized) == 0 {
		return ""
	}
	params = normalized
	preferred := []string{
		"octet-align",
		"crc",
		"robust-sorting",
		"interleaving",
		"mode-set",
		"mode-change-period",
		"mode-change-neighbor",
		"max-red",
	}
	used := make(map[string]bool, len(params))
	var parts []string
	for _, key := range preferred {
		if value := strings.TrimSpace(params[key]); value != "" {
			parts = append(parts, key+"="+value)
			used[key] = true
		}
	}
	var rest []string
	for key, value := range params {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" || used[key] || strings.TrimSpace(value) == "" {
			continue
		}
		rest = append(rest, key)
	}
	sort.Strings(rest)
	for _, key := range rest {
		parts = append(parts, key+"="+strings.TrimSpace(params[key]))
	}
	return strings.Join(parts, ";")
}

func splitSDPFmtpParameters(fmtp string) []string {
	fmtp = strings.TrimSpace(fmtp)
	if fmtp == "" {
		return nil
	}
	segments := strings.Split(fmtp, ";")
	out := make([]string, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		if strings.Contains(segment, "=") {
			if strings.Count(segment, "=") > 1 && strings.ContainsAny(segment, " \t") {
				for _, field := range strings.Fields(segment) {
					if strings.Contains(field, "=") {
						out = append(out, field)
					}
				}
				continue
			}
			out = append(out, segment)
			continue
		}
		for _, field := range strings.Fields(segment) {
			if strings.Contains(field, "=") {
				out = append(out, field)
			}
		}
	}
	return out
}
