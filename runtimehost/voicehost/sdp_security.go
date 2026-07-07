package voicehost

import (
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidSDPSecurity = errors.New("invalid SDP security")

var ErrSDPSecurityNegotiation = errors.New("SDP security negotiation failed")

type SDPCryptoAttribute struct {
	Tag           string
	Suite         string
	KeyParams     string
	SessionParams string
}

type SDPFingerprintAttribute struct {
	HashFunc    string
	Fingerprint string
}

type SDPSecurityInfo struct {
	RTPProfile        string
	Crypto            []SDPCryptoAttribute
	Fingerprints      []SDPFingerprintAttribute
	Setup             string
	RTCPMux           bool
	RTCPMuxOnly       bool
	RTCPReducedSize   bool
	RTCPFeedback      []SDPRTCPFeedbackAttribute
	UnknownAttributes []string
}

type SDPSecurityAnswerOptions struct {
	RTPProfiles  []string
	Crypto       []SDPCryptoAttribute
	Fingerprints []SDPFingerprintAttribute
	Setup        string
	PreferCrypto bool
}

func ParseSDPWithSecurity(body []byte) (SDPInfo, SDPSecurityInfo, error) {
	info, err := ParseSDP(body)
	if err != nil {
		return SDPInfo{}, SDPSecurityInfo{}, err
	}
	security, err := ParseSDPSecurity(body)
	if err != nil {
		return SDPInfo{}, SDPSecurityInfo{}, err
	}
	return info, security, nil
}

func ParseSDPSecurity(body []byte) (SDPSecurityInfo, error) {
	lines := sdpSecurityLines(body)
	var session SDPSecurityInfo
	var out SDPSecurityInfo
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
			if len(fields) >= 1 && strings.EqualFold(fields[0], "m=audio") {
				if len(fields) < 3 {
					return SDPSecurityInfo{}, fmt.Errorf("%w: missing audio RTP profile", ErrInvalidSDPSecurity)
				}
				out.RTPProfile = fields[2]
				inAudio = true
				sawAudio = true
			}
			continue
		}
		switch {
		case beforeFirstMedia:
			if fingerprint, ok, err := parseSDPFingerprintLine(line); ok || err != nil {
				if err != nil {
					return SDPSecurityInfo{}, err
				}
				session.Fingerprints = append(session.Fingerprints, fingerprint)
				continue
			}
			if setup, ok, err := parseSDPSetupLine(line); ok || err != nil {
				if err != nil {
					return SDPSecurityInfo{}, err
				}
				session.Setup = setup
				continue
			}
			if feedback, ok, err := ParseSDPRTCPFeedbackLine(line); ok || err != nil {
				if err != nil {
					return SDPSecurityInfo{}, err
				}
				session.RTCPFeedback = append(session.RTCPFeedback, feedback)
			}
		case inAudio:
			if crypto, ok, err := parseSDPCryptoLine(line); ok || err != nil {
				if err != nil {
					return SDPSecurityInfo{}, err
				}
				out.Crypto = append(out.Crypto, crypto)
				continue
			}
			if fingerprint, ok, err := parseSDPFingerprintLine(line); ok || err != nil {
				if err != nil {
					return SDPSecurityInfo{}, err
				}
				out.Fingerprints = append(out.Fingerprints, fingerprint)
				continue
			}
			if setup, ok, err := parseSDPSetupLine(line); ok || err != nil {
				if err != nil {
					return SDPSecurityInfo{}, err
				}
				out.Setup = setup
				continue
			}
			if feedback, ok, err := ParseSDPRTCPFeedbackLine(line); ok || err != nil {
				if err != nil {
					return SDPSecurityInfo{}, err
				}
				out.RTCPFeedback = append(out.RTCPFeedback, feedback)
				continue
			}
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "a=rtcp-mux":
				out.RTCPMux = true
				continue
			case "a=rtcp-mux-only":
				out.RTCPMux = true
				out.RTCPMuxOnly = true
				continue
			case "a=rtcp-rsize":
				out.RTCPReducedSize = true
				continue
			}
			if shouldPreserveUnknownSDPSecurityAttribute(line) {
				out.UnknownAttributes = append(out.UnknownAttributes, strings.TrimSpace(line))
			}
		}
	}
	if !sawAudio {
		return SDPSecurityInfo{}, fmt.Errorf("%w: missing SDP audio media", ErrInvalidSDPSecurity)
	}
	if len(out.Fingerprints) == 0 {
		out.Fingerprints = session.Fingerprints
	}
	if strings.TrimSpace(out.Setup) == "" {
		out.Setup = session.Setup
	}
	if len(out.RTCPFeedback) == 0 {
		out.RTCPFeedback = session.RTCPFeedback
	}
	return out, nil
}

func SelectSDPSecurityAnswer(offer SDPSecurityInfo, options SDPSecurityAnswerOptions) (SDPSecurityInfo, error) {
	profile, ok := selectSDPRTPProfile(offer.RTPProfile, options.RTPProfiles)
	if !ok {
		return SDPSecurityInfo{}, fmt.Errorf("%w: unsupported RTP profile %q", ErrSDPSecurityNegotiation, offer.RTPProfile)
	}
	if !options.PreferCrypto {
		if answer, ok, err := selectSDPFingerprintAnswer(offer, options, profile); ok || err != nil {
			return withSDPTransportAttributes(answer, offer), err
		}
	}
	if answer, ok := selectSDPCryptoAnswer(offer, options, profile); ok {
		return withSDPTransportAttributes(answer, offer), nil
	}
	if options.PreferCrypto {
		if answer, ok, err := selectSDPFingerprintAnswer(offer, options, profile); ok || err != nil {
			return withSDPTransportAttributes(answer, offer), err
		}
	}
	if offer.HasSecurityAttributes() {
		return SDPSecurityInfo{}, fmt.Errorf("%w: no compatible SDP security attributes", ErrSDPSecurityNegotiation)
	}
	return withSDPTransportAttributes(SDPSecurityInfo{RTPProfile: profile}, offer), nil
}

func BuildSDPAnswerWithSecurity(info SDPInfo, security SDPSecurityInfo) []byte {
	base := BuildSDPAnswer(info)
	if security.IsZero() {
		return base
	}
	return applySDPSecurity(base, security)
}

func (s SDPSecurityInfo) IsZero() bool {
	return strings.TrimSpace(s.RTPProfile) == "" &&
		len(s.Crypto) == 0 &&
		len(s.Fingerprints) == 0 &&
		strings.TrimSpace(s.Setup) == "" &&
		!s.RTCPMux &&
		!s.RTCPMuxOnly &&
		!s.RTCPReducedSize &&
		len(s.RTCPFeedback) == 0 &&
		len(s.UnknownAttributes) == 0
}

func (s SDPSecurityInfo) HasSecurityAttributes() bool {
	return len(s.Crypto) > 0 || len(s.Fingerprints) > 0 || strings.TrimSpace(s.Setup) != ""
}

func withSDPTransportAttributes(answer, offer SDPSecurityInfo) SDPSecurityInfo {
	answer.RTCPMux = offer.RTCPMux
	answer.RTCPMuxOnly = offer.RTCPMuxOnly
	answer.RTCPReducedSize = offer.RTCPReducedSize
	answer.RTCPFeedback = cloneSDPRTCPFeedbackAttributes(offer.RTCPFeedback)
	answer.UnknownAttributes = cloneSDPAttributeLines(offer.UnknownAttributes)
	return answer
}

func (a SDPCryptoAttribute) SDPValue() string {
	parts := []string{strings.TrimSpace(a.Tag), strings.TrimSpace(a.Suite), strings.TrimSpace(a.KeyParams)}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return ""
	}
	value := strings.Join(parts, " ")
	if session := strings.TrimSpace(a.SessionParams); session != "" {
		value += " " + session
	}
	return value
}

func (a SDPFingerprintAttribute) SDPValue() string {
	hashFunc := strings.TrimSpace(a.HashFunc)
	fingerprint := strings.TrimSpace(a.Fingerprint)
	if hashFunc == "" || fingerprint == "" {
		return ""
	}
	return hashFunc + " " + fingerprint
}

func applySDPSecurity(body []byte, security SDPSecurityInfo) []byte {
	lines := sdpSecurityLines(body)
	attrs := security.sdpAttributeLines()
	profile := strings.TrimSpace(security.RTPProfile)
	out := make([]string, 0, len(lines)+len(attrs))
	inserted := false
	inAudio := false
	skip := security.sdpRewriteSkipOptions()
	insertedAttr := make(map[string]bool, len(attrs))
	for _, line := range lines {
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "m=") {
			if inAudio {
				inAudio = false
			}
			fields := strings.Fields(line)
			audio := len(fields) > 0 && strings.EqualFold(fields[0], "m=audio")
			if audio {
				inAudio = true
			}
			if !inserted && audio {
				if profile != "" && len(fields) >= 3 {
					fields[2] = profile
					line = strings.Join(fields, " ")
				}
				out = append(out, line)
				for _, attr := range attrs {
					out = append(out, attr)
					insertedAttr[strings.ToLower(attr)] = true
				}
				inserted = true
				continue
			}
			out = append(out, line)
			continue
		}
		if !inserted && skip.beforeMedia(line) {
			continue
		}
		if inAudio {
			if insertedAttr[strings.ToLower(strings.TrimSpace(line))] {
				continue
			}
			if skip.audio(line) {
				continue
			}
		}
		out = append(out, line)
	}
	if !inserted {
		out = append(out, attrs...)
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n")
}

type sdpSecurityRewriteSkipOptions struct {
	crypto            bool
	fingerprint       bool
	setup             bool
	rtcpFeedback      bool
	rtcpMux           bool
	rtcpMuxOnly       bool
	rtcpReducedSize   bool
	unknownAttributes map[string]bool
}

func (s SDPSecurityInfo) sdpRewriteSkipOptions() sdpSecurityRewriteSkipOptions {
	out := sdpSecurityRewriteSkipOptions{
		crypto:            len(s.Crypto) > 0,
		fingerprint:       len(s.Fingerprints) > 0,
		setup:             strings.TrimSpace(s.Setup) != "",
		rtcpFeedback:      len(s.RTCPFeedback) > 0,
		rtcpMux:           s.RTCPMux || s.RTCPMuxOnly,
		rtcpMuxOnly:       s.RTCPMuxOnly,
		rtcpReducedSize:   s.RTCPReducedSize,
		unknownAttributes: make(map[string]bool, len(s.UnknownAttributes)),
	}
	for _, line := range s.UnknownAttributes {
		if line = strings.TrimSpace(line); line != "" {
			out.unknownAttributes[strings.ToLower(line)] = true
		}
	}
	return out
}

func (o sdpSecurityRewriteSkipOptions) beforeMedia(line string) bool {
	line = strings.TrimSpace(line)
	lower := strings.ToLower(line)
	switch {
	case o.fingerprint && strings.HasPrefix(lower, "a=fingerprint:"):
		return true
	case o.setup && strings.HasPrefix(lower, "a=setup:"):
		return true
	case o.rtcpFeedback && strings.HasPrefix(lower, "a=rtcp-fb:"):
		return true
	default:
		return false
	}
}

func (o sdpSecurityRewriteSkipOptions) audio(line string) bool {
	line = strings.TrimSpace(line)
	lower := strings.ToLower(line)
	switch {
	case o.crypto && strings.HasPrefix(lower, "a=crypto:"):
		return true
	case o.fingerprint && strings.HasPrefix(lower, "a=fingerprint:"):
		return true
	case o.setup && strings.HasPrefix(lower, "a=setup:"):
		return true
	case o.rtcpFeedback && strings.HasPrefix(lower, "a=rtcp-fb:"):
		return true
	case o.rtcpMux && lower == "a=rtcp-mux":
		return true
	case o.rtcpMuxOnly && lower == "a=rtcp-mux-only":
		return true
	case o.rtcpReducedSize && lower == "a=rtcp-rsize":
		return true
	case o.unknownAttributes[lower]:
		return true
	default:
		return false
	}
}

func (s SDPSecurityInfo) sdpAttributeLines() []string {
	out := make([]string, 0, len(s.Crypto)+len(s.Fingerprints)+len(s.RTCPFeedback)+len(s.UnknownAttributes)+4)
	seen := make(map[string]bool)
	appendLine := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		key := strings.ToLower(line)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, line)
	}
	for _, crypto := range s.Crypto {
		if value := crypto.SDPValue(); value != "" {
			appendLine("a=crypto:" + value)
		}
	}
	for _, fingerprint := range s.Fingerprints {
		if value := fingerprint.SDPValue(); value != "" {
			appendLine("a=fingerprint:" + value)
		}
	}
	if setup := strings.TrimSpace(s.Setup); setup != "" {
		appendLine("a=setup:" + setup)
	}
	if s.RTCPMux || s.RTCPMuxOnly {
		appendLine("a=rtcp-mux")
	}
	if s.RTCPMuxOnly {
		appendLine("a=rtcp-mux-only")
	}
	if s.RTCPReducedSize {
		appendLine("a=rtcp-rsize")
	}
	for _, line := range sdpRTCPFeedbackAttributeLines(s.RTCPFeedback) {
		appendLine(line)
	}
	for _, line := range s.UnknownAttributes {
		if shouldPreserveUnknownSDPSecurityAttribute(line) {
			appendLine(line)
		}
	}
	return out
}

func parseSDPCryptoLine(line string) (SDPCryptoAttribute, bool, error) {
	value, ok := cutSDPAttributeValue(line, "a=crypto:")
	if !ok {
		return SDPCryptoAttribute{}, false, nil
	}
	tag, rest, ok := cutSDPField(value)
	if !ok {
		return SDPCryptoAttribute{}, true, fmt.Errorf("%w: malformed crypto attribute", ErrInvalidSDPSecurity)
	}
	suite, rest, ok := cutSDPField(rest)
	if !ok {
		return SDPCryptoAttribute{}, true, fmt.Errorf("%w: malformed crypto attribute", ErrInvalidSDPSecurity)
	}
	keyParams, sessionParams, ok := cutSDPField(rest)
	if !ok {
		return SDPCryptoAttribute{}, true, fmt.Errorf("%w: malformed crypto attribute", ErrInvalidSDPSecurity)
	}
	attr := SDPCryptoAttribute{
		Tag:           tag,
		Suite:         suite,
		KeyParams:     keyParams,
		SessionParams: strings.TrimSpace(sessionParams),
	}
	if err := ValidateSDPCryptoAttribute(attr); err != nil {
		return SDPCryptoAttribute{}, true, fmt.Errorf("%w: %w", ErrInvalidSDPSecurity, err)
	}
	return attr, true, nil
}

func parseSDPFingerprintLine(line string) (SDPFingerprintAttribute, bool, error) {
	value, ok := cutSDPAttributeValue(line, "a=fingerprint:")
	if !ok {
		return SDPFingerprintAttribute{}, false, nil
	}
	hashFunc, fingerprint, ok := cutSDPField(value)
	if !ok || strings.TrimSpace(fingerprint) == "" {
		return SDPFingerprintAttribute{}, true, fmt.Errorf("%w: malformed fingerprint attribute", ErrInvalidSDPSecurity)
	}
	attr := SDPFingerprintAttribute{HashFunc: hashFunc, Fingerprint: strings.TrimSpace(fingerprint)}
	if err := validateSDPFingerprintAttribute(attr); err != nil {
		return SDPFingerprintAttribute{}, true, fmt.Errorf("%w: %w", ErrInvalidSDPSecurity, err)
	}
	return attr, true, nil
}

func parseSDPSetupLine(line string) (string, bool, error) {
	value, ok := cutSDPAttributeValue(line, "a=setup:")
	if !ok {
		return "", false, nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", true, fmt.Errorf("%w: malformed setup attribute", ErrInvalidSDPSecurity)
	}
	if !validSDPSetupRole(value) {
		return "", true, fmt.Errorf("%w: unsupported setup role %q", ErrInvalidSDPSecurity, value)
	}
	return value, true, nil
}

func shouldPreserveUnknownSDPSecurityAttribute(line string) bool {
	line = strings.TrimSpace(line)
	lower := strings.ToLower(line)
	if !strings.HasPrefix(lower, "a=") || len(line) <= len("a=") {
		return false
	}
	switch {
	case lower == "a=sendrecv" || lower == "a=sendonly" || lower == "a=recvonly" || lower == "a=inactive":
		return false
	case lower == "a=rtcp-mux" || lower == "a=rtcp-mux-only" || lower == "a=rtcp-rsize":
		return false
	case strings.HasPrefix(lower, "a=crypto:"):
		return false
	case strings.HasPrefix(lower, "a=fingerprint:"):
		return false
	case strings.HasPrefix(lower, "a=setup:"):
		return false
	case strings.HasPrefix(lower, "a=rtcp-fb:"):
		return false
	case strings.HasPrefix(lower, "a=rtcp:"):
		return false
	case strings.HasPrefix(lower, "a=rtpmap:"):
		return false
	case strings.HasPrefix(lower, "a=fmtp:"):
		return false
	case strings.HasPrefix(lower, "a=ptime:") || strings.HasPrefix(lower, "a=maxptime:"):
		return false
	default:
		return true
	}
}

func cloneSDPAttributeLines(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, line := range in {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func validateSDPFingerprintAttribute(attr SDPFingerprintAttribute) error {
	hashFunc := strings.ToLower(strings.TrimSpace(attr.HashFunc))
	switch hashFunc {
	case "sha-1", "sha-224", "sha-256", "sha-384", "sha-512":
	default:
		return fmt.Errorf("unsupported fingerprint hash function %q", strings.TrimSpace(attr.HashFunc))
	}
	fingerprint := strings.TrimSpace(attr.Fingerprint)
	if fingerprint == "" {
		return fmt.Errorf("empty fingerprint")
	}
	parts := strings.Split(fingerprint, ":")
	for _, part := range parts {
		if len(part) != 2 || !isSDPHexOctet(part) {
			return fmt.Errorf("malformed fingerprint")
		}
	}
	return nil
}

func validSDPSetupRole(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "active", "passive", "actpass", "holdconn":
		return true
	default:
		return false
	}
}

func isSDPHexOctet(value string) bool {
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func cutSDPAttributeValue(line, prefix string) (string, bool) {
	if len(line) < len(prefix) || !strings.EqualFold(line[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(line[len(prefix):]), true
}

func cutSDPField(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", false
	}
	for i, r := range value {
		if r == ' ' || r == '\t' {
			return value[:i], strings.TrimSpace(value[i+1:]), true
		}
	}
	return value, "", true
}

func sdpSecurityLines(body []byte) []string {
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	raw := strings.Split(text, "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		lines = append(lines, strings.TrimSpace(line))
	}
	return lines
}

func selectSDPRTPProfile(offerProfile string, allowed []string) (string, bool) {
	offerProfile = strings.TrimSpace(offerProfile)
	if offerProfile == "" {
		offerProfile = "RTP/AVP"
	}
	if len(allowed) == 0 {
		return offerProfile, true
	}
	for _, profile := range allowed {
		profile = strings.TrimSpace(profile)
		if profile == "" {
			continue
		}
		if strings.EqualFold(profile, offerProfile) {
			return offerProfile, true
		}
	}
	return "", false
}

func selectSDPFingerprintAnswer(offer SDPSecurityInfo, options SDPSecurityAnswerOptions, profile string) (SDPSecurityInfo, bool, error) {
	if len(offer.Fingerprints) == 0 || len(options.Fingerprints) == 0 {
		return SDPSecurityInfo{}, false, nil
	}
	for _, local := range options.Fingerprints {
		for _, remote := range offer.Fingerprints {
			if !strings.EqualFold(strings.TrimSpace(local.HashFunc), strings.TrimSpace(remote.HashFunc)) {
				continue
			}
			setup, err := SelectSDPSetupAnswer(offer.Setup, options.Setup)
			if err != nil {
				return SDPSecurityInfo{}, true, err
			}
			local.HashFunc = strings.TrimSpace(local.HashFunc)
			local.Fingerprint = strings.TrimSpace(local.Fingerprint)
			if local.SDPValue() == "" {
				continue
			}
			return SDPSecurityInfo{
				RTPProfile:   profile,
				Fingerprints: []SDPFingerprintAttribute{local},
				Setup:        setup,
			}, true, nil
		}
	}
	return SDPSecurityInfo{}, false, nil
}

func selectSDPCryptoAnswer(offer SDPSecurityInfo, options SDPSecurityAnswerOptions, profile string) (SDPSecurityInfo, bool) {
	if len(offer.Crypto) == 0 || len(options.Crypto) == 0 {
		return SDPSecurityInfo{}, false
	}
	for _, local := range options.Crypto {
		for _, remote := range offer.Crypto {
			if !strings.EqualFold(strings.TrimSpace(local.Suite), strings.TrimSpace(remote.Suite)) {
				continue
			}
			answer := local
			answer.Tag = strings.TrimSpace(remote.Tag)
			answer.Suite = strings.TrimSpace(local.Suite)
			answer.KeyParams = strings.TrimSpace(local.KeyParams)
			answer.SessionParams = strings.TrimSpace(local.SessionParams)
			if answer.SDPValue() == "" {
				continue
			}
			return SDPSecurityInfo{
				RTPProfile: profile,
				Crypto:     []SDPCryptoAttribute{answer},
			}, true
		}
	}
	return SDPSecurityInfo{}, false
}

func SelectSDPSetupAnswer(offerSetup, preferred string) (string, error) {
	offerSetup = strings.ToLower(strings.TrimSpace(offerSetup))
	preferred = strings.ToLower(strings.TrimSpace(preferred))
	if offerSetup == "" {
		offerSetup = "actpass"
	}
	switch offerSetup {
	case "actpass":
		if preferred == "" {
			return "active", nil
		}
		if preferred == "active" || preferred == "passive" {
			return preferred, nil
		}
	case "active":
		if preferred == "" || preferred == "passive" {
			return "passive", nil
		}
	case "passive":
		if preferred == "" || preferred == "active" {
			return "active", nil
		}
	case "holdconn":
		if preferred == "" || preferred == "holdconn" {
			return "holdconn", nil
		}
	default:
		return "", fmt.Errorf("%w: unsupported setup role %q", ErrSDPSecurityNegotiation, offerSetup)
	}
	return "", fmt.Errorf("%w: setup role %q cannot answer offer role %q", ErrSDPSecurityNegotiation, preferred, offerSetup)
}
