package tracefixture

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

const TranscriptSchemaVersion = "vowifi-go.tracefixture.transcript.v1"

const TranscriptJSONSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://vowifi-go.invalid/schemas/tracefixture-transcript-v1.json",
  "title": "vowifi-go tracefixture transcript",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "name", "events"],
  "properties": {
    "schema": {
      "const": "vowifi-go.tracefixture.transcript.v1"
    },
    "name": {
      "type": "string",
      "minLength": 1
    },
    "events": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["direction", "transport", "wire"],
        "properties": {
          "label": {
            "type": "string"
          },
          "direction": {
            "type": "string",
            "enum": ["inbound", "outbound"]
          },
          "transport": {
            "type": "string",
            "enum": ["udp", "udp4", "udp6", "tcp", "tcp4", "tcp6"]
          },
          "wire": {
            "type": "string",
            "minLength": 1
          }
        }
      }
    }
  }
}`

var (
	ErrInvalidTranscript = errors.New("invalid trace transcript")
	ErrSensitiveFixture  = errors.New("trace fixture contains unredacted sensitive data")
)

type Transcript struct {
	Schema string            `json:"schema"`
	Name   string            `json:"name"`
	Events []TranscriptEvent `json:"events"`
}

type TranscriptEvent struct {
	Label     string `json:"label,omitempty"`
	Direction string `json:"direction"`
	Transport string `json:"transport"`
	Wire      string `json:"wire"`
}

type RedactionViolation struct {
	Path string
	Kind string
}

type RedactionError struct {
	Violations []RedactionViolation
}

func (e *RedactionError) Error() string {
	if e == nil || len(e.Violations) == 0 {
		return ErrSensitiveFixture.Error()
	}
	first := e.Violations[0]
	if len(e.Violations) == 1 {
		return fmt.Sprintf("%s: %s at %s", ErrSensitiveFixture, first.Kind, first.Path)
	}
	return fmt.Sprintf("%s: %d violations, first %s at %s", ErrSensitiveFixture, len(e.Violations), first.Kind, first.Path)
}

func (e *RedactionError) Unwrap() error {
	return ErrSensitiveFixture
}

func ParseTranscriptJSON(raw []byte) (Transcript, error) {
	transcript, err := decodeTranscriptJSON(json.NewDecoder(bytes.NewReader(raw)))
	if err != nil {
		return Transcript{}, err
	}
	if err := ValidateTranscript(transcript); err != nil {
		return Transcript{}, err
	}
	return transcript, nil
}

func DecodeTranscriptJSON(r io.Reader) (Transcript, error) {
	if r == nil {
		return Transcript{}, fmt.Errorf("%w: nil reader", ErrInvalidTranscript)
	}
	transcript, err := decodeTranscriptJSON(json.NewDecoder(r))
	if err != nil {
		return Transcript{}, err
	}
	if err := ValidateTranscript(transcript); err != nil {
		return Transcript{}, err
	}
	return transcript, nil
}

func ParseAndRedactTranscriptJSON(raw []byte) (Transcript, error) {
	transcript, err := decodeTranscriptJSON(json.NewDecoder(bytes.NewReader(raw)))
	if err != nil {
		return Transcript{}, err
	}
	return RedactTranscript(transcript)
}

func DecodeAndRedactTranscriptJSON(r io.Reader) (Transcript, error) {
	if r == nil {
		return Transcript{}, fmt.Errorf("%w: nil reader", ErrInvalidTranscript)
	}
	transcript, err := decodeTranscriptJSON(json.NewDecoder(r))
	if err != nil {
		return Transcript{}, err
	}
	return RedactTranscript(transcript)
}

func decodeTranscriptJSON(dec *json.Decoder) (Transcript, error) {
	dec.DisallowUnknownFields()
	var transcript Transcript
	if err := dec.Decode(&transcript); err != nil {
		return Transcript{}, fmt.Errorf("%w: %v", ErrInvalidTranscript, err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return Transcript{}, fmt.Errorf("%w: %v", ErrInvalidTranscript, err)
		}
		return Transcript{}, fmt.Errorf("%w: trailing JSON value", ErrInvalidTranscript)
	}
	if err := ValidateTranscriptStructure(transcript); err != nil {
		return Transcript{}, err
	}
	return transcript, nil
}

func ValidateTranscript(transcript Transcript) error {
	if err := ValidateTranscriptStructure(transcript); err != nil {
		return err
	}
	return ValidateTranscriptRedaction(transcript)
}

func ValidateTranscriptStructure(transcript Transcript) error {
	if transcript.Schema != TranscriptSchemaVersion {
		return fmt.Errorf("%w: schema must be %q", ErrInvalidTranscript, TranscriptSchemaVersion)
	}
	if strings.TrimSpace(transcript.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidTranscript)
	}
	if len(transcript.Events) == 0 {
		return fmt.Errorf("%w: at least one event is required", ErrInvalidTranscript)
	}
	for i, event := range transcript.Events {
		if !validTranscriptDirection(event.Direction) {
			return fmt.Errorf("%w: events[%d].direction must be inbound or outbound", ErrInvalidTranscript, i)
		}
		if !validTranscriptTransport(event.Transport) {
			return fmt.Errorf("%w: events[%d].transport is unsupported", ErrInvalidTranscript, i)
		}
		if strings.TrimSpace(event.Wire) == "" {
			return fmt.Errorf("%w: events[%d].wire is required", ErrInvalidTranscript, i)
		}
	}
	return nil
}

func RedactTranscript(transcript Transcript) (Transcript, error) {
	if err := ValidateTranscriptStructure(transcript); err != nil {
		return Transcript{}, err
	}
	redactor := NewRedactor()
	out := Transcript{
		Schema: transcript.Schema,
		Name:   redactor.RedactString(transcript.Name),
		Events: make([]TranscriptEvent, len(transcript.Events)),
	}
	for i, event := range transcript.Events {
		out.Events[i] = TranscriptEvent{
			Label:     redactor.RedactString(event.Label),
			Direction: event.Direction,
			Transport: event.Transport,
			Wire:      redactor.RedactString(event.Wire),
		}
	}
	if err := ValidateTranscript(out); err != nil {
		return Transcript{}, err
	}
	return out, nil
}

func ValidateTranscriptRedaction(transcript Transcript) error {
	validator := redactionValidator{}
	validator.scanString("name", transcript.Name)
	for i, event := range transcript.Events {
		prefix := fmt.Sprintf("events[%d]", i)
		validator.scanString(prefix+".label", event.Label)
		validator.scanString(prefix+".wire", event.Wire)
	}
	return validator.err()
}

func validTranscriptDirection(direction string) bool {
	switch direction {
	case "inbound", "outbound":
		return true
	default:
		return false
	}
}

func validTranscriptTransport(transport string) bool {
	switch transport {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

const maxRedactionViolations = 16

var (
	transcriptHeaderLineRE = regexp.MustCompile(`(?im)^([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.*)$`)
	authOrAKAParamRE       = regexp.MustCompile(`(?i)\b(nonce|cnonce|response|auts|res|rand|autn|ck|ik)\s*=\s*("[^"]*"|[^,;\s]+)`)
	labelledSubscriberIDRE = regexp.MustCompile(`(?i)\b(?:imsi|imei|imeisv)\b[^0-9<]*(?:[0-9][0-9 .-]{12,}[0-9])`)
	ipv6CandidateRE        = regexp.MustCompile(`(?i)(?:\[[0-9a-f:.%]+\]|[0-9a-f]{0,4}:[0-9a-f:.%]*:[0-9a-f:.%]*)`)
)

type redactionValidator struct {
	violations []RedactionViolation
	seen       map[string]bool
}

func (v *redactionValidator) scanString(path, value string) {
	if value == "" {
		return
	}
	v.scanSensitiveHeaders(path, value)
	v.scanAuthAndAKAParams(path, value)
	v.scanSIPURIUserIdentifiers(path, value)
	if labelledSubscriberIDRE.MatchString(value) || longDigitRE.MatchString(value) {
		v.add(path, "subscriber identifier")
	}
	if telURIRE.MatchString(value) || e164RE.MatchString(value) {
		v.add(path, "msisdn")
	}
	if longHexRE.MatchString(value) {
		v.add(path, "auth/aka material")
	}
	v.scanIPv4(path, value)
	v.scanIPv6(path, value)
}

func (v *redactionValidator) scanSensitiveHeaders(path, value string) {
	for _, match := range transcriptHeaderLineRE.FindAllStringSubmatch(value, -1) {
		if len(match) != 3 {
			continue
		}
		kind, ok := sensitiveHeaderKind(match[1])
		if !ok || isRedactedLiteral(match[2]) {
			continue
		}
		v.add(path, kind)
	}
}

func (v *redactionValidator) scanAuthAndAKAParams(path, value string) {
	for _, match := range authOrAKAParamRE.FindAllStringSubmatch(value, -1) {
		if len(match) != 3 || isRedactedLiteral(match[2]) {
			continue
		}
		if isAKAParam(match[1]) {
			v.add(path, "aka material")
			continue
		}
		v.add(path, "auth material")
	}
}

func (v *redactionValidator) scanSIPURIUserIdentifiers(path, value string) {
	for _, match := range sipURIRE.FindAllStringSubmatch(value, -1) {
		if len(match) != 3 {
			continue
		}
		if kind, ok := sensitiveSIPURIUserKind(match[1]); ok {
			v.add(path, kind)
		}
	}
}

func (v *redactionValidator) scanIPv4(path, value string) {
	for _, candidate := range ipv4RE.FindAllString(value, -1) {
		ip := net.ParseIP(candidate)
		if ip != nil && ip.To4() != nil {
			v.add(path, "ip address")
			return
		}
	}
}

func (v *redactionValidator) scanIPv6(path, value string) {
	for _, candidate := range ipv6CandidateRE.FindAllString(value, -1) {
		candidate = normalizeIPCandidate(candidate)
		if !strings.Contains(candidate, ":") {
			continue
		}
		if zone := strings.IndexByte(candidate, '%'); zone >= 0 {
			candidate = candidate[:zone]
		}
		addr, err := netip.ParseAddr(candidate)
		if err == nil && addr.Is6() {
			v.add(path, "ip address")
			return
		}
	}
}

func (v *redactionValidator) add(path, kind string) {
	if len(v.violations) >= maxRedactionViolations {
		return
	}
	if v.seen == nil {
		v.seen = make(map[string]bool)
	}
	key := path + "\x00" + kind
	if v.seen[key] {
		return
	}
	v.seen[key] = true
	v.violations = append(v.violations, RedactionViolation{
		Path: path,
		Kind: kind,
	})
}

func (v *redactionValidator) err() error {
	if len(v.violations) == 0 {
		return nil
	}
	out := make([]RedactionViolation, len(v.violations))
	copy(out, v.violations)
	return &RedactionError{Violations: out}
}

func sensitiveSIPURIUserKind(user string) (string, bool) {
	user = strings.TrimSpace(user)
	user = strings.Trim(user, `"'<>`)
	if user == "" || isRedactedLiteral(user) {
		return "", false
	}

	digitCount := 0
	phoneShaped := true
	for i, r := range user {
		switch {
		case r >= '0' && r <= '9':
			digitCount++
		case r == '+' && i == 0:
		case r == '.' || r == '-' || r == ' ' || r == '(' || r == ')':
		default:
			phoneShaped = false
		}
	}
	if phoneShaped && digitCount >= 10 && digitCount <= 16 {
		return "sip uri user identity", true
	}

	lower := strings.ToLower(user)
	for _, marker := range []string{"imsi", "imei", "imeisv", "msisdn", "tel"} {
		if strings.Contains(lower, marker) && digitCount >= 7 {
			return "sip uri user identity", true
		}
	}
	return "", false
}

func sensitiveHeaderKind(name string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization", "www-authenticate", "proxy-authenticate",
		"authentication-info", "proxy-authentication-info":
		return "auth material", true
	case "security-client", "security-server", "security-verify":
		return "security/auth material", true
	case "x-aka", "aka":
		return "aka material", true
	default:
		return "", false
	}
}

func isAKAParam(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "auts", "res", "rand", "autn", "ck", "ik":
		return true
	default:
		return false
	}
}

func isRedactedLiteral(value string) bool {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	value = strings.TrimSpace(value)
	return strings.HasPrefix(strings.ToLower(value), "<redacted") && strings.HasSuffix(value, ">")
}

func normalizeIPCandidate(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	candidate = strings.Trim(candidate, `"'<>(),;`)
	if strings.HasPrefix(candidate, "[") {
		if end := strings.IndexByte(candidate, ']'); end >= 0 {
			return candidate[1:end]
		}
	}
	return candidate
}
