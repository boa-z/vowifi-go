package e911

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/boa-z/vowifi-go/runtimehost/voiceclient"
)

var ErrEmergencyRegistrationInvalid = errors.New("invalid emergency registration")

const (
	EmergencyContactURIParamSOS     = "sos"
	EmergencyContactURIParamRegType = "reg-type"
)

type EmergencyRegistrationValidation struct {
	Valid               bool
	Missing             []string
	ContactMarked       bool
	ServiceRoutePresent bool
	ExpiresPresent      bool
}

type EmergencySIPFailure struct {
	StatusCode                 int
	Reason                     string
	RetryAfter                 time.Duration
	Retryable                  bool
	RegistrationRecoveryNeeded bool
	RouteRefreshNeeded         bool
	EntitlementRefreshNeeded   bool
	LocationRefreshNeeded      bool
	AlternativeService         bool
	AlternativeServiceURNs     []string
	ContactURIs                []string
}

func BuildEmergencyRegisterHeaders(profile voiceclient.IMSProfile, contactURI, callID, cseq string) (map[string]string, error) {
	headers := voiceclient.BuildRegisterHeaders(profile, contactURI, callID, cseq)
	contact, err := MarkEmergencyContactHeader(headers["Contact"])
	if err != nil {
		return nil, err
	}
	headers["Contact"] = contact
	return headers, nil
}

func BuildEmergencyInviteRequest(cfg voiceclient.DialogRequestConfig, info EmergencySIPRequestInfo, sdp []byte) (voiceclient.SIPRequestMessage, error) {
	requestURI := strings.TrimSpace(info.RequestURI)
	if requestURI == "" {
		requestURI = DefaultEmergencyServiceURN
	}
	if strings.TrimSpace(cfg.RemoteURI) == "" {
		cfg.RemoteURI = requestURI
	}
	if strings.TrimSpace(cfg.RemoteTargetURI) == "" {
		cfg.RemoteTargetURI = requestURI
	}
	if len(info.RouteSet) > 0 {
		cfg.RouteSet = copyStringSlice(info.RouteSet)
	}
	body := sdp
	contentType := ""
	if len(info.PIDFLOBody) > 0 {
		var err error
		contentType, body, err = BuildEmergencyPIDFLOMultipartBody(sdp, info.PIDFLOBody, EmergencyMultipartRelatedConfig{
			PIDFLOContentID: info.PIDFLOContentID,
		})
		if err != nil {
			return voiceclient.SIPRequestMessage{}, err
		}
	}
	msg, err := voiceclient.BuildInviteRequest(cfg, body)
	if err != nil {
		return voiceclient.SIPRequestMessage{}, err
	}
	msg.URI = requestURI
	for key, value := range info.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		msg.Headers[key] = value
	}
	if contentType != "" {
		msg.Headers["Content-Type"] = contentType
		if emergencyStringHeaderValue(msg.Headers, "Geolocation") == "" {
			if contentID := emergencyContentIDForHeader(info.PIDFLOContentID, defaultEmergencyPIDFLOContentID); contentID != "" {
				msg.Headers["Geolocation"] = formatGeolocationURI("cid:" + contentID)
			}
		}
	}
	if len(info.RouteSet) > 0 {
		msg.Headers["Route"] = strings.Join(info.RouteSet, ", ")
	}
	if contact := strings.TrimSpace(msg.Headers["Contact"]); contact != "" {
		marked, err := MarkEmergencyContactHeader(contact)
		if err != nil {
			return voiceclient.SIPRequestMessage{}, err
		}
		msg.Headers["Contact"] = marked
	}
	return msg, nil
}

func emergencyStringHeaderValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func MarkEmergencyContactHeader(contact string) (string, error) {
	contact = strings.TrimSpace(contact)
	if contact == "" {
		return "", errors.New("emergency contact is empty")
	}
	if strings.HasPrefix(contact, "<") {
		end := strings.Index(contact, ">")
		if end < 0 {
			return "", errors.New("invalid emergency contact: missing closing angle")
		}
		uri, err := MarkEmergencyContactURI(contact[1:end])
		if err != nil {
			return "", err
		}
		return "<" + uri + ">" + strings.TrimSpace(contact[end+1:]), nil
	}
	uri, err := MarkEmergencyContactURI(contact)
	if err != nil {
		return "", err
	}
	return "<" + uri + ">", nil
}

func MarkEmergencyContactURI(uri string) (string, error) {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return "", errors.New("emergency contact URI is empty")
	}
	lower := strings.ToLower(uri)
	if !strings.HasPrefix(lower, "sip:") && !strings.HasPrefix(lower, "sips:") {
		return "", fmt.Errorf("emergency contact URI must be sip or sips: %q", uri)
	}
	if emergencyContactURIHasMarker(uri) {
		return uri, nil
	}
	base, query, hasQuery := strings.Cut(uri, "?")
	uri = base + ";" + EmergencyContactURIParamSOS
	if hasQuery {
		uri += "?" + query
	}
	return uri, nil
}

func EmergencyRegistrationBindingValidation(binding voiceclient.RegistrationBinding) EmergencyRegistrationValidation {
	validation := EmergencyRegistrationValidation{}
	contact := firstNonEmpty(binding.RegistrarContact, binding.ContactURI)
	validation.ContactMarked = emergencyContactHasMarker(contact)
	validation.ServiceRoutePresent = len(trimEmergencyStrings(binding.ServiceRoutes)) > 0
	validation.ExpiresPresent = binding.Expires > 0
	if !validation.ContactMarked {
		validation.Missing = append(validation.Missing, "emergency contact marker")
	}
	if !validation.ServiceRoutePresent {
		validation.Missing = append(validation.Missing, "Service-Route")
	}
	if !validation.ExpiresPresent {
		validation.Missing = append(validation.Missing, "positive expiry")
	}
	validation.Valid = len(validation.Missing) == 0
	return validation
}

func ValidateEmergencyRegistrationBinding(binding voiceclient.RegistrationBinding) error {
	validation := EmergencyRegistrationBindingValidation(binding)
	if validation.Valid {
		return nil
	}
	return fmt.Errorf("%w: missing %s", ErrEmergencyRegistrationInvalid, strings.Join(validation.Missing, ", "))
}

func ClassifyEmergencySIPFailure(resp voiceclient.SIPResponse) EmergencySIPFailure {
	failure := EmergencySIPFailure{
		StatusCode:  resp.StatusCode,
		Reason:      strings.TrimSpace(resp.Reason),
		RetryAfter:  voiceclient.SIPResponseRetryAfter(resp),
		ContactURIs: emergencyContactURIsFromHeaders(resp.Headers),
	}
	for _, uri := range failure.ContactURIs {
		if urn := NormalizeEmergencyServiceURN(uri); urn != "" {
			failure.AlternativeServiceURNs = appendUniqueStrings(failure.AlternativeServiceURNs, urn)
		}
	}
	if resp.StatusCode < 300 || resp.StatusCode >= 700 {
		return failure
	}
	switch resp.StatusCode {
	case 380:
		failure.Retryable = true
		failure.RouteRefreshNeeded = true
		failure.AlternativeService = len(failure.AlternativeServiceURNs) > 0 || len(failure.ContactURIs) > 0
	case 401, 407, 481:
		failure.Retryable = true
		failure.RegistrationRecoveryNeeded = true
	case 408, 430, 480, 500, 502, 503, 504, 580:
		failure.Retryable = true
		failure.RegistrationRecoveryNeeded = true
		failure.RouteRefreshNeeded = true
	case 424:
		failure.Retryable = true
		failure.LocationRefreshNeeded = true
		failure.EntitlementRefreshNeeded = true
	default:
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			failure.Retryable = true
			failure.RegistrationRecoveryNeeded = true
			failure.RouteRefreshNeeded = true
		}
	}
	if emergencyResponseMentionsLocation(resp) {
		failure.Retryable = true
		failure.LocationRefreshNeeded = true
		failure.EntitlementRefreshNeeded = true
	}
	return failure
}

func emergencyContactHasMarker(contact string) bool {
	contact = strings.TrimSpace(contact)
	if contact == "" {
		return false
	}
	if strings.HasPrefix(contact, "<") {
		end := strings.Index(contact, ">")
		if end < 0 {
			return false
		}
		return emergencyContactURIHasMarker(contact[1:end])
	}
	return emergencyContactURIHasMarker(contact)
}

func emergencyContactURIHasMarker(uri string) bool {
	base, _, _ := strings.Cut(strings.TrimSpace(uri), "?")
	semi := strings.Index(base, ";")
	if semi < 0 {
		return false
	}
	for _, param := range strings.Split(base[semi+1:], ";") {
		key, value, _ := strings.Cut(param, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.ToLower(strings.Trim(strings.TrimSpace(value), `"`))
		if key == EmergencyContactURIParamSOS {
			return true
		}
		if key == EmergencyContactURIParamRegType && value == EmergencyContactURIParamSOS {
			return true
		}
	}
	return false
}

func trimEmergencyStrings(in []string) []string {
	var out []string
	for _, value := range in {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func emergencyContactURIsFromHeaders(headers map[string][]string) []string {
	var out []string
	for _, value := range emergencyHeaderValues(headers, "Contact") {
		uri := emergencyHeaderURI(value)
		if uri != "" {
			out = appendUniqueStrings(out, uri)
		}
	}
	return out
}

func emergencyHeaderValues(headers map[string][]string, name string) []string {
	var out []string
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, value := range values {
			parts, err := splitSIPHeaderSegments(value, ',')
			if err != nil {
				parts = []string{value}
			}
			for _, part := range parts {
				if part = strings.TrimSpace(part); part != "" {
					out = append(out, part)
				}
			}
		}
	}
	return out
}

func emergencyHeaderURI(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "<") {
		end := strings.Index(value, ">")
		if end < 0 {
			return ""
		}
		return strings.TrimSpace(value[1:end])
	}
	if uri, _, ok := strings.Cut(value, ";"); ok {
		return strings.TrimSpace(uri)
	}
	return value
}

func emergencyResponseMentionsLocation(resp voiceclient.SIPResponse) bool {
	var text []string
	text = append(text, resp.Reason)
	for _, name := range []string{"Warning", "Reason", "Error-Info"} {
		text = append(text, emergencyHeaderValues(resp.Headers, name)...)
	}
	joined := strings.ToLower(strings.Join(text, " "))
	for _, marker := range []string{"bad location", "geolocation", "pidf", "e911", "emergency address", "location information"} {
		if strings.Contains(joined, marker) {
			return true
		}
	}
	return false
}
