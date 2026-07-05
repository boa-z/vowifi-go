package voiceclient

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var ErrInvalidDialogConfig = errors.New("invalid IMS dialog config")

type SIPRequestMessage struct {
	Method  string
	URI     string
	Headers map[string]string
	Body    []byte
}

type SIPIncomingRequest struct {
	Method  string
	URI     string
	Headers map[string][]string
	Body    []byte
}

type DialogRequestConfig struct {
	Profile         IMSProfile
	Registration    RegistrationBinding
	ContactURI      string
	LocalURI        string
	RemoteURI       string
	RemoteTargetURI string
	CallID          string
	LocalTag        string
	RemoteTag       string
	CSeq            int
	RouteSet        []string
	UserAgent       string
	SessionExpires  int
}

func BuildInviteRequest(cfg DialogRequestConfig, sdp []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("INVITE", cfg, sdp)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(sdp) > 0 {
		msg.Headers["Content-Type"] = "application/sdp"
		msg.Headers["Accept"] = "application/sdp"
	}
	msg.Headers["Supported"] = "100rel, timer, replaces, outbound"
	if cfg.SessionExpires > 0 {
		msg.Headers["Session-Expires"] = strconv.Itoa(cfg.SessionExpires)
	}
	return msg, nil
}

func BuildAckRequest(cfg DialogRequestConfig) (SIPRequestMessage, error) {
	return buildDialogRequest("ACK", cfg, nil)
}

func BuildByeRequest(cfg DialogRequestConfig) (SIPRequestMessage, error) {
	return buildDialogRequest("BYE", cfg, nil)
}

func BuildByeRequestWithBody(cfg DialogRequestConfig, contentType string, body []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("BYE", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "application/octet-stream")
	}
	return msg, nil
}

func BuildCancelRequest(cfg DialogRequestConfig) (SIPRequestMessage, error) {
	return buildDialogRequest("CANCEL", cfg, nil)
}

func BuildUpdateRequest(cfg DialogRequestConfig, sdp []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("UPDATE", cfg, sdp)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	msg.Headers["Supported"] = "timer, replaces, outbound"
	if cfg.SessionExpires > 0 {
		msg.Headers["Session-Expires"] = strconv.Itoa(cfg.SessionExpires)
	}
	if len(sdp) > 0 {
		msg.Headers["Content-Type"] = "application/sdp"
		msg.Headers["Accept"] = "application/sdp"
	}
	return msg, nil
}

func BuildPrackRequest(cfg DialogRequestConfig, rack string) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("PRACK", cfg, nil)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if strings.TrimSpace(rack) != "" {
		msg.Headers["RAck"] = strings.TrimSpace(rack)
	}
	return msg, nil
}

func BuildInfoRequest(cfg DialogRequestConfig, contentType string, body []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("INFO", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "application/octet-stream")
	}
	if contactURI := firstNonEmpty(cfg.ContactURI, cfg.Registration.ContactURI); contactURI != "" {
		msg.Headers["Contact"] = "<" + contactURI + ">"
	}
	return msg, nil
}

func BuildMessageRequest(cfg DialogRequestConfig, contentType string, body []byte) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("MESSAGE", cfg, body)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	if len(body) > 0 {
		msg.Headers["Content-Type"] = firstNonEmpty(contentType, "text/plain;charset=UTF-8")
	}
	msg.Headers["Accept"] = "text/plain, application/vnd.3gpp.sms"
	msg.Headers["P-Preferred-Service"] = "urn:urn-7:3gpp-service.ims.icsi.sms"
	msg.Headers["Accept-Contact"] = "*;+g.3gpp.smsip"
	if contactURI := firstNonEmpty(cfg.ContactURI, cfg.Registration.ContactURI); contactURI != "" {
		msg.Headers["Contact"] = "<" + contactURI + ">"
	}
	return msg, nil
}

func BuildOptionsRequest(cfg DialogRequestConfig) (SIPRequestMessage, error) {
	msg, err := buildDialogRequest("OPTIONS", cfg, nil)
	if err != nil {
		return SIPRequestMessage{}, err
	}
	msg.Headers["Accept"] = "application/sdp"
	msg.Headers["Supported"] = "100rel, timer, replaces, outbound"
	return msg, nil
}

func buildDialogRequest(method string, cfg DialogRequestConfig, body []byte) (SIPRequestMessage, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: method is empty", ErrInvalidDialogConfig)
	}
	localURI := firstNonEmpty(cfg.LocalURI, cfg.Registration.PublicIdentity, cfg.Profile.IMPU)
	remoteURI := strings.TrimSpace(cfg.RemoteURI)
	targetURI := firstNonEmpty(cfg.RemoteTargetURI, remoteURI)
	contactURI := firstNonEmpty(cfg.ContactURI, cfg.Registration.ContactURI)
	callID := strings.TrimSpace(cfg.CallID)
	if localURI == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: local URI is empty", ErrInvalidDialogConfig)
	}
	if remoteURI == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: remote URI is empty", ErrInvalidDialogConfig)
	}
	if targetURI == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: request URI is empty", ErrInvalidDialogConfig)
	}
	if contactURI == "" && method == "INVITE" {
		return SIPRequestMessage{}, fmt.Errorf("%w: contact URI is empty", ErrInvalidDialogConfig)
	}
	if callID == "" {
		return SIPRequestMessage{}, fmt.Errorf("%w: Call-ID is empty", ErrInvalidDialogConfig)
	}
	cseq := cfg.CSeq
	if cseq <= 0 {
		cseq = 1
	}
	localTag := firstNonEmpty(cfg.LocalTag, "vowifi-go")
	headers := map[string]string{
		"To":                    formatNameAddr(remoteURI, cfg.RemoteTag),
		"From":                  formatNameAddr(localURI, localTag),
		"Call-ID":               callID,
		"CSeq":                  strconv.Itoa(cseq) + " " + method,
		"Max-Forwards":          "70",
		"User-Agent":            firstNonEmpty(cfg.UserAgent, cfg.Profile.UserAgent, "vowifi-go"),
		"Allow":                 "INVITE, ACK, CANCEL, BYE, PRACK, UPDATE, INFO, MESSAGE, OPTIONS",
		"P-Preferred-Identity":  "<" + localURI + ">",
		"P-Access-Network-Info": "IEEE-802.11",
	}
	if contactURI != "" && (method == "INVITE" || method == "UPDATE" || method == "INFO") {
		headers["Contact"] = "<" + contactURI + ">"
	}
	if route := routeHeader(firstNonEmptySlice(cfg.RouteSet, cfg.Registration.ServiceRoutes)); route != "" {
		headers["Route"] = route
	}
	return SIPRequestMessage{
		Method:  method,
		URI:     targetURI,
		Headers: headers,
		Body:    append([]byte(nil), body...),
	}, nil
}

func routeHeader(routes []string) string {
	clean := trimHeaderValues(routes)
	if len(clean) == 0 {
		return ""
	}
	return strings.Join(clean, ", ")
}

func firstNonEmptySlice(items ...[]string) []string {
	for _, item := range items {
		if len(trimHeaderValues(item)) > 0 {
			return item
		}
	}
	return nil
}

func formatNameAddr(uri, tag string) string {
	out := "<" + strings.TrimSpace(uri) + ">"
	if tag = strings.TrimSpace(tag); tag != "" {
		out += ";tag=" + tag
	}
	return out
}
