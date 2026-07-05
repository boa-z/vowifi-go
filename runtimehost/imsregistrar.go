package runtimehost

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/iniwex5/vowifi-go/runtimehost/identity"
	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

type IMSRegisterTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, string, string) voiceclient.SIPRegisterTransport
type IMSVoiceTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, voiceclient.RegistrationBinding) voiceclient.SIPRequestTransport
type IMSSMSTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, voiceclient.RegistrationBinding, voiceclient.SIPRequestTransport) messaging.SMSTransport
type IMSUSSDTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, voiceclient.RegistrationBinding, voiceclient.SIPRequestTransport) messaging.USSDTransport

type WireIMSRegistrar struct {
	Transport             voiceclient.SIPRegisterTransport
	TransportFactory      IMSRegisterTransportFactory
	VoiceTransport        voiceclient.SIPRequestTransport
	VoiceFactory          IMSVoiceTransportFactory
	SMSTransport          messaging.SMSTransport
	SMSFactory            IMSSMSTransportFactory
	USSDTransport         messaging.USSDTransport
	USSDFactory           IMSUSSDTransportFactory
	RegistrarURI          string
	ContactURI            string
	ContactHost           string
	ContactPort           int
	Network               string
	ServerAddr            string
	LocalAddr             string
	Timeout               time.Duration
	Expires               int
	UserAgent             string
	CallID                string
	CNonce                string
	RetransmitInterval    time.Duration
	MaxRetransmitInterval time.Duration
	MaxRetransmits        int
}

func (r WireIMSRegistrar) RegisterIMS(ctx context.Context, cfg IMSRegistrationConfig) (IMSRegistrationResult, error) {
	profile, err := r.profileFromConfig(cfg)
	if err != nil {
		return IMSRegistrationResult{}, err
	}
	registrarURI := firstRuntimeNonEmpty(r.RegistrarURI, registrarURIForProfile(profile))
	if registrarURI == "" {
		return IMSRegistrationResult{}, errors.New("IMS registrar URI is empty")
	}
	contactURI := firstRuntimeNonEmpty(r.ContactURI, r.contactURIForProfile(profile))
	if contactURI == "" {
		return IMSRegistrationResult{}, errors.New("IMS contact URI is empty")
	}
	transport := r.Transport
	if transport == nil && r.TransportFactory != nil {
		transport = r.TransportFactory(cfg, profile, registrarURI, contactURI)
	}
	if transport == nil {
		transport = voiceclient.WireRegisterTransport{
			Network:               r.Network,
			ServerAddr:            r.ServerAddr,
			LocalAddr:             r.LocalAddr,
			Timeout:               r.Timeout,
			RetransmitInterval:    r.RetransmitInterval,
			MaxRetransmitInterval: r.MaxRetransmitInterval,
			MaxRetransmits:        r.MaxRetransmits,
		}
	}
	expires := r.Expires
	if expires <= 0 {
		expires = 3600
	}
	result, err := voiceclient.RegisterSession{
		Transport:    transport,
		AKAProvider:  cfg.SIM,
		Profile:      profile,
		RegistrarURI: registrarURI,
		ContactURI:   contactURI,
		CallID:       firstRuntimeNonEmpty(r.CallID, cfg.TraceID, cfg.DeviceID+"-ims-register"),
		CNonce:       firstRuntimeNonEmpty(r.CNonce, cfg.TraceID, cfg.DeviceID),
		Expires:      expires,
	}.Register(ctx)
	if err != nil {
		return IMSRegistrationResult{
			Registered: result.Registered,
			StatusCode: result.StatusCode,
			Reason:     result.Reason,
			Server:     result.Binding.PublicIdentity,
			Profile:    profile,
			Binding:    result.Binding,
		}, err
	}
	voiceTransport := r.voiceTransport(cfg, profile, result.Binding)
	smsTransport := r.smsTransport(cfg, profile, result.Binding, voiceTransport)
	ussdTransport := r.ussdTransport(cfg, profile, result.Binding, voiceTransport)
	return IMSRegistrationResult{
		Registered:     result.Registered,
		StatusCode:     result.StatusCode,
		Reason:         firstRuntimeNonEmpty(result.Reason, "ims registered"),
		Server:         firstRuntimeNonEmpty(result.Binding.PublicIdentity, profile.Domain),
		Profile:        profile,
		Binding:        result.Binding,
		VoiceTransport: voiceTransport,
		SMSTransport:   smsTransport,
		USSDTransport:  ussdTransport,
	}, nil
}

func (r WireIMSRegistrar) voiceTransport(cfg IMSRegistrationConfig, profile voiceclient.IMSProfile, binding voiceclient.RegistrationBinding) voiceclient.SIPRequestTransport {
	if r.VoiceTransport != nil {
		return r.VoiceTransport
	}
	if r.VoiceFactory != nil {
		return r.VoiceFactory(cfg, profile, binding)
	}
	return voiceclient.WireSIPTransport{
		Network:               r.Network,
		ServerAddr:            r.ServerAddr,
		LocalAddr:             r.LocalAddr,
		Timeout:               r.Timeout,
		RetransmitInterval:    r.RetransmitInterval,
		MaxRetransmitInterval: r.MaxRetransmitInterval,
		MaxRetransmits:        r.MaxRetransmits,
	}
}

func (r WireIMSRegistrar) smsTransport(cfg IMSRegistrationConfig, profile voiceclient.IMSProfile, binding voiceclient.RegistrationBinding, voiceTransport voiceclient.SIPRequestTransport) messaging.SMSTransport {
	if r.SMSTransport != nil {
		return r.SMSTransport
	}
	if r.SMSFactory != nil {
		return r.SMSFactory(cfg, profile, binding, voiceTransport)
	}
	if voiceTransport == nil {
		return nil
	}
	return messaging.IMSSMSTransport{
		Transport:    voiceTransport,
		Profile:      profile,
		Registration: binding,
		Domain:       profile.Domain,
		UserAgent:    firstRuntimeNonEmpty(r.UserAgent, profile.UserAgent),
	}
}

func (r WireIMSRegistrar) ussdTransport(cfg IMSRegistrationConfig, profile voiceclient.IMSProfile, binding voiceclient.RegistrationBinding, voiceTransport voiceclient.SIPRequestTransport) messaging.USSDTransport {
	if r.USSDTransport != nil {
		return r.USSDTransport
	}
	if r.USSDFactory != nil {
		return r.USSDFactory(cfg, profile, binding, voiceTransport)
	}
	if voiceTransport == nil {
		return nil
	}
	return &messaging.IMSUSSDTransport{
		Transport:    voiceTransport,
		Profile:      profile,
		Registration: binding,
		Domain:       profile.Domain,
		UserAgent:    firstRuntimeNonEmpty(r.UserAgent, profile.UserAgent),
	}
}

func (r WireIMSRegistrar) profileFromConfig(cfg IMSRegistrationConfig) (voiceclient.IMSProfile, error) {
	preparedIdentity := identity.IMSIdentityResolution{}
	if cfg.Prepared != nil {
		preparedIdentity = cfg.Prepared.IMSIdentity
	}
	imsi := strings.TrimSpace(cfg.Profile.IMSI)
	if imsi == "" && cfg.Prepared != nil {
		imsi = strings.TrimSpace(cfg.Prepared.Profile.IMSI)
	}
	domain := firstRuntimeNonEmpty(preparedIdentity.Domain, defaultIMSRealm(cfg))
	impi := firstRuntimeNonEmpty(preparedIdentity.IMPI, defaultIMPI(imsi, domain))
	impu := firstRuntimeNonEmpty(preparedIdentity.IMPU, defaultIMPU(impi, domain))
	if impi == "" {
		return voiceclient.IMSProfile{}, errors.New("IMS private identity is empty")
	}
	if impu == "" {
		return voiceclient.IMSProfile{}, errors.New("IMS public identity is empty")
	}
	return voiceclient.IMSProfile{
		IMPI:      impi,
		IMPU:      impu,
		Domain:    domain,
		LocalIP:   strings.TrimSpace(r.ContactHost),
		UserAgent: firstRuntimeNonEmpty(r.UserAgent, "vowifi-go"),
	}, nil
}

func (r WireIMSRegistrar) contactURIForProfile(profile voiceclient.IMSProfile) string {
	host := strings.TrimSpace(r.ContactHost)
	if host == "" {
		host = strings.TrimSpace(profile.LocalIP)
	}
	if host == "" {
		return ""
	}
	port := r.ContactPort
	if port <= 0 {
		port = 5060
	}
	user := sipUser(profile.IMPU)
	if user == "" {
		user = strings.TrimSpace(profile.IMPI)
	}
	if user == "" {
		user = "ue"
	}
	return "sip:" + user + "@" + formatSIPHost(host) + ":" + strconv.Itoa(port)
}

func registrarURIForProfile(profile voiceclient.IMSProfile) string {
	if strings.TrimSpace(profile.Domain) == "" {
		return ""
	}
	return "sip:" + strings.TrimSpace(profile.Domain)
}

func defaultIMSRealm(cfg IMSRegistrationConfig) string {
	mcc, mnc := cfgMCCMNC(cfg)
	if mcc == "" || mnc == "" {
		return ""
	}
	return fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", leftPadRuntime(mnc, 3), mcc)
}

func cfgMCCMNC(cfg IMSRegistrationConfig) (string, string) {
	mcc := strings.TrimSpace(cfg.Profile.MCC)
	mnc := strings.TrimSpace(cfg.Profile.MNC)
	if cfg.Prepared != nil {
		if mcc == "" {
			mcc = strings.TrimSpace(cfg.Prepared.Profile.MCC)
		}
		if mnc == "" {
			mnc = strings.TrimSpace(cfg.Prepared.Profile.MNC)
		}
	}
	if mcc == "" && len(strings.TrimSpace(cfg.Profile.IMSI)) >= 3 {
		mcc = strings.TrimSpace(cfg.Profile.IMSI)[:3]
	}
	if mnc == "" && len(strings.TrimSpace(cfg.Profile.IMSI)) >= 6 {
		mnc = strings.TrimSpace(cfg.Profile.IMSI)[3:6]
	}
	trimmedMNC := strings.TrimLeft(mnc, "0")
	if trimmedMNC == "" && mnc != "" {
		trimmedMNC = mnc
	}
	return mcc, trimmedMNC
}

func defaultIMPI(imsi, domain string) string {
	imsi = strings.TrimSpace(imsi)
	domain = strings.TrimSpace(domain)
	if imsi == "" {
		return ""
	}
	if domain == "" || strings.Contains(imsi, "@") {
		return imsi
	}
	return imsi + "@" + domain
}

func defaultIMPU(impi, domain string) string {
	impi = strings.TrimSpace(impi)
	domain = strings.TrimSpace(domain)
	if impi == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(impi), "sip:") || strings.HasPrefix(strings.ToLower(impi), "tel:") {
		return impi
	}
	if strings.Contains(impi, "@") {
		return "sip:" + impi
	}
	if domain != "" {
		return "sip:" + impi + "@" + domain
	}
	return "sip:" + impi
}

func sipUser(uri string) string {
	uri = strings.TrimSpace(uri)
	if strings.HasPrefix(strings.ToLower(uri), "sip:") {
		uri = uri[4:]
	}
	if user, _, ok := strings.Cut(uri, "@"); ok {
		return strings.TrimSpace(user)
	}
	return strings.TrimSpace(uri)
}

func leftPadRuntime(s string, n int) string {
	for len(s) < n {
		s = "0" + s
	}
	return s
}

func formatSIPHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}
