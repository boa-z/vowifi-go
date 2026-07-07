package runtimehost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	swusim "github.com/boa-z/vowifi-go/engine/sim"
	"github.com/boa-z/vowifi-go/engine/swu"
	"github.com/boa-z/vowifi-go/runtimehost/eventhost"
	"github.com/boa-z/vowifi-go/runtimehost/identity"
	"github.com/boa-z/vowifi-go/runtimehost/messaging"
	"github.com/boa-z/vowifi-go/runtimehost/simtransport"
	"github.com/boa-z/vowifi-go/runtimehost/voiceclient"
	"github.com/boa-z/vowifi-go/runtimehost/voicehost"
)

var ErrAPDUBusy = errors.New("apdu busy")

type ctxKey string

const traceIDKey ctxKey = "trace_id"

func NewTraceID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("trace-%d", time.Now().UnixNano())
	}
	return "trace-" + hex.EncodeToString(b[:])
}

func WithTraceID(ctx context.Context, traceID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, traceIDKey, strings.TrimSpace(traceID))
}

func SetLogger(any) {}

type Phase string

const (
	PhaseStarting Phase = "starting"
	PhaseSIMReady Phase = "sim_ready"
	PhaseReady    Phase = "ready"
	PhaseStopped  Phase = "stopped"
	PhaseError    Phase = "error"
)

type State struct {
	DeviceID                 string
	Phase                    Phase
	DataplaneMode            string
	SIMReady                 bool
	AccessReady              bool
	TunnelReady              bool
	IMSReady                 bool
	SMSReady                 bool
	RegStatus                int
	RegStatusText            string
	NetworkMode              string
	LastErrorClass           string
	LastError                string
	LastReason               string
	IMSRecoveryPending       bool
	IMSRecoveryRetryAfter    time.Duration
	IMSRecoveryNextAttemptAt time.Time
	IMSRecoveryReason        string
	UpdatedAt                time.Time
}

type Event struct {
	State State
}

type Observer interface {
	OnRuntimeEvent(context.Context, Event)
}

type ObserverFunc func(context.Context, Event)

func (f ObserverFunc) OnRuntimeEvent(ctx context.Context, ev Event) {
	if f != nil {
		f(ctx, ev)
	}
}

type Modem interface {
	DeviceID() string
	IsHealthy() bool
	IsSimInserted() bool
	QuerySIMInserted() (bool, error)
	GetRegStatus() (int, string)
	GetNetworkMode() string
	Stop()
}

type APDUAccess interface {
	ExecuteATSilent(cmd string, timeout time.Duration) (string, error)
	OpenLogicalChannel(aid string) (int, error)
	CloseLogicalChannel(channel int) error
	TransmitAPDU(channel int, hexAPDU string) (string, error)
}

type IdentityReader interface {
	GetISIMIdentity() (identity.Identity, error)
}

type CRSMAccess interface {
	ReadCRSMBinary(fileID uint16, offset, length int, pathID string) (simtransport.CRSMResult, error)
	ReadCRSMRecord(fileID uint16, record, length int, pathID string) (simtransport.CRSMResult, error)
}

const (
	SIMAccessRecoveryOperationISIMIdentity = "isim_identity"
	SIMAccessRecoveryOperationIMEI         = "imei"
)

type SIMAccessRecoveryRequest struct {
	Operation          string
	Attempt            int
	Class              simtransport.RecoveryClass
	Err                error
	DestructiveAllowed bool
}

type SIMAccessRecoveryHook interface {
	RecoverSIMAccess(req SIMAccessRecoveryRequest) error
}

type SIMAccessRecoveryOptions struct {
	AllowVendorSpecific bool
	DryRun              bool
	Delay               simtransport.ATRecoveryDelayFunc
}

type ModemAccess interface {
	GetISIMIdentity() (identity.Identity, error)
	RuntimeModem() Modem
}

type modemAccessAdapter struct {
	modem    Modem
	recovery SIMAccessRecoveryOptions
}

func NewModemAccessAdapter(m Modem) ModemAccess {
	return NewModemAccessAdapterWithRecovery(m, SIMAccessRecoveryOptions{})
}

func NewModemAccessAdapterWithRecovery(m Modem, recovery SIMAccessRecoveryOptions) ModemAccess {
	if m == nil {
		return nil
	}
	return &modemAccessAdapter{modem: m, recovery: recovery}
}

func (a *modemAccessAdapter) RuntimeModem() Modem {
	if a == nil {
		return nil
	}
	return a.modem
}

func (a *modemAccessAdapter) GetIMEI() (string, error) {
	imei, err := a.getIMEIOnce()
	if err == nil {
		return imei, nil
	}
	req, ok := newSIMAccessRecoveryRequest(SIMAccessRecoveryOperationIMEI, 1, err)
	if !ok {
		return "", err
	}
	recovered, recoveryErr := a.recoverSIMAccess(req)
	if !recovered {
		return "", err
	}
	if recoveryErr != nil {
		return "", errors.Join(err, fmt.Errorf("SIM access recovery: %w", recoveryErr))
	}
	imei, retryErr := a.getIMEIOnce()
	if retryErr == nil {
		return imei, nil
	}
	return "", errors.Join(err, fmt.Errorf("SIM access recovery retry: %w", retryErr))
}

func (a *modemAccessAdapter) getIMEIOnce() (string, error) {
	if a == nil || a.modem == nil {
		return "", errors.New("modem is nil")
	}
	if r, ok := a.modem.(interface{ GetIMEI() (string, error) }); ok {
		imei, err := r.GetIMEI()
		if err != nil {
			return "", err
		}
		if imei = identity.ExtractIMEI(imei); imei != "" {
			return imei, nil
		}
		return "", errors.New("modem IMEI is empty or invalid")
	}
	if at, ok := a.modem.(interface {
		ExecuteATSilent(cmd string, timeout time.Duration) (string, error)
	}); ok {
		return simtransport.NewAdapter(at).ReadIMEI()
	}
	return "", errors.New("modem does not expose IMEI")
}

func (a *modemAccessAdapter) GetISIMIdentity() (identity.Identity, error) {
	if a == nil || a.modem == nil {
		return identity.Identity{}, errors.New("modem is nil")
	}
	id, err := a.getISIMIdentityOnce()
	if err == nil {
		return id, nil
	}
	req, ok := newSIMAccessRecoveryRequest(SIMAccessRecoveryOperationISIMIdentity, 1, err)
	if !ok {
		return identity.Identity{}, err
	}
	recovered, recoveryErr := a.recoverSIMAccess(req)
	if !recovered {
		return identity.Identity{}, err
	}
	if recoveryErr != nil {
		return identity.Identity{}, errors.Join(err, fmt.Errorf("SIM access recovery: %w", recoveryErr))
	}
	id, retryErr := a.getISIMIdentityOnce()
	if retryErr == nil {
		return id, nil
	}
	return identity.Identity{}, errors.Join(err, fmt.Errorf("SIM access recovery retry: %w", retryErr))
}

func (a *modemAccessAdapter) getISIMIdentityOnce() (identity.Identity, error) {
	if r, ok := a.modem.(IdentityReader); ok {
		return r.GetISIMIdentity()
	}
	var errs []error
	if apdu, ok := a.modem.(interface {
		OpenLogicalChannel(aid string) (int, error)
		CloseLogicalChannel(channel int) error
		TransmitAPDU(channel int, hexAPDU string) (string, error)
	}); ok {
		if id, err := identity.ReadISIMIdentity(apdu); err == nil {
			return id, nil
		} else {
			errs = append(errs, fmt.Errorf("logical-channel ISIM identity: %w", err))
		}
	}
	if crsm, ok := a.modem.(CRSMAccess); ok {
		if id, err := identity.ReadISIMIdentityCRSM(crsm, "7FFF"); err == nil {
			return id, nil
		} else {
			errs = append(errs, fmt.Errorf("CRSM ISIM identity: %w", err))
		}
	}
	if at, ok := a.modem.(interface {
		ExecuteATSilent(cmd string, timeout time.Duration) (string, error)
	}); ok {
		adapter := simtransport.NewAdapter(at)
		if id, err := identity.ReadISIMIdentityCRSM(adapter, "7FFF"); err == nil {
			return id, nil
		} else {
			errs = append(errs, fmt.Errorf("AT+CRSM ISIM identity: %w", err))
		}
	}
	if len(errs) > 0 {
		return identity.Identity{}, errors.Join(errs...)
	}
	return identity.Identity{}, errors.New("modem does not expose ISIM identity")
}

func (a *modemAccessAdapter) recoverSIMAccess(req SIMAccessRecoveryRequest) (bool, error) {
	if a == nil || a.modem == nil {
		return false, nil
	}
	if hook, ok := a.modem.(SIMAccessRecoveryHook); ok {
		return true, hook.RecoverSIMAccess(req)
	}
	at, ok := a.modem.(interface {
		ExecuteATSilent(cmd string, timeout time.Duration) (string, error)
	})
	if !ok {
		return false, nil
	}
	steps := simtransport.PlanATControlRecovery(req.Class, defaultATRecoveryPlanAttempt(req.Attempt))
	if len(steps) == 0 {
		return false, nil
	}
	opts := simtransport.ATRecoveryOptions{
		AllowVendorSpecific: req.DestructiveAllowed || a.recovery.AllowVendorSpecific,
		DryRun:              a.recovery.DryRun,
		Delay:               a.recovery.Delay,
	}
	return true, simtransport.ExecuteATControlRecovery(context.Background(), at, steps, opts)
}

func defaultATRecoveryPlanAttempt(attempt int) int {
	if attempt <= 0 {
		return 0
	}
	return attempt - 1
}

func newSIMAccessRecoveryRequest(operation string, attempt int, err error) (SIMAccessRecoveryRequest, bool) {
	class := simtransport.ClassifyError(err)
	if !class.Recoverable() {
		return SIMAccessRecoveryRequest{}, false
	}
	return SIMAccessRecoveryRequest{
		Operation:          operation,
		Attempt:            attempt,
		Class:              class,
		Err:                err,
		DestructiveAllowed: false,
	}, true
}

type SIMAdapter interface {
	GetIMSI() (string, error)
	CalculateAKA(rand16, autn16 []byte) (swusim.AKAResult, error)
	Close() error
}

type readerSIMAdapter struct {
	provider swusim.AKAProvider
	mu       sync.Mutex
	imsi     string
}

func NewReaderSIMAdapter(provider swusim.AKAProvider) SIMAdapter {
	return &readerSIMAdapter{provider: provider}
}

func (a *readerSIMAdapter) GetIMSI() (string, error) {
	if a == nil || a.provider == nil {
		return "", errors.New("aka provider is nil")
	}
	a.mu.Lock()
	if a.imsi != "" {
		imsi := a.imsi
		a.mu.Unlock()
		return imsi, nil
	}
	a.mu.Unlock()

	imsi, ok, err := providerIMSI(a.provider)
	if err != nil || !ok {
		return "", err
	}
	imsi, err = normalizeRuntimeIMSI(imsi)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	a.imsi = imsi
	a.mu.Unlock()
	return imsi, nil
}

func (a *readerSIMAdapter) CalculateAKA(rand16, autn16 []byte) (swusim.AKAResult, error) {
	if a == nil || a.provider == nil {
		return swusim.AKAResult{}, errors.New("aka provider is nil")
	}
	return a.provider.CalculateAKA(rand16, autn16)
}

func (a *readerSIMAdapter) Close() error {
	if a == nil || a.provider == nil {
		return nil
	}
	if closer, ok := a.provider.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func providerIMSI(provider swusim.AKAProvider) (string, bool, error) {
	switch p := provider.(type) {
	case interface{ GetIMSI() (string, error) }:
		imsi, err := p.GetIMSI()
		return imsi, true, err
	case interface{ IMSI() (string, error) }:
		imsi, err := p.IMSI()
		return imsi, true, err
	case interface{ IMSI() string }:
		return p.IMSI(), true, nil
	default:
		return "", false, nil
	}
}

func normalizeRuntimeIMSI(imsi string) (string, error) {
	imsi = strings.TrimSpace(imsi)
	if imsi == "" {
		return "", nil
	}
	if len(imsi) < 5 || len(imsi) > 15 {
		return "", fmt.Errorf("invalid IMSI length: %d", len(imsi))
	}
	for _, r := range imsi {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("invalid IMSI digit %q", r)
		}
	}
	return imsi, nil
}

type ProxyConfig struct {
	ID       string
	URL      string
	Address  string
	Addr     string
	Username string
	Password string
	Country  string
	Enabled  bool
}

type DataplanePolicy struct {
	Mode                 string
	TUNName              string
	TUNMTU               int
	DisableTUNRouting    bool
	TUNAddresses         []string
	TUNEPDGExclusions    []swu.EPDGRouteExclusion
	TUNRoutes            []swu.TUNRoute
	TUNRules             []swu.TUNRule
	TunnelManager        swu.TunnelManager
	TunnelManagerFactory TunnelManagerFactory
}

type SessionConfig struct {
	DeviceID      string
	TraceID       string
	Profile       identity.Profile
	Prepared      *identity.PreparedSession
	DataplaneMode string
	Proxy         *ProxyConfig
}

type IMSRegistrationConfig struct {
	DeviceID    string
	TraceID     string
	Profile     identity.Profile
	Prepared    *identity.PreparedSession
	SIM         SIMAdapter
	Access      ModemAccess
	NetworkMode string
	Dataplane   DataplanePolicy
	Tunnel      swu.TunnelResult
	Proxy       *ProxyConfig
}

type IMSRegistrationResult struct {
	Registered     bool
	StatusCode     int
	Reason         string
	Server         string
	Profile        voiceclient.IMSProfile
	Binding        voiceclient.RegistrationBinding
	RegisteredAt   time.Time
	ExpiresAt      time.Time
	RefreshDelay   time.Duration
	NextRefreshAt  time.Time
	RecoveryState  IMSRegistrationRecoveryState
	VoiceTransport voiceclient.SIPRequestTransport
	SMSTransport   messaging.SMSTransport
	USSDTransport  messaging.USSDTransport
	Close          func(context.Context) error
	Recover        func(context.Context) (IMSRegistrationResult, error)
}

type IMSRegistrationRecoveryState struct {
	Attempts            int
	ConsecutiveFailures int
	LastReason          string
	LastError           string
	LastAttemptAt       time.Time
	LastSucceededAt     time.Time
	NextAttemptAt       time.Time
	LastSwitchedTarget  bool
}

type IMSRegistrar interface {
	RegisterIMS(context.Context, IMSRegistrationConfig) (IMSRegistrationResult, error)
}

const StartModeMain = "main"

type TunnelManagerFactory func(StartRequest) (swu.TunnelManager, error)

type StartRequest struct {
	Mode                       string
	DeviceID                   string
	TraceID                    string
	Profile                    identity.Profile
	Prepared                   *identity.PreparedSession
	NetworkMode                string
	VoiceGateway               *voicehost.Gateway
	SIM                        SIMAdapter
	Access                     ModemAccess
	Dataplane                  DataplanePolicy
	Proxy                      *ProxyConfig
	EAPReauthentication        swu.EAPReauthenticationState
	OnEAPReauthenticationState func(swu.EAPReauthenticationState)
	TunnelManager              swu.TunnelManager
	TunnelManagerFactory       TunnelManagerFactory
	IMSRegistrar               IMSRegistrar
	VoiceTransport             voiceclient.SIPRequestTransport
	VoiceUserAgent             string
	VoiceSessionExpires        int
	VoiceMediaRelay            *voicehost.RTPRelayConfig
	SMSTransport               messaging.SMSTransport
	USSDTransport              messaging.USSDTransport
	DeliveryStore              messaging.DeliveryStore
	Dispatch                   eventhost.Dispatcher
	BeforeStart                func(context.Context, SessionConfig) error
	ShouldRun                  func() bool
}

type runtimeVoiceAgentConfig struct {
	transport      voiceclient.SIPRequestTransport
	userAgent      string
	sessionExpires int
	mediaRelay     *voicehost.RTPRelayConfig
}

type Instance struct {
	mu           sync.RWMutex
	imsRecoverMu sync.Mutex
	state        State
	service      *messaging.Service
	observers    []Observer
	dispatch     eventhost.Dispatcher
	notifier     func(string)
	smsNotify    func(deviceID, sender, content string, ts time.Time)
	tunnel       swu.TunnelSession
	voice        voicehost.Agent
	voiceConfig  runtimeVoiceAgentConfig
	imsClose     func(context.Context) error
	imsRecover   func(context.Context) (IMSRegistrationResult, error)
	stopped      bool
}

func Start(ctx context.Context, req StartRequest) (*Instance, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(req.DeviceID) == "" {
		return nil, errors.New("device_id is empty")
	}
	if req.ShouldRun != nil && !req.ShouldRun() {
		return nil, errors.New("runtime start canceled")
	}
	cfg := SessionConfig{
		DeviceID:      req.DeviceID,
		TraceID:       req.TraceID,
		Profile:       req.Profile,
		Prepared:      req.Prepared,
		DataplaneMode: req.Dataplane.Mode,
		Proxy:         req.Proxy,
	}
	if req.BeforeStart != nil {
		if err := req.BeforeStart(ctx, cfg); err != nil {
			return nil, err
		}
	}
	regStatus, regText := 0, ""
	modem := Modem(nil)
	if req.Access != nil {
		modem = req.Access.RuntimeModem()
	}
	if modem != nil {
		regStatus, regText = modem.GetRegStatus()
	}
	var tunnel swu.TunnelSession
	var tunnelResult swu.TunnelResult
	var tunnelReady bool
	tunnelManager, err := tunnelManagerForStart(req)
	if err != nil {
		return nil, err
	}
	if tunnelManager != nil && strings.TrimSpace(req.Dataplane.Mode) != swu.DataplaneModeDisabled {
		tunnelConfig := buildTunnelConfig(req, modem)
		if err := tunnelConfig.Validate(); err != nil {
			return nil, err
		}
		session, err := tunnelManager.EstablishTunnel(ctx, tunnelConfig)
		if err != nil {
			return nil, fmt.Errorf("SWU tunnel establishment failed: %w", err)
		}
		if session == nil {
			return nil, errors.New("SWU tunnel establishment failed: nil tunnel session")
		}
		tunnel = session
		tunnelResult = session.Result()
		tunnelReady = tunnelResult.IsReady()
		if !tunnelReady {
			_ = session.Close(ctx)
			return nil, fmt.Errorf("SWU tunnel establishment incomplete: %s", firstRuntimeNonEmpty(tunnelResult.Reason, "not ready"))
		}
	}
	imsReady := req.IMSRegistrar == nil
	imsReason := ""
	imsResult := IMSRegistrationResult{}
	if req.IMSRegistrar != nil {
		imsCfg := IMSRegistrationConfig{
			DeviceID:    req.DeviceID,
			TraceID:     req.TraceID,
			Profile:     req.Profile,
			Prepared:    req.Prepared,
			SIM:         req.SIM,
			Access:      req.Access,
			NetworkMode: req.NetworkMode,
			Dataplane:   req.Dataplane,
			Tunnel:      tunnelResult,
			Proxy:       req.Proxy,
		}
		res, err := req.IMSRegistrar.RegisterIMS(ctx, imsCfg)
		if err != nil {
			return nil, fmt.Errorf("IMS registration failed: %w", err)
		}
		if !res.Registered {
			return nil, fmt.Errorf("IMS registration rejected: %d %s", res.StatusCode, strings.TrimSpace(res.Reason))
		}
		imsReady = true
		imsReason = firstRuntimeNonEmpty(res.Reason, res.Server)
		imsResult = res
	}
	state := State{
		DeviceID:      req.DeviceID,
		Phase:         PhaseReady,
		DataplaneMode: req.Dataplane.Mode,
		SIMReady:      req.SIM != nil,
		AccessReady:   modem != nil,
		TunnelReady:   tunnelReady,
		IMSReady:      imsReady,
		SMSReady:      true,
		RegStatus:     regStatus,
		RegStatusText: regText,
		NetworkMode:   strings.TrimSpace(req.NetworkMode),
		LastReason:    firstRuntimeNonEmpty(imsReason, tunnelResult.Reason, "started"),
		UpdatedAt:     time.Now(),
	}
	if state.NetworkMode == "" && modem != nil {
		state.NetworkMode = modem.GetNetworkMode()
	}
	svc := messaging.NewService(req.DeviceID, req.Profile.IMSI, req.DeliveryStore, req.Dispatch)
	smsTransport := req.SMSTransport
	if smsTransport == nil {
		smsTransport = imsResult.SMSTransport
	}
	ussdTransport := req.USSDTransport
	if ussdTransport == nil {
		ussdTransport = imsResult.USSDTransport
	}
	voiceConfig := runtimeVoiceAgentConfigFromStart(req)
	inst := &Instance{
		state:       state,
		service:     svc,
		dispatch:    req.Dispatch,
		tunnel:      tunnel,
		voice:       buildRuntimeVoiceAgentWithConfig(voiceConfig, imsResult),
		voiceConfig: voiceConfig,
		imsClose:    imsResult.Close,
		imsRecover:  imsResult.Recover,
	}
	svc.SetSMSTransport(inst.wrapSMSTransport(smsTransport))
	svc.SetUSSDTransport(inst.wrapUSSDTransport(ussdTransport))
	if req.VoiceGateway != nil {
		req.VoiceGateway.RegisterAgent(req.DeviceID, inst)
	}
	inst.notify(ctx)
	inst.dispatchRuntimeState(ctx)
	return inst, nil
}

func buildRuntimeVoiceAgent(req StartRequest, reg IMSRegistrationResult) voicehost.Agent {
	return buildRuntimeVoiceAgentWithConfig(runtimeVoiceAgentConfigFromStart(req), reg)
}

func runtimeVoiceAgentConfigFromStart(req StartRequest) runtimeVoiceAgentConfig {
	return runtimeVoiceAgentConfig{
		transport:      req.VoiceTransport,
		userAgent:      req.VoiceUserAgent,
		sessionExpires: req.VoiceSessionExpires,
		mediaRelay:     req.VoiceMediaRelay,
	}
}

func buildRuntimeVoiceAgentWithConfig(cfg runtimeVoiceAgentConfig, reg IMSRegistrationResult) voicehost.Agent {
	transport := cfg.transport
	if transport == nil {
		transport = reg.VoiceTransport
	}
	if transport == nil || !reg.Registered {
		return nil
	}
	binding := reg.Binding
	if strings.TrimSpace(binding.ContactURI) == "" {
		return nil
	}
	profile := reg.Profile
	if strings.TrimSpace(profile.IMPU) == "" {
		profile.IMPU = strings.TrimSpace(binding.PublicIdentity)
	}
	if strings.TrimSpace(profile.Domain) == "" {
		profile.Domain = sipDomainRuntime(profile.IMPU)
	}
	return &voicehost.IMSOutboundAgent{
		Transport:      transport,
		Profile:        profile,
		Registration:   binding,
		Domain:         profile.Domain,
		UserAgent:      firstRuntimeNonEmpty(cfg.userAgent, profile.UserAgent),
		SessionExpires: cfg.sessionExpires,
		MediaRelay:     cfg.mediaRelay,
	}
}

func buildRuntimeVoiceRegistrationUpdate(cfg runtimeVoiceAgentConfig, reg IMSRegistrationResult) (voicehost.IMSRegistrationUpdate, bool) {
	if !reg.Registered {
		return voicehost.IMSRegistrationUpdate{}, false
	}
	binding := reg.Binding
	if strings.TrimSpace(binding.ContactURI) == "" {
		return voicehost.IMSRegistrationUpdate{}, false
	}
	profile := reg.Profile
	if strings.TrimSpace(profile.IMPU) == "" {
		profile.IMPU = strings.TrimSpace(binding.PublicIdentity)
	}
	if strings.TrimSpace(profile.Domain) == "" {
		profile.Domain = sipDomainRuntime(profile.IMPU)
	}
	transport := cfg.transport
	if transport == nil {
		transport = reg.VoiceTransport
	}
	return voicehost.IMSRegistrationUpdate{
		Transport:      transport,
		Profile:        profile,
		Registration:   binding,
		Domain:         profile.Domain,
		UserAgent:      firstRuntimeNonEmpty(cfg.userAgent, profile.UserAgent),
		SessionExpires: cfg.sessionExpires,
		MediaRelay:     cfg.mediaRelay,
	}, true
}

func (i *Instance) AddObserver(o Observer) {
	if i == nil || o == nil {
		return
	}
	i.mu.Lock()
	i.observers = append(i.observers, o)
	state := i.state
	i.mu.Unlock()
	o.OnRuntimeEvent(context.Background(), Event{State: state})
}

func (i *Instance) notify(ctx context.Context) {
	i.mu.RLock()
	observers := append([]Observer(nil), i.observers...)
	state := i.state
	i.mu.RUnlock()
	for _, o := range observers {
		o.OnRuntimeEvent(ctx, Event{State: state})
	}
}

func (i *Instance) Stop(ctx context.Context) error {
	if i == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	i.mu.Lock()
	tunnel := i.tunnel
	imsClose := i.imsClose
	voice := i.voice
	i.tunnel = nil
	i.imsClose = nil
	i.stopped = true
	i.state.Phase = PhaseStopped
	i.state.TunnelReady = false
	i.state.LastReason = "stopped"
	i.state.UpdatedAt = time.Now()
	i.mu.Unlock()
	var err error
	if stopper, ok := voice.(interface{ StopSessionTimers() }); ok {
		stopper.StopSessionTimers()
	}
	if tunnel != nil {
		err = tunnel.Close(ctx)
	}
	if imsClose != nil {
		err = errors.Join(err, imsClose(ctx))
	}
	i.notify(ctx)
	i.dispatchRuntimeState(ctx)
	return err
}

func (i *Instance) StartOutboundCall(ctx context.Context, req voicehost.OutboundCallRequest) (voicehost.OutboundCallResult, error) {
	agent := i.outboundVoiceAgent()
	if agent == nil {
		return voicehost.OutboundCallResult{Accepted: false, Reason: "IMS voice agent unavailable"}, voicehost.ErrIMSVoiceAgentNotReady
	}
	result, err := agent.StartOutboundCall(ctx, req)
	if !result.RegistrationRecoveryNeeded {
		return result, err
	}
	_, recovered, recoveryErr := i.recoverIMSRegistration(ctx, result.Reason, true, result.RetryAfter)
	if recoveryErr != nil {
		return result, runtimeOperationRecoveryError(err, recoveryErr)
	}
	if err == nil || !recovered {
		return result, nil
	}
	agent = i.outboundVoiceAgent()
	if agent == nil {
		return result, errors.Join(err, voicehost.ErrIMSVoiceAgentNotReady)
	}
	return agent.StartOutboundCall(ctx, req)
}

func (i *Instance) EndVoiceCall(ctx context.Context, info voicehost.DialogInfo) error {
	_, err := i.EndVoiceCallWithResult(ctx, info)
	return err
}

func (i *Instance) EndVoiceCallWithResult(ctx context.Context, info voicehost.DialogInfo) (voicehost.DialogInfoResult, error) {
	agent := i.dialogTerminatorWithResult()
	if agent != nil {
		result, err := agent.EndVoiceCallWithResult(ctx, info)
		return i.recoverVoiceDialogInfoResult(ctx, result, err)
	}
	terminator := i.dialogTerminator()
	if terminator == nil {
		return voicehost.DialogInfoResult{Accepted: false, Reason: "IMS voice agent unavailable"}, voicehost.ErrIMSVoiceAgentNotReady
	}
	if err := terminator.EndVoiceCall(ctx, info); err != nil {
		return voicehost.DialogInfoResult{Accepted: false, Reason: err.Error()}, err
	}
	return voicehost.DialogInfoResult{Accepted: true, StatusCode: 200, Reason: "OK"}, nil
}

func (i *Instance) CancelVoiceCall(ctx context.Context, info voicehost.DialogInfo) error {
	_, err := i.CancelVoiceCallWithResult(ctx, info)
	return err
}

func (i *Instance) CancelVoiceCallWithResult(ctx context.Context, info voicehost.DialogInfo) (voicehost.DialogInfoResult, error) {
	agent := i.dialogCancellerWithResult()
	if agent != nil {
		result, err := agent.CancelVoiceCallWithResult(ctx, info)
		return i.recoverVoiceDialogInfoResult(ctx, result, err)
	}
	canceller := i.dialogCanceller()
	if canceller == nil {
		return voicehost.DialogInfoResult{Accepted: false, Reason: "IMS voice agent unavailable"}, voicehost.ErrIMSVoiceAgentNotReady
	}
	if err := canceller.CancelVoiceCall(ctx, info); err != nil {
		return voicehost.DialogInfoResult{Accepted: false, Reason: err.Error()}, err
	}
	return voicehost.DialogInfoResult{Accepted: true, StatusCode: 200, Reason: "OK"}, nil
}

func (i *Instance) recoverVoiceDialogInfoResult(ctx context.Context, result voicehost.DialogInfoResult, err error) (voicehost.DialogInfoResult, error) {
	if result.RegistrationRecoveryNeeded {
		if _, _, recoveryErr := i.recoverIMSRegistration(ctx, result.Reason, true, result.RetryAfter); recoveryErr != nil {
			return result, runtimeOperationRecoveryError(err, recoveryErr)
		}
	}
	return result, err
}

func (i *Instance) SendDialogInfo(ctx context.Context, req voicehost.DialogInfoRequest) (voicehost.DialogInfoResult, error) {
	agent := i.dialogInfoSender()
	if agent == nil {
		return voicehost.DialogInfoResult{Accepted: false, Reason: "IMS voice agent unavailable"}, voicehost.ErrIMSVoiceAgentNotReady
	}
	result, err := agent.SendDialogInfo(ctx, req)
	if result.RegistrationRecoveryNeeded {
		if _, _, recoveryErr := i.recoverIMSRegistration(ctx, result.Reason, true, result.RetryAfter); recoveryErr != nil {
			return result, runtimeOperationRecoveryError(err, recoveryErr)
		}
	}
	return result, err
}

func (i *Instance) SendDialogMessage(ctx context.Context, req voicehost.DialogMessageRequest) (voicehost.DialogMessageResult, error) {
	agent := i.dialogMessageSender()
	if agent == nil {
		return voicehost.DialogMessageResult{Accepted: false, Reason: "IMS voice agent unavailable"}, voicehost.ErrIMSVoiceAgentNotReady
	}
	result, err := agent.SendDialogMessage(ctx, req)
	if result.RegistrationRecoveryNeeded {
		if _, _, recoveryErr := i.recoverIMSRegistration(ctx, result.Reason, true, result.RetryAfter); recoveryErr != nil {
			return result, runtimeOperationRecoveryError(err, recoveryErr)
		}
	}
	return result, err
}

func (i *Instance) SendDialogPrack(ctx context.Context, req voicehost.DialogPrackRequest) (voicehost.DialogPrackResult, error) {
	agent := i.dialogPrackSender()
	if agent == nil {
		return voicehost.DialogPrackResult{Accepted: false, Reason: "IMS voice agent unavailable"}, voicehost.ErrIMSVoiceAgentNotReady
	}
	result, err := agent.SendDialogPrack(ctx, req)
	if result.RegistrationRecoveryNeeded {
		if _, _, recoveryErr := i.recoverIMSRegistration(ctx, result.Reason, true, result.RetryAfter); recoveryErr != nil {
			return result, runtimeOperationRecoveryError(err, recoveryErr)
		}
	}
	return result, err
}

func (i *Instance) SendDialogOptions(ctx context.Context, req voicehost.DialogOptionsRequest) (voicehost.DialogOptionsResult, error) {
	agent := i.dialogOptionsSender()
	if agent == nil {
		return voicehost.DialogOptionsResult{Accepted: false, Reason: "IMS voice agent unavailable"}, voicehost.ErrIMSVoiceAgentNotReady
	}
	result, err := agent.SendDialogOptions(ctx, req)
	if result.RegistrationRecoveryNeeded {
		if _, _, recoveryErr := i.recoverIMSRegistration(ctx, result.Reason, true, result.RetryAfter); recoveryErr != nil {
			return result, runtimeOperationRecoveryError(err, recoveryErr)
		}
	}
	return result, err
}

func (i *Instance) SendDialogRefer(ctx context.Context, req voicehost.DialogReferRequest) (voicehost.DialogReferResult, error) {
	agent := i.dialogReferSender()
	if agent == nil {
		return voicehost.DialogReferResult{Accepted: false, Reason: "IMS voice agent unavailable"}, voicehost.ErrIMSVoiceAgentNotReady
	}
	result, err := agent.SendDialogRefer(ctx, req)
	if result.RegistrationRecoveryNeeded {
		if _, _, recoveryErr := i.recoverIMSRegistration(ctx, result.Reason, true, result.RetryAfter); recoveryErr != nil {
			return result, runtimeOperationRecoveryError(err, recoveryErr)
		}
	}
	return result, err
}

func (i *Instance) SendDialogNotify(ctx context.Context, req voicehost.DialogNotifyRequest) (voicehost.DialogNotifyResult, error) {
	agent := i.dialogNotifySender()
	if agent == nil {
		return voicehost.DialogNotifyResult{Accepted: false, Reason: "IMS voice agent unavailable"}, voicehost.ErrIMSVoiceAgentNotReady
	}
	result, err := agent.SendDialogNotify(ctx, req)
	if result.RegistrationRecoveryNeeded {
		if _, _, recoveryErr := i.recoverIMSRegistration(ctx, result.Reason, true, result.RetryAfter); recoveryErr != nil {
			return result, runtimeOperationRecoveryError(err, recoveryErr)
		}
	}
	return result, err
}

func (i *Instance) SendDialogSubscribe(ctx context.Context, req voicehost.DialogSubscribeRequest) (voicehost.DialogSubscribeResult, error) {
	agent := i.dialogSubscribeSender()
	if agent == nil {
		return voicehost.DialogSubscribeResult{Accepted: false, Reason: "IMS voice agent unavailable"}, voicehost.ErrIMSVoiceAgentNotReady
	}
	result, err := agent.SendDialogSubscribe(ctx, req)
	if result.RegistrationRecoveryNeeded {
		if _, _, recoveryErr := i.recoverIMSRegistration(ctx, result.Reason, true, result.RetryAfter); recoveryErr != nil {
			return result, runtimeOperationRecoveryError(err, recoveryErr)
		}
	}
	return result, err
}

func (i *Instance) SendDialogDTMF(ctx context.Context, req voicehost.DialogDTMFRequest) (voicehost.DialogDTMFResult, error) {
	if agent := i.dialogDTMFSender(); agent != nil {
		result, err := agent.SendDialogDTMF(ctx, req)
		if result.RegistrationRecoveryNeeded {
			if _, _, recoveryErr := i.recoverIMSRegistration(ctx, result.Reason, true, result.RetryAfter); recoveryErr != nil {
				return result, runtimeOperationRecoveryError(err, recoveryErr)
			}
		}
		return result, err
	}
	infoReq, buildErr := voicehost.BuildDialogDTMFInfoRequest(req)
	if buildErr != nil {
		return voicehost.DialogDTMFResult{Accepted: false, StatusCode: 400, Reason: buildErr.Error()}, buildErr
	}
	result, err := i.SendDialogInfo(ctx, infoReq)
	return voicehost.DialogDTMFResult(result), err
}

func (i *Instance) SendDialogAutoDTMF(ctx context.Context, req voicehost.DialogDTMFRequest) (voicehost.DialogAutoDTMFResult, error) {
	if _, err := voicehost.BuildDTMFRelayBody(req.Signal, req.DurationMS); err != nil {
		return voicehost.DialogAutoDTMFResult{Accepted: false, StatusCode: 400, Reason: err.Error()}, err
	}
	if agent := i.dialogRTPDTMFSender(); agent != nil {
		rtpResult, rtpErr := agent.SendDialogRTPDTMF(ctx, runtimeDialogRTPDTMFRequest(req))
		if rtpErr == nil || !errors.Is(rtpErr, voicehost.ErrRTPRelayConfig) {
			return runtimeDialogAutoDTMFResultFromRTP(rtpResult), rtpErr
		}
	}
	infoResult, err := i.SendDialogDTMF(ctx, req)
	return runtimeDialogAutoDTMFResultFromINFO(infoResult), err
}

func runtimeDialogRTPDTMFRequest(req voicehost.DialogDTMFRequest) voicehost.DialogRTPDTMFRequest {
	return voicehost.DialogRTPDTMFRequest{
		DeviceID:   strings.TrimSpace(req.DeviceID),
		CallID:     strings.TrimSpace(req.CallID),
		Direction:  voicehost.RTPDTMFClientToIMS,
		Signal:     req.Signal,
		DurationMS: req.DurationMS,
	}
}

func runtimeDialogAutoDTMFResultFromRTP(result voicehost.DialogRTPDTMFResult) voicehost.DialogAutoDTMFResult {
	return voicehost.DialogAutoDTMFResult{
		Accepted:   result.Accepted,
		StatusCode: result.StatusCode,
		Reason:     result.Reason,
		Route:      voicehost.DialogDTMFRouteRTP,
		RTP:        result,
	}
}

func runtimeDialogAutoDTMFResultFromINFO(result voicehost.DialogDTMFResult) voicehost.DialogAutoDTMFResult {
	return voicehost.DialogAutoDTMFResult{
		Accepted:                   result.Accepted,
		StatusCode:                 result.StatusCode,
		Reason:                     result.Reason,
		Route:                      voicehost.DialogDTMFRouteInfo,
		RegistrationRecoveryNeeded: result.RegistrationRecoveryNeeded,
		RetryAfter:                 result.RetryAfter,
		INFO:                       result,
	}
}

func (i *Instance) SendDialogUpdate(ctx context.Context, req voicehost.DialogUpdateRequest) (voicehost.DialogUpdateResult, error) {
	agent := i.dialogUpdater()
	if agent == nil {
		return voicehost.DialogUpdateResult{Accepted: false, Reason: "IMS voice agent unavailable"}, voicehost.ErrIMSVoiceAgentNotReady
	}
	result, err := agent.SendDialogUpdate(ctx, req)
	if result.RegistrationRecoveryNeeded {
		if _, _, recoveryErr := i.recoverIMSRegistration(ctx, result.Reason, true, result.RetryAfter); recoveryErr != nil {
			return result, runtimeOperationRecoveryError(err, recoveryErr)
		}
	}
	return result, err
}

func (i *Instance) SendDialogHold(ctx context.Context, req voicehost.DialogHoldRequest) (voicehost.DialogUpdateResult, error) {
	agent := i.dialogHoldController()
	if agent == nil {
		return voicehost.DialogUpdateResult{Accepted: false, Reason: "IMS voice agent unavailable"}, voicehost.ErrIMSVoiceAgentNotReady
	}
	result, err := agent.SendDialogHold(ctx, req)
	if result.RegistrationRecoveryNeeded {
		if _, _, recoveryErr := i.recoverIMSRegistration(ctx, result.Reason, true, result.RetryAfter); recoveryErr != nil {
			return result, runtimeOperationRecoveryError(err, recoveryErr)
		}
	}
	return result, err
}

func (i *Instance) SendDialogResume(ctx context.Context, req voicehost.DialogResumeRequest) (voicehost.DialogUpdateResult, error) {
	agent := i.dialogHoldController()
	if agent == nil {
		return voicehost.DialogUpdateResult{Accepted: false, Reason: "IMS voice agent unavailable"}, voicehost.ErrIMSVoiceAgentNotReady
	}
	result, err := agent.SendDialogResume(ctx, req)
	if result.RegistrationRecoveryNeeded {
		if _, _, recoveryErr := i.recoverIMSRegistration(ctx, result.Reason, true, result.RetryAfter); recoveryErr != nil {
			return result, runtimeOperationRecoveryError(err, recoveryErr)
		}
	}
	return result, err
}

func (i *Instance) SendDialogReinvite(ctx context.Context, req voicehost.DialogReinviteRequest) (voicehost.DialogReinviteResult, error) {
	agent := i.dialogReinviter()
	if agent == nil {
		return voicehost.DialogReinviteResult{Accepted: false, Reason: "IMS voice agent unavailable"}, voicehost.ErrIMSVoiceAgentNotReady
	}
	result, err := agent.SendDialogReinvite(ctx, req)
	if result.RegistrationRecoveryNeeded {
		if _, _, recoveryErr := i.recoverIMSRegistration(ctx, result.Reason, true, result.RetryAfter); recoveryErr != nil {
			return result, runtimeOperationRecoveryError(err, recoveryErr)
		}
	}
	return result, err
}

func runtimeOperationRecoveryError(operationErr, recoveryErr error) error {
	if recoveryErr == nil {
		return operationErr
	}
	if operationErr == nil {
		return recoveryErr
	}
	return errors.Join(operationErr, recoveryErr)
}

func (i *Instance) recoverIMSRegistration(ctx context.Context, reason string, updateVoice bool, retryAfter time.Duration) (IMSRegistrationResult, bool, error) {
	if i == nil {
		return IMSRegistrationResult{}, false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	i.imsRecoverMu.Lock()
	defer i.imsRecoverMu.Unlock()

	i.mu.RLock()
	recover := i.imsRecover
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return IMSRegistrationResult{}, false, voicehost.ErrIMSVoiceAgentNotReady
	}
	if recover == nil {
		return IMSRegistrationResult{}, false, nil
	}
	if retryAfter > 0 {
		i.recordIMSRecoveryPending(ctx, reason, retryAfter)
		timer := time.NewTimer(retryAfter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return IMSRegistrationResult{}, false, ctx.Err()
		case <-timer.C:
		}
	}
	result, err := recover(ctx)
	if err != nil {
		i.recordIMSRecoveryFailure(ctx, err)
		return IMSRegistrationResult{}, false, err
	}
	if !result.Registered {
		err := fmt.Errorf("IMS registration recovery did not register: %d %s", result.StatusCode, strings.TrimSpace(result.Reason))
		i.recordIMSRecoveryFailure(ctx, err)
		return result, false, err
	}
	i.applyIMSRegistrationResult(ctx, result, firstRuntimeNonEmpty(result.Reason, reason, "IMS registration recovered"), updateVoice)
	return result, true, nil
}

func (i *Instance) recordIMSRecoveryPending(ctx context.Context, reason string, retryAfter time.Duration) {
	if i == nil || retryAfter <= 0 {
		return
	}
	now := time.Now()
	reason = firstRuntimeNonEmpty(reason, "IMS registration recovery")
	i.mu.Lock()
	if i.stopped {
		i.mu.Unlock()
		return
	}
	i.state.IMSRecoveryPending = true
	i.state.IMSRecoveryRetryAfter = retryAfter
	i.state.IMSRecoveryNextAttemptAt = now.Add(retryAfter)
	i.state.IMSRecoveryReason = reason
	i.state.LastReason = "IMS registration recovery delayed: " + reason
	i.state.UpdatedAt = now
	i.mu.Unlock()
	i.notify(ctx)
	i.dispatchRuntimeState(ctx)
}

func (i *Instance) recordIMSRecoveryFailure(ctx context.Context, err error) {
	if i == nil || err == nil {
		return
	}
	i.mu.Lock()
	if i.stopped {
		i.mu.Unlock()
		return
	}
	i.state.IMSReady = false
	i.state.IMSRecoveryPending = false
	i.state.IMSRecoveryRetryAfter = 0
	i.state.IMSRecoveryNextAttemptAt = time.Time{}
	i.state.IMSRecoveryReason = ""
	i.state.LastReason = "IMS registration recovery failed: " + err.Error()
	i.state.UpdatedAt = time.Now()
	i.mu.Unlock()
	i.notify(ctx)
	i.dispatchRuntimeState(ctx)
}

func (i *Instance) applyIMSRegistrationResult(ctx context.Context, result IMSRegistrationResult, reason string, updateVoice bool) {
	if i == nil {
		return
	}
	smsTransport := result.SMSTransport
	ussdTransport := result.USSDTransport
	i.mu.Lock()
	if i.stopped {
		i.mu.Unlock()
		return
	}
	if result.Close != nil {
		i.imsClose = result.Close
	}
	if result.Recover != nil {
		i.imsRecover = result.Recover
	}
	if updateVoice {
		if update, ok := buildRuntimeVoiceRegistrationUpdate(i.voiceConfig, result); ok {
			if updater, ok := i.voice.(voicehost.IMSRegistrationUpdater); ok {
				updater.UpdateIMSRegistration(update)
			} else {
				i.voice = buildRuntimeVoiceAgentWithConfig(i.voiceConfig, result)
			}
		} else {
			i.voice = nil
		}
	}
	i.state.IMSReady = result.Registered
	i.state.IMSRecoveryPending = false
	i.state.IMSRecoveryRetryAfter = 0
	i.state.IMSRecoveryNextAttemptAt = time.Time{}
	i.state.IMSRecoveryReason = ""
	i.state.LastReason = firstRuntimeNonEmpty(reason, result.Server, "IMS registration recovered")
	i.state.UpdatedAt = time.Now()
	svc := i.service
	i.mu.Unlock()

	if svc != nil {
		if smsTransport != nil {
			svc.SetSMSTransport(i.wrapSMSTransport(smsTransport))
		}
		if ussdTransport != nil {
			svc.SetUSSDTransport(i.wrapUSSDTransport(ussdTransport))
		}
	}
	i.notify(ctx)
	i.dispatchRuntimeState(ctx)
}

type runtimeRecoveringSMSTransport struct {
	owner *Instance
	inner messaging.SMSTransport
}

func (t *runtimeRecoveringSMSTransport) SendSMSPart(ctx context.Context, req messaging.SMSSendRequest) (messaging.SMSSendResult, error) {
	if t == nil || t.inner == nil {
		return messaging.SMSSendResult{State: "failed", ErrorText: messaging.ErrSMSTransportUnavailable.Error()}, messaging.ErrSMSTransportUnavailable
	}
	result, err := t.inner.SendSMSPart(ctx, req)
	if !result.RegistrationRecoveryNeeded || t.owner == nil {
		return result, err
	}
	retry := runtimeShouldRetryRecoverableIMSStatus(err, result.SIPCode)
	recovery, recovered, recoveryErr := t.owner.recoverIMSRegistration(ctx, result.ErrorText, true, result.RetryAfter)
	if recoveryErr != nil {
		return result, runtimeOperationRecoveryError(err, recoveryErr)
	}
	if !retry || !recovered || recovery.SMSTransport == nil {
		return result, err
	}
	return recovery.SMSTransport.SendSMSPart(ctx, req)
}

type runtimeRecoveringUSSDTransport struct {
	owner *Instance
	inner messaging.USSDTransport
}

func (t *runtimeRecoveringUSSDTransport) ExecuteUSSD(ctx context.Context, req messaging.USSDRequest) (messaging.USSDResult, error) {
	if t == nil || t.inner == nil {
		return messaging.USSDResult{SessionID: req.SessionID, Done: true}, messaging.ErrUSSDTransportUnavailable
	}
	result, err := t.inner.ExecuteUSSD(ctx, req)
	if !result.RegistrationRecoveryNeeded || t.owner == nil {
		return result, err
	}
	retry := runtimeShouldRetryRecoverableIMSStatus(err, result.Status)
	recovery, recovered, recoveryErr := t.owner.recoverIMSRegistration(ctx, "USSD registration recovery", true, result.RetryAfter)
	if recoveryErr != nil {
		return result, runtimeOperationRecoveryError(err, recoveryErr)
	}
	if !retry || !recovered || recovery.USSDTransport == nil {
		return result, err
	}
	return recovery.USSDTransport.ExecuteUSSD(ctx, req)
}

func runtimeShouldRetryRecoverableIMSStatus(err error, status int) bool {
	if err == nil {
		return false
	}
	if status == 0 {
		return true
	}
	if status >= 200 && status < 300 {
		return false
	}
	return messaging.IMSRegistrationRecoveryNeededStatus(status)
}

func (t *runtimeRecoveringUSSDTransport) ContinueUSSD(ctx context.Context, req messaging.USSDRequest) (messaging.USSDResult, error) {
	if t == nil || t.inner == nil {
		return messaging.USSDResult{SessionID: req.SessionID, Done: true}, messaging.ErrUSSDTransportUnavailable
	}
	result, err := t.inner.ContinueUSSD(ctx, req)
	if result.RegistrationRecoveryNeeded && t.owner != nil {
		if _, _, recoveryErr := t.owner.recoverIMSRegistration(ctx, "USSD registration recovery", true, result.RetryAfter); recoveryErr != nil {
			return result, runtimeOperationRecoveryError(err, recoveryErr)
		}
	}
	return result, err
}

func (t *runtimeRecoveringUSSDTransport) CancelUSSD(ctx context.Context, req messaging.USSDRequest) error {
	if t == nil || t.inner == nil {
		return messaging.ErrUSSDTransportUnavailable
	}
	err := t.inner.CancelUSSD(ctx, req)
	if err != nil && t.owner != nil && messaging.IsIMSRegistrationRecoveryError(err) {
		if _, _, recoveryErr := t.owner.recoverIMSRegistration(ctx, "USSD registration recovery", true, messaging.IMSRegistrationRecoveryRetryAfter(err)); recoveryErr != nil {
			return errors.Join(err, recoveryErr)
		}
	}
	return err
}

type runtimeRecoveringIMSUSSDDialogTransport struct {
	*runtimeRecoveringUSSDTransport
	dialog messaging.IMSUSSDDialogTransport
}

func (t *runtimeRecoveringIMSUSSDDialogTransport) HandleIMSInfo(ctx context.Context, req messaging.IMSUSSDDialogRequest) (messaging.IMSUSSDDialogResult, error) {
	if t == nil || t.dialog == nil {
		return messaging.IMSUSSDDialogResult{}, nil
	}
	return t.dialog.HandleIMSInfo(ctx, req)
}

func (t *runtimeRecoveringIMSUSSDDialogTransport) HandleIMSBye(ctx context.Context, req messaging.IMSUSSDDialogRequest) (messaging.IMSUSSDDialogResult, error) {
	if t == nil || t.dialog == nil {
		return messaging.IMSUSSDDialogResult{}, nil
	}
	return t.dialog.HandleIMSBye(ctx, req)
}

func (i *Instance) wrapSMSTransport(t messaging.SMSTransport) messaging.SMSTransport {
	if i == nil || t == nil {
		return t
	}
	if _, ok := t.(*runtimeRecoveringSMSTransport); ok {
		return t
	}
	return &runtimeRecoveringSMSTransport{owner: i, inner: t}
}

func (i *Instance) wrapUSSDTransport(t messaging.USSDTransport) messaging.USSDTransport {
	if i == nil || t == nil {
		return t
	}
	if _, ok := t.(*runtimeRecoveringUSSDTransport); ok {
		return t
	}
	if _, ok := t.(*runtimeRecoveringIMSUSSDDialogTransport); ok {
		return t
	}
	wrapped := &runtimeRecoveringUSSDTransport{owner: i, inner: t}
	if dialog, ok := t.(messaging.IMSUSSDDialogTransport); ok {
		return &runtimeRecoveringIMSUSSDDialogTransport{runtimeRecoveringUSSDTransport: wrapped, dialog: dialog}
	}
	return wrapped
}

func (i *Instance) outboundVoiceAgent() voicehost.OutboundCallAgent {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.OutboundCallAgent)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogTerminator() voicehost.DialogTerminator {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogTerminator)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogTerminatorWithResult() voicehost.DialogTerminatorWithResult {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogTerminatorWithResult)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogCanceller() voicehost.DialogCanceller {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogCanceller)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogCancellerWithResult() voicehost.DialogCancellerWithResult {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogCancellerWithResult)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogInfoSender() voicehost.DialogInfoSender {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogInfoSender)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogMessageSender() voicehost.DialogMessageSender {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogMessageSender)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogPrackSender() voicehost.DialogPrackSender {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogPrackSender)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogOptionsSender() voicehost.DialogOptionsSender {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogOptionsSender)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogReferSender() voicehost.DialogReferSender {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogReferSender)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogNotifySender() voicehost.DialogNotifySender {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogNotifySender)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogSubscribeSender() voicehost.DialogSubscribeSender {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogSubscribeSender)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogDTMFSender() voicehost.DialogDTMFSender {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogDTMFSender)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogRTPDTMFSender() voicehost.DialogRTPDTMFSender {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogRTPDTMFSender)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogUpdater() voicehost.DialogUpdater {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogUpdater)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogHoldController() voicehost.DialogHoldController {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogHoldController)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) dialogReinviter() voicehost.DialogReinviter {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	agent, _ := i.voice.(voicehost.DialogReinviter)
	stopped := i.stopped
	i.mu.RUnlock()
	if stopped {
		return nil
	}
	return agent
}

func (i *Instance) Service() *messaging.Service {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.service
}

func (i *Instance) SendSMSWithOptions(ctx context.Context, to, text string, opts messaging.SendOptions) (messaging.SendOutcome, error) {
	svc := i.Service()
	if svc == nil {
		return messaging.SendOutcome{}, errors.New("messaging service is nil")
	}
	return svc.SendSMSWithOptions(ctx, to, text, opts)
}

func (i *Instance) GetSMSDeliveryStatus(messageID string) (*messaging.DeliveryStatus, error) {
	svc := i.Service()
	if svc == nil {
		return nil, errors.New("messaging service is nil")
	}
	if svc == nil {
		return nil, errors.New("messaging service is nil")
	}
	return svc.GetSMSDeliveryStatus(messageID)
}

func (i *Instance) HandleIncomingSMS(ctx context.Context, msg messaging.IncomingSMS) error {
	svc := i.Service()
	if svc == nil {
		return errors.New("messaging service is nil")
	}
	return svc.HandleIncomingSMS(ctx, msg)
}

func (i *Instance) HandleSMSDeliveryReport(ctx context.Context, report messaging.SMSDeliveryReport) (messaging.DeliveryPartMatch, error) {
	svc := i.Service()
	if svc == nil {
		return messaging.DeliveryPartMatch{}, errors.New("messaging service is nil")
	}
	return svc.HandleSMSDeliveryReport(ctx, report)
}

func (i *Instance) HandleIMSMessage(ctx context.Context, req voicehost.IMSMessageRequest) (voicehost.IMSMessageResult, error) {
	svc := i.Service()
	if svc == nil {
		return voicehost.IMSMessageResult{StatusCode: 503, Reason: "messaging service is nil"}, errors.New("messaging service is nil")
	}
	res, err := svc.HandleIMSMessage(ctx, messaging.IMSMessageRequest{
		FromURI:     req.FromURI,
		ToURI:       req.ToURI,
		CallID:      req.CallID,
		CSeq:        req.CSeq,
		ContentType: req.ContentType,
		Body:        append([]byte(nil), req.Body...),
		Headers:     cloneRuntimeSIPHeaders(req.Headers),
	})
	return voicehost.IMSMessageResult{
		StatusCode:  res.StatusCode,
		Reason:      res.Reason,
		ContentType: res.ReplyContentType,
		Body:        append([]byte(nil), res.ReplyBody...),
	}, err
}

func (i *Instance) HandleIMSInfo(ctx context.Context, req voicehost.IMSInfoRequest) (voicehost.IMSInfoResult, error) {
	svc := i.Service()
	if svc == nil {
		return voicehost.IMSInfoResult{Handled: true, StatusCode: 503, Reason: "messaging service is nil"}, errors.New("messaging service is nil")
	}
	res, err := svc.HandleIMSUSSDInfo(ctx, messaging.IMSUSSDDialogRequest{
		URI:         req.URI,
		FromURI:     req.FromURI,
		ToURI:       req.ToURI,
		CallID:      req.CallID,
		CSeq:        req.CSeq,
		ContentType: req.ContentType,
		InfoPackage: req.InfoPackage,
		Body:        append([]byte(nil), req.Body...),
		Headers:     cloneRuntimeSIPHeaders(req.Headers),
	})
	return voicehost.IMSInfoResult{
		Handled:     res.Handled,
		StatusCode:  res.StatusCode,
		Reason:      res.Reason,
		ContentType: res.ContentType,
		Body:        append([]byte(nil), res.Body...),
		Headers:     cloneRuntimeHeaderMap(res.Headers),
	}, err
}

func (i *Instance) HandleIMSBye(ctx context.Context, req voicehost.IMSByeRequest) (voicehost.IMSByeResult, error) {
	svc := i.Service()
	if svc == nil {
		return voicehost.IMSByeResult{Handled: true, StatusCode: 503, Reason: "messaging service is nil"}, errors.New("messaging service is nil")
	}
	res, err := svc.HandleIMSUSSDBye(ctx, messaging.IMSUSSDDialogRequest{
		URI:         req.URI,
		FromURI:     req.FromURI,
		ToURI:       req.ToURI,
		CallID:      req.CallID,
		CSeq:        req.CSeq,
		ContentType: req.ContentType,
		Body:        append([]byte(nil), req.Body...),
		Headers:     cloneRuntimeSIPHeaders(req.Headers),
	})
	return voicehost.IMSByeResult{
		Handled:     res.Handled,
		StatusCode:  res.StatusCode,
		Reason:      res.Reason,
		ContentType: res.ContentType,
		Body:        append([]byte(nil), res.Body...),
		Headers:     cloneRuntimeHeaderMap(res.Headers),
	}, err
}

func (i *Instance) State() State {
	if i == nil {
		return State{}
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.state
}

func (i *Instance) SetNotifier(fn func(string)) {
	if i == nil {
		return
	}
	i.mu.Lock()
	i.notifier = fn
	i.mu.Unlock()
}

func (i *Instance) SetSMSNotifier(fn func(deviceID, sender, content string, ts time.Time)) {
	if i == nil {
		return
	}
	i.mu.Lock()
	i.smsNotify = fn
	i.mu.Unlock()
}

func (i *Instance) TriggerMOBIKE(oldIP, newIP string) error {
	if i == nil {
		return errors.New("runtime instance is nil")
	}
	oldIP = strings.TrimSpace(oldIP)
	newIP = strings.TrimSpace(newIP)
	i.mu.RLock()
	tunnel := i.tunnel
	deviceID := i.state.DeviceID
	i.mu.RUnlock()
	ctx := context.Background()
	pendingReason := runtimeMOBIKEReason("pending", oldIP, newIP, "")
	i.updateRuntimeReason(ctx, pendingReason)
	if tunnel == nil {
		i.updateRuntimeReason(ctx, runtimeMOBIKEReason("skipped", oldIP, newIP, "tunnel unavailable"))
		return nil
	}

	res, err := tunnel.MOBIKE(ctx, swu.MOBIKERequest{
		DeviceID: deviceID,
		OldIP:    oldIP,
		NewIP:    newIP,
		At:       time.Now(),
	})
	if err != nil {
		i.updateRuntimeReason(ctx, runtimeMOBIKEReason("failed", oldIP, newIP, err.Error()))
		return fmt.Errorf("MOBIKE update failed: %w", err)
	}
	status := "complete"
	if res.Rekeyed {
		status = "rekeyed"
	}
	i.updateRuntimeReason(ctx, runtimeMOBIKEReason(status, oldIP, newIP, res.Reason))
	return nil
}

func (i *Instance) updateRuntimeReason(ctx context.Context, reason string) {
	if i == nil {
		return
	}
	i.mu.Lock()
	i.state.LastReason = strings.TrimSpace(reason)
	i.state.UpdatedAt = time.Now()
	i.mu.Unlock()
	i.notify(ctx)
	i.dispatchRuntimeState(ctx)
}

func runtimeMOBIKEReason(status, oldIP, newIP, detail string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		status = "update"
	}
	reason := "mobike " + status
	if oldIP = strings.TrimSpace(oldIP); oldIP != "" {
		reason += " " + oldIP
	}
	if newIP = strings.TrimSpace(newIP); newIP != "" {
		if oldIP != "" {
			reason += " ->"
		}
		reason += " " + newIP
	}
	if detail = strings.TrimSpace(detail); detail != "" {
		reason += ": " + detail
	}
	return reason
}

func (i *Instance) Status() string {
	if i == nil {
		return "VoWiFi: STOPPED"
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.stopped {
		return "VoWiFi: STOPPED"
	}
	return "VoWiFi: " + string(i.state.Phase)
}

func (i *Instance) Obs() map[string]interface{} {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return map[string]interface{}{
		"device_id":                    i.state.DeviceID,
		"phase":                        string(i.state.Phase),
		"sms_ready":                    i.state.SMSReady,
		"ims_ready":                    i.state.IMSReady,
		"ims_recovery_pending":         i.state.IMSRecoveryPending,
		"ims_recovery_retry_after":     i.state.IMSRecoveryRetryAfter,
		"ims_recovery_next_attempt_at": i.state.IMSRecoveryNextAttemptAt,
		"ims_recovery_reason":          i.state.IMSRecoveryReason,
		"updated":                      i.state.UpdatedAt,
	}
}

func (i *Instance) dispatchRuntimeState(ctx context.Context) {
	if i == nil {
		return
	}
	i.mu.RLock()
	dispatcher := i.dispatch
	snapshot := runtimeStateSnapshot(i.state)
	i.mu.RUnlock()
	_, _ = eventhost.DispatchRuntimeStateSnapshot(ctx, dispatcher, snapshot)
}

func runtimeStateSnapshot(state State) eventhost.RuntimeStateSnapshot {
	return eventhost.RuntimeStateSnapshot{
		DevID:                    state.DeviceID,
		Phase:                    string(state.Phase),
		DataplaneMode:            state.DataplaneMode,
		SIMReady:                 state.SIMReady,
		AccessReady:              state.AccessReady,
		TunnelReady:              state.TunnelReady,
		IMSReady:                 state.IMSReady,
		SMSReady:                 state.SMSReady,
		RegStatus:                state.RegStatus,
		RegStatusText:            state.RegStatusText,
		NetworkMode:              state.NetworkMode,
		LastErrorClass:           state.LastErrorClass,
		LastError:                state.LastError,
		LastReason:               state.LastReason,
		IMSRecoveryPending:       state.IMSRecoveryPending,
		IMSRecoveryRetryAfter:    state.IMSRecoveryRetryAfter,
		IMSRecoveryNextAttemptAt: state.IMSRecoveryNextAttemptAt,
		IMSRecoveryReason:        state.IMSRecoveryReason,
		Time:                     state.UpdatedAt,
	}
}

type EventDispatcher = eventhost.Dispatcher
type ModuleEvent = eventhost.Event
type EventSMSReceived = eventhost.SMSReceived
type EventSMSSent = eventhost.SMSSent
type EventUSSDUpdated = eventhost.USSDUpdated
type EventLocalNumberLearned = eventhost.LocalNumberLearned
type EventLogNotify = eventhost.LogNotify
type EventRuntimeStateSnapshot = eventhost.RuntimeStateSnapshot

type PrepareStartInput = identity.PrepareStartInput

func firstRuntimeNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}

func sipDomainRuntime(uri string) string {
	uri = strings.TrimSpace(uri)
	if strings.HasPrefix(strings.ToLower(uri), "sip:") {
		uri = uri[4:]
	}
	if _, host, ok := strings.Cut(uri, "@"); ok {
		if semi := strings.IndexByte(host, ';'); semi >= 0 {
			host = host[:semi]
		}
		return strings.Trim(strings.TrimSpace(host), "<>")
	}
	return ""
}

func cloneRuntimeSIPHeaders(headers map[string][]string) map[string][]string {
	out := make(map[string][]string, len(headers))
	for key, values := range headers {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func cloneRuntimeHeaderMap(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		out[key] = value
	}
	return out
}

func tunnelManagerForStart(req StartRequest) (swu.TunnelManager, error) {
	if req.TunnelManager != nil {
		return req.TunnelManager, nil
	}
	if req.Dataplane.TunnelManager != nil {
		return req.Dataplane.TunnelManager, nil
	}
	if !explicitUserspaceDataplane(req.Dataplane.Mode) {
		return nil, nil
	}
	factory := req.TunnelManagerFactory
	if factory == nil {
		factory = req.Dataplane.TunnelManagerFactory
	}
	if factory == nil {
		factory = defaultTunnelManagerForStart
	}
	manager, err := factory(req)
	if err != nil {
		return nil, err
	}
	if manager == nil {
		return nil, errors.New("SWU tunnel manager factory returned nil")
	}
	return manager, nil
}

func explicitUserspaceDataplane(mode string) bool {
	return strings.TrimSpace(mode) == swu.DataplaneModeUserspace
}

func defaultTunnelManagerForStart(req StartRequest) (swu.TunnelManager, error) {
	if req.SIM == nil {
		return nil, errors.New("SWU tunnel manager requires SIM AKA provider")
	}
	return swu.NewTUNIKETunnelManager(
		swu.IKEPacketTunnelManagerConfig{
			SIM:                     req.SIM,
			Reauthentication:        req.EAPReauthentication,
			OnReauthenticationState: req.OnEAPReauthenticationState,
		},
		swu.TUNTunnelManagerConfig{
			TUN:                 swu.TUNDeviceConfig{Name: strings.TrimSpace(req.Dataplane.TUNName)},
			DisableRouting:      req.Dataplane.DisableTUNRouting,
			DefaultRoutes:       true,
			ProtectEPDGRoutes:   true,
			MTU:                 req.Dataplane.TUNMTU,
			Addresses:           append([]string(nil), req.Dataplane.TUNAddresses...),
			EPDGRouteExclusions: cloneRuntimeEPDGRouteExclusions(req.Dataplane.TUNEPDGExclusions),
			Routes:              append([]swu.TUNRoute(nil), req.Dataplane.TUNRoutes...),
			Rules:               append([]swu.TUNRule(nil), req.Dataplane.TUNRules...),
		},
	), nil
}

func cloneRuntimeEPDGRouteExclusions(in []swu.EPDGRouteExclusion) []swu.EPDGRouteExclusion {
	out := make([]swu.EPDGRouteExclusion, len(in))
	for i, item := range in {
		out[i] = item
		out[i].Tables = append([]string(nil), item.Tables...)
	}
	return out
}

func buildTunnelConfig(req StartRequest, modem Modem) swu.TunnelConfig {
	cfg := swu.TunnelConfig{
		DeviceID:  strings.TrimSpace(req.DeviceID),
		TraceID:   strings.TrimSpace(req.TraceID),
		Mode:      req.Dataplane.Mode,
		IMSI:      strings.TrimSpace(req.Profile.IMSI),
		MCC:       strings.TrimSpace(req.Profile.MCC),
		MNC:       strings.TrimSpace(req.Profile.MNC),
		IMEI:      strings.TrimSpace(req.Profile.IMEI),
		Proxy:     toSWUProxyConfig(req.Proxy),
		StartedAt: time.Now(),
	}
	if modem != nil {
		cfg.LocalInterface = strings.TrimSpace(modem.DeviceID())
	}
	if req.Prepared != nil {
		cfg.EPDGAddress = strings.TrimSpace(req.Prepared.EPDGAddr)
		cfg.EPDGSource = strings.TrimSpace(req.Prepared.EPDGSource)
		if cfg.IMSI == "" {
			cfg.IMSI = strings.TrimSpace(req.Prepared.Profile.IMSI)
		}
		if cfg.MCC == "" {
			cfg.MCC = strings.TrimSpace(req.Prepared.Profile.MCC)
		}
		if cfg.MNC == "" {
			cfg.MNC = strings.TrimSpace(req.Prepared.Profile.MNC)
		}
		if cfg.IMEI == "" {
			cfg.IMEI = strings.TrimSpace(req.Prepared.Profile.IMEI)
		}
		cfg.Identity = swu.IMSIdentity{
			IMPI:   strings.TrimSpace(req.Prepared.IMSIdentity.IMPI),
			IMPU:   strings.TrimSpace(req.Prepared.IMSIdentity.IMPU),
			Domain: strings.TrimSpace(req.Prepared.IMSIdentity.Domain),
		}
	}
	return cfg
}

func toSWUProxyConfig(p *ProxyConfig) *swu.ProxyConfig {
	if p == nil {
		return nil
	}
	return &swu.ProxyConfig{
		ID:       p.ID,
		URL:      p.URL,
		Address:  p.Address,
		Addr:     p.Addr,
		Username: p.Username,
		Password: p.Password,
		Country:  p.Country,
		Enabled:  p.Enabled,
	}
}
