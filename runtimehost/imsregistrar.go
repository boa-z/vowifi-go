package runtimehost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/boa-z/vowifi-go/runtimehost/identity"
	"github.com/boa-z/vowifi-go/runtimehost/messaging"
	"github.com/boa-z/vowifi-go/runtimehost/voiceclient"
)

type IMSRegisterTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, string, string) voiceclient.SIPRegisterTransport
type IMSVoiceTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, voiceclient.RegistrationBinding) voiceclient.SIPRequestTransport
type IMSSMSTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, voiceclient.RegistrationBinding, voiceclient.SIPRequestTransport) messaging.SMSTransport
type IMSUSSDTransportFactory func(IMSRegistrationConfig, voiceclient.IMSProfile, voiceclient.RegistrationBinding, voiceclient.SIPRequestTransport) messaging.USSDTransport
type imsRegistrationWaitFunc func(context.Context, time.Duration) bool

type WireIMSRegistrar struct {
	Transport              voiceclient.SIPRegisterTransport
	TransportFactory       IMSRegisterTransportFactory
	VoiceTransport         voiceclient.SIPRequestTransport
	VoiceFactory           IMSVoiceTransportFactory
	SMSTransport           messaging.SMSTransport
	SMSFactory             IMSSMSTransportFactory
	USSDTransport          messaging.USSDTransport
	USSDFactory            IMSUSSDTransportFactory
	RegistrarURI           string
	ContactURI             string
	ContactHost            string
	ContactPort            int
	Network                string
	ServerAddr             string
	LocalAddr              string
	Resolver               voiceclient.SIPServerResolver
	Timeout                time.Duration
	Expires                int
	DisableRefresh         bool
	RefreshInterval        time.Duration
	RefreshLead            time.Duration
	RefreshRetryInterval   time.Duration
	RecoveryBackoffInitial time.Duration
	RecoveryBackoffMax     time.Duration
	DisableKeepalive       bool
	KeepaliveInterval      time.Duration
	UserAgent              string
	CallID                 string
	CNonce                 string
	RetransmitInterval     time.Duration
	MaxRetransmitInterval  time.Duration
	MaxRetransmits         int
	SecurityPlanInstaller  voiceclient.SecurityPlanInstaller
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
	var defaultFlow *voiceclient.WireSIPFlow
	if transport == nil && r.TransportFactory != nil {
		transport = r.TransportFactory(cfg, profile, registrarURI, contactURI)
	}
	if transport == nil {
		defaultFlow = r.defaultSIPFlow(cfg)
		transport = defaultFlow
	}
	expires := r.Expires
	if expires <= 0 {
		expires = 3600
	}
	registerSession := voiceclient.RegisterSession{
		Transport:             transport,
		AKAProvider:           cfg.SIM,
		Profile:               profile,
		RegistrarURI:          registrarURI,
		ContactURI:            contactURI,
		CallID:                firstRuntimeNonEmpty(r.CallID, cfg.TraceID, cfg.DeviceID+"-ims-register"),
		CNonce:                firstRuntimeNonEmpty(r.CNonce, cfg.TraceID, cfg.DeviceID),
		Expires:               expires,
		SecurityPlanInstaller: r.SecurityPlanInstaller,
		SecurityLocalAddr:     firstRuntimeNonEmpty(r.ContactHost, profile.LocalIP, r.LocalAddr),
		SecurityRemoteAddr:    r.ServerAddr,
	}
	result, err := registerSession.Register(ctx)
	if err != nil {
		if defaultFlow != nil {
			_ = defaultFlow.Close()
		}
		return IMSRegistrationResult{
			Registered: result.Registered,
			StatusCode: result.StatusCode,
			Reason:     result.Reason,
			Server:     result.Binding.PublicIdentity,
			Profile:    profile,
			Binding:    result.Binding,
		}, err
	}
	registeredAt := time.Now()
	expiresAt, refreshDelay, nextRefreshAt := imsRegistrationSchedule(r, result.Binding, registerSession, registeredAt, result.Registered)
	voiceTransport := r.voiceTransport(cfg, profile, result.Binding, defaultFlow)
	smsTransport := r.smsTransport(cfg, profile, result.Binding, voiceTransport)
	ussdTransport := r.ussdTransport(cfg, profile, result.Binding, voiceTransport)
	maintenance := newIMSRegistrationMaintenance(defaultFlow, registerSession, result, r, cfg, profile, registeredAt)
	var closeRegistration func(context.Context) error
	var recoverRegistration func(context.Context) (IMSRegistrationResult, error)
	if maintenance != nil {
		closeRegistration = maintenance.Close
		recoverRegistration = maintenance.Recover
	}
	return IMSRegistrationResult{
		Registered:     result.Registered,
		StatusCode:     result.StatusCode,
		Reason:         firstRuntimeNonEmpty(result.Reason, "ims registered"),
		Server:         firstRuntimeNonEmpty(result.Binding.PublicIdentity, profile.Domain),
		Profile:        profile,
		Binding:        result.Binding,
		RegisteredAt:   registeredAt,
		ExpiresAt:      expiresAt,
		RefreshDelay:   refreshDelay,
		NextRefreshAt:  nextRefreshAt,
		VoiceTransport: voiceTransport,
		SMSTransport:   smsTransport,
		USSDTransport:  ussdTransport,
		Close:          closeRegistration,
		Recover:        recoverRegistration,
	}, nil
}

func (r WireIMSRegistrar) voiceTransport(cfg IMSRegistrationConfig, profile voiceclient.IMSProfile, binding voiceclient.RegistrationBinding, fallback voiceclient.SIPRequestTransport) voiceclient.SIPRequestTransport {
	if r.VoiceTransport != nil {
		return r.VoiceTransport
	}
	if r.VoiceFactory != nil {
		return r.VoiceFactory(cfg, profile, binding)
	}
	if fallback != nil {
		return fallback
	}
	return voiceclient.WireSIPTransport{
		Network:               r.Network,
		ServerAddr:            r.ServerAddr,
		LocalAddr:             r.LocalAddr,
		Resolver:              r.resolverForConfig(cfg),
		Timeout:               r.Timeout,
		RetransmitInterval:    r.RetransmitInterval,
		MaxRetransmitInterval: r.MaxRetransmitInterval,
		MaxRetransmits:        r.MaxRetransmits,
	}
}

func (r WireIMSRegistrar) defaultSIPFlow(cfg IMSRegistrationConfig) *voiceclient.WireSIPFlow {
	return &voiceclient.WireSIPFlow{
		Network:               r.Network,
		ServerAddr:            r.ServerAddr,
		LocalAddr:             r.LocalAddr,
		Resolver:              r.resolverForConfig(cfg),
		Timeout:               r.Timeout,
		RetransmitInterval:    r.RetransmitInterval,
		MaxRetransmitInterval: r.MaxRetransmitInterval,
		MaxRetransmits:        r.MaxRetransmits,
	}
}

func (r WireIMSRegistrar) resolverForConfig(cfg IMSRegistrationConfig) voiceclient.SIPServerResolver {
	if r.Resolver != nil {
		return r.Resolver
	}
	if candidates := preparedPCSCFCandidates(cfg); len(candidates) > 0 {
		return preparedPCSCFResolver{
			Candidates: candidates,
			DNSServers: append([]string(nil), cfg.Tunnel.DNSServers...),
			Timeout:    r.Timeout,
		}
	}
	if len(cfg.Tunnel.DNSServers) == 0 {
		return nil
	}
	return voiceclient.NetSIPResolver{
		DNSServers: append([]string(nil), cfg.Tunnel.DNSServers...),
		Timeout:    r.Timeout,
	}
}

type preparedPCSCFResolver struct {
	Candidates []string
	DNSServers []string
	Timeout    time.Duration
}

func (r preparedPCSCFResolver) ResolveSIPServer(ctx context.Context, network, uri string) (string, error) {
	targets, err := r.ResolveSIPServers(ctx, network, uri)
	if err != nil {
		return "", err
	}
	if len(targets) == 0 {
		return "", errors.New("SIP resolver returned no P-CSCF targets")
	}
	return targets[0], nil
}

func (r preparedPCSCFResolver) ResolveSIPServers(ctx context.Context, network, uri string) ([]string, error) {
	resolver := voiceclient.NetSIPResolver{
		DNSServers: append([]string(nil), r.DNSServers...),
		Timeout:    r.Timeout,
	}
	var out []string
	var lastErr error
	for _, candidate := range r.Candidates {
		candidateURI := pcscfCandidateSIPURI(candidate)
		if candidateURI == "" {
			continue
		}
		targets, err := resolver.ResolveSIPServers(ctx, network, candidateURI)
		if err != nil {
			lastErr = err
			continue
		}
		out = appendRuntimeTargets(out, targets...)
	}
	if len(out) == 0 && strings.TrimSpace(uri) != "" {
		targets, err := resolver.ResolveSIPServers(ctx, network, uri)
		if err != nil {
			lastErr = err
		} else {
			out = appendRuntimeTargets(out, targets...)
		}
	}
	if len(out) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return out, nil
}

func preparedPCSCFCandidates(cfg IMSRegistrationConfig) []string {
	if cfg.Prepared == nil {
		return nil
	}
	return appendRuntimeTargets(nil, cfg.Prepared.PCSCFFQDNs...)
}

func pcscfCandidateSIPURI(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return ""
	}
	lower := strings.ToLower(candidate)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		return candidate
	}
	if ip := net.ParseIP(strings.Trim(candidate, "[]")); ip != nil && strings.Contains(ip.String(), ":") {
		return "sip:[" + ip.String() + "]"
	}
	return "sip:" + candidate
}

func appendRuntimeTargets(out []string, targets ...string) []string {
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		duplicate := false
		for _, existing := range out {
			if existing == target {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, target)
		}
	}
	return out
}

type imsRegistrationMaintenance struct {
	flow          *voiceclient.WireSIPFlow
	session       voiceclient.RegisterSession
	config        WireIMSRegistrar
	runtimeConfig IMSRegistrationConfig
	profile       voiceclient.IMSProfile

	recoverMu      sync.Mutex
	mu             sync.Mutex
	registered     bool
	statusCode     int
	reason         string
	binding        voiceclient.RegistrationBinding
	registeredAt   time.Time
	nextCSeq       int
	authHeader     string
	authHeaderName string
	authState      voiceclient.DigestAuthState
	recoveryCount  int
	recoveryState  IMSRegistrationRecoveryState
	waitFunc       imsRegistrationWaitFunc
	cancel         context.CancelFunc
	done           chan struct{}
	wg             sync.WaitGroup
	closed         bool
}

func newIMSRegistrationMaintenance(flow *voiceclient.WireSIPFlow, session voiceclient.RegisterSession, result voiceclient.RegisterResult, config WireIMSRegistrar, runtimeConfig IMSRegistrationConfig, profile voiceclient.IMSProfile, registeredAt time.Time) *imsRegistrationMaintenance {
	if flow == nil {
		return nil
	}
	nextCSeq := result.NextCSeq
	if nextCSeq <= 0 {
		nextCSeq = 1
	}
	m := &imsRegistrationMaintenance{
		flow:          flow,
		session:       session,
		config:        config,
		runtimeConfig: runtimeConfig,
		profile:       profile,

		registered:     result.Registered,
		statusCode:     result.StatusCode,
		reason:         result.Reason,
		binding:        result.Binding,
		registeredAt:   registeredAt,
		nextCSeq:       nextCSeq,
		authHeader:     result.AuthHeader,
		authHeaderName: result.AuthHeaderName,
		authState:      result.AuthState,
	}
	if result.Registered && (!config.DisableRefresh || !config.DisableKeepalive) {
		ctx, cancel := context.WithCancel(context.Background())
		m.cancel = cancel
		m.done = make(chan struct{})
		if !config.DisableRefresh {
			m.wg.Add(1)
			go func() {
				defer m.wg.Done()
				m.refreshLoop(ctx)
			}()
		}
		if !config.DisableKeepalive {
			m.wg.Add(1)
			go func() {
				defer m.wg.Done()
				m.keepaliveLoop(ctx)
			}()
		}
		go func() {
			m.wg.Wait()
			close(m.done)
		}()
	}
	return m
}

func (m *imsRegistrationMaintenance) Recover(ctx context.Context) (IMSRegistrationResult, error) {
	if m == nil {
		return IMSRegistrationResult{}, errors.New("IMS registration maintenance unavailable")
	}
	if err := m.recoverRegistration(ctx, errors.New("requested IMS registration recovery"), 0); err != nil {
		return IMSRegistrationResult{}, err
	}
	return m.result("IMS registration recovered"), nil
}

func (m *imsRegistrationMaintenance) result(defaultReason string) IMSRegistrationResult {
	if m == nil {
		return IMSRegistrationResult{}
	}
	m.mu.Lock()
	registered := m.registered
	statusCode := m.statusCode
	reason := m.reason
	binding := m.binding
	registeredAt := m.registeredAt
	session := m.session
	recoveryState := m.recoveryState
	m.mu.Unlock()

	if statusCode == 0 && registered {
		statusCode = 200
	}
	expiresAt, refreshDelay, nextRefreshAt := imsRegistrationSchedule(m.config, binding, session, registeredAt, registered)
	voiceTransport := m.config.voiceTransport(m.runtimeConfig, m.profile, binding, m.flow)
	smsTransport := m.config.smsTransport(m.runtimeConfig, m.profile, binding, voiceTransport)
	ussdTransport := m.config.ussdTransport(m.runtimeConfig, m.profile, binding, voiceTransport)
	return IMSRegistrationResult{
		Registered:     registered,
		StatusCode:     statusCode,
		Reason:         firstRuntimeNonEmpty(reason, defaultReason),
		Server:         firstRuntimeNonEmpty(binding.PublicIdentity, m.profile.Domain),
		Profile:        m.profile,
		Binding:        binding,
		RegisteredAt:   registeredAt,
		ExpiresAt:      expiresAt,
		RefreshDelay:   refreshDelay,
		NextRefreshAt:  nextRefreshAt,
		RecoveryState:  recoveryState,
		VoiceTransport: voiceTransport,
		SMSTransport:   smsTransport,
		USSDTransport:  ussdTransport,
		Close:          m.Close,
		Recover:        m.Recover,
	}
}

func (m *imsRegistrationMaintenance) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	cancel := m.cancel
	done := m.done
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	m.mu.Lock()
	registered := m.registered
	req := voiceclient.DeregisterRequest{
		Binding:        m.binding,
		CSeq:           m.nextCSeq,
		AuthHeader:     m.authHeader,
		AuthHeaderName: m.authHeaderName,
		AuthState:      m.authState,
	}
	m.registered = false
	m.mu.Unlock()

	var deregisterErr error
	if registered {
		_, deregisterErr = m.session.Deregister(ctx, req)
	}
	return errors.Join(deregisterErr, m.flow.Close())
}

func (m *imsRegistrationMaintenance) refreshLoop(ctx context.Context) {
	for {
		if !m.wait(ctx, m.refreshDelay()) {
			return
		}
		for {
			if err := m.refresh(ctx); err != nil {
				if !m.wait(ctx, m.refreshRetryInterval()) {
					return
				}
				continue
			}
			break
		}
	}
}

func (m *imsRegistrationMaintenance) keepaliveLoop(ctx context.Context) {
	for {
		if !m.wait(ctx, m.keepaliveInterval()) {
			return
		}
		if !m.isRegistered() {
			continue
		}
		if err := m.flow.SendCRLFKeepalive(ctx); err != nil {
			if ctx.Err() != nil || errors.Is(err, voiceclient.ErrSIPFlowClosed) {
				return
			}
			_ = m.recoverRegistration(ctx, err, 0)
		}
	}
}

func (m *imsRegistrationMaintenance) wait(ctx context.Context, delay time.Duration) bool {
	if m != nil && m.waitFunc != nil {
		return m.waitFunc(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (m *imsRegistrationMaintenance) refresh(ctx context.Context) error {
	m.mu.Lock()
	if !m.registered {
		m.mu.Unlock()
		return nil
	}
	req := voiceclient.RefreshRequest{
		Binding:        m.binding,
		CSeq:           m.nextCSeq,
		AuthHeader:     m.authHeader,
		AuthHeaderName: m.authHeaderName,
		AuthState:      m.authState,
	}
	m.mu.Unlock()

	result, err := m.session.Refresh(ctx, req)
	if err != nil {
		if m.shouldRecoverRegistration(result, err) {
			return m.recoverRegistration(ctx, err, result.RetryAfter)
		}
		return err
	}
	m.mu.Lock()
	if result.Refreshed {
		m.registered = true
		m.statusCode = result.StatusCode
		m.reason = result.Reason
		m.binding = result.Binding
		m.registeredAt = time.Now()
		m.nextCSeq = result.NextCSeq
		m.authHeader = result.AuthHeader
		m.authHeaderName = result.AuthHeaderName
		m.authState = result.AuthState
	}
	m.mu.Unlock()
	return nil
}

func (m *imsRegistrationMaintenance) recoverRegistration(ctx context.Context, cause error, retryAfter time.Duration) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	m.recoverMu.Lock()
	defer m.recoverMu.Unlock()

	m.mu.Lock()
	if m.closed || !m.registered {
		m.mu.Unlock()
		return nil
	}
	if !m.recoveryState.NextAttemptAt.IsZero() {
		delay := time.Until(m.recoveryState.NextAttemptAt)
		m.mu.Unlock()
		if delay > 0 && !m.wait(ctx, delay) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return context.Canceled
		}
		m.mu.Lock()
		if m.closed || !m.registered {
			m.mu.Unlock()
			return nil
		}
	}
	m.mu.Unlock()
	switchedTarget, err := m.resetFlowForRecovery(ctx)
	if err != nil {
		return err
	}
	if retryAfter > 0 && !switchedTarget {
		m.scheduleRecoveryRetryAfter(cause, retryAfter)
		if !m.wait(ctx, retryAfter) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return context.Canceled
		}
	}
	m.mu.Lock()
	if m.closed || !m.registered {
		m.mu.Unlock()
		return nil
	}
	m.recoveryCount++
	m.recoveryState.Attempts = m.recoveryCount
	m.recoveryState.LastReason = strings.TrimSpace(fmt.Sprint(cause))
	m.recoveryState.LastError = ""
	m.recoveryState.LastAttemptAt = time.Now()
	m.recoveryState.LastSwitchedTarget = switchedTarget
	session := m.session
	session.CallID = imsRecoveryCallID(session.CallID, m.recoveryCount)
	m.mu.Unlock()

	result, err := session.Register(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m.recordRecoveryFailure(cause, err)
		return fmt.Errorf("IMS registration recovery failed after %v: %w", cause, err)
	}
	if !result.Registered {
		m.mu.Lock()
		m.registered = false
		m.statusCode = result.StatusCode
		m.reason = result.Reason
		m.recordRecoveryFailureLocked(cause, fmt.Errorf("%d %s", result.StatusCode, result.Reason))
		m.mu.Unlock()
		return fmt.Errorf("IMS registration recovery did not register: %d %s", result.StatusCode, result.Reason)
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.session = session
	m.registered = true
	m.statusCode = result.StatusCode
	m.reason = result.Reason
	m.binding = result.Binding
	m.registeredAt = time.Now()
	m.nextCSeq = result.NextCSeq
	m.authHeader = result.AuthHeader
	m.authHeaderName = result.AuthHeaderName
	m.authState = result.AuthState
	m.recordRecoverySuccessLocked()
	m.mu.Unlock()
	return nil
}

func (m *imsRegistrationMaintenance) scheduleRecoveryRetryAfter(cause error, delay time.Duration) {
	if m == nil || delay <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || !m.registered {
		return
	}
	m.recoveryState.LastReason = strings.TrimSpace(fmt.Sprint(cause))
	m.recoveryState.NextAttemptAt = time.Now().Add(delay)
}

func (m *imsRegistrationMaintenance) recordRecoveryFailure(cause, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recordRecoveryFailureLocked(cause, err)
}

func (m *imsRegistrationMaintenance) recordRecoveryFailureLocked(cause, err error) {
	if m == nil {
		return
	}
	m.recoveryState.ConsecutiveFailures++
	m.recoveryState.LastReason = strings.TrimSpace(fmt.Sprint(cause))
	m.recoveryState.LastError = strings.TrimSpace(fmt.Sprint(err))
	if m.recoveryState.LastAttemptAt.IsZero() {
		m.recoveryState.LastAttemptAt = time.Now()
	}
	delay := m.recoveryBackoffDelayLocked()
	if delay > 0 {
		m.recoveryState.NextAttemptAt = time.Now().Add(delay)
	} else {
		m.recoveryState.NextAttemptAt = time.Time{}
	}
}

func (m *imsRegistrationMaintenance) recordRecoverySuccessLocked() {
	if m == nil {
		return
	}
	m.recoveryState.ConsecutiveFailures = 0
	m.recoveryState.LastError = ""
	m.recoveryState.NextAttemptAt = time.Time{}
	m.recoveryState.LastSucceededAt = time.Now()
}

func (m *imsRegistrationMaintenance) recoveryBackoffDelayLocked() time.Duration {
	if m == nil || m.recoveryState.ConsecutiveFailures <= 0 {
		return 0
	}
	base := m.config.RecoveryBackoffInitial
	if base <= 0 {
		return 0
	}
	maxDelay := m.config.RecoveryBackoffMax
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}
	delay := base
	for i := 1; i < m.recoveryState.ConsecutiveFailures; i++ {
		if delay >= maxDelay/2 {
			delay = maxDelay
			break
		}
		delay *= 2
	}
	if delay > maxDelay {
		delay = maxDelay
	}
	return delay
}

func (m *imsRegistrationMaintenance) resetFlowForRecovery(ctx context.Context) (bool, error) {
	switched, err := m.flow.ResetToNextTarget()
	if err == nil {
		return switched, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	return false, fmt.Errorf("IMS registration recovery reset failed: %w", err)
}

func (m *imsRegistrationMaintenance) shouldRecoverRegistration(result voiceclient.RefreshResult, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, voiceclient.ErrSIPFlowClosed) ||
		errors.Is(err, voiceclient.ErrInvalidChallenge) || errors.Is(err, voiceclient.ErrInvalidAuthenticationInfo) {
		return false
	}
	if errors.Is(err, voiceclient.ErrRegistrationRejected) {
		return isRecoverableIMSRegistrationStatus(result.StatusCode)
	}
	return true
}

func isRecoverableIMSRegistrationStatus(code int) bool {
	switch code {
	case 408, 430, 480, 481, 500, 502, 503, 504, 580:
		return true
	default:
		return code >= 500 && code < 600
	}
}

func imsRecoveryCallID(base string, n int) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = "vowifi-go-register"
	}
	if n <= 0 {
		n = 1
	}
	return base + "-recovery-" + strconv.Itoa(n)
}

func (m *imsRegistrationMaintenance) isRegistered() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.registered
}

func (m *imsRegistrationMaintenance) refreshDelay() time.Duration {
	m.mu.Lock()
	expires := m.binding.Expires
	sessionExpires := m.session.Expires
	m.mu.Unlock()
	return imsRegistrationRefreshDelay(m.config, expires, sessionExpires)
}

func imsRegistrationSchedule(config WireIMSRegistrar, binding voiceclient.RegistrationBinding, session voiceclient.RegisterSession, registeredAt time.Time, registered bool) (time.Time, time.Duration, time.Time) {
	if !registered || registeredAt.IsZero() {
		return time.Time{}, 0, time.Time{}
	}
	expires := binding.Expires
	if expires <= 0 {
		expires = session.Expires
	}
	if expires <= 0 {
		expires = 3600
	}
	expiresAt := registeredAt.Add(time.Duration(expires) * time.Second)
	if config.DisableRefresh {
		return expiresAt, 0, time.Time{}
	}
	refreshDelay := imsRegistrationRefreshDelay(config, binding.Expires, session.Expires)
	if refreshDelay <= 0 {
		return expiresAt, 0, time.Time{}
	}
	return expiresAt, refreshDelay, registeredAt.Add(refreshDelay)
}

func imsRegistrationRefreshDelay(config WireIMSRegistrar, bindingExpires, sessionExpires int) time.Duration {
	if config.RefreshInterval > 0 {
		return config.RefreshInterval
	}
	expires := bindingExpires
	if expires <= 0 {
		expires = sessionExpires
	}
	if expires <= 0 {
		expires = 3600
	}
	ttl := time.Duration(expires) * time.Second
	lead := config.RefreshLead
	if lead <= 0 {
		lead = ttl / 10
		if lead < 5*time.Second {
			lead = 5 * time.Second
		}
		if lead > time.Minute {
			lead = time.Minute
		}
	}
	delay := ttl - lead
	if delay <= 0 {
		delay = ttl / 2
	}
	if delay <= 0 {
		delay = 30 * time.Second
	}
	return delay
}

func (m *imsRegistrationMaintenance) refreshRetryInterval() time.Duration {
	if m.config.RefreshRetryInterval > 0 {
		return m.config.RefreshRetryInterval
	}
	return 30 * time.Second
}

func (m *imsRegistrationMaintenance) keepaliveInterval() time.Duration {
	if m.config.KeepaliveInterval > 0 {
		return m.config.KeepaliveInterval
	}
	return 25 * time.Second
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
		LocalIP:   firstRuntimeNonEmpty(r.ContactHost, cfg.Tunnel.LocalInnerIP),
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
	imsi := strings.TrimSpace(cfg.Profile.IMSI)
	if cfg.Prepared != nil {
		if imsi == "" {
			imsi = strings.TrimSpace(cfg.Prepared.Profile.IMSI)
		}
		if mcc == "" {
			mcc = strings.TrimSpace(cfg.Prepared.Profile.MCC)
		}
		if mnc == "" {
			mnc = strings.TrimSpace(cfg.Prepared.Profile.MNC)
		}
		if mcc == "" {
			mcc = strings.TrimSpace(cfg.Prepared.EffectiveCarrier.MCC)
		}
		if mnc == "" {
			mnc = strings.TrimSpace(cfg.Prepared.EffectiveCarrier.MNC)
		}
	}
	if mcc == "" && len(imsi) >= 3 {
		mcc = imsi[:3]
	}
	if mnc == "" && len(imsi) >= 6 {
		mnc = imsi[3:6]
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
