package swu

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/boa-z/vowifi-go/engine/swu/esp"
	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

var (
	ErrInvalidPacketTunnel       = errors.New("invalid swu packet tunnel")
	ErrPacketTunnelClosed        = errors.New("swu packet tunnel closed")
	ErrUnsupportedInnerPacket    = errors.New("unsupported inner packet")
	ErrInvalidChildSARekeyPolicy = errors.New("invalid swu child sa rekey policy")
)

type ESPPacketTransport interface {
	SendESPPacket(context.Context, []byte) error
}

type ESPPacketReceiver interface {
	ReadESPPacket(context.Context) ([]byte, error)
}

type ESPPacketReadWriteTransport interface {
	ESPPacketTransport
	ESPPacketReceiver
}

type ESPPacketTransportFunc func(context.Context, []byte) error

func (f ESPPacketTransportFunc) SendESPPacket(ctx context.Context, packet []byte) error {
	if f == nil {
		return fmt.Errorf("%w: transport is nil", ErrInvalidPacketTunnel)
	}
	return f(ctx, packet)
}

type ChildSARekeyHandler func(context.Context) (ikev2.ChildSAResult, error)

type ChildSARekeyScheduler interface {
	RekeyChildSA(context.Context) (TunnelResult, error)
	NextChildSARekeyDue() (time.Time, bool)
	RunChildSARekeyDue(context.Context, time.Time) (ChildSARekeyDecision, error)
	ChildSARekeySnapshot() ChildSARekeySnapshot
}

type ChildSARekeyAction uint8

const (
	ChildSARekeyNoAction ChildSARekeyAction = iota
	ChildSARekeyDue
)

func (a ChildSARekeyAction) String() string {
	switch a {
	case ChildSARekeyNoAction:
		return "none"
	case ChildSARekeyDue:
		return "rekey"
	default:
		return fmt.Sprintf("child sa rekey action %d", a)
	}
}

type ChildSARekeyPolicy struct {
	Lifetime time.Duration
	LeadTime time.Duration
	Disabled bool
}

type ChildSARekeyDecision struct {
	Action        ChildSARekeyAction
	EstablishedAt time.Time
	DueAt         time.Time
	ExpiresAt     time.Time
	NextDue       time.Time
	Age           time.Duration
	TimeToExpire  time.Duration
	Lifetime      time.Duration
	LeadTime      time.Duration
	Expired       bool
	Reason        string
}

type ChildSARekeySnapshot struct {
	Enabled       bool
	EstablishedAt time.Time
	DueAt         time.Time
	ExpiresAt     time.Time
	Lifetime      time.Duration
	LeadTime      time.Duration
}

type ChildSARekeyWindow struct {
	Enabled       bool
	Due           bool
	Expired       bool
	EstablishedAt time.Time
	DueAt         time.Time
	ExpiresAt     time.Time
	Age           time.Duration
	TimeToRekey   time.Duration
	TimeToExpire  time.Duration
	Lifetime      time.Duration
	LeadTime      time.Duration
}

type ChildSARekeyState struct {
	policy        ChildSARekeyPolicy
	establishedAt time.Time
	enabled       bool
}

func NewChildSARekeyState(policy ChildSARekeyPolicy, establishedAt time.Time) (*ChildSARekeyState, error) {
	normalized, enabled, err := normalizeChildSARekeyPolicy(policy)
	if err != nil {
		return nil, err
	}
	if establishedAt.IsZero() {
		establishedAt = time.Now()
	}
	return &ChildSARekeyState{
		policy:        normalized,
		establishedAt: establishedAt,
		enabled:       enabled,
	}, nil
}

func (s *ChildSARekeyState) Advance(now time.Time) ChildSARekeyDecision {
	if now.IsZero() {
		now = time.Now()
	}
	if s == nil || !s.enabled {
		return ChildSARekeyDecision{
			Action: ChildSARekeyNoAction,
			Reason: "rekey disabled",
		}
	}
	decision := s.decision(now, ChildSARekeyNoAction, "child sa rekey not due")
	if decision.Expired {
		decision.Action = ChildSARekeyDue
		decision.Reason = "child sa lifetime expired"
	} else if !now.Before(decision.DueAt) {
		decision.Action = ChildSARekeyDue
		decision.Reason = "child sa rekey due"
	}
	return decision
}

func (s *ChildSARekeyState) RecordRekey(at time.Time) {
	if s == nil || !s.enabled {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	s.establishedAt = at
}

func (s *ChildSARekeyState) Snapshot() ChildSARekeySnapshot {
	if s == nil || !s.enabled {
		return ChildSARekeySnapshot{}
	}
	return ChildSARekeySnapshot{
		Enabled:       true,
		EstablishedAt: s.establishedAt,
		DueAt:         s.dueAt(),
		ExpiresAt:     s.expiresAt(),
		Lifetime:      s.policy.Lifetime,
		LeadTime:      s.policy.LeadTime,
	}
}

func (s *ChildSARekeyState) NextDue() (time.Time, bool) {
	if s == nil || !s.enabled {
		return time.Time{}, false
	}
	return s.dueAt(), true
}

func (s *ChildSARekeyState) decision(now time.Time, action ChildSARekeyAction, reason string) ChildSARekeyDecision {
	window := s.window(now)
	return ChildSARekeyDecision{
		Action:        action,
		EstablishedAt: s.establishedAt,
		DueAt:         window.DueAt,
		ExpiresAt:     window.ExpiresAt,
		NextDue:       window.DueAt,
		Age:           window.Age,
		TimeToExpire:  window.TimeToExpire,
		Lifetime:      s.policy.Lifetime,
		LeadTime:      s.policy.LeadTime,
		Expired:       window.Expired,
		Reason:        reason,
	}
}

func (s *ChildSARekeyState) dueAt() time.Time {
	return s.establishedAt.Add(s.policy.Lifetime - s.policy.LeadTime)
}

func (s *ChildSARekeyState) expiresAt() time.Time {
	return s.establishedAt.Add(s.policy.Lifetime)
}

func (s *ChildSARekeyState) window(now time.Time) ChildSARekeyWindow {
	window, _ := ChildSARekeyWindowFor(s.policy, s.establishedAt, now)
	return window
}

func ChildSARekeyWindowFor(policy ChildSARekeyPolicy, establishedAt, now time.Time) (ChildSARekeyWindow, error) {
	normalized, enabled, err := normalizeChildSARekeyPolicy(policy)
	if err != nil {
		return ChildSARekeyWindow{}, err
	}
	if !enabled {
		return ChildSARekeyWindow{}, nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	if establishedAt.IsZero() {
		establishedAt = now
	}
	expiresAt := establishedAt.Add(normalized.Lifetime)
	dueAt := expiresAt.Add(-normalized.LeadTime)
	age := time.Duration(0)
	if now.After(establishedAt) {
		age = now.Sub(establishedAt)
	}
	timeToRekey := time.Duration(0)
	if now.Before(dueAt) {
		timeToRekey = dueAt.Sub(now)
	}
	timeToExpire := time.Duration(0)
	if now.Before(expiresAt) {
		timeToExpire = expiresAt.Sub(now)
	}
	return ChildSARekeyWindow{
		Enabled:       true,
		Due:           !now.Before(dueAt),
		Expired:       !now.Before(expiresAt),
		EstablishedAt: establishedAt,
		DueAt:         dueAt,
		ExpiresAt:     expiresAt,
		Age:           age,
		TimeToRekey:   timeToRekey,
		TimeToExpire:  timeToExpire,
		Lifetime:      normalized.Lifetime,
		LeadTime:      normalized.LeadTime,
	}, nil
}

func normalizeChildSARekeyPolicy(policy ChildSARekeyPolicy) (ChildSARekeyPolicy, bool, error) {
	if policy.Lifetime < 0 {
		return ChildSARekeyPolicy{}, false, fmt.Errorf("%w: lifetime is negative", ErrInvalidChildSARekeyPolicy)
	}
	if policy.LeadTime < 0 {
		return ChildSARekeyPolicy{}, false, fmt.Errorf("%w: lead time is negative", ErrInvalidChildSARekeyPolicy)
	}
	if policy.Disabled || policy.Lifetime == 0 {
		return ChildSARekeyPolicy{Disabled: true}, false, nil
	}
	if policy.LeadTime >= policy.Lifetime {
		return ChildSARekeyPolicy{}, false, fmt.Errorf("%w: lead time must be less than lifetime", ErrInvalidChildSARekeyPolicy)
	}
	return policy, true, nil
}

type ESPPacketTransportCloser interface {
	ESPPacketTransport
	Close(context.Context) error
}

type NATTKeepaliveSender interface {
	SendNATTKeepalive(context.Context) error
}

type PacketTunnelStats struct {
	OutboundInnerPackets uint64
	OutboundInnerBytes   uint64
	OutboundESPPackets   uint64
	OutboundESPBytes     uint64
	OutboundErrors       uint64
	InboundInnerPackets  uint64
	InboundInnerBytes    uint64
	InboundESPPackets    uint64
	InboundESPBytes      uint64
	InboundErrors        uint64
	ReplayDrops          uint64
	InvalidDrops         uint64
	UnsupportedDrops     uint64
}

type PacketTunnelPacket struct {
	SPI        uint32
	Sequence   uint32
	NextHeader uint8
	Payload    []byte
}

type PacketTunnelSession interface {
	TunnelSession
	SendInnerPacket(context.Context, []byte) error
	SendInnerPacketWithNextHeader(context.Context, uint8, []byte) error
	ReceiveESPPacket(context.Context, []byte) (PacketTunnelPacket, error)
	PacketStats() PacketTunnelStats
}

type PacketTunnelReadSession interface {
	PacketTunnelSession
	ReadInnerPacket(context.Context) (PacketTunnelPacket, error)
}

type PacketSessionConfig struct {
	Result        TunnelResult
	ChildSA       ikev2.ChildSAResult
	OutboundSA    *esp.SA
	InboundSA     *esp.SA
	Transport     ESPPacketTransport
	Random        io.Reader
	MOBIKEHandler func(context.Context, MOBIKERequest) (MOBIKEResult, error)
	RekeyHandler  ChildSARekeyHandler
	RekeyPolicy   ChildSARekeyPolicy
	MOBIKENAT     *MOBIKENATState
	Liveness      *IKELivenessState
	DPDHandler    func(context.Context) error
	CloseHandler  func(context.Context) error
}

type PacketSession struct {
	mu            sync.Mutex
	result        TunnelResult
	outbound      *esp.SA
	inbound       *esp.SA
	transport     ESPPacketTransport
	random        io.Reader
	mobikeHandler func(context.Context, MOBIKERequest) (MOBIKEResult, error)
	rekeyHandler  ChildSARekeyHandler
	rekeyState    *ChildSARekeyState
	mobikeNAT     *MOBIKENATState
	liveness      *IKELivenessState
	dpdHandler    func(context.Context) error
	closeHandler  func(context.Context) error
	stats         PacketTunnelStats
	closed        bool
}

var (
	_ PacketTunnelSession     = (*PacketSession)(nil)
	_ PacketTunnelReadSession = (*PacketSession)(nil)
	_ MOBIKENATObserver       = (*PacketSession)(nil)
	_ IKELivenessController   = (*PacketSession)(nil)
	_ ChildSARekeyController  = (*PacketSession)(nil)
	_ ChildSARekeyScheduler   = (*PacketSession)(nil)
)

func NewPacketSession(cfg PacketSessionConfig) (*PacketSession, error) {
	if cfg.Transport == nil {
		return nil, fmt.Errorf("%w: transport is nil", ErrInvalidPacketTunnel)
	}
	outbound, inbound, err := packetSAs(cfg)
	if err != nil {
		return nil, err
	}
	result := cfg.Result
	if isZeroTunnelResult(result) {
		result.Ready = true
		result.IKEEstablished = true
		result.IPsecEstablished = true
	}
	if result.Mode == "" {
		result.Mode = DataplaneModeUserspace
	}
	if result.Reason == "" {
		result.Reason = "packet tunnel ready"
	}
	if result.EstablishedAt.IsZero() {
		result.EstablishedAt = time.Now()
	}
	rekeyState, err := NewChildSARekeyState(cfg.RekeyPolicy, result.EstablishedAt)
	if err != nil {
		return nil, err
	}
	return &PacketSession{
		result:        result,
		outbound:      outbound,
		inbound:       inbound,
		transport:     cfg.Transport,
		random:        cfg.Random,
		mobikeHandler: cfg.MOBIKEHandler,
		rekeyHandler:  cfg.RekeyHandler,
		rekeyState:    rekeyState,
		mobikeNAT:     cfg.MOBIKENAT,
		liveness:      cfg.Liveness,
		dpdHandler:    cfg.DPDHandler,
		closeHandler:  cfg.CloseHandler,
	}, nil
}

func NextHeaderForInnerPacket(packet []byte) (uint8, error) {
	if len(packet) == 0 {
		return 0, fmt.Errorf("%w: packet is empty", ErrUnsupportedInnerPacket)
	}
	switch packet[0] >> 4 {
	case 4:
		return esp.NextHeaderIPv4, nil
	case 6:
		return esp.NextHeaderIPv6, nil
	default:
		return 0, fmt.Errorf("%w: ip version %d", ErrUnsupportedInnerPacket, packet[0]>>4)
	}
}

func (s *PacketSession) Result() TunnelResult {
	if s == nil {
		return TunnelResult{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneTunnelResult(s.result)
}

func (s *PacketSession) RekeyChildSA(ctx context.Context) (TunnelResult, error) {
	return s.rekeyChildSA(ctx, time.Time{})
}

func (s *PacketSession) rekeyChildSA(ctx context.Context, rekeyedAt time.Time) (TunnelResult, error) {
	if s == nil {
		return TunnelResult{}, ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		return TunnelResult{}, err
	}
	s.mu.Lock()
	closed := s.closed
	handler := s.rekeyHandler
	s.mu.Unlock()
	if closed {
		return TunnelResult{}, ErrPacketTunnelClosed
	}
	if handler == nil {
		return TunnelResult{}, fmt.Errorf("%w: child sa rekey handler is nil", ErrInvalidPacketTunnel)
	}
	child, err := handler(ctx)
	if err != nil {
		return TunnelResult{}, err
	}
	outbound, inbound, err := packetSAs(PacketSessionConfig{ChildSA: child})
	if err != nil {
		return TunnelResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return TunnelResult{}, ErrPacketTunnelClosed
	}
	s.outbound = outbound
	s.inbound = inbound
	s.result.IKEEstablished = true
	s.result.IPsecEstablished = true
	s.result.Ready = true
	s.result.ChildSAIdentifier = childSAIdentifier(child)
	s.result.Reason = "child sa rekeyed"
	if s.rekeyState != nil {
		s.rekeyState.RecordRekey(rekeyedAt)
	}
	if local := firstPacketNonEmpty(
		childConfigurationAddress(child, ikev2.ConfigInternalIPv4Address),
		childConfigurationAddress(child, ikev2.ConfigInternalIPv6Address),
	); local != "" {
		s.result.LocalInnerIP = local
	}
	if dns := childConfigurationDNS(child); len(dns) > 0 {
		s.result.DNSServers = dns
	}
	return cloneTunnelResult(s.result), nil
}

func (s *PacketSession) AdvanceChildSARekey(ctx context.Context, now time.Time) (ChildSARekeyDecision, error) {
	if s == nil {
		return ChildSARekeyDecision{}, ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		return ChildSARekeyDecision{}, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ChildSARekeyDecision{}, ErrPacketTunnelClosed
	}
	if s.rekeyState == nil {
		s.mu.Unlock()
		return ChildSARekeyDecision{Action: ChildSARekeyNoAction, Reason: "rekey disabled"}, nil
	}
	decision := s.rekeyState.Advance(now)
	s.mu.Unlock()
	if decision.Action != ChildSARekeyDue {
		return decision, nil
	}
	_, err := s.rekeyChildSA(ctx, now)
	return decision, err
}

func (s *PacketSession) RunChildSARekeyDue(ctx context.Context, now time.Time) (ChildSARekeyDecision, error) {
	decision, err := s.AdvanceChildSARekey(ctx, now)
	if err != nil || decision.Action != ChildSARekeyDue {
		return decision, err
	}
	if nextDue, ok := s.NextChildSARekeyDue(); ok {
		decision.NextDue = nextDue
	}
	return decision, nil
}

func (s *PacketSession) NextChildSARekeyDue() (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.rekeyState == nil {
		return time.Time{}, false
	}
	return s.rekeyState.NextDue()
}

func (s *PacketSession) ChildSARekeySnapshot() ChildSARekeySnapshot {
	if s == nil {
		return ChildSARekeySnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rekeyState == nil {
		return ChildSARekeySnapshot{}
	}
	return s.rekeyState.Snapshot()
}

func (s *PacketSession) MOBIKE(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
	if s == nil {
		return MOBIKEResult{}, ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		return MOBIKEResult{}, err
	}
	s.mu.Lock()
	closed := s.closed
	handler := s.mobikeHandler
	result := s.result
	s.mu.Unlock()
	if closed {
		return MOBIKEResult{}, ErrPacketTunnelClosed
	}
	if handler != nil {
		res, err := handler(ctx, req)
		if err != nil {
			return MOBIKEResult{}, err
		}
		res = completeMOBIKEResult(res, req, result, "mobike updated")
		s.applyMOBIKEResult(res)
		return res, nil
	}
	return MOBIKEResult{
		Rekeyed:          false,
		OuterLocalIP:     firstPacketNonEmpty(req.NewIP, req.OldIP, result.EPDGAddress),
		LocalInnerIP:     result.LocalInnerIP,
		RemoteInnerIP:    result.RemoteInnerIP,
		DNSServers:       append([]string(nil), result.DNSServers...),
		IKEEstablished:   result.IKEEstablished,
		IPsecEstablished: result.IPsecEstablished,
		Reason:           "mobike unsupported",
		UpdatedAt:        time.Now(),
	}, nil
}

func (s *PacketSession) ObserveMOBIKENAT(ctx context.Context, obs MOBIKENATObservation) (MOBIKENATChange, MOBIKEResult, error) {
	if s == nil {
		return MOBIKENATChange{}, MOBIKEResult{}, ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		return MOBIKENATChange{}, MOBIKEResult{}, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return MOBIKENATChange{}, MOBIKEResult{}, ErrPacketTunnelClosed
	}
	if s.mobikeNAT == nil {
		s.mobikeNAT = NewMOBIKENATState(MOBIKENATStateConfig{MOBIKESupported: s.result.MOBIKESupported})
	}
	change := s.mobikeNAT.Observe(obs)
	s.mu.Unlock()
	if !change.RequiresMOBIKEUpdate {
		return change, MOBIKEResult{}, nil
	}
	res, err := s.MOBIKE(ctx, change.Request)
	return change, res, err
}

func (s *PacketSession) MOBIKENATSnapshot() (MOBIKENATEndpoint, time.Time) {
	if s == nil {
		return MOBIKENATEndpoint{}, time.Time{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mobikeNAT == nil {
		return MOBIKENATEndpoint{}, time.Time{}
	}
	return s.mobikeNAT.Snapshot()
}

func (s *PacketSession) AdvanceIKELiveness(ctx context.Context, now time.Time) (IKELivenessDecision, error) {
	if s == nil {
		return IKELivenessDecision{}, ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		return IKELivenessDecision{}, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return IKELivenessDecision{}, ErrPacketTunnelClosed
	}
	if s.liveness == nil {
		cfg := IKELivenessConfig{}
		if s.dpdHandler == nil {
			cfg.DisableDPD = true
		}
		establishedAt := s.result.EstablishedAt
		liveness, err := NewIKELivenessState(cfg, establishedAt)
		if err != nil {
			s.mu.Unlock()
			return IKELivenessDecision{}, err
		}
		s.liveness = liveness
	}
	decision := s.liveness.Advance(now)
	transport := s.transport
	dpdHandler := s.dpdHandler
	s.mu.Unlock()
	switch decision.Action {
	case IKELivenessSendKeepalive:
		sender, ok := transport.(NATTKeepaliveSender)
		if !ok {
			return decision, fmt.Errorf("%w: transport cannot send NAT-T keepalive", ErrInvalidPacketTunnel)
		}
		if err := sender.SendNATTKeepalive(ctx); err != nil {
			return decision, err
		}
	case IKELivenessSendDPD:
		if dpdHandler == nil {
			return decision, fmt.Errorf("%w: DPD handler is nil", ErrInvalidPacketTunnel)
		}
		err := dpdHandler(ctx)
		s.RecordIKELivenessResult(now, err == nil)
		if err != nil {
			if snapshot := s.IKELivenessSnapshot(); snapshot.Dead {
				decision.Dead = true
				decision.MissedDPDProbes = snapshot.MissedDPDProbes
				decision.Reason = firstPacketNonEmpty(err.Error(), "dpd probe failed")
				s.markTunnelNotReady(ikeLivenessDeadReason(decision))
			}
		}
		return decision, err
	case IKELivenessDeclareDead:
		s.markTunnelNotReady(ikeLivenessDeadReason(decision))
	}
	return decision, nil
}

func (s *PacketSession) RecordIKELivenessInbound(at time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.liveness != nil {
		s.liveness.RecordInbound(at)
	}
}

func (s *PacketSession) RecordIKELivenessOutbound(at time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.liveness != nil {
		s.liveness.RecordOutbound(at)
	}
}

func (s *PacketSession) RecordIKELivenessResult(at time.Time, ok bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.liveness != nil {
		s.liveness.RecordLivenessResult(at, ok)
	}
}

func (s *PacketSession) IKELivenessSnapshot() IKELivenessSnapshot {
	if s == nil {
		return IKELivenessSnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.liveness == nil {
		return IKELivenessSnapshot{}
	}
	return s.liveness.Snapshot()
}

func (s *PacketSession) markTunnelNotReady(reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.result.Ready = false
	s.result.IKEEstablished = false
	s.result.IPsecEstablished = false
	s.result.Reason = firstPacketNonEmpty(reason, "ike liveness dead")
}

func ikeLivenessDeadReason(decision IKELivenessDecision) string {
	reason := firstPacketNonEmpty(decision.Reason, "dpd timeout")
	if strings.Contains(strings.ToLower(reason), "ike liveness") {
		return reason
	}
	return "ike liveness dead: " + reason
}

func completeMOBIKEResult(res MOBIKEResult, req MOBIKERequest, current TunnelResult, fallbackReason string) MOBIKEResult {
	if res.OuterLocalIP == "" {
		res.OuterLocalIP = firstPacketNonEmpty(req.NewIP, req.OldIP, current.EPDGAddress)
	}
	if res.LocalInnerIP == "" {
		res.LocalInnerIP = current.LocalInnerIP
	}
	if res.RemoteInnerIP == "" {
		res.RemoteInnerIP = current.RemoteInnerIP
	}
	if len(res.DNSServers) == 0 {
		res.DNSServers = append([]string(nil), current.DNSServers...)
	} else {
		res.DNSServers = append([]string(nil), res.DNSServers...)
	}
	if !res.IKEEstablished {
		res.IKEEstablished = current.IKEEstablished
	}
	if !res.IPsecEstablished {
		res.IPsecEstablished = current.IPsecEstablished
	}
	if res.Reason == "" {
		res.Reason = fallbackReason
	}
	if res.UpdatedAt.IsZero() {
		res.UpdatedAt = time.Now()
	}
	return res
}

func (s *PacketSession) applyMOBIKEResult(res MOBIKEResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.result.LocalInnerIP = res.LocalInnerIP
	s.result.RemoteInnerIP = res.RemoteInnerIP
	s.result.DNSServers = append([]string(nil), res.DNSServers...)
	s.result.IKEEstablished = res.IKEEstablished
	s.result.IPsecEstablished = res.IPsecEstablished
	s.result.Ready = res.IKEEstablished && res.IPsecEstablished
	if res.Reason != "" {
		s.result.Reason = res.Reason
	}
}

func (s *PacketSession) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	handler := s.closeHandler
	transport := s.transport
	s.mu.Unlock()
	var err error
	if handler != nil {
		err = handler(ctx)
	}
	if closer, ok := transport.(ESPPacketTransportCloser); ok {
		if closeErr := closer.Close(ctx); err == nil {
			err = closeErr
		}
	}
	return err
}

func (s *PacketSession) SendInnerPacket(ctx context.Context, inner []byte) error {
	nextHeader, err := NextHeaderForInnerPacket(inner)
	if err != nil {
		if s != nil {
			s.recordOutboundError(true)
		}
		return err
	}
	return s.SendInnerPacketWithNextHeader(ctx, nextHeader, inner)
}

func (s *PacketSession) SendInnerPacketWithNextHeader(ctx context.Context, nextHeader uint8, inner []byte) error {
	if s == nil {
		return ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		s.recordOutboundError(false)
		return err
	}
	innerCopy := append([]byte(nil), inner...)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrPacketTunnelClosed
	}
	if s.outbound == nil || s.transport == nil {
		s.stats.OutboundErrors++
		s.mu.Unlock()
		return fmt.Errorf("%w: outbound sa or transport is nil", ErrInvalidPacketTunnel)
	}
	if err := validateInnerPacketNextHeader(nextHeader, innerCopy); err != nil {
		s.stats.OutboundErrors++
		s.stats.UnsupportedDrops++
		s.mu.Unlock()
		return err
	}
	packet, err := s.outbound.Seal(nextHeader, innerCopy, esp.SealOptions{Random: s.random})
	transport := s.transport
	if err != nil {
		s.stats.OutboundErrors++
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	if err := transport.SendESPPacket(ctx, packet); err != nil {
		s.recordOutboundError(false)
		return err
	}
	s.mu.Lock()
	s.stats.OutboundInnerPackets++
	s.stats.OutboundInnerBytes += uint64(len(innerCopy))
	s.stats.OutboundESPPackets++
	s.stats.OutboundESPBytes += uint64(len(packet))
	if s.liveness != nil {
		s.liveness.RecordOutbound(time.Now())
	}
	s.mu.Unlock()
	return nil
}

func (s *PacketSession) ReceiveESPPacket(ctx context.Context, packet []byte) (PacketTunnelPacket, error) {
	if s == nil {
		return PacketTunnelPacket{}, ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		s.recordInboundError(err)
		return PacketTunnelPacket{}, err
	}
	packetCopy := append([]byte(nil), packet...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return PacketTunnelPacket{}, ErrPacketTunnelClosed
	}
	if s.inbound == nil {
		s.stats.InboundErrors++
		return PacketTunnelPacket{}, fmt.Errorf("%w: inbound sa is nil", ErrInvalidPacketTunnel)
	}
	out, err := s.inbound.Open(packetCopy)
	if err != nil {
		s.recordInboundErrorLocked(err)
		return PacketTunnelPacket{}, err
	}
	if err := validateInnerPacketNextHeader(out.NextHeader, out.Payload); err != nil {
		s.recordInboundErrorLocked(err)
		return PacketTunnelPacket{}, err
	}
	payload := append([]byte(nil), out.Payload...)
	s.stats.InboundInnerPackets++
	s.stats.InboundInnerBytes += uint64(len(payload))
	s.stats.InboundESPPackets++
	s.stats.InboundESPBytes += uint64(len(packetCopy))
	if s.liveness != nil {
		s.liveness.RecordInbound(time.Now())
	}
	return PacketTunnelPacket{
		SPI:        out.SPI,
		Sequence:   out.Sequence,
		NextHeader: out.NextHeader,
		Payload:    payload,
	}, nil
}

func (s *PacketSession) ReadInnerPacket(ctx context.Context) (PacketTunnelPacket, error) {
	if s == nil {
		return PacketTunnelPacket{}, ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		s.recordInboundError(err)
		return PacketTunnelPacket{}, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return PacketTunnelPacket{}, ErrPacketTunnelClosed
	}
	receiver, ok := s.transport.(ESPPacketReceiver)
	s.mu.Unlock()
	if !ok {
		err := fmt.Errorf("%w: transport cannot read ESP packets", ErrInvalidPacketTunnel)
		s.recordInboundError(err)
		return PacketTunnelPacket{}, err
	}
	packet, err := receiver.ReadESPPacket(ctx)
	if err != nil {
		s.recordInboundError(err)
		return PacketTunnelPacket{}, err
	}
	return s.ReceiveESPPacket(ctx, packet)
}

func (s *PacketSession) PacketStats() PacketTunnelStats {
	if s == nil {
		return PacketTunnelStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func validateInnerPacketNextHeader(nextHeader uint8, packet []byte) error {
	detected, err := NextHeaderForInnerPacket(packet)
	if err != nil {
		return err
	}
	if detected != nextHeader {
		return fmt.Errorf("%w: next header %d does not match inner packet", ErrUnsupportedInnerPacket, nextHeader)
	}
	return nil
}

func (s *PacketSession) recordOutboundError(unsupported bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.OutboundErrors++
	if unsupported {
		s.stats.UnsupportedDrops++
	}
}

func (s *PacketSession) recordInboundError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordInboundErrorLocked(err)
}

func (s *PacketSession) recordInboundErrorLocked(err error) {
	s.stats.InboundErrors++
	switch {
	case errors.Is(err, esp.ErrReplay):
		s.stats.ReplayDrops++
	case errors.Is(err, esp.ErrInvalidPacket):
		s.stats.InvalidDrops++
	case errors.Is(err, ErrUnsupportedInnerPacket):
		s.stats.UnsupportedDrops++
	}
}

func packetSAs(cfg PacketSessionConfig) (*esp.SA, *esp.SA, error) {
	outbound := cfg.OutboundSA
	inbound := cfg.InboundSA
	if outbound == nil || inbound == nil {
		if !hasChildSA(cfg.ChildSA) {
			return nil, nil, fmt.Errorf("%w: child sa is empty", ErrInvalidPacketTunnel)
		}
		if outbound == nil {
			var err error
			outbound, err = esp.NewOutboundSAFromChild(cfg.ChildSA)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: outbound: %v", ErrInvalidPacketTunnel, err)
			}
		}
		if inbound == nil {
			var err error
			inbound, err = esp.NewInboundSAFromChild(cfg.ChildSA)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: inbound: %v", ErrInvalidPacketTunnel, err)
			}
		}
	}
	outbound, err := cloneSA(outbound)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: outbound: %v", ErrInvalidPacketTunnel, err)
	}
	inbound, err = cloneSA(inbound)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: inbound: %v", ErrInvalidPacketTunnel, err)
	}
	return outbound, inbound, nil
}

func hasChildSA(child ikev2.ChildSAResult) bool {
	return len(child.LocalSPI) > 0 || len(child.RemoteSPI) > 0 ||
		len(child.Keys.Outbound.EncryptionKey) > 0 || len(child.Keys.Inbound.EncryptionKey) > 0
}

func cloneSA(sa *esp.SA) (*esp.SA, error) {
	if sa == nil {
		return nil, ErrInvalidPacketTunnel
	}
	cp := *sa
	cp.EncryptionKey = append([]byte(nil), sa.EncryptionKey...)
	cp.IntegrityKey = append([]byte(nil), sa.IntegrityKey...)
	return esp.NewSA(cp)
}

func contextReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func firstPacketNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}
