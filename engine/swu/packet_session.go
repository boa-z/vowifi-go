package swu

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu/esp"
	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

var (
	ErrInvalidPacketTunnel    = errors.New("invalid swu packet tunnel")
	ErrPacketTunnelClosed     = errors.New("swu packet tunnel closed")
	ErrUnsupportedInnerPacket = errors.New("unsupported inner packet")
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

type ESPPacketTransportCloser interface {
	ESPPacketTransport
	Close(context.Context) error
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
	closeHandler  func(context.Context) error
	stats         PacketTunnelStats
	closed        bool
}

var (
	_ PacketTunnelSession     = (*PacketSession)(nil)
	_ PacketTunnelReadSession = (*PacketSession)(nil)
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
	if result == (TunnelResult{}) {
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
	return &PacketSession{
		result:        result,
		outbound:      outbound,
		inbound:       inbound,
		transport:     cfg.Transport,
		random:        cfg.Random,
		mobikeHandler: cfg.MOBIKEHandler,
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
	return s.result
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
		return handler(ctx, req)
	}
	return MOBIKEResult{
		Rekeyed:          false,
		OuterLocalIP:     firstPacketNonEmpty(req.NewIP, req.OldIP, result.EPDGAddress),
		LocalInnerIP:     result.LocalInnerIP,
		RemoteInnerIP:    result.RemoteInnerIP,
		IKEEstablished:   result.IKEEstablished,
		IPsecEstablished: result.IPsecEstablished,
		Reason:           "mobike unsupported",
		UpdatedAt:        time.Now(),
	}, nil
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
	payload := append([]byte(nil), out.Payload...)
	s.stats.InboundInnerPackets++
	s.stats.InboundInnerBytes += uint64(len(payload))
	s.stats.InboundESPPackets++
	s.stats.InboundESPBytes += uint64(len(packetCopy))
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
