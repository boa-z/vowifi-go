package swu

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/iniwex5/vowifi-go/engine/swu/esp"
	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

func TestPacketSessionSendsAndReceivesIPv4AndIPv6(t *testing.T) {
	aToB := &captureESPPacketTransport{}
	a, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: aToB,
		Result:    TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true},
	})
	if err != nil {
		t.Fatalf("NewPacketSession(a) error = %v", err)
	}
	b, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(false),
		Transport: &captureESPPacketTransport{},
		Result:    TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true},
	})
	if err != nil {
		t.Fatalf("NewPacketSession(b) error = %v", err)
	}

	ipv4 := []byte{0x45, 0x00, 0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd}
	if err := a.SendInnerPacket(context.Background(), ipv4); err != nil {
		t.Fatalf("SendInnerPacket(ipv4) error = %v", err)
	}
	if len(aToB.packets) != 1 {
		t.Fatalf("captured packets=%d, want 1", len(aToB.packets))
	}
	got4, err := b.ReceiveESPPacket(context.Background(), aToB.packets[0])
	if err != nil {
		t.Fatalf("ReceiveESPPacket(ipv4) error = %v", err)
	}
	if got4.NextHeader != esp.NextHeaderIPv4 || !bytes.Equal(got4.Payload, ipv4) || got4.Sequence != 1 {
		t.Fatalf("got4=%+v payload=%x", got4, got4.Payload)
	}

	ipv6 := []byte{0x60, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef}
	if err := a.SendInnerPacket(context.Background(), ipv6); err != nil {
		t.Fatalf("SendInnerPacket(ipv6) error = %v", err)
	}
	got6, err := b.ReceiveESPPacket(context.Background(), aToB.packets[1])
	if err != nil {
		t.Fatalf("ReceiveESPPacket(ipv6) error = %v", err)
	}
	if got6.NextHeader != esp.NextHeaderIPv6 || !bytes.Equal(got6.Payload, ipv6) || got6.Sequence != 2 {
		t.Fatalf("got6=%+v payload=%x", got6, got6.Payload)
	}

	outStats := a.PacketStats()
	if outStats.OutboundInnerPackets != 2 || outStats.OutboundInnerBytes != uint64(len(ipv4)+len(ipv6)) || outStats.OutboundESPPackets != 2 {
		t.Fatalf("out stats=%+v", outStats)
	}
	inStats := b.PacketStats()
	if inStats.InboundInnerPackets != 2 || inStats.InboundInnerBytes != uint64(len(ipv4)+len(ipv6)) || inStats.InboundESPPackets != 2 {
		t.Fatalf("in stats=%+v", inStats)
	}
}

func TestPacketSessionDefaultResultIsReady(t *testing.T) {
	session, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: &captureESPPacketTransport{}})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	result := session.Result()
	if !result.IsReady() || result.Mode != DataplaneModeUserspace || result.Reason == "" {
		t.Fatalf("result=%+v", result)
	}
}

func TestPacketSessionReadInnerPacketUsesReadableTransport(t *testing.T) {
	wire := &captureESPPacketTransport{}
	a, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: wire})
	if err != nil {
		t.Fatalf("NewPacketSession(a) error = %v", err)
	}
	b, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(false), Transport: wire})
	if err != nil {
		t.Fatalf("NewPacketSession(b) error = %v", err)
	}
	inner := []byte{0x45, 0x00, 0x00, 0x14, 0xde, 0xad}
	if err := a.SendInnerPacket(context.Background(), inner); err != nil {
		t.Fatalf("SendInnerPacket() error = %v", err)
	}
	got, err := b.ReadInnerPacket(context.Background())
	if err != nil {
		t.Fatalf("ReadInnerPacket() error = %v", err)
	}
	if got.NextHeader != esp.NextHeaderIPv4 || !bytes.Equal(got.Payload, inner) {
		t.Fatalf("got=%+v payload=%x", got, got.Payload)
	}
	stats := b.PacketStats()
	if stats.InboundInnerPackets != 1 || stats.InboundESPPackets != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPacketSessionRejectsReplayAndCountsDrop(t *testing.T) {
	transport := &captureESPPacketTransport{}
	a, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: transport})
	if err != nil {
		t.Fatalf("NewPacketSession(a) error = %v", err)
	}
	b, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(false), Transport: &captureESPPacketTransport{}})
	if err != nil {
		t.Fatalf("NewPacketSession(b) error = %v", err)
	}
	if err := a.SendInnerPacket(context.Background(), []byte{0x45, 0x00, 0x00, 0x14}); err != nil {
		t.Fatalf("SendInnerPacket() error = %v", err)
	}
	if _, err := b.ReceiveESPPacket(context.Background(), transport.packets[0]); err != nil {
		t.Fatalf("ReceiveESPPacket(first) error = %v", err)
	}
	if _, err := b.ReceiveESPPacket(context.Background(), transport.packets[0]); !errors.Is(err, esp.ErrReplay) {
		t.Fatalf("ReceiveESPPacket(replay) err=%v, want ErrReplay", err)
	}
	stats := b.PacketStats()
	if stats.InboundErrors != 1 || stats.ReplayDrops != 1 || stats.InvalidDrops != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPacketSessionCloseRejectsTrafficAndClosesTransport(t *testing.T) {
	transport := &captureESPPacketTransport{}
	session, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: transport})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !transport.closed {
		t.Fatalf("transport was not closed")
	}
	if err := session.SendInnerPacket(context.Background(), []byte{0x45, 0x00}); !errors.Is(err, ErrPacketTunnelClosed) {
		t.Fatalf("SendInnerPacket() err=%v, want ErrPacketTunnelClosed", err)
	}
	if _, err := session.ReceiveESPPacket(context.Background(), []byte{1, 2, 3}); !errors.Is(err, ErrPacketTunnelClosed) {
		t.Fatalf("ReceiveESPPacket() err=%v, want ErrPacketTunnelClosed", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close(second) error = %v", err)
	}
}

func TestPacketSessionCountsUnsupportedInnerPacket(t *testing.T) {
	session, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: &captureESPPacketTransport{}})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if err := session.SendInnerPacket(context.Background(), []byte{0x10, 0x00}); !errors.Is(err, ErrUnsupportedInnerPacket) {
		t.Fatalf("SendInnerPacket() err=%v, want ErrUnsupportedInnerPacket", err)
	}
	stats := session.PacketStats()
	if stats.OutboundErrors != 1 || stats.UnsupportedDrops != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPacketSessionCountsTransportFailure(t *testing.T) {
	wantErr := errors.New("send failed")
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA: packetChildSA(true),
		Transport: ESPPacketTransportFunc(func(context.Context, []byte) error {
			return wantErr
		}),
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if err := session.SendInnerPacket(context.Background(), []byte{0x45, 0x00, 0x00, 0x14}); !errors.Is(err, wantErr) {
		t.Fatalf("SendInnerPacket() err=%v, want send failed", err)
	}
	stats := session.PacketStats()
	if stats.OutboundErrors != 1 || stats.OutboundInnerPackets != 0 || stats.OutboundESPPackets != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

type captureESPPacketTransport struct {
	packets [][]byte
	closed  bool
}

func (t *captureESPPacketTransport) SendESPPacket(ctx context.Context, packet []byte) error {
	t.packets = append(t.packets, append([]byte(nil), packet...))
	return nil
}

func (t *captureESPPacketTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	if len(t.packets) == 0 {
		return nil, errors.New("no packets")
	}
	packet := append([]byte(nil), t.packets[0]...)
	t.packets = t.packets[1:]
	return packet, nil
}

func (t *captureESPPacketTransport) Close(ctx context.Context) error {
	t.closed = true
	return nil
}

func packetChildSA(aToB bool) ikev2.ChildSAResult {
	aOutbound := ikev2.ESPKeys{
		EncryptionKey: bytes.Repeat([]byte{0x10}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x20}, 32),
	}
	aInbound := ikev2.ESPKeys{
		EncryptionKey: bytes.Repeat([]byte{0x30}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x40}, 32),
	}
	child := ikev2.ChildSAResult{
		LocalSPI:  []byte{0x11, 0x11, 0x11, 0x11},
		RemoteSPI: []byte{0x22, 0x22, 0x22, 0x22},
		Keys: ikev2.ChildSAKeys{
			Profile:  ikev2.ESPKeyProfile{IntegrityID: ikev2.INTEG_HMAC_SHA2_256_128},
			Outbound: aOutbound,
			Inbound:  aInbound,
		},
	}
	if aToB {
		return child
	}
	child.LocalSPI = []byte{0x22, 0x22, 0x22, 0x22}
	child.RemoteSPI = []byte{0x11, 0x11, 0x11, 0x11}
	child.Keys.Outbound = aInbound
	child.Keys.Inbound = aOutbound
	return child
}
