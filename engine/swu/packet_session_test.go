package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/engine/swu/esp"
	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
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

func TestPacketSessionResultClonesDNSServers(t *testing.T) {
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result: TunnelResult{
			Ready:            true,
			IKEEstablished:   true,
			IPsecEstablished: true,
			DNSServers:       []string{"10.0.0.1"},
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	result := session.Result()
	result.DNSServers[0] = "198.51.100.53"
	if got := session.Result().DNSServers[0]; got != "10.0.0.1" {
		t.Fatalf("Result() DNS=%q, want original", got)
	}
}

func TestPacketSessionRekeyChildSAReplacesSAsAndResult(t *testing.T) {
	transport := &captureESPPacketTransport{}
	newChild := packetRekeyChildSA(true)
	rekeyCalls := 0
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: transport,
		Result: TunnelResult{
			Ready:             true,
			Mode:              DataplaneModeUserspace,
			IKEEstablished:    true,
			IPsecEstablished:  true,
			LocalInnerIP:      "10.0.0.2",
			RemoteInnerIP:     "0.0.0.0/0",
			DNSServers:        []string{"10.0.0.1"},
			ChildSAIdentifier: "11111111/22222222",
			Reason:            "packet tunnel ready",
		},
		RekeyHandler: func(context.Context) (ikev2.ChildSAResult, error) {
			rekeyCalls++
			return newChild, nil
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if err := session.SendInnerPacket(context.Background(), []byte{0x45, 0x00, 0x00, 0x14}); err != nil {
		t.Fatalf("SendInnerPacket(before rekey) error = %v", err)
	}
	statsBefore := session.PacketStats()

	result, err := session.RekeyChildSA(context.Background())
	if err != nil {
		t.Fatalf("RekeyChildSA() error = %v", err)
	}
	if rekeyCalls != 1 {
		t.Fatalf("rekey calls=%d, want 1", rekeyCalls)
	}
	if !result.IsReady() || result.ChildSAIdentifier != "33333333/44444444" ||
		result.Reason != "child sa rekeyed" || result.LocalInnerIP != "10.0.0.2" ||
		len(result.DNSServers) != 1 || result.DNSServers[0] != "10.0.0.1" {
		t.Fatalf("result=%+v", result)
	}
	if stats := session.PacketStats(); stats != statsBefore {
		t.Fatalf("stats changed during rekey: before=%+v after=%+v", statsBefore, stats)
	}

	if err := session.SendInnerPacket(context.Background(), []byte{0x45, 0x00, 0x00, 0x14, 0xaa}); err != nil {
		t.Fatalf("SendInnerPacket(after rekey) error = %v", err)
	}
	if gotSPI := binary.BigEndian.Uint32(transport.packets[len(transport.packets)-1][0:4]); gotSPI != 0x44444444 {
		t.Fatalf("outbound SPI=%08x, want new remote SPI", gotSPI)
	}
	peerOutbound, err := esp.NewOutboundSAFromChild(packetRekeyChildSA(false))
	if err != nil {
		t.Fatalf("NewOutboundSAFromChild(peer) error = %v", err)
	}
	packet, err := peerOutbound.Seal(esp.NextHeaderIPv4, []byte{0x45, 0x00, 0x00, 0x14, 0xbb}, esp.SealOptions{
		Sequence: 1,
		IV:       bytes.Repeat([]byte{0x77}, 16),
	})
	if err != nil {
		t.Fatalf("Seal(peer) error = %v", err)
	}
	got, err := session.ReceiveESPPacket(context.Background(), packet)
	if err != nil {
		t.Fatalf("ReceiveESPPacket(after rekey) error = %v", err)
	}
	if got.SPI != 0x33333333 || got.NextHeader != esp.NextHeaderIPv4 {
		t.Fatalf("received packet=%+v", got)
	}
}

func TestPacketSessionRekeyChildSAErrorKeepsOldSAAndResult(t *testing.T) {
	wantErr := errors.New("rekey failed")
	transport := &captureESPPacketTransport{}
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: transport,
		Result: TunnelResult{
			Ready:             true,
			Mode:              DataplaneModeUserspace,
			IKEEstablished:    true,
			IPsecEstablished:  true,
			ChildSAIdentifier: "11111111/22222222",
			Reason:            "packet tunnel ready",
		},
		RekeyHandler: func(context.Context) (ikev2.ChildSAResult, error) {
			return ikev2.ChildSAResult{}, wantErr
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	statsBefore := session.PacketStats()
	_, err = session.RekeyChildSA(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("RekeyChildSA() err=%v, want rekey failed", err)
	}
	if result := session.Result(); result.ChildSAIdentifier != "11111111/22222222" || result.Reason != "packet tunnel ready" || !result.IsReady() {
		t.Fatalf("result changed after failed rekey: %+v", result)
	}
	if stats := session.PacketStats(); stats != statsBefore {
		t.Fatalf("stats changed during failed rekey: before=%+v after=%+v", statsBefore, stats)
	}
	if err := session.SendInnerPacket(context.Background(), []byte{0x45, 0x00, 0x00, 0x14}); err != nil {
		t.Fatalf("SendInnerPacket(after failed rekey) error = %v", err)
	}
	if gotSPI := binary.BigEndian.Uint32(transport.packets[0][0:4]); gotSPI != 0x22222222 {
		t.Fatalf("outbound SPI=%08x, want old remote SPI", gotSPI)
	}
}

func TestPacketSessionAdvanceChildSARekeyTriggersWhenDue(t *testing.T) {
	start := time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)
	newChild := packetRekeyChildSA(true)
	rekeyCalls := 0
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result: TunnelResult{
			Ready:             true,
			Mode:              DataplaneModeUserspace,
			IKEEstablished:    true,
			IPsecEstablished:  true,
			ChildSAIdentifier: "11111111/22222222",
			EstablishedAt:     start,
		},
		RekeyHandler: func(context.Context) (ikev2.ChildSAResult, error) {
			rekeyCalls++
			return newChild, nil
		},
		RekeyPolicy: ChildSARekeyPolicy{
			Lifetime: time.Minute,
			LeadTime: 10 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	early, err := session.AdvanceChildSARekey(context.Background(), start.Add(49*time.Second))
	if err != nil {
		t.Fatalf("AdvanceChildSARekey(early) error = %v", err)
	}
	if early.Action != ChildSARekeyNoAction || rekeyCalls != 0 || !early.NextDue.Equal(start.Add(50*time.Second)) {
		t.Fatalf("early decision=%+v rekeyCalls=%d", early, rekeyCalls)
	}

	dueAt := start.Add(50 * time.Second)
	due, err := session.AdvanceChildSARekey(context.Background(), dueAt)
	if err != nil {
		t.Fatalf("AdvanceChildSARekey(due) error = %v", err)
	}
	if due.Action != ChildSARekeyDue || rekeyCalls != 1 {
		t.Fatalf("due decision=%+v rekeyCalls=%d", due, rekeyCalls)
	}
	if result := session.Result(); !result.IsReady() || result.ChildSAIdentifier != "33333333/44444444" ||
		result.Reason != "child sa rekeyed" {
		t.Fatalf("result after due rekey=%+v", result)
	}
	snapshot := session.ChildSARekeySnapshot()
	if !snapshot.Enabled || !snapshot.EstablishedAt.Equal(dueAt) || !snapshot.DueAt.Equal(dueAt.Add(50*time.Second)) {
		t.Fatalf("rekey snapshot=%+v", snapshot)
	}
}

func TestPacketSessionRunChildSARekeyDueUpdatesNextDue(t *testing.T) {
	start := time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)
	newChild := packetRekeyChildSA(true)
	rekeyCalls := 0
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result: TunnelResult{
			Ready:             true,
			Mode:              DataplaneModeUserspace,
			IKEEstablished:    true,
			IPsecEstablished:  true,
			ChildSAIdentifier: "11111111/22222222",
			EstablishedAt:     start,
		},
		RekeyHandler: func(context.Context) (ikev2.ChildSAResult, error) {
			rekeyCalls++
			return newChild, nil
		},
		RekeyPolicy: ChildSARekeyPolicy{
			Lifetime: time.Minute,
			LeadTime: 10 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	dueAt := start.Add(50 * time.Second)
	nextDue, ok := session.NextChildSARekeyDue()
	if !ok || !nextDue.Equal(dueAt) {
		t.Fatalf("NextChildSARekeyDue()=%v,%t want %v,true", nextDue, ok, dueAt)
	}

	decision, err := session.RunChildSARekeyDue(context.Background(), dueAt)
	if err != nil {
		t.Fatalf("RunChildSARekeyDue() error = %v", err)
	}
	if decision.Action != ChildSARekeyDue || rekeyCalls != 1 {
		t.Fatalf("decision=%+v rekeyCalls=%d", decision, rekeyCalls)
	}
	wantNext := dueAt.Add(50 * time.Second)
	if !decision.DueAt.Equal(dueAt) || !decision.NextDue.Equal(wantNext) {
		t.Fatalf("decision schedule=%+v want due=%v next=%v", decision, dueAt, wantNext)
	}
	nextDue, ok = session.NextChildSARekeyDue()
	if !ok || !nextDue.Equal(wantNext) {
		t.Fatalf("NextChildSARekeyDue(after)=%v,%t want %v,true", nextDue, ok, wantNext)
	}
}

func TestChildSARekeyWindowTracksSoftDueAndHardExpiry(t *testing.T) {
	start := time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)
	policy := ChildSARekeyPolicy{
		Lifetime: time.Hour,
		LeadTime: 5 * time.Minute,
	}
	before, err := ChildSARekeyWindowFor(policy, start, start.Add(54*time.Minute+59*time.Second))
	if err != nil {
		t.Fatalf("ChildSARekeyWindowFor(before) error = %v", err)
	}
	if !before.Enabled || before.Due || before.Expired ||
		!before.DueAt.Equal(start.Add(55*time.Minute)) ||
		!before.ExpiresAt.Equal(start.Add(time.Hour)) ||
		before.TimeToRekey != time.Second ||
		before.TimeToExpire != 5*time.Minute+time.Second {
		t.Fatalf("before window=%+v", before)
	}
	due, err := ChildSARekeyWindowFor(policy, start, start.Add(55*time.Minute))
	if err != nil {
		t.Fatalf("ChildSARekeyWindowFor(due) error = %v", err)
	}
	if !due.Due || due.Expired || due.TimeToRekey != 0 || due.TimeToExpire != 5*time.Minute {
		t.Fatalf("due window=%+v", due)
	}
	expired, err := ChildSARekeyWindowFor(policy, start, start.Add(time.Hour))
	if err != nil {
		t.Fatalf("ChildSARekeyWindowFor(expired) error = %v", err)
	}
	if !expired.Due || !expired.Expired || expired.TimeToExpire != 0 {
		t.Fatalf("expired window=%+v", expired)
	}
}

func TestChildSARekeyStateReportsExpiredLifetime(t *testing.T) {
	start := time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)
	state, err := NewChildSARekeyState(ChildSARekeyPolicy{
		Lifetime: time.Hour,
		LeadTime: 5 * time.Minute,
	}, start)
	if err != nil {
		t.Fatalf("NewChildSARekeyState() error = %v", err)
	}
	decision := state.Advance(start.Add(time.Hour))
	if decision.Action != ChildSARekeyDue ||
		decision.Reason != "child sa lifetime expired" ||
		!decision.Expired ||
		!decision.ExpiresAt.Equal(start.Add(time.Hour)) ||
		decision.TimeToExpire != 0 {
		t.Fatalf("expired decision=%+v", decision)
	}
	snapshot := state.Snapshot()
	if !snapshot.ExpiresAt.Equal(start.Add(time.Hour)) {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestPacketSessionRunChildSARekeyDueDisabledNoops(t *testing.T) {
	start := time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)
	rekeyCalls := 0
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result: TunnelResult{
			Ready:            true,
			IKEEstablished:   true,
			IPsecEstablished: true,
			EstablishedAt:    start,
		},
		RekeyHandler: func(context.Context) (ikev2.ChildSAResult, error) {
			rekeyCalls++
			return packetRekeyChildSA(true), nil
		},
		RekeyPolicy: ChildSARekeyPolicy{Disabled: true},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	nextDue, ok := session.NextChildSARekeyDue()
	if ok || !nextDue.IsZero() {
		t.Fatalf("NextChildSARekeyDue()=%v,%t want zero,false", nextDue, ok)
	}
	decision, err := session.RunChildSARekeyDue(context.Background(), start.Add(time.Hour))
	if err != nil {
		t.Fatalf("RunChildSARekeyDue(disabled) error = %v", err)
	}
	if decision.Action != ChildSARekeyNoAction || decision.Reason != "rekey disabled" || rekeyCalls != 0 {
		t.Fatalf("decision=%+v rekeyCalls=%d", decision, rekeyCalls)
	}
}

func TestPacketSessionRunChildSARekeyDueErrorKeepsScheduleAndResult(t *testing.T) {
	start := time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)
	wantErr := errors.New("rekey failed")
	rekeyCalls := 0
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result: TunnelResult{
			Ready:             true,
			Mode:              DataplaneModeUserspace,
			IKEEstablished:    true,
			IPsecEstablished:  true,
			ChildSAIdentifier: "11111111/22222222",
			Reason:            "packet tunnel ready",
			EstablishedAt:     start,
		},
		RekeyHandler: func(context.Context) (ikev2.ChildSAResult, error) {
			rekeyCalls++
			return ikev2.ChildSAResult{}, wantErr
		},
		RekeyPolicy: ChildSARekeyPolicy{
			Lifetime: time.Minute,
			LeadTime: 10 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	dueAt := start.Add(50 * time.Second)
	decision, err := session.RunChildSARekeyDue(context.Background(), dueAt)
	if !errors.Is(err, wantErr) {
		t.Fatalf("RunChildSARekeyDue() err=%v, want rekey failed", err)
	}
	if decision.Action != ChildSARekeyDue || rekeyCalls != 1 {
		t.Fatalf("decision=%+v rekeyCalls=%d", decision, rekeyCalls)
	}
	nextDue, ok := session.NextChildSARekeyDue()
	if !ok || !nextDue.Equal(dueAt) {
		t.Fatalf("NextChildSARekeyDue(after error)=%v,%t want %v,true", nextDue, ok, dueAt)
	}
	result := session.Result()
	if result.ChildSAIdentifier != "11111111/22222222" || result.Reason != "packet tunnel ready" || !result.IsReady() {
		t.Fatalf("result changed after failed due rekey: %+v", result)
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

func TestPacketSessionRejectsOutboundNextHeaderMismatchAndCountsDrop(t *testing.T) {
	transport := &captureESPPacketTransport{}
	session, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(true), Transport: transport})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if err := session.SendInnerPacketWithNextHeader(context.Background(), esp.NextHeaderIPv6, []byte{0x45, 0x00}); !errors.Is(err, ErrUnsupportedInnerPacket) {
		t.Fatalf("SendInnerPacketWithNextHeader() err=%v, want ErrUnsupportedInnerPacket", err)
	}
	if len(transport.packets) != 0 {
		t.Fatalf("captured packets=%d, want 0", len(transport.packets))
	}
	stats := session.PacketStats()
	if stats.OutboundErrors != 1 || stats.UnsupportedDrops != 1 || stats.OutboundESPPackets != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestPacketSessionRejectsInboundNextHeaderMismatchAndCountsDrop(t *testing.T) {
	sealer, err := esp.NewOutboundSAFromChild(packetChildSA(true))
	if err != nil {
		t.Fatalf("NewOutboundSAFromChild() error = %v", err)
	}
	packet, err := sealer.Seal(esp.NextHeaderIPv6, []byte{0x45, 0x00, 0x00, 0x14}, esp.SealOptions{
		Sequence: 1,
		IV:       bytes.Repeat([]byte{0x77}, 16),
	})
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	session, err := NewPacketSession(PacketSessionConfig{ChildSA: packetChildSA(false), Transport: &captureESPPacketTransport{}})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if _, err := session.ReceiveESPPacket(context.Background(), packet); !errors.Is(err, ErrUnsupportedInnerPacket) {
		t.Fatalf("ReceiveESPPacket() err=%v, want ErrUnsupportedInnerPacket", err)
	}
	stats := session.PacketStats()
	if stats.InboundErrors != 1 || stats.UnsupportedDrops != 1 || stats.InboundInnerPackets != 0 || stats.InboundESPPackets != 0 {
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

func TestPacketSessionObserveMOBIKENATTriggersMOBIKE(t *testing.T) {
	start := time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)
	var requests []MOBIKERequest
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result: TunnelResult{
			Ready:            true,
			IKEEstablished:   true,
			IPsecEstablished: true,
			MOBIKESupported:  true,
			LocalInnerIP:     "10.0.0.2",
			RemoteInnerIP:    "0.0.0.0/0",
			DNSServers:       []string{"10.0.0.1"},
		},
		MOBIKENAT: NewMOBIKENATState(MOBIKENATStateConfig{
			MOBIKESupported: true,
			LocalIP:         net.IPv4(192, 0, 2, 10),
			RemoteIP:        net.IPv4(198, 51, 100, 7),
			LocalPort:       4500,
			RemotePort:      4500,
			NATDetected:     true,
			UpdatedAt:       start,
		}),
		MOBIKEHandler: func(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
			requests = append(requests, req)
			return MOBIKEResult{
				IKEEstablished:   true,
				IPsecEstablished: true,
				LocalInnerIP:     "10.0.0.2",
				RemoteInnerIP:    "0.0.0.0/0",
				DNSServers:       []string{"10.0.0.1"},
				Reason:           "mobike updated from observation",
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}

	change, result, err := session.ObserveMOBIKENAT(context.Background(), MOBIKENATObservation{
		DeviceID:         "dev-1",
		TraceID:          "trace-1",
		LocalIP:          net.IPv4(192, 0, 2, 20),
		RemoteIP:         net.IPv4(198, 51, 100, 7),
		LocalPort:        4500,
		RemotePort:       4500,
		NATDetected:      true,
		NATDetectedKnown: true,
		At:               start.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("ObserveMOBIKENAT() error = %v", err)
	}
	if !change.Changed || !change.RequiresMOBIKEUpdate || !change.LocalAddressChanged || change.RemoteAddressChanged {
		t.Fatalf("change=%+v", change)
	}
	if len(requests) != 1 || requests[0].DeviceID != "dev-1" || requests[0].OldIP != "192.0.2.10" || requests[0].NewIP != "192.0.2.20" {
		t.Fatalf("MOBIKE requests=%+v", requests)
	}
	if result.Reason != "mobike updated from observation" || session.Result().Reason != "mobike updated from observation" {
		t.Fatalf("MOBIKE result=%+v session=%+v", result, session.Result())
	}
	endpoint, updatedAt := session.MOBIKENATSnapshot()
	if !endpoint.LocalIP.Equal(net.IPv4(192, 0, 2, 20)) || !updatedAt.Equal(start.Add(time.Minute)) {
		t.Fatalf("snapshot endpoint=%+v updatedAt=%v", endpoint, updatedAt)
	}

	change, result, err = session.ObserveMOBIKENAT(context.Background(), MOBIKENATObservation{
		DeviceID:         "dev-1",
		TraceID:          "trace-1",
		LocalIP:          net.IPv4(192, 0, 2, 20),
		RemoteIP:         net.IPv4(198, 51, 100, 7),
		LocalPort:        4500,
		RemotePort:       4500,
		NATDetected:      true,
		NATDetectedKnown: true,
		At:               start.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("ObserveMOBIKENAT(unchanged) error = %v", err)
	}
	if change.Changed || result.Reason != "" || len(requests) != 1 {
		t.Fatalf("unchanged change=%+v result=%+v requests=%+v", change, result, requests)
	}
}

func TestPacketSessionAdvanceIKELivenessSendsKeepalive(t *testing.T) {
	start := time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)
	liveness, err := NewIKELivenessState(IKELivenessConfig{
		KeepaliveInterval: 20 * time.Second,
		DisableDPD:        true,
	}, start)
	if err != nil {
		t.Fatalf("NewIKELivenessState() error = %v", err)
	}
	transport := &captureESPPacketTransport{}
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: transport,
		Liveness:  liveness,
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	decision, err := session.AdvanceIKELiveness(context.Background(), start.Add(20*time.Second))
	if err != nil {
		t.Fatalf("AdvanceIKELiveness() error = %v", err)
	}
	if decision.Action != IKELivenessSendKeepalive || transport.keepalives != 1 {
		t.Fatalf("decision=%+v keepalives=%d", decision, transport.keepalives)
	}
	if snapshot := session.IKELivenessSnapshot(); !snapshot.LastOutbound.Equal(start.Add(20 * time.Second)) {
		t.Fatalf("liveness snapshot=%+v", snapshot)
	}
}

func TestPacketSessionAdvanceIKELivenessSendsDPD(t *testing.T) {
	start := time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)
	liveness, err := NewIKELivenessState(IKELivenessConfig{
		DisableKeepalive: true,
		DPDInterval:      30 * time.Second,
		DPDTimeout:       10 * time.Second,
	}, start)
	if err != nil {
		t.Fatalf("NewIKELivenessState() error = %v", err)
	}
	dpdCalls := 0
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Liveness:  liveness,
		DPDHandler: func(ctx context.Context) error {
			dpdCalls++
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	decision, err := session.AdvanceIKELiveness(context.Background(), start.Add(30*time.Second))
	if err != nil {
		t.Fatalf("AdvanceIKELiveness() error = %v", err)
	}
	if decision.Action != IKELivenessSendDPD || dpdCalls != 1 {
		t.Fatalf("decision=%+v dpdCalls=%d", decision, dpdCalls)
	}
	if snapshot := session.IKELivenessSnapshot(); snapshot.OutstandingDPD || snapshot.MissedDPDProbes != 0 {
		t.Fatalf("liveness snapshot after successful DPD=%+v", snapshot)
	}
}

func TestPacketSessionAdvanceIKELivenessMarksResultDeadOnDPDHandlerTimeout(t *testing.T) {
	start := time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)
	liveness, err := NewIKELivenessState(IKELivenessConfig{
		DisableKeepalive:   true,
		DPDInterval:        30 * time.Second,
		DPDTimeout:         10 * time.Second,
		MaxMissedDPDProbes: 1,
	}, start)
	if err != nil {
		t.Fatalf("NewIKELivenessState() error = %v", err)
	}
	wantErr := errors.New("dpd exchange timeout")
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result: TunnelResult{
			Ready:            true,
			IKEEstablished:   true,
			IPsecEstablished: true,
			Reason:           "packet tunnel ready",
			EstablishedAt:    start,
		},
		Liveness: liveness,
		DPDHandler: func(ctx context.Context) error {
			return wantErr
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}

	decision, err := session.AdvanceIKELiveness(context.Background(), start.Add(30*time.Second))
	if !errors.Is(err, wantErr) {
		t.Fatalf("AdvanceIKELiveness() err=%v, want dpd exchange timeout", err)
	}
	if decision.Action != IKELivenessSendDPD || !decision.Dead || decision.MissedDPDProbes != 1 {
		t.Fatalf("decision=%+v", decision)
	}
	if result := session.Result(); result.IsReady() || !strings.Contains(result.Reason, "dpd exchange timeout") {
		t.Fatalf("result after DPD handler timeout=%+v", result)
	}
}

func TestPacketSessionAdvanceIKELivenessMarksResultDeadOnDPDTimeout(t *testing.T) {
	start := time.Date(2026, 7, 8, 9, 0, 0, 0, time.UTC)
	liveness, err := NewIKELivenessState(IKELivenessConfig{
		DisableKeepalive:   true,
		DPDInterval:        30 * time.Second,
		DPDTimeout:         10 * time.Second,
		MaxMissedDPDProbes: 1,
	}, start)
	if err != nil {
		t.Fatalf("NewIKELivenessState() error = %v", err)
	}
	if first := liveness.Advance(start.Add(30 * time.Second)); first.Action != IKELivenessSendDPD {
		t.Fatalf("first liveness decision=%+v", first)
	}
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result: TunnelResult{
			Ready:            true,
			IKEEstablished:   true,
			IPsecEstablished: true,
			Reason:           "packet tunnel ready",
			EstablishedAt:    start,
		},
		Liveness: liveness,
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}

	decision, err := session.AdvanceIKELiveness(context.Background(), start.Add(40*time.Second))
	if err != nil {
		t.Fatalf("AdvanceIKELiveness(timeout) error = %v", err)
	}
	if decision.Action != IKELivenessDeclareDead || !decision.Dead {
		t.Fatalf("timeout decision=%+v", decision)
	}
	result := session.Result()
	if result.IsReady() || result.IKEEstablished || result.IPsecEstablished ||
		!strings.Contains(result.Reason, "ike liveness dead") ||
		!strings.Contains(result.Reason, "dpd") {
		t.Fatalf("result after DPD timeout=%+v", result)
	}
}

type captureESPPacketTransport struct {
	packets    [][]byte
	keepalives int
	closed     bool
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

func (t *captureESPPacketTransport) SendNATTKeepalive(ctx context.Context) error {
	t.keepalives++
	return nil
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

func packetRekeyChildSA(aToB bool) ikev2.ChildSAResult {
	aOutbound := ikev2.ESPKeys{
		EncryptionKey: bytes.Repeat([]byte{0x50}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x60}, 32),
	}
	aInbound := ikev2.ESPKeys{
		EncryptionKey: bytes.Repeat([]byte{0x70}, 16),
		IntegrityKey:  bytes.Repeat([]byte{0x80}, 32),
	}
	child := ikev2.ChildSAResult{
		LocalSPI:  []byte{0x33, 0x33, 0x33, 0x33},
		RemoteSPI: []byte{0x44, 0x44, 0x44, 0x44},
		Keys: ikev2.ChildSAKeys{
			Profile:  ikev2.ESPKeyProfile{IntegrityID: ikev2.INTEG_HMAC_SHA2_256_128},
			Outbound: aOutbound,
			Inbound:  aInbound,
		},
	}
	if aToB {
		return child
	}
	child.LocalSPI = []byte{0x44, 0x44, 0x44, 0x44}
	child.RemoteSPI = []byte{0x33, 0x33, 0x33, 0x33}
	child.Keys.Outbound = aInbound
	child.Keys.Inbound = aOutbound
	return child
}
