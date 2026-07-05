package swu

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestUDPESPPacketTransportSendsRawESP(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer server.Close()
	transport := &UDPESPPacketTransport{
		RemoteAddr: server.LocalAddr().String(),
		Timeout:    time.Second,
	}
	packet := []byte{0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1, 0xaa, 0xbb}
	if err := transport.SendESPPacket(context.Background(), packet); err != nil {
		t.Fatalf("SendESPPacket() error = %v", err)
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server ReadFrom() error = %v", err)
	}
	if !bytes.Equal(buf[:n], packet) {
		t.Fatalf("server packet=%x, want %x", buf[:n], packet)
	}
}

func TestUDPESPPacketTransportReadFiltersNATTControlPackets(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer server.Close()
	transport := &UDPESPPacketTransport{
		RemoteAddr: server.LocalAddr().String(),
		Timeout:    time.Second,
	}
	if err := transport.SendESPPacket(context.Background(), []byte{0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1}); err != nil {
		t.Fatalf("SendESPPacket() error = %v", err)
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	if _, clientAddr, err := server.ReadFrom(buf); err != nil {
		t.Fatalf("server ReadFrom() error = %v", err)
	} else {
		if _, err := server.WriteTo([]byte{0xff}, clientAddr); err != nil {
			t.Fatalf("WriteTo(keepalive) error = %v", err)
		}
		if _, err := server.WriteTo([]byte{0, 0, 0, 0, 1, 2, 3, 4}, clientAddr); err != nil {
			t.Fatalf("WriteTo(non-esp) error = %v", err)
		}
		want := []byte{0x87, 0x65, 0x43, 0x21, 0, 0, 0, 2, 0xcc}
		if _, err := server.WriteTo(want, clientAddr); err != nil {
			t.Fatalf("WriteTo(esp) error = %v", err)
		}
		got, err := transport.ReadESPPacket(context.Background())
		if err != nil {
			t.Fatalf("ReadESPPacket() error = %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("ReadESPPacket()=%x, want %x", got, want)
		}
	}
}

func TestUDPESPPacketTransportCloseRejectsTraffic(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer server.Close()
	transport := &UDPESPPacketTransport{
		RemoteAddr: server.LocalAddr().String(),
		Timeout:    time.Second,
	}
	if err := transport.SendESPPacket(context.Background(), []byte{0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1}); err != nil {
		t.Fatalf("SendESPPacket() error = %v", err)
	}
	if transport.LocalNetworkAddr() == nil {
		t.Fatalf("LocalNetworkAddr() is nil after dialing")
	}
	if err := transport.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := transport.SendESPPacket(context.Background(), []byte{0x12, 0x34, 0x56, 0x78, 0, 0, 0, 2}); !errors.Is(err, ErrPacketTunnelClosed) {
		t.Fatalf("SendESPPacket(after close) err=%v, want ErrPacketTunnelClosed", err)
	}
	if _, err := transport.ReadESPPacket(context.Background()); !errors.Is(err, ErrPacketTunnelClosed) {
		t.Fatalf("ReadESPPacket(after close) err=%v, want ErrPacketTunnelClosed", err)
	}
}
