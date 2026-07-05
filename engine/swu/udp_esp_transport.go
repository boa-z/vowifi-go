package swu

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const DefaultNATTUDPPort = "4500"

type UDPESPPacketTransport struct {
	RemoteAddr     string
	LocalAddr      string
	Timeout        time.Duration
	ReadBufferSize int

	mu     sync.Mutex
	conn   net.Conn
	closed bool
}

var (
	_ ESPPacketReadWriteTransport = (*UDPESPPacketTransport)(nil)
	_ ESPPacketTransportCloser    = (*UDPESPPacketTransport)(nil)
)

func (t *UDPESPPacketTransport) SendESPPacket(ctx context.Context, packet []byte) error {
	if t == nil {
		return ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	if len(packet) < 8 {
		return fmt.Errorf("%w: ESP packet too short", ErrInvalidPacketTunnel)
	}
	if isNonESPMarker(packet) {
		return fmt.Errorf("%w: non-ESP marker cannot be sent as ESP", ErrInvalidPacketTunnel)
	}
	conn, err := t.getConn(ctx)
	if err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(t.deadline(ctx)); err != nil {
		return err
	}
	_, err = conn.Write(packet)
	return transportNetError(ctx, err)
}

func (t *UDPESPPacketTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	if t == nil {
		return nil, ErrInvalidPacketTunnel
	}
	if ctx == nil {
		ctx = context.Background()
	}
	conn, err := t.getConn(ctx)
	if err != nil {
		return nil, err
	}
	size := t.ReadBufferSize
	if size <= 0 {
		size = 64 * 1024
	}
	buf := make([]byte, size)
	for {
		if err := contextReady(ctx); err != nil {
			return nil, err
		}
		if err := conn.SetReadDeadline(t.deadline(ctx)); err != nil {
			return nil, err
		}
		n, err := conn.Read(buf)
		if err != nil {
			return nil, transportNetError(ctx, err)
		}
		wire := buf[:n]
		switch {
		case isNATTKeepalive(wire):
			continue
		case isNonESPMarker(wire):
			continue
		case len(wire) < 8:
			return nil, fmt.Errorf("%w: ESP packet too short", ErrInvalidPacketTunnel)
		default:
			return append([]byte(nil), wire...), nil
		}
	}
}

func (t *UDPESPPacketTransport) Close(ctx context.Context) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	conn := t.conn
	t.conn = nil
	t.mu.Unlock()
	if conn != nil {
		return transportNetError(ctx, conn.Close())
	}
	return nil
}

func (t *UDPESPPacketTransport) LocalNetworkAddr() net.Addr {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn == nil {
		return nil
	}
	return t.conn.LocalAddr()
}

func (t *UDPESPPacketTransport) getConn(ctx context.Context) (net.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, ErrPacketTunnelClosed
	}
	if t.conn != nil {
		return t.conn, nil
	}
	remote, err := udpAddrWithDefaultPort(t.RemoteAddr, DefaultNATTUDPPort)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{}
	if strings.TrimSpace(t.LocalAddr) != "" {
		local, err := udpAddrWithDefaultPort(t.LocalAddr, "0")
		if err != nil {
			return nil, err
		}
		addr, err := net.ResolveUDPAddr("udp", local)
		if err != nil {
			return nil, err
		}
		dialer.LocalAddr = addr
	}
	conn, err := dialer.DialContext(ctx, "udp", remote)
	if err != nil {
		return nil, err
	}
	if t.closed {
		_ = conn.Close()
		return nil, ErrPacketTunnelClosed
	}
	t.conn = conn
	return conn, nil
}

func (t *UDPESPPacketTransport) deadline(ctx context.Context) time.Time {
	var deadline time.Time
	if ctx != nil {
		if ctxDeadline, ok := ctx.Deadline(); ok {
			deadline = ctxDeadline
		}
	}
	if t != nil && t.Timeout > 0 {
		timeoutDeadline := time.Now().Add(t.Timeout)
		if deadline.IsZero() || timeoutDeadline.Before(deadline) {
			deadline = timeoutDeadline
		}
	}
	return deadline
}

func udpAddrWithDefaultPort(addr, defaultPort string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("%w: udp address is empty", ErrInvalidPacketTunnel)
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr, nil
	}
	defaultPort = strings.TrimSpace(defaultPort)
	if defaultPort == "" {
		return "", fmt.Errorf("%w: udp port is empty", ErrInvalidPacketTunnel)
	}
	host := strings.Trim(addr, "[]")
	return net.JoinHostPort(host, defaultPort), nil
}

func isNATTKeepalive(packet []byte) bool {
	return len(packet) == 1 && packet[0] == 0xff
}

func isNonESPMarker(packet []byte) bool {
	return len(packet) >= 4 && packet[0] == 0 && packet[1] == 0 && packet[2] == 0 && packet[3] == 0
}

func transportNetError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, net.ErrClosed) {
		return ErrPacketTunnelClosed
	}
	if ctx != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
	}
	return err
}
