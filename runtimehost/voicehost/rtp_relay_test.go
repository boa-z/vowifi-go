package voicehost

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestRTPRelaySessionForwardsBidirectionalPackets(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	imsPeer := listenTestUDP(t)
	defer imsPeer.Close()

	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	imsAddr := imsPeer.LocalAddr().(*net.UDPAddr)
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "127.0.0.1",
		IMSListenIP:       "127.0.0.1",
		IMSAdvertiseIP:    "127.0.0.1",
	}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()
	if err := relay.SetIMSRemote(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: imsAddr.Port}); err != nil {
		t.Fatalf("SetIMSRemote() error = %v", err)
	}

	clientEndpoint := udpAddrFromSDP(t, relay.ClientEndpoint())
	imsEndpoint := udpAddrFromSDP(t, relay.IMSEndpoint())

	if _, err := clientPeer.WriteToUDP([]byte{0x11, 0x22, 0x33}, clientEndpoint); err != nil {
		t.Fatalf("client WriteToUDP() error = %v", err)
	}
	got, from := readTestUDP(t, imsPeer)
	if string(got) != string([]byte{0x11, 0x22, 0x33}) {
		t.Fatalf("IMS got=%x", got)
	}
	if from.Port != imsEndpoint.Port {
		t.Fatalf("IMS packet source port=%d, want relay IMS port %d", from.Port, imsEndpoint.Port)
	}

	if _, err := imsPeer.WriteToUDP([]byte{0x44, 0x55}, imsEndpoint); err != nil {
		t.Fatalf("ims WriteToUDP() error = %v", err)
	}
	got, from = readTestUDP(t, clientPeer)
	if string(got) != string([]byte{0x44, 0x55}) {
		t.Fatalf("client got=%x", got)
	}
	if from.Port != clientEndpoint.Port {
		t.Fatalf("client packet source port=%d, want relay client port %d", from.Port, clientEndpoint.Port)
	}
	stats := relay.Stats()
	if stats.ClientToIMSPackets != 1 || stats.IMSToClientPackets != 1 || stats.ClientToIMSBytes != 3 || stats.IMSToClientBytes != 2 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestRTPRelaySessionRewritesSDP(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "198.51.100.10",
		IMSListenIP:       "127.0.0.1",
		IMSAdvertiseIP:    "203.0.113.10",
	}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port, Payloads: []int{0, 101}, Direction: "sendrecv"})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()

	offer, err := ParseSDP(relay.IMSOfferSDP(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port, Payloads: []int{0, 101}}))
	if err != nil {
		t.Fatalf("ParseSDP(offer) error = %v", err)
	}
	if offer.ConnectionIP != "203.0.113.10" || offer.MediaPort != relay.IMSEndpoint().MediaPort {
		t.Fatalf("offer=%+v relayIMS=%+v", offer, relay.IMSEndpoint())
	}
	answer, err := ParseSDP(relay.ClientAnswerSDP(SDPInfo{ConnectionIP: "192.0.2.20", MediaPort: 49170, Payloads: []int{0}}))
	if err != nil {
		t.Fatalf("ParseSDP(answer) error = %v", err)
	}
	if answer.ConnectionIP != "198.51.100.10" || answer.MediaPort != relay.ClientEndpoint().MediaPort {
		t.Fatalf("answer=%+v relayClient=%+v", answer, relay.ClientEndpoint())
	}
}

func listenTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	return conn
}

func readTestUDP(t *testing.T, conn *net.UDPConn) ([]byte, *net.UDPAddr) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 128)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP() error = %v", err)
	}
	return append([]byte(nil), buf[:n]...), addr
}

func udpAddrFromSDP(t *testing.T, info SDPInfo) *net.UDPAddr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(info.ConnectionIP, strconv.Itoa(info.MediaPort)))
	if err != nil {
		t.Fatalf("ResolveUDPAddr(%+v) error = %v", info, err)
	}
	return addr
}
