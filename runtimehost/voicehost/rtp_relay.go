package voicehost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

var ErrRTPRelayConfig = errors.New("invalid rtp relay config")

type RTPRelayConfig struct {
	ClientListenIP    string
	ClientAdvertiseIP string
	ClientPort        int
	IMSListenIP       string
	IMSAdvertiseIP    string
	IMSPort           int
	BufferSize        int
}

type RTPRelayStats struct {
	ClientToIMSPackets uint64
	IMSToClientPackets uint64
	ClientToIMSBytes   uint64
	IMSToClientBytes   uint64
}

type RTPRelaySession struct {
	clientConn *net.UDPConn
	imsConn    *net.UDPConn

	clientTarget *net.UDPAddr

	mu        sync.RWMutex
	imsTarget *net.UDPAddr
	closed    bool

	clientAdvertiseIP string
	imsAdvertiseIP    string
	bufferSize        int

	cancel context.CancelFunc
	wg     sync.WaitGroup

	clientToIMSPackets atomic.Uint64
	imsToClientPackets atomic.Uint64
	clientToIMSBytes   atomic.Uint64
	imsToClientBytes   atomic.Uint64
}

func NewRTPRelaySession(ctx context.Context, cfg RTPRelayConfig, clientTarget SDPInfo) (*RTPRelaySession, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(clientTarget.ConnectionIP) == "" || clientTarget.MediaPort <= 0 {
		return nil, fmt.Errorf("%w: client media target is incomplete", ErrRTPRelayConfig)
	}
	clientAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(clientTarget.ConnectionIP, strconv.Itoa(clientTarget.MediaPort)))
	if err != nil {
		return nil, err
	}
	clientListenIP := firstVoiceNonEmpty(cfg.ClientListenIP, "0.0.0.0")
	imsListenIP := firstVoiceNonEmpty(cfg.IMSListenIP, clientListenIP)
	clientConn, err := listenUDP(clientListenIP, cfg.ClientPort)
	if err != nil {
		return nil, err
	}
	imsConn, err := listenUDP(imsListenIP, cfg.IMSPort)
	if err != nil {
		_ = clientConn.Close()
		return nil, err
	}
	childCtx, cancel := context.WithCancel(ctx)
	s := &RTPRelaySession{
		clientConn:        clientConn,
		imsConn:           imsConn,
		clientTarget:      clientAddr,
		clientAdvertiseIP: advertiseIP(cfg.ClientAdvertiseIP, clientListenIP),
		imsAdvertiseIP:    advertiseIP(cfg.IMSAdvertiseIP, imsListenIP),
		bufferSize:        cfg.BufferSize,
		cancel:            cancel,
	}
	if s.bufferSize <= 0 {
		s.bufferSize = 2048
	}
	s.wg.Add(2)
	go s.forwardLoop(childCtx, s.clientConn, s.imsConn, s.currentIMSTarget, true)
	go s.forwardLoop(childCtx, s.imsConn, s.clientConn, s.currentClientTarget, false)
	return s, nil
}

func (s *RTPRelaySession) IMSOfferSDP(clientOffer SDPInfo) []byte {
	info := clientOffer
	info.ConnectionIP = s.imsAdvertiseIP
	info.MediaPort = s.imsPort()
	return BuildSDPAnswer(info)
}

func (s *RTPRelaySession) ClientAnswerSDP(imsAnswer SDPInfo) []byte {
	info := imsAnswer
	info.ConnectionIP = s.clientAdvertiseIP
	info.MediaPort = s.clientPort()
	return BuildSDPAnswer(info)
}

func (s *RTPRelaySession) SetIMSRemote(info SDPInfo) error {
	if s == nil {
		return nil
	}
	if strings.TrimSpace(info.ConnectionIP) == "" || info.MediaPort <= 0 {
		return fmt.Errorf("%w: IMS media target is incomplete", ErrRTPRelayConfig)
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(info.ConnectionIP, strconv.Itoa(info.MediaPort)))
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.imsTarget = addr
	s.mu.Unlock()
	return nil
}

func (s *RTPRelaySession) ClientEndpoint() SDPInfo {
	if s == nil {
		return SDPInfo{}
	}
	return SDPInfo{ConnectionIP: s.clientAdvertiseIP, MediaPort: s.clientPort()}
}

func (s *RTPRelaySession) IMSEndpoint() SDPInfo {
	if s == nil {
		return SDPInfo{}
	}
	return SDPInfo{ConnectionIP: s.imsAdvertiseIP, MediaPort: s.imsPort()}
}

func (s *RTPRelaySession) Stats() RTPRelayStats {
	if s == nil {
		return RTPRelayStats{}
	}
	return RTPRelayStats{
		ClientToIMSPackets: s.clientToIMSPackets.Load(),
		IMSToClientPackets: s.imsToClientPackets.Load(),
		ClientToIMSBytes:   s.clientToIMSBytes.Load(),
		IMSToClientBytes:   s.imsToClientBytes.Load(),
	}
}

func (s *RTPRelaySession) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	var err error
	if s.clientConn != nil {
		err = errors.Join(err, s.clientConn.Close())
	}
	if s.imsConn != nil {
		err = errors.Join(err, s.imsConn.Close())
	}
	s.wg.Wait()
	return err
}

func (s *RTPRelaySession) forwardLoop(ctx context.Context, src, out *net.UDPConn, target func() *net.UDPAddr, clientToIMS bool) {
	defer s.wg.Done()
	buf := make([]byte, s.bufferSize)
	for {
		n, _, err := src.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				return
			}
		}
		dst := target()
		if dst == nil {
			continue
		}
		if _, err := out.WriteToUDP(buf[:n], dst); err != nil {
			continue
		}
		if clientToIMS {
			s.clientToIMSPackets.Add(1)
			s.clientToIMSBytes.Add(uint64(n))
		} else {
			s.imsToClientPackets.Add(1)
			s.imsToClientBytes.Add(uint64(n))
		}
	}
}

func (s *RTPRelaySession) currentIMSTarget() *net.UDPAddr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.imsTarget == nil {
		return nil
	}
	cp := *s.imsTarget
	return &cp
}

func (s *RTPRelaySession) currentClientTarget() *net.UDPAddr {
	if s == nil || s.clientTarget == nil {
		return nil
	}
	cp := *s.clientTarget
	return &cp
}

func (s *RTPRelaySession) clientPort() int {
	if s == nil || s.clientConn == nil {
		return 0
	}
	return udpLocalPort(s.clientConn)
}

func (s *RTPRelaySession) imsPort() int {
	if s == nil || s.imsConn == nil {
		return 0
	}
	return udpLocalPort(s.imsConn)
}

func listenUDP(host string, port int) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", addr)
}

func udpLocalPort(conn *net.UDPConn) int {
	if conn == nil {
		return 0
	}
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.Port
	}
	return 0
}

func advertiseIP(explicit, listenIP string) string {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit)
	}
	ip := strings.TrimSpace(listenIP)
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		return "127.0.0.1"
	}
	return ip
}
