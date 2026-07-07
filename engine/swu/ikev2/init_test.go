package ikev2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"net"
	"testing"
	"time"
)

type initFakeTransport struct {
	t            *testing.T
	responderSPI uint64
	responderKey []byte
	nonceR       []byte
	remoteIP     net.IP
	remotePort   uint16
	localIP      net.IP
	localPort    uint16
	request      Message
}

func (f *initFakeTransport) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	f.t.Helper()
	req, err := ParseMessage(request)
	if err != nil {
		return nil, err
	}
	f.request = req
	if req.Header.ExchangeType != ExchangeIKE_SA_INIT || req.Header.Flags&FlagInitiator == 0 {
		f.t.Fatalf("request header=%+v", req.Header)
	}
	if len(req.Payloads) < 3 || req.Payloads[0].Type != PayloadSA || req.Payloads[1].Type != PayloadKE || req.Payloads[2].Type != PayloadNonce {
		f.t.Fatalf("request payloads=%+v", req.Payloads)
	}
	privR, err := ecdh.X25519().NewPrivateKey(f.responderKey)
	if err != nil {
		return nil, err
	}
	payloads := []Payload{
		req.Payloads[0],
		KeyExchangePayload(DHGroupCurve25519, privR.PublicKey().Bytes()),
		NoncePayload(f.nonceR),
	}
	src, err := NATDetectionNotify(NotifyNATDetectionSourceIP, req.Header.InitiatorSPI, f.responderSPI, f.remoteIP, f.remotePort)
	if err != nil {
		return nil, err
	}
	dst, err := NATDetectionNotify(NotifyNATDetectionDestinationIP, req.Header.InitiatorSPI, f.responderSPI, f.localIP, f.localPort)
	if err != nil {
		return nil, err
	}
	payloads = append(payloads, src, dst, MOBIKESupportedNotify())
	resp := Message{
		Header: Header{
			InitiatorSPI: req.Header.InitiatorSPI,
			ResponderSPI: f.responderSPI,
			ExchangeType: ExchangeIKE_SA_INIT,
			Flags:        FlagResponse,
		},
		Payloads: payloads,
	}
	return resp.MarshalBinary()
}

func TestRunIKESAInitDerivesKeys(t *testing.T) {
	initiatorKey := bytes.Repeat([]byte{0x11}, 32)
	responderKey := bytes.Repeat([]byte{0x22}, 32)
	nonceI := bytes.Repeat([]byte{0xa1}, 32)
	nonceR := bytes.Repeat([]byte{0xb2}, 32)
	fake := &initFakeTransport{
		t:            t,
		responderSPI: 0x1112131415161718,
		responderKey: responderKey,
		nonceR:       nonceR,
		remoteIP:     net.ParseIP("192.0.2.20"),
		remotePort:   500,
		localIP:      net.ParseIP("192.0.2.10"),
		localPort:    500,
	}
	res, err := RunIKE_SA_INIT(context.Background(), InitConfig{
		Transport:        fake,
		InitiatorSPI:     0x0102030405060708,
		NonceI:           nonceI,
		X25519PrivateKey: initiatorKey,
		LocalIP:          fake.localIP,
		LocalPort:        fake.localPort,
		RemoteIP:         fake.remoteIP,
		RemotePort:       fake.remotePort,
	})
	if err != nil {
		t.Fatalf("RunIKE_SA_INIT() error = %v", err)
	}
	if res.InitiatorSPI != 0x0102030405060708 || res.ResponderSPI != fake.responderSPI {
		t.Fatalf("SPIs=%x/%x", res.InitiatorSPI, res.ResponderSPI)
	}
	if !res.MOBIKESupported || res.NATDetected || res.PRF != crypto.SHA256 {
		t.Fatalf("mobike=%t nat=%t prf=%v", res.MOBIKESupported, res.NATDetected, res.PRF)
	}
	if len(res.SKEYSEED) != crypto.SHA256.Size() || len(res.KeyMaterial) != res.Keys.Profile.RequiredLength() {
		t.Fatalf("key lengths skeyseed=%d material=%d", len(res.SKEYSEED), len(res.KeyMaterial))
	}
	if len(res.Keys.SKAi) != crypto.SHA256.Size() || len(res.Keys.SKEi) != 16 || len(res.Keys.SKPi) != crypto.SHA256.Size() {
		t.Fatalf("split keys=%+v", res.Keys)
	}
	privR, err := ecdh.X25519().NewPrivateKey(responderKey)
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}
	pubI, err := ecdh.X25519().NewPublicKey(res.PublicKeyI)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}
	wantShared, err := privR.ECDH(pubI)
	if err != nil {
		t.Fatalf("ECDH() error = %v", err)
	}
	if !bytes.Equal(res.SharedSecret, wantShared) {
		t.Fatalf("shared=%x want %x", res.SharedSecret, wantShared)
	}
	wantSKEYSEED, err := SKEYSEED(crypto.SHA256, nonceI, nonceR, wantShared)
	if err != nil {
		t.Fatalf("SKEYSEED() error = %v", err)
	}
	if !bytes.Equal(res.SKEYSEED, wantSKEYSEED) {
		t.Fatalf("skeyseed=%x want %x", res.SKEYSEED, wantSKEYSEED)
	}
	if got := countPayloadType(fake.request.Payloads, PayloadNotify); got != 3 {
		t.Fatalf("request notify payloads=%d, want NAT-D source/dest + MOBIKE", got)
	}
}

func TestRunIKESAInitRetriesWithCookieNotify(t *testing.T) {
	initiatorKey := bytes.Repeat([]byte{0x11}, 32)
	responderKey := bytes.Repeat([]byte{0x22}, 32)
	nonceI := bytes.Repeat([]byte{0xa1}, 32)
	nonceR := bytes.Repeat([]byte{0xb2}, 32)
	cookie := []byte("ike-cookie-1")
	responderSPI := uint64(0x1112131415161718)
	calls := 0
	var firstRequest Message
	var secondRequest Message

	transport := InitTransportFunc(func(ctx context.Context, request []byte) ([]byte, error) {
		req, err := ParseMessage(request)
		if err != nil {
			return nil, err
		}
		calls++
		switch calls {
		case 1:
			if len(req.Payloads) < 3 || req.Payloads[0].Type != PayloadSA {
				t.Fatalf("first request payloads=%+v", req.Payloads)
			}
			firstRequest = req
			cookiePayload, err := CookieNotify(cookie)
			if err != nil {
				return nil, err
			}
			resp := Message{
				Header: Header{
					InitiatorSPI: req.Header.InitiatorSPI,
					ExchangeType: ExchangeIKE_SA_INIT,
					Flags:        FlagResponse,
				},
				Payloads: []Payload{cookiePayload},
			}
			return resp.MarshalBinary()
		case 2:
			secondRequest = req
			if len(req.Payloads) < 4 ||
				req.Payloads[0].Type != PayloadNotify ||
				req.Payloads[1].Type != PayloadSA ||
				req.Payloads[2].Type != PayloadKE ||
				req.Payloads[3].Type != PayloadNonce {
				t.Fatalf("second request payloads=%+v", req.Payloads)
			}
			notify, err := ParseNotify(req.Payloads[0].Body)
			if err != nil {
				return nil, err
			}
			gotCookie, ok, err := notify.Cookie()
			if err != nil {
				return nil, err
			}
			if !ok || !bytes.Equal(gotCookie, cookie) {
				t.Fatalf("second request COOKIE=%x ok=%t, want %x", gotCookie, ok, cookie)
			}
			privR, err := ecdh.X25519().NewPrivateKey(responderKey)
			if err != nil {
				return nil, err
			}
			resp := Message{
				Header: Header{
					InitiatorSPI: req.Header.InitiatorSPI,
					ResponderSPI: responderSPI,
					ExchangeType: ExchangeIKE_SA_INIT,
					Flags:        FlagResponse,
				},
				Payloads: []Payload{
					req.Payloads[1],
					KeyExchangePayload(DHGroupCurve25519, privR.PublicKey().Bytes()),
					NoncePayload(nonceR),
					MOBIKESupportedNotify(),
				},
			}
			return resp.MarshalBinary()
		default:
			return nil, errors.New("unexpected extra IKE_SA_INIT request")
		}
	})

	res, err := RunIKE_SA_INIT(context.Background(), InitConfig{
		Transport:        transport,
		InitiatorSPI:     0x0102030405060708,
		NonceI:           nonceI,
		X25519PrivateKey: initiatorKey,
	})
	if err != nil {
		t.Fatalf("RunIKE_SA_INIT() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("IKE_SA_INIT requests=%d, want 2", calls)
	}
	if firstRequest.Header.InitiatorSPI != secondRequest.Header.InitiatorSPI {
		t.Fatalf("retried SPI=%x want %x", secondRequest.Header.InitiatorSPI, firstRequest.Header.InitiatorSPI)
	}
	if got, want := firstPayloadBody(t, secondRequest.Payloads, PayloadNonce), firstPayloadBody(t, firstRequest.Payloads, PayloadNonce); !bytes.Equal(got, want) {
		t.Fatalf("retried nonce=%x want %x", got, want)
	}
	if res.ResponderSPI != responderSPI || !res.MOBIKESupported {
		t.Fatalf("responder SPI=%x mobike=%t", res.ResponderSPI, res.MOBIKESupported)
	}
	if len(res.Request.Payloads) == 0 || res.Request.Payloads[0].Type != PayloadNotify ||
		!bytes.Equal(res.Request.Payloads[0].Body, secondRequest.Payloads[0].Body) {
		t.Fatalf("result request payloads=%+v second=%+v", res.Request.Payloads, secondRequest.Payloads)
	}
}

func TestRunIKESAInitRejectsRepeatedCookieNotify(t *testing.T) {
	nonceI := bytes.Repeat([]byte{0xa1}, 32)
	calls := 0
	var firstRequest Message
	var secondRequest Message

	transport := InitTransportFunc(func(ctx context.Context, request []byte) ([]byte, error) {
		req, err := ParseMessage(request)
		if err != nil {
			return nil, err
		}
		calls++
		switch calls {
		case 1:
			firstRequest = req
			return initCookieResponse(t, req.Header.InitiatorSPI, []byte("ike-cookie-1")), nil
		case 2:
			secondRequest = req
			return initCookieResponse(t, req.Header.InitiatorSPI, []byte("ike-cookie-2")), nil
		default:
			return nil, errors.New("unexpected extra IKE_SA_INIT request")
		}
	})

	_, err := RunIKE_SA_INIT(context.Background(), InitConfig{
		Transport:        transport,
		InitiatorSPI:     0x0102030405060708,
		NonceI:           nonceI,
		X25519PrivateKey: bytes.Repeat([]byte{0x11}, 32),
	})
	if !errors.Is(err, ErrInvalidInitResponse) {
		t.Fatalf("RunIKE_SA_INIT() err=%v, want ErrInvalidInitResponse", err)
	}
	if calls != 2 {
		t.Fatalf("IKE_SA_INIT requests=%d, want 2", calls)
	}
	if firstRequest.Header.InitiatorSPI != secondRequest.Header.InitiatorSPI {
		t.Fatalf("retried SPI=%x want %x", secondRequest.Header.InitiatorSPI, firstRequest.Header.InitiatorSPI)
	}
	if got, want := firstPayloadBody(t, secondRequest.Payloads, PayloadNonce), firstPayloadBody(t, firstRequest.Payloads, PayloadNonce); !bytes.Equal(got, want) {
		t.Fatalf("retried nonce=%x want %x", got, want)
	}
	if len(secondRequest.Payloads) == 0 || secondRequest.Payloads[0].Type != PayloadNotify {
		t.Fatalf("second request payloads=%+v, want leading COOKIE notify", secondRequest.Payloads)
	}
	notify, err := ParseNotify(secondRequest.Payloads[0].Body)
	if err != nil {
		t.Fatalf("ParseNotify(COOKIE) error = %v", err)
	}
	cookie, ok, err := notify.Cookie()
	if err != nil || !ok || !bytes.Equal(cookie, []byte("ike-cookie-1")) {
		t.Fatalf("second request COOKIE=%x ok=%t err=%v", cookie, ok, err)
	}
}

func TestRunIKESAInitRejectsMissingNonce(t *testing.T) {
	transport := InitTransportFunc(func(ctx context.Context, request []byte) ([]byte, error) {
		req, err := ParseMessage(request)
		if err != nil {
			return nil, err
		}
		resp := Message{
			Header: Header{
				InitiatorSPI: req.Header.InitiatorSPI,
				ResponderSPI: 0x1112131415161718,
				ExchangeType: ExchangeIKE_SA_INIT,
				Flags:        FlagResponse,
			},
			Payloads: []Payload{
				req.Payloads[0],
				KeyExchangePayload(DHGroupCurve25519, bytes.Repeat([]byte{0x33}, 32)),
			},
		}
		return resp.MarshalBinary()
	})
	_, err := RunIKE_SA_INIT(context.Background(), InitConfig{
		Transport:        transport,
		InitiatorSPI:     1,
		NonceI:           bytes.Repeat([]byte{0x01}, 32),
		X25519PrivateKey: bytes.Repeat([]byte{0x02}, 32),
	})
	if !errors.Is(err, ErrInvalidInitResponse) {
		t.Fatalf("RunIKE_SA_INIT() err=%v, want ErrInvalidInitResponse", err)
	}
}

func TestRunIKESAInitRejectsUnsupportedSelectedSA(t *testing.T) {
	responderKey := bytes.Repeat([]byte{0x22}, 32)
	transport := InitTransportFunc(func(ctx context.Context, request []byte) ([]byte, error) {
		req, err := ParseMessage(request)
		if err != nil {
			return nil, err
		}
		selected := DefaultIKEProposal()
		selected.Proposals[0].Transforms[1].ID = PRF_HMAC_SHA2_512
		saPayload, err := SecurityAssociationPayload(selected)
		if err != nil {
			return nil, err
		}
		privR, err := ecdh.X25519().NewPrivateKey(responderKey)
		if err != nil {
			return nil, err
		}
		resp := Message{
			Header: Header{
				InitiatorSPI: req.Header.InitiatorSPI,
				ResponderSPI: 0x1112131415161718,
				ExchangeType: ExchangeIKE_SA_INIT,
				Flags:        FlagResponse,
			},
			Payloads: []Payload{
				saPayload,
				KeyExchangePayload(DHGroupCurve25519, privR.PublicKey().Bytes()),
				NoncePayload(bytes.Repeat([]byte{0xb2}, 32)),
			},
		}
		return resp.MarshalBinary()
	})
	_, err := RunIKE_SA_INIT(context.Background(), InitConfig{
		Transport:        transport,
		InitiatorSPI:     1,
		NonceI:           bytes.Repeat([]byte{0x01}, 32),
		X25519PrivateKey: bytes.Repeat([]byte{0x02}, 32),
	})
	if !errors.Is(err, ErrUnsupportedSASelection) {
		t.Fatalf("RunIKE_SA_INIT() err=%v, want ErrUnsupportedSASelection", err)
	}
}

func TestRunIKESAInitClassifiesResponseNotifyErrors(t *testing.T) {
	cases := []struct {
		name      string
		notify    Notify
		want      error
		wantGroup uint16
		groupOK   bool
	}{
		{
			name:   "no proposal chosen",
			notify: Notify{NotifyType: NotifyNoProposalChosen},
			want:   ErrNotifyNoProposalChosen,
		},
		{
			name: "invalid ke payload",
			notify: Notify{
				NotifyType:       NotifyInvalidKEPayload,
				NotificationData: []byte{0, byte(DHGroup2048BitMODP)},
			},
			want:      ErrNotifyInvalidKEPayload,
			wantGroup: DHGroup2048BitMODP,
			groupOK:   true,
		},
		{
			name:   "unsupported critical payload",
			notify: Notify{NotifyType: NotifyUnsupportedCriticalPayload, NotificationData: []byte{PayloadKE}},
			want:   ErrNotifyUnsupportedCriticalPayload,
		},
		{
			name:   "unknown error notify",
			notify: Notify{NotifyType: 1234},
			want:   ErrIKEv2NotifyError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runInitWithNotifyError(t, tc.notify)
			if !errors.Is(err, ErrInvalidInitResponse) ||
				!errors.Is(err, ErrIKEv2NotifyError) ||
				!errors.Is(err, tc.want) {
				t.Fatalf("RunIKE_SA_INIT() err=%v, want ErrInvalidInitResponse, ErrIKEv2NotifyError, and %v", err, tc.want)
			}
			var notifyErr *NotifyError
			if !errors.As(err, &notifyErr) {
				t.Fatalf("RunIKE_SA_INIT() err=%T, want *NotifyError", err)
			}
			if notifyErr.Notify.NotifyType != tc.notify.NotifyType ||
				!bytes.Equal(notifyErr.Notify.NotificationData, tc.notify.NotificationData) {
				t.Fatalf("notifyErr=%+v want notify=%+v", notifyErr, tc.notify)
			}
			group, ok, parseErr := InvalidKEPayloadAlternativeGroupFromError(err)
			if parseErr != nil || ok != tc.groupOK || group != tc.wantGroup {
				t.Fatalf("InvalidKEPayloadAlternativeGroupFromError() group=%d ok=%t err=%v, want group=%d ok=%t", group, ok, parseErr, tc.wantGroup, tc.groupOK)
			}
		})
	}
}

func TestDetectNATFromInitResponseNotifies(t *testing.T) {
	const spiI = uint64(0x0102030405060708)
	const spiR = uint64(0x1112131415161718)

	cases := []struct {
		name       string
		cfg        InitConfig
		sourceIP   string
		sourcePort uint16
		destIP     string
		destPort   uint16
		want       bool
	}{
		{
			name: "ipv4 exact addresses and ports",
			cfg: InitConfig{
				LocalIP:    net.ParseIP("192.0.2.10"),
				LocalPort:  500,
				RemoteIP:   net.ParseIP("198.51.100.20"),
				RemotePort: 500,
			},
			sourceIP:   "198.51.100.20",
			sourcePort: 500,
			destIP:     "192.0.2.10",
			destPort:   500,
		},
		{
			name: "ipv4 source port mismatch",
			cfg: InitConfig{
				LocalIP:    net.ParseIP("192.0.2.10"),
				LocalPort:  500,
				RemoteIP:   net.ParseIP("198.51.100.20"),
				RemotePort: 500,
			},
			sourceIP:   "198.51.100.20",
			sourcePort: 4500,
			destIP:     "192.0.2.10",
			destPort:   500,
			want:       true,
		},
		{
			name: "ipv4 destination port mismatch",
			cfg: InitConfig{
				LocalIP:    net.ParseIP("192.0.2.10"),
				LocalPort:  500,
				RemoteIP:   net.ParseIP("198.51.100.20"),
				RemotePort: 500,
			},
			sourceIP:   "198.51.100.20",
			sourcePort: 500,
			destIP:     "192.0.2.10",
			destPort:   4500,
			want:       true,
		},
		{
			name: "ipv6 exact addresses and ports",
			cfg: InitConfig{
				LocalIP:    net.ParseIP("2001:db8::10"),
				LocalPort:  4500,
				RemoteIP:   net.ParseIP("2001:db8::20"),
				RemotePort: 4500,
			},
			sourceIP:   "2001:db8::20",
			sourcePort: 4500,
			destIP:     "2001:db8::10",
			destPort:   4500,
		},
		{
			name: "ipv6 destination address mismatch",
			cfg: InitConfig{
				LocalIP:    net.ParseIP("2001:db8::10"),
				LocalPort:  4500,
				RemoteIP:   net.ParseIP("2001:db8::20"),
				RemotePort: 4500,
			},
			sourceIP:   "2001:db8::20",
			sourcePort: 4500,
			destIP:     "2001:db8::99",
			destPort:   4500,
			want:       true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			notifies := initNATNotifies(t, spiI, spiR, net.ParseIP(tc.sourceIP), tc.sourcePort, net.ParseIP(tc.destIP), tc.destPort)
			if got := detectNAT(notifies, spiI, spiR, tc.cfg); got != tc.want {
				t.Fatalf("detectNAT()=%t, want %t", got, tc.want)
			}
		})
	}
}

func TestUDPTransportExchangesWithNonESPMarker(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			done <- err
			return
		}
		if got := hex.EncodeToString(buf[:n]); got != "00000000010203" {
			done <- errors.New("unexpected UDP request " + got)
			return
		}
		_, err = conn.WriteTo([]byte{0, 0, 0, 0, 4, 5, 6}, addr)
		done <- err
	}()
	transport := UDPTransport{
		RemoteAddr:      conn.LocalAddr().String(),
		Timeout:         2 * time.Second,
		UseNonESPMarker: true,
	}
	resp, err := transport.ExchangeIKE(context.Background(), []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("ExchangeIKE() error = %v", err)
	}
	if hex.EncodeToString(resp) != "040506" {
		t.Fatalf("resp=%x", resp)
	}
	if err := <-done; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

type InitTransportFunc func(context.Context, []byte) ([]byte, error)

func (f InitTransportFunc) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	return f(ctx, request)
}

func countPayloadType(payloads []Payload, payloadType uint8) int {
	count := 0
	for _, p := range payloads {
		if p.Type == payloadType {
			count++
		}
	}
	return count
}

func firstPayloadBody(t *testing.T, payloads []Payload, payloadType uint8) []byte {
	t.Helper()
	for _, p := range payloads {
		if p.Type == payloadType {
			return append([]byte(nil), p.Body...)
		}
	}
	t.Fatalf("payload type %d not found in %+v", payloadType, payloads)
	return nil
}

func initCookieResponse(t *testing.T, spiI uint64, cookie []byte) []byte {
	t.Helper()
	cookiePayload, err := CookieNotify(cookie)
	if err != nil {
		t.Fatalf("CookieNotify() error = %v", err)
	}
	resp := Message{
		Header: Header{
			InitiatorSPI: spiI,
			ExchangeType: ExchangeIKE_SA_INIT,
			Flags:        FlagResponse,
		},
		Payloads: []Payload{cookiePayload},
	}
	out, err := resp.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(COOKIE response) error = %v", err)
	}
	return out
}

func runInitWithNotifyError(t *testing.T, notify Notify) error {
	t.Helper()
	transport := InitTransportFunc(func(ctx context.Context, request []byte) ([]byte, error) {
		req, err := ParseMessage(request)
		if err != nil {
			return nil, err
		}
		notifyPayload, err := NotifyPayload(notify)
		if err != nil {
			return nil, err
		}
		resp := Message{
			Header: Header{
				InitiatorSPI: req.Header.InitiatorSPI,
				ExchangeType: ExchangeIKE_SA_INIT,
				Flags:        FlagResponse,
			},
			Payloads: []Payload{notifyPayload},
		}
		return resp.MarshalBinary()
	})
	_, err := RunIKE_SA_INIT(context.Background(), InitConfig{
		Transport:        transport,
		InitiatorSPI:     1,
		NonceI:           bytes.Repeat([]byte{0x01}, 32),
		X25519PrivateKey: bytes.Repeat([]byte{0x02}, 32),
	})
	return err
}

func initNATNotifies(t *testing.T, spiI, spiR uint64, sourceIP net.IP, sourcePort uint16, destIP net.IP, destPort uint16) []Notify {
	t.Helper()
	source := initNATNotify(t, NotifyNATDetectionSourceIP, spiI, spiR, sourceIP, sourcePort)
	dest := initNATNotify(t, NotifyNATDetectionDestinationIP, spiI, spiR, destIP, destPort)
	return []Notify{source, dest}
}

func initNATNotify(t *testing.T, notifyType uint16, spiI, spiR uint64, ip net.IP, port uint16) Notify {
	t.Helper()
	payload, err := NATDetectionNotify(notifyType, spiI, spiR, ip, port)
	if err != nil {
		t.Fatalf("NATDetectionNotify() error = %v", err)
	}
	notify, err := ParseNotify(payload.Body)
	if err != nil {
		t.Fatalf("ParseNotify(NAT-D) error = %v", err)
	}
	return notify
}
