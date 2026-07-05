package swu

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

func TestPacketSessionCloseSendsIKEDeletes(t *testing.T) {
	init := ikeControlInit(t)
	child := packetChildSA(true)
	control := &ikeCloseTransport{
		t:         t,
		init:      init,
		keys:      init.Keys,
		child:     child,
		messageID: 8,
	}
	handler, err := NewIKECloseHandler(IKECloseConfig{
		Transport:     control,
		Init:          init,
		ChildSA:       child,
		NextMessageID: 8,
	})
	if err != nil {
		t.Fatalf("NewIKECloseHandler() error = %v", err)
	}
	espTransport := &captureESPPacketTransport{}
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:      child,
		Transport:    espTransport,
		CloseHandler: handler,
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if control.requests != 1 || !control.sawChildDelete || !control.sawIKEDelete {
		t.Fatalf("control requests=%d child=%t ike=%t", control.requests, control.sawChildDelete, control.sawIKEDelete)
	}
	if !espTransport.closed {
		t.Fatalf("ESP transport was not closed")
	}
}

func TestNewIKECloseHandlerRejectsInvalidConfig(t *testing.T) {
	init := ikeControlInit(t)
	if _, err := NewIKECloseHandler(IKECloseConfig{Init: init, NextMessageID: 1}); !errors.Is(err, ErrInvalidIKEControl) {
		t.Fatalf("NewIKECloseHandler(missing transport) err=%v, want ErrInvalidIKEControl", err)
	}
	if _, err := NewIKECloseHandler(IKECloseConfig{Transport: &ikeCloseTransport{t: t}, Init: init}); !errors.Is(err, ErrInvalidIKEControl) {
		t.Fatalf("NewIKECloseHandler(missing msgid) err=%v, want ErrInvalidIKEControl", err)
	}
}

func TestNewIKEMOBIKEHandlerSendsUpdateSAAddresses(t *testing.T) {
	init := ikeControlInit(t)
	control := &ikeMOBIKETransport{
		t:          t,
		init:       init,
		keys:       init.Keys,
		messageIDs: []uint32{9, 10},
	}
	handler, err := NewIKEMOBIKEHandler(IKEMOBIKEConfig{
		Transport:             control,
		Init:                  init,
		NextMessageID:         9,
		Result:                TunnelResult{LocalInnerIP: "10.0.0.2", RemoteInnerIP: "10.0.0.1"},
		RemoteIP:              net.ParseIP("198.51.100.10"),
		LocalPort:             4500,
		RemotePort:            4500,
		AdditionalAddresses:   []net.IP{net.ParseIP("2001:db8::10")},
		NoAdditionalAddresses: true,
	})
	if err != nil {
		t.Fatalf("NewIKEMOBIKEHandler() error = %v", err)
	}
	res, err := handler(context.Background(), MOBIKERequest{OldIP: "192.0.2.20", NewIP: "192.0.2.21"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if control.requests != 1 || !control.sawUpdate || !control.sawNATSource || !control.sawNATDestination ||
		!control.sawAdditionalIPv6 || !control.sawNoAdditional {
		t.Fatalf("control=%+v", control)
	}
	if res.OuterLocalIP != "192.0.2.21" || !res.IKEEstablished || !res.IPsecEstablished ||
		res.LocalInnerIP != "10.0.0.2" || res.RemoteInnerIP != "10.0.0.1" ||
		res.Reason != "mobike update sa addresses sent" {
		t.Fatalf("res=%+v", res)
	}
	if _, err := handler(context.Background(), MOBIKERequest{OldIP: "192.0.2.21", NewIP: "192.0.2.22"}); err != nil {
		t.Fatalf("handler(second) error = %v", err)
	}
	if control.requests != 2 {
		t.Fatalf("requests=%d, want 2", control.requests)
	}
}

func TestNewIKEMOBIKEHandlerRejectsUnacceptableAddresses(t *testing.T) {
	init := ikeControlInit(t)
	control := &ikeMOBIKETransport{
		t:              t,
		init:           init,
		keys:           init.Keys,
		messageID:      10,
		responseNotify: ikev2.NotifyUnacceptableAddresses,
	}
	handler, err := NewIKEMOBIKEHandler(IKEMOBIKEConfig{
		Transport:     control,
		Init:          init,
		NextMessageID: 10,
	})
	if err != nil {
		t.Fatalf("NewIKEMOBIKEHandler() error = %v", err)
	}
	_, err = handler(context.Background(), MOBIKERequest{NewIP: "192.0.2.30"})
	if !errors.Is(err, ErrMOBIKEUpdateRejected) {
		t.Fatalf("handler() err=%v, want ErrMOBIKEUpdateRejected", err)
	}
}

func TestPacketSessionMOBIKEHandlerUpdatesResult(t *testing.T) {
	session, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: &captureESPPacketTransport{},
		Result: TunnelResult{
			Ready:            true,
			IKEEstablished:   true,
			IPsecEstablished: true,
			LocalInnerIP:     "10.0.0.2",
			RemoteInnerIP:    "10.0.0.1",
			Reason:           "packet tunnel ready",
		},
		MOBIKEHandler: func(context.Context, MOBIKERequest) (MOBIKEResult, error) {
			return MOBIKEResult{Reason: "mobike test update"}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewPacketSession() error = %v", err)
	}
	res, err := session.MOBIKE(context.Background(), MOBIKERequest{OldIP: "192.0.2.40", NewIP: "192.0.2.41"})
	if err != nil {
		t.Fatalf("MOBIKE() error = %v", err)
	}
	if res.OuterLocalIP != "192.0.2.41" || !res.IKEEstablished || !res.IPsecEstablished {
		t.Fatalf("res=%+v", res)
	}
	result := session.Result()
	if !result.Ready || result.Reason != "mobike test update" ||
		result.LocalInnerIP != "10.0.0.2" || result.RemoteInnerIP != "10.0.0.1" {
		t.Fatalf("result=%+v", result)
	}
}

type ikeCloseTransport struct {
	t              *testing.T
	init           ikev2.InitResult
	keys           ikev2.IKEKeys
	child          ikev2.ChildSAResult
	messageID      uint32
	requests       int
	sawChildDelete bool
	sawIKEDelete   bool
}

func (tr *ikeCloseTransport) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	tr.t.Helper()
	_, inner, err := ikev2.ParseInformationalRequest(request, tr.init, tr.keys, tr.messageID)
	if err != nil {
		tr.t.Fatalf("ParseInformationalRequest() error = %v", err)
	}
	tr.requests++
	for _, payload := range inner {
		if payload.Type != ikev2.PayloadDelete {
			continue
		}
		deletePayload, err := ikev2.ParseDelete(payload.Body)
		if err != nil {
			tr.t.Fatalf("ParseDelete() error = %v", err)
		}
		switch deletePayload.ProtocolID {
		case ikev2.ProtocolESP:
			if len(deletePayload.SPIs) != 1 || !bytes.Equal(deletePayload.SPIs[0], tr.child.LocalSPI) {
				tr.t.Fatalf("ESP delete=%+v, want local SPI %x", deletePayload, tr.child.LocalSPI)
			}
			tr.sawChildDelete = true
		case ikev2.ProtocolIKE:
			if len(deletePayload.SPIs) != 0 {
				tr.t.Fatalf("IKE delete=%+v, want no SPIs", deletePayload)
			}
			tr.sawIKEDelete = true
		}
	}
	_, raw, err := ikev2.BuildInformationalResponse(
		tr.init,
		tr.keys,
		tr.messageID,
		nil,
		bytes.Repeat([]byte{0x88}, tr.keys.Profile.EncryptionBlockSize),
	)
	if err != nil {
		tr.t.Fatalf("BuildInformationalResponse() error = %v", err)
	}
	return raw, nil
}

type ikeMOBIKETransport struct {
	t                 *testing.T
	init              ikev2.InitResult
	keys              ikev2.IKEKeys
	messageID         uint32
	messageIDs        []uint32
	responseNotify    uint16
	requests          int
	sawUpdate         bool
	sawNATSource      bool
	sawNATDestination bool
	sawAdditionalIPv6 bool
	sawNoAdditional   bool
}

func (tr *ikeMOBIKETransport) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	tr.t.Helper()
	messageID := tr.messageID
	if len(tr.messageIDs) > tr.requests {
		messageID = tr.messageIDs[tr.requests]
	}
	_, inner, err := ikev2.ParseInformationalRequest(request, tr.init, tr.keys, messageID)
	if err != nil {
		tr.t.Fatalf("ParseInformationalRequest() error = %v", err)
	}
	tr.requests++
	for _, payload := range inner {
		if payload.Type != ikev2.PayloadNotify {
			continue
		}
		notify, err := ikev2.ParseNotify(payload.Body)
		if err != nil {
			tr.t.Fatalf("ParseNotify() error = %v", err)
		}
		switch notify.NotifyType {
		case ikev2.NotifyUpdateSAAddresses:
			tr.sawUpdate = true
		case ikev2.NotifyNATDetectionSourceIP:
			if len(notify.NotificationData) != 20 {
				tr.t.Fatalf("NAT source hash len=%d", len(notify.NotificationData))
			}
			tr.sawNATSource = true
		case ikev2.NotifyNATDetectionDestinationIP:
			if len(notify.NotificationData) != 20 {
				tr.t.Fatalf("NAT destination hash len=%d", len(notify.NotificationData))
			}
			tr.sawNATDestination = true
		case ikev2.NotifyAdditionalIPv6Address:
			if !bytes.Equal(notify.NotificationData, net.ParseIP("2001:db8::10").To16()) {
				tr.t.Fatalf("additional IPv6=%x", notify.NotificationData)
			}
			tr.sawAdditionalIPv6 = true
		case ikev2.NotifyNoAdditionalAddresses:
			tr.sawNoAdditional = true
		}
	}
	var responseInner []ikev2.Payload
	if tr.responseNotify != 0 {
		responseInner = append(responseInner, ikev2.NotifyWithZeroSPI(tr.responseNotify, nil))
	}
	_, raw, err := ikev2.BuildInformationalResponse(
		tr.init,
		tr.keys,
		messageID,
		responseInner,
		bytes.Repeat([]byte{0x89}, tr.keys.Profile.EncryptionBlockSize),
	)
	if err != nil {
		tr.t.Fatalf("BuildInformationalResponse() error = %v", err)
	}
	return raw, nil
}

func ikeControlInit(t *testing.T) ikev2.InitResult {
	t.Helper()
	profile, err := ikev2.KeyMaterialProfileFromSA(ikev2.DefaultIKEProposal())
	if err != nil {
		t.Fatalf("KeyMaterialProfileFromSA() error = %v", err)
	}
	keys, err := ikev2.SplitIKEKeys(profile, ikeControlBytes(profile.RequiredLength()))
	if err != nil {
		t.Fatalf("SplitIKEKeys() error = %v", err)
	}
	return ikev2.InitResult{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		NonceI:       bytes.Repeat([]byte{0xa1}, 32),
		NonceR:       bytes.Repeat([]byte{0xb2}, 32),
		SelectedSA:   ikev2.DefaultIKEProposal(),
		Keys:         keys,
	}
}

func ikeControlBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}
