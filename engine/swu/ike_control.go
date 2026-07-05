package swu

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/iniwex5/vowifi-go/engine/swu/ikev2"
)

var ErrInvalidIKEControl = errors.New("invalid swu ike control")
var ErrMOBIKEUpdateRejected = errors.New("mobike update rejected")

type IKECloseConfig struct {
	Transport     ikev2.InitTransport
	Init          ikev2.InitResult
	Keys          ikev2.IKEKeys
	ChildSA       ikev2.ChildSAResult
	NextMessageID uint32
	Payloads      []ikev2.Payload
	Random        io.Reader
}

type IKEMOBIKEConfig struct {
	Transport             ikev2.InitTransport
	Init                  ikev2.InitResult
	Keys                  ikev2.IKEKeys
	NextMessageID         uint32
	Result                TunnelResult
	LocalIP               net.IP
	RemoteIP              net.IP
	LocalPort             uint16
	RemotePort            uint16
	AdditionalAddresses   []net.IP
	NoAdditionalAddresses bool
	Random                io.Reader
}

func NewIKECloseHandler(cfg IKECloseConfig) (func(context.Context) error, error) {
	if cfg.Transport == nil {
		return nil, fmt.Errorf("%w: transport is nil", ErrInvalidIKEControl)
	}
	if cfg.NextMessageID == 0 {
		return nil, fmt.Errorf("%w: next message_id is zero", ErrInvalidIKEControl)
	}
	payloads := cloneIKEPayloads(cfg.Payloads)
	if len(payloads) == 0 {
		var err error
		payloads, err = ikev2.TeardownDeletePayloads(cfg.ChildSA, true)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidIKEControl, err)
		}
	}
	return func(ctx context.Context) error {
		_, err := ikev2.RunInformationalExchange(ctx, ikev2.InformationalConfig{
			Transport: cfg.Transport,
			Init:      cfg.Init,
			Keys:      cfg.Keys,
			MessageID: cfg.NextMessageID,
			Payloads:  payloads,
			Random:    cfg.Random,
		})
		return err
	}, nil
}

func NewIKEMOBIKEHandler(cfg IKEMOBIKEConfig) (func(context.Context, MOBIKERequest) (MOBIKEResult, error), error) {
	if cfg.Transport == nil {
		return nil, fmt.Errorf("%w: transport is nil", ErrInvalidIKEControl)
	}
	if cfg.NextMessageID == 0 {
		return nil, fmt.Errorf("%w: next message_id is zero", ErrInvalidIKEControl)
	}
	additional := cloneIPs(cfg.AdditionalAddresses)
	var mu sync.Mutex
	nextMessageID := cfg.NextMessageID
	return func(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
		mu.Lock()
		defer mu.Unlock()
		payloads, err := mobikeUpdatePayloads(cfg, additional, req)
		if err != nil {
			return MOBIKEResult{}, err
		}
		res, err := ikev2.RunInformationalExchange(ctx, ikev2.InformationalConfig{
			Transport: cfg.Transport,
			Init:      cfg.Init,
			Keys:      cfg.Keys,
			MessageID: nextMessageID,
			Payloads:  payloads,
			Random:    cfg.Random,
		})
		if err != nil {
			return MOBIKEResult{}, err
		}
		if err := rejectMOBIKEResponse(res.ResponseInner); err != nil {
			return MOBIKEResult{}, err
		}
		nextMessageID = res.NextMessageID
		return MOBIKEResult{
			Rekeyed:          false,
			OuterLocalIP:     firstPacketNonEmpty(req.NewIP, req.OldIP, cfg.Result.EPDGAddress),
			LocalInnerIP:     cfg.Result.LocalInnerIP,
			RemoteInnerIP:    cfg.Result.RemoteInnerIP,
			IKEEstablished:   true,
			IPsecEstablished: true,
			Reason:           "mobike update sa addresses sent",
			UpdatedAt:        time.Now(),
		}, nil
	}, nil
}

func cloneIKEPayloads(in []ikev2.Payload) []ikev2.Payload {
	out := make([]ikev2.Payload, len(in))
	for i, p := range in {
		out[i] = ikev2.Payload{
			Type:        p.Type,
			NextPayload: p.NextPayload,
			Critical:    p.Critical,
			Body:        append([]byte(nil), p.Body...),
		}
	}
	return out
}

func mobikeUpdatePayloads(cfg IKEMOBIKEConfig, additional []net.IP, req MOBIKERequest) ([]ikev2.Payload, error) {
	payloads := []ikev2.Payload{ikev2.UpdateSAAddressesNotify()}
	localIP := normalizedMOBIKEIP(cfg.LocalIP, req.NewIP, req.OldIP)
	remoteIP := normalizedMOBIKEIP(cfg.RemoteIP)
	if localIP != nil && remoteIP != nil {
		localPort := cfg.LocalPort
		if localPort == 0 {
			localPort = 4500
		}
		remotePort := cfg.RemotePort
		if remotePort == 0 {
			remotePort = 4500
		}
		src, err := ikev2.NATDetectionNotify(ikev2.NotifyNATDetectionSourceIP, cfg.Init.InitiatorSPI, cfg.Init.ResponderSPI, localIP, localPort)
		if err != nil {
			return nil, err
		}
		dst, err := ikev2.NATDetectionNotify(ikev2.NotifyNATDetectionDestinationIP, cfg.Init.InitiatorSPI, cfg.Init.ResponderSPI, remoteIP, remotePort)
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, src, dst)
	}
	for _, ip := range additional {
		payload, err := ikev2.AdditionalIPAddressNotify(ip)
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, payload)
	}
	if cfg.NoAdditionalAddresses {
		payloads = append(payloads, ikev2.NoAdditionalAddressesNotify())
	}
	return payloads, nil
}

func rejectMOBIKEResponse(payloads []ikev2.Payload) error {
	for _, payload := range payloads {
		if payload.Type != ikev2.PayloadNotify {
			continue
		}
		notify, err := ikev2.ParseNotify(payload.Body)
		if err != nil {
			return err
		}
		switch notify.NotifyType {
		case ikev2.NotifyUnacceptableAddresses:
			return fmt.Errorf("%w: unacceptable addresses", ErrMOBIKEUpdateRejected)
		case ikev2.NotifyUnexpectedNATDetected:
			return fmt.Errorf("%w: unexpected NAT detected", ErrMOBIKEUpdateRejected)
		}
	}
	return nil
}

func normalizedMOBIKEIP(primary net.IP, fallbacks ...string) net.IP {
	if primary != nil {
		if ip := primary.To4(); ip != nil {
			return append(net.IP(nil), ip...)
		}
		if ip := primary.To16(); ip != nil {
			return append(net.IP(nil), ip...)
		}
	}
	for _, item := range fallbacks {
		ip := net.ParseIP(firstPacketNonEmpty(item))
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			return append(net.IP(nil), v4...)
		}
		if v6 := ip.To16(); v6 != nil {
			return append(net.IP(nil), v6...)
		}
	}
	return nil
}

func cloneIPs(in []net.IP) []net.IP {
	out := make([]net.IP, 0, len(in))
	for _, ip := range in {
		if normalized := normalizedMOBIKEIP(ip); normalized != nil {
			out = append(out, normalized)
		}
	}
	return out
}
