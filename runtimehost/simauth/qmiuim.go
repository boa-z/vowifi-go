package simauth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

type QMIUIMManager interface {
	OpenLogicalChannelContext(context.Context, uint8, []byte) (byte, error)
	CloseLogicalChannelContext(context.Context, uint8, byte) error
	SendAPDUContext(context.Context, uint8, byte, []byte) ([]byte, error)
}

type QMIUIMAIDResolver interface {
	GetUSIMAID(context.Context) ([]byte, error)
	GetISIMAID(context.Context) ([]byte, error)
}

type QMIUIMContextHook func(context.Context) context.Context

type QMIUIMTransportOption func(*QMIUIMTransport)

type QMIUIMTransport struct {
	Manager     QMIUIMManager
	AIDResolver QMIUIMAIDResolver
	Slot        uint8
	Timeout     time.Duration
	ContextHook QMIUIMContextHook
}

var _ LogicalChannelTransport = (*QMIUIMTransport)(nil)
var _ LogicalChannelAIDResolver = (*QMIUIMTransport)(nil)

func NewQMIUIMTransport(manager QMIUIMManager, opts ...QMIUIMTransportOption) *QMIUIMTransport {
	t := &QMIUIMTransport{Manager: manager}
	for _, opt := range opts {
		if opt != nil {
			opt(t)
		}
	}
	return t
}

func WithQMIUIMSlot(slot uint8) QMIUIMTransportOption {
	return func(t *QMIUIMTransport) {
		t.Slot = slot
	}
}

func WithQMIUIMTimeout(timeout time.Duration) QMIUIMTransportOption {
	return func(t *QMIUIMTransport) {
		t.Timeout = timeout
	}
}

func WithQMIUIMAIDResolver(resolver QMIUIMAIDResolver) QMIUIMTransportOption {
	return func(t *QMIUIMTransport) {
		t.AIDResolver = resolver
	}
}

func WithQMIUIMContextHook(hook QMIUIMContextHook) QMIUIMTransportOption {
	return func(t *QMIUIMTransport) {
		t.ContextHook = hook
	}
}

func (t *QMIUIMTransport) OpenLogicalChannel(aid string) (int, error) {
	if t == nil || t.Manager == nil {
		return 0, errors.New("nil QMI UIM manager")
	}
	aidBytes, err := decodeQMIUIMHex("AID", aid)
	if err != nil {
		return 0, err
	}
	ctx, cancel, err := t.context()
	if err != nil {
		return 0, err
	}
	defer cancel()
	channel, err := t.Manager.OpenLogicalChannelContext(ctx, t.Slot, aidBytes)
	if err != nil {
		return 0, err
	}
	if channel == 0 {
		return 0, errors.New("QMI UIM opened invalid logical channel 0")
	}
	return int(channel), nil
}

func (t *QMIUIMTransport) CloseLogicalChannel(channel int) error {
	if t == nil || t.Manager == nil {
		return errors.New("nil QMI UIM manager")
	}
	channelByte, err := qmiUIMChannelByte(channel)
	if err != nil {
		return err
	}
	ctx, cancel, err := t.context()
	if err != nil {
		return err
	}
	defer cancel()
	return t.Manager.CloseLogicalChannelContext(ctx, t.Slot, channelByte)
}

func (t *QMIUIMTransport) TransmitAPDU(channel int, hexAPDU string) (string, error) {
	if t == nil || t.Manager == nil {
		return "", errors.New("nil QMI UIM manager")
	}
	channelByte, err := qmiUIMChannelByte(channel)
	if err != nil {
		return "", err
	}
	apdu, err := decodeQMIUIMHex("APDU", hexAPDU)
	if err != nil {
		return "", err
	}
	ctx, cancel, err := t.context()
	if err != nil {
		return "", err
	}
	defer cancel()
	resp, err := t.Manager.SendAPDUContext(ctx, t.Slot, channelByte, apdu)
	if err != nil {
		return "", err
	}
	if len(resp) < 2 {
		return "", fmt.Errorf("QMI UIM APDU response too short: %d", len(resp))
	}
	return strings.ToUpper(hex.EncodeToString(resp)), nil
}

func (t *QMIUIMTransport) ResolveLogicalChannelAID(app string, fallbackAID string) (string, string, error) {
	fallback := normalizeLogicalChannelAID(fallbackAID)
	if t == nil || t.AIDResolver == nil {
		if fallback == "" {
			return "", "", fmt.Errorf("%s AID is empty", qmiUIMAppName(app))
		}
		return fallback, "fallback", nil
	}
	ctx, cancel, err := t.context()
	if err != nil {
		return "", "", err
	}
	defer cancel()

	var aid []byte
	switch strings.ToLower(strings.TrimSpace(app)) {
	case "usim":
		aid, err = t.AIDResolver.GetUSIMAID(ctx)
	case "isim":
		aid, err = t.AIDResolver.GetISIMAID(ctx)
	default:
		if fallback == "" {
			return "", "", fmt.Errorf("%s AID is empty", qmiUIMAppName(app))
		}
		return fallback, "fallback", nil
	}
	if err != nil {
		return "", "", err
	}
	if len(aid) == 0 {
		if fallback == "" {
			return "", "", fmt.Errorf("%s AID is empty", qmiUIMAppName(app))
		}
		return fallback, "fallback", nil
	}
	return strings.ToUpper(hex.EncodeToString(aid)), "qmi_uim", nil
}

func (t *QMIUIMTransport) context() (context.Context, context.CancelFunc, error) {
	ctx := context.Background()
	cancel := func() {}
	if t != nil && t.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, t.Timeout)
	}
	if t != nil && t.ContextHook != nil {
		ctx = t.ContextHook(ctx)
		if ctx == nil {
			cancel()
			return nil, nil, errors.New("QMI UIM context hook returned nil context")
		}
	}
	return ctx, cancel, nil
}

func decodeQMIUIMHex(label string, in string) ([]byte, error) {
	compacted := compactHex(in)
	if compacted == "" {
		return nil, fmt.Errorf("%s is empty", label)
	}
	out, err := hex.DecodeString(compacted)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	return out, nil
}

func qmiUIMChannelByte(channel int) (byte, error) {
	if channel <= 0 || channel > 0xFF {
		return 0, fmt.Errorf("invalid logical channel: %d", channel)
	}
	return byte(channel), nil
}

func qmiUIMAppName(app string) string {
	app = strings.TrimSpace(app)
	if app == "" {
		return "application"
	}
	return app
}
