package simauth

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"
)

type qmiUIMCall struct {
	op      string
	slot    uint8
	channel byte
	data    []byte
}

type fakeQMIUIMManager struct {
	calls          []qmiUIMCall
	openChannel    byte
	openErr        error
	closeErr       error
	sendResponses  [][]byte
	sendErr        error
	wantDeadline   bool
	deadlineOK     bool
	wantValue      any
	contextValueOK bool
}

func (f *fakeQMIUIMManager) OpenLogicalChannelContext(ctx context.Context, slot uint8, aid []byte) (byte, error) {
	f.checkContext(ctx)
	f.calls = append(f.calls, qmiUIMCall{op: "open", slot: slot, data: append([]byte(nil), aid...)})
	if f.openErr != nil {
		return 0, f.openErr
	}
	if f.openChannel != 0 {
		return f.openChannel, nil
	}
	return 1, nil
}

func (f *fakeQMIUIMManager) CloseLogicalChannelContext(ctx context.Context, slot uint8, channel byte) error {
	f.checkContext(ctx)
	f.calls = append(f.calls, qmiUIMCall{op: "close", slot: slot, channel: channel})
	return f.closeErr
}

func (f *fakeQMIUIMManager) SendAPDUContext(ctx context.Context, slot uint8, channel byte, apdu []byte) ([]byte, error) {
	f.checkContext(ctx)
	f.calls = append(f.calls, qmiUIMCall{op: "send", slot: slot, channel: channel, data: append([]byte(nil), apdu...)})
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	if len(f.sendResponses) == 0 {
		return []byte{0x90, 0x00}, nil
	}
	resp := f.sendResponses[0]
	f.sendResponses = f.sendResponses[1:]
	return append([]byte(nil), resp...), nil
}

func (f *fakeQMIUIMManager) checkContext(ctx context.Context) {
	if f.wantDeadline {
		if _, ok := ctx.Deadline(); ok {
			f.deadlineOK = true
		}
	}
	if f.wantValue != nil && ctx.Value(qmiUIMTestContextKey{}) == f.wantValue {
		f.contextValueOK = true
	}
}

type fakeQMIUIMAIDResolver struct {
	usim []byte
	isim []byte
	err  error
}

func (f *fakeQMIUIMAIDResolver) GetUSIMAID(context.Context) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]byte(nil), f.usim...), nil
}

func (f *fakeQMIUIMAIDResolver) GetISIMAID(context.Context) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]byte(nil), f.isim...), nil
}

type qmiUIMTestContextKey struct{}

func TestQMIUIMTransportOpenTransmitCloseMapsBytes(t *testing.T) {
	manager := &fakeQMIUIMManager{
		openChannel:   7,
		sendResponses: [][]byte{{0xDE, 0xAD, 0x90, 0x00}},
		wantDeadline:  true,
		wantValue:     "hooked",
	}
	transport := NewQMIUIMTransport(
		manager,
		WithQMIUIMSlot(2),
		WithQMIUIMTimeout(time.Minute),
		WithQMIUIMContextHook(func(ctx context.Context) context.Context {
			return context.WithValue(ctx, qmiUIMTestContextKey{}, "hooked")
		}),
	)

	channel, err := transport.OpenLogicalChannel("a0 00 00 00 87 10 02")
	if err != nil {
		t.Fatalf("OpenLogicalChannel() error = %v", err)
	}
	if channel != 7 {
		t.Fatalf("OpenLogicalChannel() = %d, want 7", channel)
	}
	resp, err := transport.TransmitAPDU(channel, "00 a4 04 00")
	if err != nil {
		t.Fatalf("TransmitAPDU() error = %v", err)
	}
	if resp != "DEAD9000" {
		t.Fatalf("TransmitAPDU() = %s, want DEAD9000", resp)
	}
	if err := transport.CloseLogicalChannel(channel); err != nil {
		t.Fatalf("CloseLogicalChannel() error = %v", err)
	}

	want := []qmiUIMCall{
		{op: "open", slot: 2, data: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}},
		{op: "send", slot: 2, channel: 7, data: []byte{0x00, 0xA4, 0x04, 0x00}},
		{op: "close", slot: 2, channel: 7},
	}
	if !reflect.DeepEqual(manager.calls, want) {
		t.Fatalf("calls = %#v, want %#v", manager.calls, want)
	}
	if !manager.deadlineOK || !manager.contextValueOK {
		t.Fatal("manager did not observe configured context options")
	}
}

func TestQMIUIMTransportResolvesUSIMAndISIMAIDs(t *testing.T) {
	resolver := &fakeQMIUIMAIDResolver{
		usim: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xFF},
		isim: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04, 0xEE},
	}
	transport := NewQMIUIMTransport(&fakeQMIUIMManager{}, WithQMIUIMAIDResolver(resolver))

	aid, source, err := transport.ResolveLogicalChannelAID("usim", USIMAIDPrefix)
	if err != nil {
		t.Fatalf("ResolveLogicalChannelAID(usim) error = %v", err)
	}
	if aid != USIMAIDPrefix+"FF" || source != "qmi_uim" {
		t.Fatalf("USIM AID = %s/%s, want full qmi_uim", aid, source)
	}

	aid, source, err = transport.ResolveLogicalChannelAID("isim", ISIMAIDPrefix)
	if err != nil {
		t.Fatalf("ResolveLogicalChannelAID(isim) error = %v", err)
	}
	if aid != ISIMAIDPrefix+"EE" || source != "qmi_uim" {
		t.Fatalf("ISIM AID = %s/%s, want full qmi_uim", aid, source)
	}
}

func TestQMIUIMTransportAIDFallbackWhenResolverMissingOrEmpty(t *testing.T) {
	transport := NewQMIUIMTransport(&fakeQMIUIMManager{})
	candidates, err := ResolveAIDCandidates(transport, "usim", USIMAIDPrefix, USIMAIDPrefix)
	if err != nil {
		t.Fatalf("ResolveAIDCandidates(missing resolver) error = %v", err)
	}
	if want := []LogicalChannelAIDCandidate{{AID: USIMAIDPrefix, Source: "fallback"}}; !reflect.DeepEqual(candidates, want) {
		t.Fatalf("missing resolver candidates = %#v, want %#v", candidates, want)
	}

	transport = NewQMIUIMTransport(&fakeQMIUIMManager{}, WithQMIUIMAIDResolver(&fakeQMIUIMAIDResolver{}))
	candidates, err = ResolveAIDCandidates(transport, "isim", ISIMAIDPrefix, ISIMAIDPrefix)
	if err != nil {
		t.Fatalf("ResolveAIDCandidates(empty resolver) error = %v", err)
	}
	if want := []LogicalChannelAIDCandidate{{AID: ISIMAIDPrefix, Source: "fallback"}}; !reflect.DeepEqual(candidates, want) {
		t.Fatalf("empty resolver candidates = %#v, want %#v", candidates, want)
	}
}

func TestQMIUIMTransportRejectsInvalidInputs(t *testing.T) {
	transport := NewQMIUIMTransport(&fakeQMIUIMManager{})
	tests := []struct {
		name string
		fn   func() error
	}{
		{name: "empty AID", fn: func() error { _, err := transport.OpenLogicalChannel(""); return err }},
		{name: "invalid AID", fn: func() error { _, err := transport.OpenLogicalChannel("A0ZZ"); return err }},
		{name: "close channel zero", fn: func() error { return transport.CloseLogicalChannel(0) }},
		{name: "close channel too large", fn: func() error { return transport.CloseLogicalChannel(256) }},
		{name: "transmit channel negative", fn: func() error { _, err := transport.TransmitAPDU(-1, "00A4"); return err }},
		{name: "empty APDU", fn: func() error { _, err := transport.TransmitAPDU(1, ""); return err }},
		{name: "invalid APDU", fn: func() error { _, err := transport.TransmitAPDU(1, "0"); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); err == nil {
				t.Fatal("err=nil, want error")
			}
		})
	}
	if len(transport.Manager.(*fakeQMIUIMManager).calls) != 0 {
		t.Fatalf("manager calls = %#v, want none", transport.Manager.(*fakeQMIUIMManager).calls)
	}
}

func TestQMIUIMTransportPropagatesManagerErrorsAndShortResponses(t *testing.T) {
	openErr := errors.New("open failed")
	transport := NewQMIUIMTransport(&fakeQMIUIMManager{openErr: openErr})
	if _, err := transport.OpenLogicalChannel(USIMAIDPrefix); !errors.Is(err, openErr) {
		t.Fatalf("OpenLogicalChannel() err = %v, want %v", err, openErr)
	}

	sendErr := errors.New("send failed")
	transport = NewQMIUIMTransport(&fakeQMIUIMManager{sendErr: sendErr})
	if _, err := transport.TransmitAPDU(1, "00A4"); !errors.Is(err, sendErr) {
		t.Fatalf("TransmitAPDU() err = %v, want %v", err, sendErr)
	}

	transport = NewQMIUIMTransport(&fakeQMIUIMManager{sendResponses: [][]byte{{0x90}}})
	if _, err := transport.TransmitAPDU(1, "00A4"); err == nil {
		t.Fatal("TransmitAPDU(short response) err=nil, want error")
	}
}

func TestQMIUIMTransportWorksWithAKAProvider(t *testing.T) {
	rand16 := bytesFrom(0x10, 16)
	autn16 := bytesFrom(0x30, 16)
	resp, err := hex.DecodeString(successfulAKAResponseHex())
	if err != nil {
		t.Fatalf("decode successful AKA response: %v", err)
	}
	manager := &fakeQMIUIMManager{
		openChannel:   4,
		sendResponses: [][]byte{resp},
	}
	transport := NewQMIUIMTransport(manager)
	provider := NewAKAProvider(transport)

	res, err := provider.CalculateAKA(rand16, autn16)
	if err != nil {
		t.Fatalf("CalculateAKA() error = %v", err)
	}
	if len(res.RES) != 4 || len(res.CK) != 16 || len(res.IK) != 16 {
		t.Fatalf("AKA result lengths = RES %d CK %d IK %d", len(res.RES), len(res.CK), len(res.IK))
	}
	wantAPDU, err := BuildUSIMAuthAPDU(rand16, autn16, false)
	if err != nil {
		t.Fatalf("BuildUSIMAuthAPDU() error = %v", err)
	}
	if len(manager.calls) != 3 {
		t.Fatalf("calls = %#v, want open/send/close", manager.calls)
	}
	if !bytes.Equal(manager.calls[0].data, mustDecodeHex(t, USIMAIDPrefix)) {
		t.Fatalf("open AID = % X, want %s", manager.calls[0].data, USIMAIDPrefix)
	}
	if manager.calls[1].channel != 4 || !bytes.Equal(manager.calls[1].data, wantAPDU) {
		t.Fatalf("send call = %#v, want channel 4 APDU % X", manager.calls[1], wantAPDU)
	}
	if manager.calls[2].op != "close" || manager.calls[2].channel != 4 {
		t.Fatalf("close call = %#v, want channel 4 close", manager.calls[2])
	}
}

func mustDecodeHex(t *testing.T, in string) []byte {
	t.Helper()
	out, err := hex.DecodeString(in)
	if err != nil {
		t.Fatalf("decode %s: %v", in, err)
	}
	return out
}
