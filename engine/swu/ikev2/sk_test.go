package ikev2

import (
	"bytes"
	"crypto"
	"errors"
	"testing"
)

func TestKeyMaterialProfileAndSplitDefaultIKEProposal(t *testing.T) {
	profile, err := KeyMaterialProfileFromSA(DefaultIKEProposal())
	if err != nil {
		t.Fatalf("KeyMaterialProfileFromSA() error = %v", err)
	}
	if profile.PRF != crypto.SHA256 || profile.EncryptionKeyLength != 16 || profile.IntegrityChecksumLength != 16 {
		t.Fatalf("profile=%+v", profile)
	}
	if profile.RequiredLength() != DefaultIKEKeyMaterialLength {
		t.Fatalf("RequiredLength()=%d, want %d", profile.RequiredLength(), DefaultIKEKeyMaterialLength)
	}
	keys, err := SplitIKEKeys(profile, incrementalBytes(profile.RequiredLength()))
	if err != nil {
		t.Fatalf("SplitIKEKeys() error = %v", err)
	}
	if !bytes.Equal(keys.SKD, incrementalBytes(32)) {
		t.Fatalf("SK_d=%x", keys.SKD)
	}
	if !bytes.Equal(keys.SKAi, incrementalBytesRange(32, 64)) ||
		!bytes.Equal(keys.SKAr, incrementalBytesRange(64, 96)) ||
		!bytes.Equal(keys.SKEi, incrementalBytesRange(96, 112)) ||
		!bytes.Equal(keys.SKEr, incrementalBytesRange(112, 128)) ||
		!bytes.Equal(keys.SKPi, incrementalBytesRange(128, 160)) ||
		!bytes.Equal(keys.SKPr, incrementalBytesRange(160, 192)) {
		t.Fatalf("split keys=%+v", keys)
	}
}

func TestProtectAndUnprotectMessage(t *testing.T) {
	profile, err := KeyMaterialProfileFromSA(DefaultIKEProposal())
	if err != nil {
		t.Fatalf("KeyMaterialProfileFromSA() error = %v", err)
	}
	keys, err := SplitIKEKeys(profile, incrementalBytes(profile.RequiredLength()))
	if err != nil {
		t.Fatalf("SplitIKEKeys() error = %v", err)
	}
	idi, err := IdentityPayload(PayloadIDi, Identity{Type: IDRFC822Addr, Data: []byte("310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org")})
	if err != nil {
		t.Fatalf("IdentityPayload() error = %v", err)
	}
	cp, err := ConfigurationPayload(SWuConfigurationRequest())
	if err != nil {
		t.Fatalf("ConfigurationPayload() error = %v", err)
	}
	header := Header{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		ExchangeType: ExchangeIKE_AUTH,
		Flags:        FlagInitiator,
		MessageID:    1,
	}
	iv := bytes.Repeat([]byte{0xa5}, profile.EncryptionBlockSize)
	msg, raw, err := ProtectMessage(header, keys, true, []Payload{idi, cp}, iv)
	if err != nil {
		t.Fatalf("ProtectMessage() error = %v", err)
	}
	if msg.Header.NextPayload != 0 {
		t.Fatalf("message header should be set during marshal only: %+v", msg.Header)
	}
	if raw[16] != PayloadSK || raw[28] != PayloadIDi {
		t.Fatalf("raw header next=%d SK next=%d", raw[16], raw[28])
	}
	parsed, inner, err := UnprotectMessage(raw, keys, true)
	if err != nil {
		t.Fatalf("UnprotectMessage() error = %v", err)
	}
	if len(parsed.Payloads) != 1 || parsed.Payloads[0].Type != PayloadSK || parsed.Payloads[0].NextPayload != PayloadIDi {
		t.Fatalf("parsed=%+v", parsed)
	}
	if len(inner) != 2 || inner[0].Type != PayloadIDi || inner[1].Type != PayloadCP {
		t.Fatalf("inner=%+v", inner)
	}
	id, err := ParseIdentity(inner[0].Body)
	if err != nil {
		t.Fatalf("ParseIdentity() error = %v", err)
	}
	if string(id.Data) != "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org" {
		t.Fatalf("id=%+v", id)
	}
}

func TestUnprotectRejectsTamperedICV(t *testing.T) {
	profile, err := KeyMaterialProfileFromSA(DefaultIKEProposal())
	if err != nil {
		t.Fatalf("KeyMaterialProfileFromSA() error = %v", err)
	}
	keys, err := SplitIKEKeys(profile, incrementalBytes(profile.RequiredLength()))
	if err != nil {
		t.Fatalf("SplitIKEKeys() error = %v", err)
	}
	idi, err := IdentityPayload(PayloadIDi, Identity{Type: IDRFC822Addr, Data: []byte("user@example.com")})
	if err != nil {
		t.Fatalf("IdentityPayload() error = %v", err)
	}
	_, raw, err := ProtectMessage(Header{InitiatorSPI: 1, ResponderSPI: 2, ExchangeType: ExchangeIKE_AUTH, MessageID: 1}, keys, true, []Payload{idi}, bytes.Repeat([]byte{0x5a}, 16))
	if err != nil {
		t.Fatalf("ProtectMessage() error = %v", err)
	}
	raw[len(raw)-1] ^= 0xff
	_, _, err = UnprotectMessage(raw, keys, true)
	if !errors.Is(err, ErrInvalidSKPayload) {
		t.Fatalf("UnprotectMessage() err=%v, want ErrInvalidSKPayload", err)
	}
}

func TestMarshalRejectsOuterPayloadAfterSK(t *testing.T) {
	_, _, err := MarshalPayloads([]Payload{
		{Type: PayloadSK, NextPayload: PayloadIDi, Body: []byte{1, 2, 3, 4}},
		{Type: PayloadNotify, Body: []byte{1, 2, 3, 4}},
	})
	if !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("MarshalPayloads() err=%v, want ErrInvalidLength", err)
	}
}

func incrementalBytes(n int) []byte {
	return incrementalBytesRange(0, n)
}

func incrementalBytesRange(start, end int) []byte {
	out := make([]byte, end-start)
	for i := range out {
		out[i] = byte(start + i)
	}
	return out
}
