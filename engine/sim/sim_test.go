package sim

import (
	"bytes"
	"errors"
	"testing"
)

func TestSyncFailureErrorCarriesAUTS(t *testing.T) {
	auts := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D}
	err := NewSyncFailureError(auts)
	auts[0] = 0xFF

	if !errors.Is(err, ErrSyncFailure) {
		t.Fatalf("errors.Is(SyncFailureError, ErrSyncFailure) = false")
	}
	if got := err.Error(); got != ErrSyncFailure.Error() {
		t.Fatalf("SyncFailureError.Error() = %q, want %q", got, ErrSyncFailure.Error())
	}
	if got := err.AUTS(); !bytes.Equal(got, []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D}) {
		t.Fatalf("SyncFailureError.AUTS() = % X", got)
	}

	got := err.AUTS()
	got[0] = 0xEE
	if bytes.Equal(err.AUTS(), got) {
		t.Fatalf("SyncFailureError.AUTS() returned mutable backing storage")
	}
}

func TestMACFailureErrorWrapsAuthFailure(t *testing.T) {
	err := NewMACFailureError()
	if !errors.Is(err, ErrAuthFailure) {
		t.Fatalf("errors.Is(MACFailureError, ErrAuthFailure) = false")
	}
	if got := err.Error(); got != ErrAuthFailure.Error() {
		t.Fatalf("MACFailureError.Error() = %q, want %q", got, ErrAuthFailure.Error())
	}
}

func TestAKAAuthRequestCopiesAndValidatesInputs(t *testing.T) {
	rand16 := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}
	autn16 := []byte{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F}

	req, err := NewAKAAuthRequest(" ISIM ", rand16, autn16)
	if err != nil {
		t.Fatalf("NewAKAAuthRequest() error = %v", err)
	}
	if req.Application != AKAApplicationISIM {
		t.Fatalf("Application = %q, want ISIM", req.Application)
	}
	rand16[0] = 0xFF
	autn16[0] = 0xEE
	if req.RAND[0] != 0x10 || req.AUTN[0] != 0x30 {
		t.Fatalf("request aliases input buffers: RAND=% X AUTN=% X", req.RAND, req.AUTN)
	}

	clone := req.Clone()
	clone.RAND[0] = 0xAA
	clone.AUTN[0] = 0xBB
	if req.RAND[0] != 0x10 || req.AUTN[0] != 0x30 {
		t.Fatalf("Clone() returned mutable backing storage")
	}

	if _, err := NewAKAAuthRequest("", req.RAND[:15], req.AUTN); err == nil {
		t.Fatal("NewAKAAuthRequest(short RAND) err=nil, want error")
	}
	if _, err := NewAKAAuthRequest("mbim", req.RAND, req.AUTN); err == nil {
		t.Fatal("NewAKAAuthRequest(unsupported app) err=nil, want error")
	}
	if got := NormalizeAKAApplication(""); got != AKAApplicationUSIM {
		t.Fatalf("NormalizeAKAApplication(empty) = %q, want USIM", got)
	}
}
