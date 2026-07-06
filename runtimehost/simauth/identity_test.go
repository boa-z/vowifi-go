package simauth

import (
	"strings"
	"testing"
)

func TestDecodeISIMIdentityString(t *testing.T) {
	short := []byte{0x00, 0x80, 0x14}
	short = append(short, []byte("sip:user@ims.example")...)
	short = append(short, 0xFF)
	if got := DecodeISIMIdentityString(short); got != "sip:user@ims.example" {
		t.Fatalf("DecodeISIMIdentityString(short TLV) = %q", got)
	}

	longValue := strings.Repeat("a", 130) + "@private.example.test"
	longDO := append([]byte{0x80, 0x81, byte(len(longValue))}, []byte(longValue)...)
	wrapped := append([]byte{0xA0, 0x81, byte(len(longDO))}, longDO...)
	if got := DecodeISIMIdentityString(wrapped); got != longValue {
		t.Fatalf("DecodeISIMIdentityString(wrapped long TLV) length=%d, want %d", len(got), len(longValue))
	}

	plain := append([]byte{0x05}, []byte("hello")...)
	plain = append(plain, 0x00, 0xFF)
	if got := DecodeISIMIdentityString(plain); got != "hello" {
		t.Fatalf("DecodeISIMIdentityString(plain length) = %q", got)
	}
}

func TestDecodeUSIMIMSI(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "odd digit count",
			raw:  []byte{0x08, 0x39, 0x01, 0x62, 0x10, 0x32, 0x54, 0x76, 0x98, 0xFF},
			want: "310260123456789",
		},
		{
			name: "significant trailing zero octet",
			raw:  []byte{0x08, 0x39, 0x01, 0x62, 0x10, 0x32, 0x54, 0x76, 0x00, 0xFF},
			want: "310260123456700",
		},
		{
			name: "even digit count",
			raw:  []byte{0x08, 0x01, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0xF8},
			want: "00101012345678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeUSIMIMSI(tt.raw)
			if err != nil {
				t.Fatalf("DecodeUSIMIMSI() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("DecodeUSIMIMSI() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeUSIMIMSIRejectsMalformedEF(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: nil},
		{name: "length exceeds data", raw: []byte{0x09, 0x39, 0x01, 0x62, 0x10, 0x32, 0x54, 0x76, 0x98}},
		{name: "wrong identity type", raw: []byte{0x01, 0x38}},
		{name: "bad bcd digit", raw: []byte{0x02, 0x39, 0xFA}},
		{name: "bad even filler", raw: []byte{0x02, 0x31, 0x98}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := DecodeUSIMIMSI(tt.raw); err == nil {
				t.Fatalf("DecodeUSIMIMSI() = %q nil error, want error", got)
			}
		})
	}
}

func TestMNCLengthFromAD(t *testing.T) {
	if got, ok := MNCLengthFromAD([]byte{0x00, 0x00, 0x00, 0x03}); !ok || got != 3 {
		t.Fatalf("MNCLengthFromAD(3-digit) = %d/%v, want 3/true", got, ok)
	}
	if got, ok := MNCLengthFromAD([]byte{0x01, 0x02, 0x03, 0xF2}); !ok || got != 2 {
		t.Fatalf("MNCLengthFromAD(2-digit) = %d/%v, want 2/true", got, ok)
	}
	if got, ok := MNCLengthFromAD([]byte{0x00, 0x00, 0x00, 0x04}); ok || got != 0 {
		t.Fatalf("MNCLengthFromAD(invalid) = %d/%v, want 0/false", got, ok)
	}
	if got, ok := MNCLengthFromAD([]byte{0x00, 0x00, 0x00}); ok || got != 0 {
		t.Fatalf("MNCLengthFromAD(short) = %d/%v, want 0/false", got, ok)
	}
}
