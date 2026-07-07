package simauth

import (
	"reflect"
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

func TestEncodeISIMIdentityStringRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		wantPrefix []byte
	}{
		{
			name:       "short",
			value:      "sip:user@ims.example",
			wantPrefix: []byte{0x80, 0x14},
		},
		{
			name:       "long one byte",
			value:      strings.Repeat("a", 130) + "@ims.example",
			wantPrefix: []byte{0x80, 0x81, 0x8E},
		},
		{
			name:       "long two byte",
			value:      strings.Repeat("b", 300),
			wantPrefix: []byte{0x80, 0x82, 0x01, 0x2C},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodeISIMIdentityString(tt.value)
			if err != nil {
				t.Fatalf("EncodeISIMIdentityString() error = %v", err)
			}
			if got := encoded[:len(tt.wantPrefix)]; !reflect.DeepEqual(got, tt.wantPrefix) {
				t.Fatalf("encoded prefix=% X, want % X", got, tt.wantPrefix)
			}
			if got := DecodeISIMIdentityString(encoded); got != tt.value {
				t.Fatalf("DecodeISIMIdentityString(encoded) = %q, want %q", got, tt.value)
			}
		})
	}
}

func TestPadISIMIdentityRecord(t *testing.T) {
	encoded, err := EncodeISIMIdentityString("sip:user@ims.example")
	if err != nil {
		t.Fatalf("EncodeISIMIdentityString() error = %v", err)
	}
	record, err := PadISIMIdentityRecord(encoded, len(encoded)+3)
	if err != nil {
		t.Fatalf("PadISIMIdentityRecord() error = %v", err)
	}
	if got := DecodeISIMIdentityString(record); got != "sip:user@ims.example" {
		t.Fatalf("DecodeISIMIdentityString(record) = %q", got)
	}
	if tail := record[len(encoded):]; !reflect.DeepEqual(tail, []byte{0xFF, 0xFF, 0xFF}) {
		t.Fatalf("record padding=% X", tail)
	}
	if got, err := PadISIMIdentityRecord(encoded, len(encoded)-1); err == nil {
		t.Fatalf("PadISIMIdentityRecord(short) = %x nil error, want error", got)
	}
	if got, err := EncodeISIMIdentityString(" "); err == nil {
		t.Fatalf("EncodeISIMIdentityString(empty) = %x nil error, want error", got)
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

func TestEncodeUSIMIMSIRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		imsi string
		want []byte
	}{
		{
			name: "odd digit count",
			imsi: "310260123456789",
			want: []byte{0x08, 0x39, 0x01, 0x62, 0x10, 0x32, 0x54, 0x76, 0x98},
		},
		{
			name: "significant trailing zero octet",
			imsi: "310260123456700",
			want: []byte{0x08, 0x39, 0x01, 0x62, 0x10, 0x32, 0x54, 0x76, 0x00},
		},
		{
			name: "even digit count",
			imsi: "00101012345678",
			want: []byte{0x08, 0x01, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0xF8},
		},
		{
			name: "minimum length",
			imsi: "12345",
			want: []byte{0x03, 0x19, 0x32, 0x54},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeUSIMIMSI(tt.imsi)
			if err != nil {
				t.Fatalf("EncodeUSIMIMSI() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("EncodeUSIMIMSI() = % X, want % X", got, tt.want)
			}
			decoded, err := DecodeUSIMIMSI(got)
			if err != nil {
				t.Fatalf("DecodeUSIMIMSI(EncodeUSIMIMSI()) error = %v", err)
			}
			if decoded != tt.imsi {
				t.Fatalf("DecodeUSIMIMSI(EncodeUSIMIMSI()) = %q, want %q", decoded, tt.imsi)
			}
		})
	}
}

func TestEncodeUSIMIMSIRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		imsi string
	}{
		{name: "empty", imsi: ""},
		{name: "blank", imsi: "   "},
		{name: "too short", imsi: "1234"},
		{name: "too long", imsi: "1234567890123456"},
		{name: "non digit", imsi: "31026A123456789"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := EncodeUSIMIMSI(tt.imsi); err == nil {
				t.Fatalf("EncodeUSIMIMSI() = % X nil error, want error", got)
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

func TestFormatEAPAKAPermanentIdentity(t *testing.T) {
	tests := []struct {
		name   string
		format func(string, string, string) (string, error)
		imsi   string
		mcc    string
		mnc    string
		want   string
	}{
		{
			name:   "aka with three digit mnc",
			format: FormatEAPAKAPermanentIdentity,
			imsi:   "001010123456789",
			mcc:    "001",
			mnc:    "010",
			want:   "0001010123456789@wlan.mnc010.mcc001.3gppnetwork.org",
		},
		{
			name:   "aka prime with two digit mnc",
			format: FormatEAPAKAPrimePermanentIdentity,
			imsi:   "310260123456789",
			mcc:    "310",
			mnc:    "26",
			want:   "6310260123456789@wlan.mnc026.mcc310.3gppnetwork.org",
		},
		{
			name:   "derive plmn from imsi",
			format: FormatEAPAKAPermanentIdentity,
			imsi:   "001010123456789",
			want:   "0001010123456789@wlan.mnc010.mcc001.3gppnetwork.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.format(tt.imsi, tt.mcc, tt.mnc)
			if err != nil {
				t.Fatalf("format() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("format() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseEAPAKAPermanentIdentity(t *testing.T) {
	tests := []struct {
		name string
		nai  string
		want EAPAKAPermanentIdentity
	}{
		{
			name: "aka",
			nai:  "0001010123456789@wlan.mnc010.mcc001.3gppnetwork.org",
			want: EAPAKAPermanentIdentity{
				Prefix: EAPAKAPermanentIdentityPrefix,
				IMSI:   "001010123456789",
				MCC:    "001",
				MNC:    "010",
				Realm:  "wlan.mnc010.mcc001.3gppnetwork.org",
			},
		},
		{
			name: "aka prime with two digit mnc",
			nai:  "6310260123456789@WLAN.MNC026.MCC310.3GPPNETWORK.ORG.",
			want: EAPAKAPermanentIdentity{
				Prefix: EAPAKAPrimePermanentIdentityPrefix,
				IMSI:   "310260123456789",
				MCC:    "310",
				MNC:    "26",
				Realm:  "wlan.mnc026.mcc310.3gppnetwork.org",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEAPAKAPermanentIdentity(tt.nai)
			if err != nil {
				t.Fatalf("ParseEAPAKAPermanentIdentity() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseEAPAKAPermanentIdentity() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestEAPAKAPermanentIdentityRejectsMalformedInput(t *testing.T) {
	badFormats := []struct {
		name string
		imsi string
		mcc  string
		mnc  string
	}{
		{name: "non digit imsi", imsi: "00101A123456789", mcc: "001", mnc: "010"},
		{name: "mcc mismatch", imsi: "001010123456789", mcc: "999", mnc: "010"},
		{name: "mnc mismatch", imsi: "001010123456789", mcc: "001", mnc: "011"},
		{name: "bad mnc length", imsi: "001010123456789", mcc: "001", mnc: "1"},
	}
	for _, tt := range badFormats {
		t.Run("format "+tt.name, func(t *testing.T) {
			if got, err := FormatEAPAKAPermanentIdentity(tt.imsi, tt.mcc, tt.mnc); err == nil {
				t.Fatalf("FormatEAPAKAPermanentIdentity() = %q nil error, want error", got)
			}
		})
	}

	badParses := []string{
		"001010123456789",
		"2001010123456789@wlan.mnc010.mcc001.3gppnetwork.org",
		"0001010123456789@ims.mnc010.mcc001.3gppnetwork.org",
		"0001010123456789@wlan.mnc011.mcc001.3gppnetwork.org",
		"0001010123456789@wlan.mnc01a.mcc001.3gppnetwork.org",
	}
	for _, nai := range badParses {
		t.Run("parse "+nai, func(t *testing.T) {
			if got, err := ParseEAPAKAPermanentIdentity(nai); err == nil {
				t.Fatalf("ParseEAPAKAPermanentIdentity() = %+v nil error, want error", got)
			}
		})
	}
}
