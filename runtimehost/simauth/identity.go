package simauth

import (
	"fmt"
	"math"
	"strings"
)

// DecodeISIMIdentityString decodes EF_IMPI, EF_IMPU, and EF_DOMAIN string data.
func DecodeISIMIdentityString(raw []byte) string {
	data := trimEFPadding(raw)
	if len(data) == 0 {
		return ""
	}
	if data[0] == 0x80 {
		if v, ok := decodeISIMDataObject(data[1:]); ok {
			return decodeISIMTextValue(v)
		}
	}
	if v, ok := FindTLV(data, 0x80); ok {
		if s := decodeISIMTextValue(v); s != "" {
			return s
		}
	}
	return decodeISIMStringValue(data)
}

// DecodeUSIMIMSI decodes the transparent EF_IMSI mobile-identity payload.
func DecodeUSIMIMSI(raw []byte) (string, error) {
	if len(trimEFPadding(raw)) == 0 {
		return "", fmt.Errorf("EF_IMSI data empty")
	}
	data := trimTrailingFF(raw)
	length := int(data[0])
	if length <= 0 {
		return "", fmt.Errorf("EF_IMSI length is zero")
	}
	if len(data)-1 < length {
		return "", fmt.Errorf("EF_IMSI length %d exceeds remaining %d", length, len(data)-1)
	}
	mobileID := data[1 : 1+length]
	if len(mobileID) == 0 {
		return "", fmt.Errorf("EF_IMSI mobile identity empty")
	}
	if mobileID[0]&0x07 != 0x01 {
		return "", fmt.Errorf("EF_IMSI mobile identity type is 0x%X, want IMSI", mobileID[0]&0x07)
	}
	oddDigits := mobileID[0]&0x08 != 0
	digits := make([]byte, 0, 1+2*(len(mobileID)-1))
	if !appendBCDDigit(&digits, mobileID[0]>>4) {
		return "", fmt.Errorf("EF_IMSI digit 1 is not BCD")
	}
	for i, b := range mobileID[1:] {
		if !appendBCDDigit(&digits, b&0x0F) {
			return "", fmt.Errorf("EF_IMSI digit %d is not BCD", len(digits)+1)
		}
		hi := b >> 4
		last := i == len(mobileID[1:])-1
		if last && !oddDigits {
			if hi != 0x0F {
				return "", fmt.Errorf("EF_IMSI even-length filler is 0x%X, want 0xF", hi)
			}
			continue
		}
		if !appendBCDDigit(&digits, hi) {
			return "", fmt.Errorf("EF_IMSI digit %d is not BCD", len(digits)+1)
		}
	}
	if oddDigits && len(digits)%2 == 0 {
		return "", fmt.Errorf("EF_IMSI odd/even indicator does not match %d digits", len(digits))
	}
	if !oddDigits && len(digits)%2 != 0 {
		return "", fmt.Errorf("EF_IMSI odd/even indicator does not match %d digits", len(digits))
	}
	return string(digits), nil
}

// MNCLengthFromAD returns the MNC length advertised in USIM EF_AD byte 4.
func MNCLengthFromAD(ad []byte) (int, bool) {
	if len(ad) < 4 {
		return 0, false
	}
	mncLen := int(ad[3] & 0x0F)
	if mncLen != 2 && mncLen != 3 {
		return 0, false
	}
	return mncLen, true
}

func decodeISIMDataObject(data []byte) ([]byte, bool) {
	l, rest, ok := readSIMStringLength(data)
	if !ok || len(rest) < l {
		return nil, false
	}
	return rest[:l], true
}

func decodeISIMStringValue(data []byte) string {
	data = trimEFPadding(data)
	if len(data) == 0 {
		return ""
	}
	if l, rest, ok := readSIMStringLength(data); ok && l > 0 && len(rest) >= l {
		return strings.TrimSpace(string(trimEFPadding(rest[:l])))
	}
	return strings.TrimSpace(string(data))
}

func decodeISIMTextValue(data []byte) string {
	data = trimEFPadding(data)
	if len(data) == 0 {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readSIMStringLength(data []byte) (int, []byte, bool) {
	if len(data) == 0 {
		return 0, nil, false
	}
	first := data[0]
	data = data[1:]
	if first&0x80 == 0 {
		return int(first), data, true
	}
	n := int(first & 0x7F)
	if n == 0 || n > 4 || len(data) < n {
		return 0, nil, false
	}
	length := 0
	for _, part := range data[:n] {
		if length > (math.MaxInt-int(part))/256 {
			return 0, nil, false
		}
		length = (length << 8) | int(part)
	}
	return length, data[n:], true
}

func trimEFPadding(data []byte) []byte {
	start := 0
	for start < len(data) && (data[start] == 0x00 || data[start] == 0xFF) {
		start++
	}
	end := len(data)
	for end > start && (data[end-1] == 0x00 || data[end-1] == 0xFF) {
		end--
	}
	return data[start:end]
}

func trimTrailingFF(data []byte) []byte {
	end := len(data)
	for end > 0 && data[end-1] == 0xFF {
		end--
	}
	return data[:end]
}

func appendBCDDigit(out *[]byte, nibble byte) bool {
	if nibble > 9 {
		return false
	}
	*out = append(*out, '0'+nibble)
	return true
}
