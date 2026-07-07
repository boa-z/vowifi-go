package simauth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	swusim "github.com/boa-z/vowifi-go/engine/sim"
)

const (
	AKAAppPreferenceUSIM       = "usim"
	AKAAppPreferenceAuto       = "auto"
	AKAAppPreferenceISIM       = "isim"
	AKAAppPreferenceISIMStrict = "isim_strict"

	AKARESMinLength = 4
	AKARESMaxLength = 16
	AKACKLength     = 16
	AKAIKLength     = 16
	AKAKcLength     = 8
	AKAAUTSLength   = 14
	AKAAKLength     = 6
	AKAMACLength    = 8

	defaultAKAAuthTransientRetries = 1
	defaultAKAAuthRetryDelay       = 200 * time.Millisecond
)

type AKAResult = swusim.AKAResult

type AUTSFields struct {
	SQNMSXorAK []byte
	MACS       []byte
}

type AKAProvider struct {
	Transport               LogicalChannelTransport
	AuthTransientRetries    int
	AuthTransientRetryDelay time.Duration

	retrySleep func(time.Duration)
}

func NewAKAProvider(t LogicalChannelTransport) *AKAProvider {
	return &AKAProvider{Transport: t}
}

func (p *AKAProvider) CalculateAKA(rand16, autn16 []byte) (AKAResult, error) {
	return p.CalculateAKAWithPreference(rand16, autn16, AKAAppPreferenceUSIM)
}

func (p *AKAProvider) CalculateISIMAKA(rand16, autn16 []byte) (AKAResult, error) {
	return p.CalculateAKAWithPreference(rand16, autn16, AKAAppPreferenceISIMStrict)
}

func (p *AKAProvider) CalculateAKAWithPreference(rand16, autn16 []byte, preference string) (AKAResult, error) {
	if p == nil || p.Transport == nil {
		return AKAResult{}, errors.New("nil AKA transport")
	}
	pref := strings.ToLower(strings.TrimSpace(preference))
	if pref == "" {
		pref = AKAAppPreferenceUSIM
	}
	switch pref {
	case AKAAppPreferenceAuto, AKAAppPreferenceISIM, AKAAppPreferenceISIMStrict:
		if res, err := p.calculateAKAOnApp("isim", ISIMAIDPrefix, ISIMAIDPrefix, rand16, autn16); err == nil {
			return res, nil
		} else if pref == AKAAppPreferenceISIMStrict {
			return AKAResult{}, err
		}
		return p.calculateAKAOnApp("usim", USIMAIDPrefix, USIMAIDPrefix, rand16, autn16)
	default:
		return p.calculateAKAOnApp("usim", USIMAIDPrefix, USIMAIDPrefix, rand16, autn16)
	}
}

func (p *AKAProvider) calculateAKAOnApp(app, fallbackAID, expectedPrefix string, rand16, autn16 []byte) (AKAResult, error) {
	ch, _, _, err := OpenLogicalChannelWithAIDFallback(p.Transport, app, fallbackAID, expectedPrefix)
	if err != nil {
		return AKAResult{}, err
	}
	defer func() { _ = p.Transport.CloseLogicalChannel(ch) }()

	apdu, err := BuildUSIMAuthAPDU(rand16, autn16, false)
	if err != nil {
		return AKAResult{}, err
	}
	resp, err := p.transmitUSIMAuth(ch, apdu)
	if err == nil && resp.Success() {
		return ParseUSIMAuthResponse(resp.Body, resp.SW1, resp.SW2)
	}

	apdu, buildErr := BuildUSIMAuthAPDU(rand16, autn16, true)
	if buildErr != nil {
		return AKAResult{}, buildErr
	}
	resp2, err2 := p.transmitUSIMAuth(ch, apdu)
	if err2 != nil {
		if err != nil {
			return AKAResult{}, fmt.Errorf("%s AKA failed: first=%v second=%v", strings.ToUpper(app), err, err2)
		}
		return AKAResult{}, err2
	}
	return ParseUSIMAuthResponse(resp2.Body, resp2.SW1, resp2.SW2)
}

func (p *AKAProvider) transmitUSIMAuth(channel int, apdu []byte) (Response, error) {
	retries := p.authTransientRetries()
	for attempt := 0; ; attempt++ {
		resp, err := Transmit(p.Transport, channel, apdu)
		if attempt >= retries || !isTransientUSIMAuthFailure(resp, err) {
			return resp, err
		}
		p.sleepBeforeAuthRetry(attempt)
	}
}

func (p *AKAProvider) authTransientRetries() int {
	if p.AuthTransientRetries < 0 {
		return 0
	}
	if p.AuthTransientRetries > 0 {
		return p.AuthTransientRetries
	}
	return defaultAKAAuthTransientRetries
}

func (p *AKAProvider) sleepBeforeAuthRetry(attempt int) {
	delay := p.authTransientRetryDelay(attempt)
	if delay <= 0 {
		return
	}
	if p.retrySleep != nil {
		p.retrySleep(delay)
		return
	}
	time.Sleep(delay)
}

func (p *AKAProvider) authTransientRetryDelay(attempt int) time.Duration {
	delay := p.AuthTransientRetryDelay
	if delay < 0 {
		return 0
	}
	if delay == 0 {
		delay = defaultAKAAuthRetryDelay
	}
	for i := 0; i < attempt; i++ {
		if delay > time.Hour/2 {
			return time.Hour
		}
		delay *= 2
	}
	return delay
}

type apduStatusCarrier interface {
	Status() uint16
}

func isTransientUSIMAuthFailure(resp Response, err error) bool {
	if err != nil {
		return isTransientUSIMAuthError(err)
	}
	return isTransientUSIMAuthStatus(resp.SW1, resp.SW2)
}

func isTransientUSIMAuthError(err error) bool {
	var status apduStatusCarrier
	if errors.As(err, &status) && isTransientUSIMAuthStatus(byte(status.Status()>>8), byte(status.Status())) {
		return true
	}
	s := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(s, "sim busy") ||
		strings.Contains(s, "apdu busy") ||
		strings.Contains(s, "temporarily not allowed") ||
		strings.Contains(s, "resource busy") ||
		strings.Contains(s, "at cme error: 14")
}

func isTransientUSIMAuthStatus(sw1, sw2 byte) bool {
	return sw1 == 0x93 ||
		(sw1 == 0x62 && sw2 == 0x83) ||
		(sw1 == 0x64 && sw2 == 0x00) ||
		sw1 == 0x65 ||
		(sw1 == 0x6F && sw2 == 0x00)
}

func BuildUSIMAuthAPDU(rand16, autn16 []byte, includeLe bool) ([]byte, error) {
	if len(rand16) != 16 {
		return nil, fmt.Errorf("RAND length must be 16 bytes: %d", len(rand16))
	}
	if len(autn16) != 16 {
		return nil, fmt.Errorf("AUTN length must be 16 bytes: %d", len(autn16))
	}
	authData := make([]byte, 0, 1+16+1+16)
	authData = append(authData, 0x10)
	authData = append(authData, rand16...)
	authData = append(authData, 0x10)
	authData = append(authData, autn16...)

	apdu := make([]byte, 0, 5+len(authData)+1)
	apdu = append(apdu, 0x00, 0x88, 0x00, 0x81, byte(len(authData)))
	apdu = append(apdu, authData...)
	if includeLe {
		apdu = append(apdu, 0x00)
	}
	return apdu, nil
}

func ParseUSIMAuthResponse(body []byte, sw1, sw2 byte) (AKAResult, error) {
	if sw1 != 0x90 || sw2 != 0x00 {
		resp := Response{SW1: sw1, SW2: sw2}
		return AKAResult{}, newStatusMessageError(fmt.Sprintf("APDU status is not 9000: %02X%02X", sw1, sw2), resp)
	}
	body = trimTLVPadding(body)
	if len(body) < 2 {
		return AKAResult{}, fmt.Errorf("AKA response body too short: %d", len(body))
	}

	if body[0] == 0xDB {
		if out, ok := parseUSIMAuthDB(body); ok {
			return out, nil
		}
	}
	if tag, data, ok, err := parseUSIMAuthTLV(body); err != nil {
		return AKAResult{}, err
	} else if ok {
		return parseUSIMAuthPayload(tag, data)
	}

	switch body[0] {
	case 0xDB:
		return AKAResult{}, errors.New("parse AKA success response failed")
	case 0xDC:
		return AKAResult{}, errors.New("parse AKA sync failure response failed")
	case 0xDD:
		return AKAResult{}, errors.New("parse AKA MAC failure response failed")
	default:
		return AKAResult{}, fmt.Errorf("unknown AKA response tag: 0x%02X", body[0])
	}
}

func ParseAUTS(auts14 []byte) (AUTSFields, error) {
	if len(auts14) != AKAAUTSLength {
		return AUTSFields{}, fmt.Errorf("AKA AUTS length must be %d bytes: %d", AKAAUTSLength, len(auts14))
	}
	return AUTSFields{
		SQNMSXorAK: append([]byte(nil), auts14[:AKAAKLength]...),
		MACS:       append([]byte(nil), auts14[AKAAKLength:]...),
	}, nil
}

func (a AUTSFields) Bytes() ([]byte, error) {
	if len(a.SQNMSXorAK) != AKAAKLength {
		return nil, fmt.Errorf("AKA AUTS SQN_MS xor AK length must be %d bytes: %d", AKAAKLength, len(a.SQNMSXorAK))
	}
	if len(a.MACS) != AKAMACLength {
		return nil, fmt.Errorf("AKA AUTS MAC-S length must be %d bytes: %d", AKAMACLength, len(a.MACS))
	}
	out := make([]byte, 0, AKAAUTSLength)
	out = append(out, a.SQNMSXorAK...)
	out = append(out, a.MACS...)
	return out, nil
}

func (a AUTSFields) SQNMS(ak []byte) ([]byte, error) {
	if len(a.SQNMSXorAK) != AKAAKLength {
		return nil, fmt.Errorf("AKA AUTS SQN_MS xor AK length must be %d bytes: %d", AKAAKLength, len(a.SQNMSXorAK))
	}
	if len(ak) != AKAAKLength {
		return nil, fmt.Errorf("AKA AK length must be %d bytes: %d", AKAAKLength, len(ak))
	}
	sqn := make([]byte, AKAAKLength)
	for i := range sqn {
		sqn[i] = a.SQNMSXorAK[i] ^ ak[i]
	}
	return sqn, nil
}

func parseSimpleTLVData(body []byte) ([]byte, error) {
	if len(body) < 2 {
		return nil, errors.New("response body too short")
	}
	l := int(body[1])
	if len(body) != 2+l {
		return nil, fmt.Errorf("response length mismatch: need=%d have=%d", 2+l, len(body))
	}
	return append([]byte(nil), body[2:2+l]...), nil
}

func parseUSIMAuthTLV(body []byte) (int, []byte, bool, error) {
	return parseUSIMAuthTLVDepth(body, 0)
}

func parseUSIMAuthTLVDepth(body []byte, depth int) (int, []byte, bool, error) {
	if depth > 4 {
		return 0, nil, false, errors.New("AKA response TLV nesting too deep")
	}
	body = trimTLVPadding(body)
	if len(body) == 0 {
		return 0, nil, false, errors.New("AKA response body empty")
	}
	tag, rest, err := readTag(body)
	if err != nil {
		return 0, nil, false, err
	}
	length, rest, err := readLength(rest)
	if err != nil {
		return 0, nil, false, err
	}
	if length > len(rest) {
		return 0, nil, false, fmt.Errorf("AKA response TLV tag 0x%X length %d exceeds remaining %d", tag, length, len(rest))
	}
	value := rest[:length]
	if tail := trimTLVPadding(rest[length:]); len(tail) != 0 {
		return 0, nil, false, fmt.Errorf("AKA response TLV tag 0x%X has %d trailing bytes", tag, len(tail))
	}
	switch tag {
	case 0xDB, 0xDC, 0xDD:
		return tag, append([]byte(nil), value...), true, nil
	default:
		if isConstructed(tag) {
			return parseUSIMAuthTLVDepth(value, depth+1)
		}
		return tag, nil, false, nil
	}
}

func parseUSIMAuthPayload(tag int, data []byte) (AKAResult, error) {
	switch tag {
	case 0xDB:
		body := make([]byte, 0, 1+len(data))
		body = append(body, 0xDB)
		body = append(body, data...)
		if out, ok := parseUSIMAuthDB(body); ok {
			return out, nil
		}
		return AKAResult{}, errors.New("parse AKA success response failed")
	case 0xDC:
		if _, err := ParseAUTS(data); err != nil {
			return AKAResult{}, err
		}
		auts := append([]byte(nil), data...)
		return AKAResult{AUTS: auts}, swusim.NewSyncFailureError(auts)
	case 0xDD:
		if len(data) != 0 {
			return AKAResult{}, fmt.Errorf("AKA MAC failure tag length must be 0 bytes: %d", len(data))
		}
		return AKAResult{}, swusim.NewMACFailureError()
	default:
		return AKAResult{}, fmt.Errorf("unknown AKA response tag: 0x%02X", tag)
	}
}

func parseUSIMAuthDB(body []byte) (AKAResult, bool) {
	if len(body) < 2 || body[0] != 0xDB {
		return AKAResult{}, false
	}
	pos := 1
	resLen := int(body[pos])
	pos++
	if resLen <= 0 || len(body) < pos+resLen+1 {
		return AKAResult{}, false
	}
	res := append([]byte(nil), body[pos:pos+resLen]...)
	if resLen < AKARESMinLength || resLen > AKARESMaxLength {
		return AKAResult{}, false
	}
	pos += resLen

	keyLen := AKACKLength + AKAIKLength
	remain := len(body) - pos
	if remain == keyLen {
		return AKAResult{
			RES: res,
			CK:  append([]byte(nil), body[pos:pos+AKACKLength]...),
			IK:  append([]byte(nil), body[pos+AKACKLength:pos+keyLen]...),
		}, true
	}

	ckLen := int(body[pos])
	pos++
	if ckLen != AKACKLength || len(body) < pos+ckLen+1 {
		return AKAResult{}, false
	}
	ck := append([]byte(nil), body[pos:pos+ckLen]...)
	pos += ckLen

	ikLen := int(body[pos])
	pos++
	if ikLen != AKAIKLength || len(body) < pos+ikLen {
		return AKAResult{}, false
	}
	ik := append([]byte(nil), body[pos:pos+ikLen]...)
	pos += ikLen
	// Some USIMs append Kc after CK/IK; AKAResult keeps the legacy RES/CK/IK surface.
	if len(body) != pos && !hasOnlyTLVPadding(body, pos) && !hasOptionalKc(body, pos) {
		return AKAResult{}, false
	}
	return AKAResult{RES: res, CK: ck, IK: ik}, true
}

func hasOptionalKc(body []byte, pos int) bool {
	return pos < len(body) &&
		int(body[pos]) == AKAKcLength &&
		pos+1+AKAKcLength <= len(body) &&
		hasOnlyTLVPadding(body, pos+1+AKAKcLength)
}

func hasOnlyTLVPadding(body []byte, pos int) bool {
	return pos <= len(body) && len(trimTLVPadding(body[pos:])) == 0
}
