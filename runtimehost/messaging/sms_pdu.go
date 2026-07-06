package messaging

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const IMS3GPPSMSContentType = "application/vnd.3gpp.sms"
const SMSRPCauseTemporaryFailure byte = 41

type SMSRPDUKind string

const (
	SMSRPDUKindUnknown SMSRPDUKind = "UNKNOWN"
	SMSRPDUKindData    SMSRPDUKind = "RP-DATA"
	SMSRPDUKindAck     SMSRPDUKind = "RP-ACK"
	SMSRPDUKindError   SMSRPDUKind = "RP-ERROR"
)

type SMSRPDU struct {
	Kind             SMSRPDUKind
	RawType          byte
	MR               byte
	Cause            int
	CauseDiagnostics []byte
	Originator       string
	Destination      string
	TPDU             []byte
}

type SMSConcatInfo struct {
	IsConcat bool
	Ref      int
	RefBits  int
	Total    int
	Seq      int
}

type SMSUDHElement struct {
	Identifier byte
	Data       []byte
}

type SMSSpecialMessageIndication struct {
	Raw          byte
	StoreMessage bool
	ProfileID    int
	BasicType    int
	ExtendedType int
	MessageType  string
	Count        int
	Active       bool
	ReservedType bool
}

type SMSSMSCControlParameters struct {
	Raw                                      byte
	StatusReportTransactionCompleted         bool
	StatusReportPermanentError               bool
	StatusReportTemporaryErrorNoMoreAttempts bool
	StatusReportTemporaryErrorMoreAttempts   bool
	CancelSRRForRemainingConcatParts         bool
	IncludeOriginalUDHInStatusReport         bool
	ReservedBits                             byte
}

type SMSUDHSourceIndicator struct {
	Value       int
	Description string
}

type SMSUserDataHeaderInfo struct {
	Raw                       []byte
	Elements                  []SMSUDHElement
	Concat                    SMSConcatInfo
	HasPorts                  bool
	DestinationPort           int
	SourcePort                int
	PortBits                  int
	SpecialMessageIndications []SMSSpecialMessageIndication
	HasSMSCControl            bool
	SMSCControl               SMSSMSCControlParameters
	SourceIndicators          []SMSUDHSourceIndicator
	HasRFC822EmailHeader      bool
	RFC822EmailHeaderLength   int
	HasSingleShift            bool
	SingleShiftLang           int
	HasLockingShift           bool
	LockingShiftLang          int
}

type SMSDataCodingInfo struct {
	Raw                   byte
	Alphabet              string
	Compressed            bool
	AutoDelete            bool
	HasMessageClass       bool
	MessageClass          int
	MessageWaiting        bool
	MessageWaitingActive  bool
	MessageWaitingDiscard bool
	MessageWaitingType    string
	Reserved              bool
}

type SMSDeliver struct {
	Sender                 string
	Recipient              string
	Text                   string
	Timestamp              time.Time
	Concat                 SMSConcatInfo
	FirstOctet             byte
	ProtocolID             byte
	DataCodingScheme       byte
	DataCoding             SMSDataCodingInfo
	UserDataLength         int
	UserDataHeader         bool
	UserDataHeaderInfo     SMSUserDataHeaderInfo
	MoreMessagesToSend     bool
	StatusReportIndication bool
	ReplyPath              bool
	RawTPDU                []byte
}

type SMSStatusReport struct {
	Reference             byte
	Recipient             string
	Timestamp             time.Time
	DoneAt                time.Time
	Status                byte
	State                 string
	FirstOctet            byte
	MoreMessagesToSend    bool
	StatusReportQualifier bool
	UserDataHeader        bool
	ParameterIndicator    byte
	HasParameterIndicator bool
	ProtocolID            byte
	HasProtocolID         bool
	DataCodingScheme      byte
	HasDataCodingScheme   bool
	DataCoding            SMSDataCodingInfo
	UserDataLength        int
	UserDataHeaderInfo    SMSUserDataHeaderInfo
	UserData              string
	HasUserData           bool
	RawTPDU               []byte
}

func BuildSMSSubmitTPDU(to string, part SMSPart, mr byte) ([]byte, error) {
	number := normalizeSMSNumber(to)
	if number == "" {
		return nil, errors.New("sms destination address is empty")
	}
	digits, toa, bcd, err := encodeSMSAddress(number)
	if err != nil {
		return nil, err
	}
	dcsOverride, hasDCSOverride := smsSubmitDataCodingScheme(part)
	encoding, err := normalizeSMSSubmitEncodingWithLanguage(part.Text, part.Encoding, dcsOverride, hasDCSOverride, part.LockingShiftLang, part.SingleShiftLang)
	if err != nil {
		return nil, err
	}
	udh := append([]byte(nil), part.UDH...)
	if len(udh) == 0 {
		var err error
		udh, err = buildSMSSubmitUDHForPart(part)
		if err != nil {
			return nil, err
		}
	}
	firstOctet := byte(0x01)
	if part.RejectDuplicates {
		firstOctet |= 0x04
	}
	if part.RequestStatusReport {
		firstOctet |= 0x20
	}
	if len(udh) > 0 {
		firstOctet |= 0x40
	}
	if part.ReplyPath {
		firstOctet |= 0x80
	}
	vpf, vp, err := encodeSMSSubmitValidityPeriod(part.ValidityPeriod, part.ValidityDeadline)
	if err != nil {
		return nil, err
	}
	firstOctet |= vpf
	userData, udl, dcs, err := encodeSMSUserDataWithLanguage(part.Text, encoding, udh, part.LockingShiftLang, part.SingleShiftLang)
	if err != nil {
		return nil, err
	}
	if hasDCSOverride {
		dcs = dcsOverride
	}
	out := make([]byte, 0, 7+len(bcd)+len(vp)+len(userData))
	out = append(out, firstOctet, mr, byte(digits), toa)
	out = append(out, bcd...)
	out = append(out, smsSubmitProtocolID(part), dcs)
	out = append(out, vp...)
	out = append(out, byte(udl))
	out = append(out, userData...)
	return out, nil
}

func smsSubmitProtocolID(part SMSPart) byte {
	if part.UseProtocolID || part.ProtocolID != 0 {
		return part.ProtocolID
	}
	return 0
}

func smsSubmitDataCodingScheme(part SMSPart) (byte, bool) {
	if part.UseDataCodingScheme || part.DataCodingScheme != 0 {
		return part.DataCodingScheme, true
	}
	return 0, false
}

func normalizeSMSSubmitEncoding(text, requested string, dcs byte, hasDCS bool) (string, error) {
	encodingRequested := strings.TrimSpace(requested) != ""
	encoding := normalizeEncoding(text, requested)
	if !hasDCS {
		return encoding, nil
	}
	if !encodingRequested {
		encoding = smsEncodingForDCS(dcs)
	}
	if err := validateSMSSubmitDataCodingScheme(dcs, encoding); err != nil {
		return "", err
	}
	return encoding, nil
}

func smsEncodingForDCS(dcs byte) string {
	switch smsDCSAlphabet(dcs) {
	case "ucs2":
		return "ucs2"
	case "8bit":
		return "utf8"
	default:
		return "gsm7"
	}
}

func validateSMSSubmitDataCodingScheme(dcs byte, encoding string) error {
	info := ParseSMSDataCodingScheme(dcs)
	if info.Compressed {
		return fmt.Errorf("sms compressed data coding scheme is unsupported: 0x%02x", dcs)
	}
	want := info.Alphabet
	got := "gsm7"
	switch encoding {
	case "ucs2":
		got = "ucs2"
	case "utf8":
		got = "8bit"
	}
	if want != got {
		return fmt.Errorf("sms data coding scheme 0x%02x expects %s user data, got %s", dcs, want, got)
	}
	return nil
}

func encodeSMSSubmitValidityPeriod(relative time.Duration, absolute time.Time) (byte, []byte, error) {
	if relative != 0 && !absolute.IsZero() {
		return 0, nil, errors.New("sms validity period and deadline are mutually exclusive")
	}
	if !absolute.IsZero() {
		encoded, err := encodeSMSTimestamp(absolute)
		if err != nil {
			return 0, nil, err
		}
		return 0x18, encoded, nil
	}
	vp, ok, err := encodeSMSRelativeValidityPeriod(relative)
	if err != nil || !ok {
		return 0, nil, err
	}
	return 0x10, []byte{vp}, nil
}

func encodeSMSRelativeValidityPeriod(validity time.Duration) (byte, bool, error) {
	if validity == 0 {
		return 0, false, nil
	}
	if validity < 0 {
		return 0, false, fmt.Errorf("sms validity period is negative: %s", validity)
	}
	const (
		fiveMinutes  = 5 * time.Minute
		thirtyMinute = 30 * time.Minute
		twelveHours  = 12 * time.Hour
		oneDay       = 24 * time.Hour
		oneWeek      = 7 * oneDay
		maxValidity  = 63 * oneWeek
	)
	if validity > maxValidity {
		return 0, false, fmt.Errorf("sms validity period %s exceeds maximum %s", validity, maxValidity)
	}
	if validity <= twelveHours {
		return byte(ceilDuration(validity, fiveMinutes) - 1), true, nil
	}
	if validity <= oneDay {
		steps := ceilDuration(validity-twelveHours, thirtyMinute)
		if steps < 1 {
			steps = 1
		}
		return byte(143 + steps), true, nil
	}
	if validity <= 30*oneDay {
		days := ceilDuration(validity, oneDay)
		if days < 2 {
			days = 2
		}
		return byte(166 + days), true, nil
	}
	weeks := ceilDuration(validity, oneWeek)
	if weeks < 5 {
		weeks = 5
	}
	return byte(192 + weeks), true, nil
}

func ceilDuration(value, unit time.Duration) int64 {
	if value <= 0 {
		return 0
	}
	return int64((value + unit - 1) / unit)
}

func BuildSMSRPData(rpMR byte, smsc string, tpdu []byte) ([]byte, error) {
	if len(tpdu) > 255 {
		return nil, fmt.Errorf("SMS TPDU too long: %d", len(tpdu))
	}
	rpDA, err := encodeRPAddress(smsc)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 4+len(rpDA)+len(tpdu))
	out = append(out, 0x00, rpMR, 0x00)
	out = append(out, rpDA...)
	out = append(out, byte(len(tpdu)))
	out = append(out, tpdu...)
	return out, nil
}

func ParseSMSRPData(body []byte) (rpMR byte, tpdu []byte, err error) {
	rpdu, err := ParseSMSRPDU(body)
	if err != nil {
		return 0, nil, err
	}
	if rpdu.Kind != SMSRPDUKindData {
		return 0, nil, fmt.Errorf("not RP-DATA: 0x%02x", rpdu.RawType)
	}
	return rpdu.MR, append([]byte(nil), rpdu.TPDU...), nil
}

func ParseSMSRPDU(body []byte) (SMSRPDU, error) {
	if len(body) < 2 {
		return SMSRPDU{}, errors.New("RPDU too short")
	}
	rpdu := SMSRPDU{RawType: body[0], MR: body[1], Kind: SMSRPDUKindUnknown}
	switch body[0] {
	case 0x00, 0x01:
		rpdu.Kind = SMSRPDUKindData
		originator, destination, tpdu, err := parseSMSRPDataFields(body)
		if err != nil {
			return SMSRPDU{}, err
		}
		rpdu.Originator = originator
		rpdu.Destination = destination
		rpdu.TPDU = tpdu
	case 0x02, 0x03:
		rpdu.Kind = SMSRPDUKindAck
		tpdu, err := parseSMSRPUserData(body, 2, "RP-ACK")
		if err != nil {
			return SMSRPDU{}, err
		}
		rpdu.TPDU = tpdu
	case 0x04, 0x05:
		rpdu.Kind = SMSRPDUKindError
		cause, diagnostics, next, err := parseSMSRPErrorCauseFields(body)
		if err != nil {
			return SMSRPDU{}, err
		}
		rpdu.Cause = int(cause)
		rpdu.CauseDiagnostics = diagnostics
		tpdu, err := parseSMSRPUserData(body, next, "RP-ERROR")
		if err != nil {
			return SMSRPDU{}, err
		}
		rpdu.TPDU = tpdu
	default:
		return SMSRPDU{}, fmt.Errorf("unsupported RPDU type: 0x%02x", body[0])
	}
	return rpdu, nil
}

func parseSMSRPDataFields(body []byte) (originator string, destination string, tpdu []byte, err error) {
	if len(body) < 5 {
		return "", "", nil, errors.New("RP-DATA too short")
	}
	i := 1
	i++ // RP-MR
	if i >= len(body) {
		return "", "", nil, errors.New("RP originator address missing")
	}
	oaLen := int(body[i])
	i++
	if i+oaLen > len(body) {
		return "", "", nil, errors.New("RP originator address truncated")
	}
	if oaLen > 0 {
		originator, _ = decodeRPAddressValue(body[i : i+oaLen])
	}
	i += oaLen
	if i >= len(body) {
		return "", "", nil, errors.New("RP destination address missing")
	}
	daLen := int(body[i])
	i++
	if i+daLen > len(body) {
		return "", "", nil, errors.New("RP destination address truncated")
	}
	if daLen > 0 {
		destination, _ = decodeRPAddressValue(body[i : i+daLen])
	}
	i += daLen
	if i >= len(body) {
		return "", "", nil, errors.New("RP user data missing")
	}
	udLen := int(body[i])
	i++
	if i+udLen > len(body) {
		return "", "", nil, errors.New("RP user data truncated")
	}
	return originator, destination, append([]byte(nil), body[i:i+udLen]...), nil
}

func ParseSMSRPErrorCause(body []byte) (byte, error) {
	cause, _, _, err := parseSMSRPErrorCauseFields(body)
	return cause, err
}

func parseSMSRPErrorCauseFields(body []byte) (cause byte, diagnostics []byte, next int, err error) {
	if len(body) < 4 {
		return 0, nil, 0, errors.New("RP-ERROR too short")
	}
	if body[0] != 0x04 && body[0] != 0x05 {
		return 0, nil, 0, fmt.Errorf("not RP-ERROR: 0x%02x", body[0])
	}
	causeLen := int(body[2])
	if causeLen <= 0 {
		return 0, nil, 0, errors.New("RP-ERROR cause IE empty")
	}
	if 3+causeLen > len(body) {
		return 0, nil, 0, errors.New("RP-ERROR cause IE truncated")
	}
	if causeLen > 1 {
		diagnostics = append([]byte(nil), body[4:3+causeLen]...)
	}
	return body[3] & 0x7f, diagnostics, 3 + causeLen, nil
}

func parseSMSRPUserData(body []byte, offset int, label string) ([]byte, error) {
	if offset >= len(body) {
		return nil, nil
	}
	udLen := int(body[offset])
	offset++
	if offset+udLen > len(body) {
		return nil, fmt.Errorf("%s user data truncated", label)
	}
	if udLen == 0 {
		return nil, nil
	}
	return append([]byte(nil), body[offset:offset+udLen]...), nil
}

func BuildSMSRPAck(rpMR byte) []byte {
	return []byte{0x02, rpMR}
}

func BuildSMSRPAckWithTPDU(rpMR byte, tpdu []byte) ([]byte, error) {
	if len(tpdu) > 255 {
		return nil, fmt.Errorf("SMS TPDU too long: %d", len(tpdu))
	}
	out := make([]byte, 0, 3+len(tpdu))
	out = append(out, 0x02, rpMR, byte(len(tpdu)))
	out = append(out, tpdu...)
	return out, nil
}

func BuildSMSRPError(rpMR byte, cause byte) []byte {
	return []byte{0x04, rpMR, 0x01, cause, 0x00}
}

func smsRPCauseText(code int) string {
	switch code {
	case 1:
		return "RP cause 1: unassigned number"
	case 8:
		return "RP cause 8: operator determined barring"
	case 10:
		return "RP cause 10: call barred"
	case 21:
		return "RP cause 21: short message transfer rejected"
	case 22:
		return "RP cause 22: memory capacity exceeded"
	case 27:
		return "RP cause 27: destination out of order"
	case 28:
		return "RP cause 28: unidentified subscriber"
	case 29:
		return "RP cause 29: facility rejected"
	case 30:
		return "RP cause 30: unknown subscriber"
	case 38:
		return "RP cause 38: network out of order"
	case 41:
		return "RP cause 41: temporary failure"
	case 42:
		return "RP cause 42: congestion"
	case 47:
		return "RP cause 47: resources unavailable"
	case 50:
		return "RP cause 50: requested facility not subscribed"
	case 69:
		return "RP cause 69: requested facility not implemented"
	case 81:
		return "RP cause 81: invalid short message transfer reference"
	case 95:
		return "RP cause 95: semantically incorrect message"
	case 96:
		return "RP cause 96: invalid mandatory information"
	case 97:
		return "RP cause 97: message type not implemented"
	case 98:
		return "RP cause 98: message not compatible with SMS protocol state"
	case 99:
		return "RP cause 99: information element not implemented"
	case 111:
		return "RP cause 111: protocol error"
	case 127:
		return "RP cause 127: interworking unspecified"
	default:
		return ""
	}
}

func ParseSMSDeliverTPDU(tpdu []byte) (SMSDeliver, error) {
	raw := append([]byte(nil), tpdu...)
	if len(tpdu) < 12 {
		return SMSDeliver{}, errors.New("SMS-DELIVER TPDU too short")
	}
	firstOctet := tpdu[0]
	if firstOctet&0x03 != 0x00 {
		return SMSDeliver{}, fmt.Errorf("not SMS-DELIVER TPDU: 0x%02x", firstOctet&0x03)
	}
	i := 1
	oaDigits := int(tpdu[i])
	i++
	if i >= len(tpdu) {
		return SMSDeliver{}, errors.New("SMS-DELIVER originator address type missing")
	}
	oaTOA := tpdu[i]
	i++
	oaOctets, err := smsAddressOctets(oaDigits, oaTOA)
	if err != nil {
		return SMSDeliver{}, err
	}
	if i+oaOctets > len(tpdu) {
		return SMSDeliver{}, errors.New("SMS-DELIVER originator address truncated")
	}
	sender, err := decodeSMSAddress(oaDigits, oaTOA, tpdu[i:i+oaOctets])
	if err != nil {
		return SMSDeliver{}, err
	}
	i += oaOctets
	if i+10 > len(tpdu) {
		return SMSDeliver{}, errors.New("SMS-DELIVER fields truncated")
	}
	pid := tpdu[i]
	i++
	dcs := tpdu[i]
	i++
	ts, err := decodeSMSTimestamp(tpdu[i : i+7])
	if err != nil {
		return SMSDeliver{}, err
	}
	i += 7
	udl := int(tpdu[i])
	i++
	if i > len(tpdu) {
		return SMSDeliver{}, errors.New("SMS-DELIVER user data missing")
	}
	text, headerInfo, err := decodeSMSUserDataWithHeader(tpdu[i:], udl, dcs, firstOctet&0x40 != 0)
	if err != nil {
		return SMSDeliver{}, err
	}
	return SMSDeliver{
		Sender:                 sender,
		Text:                   text,
		Timestamp:              ts,
		Concat:                 headerInfo.Concat,
		FirstOctet:             firstOctet,
		ProtocolID:             pid,
		DataCodingScheme:       dcs,
		DataCoding:             ParseSMSDataCodingScheme(dcs),
		UserDataLength:         udl,
		UserDataHeader:         firstOctet&0x40 != 0,
		UserDataHeaderInfo:     headerInfo,
		MoreMessagesToSend:     firstOctet&0x04 == 0,
		StatusReportIndication: firstOctet&0x20 != 0,
		ReplyPath:              firstOctet&0x80 != 0,
		RawTPDU:                raw,
	}, nil
}

func ParseSMSStatusReportTPDU(tpdu []byte) (SMSStatusReport, error) {
	raw := append([]byte(nil), tpdu...)
	if len(tpdu) < 17 {
		return SMSStatusReport{}, errors.New("SMS-STATUS-REPORT TPDU too short")
	}
	if tpdu[0]&0x03 != 0x02 {
		return SMSStatusReport{}, fmt.Errorf("not SMS-STATUS-REPORT TPDU: 0x%02x", tpdu[0]&0x03)
	}
	i := 1
	report := SMSStatusReport{
		FirstOctet:            tpdu[0],
		MoreMessagesToSend:    tpdu[0]&0x04 == 0,
		StatusReportQualifier: tpdu[0]&0x20 != 0,
		UserDataHeader:        tpdu[0]&0x40 != 0,
		Reference:             tpdu[i],
		RawTPDU:               raw,
	}
	i++
	raDigits := int(tpdu[i])
	i++
	if i >= len(tpdu) {
		return SMSStatusReport{}, errors.New("SMS-STATUS-REPORT recipient address type missing")
	}
	raTOA := tpdu[i]
	i++
	raOctets, err := smsAddressOctets(raDigits, raTOA)
	if err != nil {
		return SMSStatusReport{}, err
	}
	if i+raOctets > len(tpdu) {
		return SMSStatusReport{}, errors.New("SMS-STATUS-REPORT recipient address truncated")
	}
	recipient, err := decodeSMSAddress(raDigits, raTOA, tpdu[i:i+raOctets])
	if err != nil {
		return SMSStatusReport{}, err
	}
	report.Recipient = recipient
	i += raOctets
	if i+15 > len(tpdu) {
		return SMSStatusReport{}, errors.New("SMS-STATUS-REPORT timestamps truncated")
	}
	report.Timestamp, err = decodeSMSTimestamp(tpdu[i : i+7])
	if err != nil {
		return SMSStatusReport{}, err
	}
	i += 7
	report.DoneAt, err = decodeSMSTimestamp(tpdu[i : i+7])
	if err != nil {
		return SMSStatusReport{}, err
	}
	i += 7
	report.Status = tpdu[i]
	report.State = smsStatusReportState(report.Status)
	i++
	if i < len(tpdu) {
		if err := parseSMSStatusReportOptionalParameters(tpdu[i:], &report); err != nil {
			return SMSStatusReport{}, err
		}
	}
	return report, nil
}

func parseSMSStatusReportOptionalParameters(data []byte, report *SMSStatusReport) error {
	if len(data) == 0 || report == nil {
		return nil
	}
	i := 0
	report.ParameterIndicator = data[i]
	report.HasParameterIndicator = true
	i++
	if report.ParameterIndicator&0x01 != 0 {
		if i >= len(data) {
			return errors.New("SMS-STATUS-REPORT PID missing")
		}
		report.ProtocolID = data[i]
		report.HasProtocolID = true
		i++
	}
	if report.ParameterIndicator&0x02 != 0 {
		if i >= len(data) {
			return errors.New("SMS-STATUS-REPORT DCS missing")
		}
		report.DataCodingScheme = data[i]
		report.DataCoding = ParseSMSDataCodingScheme(report.DataCodingScheme)
		report.HasDataCodingScheme = true
		i++
	}
	if report.ParameterIndicator&0x04 != 0 {
		if i >= len(data) {
			return errors.New("SMS-STATUS-REPORT UDL missing")
		}
		udl := int(data[i])
		i++
		if i > len(data) {
			return errors.New("SMS-STATUS-REPORT user data missing")
		}
		dcs := report.DataCodingScheme
		text, headerInfo, err := decodeSMSUserDataWithHeader(data[i:], udl, dcs, report.UserDataHeader)
		if err != nil {
			return err
		}
		report.UserDataLength = udl
		report.UserDataHeaderInfo = headerInfo
		report.UserData = text
		report.HasUserData = true
	}
	return nil
}

func encodeSMSUserData(text, encoding string, udh []byte) ([]byte, int, byte, error) {
	return encodeSMSUserDataWithLanguage(text, encoding, udh, 0, 0)
}

func encodeSMSUserDataWithLanguage(text, encoding string, udh []byte, lockingLang, singleLang int) ([]byte, int, byte, error) {
	switch encoding {
	case "gsm7":
		septets, err := encodeGSM7WithLanguage(text, lockingLang, singleLang)
		if err != nil {
			return nil, 0, 0, err
		}
		userData := append([]byte(nil), udh...)
		fillBits := 0
		if len(udh) > 0 {
			fillBits = (7 - ((len(udh) * 8) % 7)) % 7
		}
		userData = append(userData, packSeptets(septets, fillBits)...)
		udl := len(septets)
		if len(udh) > 0 {
			udl += (len(udh)*8 + 6) / 7
		}
		return userData, udl, 0x00, nil
	case "utf8":
		userData := append([]byte(nil), udh...)
		userData = append(userData, []byte(text)...)
		return userData, len(userData), 0x04, nil
	default:
		userData := append([]byte(nil), udh...)
		for _, unit := range utf16.Encode([]rune(text)) {
			userData = append(userData, byte(unit>>8), byte(unit))
		}
		return userData, len(userData), 0x08, nil
	}
}

func encodeGSM7(text string) ([]byte, error) {
	return encodeGSM7WithLanguage(text, 0, 0)
}

func encodeGSM7WithLanguage(text string, lockingLang, singleLang int) ([]byte, error) {
	out := make([]byte, 0, len(text))
	for _, r := range text {
		if idx, ok := gsm7LockingCode(r, lockingLang); ok {
			out = append(out, idx)
			continue
		}
		ext, ok := gsm7SingleShiftCode(r, singleLang)
		if !ok {
			return nil, fmt.Errorf("character %q is not in GSM 7-bit alphabet", r)
		}
		out = append(out, 0x1b, ext)
	}
	return out, nil
}

func gsm7SeptetLen(text string) (int, bool) {
	return gsm7SeptetLenWithLanguage(text, 0, 0)
}

func gsm7SeptetLenWithLanguage(text string, lockingLang, singleLang int) (int, bool) {
	septets := 0
	for _, r := range text {
		if _, ok := gsm7LockingCode(r, lockingLang); ok {
			septets++
			continue
		}
		if _, ok := gsm7SingleShiftCode(r, singleLang); ok {
			septets += 2
			continue
		}
		return 0, false
	}
	return septets, true
}

func takeGSM7Chunk(text string, limit int) (string, string) {
	return takeGSM7ChunkWithLanguage(text, limit, 0, 0)
}

func takeGSM7ChunkWithLanguage(text string, limit int, lockingLang, singleLang int) (string, string) {
	if text == "" || limit <= 0 {
		return "", text
	}
	used := 0
	end := 0
	for pos, r := range text {
		charSeptets := 0
		switch {
		case gsm7CanEncodeLocking(r, lockingLang):
			charSeptets = 1
		default:
			if _, ok := gsm7SingleShiftCode(r, singleLang); ok {
				charSeptets = 2
			} else {
				charSeptets = 1
			}
		}
		if used > 0 && used+charSeptets > limit {
			break
		}
		used += charSeptets
		_, size := utf8.DecodeRuneInString(text[pos:])
		end = pos + size
		if used >= limit {
			break
		}
	}
	if end <= 0 {
		_, size := utf8.DecodeRuneInString(text)
		end = size
	}
	return text[:end], text[end:]
}

func gsm7CanEncodeLocking(r rune, lockingLang int) bool {
	_, ok := gsm7LockingCode(r, lockingLang)
	return ok
}

func gsm7Code(r rune) int {
	for i, candidate := range gsm7BasicAlphabet {
		if candidate == r {
			return i
		}
	}
	return -1
}

func gsm7ExtensionCode(r rune) (byte, bool) {
	return gsm7SingleShiftCode(r, 0)
}

var gsm7BasicAlphabet = []rune{
	'@', '£', '$', '¥', 'è', 'é', 'ù', 'ì',
	'ò', 'Ç', '\n', 'Ø', 'ø', '\r', 'Å', 'å',
	'Δ', '_', 'Φ', 'Γ', 'Λ', 'Ω', 'Π', 'Ψ',
	'Σ', 'Θ', 'Ξ', '\x1b', 'Æ', 'æ', 'ß', 'É',
	' ', '!', '"', '#', '¤', '%', '&', '\'',
	'(', ')', '*', '+', ',', '-', '.', '/',
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', ':', ';', '<', '=', '>', '?',
	'¡', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
	'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
	'X', 'Y', 'Z', 'Ä', 'Ö', 'Ñ', 'Ü', '§',
	'¿', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
	'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
	'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
	'x', 'y', 'z', 'ä', 'ö', 'ñ', 'ü', 'à',
}

func packSeptets(septets []byte, bitOffset int) []byte {
	if len(septets) == 0 {
		return nil
	}
	totalBits := bitOffset + len(septets)*7
	out := make([]byte, (totalBits+7)/8)
	for i, septet := range septets {
		bitPos := bitOffset + i*7
		bytePos := bitPos / 8
		shift := bitPos % 8
		out[bytePos] |= (septet & 0x7f) << shift
		if shift > 1 && bytePos+1 < len(out) {
			out[bytePos+1] |= (septet & 0x7f) >> (8 - shift)
		}
	}
	return out
}

func unpackSeptets(data []byte, septetCount int, bitOffset int) []byte {
	if septetCount <= 0 {
		return nil
	}
	out := make([]byte, 0, septetCount)
	for i := 0; i < septetCount; i++ {
		bitPos := bitOffset + i*7
		bytePos := bitPos / 8
		shift := bitPos % 8
		if bytePos >= len(data) {
			break
		}
		value := (data[bytePos] >> shift) & 0x7f
		if shift > 1 && bytePos+1 < len(data) {
			value |= (data[bytePos+1] << (8 - shift)) & 0x7f
		}
		out = append(out, value)
	}
	return out
}

func encodeRPAddress(number string) ([]byte, error) {
	number = normalizeSMSNumber(number)
	if number == "" {
		return []byte{0x00}, nil
	}
	_, toa, bcd, err := encodeSMSAddress(number)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 2+len(bcd))
	out = append(out, byte(1+len(bcd)), toa)
	out = append(out, bcd...)
	return out, nil
}

func decodeRPAddressValue(value []byte) (string, error) {
	if len(value) == 0 {
		return "", nil
	}
	return decodeSMSAddress((len(value)-1)*2, value[0], value[1:])
}

func smsAddressOctets(digits int, toa byte) (int, error) {
	if digits < 0 {
		return 0, errors.New("sms address digit count is invalid")
	}
	if toa&0x70 == 0x50 {
		return (digits*7 + 7) / 8, nil
	}
	return (digits + 1) / 2, nil
}

func encodeSMSAddress(number string) (digits int, toa byte, bcd []byte, err error) {
	number = normalizeSMSNumber(number)
	if number == "" {
		return 0, 0, nil, errors.New("sms address is empty")
	}
	toa = 0x81
	if strings.HasPrefix(number, "+") {
		toa = 0x91
		number = strings.TrimPrefix(number, "+")
	}
	if number == "" {
		return 0, 0, nil, errors.New("sms address has no digits")
	}
	for _, r := range number {
		if _, ok := smsAddressSemiOctet(r); !ok {
			return 0, 0, nil, fmt.Errorf("sms address contains unsupported digit %q", r)
		}
	}
	digits = len(number)
	bcd = make([]byte, (digits+1)/2)
	for i := 0; i < digits; i++ {
		d, _ := smsAddressSemiOctet(rune(number[i]))
		if i%2 == 0 {
			bcd[i/2] |= d
		} else {
			bcd[i/2] |= d << 4
		}
	}
	if digits%2 != 0 {
		bcd[digits/2] |= 0xf0
	}
	return digits, toa, bcd, nil
}

func smsAddressSemiOctet(r rune) (byte, bool) {
	switch {
	case r >= '0' && r <= '9':
		return byte(r - '0'), true
	case r == '*':
		return 0x0a, true
	case r == '#':
		return 0x0b, true
	case r == 'a' || r == 'A':
		return 0x0c, true
	case r == 'b' || r == 'B':
		return 0x0d, true
	case r == 'c' || r == 'C':
		return 0x0e, true
	default:
		return 0, false
	}
}

func smsAddressSemiOctetDigit(nibble byte) (byte, bool) {
	switch {
	case nibble <= 9:
		return '0' + nibble, true
	case nibble == 0x0a:
		return '*', true
	case nibble == 0x0b:
		return '#', true
	case nibble == 0x0c:
		return 'a', true
	case nibble == 0x0d:
		return 'b', true
	case nibble == 0x0e:
		return 'c', true
	default:
		return 0, false
	}
}

func decodeSMSAddress(digits int, toa byte, bcd []byte) (string, error) {
	if digits < 0 {
		return "", errors.New("sms address digit count is invalid")
	}
	if toa&0x70 == 0x50 {
		return decodeGSM7(unpackSeptets(bcd, digits, 0)), nil
	}
	var b strings.Builder
	if toa&0x70 == 0x10 {
		b.WriteByte('+')
	}
	written := 0
	for _, item := range bcd {
		for _, nibble := range []byte{item & 0x0f, (item >> 4) & 0x0f} {
			if written >= digits {
				break
			}
			if nibble == 0x0f {
				return b.String(), nil
			}
			digit, ok := smsAddressSemiOctetDigit(nibble)
			if !ok {
				return "", fmt.Errorf("invalid BCD digit: 0x%x", nibble)
			}
			b.WriteByte(digit)
			written++
		}
	}
	if written < digits {
		return "", errors.New("sms address truncated")
	}
	return b.String(), nil
}

func normalizeSMSNumber(value string) string {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		if _, rest, ok := strings.Cut(value, ":"); ok {
			value = rest
		}
		if user, _, ok := strings.Cut(value, "@"); ok {
			value = user
		}
	}
	if strings.HasPrefix(strings.ToLower(value), "tel:") {
		value = strings.TrimSpace(value[4:])
	}
	if semi := strings.IndexByte(value, ';'); semi >= 0 {
		value = value[:semi]
	}
	value = strings.Trim(value, "<>")
	var b strings.Builder
	for i, r := range value {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && i == 0:
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '(' || r == ')':
			continue
		default:
			return strings.TrimSpace(value)
		}
	}
	return b.String()
}

func decodeSMSUserData(data []byte, udl int, dcs byte, hasUDH bool) (string, SMSConcatInfo, error) {
	text, headerInfo, err := decodeSMSUserDataWithHeader(data, udl, dcs, hasUDH)
	return text, headerInfo.Concat, err
}

func decodeSMSUserDataWithHeader(data []byte, udl int, dcs byte, hasUDH bool) (string, SMSUserDataHeaderInfo, error) {
	if udl < 0 {
		return "", SMSUserDataHeaderInfo{}, errors.New("SMS user data length is invalid")
	}
	udh, payload, headerSeptets, headerInfo, err := splitSMSUDH(data, hasUDH)
	if err != nil {
		return "", SMSUserDataHeaderInfo{}, err
	}
	switch smsDCSAlphabet(dcs) {
	case "ucs2":
		payloadOctets := udl
		if hasUDH {
			payloadOctets -= len(udh)
		}
		if payloadOctets < 0 || payloadOctets > len(payload) {
			payloadOctets = len(payload)
		}
		text, err := decodeUCS2(payload[:payloadOctets])
		return text, headerInfo, err
	case "8bit":
		payloadOctets := udl
		if hasUDH {
			payloadOctets -= len(udh)
		}
		if payloadOctets < 0 || payloadOctets > len(payload) {
			payloadOctets = len(payload)
		}
		return strings.ToValidUTF8(string(payload[:payloadOctets]), ""), headerInfo, nil
	default:
		septets := udl
		if hasUDH {
			septets -= headerSeptets
		}
		if septets < 0 {
			septets = 0
		}
		fillBits := 0
		if hasUDH {
			fillBits = (7 - ((len(udh) * 8) % 7)) % 7
		}
		return decodeGSM7WithLanguage(unpackSeptets(payload, septets, fillBits), headerInfo.LockingShiftLang, headerInfo.SingleShiftLang), headerInfo, nil
	}
}

func splitSMSUDH(data []byte, hasUDH bool) (udh []byte, payload []byte, headerSeptets int, headerInfo SMSUserDataHeaderInfo, err error) {
	if !hasUDH {
		return nil, data, 0, SMSUserDataHeaderInfo{}, nil
	}
	if len(data) == 0 {
		return nil, nil, 0, SMSUserDataHeaderInfo{}, errors.New("SMS UDH length missing")
	}
	headerLen := int(data[0]) + 1
	if headerLen > len(data) {
		return nil, nil, 0, SMSUserDataHeaderInfo{}, errors.New("SMS UDH truncated")
	}
	udh = append([]byte(nil), data[:headerLen]...)
	headerInfo = parseSMSUDHInfo(udh)
	headerSeptets = (headerLen*8 + 6) / 7
	return udh, data[headerLen:], headerSeptets, headerInfo, nil
}

func parseSMSConcatUDH(udh []byte) SMSConcatInfo {
	return parseSMSUDHInfo(udh).Concat
}

func parseSMSUDHInfo(udh []byte) SMSUserDataHeaderInfo {
	info := SMSUserDataHeaderInfo{Raw: append([]byte(nil), udh...)}
	if len(udh) < 2 {
		return info
	}
	for i := 1; i+1 < len(udh); {
		iei := udh[i]
		iedl := int(udh[i+1])
		i += 2
		if i+iedl > len(udh) {
			return info
		}
		ie := udh[i : i+iedl]
		info.Elements = append(info.Elements, SMSUDHElement{Identifier: iei, Data: append([]byte(nil), ie...)})
		switch iei {
		case 0x00:
			if len(ie) == 3 && ie[1] > 1 {
				info.Concat = SMSConcatInfo{IsConcat: true, Ref: int(ie[0]), RefBits: 8, Total: int(ie[1]), Seq: int(ie[2])}
			}
		case 0x01:
			if len(ie) == 2 {
				info.SpecialMessageIndications = append(info.SpecialMessageIndications, parseSMSSpecialMessageIndication(ie))
			}
		case 0x04:
			if len(ie) == 2 {
				info.HasPorts = true
				info.DestinationPort = int(ie[0])
				info.SourcePort = int(ie[1])
				info.PortBits = 8
			}
		case 0x05:
			if len(ie) == 4 {
				info.HasPorts = true
				info.DestinationPort = int(ie[0])<<8 | int(ie[1])
				info.SourcePort = int(ie[2])<<8 | int(ie[3])
				info.PortBits = 16
			}
		case 0x08:
			if len(ie) == 4 && ie[2] > 1 {
				info.Concat = SMSConcatInfo{IsConcat: true, Ref: int(ie[0])<<8 | int(ie[1]), RefBits: 16, Total: int(ie[2]), Seq: int(ie[3])}
			}
		case 0x06:
			if len(ie) == 1 {
				info.HasSMSCControl = true
				info.SMSCControl = parseSMSSMSCControlParameters(ie[0])
			}
		case 0x07:
			if len(ie) == 1 {
				value := int(ie[0])
				info.SourceIndicators = append(info.SourceIndicators, SMSUDHSourceIndicator{Value: value, Description: smsUDHSourceIndicatorDescription(value)})
			}
		case 0x20:
			if len(ie) == 1 {
				info.HasRFC822EmailHeader = true
				info.RFC822EmailHeaderLength = int(ie[0])
			}
		case smsUDHIEINationalLanguageSingleShift:
			if len(ie) == 1 && smsNationalLanguageIdentifierKnown(int(ie[0])) {
				info.HasSingleShift = true
				info.SingleShiftLang = int(ie[0])
			}
		case smsUDHIEINationalLanguageLockingShift:
			if len(ie) == 1 && smsNationalLanguageIdentifierKnown(int(ie[0])) {
				info.HasLockingShift = true
				info.LockingShiftLang = int(ie[0])
			}
		}
		i += iedl
	}
	return info
}

func parseSMSSpecialMessageIndication(data []byte) SMSSpecialMessageIndication {
	raw := data[0]
	count := int(data[1])
	indication := SMSSpecialMessageIndication{
		Raw:          raw,
		StoreMessage: raw&0x80 != 0,
		ProfileID:    int((raw>>5)&0x03) + 1,
		BasicType:    int(raw & 0x03),
		ExtendedType: int((raw >> 2) & 0x07),
		Count:        count,
		Active:       count > 0,
	}
	indication.MessageType, indication.ReservedType = smsSpecialMessageIndicationType(indication.BasicType, indication.ExtendedType)
	return indication
}

func smsSpecialMessageIndicationType(basic, extended int) (string, bool) {
	if extended == 0 {
		switch basic {
		case 0:
			return "voicemail", false
		case 1:
			return "fax", false
		case 2:
			return "email", false
		default:
			return "other", false
		}
	}
	if basic == 3 && extended == 1 {
		return "video", false
	}
	return "reserved", true
}

func parseSMSSMSCControlParameters(raw byte) SMSSMSCControlParameters {
	return SMSSMSCControlParameters{
		Raw:                                      raw,
		StatusReportTransactionCompleted:         raw&0x01 != 0,
		StatusReportPermanentError:               raw&0x02 != 0,
		StatusReportTemporaryErrorNoMoreAttempts: raw&0x04 != 0,
		StatusReportTemporaryErrorMoreAttempts:   raw&0x08 != 0,
		CancelSRRForRemainingConcatParts:         raw&0x40 != 0,
		IncludeOriginalUDHInStatusReport:         raw&0x80 != 0,
		ReservedBits:                             raw & 0x30,
	}
}

func smsUDHSourceIndicatorDescription(value int) string {
	switch value {
	case 1:
		return "original-sender"
	case 2:
		return "original-receiver"
	case 3:
		return "smsc"
	default:
		return "reserved"
	}
}

func smsDCSAlphabet(dcs byte) string {
	return ParseSMSDataCodingScheme(dcs).Alphabet
}

func ParseSMSDataCodingScheme(dcs byte) SMSDataCodingInfo {
	info := SMSDataCodingInfo{Raw: dcs, Alphabet: "gsm7"}
	group := dcs & 0xf0
	switch {
	case group <= 0x70:
		info.AutoDelete = dcs&0x40 != 0
		info.Compressed = dcs&0x20 != 0
		if dcs&0x10 != 0 {
			info.HasMessageClass = true
			info.MessageClass = int(dcs & 0x03)
		}
		switch dcs & 0x0c {
		case 0x04:
			info.Alphabet = "8bit"
		case 0x08:
			info.Alphabet = "ucs2"
		case 0x0c:
			info.Reserved = true
		}
	case group >= 0x80 && group <= 0xb0:
		info.Reserved = true
	case group == 0xc0:
		info.MessageWaiting = true
		info.MessageWaitingActive = dcs&0x08 != 0
		info.MessageWaitingDiscard = true
		info.MessageWaitingType = smsMessageWaitingType(dcs)
	case group == 0xd0:
		info.MessageWaiting = true
		info.MessageWaitingActive = dcs&0x08 != 0
		info.MessageWaitingType = smsMessageWaitingType(dcs)
	case group == 0xe0:
		info.Alphabet = "ucs2"
		info.MessageWaiting = true
		info.MessageWaitingActive = dcs&0x08 != 0
		info.MessageWaitingType = smsMessageWaitingType(dcs)
	case group == 0xf0:
		info.HasMessageClass = true
		info.MessageClass = int(dcs & 0x03)
		if dcs&0x04 != 0 {
			info.Alphabet = "8bit"
		}
	}
	return info
}

func smsMessageWaitingType(dcs byte) string {
	switch dcs & 0x03 {
	case 0:
		return "voicemail"
	case 1:
		return "fax"
	case 2:
		return "email"
	default:
		return "other"
	}
}

func decodeGSM7(septets []byte) string {
	return decodeGSM7WithLanguage(septets, 0, 0)
}

func decodeGSM7WithLanguage(septets []byte, lockingLang, singleLang int) string {
	var b strings.Builder
	for i := 0; i < len(septets); i++ {
		code := septets[i] & 0x7f
		if code == 0x1b && i+1 < len(septets) {
			shiftCode := septets[i+1] & 0x7f
			if r, ok := gsm7SingleShiftRune(shiftCode, singleLang); ok {
				b.WriteRune(r)
				i++
				continue
			}
			if lockingLang != 0 || singleLang != 0 {
				if r, ok := gsm7LockingRune(shiftCode, lockingLang); ok {
					b.WriteRune(r)
					i++
					continue
				}
			}
		}
		if r, ok := gsm7LockingRune(code, lockingLang); ok {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func gsm7ExtensionRune(code byte) (rune, bool) {
	return gsm7SingleShiftRune(code, 0)
}

func decodeUCS2(data []byte) (string, error) {
	if len(data)%2 != 0 {
		return "", errors.New("UCS2 payload has odd length")
	}
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		units = append(units, uint16(data[i])<<8|uint16(data[i+1]))
	}
	return string(utf16.Decode(units)), nil
}

func decodeSMSTimestamp(raw []byte) (time.Time, error) {
	if len(raw) != 7 {
		return time.Time{}, errors.New("SMS timestamp must be 7 octets")
	}
	year := decodeSemiOctetDecimal(raw[0])
	month := decodeSemiOctetDecimal(raw[1])
	day := decodeSemiOctetDecimal(raw[2])
	hour := decodeSemiOctetDecimal(raw[3])
	minute := decodeSemiOctetDecimal(raw[4])
	second := decodeSemiOctetDecimal(raw[5])
	tzOctet := raw[6]
	negative := tzOctet&0x08 != 0
	tzOctet &^= 0x08
	tzQuarterHours := decodeSemiOctetDecimal(tzOctet)
	if year < 0 || month <= 0 || month > 12 || day <= 0 || day > 31 || hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59 || tzQuarterHours < 0 {
		return time.Time{}, errors.New("SMS timestamp contains invalid BCD")
	}
	fullYear := 2000 + year
	if year >= 90 {
		fullYear = 1900 + year
	}
	offset := tzQuarterHours * 15 * 60
	if negative {
		offset = -offset
	}
	return time.Date(fullYear, time.Month(month), day, hour, minute, second, 0, time.FixedZone("", offset)), nil
}

func encodeSMSTimestamp(ts time.Time) ([]byte, error) {
	if ts.IsZero() {
		return nil, errors.New("SMS timestamp is zero")
	}
	year := ts.Year()
	if year < 1990 || year > 2089 {
		return nil, fmt.Errorf("SMS timestamp year %d is outside encodable range 1990-2089", year)
	}
	_, offset := ts.Zone()
	if offset%900 != 0 {
		return nil, fmt.Errorf("SMS timestamp timezone offset %d is not a 15-minute multiple", offset)
	}
	tzQuarterHours := offset / 900
	negative := tzQuarterHours < 0
	if negative {
		tzQuarterHours = -tzQuarterHours
	}
	if tzQuarterHours > 79 {
		return nil, fmt.Errorf("SMS timestamp timezone quarter-hours out of range: %d", tzQuarterHours)
	}
	tz := encodeSemiOctetDecimal(tzQuarterHours)
	if negative {
		tz |= 0x08
	}
	return []byte{
		encodeSemiOctetDecimal(year % 100),
		encodeSemiOctetDecimal(int(ts.Month())),
		encodeSemiOctetDecimal(ts.Day()),
		encodeSemiOctetDecimal(ts.Hour()),
		encodeSemiOctetDecimal(ts.Minute()),
		encodeSemiOctetDecimal(ts.Second()),
		tz,
	}, nil
}

func encodeSemiOctetDecimal(value int) byte {
	if value < 0 {
		return 0
	}
	return byte((value%10)<<4 | (value/10)%10)
}

func decodeSemiOctetDecimal(value byte) int {
	lo := int(value & 0x0f)
	hi := int((value >> 4) & 0x0f)
	if lo > 9 || hi > 9 {
		return -1
	}
	return lo*10 + hi
}

func smsStatusReportState(status byte) string {
	if status <= 0x1f {
		return "delivered"
	}
	if status >= 0x40 {
		return "failed"
	}
	return "accepted"
}

func SMSStatusReportText(status byte) string {
	switch status {
	case 0x00:
		return "SMS status 0x00: short message received by SME"
	case 0x01:
		return "SMS status 0x01: short message forwarded by service center but delivery not confirmed"
	case 0x02:
		return "SMS status 0x02: short message replaced by service center"
	case 0x20:
		return "SMS status 0x20: congestion, service center still retrying"
	case 0x21:
		return "SMS status 0x21: SME busy, service center still retrying"
	case 0x22:
		return "SMS status 0x22: no response from SME, service center still retrying"
	case 0x23:
		return "SMS status 0x23: service rejected, service center still retrying"
	case 0x24:
		return "SMS status 0x24: quality of service unavailable, service center still retrying"
	case 0x25:
		return "SMS status 0x25: error in SME, service center still retrying"
	case 0x40:
		return "SMS status 0x40: remote procedure error"
	case 0x41:
		return "SMS status 0x41: incompatible destination"
	case 0x42:
		return "SMS status 0x42: connection rejected by SME"
	case 0x43:
		return "SMS status 0x43: not obtainable"
	case 0x44:
		return "SMS status 0x44: quality of service not available"
	case 0x45:
		return "SMS status 0x45: no interworking available"
	case 0x46:
		return "SMS status 0x46: short message validity period expired"
	case 0x47:
		return "SMS status 0x47: short message deleted by originating SME"
	case 0x48:
		return "SMS status 0x48: short message deleted by service center administration"
	case 0x49:
		return "SMS status 0x49: short message does not exist"
	}
	switch {
	case status <= 0x1f:
		return "SMS status 0x" + strings.ToUpper(hexByte(status)) + ": completed"
	case status <= 0x3f:
		return "SMS status 0x" + strings.ToUpper(hexByte(status)) + ": temporary error, service center still retrying"
	case status <= 0x5f:
		return "SMS status 0x" + strings.ToUpper(hexByte(status)) + ": permanent error, service center stopped retrying"
	case status <= 0x7f:
		return "SMS status 0x" + strings.ToUpper(hexByte(status)) + ": temporary error, service center stopped retrying"
	default:
		return "SMS status 0x" + strings.ToUpper(hexByte(status)) + ": reserved"
	}
}
