package messaging

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestBuildSMSSubmitTPDUGSM7(t *testing.T) {
	tpdu, err := BuildSMSSubmitTPDU("+18005551212", SMSPart{PartNo: 2, TotalParts: 2, Text: "hello", Encoding: "gsm7"}, 2)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	got := strings.ToUpper(hex.EncodeToString(tpdu))
	want := "01020B918100551512F2000005E8329BFD06"
	if got != want {
		t.Fatalf("TPDU=%s want %s", got, want)
	}
}

func TestBuildSMSSubmitTPDUSpecialAddressDigits(t *testing.T) {
	tpdu, err := BuildSMSSubmitTPDU("*123#", SMSPart{Text: "ok", Encoding: "gsm7"}, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	got := strings.ToUpper(hex.EncodeToString(tpdu))
	want := "010105811A32FB000002EF35"
	if got != want {
		t.Fatalf("TPDU=%s want %s", got, want)
	}
}

func TestBuildSMSSubmitTPDUWithApplicationPorts(t *testing.T) {
	tpdu, err := BuildSMSSubmitTPDU("10086", SMSPart{
		Text:                  "hi",
		Encoding:              "gsm7",
		ApplicationDestPort:   2948,
		ApplicationSourcePort: 9200,
	}, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	got := strings.ToUpper(hex.EncodeToString(tpdu))
	want := "410105810180F600000A0605040B8423F0E834"
	if got != want {
		t.Fatalf("TPDU=%s want %s", got, want)
	}
}

func TestBuildSMSSubmitTPDURelativeValidityPeriod(t *testing.T) {
	tpdu, err := BuildSMSSubmitTPDU("+18005551212", SMSPart{Text: "hello", Encoding: "gsm7", ValidityPeriod: time.Hour}, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	got := strings.ToUpper(hex.EncodeToString(tpdu))
	want := "11010B918100551512F200000B05E8329BFD06"
	if got != want {
		t.Fatalf("TPDU=%s want %s", got, want)
	}
	if tpdu[0]&0x18 != 0x10 || tpdu[12] != 0x0b || tpdu[13] != 5 {
		t.Fatalf("first=0x%02x VP=0x%02x UDL=%d TPDU=%x", tpdu[0], tpdu[12], tpdu[13], tpdu)
	}
}

func TestBuildSMSSubmitTPDUReplyPathAndRejectDuplicates(t *testing.T) {
	tpdu, err := BuildSMSSubmitTPDU("+18005551212", SMSPart{Text: "hello", Encoding: "gsm7", ReplyPath: true, RejectDuplicates: true}, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	if tpdu[0] != 0x85 {
		t.Fatalf("first octet=0x%02x want SMS-SUBMIT with TP-RP and TP-RD", tpdu[0])
	}

	tpdu, err = BuildSMSSubmitTPDU("+18005551212", SMSPart{Text: "hello", Encoding: "gsm7", ReplyPath: true, RejectDuplicates: true, RequestStatusReport: true, UDH: concatUDH(2, 1)}, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU(UDH) error = %v", err)
	}
	if tpdu[0] != 0xe5 {
		t.Fatalf("first octet=0x%02x want SMS-SUBMIT with TP-RP/TP-UDHI/TP-SRR/TP-RD", tpdu[0])
	}
}

func TestBuildSMSSubmitTPDUAbsoluteValidityDeadline(t *testing.T) {
	deadline := time.Date(2026, 7, 5, 12, 34, 56, 0, time.FixedZone("CST", 8*3600))
	tpdu, err := BuildSMSSubmitTPDU("+18005551212", SMSPart{Text: "hello", Encoding: "gsm7", ValidityDeadline: deadline}, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	got := strings.ToUpper(hex.EncodeToString(tpdu))
	want := "19010B918100551512F200006270502143652305E8329BFD06"
	if got != want {
		t.Fatalf("TPDU=%s want %s", got, want)
	}
	if tpdu[0]&0x18 != 0x18 || tpdu[19] != 5 {
		t.Fatalf("first=0x%02x UDL=%d TPDU=%x", tpdu[0], tpdu[19], tpdu)
	}
	decoded, err := decodeSMSTimestamp(tpdu[12:19])
	if err != nil {
		t.Fatalf("decodeSMSTimestamp() error = %v", err)
	}
	if !decoded.Equal(deadline) {
		t.Fatalf("decoded deadline=%s want %s", decoded, deadline)
	}
}

func TestBuildSMSSubmitTPDUCustomProtocolIDAndDCS(t *testing.T) {
	tpdu, err := BuildSMSSubmitTPDU("+18005551212", SMSPart{Text: "flash", ProtocolID: 0x7f, DataCodingScheme: 0x10}, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	if tpdu[10] != 0x7f || tpdu[11] != 0x10 || tpdu[12] != 5 {
		t.Fatalf("PID=0x%02x DCS=0x%02x UDL=%d TPDU=%x", tpdu[10], tpdu[11], tpdu[12], tpdu)
	}
	textOut, _, err := decodeSMSUserData(tpdu[13:], int(tpdu[12]), tpdu[11], false)
	if err != nil {
		t.Fatalf("decodeSMSUserData() error = %v", err)
	}
	if textOut != "flash" {
		t.Fatalf("decoded TPDU text=%q", textOut)
	}
}

func TestBuildSMSSubmitTPDUDCSSelectsUCS2Encoding(t *testing.T) {
	tpdu, err := BuildSMSSubmitTPDU("10086", SMSPart{Text: "OK", DataCodingScheme: 0x18}, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	if tpdu[8] != 0x18 || tpdu[9] != 4 {
		t.Fatalf("DCS=0x%02x UDL=%d TPDU=%x", tpdu[8], tpdu[9], tpdu)
	}
	if got := strings.ToUpper(hex.EncodeToString(tpdu[10:])); got != "004F004B" {
		t.Fatalf("user data=%s want 004F004B", got)
	}
}

func TestBuildSMSSubmitTPDURejectsConflictingDCS(t *testing.T) {
	_, err := BuildSMSSubmitTPDU("+18005551212", SMSPart{Text: "hello", Encoding: "ucs2", UseDataCodingScheme: true}, 1)
	if err == nil || !strings.Contains(err.Error(), "data coding scheme") {
		t.Fatalf("BuildSMSSubmitTPDU() err=%v, want data coding scheme mismatch", err)
	}
	_, err = BuildSMSSubmitTPDU("+18005551212", SMSPart{Text: "hello", DataCodingScheme: 0x20}, 1)
	if err == nil || !strings.Contains(err.Error(), "compressed") {
		t.Fatalf("BuildSMSSubmitTPDU() err=%v, want compressed DCS rejection", err)
	}
	_, err = BuildSMSSubmitTPDU("+18005551212", SMSPart{Text: "hello", DataCodingScheme: 0x60}, 1)
	if err == nil || !strings.Contains(err.Error(), "compressed") {
		t.Fatalf("BuildSMSSubmitTPDU(auto-delete compressed) err=%v, want compressed DCS rejection", err)
	}
}

func TestParseSMSDataCodingScheme(t *testing.T) {
	tests := []struct {
		name string
		dcs  byte
		want SMSDataCodingInfo
	}{
		{name: "gsm7 class0", dcs: 0x10, want: SMSDataCodingInfo{Raw: 0x10, Alphabet: "gsm7", HasMessageClass: true, MessageClass: 0}},
		{name: "auto delete compressed", dcs: 0x60, want: SMSDataCodingInfo{Raw: 0x60, Alphabet: "gsm7", AutoDelete: true, Compressed: true}},
		{name: "ucs2", dcs: 0x08, want: SMSDataCodingInfo{Raw: 0x08, Alphabet: "ucs2"}},
		{name: "mwi discard inactive", dcs: 0xc0, want: SMSDataCodingInfo{Raw: 0xc0, Alphabet: "gsm7", MessageWaiting: true, MessageWaitingDiscard: true, MessageWaitingType: "voicemail"}},
		{name: "mwi store active", dcs: 0xd8, want: SMSDataCodingInfo{Raw: 0xd8, Alphabet: "gsm7", MessageWaiting: true, MessageWaitingActive: true, MessageWaitingType: "voicemail"}},
		{name: "mwi ucs2 fax", dcs: 0xe9, want: SMSDataCodingInfo{Raw: 0xe9, Alphabet: "ucs2", MessageWaiting: true, MessageWaitingActive: true, MessageWaitingType: "fax"}},
		{name: "8bit class0", dcs: 0xf4, want: SMSDataCodingInfo{Raw: 0xf4, Alphabet: "8bit", HasMessageClass: true, MessageClass: 0}},
		{name: "reserved coding", dcs: 0x8c, want: SMSDataCodingInfo{Raw: 0x8c, Alphabet: "gsm7", Reserved: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSMSDataCodingScheme(tt.dcs)
			if got != tt.want {
				t.Fatalf("ParseSMSDataCodingScheme(0x%02x)=%+v want %+v", tt.dcs, got, tt.want)
			}
		})
	}
}

func TestEncodeSMSSubmitValidityPeriodRejectsConflicts(t *testing.T) {
	deadline := time.Date(2026, 7, 5, 12, 34, 56, 0, time.UTC)
	_, _, err := encodeSMSSubmitValidityPeriod(time.Hour, deadline)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("encodeSMSSubmitValidityPeriod() err=%v, want mutual exclusion", err)
	}
}

func TestEncodeSMSTimestampRejectsUnsupportedValues(t *testing.T) {
	_, err := encodeSMSTimestamp(time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "encodable range") {
		t.Fatalf("encodeSMSTimestamp(year) err=%v, want encodable range", err)
	}
	_, err = encodeSMSTimestamp(time.Date(2026, 1, 1, 0, 0, 0, 0, time.FixedZone("odd", 61)))
	if err == nil || !strings.Contains(err.Error(), "15-minute") {
		t.Fatalf("encodeSMSTimestamp(offset) err=%v, want 15-minute error", err)
	}
}

func TestEncodeSMSRelativeValidityPeriod(t *testing.T) {
	tests := []struct {
		name     string
		validity time.Duration
		want     byte
		wantSet  bool
		wantErr  bool
	}{
		{name: "unset", validity: 0, wantSet: false},
		{name: "round up sub five minutes", validity: time.Nanosecond, want: 0x00, wantSet: true},
		{name: "five minutes", validity: 5 * time.Minute, want: 0x00, wantSet: true},
		{name: "twelve hours", validity: 12 * time.Hour, want: 0x8f, wantSet: true},
		{name: "after twelve hours", validity: 12*time.Hour + time.Nanosecond, want: 0x90, wantSet: true},
		{name: "one day", validity: 24 * time.Hour, want: 0xa7, wantSet: true},
		{name: "after one day", validity: 24*time.Hour + time.Nanosecond, want: 0xa8, wantSet: true},
		{name: "thirty days", validity: 30 * 24 * time.Hour, want: 0xc4, wantSet: true},
		{name: "thirty one days", validity: 31 * 24 * time.Hour, want: 0xc5, wantSet: true},
		{name: "sixty three weeks", validity: 63 * 7 * 24 * time.Hour, want: 0xff, wantSet: true},
		{name: "negative", validity: -time.Second, wantErr: true},
		{name: "too large", validity: 64 * 7 * 24 * time.Hour, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotSet, err := encodeSMSRelativeValidityPeriod(tt.validity)
			if tt.wantErr {
				if err == nil {
					t.Fatal("encodeSMSRelativeValidityPeriod() err=nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("encodeSMSRelativeValidityPeriod() error = %v", err)
			}
			if got != tt.want || gotSet != tt.wantSet {
				t.Fatalf("encodeSMSRelativeValidityPeriod()=(0x%02x,%v), want (0x%02x,%v)", got, gotSet, tt.want, tt.wantSet)
			}
		})
	}
}

func TestBuildSMSSubmitTPDUGSM7ExtendedCharacters(t *testing.T) {
	text := "^{}\\[~]|€\f"
	septets, err := encodeGSM7(text)
	if err != nil {
		t.Fatalf("encodeGSM7() error = %v", err)
	}
	gotSeptets := strings.ToUpper(hex.EncodeToString(septets))
	wantSeptets := "1B141B281B291B2F1B3C1B3D1B3E1B401B651B0A"
	if gotSeptets != wantSeptets {
		t.Fatalf("septets=%s want %s", gotSeptets, wantSeptets)
	}
	if decoded := decodeGSM7(septets); decoded != text {
		t.Fatalf("decoded=%q want %q", decoded, text)
	}

	tpdu, err := BuildSMSSubmitTPDU("+18005551212", SMSPart{Text: "cost {10}€", Encoding: "gsm7"}, 3)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	if tpdu[11] != 0x00 || int(tpdu[12]) != 13 {
		t.Fatalf("DCS=0x%02x UDL=%d want GSM7/13 septets TPDU=%x", tpdu[11], tpdu[12], tpdu)
	}
	textOut, _, err := decodeSMSUserData(tpdu[13:], int(tpdu[12]), tpdu[11], false)
	if err != nil {
		t.Fatalf("decodeSMSUserData() error = %v", err)
	}
	if textOut != "cost {10}€" {
		t.Fatalf("decoded TPDU text=%q", textOut)
	}
}

func TestGSM7NationalLanguageTurkishTables(t *testing.T) {
	singleText := "\u011e\u0130\u015e\u00e7\u20ac\u011f\u0131\u015f"
	septets, err := encodeGSM7WithLanguage(singleText, 0, SMSNationalLanguageTurkish)
	if err != nil {
		t.Fatalf("encodeGSM7WithLanguage(single shift) error = %v", err)
	}
	if got, want := strings.ToUpper(hex.EncodeToString(septets)), "1B471B491B531B631B651B671B691B73"; got != want {
		t.Fatalf("single shift septets=%s want %s", got, want)
	}
	if decoded := decodeGSM7WithLanguage(septets, 0, SMSNationalLanguageTurkish); decoded != singleText {
		t.Fatalf("single shift decoded=%q want %q", decoded, singleText)
	}

	lockingText := "\u011e\u011f\u0130\u015e\u015f\u00e7\u0131\u20ac"
	septets, err = encodeGSM7WithLanguage(lockingText, SMSNationalLanguageTurkish, 0)
	if err != nil {
		t.Fatalf("encodeGSM7WithLanguage(locking shift) error = %v", err)
	}
	if got, want := strings.ToUpper(hex.EncodeToString(septets)), "0B0C401C1D600704"; got != want {
		t.Fatalf("locking shift septets=%s want %s", got, want)
	}
	if decoded := decodeGSM7WithLanguage(septets, SMSNationalLanguageTurkish, 0); decoded != lockingText {
		t.Fatalf("locking shift decoded=%q want %q", decoded, lockingText)
	}
}

func TestBuildSMSSubmitTPDUGSM7NationalLanguageUDH(t *testing.T) {
	tpdu, err := BuildSMSSubmitTPDU("10086", SMSPart{Text: "\u011e", SingleShiftLang: SMSNationalLanguageTurkish}, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	if tpdu[0] != 0x41 || tpdu[8] != 0x00 || tpdu[9] != 7 {
		t.Fatalf("TPDU header first=0x%02x dcs=0x%02x udl=%d tpdu=%x", tpdu[0], tpdu[8], tpdu[9], tpdu)
	}
	wantUDH := []byte{0x03, 0x24, 0x01, 0x01}
	if string(tpdu[10:14]) != string(wantUDH) {
		t.Fatalf("UDH=%x want %x", tpdu[10:14], wantUDH)
	}
	text, header, err := decodeSMSUserDataWithHeader(tpdu[10:], int(tpdu[9]), tpdu[8], true)
	if err != nil {
		t.Fatalf("decodeSMSUserDataWithHeader() error = %v", err)
	}
	if text != "\u011e" || !header.HasSingleShift || header.SingleShiftLang != SMSNationalLanguageTurkish {
		t.Fatalf("text=%q header=%+v", text, header)
	}
}

func TestBuildSMSSubmitTPDUUCS2(t *testing.T) {
	tpdu, err := BuildSMSSubmitTPDU("10086", SMSPart{Text: "你", Encoding: "ucs2"}, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	got := strings.ToUpper(hex.EncodeToString(tpdu))
	want := "010105810180F60008024F60"
	if got != want {
		t.Fatalf("TPDU=%s want %s", got, want)
	}
}

func TestBuildAndParseSMSRPData(t *testing.T) {
	tpdu, err := BuildSMSSubmitTPDU("+18005551212", SMSPart{Text: "hello", Encoding: "gsm7"}, 7)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	rpData, err := BuildSMSRPData(7, "", tpdu)
	if err != nil {
		t.Fatalf("BuildSMSRPData() error = %v", err)
	}
	got := strings.ToUpper(hex.EncodeToString(rpData))
	want := "000700001201070B918100551512F2000005E8329BFD06"
	if got != want {
		t.Fatalf("RP-DATA=%s want %s", got, want)
	}
	rpMR, parsedTPDU, err := ParseSMSRPData(rpData)
	if err != nil {
		t.Fatalf("ParseSMSRPData() error = %v", err)
	}
	if rpMR != 7 || string(parsedTPDU) != string(tpdu) {
		t.Fatalf("rpMR=%d tpdu=%x want %d/%x", rpMR, parsedTPDU, 7, tpdu)
	}
}

func TestBuildSMSSubmitTPDUGSM7WithUDH(t *testing.T) {
	part := SMSPart{PartNo: 1, TotalParts: 2, Text: strings.Repeat("a", 153), Encoding: "gsm7", UDH: concatUDH(2, 1)}
	tpdu, err := BuildSMSSubmitTPDU("+18005551212", part, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	if tpdu[0] != 0x41 {
		t.Fatalf("first octet=0x%02x want UDHI set", tpdu[0])
	}
	if tpdu[12] != 160 {
		t.Fatalf("UDL=%d want 160 septets", tpdu[12])
	}
	if len(tpdu) != 13+140 {
		t.Fatalf("TPDU length=%d want %d", len(tpdu), 153)
	}
}

func TestBuildSMSSubmitTPDURequestsStatusReport(t *testing.T) {
	tpdu, err := BuildSMSSubmitTPDU("+18005551212", SMSPart{Text: "hello", Encoding: "gsm7", RequestStatusReport: true}, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	if tpdu[0] != 0x21 {
		t.Fatalf("first octet=0x%02x want SMS-SUBMIT with TP-SRR", tpdu[0])
	}

	tpdu, err = BuildSMSSubmitTPDU("+18005551212", SMSPart{PartNo: 1, TotalParts: 2, Text: "hello", Encoding: "gsm7", UDH: concatUDH(2, 1), RequestStatusReport: true}, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU(UDH) error = %v", err)
	}
	if tpdu[0] != 0x61 {
		t.Fatalf("first octet=0x%02x want SMS-SUBMIT with TP-SRR and UDHI", tpdu[0])
	}
}

func TestParseSMSRPDUAckAndError(t *testing.T) {
	ack, err := ParseSMSRPDU(BuildSMSRPAck(0x22))
	if err != nil {
		t.Fatalf("ParseSMSRPDU(ack) error = %v", err)
	}
	if ack.Kind != SMSRPDUKindAck || ack.MR != 0x22 {
		t.Fatalf("ack=%+v", ack)
	}
	errRPDU, err := ParseSMSRPDU(BuildSMSRPError(0x23, SMSRPCauseTemporaryFailure))
	if err != nil {
		t.Fatalf("ParseSMSRPDU(error) error = %v", err)
	}
	if errRPDU.Kind != SMSRPDUKindError || errRPDU.MR != 0x23 || errRPDU.Cause != int(SMSRPCauseTemporaryFailure) {
		t.Fatalf("error rpdu=%+v", errRPDU)
	}
}

func TestParseSMSRPDUAckWithUserData(t *testing.T) {
	tpdu := mustHex(t, "02070B918100551512F2627050214365006270502144000000")
	body, err := BuildSMSRPAckWithTPDU(0x55, tpdu)
	if err != nil {
		t.Fatalf("BuildSMSRPAckWithTPDU() error = %v", err)
	}
	rpdu, err := ParseSMSRPDU(body)
	if err != nil {
		t.Fatalf("ParseSMSRPDU(ack with user data) error = %v", err)
	}
	if rpdu.Kind != SMSRPDUKindAck || rpdu.MR != 0x55 || string(rpdu.TPDU) != string(tpdu) {
		t.Fatalf("rpdu=%+v tpdu=%x", rpdu, rpdu.TPDU)
	}
	report, err := ParseSMSStatusReportTPDU(rpdu.TPDU)
	if err != nil {
		t.Fatalf("ParseSMSStatusReportTPDU() error = %v", err)
	}
	if report.Reference != 7 || report.State != "delivered" {
		t.Fatalf("report=%+v", report)
	}
}

func TestParseSMSRPDUErrorPreservesDiagnosticsAndUserData(t *testing.T) {
	tpdu := mustHex(t, "02070B918100551512F2627050214365006270502144000046")
	body := append([]byte{0x04, 0x56, 0x02, SMSRPCauseTemporaryFailure, 0x80, byte(len(tpdu))}, tpdu...)
	rpdu, err := ParseSMSRPDU(body)
	if err != nil {
		t.Fatalf("ParseSMSRPDU(error with user data) error = %v", err)
	}
	if rpdu.Kind != SMSRPDUKindError || rpdu.MR != 0x56 || rpdu.Cause != int(SMSRPCauseTemporaryFailure) {
		t.Fatalf("rpdu=%+v", rpdu)
	}
	if string(rpdu.CauseDiagnostics) != string([]byte{0x80}) || string(rpdu.TPDU) != string(tpdu) {
		t.Fatalf("diagnostics=%x tpdu=%x", rpdu.CauseDiagnostics, rpdu.TPDU)
	}
	cause, err := ParseSMSRPErrorCause(body)
	if err != nil || cause != SMSRPCauseTemporaryFailure {
		t.Fatalf("ParseSMSRPErrorCause() cause=%d err=%v", cause, err)
	}
}

func TestParseSMSRPDUBoundsUserDataLength(t *testing.T) {
	tpdu := mustHex(t, "0005810180F600006270502143650005E8329BFD06")
	rpData, err := BuildSMSRPData(0x33, "", tpdu)
	if err != nil {
		t.Fatalf("BuildSMSRPData() error = %v", err)
	}
	if _, err := ParseSMSRPDU(append(append([]byte(nil), rpData...), 0xff)); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("ParseSMSRPDU(RP-DATA trailing) err=%v, want trailing data", err)
	}
	if _, err := ParseSMSRPDU([]byte{0x02, 0x22, 0x00, 0xff}); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("ParseSMSRPDU(RP-ACK trailing) err=%v, want trailing data", err)
	}
	if _, err := ParseSMSRPDU([]byte{0x04, 0x23, 0x01, SMSRPCauseTemporaryFailure, 0x00, 0xff}); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("ParseSMSRPDU(RP-ERROR trailing) err=%v, want trailing data", err)
	}
	if _, err := ParseSMSRPDU([]byte{0x04, 0x23, 0x03, SMSRPCauseTemporaryFailure}); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("ParseSMSRPDU(RP-ERROR truncated cause) err=%v, want truncation", err)
	}
}

func TestBuildSMSRPErrorWithDiagnosticsRoundTrip(t *testing.T) {
	tpdu := mustHex(t, "02070B918100551512F2627050214365006270502144000046")
	body, err := BuildSMSRPErrorWithDiagnostics(0x56, SMSRPCauseTemporaryFailure, []byte{0x80, 0x01}, tpdu)
	if err != nil {
		t.Fatalf("BuildSMSRPErrorWithDiagnostics() error = %v", err)
	}
	rpdu, err := ParseSMSRPDU(body)
	if err != nil {
		t.Fatalf("ParseSMSRPDU() error = %v", err)
	}
	if rpdu.Kind != SMSRPDUKindError || rpdu.MR != 0x56 || rpdu.Cause != int(SMSRPCauseTemporaryFailure) {
		t.Fatalf("rpdu=%+v", rpdu)
	}
	if string(rpdu.CauseDiagnostics) != string([]byte{0x80, 0x01}) || string(rpdu.TPDU) != string(tpdu) {
		t.Fatalf("diagnostics=%x tpdu=%x", rpdu.CauseDiagnostics, rpdu.TPDU)
	}
}

func TestParseSMSDeliverTPDUGSM7(t *testing.T) {
	tpdu := mustHex(t, "0005810180F600006270502143650005E8329BFD06")
	deliver, err := ParseSMSDeliverTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSDeliverTPDU() error = %v", err)
	}
	if deliver.Sender != "10086" || deliver.Text != "hello" {
		t.Fatalf("deliver=%+v", deliver)
	}
	want := time.Date(2026, 7, 5, 12, 34, 56, 0, time.FixedZone("", 0))
	if !deliver.Timestamp.Equal(want) {
		t.Fatalf("timestamp=%s want %s", deliver.Timestamp, want)
	}
}

func TestParseSMSDeliverTPDUAlphanumericSender(t *testing.T) {
	tpdu := mustHex(t, "0006D0C7F7FBCC2E0300006270502143650005E8329BFD06")
	deliver, err := ParseSMSDeliverTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSDeliverTPDU() error = %v", err)
	}
	if deliver.Sender != "Google" || deliver.Text != "hello" {
		t.Fatalf("deliver=%+v", deliver)
	}
}

func TestParseSMSDeliverTPDUSpecialAddressDigits(t *testing.T) {
	tpdu := mustHex(t, "0005811A32FB00006270502143650002EF35")
	deliver, err := ParseSMSDeliverTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSDeliverTPDU() error = %v", err)
	}
	if deliver.Sender != "*123#" || deliver.Text != "ok" {
		t.Fatalf("deliver=%+v", deliver)
	}
}

func TestParseSMSDeliverTPDUUCS2WithConcatUDH(t *testing.T) {
	tpdu := mustHex(t, "4005810180F6000862705021436500080500037A02014F60")
	deliver, err := ParseSMSDeliverTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSDeliverTPDU() error = %v", err)
	}
	if deliver.Text != "你" || !deliver.Concat.IsConcat || deliver.Concat.Ref != 0x7a || deliver.Concat.Total != 2 || deliver.Concat.Seq != 1 {
		t.Fatalf("deliver=%+v", deliver)
	}
	if string(deliver.UserDataHeaderInfo.Raw) != string([]byte{0x05, 0x00, 0x03, 0x7a, 0x02, 0x01}) || len(deliver.UserDataHeaderInfo.Elements) != 1 {
		t.Fatalf("UDH=%+v", deliver.UserDataHeaderInfo)
	}
}

func TestParseSMSDeliverTPDURejectsTruncatedOctetEncodedUserData(t *testing.T) {
	tests := []struct {
		name string
		tpdu string
	}{
		{
			name: "ucs2 declared longer than payload",
			tpdu: "0005810180F6000862705021436500044F60",
		},
		{
			name: "8bit declared longer than payload",
			tpdu: "0005810180F6000462705021436500036F6B",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSMSDeliverTPDU(mustHex(t, tt.tpdu))
			if err == nil || !strings.Contains(err.Error(), "SMS user data truncated") {
				t.Fatalf("ParseSMSDeliverTPDU() err=%v, want truncated user data", err)
			}
		})
	}
}

func TestParseSMSDeliverTPDUPreservesProtocolMetadata(t *testing.T) {
	tpdu := mustHex(t, "E405810180F67F0862705021436500080500037A02014F60")
	deliver, err := ParseSMSDeliverTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSDeliverTPDU() error = %v", err)
	}
	if deliver.FirstOctet != 0xe4 || deliver.ProtocolID != 0x7f || deliver.DataCodingScheme != 0x08 || deliver.UserDataLength != 8 {
		t.Fatalf("deliver metadata=%+v", deliver)
	}
	if deliver.DataCoding.Alphabet != "ucs2" || deliver.DataCoding.Raw != 0x08 {
		t.Fatalf("deliver data coding=%+v", deliver.DataCoding)
	}
	if !deliver.UserDataHeader || !deliver.StatusReportIndication || !deliver.ReplyPath || deliver.MoreMessagesToSend {
		t.Fatalf("deliver flags=%+v", deliver)
	}
	if deliver.Text != "你" || !deliver.Concat.IsConcat {
		t.Fatalf("deliver content=%+v", deliver)
	}
}

func TestParseSMSDeliverTPDUGSM7WithNationalLanguageLockingShift(t *testing.T) {
	tpdu := deliverTPDUWithUserData(t, []byte{0x03, 0x25, 0x01, 0x01}, "\u011e\u011f\u0130", SMSNationalLanguageTurkish, 0)
	deliver, err := ParseSMSDeliverTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSDeliverTPDU() error = %v", err)
	}
	header := deliver.UserDataHeaderInfo
	if deliver.Text != "\u011e\u011f\u0130" || !header.HasLockingShift || header.LockingShiftLang != SMSNationalLanguageTurkish {
		t.Fatalf("deliver=%+v header=%+v", deliver, header)
	}
	if len(header.Elements) != 1 || header.Elements[0].Identifier != 0x25 {
		t.Fatalf("UDH elements=%+v", header.Elements)
	}
}

func TestParseSMSDeliverTPDUWithSpecialMessageIndicationUDH(t *testing.T) {
	tpdu := deliverTPDUWithUserData(t, []byte{0x04, 0x01, 0x02, 0x81, 0x04}, "mail", 0, 0)
	deliver, err := ParseSMSDeliverTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSDeliverTPDU() error = %v", err)
	}
	header := deliver.UserDataHeaderInfo
	if deliver.Text != "mail" || len(header.SpecialMessageIndications) != 1 {
		t.Fatalf("deliver=%+v header=%+v", deliver, header)
	}
	indication := header.SpecialMessageIndications[0]
	if indication.Raw != 0x81 || !indication.StoreMessage || indication.ProfileID != 1 || indication.MessageType != "fax" || indication.Count != 4 || !indication.Active || indication.ReservedType {
		t.Fatalf("special indication=%+v", indication)
	}
}

func TestParseSMSUDHInfoSpecialMessageIndicationTypes(t *testing.T) {
	header := parseSMSUDHInfo([]byte{0x08, 0x01, 0x02, 0x07, 0xff, 0x01, 0x02, 0x0b, 0x01})
	if len(header.SpecialMessageIndications) != 2 {
		t.Fatalf("special indications=%+v", header.SpecialMessageIndications)
	}
	video := header.SpecialMessageIndications[0]
	if video.MessageType != "video" || video.ReservedType || video.BasicType != 3 || video.ExtendedType != 1 || video.Count != 255 {
		t.Fatalf("video indication=%+v", video)
	}
	reserved := header.SpecialMessageIndications[1]
	if reserved.MessageType != "reserved" || !reserved.ReservedType || reserved.Count != 1 {
		t.Fatalf("reserved indication=%+v", reserved)
	}
}

func TestParseSMSUDHInfoSMSCControlSourceAndEmailHeader(t *testing.T) {
	header := parseSMSUDHInfo([]byte{0x0c, 0x06, 0x01, 0xcf, 0x07, 0x01, 0x03, 0x07, 0x01, 0x09, 0x20, 0x01, 0x12})
	if !header.HasSMSCControl {
		t.Fatalf("missing SMSC control: %+v", header)
	}
	control := header.SMSCControl
	if control.Raw != 0xcf || !control.StatusReportTransactionCompleted || !control.StatusReportPermanentError || !control.StatusReportTemporaryErrorNoMoreAttempts || !control.StatusReportTemporaryErrorMoreAttempts || !control.CancelSRRForRemainingConcatParts || !control.IncludeOriginalUDHInStatusReport || control.ReservedBits != 0 {
		t.Fatalf("SMSC control=%+v", control)
	}
	if len(header.SourceIndicators) != 2 || header.SourceIndicators[0].Value != 3 || header.SourceIndicators[0].Description != "smsc" || header.SourceIndicators[1].Description != "reserved" {
		t.Fatalf("source indicators=%+v", header.SourceIndicators)
	}
	if !header.HasRFC822EmailHeader || header.RFC822EmailHeaderLength != 18 {
		t.Fatalf("email header metadata=%+v", header)
	}
	if len(header.Elements) != 4 {
		t.Fatalf("elements=%+v", header.Elements)
	}
}

func TestParseSMSUDHInfoIgnoresReservedNationalLanguage(t *testing.T) {
	header := parseSMSUDHInfo([]byte{0x06, 0x24, 0x01, 0x0e, 0x25, 0x01, 0x00})
	if header.HasSingleShift || header.SingleShiftLang != 0 || header.HasLockingShift || header.LockingShiftLang != 0 {
		t.Fatalf("reserved NLI header=%+v", header)
	}
	if len(header.Elements) != 2 || header.Elements[0].Identifier != 0x24 || header.Elements[1].Identifier != 0x25 {
		t.Fatalf("reserved NLI elements=%+v", header.Elements)
	}
}

func TestParseSMSDeliverTPDUWith16BitPortUDH(t *testing.T) {
	tpdu := mustHex(t, "4005810180F6000462705021436500090605040B8423F06869")
	deliver, err := ParseSMSDeliverTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSDeliverTPDU() error = %v", err)
	}
	header := deliver.UserDataHeaderInfo
	if deliver.Text != "hi" || !deliver.UserDataHeader || deliver.UserDataLength != 9 {
		t.Fatalf("deliver=%+v", deliver)
	}
	if !header.HasPorts || header.PortBits != 16 || header.DestinationPort != 2948 || header.SourcePort != 9200 {
		t.Fatalf("UDH ports=%+v", header)
	}
	if len(header.Elements) != 1 || header.Elements[0].Identifier != 0x05 || string(header.Elements[0].Data) != string([]byte{0x0b, 0x84, 0x23, 0xf0}) {
		t.Fatalf("UDH elements=%+v", header.Elements)
	}
}

func TestParseSMSDeliverTPDUWith8BitPortAndUnknownUDH(t *testing.T) {
	tpdu := mustHex(t, "4005810180F60004627050214365000B0804027F009902AABB6F6B")
	deliver, err := ParseSMSDeliverTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSDeliverTPDU() error = %v", err)
	}
	header := deliver.UserDataHeaderInfo
	if deliver.Text != "ok" {
		t.Fatalf("deliver=%+v", deliver)
	}
	if !header.HasPorts || header.PortBits != 8 || header.DestinationPort != 0x7f || header.SourcePort != 0 {
		t.Fatalf("UDH ports=%+v", header)
	}
	if len(header.Elements) != 2 || header.Elements[0].Identifier != 0x04 || header.Elements[1].Identifier != 0x99 {
		t.Fatalf("UDH elements=%+v", header.Elements)
	}
}

func TestParseSMSDeliverTPDUPreservesMWIDataCoding(t *testing.T) {
	tpdu := mustHex(t, "0005810180F600D86270502143650002EF35")
	deliver, err := ParseSMSDeliverTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSDeliverTPDU() error = %v", err)
	}
	if deliver.Text != "ok" || !deliver.DataCoding.MessageWaiting || !deliver.DataCoding.MessageWaitingActive || deliver.DataCoding.MessageWaitingType != "voicemail" {
		t.Fatalf("deliver=%+v dataCoding=%+v", deliver, deliver.DataCoding)
	}
}

func TestParseSMSDeliverTPDUUCS2With16BitConcatUDH(t *testing.T) {
	tpdu := mustHex(t, "4005810180F600086270502143650009060804123402014F60")
	deliver, err := ParseSMSDeliverTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSDeliverTPDU() error = %v", err)
	}
	if deliver.Text != "你" || !deliver.Concat.IsConcat || deliver.Concat.Ref != 0x1234 || deliver.Concat.RefBits != 16 || deliver.Concat.Total != 2 || deliver.Concat.Seq != 1 {
		t.Fatalf("deliver=%+v", deliver)
	}
}

func TestParseSMSStatusReportTPDU(t *testing.T) {
	tpdu := mustHex(t, "02070B918100551512F2627050214365006270502144000000")
	report, err := ParseSMSStatusReportTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSStatusReportTPDU() error = %v", err)
	}
	if report.Reference != 7 || report.Recipient != "+18005551212" || report.Status != 0 || report.State != "delivered" {
		t.Fatalf("report=%+v", report)
	}
	if text := SMSStatusReportText(report.Status); !strings.Contains(text, "received by SME") {
		t.Fatalf("SMSStatusReportText(0x00)=%q", text)
	}
}

func TestBuildSMSStatusReportTPDURoundTrip(t *testing.T) {
	sentAt := time.Date(2026, 7, 5, 12, 34, 56, 0, time.FixedZone("", 0))
	doneAt := time.Date(2026, 7, 5, 12, 44, 0, 0, time.FixedZone("", 0))
	tpdu, err := BuildSMSStatusReportTPDU(SMSStatusReport{
		FirstOctet: 0x02,
		Reference:  7,
		Recipient:  "+18005551212",
		Timestamp:  sentAt,
		DoneAt:     doneAt,
		Status:     0x00,
	})
	if err != nil {
		t.Fatalf("BuildSMSStatusReportTPDU() error = %v", err)
	}
	got := strings.ToUpper(hex.EncodeToString(tpdu))
	want := "02070B918100551512F2627050214365006270502144000000"
	if got != want {
		t.Fatalf("TPDU=%s want %s", got, want)
	}
	report, err := ParseSMSStatusReportTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSStatusReportTPDU() error = %v", err)
	}
	if report.Reference != 7 || report.Recipient != "+18005551212" || report.Status != 0x00 || report.State != "delivered" {
		t.Fatalf("report=%+v", report)
	}
	if !report.Timestamp.Equal(sentAt) || !report.DoneAt.Equal(doneAt) {
		t.Fatalf("timestamps=%s/%s want %s/%s", report.Timestamp, report.DoneAt, sentAt, doneAt)
	}
}

func TestParseSMSStatusReportTPDUPreservesOptionalParameters(t *testing.T) {
	tpdu := mustHex(t, "26070B918100551512F2627050214365006270502144000000077F0005E8329BFD06")
	report, err := ParseSMSStatusReportTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSStatusReportTPDU() error = %v", err)
	}
	if report.FirstOctet != 0x26 || report.Reference != 7 || report.Status != 0 || report.State != "delivered" {
		t.Fatalf("report metadata=%+v", report)
	}
	if report.MoreMessagesToSend || !report.StatusReportQualifier || report.UserDataHeader {
		t.Fatalf("report flags=%+v", report)
	}
	if !report.HasParameterIndicator || report.ParameterIndicator != 0x07 || !report.HasProtocolID || report.ProtocolID != 0x7f || !report.HasDataCodingScheme || report.DataCodingScheme != 0x00 {
		t.Fatalf("report optional fields=%+v", report)
	}
	if report.DataCoding.Raw != 0x00 || report.DataCoding.Alphabet != "gsm7" {
		t.Fatalf("report data coding=%+v", report.DataCoding)
	}
	if !report.HasUserData || report.UserDataLength != 5 || report.UserData != "hello" {
		t.Fatalf("report user data=%+v", report)
	}
}

func TestBuildSMSStatusReportTPDUOptionalParameters(t *testing.T) {
	sentAt := time.Date(2026, 7, 5, 12, 34, 56, 0, time.FixedZone("", 0))
	doneAt := time.Date(2026, 7, 5, 12, 44, 0, 0, time.FixedZone("", 0))
	tpdu, err := BuildSMSStatusReportTPDU(SMSStatusReport{
		FirstOctet:          0x26,
		Reference:           7,
		Recipient:           "+18005551212",
		Timestamp:           sentAt,
		DoneAt:              doneAt,
		Status:              0x00,
		ProtocolID:          0x7f,
		HasProtocolID:       true,
		DataCodingScheme:    0x00,
		HasDataCodingScheme: true,
		UserData:            "hello",
		HasUserData:         true,
	})
	if err != nil {
		t.Fatalf("BuildSMSStatusReportTPDU() error = %v", err)
	}
	got := strings.ToUpper(hex.EncodeToString(tpdu))
	want := "26070B918100551512F2627050214365006270502144000000077F0005E8329BFD06"
	if got != want {
		t.Fatalf("TPDU=%s want %s", got, want)
	}

	rpAck, err := BuildSMSRPAckWithTPDU(0x55, tpdu)
	if err != nil {
		t.Fatalf("BuildSMSRPAckWithTPDU() error = %v", err)
	}
	rpdu, err := ParseSMSRPDU(rpAck)
	if err != nil {
		t.Fatalf("ParseSMSRPDU() error = %v", err)
	}
	if rpdu.Kind != SMSRPDUKindAck || rpdu.MR != 0x55 || string(rpdu.TPDU) != string(tpdu) {
		t.Fatalf("rpdu=%+v", rpdu)
	}
	report, err := ParseSMSStatusReportTPDU(rpdu.TPDU)
	if err != nil {
		t.Fatalf("ParseSMSStatusReportTPDU() error = %v", err)
	}
	if !report.HasProtocolID || report.ProtocolID != 0x7f || !report.HasDataCodingScheme || !report.HasUserData || report.UserData != "hello" {
		t.Fatalf("report optional fields=%+v", report)
	}
}

func TestBuildSMSStatusReportTPDUWithNationalLanguageUDH(t *testing.T) {
	sentAt := time.Date(2026, 7, 5, 12, 34, 56, 0, time.FixedZone("", 0))
	doneAt := time.Date(2026, 7, 5, 12, 44, 0, 0, time.FixedZone("", 0))
	tpdu, err := BuildSMSStatusReportTPDU(SMSStatusReport{
		Reference: 7,
		Recipient: "10086",
		Timestamp: sentAt,
		DoneAt:    doneAt,
		Status:    0x20,
		UserDataHeaderInfo: SMSUserDataHeaderInfo{
			Raw: []byte{0x03, 0x24, 0x01, byte(SMSNationalLanguageTurkish)},
		},
		UserData:    "\u011e",
		HasUserData: true,
	})
	if err != nil {
		t.Fatalf("BuildSMSStatusReportTPDU() error = %v", err)
	}
	report, err := ParseSMSStatusReportTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSStatusReportTPDU() error = %v tpdu=%x", err, tpdu)
	}
	if report.FirstOctet&0x40 == 0 || !report.UserDataHeader || report.UserData != "\u011e" || report.UserDataLength != 7 {
		t.Fatalf("report user data=%+v", report)
	}
	if !report.UserDataHeaderInfo.HasSingleShift || report.UserDataHeaderInfo.SingleShiftLang != SMSNationalLanguageTurkish {
		t.Fatalf("report UDH=%+v", report.UserDataHeaderInfo)
	}
}

func TestParseSMSStatusReportTPDUStatesAndText(t *testing.T) {
	tpdu := mustHex(t, "02070B918100551512F2627050214365006270502144000020")
	report, err := ParseSMSStatusReportTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSStatusReportTPDU(pending) error = %v", err)
	}
	if report.Status != 0x20 || report.State != "accepted" || !strings.Contains(SMSStatusReportText(report.Status), "still retrying") {
		t.Fatalf("pending report=%+v text=%q", report, SMSStatusReportText(report.Status))
	}

	tpdu[len(tpdu)-1] = 0x46
	report, err = ParseSMSStatusReportTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSStatusReportTPDU(failed) error = %v", err)
	}
	if report.Status != 0x46 || report.State != "failed" || !strings.Contains(SMSStatusReportText(report.Status), "validity period expired") {
		t.Fatalf("failed report=%+v text=%q", report, SMSStatusReportText(report.Status))
	}
}

func mustHex(tb testing.TB, s string) []byte {
	tb.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatalf("DecodeString(%q) error = %v", s, err)
	}
	return out
}

func deliverTPDUWithUserData(tb testing.TB, udh []byte, text string, lockingLang, singleLang int) []byte {
	tb.Helper()
	userData, udl, dcs, err := encodeSMSUserDataWithLanguage(text, "gsm7", udh, lockingLang, singleLang)
	if err != nil {
		tb.Fatalf("encodeSMSUserDataWithLanguage() error = %v", err)
	}
	tpdu := mustHex(tb, "4005810180F6000062705021436500")
	tpdu[7] = dcs
	tpdu = append(tpdu, byte(udl))
	tpdu = append(tpdu, userData...)
	return tpdu
}
