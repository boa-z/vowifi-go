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

func TestParseSMSDeliverTPDUUCS2WithConcatUDH(t *testing.T) {
	tpdu := mustHex(t, "4005810180F6000862705021436500080500037A02014F60")
	deliver, err := ParseSMSDeliverTPDU(tpdu)
	if err != nil {
		t.Fatalf("ParseSMSDeliverTPDU() error = %v", err)
	}
	if deliver.Text != "你" || !deliver.Concat.IsConcat || deliver.Concat.Ref != 0x7a || deliver.Concat.Total != 2 || deliver.Concat.Seq != 1 {
		t.Fatalf("deliver=%+v", deliver)
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
