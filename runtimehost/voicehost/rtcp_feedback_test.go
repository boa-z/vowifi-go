package voicehost

import (
	"errors"
	"strings"
	"testing"

	"github.com/pion/rtcp"
)

func TestParseAndSelectSDPRTCPFeedbackAttributes(t *testing.T) {
	raw := []byte("v=0\r\n" +
		"c=IN IP4 203.0.113.8\r\n" +
		"m=audio 49170 RTP/SAVPF 96 110 111\r\n" +
		"a=rtcp-fb:* nack pli\r\n" +
		"a=rtcp-fb:96 goog-remb\r\n" +
		"a=rtcp-fb:110 transport-cc\r\n" +
		"a=rtcp-fb:111 nack\r\n")
	attrs, err := ParseSDPRTCPFeedbackAttributes(raw)
	if err != nil {
		t.Fatalf("ParseSDPRTCPFeedbackAttributes() error = %v", err)
	}
	if len(attrs) != 4 || attrs[0].Payload != "*" || attrs[0].Type != "nack" || attrs[0].Parameter != "pli" {
		t.Fatalf("attrs=%+v", attrs)
	}

	selected := SelectSDPRTCPFeedbackAnswer(attrs, []SDPRTCPFeedbackAttribute{
		{Payload: "96", Type: "nack", Parameter: "pli"},
		{Payload: "*", Type: "goog-remb"},
		{Payload: "*", Type: "transport-cc"},
	}, []int{96, 110})
	if len(selected) != 3 {
		t.Fatalf("selected=%+v", selected)
	}
	if selected[0].Payload != "96" || selected[0].Type != "nack" || selected[0].Parameter != "pli" {
		t.Fatalf("selected[0]=%+v", selected[0])
	}
	if selected[1].Payload != "96" || selected[1].Type != "goog-remb" {
		t.Fatalf("selected[1]=%+v", selected[1])
	}
	if selected[2].Payload != "110" || selected[2].Type != "transport-cc" {
		t.Fatalf("selected[2]=%+v", selected[2])
	}

	_, _, err = ParseSDPRTCPFeedbackLine("a=rtcp-fb:abc nack")
	if !errors.Is(err, ErrInvalidSDPSecurity) {
		t.Fatalf("ParseSDPRTCPFeedbackLine(invalid) err=%v, want ErrInvalidSDPSecurity", err)
	}
}

func TestRewriteSDPRTCPFeedbackReplacesOnlyAudioFeedback(t *testing.T) {
	body := []byte("v=0\r\n" +
		"c=IN IP4 203.0.113.8\r\n" +
		"m=audio 49170 RTP/SAVPF 96\r\n" +
		"a=rtcp-fb:* nack\r\n" +
		"a=rtpmap:96 AMR/8000\r\n" +
		"m=video 50000 RTP/SAVPF 120\r\n" +
		"a=rtcp-fb:120 nack\r\n")
	rewritten := string(RewriteSDPRTCPFeedback(body, []SDPRTCPFeedbackAttribute{
		{Payload: "96", Type: "nack", Parameter: "pli"},
		{Payload: "*", Type: "trr-int", Parameter: "100"},
	}))
	for _, want := range []string{
		"m=audio 49170 RTP/SAVPF 96\r\n",
		"a=rtcp-fb:96 nack pli\r\n",
		"a=rtcp-fb:* trr-int 100\r\n",
		"a=rtpmap:96 AMR/8000\r\n",
		"m=video 50000 RTP/SAVPF 120\r\n",
		"a=rtcp-fb:120 nack\r\n",
	} {
		if !strings.Contains(rewritten, want) {
			t.Fatalf("rewritten missing %q:\n%s", want, rewritten)
		}
	}
	if strings.Contains(rewritten, "a=rtcp-fb:* nack\r\n") {
		t.Fatalf("rewritten kept old audio feedback:\n%s", rewritten)
	}
}

func TestInspectRTCPFeedbackReportsReceptionBlocks(t *testing.T) {
	raw, err := rtcp.Marshal([]rtcp.Packet{
		&rtcp.ReceiverReport{
			SSRC: 0x11111111,
			Reports: []rtcp.ReceptionReport{{
				SSRC:               0x22222222,
				FractionLost:       32,
				TotalLost:          7,
				LastSequenceNumber: 0x00010010,
				Jitter:             41,
				LastSenderReport:   0x12345678,
				Delay:              0x00001000,
			}},
		},
		&rtcp.SenderReport{
			SSRC:        0x33333333,
			NTPTime:     0x0102030405060708,
			RTPTime:     0x11223344,
			PacketCount: 19,
			OctetCount:  3040,
			Reports: []rtcp.ReceptionReport{{
				SSRC:               0x44444444,
				FractionLost:       8,
				TotalLost:          2,
				LastSequenceNumber: 0x00020020,
				Jitter:             11,
			}},
		},
	})
	if err != nil {
		t.Fatalf("rtcp.Marshal() error = %v", err)
	}

	var events []RTCPFeedbackEvent
	summary, err := InspectRTCPFeedback(RTCPFeedbackIMSToClient, raw, func(event RTCPFeedbackEvent) {
		events = append(events, event)
	})
	if err != nil {
		t.Fatalf("InspectRTCPFeedback() error = %v", err)
	}
	if summary.Packets != 2 || summary.ReceiverReports != 1 || summary.SenderReports != 1 {
		t.Fatalf("summary=%+v", summary)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d, want 2", len(events))
	}

	rr := events[0]
	if rr.Direction != RTCPFeedbackIMSToClient || rr.Kind != RTCPFeedbackReceiverReport || rr.SSRC != 0x11111111 || rr.ReportCount != 1 {
		t.Fatalf("receiver report event=%+v", rr)
	}
	if len(rr.Reports) != 1 {
		t.Fatalf("receiver report blocks=%+v", rr.Reports)
	}
	if got := rr.Reports[0]; got.SSRC != 0x22222222 || got.FractionLost != 32 || got.TotalLost != 7 ||
		got.LastSequenceNumber != 0x00010010 || got.Jitter != 41 || got.LastSenderReport != 0x12345678 || got.Delay != 0x00001000 {
		t.Fatalf("receiver report block=%+v", got)
	}

	sr := events[1]
	if sr.Kind != RTCPFeedbackSenderReport || sr.SSRC != 0x33333333 || sr.ReportCount != 1 {
		t.Fatalf("sender report event=%+v", sr)
	}
	if sr.NTPTime != 0x0102030405060708 || sr.RTPTime != 0x11223344 || sr.PacketCount != 19 || sr.OctetCount != 3040 {
		t.Fatalf("sender report timing/counters=%+v", sr)
	}
	if len(sr.Reports) != 1 {
		t.Fatalf("sender report blocks=%+v", sr.Reports)
	}
	if got := sr.Reports[0]; got.SSRC != 0x44444444 || got.FractionLost != 8 || got.TotalLost != 2 ||
		got.LastSequenceNumber != 0x00020020 || got.Jitter != 11 {
		t.Fatalf("sender report block=%+v", got)
	}
}
