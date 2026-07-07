package voicehost

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/pion/rtcp"
)

func TestRTPStreamStatsSequentialPackets(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	ssrc := uint32(0x11223344)
	for i := 0; i < 3; i++ {
		packet := buildRTPStatsPacket(ssrc, uint16(10+i), uint32(1000+i*160))
		if _, err := tracker.ObserveRTPPacket(packet, base.Add(time.Duration(i)*20*time.Millisecond), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", i, err)
		}
	}

	stats, ok := tracker.StatsForSSRC(ssrc)
	if !ok {
		t.Fatalf("StatsForSSRC() ok=false")
	}
	if stats.Packets != 3 || stats.ExpectedPackets != 3 || stats.LostPackets != 0 || stats.FractionLost != 0 {
		t.Fatalf("stats packet/loss=%+v", stats)
	}
	if stats.LastSequenceNumber != 12 || stats.Jitter != 0 {
		t.Fatalf("stats sequence/jitter=%+v", stats)
	}
}

func TestRTPStreamStatsEstimatesLoss(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	ssrc := uint32(0x22334455)
	inputs := []struct {
		sequence  uint16
		timestamp uint32
		arrival   time.Duration
	}{
		{sequence: 10, timestamp: 1000},
		{sequence: 12, timestamp: 1320, arrival: 40 * time.Millisecond},
	}
	for _, input := range inputs {
		packet := buildRTPStatsPacket(ssrc, input.sequence, input.timestamp)
		if _, err := tracker.ObserveRTPPacket(packet, base.Add(input.arrival), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", input.sequence, err)
		}
	}

	stats, ok := tracker.StatsForSSRC(ssrc)
	if !ok {
		t.Fatalf("StatsForSSRC() ok=false")
	}
	if stats.Packets != 2 || stats.ExpectedPackets != 3 || stats.LostPackets != 1 || stats.FractionLost != 85 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestRTPStreamStatsOutOfOrderAndDuplicate(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	ssrc := uint32(0x33445566)
	packets := []struct {
		sequence  uint16
		timestamp uint32
		arrival   time.Duration
	}{
		{sequence: 10, timestamp: 1000},
		{sequence: 12, timestamp: 1320, arrival: 40 * time.Millisecond},
		{sequence: 12, timestamp: 1320, arrival: 45 * time.Millisecond},
		{sequence: 11, timestamp: 1160, arrival: 50 * time.Millisecond},
	}
	for _, packet := range packets {
		raw := buildRTPStatsPacket(ssrc, packet.sequence, packet.timestamp)
		if _, err := tracker.ObserveRTPPacket(raw, base.Add(packet.arrival), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", packet.sequence, err)
		}
	}

	stats, ok := tracker.StatsForSSRC(ssrc)
	if !ok {
		t.Fatalf("StatsForSSRC() ok=false")
	}
	if stats.Packets != 3 || stats.ExpectedPackets != 3 || stats.LostPackets != 0 || stats.LastSequenceNumber != 12 {
		t.Fatalf("stats=%+v", stats)
	}
	if stats.DuplicatePackets != 1 || stats.OutOfOrderPackets != 1 {
		t.Fatalf("duplicate/out-of-order stats=%+v", stats)
	}
}

func TestRTPStreamStatsTracksMultipleSSRCs(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	firstSSRC := uint32(0x33445566)
	secondSSRC := uint32(0x33445567)
	inputs := []struct {
		ssrc      uint32
		sequence  uint16
		timestamp uint32
	}{
		{ssrc: secondSSRC, sequence: 44, timestamp: 2000},
		{ssrc: firstSSRC, sequence: 7, timestamp: 1000},
		{ssrc: secondSSRC, sequence: 45, timestamp: 2160},
	}
	for i, input := range inputs {
		packet := buildRTPStatsPacket(input.ssrc, input.sequence, input.timestamp)
		if _, err := tracker.ObserveRTPPacket(packet, base.Add(time.Duration(i)*20*time.Millisecond), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", i, err)
		}
	}

	stats := tracker.Stats()
	if len(stats) != 2 {
		t.Fatalf("stats=%+v", stats)
	}
	if stats[0].SSRC != firstSSRC || stats[0].Packets != 1 || stats[0].LastSequenceNumber != 7 {
		t.Fatalf("first stats=%+v", stats[0])
	}
	if stats[1].SSRC != secondSSRC || stats[1].Packets != 2 || stats[1].LastSequenceNumber != 45 {
		t.Fatalf("second stats=%+v", stats[1])
	}
}

func TestRTPStreamStatsSequenceRollover(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	ssrc := uint32(0x44556677)
	sequences := []uint16{0xfffe, 0xffff, 0x0000, 0x0001}
	for i, sequence := range sequences {
		packet := buildRTPStatsPacket(ssrc, sequence, uint32(1000+i*160))
		if _, err := tracker.ObserveRTPPacket(packet, base.Add(time.Duration(i)*20*time.Millisecond), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", sequence, err)
		}
	}

	stats, ok := tracker.StatsForSSRC(ssrc)
	if !ok {
		t.Fatalf("StatsForSSRC() ok=false")
	}
	if stats.Packets != 4 || stats.ExpectedPackets != 4 || stats.LostPackets != 0 {
		t.Fatalf("stats=%+v", stats)
	}
	if stats.LastSequenceNumber != 0x00010001 {
		t.Fatalf("LastSequenceNumber=%d, want %d", stats.LastSequenceNumber, uint32(0x00010001))
	}
	if stats.SequenceRollovers != 1 {
		t.Fatalf("SequenceRollovers=%d, want 1", stats.SequenceRollovers)
	}
}

func TestRTPStreamStatsTimestampRollover(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	ssrc := uint32(0x44556678)
	inputs := []struct {
		sequence  uint16
		timestamp uint32
		arrival   time.Duration
	}{
		{sequence: 10, timestamp: 0xfffffff0},
		{sequence: 11, timestamp: 0x00000090, arrival: 20 * time.Millisecond},
		{sequence: 12, timestamp: 0x00000130, arrival: 40 * time.Millisecond},
	}
	for _, input := range inputs {
		packet := buildRTPStatsPacket(ssrc, input.sequence, input.timestamp)
		if _, err := tracker.ObserveRTPPacket(packet, base.Add(input.arrival), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", input.sequence, err)
		}
	}

	stats, ok := tracker.StatsForSSRC(ssrc)
	if !ok {
		t.Fatalf("StatsForSSRC() ok=false")
	}
	if stats.Packets != 3 || stats.ExpectedPackets != 3 || stats.LostPackets != 0 {
		t.Fatalf("stats=%+v", stats)
	}
	if stats.LastTimestamp != 0x0000000100000130 || stats.TimestampRollovers != 1 {
		t.Fatalf("timestamp stats=%+v", stats)
	}
	if stats.Jitter != 0 {
		t.Fatalf("Jitter=%d, want 0", stats.Jitter)
	}
}

func TestRTPRelayDirectionQualityAggregatesRTPRollovers(t *testing.T) {
	quality := newRTPRelayDirectionQuality(RTCPFeedbackClientToIMS, 0, 0, 0, 0, 0, 0, []RTPStreamStats{
		{Packets: 3, ExpectedPackets: 3, SequenceRollovers: 1, TimestampRollovers: 2},
		{Packets: 2, ExpectedPackets: 2, SequenceRollovers: 3, TimestampRollovers: 4},
	}, nil)

	if quality.RTPReceivedPackets != 5 || quality.RTPExpectedPackets != 5 {
		t.Fatalf("quality packets=%+v", quality)
	}
	if quality.RTPSequenceRollovers != 4 || quality.RTPTimestampRollovers != 6 {
		t.Fatalf("quality rollover stats=%+v", quality)
	}
}

func TestRTPStreamStatsTracksSenderReportDelay(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(10, 0)
	ssrc := uint32(0x55443322)
	packet := buildRTPStatsPacket(ssrc, 40, 4000)
	if _, err := tracker.ObserveRTPPacket(packet, base, 8000); err != nil {
		t.Fatalf("ObserveRTPPacket() error = %v", err)
	}

	ntpTime := uint64(0x123456789abcdef0)
	srArrival := base.Add(25 * time.Millisecond)
	stats, ok := tracker.ObserveRTCPSenderReport(ssrc, ntpTime, srArrival)
	if !ok {
		t.Fatalf("ObserveRTCPSenderReport() ok=false")
	}
	if stats.LastSenderReport != rtcpLastSenderReport(ntpTime) || stats.Delay != 0 {
		t.Fatalf("sender report stats=%+v", stats)
	}

	now := base.Add(1575 * time.Millisecond)
	stats, ok = tracker.StatsForSSRCAt(ssrc, now)
	if !ok {
		t.Fatalf("StatsForSSRCAt() ok=false")
	}
	wantDelay := rtcpCompactDelay(now.Sub(srArrival))
	if stats.LastSenderReport != rtcpLastSenderReport(ntpTime) || stats.Delay != wantDelay {
		t.Fatalf("sender report stats=%+v want LSR=%08x DLSR=%08x", stats, rtcpLastSenderReport(ntpTime), wantDelay)
	}

	report := BuildReceiverReport(0x01020304, []RTPStreamStats{stats})
	if len(report.Reports) != 1 {
		t.Fatalf("reports=%d, want 1", len(report.Reports))
	}
	block := report.Reports[0]
	if block.LastSenderReport != rtcpLastSenderReport(ntpTime) || block.Delay != wantDelay {
		t.Fatalf("report block=%+v want LSR=%08x DLSR=%08x", block, rtcpLastSenderReport(ntpTime), wantDelay)
	}
}

func TestRTPStreamStatsObservesRTCPSenderReportPacket(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(20, 0)
	firstSSRC := uint32(0x01020304)
	secondSSRC := uint32(0x01020305)
	for i, ssrc := range []uint32{secondSSRC, firstSSRC} {
		packet := buildRTPStatsPacket(ssrc, uint16(40+i), uint32(4000+i*160))
		if _, err := tracker.ObserveRTPPacket(packet, base.Add(time.Duration(i)*20*time.Millisecond), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%08x) error = %v", ssrc, err)
		}
	}

	firstNTP := rtcpNTPTime(time.Unix(21, int64(250*time.Millisecond)))
	secondNTP := rtcpNTPTime(time.Unix(22, int64(500*time.Millisecond)))
	raw, err := rtcp.Marshal([]rtcp.Packet{
		&rtcp.SenderReport{SSRC: secondSSRC, NTPTime: secondNTP, RTPTime: 0x22222222, PacketCount: 10, OctetCount: 1600},
		&rtcp.ReceiverReport{SSRC: 0x11111111},
		&rtcp.SenderReport{SSRC: firstSSRC, NTPTime: firstNTP, RTPTime: 0x11111111, PacketCount: 7, OctetCount: 1120},
	})
	if err != nil {
		t.Fatalf("rtcp.Marshal() error = %v", err)
	}

	srArrival := base.Add(100 * time.Millisecond)
	updated, err := tracker.ObserveRTCPPacket(raw, srArrival)
	if err != nil {
		t.Fatalf("ObserveRTCPPacket() error = %v", err)
	}
	if len(updated) != 2 || updated[0].SSRC != firstSSRC || updated[1].SSRC != secondSSRC {
		t.Fatalf("updated=%+v", updated)
	}
	if updated[0].LastSenderReport != rtcpLastSenderReport(firstNTP) || updated[0].Delay != 0 ||
		updated[1].LastSenderReport != rtcpLastSenderReport(secondNTP) || updated[1].Delay != 0 {
		t.Fatalf("updated sender report stats=%+v", updated)
	}

	now := srArrival.Add(1500 * time.Millisecond)
	firstStats, ok := tracker.StatsForSSRCAt(firstSSRC, now)
	if !ok {
		t.Fatalf("StatsForSSRCAt(%08x) ok=false", firstSSRC)
	}
	wantDelay := rtcpCompactDelay(now.Sub(srArrival))
	if firstStats.LastSenderReport != rtcpLastSenderReport(firstNTP) || firstStats.Delay != wantDelay {
		t.Fatalf("first stats=%+v want LSR=%08x DLSR=%08x", firstStats, rtcpLastSenderReport(firstNTP), wantDelay)
	}
}

func TestRTPStreamStatsCachesRTCPSenderReportBeforeRTP(t *testing.T) {
	var tracker RTPStreamStatsTracker
	ssrc := uint32(0x66554433)
	ntpTime := rtcpNTPTime(time.Unix(30, int64(125*time.Millisecond)))
	raw, err := rtcp.Marshal([]rtcp.Packet{&rtcp.SenderReport{SSRC: ssrc, NTPTime: ntpTime}})
	if err != nil {
		t.Fatalf("rtcp.Marshal() error = %v", err)
	}

	srArrival := time.Unix(31, 0)
	updated, err := tracker.ObserveRTCPPacket(raw, srArrival)
	if err != nil {
		t.Fatalf("ObserveRTCPPacket() error = %v", err)
	}
	if len(updated) != 0 {
		t.Fatalf("updated=%+v, want no tracked streams", updated)
	}

	rtpArrival := srArrival.Add(750 * time.Millisecond)
	stats, err := tracker.ObserveRTPPacket(buildRTPStatsPacket(ssrc, 90, 9000), rtpArrival, 8000)
	if err != nil {
		t.Fatalf("ObserveRTPPacket() error = %v", err)
	}
	wantDelay := rtcpCompactDelay(rtpArrival.Sub(srArrival))
	if stats.LastSenderReport != rtcpLastSenderReport(ntpTime) || stats.Delay != wantDelay {
		t.Fatalf("stats=%+v want LSR=%08x DLSR=%08x", stats, rtcpLastSenderReport(ntpTime), wantDelay)
	}
}

func TestRTPStreamStatsObserveRTCPPacketRejectsInvalidPacket(t *testing.T) {
	var tracker RTPStreamStatsTracker
	if _, err := tracker.ObserveRTCPPacket([]byte{0x80}, time.Unix(0, 0)); err == nil {
		t.Fatal("ObserveRTCPPacket(invalid) err=nil, want error")
	}
}

func TestBuildReceiverReport(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	mediaSSRC := uint32(0x55667788)
	inputs := []struct {
		sequence  uint16
		timestamp uint32
		arrival   time.Duration
	}{
		{sequence: 10, timestamp: 1000},
		{sequence: 12, timestamp: 1320, arrival: 45 * time.Millisecond},
	}
	for _, input := range inputs {
		packet := buildRTPStatsPacket(mediaSSRC, input.sequence, input.timestamp)
		if _, err := tracker.ObserveRTPPacket(packet, base.Add(input.arrival), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", input.sequence, err)
		}
	}

	report := BuildReceiverReport(0x01020304, tracker.Stats())
	if report.SSRC != 0x01020304 || len(report.Reports) != 1 {
		t.Fatalf("report=%+v", report)
	}
	block := report.Reports[0]
	if block.SSRC != mediaSSRC || block.TotalLost != 1 || block.FractionLost != 85 || block.LastSequenceNumber != 12 {
		t.Fatalf("report block=%+v", block)
	}
	if block.Jitter != 2 {
		t.Fatalf("Jitter=%d, want 2", block.Jitter)
	}
	raw, err := report.Marshal()
	if err != nil {
		t.Fatalf("ReceiverReport.Marshal() error = %v", err)
	}
	packets, err := rtcp.Unmarshal(raw)
	if err != nil {
		t.Fatalf("rtcp.Unmarshal() error = %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("packets=%d, want 1", len(packets))
	}
}

func TestBuildSenderReportAndSourceDescription(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	mediaSSRC := uint32(0x66778899)
	for _, input := range []struct {
		sequence  uint16
		timestamp uint32
		arrival   time.Duration
	}{
		{sequence: 20, timestamp: 2000},
		{sequence: 22, timestamp: 2320, arrival: 45 * time.Millisecond},
	} {
		packet := buildRTPStatsPacket(mediaSSRC, input.sequence, input.timestamp)
		if _, err := tracker.ObserveRTPPacket(packet, base.Add(input.arrival), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", input.sequence, err)
		}
	}

	wallClock := time.Unix(1, int64(250*time.Millisecond))
	report := BuildSenderReport(RTCPSenderReportConfig{
		SSRC:           0x01020304,
		WallClock:      wallClock,
		RTPTime:        0x10203040,
		PacketCount:    17,
		OctetCount:     3200,
		ReceptionStats: tracker.Stats(),
	})
	wantNTP := uint64(ntpEpochOffsetSeconds+1)<<32 | uint64(1<<30)
	if report.SSRC != 0x01020304 || report.NTPTime != wantNTP || report.RTPTime != 0x10203040 ||
		report.PacketCount != 17 || report.OctetCount != 3200 || len(report.Reports) != 1 {
		t.Fatalf("sender report=%+v", report)
	}
	if block := report.Reports[0]; block.SSRC != mediaSSRC || block.TotalLost != 1 || block.FractionLost != 85 || block.LastSequenceNumber != 22 {
		t.Fatalf("sender report block=%+v", block)
	}

	sdes := BuildSourceDescription(RTCPSourceDescriptionConfig{
		SSRC:  0x01020304,
		CNAME: "session-01020304",
		Name:  "ims-audio",
		Tool:  "vowifi-go",
	})
	raw, err := rtcp.Marshal([]rtcp.Packet{report, sdes})
	if err != nil {
		t.Fatalf("rtcp.Marshal() error = %v", err)
	}
	packets, err := rtcp.Unmarshal(raw)
	if err != nil {
		t.Fatalf("rtcp.Unmarshal() error = %v", err)
	}
	if len(packets) != 2 {
		t.Fatalf("packets=%d, want 2", len(packets))
	}
	gotSR, ok := packets[0].(*rtcp.SenderReport)
	if !ok || gotSR.SSRC != 0x01020304 || len(gotSR.Reports) != 1 {
		t.Fatalf("sender report packet=%+v ok=%v", packets[0], ok)
	}
	gotSDES, ok := packets[1].(*rtcp.SourceDescription)
	if !ok || len(gotSDES.Chunks) != 1 || gotSDES.Chunks[0].Source != 0x01020304 || len(gotSDES.Chunks[0].Items) != 3 {
		t.Fatalf("source description packet=%+v ok=%v", packets[1], ok)
	}
	if gotSDES.Chunks[0].Items[0].Type != rtcp.SDESCNAME || gotSDES.Chunks[0].Items[0].Text != "session-01020304" {
		t.Fatalf("source description CNAME=%+v", gotSDES.Chunks[0].Items[0])
	}
}

func buildRTPStatsPacket(ssrc uint32, sequence uint16, timestamp uint32) []byte {
	packet := make([]byte, 13)
	packet[0] = 0x80
	packet[1] = 0x00
	binary.BigEndian.PutUint16(packet[2:4], sequence)
	binary.BigEndian.PutUint32(packet[4:8], timestamp)
	binary.BigEndian.PutUint32(packet[8:12], ssrc)
	packet[12] = 0xff
	return packet
}
