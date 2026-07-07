package voicehost

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/pion/rtcp"
)

func TestSRTPMediaSessionProtectsRTPAndRTCP(t *testing.T) {
	session, err := NewSRTPMediaSession(testSRTPMediaConfig())
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	clientRTP := testRTPPacket(1, 0x11111111, []byte{0xaa, 0xbb, 0xcc})
	clientProtected, err := session.ProtectClientRTP(clientRTP)
	if err != nil {
		t.Fatalf("ProtectClientRTP() error = %v", err)
	}
	if bytes.Equal(clientProtected, clientRTP) || len(clientProtected) <= len(clientRTP) {
		t.Fatalf("client SRTP did not protect packet: %x", clientProtected)
	}
	gotClientRTP, err := session.UnprotectClientRTP(clientProtected)
	if err != nil {
		t.Fatalf("UnprotectClientRTP() error = %v", err)
	}
	if !bytes.Equal(gotClientRTP, clientRTP) {
		t.Fatalf("client RTP=%x, want %x", gotClientRTP, clientRTP)
	}

	imsRTP := testRTPPacket(2, 0x22222222, []byte{0x44, 0x55})
	imsProtected, err := session.ProtectIMSRTP(imsRTP)
	if err != nil {
		t.Fatalf("ProtectIMSRTP() error = %v", err)
	}
	gotIMSRTP, err := session.UnprotectIMSRTP(imsProtected)
	if err != nil {
		t.Fatalf("UnprotectIMSRTP() error = %v", err)
	}
	if !bytes.Equal(gotIMSRTP, imsRTP) {
		t.Fatalf("IMS RTP=%x, want %x", gotIMSRTP, imsRTP)
	}

	clientRTCP := testRTCPPacket(0x11111111)
	clientRTCPProtected, err := session.ProtectClientRTCP(clientRTCP)
	if err != nil {
		t.Fatalf("ProtectClientRTCP() error = %v", err)
	}
	if bytes.Equal(clientRTCPProtected, clientRTCP) || len(clientRTCPProtected) <= len(clientRTCP) {
		t.Fatalf("client SRTCP did not protect packet: %x", clientRTCPProtected)
	}
	gotClientRTCP, err := session.UnprotectClientRTCP(clientRTCPProtected)
	if err != nil {
		t.Fatalf("UnprotectClientRTCP() error = %v", err)
	}
	if !bytes.Equal(gotClientRTCP, clientRTCP) {
		t.Fatalf("client RTCP=%x, want %x", gotClientRTCP, clientRTCP)
	}

	imsRTCP := testRTCPPacket(0x22222222)
	imsRTCPProtected, err := session.ProtectIMSRTCP(imsRTCP)
	if err != nil {
		t.Fatalf("ProtectIMSRTCP() error = %v", err)
	}
	gotIMSRTCP, err := session.UnprotectIMSRTCP(imsRTCPProtected)
	if err != nil {
		t.Fatalf("UnprotectIMSRTCP() error = %v", err)
	}
	if !bytes.Equal(gotIMSRTCP, imsRTCP) {
		t.Fatalf("IMS RTCP=%x, want %x", gotIMSRTCP, imsRTCP)
	}
}

func TestSRTPMediaSessionRejectsReplay(t *testing.T) {
	session, err := NewSRTPMediaSession(testSRTPMediaConfig())
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	protected, err := session.ProtectClientRTP(testRTPPacket(10, 0x11111111, []byte{0xaa}))
	if err != nil {
		t.Fatalf("ProtectClientRTP() error = %v", err)
	}
	if _, err := session.UnprotectClientRTP(protected); err != nil {
		t.Fatalf("first UnprotectClientRTP() error = %v", err)
	}
	if _, err := session.UnprotectClientRTP(protected); err == nil {
		t.Fatalf("second UnprotectClientRTP() error = nil, want replay rejection")
	}
}

func TestSRTPMediaSessionRejectsWrongKey(t *testing.T) {
	good, err := NewSRTPMediaSession(testSRTPMediaConfig())
	if err != nil {
		t.Fatalf("NewSRTPMediaSession(good) error = %v", err)
	}
	badCfg := testSRTPMediaConfig()
	badCfg.ClientKeys.MasterKey[0] ^= 0xff
	bad, err := NewSRTPMediaSession(badCfg)
	if err != nil {
		t.Fatalf("NewSRTPMediaSession(bad) error = %v", err)
	}
	protected, err := good.ProtectClientRTP(testRTPPacket(11, 0x11111111, []byte{0xaa}))
	if err != nil {
		t.Fatalf("ProtectClientRTP() error = %v", err)
	}
	if _, err := bad.UnprotectClientRTP(protected); err == nil {
		t.Fatalf("UnprotectClientRTP(wrong key) error = nil")
	}
}

func TestSRTPMediaSessionRejectsInvalidConfig(t *testing.T) {
	cfg := testSRTPMediaConfig()
	cfg.ClientKeys.MasterKey = cfg.ClientKeys.MasterKey[:15]
	if _, err := NewSRTPMediaSession(cfg); !errors.Is(err, ErrSRTPMediaConfig) {
		t.Fatalf("NewSRTPMediaSession(short key) err=%v, want ErrSRTPMediaConfig", err)
	}
	cfg = testSRTPMediaConfig()
	cfg.IMSKeys.MasterSalt = cfg.IMSKeys.MasterSalt[:13]
	if _, err := NewSRTPMediaSession(cfg); !errors.Is(err, ErrSRTPMediaConfig) {
		t.Fatalf("NewSRTPMediaSession(short salt) err=%v, want ErrSRTPMediaConfig", err)
	}
	cfg = testSRTPMediaConfig()
	cfg.Profile = "bogus"
	if _, err := NewSRTPMediaSession(cfg); !errors.Is(err, ErrSRTPMediaConfig) {
		t.Fatalf("NewSRTPMediaSession(profile) err=%v, want ErrSRTPMediaConfig", err)
	}
}

func TestSRTPProtectionProfileFromSDPCryptoSuite(t *testing.T) {
	profile, err := SRTPProtectionProfileFromSDPCryptoSuite("aes_cm_128_hmac_sha1_80")
	if err != nil {
		t.Fatalf("SRTPProtectionProfileFromSDPCryptoSuite() error = %v", err)
	}
	if profile != SRTPProfileAes128CmHmacSha1_80 || profile.SDPCryptoSuite() != "AES_CM_128_HMAC_SHA1_80" {
		t.Fatalf("profile=%q suite=%q", profile, profile.SDPCryptoSuite())
	}
	if _, err := SRTPProtectionProfileFromSDPCryptoSuite("bogus"); !errors.Is(err, ErrSRTPMediaConfig) {
		t.Fatalf("SRTPProtectionProfileFromSDPCryptoSuite(bogus) err=%v, want ErrSRTPMediaConfig", err)
	}
}

func TestSDPCryptoInlineKeyParamsRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x10}, 16)
	salt := bytes.Repeat([]byte{0x20}, 14)
	raw := append(append([]byte(nil), key...), salt...)
	params, err := ParseSDPCryptoInlineKeyParams(SRTPProfileAes128CmHmacSha1_80, "inline:"+base64.StdEncoding.EncodeToString(raw)+"|2^20|1:32")
	if err != nil {
		t.Fatalf("ParseSDPCryptoInlineKeyParams() error = %v", err)
	}
	if !bytes.Equal(params.MasterKey, key) || !bytes.Equal(params.MasterSalt, salt) || params.Lifetime != "2^20" || params.MKIValue != "1" || params.MKILength != 32 {
		t.Fatalf("params=%+v", params)
	}
	built, err := BuildSDPCryptoInlineKeyParams(SRTPProfileAes128CmHmacSha1_80, params)
	if err != nil {
		t.Fatalf("BuildSDPCryptoInlineKeyParams() error = %v", err)
	}
	reparsed, err := ParseSDPCryptoInlineKeyParams(SRTPProfileAes128CmHmacSha1_80, built)
	if err != nil {
		t.Fatalf("ParseSDPCryptoInlineKeyParams(built) error = %v", err)
	}
	if !bytes.Equal(reparsed.MasterKey, key) || !bytes.Equal(reparsed.MasterSalt, salt) || reparsed.Lifetime != "2^20" || reparsed.MKILength != 32 {
		t.Fatalf("reparsed=%+v built=%q", reparsed, built)
	}
}

func TestSDPCryptoAttributeKeyHelpers(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 16)
	salt := bytes.Repeat([]byte{0x22}, 14)
	attr, err := BuildSDPCryptoAttribute("3", SRTPProfileAes128CmHmacSha1_80, SDPCryptoInlineKeyParams{
		MasterKey:  key,
		MasterSalt: salt,
		Lifetime:   "2^20",
		MKIValue:   "7",
		MKILength:  4,
	}, "UNENCRYPTED_SRTCP")
	if err != nil {
		t.Fatalf("BuildSDPCryptoAttribute() error = %v", err)
	}
	if attr.Tag != "3" || attr.Suite != "AES_CM_128_HMAC_SHA1_80" || attr.SessionParams != "UNENCRYPTED_SRTCP" {
		t.Fatalf("attr=%+v", attr)
	}
	if attr.SDPValue() == "" {
		t.Fatalf("empty crypto SDP value attr=%+v", attr)
	}
	profile, parsed, err := ParseSDPCryptoAttributeKeys(attr)
	if err != nil {
		t.Fatalf("ParseSDPCryptoAttributeKeys() error = %v", err)
	}
	if profile != SRTPProfileAes128CmHmacSha1_80 || !bytes.Equal(parsed.MasterKey, key) ||
		!bytes.Equal(parsed.MasterSalt, salt) || parsed.Lifetime != "2^20" || parsed.MKIValue != "7" || parsed.MKILength != 4 {
		t.Fatalf("profile=%q parsed=%+v", profile, parsed)
	}

	answer := BuildSDPAnswerWithSecurity(SDPInfo{
		ConnectionIP: "192.0.2.2",
		MediaPort:    6000,
		Payloads:     []int{0},
		Direction:    "sendrecv",
	}, SDPSecurityInfo{
		RTPProfile: "RTP/SAVP",
		Crypto:     []SDPCryptoAttribute{attr},
	})
	_, security, err := ParseSDPWithSecurity(answer)
	if err != nil {
		t.Fatalf("ParseSDPWithSecurity(answer) error = %v", err)
	}
	if len(security.Crypto) != 1 {
		t.Fatalf("security=%+v", security)
	}
	if _, reparsed, err := ParseSDPCryptoAttributeKeys(security.Crypto[0]); err != nil ||
		!bytes.Equal(reparsed.MasterKey, key) || !bytes.Equal(reparsed.MasterSalt, salt) {
		t.Fatalf("reparsed=%+v err=%v", reparsed, err)
	}
	if _, _, err := ParseSDPCryptoAttributeKeys(SDPCryptoAttribute{Suite: "bogus", KeyParams: attr.KeyParams}); !errors.Is(err, ErrSRTPMediaConfig) {
		t.Fatalf("ParseSDPCryptoAttributeKeys(bogus) err=%v, want ErrSRTPMediaConfig", err)
	}
	if _, err := BuildSDPCryptoAttribute("", SRTPProfileAes128CmHmacSha1_80, SDPCryptoInlineKeyParams{MasterKey: key, MasterSalt: salt}, ""); !errors.Is(err, ErrSRTPMediaConfig) {
		t.Fatalf("BuildSDPCryptoAttribute(empty tag) err=%v, want ErrSRTPMediaConfig", err)
	}
}

func TestSelectSDPCryptoAttributeHonorsPreferencesAndSkipsUnsupported(t *testing.T) {
	key128 := testSDPSecurityCryptoInlineKeyParamsForProfile(t, SRTPProfileAes128CmHmacSha1_80)
	key256 := testSDPSecurityCryptoInlineKeyParamsForProfile(t, SRTPProfileAes256CmHmacSha1_80)
	crypto := []SDPCryptoAttribute{
		{Tag: "9", Suite: "F8_128_HMAC_SHA1_80", KeyParams: "inline:unsupported"},
		{Tag: "1", Suite: "AES_CM_128_HMAC_SHA1_80", KeyParams: key128},
		{Tag: "2", Suite: "AES_CM_256_HMAC_SHA1_80", KeyParams: key256},
	}
	attr, profile, params, ok, err := SelectSDPCryptoAttribute(crypto, []SRTPProtectionProfile{
		SRTPProfileAes256CmHmacSha1_80,
		SRTPProfileAes128CmHmacSha1_80,
	})
	if err != nil {
		t.Fatalf("SelectSDPCryptoAttribute(preferred) error = %v", err)
	}
	if !ok || attr.Tag != "2" || profile != SRTPProfileAes256CmHmacSha1_80 || len(params.MasterKey) != 32 || len(params.MasterSalt) != 14 {
		t.Fatalf("selected attr=%+v profile=%q params=%+v ok=%v", attr, profile, params, ok)
	}

	attr, profile, _, ok, err = SelectSDPCryptoAttribute(crypto, nil)
	if err != nil {
		t.Fatalf("SelectSDPCryptoAttribute(no preference) error = %v", err)
	}
	if !ok || attr.Tag != "1" || profile != SRTPProfileAes128CmHmacSha1_80 {
		t.Fatalf("selected attr=%+v profile=%q ok=%v", attr, profile, ok)
	}

	_, _, _, ok, err = SelectSDPCryptoAttribute(crypto, []SRTPProtectionProfile{SRTPProfileAeadAes128Gcm})
	if err != nil || ok {
		t.Fatalf("SelectSDPCryptoAttribute(no match) ok=%v err=%v", ok, err)
	}
	_, _, _, ok, err = SelectSDPCryptoAttribute([]SDPCryptoAttribute{{Tag: "1", Suite: "AES_CM_128_HMAC_SHA1_80", KeyParams: "inline:short"}}, nil)
	if ok || !errors.Is(err, ErrSRTPMediaConfig) {
		t.Fatalf("SelectSDPCryptoAttribute(bad key) ok=%v err=%v, want ErrSRTPMediaConfig", ok, err)
	}
}

func TestSRTPMediaSessionSupportsGCMProfile(t *testing.T) {
	cfg := testSRTPMediaConfig()
	cfg.Profile = SRTPProfileAeadAes128Gcm
	cfg.ClientKeys.MasterSalt = bytes.Repeat([]byte{0x20}, 12)
	cfg.IMSKeys.MasterSalt = bytes.Repeat([]byte{0x40}, 12)
	session, err := NewSRTPMediaSession(cfg)
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	protected, err := session.ProtectClientRTP(testRTPPacket(12, 0x11111111, []byte{0xaa, 0xbb}))
	if err != nil {
		t.Fatalf("ProtectClientRTP() error = %v", err)
	}
	got, err := session.UnprotectClientRTP(protected)
	if err != nil {
		t.Fatalf("UnprotectClientRTP() error = %v", err)
	}
	if want := testRTPPacket(12, 0x11111111, []byte{0xaa, 0xbb}); !bytes.Equal(got, want) {
		t.Fatalf("RTP=%x, want %x", got, want)
	}
}

func TestSRTPMediaSessionReportsRTCPFeedbackInRelayTransform(t *testing.T) {
	events := make(chan RTCPFeedbackEvent, 1)
	cfg := testSRTPMediaConfig()
	cfg.RTCPFeedbackHandler = func(event RTCPFeedbackEvent) {
		events <- event
	}
	session, err := NewSRTPMediaSession(cfg)
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	packet, err := (&rtcp.PictureLossIndication{SenderSSRC: 0x11111111, MediaSSRC: 0x22222222}).Marshal()
	if err != nil {
		t.Fatalf("PLI Marshal() error = %v", err)
	}
	protected, err := session.ProtectClientRTCP(packet)
	if err != nil {
		t.Fatalf("ProtectClientRTCP() error = %v", err)
	}
	transformed, err := session.RelayTransforms().ClientToIMSRTCP(protected)
	if err != nil {
		t.Fatalf("ClientToIMSRTCP() error = %v", err)
	}
	plain, err := session.UnprotectIMSRTCP(transformed)
	if err != nil {
		t.Fatalf("UnprotectIMSRTCP() error = %v", err)
	}
	if !bytes.Equal(plain, packet) {
		t.Fatalf("RTCP plain=%x, want %x", plain, packet)
	}
	event := readRTCPFeedbackEvent(t, events)
	if event.Direction != RTCPFeedbackClientToIMS || event.Kind != RTCPFeedbackPictureLossIndication || event.MediaSSRC != 0x22222222 {
		t.Fatalf("event=%+v", event)
	}
}

func TestSRTPMediaSessionReportsRTPDTMFInRelayTransform(t *testing.T) {
	events := make(chan RTPDTMFEvent, 1)
	cfg := testSRTPMediaConfig()
	cfg.ClientRTPDTMFPayloads = map[uint8]int{110: 16000}
	cfg.IMSRTPDTMFPayloads = map[uint8]int{101: 8000}
	cfg.RTPDTMFHandler = func(event RTPDTMFEvent) {
		events <- event
	}
	session, err := NewSRTPMediaSession(cfg)
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	packet, err := BuildRTPDTMFPacket(RTPDTMFPacket{PayloadType: 110, Marker: true, SequenceNumber: 44, Timestamp: 3200, SSRC: 0x11111111, Signal: "A", DurationSamples: 1600, ClockRate: 16000})
	if err != nil {
		t.Fatalf("BuildRTPDTMFPacket() error = %v", err)
	}
	protected, err := session.ProtectClientRTP(packet)
	if err != nil {
		t.Fatalf("ProtectClientRTP() error = %v", err)
	}
	transformed, err := session.RelayTransforms().ClientToIMSRTP(protected)
	if err != nil {
		t.Fatalf("ClientToIMSRTP() error = %v", err)
	}
	plain, err := session.UnprotectIMSRTP(transformed)
	if err != nil {
		t.Fatalf("UnprotectIMSRTP() error = %v", err)
	}
	wantPlain, remapped, err := RewriteRTPDTMFPayloadType(packet, cfg.ClientRTPDTMFPayloads, cfg.IMSRTPDTMFPayloads)
	if err != nil || !remapped {
		t.Fatalf("RewriteRTPDTMFPayloadType() remapped=%v err=%v", remapped, err)
	}
	if !bytes.Equal(plain, wantPlain) {
		t.Fatalf("RTP plain=%x, want %x", plain, wantPlain)
	}
	event := readRTPDTMFEvent(t, events)
	if event.Direction != RTPDTMFClientToIMS || event.PayloadType != 110 || event.Signal != "A" || event.DurationMS != 100 || !event.Marker {
		t.Fatalf("event=%+v", event)
	}
}

func TestSRTPMediaSessionReportsPlaintextRTPInRelayTransform(t *testing.T) {
	events := make(chan RTPPlaintextEvent, 4)
	session, err := NewSRTPMediaSession(testSRTPMediaConfig())
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	transforms := session.RelayTransformsWithMediaObservers(nil, nil, func(event RTPPlaintextEvent) {
		events <- event
	}, nil, nil)

	clientPlain := testRTPPacket(20, 0x11111111, []byte{0xaa})
	clientProtected, err := session.ProtectClientRTP(clientPlain)
	if err != nil {
		t.Fatalf("ProtectClientRTP() error = %v", err)
	}
	clientTransformed, err := transforms.ClientToIMSRTP(clientProtected)
	if err != nil {
		t.Fatalf("ClientToIMSRTP() error = %v", err)
	}
	clientForwardedPlain, err := session.UnprotectIMSRTP(clientTransformed)
	if err != nil {
		t.Fatalf("UnprotectIMSRTP() error = %v", err)
	}
	if !bytes.Equal(clientForwardedPlain, clientPlain) {
		t.Fatalf("client forwarded plain=%x, want %x", clientForwardedPlain, clientPlain)
	}
	clientEvent := readRTPPlaintextEvent(t, events)
	if clientEvent.Direction != RTPDTMFClientToIMS || !bytes.Equal(clientEvent.Packet, clientPlain) {
		t.Fatalf("client event=%+v packet=%x", clientEvent, clientEvent.Packet)
	}

	tracker := NewRTPStreamStatsTracker()
	arrival := time.Unix(100, 0)
	for i, seq := range []uint16{10, 12} {
		imsPlain := testRTPPacket(seq, 0x22222222, []byte{byte(seq)})
		imsProtected, err := session.ProtectIMSRTP(imsPlain)
		if err != nil {
			t.Fatalf("ProtectIMSRTP(%d) error = %v", seq, err)
		}
		imsTransformed, err := transforms.IMSToClientRTP(imsProtected)
		if err != nil {
			t.Fatalf("IMSToClientRTP(%d) error = %v", seq, err)
		}
		imsForwardedPlain, err := session.UnprotectClientRTP(imsTransformed)
		if err != nil {
			t.Fatalf("UnprotectClientRTP(%d) error = %v", seq, err)
		}
		if !bytes.Equal(imsForwardedPlain, imsPlain) {
			t.Fatalf("IMS forwarded plain=%x, want %x", imsForwardedPlain, imsPlain)
		}
		event := readRTPPlaintextEvent(t, events)
		if event.Direction != RTPDTMFIMSToClient || !bytes.Equal(event.Packet, imsPlain) {
			t.Fatalf("IMS event=%+v packet=%x want=%x", event, event.Packet, imsPlain)
		}
		if _, err := tracker.ObserveRTPPacket(event.Packet, arrival.Add(time.Duration(i)*20*time.Millisecond), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", seq, err)
		}
	}
	stats := tracker.Stats()
	if len(stats) != 1 || stats[0].SSRC != 0x22222222 || stats[0].Packets != 2 || stats[0].ExpectedPackets != 3 || stats[0].LostPackets != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func testSRTPMediaConfig() SRTPMediaConfig {
	return SRTPMediaConfig{
		Profile: SRTPProfileAes128CmHmacSha1_80,
		ClientKeys: SRTPKeys{
			MasterKey:  bytes.Repeat([]byte{0x10}, 16),
			MasterSalt: bytes.Repeat([]byte{0x20}, 14),
		},
		IMSKeys: SRTPKeys{
			MasterKey:  bytes.Repeat([]byte{0x30}, 16),
			MasterSalt: bytes.Repeat([]byte{0x40}, 14),
		},
	}
}

func testRTPPacket(sequence uint16, ssrc uint32, payload []byte) []byte {
	packet := []byte{
		0x80, 0x00,
		byte(sequence >> 8), byte(sequence),
		0x00, 0x00, 0x00, 0x01,
		byte(ssrc >> 24), byte(ssrc >> 16), byte(ssrc >> 8), byte(ssrc),
	}
	return append(packet, payload...)
}

func testRTCPPacket(ssrc uint32) []byte {
	return []byte{
		0x80, 0xc9, 0x00, 0x01,
		byte(ssrc >> 24), byte(ssrc >> 16), byte(ssrc >> 8), byte(ssrc),
	}
}

func readRTPPlaintextEvent(t *testing.T, events <-chan RTPPlaintextEvent) RTPPlaintextEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for RTP plaintext event")
		return RTPPlaintextEvent{}
	}
}
