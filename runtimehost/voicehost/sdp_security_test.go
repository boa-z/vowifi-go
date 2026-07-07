package voicehost

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestSDPSecurityPlaintextDefaultBehavior(t *testing.T) {
	plain := []byte("v=0\r\n" +
		"o=user 0 0 IN IP4 203.0.113.8\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.8\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0 8 101\r\n" +
		"a=sendrecv\r\n")
	info, security, err := ParseSDPWithSecurity(plain)
	if err != nil {
		t.Fatalf("ParseSDPWithSecurity() error = %v", err)
	}
	if security.RTPProfile != "RTP/AVP" || security.HasSecurityAttributes() {
		t.Fatalf("security=%+v", security)
	}
	if got, want := string(BuildSDPAnswerWithSecurity(info, SDPSecurityInfo{})), string(BuildSDPAnswer(info)); got != want {
		t.Fatalf("BuildSDPAnswerWithSecurity(zero) changed plaintext SDP:\ngot:\n%s\nwant:\n%s", got, want)
	}

	secure := []byte("v=0\r\n" +
		"c=IN IP4 203.0.113.8\r\n" +
		"m=audio 49170 RTP/SAVP 96 110\r\n" +
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:MTIzNDU2Nzg5MDEyMzQ1Ng==\r\n" +
		"a=rtpmap:110 telephone-event/16000\r\n")
	secureInfo, err := ParseSDP(secure)
	if err != nil {
		t.Fatalf("ParseSDP(secure) error = %v", err)
	}
	answer := string(BuildSDPAnswer(secureInfo))
	if !strings.Contains(answer, "m=audio 49170 RTP/AVP 96 110\r\n") {
		t.Fatalf("default BuildSDPAnswer did not keep plaintext profile:\n%s", answer)
	}
	for _, unexpected := range []string{"RTP/SAVP", "a=crypto:", "a=fingerprint:", "a=setup:"} {
		if strings.Contains(answer, unexpected) {
			t.Fatalf("default BuildSDPAnswer leaked %q:\n%s", unexpected, answer)
		}
	}
}

func TestParseSDPSecuritySAVPCrypto(t *testing.T) {
	raw := []byte("v=0\r\n" +
		"o=user 0 0 IN IP4 203.0.113.8\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.8\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/SAVP 96 110\r\n" +
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 " + testSDPSecurityCryptoInlineKeyParams(t) + "|2^20|1:32 UNENCRYPTED_SRTCP\r\n" +
		"a=rtpmap:96 AMR/8000\r\n" +
		"a=rtpmap:110 telephone-event/16000\r\n" +
		"a=sendrecv\r\n")
	info, security, err := ParseSDPWithSecurity(raw)
	if err != nil {
		t.Fatalf("ParseSDPWithSecurity() error = %v", err)
	}
	if info.ConnectionIP != "203.0.113.8" || info.MediaPort != 49170 || len(info.Payloads) != 2 || info.Payloads[0] != 96 || info.Payloads[1] != 110 {
		t.Fatalf("info=%+v", info)
	}
	if security.RTPProfile != "RTP/SAVP" || len(security.Crypto) != 1 {
		t.Fatalf("security=%+v", security)
	}
	crypto := security.Crypto[0]
	if crypto.Tag != "1" ||
		crypto.Suite != "AES_CM_128_HMAC_SHA1_80" ||
		crypto.KeyParams != testSDPSecurityCryptoInlineKeyParams(t)+"|2^20|1:32" ||
		crypto.SessionParams != "UNENCRYPTED_SRTCP" {
		t.Fatalf("crypto=%+v", crypto)
	}
}

func TestParseSDPSecurityRejectsInvalidCryptoAttributes(t *testing.T) {
	validKey := testSDPSecurityCryptoInlineKeyParams(t)
	tests := []struct {
		name   string
		crypto string
	}{
		{name: "zero tag", crypto: "0 AES_CM_128_HMAC_SHA1_80 " + validKey},
		{name: "nonnumeric tag", crypto: "x AES_CM_128_HMAC_SHA1_80 " + validKey},
		{name: "unsupported suite", crypto: "1 F8_128_HMAC_SHA1_80 " + validKey},
		{name: "unsupported key method", crypto: "1 AES_CM_128_HMAC_SHA1_80 prompt:abc"},
		{name: "short inline key", crypto: "1 AES_CM_128_HMAC_SHA1_80 inline:MTIzNDU2Nzg5MDEyMzQ1Ng=="},
		{name: "bad lifetime", crypto: "1 AES_CM_128_HMAC_SHA1_80 " + validKey + "|never"},
		{name: "bad mki", crypto: "1 AES_CM_128_HMAC_SHA1_80 " + validKey + "|2^20|abc:4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte("v=0\r\n" +
				"c=IN IP4 203.0.113.8\r\n" +
				"m=audio 49170 RTP/SAVP 96\r\n" +
				"a=crypto:" + tt.crypto + "\r\n" +
				"a=rtpmap:96 AMR/8000\r\n")
			_, err := ParseSDPSecurity(raw)
			if !errors.Is(err, ErrInvalidSDPSecurity) {
				t.Fatalf("ParseSDPSecurity() err=%v, want ErrInvalidSDPSecurity", err)
			}
		})
	}
}

func TestParseAndBuildSDPSecurityFingerprintSetup(t *testing.T) {
	raw := []byte("v=0\r\n" +
		"o=user 0 0 IN IP4 203.0.113.8\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.8\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/SAVPF 111 101\r\n" +
		"a=fingerprint:SHA-256 AA:BB:CC:DD:EE:FF\r\n" +
		"a=setup:actpass\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=sendrecv\r\n")
	info, security, err := ParseSDPWithSecurity(raw)
	if err != nil {
		t.Fatalf("ParseSDPWithSecurity() error = %v", err)
	}
	if security.RTPProfile != "RTP/SAVPF" || security.Setup != "actpass" || len(security.Fingerprints) != 1 {
		t.Fatalf("security=%+v", security)
	}
	fingerprint := security.Fingerprints[0]
	if fingerprint.HashFunc != "SHA-256" || fingerprint.Fingerprint != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("fingerprint=%+v", fingerprint)
	}

	answer := string(BuildSDPAnswerWithSecurity(info, security))
	for _, want := range []string{
		"m=audio 49170 RTP/SAVPF 111 101\r\n",
		"a=fingerprint:SHA-256 AA:BB:CC:DD:EE:FF\r\n",
		"a=setup:actpass\r\n",
		"a=rtpmap:101 telephone-event/8000\r\n",
	} {
		if !strings.Contains(answer, want) {
			t.Fatalf("answer missing %q:\n%s", want, answer)
		}
	}
	_, reparsed, err := ParseSDPWithSecurity([]byte(answer))
	if err != nil {
		t.Fatalf("ParseSDPWithSecurity(answer) error = %v", err)
	}
	if reparsed.RTPProfile != "RTP/SAVPF" || reparsed.Setup != "actpass" || len(reparsed.Fingerprints) != 1 {
		t.Fatalf("reparsed security=%+v", reparsed)
	}
}

func TestParseSDPSecurityRejectsInvalidFingerprintAndSetup(t *testing.T) {
	tests := []struct {
		name string
		attr string
	}{
		{name: "unsupported hash", attr: "a=fingerprint:MD5 AA:BB:CC"},
		{name: "non hex octet", attr: "a=fingerprint:SHA-256 AA:GG:CC"},
		{name: "short octet", attr: "a=fingerprint:SHA-256 AA:B:CC"},
		{name: "empty octet", attr: "a=fingerprint:SHA-256 AA::CC"},
		{name: "unsupported setup", attr: "a=setup:sideways"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte("v=0\r\n" +
				"c=IN IP4 203.0.113.8\r\n" +
				"m=audio 49170 RTP/SAVPF 111\r\n" +
				tt.attr + "\r\n" +
				"a=rtpmap:111 AMR/8000\r\n")
			_, err := ParseSDPSecurity(raw)
			if !errors.Is(err, ErrInvalidSDPSecurity) {
				t.Fatalf("ParseSDPSecurity() err=%v, want ErrInvalidSDPSecurity", err)
			}
		})
	}
}

func TestBuildSDPAnswerWithSecurityConstructsCrypto(t *testing.T) {
	keyParams := testSDPSecurityCryptoInlineKeyParams(t)
	security := SDPSecurityInfo{
		RTPProfile: "RTP/SAVP",
		Crypto: []SDPCryptoAttribute{{
			Tag:       "2",
			Suite:     "AES_CM_128_HMAC_SHA1_32",
			KeyParams: keyParams,
		}},
	}
	answer := string(BuildSDPAnswerWithSecurity(SDPInfo{
		ConnectionIP: "192.0.2.2",
		MediaPort:    6000,
		Payloads:     []int{0, 101},
		Direction:    "sendrecv",
	}, security))
	for _, want := range []string{
		"m=audio 6000 RTP/SAVP 0 101\r\n",
		"a=crypto:2 AES_CM_128_HMAC_SHA1_32 " + keyParams + "\r\n",
		"a=sendrecv\r\n",
	} {
		if !strings.Contains(answer, want) {
			t.Fatalf("answer missing %q:\n%s", want, answer)
		}
	}
	_, parsed, err := ParseSDPWithSecurity([]byte(answer))
	if err != nil {
		t.Fatalf("ParseSDPWithSecurity(answer) error = %v", err)
	}
	if parsed.RTPProfile != "RTP/SAVP" || len(parsed.Crypto) != 1 || parsed.Crypto[0].Suite != "AES_CM_128_HMAC_SHA1_32" {
		t.Fatalf("parsed security=%+v", parsed)
	}
}

func TestParseSDPSecurityPreservesRTCPFeedbackMuxRSizeAndUnknownAttributes(t *testing.T) {
	key128 := testSDPSecurityCryptoInlineKeyParamsForProfile(t, SRTPProfileAes128CmHmacSha1_80)
	key256 := testSDPSecurityCryptoInlineKeyParamsForProfile(t, SRTPProfileAes256CmHmacSha1_80)
	raw := []byte("v=0\r\n" +
		"o=user 0 0 IN IP4 203.0.113.8\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.8\r\n" +
		"t=0 0\r\n" +
		"a=fingerprint:SHA-256 AA:BB:CC:DD:EE:FF\r\n" +
		"a=setup:actpass\r\n" +
		"a=rtcp-fb:* nack\r\n" +
		"m=audio 49170 RTP/SAVPF 96 97 110\r\n" +
		"a=rtcp-mux\r\n" +
		"a=rtcp-rsize\r\n" +
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 " + key128 + " UNENCRYPTED_SRTP\r\n" +
		"a=crypto:2 AES_CM_256_HMAC_SHA1_80 " + key256 + "\r\n" +
		"a=rtcp-fb:96 nack pli\r\n" +
		"a=rtcp-fb:97 goog-remb\r\n" +
		"a=rtcp-fb:* trr-int 100\r\n" +
		"a=x-ims-bearer:preserve me\r\n" +
		"a=rtpmap:96 AMR/8000\r\n" +
		"a=rtpmap:97 AMR-WB/16000\r\n" +
		"a=rtpmap:110 telephone-event/16000\r\n")

	info, security, err := ParseSDPWithSecurity(raw)
	if err != nil {
		t.Fatalf("ParseSDPWithSecurity() error = %v", err)
	}
	if security.RTPProfile != "RTP/SAVPF" || len(security.Crypto) != 2 || !security.RTCPMux || !security.RTCPReducedSize {
		t.Fatalf("security=%+v", security)
	}
	if security.Setup != "actpass" || len(security.Fingerprints) != 1 || security.Fingerprints[0].HashFunc != "SHA-256" {
		t.Fatalf("inherited fingerprint/setup=%+v", security)
	}
	if len(security.RTCPFeedback) != 3 || security.RTCPFeedback[0].Payload != "96" || security.RTCPFeedback[0].Parameter != "pli" {
		t.Fatalf("rtcp feedback=%+v", security.RTCPFeedback)
	}
	if len(security.UnknownAttributes) != 1 || security.UnknownAttributes[0] != "a=x-ims-bearer:preserve me" {
		t.Fatalf("unknown attributes=%+v", security.UnknownAttributes)
	}

	answer := string(BuildSDPAnswerWithSecurity(info, security))
	for _, want := range []string{
		"m=audio 49170 RTP/SAVPF 96 97 110\r\n",
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 " + key128 + " UNENCRYPTED_SRTP\r\n",
		"a=crypto:2 AES_CM_256_HMAC_SHA1_80 " + key256 + "\r\n",
		"a=fingerprint:SHA-256 AA:BB:CC:DD:EE:FF\r\n",
		"a=setup:actpass\r\n",
		"a=rtcp-mux\r\n",
		"a=rtcp-rsize\r\n",
		"a=rtcp-fb:96 nack pli\r\n",
		"a=rtcp-fb:97 goog-remb\r\n",
		"a=rtcp-fb:* trr-int 100\r\n",
		"a=x-ims-bearer:preserve me\r\n",
	} {
		if !strings.Contains(answer, want) {
			t.Fatalf("answer missing %q:\n%s", want, answer)
		}
	}
	if strings.Contains(answer, "a=rtcp-fb:* nack\r\n") {
		t.Fatalf("answer used session-level rtcp-fb despite media override:\n%s", answer)
	}
}

func TestApplySDPSecurityRewritesExistingSecurityAndRTCPAttributes(t *testing.T) {
	keyParams := testSDPSecurityCryptoInlineKeyParams(t)
	base := []byte("v=0\r\n" +
		"c=IN IP4 192.0.2.10\r\n" +
		"a=fingerprint:SHA-256 AA:AA:AA\r\n" +
		"a=setup:actpass\r\n" +
		"m=audio 4000 RTP/SAVP 0 101\r\n" +
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 " + keyParams + "\r\n" +
		"a=rtcp-mux\r\n" +
		"a=rtcp-rsize\r\n" +
		"a=rtcp-fb:* nack\r\n" +
		"a=x-ims-bearer:old\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n")
	rewritten := string(applySDPSecurity(base, SDPSecurityInfo{
		RTPProfile: "RTP/SAVPF",
		Crypto: []SDPCryptoAttribute{{
			Tag:       "2",
			Suite:     "AES_CM_128_HMAC_SHA1_80",
			KeyParams: keyParams,
		}},
		Fingerprints: []SDPFingerprintAttribute{{
			HashFunc:    "SHA-256",
			Fingerprint: "BB:BB:BB",
		}},
		Setup:           "passive",
		RTCPMux:         true,
		RTCPReducedSize: true,
		RTCPFeedback: []SDPRTCPFeedbackAttribute{{
			Payload:   "101",
			Type:      "nack",
			Parameter: "pli",
		}},
		UnknownAttributes: []string{"a=x-ims-bearer:new"},
	}))

	for _, want := range []string{
		"m=audio 4000 RTP/SAVPF 0 101\r\n",
		"a=crypto:2 AES_CM_128_HMAC_SHA1_80 " + keyParams + "\r\n",
		"a=fingerprint:SHA-256 BB:BB:BB\r\n",
		"a=setup:passive\r\n",
		"a=rtcp-mux\r\n",
		"a=rtcp-rsize\r\n",
		"a=rtcp-fb:101 nack pli\r\n",
		"a=x-ims-bearer:new\r\n",
		"a=x-ims-bearer:old\r\n",
		"a=rtpmap:0 PCMU/8000\r\n",
	} {
		if !strings.Contains(rewritten, want) {
			t.Fatalf("rewritten missing %q:\n%s", want, rewritten)
		}
	}
	for _, unexpected := range []string{"AA:AA:AA", "a=setup:actpass", "a=rtcp-fb:* nack"} {
		if strings.Contains(rewritten, unexpected) {
			t.Fatalf("rewritten kept %q:\n%s", unexpected, rewritten)
		}
	}
	if strings.Count(rewritten, "a=rtcp-mux\r\n") != 1 || strings.Count(rewritten, "a=rtcp-rsize\r\n") != 1 {
		t.Fatalf("rewritten duplicated mux/rsize:\n%s", rewritten)
	}
}

func testSDPSecurityCryptoInlineKeyParams(t *testing.T) string {
	t.Helper()
	return testSDPSecurityCryptoInlineKeyParamsForProfile(t, SRTPProfileAes128CmHmacSha1_80)
}

func testSDPSecurityCryptoInlineKeyParamsForProfile(t *testing.T, profile SRTPProtectionProfile) string {
	t.Helper()
	srtpProfile, err := srtpProtectionProfile(profile)
	if err != nil {
		t.Fatalf("srtpProtectionProfile() error = %v", err)
	}
	keyLen, err := srtpProfile.KeyLen()
	if err != nil {
		t.Fatalf("KeyLen() error = %v", err)
	}
	saltLen, err := srtpProfile.SaltLen()
	if err != nil {
		t.Fatalf("SaltLen() error = %v", err)
	}
	value, err := BuildSDPCryptoInlineKeyParams(profile, SDPCryptoInlineKeyParams{
		MasterKey:  bytes.Repeat([]byte{0x11}, keyLen),
		MasterSalt: bytes.Repeat([]byte{0x22}, saltLen),
	})
	if err != nil {
		t.Fatalf("BuildSDPCryptoInlineKeyParams() error = %v", err)
	}
	return value
}

func TestSelectSDPSecurityAnswerChoosesFingerprintAndSetup(t *testing.T) {
	offer := SDPSecurityInfo{
		RTPProfile: "RTP/SAVPF",
		Fingerprints: []SDPFingerprintAttribute{{
			HashFunc:    "SHA-256",
			Fingerprint: "AA:BB:CC",
		}},
		Setup: "actpass",
	}
	got, err := SelectSDPSecurityAnswer(offer, SDPSecurityAnswerOptions{
		RTPProfiles: []string{"RTP/SAVPF"},
		Fingerprints: []SDPFingerprintAttribute{{
			HashFunc:    "sha-256",
			Fingerprint: "11:22:33",
		}},
		Setup: "passive",
	})
	if err != nil {
		t.Fatalf("SelectSDPSecurityAnswer() error = %v", err)
	}
	if got.RTPProfile != "RTP/SAVPF" || got.Setup != "passive" || len(got.Fingerprints) != 1 || got.Fingerprints[0].Fingerprint != "11:22:33" {
		t.Fatalf("answer security=%+v", got)
	}
	answer := string(BuildSDPAnswerWithSecurity(SDPInfo{ConnectionIP: "192.0.2.2", MediaPort: 6000, Payloads: []int{111}}, got))
	if !strings.Contains(answer, "a=fingerprint:sha-256 11:22:33\r\n") || !strings.Contains(answer, "a=setup:passive\r\n") || strings.Contains(answer, "AA:BB:CC") {
		t.Fatalf("answer SDP:\n%s", answer)
	}
}

func TestSelectSDPSecurityAnswerChoosesCryptoWithOfferTag(t *testing.T) {
	offer := SDPSecurityInfo{
		RTPProfile: "RTP/SAVP",
		Crypto: []SDPCryptoAttribute{{
			Tag:       "7",
			Suite:     "AES_CM_128_HMAC_SHA1_80",
			KeyParams: "inline:remote",
		}},
		Fingerprints: []SDPFingerprintAttribute{{
			HashFunc:    "SHA-256",
			Fingerprint: "AA:BB:CC",
		}},
		Setup: "actpass",
	}
	got, err := SelectSDPSecurityAnswer(offer, SDPSecurityAnswerOptions{
		RTPProfiles:  []string{"RTP/SAVP"},
		PreferCrypto: true,
		Crypto: []SDPCryptoAttribute{{
			Tag:       "1",
			Suite:     "AES_CM_128_HMAC_SHA1_80",
			KeyParams: "inline:local",
		}},
		Fingerprints: []SDPFingerprintAttribute{{
			HashFunc:    "SHA-256",
			Fingerprint: "11:22:33",
		}},
	})
	if err != nil {
		t.Fatalf("SelectSDPSecurityAnswer() error = %v", err)
	}
	if got.RTPProfile != "RTP/SAVP" || len(got.Crypto) != 1 || got.Crypto[0].Tag != "7" || got.Crypto[0].KeyParams != "inline:local" || len(got.Fingerprints) != 0 {
		t.Fatalf("answer security=%+v", got)
	}
}

func TestSelectSDPSecurityAnswerRejectsUnsupportedSetup(t *testing.T) {
	_, err := SelectSDPSecurityAnswer(SDPSecurityInfo{
		RTPProfile: "RTP/SAVPF",
		Fingerprints: []SDPFingerprintAttribute{{
			HashFunc:    "SHA-256",
			Fingerprint: "AA:BB:CC",
		}},
		Setup: "active",
	}, SDPSecurityAnswerOptions{
		Fingerprints: []SDPFingerprintAttribute{{
			HashFunc:    "SHA-256",
			Fingerprint: "11:22:33",
		}},
		Setup: "active",
	})
	if err == nil {
		t.Fatalf("SelectSDPSecurityAnswer() error = nil, want setup rejection")
	}
}

func TestSelectSDPSecurityAnswerCarriesRTCPAttributesWithoutSecurityFailure(t *testing.T) {
	got, err := SelectSDPSecurityAnswer(SDPSecurityInfo{
		RTPProfile:      "RTP/AVP",
		RTCPMux:         true,
		RTCPReducedSize: true,
		RTCPFeedback: []SDPRTCPFeedbackAttribute{{
			Payload:   "*",
			Type:      "nack",
			Parameter: "pli",
		}},
		UnknownAttributes: []string{"a=x-ims-bearer:preserve"},
	}, SDPSecurityAnswerOptions{RTPProfiles: []string{"RTP/AVP"}})
	if err != nil {
		t.Fatalf("SelectSDPSecurityAnswer() error = %v", err)
	}
	if got.RTPProfile != "RTP/AVP" || !got.RTCPMux || !got.RTCPReducedSize || len(got.RTCPFeedback) != 1 || len(got.UnknownAttributes) != 1 {
		t.Fatalf("answer security=%+v", got)
	}
	answer := string(BuildSDPAnswerWithSecurity(SDPInfo{ConnectionIP: "192.0.2.2", MediaPort: 6000, Payloads: []int{0}}, got))
	for _, want := range []string{
		"a=rtcp-mux\r\n",
		"a=rtcp-rsize\r\n",
		"a=rtcp-fb:* nack pli\r\n",
		"a=x-ims-bearer:preserve\r\n",
	} {
		if !strings.Contains(answer, want) {
			t.Fatalf("answer missing %q:\n%s", want, answer)
		}
	}
}
