package voicehost

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/pion/srtp/v3"
)

var ErrSRTPMediaConfig = errors.New("invalid srtp media config")

type SRTPProtectionProfile string

const (
	SRTPProfileAes128CmHmacSha1_80 SRTPProtectionProfile = "AES_CM_128_HMAC_SHA1_80"
	SRTPProfileAes128CmHmacSha1_32 SRTPProtectionProfile = "AES_CM_128_HMAC_SHA1_32"
	SRTPProfileAes256CmHmacSha1_80 SRTPProtectionProfile = "AES_CM_256_HMAC_SHA1_80"
	SRTPProfileAes256CmHmacSha1_32 SRTPProtectionProfile = "AES_CM_256_HMAC_SHA1_32"
	SRTPProfileAeadAes128Gcm       SRTPProtectionProfile = "AEAD_AES_128_GCM"
	SRTPProfileAeadAes256Gcm       SRTPProtectionProfile = "AEAD_AES_256_GCM"
)

type SRTPKeys struct {
	MasterKey  []byte
	MasterSalt []byte
}

type SDPCryptoInlineKeyParams struct {
	MasterKey  []byte
	MasterSalt []byte
	Lifetime   string
	MKIValue   string
	MKILength  int
}

type SRTPMediaConfig struct {
	Profile               SRTPProtectionProfile
	ClientKeys            SRTPKeys
	IMSKeys               SRTPKeys
	ReplayWindowSize      uint
	RTCPFeedbackHandler   RTCPFeedbackHandler
	RTPDTMFHandler        RTPDTMFHandler
	RTPPlaintextHandler   RTPPlaintextHandler
	ClientRTPDTMFPayloads map[uint8]int
	IMSRTPDTMFPayloads    map[uint8]int
}

type RTPPlaintextHandler func(RTPPlaintextEvent)

type RTPPlaintextEvent struct {
	Direction RTPDTMFDirection
	Packet    []byte
}

type SRTPMediaSession struct {
	mu sync.Mutex

	clientProtect         *srtp.Context
	clientUnprotect       *srtp.Context
	imsProtect            *srtp.Context
	imsUnprotect          *srtp.Context
	rtcpFeedbackHandler   RTCPFeedbackHandler
	rtpDTMFHandler        RTPDTMFHandler
	rtpPlaintextHandler   RTPPlaintextHandler
	clientRTPDTMFPayloads map[uint8]int
	imsRTPDTMFPayloads    map[uint8]int
}

func (p SRTPProtectionProfile) SDPCryptoSuite() string {
	switch SRTPProtectionProfile(strings.ToUpper(strings.TrimSpace(string(p)))) {
	case "", SRTPProfileAes128CmHmacSha1_80:
		return string(SRTPProfileAes128CmHmacSha1_80)
	case SRTPProfileAes128CmHmacSha1_32:
		return string(SRTPProfileAes128CmHmacSha1_32)
	case SRTPProfileAes256CmHmacSha1_80:
		return string(SRTPProfileAes256CmHmacSha1_80)
	case SRTPProfileAes256CmHmacSha1_32:
		return string(SRTPProfileAes256CmHmacSha1_32)
	case SRTPProfileAeadAes128Gcm:
		return string(SRTPProfileAeadAes128Gcm)
	case SRTPProfileAeadAes256Gcm:
		return string(SRTPProfileAeadAes256Gcm)
	default:
		return ""
	}
}

func SRTPProtectionProfileFromSDPCryptoSuite(suite string) (SRTPProtectionProfile, error) {
	switch strings.ToUpper(strings.TrimSpace(suite)) {
	case string(SRTPProfileAes128CmHmacSha1_80):
		return SRTPProfileAes128CmHmacSha1_80, nil
	case string(SRTPProfileAes128CmHmacSha1_32):
		return SRTPProfileAes128CmHmacSha1_32, nil
	case string(SRTPProfileAes256CmHmacSha1_80):
		return SRTPProfileAes256CmHmacSha1_80, nil
	case string(SRTPProfileAes256CmHmacSha1_32):
		return SRTPProfileAes256CmHmacSha1_32, nil
	case string(SRTPProfileAeadAes128Gcm):
		return SRTPProfileAeadAes128Gcm, nil
	case string(SRTPProfileAeadAes256Gcm):
		return SRTPProfileAeadAes256Gcm, nil
	default:
		return "", fmt.Errorf("%w: unsupported SDP crypto suite %q", ErrSRTPMediaConfig, suite)
	}
}

func ParseSDPCryptoInlineKeyParams(profile SRTPProtectionProfile, keyParams string) (SDPCryptoInlineKeyParams, error) {
	srtpProfile, err := srtpProtectionProfile(profile)
	if err != nil {
		return SDPCryptoInlineKeyParams{}, err
	}
	keyLen, err := srtpProfile.KeyLen()
	if err != nil {
		return SDPCryptoInlineKeyParams{}, fmt.Errorf("%w: key length: %v", ErrSRTPMediaConfig, err)
	}
	saltLen, err := srtpProfile.SaltLen()
	if err != nil {
		return SDPCryptoInlineKeyParams{}, fmt.Errorf("%w: salt length: %v", ErrSRTPMediaConfig, err)
	}
	keyParams = strings.TrimSpace(keyParams)
	if !strings.HasPrefix(strings.ToLower(keyParams), "inline:") {
		return SDPCryptoInlineKeyParams{}, fmt.Errorf("%w: unsupported SDP crypto key method", ErrSRTPMediaConfig)
	}
	parts := strings.Split(keyParams[len("inline:"):], "|")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return SDPCryptoInlineKeyParams{}, fmt.Errorf("%w: empty SDP crypto inline key", ErrSRTPMediaConfig)
	}
	raw, err := decodeSDPInlineKey(strings.TrimSpace(parts[0]))
	if err != nil {
		return SDPCryptoInlineKeyParams{}, err
	}
	if len(raw) != keyLen+saltLen {
		return SDPCryptoInlineKeyParams{}, fmt.Errorf("%w: SDP crypto inline key/salt length %d != %d", ErrSRTPMediaConfig, len(raw), keyLen+saltLen)
	}
	out := SDPCryptoInlineKeyParams{
		MasterKey:  append([]byte(nil), raw[:keyLen]...),
		MasterSalt: append([]byte(nil), raw[keyLen:]...),
	}
	if len(parts) >= 2 {
		lifetime := strings.TrimSpace(parts[1])
		if lifetime != "" && !validSDPCryptoLifetime(lifetime) {
			return SDPCryptoInlineKeyParams{}, fmt.Errorf("%w: malformed SDP crypto lifetime", ErrSRTPMediaConfig)
		}
		out.Lifetime = lifetime
	}
	if len(parts) >= 3 {
		value, length, ok := strings.Cut(strings.TrimSpace(parts[2]), ":")
		if !ok || strings.TrimSpace(value) == "" || strings.TrimSpace(length) == "" {
			return SDPCryptoInlineKeyParams{}, fmt.Errorf("%w: malformed SDP crypto MKI", ErrSRTPMediaConfig)
		}
		if !validSDPCryptoDecimal(strings.TrimSpace(value), false) {
			return SDPCryptoInlineKeyParams{}, fmt.Errorf("%w: malformed SDP crypto MKI value", ErrSRTPMediaConfig)
		}
		mkiLength, err := strconv.Atoi(strings.TrimSpace(length))
		if err != nil || mkiLength <= 0 {
			return SDPCryptoInlineKeyParams{}, fmt.Errorf("%w: malformed SDP crypto MKI length", ErrSRTPMediaConfig)
		}
		out.MKIValue = strings.TrimSpace(value)
		out.MKILength = mkiLength
	}
	if len(parts) > 3 {
		return SDPCryptoInlineKeyParams{}, fmt.Errorf("%w: unsupported SDP crypto inline key params", ErrSRTPMediaConfig)
	}
	return out, nil
}

func ValidateSDPCryptoAttribute(attr SDPCryptoAttribute) error {
	if err := validateSDPCryptoTag(attr.Tag); err != nil {
		return err
	}
	_, _, err := ParseSDPCryptoAttributeKeys(attr)
	return err
}

func BuildSDPCryptoInlineKeyParams(profile SRTPProtectionProfile, params SDPCryptoInlineKeyParams) (string, error) {
	srtpProfile, err := srtpProtectionProfile(profile)
	if err != nil {
		return "", err
	}
	keys := SRTPKeys{
		MasterKey:  append([]byte(nil), params.MasterKey...),
		MasterSalt: append([]byte(nil), params.MasterSalt...),
	}
	if err := validateSRTPKeys(srtpProfile, keys, "SDP crypto"); err != nil {
		return "", err
	}
	raw := make([]byte, 0, len(params.MasterKey)+len(params.MasterSalt))
	raw = append(raw, params.MasterKey...)
	raw = append(raw, params.MasterSalt...)
	value := "inline:" + base64.StdEncoding.EncodeToString(raw)
	if lifetime := strings.TrimSpace(params.Lifetime); lifetime != "" || strings.TrimSpace(params.MKIValue) != "" || params.MKILength > 0 {
		value += "|" + lifetime
	}
	if strings.TrimSpace(params.MKIValue) != "" || params.MKILength > 0 {
		if strings.TrimSpace(params.MKIValue) == "" || params.MKILength <= 0 {
			return "", fmt.Errorf("%w: incomplete SDP crypto MKI", ErrSRTPMediaConfig)
		}
		value += "|" + strings.TrimSpace(params.MKIValue) + ":" + strconv.Itoa(params.MKILength)
	}
	return value, nil
}

func ParseSDPCryptoAttributeKeys(attr SDPCryptoAttribute) (SRTPProtectionProfile, SDPCryptoInlineKeyParams, error) {
	profile, err := SRTPProtectionProfileFromSDPCryptoSuite(attr.Suite)
	if err != nil {
		return "", SDPCryptoInlineKeyParams{}, err
	}
	params, err := ParseSDPCryptoInlineKeyParams(profile, attr.KeyParams)
	if err != nil {
		return "", SDPCryptoInlineKeyParams{}, err
	}
	return profile, params, nil
}

func SelectSDPCryptoAttribute(crypto []SDPCryptoAttribute, preferred []SRTPProtectionProfile) (SDPCryptoAttribute, SRTPProtectionProfile, SDPCryptoInlineKeyParams, bool, error) {
	if len(crypto) == 0 {
		return SDPCryptoAttribute{}, "", SDPCryptoInlineKeyParams{}, false, nil
	}
	var firstErr error
	if len(preferred) == 0 {
		for _, attr := range crypto {
			profile, params, err := ParseSDPCryptoAttributeKeys(attr)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			return trimSDPCryptoAttribute(attr), profile, params, true, nil
		}
		if firstErr != nil {
			return SDPCryptoAttribute{}, "", SDPCryptoInlineKeyParams{}, false, firstErr
		}
		return SDPCryptoAttribute{}, "", SDPCryptoInlineKeyParams{}, false, nil
	}
	for _, want := range preferred {
		wantSuite := want.SDPCryptoSuite()
		if wantSuite == "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("%w: unsupported SDP crypto suite %q", ErrSRTPMediaConfig, want)
			}
			continue
		}
		for _, attr := range crypto {
			if !strings.EqualFold(strings.TrimSpace(attr.Suite), wantSuite) {
				continue
			}
			profile, params, err := ParseSDPCryptoAttributeKeys(attr)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			return trimSDPCryptoAttribute(attr), profile, params, true, nil
		}
	}
	if firstErr != nil {
		return SDPCryptoAttribute{}, "", SDPCryptoInlineKeyParams{}, false, firstErr
	}
	return SDPCryptoAttribute{}, "", SDPCryptoInlineKeyParams{}, false, nil
}

func BuildSDPCryptoAttribute(tag string, profile SRTPProtectionProfile, params SDPCryptoInlineKeyParams, sessionParams string) (SDPCryptoAttribute, error) {
	tag = strings.TrimSpace(tag)
	if err := validateSDPCryptoTag(tag); err != nil {
		return SDPCryptoAttribute{}, err
	}
	suite := profile.SDPCryptoSuite()
	if suite == "" {
		return SDPCryptoAttribute{}, fmt.Errorf("%w: unsupported SDP crypto suite %q", ErrSRTPMediaConfig, profile)
	}
	keyParams, err := BuildSDPCryptoInlineKeyParams(profile, params)
	if err != nil {
		return SDPCryptoAttribute{}, err
	}
	return SDPCryptoAttribute{
		Tag:           tag,
		Suite:         suite,
		KeyParams:     keyParams,
		SessionParams: strings.TrimSpace(sessionParams),
	}, nil
}

func trimSDPCryptoAttribute(attr SDPCryptoAttribute) SDPCryptoAttribute {
	return SDPCryptoAttribute{
		Tag:           strings.TrimSpace(attr.Tag),
		Suite:         strings.TrimSpace(attr.Suite),
		KeyParams:     strings.TrimSpace(attr.KeyParams),
		SessionParams: strings.TrimSpace(attr.SessionParams),
	}
}

func NewSRTPMediaSession(cfg SRTPMediaConfig) (*SRTPMediaSession, error) {
	profile, err := srtpProtectionProfile(cfg.Profile)
	if err != nil {
		return nil, err
	}
	if err := validateSRTPKeys(profile, cfg.ClientKeys, "client"); err != nil {
		return nil, err
	}
	if err := validateSRTPKeys(profile, cfg.IMSKeys, "ims"); err != nil {
		return nil, err
	}
	window := cfg.ReplayWindowSize
	if window == 0 {
		window = 64
	}
	clientProtect, err := srtp.CreateContext(cfg.ClientKeys.MasterKey, cfg.ClientKeys.MasterSalt, profile)
	if err != nil {
		return nil, fmt.Errorf("%w: client protect: %v", ErrSRTPMediaConfig, err)
	}
	clientUnprotect, err := srtp.CreateContext(cfg.ClientKeys.MasterKey, cfg.ClientKeys.MasterSalt, profile, srtp.SRTPReplayProtection(window), srtp.SRTCPReplayProtection(window))
	if err != nil {
		return nil, fmt.Errorf("%w: client unprotect: %v", ErrSRTPMediaConfig, err)
	}
	imsProtect, err := srtp.CreateContext(cfg.IMSKeys.MasterKey, cfg.IMSKeys.MasterSalt, profile)
	if err != nil {
		return nil, fmt.Errorf("%w: ims protect: %v", ErrSRTPMediaConfig, err)
	}
	imsUnprotect, err := srtp.CreateContext(cfg.IMSKeys.MasterKey, cfg.IMSKeys.MasterSalt, profile, srtp.SRTPReplayProtection(window), srtp.SRTCPReplayProtection(window))
	if err != nil {
		return nil, fmt.Errorf("%w: ims unprotect: %v", ErrSRTPMediaConfig, err)
	}
	return &SRTPMediaSession{
		clientProtect:         clientProtect,
		clientUnprotect:       clientUnprotect,
		imsProtect:            imsProtect,
		imsUnprotect:          imsUnprotect,
		rtcpFeedbackHandler:   cfg.RTCPFeedbackHandler,
		rtpDTMFHandler:        cfg.RTPDTMFHandler,
		rtpPlaintextHandler:   cfg.RTPPlaintextHandler,
		clientRTPDTMFPayloads: cloneRTPDTMFPayloadTypes(cfg.ClientRTPDTMFPayloads),
		imsRTPDTMFPayloads:    cloneRTPDTMFPayloadTypes(cfg.IMSRTPDTMFPayloads),
	}, nil
}

func (s *SRTPMediaSession) ProtectClientRTP(packet []byte) ([]byte, error) {
	if s == nil || s.clientProtect == nil {
		return nil, ErrSRTPMediaConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clientProtect.EncryptRTP(nil, packet, nil)
}

func (s *SRTPMediaSession) UnprotectClientRTP(packet []byte) ([]byte, error) {
	if s == nil || s.clientUnprotect == nil {
		return nil, ErrSRTPMediaConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clientUnprotect.DecryptRTP(nil, packet, nil)
}

func (s *SRTPMediaSession) ProtectIMSRTP(packet []byte) ([]byte, error) {
	if s == nil || s.imsProtect == nil {
		return nil, ErrSRTPMediaConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.imsProtect.EncryptRTP(nil, packet, nil)
}

func (s *SRTPMediaSession) UnprotectIMSRTP(packet []byte) ([]byte, error) {
	if s == nil || s.imsUnprotect == nil {
		return nil, ErrSRTPMediaConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.imsUnprotect.DecryptRTP(nil, packet, nil)
}

func (s *SRTPMediaSession) ProtectClientRTCP(packet []byte) ([]byte, error) {
	if s == nil || s.clientProtect == nil {
		return nil, ErrSRTPMediaConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clientProtect.EncryptRTCP(nil, packet, nil)
}

func (s *SRTPMediaSession) UnprotectClientRTCP(packet []byte) ([]byte, error) {
	if s == nil || s.clientUnprotect == nil {
		return nil, ErrSRTPMediaConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clientUnprotect.DecryptRTCP(nil, packet, nil)
}

func (s *SRTPMediaSession) ProtectIMSRTCP(packet []byte) ([]byte, error) {
	if s == nil || s.imsProtect == nil {
		return nil, ErrSRTPMediaConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.imsProtect.EncryptRTCP(nil, packet, nil)
}

func (s *SRTPMediaSession) UnprotectIMSRTCP(packet []byte) ([]byte, error) {
	if s == nil || s.imsUnprotect == nil {
		return nil, ErrSRTPMediaConfig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.imsUnprotect.DecryptRTCP(nil, packet, nil)
}

func (s *SRTPMediaSession) RelayTransforms() RTPRelayTransforms {
	if s == nil {
		return RTPRelayTransforms{}
	}
	return s.RelayTransformsWithRTCPFeedback(s.rtcpFeedbackHandler)
}

func (s *SRTPMediaSession) RelayTransformsWithRTCPFeedback(handler RTCPFeedbackHandler) RTPRelayTransforms {
	if s == nil {
		return RTPRelayTransforms{}
	}
	return s.RelayTransformsWithMediaEvents(handler, s.rtpDTMFHandler, s.clientRTPDTMFPayloads, s.imsRTPDTMFPayloads)
}

func (s *SRTPMediaSession) RelayTransformsWithMediaEvents(rtcpHandler RTCPFeedbackHandler, dtmfHandler RTPDTMFHandler, clientRTPDTMFPayloads, imsRTPDTMFPayloads map[uint8]int) RTPRelayTransforms {
	return s.RelayTransformsWithMediaObservers(rtcpHandler, dtmfHandler, s.rtpPlaintextHandler, clientRTPDTMFPayloads, imsRTPDTMFPayloads)
}

func (s *SRTPMediaSession) RelayTransformsWithMediaObservers(rtcpHandler RTCPFeedbackHandler, dtmfHandler RTPDTMFHandler, rtpHandler RTPPlaintextHandler, clientRTPDTMFPayloads, imsRTPDTMFPayloads map[uint8]int) RTPRelayTransforms {
	if s == nil {
		return RTPRelayTransforms{}
	}
	clientPayloads := cloneRTPDTMFPayloadTypes(clientRTPDTMFPayloads)
	imsPayloads := cloneRTPDTMFPayloadTypes(imsRTPDTMFPayloads)
	return RTPRelayTransforms{
		ClientToIMSRTP: func(packet []byte) ([]byte, error) {
			return s.clientToIMSRTP(packet, dtmfHandler, rtpHandler, clientPayloads, imsPayloads)
		},
		IMSToClientRTP: func(packet []byte) ([]byte, error) {
			return s.imsToClientRTP(packet, dtmfHandler, rtpHandler, imsPayloads, clientPayloads)
		},
		ClientToIMSRTCP: func(packet []byte) ([]byte, error) {
			return s.clientToIMSRTCP(packet, rtcpHandler)
		},
		IMSToClientRTCP: func(packet []byte) ([]byte, error) {
			return s.imsToClientRTCP(packet, rtcpHandler)
		},
		GeneratedToIMSRTP: func(packet []byte) ([]byte, error) {
			return s.ProtectIMSRTP(packet)
		},
		GeneratedToClientRTP: func(packet []byte) ([]byte, error) {
			return s.ProtectClientRTP(packet)
		},
		GeneratedToIMSRTCP: func(packet []byte) ([]byte, error) {
			return s.ProtectIMSRTCP(packet)
		},
		GeneratedToClientRTCP: func(packet []byte) ([]byte, error) {
			return s.ProtectClientRTCP(packet)
		},
	}
}

func (s *SRTPMediaSession) ClientToIMSRTP(packet []byte) ([]byte, error) {
	if s == nil {
		return nil, ErrSRTPMediaConfig
	}
	return s.clientToIMSRTP(packet, s.rtpDTMFHandler, s.rtpPlaintextHandler, s.clientRTPDTMFPayloads, s.imsRTPDTMFPayloads)
}

func (s *SRTPMediaSession) clientToIMSRTP(packet []byte, dtmfHandler RTPDTMFHandler, rtpHandler RTPPlaintextHandler, payloads, targetPayloads map[uint8]int) ([]byte, error) {
	plain, err := s.UnprotectClientRTP(packet)
	if err != nil {
		return nil, err
	}
	emitRTPPlaintext(rtpHandler, RTPDTMFClientToIMS, plain)
	plain = rewriteSRTPRTPDTMF(RTPDTMFClientToIMS, plain, payloads, targetPayloads, dtmfHandler)
	return s.ProtectIMSRTP(plain)
}

func (s *SRTPMediaSession) IMSToClientRTP(packet []byte) ([]byte, error) {
	if s == nil {
		return nil, ErrSRTPMediaConfig
	}
	return s.imsToClientRTP(packet, s.rtpDTMFHandler, s.rtpPlaintextHandler, s.imsRTPDTMFPayloads, s.clientRTPDTMFPayloads)
}

func (s *SRTPMediaSession) imsToClientRTP(packet []byte, dtmfHandler RTPDTMFHandler, rtpHandler RTPPlaintextHandler, payloads, targetPayloads map[uint8]int) ([]byte, error) {
	plain, err := s.UnprotectIMSRTP(packet)
	if err != nil {
		return nil, err
	}
	emitRTPPlaintext(rtpHandler, RTPDTMFIMSToClient, plain)
	plain = rewriteSRTPRTPDTMF(RTPDTMFIMSToClient, plain, payloads, targetPayloads, dtmfHandler)
	return s.ProtectClientRTP(plain)
}

func emitRTPPlaintext(handler RTPPlaintextHandler, direction RTPDTMFDirection, packet []byte) {
	if handler == nil {
		return
	}
	handler(RTPPlaintextEvent{
		Direction: direction,
		Packet:    append([]byte(nil), packet...),
	})
}

func rewriteSRTPRTPDTMF(direction RTPDTMFDirection, packet []byte, sourcePayloads, targetPayloads map[uint8]int, handler RTPDTMFHandler) []byte {
	_, _ = InspectRTPDTMF(direction, packet, sourcePayloads, handler)
	rewritten, remapped, err := RewriteRTPDTMFPayloadType(packet, sourcePayloads, targetPayloads)
	if err != nil || !remapped {
		return packet
	}
	return rewritten
}

func (s *SRTPMediaSession) ClientToIMSRTCP(packet []byte) ([]byte, error) {
	return s.clientToIMSRTCP(packet, s.rtcpFeedbackHandler)
}

func (s *SRTPMediaSession) clientToIMSRTCP(packet []byte, handler RTCPFeedbackHandler) ([]byte, error) {
	plain, err := s.UnprotectClientRTCP(packet)
	if err != nil {
		return nil, err
	}
	_, _ = InspectRTCPFeedback(RTCPFeedbackClientToIMS, plain, handler)
	return s.ProtectIMSRTCP(plain)
}

func (s *SRTPMediaSession) IMSToClientRTCP(packet []byte) ([]byte, error) {
	return s.imsToClientRTCP(packet, s.rtcpFeedbackHandler)
}

func (s *SRTPMediaSession) imsToClientRTCP(packet []byte, handler RTCPFeedbackHandler) ([]byte, error) {
	plain, err := s.UnprotectIMSRTCP(packet)
	if err != nil {
		return nil, err
	}
	_, _ = InspectRTCPFeedback(RTCPFeedbackIMSToClient, plain, handler)
	return s.ProtectClientRTCP(plain)
}

func srtpProtectionProfile(profile SRTPProtectionProfile) (srtp.ProtectionProfile, error) {
	switch SRTPProtectionProfile(strings.ToUpper(strings.TrimSpace(string(profile)))) {
	case "", SRTPProfileAes128CmHmacSha1_80:
		return srtp.ProtectionProfileAes128CmHmacSha1_80, nil
	case SRTPProfileAes128CmHmacSha1_32:
		return srtp.ProtectionProfileAes128CmHmacSha1_32, nil
	case SRTPProfileAes256CmHmacSha1_80:
		return srtp.ProtectionProfileAes256CmHmacSha1_80, nil
	case SRTPProfileAes256CmHmacSha1_32:
		return srtp.ProtectionProfileAes256CmHmacSha1_32, nil
	case SRTPProfileAeadAes128Gcm:
		return srtp.ProtectionProfileAeadAes128Gcm, nil
	case SRTPProfileAeadAes256Gcm:
		return srtp.ProtectionProfileAeadAes256Gcm, nil
	default:
		return 0, fmt.Errorf("%w: unsupported profile %q", ErrSRTPMediaConfig, profile)
	}
}

func validateSRTPKeys(profile srtp.ProtectionProfile, keys SRTPKeys, label string) error {
	keyLen, err := profile.KeyLen()
	if err != nil {
		return fmt.Errorf("%w: %s key length: %v", ErrSRTPMediaConfig, label, err)
	}
	saltLen, err := profile.SaltLen()
	if err != nil {
		return fmt.Errorf("%w: %s salt length: %v", ErrSRTPMediaConfig, label, err)
	}
	if len(keys.MasterKey) != keyLen {
		return fmt.Errorf("%w: %s master key length %d != %d", ErrSRTPMediaConfig, label, len(keys.MasterKey), keyLen)
	}
	if len(keys.MasterSalt) != saltLen {
		return fmt.Errorf("%w: %s master salt length %d != %d", ErrSRTPMediaConfig, label, len(keys.MasterSalt), saltLen)
	}
	return nil
}

func validateSDPCryptoTag(tag string) error {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return fmt.Errorf("%w: SDP crypto tag is empty", ErrSRTPMediaConfig)
	}
	if !validSDPCryptoDecimal(tag, true) {
		return fmt.Errorf("%w: malformed SDP crypto tag", ErrSRTPMediaConfig)
	}
	value, err := strconv.ParseInt(tag, 10, 32)
	if err != nil || value <= 0 {
		return fmt.Errorf("%w: SDP crypto tag out of range", ErrSRTPMediaConfig)
	}
	return nil
}

func validSDPCryptoLifetime(value string) bool {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "2^") {
		return validSDPCryptoDecimal(strings.TrimPrefix(value, "2^"), true)
	}
	return validSDPCryptoDecimal(value, true)
}

func validSDPCryptoDecimal(value string, positive bool) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	if !positive {
		return true
	}
	for _, ch := range value {
		if ch != '0' {
			return true
		}
	}
	return false
}

func decodeSDPInlineKey(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return raw, nil
	}
	raw, rawErr := base64.RawStdEncoding.DecodeString(value)
	if rawErr == nil {
		return raw, nil
	}
	return nil, fmt.Errorf("%w: malformed SDP crypto inline key: %v", ErrSRTPMediaConfig, err)
}
