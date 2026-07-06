package ikev2

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/boa-z/vowifi-go/engine/sim"
	"github.com/boa-z/vowifi-go/engine/swu/eapaka"
)

var (
	ErrInvalidAuthConfig   = errors.New("invalid ikev2 auth config")
	ErrInvalidAuthResponse = errors.New("invalid ikev2 auth response")
)

const (
	maxAKAControlFollowups  = 3
	maxFullAuthEAPExchanges = 8
)

type AuthConfig struct {
	Transport         InitTransport
	Init              InitResult
	Keys              IKEKeys
	InitiatorID       Identity
	EAPIdentity       string
	EAPPseudonym      string
	EAPReauthIdentity string
	ChildSA           SecurityAssociation
	ChildSPI          []byte
	TSi               TrafficSelectors
	TSr               TrafficSelectors
	Configuration     Configuration
	Random            io.Reader
	InitialIV         []byte
	EAPIdentityIV     []byte
	InitialMessageID  uint32
}

type AuthResult struct {
	InitialRequestBytes   []byte
	InitialResponseBytes  []byte
	IdentityRequestBytes  []byte
	IdentityResponseBytes []byte
	InitialResponseInner  []Payload
	IdentityResponseInner []Payload
	EAPRequest            *eapaka.Packet
	EAPAfterIdentity      *eapaka.Packet
	EAPIdentityUsed       string
	IdentityTranscript    [][]byte
	NextMessageID         uint32
}

type AKAChallengeConfig struct {
	Transport          InitTransport
	Init               InitResult
	Keys               IKEKeys
	SIM                sim.AKAProvider
	EAPKeys            eapaka.Keys
	Identity           string
	Request            eapaka.Packet
	IdentityTranscript [][]byte
	ChildSPI           []byte
	TSi                TrafficSelectors
	TSr                TrafficSelectors
	MessageID          uint32
	Random             io.Reader
	IV                 []byte
	EAPReauthIV        []byte
	EAPReauthCounter   uint16
	EAPReauthCounterOK bool
}

type AKAChallengeResult struct {
	RequestBytes             []byte
	ResponseBytes            []byte
	ResponseInner            []Payload
	EAPResponse              eapaka.Packet
	EAPNext                  *eapaka.Packet
	EAPKeys                  eapaka.Keys
	EAPEncryptedAttributes   []eapaka.Attribute
	EAPNextPseudonym         string
	EAPNextReauthID          string
	EAPReauthenticated       bool
	EAPReauthCounter         uint16
	EAPReauthCounterTooSmall bool
	EAPNotifications         []eapaka.Packet
	EAPClientError           bool
	ChildSA                  *ChildSAResult
	SyncFailure              bool
	AuthFailure              bool
	KDFNegotiated            bool
	NextMessageID            uint32
	FollowupRequestBytes     [][]byte
	FollowupResponseBytes    [][]byte
	FinalResponseBytes       []byte
	FinalResponseInner       []Payload
}

type FullAuthConfig struct {
	Transport          InitTransport
	Init               InitResult
	Keys               IKEKeys
	SIM                sim.AKAProvider
	EAPKeys            eapaka.Keys
	InitiatorID        Identity
	EAPIdentity        string
	EAPPseudonym       string
	EAPReauthIdentity  string
	EAPReauthCounter   uint16
	EAPReauthCounterOK bool
	ChildSA            SecurityAssociation
	ChildSPI           []byte
	TSi                TrafficSelectors
	TSr                TrafficSelectors
	Configuration      Configuration
	Random             io.Reader
	InitialIV          []byte
	EAPIdentityIV      []byte
	EAPReauthIV        []byte
	InitialMessageID   uint32
}

type FullAuthResult struct {
	Auth                     AuthResult
	IdentityExchanges        []EAPIdentityExchange
	AKAChallenges            []AKAChallengeResult
	ChildSA                  *ChildSAResult
	EAPKeys                  eapaka.Keys
	EAPLast                  *eapaka.Packet
	EAPNotifications         []eapaka.Packet
	EAPClientError           bool
	EAPNextPseudonym         string
	EAPNextReauthID          string
	EAPReauthenticated       bool
	EAPReauthCounter         uint16
	EAPReauthCounterTooSmall bool
	SyncFailure              bool
	AuthFailure              bool
	KDFNegotiations          int
	NextMessageID            uint32
	FinalResponseBytes       []byte
	FinalResponseInner       []Payload
}

type EAPIdentityExchange struct {
	Request       eapaka.Packet
	Response      eapaka.Packet
	Identity      string
	RequestBytes  []byte
	ResponseBytes []byte
	ResponseInner []Payload
	EAPNext       *eapaka.Packet
	Transcript    [][]byte
	NextMessageID uint32
}

func RunIKE_AUTH_EAPIdentity(ctx context.Context, cfg AuthConfig) (AuthResult, error) {
	if cfg.Transport == nil {
		return AuthResult{}, fmt.Errorf("%w: transport is nil", ErrInvalidAuthConfig)
	}
	keys := cfg.Keys
	if keys.Profile.RequiredLength() == 0 {
		keys = cfg.Init.Keys
	}
	if err := validateKeySet(keys); err != nil {
		return AuthResult{}, err
	}
	spiI, spiR := cfg.Init.InitiatorSPI, cfg.Init.ResponderSPI
	if spiI == 0 || spiR == 0 {
		return AuthResult{}, fmt.Errorf("%w: missing IKE SPIs", ErrInvalidAuthConfig)
	}
	messageID := cfg.InitialMessageID
	if messageID == 0 {
		messageID = 1
	}
	initialInner, err := BuildIKEAuthInitialPayloads(cfg)
	if err != nil {
		return AuthResult{}, err
	}
	initialIV, err := authIV(cfg.Random, keys.Profile, cfg.InitialIV)
	if err != nil {
		return AuthResult{}, err
	}
	_, initialReqBytes, err := ProtectMessage(authHeader(cfg.Init, messageID, true), keys, true, initialInner, initialIV)
	if err != nil {
		return AuthResult{}, err
	}
	initialRespBytes, err := cfg.Transport.ExchangeIKE(ctx, initialReqBytes)
	if err != nil {
		return AuthResult{}, err
	}
	initialResp, initialInnerResp, err := unprotectAuthResponse(initialRespBytes, cfg.Init, keys, messageID)
	if err != nil {
		return AuthResult{}, err
	}
	eapReq, eapReqRaw, hasEAP, err := firstEAPPacketWithRaw(initialInnerResp)
	if err != nil {
		return AuthResult{}, err
	}
	out := AuthResult{
		InitialRequestBytes:  append([]byte(nil), initialReqBytes...),
		InitialResponseBytes: append([]byte(nil), initialRespBytes...),
		InitialResponseInner: clonePayloads(initialInnerResp),
		NextMessageID:        messageID + 1,
	}
	_ = initialResp
	if !hasEAP {
		return out, nil
	}
	out.EAPRequest = &eapReq
	if eapReq.Code != eapaka.CodeRequest || eapReq.Subtype != eapaka.SubtypeIdentity {
		return out, nil
	}
	permanentIdentity := authPermanentIdentity(cfg.EAPIdentity, cfg.InitiatorID)
	identity := identityForEAPRequest(eapReq, eapIdentityOptions{
		PermanentIdentity: permanentIdentity,
		Pseudonym:         cfg.EAPPseudonym,
		ReauthIdentity:    cfg.EAPReauthIdentity,
	})
	if identity == "" {
		return AuthResult{}, fmt.Errorf("%w: eap identity is empty", ErrInvalidAuthConfig)
	}
	identityResponse, err := eapaka.BuildIdentityResponse(identity, eapReq)
	if err != nil {
		return AuthResult{}, err
	}
	identityPacket, err := identityResponse.MarshalBinary()
	if err != nil {
		return AuthResult{}, err
	}
	identityIV, err := authIV(cfg.Random, keys.Profile, cfg.EAPIdentityIV)
	if err != nil {
		return AuthResult{}, err
	}
	_, identityReqBytes, err := ProtectMessage(authHeader(cfg.Init, messageID+1, true), keys, true, []Payload{EAPPayload(identityPacket)}, identityIV)
	if err != nil {
		return AuthResult{}, err
	}
	identityRespBytes, err := cfg.Transport.ExchangeIKE(ctx, identityReqBytes)
	if err != nil {
		return AuthResult{}, err
	}
	_, identityInnerResp, err := unprotectAuthResponse(identityRespBytes, cfg.Init, keys, messageID+1)
	if err != nil {
		return AuthResult{}, err
	}
	out.IdentityRequestBytes = append([]byte(nil), identityReqBytes...)
	out.IdentityResponseBytes = append([]byte(nil), identityRespBytes...)
	out.IdentityResponseInner = clonePayloads(identityInnerResp)
	out.EAPIdentityUsed = identity
	out.IdentityTranscript = cloneByteSlices([][]byte{eapReqRaw, identityPacket})
	out.NextMessageID = messageID + 2
	if nextEAP, ok, err := firstEAPPacket(identityInnerResp); err != nil {
		return AuthResult{}, err
	} else if ok {
		out.EAPAfterIdentity = &nextEAP
	}
	return out, nil
}

func RunIKE_AUTH_Full(ctx context.Context, cfg FullAuthConfig) (FullAuthResult, error) {
	localChildSPI, err := fullAuthLocalChildSPI(cfg)
	if err != nil {
		return FullAuthResult{}, err
	}
	auth, err := RunIKE_AUTH_EAPIdentity(ctx, AuthConfig{
		Transport:         cfg.Transport,
		Init:              cfg.Init,
		Keys:              cfg.Keys,
		InitiatorID:       cfg.InitiatorID,
		EAPIdentity:       cfg.EAPIdentity,
		EAPPseudonym:      cfg.EAPPseudonym,
		EAPReauthIdentity: cfg.EAPReauthIdentity,
		ChildSA:           cfg.ChildSA,
		ChildSPI:          localChildSPI,
		TSi:               cfg.TSi,
		TSr:               cfg.TSr,
		Configuration:     cfg.Configuration,
		Random:            cfg.Random,
		InitialIV:         cfg.InitialIV,
		EAPIdentityIV:     cfg.EAPIdentityIV,
		InitialMessageID:  cfg.InitialMessageID,
	})
	if err != nil {
		return FullAuthResult{}, err
	}
	finalInner, finalBytes := authFinalResponse(auth)
	out := FullAuthResult{
		Auth:               auth,
		EAPKeys:            cfg.EAPKeys,
		NextMessageID:      auth.NextMessageID,
		FinalResponseBytes: append([]byte(nil), finalBytes...),
		FinalResponseInner: clonePayloads(finalInner),
	}
	offeredChildSA := authOfferedChildSA(cfg.ChildSA, localChildSPI)
	offeredTSi := trafficSelectorsOrIPv4Any(cfg.TSi)
	offeredTSr := trafficSelectorsOrIPv4Any(cfg.TSr)
	if child, ok, err := parseChildSAIfPresent(cfg.Init, finalInner, localChildSPI, out.NextMessageID, offeredChildSA, offeredTSi, offeredTSr); err != nil {
		return FullAuthResult{}, err
	} else if ok {
		out.ChildSA = &child
		return out, nil
	}
	next := authNextEAP(auth)
	identity := authPermanentIdentity(cfg.EAPIdentity, cfg.InitiatorID)
	currentFullAuthIdentity := firstIKEAuthNonEmpty(auth.EAPIdentityUsed, identity)
	identityTranscript := cloneByteSlices(auth.IdentityTranscript)
	for i := 0; i < maxFullAuthEAPExchanges; i++ {
		if next == nil {
			return out, fmt.Errorf("%w: IKE_AUTH did not complete EAP", ErrInvalidAuthResponse)
		}
		out.EAPLast = cloneEAPPacketPtr(next)
		if next.Code == eapaka.CodeSuccess {
			if child, ok, err := parseChildSAIfPresent(cfg.Init, out.FinalResponseInner, localChildSPI, out.NextMessageID, offeredChildSA, offeredTSi, offeredTSr); err != nil {
				return FullAuthResult{}, err
			} else if ok {
				out.ChildSA = &child
				return out, nil
			}
			return out, fmt.Errorf("%w: EAP success without CHILD_SA", ErrInvalidAuthResponse)
		}
		if next.Code == eapaka.CodeFailure {
			return out, fmt.Errorf("%w: EAP failure", ErrInvalidAuthResponse)
		}
		if next.Code != eapaka.CodeRequest {
			return out, fmt.Errorf("%w: unexpected EAP code %d", ErrInvalidAuthResponse, next.Code)
		}
		if next.Subtype == eapaka.SubtypeIdentity {
			_, requestRaw, _, err := firstEAPPacketWithRaw(out.FinalResponseInner)
			if err != nil {
				return FullAuthResult{}, err
			}
			exchangeIdentity := identityForEAPRequest(*next, eapIdentityOptions{
				PermanentIdentity: identity,
				Pseudonym:         firstIKEAuthNonEmpty(out.EAPNextPseudonym, cfg.EAPPseudonym),
				ReauthIdentity:    cfg.EAPReauthIdentity,
			})
			exchange, err := runIKEAuthIdentityExchange(ctx, identityExchangeConfig{
				Transport:  cfg.Transport,
				Init:       cfg.Init,
				Keys:       cfg.Keys,
				Random:     cfg.Random,
				Request:    *next,
				RequestRaw: requestRaw,
				Identity:   exchangeIdentity,
				MessageID:  out.NextMessageID,
			})
			if err != nil {
				return FullAuthResult{}, err
			}
			currentFullAuthIdentity = exchange.Identity
			out.IdentityExchanges = append(out.IdentityExchanges, exchange)
			identityTranscript = append(identityTranscript, exchange.Transcript...)
			out.NextMessageID = exchange.NextMessageID
			out.FinalResponseBytes = append([]byte(nil), exchange.ResponseBytes...)
			out.FinalResponseInner = clonePayloads(exchange.ResponseInner)
			if child, ok, err := parseChildSAIfPresent(cfg.Init, out.FinalResponseInner, localChildSPI, out.NextMessageID, offeredChildSA, offeredTSi, offeredTSr); err != nil {
				return FullAuthResult{}, err
			} else if ok {
				out.ChildSA = &child
				return out, nil
			}
			next = exchange.EAPNext
			continue
		}
		challengeIdentity := currentFullAuthIdentity
		if next.Subtype == eapaka.SubtypeReauthentication && strings.TrimSpace(cfg.EAPReauthIdentity) != "" {
			challengeIdentity = strings.TrimSpace(cfg.EAPReauthIdentity)
		}
		challenge, err := runIKE_AUTH_AKAChallenge(ctx, AKAChallengeConfig{
			Transport:          cfg.Transport,
			Init:               cfg.Init,
			Keys:               cfg.Keys,
			SIM:                cfg.SIM,
			EAPKeys:            out.EAPKeys,
			Identity:           challengeIdentity,
			Request:            *next,
			IdentityTranscript: identityTranscript,
			ChildSPI:           localChildSPI,
			TSi:                offeredTSi,
			TSr:                offeredTSr,
			MessageID:          out.NextMessageID,
			Random:             cfg.Random,
			EAPReauthIV:        cfg.EAPReauthIV,
			EAPReauthCounter:   cfg.EAPReauthCounter,
			EAPReauthCounterOK: cfg.EAPReauthCounterOK,
		}, offeredChildSA, offeredTSi, offeredTSr)
		if err != nil {
			return FullAuthResult{}, err
		}
		out.AKAChallenges = append(out.AKAChallenges, challenge)
		out.NextMessageID = challenge.NextMessageID
		out.FinalResponseBytes = append([]byte(nil), challenge.FinalResponseBytes...)
		out.FinalResponseInner = clonePayloads(challenge.FinalResponseInner)
		out.EAPNotifications = append(out.EAPNotifications, challenge.EAPNotifications...)
		out.EAPClientError = out.EAPClientError || challenge.EAPClientError
		if challenge.EAPNextPseudonym != "" {
			out.EAPNextPseudonym = challenge.EAPNextPseudonym
		}
		if challenge.EAPNextReauthID != "" {
			out.EAPNextReauthID = challenge.EAPNextReauthID
		}
		out.EAPReauthenticated = out.EAPReauthenticated || challenge.EAPReauthenticated
		if challenge.EAPReauthCounter != 0 {
			out.EAPReauthCounter = challenge.EAPReauthCounter
		}
		out.EAPReauthCounterTooSmall = out.EAPReauthCounterTooSmall || challenge.EAPReauthCounterTooSmall
		out.SyncFailure = out.SyncFailure || challenge.SyncFailure
		out.AuthFailure = out.AuthFailure || challenge.AuthFailure
		if challenge.KDFNegotiated {
			out.KDFNegotiations++
		}
		if len(challenge.EAPKeys.KAut) > 0 {
			out.EAPKeys = challenge.EAPKeys
		}
		if challenge.ChildSA != nil {
			child := *challenge.ChildSA
			out.ChildSA = &child
			if challenge.EAPNext != nil {
				out.EAPLast = cloneEAPPacketPtr(challenge.EAPNext)
			}
			return out, nil
		}
		next = challenge.EAPNext
	}
	return out, fmt.Errorf("%w: too many IKE_AUTH EAP exchanges", ErrInvalidAuthResponse)
}

func RunIKE_AUTH_AKAChallenge(ctx context.Context, cfg AKAChallengeConfig) (AKAChallengeResult, error) {
	var offeredChildSA SecurityAssociation
	if len(cfg.ChildSPI) > 0 {
		offeredChildSA = DefaultESPProposal(cfg.ChildSPI)
	}
	return runIKE_AUTH_AKAChallenge(ctx, cfg, offeredChildSA, cfg.TSi, cfg.TSr)
}

func runIKE_AUTH_AKAChallenge(ctx context.Context, cfg AKAChallengeConfig, offeredChildSA SecurityAssociation, offeredTSi, offeredTSr TrafficSelectors) (AKAChallengeResult, error) {
	if cfg.Transport == nil {
		return AKAChallengeResult{}, fmt.Errorf("%w: transport is nil", ErrInvalidAuthConfig)
	}
	keys := cfg.Keys
	if keys.Profile.RequiredLength() == 0 {
		keys = cfg.Init.Keys
	}
	if err := validateKeySet(keys); err != nil {
		return AKAChallengeResult{}, err
	}
	if cfg.MessageID == 0 {
		return AKAChallengeResult{}, fmt.Errorf("%w: message_id is zero", ErrInvalidAuthConfig)
	}
	var eapResp eapaka.Packet
	var eapKeys eapaka.Keys
	var syncFailure bool
	var authFailure bool
	var kdfNegotiated bool
	var clientError bool
	var reauthenticated bool
	var reauthCounter uint16
	var reauthCounterTooSmall bool
	var notifications []eapaka.Packet
	var encryptedAttributes []eapaka.Attribute
	var identityState eapaka.EncryptedIdentityState
	if cfg.Request.Code == eapaka.CodeRequest && cfg.Request.Subtype == eapaka.SubtypeReauthentication && len(cfg.EAPKeys.KAut) > 0 {
		parsed, err := eapaka.ParseReauthenticationRequest(cfg.Request, cfg.EAPKeys)
		if err != nil {
			return AKAChallengeResult{}, err
		}
		reauthCounter = parsed.Counter
		encryptedAttributes = parsed.EncryptedAttributes
		identityState = parsed.IdentityState
		eapIV, err := eapReauthIV(cfg.Random, cfg.EAPReauthIV)
		if err != nil {
			return AKAChallengeResult{}, err
		}
		if cfg.EAPReauthCounterOK && parsed.Counter <= cfg.EAPReauthCounter {
			eapResp, err = eapaka.BuildReauthenticationCounterTooSmallResponse(cfg.Request, cfg.EAPKeys, eapIV)
			if err != nil {
				return AKAChallengeResult{}, err
			}
			eapKeys = cfg.EAPKeys
			reauthCounterTooSmall = true
		} else {
			identity := strings.TrimSpace(cfg.Identity)
			if identity == "" {
				return AKAChallengeResult{}, fmt.Errorf("%w: reauthentication identity is empty", ErrInvalidAuthConfig)
			}
			eapResp, eapKeys, err = eapaka.BuildReauthenticationResponse(identity, cfg.Request, cfg.EAPKeys, eapIV)
			if err != nil {
				return AKAChallengeResult{}, err
			}
			reauthenticated = true
		}
	} else if response, handled, err := buildAKAControlResponse(cfg.Request, cfg.EAPKeys); err != nil {
		return AKAChallengeResult{}, err
	} else if handled {
		eapResp = response
		clientError = response.Subtype == eapaka.SubtypeClientError
		if response.Subtype == eapaka.SubtypeNotification {
			notifications = append(notifications, cloneEAPPacket(cfg.Request))
		}
	} else if response, negotiated, err := eapaka.BuildAKAPrimeKDFNegotiationResponse(cfg.Request); err != nil {
		return AKAChallengeResult{}, err
	} else if negotiated {
		eapResp = response
		kdfNegotiated = true
	} else {
		if cfg.SIM == nil {
			return AKAChallengeResult{}, fmt.Errorf("%w: SIM provider is nil", ErrInvalidAuthConfig)
		}
		challenge, err := eapaka.BuildChallengeResponseFromProvider(cfg.Identity, cfg.Request, cfg.SIM, cfg.IdentityTranscript)
		if err != nil {
			if strings.TrimSpace(cfg.Identity) == "" && errors.Is(err, eapaka.ErrInvalidKeyMaterial) {
				return AKAChallengeResult{}, fmt.Errorf("%w: identity is empty", ErrInvalidAuthConfig)
			}
			return AKAChallengeResult{}, err
		}
		eapResp = challenge.Response
		eapKeys = challenge.Keys
		syncFailure = challenge.SyncFailure
		authFailure = challenge.AuthFailure
		if !syncFailure && !authFailure {
			if attrs, _, err := eapaka.DecryptChallengeEncryptedAttributes(cfg.Request, eapKeys); err != nil {
				return AKAChallengeResult{}, err
			} else if len(attrs) > 0 {
				encryptedAttributes = attrs
				identityState, err = eapaka.IdentityStateFromAttributes(attrs)
				if err != nil {
					return AKAChallengeResult{}, err
				}
			}
		}
	}
	eapRaw, err := eapResp.MarshalBinary()
	if err != nil {
		return AKAChallengeResult{}, err
	}
	iv, err := authIV(cfg.Random, keys.Profile, cfg.IV)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	_, reqBytes, err := ProtectMessage(authHeader(cfg.Init, cfg.MessageID, true), keys, true, []Payload{EAPPayload(eapRaw)}, iv)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	respBytes, err := cfg.Transport.ExchangeIKE(ctx, reqBytes)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	_, inner, err := unprotectAuthResponse(respBytes, cfg.Init, keys, cfg.MessageID)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	controlKeys := eapKeys
	if len(controlKeys.KAut) == 0 {
		controlKeys = cfg.EAPKeys
	}
	resultEAPKeys := eapKeys
	if len(resultEAPKeys.KAut) == 0 {
		resultEAPKeys = cfg.EAPKeys
	}
	followups, err := runAKAControlFollowups(ctx, cfg, keys, inner, cfg.MessageID+1, controlKeys)
	if err != nil {
		return AKAChallengeResult{}, err
	}
	notifications = append(notifications, followups.Notifications...)
	finalRespBytes := respBytes
	finalInner := inner
	nextMessageID := cfg.MessageID + 1
	if len(followups.ResponseBytes) > 0 {
		finalRespBytes = followups.ResponseBytes[len(followups.ResponseBytes)-1]
		finalInner = followups.FinalInner
		nextMessageID = followups.NextMessageID
		clientError = clientError || followups.ClientError
	}
	out := AKAChallengeResult{
		RequestBytes:             append([]byte(nil), reqBytes...),
		ResponseBytes:            append([]byte(nil), respBytes...),
		ResponseInner:            clonePayloads(inner),
		EAPResponse:              eapResp,
		EAPKeys:                  resultEAPKeys,
		EAPEncryptedAttributes:   cloneEAPAttributes(encryptedAttributes),
		EAPNextPseudonym:         identityState.NextPseudonym,
		EAPNextReauthID:          identityState.NextReauthID,
		EAPReauthenticated:       reauthenticated,
		EAPReauthCounter:         reauthCounter,
		EAPReauthCounterTooSmall: reauthCounterTooSmall,
		EAPNotifications:         cloneEAPPackets(notifications),
		EAPClientError:           clientError,
		SyncFailure:              syncFailure,
		AuthFailure:              authFailure,
		KDFNegotiated:            kdfNegotiated,
		NextMessageID:            nextMessageID,
		FollowupRequestBytes:     cloneByteSlices(followups.RequestBytes),
		FollowupResponseBytes:    cloneByteSlices(followups.ResponseBytes),
		FinalResponseBytes:       append([]byte(nil), finalRespBytes...),
		FinalResponseInner:       clonePayloads(finalInner),
	}
	if next, ok, err := firstEAPPacket(finalInner); err != nil {
		return AKAChallengeResult{}, err
	} else if ok {
		out.EAPNext = &next
	}
	if hasPayload(finalInner, PayloadSA) {
		var offeredSA *SecurityAssociation
		if len(offeredChildSA.Proposals) > 0 {
			offeredSA = &offeredChildSA
		}
		child, err := parseChildSAResultWithNonces(cfg.Init, finalInner, cfg.ChildSPI, cfg.Init.NonceI, cfg.Init.NonceR, offeredSA, offeredTSi, offeredTSr)
		if err != nil {
			return AKAChallengeResult{}, err
		}
		child.NextMessageID = nextMessageID
		out.ChildSA = &child
	}
	return out, nil
}

type akaControlFollowups struct {
	RequestBytes  [][]byte
	ResponseBytes [][]byte
	FinalInner    []Payload
	NextMessageID uint32
	Notifications []eapaka.Packet
	ClientError   bool
}

func runAKAControlFollowups(ctx context.Context, cfg AKAChallengeConfig, keys IKEKeys, initialInner []Payload, messageID uint32, eapKeys eapaka.Keys) (akaControlFollowups, error) {
	out := akaControlFollowups{
		FinalInner:    clonePayloads(initialInner),
		NextMessageID: messageID,
	}
	for i := 0; i < maxAKAControlFollowups; i++ {
		next, ok, err := firstEAPPacket(out.FinalInner)
		if err != nil {
			return akaControlFollowups{}, err
		}
		if !ok {
			return out, nil
		}
		response, handled, err := buildAKAControlResponse(next, eapKeys)
		if err != nil {
			return akaControlFollowups{}, err
		}
		if !handled {
			return out, nil
		}
		if response.Subtype == eapaka.SubtypeNotification {
			out.Notifications = append(out.Notifications, cloneEAPPacket(next))
		}
		if response.Subtype == eapaka.SubtypeClientError {
			out.ClientError = true
		}
		raw, err := response.MarshalBinary()
		if err != nil {
			return akaControlFollowups{}, err
		}
		iv, err := authIV(cfg.Random, keys.Profile, nil)
		if err != nil {
			return akaControlFollowups{}, err
		}
		_, reqBytes, err := ProtectMessage(authHeader(cfg.Init, out.NextMessageID, true), keys, true, []Payload{EAPPayload(raw)}, iv)
		if err != nil {
			return akaControlFollowups{}, err
		}
		respBytes, err := cfg.Transport.ExchangeIKE(ctx, reqBytes)
		if err != nil {
			return akaControlFollowups{}, err
		}
		_, inner, err := unprotectAuthResponse(respBytes, cfg.Init, keys, out.NextMessageID)
		if err != nil {
			return akaControlFollowups{}, err
		}
		out.RequestBytes = append(out.RequestBytes, append([]byte(nil), reqBytes...))
		out.ResponseBytes = append(out.ResponseBytes, append([]byte(nil), respBytes...))
		out.FinalInner = clonePayloads(inner)
		out.NextMessageID++
	}
	next, ok, err := firstEAPPacket(out.FinalInner)
	if err != nil {
		return akaControlFollowups{}, err
	}
	if ok {
		if _, handled, err := buildAKAControlResponse(next, eapKeys); err != nil {
			return akaControlFollowups{}, err
		} else if handled {
			return akaControlFollowups{}, fmt.Errorf("%w: too many EAP-AKA control followups", ErrInvalidAuthResponse)
		}
	}
	return out, nil
}

func buildAKAControlResponse(request eapaka.Packet, keys eapaka.Keys) (eapaka.Packet, bool, error) {
	if response, handled, err := eapaka.BuildNotificationResponse(request); err != nil {
		if errors.Is(err, eapaka.ErrInvalidKeyMaterial) && len(keys.KAut) > 0 {
			return eapaka.BuildAuthenticatedNotificationResponse(request, keys.KAut)
		}
		return eapaka.Packet{}, handled, err
	} else if handled {
		return response, true, nil
	}
	if request.Code == eapaka.CodeRequest && request.Subtype != eapaka.SubtypeChallenge && request.Subtype != eapaka.SubtypeIdentity {
		response, err := eapaka.BuildClientErrorResponse(request, eapaka.ClientErrorUnableToProcessPacket)
		return response, true, err
	}
	return eapaka.Packet{}, false, nil
}

type identityExchangeConfig struct {
	Transport  InitTransport
	Init       InitResult
	Keys       IKEKeys
	Random     io.Reader
	Request    eapaka.Packet
	RequestRaw []byte
	Identity   string
	MessageID  uint32
}

type eapIdentityOptions struct {
	PermanentIdentity string
	Pseudonym         string
	ReauthIdentity    string
}

func authPermanentIdentity(identity string, initiator Identity) string {
	out := strings.TrimSpace(identity)
	if out == "" {
		out = strings.TrimSpace(string(initiator.Data))
	}
	return out
}

func identityForEAPRequest(request eapaka.Packet, opts eapIdentityOptions) string {
	permanent := strings.TrimSpace(opts.PermanentIdentity)
	pseudonym := strings.TrimSpace(opts.Pseudonym)
	reauth := strings.TrimSpace(opts.ReauthIdentity)
	switch {
	case hasEAPIdentityRequestAttribute(request, eapaka.AttributePermanentIDReq):
		return permanent
	case hasEAPIdentityRequestAttribute(request, eapaka.AttributeFullAuthIDReq):
		return firstIKEAuthNonEmpty(pseudonym, permanent)
	case hasEAPIdentityRequestAttribute(request, eapaka.AttributeAnyIDReq):
		return firstIKEAuthNonEmpty(reauth, pseudonym, permanent)
	default:
		return permanent
	}
}

func hasEAPIdentityRequestAttribute(request eapaka.Packet, typ uint8) bool {
	_, ok := eapaka.FindAttribute(request.Attributes, typ)
	return ok
}

func firstIKEAuthNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func runIKEAuthIdentityExchange(ctx context.Context, cfg identityExchangeConfig) (EAPIdentityExchange, error) {
	if cfg.Transport == nil {
		return EAPIdentityExchange{}, fmt.Errorf("%w: transport is nil", ErrInvalidAuthConfig)
	}
	if cfg.MessageID == 0 {
		return EAPIdentityExchange{}, fmt.Errorf("%w: message_id is zero", ErrInvalidAuthConfig)
	}
	if cfg.Request.Code != eapaka.CodeRequest || cfg.Request.Subtype != eapaka.SubtypeIdentity {
		return EAPIdentityExchange{}, fmt.Errorf("%w: not an EAP identity request", ErrInvalidAuthConfig)
	}
	identity := strings.TrimSpace(cfg.Identity)
	if identity == "" {
		return EAPIdentityExchange{}, fmt.Errorf("%w: eap identity is empty", ErrInvalidAuthConfig)
	}
	keys := cfg.Keys
	if keys.Profile.RequiredLength() == 0 {
		keys = cfg.Init.Keys
	}
	if err := validateKeySet(keys); err != nil {
		return EAPIdentityExchange{}, err
	}
	requestRaw := append([]byte(nil), cfg.RequestRaw...)
	if len(requestRaw) == 0 {
		encoded, err := cfg.Request.MarshalBinary()
		if err != nil {
			return EAPIdentityExchange{}, err
		}
		requestRaw = encoded
	}
	response, err := eapaka.BuildIdentityResponse(identity, cfg.Request)
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	raw, err := response.MarshalBinary()
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	iv, err := authIV(cfg.Random, keys.Profile, nil)
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	_, reqBytes, err := ProtectMessage(authHeader(cfg.Init, cfg.MessageID, true), keys, true, []Payload{EAPPayload(raw)}, iv)
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	respBytes, err := cfg.Transport.ExchangeIKE(ctx, reqBytes)
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	_, inner, err := unprotectAuthResponse(respBytes, cfg.Init, keys, cfg.MessageID)
	if err != nil {
		return EAPIdentityExchange{}, err
	}
	out := EAPIdentityExchange{
		Request:       cloneEAPPacket(cfg.Request),
		Response:      cloneEAPPacket(response),
		Identity:      identity,
		RequestBytes:  append([]byte(nil), reqBytes...),
		ResponseBytes: append([]byte(nil), respBytes...),
		ResponseInner: clonePayloads(inner),
		Transcript:    cloneByteSlices([][]byte{requestRaw, raw}),
		NextMessageID: cfg.MessageID + 1,
	}
	if next, ok, err := firstEAPPacket(inner); err != nil {
		return EAPIdentityExchange{}, err
	} else if ok {
		out.EAPNext = &next
	}
	return out, nil
}

func BuildIKEAuthInitialPayloads(cfg AuthConfig) ([]Payload, error) {
	idPayload, err := IdentityPayload(PayloadIDi, cfg.InitiatorID)
	if err != nil {
		return nil, err
	}
	childSA := cfg.ChildSA
	if len(childSA.Proposals) == 0 {
		spi := append([]byte(nil), cfg.ChildSPI...)
		if len(spi) == 0 {
			random := cfg.Random
			if random == nil {
				random = rand.Reader
			}
			var err error
			spi, err = randomBytes(random, 4)
			if err != nil {
				return nil, err
			}
		}
		if len(spi) != 4 {
			return nil, fmt.Errorf("%w: child SPI length %d", ErrInvalidAuthConfig, len(spi))
		}
		childSA = DefaultESPProposal(spi)
	}
	saPayload, err := SecurityAssociationPayload(childSA)
	if err != nil {
		return nil, err
	}
	tsi := cfg.TSi
	if len(tsi.Selectors) == 0 {
		tsi = IPv4AnyTrafficSelectors()
	}
	tsiPayload, err := TrafficSelectorsPayload(PayloadTSi, tsi)
	if err != nil {
		return nil, err
	}
	tsr := cfg.TSr
	if len(tsr.Selectors) == 0 {
		tsr = IPv4AnyTrafficSelectors()
	}
	tsrPayload, err := TrafficSelectorsPayload(PayloadTSr, tsr)
	if err != nil {
		return nil, err
	}
	cfgPayload, err := ConfigurationPayload(firstConfiguration(cfg.Configuration, SWuConfigurationRequest()))
	if err != nil {
		return nil, err
	}
	return []Payload{idPayload, cfgPayload, saPayload, tsiPayload, tsrPayload}, nil
}

func authHeader(init InitResult, messageID uint32, fromInitiator bool) Header {
	flags := uint8(0)
	if fromInitiator {
		flags |= FlagInitiator
	} else {
		flags |= FlagResponse
	}
	return Header{
		InitiatorSPI: init.InitiatorSPI,
		ResponderSPI: init.ResponderSPI,
		ExchangeType: ExchangeIKE_AUTH,
		Flags:        flags,
		MessageID:    messageID,
	}
}

func unprotectAuthResponse(raw []byte, init InitResult, keys IKEKeys, messageID uint32) (Message, []Payload, error) {
	msg, inner, err := UnprotectMessage(raw, keys, false)
	if err != nil {
		return Message{}, nil, err
	}
	h := msg.Header
	if h.InitiatorSPI != init.InitiatorSPI || h.ResponderSPI != init.ResponderSPI ||
		h.ExchangeType != ExchangeIKE_AUTH || h.MessageID != messageID || h.Flags&FlagResponse == 0 {
		return Message{}, nil, fmt.Errorf("%w: unexpected IKE_AUTH response header", ErrInvalidAuthResponse)
	}
	if err := FirstNotifyError(inner); err != nil {
		return Message{}, nil, fmt.Errorf("%w: %w", ErrInvalidAuthResponse, err)
	}
	return msg, inner, nil
}

func firstEAPPacket(payloads []Payload) (eapaka.Packet, bool, error) {
	pkt, _, ok, err := firstEAPPacketWithRaw(payloads)
	return pkt, ok, err
}

func firstEAPPacketWithRaw(payloads []Payload) (eapaka.Packet, []byte, bool, error) {
	for _, p := range payloads {
		if p.Type != PayloadEAP {
			continue
		}
		pkt, err := eapaka.ParsePacket(p.Body)
		if err != nil {
			return eapaka.Packet{}, nil, false, err
		}
		return pkt, append([]byte(nil), p.Body...), true, nil
	}
	return eapaka.Packet{}, nil, false, nil
}

func authFinalResponse(auth AuthResult) ([]Payload, []byte) {
	if len(auth.IdentityResponseInner) > 0 || len(auth.IdentityResponseBytes) > 0 {
		return clonePayloads(auth.IdentityResponseInner), append([]byte(nil), auth.IdentityResponseBytes...)
	}
	return clonePayloads(auth.InitialResponseInner), append([]byte(nil), auth.InitialResponseBytes...)
}

func authNextEAP(auth AuthResult) *eapaka.Packet {
	if auth.EAPAfterIdentity != nil {
		return cloneEAPPacketPtr(auth.EAPAfterIdentity)
	}
	if auth.EAPRequest != nil {
		if auth.EAPRequest.Code == eapaka.CodeRequest && auth.EAPRequest.Subtype == eapaka.SubtypeIdentity && len(auth.IdentityResponseBytes) > 0 {
			return nil
		}
		return cloneEAPPacketPtr(auth.EAPRequest)
	}
	return nil
}

func parseChildSAIfPresent(init InitResult, inner []Payload, localSPI []byte, nextMessageID uint32, offeredSA SecurityAssociation, offeredTSi, offeredTSr TrafficSelectors) (ChildSAResult, bool, error) {
	if !hasPayload(inner, PayloadSA) {
		return ChildSAResult{}, false, nil
	}
	var offered *SecurityAssociation
	if len(offeredSA.Proposals) > 0 {
		offered = &offeredSA
	}
	child, err := parseChildSAResultWithNonces(init, inner, localSPI, init.NonceI, init.NonceR, offered, offeredTSi, offeredTSr)
	if err != nil {
		return ChildSAResult{}, false, err
	}
	child.NextMessageID = nextMessageID
	return child, true, nil
}

func fullAuthLocalChildSPI(cfg FullAuthConfig) ([]byte, error) {
	if len(cfg.ChildSA.Proposals) > 0 && len(cfg.ChildSA.Proposals[0].SPI) > 0 {
		return append([]byte(nil), cfg.ChildSA.Proposals[0].SPI...), nil
	}
	if len(cfg.ChildSPI) > 0 {
		if len(cfg.ChildSPI) != 4 {
			return nil, fmt.Errorf("%w: child SPI length %d", ErrInvalidAuthConfig, len(cfg.ChildSPI))
		}
		return append([]byte(nil), cfg.ChildSPI...), nil
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	return randomBytes(random, 4)
}

func authOfferedChildSA(sa SecurityAssociation, localSPI []byte) SecurityAssociation {
	if len(sa.Proposals) == 0 {
		if len(localSPI) == 0 {
			return SecurityAssociation{}
		}
		return DefaultESPProposal(localSPI)
	}
	return cloneSecurityAssociation(sa)
}

func authIV(random io.Reader, profile KeyMaterialProfile, override []byte) ([]byte, error) {
	if len(override) > 0 {
		if len(override) != profile.EncryptionBlockSize {
			return nil, fmt.Errorf("%w: IV length %d != %d", ErrInvalidAuthConfig, len(override), profile.EncryptionBlockSize)
		}
		return append([]byte(nil), override...), nil
	}
	return RandomIV(random, profile)
}

func eapReauthIV(random io.Reader, override []byte) ([]byte, error) {
	if len(override) > 0 {
		if len(override) != aes.BlockSize {
			return nil, fmt.Errorf("%w: EAP reauthentication IV length %d != %d", ErrInvalidAuthConfig, len(override), aes.BlockSize)
		}
		return append([]byte(nil), override...), nil
	}
	if random == nil {
		random = rand.Reader
	}
	return randomBytes(random, aes.BlockSize)
}

func firstConfiguration(value, fallback Configuration) Configuration {
	if value.Type != 0 || len(value.Attributes) > 0 {
		return value
	}
	return fallback
}

func clonePayloads(in []Payload) []Payload {
	out := make([]Payload, len(in))
	for i, p := range in {
		out[i] = Payload{
			Type:        p.Type,
			NextPayload: p.NextPayload,
			Critical:    p.Critical,
			Body:        append([]byte(nil), p.Body...),
		}
	}
	return out
}

func cloneByteSlices(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, item := range in {
		out[i] = append([]byte(nil), item...)
	}
	return out
}

func cloneEAPPackets(in []eapaka.Packet) []eapaka.Packet {
	out := make([]eapaka.Packet, len(in))
	for i, packet := range in {
		out[i] = cloneEAPPacket(packet)
	}
	return out
}

func cloneEAPPacketPtr(packet *eapaka.Packet) *eapaka.Packet {
	if packet == nil {
		return nil
	}
	out := cloneEAPPacket(*packet)
	return &out
}

func cloneEAPPacket(packet eapaka.Packet) eapaka.Packet {
	out := packet
	out.Attributes = cloneEAPAttributes(packet.Attributes)
	out.Data = append([]byte(nil), packet.Data...)
	return out
}

func cloneEAPAttributes(in []eapaka.Attribute) []eapaka.Attribute {
	out := make([]eapaka.Attribute, len(in))
	for i, attr := range in {
		out[i] = eapaka.Attribute{
			Type: attr.Type,
			Data: append([]byte(nil), attr.Data...),
		}
	}
	return out
}

func hasPayload(payloads []Payload, payloadType uint8) bool {
	for _, p := range payloads {
		if p.Type == payloadType {
			return true
		}
	}
	return false
}
