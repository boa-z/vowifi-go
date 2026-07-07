package eapaka

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/boa-z/vowifi-go/engine/sim"
)

func TestDeriveKeysAndBuildChallengeResponse(t *testing.T) {
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	req := signedChallengeRequest(t, identity, aka)
	resp, keys, err := BuildChallengeResponse(identity, req, aka)
	if err != nil {
		t.Fatalf("BuildChallengeResponse() error = %v", err)
	}
	if len(keys.KEncr) != KeyLengthKEncr || len(keys.KAut) != KeyLengthKAut || len(keys.MSK) != KeyLengthMSK || len(keys.EMSK) != KeyLengthEMSK {
		t.Fatalf("key lengths KEncr=%d KAut=%d MSK=%d EMSK=%d", len(keys.KEncr), len(keys.KAut), len(keys.MSK), len(keys.EMSK))
	}
	if resp.Code != CodeResponse || resp.Identifier != req.Identifier || resp.Subtype != SubtypeChallenge {
		t.Fatalf("response=%+v", resp)
	}
	resAttr, ok := FindAttribute(resp.Attributes, AttributeRES)
	if !ok {
		t.Fatal("missing AT_RES")
	}
	res, bits, err := resAttr.RESValue()
	if err != nil {
		t.Fatalf("RESValue() error = %v", err)
	}
	if bits != 32 || !bytes.Equal(res, aka.RES) {
		t.Fatalf("RES bits=%d value=%x", bits, res)
	}
	raw, err := resp.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if err := VerifyMAC(keys.KAut, raw, nil); err != nil {
		t.Fatalf("VerifyMAC(response) error = %v", err)
	}
}

func TestBuildChallengeResponseWithCheckcode(t *testing.T) {
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	transcript := identityTranscriptPackets(t, identity)
	req := signedChallengeRequestWithCheckcode(t, identity, aka, transcript)
	resp, keys, err := BuildChallengeResponseWithCheckcode(identity, req, aka, transcript)
	if err != nil {
		t.Fatalf("BuildChallengeResponseWithCheckcode() error = %v", err)
	}
	attr, ok := FindAttribute(resp.Attributes, AttributeCheckcode)
	if !ok {
		t.Fatal("missing AT_CHECKCODE")
	}
	if err := VerifyCheckcodeAttribute(attr, transcript); err != nil {
		t.Fatalf("VerifyCheckcodeAttribute(response) error = %v", err)
	}
	raw, err := resp.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if err := VerifyMAC(keys.KAut, raw, nil); err != nil {
		t.Fatalf("VerifyMAC(response) error = %v", err)
	}
}

func TestBuildChallengeResponseRejectsBadCheckcode(t *testing.T) {
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	transcript := identityTranscriptPackets(t, identity)
	req := signedChallengeRequestWithCheckcode(t, identity, aka, transcript)
	badTranscript := identityTranscriptPackets(t, identity+"x")
	_, _, err := BuildChallengeResponseWithCheckcode(identity, req, aka, badTranscript)
	if !errors.Is(err, ErrInvalidCheckcode) {
		t.Fatalf("BuildChallengeResponseWithCheckcode() err=%v, want ErrInvalidCheckcode", err)
	}
}

func TestBuildChallengeResponseEchoesResultInd(t *testing.T) {
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	req := signedChallengeRequestWithResultInd(t, identity, aka)
	resp, keys, err := BuildChallengeResponse(identity, req, aka)
	if err != nil {
		t.Fatalf("BuildChallengeResponse() error = %v", err)
	}
	if _, ok := FindAttribute(resp.Attributes, AttributeResultInd); !ok {
		t.Fatal("missing AT_RESULT_IND")
	}
	raw, err := resp.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if err := VerifyMAC(keys.KAut, raw, nil); err != nil {
		t.Fatalf("VerifyMAC(response) error = %v", err)
	}
}

func TestBuildChallengeResponseRejectsBiddingDown(t *testing.T) {
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	req := signedChallengeRequestWithEncryptedAttrs(t, identity, aka, BiddingAttribute(true))
	_, _, err := BuildChallengeResponse(identity, req, aka)
	if !errors.Is(err, ErrBiddingDown) {
		t.Fatalf("BuildChallengeResponse() err=%v, want ErrBiddingDown", err)
	}
}

func TestBuildChallengeResponseIgnoresNonPreferredBidding(t *testing.T) {
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	req := signedChallengeRequestWithEncryptedAttrs(t, identity, aka, BiddingAttribute(false))
	resp, keys, err := BuildChallengeResponse(identity, req, aka)
	if err != nil {
		t.Fatalf("BuildChallengeResponse() error = %v", err)
	}
	if _, ok := FindAttribute(resp.Attributes, AttributeRES); !ok {
		t.Fatalf("response missing AT_RES: %+v", resp)
	}
	raw, err := resp.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if err := VerifyMAC(keys.KAut, raw, nil); err != nil {
		t.Fatalf("VerifyMAC(response) error = %v", err)
	}
}

func TestBuildIdentityResponseSelectsSupportedVersion(t *testing.T) {
	request := Packet{
		Code:       CodeRequest,
		Identifier: 4,
		Type:       TypeAKA,
		Subtype:    SubtypeIdentity,
		Attributes: []Attribute{
			FullAuthIDReqAttribute(),
			VersionListAttribute(2, SupportedVersion),
		},
	}
	response, err := BuildIdentityResponse("310280233641503@private.att.net", request)
	if err != nil {
		t.Fatalf("BuildIdentityResponse() error = %v", err)
	}
	if response.Code != CodeResponse || response.Identifier != request.Identifier || response.Subtype != SubtypeIdentity {
		t.Fatalf("response=%+v", response)
	}
	if _, ok := FindAttribute(response.Attributes, AttributeIdentity); !ok {
		t.Fatal("missing AT_IDENTITY")
	}
	selectedAttr, ok := FindAttribute(response.Attributes, AttributeSelectedVersion)
	if !ok {
		t.Fatalf("missing AT_SELECTED_VERSION: %+v", response.Attributes)
	}
	selected, err := selectedAttr.SelectedVersionValue()
	if err != nil {
		t.Fatalf("SelectedVersionValue() error = %v", err)
	}
	if selected != SupportedVersion {
		t.Fatalf("selected=%d", selected)
	}
}

func TestBuildIdentityResponseRejectsUnsupportedVersionList(t *testing.T) {
	request := Packet{
		Code:       CodeRequest,
		Identifier: 5,
		Type:       TypeAKA,
		Subtype:    SubtypeIdentity,
		Attributes: []Attribute{VersionListAttribute(2, 3)},
	}
	response, err := BuildIdentityResponse("310280233641503@private.att.net", request)
	if err != nil {
		t.Fatalf("BuildIdentityResponse() error = %v", err)
	}
	if response.Code != CodeResponse || response.Subtype != SubtypeClientError {
		t.Fatalf("response=%+v", response)
	}
	attr, ok := FindAttribute(response.Attributes, AttributeClientErrorCode)
	if !ok {
		t.Fatalf("missing AT_CLIENT_ERROR_CODE: %+v", response.Attributes)
	}
	code, err := attr.ClientErrorCodeValue()
	if err != nil {
		t.Fatalf("ClientErrorCodeValue() error = %v", err)
	}
	if code != ClientErrorUnsupportedVersion {
		t.Fatalf("client error=%d", code)
	}
}

func TestEncryptDecryptAttributes(t *testing.T) {
	kEncr := bytes.Repeat([]byte{0x11}, 16)
	iv := bytes.Repeat([]byte{0x22}, 16)
	attrs := []Attribute{
		NextPseudonymAttribute("pseudo-123"),
		ResultIndAttribute(),
	}
	encrypted, err := EncryptAttributes(kEncr, iv, attrs)
	if err != nil {
		t.Fatalf("EncryptAttributes() error = %v", err)
	}
	if encrypted.Type != AttributeEncrData {
		t.Fatalf("encrypted type=%d, want AT_ENCR_DATA", encrypted.Type)
	}
	ciphertext, err := encrypted.EncrDataValue()
	if err != nil {
		t.Fatalf("EncrDataValue() error = %v", err)
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		t.Fatalf("ciphertext length=%d, want non-zero block multiple", len(ciphertext))
	}
	ivAttr := IVAttribute(iv)
	gotIV, err := ivAttr.IVValue()
	if err != nil {
		t.Fatalf("IVValue() error = %v", err)
	}
	decrypted, err := DecryptEncryptedAttributes(kEncr, ivAttr, encrypted)
	if err != nil {
		t.Fatalf("DecryptEncryptedAttributes() error = %v", err)
	}
	if len(decrypted) != 2 || decrypted[0].Type != AttributeNextPseudonym || decrypted[1].Type != AttributeResultInd {
		t.Fatalf("decrypted=%+v", decrypted)
	}
	value, err := decrypted[0].VariableValue()
	if err != nil {
		t.Fatalf("VariableValue() error = %v", err)
	}
	if string(value) != "pseudo-123" || !bytes.Equal(gotIV, iv) {
		t.Fatalf("value=%q iv=%x", string(value), gotIV)
	}
}

func TestEncryptAttributesRejectsInvalidKEncrLength(t *testing.T) {
	_, err := EncryptAttributes(bytes.Repeat([]byte{0x11}, 15), bytes.Repeat([]byte{0x22}, 16), []Attribute{ResultIndAttribute()})
	if !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("EncryptAttributes(short K_encr) err=%v, want ErrInvalidKeyMaterial", err)
	}
}

func TestDecryptChallengeEncryptedAttributes(t *testing.T) {
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	iv := bytes.Repeat([]byte{0x33}, 16)
	encrypted, err := EncryptAttributes(keys.KEncr, iv, []Attribute{
		NextReauthIDAttribute("reauth-1"),
	})
	if err != nil {
		t.Fatalf("EncryptAttributes() error = %v", err)
	}
	req := signedChallengeRequestWithEncryptedAttrs(t, identity, aka, IVAttribute(iv), encrypted)
	attrs, ok, err := DecryptChallengeEncryptedAttributes(req, keys)
	if err != nil {
		t.Fatalf("DecryptChallengeEncryptedAttributes() error = %v", err)
	}
	if !ok || len(attrs) != 1 || attrs[0].Type != AttributeNextReauthID {
		t.Fatalf("ok=%v attrs=%+v", ok, attrs)
	}
	value, err := attrs[0].VariableValue()
	if err != nil {
		t.Fatalf("VariableValue() error = %v", err)
	}
	if string(value) != "reauth-1" {
		t.Fatalf("next reauth=%q", string(value))
	}
}

func TestParseChallengeWithKeysExtractsAuthenticatedFields(t *testing.T) {
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	iv := bytes.Repeat([]byte{0x33}, 16)
	encrypted, err := EncryptAttributes(keys.KEncr, iv, []Attribute{
		NextPseudonymAttribute("pseudo-2"),
		NextReauthIDAttribute("reauth-2"),
	})
	if err != nil {
		t.Fatalf("EncryptAttributes() error = %v", err)
	}
	transcript := identityTranscriptPackets(t, identity)
	req := signedChallengeRequestWithEncryptedAttrs(t, identity, aka,
		ResultIndAttribute(),
		BiddingAttribute(false),
		CheckcodeAttributeForPackets(transcript),
		IVAttribute(iv),
		encrypted,
	)

	challenge, err := ParseChallengeWithKeys(req, keys)
	if err != nil {
		t.Fatalf("ParseChallengeWithKeys() error = %v", err)
	}
	if len(challenge.Vectors) != 1 || !bytes.Equal(challenge.RAND, bytes.Repeat([]byte{0xa1}, 16)) ||
		!bytes.Equal(challenge.AUTN, bytes.Repeat([]byte{0xb2}, 16)) {
		t.Fatalf("vectors=%+v RAND=%x AUTN=%x", challenge.Vectors, challenge.RAND, challenge.AUTN)
	}
	if !bytes.Equal(challenge.AUTNFields.SQNXorAK, bytes.Repeat([]byte{0xb2}, AKLength)) ||
		!bytes.Equal(challenge.AUTNFields.AMF, bytes.Repeat([]byte{0xb2}, AMFLength)) ||
		!bytes.Equal(challenge.AUTNFields.MAC, bytes.Repeat([]byte{0xb2}, AUTNMACLength)) {
		t.Fatalf("AUTN fields=%+v", challenge.AUTNFields)
	}
	if !challenge.HasMAC || len(challenge.MAC) != 16 {
		t.Fatalf("AT_MAC present=%t len=%d", challenge.HasMAC, len(challenge.MAC))
	}
	if !challenge.ResultInd || !challenge.HasCheckcode || len(challenge.Checkcode) != 20 {
		t.Fatalf("result-ind=%t checkcode=%x", challenge.ResultInd, challenge.Checkcode)
	}
	if !challenge.HasBidding || challenge.Bidding {
		t.Fatalf("bidding present=%t value=%t", challenge.HasBidding, challenge.Bidding)
	}
	if challenge.IdentityState.NextPseudonym != "pseudo-2" || challenge.IdentityState.NextReauthID != "reauth-2" {
		t.Fatalf("identity state=%+v", challenge.IdentityState)
	}
	if len(challenge.EncryptedAttributes) != 2 {
		t.Fatalf("encrypted attrs=%+v", challenge.EncryptedAttributes)
	}
	challenge.EncryptedAttributes[0].Data[1] = 99
	again, err := ParseChallengeWithKeys(req, keys)
	if err != nil {
		t.Fatalf("ParseChallengeWithKeys(again) error = %v", err)
	}
	if again.IdentityState.NextPseudonym != "pseudo-2" {
		t.Fatalf("parse result was not cloned: state=%+v", again.IdentityState)
	}
}

func TestParseChallengeSupportsMultipleVectors(t *testing.T) {
	rand1 := bytes.Repeat([]byte{0x11}, 16)
	rand2 := bytes.Repeat([]byte{0x22}, 16)
	autn1 := mustHex(t, "0102030405068000a1a2a3a4a5a6a7a8")
	autn2 := mustHex(t, "1112131415160000b1b2b3b4b5b6b7b8")
	req := Packet{
		Code:    CodeRequest,
		Type:    TypeAKA,
		Subtype: SubtypeChallenge,
		Attributes: []Attribute{
			RANDAttribute(rand1, rand2),
			FixedAttribute(AttributeAUTN, append(append([]byte(nil), autn1...), autn2...)),
		},
	}
	challenge, err := ParseChallenge(req)
	if err != nil {
		t.Fatalf("ParseChallenge() error = %v", err)
	}
	if len(challenge.Vectors) != 2 || !bytes.Equal(challenge.Vectors[0].RAND, rand1) || !bytes.Equal(challenge.Vectors[1].AUTN, autn2) {
		t.Fatalf("vectors=%+v", challenge.Vectors)
	}
	if challenge.HasMAC {
		t.Fatalf("unexpected AT_MAC=%x", challenge.MAC)
	}
	if _, _, err := ChallengeRANDAndAUTN(req); !errors.Is(err, ErrInvalidAKAChallenge) {
		t.Fatalf("ChallengeRANDAndAUTN(multiple vectors) err=%v, want ErrInvalidAKAChallenge", err)
	}
}

func TestParseChallengeRejectsInvalidVectors(t *testing.T) {
	req := Packet{
		Code:    CodeRequest,
		Type:    TypeAKA,
		Subtype: SubtypeChallenge,
		Attributes: []Attribute{
			RANDAttribute(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)),
			AUTNAttribute(bytes.Repeat([]byte{0x33}, 16)),
		},
	}
	if _, err := ParseChallenge(req); !errors.Is(err, ErrInvalidAKAChallenge) {
		t.Fatalf("ParseChallenge(mismatched vectors) err=%v, want ErrInvalidAKAChallenge", err)
	}

	req.Attributes = []Attribute{
		RANDAttribute(bytes.Repeat([]byte{0x11}, 16)),
		RANDAttribute(bytes.Repeat([]byte{0x22}, 16)),
		AUTNAttribute(bytes.Repeat([]byte{0x33}, 16)),
	}
	if _, err := ParseChallenge(req); !errors.Is(err, ErrInvalidAKAChallenge) {
		t.Fatalf("ParseChallenge(duplicate RAND) err=%v, want ErrInvalidAKAChallenge", err)
	}
}

func TestParseReauthenticationRequest(t *testing.T) {
	identity := "reauth-identity@example"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	nonceS := []byte("0123456789abcdef")
	request := signedReauthenticationRequest(t, keys, 12, nonceS, []Attribute{
		NextReauthIDAttribute("reauth-next"),
	})
	parsed, err := ParseReauthenticationRequest(request, keys)
	if err != nil {
		t.Fatalf("ParseReauthenticationRequest() error = %v", err)
	}
	if parsed.Counter != 12 || !bytes.Equal(parsed.NonceS, nonceS) || parsed.IdentityState.NextReauthID != "reauth-next" {
		t.Fatalf("parsed=%+v nonce=%x", parsed, parsed.NonceS)
	}
	if len(parsed.EncryptedAttributes) != 3 {
		t.Fatalf("encrypted attrs=%+v", parsed.EncryptedAttributes)
	}
	parsed.EncryptedAttributes[0].Data[1] = 99
	again, err := ParseReauthenticationRequest(request, keys)
	if err != nil {
		t.Fatalf("ParseReauthenticationRequest(again) error = %v", err)
	}
	if again.Counter != 12 {
		t.Fatalf("parsed result was not cloned: counter=%d", again.Counter)
	}
}

func TestParseReauthenticationRequestRejectsMethodMismatch(t *testing.T) {
	identity := "0555444333222111"
	networkName := "WLAN"
	aka := sim.AKAResult{
		RES: mustHex(t, "28d7b0f2a2ec3de5"),
		IK:  mustHex(t, "9744871ad32bf9bbd1dd5ce54e3e2e5a"),
		CK:  mustHex(t, "5349fbe098649f948f5d2e973a81c00f"),
	}
	keys, err := DeriveAKAPrimeKeys(identity, networkName, mustHex(t, "bb52e91c747ac3ab2a5c23d15ee351d5"), aka)
	if err != nil {
		t.Fatalf("DeriveAKAPrimeKeys() error = %v", err)
	}
	request := signedReauthenticationRequestWithOptions(t, TypeAKAPrime, keys, 1, []byte("0123456789abcdef"), nil, nil)
	request.Type = TypeAKA
	_, err = ParseReauthenticationRequest(request, keys)
	if !errors.Is(err, ErrInvalidReauth) {
		t.Fatalf("ParseReauthenticationRequest() err=%v, want ErrInvalidReauth", err)
	}
}

func TestParseReauthenticationRequestRejectsDuplicateControlAttributes(t *testing.T) {
	identity := "reauth-identity@example"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	nonceS := []byte("0123456789abcdef")
	for _, tc := range []struct {
		name  string
		extra []Attribute
	}{
		{
			name:  "counter",
			extra: []Attribute{CounterAttribute(13)},
		},
		{
			name:  "nonce_s",
			extra: []Attribute{NonceSAttribute([]byte("fedcba9876543210"))},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := signedReauthenticationRequest(t, keys, 12, nonceS, tc.extra)
			_, err := ParseReauthenticationRequest(request, keys)
			if !errors.Is(err, ErrInvalidAttribute) {
				t.Fatalf("ParseReauthenticationRequest() err=%v, want ErrInvalidAttribute", err)
			}
		})
	}
}

func TestParseReauthenticationRequestRejectsDuplicateCryptoAttributes(t *testing.T) {
	identity := "reauth-identity@example"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	nonceS := []byte("0123456789abcdef")
	for _, tc := range []struct {
		name  string
		extra Attribute
	}{
		{
			name:  "iv",
			extra: IVAttribute(bytes.Repeat([]byte{0x99}, 16)),
		},
		{
			name:  "encrypted_data",
			extra: EncrDataAttribute(bytes.Repeat([]byte{0x77}, 16)),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := signedReauthenticationRequestWithOptions(t, TypeAKA, keys, 12, nonceS, nil, []Attribute{tc.extra})
			_, err := ParseReauthenticationRequest(request, keys)
			if !errors.Is(err, ErrInvalidAttribute) {
				t.Fatalf("ParseReauthenticationRequest() err=%v, want ErrInvalidAttribute", err)
			}
		})
	}
}

func TestDeriveReauthenticationKeys(t *testing.T) {
	identity := "reauth-identity@example"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	nonceS := []byte("0123456789abcdef")
	next, err := DeriveReauthenticationKeys(identity, keys, 12, nonceS)
	if err != nil {
		t.Fatalf("DeriveReauthenticationKeys() error = %v", err)
	}
	if len(next.MSK) != KeyLengthMSK || len(next.EMSK) != KeyLengthEMSK {
		t.Fatalf("reauth key lengths MSK=%d EMSK=%d", len(next.MSK), len(next.EMSK))
	}
	if !bytes.Equal(next.MK, keys.MK) || !bytes.Equal(next.KEncr, keys.KEncr) || !bytes.Equal(next.KAut, keys.KAut) {
		t.Fatalf("reauth keys did not preserve MK/TEKs")
	}
	if bytes.Equal(next.MSK, keys.MSK) || bytes.Equal(next.EMSK, keys.EMSK) {
		t.Fatal("reauth MSK/EMSK should differ from full-auth MSK/EMSK")
	}
	again, err := DeriveReauthenticationKeys(identity, keys, 12, nonceS)
	if err != nil {
		t.Fatalf("DeriveReauthenticationKeys(again) error = %v", err)
	}
	if !bytes.Equal(again.MSK, next.MSK) || !bytes.Equal(again.EMSK, next.EMSK) {
		t.Fatal("reauth derivation is not deterministic")
	}
}

func TestDeriveReauthenticationKeysRejectsInvalidTEKs(t *testing.T) {
	nonceS := []byte("0123456789abcdef")
	keys := Keys{
		MK:    bytes.Repeat([]byte{0xaa}, 20),
		KEncr: bytes.Repeat([]byte{0x11}, 16),
		KAut:  bytes.Repeat([]byte{0x22}, 16),
	}
	keys.KEncr = keys.KEncr[:15]
	if _, err := DeriveReauthenticationKeys("identity", keys, 1, nonceS); !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("DeriveReauthenticationKeys(short K_encr) err=%v, want ErrInvalidKeyMaterial", err)
	}

	keys.KEncr = bytes.Repeat([]byte{0x11}, 16)
	keys.KAut = keys.KAut[:15]
	if _, err := DeriveReauthenticationKeys("identity", keys, 1, nonceS); !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("DeriveReauthenticationKeys(short K_aut) err=%v, want ErrInvalidKeyMaterial", err)
	}

	keys.KAut = bytes.Repeat([]byte{0x22}, 16)
	keys.KRe = bytes.Repeat([]byte{0x33}, 32)
	if _, err := DeriveReauthenticationKeys("identity", keys, 1, nonceS); !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("DeriveReauthenticationKeys(AKA' short K_aut) err=%v, want ErrInvalidKeyMaterial", err)
	}
}

func TestDeriveAKAPrimeReauthenticationKeys(t *testing.T) {
	fullIdentity := "0555444333222111"
	reauthIdentity := "reauth-prime@example"
	networkName := "WLAN"
	autn := mustHex(t, "bb52e91c747ac3ab2a5c23d15ee351d5")
	aka := sim.AKAResult{
		RES: mustHex(t, "28d7b0f2a2ec3de5"),
		IK:  mustHex(t, "9744871ad32bf9bbd1dd5ce54e3e2e5a"),
		CK:  mustHex(t, "5349fbe098649f948f5d2e973a81c00f"),
	}
	keys, err := DeriveAKAPrimeKeys(fullIdentity, networkName, autn, aka)
	if err != nil {
		t.Fatalf("DeriveAKAPrimeKeys() error = %v", err)
	}
	nonceS := []byte("fedcba9876543210")
	next, err := DeriveReauthenticationKeys(reauthIdentity, keys, 23, nonceS)
	if err != nil {
		t.Fatalf("DeriveReauthenticationKeys(AKA') error = %v", err)
	}
	if len(next.MK) != KeyLengthMSK+KeyLengthEMSK || len(next.MSK) != KeyLengthMSK || len(next.EMSK) != KeyLengthEMSK {
		t.Fatalf("AKA' reauth key lengths MK=%d MSK=%d EMSK=%d", len(next.MK), len(next.MSK), len(next.EMSK))
	}
	if !bytes.Equal(next.KRe, keys.KRe) || !bytes.Equal(next.KEncr, keys.KEncr) || !bytes.Equal(next.KAut, keys.KAut) {
		t.Fatalf("AKA' reauth keys did not preserve K_re/TEKs")
	}
	if bytes.Equal(next.MSK, keys.MSK) || bytes.Equal(next.EMSK, keys.EMSK) {
		t.Fatal("AKA' reauth MSK/EMSK should differ from full-auth MSK/EMSK")
	}
	again, err := DeriveReauthenticationKeys(reauthIdentity, keys, 23, nonceS)
	if err != nil {
		t.Fatalf("DeriveReauthenticationKeys(AKA' again) error = %v", err)
	}
	if !bytes.Equal(again.MSK, next.MSK) || !bytes.Equal(again.EMSK, next.EMSK) {
		t.Fatal("AKA' reauth derivation is not deterministic")
	}
}

func TestBuildReauthenticationResponse(t *testing.T) {
	identity := "reauth-identity@example"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	nonceS := []byte("0123456789abcdef")
	request := signedReauthenticationRequestWithOptions(t, TypeAKA, keys, 12, nonceS, nil, []Attribute{ResultIndAttribute()})
	responseIV := bytes.Repeat([]byte{0x66}, 16)
	response, next, err := BuildReauthenticationResponse(identity, request, keys, responseIV)
	if err != nil {
		t.Fatalf("BuildReauthenticationResponse() error = %v", err)
	}
	if response.Code != CodeResponse || response.Identifier != request.Identifier || response.Type != TypeAKA || response.Subtype != SubtypeReauthentication {
		t.Fatalf("response=%+v", response)
	}
	if _, ok := FindAttribute(response.Attributes, AttributeResultInd); !ok {
		t.Fatal("missing echoed AT_RESULT_IND")
	}
	raw, err := response.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(response) error = %v", err)
	}
	if err := VerifyMAC(keys.KAut, raw, nonceS); err != nil {
		t.Fatalf("VerifyMAC(response) error = %v", err)
	}
	attrs := decryptedReauthenticationResponseAttributes(t, keys, response)
	counterAttr, ok := FindAttribute(attrs, AttributeCounter)
	if !ok {
		t.Fatalf("missing encrypted AT_COUNTER in attrs=%+v", attrs)
	}
	counter, err := counterAttr.CounterValue()
	if err != nil {
		t.Fatalf("CounterValue() error = %v", err)
	}
	if counter != 12 {
		t.Fatalf("encrypted counter=%d", counter)
	}
	if _, ok := FindAttribute(attrs, AttributeCounterTooSmall); ok {
		t.Fatal("normal reauth response included AT_COUNTER_TOO_SMALL")
	}
	derived, err := DeriveReauthenticationKeys(identity, keys, 12, nonceS)
	if err != nil {
		t.Fatalf("DeriveReauthenticationKeys() error = %v", err)
	}
	if !bytes.Equal(next.MSK, derived.MSK) || !bytes.Equal(next.EMSK, derived.EMSK) {
		t.Fatal("returned keys do not match reauth derivation")
	}
}

func TestBuildReauthenticationResponseWithCounterCheckAcceptsFreshCounter(t *testing.T) {
	identity := "reauth-identity@example"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	nonceS := []byte("0123456789abcdef")
	request := signedReauthenticationRequest(t, keys, 12, nonceS, nil)
	response, next, counterTooSmall, err := BuildReauthenticationResponseWithCounterCheck(identity, request, keys, bytes.Repeat([]byte{0x66}, 16), 11, true)
	if err != nil {
		t.Fatalf("BuildReauthenticationResponseWithCounterCheck() error = %v", err)
	}
	if counterTooSmall {
		t.Fatal("counterTooSmall=true, want accepted reauthentication")
	}
	raw, err := response.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(response) error = %v", err)
	}
	if err := VerifyMAC(keys.KAut, raw, nonceS); err != nil {
		t.Fatalf("VerifyMAC(response) error = %v", err)
	}
	attrs := decryptedReauthenticationResponseAttributes(t, keys, response)
	if _, ok := FindAttribute(attrs, AttributeCounterTooSmall); ok {
		t.Fatal("accepted reauth response included AT_COUNTER_TOO_SMALL")
	}
	derived, err := DeriveReauthenticationKeys(identity, keys, 12, nonceS)
	if err != nil {
		t.Fatalf("DeriveReauthenticationKeys() error = %v", err)
	}
	if !bytes.Equal(next.MSK, derived.MSK) || !bytes.Equal(next.EMSK, derived.EMSK) {
		t.Fatal("returned keys do not match reauth derivation")
	}
}

func TestBuildReauthenticationResponseWithCounterCheckRejectsStaleCounter(t *testing.T) {
	identity := "reauth-identity@example"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	nonceS := []byte("0123456789abcdef")
	request := signedReauthenticationRequest(t, keys, 12, nonceS, nil)
	response, next, counterTooSmall, err := BuildReauthenticationResponseWithCounterCheck("", request, keys, bytes.Repeat([]byte{0x88}, 16), 12, true)
	if err != nil {
		t.Fatalf("BuildReauthenticationResponseWithCounterCheck() error = %v", err)
	}
	if !counterTooSmall {
		t.Fatal("counterTooSmall=false, want stale counter rejection")
	}
	if !bytes.Equal(next.KAut, keys.KAut) || !bytes.Equal(next.KEncr, keys.KEncr) || !bytes.Equal(next.MSK, keys.MSK) {
		t.Fatal("counter-too-small response should keep existing keys")
	}
	raw, err := response.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(response) error = %v", err)
	}
	if err := VerifyMAC(keys.KAut, raw, nonceS); err != nil {
		t.Fatalf("VerifyMAC(response) error = %v", err)
	}
	attrs := decryptedReauthenticationResponseAttributes(t, keys, response)
	if tooSmall, ok := FindAttribute(attrs, AttributeCounterTooSmall); !ok {
		t.Fatalf("missing encrypted AT_COUNTER_TOO_SMALL in attrs=%+v", attrs)
	} else if err := tooSmall.CounterTooSmallValue(); err != nil {
		t.Fatalf("CounterTooSmallValue() error = %v", err)
	}
	counterAttr, ok := FindAttribute(attrs, AttributeCounter)
	if !ok {
		t.Fatalf("missing encrypted AT_COUNTER in attrs=%+v", attrs)
	}
	counter, err := counterAttr.CounterValue()
	if err != nil {
		t.Fatalf("CounterValue() error = %v", err)
	}
	if counter != 12 {
		t.Fatalf("encrypted counter=%d", counter)
	}
}

func TestBuildAKAPrimeReauthenticationResponse(t *testing.T) {
	fullIdentity := "0555444333222111"
	reauthIdentity := "reauth-prime@example"
	networkName := "WLAN"
	aka := sim.AKAResult{
		RES: mustHex(t, "28d7b0f2a2ec3de5"),
		IK:  mustHex(t, "9744871ad32bf9bbd1dd5ce54e3e2e5a"),
		CK:  mustHex(t, "5349fbe098649f948f5d2e973a81c00f"),
	}
	keys, err := DeriveAKAPrimeKeys(fullIdentity, networkName, mustHex(t, "bb52e91c747ac3ab2a5c23d15ee351d5"), aka)
	if err != nil {
		t.Fatalf("DeriveAKAPrimeKeys() error = %v", err)
	}
	nonceS := []byte("fedcba9876543210")
	request := signedReauthenticationRequestWithOptions(t, TypeAKAPrime, keys, 23, nonceS, nil, nil)
	response, next, err := BuildReauthenticationResponse(reauthIdentity, request, keys, bytes.Repeat([]byte{0x77}, 16))
	if err != nil {
		t.Fatalf("BuildReauthenticationResponse(AKA') error = %v", err)
	}
	if response.Code != CodeResponse || response.Type != TypeAKAPrime || response.Subtype != SubtypeReauthentication {
		t.Fatalf("response=%+v", response)
	}
	raw, err := response.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(response) error = %v", err)
	}
	if err := VerifyAKAPrimeMAC(keys.KAut, raw, nonceS); err != nil {
		t.Fatalf("VerifyAKAPrimeMAC(response) error = %v", err)
	}
	attrs := decryptedReauthenticationResponseAttributes(t, keys, response)
	counterAttr, ok := FindAttribute(attrs, AttributeCounter)
	if !ok {
		t.Fatalf("missing encrypted AT_COUNTER in attrs=%+v", attrs)
	}
	counter, err := counterAttr.CounterValue()
	if err != nil {
		t.Fatalf("CounterValue() error = %v", err)
	}
	if counter != 23 {
		t.Fatalf("encrypted counter=%d", counter)
	}
	if !bytes.Equal(next.KRe, keys.KRe) || bytes.Equal(next.MSK, keys.MSK) || bytes.Equal(next.EMSK, keys.EMSK) {
		t.Fatalf("AKA' reauth keys=%+v", next)
	}
}

func TestBuildReauthenticationCounterTooSmallResponse(t *testing.T) {
	identity := "reauth-identity@example"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	nonceS := []byte("0123456789abcdef")
	request := signedReauthenticationRequest(t, keys, 2, nonceS, nil)
	response, err := BuildReauthenticationCounterTooSmallResponse(request, keys, bytes.Repeat([]byte{0x88}, 16))
	if err != nil {
		t.Fatalf("BuildReauthenticationCounterTooSmallResponse() error = %v", err)
	}
	if response.Code != CodeResponse || response.Identifier != request.Identifier || response.Subtype != SubtypeReauthentication {
		t.Fatalf("response=%+v", response)
	}
	raw, err := response.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(response) error = %v", err)
	}
	if err := VerifyMAC(keys.KAut, raw, nonceS); err != nil {
		t.Fatalf("VerifyMAC(response) error = %v", err)
	}
	attrs := decryptedReauthenticationResponseAttributes(t, keys, response)
	if tooSmall, ok := FindAttribute(attrs, AttributeCounterTooSmall); !ok {
		t.Fatalf("missing encrypted AT_COUNTER_TOO_SMALL in attrs=%+v", attrs)
	} else if err := tooSmall.CounterTooSmallValue(); err != nil {
		t.Fatalf("CounterTooSmallValue() error = %v", err)
	}
	counterAttr, ok := FindAttribute(attrs, AttributeCounter)
	if !ok {
		t.Fatalf("missing encrypted AT_COUNTER in attrs=%+v", attrs)
	}
	counter, err := counterAttr.CounterValue()
	if err != nil {
		t.Fatalf("CounterValue() error = %v", err)
	}
	if counter != 2 {
		t.Fatalf("encrypted counter=%d", counter)
	}
}

func TestDecryptAttributesRejectsBadPadding(t *testing.T) {
	kEncr := bytes.Repeat([]byte{0x11}, 16)
	iv := bytes.Repeat([]byte{0x22}, 16)
	plaintext, err := MarshalAttributes([]Attribute{
		ResultIndAttribute(),
		NextPseudonymAttribute("abc"),
		{Type: AttributePadding, Data: []byte{0, 1}},
	})
	if err != nil {
		t.Fatalf("MarshalAttributes() error = %v", err)
	}
	block, err := aes.NewCipher(kEncr)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	_, err = DecryptAttributes(kEncr, iv, EncrDataAttribute(ciphertext))
	if !errors.Is(err, ErrInvalidEncryptedData) {
		t.Fatalf("DecryptAttributes() err=%v, want ErrInvalidEncryptedData", err)
	}
}

func TestDeriveAKAPrimeKeysRFC9048Vector(t *testing.T) {
	identity := "0555444333222111"
	networkName := "WLAN"
	autn := mustHex(t, "bb52e91c747ac3ab2a5c23d15ee351d5")
	aka := sim.AKAResult{
		RES: mustHex(t, "28d7b0f2a2ec3de5"),
		IK:  mustHex(t, "9744871ad32bf9bbd1dd5ce54e3e2e5a"),
		CK:  mustHex(t, "5349fbe098649f948f5d2e973a81c00f"),
	}
	keys, err := DeriveAKAPrimeKeys(identity, networkName, autn, aka)
	if err != nil {
		t.Fatalf("DeriveAKAPrimeKeys() error = %v", err)
	}
	assertHex(t, "CK'", keys.CKPrime, "0093962d0dd84aa5684b045c9edffa04")
	assertHex(t, "IK'", keys.IKPrime, "ccfc230ca74fcc96c0a5d61164f5a76c")
	assertHex(t, "K_encr", keys.KEncr, "766fa0a6c317174b812d52fbcd11a179")
	assertHex(t, "K_aut", keys.KAut, "0842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71ea")
	assertHex(t, "K_re", keys.KRe, "cf83aa8bc7e0aced892acc98e76a9b2095b558c7795c7094715cb3393aa7d17a")
	assertHex(t, "MSK", keys.MSK, "67c42d9aa56c1b79e295e3459fc3d187d42be0bf818d3070e362c5e967a4d544e8ecfe19358ab3039aff03b7c930588c055babee58a02650b067ec4e9347c75a")
	assertHex(t, "EMSK", keys.EMSK, "f861703cd775590e16c7679ea3874ada866311de290764d760cf76df647ea01c313f69924bdd7650ca9bac141ea075c4ef9e8029c0e290cdbad5638b63bc23fb")
}

func TestBuildAKAPrimeChallengeResponse(t *testing.T) {
	identity := "0555444333222111"
	networkName := "WLAN"
	aka := sim.AKAResult{
		RES: mustHex(t, "28d7b0f2a2ec3de5"),
		IK:  mustHex(t, "9744871ad32bf9bbd1dd5ce54e3e2e5a"),
		CK:  mustHex(t, "5349fbe098649f948f5d2e973a81c00f"),
	}
	req := signedAKAPrimeChallengeRequest(t, identity, networkName, aka)
	resp, keys, err := BuildChallengeResponse(identity, req, aka)
	if err != nil {
		t.Fatalf("BuildChallengeResponse(AKA') error = %v", err)
	}
	if resp.Type != TypeAKAPrime || resp.Code != CodeResponse || resp.Subtype != SubtypeChallenge {
		t.Fatalf("response=%+v", resp)
	}
	if len(keys.KAut) != KeyLengthAKAPrimeKAut || len(keys.KRe) != KeyLengthKRe {
		t.Fatalf("AKA' key lengths KAut=%d KRe=%d", len(keys.KAut), len(keys.KRe))
	}
	if _, ok := FindAttribute(resp.Attributes, AttributeRES); !ok {
		t.Fatal("missing AT_RES")
	}
	kdfAttr, ok := FindAttribute(resp.Attributes, AttributeKDF)
	if !ok {
		t.Fatal("missing AT_KDF")
	}
	kdf, err := kdfAttr.KDFValue()
	if err != nil {
		t.Fatalf("KDFValue() error = %v", err)
	}
	if kdf != AKAPrimeKDFDefault {
		t.Fatalf("AT_KDF=%d", kdf)
	}
	raw, err := resp.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if err := VerifyAKAPrimeMAC(keys.KAut, raw, nil); err != nil {
		t.Fatalf("VerifyAKAPrimeMAC(response) error = %v", err)
	}
}

func TestBuildAKAPrimeChallengeResponseRequiresKDFInput(t *testing.T) {
	identity := "0555444333222111"
	aka := sim.AKAResult{
		RES: mustHex(t, "28d7b0f2a2ec3de5"),
		IK:  mustHex(t, "9744871ad32bf9bbd1dd5ce54e3e2e5a"),
		CK:  mustHex(t, "5349fbe098649f948f5d2e973a81c00f"),
	}
	req := signedAKAPrimeChallengeRequest(t, identity, "WLAN", aka)
	var attrs []Attribute
	for _, attr := range req.Attributes {
		if attr.Type != AttributeKDFInput {
			attrs = append(attrs, attr)
		}
	}
	req.Attributes = attrs
	_, _, err := BuildChallengeResponse(identity, req, aka)
	if !errors.Is(err, ErrInvalidAKAChallenge) {
		t.Fatalf("BuildChallengeResponse() err=%v, want ErrInvalidAKAChallenge", err)
	}
}

func TestBuildAKAPrimeKDFNegotiationResponse(t *testing.T) {
	req := Packet{
		Code:       CodeRequest,
		Identifier: 12,
		Type:       TypeAKAPrime,
		Subtype:    SubtypeChallenge,
		Attributes: []Attribute{
			KDFAttribute(99),
			KDFAttribute(AKAPrimeKDFDefault),
			KDFInputAttribute("WLAN"),
		},
	}
	resp, negotiated, err := BuildAKAPrimeKDFNegotiationResponse(req)
	if err != nil {
		t.Fatalf("BuildAKAPrimeKDFNegotiationResponse() error = %v", err)
	}
	if !negotiated {
		t.Fatal("negotiated=false")
	}
	if resp.Code != CodeResponse || resp.Identifier != req.Identifier || resp.Type != TypeAKAPrime || resp.Subtype != SubtypeChallenge {
		t.Fatalf("response=%+v", resp)
	}
	if len(resp.Attributes) != 1 || resp.Attributes[0].Type != AttributeKDF {
		t.Fatalf("attributes=%+v, want only AT_KDF", resp.Attributes)
	}
	kdf, err := resp.Attributes[0].KDFValue()
	if err != nil {
		t.Fatalf("KDFValue() error = %v", err)
	}
	if kdf != AKAPrimeKDFDefault {
		t.Fatalf("AT_KDF=%d", kdf)
	}
}

func TestBuildAKAPrimeKDFNegotiationResponseSkipsWhenFirstSupported(t *testing.T) {
	resp, negotiated, err := BuildAKAPrimeKDFNegotiationResponse(Packet{
		Code:       CodeRequest,
		Identifier: 12,
		Type:       TypeAKAPrime,
		Subtype:    SubtypeChallenge,
		Attributes: []Attribute{KDFAttribute(AKAPrimeKDFDefault), KDFAttribute(99)},
	})
	if err != nil {
		t.Fatalf("BuildAKAPrimeKDFNegotiationResponse() error = %v", err)
	}
	if negotiated || resp.Code != 0 {
		t.Fatalf("response=%+v negotiated=%v, want no negotiation", resp, negotiated)
	}
}

func TestBuildAKAPrimeKDFNegotiationResponseRejectsUnsupportedOffer(t *testing.T) {
	_, _, err := BuildAKAPrimeKDFNegotiationResponse(Packet{
		Code:       CodeRequest,
		Identifier: 12,
		Type:       TypeAKAPrime,
		Subtype:    SubtypeChallenge,
		Attributes: []Attribute{KDFAttribute(99)},
	})
	if !errors.Is(err, ErrUnsupportedKDF) {
		t.Fatalf("BuildAKAPrimeKDFNegotiationResponse() err=%v, want ErrUnsupportedKDF", err)
	}
}

func TestBuildNotificationResponseBeforeAuthentication(t *testing.T) {
	req := Packet{
		Code:       CodeRequest,
		Identifier: 21,
		Type:       TypeAKA,
		Subtype:    SubtypeNotification,
		Attributes: []Attribute{NotificationAttribute(NotificationGeneralFailureBeforeAuthentication)},
	}
	resp, ok, err := BuildNotificationResponse(req)
	if err != nil {
		t.Fatalf("BuildNotificationResponse() error = %v", err)
	}
	if !ok {
		t.Fatal("ok=false")
	}
	if resp.Code != CodeResponse || resp.Identifier != req.Identifier || resp.Type != TypeAKA || resp.Subtype != SubtypeNotification {
		t.Fatalf("response=%+v", resp)
	}
	if len(resp.Attributes) != 0 {
		t.Fatalf("attributes=%+v, want empty pre-auth notification ack", resp.Attributes)
	}
	raw, err := resp.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if got, want := hex.EncodeToString(raw), "02150008170c0000"; got != want {
		t.Fatalf("notification response=%s, want %s", got, want)
	}
}

func TestBuildNotificationResponseAfterAuthenticationRequiresKeys(t *testing.T) {
	_, _, err := BuildNotificationResponse(Packet{
		Code:       CodeRequest,
		Identifier: 21,
		Type:       TypeAKA,
		Subtype:    SubtypeNotification,
		Attributes: []Attribute{NotificationAttribute(NotificationSuccess), MACAttribute(nil)},
	})
	if !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("BuildNotificationResponse() err=%v, want ErrInvalidKeyMaterial", err)
	}
}

func TestBuildAuthenticatedNotificationResponse(t *testing.T) {
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	req := Packet{
		Code:       CodeRequest,
		Identifier: 22,
		Type:       TypeAKA,
		Subtype:    SubtypeNotification,
		Attributes: []Attribute{NotificationAttribute(NotificationSuccess), MACAttribute(nil)},
	}
	raw, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(request) error = %v", err)
	}
	mac, err := CalculateMAC(keys.KAut, raw, nil)
	if err != nil {
		t.Fatalf("CalculateMAC(request) error = %v", err)
	}
	req.Attributes[len(req.Attributes)-1] = MACAttribute(mac)

	resp, ok, err := BuildAuthenticatedNotificationResponse(req, keys.KAut)
	if err != nil {
		t.Fatalf("BuildAuthenticatedNotificationResponse() error = %v", err)
	}
	if !ok {
		t.Fatal("ok=false")
	}
	if resp.Code != CodeResponse || resp.Identifier != req.Identifier || resp.Subtype != SubtypeNotification {
		t.Fatalf("response=%+v", resp)
	}
	if len(resp.Attributes) != 1 || resp.Attributes[0].Type != AttributeMAC {
		t.Fatalf("attributes=%+v, want AT_MAC", resp.Attributes)
	}
	raw, err = resp.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(response) error = %v", err)
	}
	if err := VerifyMAC(keys.KAut, raw, nil); err != nil {
		t.Fatalf("VerifyMAC(response) error = %v", err)
	}
}

func TestBuildClientErrorResponse(t *testing.T) {
	resp, err := BuildClientErrorResponse(Packet{
		Code:       CodeRequest,
		Identifier: 23,
		Type:       TypeAKAPrime,
		Subtype:    SubtypeReauthentication,
	}, ClientErrorUnableToProcessPacket)
	if err != nil {
		t.Fatalf("BuildClientErrorResponse() error = %v", err)
	}
	if resp.Code != CodeResponse || resp.Identifier != 23 || resp.Type != TypeAKAPrime || resp.Subtype != SubtypeClientError {
		t.Fatalf("response=%+v", resp)
	}
	attr, ok := FindAttribute(resp.Attributes, AttributeClientErrorCode)
	if !ok {
		t.Fatal("missing AT_CLIENT_ERROR_CODE")
	}
	code, err := attr.ClientErrorCodeValue()
	if err != nil {
		t.Fatalf("ClientErrorCodeValue() error = %v", err)
	}
	if code != ClientErrorUnableToProcessPacket {
		t.Fatalf("client error=%d", code)
	}
}

func TestBuildChallengeResponseRejectsBadRequestMAC(t *testing.T) {
	identity := "user@example.com"
	aka := sim.AKAResult{RES: []byte{1, 2, 3, 4}, CK: bytes.Repeat([]byte{2}, 16), IK: bytes.Repeat([]byte{3}, 16)}
	req := signedChallengeRequest(t, identity, aka)
	req.Attributes[len(req.Attributes)-1] = MACAttribute(bytes.Repeat([]byte{0xff}, 16))
	_, _, err := BuildChallengeResponse(identity, req, aka)
	if !errors.Is(err, ErrInvalidMAC) {
		t.Fatalf("BuildChallengeResponse() err=%v, want ErrInvalidMAC", err)
	}
}

func TestBuildChallengeResponseRejectsDuplicateRequestMAC(t *testing.T) {
	identity := "user@example.com"
	aka := sim.AKAResult{RES: []byte{1, 2, 3, 4}, CK: bytes.Repeat([]byte{2}, 16), IK: bytes.Repeat([]byte{3}, 16)}
	req := signedChallengeRequest(t, identity, aka)
	req.Attributes = append(req.Attributes, req.Attributes[len(req.Attributes)-1])
	_, _, err := BuildChallengeResponse(identity, req, aka)
	if !errors.Is(err, ErrInvalidMAC) {
		t.Fatalf("BuildChallengeResponse(duplicate AT_MAC) err=%v, want ErrInvalidMAC", err)
	}
}

func TestBuildChallengeResponseRejectsDuplicateCheckcode(t *testing.T) {
	identity := "user@example.com"
	aka := sim.AKAResult{RES: []byte{1, 2, 3, 4}, CK: bytes.Repeat([]byte{2}, 16), IK: bytes.Repeat([]byte{3}, 16)}
	transcript := identityTranscriptPackets(t, identity)
	req := signedChallengeRequestWithCheckcode(t, identity, aka, transcript)
	checkcode, ok := FindAttribute(req.Attributes, AttributeCheckcode)
	if !ok {
		t.Fatal("missing test AT_CHECKCODE")
	}
	req.Attributes = append(req.Attributes[:len(req.Attributes)-1], checkcode, req.Attributes[len(req.Attributes)-1])
	_, _, err := BuildChallengeResponseWithCheckcode(identity, req, aka, transcript)
	if !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("BuildChallengeResponseWithCheckcode(duplicate AT_CHECKCODE) err=%v, want ErrInvalidAttribute", err)
	}
}

func TestBuildChallengeResponseRejectsMissingRAND(t *testing.T) {
	identity := "user@example.com"
	aka := sim.AKAResult{RES: []byte{1, 2, 3, 4}, CK: bytes.Repeat([]byte{2}, 16), IK: bytes.Repeat([]byte{3}, 16)}
	req := Packet{
		Code:       CodeRequest,
		Identifier: 7,
		Type:       TypeAKA,
		Subtype:    SubtypeChallenge,
		Attributes: []Attribute{
			AUTNAttribute(bytes.Repeat([]byte{0xb2}, 16)),
			MACAttribute(nil),
		},
	}
	_, _, err := BuildChallengeResponse(identity, req, aka)
	if !errors.Is(err, ErrInvalidAKAChallenge) {
		t.Fatalf("BuildChallengeResponse(missing RAND) err=%v, want ErrInvalidAKAChallenge", err)
	}
}

func TestBuildChallengeResponseFromProviderSuccess(t *testing.T) {
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	req := signedChallengeRequest(t, identity, aka)
	var gotRAND, gotAUTN []byte
	result, err := BuildChallengeResponseFromProvider(identity, req, challengeAKAProviderFunc(func(rand16, autn16 []byte) (sim.AKAResult, error) {
		gotRAND = append([]byte(nil), rand16...)
		gotAUTN = append([]byte(nil), autn16...)
		return aka, nil
	}), nil)
	if err != nil {
		t.Fatalf("BuildChallengeResponseFromProvider() error = %v", err)
	}
	if result.SyncFailure || result.AuthFailure || result.BiddingDown {
		t.Fatalf("unexpected failure flags: %+v", result)
	}
	if !bytes.Equal(gotRAND, bytes.Repeat([]byte{0xa1}, 16)) || !bytes.Equal(gotAUTN, bytes.Repeat([]byte{0xb2}, 16)) {
		t.Fatalf("provider RAND=%x AUTN=%x", gotRAND, gotAUTN)
	}
	if !bytes.Equal(result.RAND, gotRAND) || !bytes.Equal(result.AUTN, gotAUTN) {
		t.Fatalf("result RAND=%x AUTN=%x", result.RAND, result.AUTN)
	}
	if !bytes.Equal(result.AKA.RES, aka.RES) || len(result.Keys.KAut) != KeyLengthKAut {
		t.Fatalf("result AKA=%+v keys=%+v", result.AKA, result.Keys)
	}
	raw, err := result.Response.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(response) error = %v", err)
	}
	if err := VerifyMAC(result.Keys.KAut, raw, nil); err != nil {
		t.Fatalf("VerifyMAC(response) error = %v", err)
	}
}

func TestBuildChallengeResponseFromProviderSyncFailure(t *testing.T) {
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	req := signedChallengeRequest(t, identity, aka)
	wantAUTS := bytes.Repeat([]byte{0xee}, AUTSLength)
	result, err := BuildChallengeResponseFromProvider(identity, req, challengeAKAProviderFunc(func(rand16, autn16 []byte) (sim.AKAResult, error) {
		return sim.AKAResult{AUTS: wantAUTS}, sim.ErrSyncFailure
	}), nil)
	if err != nil {
		t.Fatalf("BuildChallengeResponseFromProvider(sync) error = %v", err)
	}
	if !result.SyncFailure || result.AuthFailure || result.Response.Subtype != SubtypeSynchronizationFailure {
		t.Fatalf("sync result=%+v", result)
	}
	attr, ok := FindAttribute(result.Response.Attributes, AttributeAUTS)
	if !ok {
		t.Fatal("missing AT_AUTS")
	}
	auts, err := attr.AUTSValue()
	if err != nil {
		t.Fatalf("AUTSValue() error = %v", err)
	}
	if !bytes.Equal(auts, wantAUTS) {
		t.Fatalf("AUTS=%x", auts)
	}
}

func TestBuildChallengeResponseFromProviderAuthFailure(t *testing.T) {
	identity := "310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	req := signedChallengeRequest(t, identity, aka)
	result, err := BuildChallengeResponseFromProvider(identity, req, challengeAKAProviderFunc(func(rand16, autn16 []byte) (sim.AKAResult, error) {
		return sim.AKAResult{}, sim.ErrAuthFailure
	}), nil)
	if err != nil {
		t.Fatalf("BuildChallengeResponseFromProvider(auth) error = %v", err)
	}
	if result.SyncFailure || !result.AuthFailure || result.Response.Subtype != SubtypeAuthenticationReject {
		t.Fatalf("auth result=%+v", result)
	}
	if len(result.Response.Attributes) != 0 {
		t.Fatalf("auth reject attributes=%+v", result.Response.Attributes)
	}
}

func TestBuildChallengeResponseFromProviderRejectsNilProvider(t *testing.T) {
	_, err := BuildChallengeResponseFromProvider("identity", Packet{Code: CodeRequest, Type: TypeAKA, Subtype: SubtypeChallenge}, nil, nil)
	if !errors.Is(err, ErrInvalidAKAChallenge) {
		t.Fatalf("BuildChallengeResponseFromProvider(nil) err=%v, want ErrInvalidAKAChallenge", err)
	}
}

func TestDeriveKeysRejectsInvalidAKAInputLengths(t *testing.T) {
	valid := sim.AKAResult{
		RES: []byte{1, 2, 3, 4},
		CK:  bytes.Repeat([]byte{0xc1}, 16),
		IK:  bytes.Repeat([]byte{0xd2}, 16),
	}
	if _, err := DeriveKeys("identity", sim.AKAResult{CK: bytes.Repeat([]byte{0xc1}, 15), IK: valid.IK}); !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("DeriveKeys(short CK) err=%v, want ErrInvalidKeyMaterial", err)
	}
	if _, err := DeriveKeys("identity", sim.AKAResult{CK: valid.CK, IK: bytes.Repeat([]byte{0xd2}, 15)}); !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("DeriveKeys(short IK) err=%v, want ErrInvalidKeyMaterial", err)
	}
	if _, err := DeriveAKAPrimeKeys("identity", "WLAN", bytes.Repeat([]byte{0xb2}, 15), valid); !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("DeriveAKAPrimeKeys(short AUTN) err=%v, want ErrInvalidKeyMaterial", err)
	}
	if _, err := DeriveAKAPrimeKeys("identity", "WLAN", bytes.Repeat([]byte{0xb2}, 16), sim.AKAResult{CK: valid.CK, IK: bytes.Repeat([]byte{0xd2}, 17)}); !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("DeriveAKAPrimeKeys(long IK) err=%v, want ErrInvalidKeyMaterial", err)
	}
}

func TestBuildChallengeResponseRejectsInvalidRESLength(t *testing.T) {
	identity := "user@example.com"
	aka := sim.AKAResult{RES: []byte{1, 2, 3}, CK: bytes.Repeat([]byte{2}, 16), IK: bytes.Repeat([]byte{3}, 16)}
	req := signedChallengeRequest(t, identity, aka)
	_, _, err := BuildChallengeResponse(identity, req, aka)
	if !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("BuildChallengeResponse(short RES) err=%v, want ErrInvalidKeyMaterial", err)
	}
}

func TestMACRejectsInvalidKAutLength(t *testing.T) {
	raw, err := (Packet{
		Code:       CodeResponse,
		Identifier: 1,
		Type:       TypeAKA,
		Subtype:    SubtypeChallenge,
		Attributes: []Attribute{MACAttribute(nil)},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if _, err := CalculateMAC(bytes.Repeat([]byte{0x01}, 15), raw, nil); !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("CalculateMAC(short K_aut) err=%v, want ErrInvalidKeyMaterial", err)
	}
	if _, err := CalculateAKAPrimeMAC(bytes.Repeat([]byte{0x01}, 16), raw, nil); !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("CalculateAKAPrimeMAC(short K_aut) err=%v, want ErrInvalidKeyMaterial", err)
	}
}

func TestMACRejectsDuplicateATMAC(t *testing.T) {
	raw, err := (Packet{
		Code:       CodeResponse,
		Identifier: 1,
		Type:       TypeAKA,
		Subtype:    SubtypeChallenge,
		Attributes: []Attribute{MACAttribute(nil), MACAttribute(nil)},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	kAut := bytes.Repeat([]byte{0x01}, KeyLengthKAut)
	if _, err := CalculateMAC(kAut, raw, nil); !errors.Is(err, ErrInvalidMAC) {
		t.Fatalf("CalculateMAC(duplicate AT_MAC) err=%v, want ErrInvalidMAC", err)
	}
	if err := VerifyMAC(kAut, raw, nil); !errors.Is(err, ErrInvalidMAC) {
		t.Fatalf("VerifyMAC(duplicate AT_MAC) err=%v, want ErrInvalidMAC", err)
	}
}

func TestBuildSynchronizationFailureResponse(t *testing.T) {
	req := Packet{Code: CodeRequest, Identifier: 3, Type: TypeAKA, Subtype: SubtypeChallenge}
	wantAUTS := bytes.Repeat([]byte{0xaa}, 14)
	resp, err := BuildSynchronizationFailureResponse(req, wantAUTS)
	if err != nil {
		t.Fatalf("BuildSynchronizationFailureResponse() error = %v", err)
	}
	if resp.Code != CodeResponse || resp.Subtype != SubtypeSynchronizationFailure {
		t.Fatalf("response=%+v", resp)
	}
	attr, ok := FindAttribute(resp.Attributes, AttributeAUTS)
	if !ok {
		t.Fatal("missing AT_AUTS")
	}
	auts, err := attr.AUTSValue()
	if err != nil {
		t.Fatalf("AUTSValue() error = %v", err)
	}
	if !bytes.Equal(auts, wantAUTS) {
		t.Fatalf("AUTS=%x", auts)
	}
}

func TestBuildAKAFailureResponse(t *testing.T) {
	req := Packet{Code: CodeRequest, Identifier: 3, Type: TypeAKA, Subtype: SubtypeChallenge}
	wantAUTS := bytes.Repeat([]byte{0xaa}, 14)

	resp, handled, err := BuildAKAFailureResponse(req, sim.AKAResult{AUTS: wantAUTS}, sim.ErrSyncFailure)
	if err != nil {
		t.Fatalf("BuildAKAFailureResponse(sync) error = %v", err)
	}
	if !handled || resp.Subtype != SubtypeSynchronizationFailure {
		t.Fatalf("sync failure handled=%t response=%+v", handled, resp)
	}
	attr, ok := FindAttribute(resp.Attributes, AttributeAUTS)
	if !ok {
		t.Fatal("missing AT_AUTS")
	}
	auts, err := attr.AUTSValue()
	if err != nil {
		t.Fatalf("AUTSValue() error = %v", err)
	}
	if !bytes.Equal(auts, wantAUTS) {
		t.Fatalf("AUTS=%x", auts)
	}

	resp, handled, err = BuildAKAFailureResponse(req, sim.AKAResult{}, sim.ErrAuthFailure)
	if err != nil {
		t.Fatalf("BuildAKAFailureResponse(auth) error = %v", err)
	}
	if !handled || resp.Subtype != SubtypeAuthenticationReject {
		t.Fatalf("auth failure handled=%t response=%+v", handled, resp)
	}

	sentinel := errors.New("aka transport failure")
	_, handled, err = BuildAKAFailureResponse(req, sim.AKAResult{}, sentinel)
	if handled || !errors.Is(err, sentinel) {
		t.Fatalf("unknown failure handled=%t err=%v", handled, err)
	}
	_, handled, err = BuildAKAFailureResponse(req, sim.AKAResult{}, nil)
	if handled || err != nil {
		t.Fatalf("nil failure handled=%t err=%v", handled, err)
	}
}

func TestBuildSynchronizationFailureResponseRejectsInvalidAUTS(t *testing.T) {
	req := Packet{Code: CodeRequest, Identifier: 3, Type: TypeAKA, Subtype: SubtypeChallenge}
	if _, err := BuildSynchronizationFailureResponse(req, bytes.Repeat([]byte{0xaa}, 13)); !errors.Is(err, ErrInvalidAKAChallenge) {
		t.Fatalf("BuildSynchronizationFailureResponse(short AUTS) err=%v, want ErrInvalidAKAChallenge", err)
	}
	req.Type = 99
	if _, err := BuildSynchronizationFailureResponse(req, bytes.Repeat([]byte{0xaa}, 14)); !errors.Is(err, ErrInvalidAKAChallenge) {
		t.Fatalf("BuildSynchronizationFailureResponse(bad type) err=%v, want ErrInvalidAKAChallenge", err)
	}
}

func TestBuildAuthenticationRejectResponse(t *testing.T) {
	req := Packet{Code: CodeRequest, Identifier: 4, Type: TypeAKA, Subtype: SubtypeChallenge}
	resp, err := BuildAuthenticationRejectResponse(req)
	if err != nil {
		t.Fatalf("BuildAuthenticationRejectResponse() error = %v", err)
	}
	if resp.Code != CodeResponse || resp.Identifier != 4 || resp.Type != TypeAKA || resp.Subtype != SubtypeAuthenticationReject || len(resp.Attributes) != 0 {
		t.Fatalf("response=%+v", resp)
	}
}

func TestBuildSynchronizationFailureResponseCopiesAKAPrimeKDF(t *testing.T) {
	req := Packet{
		Code:    CodeRequest,
		Type:    TypeAKAPrime,
		Subtype: SubtypeChallenge,
		Attributes: []Attribute{
			KDFInputAttribute("WLAN"),
			KDFAttribute(AKAPrimeKDFDefault),
		},
	}
	resp, err := BuildSynchronizationFailureResponse(req, bytes.Repeat([]byte{0xaa}, 14))
	if err != nil {
		t.Fatalf("BuildSynchronizationFailureResponse() error = %v", err)
	}
	if _, ok := FindAttribute(resp.Attributes, AttributeAUTS); !ok {
		t.Fatal("missing AT_AUTS")
	}
	kdfAttr, ok := FindAttribute(resp.Attributes, AttributeKDF)
	if !ok {
		t.Fatal("missing copied AT_KDF")
	}
	kdf, err := kdfAttr.KDFValue()
	if err != nil {
		t.Fatalf("KDFValue() error = %v", err)
	}
	if kdf != AKAPrimeKDFDefault {
		t.Fatalf("copied AT_KDF=%d", kdf)
	}
	if _, ok := FindAttribute(resp.Attributes, AttributeKDFInput); ok {
		t.Fatal("AKA' sync failure must copy AT_KDF, not AT_KDF_INPUT")
	}
}

func TestChallengeRANDAndAUTNRejectsInvalidAttributes(t *testing.T) {
	req := Packet{
		Code:    CodeRequest,
		Type:    TypeAKA,
		Subtype: SubtypeChallenge,
		Attributes: []Attribute{
			RANDAttribute(bytes.Repeat([]byte{0xa1}, 16), bytes.Repeat([]byte{0xa2}, 16)),
			AUTNAttribute(bytes.Repeat([]byte{0xb2}, 16)),
		},
	}
	if _, _, err := ChallengeRANDAndAUTN(req); !errors.Is(err, ErrInvalidAKAChallenge) {
		t.Fatalf("ChallengeRANDAndAUTN(two RANDs) err=%v, want ErrInvalidAKAChallenge", err)
	}

	req.Attributes = []Attribute{
		RANDAttribute(bytes.Repeat([]byte{0xa1}, 16)),
		AUTNAttribute(bytes.Repeat([]byte{0xb2}, 15)),
	}
	if _, _, err := ChallengeRANDAndAUTN(req); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("ChallengeRANDAndAUTN(short AUTN) err=%v, want ErrInvalidAttribute", err)
	}

	req.Attributes = []Attribute{
		RANDAttribute(bytes.Repeat([]byte{0xa1}, 16)),
		AUTNAttribute(bytes.Repeat([]byte{0xb2}, 16)),
		{Type: AttributeResultInd, Data: []byte{0x00, 0x01}},
	}
	if _, _, err := ChallengeRANDAndAUTN(req); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("ChallengeRANDAndAUTN(bad result-ind) err=%v, want ErrInvalidAttribute", err)
	}

	req.Subtype = SubtypeIdentity
	if _, _, err := ChallengeRANDAndAUTN(req); !errors.Is(err, ErrInvalidAKAChallenge) {
		t.Fatalf("ChallengeRANDAndAUTN(non-challenge) err=%v, want ErrInvalidAKAChallenge", err)
	}
}

func signedChallengeRequest(t *testing.T, identity string, aka sim.AKAResult) Packet {
	t.Helper()
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	req := Packet{
		Code:       CodeRequest,
		Identifier: 7,
		Type:       TypeAKA,
		Subtype:    SubtypeChallenge,
		Attributes: []Attribute{
			RANDAttribute(bytes.Repeat([]byte{0xa1}, 16)),
			AUTNAttribute(bytes.Repeat([]byte{0xb2}, 16)),
			MACAttribute(nil),
		},
	}
	raw, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	mac, err := CalculateMAC(keys.KAut, raw, nil)
	if err != nil {
		t.Fatalf("CalculateMAC() error = %v", err)
	}
	req.Attributes[len(req.Attributes)-1] = MACAttribute(mac)
	return req
}

type challengeAKAProviderFunc func(rand16, autn16 []byte) (sim.AKAResult, error)

func (f challengeAKAProviderFunc) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	return f(rand16, autn16)
}

func signedChallengeRequestWithCheckcode(t *testing.T, identity string, aka sim.AKAResult, transcript [][]byte) Packet {
	t.Helper()
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	req := Packet{
		Code:       CodeRequest,
		Identifier: 7,
		Type:       TypeAKA,
		Subtype:    SubtypeChallenge,
		Attributes: []Attribute{
			RANDAttribute(bytes.Repeat([]byte{0xa1}, 16)),
			AUTNAttribute(bytes.Repeat([]byte{0xb2}, 16)),
			CheckcodeAttributeForPackets(transcript),
			MACAttribute(nil),
		},
	}
	raw, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	mac, err := CalculateMAC(keys.KAut, raw, nil)
	if err != nil {
		t.Fatalf("CalculateMAC() error = %v", err)
	}
	req.Attributes[len(req.Attributes)-1] = MACAttribute(mac)
	return req
}

func signedChallengeRequestWithResultInd(t *testing.T, identity string, aka sim.AKAResult) Packet {
	t.Helper()
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	req := Packet{
		Code:       CodeRequest,
		Identifier: 7,
		Type:       TypeAKA,
		Subtype:    SubtypeChallenge,
		Attributes: []Attribute{
			RANDAttribute(bytes.Repeat([]byte{0xa1}, 16)),
			AUTNAttribute(bytes.Repeat([]byte{0xb2}, 16)),
			ResultIndAttribute(),
			MACAttribute(nil),
		},
	}
	raw, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	mac, err := CalculateMAC(keys.KAut, raw, nil)
	if err != nil {
		t.Fatalf("CalculateMAC() error = %v", err)
	}
	req.Attributes[len(req.Attributes)-1] = MACAttribute(mac)
	return req
}

func signedChallengeRequestWithEncryptedAttrs(t *testing.T, identity string, aka sim.AKAResult, attrs ...Attribute) Packet {
	t.Helper()
	keys, err := DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	challengeAttrs := []Attribute{
		RANDAttribute(bytes.Repeat([]byte{0xa1}, 16)),
		AUTNAttribute(bytes.Repeat([]byte{0xb2}, 16)),
	}
	challengeAttrs = append(challengeAttrs, attrs...)
	challengeAttrs = append(challengeAttrs, MACAttribute(nil))
	req := Packet{
		Code:       CodeRequest,
		Identifier: 7,
		Type:       TypeAKA,
		Subtype:    SubtypeChallenge,
		Attributes: challengeAttrs,
	}
	raw, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	mac, err := CalculateMAC(keys.KAut, raw, nil)
	if err != nil {
		t.Fatalf("CalculateMAC() error = %v", err)
	}
	req.Attributes[len(req.Attributes)-1] = MACAttribute(mac)
	return req
}

func signedReauthenticationRequest(t *testing.T, keys Keys, counter uint16, nonceS []byte, extra []Attribute) Packet {
	t.Helper()
	return signedReauthenticationRequestWithOptions(t, TypeAKA, keys, counter, nonceS, extra, nil)
}

func signedReauthenticationRequestWithOptions(t *testing.T, eapType uint8, keys Keys, counter uint16, nonceS []byte, encryptedExtra, topLevelExtra []Attribute) Packet {
	t.Helper()
	iv := bytes.Repeat([]byte{0x55}, 16)
	encryptedAttrs := []Attribute{CounterAttribute(counter), NonceSAttribute(nonceS)}
	encryptedAttrs = append(encryptedAttrs, encryptedExtra...)
	encrypted, err := EncryptAttributes(keys.KEncr, iv, encryptedAttrs)
	if err != nil {
		t.Fatalf("EncryptAttributes() error = %v", err)
	}
	attrs := []Attribute{
		IVAttribute(iv),
		encrypted,
	}
	attrs = append(attrs, topLevelExtra...)
	attrs = append(attrs, MACAttribute(nil))
	req := Packet{
		Code:       CodeRequest,
		Identifier: 15,
		Type:       eapType,
		Subtype:    SubtypeReauthentication,
		Attributes: attrs,
	}
	raw, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	mac, err := calculatePacketMAC(eapType, keys.KAut, raw, nil)
	if err != nil {
		t.Fatalf("calculatePacketMAC() error = %v", err)
	}
	req.Attributes[len(req.Attributes)-1] = MACAttribute(mac)
	return req
}

func decryptedReauthenticationResponseAttributes(t *testing.T, keys Keys, response Packet) []Attribute {
	t.Helper()
	ivAttr, ok := FindAttribute(response.Attributes, AttributeIV)
	if !ok {
		t.Fatal("missing response AT_IV")
	}
	encryptedAttr, ok := FindAttribute(response.Attributes, AttributeEncrData)
	if !ok {
		t.Fatal("missing response AT_ENCR_DATA")
	}
	attrs, err := DecryptEncryptedAttributes(keys.KEncr, ivAttr, encryptedAttr)
	if err != nil {
		t.Fatalf("DecryptEncryptedAttributes(response) error = %v", err)
	}
	return attrs
}

func identityTranscriptPackets(t *testing.T, identity string) [][]byte {
	t.Helper()
	request, err := (Packet{
		Code:       CodeRequest,
		Identifier: 6,
		Type:       TypeAKA,
		Subtype:    SubtypeIdentity,
		Attributes: []Attribute{FullAuthIDReqAttribute()},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(request) error = %v", err)
	}
	response, err := (Packet{
		Code:       CodeResponse,
		Identifier: 6,
		Type:       TypeAKA,
		Subtype:    SubtypeIdentity,
		Attributes: []Attribute{IdentityAttribute(identity)},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(response) error = %v", err)
	}
	return [][]byte{request, response}
}

func signedAKAPrimeChallengeRequest(t *testing.T, identity, networkName string, aka sim.AKAResult) Packet {
	t.Helper()
	autn := mustHex(t, "bb52e91c747ac3ab2a5c23d15ee351d5")
	keys, err := DeriveAKAPrimeKeys(identity, networkName, autn, aka)
	if err != nil {
		t.Fatalf("DeriveAKAPrimeKeys() error = %v", err)
	}
	req := Packet{
		Code:       CodeRequest,
		Identifier: 9,
		Type:       TypeAKAPrime,
		Subtype:    SubtypeChallenge,
		Attributes: []Attribute{
			RANDAttribute(mustHex(t, "81e92b6c0ee0e12ebceba8d92a99dfa5")),
			AUTNAttribute(autn),
			KDFInputAttribute(networkName),
			KDFAttribute(AKAPrimeKDFDefault),
			MACAttribute(nil),
		},
	}
	raw, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	mac, err := CalculateAKAPrimeMAC(keys.KAut, raw, nil)
	if err != nil {
		t.Fatalf("CalculateAKAPrimeMAC() error = %v", err)
	}
	req.Attributes[len(req.Attributes)-1] = MACAttribute(mac)
	return req
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) error = %v", value, err)
	}
	return out
}

func assertHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if !bytes.Equal(got, mustHex(t, want)) {
		t.Fatalf("%s=%x, want %s", name, got, want)
	}
}
