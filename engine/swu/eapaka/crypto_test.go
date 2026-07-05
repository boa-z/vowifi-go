package eapaka

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/iniwex5/vowifi-go/engine/sim"
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

func TestEncryptDecryptAttributes(t *testing.T) {
	kEncr := bytes.Repeat([]byte{0x11}, 16)
	iv := bytes.Repeat([]byte{0x22}, 16)
	attrs := []Attribute{
		VariableAttribute(AttributeNextPseudonym, []byte("pseudo-123")),
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

func TestDecryptAttributesRejectsBadPadding(t *testing.T) {
	kEncr := bytes.Repeat([]byte{0x11}, 16)
	iv := bytes.Repeat([]byte{0x22}, 16)
	plaintext, err := MarshalAttributes([]Attribute{
		ResultIndAttribute(),
		VariableAttribute(AttributeNextPseudonym, []byte("abc")),
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
	aka := sim.AKAResult{RES: []byte{1}, CK: bytes.Repeat([]byte{2}, 16), IK: bytes.Repeat([]byte{3}, 16)}
	req := signedChallengeRequest(t, identity, aka)
	req.Attributes[len(req.Attributes)-1] = MACAttribute(bytes.Repeat([]byte{0xff}, 16))
	_, _, err := BuildChallengeResponse(identity, req, aka)
	if !errors.Is(err, ErrInvalidMAC) {
		t.Fatalf("BuildChallengeResponse() err=%v, want ErrInvalidMAC", err)
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
