package eapaka

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	CodeRequest  uint8 = 1
	CodeResponse uint8 = 2
	CodeSuccess  uint8 = 3
	CodeFailure  uint8 = 4
)

const (
	TypeAKA      uint8 = 23
	TypeAKAPrime uint8 = 50
)

const (
	SubtypeChallenge              uint8 = 1
	SubtypeAuthenticationReject   uint8 = 2
	SubtypeSynchronizationFailure uint8 = 4
	SubtypeIdentity               uint8 = 5
	SubtypeNotification           uint8 = 12
	SubtypeReauthentication       uint8 = 13
	SubtypeClientError            uint8 = 14
)

const (
	AttributeRAND            uint8 = 1
	AttributeAUTN            uint8 = 2
	AttributeRES             uint8 = 3
	AttributeAUTS            uint8 = 4
	AttributePadding         uint8 = 6
	AttributePermanentIDReq  uint8 = 10
	AttributeMAC             uint8 = 11
	AttributeNotification    uint8 = 12
	AttributeAnyIDReq        uint8 = 13
	AttributeIdentity        uint8 = 14
	AttributeVersionList     uint8 = 15
	AttributeSelectedVersion uint8 = 16
	AttributeFullAuthIDReq   uint8 = 17
	AttributeCounter         uint8 = 19
	AttributeCounterTooSmall uint8 = 20
	AttributeNonceS          uint8 = 21
	AttributeClientErrorCode uint8 = 22
	AttributeKDFInput        uint8 = 23
	AttributeKDF             uint8 = 24
	AttributeIV              uint8 = 129
	AttributeEncrData        uint8 = 130
	AttributeNextPseudonym   uint8 = 132
	AttributeNextReauthID    uint8 = 133
	AttributeCheckcode       uint8 = 134
	AttributeResultInd       uint8 = 135
	AttributeBidding         uint8 = 136
)

const (
	NotificationSuccessBit uint16 = 0x8000
	NotificationPBit       uint16 = 0x4000

	NotificationGeneralFailureAfterAuthentication  uint16 = 0
	NotificationGeneralFailureBeforeAuthentication uint16 = NotificationPBit
	NotificationSuccess                            uint16 = NotificationSuccessBit
)

const (
	ClientErrorUnableToProcessPacket  uint16 = 0
	ClientErrorUnsupportedVersion     uint16 = 1
	ClientErrorInsufficientChallenges uint16 = 2
	ClientErrorRANDNotFresh           uint16 = 3
)

const (
	SupportedVersion uint16 = 1

	RANDLength    = 16
	AUTNLength    = 16
	AUTSLength    = 14
	AKLength      = 6
	AMFLength     = 2
	AUTNMACLength = 8
	RESMinBits    = 32
	RESMaxBits    = 128
)

var (
	ErrInvalidPacket    = errors.New("invalid eap-aka packet")
	ErrInvalidAttribute = errors.New("invalid eap-aka attribute")
	ErrInvalidCheckcode = errors.New("invalid eap-aka checkcode")
)

type Packet struct {
	Code       uint8
	Identifier uint8
	Type       uint8
	Subtype    uint8
	Attributes []Attribute
	Data       []byte
}

type Attribute struct {
	Type uint8
	Data []byte
}

type EncryptedIdentityState struct {
	NextPseudonym string
	NextReauthID  string
}

type AUTNFields struct {
	SQNXorAK []byte
	AMF      []byte
	MAC      []byte
}

type AUTSFields struct {
	SQNMSXorAK []byte
	MACS       []byte
}

type ChallengeVector struct {
	RAND       []byte
	AUTN       []byte
	AUTNFields AUTNFields
}

type Challenge struct {
	Packet              Packet
	Vectors             []ChallengeVector
	RAND                []byte
	AUTN                []byte
	AUTNFields          AUTNFields
	MAC                 []byte
	HasMAC              bool
	ResultInd           bool
	Checkcode           []byte
	HasCheckcode        bool
	Bidding             bool
	HasBidding          bool
	KDFInput            string
	KDFValues           []uint16
	EncryptedAttributes []Attribute
	IdentityState       EncryptedIdentityState
}

type ReauthenticationRequest struct {
	Counter             uint16
	NonceS              []byte
	IdentityState       EncryptedIdentityState
	EncryptedAttributes []Attribute
}

type NotificationInfo struct {
	Value                uint16
	Code                 uint16
	Success              bool
	BeforeAuthentication bool
}

func (p Packet) MarshalBinary() ([]byte, error) {
	if p.Code == CodeSuccess || p.Code == CodeFailure {
		out := []byte{p.Code, p.Identifier, 0, 4}
		return out, nil
	}
	if p.Type == 0 {
		p.Type = TypeAKA
	}
	var body []byte
	body = append(body, p.Type)
	if len(p.Data) > 0 {
		body = append(body, p.Data...)
	} else {
		body = append(body, p.Subtype, 0, 0)
		attrs, err := MarshalAttributes(p.Attributes)
		if err != nil {
			return nil, err
		}
		body = append(body, attrs...)
	}
	if len(body)+4 > 0xffff {
		return nil, fmt.Errorf("%w: packet too long", ErrInvalidPacket)
	}
	out := make([]byte, 4, len(body)+4)
	out[0] = p.Code
	out[1] = p.Identifier
	binary.BigEndian.PutUint16(out[2:4], uint16(len(body)+4))
	out = append(out, body...)
	return out, nil
}

func ParsePacket(data []byte) (Packet, error) {
	if len(data) < 4 {
		return Packet{}, ErrInvalidPacket
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < 4 || length > len(data) {
		return Packet{}, fmt.Errorf("%w: length %d", ErrInvalidPacket, length)
	}
	p := Packet{Code: data[0], Identifier: data[1]}
	if p.Code == CodeSuccess || p.Code == CodeFailure {
		if length != 4 {
			return Packet{}, fmt.Errorf("%w: terminal packet length %d", ErrInvalidPacket, length)
		}
		return p, nil
	}
	if length < 8 {
		return Packet{}, ErrInvalidPacket
	}
	p.Type = data[4]
	if p.Type != TypeAKA && p.Type != TypeAKAPrime {
		p.Data = append([]byte(nil), data[5:length]...)
		return p, nil
	}
	p.Subtype = data[5]
	attrs, err := ParseAttributes(data[8:length])
	if err != nil {
		return Packet{}, err
	}
	p.Attributes = attrs
	return p, nil
}

func MarshalAttributes(attrs []Attribute) ([]byte, error) {
	var out []byte
	for _, attr := range attrs {
		encoded, err := attr.MarshalBinary()
		if err != nil {
			return nil, err
		}
		out = append(out, encoded...)
	}
	return out, nil
}

func ParseAttributes(data []byte) ([]Attribute, error) {
	var out []Attribute
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, ErrInvalidAttribute
		}
		length := int(data[1]) * 4
		if length < 4 || length > len(data) {
			return nil, fmt.Errorf("%w: length %d", ErrInvalidAttribute, length)
		}
		out = append(out, Attribute{
			Type: data[0],
			Data: append([]byte(nil), data[2:length]...),
		})
		data = data[length:]
	}
	return out, nil
}

func (a Attribute) MarshalBinary() ([]byte, error) {
	length := 2 + len(a.Data)
	pad := paddingFor4(length)
	total := length + pad
	if total < 4 || total > 0xff*4 {
		return nil, fmt.Errorf("%w: length %d", ErrInvalidAttribute, total)
	}
	out := make([]byte, 2, total)
	out[0] = a.Type
	out[1] = byte(total / 4)
	out = append(out, a.Data...)
	if pad > 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out, nil
}

func FixedAttribute(attributeType uint8, value []byte) Attribute {
	data := make([]byte, 2, 2+len(value))
	data = append(data, value...)
	return Attribute{Type: attributeType, Data: data}
}

func VariableAttribute(attributeType uint8, value []byte) Attribute {
	data := make([]byte, 2, 2+len(value))
	binary.BigEndian.PutUint16(data[0:2], uint16(len(value)))
	data = append(data, value...)
	return Attribute{Type: attributeType, Data: data}
}

func IdentityAttribute(identity string) Attribute {
	return VariableAttribute(AttributeIdentity, []byte(identity))
}

func VersionListAttribute(versions ...uint16) Attribute {
	value := make([]byte, 0, len(versions)*2)
	for _, version := range versions {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], version)
		value = append(value, b[:]...)
	}
	return VariableAttribute(AttributeVersionList, value)
}

func SelectedVersionAttribute(version uint16) Attribute {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], version)
	return Attribute{Type: AttributeSelectedVersion, Data: b[:]}
}

func BiddingAttribute(preferAKAPrime bool) Attribute {
	data := []byte{0, 0}
	if preferAKAPrime {
		data[0] = 0x80
	}
	return Attribute{Type: AttributeBidding, Data: data}
}

func RESAttribute(res []byte) Attribute {
	bits := len(res) * 8
	data := make([]byte, 2, 2+len(res))
	binary.BigEndian.PutUint16(data[0:2], uint16(bits))
	data = append(data, res...)
	return Attribute{Type: AttributeRES, Data: data}
}

func AUTSAttribute(auts []byte) Attribute {
	return FixedAttribute(AttributeAUTS, auts)
}

func RANDAttribute(rand16 ...[]byte) Attribute {
	var value []byte
	for _, rand := range rand16 {
		value = append(value, rand...)
	}
	return FixedAttribute(AttributeRAND, value)
}

func AUTNAttribute(autn16 []byte) Attribute {
	return FixedAttribute(AttributeAUTN, autn16)
}

func PermanentIDReqAttribute() Attribute {
	return FixedAttribute(AttributePermanentIDReq, nil)
}

func AnyIDReqAttribute() Attribute {
	return FixedAttribute(AttributeAnyIDReq, nil)
}

func FullAuthIDReqAttribute() Attribute {
	return FixedAttribute(AttributeFullAuthIDReq, nil)
}

func KDFInputAttribute(networkName string) Attribute {
	return VariableAttribute(AttributeKDFInput, []byte(networkName))
}

func KDFAttribute(kdf uint16) Attribute {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], kdf)
	return Attribute{Type: AttributeKDF, Data: b[:]}
}

func NotificationAttribute(code uint16) Attribute {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], code)
	return Attribute{Type: AttributeNotification, Data: b[:]}
}

func ClientErrorCodeAttribute(code uint16) Attribute {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], code)
	return Attribute{Type: AttributeClientErrorCode, Data: b[:]}
}

func CounterAttribute(counter uint16) Attribute {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], counter)
	return Attribute{Type: AttributeCounter, Data: b[:]}
}

func CounterTooSmallAttribute() Attribute {
	return FixedAttribute(AttributeCounterTooSmall, nil)
}

func NonceSAttribute(nonce16 []byte) Attribute {
	return FixedAttribute(AttributeNonceS, nonce16)
}

func IVAttribute(iv16 []byte) Attribute {
	return FixedAttribute(AttributeIV, iv16)
}

func EncrDataAttribute(ciphertext []byte) Attribute {
	return FixedAttribute(AttributeEncrData, ciphertext)
}

func NextPseudonymAttribute(identity string) Attribute {
	return VariableAttribute(AttributeNextPseudonym, []byte(identity))
}

func NextReauthIDAttribute(identity string) Attribute {
	return VariableAttribute(AttributeNextReauthID, []byte(identity))
}

func CheckcodeAttribute(checkcode []byte) Attribute {
	return FixedAttribute(AttributeCheckcode, checkcode)
}

func ResultIndAttribute() Attribute {
	return FixedAttribute(AttributeResultInd, nil)
}

func CheckcodeAttributeForPackets(packets [][]byte) Attribute {
	if len(packets) == 0 {
		return CheckcodeAttribute(nil)
	}
	return CheckcodeAttribute(IdentityCheckcode(packets))
}

func IdentityCheckcode(packets [][]byte) []byte {
	h := sha1.New()
	for _, packet := range packets {
		_, _ = h.Write(packet)
	}
	return h.Sum(nil)
}

func FindAttribute(attrs []Attribute, attributeType uint8) (Attribute, bool) {
	for _, attr := range attrs {
		if attr.Type == attributeType {
			return attr, true
		}
	}
	return Attribute{}, false
}

func FindSingleAttribute(attrs []Attribute, attributeType uint8) (Attribute, bool, error) {
	var out Attribute
	count := 0
	for _, attr := range attrs {
		if attr.Type != attributeType {
			continue
		}
		out = attr
		count++
	}
	switch count {
	case 0:
		return Attribute{}, false, nil
	case 1:
		return out, true, nil
	default:
		return Attribute{}, true, fmt.Errorf("%w: duplicate attribute %d", ErrInvalidAttribute, attributeType)
	}
}

func NotificationFromAttributes(attrs []Attribute) (NotificationInfo, bool, error) {
	attr, ok, err := FindSingleAttribute(attrs, AttributeNotification)
	if err != nil || !ok {
		return NotificationInfo{}, ok, err
	}
	info, err := attr.NotificationInfo()
	if err != nil {
		return NotificationInfo{}, true, err
	}
	return info, true, nil
}

func ParseNotificationRequest(request Packet) (NotificationInfo, error) {
	if request.Code != CodeRequest || request.Subtype != SubtypeNotification {
		return NotificationInfo{}, fmt.Errorf("%w: not an EAP-AKA notification request", ErrInvalidPacket)
	}
	if !isAKAType(request.Type) {
		return NotificationInfo{}, fmt.Errorf("%w: EAP type %d", ErrInvalidPacket, request.Type)
	}
	info, ok, err := NotificationFromAttributes(request.Attributes)
	if err != nil {
		return NotificationInfo{}, err
	}
	if !ok {
		return NotificationInfo{}, fmt.Errorf("%w: missing AT_NOTIFICATION", ErrInvalidAttribute)
	}
	return info, nil
}

func ClientErrorCodeFromAttributes(attrs []Attribute) (uint16, bool, error) {
	attr, ok, err := FindSingleAttribute(attrs, AttributeClientErrorCode)
	if err != nil || !ok {
		return 0, ok, err
	}
	code, err := attr.ClientErrorCodeValue()
	if err != nil {
		return 0, true, err
	}
	return code, true, nil
}

func ParseClientErrorResponse(response Packet) (uint16, error) {
	if response.Code != CodeResponse || response.Subtype != SubtypeClientError {
		return 0, fmt.Errorf("%w: not an EAP-AKA client-error response", ErrInvalidPacket)
	}
	if !isAKAType(response.Type) {
		return 0, fmt.Errorf("%w: EAP type %d", ErrInvalidPacket, response.Type)
	}
	code, ok, err := ClientErrorCodeFromAttributes(response.Attributes)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("%w: missing AT_CLIENT_ERROR_CODE", ErrInvalidAttribute)
	}
	return code, nil
}

func CounterTooSmallFromAttributes(attrs []Attribute) (bool, error) {
	attr, ok, err := FindSingleAttribute(attrs, AttributeCounterTooSmall)
	if err != nil || !ok {
		return ok, err
	}
	return true, attr.CounterTooSmallValue()
}

func CheckcodeFromAttributes(attrs []Attribute) ([]byte, bool, error) {
	attr, ok, err := FindSingleAttribute(attrs, AttributeCheckcode)
	if err != nil || !ok {
		return nil, ok, err
	}
	value, err := attr.CheckcodeValue()
	if err != nil {
		return nil, true, err
	}
	return value, true, nil
}

func ResultIndFromAttributes(attrs []Attribute) (bool, error) {
	attr, ok, err := FindSingleAttribute(attrs, AttributeResultInd)
	if err != nil || !ok {
		return ok, err
	}
	return true, attr.ResultIndValue()
}

func ValidateAttributes(attrs []Attribute) error {
	for _, attr := range attrs {
		if err := ValidateAttribute(attr); err != nil {
			return fmt.Errorf("attribute %d: %w", attr.Type, err)
		}
	}
	return nil
}

func ValidateAttribute(a Attribute) error {
	switch a.Type {
	case AttributeRAND:
		_, err := a.RANDValues()
		return err
	case AttributeAUTN:
		_, err := a.AUTNValues()
		return err
	case AttributeRES:
		_, _, err := a.RESValue()
		return err
	case AttributeAUTS:
		_, err := a.AUTSValue()
		return err
	case AttributePadding:
		totalLength := len(a.Data) + 2
		if totalLength != 4 && totalLength != 8 && totalLength != 12 {
			return fmt.Errorf("%w: padding length %d", ErrInvalidAttribute, totalLength)
		}
		return requireZeroBytes(a.Data, "padding bytes")
	case AttributePermanentIDReq, AttributeAnyIDReq, AttributeFullAuthIDReq:
		_, err := a.fixedValueExact(0)
		return err
	case AttributeMAC:
		_, err := a.MACValue()
		return err
	case AttributeNotification:
		_, err := a.NotificationValue()
		return err
	case AttributeIdentity:
		_, err := a.IdentityValue()
		return err
	case AttributeVersionList:
		_, err := a.VersionListValue()
		return err
	case AttributeSelectedVersion:
		_, err := a.SelectedVersionValue()
		return err
	case AttributeCounter:
		_, err := a.CounterValue()
		return err
	case AttributeCounterTooSmall:
		return a.CounterTooSmallValue()
	case AttributeNonceS:
		_, err := a.NonceSValue()
		return err
	case AttributeClientErrorCode:
		_, err := a.ClientErrorCodeValue()
		return err
	case AttributeKDFInput:
		_, err := a.KDFInputValue()
		return err
	case AttributeKDF:
		_, err := a.KDFValue()
		return err
	case AttributeIV:
		_, err := a.IVValue()
		return err
	case AttributeEncrData:
		_, err := a.EncrDataValue()
		return err
	case AttributeNextPseudonym:
		_, err := a.NextPseudonymValue()
		return err
	case AttributeNextReauthID:
		_, err := a.NextReauthIDValue()
		return err
	case AttributeCheckcode:
		_, err := a.CheckcodeValue()
		return err
	case AttributeResultInd:
		return a.ResultIndValue()
	case AttributeBidding:
		_, err := a.BiddingValue()
		return err
	default:
		return nil
	}
}

func (a Attribute) VariableValue() ([]byte, error) {
	if len(a.Data) < 2 {
		return nil, ErrInvalidAttribute
	}
	length := int(binary.BigEndian.Uint16(a.Data[0:2]))
	if length > len(a.Data)-2 {
		return nil, fmt.Errorf("%w: value length %d > %d", ErrInvalidAttribute, length, len(a.Data)-2)
	}
	if err := requireZeroBytes(a.Data[2+length:], "variable value padding"); err != nil {
		return nil, err
	}
	return append([]byte(nil), a.Data[2:2+length]...), nil
}

func (a Attribute) IdentityValue() (string, error) {
	value, err := a.VariableValue()
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func (a Attribute) VersionListValue() ([]uint16, error) {
	value, err := a.VariableValue()
	if err != nil {
		return nil, err
	}
	if len(value) == 0 || len(value)%2 != 0 {
		return nil, fmt.Errorf("%w: version list length %d", ErrInvalidAttribute, len(value))
	}
	out := make([]uint16, 0, len(value)/2)
	for offset := 0; offset < len(value); offset += 2 {
		out = append(out, binary.BigEndian.Uint16(value[offset:offset+2]))
	}
	return out, nil
}

func (a Attribute) SelectedVersionValue() (uint16, error) {
	return a.directUint16Value()
}

func (a Attribute) BiddingValue() (bool, error) {
	if len(a.Data) != 2 {
		return false, fmt.Errorf("%w: bidding value length %d", ErrInvalidAttribute, len(a.Data))
	}
	if a.Data[0]&0x7f != 0 || a.Data[1] != 0 {
		return false, fmt.Errorf("%w: non-zero bidding reserved bits", ErrInvalidAttribute)
	}
	return a.Data[0]&0x80 != 0, nil
}

func (a Attribute) RESValue() ([]byte, uint16, error) {
	if len(a.Data) < 2 {
		return nil, 0, ErrInvalidAttribute
	}
	bits := binary.BigEndian.Uint16(a.Data[0:2])
	if bits < RESMinBits || bits > RESMaxBits {
		return nil, 0, fmt.Errorf("%w: RES bits %d outside %d..%d", ErrInvalidAttribute, bits, RESMinBits, RESMaxBits)
	}
	octets := int((uint32(bits) + 7) / 8)
	baseLength := 2 + octets
	paddedLength := baseLength + paddingFor4(2+baseLength)
	if len(a.Data) != baseLength && len(a.Data) != paddedLength {
		return nil, 0, fmt.Errorf("%w: RES value length %d for %d bits", ErrInvalidAttribute, len(a.Data), bits)
	}
	if octets > len(a.Data)-2 {
		return nil, 0, fmt.Errorf("%w: RES bits %d exceeds %d octets", ErrInvalidAttribute, bits, len(a.Data)-2)
	}
	if bits%8 != 0 {
		unusedMask := byte(1<<(8-bits%8)) - 1
		if a.Data[1+octets]&unusedMask != 0 {
			return nil, 0, fmt.Errorf("%w: non-zero unused RES bits", ErrInvalidAttribute)
		}
	}
	for _, b := range a.Data[baseLength:] {
		if b != 0 {
			return nil, 0, fmt.Errorf("%w: non-zero RES padding", ErrInvalidAttribute)
		}
	}
	return append([]byte(nil), a.Data[2:2+octets]...), bits, nil
}

func (a Attribute) FixedValue(size int) ([]byte, error) {
	if size < 0 || len(a.Data) < 2+size {
		return nil, ErrInvalidAttribute
	}
	if err := requireReservedZero(a.Data, "fixed value reserved bytes"); err != nil {
		return nil, err
	}
	return append([]byte(nil), a.Data[2:2+size]...), nil
}

func (a Attribute) RANDValues() ([][]byte, error) {
	return fixed16Values(a)
}

func (a Attribute) AUTNValue() ([]byte, error) {
	return a.fixedValueExact(AUTNLength)
}

func (a Attribute) AUTNValues() ([][]byte, error) {
	return fixed16Values(a)
}

func (a Attribute) AUTNFields() (AUTNFields, error) {
	autn, err := a.AUTNValue()
	if err != nil {
		return AUTNFields{}, err
	}
	return ParseAUTN(autn)
}

func (a Attribute) AUTSValue() ([]byte, error) {
	return a.fixedValueExact(AUTSLength)
}

func (a Attribute) AUTSFields() (AUTSFields, error) {
	auts, err := a.AUTSValue()
	if err != nil {
		return AUTSFields{}, err
	}
	return ParseAUTS(auts)
}

func (a Attribute) MACValue() ([]byte, error) {
	return a.fixedValueExact(16)
}

func (a Attribute) ResultIndValue() error {
	if len(a.Data) != 2 {
		return fmt.Errorf("%w: result-ind value length %d", ErrInvalidAttribute, len(a.Data))
	}
	return requireReservedZero(a.Data, "result-ind reserved bytes")
}

func (a Attribute) KDFInputValue() (string, error) {
	value, err := a.VariableValue()
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func (a Attribute) KDFValue() (uint16, error) {
	if len(a.Data) == 2 {
		return binary.BigEndian.Uint16(a.Data), nil
	}
	if len(a.Data) >= 4 && a.Data[0] == 0 && a.Data[1] == 0 {
		return binary.BigEndian.Uint16(a.Data[2:4]), nil
	}
	return 0, ErrInvalidAttribute
}

func (a Attribute) NotificationValue() (uint16, error) {
	return a.directUint16Value()
}

func (a Attribute) NotificationInfo() (NotificationInfo, error) {
	value, err := a.NotificationValue()
	if err != nil {
		return NotificationInfo{}, err
	}
	return NotificationInfo{
		Value:                value,
		Code:                 value &^ (NotificationSuccessBit | NotificationPBit),
		Success:              value&NotificationSuccessBit != 0,
		BeforeAuthentication: value&NotificationPBit != 0,
	}, nil
}

func (a Attribute) ClientErrorCodeValue() (uint16, error) {
	return a.directUint16Value()
}

func (a Attribute) CounterValue() (uint16, error) {
	return a.directUint16Value()
}

func (a Attribute) CounterTooSmallValue() error {
	if len(a.Data) != 2 {
		return fmt.Errorf("%w: counter-too-small value length %d", ErrInvalidAttribute, len(a.Data))
	}
	return requireReservedZero(a.Data, "counter-too-small reserved bytes")
}

func (a Attribute) NonceSValue() ([]byte, error) {
	return a.fixedValueExact(RANDLength)
}

func (a Attribute) IVValue() ([]byte, error) {
	return a.fixedValueExact(RANDLength)
}

func (a Attribute) EncrDataValue() ([]byte, error) {
	if len(a.Data) < 2 {
		return nil, ErrInvalidAttribute
	}
	if err := requireReservedZero(a.Data, "encrypted-data reserved bytes"); err != nil {
		return nil, err
	}
	return append([]byte(nil), a.Data[2:]...), nil
}

func (a Attribute) NextPseudonymValue() (string, error) {
	value, err := a.VariableValue()
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func (a Attribute) NextReauthIDValue() (string, error) {
	value, err := a.VariableValue()
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func IdentityStateFromAttributes(attrs []Attribute) (EncryptedIdentityState, error) {
	var out EncryptedIdentityState
	for _, attr := range attrs {
		switch attr.Type {
		case AttributeNextPseudonym:
			value, err := attr.NextPseudonymValue()
			if err != nil {
				return EncryptedIdentityState{}, err
			}
			out.NextPseudonym = value
		case AttributeNextReauthID:
			value, err := attr.NextReauthIDValue()
			if err != nil {
				return EncryptedIdentityState{}, err
			}
			out.NextReauthID = value
		}
	}
	return out, nil
}

func (a Attribute) CheckcodeValue() ([]byte, error) {
	switch len(a.Data) {
	case 2:
		if err := requireReservedZero(a.Data, "checkcode reserved bytes"); err != nil {
			return nil, err
		}
		return nil, nil
	case 22:
		if err := requireReservedZero(a.Data, "checkcode reserved bytes"); err != nil {
			return nil, err
		}
		return append([]byte(nil), a.Data[2:]...), nil
	default:
		return nil, fmt.Errorf("%w: checkcode value length %d", ErrInvalidAttribute, len(a.Data))
	}
}

func VerifyCheckcodeAttribute(attr Attribute, packets [][]byte) error {
	value, err := attr.CheckcodeValue()
	if err != nil {
		return err
	}
	if len(value) == 0 {
		if len(packets) == 0 {
			return nil
		}
		return ErrInvalidCheckcode
	}
	expected := IdentityCheckcode(packets)
	if subtle.ConstantTimeCompare(value, expected) != 1 {
		return ErrInvalidCheckcode
	}
	return nil
}

func ParseAUTN(autn16 []byte) (AUTNFields, error) {
	if len(autn16) != AUTNLength {
		return AUTNFields{}, fmt.Errorf("%w: AUTN length %d", ErrInvalidAttribute, len(autn16))
	}
	return AUTNFields{
		SQNXorAK: append([]byte(nil), autn16[:AKLength]...),
		AMF:      append([]byte(nil), autn16[AKLength:AKLength+AMFLength]...),
		MAC:      append([]byte(nil), autn16[AKLength+AMFLength:]...),
	}, nil
}

func ParseAUTS(auts14 []byte) (AUTSFields, error) {
	if len(auts14) != AUTSLength {
		return AUTSFields{}, fmt.Errorf("%w: AUTS length %d", ErrInvalidAttribute, len(auts14))
	}
	return AUTSFields{
		SQNMSXorAK: append([]byte(nil), auts14[:AKLength]...),
		MACS:       append([]byte(nil), auts14[AKLength:]...),
	}, nil
}

func (a AUTNFields) SQN(ak []byte) ([]byte, error) {
	if len(a.SQNXorAK) != AKLength {
		return nil, fmt.Errorf("%w: SQN xor AK length %d", ErrInvalidAttribute, len(a.SQNXorAK))
	}
	if len(ak) != AKLength {
		return nil, fmt.Errorf("%w: AK length %d", ErrInvalidAttribute, len(ak))
	}
	sqn := make([]byte, AKLength)
	for i := range sqn {
		sqn[i] = a.SQNXorAK[i] ^ ak[i]
	}
	return sqn, nil
}

func (a AUTSFields) Bytes() ([]byte, error) {
	if len(a.SQNMSXorAK) != AKLength {
		return nil, fmt.Errorf("%w: AUTS SQN_MS xor AK length %d", ErrInvalidAttribute, len(a.SQNMSXorAK))
	}
	if len(a.MACS) != AUTNMACLength {
		return nil, fmt.Errorf("%w: AUTS MAC-S length %d", ErrInvalidAttribute, len(a.MACS))
	}
	out := make([]byte, 0, AUTSLength)
	out = append(out, a.SQNMSXorAK...)
	out = append(out, a.MACS...)
	return out, nil
}

func (a AUTSFields) SQNMS(ak []byte) ([]byte, error) {
	if len(a.SQNMSXorAK) != AKLength {
		return nil, fmt.Errorf("%w: AUTS SQN_MS xor AK length %d", ErrInvalidAttribute, len(a.SQNMSXorAK))
	}
	if len(ak) != AKLength {
		return nil, fmt.Errorf("%w: AK length %d", ErrInvalidAttribute, len(ak))
	}
	sqn := make([]byte, AKLength)
	for i := range sqn {
		sqn[i] = a.SQNMSXorAK[i] ^ ak[i]
	}
	return sqn, nil
}

func (a Attribute) directUint16Value() (uint16, error) {
	if len(a.Data) != 2 {
		return 0, fmt.Errorf("%w: uint16 value length %d", ErrInvalidAttribute, len(a.Data))
	}
	return binary.BigEndian.Uint16(a.Data), nil
}

func (a Attribute) fixedValueExact(size int) ([]byte, error) {
	if size < 0 || len(a.Data) < 2 {
		return nil, ErrInvalidAttribute
	}
	if err := requireReservedZero(a.Data, "fixed value reserved bytes"); err != nil {
		return nil, err
	}
	baseLength := 2 + size
	paddedLength := baseLength + paddingFor4(2+baseLength)
	if len(a.Data) != baseLength && len(a.Data) != paddedLength {
		return nil, fmt.Errorf("%w: fixed value length %d for %d-byte value", ErrInvalidAttribute, len(a.Data), size)
	}
	if err := requireZeroBytes(a.Data[baseLength:], "fixed value padding"); err != nil {
		return nil, err
	}
	return append([]byte(nil), a.Data[2:baseLength]...), nil
}

func fixed16Values(a Attribute) ([][]byte, error) {
	if len(a.Data) < 2 || (len(a.Data)-2)%16 != 0 {
		return nil, ErrInvalidAttribute
	}
	if err := requireReservedZero(a.Data, "fixed value reserved bytes"); err != nil {
		return nil, err
	}
	var out [][]byte
	for offset := 2; offset < len(a.Data); offset += 16 {
		out = append(out, append([]byte(nil), a.Data[offset:offset+16]...))
	}
	if len(out) == 0 {
		return nil, ErrInvalidAttribute
	}
	return out, nil
}

func requireReservedZero(data []byte, name string) error {
	if len(data) < 2 {
		return ErrInvalidAttribute
	}
	return requireZeroBytes(data[:2], name)
}

func requireZeroBytes(data []byte, name string) error {
	for _, b := range data {
		if b != 0 {
			return fmt.Errorf("%w: non-zero %s", ErrInvalidAttribute, name)
		}
	}
	return nil
}

func paddingFor4(n int) int {
	if rem := n % 4; rem != 0 {
		return 4 - rem
	}
	return 0
}
