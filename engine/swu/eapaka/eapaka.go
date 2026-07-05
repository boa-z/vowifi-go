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

func IVAttribute(iv16 []byte) Attribute {
	return FixedAttribute(AttributeIV, iv16)
}

func EncrDataAttribute(ciphertext []byte) Attribute {
	return FixedAttribute(AttributeEncrData, ciphertext)
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

func (a Attribute) VariableValue() ([]byte, error) {
	if len(a.Data) < 2 {
		return nil, ErrInvalidAttribute
	}
	length := int(binary.BigEndian.Uint16(a.Data[0:2]))
	if length > len(a.Data)-2 {
		return nil, fmt.Errorf("%w: value length %d > %d", ErrInvalidAttribute, length, len(a.Data)-2)
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

func (a Attribute) RESValue() ([]byte, uint16, error) {
	if len(a.Data) < 2 {
		return nil, 0, ErrInvalidAttribute
	}
	bits := binary.BigEndian.Uint16(a.Data[0:2])
	octets := int((uint32(bits) + 7) / 8)
	if octets > len(a.Data)-2 {
		return nil, 0, fmt.Errorf("%w: RES bits %d exceeds %d octets", ErrInvalidAttribute, bits, len(a.Data)-2)
	}
	return append([]byte(nil), a.Data[2:2+octets]...), bits, nil
}

func (a Attribute) FixedValue(size int) ([]byte, error) {
	if size < 0 || len(a.Data) < 2+size {
		return nil, ErrInvalidAttribute
	}
	return append([]byte(nil), a.Data[2:2+size]...), nil
}

func (a Attribute) RANDValues() ([][]byte, error) {
	return fixed16Values(a)
}

func (a Attribute) AUTNValue() ([]byte, error) {
	return a.FixedValue(16)
}

func (a Attribute) AUTSValue() ([]byte, error) {
	return a.FixedValue(14)
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

func (a Attribute) ClientErrorCodeValue() (uint16, error) {
	return a.directUint16Value()
}

func (a Attribute) IVValue() ([]byte, error) {
	return a.FixedValue(16)
}

func (a Attribute) EncrDataValue() ([]byte, error) {
	if len(a.Data) < 2 {
		return nil, ErrInvalidAttribute
	}
	return append([]byte(nil), a.Data[2:]...), nil
}

func (a Attribute) CheckcodeValue() ([]byte, error) {
	switch len(a.Data) {
	case 2:
		return nil, nil
	case 22:
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

func (a Attribute) directUint16Value() (uint16, error) {
	if len(a.Data) != 2 {
		return 0, fmt.Errorf("%w: uint16 value length %d", ErrInvalidAttribute, len(a.Data))
	}
	return binary.BigEndian.Uint16(a.Data), nil
}

func fixed16Values(a Attribute) ([][]byte, error) {
	if len(a.Data) < 2 || (len(a.Data)-2)%16 != 0 {
		return nil, ErrInvalidAttribute
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

func paddingFor4(n int) int {
	if rem := n % 4; rem != 0 {
		return 4 - rem
	}
	return 0
}
