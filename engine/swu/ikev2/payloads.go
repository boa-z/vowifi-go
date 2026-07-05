package ikev2

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	ProtocolIKE uint8 = 1
	ProtocolAH  uint8 = 2
	ProtocolESP uint8 = 3
)

const (
	NotifyUnacceptableAddresses     uint16 = 40
	NotifyUnexpectedNATDetected     uint16 = 41
	NotifyNATDetectionSourceIP      uint16 = 16388
	NotifyNATDetectionDestinationIP uint16 = 16389
	NotifyMOBIKESupported           uint16 = 16396
	NotifyAdditionalIPv4Address     uint16 = 16397
	NotifyAdditionalIPv6Address     uint16 = 16398
	NotifyNoAdditionalAddresses     uint16 = 16399
	NotifyUpdateSAAddresses         uint16 = 16400
	NotifyCookie2                   uint16 = 16401
	NotifyNoNATsAllowed             uint16 = 16402
)

const (
	DHGroup2048BitMODP uint16 = 14
	DHGroup256BitECP   uint16 = 19
	DHGroup384BitECP   uint16 = 20
	DHGroup521BitECP   uint16 = 21
	DHGroupCurve25519  uint16 = 31
)

var (
	ErrInvalidNotify  = errors.New("invalid ikev2 notify payload")
	ErrInvalidDelete  = errors.New("invalid ikev2 delete payload")
	ErrInvalidAddress = errors.New("invalid ikev2 address")
)

type Notify struct {
	ProtocolID       uint8
	NotifyType       uint16
	SPI              []byte
	NotificationData []byte
}

func (n Notify) MarshalBinary() ([]byte, error) {
	if len(n.SPI) > 0xff {
		return nil, fmt.Errorf("%w: spi too long", ErrInvalidNotify)
	}
	out := make([]byte, 4, 4+len(n.SPI)+len(n.NotificationData))
	out[0] = n.ProtocolID
	out[1] = byte(len(n.SPI))
	binary.BigEndian.PutUint16(out[2:4], n.NotifyType)
	out = append(out, n.SPI...)
	out = append(out, n.NotificationData...)
	return out, nil
}

func ParseNotify(data []byte) (Notify, error) {
	if len(data) < 4 {
		return Notify{}, ErrInvalidNotify
	}
	spiSize := int(data[1])
	if len(data) < 4+spiSize {
		return Notify{}, ErrInvalidNotify
	}
	return Notify{
		ProtocolID:       data[0],
		NotifyType:       binary.BigEndian.Uint16(data[2:4]),
		SPI:              append([]byte(nil), data[4:4+spiSize]...),
		NotificationData: append([]byte(nil), data[4+spiSize:]...),
	}, nil
}

func NotifyPayload(n Notify) (Payload, error) {
	body, err := n.MarshalBinary()
	if err != nil {
		return Payload{}, err
	}
	return Payload{Type: PayloadNotify, Body: body}, nil
}

type Delete struct {
	ProtocolID uint8
	SPIs       [][]byte
}

func (d Delete) MarshalBinary() ([]byte, error) {
	if err := validateDelete(d); err != nil {
		return nil, err
	}
	spiSize := 0
	if len(d.SPIs) > 0 {
		spiSize = len(d.SPIs[0])
	}
	out := make([]byte, 4, 4+spiSize*len(d.SPIs))
	out[0] = d.ProtocolID
	out[1] = byte(spiSize)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(d.SPIs)))
	for _, spi := range d.SPIs {
		out = append(out, spi...)
	}
	return out, nil
}

func ParseDelete(data []byte) (Delete, error) {
	if len(data) < 4 {
		return Delete{}, ErrInvalidDelete
	}
	spiSize := int(data[1])
	spiCount := int(binary.BigEndian.Uint16(data[2:4]))
	want := 4 + spiSize*spiCount
	if want != len(data) {
		return Delete{}, fmt.Errorf("%w: length %d != %d", ErrInvalidDelete, len(data), want)
	}
	d := Delete{
		ProtocolID: data[0],
		SPIs:       make([][]byte, 0, spiCount),
	}
	rest := data[4:]
	for i := 0; i < spiCount; i++ {
		d.SPIs = append(d.SPIs, append([]byte(nil), rest[:spiSize]...))
		rest = rest[spiSize:]
	}
	if err := validateDelete(d); err != nil {
		return Delete{}, err
	}
	return d, nil
}

func DeletePayload(d Delete) (Payload, error) {
	body, err := d.MarshalBinary()
	if err != nil {
		return Payload{}, err
	}
	return Payload{Type: PayloadDelete, Body: body}, nil
}

func IKEDeletePayload() Payload {
	return Payload{Type: PayloadDelete, Body: []byte{ProtocolIKE, 0, 0, 0}}
}

func ESPDeletePayload(spis ...[]byte) (Payload, error) {
	copied := make([][]byte, 0, len(spis))
	for _, spi := range spis {
		copied = append(copied, append([]byte(nil), spi...))
	}
	return DeletePayload(Delete{ProtocolID: ProtocolESP, SPIs: copied})
}

func ChildSADeletePayload(child ChildSAResult) (Payload, error) {
	if len(child.LocalSPI) == 0 {
		return Payload{}, fmt.Errorf("%w: missing local child SPI", ErrInvalidDelete)
	}
	return ESPDeletePayload(child.LocalSPI)
}

func TeardownDeletePayloads(child ChildSAResult, includeIKESA bool) ([]Payload, error) {
	var out []Payload
	if len(child.LocalSPI) > 0 {
		payload, err := ChildSADeletePayload(child)
		if err != nil {
			return nil, err
		}
		out = append(out, payload)
	}
	if includeIKESA {
		out = append(out, IKEDeletePayload())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no SAs selected", ErrInvalidDelete)
	}
	return out, nil
}

func validateDelete(d Delete) error {
	switch d.ProtocolID {
	case ProtocolIKE:
		if len(d.SPIs) != 0 {
			return fmt.Errorf("%w: IKE delete must not include SPIs", ErrInvalidDelete)
		}
		return nil
	case ProtocolAH, ProtocolESP:
	default:
		return fmt.Errorf("%w: protocol %d", ErrInvalidDelete, d.ProtocolID)
	}
	if len(d.SPIs) == 0 {
		return fmt.Errorf("%w: no SPIs", ErrInvalidDelete)
	}
	if len(d.SPIs) > 0xffff {
		return fmt.Errorf("%w: too many SPIs", ErrInvalidDelete)
	}
	spiSize := len(d.SPIs[0])
	if spiSize != 4 {
		return fmt.Errorf("%w: SPI size %d", ErrInvalidDelete, spiSize)
	}
	for _, spi := range d.SPIs {
		if len(spi) != spiSize {
			return fmt.Errorf("%w: mixed SPI sizes", ErrInvalidDelete)
		}
	}
	return nil
}

type KeyExchange struct {
	DHGroup uint16
	KeyData []byte
}

func (k KeyExchange) MarshalBinary() []byte {
	out := make([]byte, 4, 4+len(k.KeyData))
	binary.BigEndian.PutUint16(out[0:2], k.DHGroup)
	out = append(out, k.KeyData...)
	return out
}

func ParseKeyExchange(data []byte) (KeyExchange, error) {
	if len(data) < 4 {
		return KeyExchange{}, ErrShortPayload
	}
	return KeyExchange{
		DHGroup: binary.BigEndian.Uint16(data[0:2]),
		KeyData: append([]byte(nil), data[4:]...),
	}, nil
}

func KeyExchangePayload(group uint16, keyData []byte) Payload {
	return Payload{Type: PayloadKE, Body: (KeyExchange{DHGroup: group, KeyData: append([]byte(nil), keyData...)}).MarshalBinary()}
}

func NoncePayload(nonce []byte) Payload {
	return Payload{Type: PayloadNonce, Body: append([]byte(nil), nonce...)}
}

func EAPPayload(packet []byte) Payload {
	return Payload{Type: PayloadEAP, Body: append([]byte(nil), packet...)}
}

func NATDetectionHash(spiI, spiR uint64, ip net.IP, port uint16) ([]byte, error) {
	normalized := ip.To4()
	if normalized == nil {
		normalized = ip.To16()
	}
	if normalized == nil {
		return nil, ErrInvalidAddress
	}
	data := make([]byte, 0, 16+len(normalized)+2)
	data = appendUint64(data, spiI)
	data = appendUint64(data, spiR)
	data = append(data, normalized...)
	data = append(data, byte(port>>8), byte(port))
	sum := sha1.Sum(data)
	return sum[:], nil
}

func NATDetectionNotify(notifyType uint16, spiI, spiR uint64, ip net.IP, port uint16) (Payload, error) {
	if notifyType != NotifyNATDetectionSourceIP && notifyType != NotifyNATDetectionDestinationIP {
		return Payload{}, fmt.Errorf("%w: unsupported NAT detection type %d", ErrInvalidNotify, notifyType)
	}
	hash, err := NATDetectionHash(spiI, spiR, ip, port)
	if err != nil {
		return Payload{}, err
	}
	return NotifyPayload(Notify{
		ProtocolID:       ProtocolIKE,
		NotifyType:       notifyType,
		NotificationData: hash,
	})
}

func MOBIKESupportedNotify() Payload {
	body, _ := (Notify{NotifyType: NotifyMOBIKESupported}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func UpdateSAAddressesNotify() Payload {
	body, _ := (Notify{NotifyType: NotifyUpdateSAAddresses}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func NoAdditionalAddressesNotify() Payload {
	body, _ := (Notify{NotifyType: NotifyNoAdditionalAddresses}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func AdditionalIPAddressNotify(ip net.IP) (Payload, error) {
	if v4 := ip.To4(); v4 != nil {
		return NotifyWithZeroSPI(NotifyAdditionalIPv4Address, v4), nil
	}
	if v6 := ip.To16(); v6 != nil {
		return NotifyWithZeroSPI(NotifyAdditionalIPv6Address, v6), nil
	}
	return Payload{}, ErrInvalidAddress
}

func Cookie2Notify(cookie []byte) (Payload, error) {
	if len(cookie) < 8 || len(cookie) > 64 {
		return Payload{}, fmt.Errorf("%w: COOKIE2 length %d", ErrInvalidNotify, len(cookie))
	}
	body, err := (Notify{NotifyType: NotifyCookie2, NotificationData: append([]byte(nil), cookie...)}).MarshalBinary()
	if err != nil {
		return Payload{}, err
	}
	return Payload{Type: PayloadNotify, Body: body}, nil
}

func NotifyWithZeroSPI(notifyType uint16, data []byte) Payload {
	body, _ := (Notify{NotifyType: notifyType, NotificationData: append([]byte(nil), data...)}).MarshalBinary()
	return Payload{Type: PayloadNotify, Body: body}
}

func FirstNotify(payloads []Payload, notifyType uint16) (Notify, bool, error) {
	for _, payload := range payloads {
		if payload.Type != PayloadNotify {
			continue
		}
		notify, err := ParseNotify(payload.Body)
		if err != nil {
			return Notify{}, false, err
		}
		if notify.NotifyType == notifyType {
			return notify, true, nil
		}
	}
	return Notify{}, false, nil
}

func appendUint64(dst []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(dst, b[:]...)
}
