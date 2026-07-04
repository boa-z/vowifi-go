package ikev2

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	PayloadNoNext   uint8 = 0
	PayloadSA       uint8 = 33
	PayloadKE       uint8 = 34
	PayloadIDi      uint8 = 35
	PayloadIDr      uint8 = 36
	PayloadCERT     uint8 = 37
	PayloadCERTREQ  uint8 = 38
	PayloadAUTH     uint8 = 39
	PayloadNonce    uint8 = 40
	PayloadNotify   uint8 = 41
	PayloadDelete   uint8 = 42
	PayloadVendorID uint8 = 43
	PayloadTSi      uint8 = 44
	PayloadTSr      uint8 = 45
	PayloadSK       uint8 = 46
	PayloadCP       uint8 = 47
	PayloadEAP      uint8 = 48
)

const (
	ExchangeIKE_SA_INIT     uint8 = 34
	ExchangeIKE_AUTH        uint8 = 35
	ExchangeCREATE_CHILD_SA uint8 = 36
	ExchangeINFORMATIONAL   uint8 = 37
)

const (
	FlagInitiator uint8 = 0x08
	FlagVersion   uint8 = 0x10
	FlagResponse  uint8 = 0x20
)

const HeaderLength = 28

var (
	ErrShortHeader   = errors.New("ikev2 header too short")
	ErrShortPayload  = errors.New("ikev2 payload too short")
	ErrInvalidLength = errors.New("ikev2 invalid length")
)

type Header struct {
	InitiatorSPI uint64
	ResponderSPI uint64
	NextPayload  uint8
	Version      uint8
	ExchangeType uint8
	Flags        uint8
	MessageID    uint32
	Length       uint32
}

func (h Header) MarshalBinary() ([]byte, error) {
	version := h.Version
	if version == 0 {
		version = 0x20
	}
	length := h.Length
	if length == 0 {
		length = HeaderLength
	}
	if length < HeaderLength {
		return nil, fmt.Errorf("%w: header length %d", ErrInvalidLength, length)
	}
	out := make([]byte, HeaderLength)
	binary.BigEndian.PutUint64(out[0:8], h.InitiatorSPI)
	binary.BigEndian.PutUint64(out[8:16], h.ResponderSPI)
	out[16] = h.NextPayload
	out[17] = version
	out[18] = h.ExchangeType
	out[19] = h.Flags
	binary.BigEndian.PutUint32(out[20:24], h.MessageID)
	binary.BigEndian.PutUint32(out[24:28], length)
	return out, nil
}

func ParseHeader(data []byte) (Header, error) {
	if len(data) < HeaderLength {
		return Header{}, ErrShortHeader
	}
	h := Header{
		InitiatorSPI: binary.BigEndian.Uint64(data[0:8]),
		ResponderSPI: binary.BigEndian.Uint64(data[8:16]),
		NextPayload:  data[16],
		Version:      data[17],
		ExchangeType: data[18],
		Flags:        data[19],
		MessageID:    binary.BigEndian.Uint32(data[20:24]),
		Length:       binary.BigEndian.Uint32(data[24:28]),
	}
	if h.Length < HeaderLength {
		return Header{}, fmt.Errorf("%w: header length %d", ErrInvalidLength, h.Length)
	}
	if int(h.Length) > len(data) {
		return Header{}, fmt.Errorf("%w: message length %d > buffer %d", ErrInvalidLength, h.Length, len(data))
	}
	return h, nil
}

type Payload struct {
	Type        uint8
	NextPayload uint8
	Critical    bool
	Body        []byte
}

func MarshalPayloads(payloads []Payload) (first uint8, data []byte, err error) {
	if len(payloads) == 0 {
		return PayloadNoNext, nil, nil
	}
	first = payloads[0].Type
	for i, p := range payloads {
		next := PayloadNoNext
		if p.Type == PayloadSK && p.NextPayload != PayloadNoNext {
			next = p.NextPayload
			if i+1 < len(payloads) {
				return 0, nil, fmt.Errorf("%w: SK payload must be last", ErrInvalidLength)
			}
		} else if i+1 < len(payloads) {
			next = payloads[i+1].Type
		}
		if len(p.Body)+4 > 0xffff {
			return 0, nil, fmt.Errorf("%w: payload length %d", ErrInvalidLength, len(p.Body)+4)
		}
		flags := uint8(0)
		if p.Critical {
			flags = 0x80
		}
		hdr := make([]byte, 4)
		hdr[0] = next
		hdr[1] = flags
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(p.Body)+4))
		data = append(data, hdr...)
		data = append(data, p.Body...)
	}
	return first, data, nil
}

func ParsePayloads(first uint8, data []byte) ([]Payload, error) {
	var out []Payload
	next := first
	rest := data
	for next != PayloadNoNext {
		if len(rest) < 4 {
			return nil, ErrShortPayload
		}
		length := int(binary.BigEndian.Uint16(rest[2:4]))
		if length < 4 || length > len(rest) {
			return nil, fmt.Errorf("%w: payload length %d buffer %d", ErrInvalidLength, length, len(rest))
		}
		current := next
		next = rest[0]
		if current == PayloadSK {
			next = PayloadNoNext
		}
		out = append(out, Payload{
			Type:        current,
			NextPayload: rest[0],
			Critical:    rest[1]&0x80 != 0,
			Body:        append([]byte(nil), rest[4:length]...),
		})
		rest = rest[length:]
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: trailing payload bytes %d", ErrInvalidLength, len(rest))
	}
	return out, nil
}

type Message struct {
	Header   Header
	Payloads []Payload
}

func (m Message) MarshalBinary() ([]byte, error) {
	first, payloadBytes, err := MarshalPayloads(m.Payloads)
	if err != nil {
		return nil, err
	}
	h := m.Header
	h.NextPayload = first
	h.Length = uint32(HeaderLength + len(payloadBytes))
	headerBytes, err := h.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(headerBytes, payloadBytes...), nil
}

func ParseMessage(data []byte) (Message, error) {
	h, err := ParseHeader(data)
	if err != nil {
		return Message{}, err
	}
	payloads, err := ParsePayloads(h.NextPayload, data[HeaderLength:h.Length])
	if err != nil {
		return Message{}, err
	}
	return Message{Header: h, Payloads: payloads}, nil
}
