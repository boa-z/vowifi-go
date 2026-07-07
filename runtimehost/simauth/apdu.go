package simauth

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	USIMAIDPrefix = "A0000000871002"
	ISIMAIDPrefix = "A0000000871004"

	maxGetResponseAPDUs = 4
)

type LogicalChannelTransport interface {
	OpenLogicalChannel(aid string) (int, error)
	CloseLogicalChannel(channel int) error
	TransmitAPDU(channel int, hexAPDU string) (string, error)
}

type LogicalChannelAIDResolver interface {
	ResolveLogicalChannelAID(app string, fallbackAID string) (resolvedAID string, source string, err error)
}

type Response struct {
	Body []byte
	SW1  byte
	SW2  byte
}

type StatusError struct {
	Operation string
	Response  Response
	message   string
}

func (e *StatusError) Error() string {
	if e == nil {
		return "APDU status error"
	}
	if e.message != "" {
		return e.message
	}
	op := strings.TrimSpace(e.Operation)
	if op == "" {
		op = "APDU"
	}
	return fmt.Sprintf("%s failed: SW=%s", op, e.Response.StatusString())
}

func (e *StatusError) Status() uint16 {
	if e == nil {
		return 0
	}
	return e.Response.Status()
}

func (e *StatusError) StatusString() string {
	if e == nil {
		return "0000"
	}
	return e.Response.StatusString()
}

func newStatusError(operation string, resp Response) error {
	return &StatusError{Operation: operation, Response: resp}
}

func newStatusMessageError(message string, resp Response) error {
	return &StatusError{Response: resp, message: message}
}

func (r Response) Success() bool {
	return r.SW1 == 0x90 && r.SW2 == 0x00
}

func (r Response) Status() uint16 {
	return uint16(r.SW1)<<8 | uint16(r.SW2)
}

func (r Response) StatusString() string {
	return fmt.Sprintf("%02X%02X", r.SW1, r.SW2)
}

func ResolveAID(t LogicalChannelTransport, app, fallbackAID, expectedPrefix string) (string, string, error) {
	fallback := strings.ToUpper(strings.TrimSpace(fallbackAID))
	want := strings.ToUpper(strings.TrimSpace(expectedPrefix))
	if resolver, ok := t.(LogicalChannelAIDResolver); ok {
		aid, source, err := resolver.ResolveLogicalChannelAID(app, fallback)
		if err == nil {
			aid = strings.ToUpper(strings.TrimSpace(aid))
			if strings.HasPrefix(aid, want) && len(aid) > len(want) {
				if strings.TrimSpace(source) == "" {
					source = "resolver"
				}
				return aid, source, nil
			}
			return "", "resolver_invalid", fmt.Errorf("%s AID does not match %s: %s", app, want, aid)
		}
	}
	if fallback == "" {
		return "", "missing", fmt.Errorf("%s AID is empty", app)
	}
	return fallback, "fallback", nil
}

func SelectFileAPDU(fid uint16) []byte {
	return []byte{0x00, 0xA4, 0x00, 0x04, 0x02, byte(fid >> 8), byte(fid)}
}

func ReadBinaryAPDU(offset, le int) []byte {
	if le <= 0 || le > 256 {
		le = 256
	}
	leByte := byte(le)
	if le == 256 {
		leByte = 0x00
	}
	return []byte{0x00, 0xB0, byte(offset >> 8), byte(offset), leByte}
}

func ReadRecordAPDU(record, le int) []byte {
	if le <= 0 || le > 256 {
		le = 256
	}
	leByte := byte(le)
	if le == 256 {
		leByte = 0x00
	}
	return []byte{0x00, 0xB2, byte(record), 0x04, leByte}
}

func UpdateBinaryAPDU(offset int, data []byte) ([]byte, error) {
	if offset < 0 || offset > 0xFFFF {
		return nil, fmt.Errorf("invalid UPDATE BINARY offset: %d", offset)
	}
	if err := validateShortAPDUData("UPDATE BINARY", data); err != nil {
		return nil, err
	}
	apdu := []byte{0x00, 0xD6, byte(offset >> 8), byte(offset), byte(len(data))}
	apdu = append(apdu, data...)
	return apdu, nil
}

func UpdateRecordAPDU(record int, data []byte) ([]byte, error) {
	if record <= 0 || record > 0xFF {
		return nil, fmt.Errorf("invalid UPDATE RECORD number: %d", record)
	}
	if err := validateShortAPDUData("UPDATE RECORD", data); err != nil {
		return nil, err
	}
	apdu := []byte{0x00, 0xDC, byte(record), 0x04, byte(len(data))}
	apdu = append(apdu, data...)
	return apdu, nil
}

func validateShortAPDUData(operation string, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("%s data is empty", operation)
	}
	if len(data) > 0xFF {
		return fmt.Errorf("%s data too long for short APDU Lc: %d", operation, len(data))
	}
	return nil
}

func Transmit(t LogicalChannelTransport, channel int, cmd []byte) (Response, error) {
	resp, err := transmitOnce(t, channel, cmd)
	if err != nil {
		return Response{}, err
	}
	if resp.SW1 == 0x6C {
		retry, err := correctAPDULe(cmd, apduLeFromSW2(resp.SW2))
		if err != nil {
			return Response{}, err
		}
		resp, err = transmitOnce(t, channel, retry)
		if err != nil {
			return Response{}, err
		}
	}
	return chaseGetResponse(t, channel, commandCLA(cmd), resp)
}

func chaseGetResponse(t LogicalChannelTransport, channel int, cla byte, resp Response) (Response, error) {
	if !requestsGetResponse(resp.SW1) {
		return resp, nil
	}
	body := append([]byte(nil), resp.Body...)
	for count := 0; requestsGetResponse(resp.SW1) && count < maxGetResponseAPDUs; count++ {
		le := apduLeFromSW2(resp.SW2)
		leByte, err := apduLeByte(le)
		if err != nil {
			return Response{}, err
		}
		getResp, err := transmitOnce(t, channel, []byte{cla, 0xC0, 0x00, 0x00, leByte})
		if err != nil {
			return Response{}, err
		}
		resp = getResp
		body = append(body, resp.Body...)
	}
	resp.Body = body
	return resp, nil
}

func requestsGetResponse(sw1 byte) bool {
	return sw1 == 0x61 || sw1 == 0x9F
}

func commandCLA(cmd []byte) byte {
	if len(cmd) == 0 {
		return 0x00
	}
	return cmd[0]
}

func correctAPDULe(apdu []byte, le int) ([]byte, error) {
	leByte, err := apduLeByte(le)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), apdu...)
	switch {
	case len(out) < 4:
		return nil, fmt.Errorf("APDU too short for Le correction: %d bytes", len(out))
	case len(out) == 4:
		out = append(out, leByte)
		return out, nil
	case len(out) == 5:
		out[len(out)-1] = leByte
		return out, nil
	case out[4] == 0:
		leHi, leLo, err := apduExtendedLeBytes(le)
		if err != nil {
			return nil, err
		}
		if len(out) == 7 {
			out[5], out[6] = leHi, leLo
			return out, nil
		}
		if len(out) < 7 {
			return nil, fmt.Errorf("invalid extended APDU length for Le correction: %d bytes", len(out))
		}
		lc := int(out[5])<<8 | int(out[6])
		if lc <= 0 {
			return nil, fmt.Errorf("invalid extended APDU Lc for Le correction: %d", lc)
		}
		switch len(out) {
		case 7 + lc:
			out = append(out, leHi, leLo)
			return out, nil
		case 9 + lc:
			out[len(out)-2], out[len(out)-1] = leHi, leLo
			return out, nil
		default:
			return nil, fmt.Errorf("invalid extended APDU length for Le correction: %d bytes with Lc=%d", len(out), lc)
		}
	}
	lc := int(out[4])
	switch len(out) {
	case 5 + lc:
		out = append(out, leByte)
		return out, nil
	case 6 + lc:
		out[len(out)-1] = leByte
		return out, nil
	default:
		return nil, fmt.Errorf("invalid short APDU length for Le correction: %d bytes with Lc=%d", len(out), lc)
	}
}

func apduLeFromSW2(sw2 byte) int {
	if sw2 == 0 {
		return 256
	}
	return int(sw2)
}

func apduLeByte(le int) (byte, error) {
	if le < 1 || le > 256 {
		return 0, fmt.Errorf("invalid APDU Le: %d", le)
	}
	if le == 256 {
		return 0x00, nil
	}
	return byte(le), nil
}

func apduExtendedLeBytes(le int) (byte, byte, error) {
	if le < 1 || le > 65536 {
		return 0, 0, fmt.Errorf("invalid extended APDU Le: %d", le)
	}
	if le == 65536 {
		return 0, 0, nil
	}
	return byte(le >> 8), byte(le), nil
}

func transmitOnce(t LogicalChannelTransport, channel int, cmd []byte) (Response, error) {
	if t == nil {
		return Response{}, errors.New("nil logical channel transport")
	}
	out, err := t.TransmitAPDU(channel, strings.ToUpper(hex.EncodeToString(cmd)))
	if err != nil {
		return Response{}, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(out))
	if err != nil {
		return Response{}, fmt.Errorf("decode APDU response: %w", err)
	}
	if len(raw) < 2 {
		return Response{}, fmt.Errorf("APDU response too short: %d", len(raw))
	}
	return Response{
		Body: append([]byte(nil), raw[:len(raw)-2]...),
		SW1:  raw[len(raw)-2],
		SW2:  raw[len(raw)-1],
	}, nil
}

func SelectFile(t LogicalChannelTransport, channel int, fid uint16) (Response, error) {
	resp, err := Transmit(t, channel, SelectFileAPDU(fid))
	if err != nil {
		return Response{}, err
	}
	if !resp.Success() {
		return resp, newStatusError(fmt.Sprintf("SELECT %04X", fid), resp)
	}
	return resp, nil
}

func ReadTransparentEF(t LogicalChannelTransport, channel int, fid uint16) ([]byte, Response, error) {
	selectResp, err := SelectFile(t, channel, fid)
	if err != nil {
		return nil, selectResp, err
	}
	size := FileSizeFromFCP(selectResp.Body)
	if size <= 0 {
		size = 256
	}
	var out []byte
	for offset := 0; offset < size; {
		chunk := size - offset
		if chunk > 256 {
			chunk = 256
		}
		resp, err := Transmit(t, channel, ReadBinaryAPDU(offset, chunk))
		if err != nil {
			return nil, resp, err
		}
		if !resp.Success() {
			return nil, resp, newStatusError(fmt.Sprintf("READ BINARY %04X offset=%d", fid, offset), resp)
		}
		out = append(out, resp.Body...)
		if len(resp.Body) == 0 || size == 256 && len(resp.Body) < chunk {
			break
		}
		offset += len(resp.Body)
	}
	return out, selectResp, nil
}

func ReadLinearFixedEF(t LogicalChannelTransport, channel int, fid uint16, maxRecords int) ([][]byte, Response, error) {
	selectResp, err := SelectFile(t, channel, fid)
	if err != nil {
		return nil, selectResp, err
	}
	if maxRecords <= 0 {
		maxRecords = 16
	}
	recordLen, recordCount := RecordInfoFromFCP(selectResp.Body)
	if recordCount > 0 && recordCount < maxRecords {
		maxRecords = recordCount
	}
	if recordLen <= 0 {
		recordLen = 256
	}
	var records [][]byte
	for rec := 1; rec <= maxRecords; rec++ {
		resp, err := Transmit(t, channel, ReadRecordAPDU(rec, recordLen))
		if err != nil {
			return nil, resp, err
		}
		if isRecordNotFound(resp.SW1, resp.SW2) {
			break
		}
		if !resp.Success() {
			return nil, resp, newStatusError(fmt.Sprintf("READ RECORD %04X #%d", fid, rec), resp)
		}
		records = append(records, append([]byte(nil), resp.Body...))
	}
	return records, selectResp, nil
}

func WriteTransparentEF(t LogicalChannelTransport, channel int, fid uint16, data []byte) (Response, error) {
	apdu, err := UpdateBinaryAPDU(0, data)
	if err != nil {
		return Response{}, err
	}
	selectResp, err := SelectFile(t, channel, fid)
	if err != nil {
		return selectResp, err
	}
	resp, err := Transmit(t, channel, apdu)
	if err != nil {
		return Response{}, err
	}
	if !resp.Success() {
		return resp, newStatusError(fmt.Sprintf("UPDATE BINARY %04X offset=0", fid), resp)
	}
	return resp, nil
}

func WriteLinearFixedEFRecord(t LogicalChannelTransport, channel int, fid uint16, record int, data []byte) (Response, error) {
	apdu, err := UpdateRecordAPDU(record, data)
	if err != nil {
		return Response{}, err
	}
	selectResp, err := SelectFile(t, channel, fid)
	if err != nil {
		return selectResp, err
	}
	resp, err := Transmit(t, channel, apdu)
	if err != nil {
		return Response{}, err
	}
	if !resp.Success() {
		return resp, newStatusError(fmt.Sprintf("UPDATE RECORD %04X #%d", fid, record), resp)
	}
	return resp, nil
}

func isRecordNotFound(sw1, sw2 byte) bool {
	return (sw1 == 0x6A && (sw2 == 0x82 || sw2 == 0x83)) ||
		(sw2 == 0x6A && (sw1 == 0x82 || sw1 == 0x83))
}
