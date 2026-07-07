package simauth

import (
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	swusim "github.com/boa-z/vowifi-go/engine/sim"
	"github.com/boa-z/vowifi-go/runtimehost/simtransport"
)

type fakeTransport struct {
	calls     []string
	responses []string
	err       error
}

func (f *fakeTransport) OpenLogicalChannel(aid string) (int, error) { return 1, nil }
func (f *fakeTransport) CloseLogicalChannel(channel int) error      { return nil }
func (f *fakeTransport) TransmitAPDU(channel int, hexAPDU string) (string, error) {
	f.calls = append(f.calls, hexAPDU)
	if f.err != nil {
		return "", f.err
	}
	if len(f.responses) == 0 {
		return "9000", nil
	}
	resp := f.responses[0]
	f.responses = f.responses[1:]
	return resp, nil
}

func TestParseTLVListAndFCP(t *testing.T) {
	fcp := []byte{0x62, 0x0B, 0x80, 0x02, 0x00, 0x20, 0x82, 0x05, 0x21, 0x00, 0x00, 0x10, 0x02}
	if got := FileSizeFromFCP(fcp); got != 32 {
		t.Fatalf("FileSizeFromFCP() = %d, want 32", got)
	}
	recordLen, recordCount := RecordInfoFromFCP(fcp)
	if recordLen != 16 || recordCount != 2 {
		t.Fatalf("RecordInfoFromFCP() = %d/%d, want 16/2", recordLen, recordCount)
	}
	highTag := []byte{0x5F, 0x20, 0x03, 'b', 'o', 'a'}
	if v, ok := FindTLV(highTag, 0x5F20); !ok || string(v) != "boa" {
		t.Fatalf("FindTLV(high tag) = %q/%v, want boa/true", string(v), ok)
	}

	longLength := append([]byte{0x62, 0x84, 0x00, 0x00, 0x00, 0x05}, []byte{0x80, 0x03, 0x01, 0x02, 0x03}...)
	items, err := ParseTLVList(longLength)
	if err != nil {
		t.Fatalf("ParseTLVList(0x84 length) error = %v", err)
	}
	if len(items) != 1 || items[0].Tag != 0x62 || !reflect.DeepEqual(items[0].Value, []byte{0x80, 0x03, 0x01, 0x02, 0x03}) {
		t.Fatalf("0x84 length items=%+v", items)
	}
	if _, err := ParseTLVList([]byte{0x62, 0x80, 0x00, 0x00}); err == nil {
		t.Fatal("ParseTLVList(indefinite length) err=nil, want error")
	}
	if _, err := ParseTLVList([]byte{0x62, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}); err == nil {
		t.Fatal("ParseTLVList(0x85 length) err=nil, want error")
	}
}

func TestTransmitHandlesRetryLengthAndGetResponse(t *testing.T) {
	retry := &fakeTransport{responses: []string{"6C03", "0102039000"}}
	resp, err := Transmit(retry, 1, []byte{0x00, 0xB0, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("Transmit(6C) error = %v", err)
	}
	if !reflect.DeepEqual(resp.Body, []byte{1, 2, 3}) {
		t.Fatalf("retry body = % X", resp.Body)
	}
	if !reflect.DeepEqual(retry.calls, []string{"00B0000000", "00B0000003"}) {
		t.Fatalf("retry calls = %#v", retry.calls)
	}

	dataRetry := &fakeTransport{responses: []string{"6C03", "0102039000"}}
	resp, err = Transmit(dataRetry, 1, []byte{0x00, 0x88, 0x00, 0x81, 0x02, 0xAA, 0xBB})
	if err != nil {
		t.Fatalf("Transmit(6C data APDU) error = %v", err)
	}
	if !reflect.DeepEqual(resp.Body, []byte{1, 2, 3}) {
		t.Fatalf("data retry body = % X", resp.Body)
	}
	if !reflect.DeepEqual(dataRetry.calls, []string{"0088008102AABB", "0088008102AABB03"}) {
		t.Fatalf("data retry calls = %#v", dataRetry.calls)
	}

	extendedRetry := &fakeTransport{responses: []string{"6C03", "0102039000"}}
	resp, err = Transmit(extendedRetry, 1, []byte{0x00, 0x88, 0x00, 0x81, 0x00, 0x00, 0x02, 0xAA, 0xBB})
	if err != nil {
		t.Fatalf("Transmit(6C extended data APDU) error = %v", err)
	}
	if !reflect.DeepEqual(resp.Body, []byte{1, 2, 3}) {
		t.Fatalf("extended retry body = % X", resp.Body)
	}
	if !reflect.DeepEqual(extendedRetry.calls, []string{"00880081000002AABB", "00880081000002AABB0003"}) {
		t.Fatalf("extended retry calls = %#v", extendedRetry.calls)
	}

	getResponse := &fakeTransport{responses: []string{"AA6102", "BBCC9000"}}
	resp, err = Transmit(getResponse, 1, []byte{0x00, 0xA4, 0x00, 0x04, 0x02, 0x6F, 0x02})
	if err != nil {
		t.Fatalf("Transmit(61) error = %v", err)
	}
	if !reflect.DeepEqual(resp.Body, []byte{0xAA, 0xBB, 0xCC}) {
		t.Fatalf("get-response body = % X", resp.Body)
	}
	if !reflect.DeepEqual(getResponse.calls, []string{"00A40004026F02", "00C0000002"}) {
		t.Fatalf("get-response calls = %#v", getResponse.calls)
	}

	chainedGetResponse := &fakeTransport{responses: []string{"AA6102", "BB6101", "CC9000"}}
	resp, err = Transmit(chainedGetResponse, 1, []byte{0x00, 0xA4, 0x04, 0x04, 0x02, 0x6F, 0x02})
	if err != nil {
		t.Fatalf("Transmit(chained 61) error = %v", err)
	}
	if !reflect.DeepEqual(resp.Body, []byte{0xAA, 0xBB, 0xCC}) {
		t.Fatalf("chained get-response body = % X", resp.Body)
	}
	if !reflect.DeepEqual(chainedGetResponse.calls, []string{"00A40404026F02", "00C0000002", "00C0000001"}) {
		t.Fatalf("chained get-response calls = %#v", chainedGetResponse.calls)
	}

	simGetResponse := &fakeTransport{responses: []string{"AA9F02", "BBCC9000"}}
	resp, err = Transmit(simGetResponse, 1, []byte{0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x02})
	if err != nil {
		t.Fatalf("Transmit(9F) error = %v", err)
	}
	if !reflect.DeepEqual(resp.Body, []byte{0xAA, 0xBB, 0xCC}) {
		t.Fatalf("9F get-response body = % X", resp.Body)
	}
	if !reflect.DeepEqual(simGetResponse.calls, []string{"A0A40000026F02", "A0C0000002"}) {
		t.Fatalf("9F get-response calls = %#v", simGetResponse.calls)
	}
}

func TestTransmitLimitsGetResponseChain(t *testing.T) {
	ft := &fakeTransport{responses: []string{"AA6101", "BB6101", "CC6101", "DD6101", "EE6101"}}
	resp, err := Transmit(ft, 1, []byte{0x00, 0xCA, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatalf("Transmit(long 61 chain) error = %v", err)
	}
	if resp.StatusString() != "6101" {
		t.Fatalf("long 61 chain status = %s, want 6101", resp.StatusString())
	}
	if !reflect.DeepEqual(resp.Body, []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}) {
		t.Fatalf("long 61 chain body = % X", resp.Body)
	}
	wantCalls := []string{"00CA000000", "00C0000001", "00C0000001", "00C0000001", "00C0000001"}
	if !reflect.DeepEqual(ft.calls, wantCalls) {
		t.Fatalf("long 61 chain calls = %#v, want %#v", ft.calls, wantCalls)
	}
}

func TestAPDUStatusErrorsCarryRecoveryStatus(t *testing.T) {
	ft := &fakeTransport{responses: []string{"6F00"}}
	resp, err := SelectFile(ft, 1, 0x6F02)
	if err == nil {
		t.Fatal("SelectFile(6F00) err=nil, want status error")
	}
	if resp.StatusString() != "6F00" {
		t.Fatalf("response status = %s, want 6F00", resp.StatusString())
	}
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("SelectFile(6F00) err=%T, want StatusError", err)
	}
	if statusErr.Status() != 0x6F00 || statusErr.StatusString() != "6F00" {
		t.Fatalf("status error status = %s/%04X, want 6F00", statusErr.StatusString(), statusErr.Status())
	}
	if got := simtransport.ClassifyError(err); got != simtransport.RecoveryClassSIMBusy {
		t.Fatalf("ClassifyError(StatusError) = %q, want SIM busy", got)
	}

	_, err = ParseUSIMAuthResponse(nil, 0x62, 0x82)
	statusErr = nil
	if !errors.As(err, &statusErr) {
		t.Fatalf("ParseUSIMAuthResponse(6282) err=%T, want StatusError", err)
	}
	if got := simtransport.ClassifyError(err); got != simtransport.RecoveryClassEmptyEF {
		t.Fatalf("ClassifyError(AKA StatusError) = %q, want empty EF", got)
	}
}

func TestReadTransparentAndLinearFixedEF(t *testing.T) {
	ft := &fakeTransport{responses: []string{
		"6204800200039000",
		"0102039000",
		"6207820521000005029000",
		"11223344559000",
		"66778899AA9000",
	}}
	data, _, err := ReadTransparentEF(ft, 1, 0x6F02)
	if err != nil {
		t.Fatalf("ReadTransparentEF() error = %v", err)
	}
	if !reflect.DeepEqual(data, []byte{1, 2, 3}) {
		t.Fatalf("transparent data = % X", data)
	}
	records, _, err := ReadLinearFixedEF(ft, 1, 0x6F04, 16)
	if err != nil {
		t.Fatalf("ReadLinearFixedEF() error = %v", err)
	}
	if len(records) != 2 || hex.EncodeToString(records[0]) != "1122334455" || hex.EncodeToString(records[1]) != "66778899aa" {
		t.Fatalf("records = % X", records)
	}
	wantCalls := []string{"00A40004026F02", "00B0000003", "00A40004026F04", "00B2010405", "00B2020405"}
	if !reflect.DeepEqual(ft.calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", ft.calls, wantCalls)
	}
}

func TestUpdateAPDUBuildersValidateInputs(t *testing.T) {
	apdu, err := UpdateBinaryAPDU(0x0123, []byte{0xAA, 0xBB})
	if err != nil {
		t.Fatalf("UpdateBinaryAPDU() error = %v", err)
	}
	if !reflect.DeepEqual(apdu, []byte{0x00, 0xD6, 0x01, 0x23, 0x02, 0xAA, 0xBB}) {
		t.Fatalf("UpdateBinaryAPDU() = % X", apdu)
	}

	apdu, err = UpdateRecordAPDU(2, []byte{0x11, 0x22, 0x33})
	if err != nil {
		t.Fatalf("UpdateRecordAPDU() error = %v", err)
	}
	if !reflect.DeepEqual(apdu, []byte{0x00, 0xDC, 0x02, 0x04, 0x03, 0x11, 0x22, 0x33}) {
		t.Fatalf("UpdateRecordAPDU() = % X", apdu)
	}

	longData := make([]byte, 256)
	tests := []struct {
		name string
		fn   func() ([]byte, error)
	}{
		{name: "negative offset", fn: func() ([]byte, error) { return UpdateBinaryAPDU(-1, []byte{1}) }},
		{name: "large offset", fn: func() ([]byte, error) { return UpdateBinaryAPDU(0x10000, []byte{1}) }},
		{name: "nil binary data", fn: func() ([]byte, error) { return UpdateBinaryAPDU(0, nil) }},
		{name: "empty binary data", fn: func() ([]byte, error) { return UpdateBinaryAPDU(0, []byte{}) }},
		{name: "long binary data", fn: func() ([]byte, error) { return UpdateBinaryAPDU(0, longData) }},
		{name: "zero record", fn: func() ([]byte, error) { return UpdateRecordAPDU(0, []byte{1}) }},
		{name: "large record", fn: func() ([]byte, error) { return UpdateRecordAPDU(0x100, []byte{1}) }},
		{name: "nil record data", fn: func() ([]byte, error) { return UpdateRecordAPDU(1, nil) }},
		{name: "empty record data", fn: func() ([]byte, error) { return UpdateRecordAPDU(1, []byte{}) }},
		{name: "long record data", fn: func() ([]byte, error) { return UpdateRecordAPDU(1, longData) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if apdu, err := tt.fn(); err == nil {
				t.Fatalf("%s err=nil, apdu=% X", tt.name, apdu)
			}
		})
	}
}

func TestWriteTransparentAndLinearFixedEFRecord(t *testing.T) {
	ft := &fakeTransport{responses: []string{
		"6204800200039000",
		"9000",
		"6207820521000005029000",
		"9000",
	}}
	resp, err := WriteTransparentEF(ft, 1, 0x6F02, []byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("WriteTransparentEF() error = %v", err)
	}
	if !resp.Success() {
		t.Fatalf("WriteTransparentEF() status = %s, want success", resp.StatusString())
	}
	resp, err = WriteLinearFixedEFRecord(ft, 1, 0x6F04, 2, []byte{0xAA, 0xBB})
	if err != nil {
		t.Fatalf("WriteLinearFixedEFRecord() error = %v", err)
	}
	if !resp.Success() {
		t.Fatalf("WriteLinearFixedEFRecord() status = %s, want success", resp.StatusString())
	}
	wantCalls := []string{"00A40004026F02", "00D6000003010203", "00A40004026F04", "00DC020402AABB"}
	if !reflect.DeepEqual(ft.calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", ft.calls, wantCalls)
	}
}

func TestWriteEFValidationRunsBeforeSelect(t *testing.T) {
	ft := &fakeTransport{}
	if _, err := WriteTransparentEF(ft, 1, 0x6F02, nil); err == nil {
		t.Fatal("WriteTransparentEF(nil) err=nil, want error")
	}
	if _, err := WriteLinearFixedEFRecord(ft, 1, 0x6F04, 0, []byte{1}); err == nil {
		t.Fatal("WriteLinearFixedEFRecord(record 0) err=nil, want error")
	}
	if len(ft.calls) != 0 {
		t.Fatalf("validation calls = %#v, want none", ft.calls)
	}
}

func TestWriteEFStatusErrors(t *testing.T) {
	ft := &fakeTransport{responses: []string{
		"6204800200019000",
		"6985",
	}}
	resp, err := WriteTransparentEF(ft, 1, 0x6F02, []byte{0x01})
	if err == nil {
		t.Fatal("WriteTransparentEF(6985) err=nil, want status error")
	}
	if resp.StatusString() != "6985" {
		t.Fatalf("WriteTransparentEF() status = %s, want 6985", resp.StatusString())
	}
	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("WriteTransparentEF() err=%T, want StatusError", err)
	}

	ft = &fakeTransport{responses: []string{
		"6207820521000005019000",
		"6A84",
	}}
	resp, err = WriteLinearFixedEFRecord(ft, 1, 0x6F04, 1, []byte{0xAA})
	if err == nil {
		t.Fatal("WriteLinearFixedEFRecord(6A84) err=nil, want status error")
	}
	if resp.StatusString() != "6A84" {
		t.Fatalf("WriteLinearFixedEFRecord() status = %s, want 6A84", resp.StatusString())
	}
	statusErr = nil
	if !errors.As(err, &statusErr) {
		t.Fatalf("WriteLinearFixedEFRecord() err=%T, want StatusError", err)
	}
}

func TestBuildAndParseUSIMAuth(t *testing.T) {
	rand16 := make([]byte, 16)
	autn16 := make([]byte, 16)
	apdu, err := BuildUSIMAuthAPDU(rand16, autn16, true)
	if err != nil {
		t.Fatalf("BuildUSIMAuthAPDU() error = %v", err)
	}
	if got, want := hex.EncodeToString(apdu[:5]), "0088008122"; got != want {
		t.Fatalf("APDU prefix = %s, want %s", got, want)
	}
	if apdu[len(apdu)-1] != 0x00 {
		t.Fatalf("APDU Le = 0x%02X, want 0", apdu[len(apdu)-1])
	}

	body := append([]byte{0xDB, 0x04, 0x11, 0x22, 0x33, 0x44, 0x10}, bytesFrom(0x01, 16)...)
	body = append(body, 0x10)
	body = append(body, bytesFrom(0x21, 16)...)
	res, err := ParseUSIMAuthResponse(body, 0x90, 0x00)
	if err != nil {
		t.Fatalf("ParseUSIMAuthResponse() error = %v", err)
	}
	if len(res.RES) != 4 || len(res.CK) != 16 || len(res.IK) != 16 {
		t.Fatalf("AKA lengths = RES %d CK %d IK %d", len(res.RES), len(res.CK), len(res.IK))
	}

	bodyWithKc := append([]byte{0xDB, 0x04, 0x11, 0x22, 0x33, 0x44, 0x10}, bytesFrom(0x31, 16)...)
	bodyWithKc = append(bodyWithKc, 0x10)
	bodyWithKc = append(bodyWithKc, bytesFrom(0x51, 16)...)
	bodyWithKc = append(bodyWithKc, 0x08)
	bodyWithKc = append(bodyWithKc, bytesFrom(0x71, 8)...)
	bodyWithKc = append(bodyWithKc, 0x00, 0xFF)
	res, err = ParseUSIMAuthResponse(bodyWithKc, 0x90, 0x00)
	if err != nil {
		t.Fatalf("ParseUSIMAuthResponse(Kc) error = %v", err)
	}
	if hex.EncodeToString(res.RES) != "11223344" ||
		hex.EncodeToString(res.CK) != "3132333435363738393a3b3c3d3e3f40" ||
		hex.EncodeToString(res.IK) != "5152535455565758595a5b5c5d5e5f60" {
		t.Fatalf("AKA with Kc result=%+v", res)
	}

	res, err = ParseUSIMAuthResponse(append([]byte{0xDC, 0x0E}, bytesFrom(0xAA, 14)...), 0x90, 0x00)
	if !errors.Is(err, swusim.ErrSyncFailure) || len(res.AUTS) != AKAAUTSLength {
		t.Fatalf("sync failure = %+v err=%v, want AUTS and ErrSyncFailure", res, err)
	}

	_, err = ParseUSIMAuthResponse([]byte{0xDD, 0x00}, 0x90, 0x00)
	if !errors.Is(err, swusim.ErrAuthFailure) {
		t.Fatalf("auth failure err=%v, want ErrAuthFailure", err)
	}
}

func TestParseUSIMAuthResponseNestedTLVAndPadding(t *testing.T) {
	successPayload := append([]byte{0x04, 0x11, 0x22, 0x33, 0x44, 0x10}, bytesFrom(0x01, 16)...)
	successPayload = append(successPayload, 0x10)
	successPayload = append(successPayload, bytesFrom(0x21, 16)...)
	success := append([]byte{0xDB, byte(len(successPayload))}, successPayload...)
	wrapped := append([]byte{0xA0, byte(len(success))}, success...)
	wrapped = append(wrapped, 0x00, 0xFF)
	res, err := ParseUSIMAuthResponse(wrapped, 0x90, 0x00)
	if err != nil {
		t.Fatalf("ParseUSIMAuthResponse(wrapped success) error = %v", err)
	}
	if hex.EncodeToString(res.RES) != "11223344" || len(res.CK) != 16 || len(res.IK) != 16 {
		t.Fatalf("wrapped AKA result=%+v", res)
	}

	longWrapped := append([]byte{0xA0, 0x84, 0x00, 0x00, 0x00, byte(len(success))}, success...)
	res, err = ParseUSIMAuthResponse(longWrapped, 0x90, 0x00)
	if err != nil {
		t.Fatalf("ParseUSIMAuthResponse(long wrapped success) error = %v", err)
	}
	if hex.EncodeToString(res.RES) != "11223344" || len(res.CK) != 16 || len(res.IK) != 16 {
		t.Fatalf("long wrapped AKA result=%+v", res)
	}

	auts := bytesFrom(0xA0, AKAAUTSLength)
	wrappedSync := append([]byte{0xA0, 0x10, 0xDC, 0x0E}, auts...)
	res, err = ParseUSIMAuthResponse(wrappedSync, 0x90, 0x00)
	if !errors.Is(err, swusim.ErrSyncFailure) || hex.EncodeToString(res.AUTS) != hex.EncodeToString(auts) {
		t.Fatalf("wrapped sync failure res=%+v err=%v", res, err)
	}

	_, err = ParseUSIMAuthResponse([]byte{0xA0, 0x02, 0xDD, 0x00}, 0x90, 0x00)
	if !errors.Is(err, swusim.ErrAuthFailure) {
		t.Fatalf("wrapped MAC failure err=%v, want ErrAuthFailure", err)
	}

	_, err = ParseUSIMAuthResponse(append([]byte{0xDC, 0x0E}, append(bytesFrom(0xA0, AKAAUTSLength), 0x01)...), 0x90, 0x00)
	if err == nil {
		t.Fatal("ParseUSIMAuthResponse(non-padding trailing byte) err=nil, want error")
	}
}

func TestParseAUTSFields(t *testing.T) {
	raw := bytesFrom(0x10, AKAAUTSLength)
	fields, err := ParseAUTS(raw)
	if err != nil {
		t.Fatalf("ParseAUTS() error = %v", err)
	}
	if hex.EncodeToString(fields.SQNMSXorAK) != "101112131415" || hex.EncodeToString(fields.MACS) != "161718191a1b1c1d" {
		t.Fatalf("AUTS fields=%+v", fields)
	}

	raw[0] = 0xff
	rebuilt, err := fields.Bytes()
	if err != nil {
		t.Fatalf("AUTSFields.Bytes() error = %v", err)
	}
	if hex.EncodeToString(rebuilt) != "101112131415161718191a1b1c1d" {
		t.Fatalf("rebuilt AUTS=%x", rebuilt)
	}

	sqn, err := fields.SQNMS([]byte{1, 1, 1, 1, 1, 1})
	if err != nil {
		t.Fatalf("AUTSFields.SQNMS() error = %v", err)
	}
	if hex.EncodeToString(sqn) != "111013121514" {
		t.Fatalf("SQN_MS=%x", sqn)
	}

	if _, err := ParseAUTS(bytesFrom(0x20, AKAAUTSLength-1)); err == nil {
		t.Fatal("ParseAUTS(short) err=nil, want error")
	}
	if _, err := (AUTSFields{SQNMSXorAK: []byte{1}, MACS: bytesFrom(0x30, AKAMACLength)}).Bytes(); err == nil {
		t.Fatal("AUTSFields.Bytes(short SQN) err=nil, want error")
	}
	if _, err := fields.SQNMS([]byte{1}); err == nil {
		t.Fatal("AUTSFields.SQNMS(short AK) err=nil, want error")
	}
}

func TestParseUSIMAuthRejectsInvalidLengths(t *testing.T) {
	shortRES := append([]byte{0xDB, 0x02, 0x11, 0x22, 0x10}, bytesFrom(0x01, 16)...)
	shortRES = append(shortRES, 0x10)
	shortRES = append(shortRES, bytesFrom(0x21, 16)...)
	if _, err := ParseUSIMAuthResponse(shortRES, 0x90, 0x00); err == nil {
		t.Fatal("ParseUSIMAuthResponse(short RES) err=nil, want error")
	}

	shortCK := append([]byte{0xDB, 0x04, 0x11, 0x22, 0x33, 0x44, 0x0F}, bytesFrom(0x01, 15)...)
	shortCK = append(shortCK, 0x10)
	shortCK = append(shortCK, bytesFrom(0x21, 16)...)
	if _, err := ParseUSIMAuthResponse(shortCK, 0x90, 0x00); err == nil {
		t.Fatal("ParseUSIMAuthResponse(short CK) err=nil, want error")
	}

	badKc := append([]byte{0xDB, 0x04, 0x11, 0x22, 0x33, 0x44, 0x10}, bytesFrom(0x01, 16)...)
	badKc = append(badKc, 0x10)
	badKc = append(badKc, bytesFrom(0x21, 16)...)
	badKc = append(badKc, 0x07)
	badKc = append(badKc, bytesFrom(0x31, 7)...)
	if _, err := ParseUSIMAuthResponse(badKc, 0x90, 0x00); err == nil {
		t.Fatal("ParseUSIMAuthResponse(bad Kc) err=nil, want error")
	}

	wrongAUTS := append([]byte{0xDC, 0x02}, 0xAA, 0xBB)
	if _, err := ParseUSIMAuthResponse(wrongAUTS, 0x90, 0x00); err == nil {
		t.Fatal("ParseUSIMAuthResponse(short AUTS) err=nil, want error")
	}

	padded := append([]byte{0xDC, 0x0E}, bytesFrom(0xA0, 14)...)
	padded = append(padded, 0x00, 0xFF)
	if _, err := ParseUSIMAuthResponse(padded, 0x90, 0x00); !errors.Is(err, swusim.ErrSyncFailure) {
		t.Fatalf("ParseUSIMAuthResponse(padded AUTS) err=%v, want ErrSyncFailure", err)
	}
	trailing := append([]byte{0xDC, 0x0E}, bytesFrom(0xA0, 14)...)
	trailing = append(trailing, 0x01)
	if _, err := ParseUSIMAuthResponse(trailing, 0x90, 0x00); err == nil {
		t.Fatal("ParseUSIMAuthResponse(non-padding trailing TLV bytes) err=nil, want error")
	}
}

func bytesFrom(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}
