package identity

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/boa-z/vowifi-go/runtimehost/carrier"
	"github.com/boa-z/vowifi-go/runtimehost/simauth"
	"github.com/boa-z/vowifi-go/runtimehost/simtransport"
)

type isimTransportFake struct {
	aid          string
	openedAIDs   []string
	closed       []int
	calls        []string
	responses    []string
	resolvedAID  string
	resolveErr   error
	openErrByAID map[string]error
}

func (f *isimTransportFake) ResolveLogicalChannelAID(app string, fallbackAID string) (string, string, error) {
	if f.resolveErr != nil {
		return "", "", f.resolveErr
	}
	if strings.TrimSpace(f.resolvedAID) != "" {
		return f.resolvedAID, "test_card_status", nil
	}
	return "A0000000871004FFFFFFFF8903020000", "test_card_status", nil
}

func (f *isimTransportFake) OpenLogicalChannel(aid string) (int, error) {
	aid = strings.ToUpper(aid)
	f.aid = aid
	f.openedAIDs = append(f.openedAIDs, aid)
	if f.openErrByAID != nil {
		if err := f.openErrByAID[aid]; err != nil {
			return 0, err
		}
	}
	return 6 + len(f.openedAIDs), nil
}

func (f *isimTransportFake) CloseLogicalChannel(channel int) error {
	f.closed = append(f.closed, channel)
	return nil
}

func (f *isimTransportFake) TransmitAPDU(channel int, hexAPDU string) (string, error) {
	f.calls = append(f.calls, hexAPDU)
	if len(f.responses) == 0 {
		return "6A82", nil
	}
	resp := f.responses[0]
	f.responses = f.responses[1:]
	return resp, nil
}

func TestReadISIMIdentityReadsIMPIIMPUAndDomain(t *testing.T) {
	ft := &isimTransportFake{responses: []string{
		"9000",
		hexResponse(isimTLVString("310280233621715@private.att.net")),
		"9000",
		hexResponse(isimLengthString("one.att.net")),
		"6207820521000028029000",
		hexResponse(padRecord(isimTLVString("sip:310280233621715@one.att.net"), 40)),
		hexResponse(padRecord(isimLengthString("tel:+13105551212"), 40)),
	}}

	id, err := ReadISIMIdentity(ft)
	if err != nil {
		t.Fatalf("ReadISIMIdentity() error = %v", err)
	}
	if ft.aid != "A0000000871004FFFFFFFF8903020000" {
		t.Fatalf("opened AID = %q", ft.aid)
	}
	if !reflect.DeepEqual(ft.closed, []int{7}) {
		t.Fatalf("closed = %#v, want channel 7", ft.closed)
	}
	if id.IMPI != "310280233621715@private.att.net" || id.Domain != "one.att.net" {
		t.Fatalf("identity = %+v", id)
	}
	wantIMPU := []string{"sip:310280233621715@one.att.net", "tel:+13105551212"}
	if !reflect.DeepEqual(id.IMPU, wantIMPU) {
		t.Fatalf("IMPU = %#v, want %#v", id.IMPU, wantIMPU)
	}
	wantCalls := []string{
		"00A40004026F02", "00B0000000",
		"00A40004026F03", "00B0000000",
		"00A40004026F04", "00B2010428", "00B2020428",
	}
	if !reflect.DeepEqual(ft.calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", ft.calls, wantCalls)
	}
}

func TestReadISIMIdentityFallsBackToShortAIDWhenResolvedFullAIDOpenFails(t *testing.T) {
	fullISIM := simauth.ISIMAIDPrefix + "FFFFFFFF8903020000"
	ft := &isimTransportFake{
		resolvedAID: fullISIM,
		openErrByAID: map[string]error{
			fullISIM: errors.New("AT CME ERROR: operation not allowed"),
		},
		responses: []string{
			"9000",
			hexResponse(isimTLVString("310280233621715@private.att.net")),
			"6A82",
			"6A82",
		},
	}

	id, err := ReadISIMIdentity(ft)
	if err != nil {
		t.Fatalf("ReadISIMIdentity(short AID fallback) error = %v", err)
	}
	if id.IMPI != "310280233621715@private.att.net" {
		t.Fatalf("IMPI = %q, want ISIM value", id.IMPI)
	}
	if !reflect.DeepEqual(ft.openedAIDs, []string{fullISIM, simauth.ISIMAIDPrefix}) {
		t.Fatalf("opened AIDs = %#v, want full then short", ft.openedAIDs)
	}
	if !reflect.DeepEqual(ft.closed, []int{8}) {
		t.Fatalf("closed channels = %#v, want short channel 8", ft.closed)
	}
}

func TestReadISIMIdentityReturnsPartialIdentityForStrictPrepare(t *testing.T) {
	ft := &isimTransportFake{responses: []string{
		"9000",
		hexResponse(isimTLVString("310280233621715@private.att.net")),
		"6A82",
		"6A82",
	}}
	id, err := ReadISIMIdentity(ft)
	if err != nil {
		t.Fatalf("ReadISIMIdentity() error = %v", err)
	}
	if id.IMPI == "" || id.Domain != "" || len(id.IMPU) != 0 {
		t.Fatalf("identity = %+v, want partial IMPI only", id)
	}

	_, err = PrepareStart(PrepareStartInput{
		Profile: Profile{IMSI: "310280233621715"},
		Access:  partialAccess{id: id},
	})
	if err == nil || !strings.Contains(err.Error(), "ISIM 身份不完整") {
		t.Fatalf("PrepareStart() err = %v, want incomplete ISIM error", err)
	}
}

func TestPrepareStartPrefersSIPIMPUOverTEL(t *testing.T) {
	prepared, err := PrepareStart(PrepareStartInput{
		Profile: Profile{IMSI: "001010123456789"},
		Access: partialAccess{id: Identity{
			IMPI:   "001010123456789@private.example.test",
			IMPU:   []string{"tel:+15550101000", "sip:001010123456789@ims.example.test"},
			Domain: "ims.example.test",
		}},
	})
	if err != nil {
		t.Fatalf("PrepareStart() error = %v", err)
	}
	if got := prepared.IMSIdentity.IMPU; got != "sip:001010123456789@ims.example.test" {
		t.Fatalf("IMPU = %q, want SIP identity", got)
	}
}

func TestPrepareStartDerivesProfileIMSIdentityWith3GPPRealm(t *testing.T) {
	prepared, err := PrepareStart(PrepareStartInput{
		Profile: Profile{IMSI: "001010123456789"},
	})
	if err != nil {
		t.Fatalf("PrepareStart() error = %v", err)
	}
	if prepared.Profile.MCC != "001" || prepared.Profile.MNC != "010" {
		t.Fatalf("profile PLMN=(%q,%q), want 001/010", prepared.Profile.MCC, prepared.Profile.MNC)
	}
	if prepared.IMSIdentity.IMPI != "001010123456789@ims.mnc010.mcc001.3gppnetwork.org" ||
		prepared.IMSIdentity.IMPU != "sip:001010123456789@ims.mnc010.mcc001.3gppnetwork.org" ||
		prepared.IMSIdentity.Domain != "ims.mnc010.mcc001.3gppnetwork.org" ||
		prepared.IMSIdentity.ActualSource != IMSIdentitySourceProfile {
		t.Fatalf("profile IMS identity=%+v", prepared.IMSIdentity)
	}
	if prepared.EPDGAddr != "epdg.epc.mnc010.mcc001.pub.3gppnetwork.org" {
		t.Fatalf("EPDGAddr=%q", prepared.EPDGAddr)
	}
	for _, field := range []string{IdentityFieldMCC, IdentityFieldMNC} {
		meta, ok := fallbackByField(prepared.Fallbacks, field)
		if !ok || meta.PrimarySource != IMSISourceProfile || meta.FallbackSource != PLMNSourceIMSI || !meta.Used {
			t.Fatalf("%s fallback metadata=%+v ok=%t, want profile-to-IMSI fallback", field, meta, ok)
		}
	}
}

func TestPrepareStartNormalizesInvalidProfilePLMNFromIMSI(t *testing.T) {
	prepared, err := PrepareStart(PrepareStartInput{
		Profile: Profile{
			IMSI: "001010123456789",
			MCC:  "31x",
			MNC:  "1",
		},
	})
	if err != nil {
		t.Fatalf("PrepareStart() error = %v", err)
	}
	if prepared.Profile.MCC != "001" || prepared.Profile.MNC != "010" {
		t.Fatalf("profile PLMN=(%q,%q), want IMSI-derived 001/010", prepared.Profile.MCC, prepared.Profile.MNC)
	}
	for _, field := range []string{IdentityFieldMCC, IdentityFieldMNC} {
		meta, ok := fallbackByField(prepared.Fallbacks, field)
		if !ok || meta.FallbackSource != PLMNSourceIMSI || !strings.Contains(meta.Reason, "invalid") {
			t.Fatalf("%s fallback metadata=%+v ok=%t, want invalid profile PLMN fallback", field, meta, ok)
		}
	}
}

func TestPrepareStartRejectsInvalidIMSI(t *testing.T) {
	_, err := PrepareStart(PrepareStartInput{
		Profile: Profile{IMSI: "00101x123456789", MCC: "001", MNC: "010"},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid IMSI") {
		t.Fatalf("PrepareStart() err=%v, want invalid IMSI error", err)
	}
}

func TestPrepareStartUsesCarrierPrivateIdentityRealmOverride(t *testing.T) {
	carrier.ClearCarrierOverrides()
	t.Cleanup(carrier.ClearCarrierOverrides)

	path := t.TempDir() + "/carriers.json"
	if err := os.WriteFile(path, []byte(`{
		"001010": {
			"mcc": "001",
			"mnc": "010",
			"network": {
				"ims_realm": " ims.example.test. ",
				"private_identity_realm": " private.example.test. ",
				"pcscf_fqdn": " pcscf-a.example.test. ",
				"pcscf_fqdns": ["pcscf-b.example.test", "pcscf-a.example.test"],
				"epdg_fqdn": " epdg.example.test. "
			}
		}
	}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := carrier.LoadCarrierOverrides(path); err != nil {
		t.Fatalf("LoadCarrierOverrides() error = %v", err)
	}

	prepared, err := PrepareStart(PrepareStartInput{
		Profile: Profile{IMSI: "001010123456789"},
	})
	if err != nil {
		t.Fatalf("PrepareStart() error = %v", err)
	}
	if prepared.IMSIdentity.IMPI != "001010123456789@private.example.test" ||
		prepared.IMSIdentity.IMPU != "sip:001010123456789@ims.example.test" ||
		prepared.IMSIdentity.Domain != "ims.example.test" {
		t.Fatalf("profile IMS identity=%+v, want private IMPI realm with public IMS realm", prepared.IMSIdentity)
	}
	if prepared.EPDGAddr != "epdg.example.test" {
		t.Fatalf("EPDGAddr=%q, want override", prepared.EPDGAddr)
	}
	if !reflect.DeepEqual(prepared.PCSCFFQDNs, []string{"pcscf-a.example.test", "pcscf-b.example.test"}) {
		t.Fatalf("PCSCFFQDNs=%+v", prepared.PCSCFFQDNs)
	}
	if prepared.EffectiveCarrier.MCC != "001" || prepared.EffectiveCarrier.MNC != "010" ||
		prepared.EffectiveCarrier.PresetID != "001010" {
		t.Fatalf("EffectiveCarrier=%+v, want normalized override carrier", prepared.EffectiveCarrier)
	}
}

func TestPrepareStartPrefersDomainMatchedSIPIMPU(t *testing.T) {
	prepared, err := PrepareStart(PrepareStartInput{
		Profile: Profile{IMSI: "001010123456789"},
		Access: partialAccess{id: Identity{
			IMPI: "001010123456789@private.example.test",
			IMPU: []string{
				"sip:001010123456789@visited.example.test",
				"sip:001010123456789@ims.example.test;user=phone",
			},
			Domain: "ims.example.test",
		}},
	})
	if err != nil {
		t.Fatalf("PrepareStart() error = %v", err)
	}
	if got := prepared.IMSIdentity.IMPU; got != "sip:001010123456789@ims.example.test;user=phone" {
		t.Fatalf("IMPU = %q, want domain-matched SIP identity", got)
	}
}

func TestPrepareStartDerivesIMEIFromDeviceID(t *testing.T) {
	prepared, err := PrepareStart(PrepareStartInput{
		DeviceID: "quectel-imei-490154203237518-control",
		Profile:  Profile{IMSI: "001010123456789"},
	})
	if err != nil {
		t.Fatalf("PrepareStart() error = %v", err)
	}
	if prepared.Profile.IMEI != "490154203237518" || prepared.IdentityIMEISource != IMEISourceDeviceID {
		t.Fatalf("IMEI=%q source=%q, want device-derived IMEI", prepared.Profile.IMEI, prepared.IdentityIMEISource)
	}
}

func TestPrepareStartKeepsProfileIMEI(t *testing.T) {
	prepared, err := PrepareStart(PrepareStartInput{
		DeviceID: "quectel-imei-490154203237518-control",
		Profile:  Profile{IMSI: "001010123456789", IMEI: "356938035643809"},
	})
	if err != nil {
		t.Fatalf("PrepareStart() error = %v", err)
	}
	if prepared.Profile.IMEI != "356938035643809" || prepared.IdentityIMEISource != IMEISourceProfile {
		t.Fatalf("IMEI=%q source=%q, want profile IMEI", prepared.Profile.IMEI, prepared.IdentityIMEISource)
	}
}

func TestPrepareStartRecordsDeviceIDIMEIFallback(t *testing.T) {
	prepared, err := PrepareStart(PrepareStartInput{
		DeviceID: "modem-imei-490154203237518",
		Profile:  Profile{IMSI: "001010123456789"},
	})
	if err != nil {
		t.Fatalf("PrepareStart() error = %v", err)
	}
	if prepared.IdentityIMSISource != IMSISourceProfile || prepared.IdentityIMEISource != IMEISourceDeviceID {
		t.Fatalf("sources IMSI=%q IMEI=%q, want profile/device_id", prepared.IdentityIMSISource, prepared.IdentityIMEISource)
	}
	meta, ok := fallbackByField(prepared.Fallbacks, IdentityFieldIMEI)
	if !ok {
		t.Fatalf("Fallbacks=%#v, want IMEI fallback metadata", prepared.Fallbacks)
	}
	if meta.Field != IdentityFieldIMEI || meta.PrimarySource != IMEISourceProfile ||
		meta.FallbackSource != IMEISourceDeviceID || !meta.Used || meta.RecoveryClass != simtransport.RecoveryClassNone {
		t.Fatalf("IMEI fallback metadata=%+v", meta)
	}
}

func TestPrepareStartReadsIMEIFromAccess(t *testing.T) {
	prepared, err := PrepareStart(PrepareStartInput{
		Profile: Profile{IMSI: "001010123456789"},
		Access:  imeiAccess{imei: "imei:356938035643809"},
	})
	if err != nil {
		t.Fatalf("PrepareStart() error = %v", err)
	}
	if prepared.Profile.IMEI != "356938035643809" || prepared.IdentityIMEISource != IMEISourceModem {
		t.Fatalf("IMEI=%q source=%q, want modem IMEI", prepared.Profile.IMEI, prepared.IdentityIMEISource)
	}
	meta, ok := fallbackByField(prepared.Fallbacks, IdentityFieldIMEI)
	if !ok {
		t.Fatalf("Fallbacks=%#v, want IMEI fallback metadata", prepared.Fallbacks)
	}
	if meta.Field != IdentityFieldIMEI || meta.PrimarySource != IMEISourceProfile ||
		meta.FallbackSource != IMEISourceModem || !meta.Used || meta.RecoveryClass != simtransport.RecoveryClassNone {
		t.Fatalf("IMEI fallback metadata=%+v", meta)
	}
}

func TestPrepareStartFallsBackToDeviceIDAfterAccessIMEIFailure(t *testing.T) {
	prepared, err := PrepareStart(PrepareStartInput{
		DeviceID: "quectel-imei-490154203237518-control",
		Profile:  Profile{IMSI: "001010123456789"},
		Access:   imeiAccess{err: context.DeadlineExceeded},
	})
	if err != nil {
		t.Fatalf("PrepareStart() error = %v", err)
	}
	if prepared.Profile.IMEI != "490154203237518" || prepared.IdentityIMEISource != IMEISourceDeviceID {
		t.Fatalf("IMEI=%q source=%q, want device fallback", prepared.Profile.IMEI, prepared.IdentityIMEISource)
	}
	meta, ok := fallbackByField(prepared.Fallbacks, IdentityFieldIMEI)
	if !ok {
		t.Fatalf("Fallbacks=%#v, want IMEI fallback metadata", prepared.Fallbacks)
	}
	if meta.Field != IdentityFieldIMEI || meta.PrimarySource != IMEISourceModem ||
		meta.FallbackSource != IMEISourceDeviceID || !meta.Used || !meta.Recoverable ||
		meta.RecoveryClass != simtransport.RecoveryClassControlPortHung {
		t.Fatalf("IMEI fallback metadata=%+v", meta)
	}
	rec := meta.RecoveryRecommendation
	if rec.Action != simtransport.RecoveryActionATControlRecovery ||
		!rec.HardwareAffecting ||
		len(rec.ATControlPlan) != 2 ||
		rec.ATControlPlan[0].Command != "AT+CFUN=0" ||
		rec.ATControlPlan[1].Command != "AT+CFUN=1" {
		t.Fatalf("IMEI recovery recommendation=%+v", rec)
	}
}

func TestPrepareStartClassifiesISIMReadFallback(t *testing.T) {
	prepared, err := PrepareStart(PrepareStartInput{
		Profile: Profile{IMSI: "001010123456789", IMEI: "490154203237518"},
		Access:  failingAccess{err: context.DeadlineExceeded},
	})
	if err != nil {
		t.Fatalf("PrepareStart() error = %v", err)
	}
	if prepared.IMSIdentity.RequestedSource != IMSIdentitySourceISIM ||
		prepared.IMSIdentity.ActualSource != IMSIdentitySourceProfile ||
		!prepared.IMSIdentity.FallbackUsed ||
		prepared.IMSIdentity.RecoveryClass != simtransport.RecoveryClassControlPortHung {
		t.Fatalf("IMS fallback resolution=%+v", prepared.IMSIdentity)
	}
	meta, ok := fallbackByField(prepared.Fallbacks, IdentityFieldIMSIdentity)
	if !ok {
		t.Fatalf("Fallbacks=%#v, want ISIM fallback metadata", prepared.Fallbacks)
	}
	if meta.Field != IdentityFieldIMSIdentity || meta.PrimarySource != IMSIdentitySourceISIM ||
		meta.FallbackSource != IMSIdentitySourceProfile || !meta.Used || !meta.Recoverable ||
		meta.RecoveryClass != simtransport.RecoveryClassControlPortHung {
		t.Fatalf("ISIM fallback metadata=%+v", meta)
	}
}

func TestNewReadFallbackMetadataClassifiesIMSIReadFailure(t *testing.T) {
	meta := NewReadFallbackMetadata(IdentityFieldIMSI, "qmi", IMSISourceProfile, context.DeadlineExceeded)
	if meta.Field != IdentityFieldIMSI || meta.PrimarySource != "qmi" || meta.FallbackSource != IMSISourceProfile {
		t.Fatalf("metadata sources=%+v", meta)
	}
	if !meta.Used || !meta.Recoverable || meta.RecoveryClass != simtransport.RecoveryClassControlPortHung {
		t.Fatalf("metadata recovery=%+v, want control port hung fallback", meta)
	}
}

func TestExtractIMEIIgnoresNonIMEIDeviceID(t *testing.T) {
	if got := ExtractIMEI("dev-1"); got != "" {
		t.Fatalf("ExtractIMEI(dev-1) = %q, want empty", got)
	}
	if got := ExtractIMEI("prefix-490154203237518-suffix"); got != "490154203237518" {
		t.Fatalf("ExtractIMEI() = %q, want IMEI", got)
	}
}

func fallbackByField(fallbacks []FallbackMetadata, field string) (FallbackMetadata, bool) {
	for _, meta := range fallbacks {
		if meta.Field == field {
			return meta, true
		}
	}
	return FallbackMetadata{}, false
}

type partialAccess struct {
	id Identity
}

func (a partialAccess) GetISIMIdentity() (Identity, error) { return a.id, nil }

type imeiAccess struct {
	imei string
	err  error
}

func (a imeiAccess) GetISIMIdentity() (Identity, error) { return Identity{}, nil }

func (a imeiAccess) GetIMEI() (string, error) {
	if a.err != nil {
		return "", a.err
	}
	return a.imei, nil
}

type failingAccess struct {
	err error
}

func (a failingAccess) GetISIMIdentity() (Identity, error) { return Identity{}, a.err }

type crsmIdentityFake struct {
	binaryCalls []string
	recordCalls []string
	binary      []simtransport.CRSMResult
	records     []simtransport.CRSMResult
}

func (f *crsmIdentityFake) ReadCRSMBinary(fileID uint16, offset, length int, pathID string) (simtransport.CRSMResult, error) {
	f.binaryCalls = append(f.binaryCalls, crsmCall(fileID, offset, length, pathID))
	if len(f.binary) == 0 {
		return simtransport.CRSMResult{SW1: 0x6A, SW2: 0x82}, nil
	}
	resp := f.binary[0]
	f.binary = f.binary[1:]
	return resp, nil
}

func (f *crsmIdentityFake) ReadCRSMRecord(fileID uint16, record, length int, pathID string) (simtransport.CRSMResult, error) {
	f.recordCalls = append(f.recordCalls, crsmCall(fileID, record, length, pathID))
	if len(f.records) == 0 {
		return simtransport.CRSMResult{SW1: 0x6A, SW2: 0x82}, nil
	}
	resp := f.records[0]
	f.records = f.records[1:]
	return resp, nil
}

func TestReadISIMIdentityCRSMReadsIMPIIMPUAndDomain(t *testing.T) {
	ft := &crsmIdentityFake{
		binary: []simtransport.CRSMResult{
			crsmOK(isimTLVString("001010123456789@private.example.test")),
			crsmOK(isimLengthString("ims.example.test")),
		},
		records: []simtransport.CRSMResult{
			crsmOK(padRecord(isimTLVString("sip:001010123456789@ims.example.test"), 48)),
			crsmOK(padRecord(isimLengthString("tel:+15550101000"), 48)),
			{SW1: 0x6A, SW2: 0x83},
		},
	}

	id, err := ReadISIMIdentityCRSM(ft, "7fff")
	if err != nil {
		t.Fatalf("ReadISIMIdentityCRSM() error = %v", err)
	}
	if id.IMPI != "001010123456789@private.example.test" || id.Domain != "ims.example.test" {
		t.Fatalf("identity = %+v", id)
	}
	wantIMPU := []string{"sip:001010123456789@ims.example.test", "tel:+15550101000"}
	if !reflect.DeepEqual(id.IMPU, wantIMPU) {
		t.Fatalf("IMPU = %#v, want %#v", id.IMPU, wantIMPU)
	}
	if want := []string{"6F02/0/256/7fff", "6F03/0/256/7fff"}; !reflect.DeepEqual(ft.binaryCalls, want) {
		t.Fatalf("binary calls = %#v, want %#v", ft.binaryCalls, want)
	}
	if want := []string{"6F04/1/256/7fff", "6F04/2/256/7fff", "6F04/3/256/7fff"}; !reflect.DeepEqual(ft.recordCalls, want) {
		t.Fatalf("record calls = %#v, want %#v", ft.recordCalls, want)
	}
}

func TestReadISIMIdentityCRSMReadsLongFormISIMStrings(t *testing.T) {
	longIMPI := strings.Repeat("a", 118) + "@private.example.test"
	longDomain := strings.Repeat("ims", 43) + ".example.test"
	longIMPU := "sip:" + strings.Repeat("u", 116) + "@ims.example.test"
	ft := &crsmIdentityFake{
		binary: []simtransport.CRSMResult{
			crsmOK(isimTLVLongString(longIMPI)),
			crsmOK(isimLengthLongString(longDomain)),
		},
		records: []simtransport.CRSMResult{
			crsmOK(padRecord(isimTLVLongString(longIMPU), 180)),
			{SW1: 0x6A, SW2: 0x83},
		},
	}

	id, err := ReadISIMIdentityCRSM(ft, "7fff")
	if err != nil {
		t.Fatalf("ReadISIMIdentityCRSM(long form) error = %v", err)
	}
	if id.IMPI != longIMPI || id.Domain != longDomain || !reflect.DeepEqual(id.IMPU, []string{longIMPU}) {
		t.Fatalf("identity = %+v", id)
	}
}

func TestDecodeISIMStringSupportsFourByteLongFormLength(t *testing.T) {
	value := strings.Repeat("x", 130)
	tlv := append([]byte{0x80, 0x84, 0x00, 0x00, 0x00, byte(len(value))}, []byte(value)...)
	if got := decodeISIMString(tlv); got != value {
		t.Fatalf("decodeISIMString(TLV 0x84) length=%d want %d", len(got), len(value))
	}
	plain := append([]byte{0x84, 0x00, 0x00, 0x00, byte(len(value))}, []byte(value)...)
	if got := decodeISIMString(plain); got != value {
		t.Fatalf("decodeISIMString(plain 0x84) length=%d want %d", len(got), len(value))
	}
}

func TestReadISIMIdentityCRSMReturnsPartialIdentity(t *testing.T) {
	ft := &crsmIdentityFake{
		binary: []simtransport.CRSMResult{
			crsmOK(isimTLVString("001010123456789@private.example.test")),
			{SW1: 0x6A, SW2: 0x82},
		},
		records: []simtransport.CRSMResult{{SW1: 0x6A, SW2: 0x82}},
	}
	id, err := ReadISIMIdentityCRSM(ft, "")
	if err != nil {
		t.Fatalf("ReadISIMIdentityCRSM() error = %v", err)
	}
	if id.IMPI == "" || id.Domain != "" || len(id.IMPU) != 0 {
		t.Fatalf("identity = %+v, want partial IMPI only", id)
	}
}

func TestReadISIMIdentityCRSMReturnsErrorWhenNoEFCanBeRead(t *testing.T) {
	ft := &crsmIdentityFake{}
	_, err := ReadISIMIdentityCRSM(ft, "")
	if err == nil {
		t.Fatal("ReadISIMIdentityCRSM() err=nil, want joined read error")
	}
	if !strings.Contains(err.Error(), "CRSM read EF_IMPI") {
		t.Fatalf("err = %v, want CRSM EF read context", err)
	}
}

func TestReadISIMIdentityReturnsErrorWhenEFDataIsEmpty(t *testing.T) {
	ft := &isimTransportFake{responses: []string{"9000", "9000", "9000", "9000", "9000", "9000"}}
	_, err := ReadISIMIdentity(ft)
	if err == nil || !strings.Contains(err.Error(), "ISIM identity data empty") {
		t.Fatalf("ReadISIMIdentity(empty) err=%v, want empty identity error", err)
	}
	var readErr *ISIMIdentityReadError
	if !errors.As(err, &readErr) || readErr.Class != simtransport.RecoveryClassEmptyEF || !errors.Is(err, ErrISIMIdentityDataEmpty) {
		t.Fatalf("ReadISIMIdentity(empty) readErr=%+v err=%v, want empty EF class", readErr, err)
	}

	crsm := &crsmIdentityFake{
		binary:  []simtransport.CRSMResult{{SW1: 0x90, SW2: 0x00}, {SW1: 0x90, SW2: 0x00}},
		records: []simtransport.CRSMResult{{SW1: 0x90, SW2: 0x00}},
	}
	_, err = ReadISIMIdentityCRSM(crsm, "")
	if err == nil || !strings.Contains(err.Error(), "ISIM identity data empty") {
		t.Fatalf("ReadISIMIdentityCRSM(empty) err=%v, want empty identity error", err)
	}
	readErr = nil
	if !errors.As(err, &readErr) || readErr.Class != simtransport.RecoveryClassEmptyEF || !IsISIMIdentityDataEmpty(err) {
		t.Fatalf("ReadISIMIdentityCRSM(empty) readErr=%+v err=%v, want empty EF class", readErr, err)
	}
}

func TestReadISIMIdentityReturnsErrorWhenNoEFCanBeRead(t *testing.T) {
	ft := &isimTransportFake{responses: []string{"6A82", "6A82", "6A82"}}
	_, err := ReadISIMIdentity(ft)
	if err == nil {
		t.Fatal("ReadISIMIdentity() err=nil, want joined read error")
	}
	if !strings.Contains(err.Error(), "read EF_IMPI") {
		t.Fatalf("err = %v, want EF read context", err)
	}
}

func TestReadISIMIdentityClassifiesAPDUStatusFailures(t *testing.T) {
	ft := &isimTransportFake{responses: []string{"9300", "9300", "9300"}}
	_, err := ReadISIMIdentity(ft)
	if err == nil {
		t.Fatal("ReadISIMIdentity() err=nil, want SIM busy read error")
	}
	var readErr *ISIMIdentityReadError
	if !errors.As(err, &readErr) || readErr.Class != simtransport.RecoveryClassSIMBusy {
		t.Fatalf("ReadISIMIdentity() readErr=%+v err=%v, want SIM busy class", readErr, err)
	}
	if got := simtransport.ClassifyError(err); got != simtransport.RecoveryClassSIMBusy {
		t.Fatalf("ClassifyError(ReadISIMIdentity err) = %q, want SIM busy", got)
	}
	if !strings.Contains(err.Error(), "SW=9300") {
		t.Fatalf("err = %v, want status context", err)
	}
}

func TestReadISIMIdentityCRSMClassifiesStatusFailures(t *testing.T) {
	ft := &crsmIdentityFake{
		binary:  []simtransport.CRSMResult{{SW1: 0x93, SW2: 0x00}, {SW1: 0x93, SW2: 0x00}},
		records: []simtransport.CRSMResult{{SW1: 0x93, SW2: 0x00}},
	}
	_, err := ReadISIMIdentityCRSM(ft, "")
	if err == nil {
		t.Fatal("ReadISIMIdentityCRSM() err=nil, want SIM busy read error")
	}
	var readErr *ISIMIdentityReadError
	if !errors.As(err, &readErr) || readErr.Class != simtransport.RecoveryClassSIMBusy {
		t.Fatalf("ReadISIMIdentityCRSM() readErr=%+v err=%v, want SIM busy class", readErr, err)
	}
	if got := simtransport.ClassifyError(err); got != simtransport.RecoveryClassSIMBusy {
		t.Fatalf("ClassifyError(ReadISIMIdentityCRSM err) = %q, want SIM busy", got)
	}
	if !strings.Contains(err.Error(), "SW=9300") {
		t.Fatalf("err = %v, want status context", err)
	}
}

func isimTLVString(s string) []byte {
	return append([]byte{0x80, byte(len(s))}, []byte(s)...)
}

func isimTLVLongString(s string) []byte {
	return append(append([]byte{0x80}, isimLongLength(len(s))...), []byte(s)...)
}

func isimLengthString(s string) []byte {
	return append([]byte{byte(len(s))}, []byte(s)...)
}

func isimLengthLongString(s string) []byte {
	return append(isimLongLength(len(s)), []byte(s)...)
}

func isimLongLength(n int) []byte {
	switch {
	case n <= 0xff:
		return []byte{0x81, byte(n)}
	case n <= 0xffff:
		return []byte{0x82, byte(n >> 8), byte(n)}
	default:
		return []byte{0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func hexResponse(body []byte) string {
	out := append(append([]byte(nil), body...), 0x90, 0x00)
	return strings.ToUpper(hex.EncodeToString(out))
}

func crsmOK(body []byte) simtransport.CRSMResult {
	return simtransport.CRSMResult{Data: strings.ToUpper(hex.EncodeToString(body)), SW1: 0x90, SW2: 0x00}
}

func crsmCall(fileID uint16, p1, length int, pathID string) string {
	return strings.ToUpper(hex.EncodeToString([]byte{byte(fileID >> 8), byte(fileID)})) + "/" +
		strings.Join([]string{
			strconv.Itoa(p1),
			strconv.Itoa(length),
			pathID,
		}, "/")
}

func padRecord(body []byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = 0xFF
	}
	copy(out, body)
	return out
}
