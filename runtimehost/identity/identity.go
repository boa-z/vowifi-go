package identity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/boa-z/vowifi-go/runtimehost/carrier"
	"github.com/boa-z/vowifi-go/runtimehost/simauth"
	"github.com/boa-z/vowifi-go/runtimehost/simtransport"
)

const (
	IMSIdentitySourceProfile = "profile"
	IMSIdentitySourceISIM    = "isim"

	IMSISourceProfile = "profile"
	PLMNSourceIMSI    = "imsi"

	IdentityFieldMCC = "mcc"
	IdentityFieldMNC = "mnc"

	IMEISourceProfile     = "profile"
	IMEISourceDeviceID    = "device_id"
	IMEISourceUnavailable = "unavailable"

	AKAAppPreferenceUSIM       = "usim"
	AKAAppPreferenceAuto       = "auto"
	AKAAppPreferenceISIM       = "isim"
	AKAAppPreferenceISIMStrict = "isim_strict"
)

type Profile struct {
	IMSI string
	MCC  string
	MNC  string
	IMEI string
	SMSC string
}

type Identity struct {
	IMPI   string
	IMPU   []string
	Domain string
}

type IMSIdentityResolution struct {
	RequestedSource  string
	ActualSource     string
	AKAAppPreference string
	Applied          bool
	IMPI             string
	IMPU             string
	Domain           string
	FallbackUsed     bool
	FallbackReason   string
	RecoveryClass    simtransport.RecoveryClass
}

type EffectiveCarrier struct {
	MCC      string
	MNC      string
	PresetID string
}

type PreparedSession struct {
	Profile            Profile
	EffectiveCarrier   EffectiveCarrier
	EPDGAddr           string
	PCSCFFQDNs         []string
	EPDGSource         string
	IdentityIMSISource string
	IdentityIMEISource string
	IMSIdentity        IMSIdentityResolution
	Fallbacks          []FallbackMetadata
}

type PrepareStartInput struct {
	DeviceID            string
	Profile             Profile
	RuntimeEPDGOverride string
	Access              interface {
		GetISIMIdentity() (Identity, error)
	}
}

func NormalizeProfile(p Profile) Profile {
	p.IMSI = strings.TrimSpace(p.IMSI)
	p.MCC = normalizeMCC(p.MCC)
	p.MNC = normalizeMNC(p.MNC)
	p.IMEI = strings.TrimSpace(p.IMEI)
	p.SMSC = strings.TrimSpace(p.SMSC)
	imsiMCC, imsiMNC := plmnFromIMSI(p.IMSI)
	if p.MCC == "" {
		p.MCC = imsiMCC
	}
	if p.MNC == "" {
		p.MNC = imsiMNC
	}
	return p
}

func PrepareStart(in PrepareStartInput) (PreparedSession, error) {
	profile, fallbacks, err := prepareProfile(in.Profile)
	if err != nil {
		return PreparedSession{}, err
	}
	effectiveCfg := carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{
		IMSI: profile.IMSI,
		MCC:  profile.MCC,
		MNC:  profile.MNC,
	})
	if effectiveCfg.MCC != "" {
		profile.MCC = effectiveCfg.MCC
	}
	if effectiveCfg.MNC != "" {
		profile.MNC = effectiveCfg.MNC
	}
	imeiSource := IMEISourceProfile
	if profile.IMEI == "" {
		if imei := ExtractIMEI(in.DeviceID); imei != "" {
			profile.IMEI = imei
			imeiSource = IMEISourceDeviceID
			fallbacks = append(fallbacks, NewReadFallbackMetadata(
				IdentityFieldIMEI,
				IMEISourceProfile,
				IMEISourceDeviceID,
				errors.New("profile IMEI is empty"),
			))
		} else {
			imeiSource = IMEISourceUnavailable
			fallbacks = append(fallbacks, NewReadFallbackMetadata(
				IdentityFieldIMEI,
				IMEISourceProfile,
				"",
				errors.New("profile IMEI is empty and device ID fallback is unavailable"),
			))
		}
	}
	prepared := PreparedSession{
		Profile: profile,
		EffectiveCarrier: EffectiveCarrier{
			MCC:      effectiveCfg.MCC,
			MNC:      effectiveCfg.MNC,
			PresetID: effectiveCfg.PresetID,
		},
		EPDGAddr:           defaultEPDGWithNetwork(effectiveCfg.Network),
		PCSCFFQDNs:         carrier.PCSCFCandidates(effectiveCfg.Network),
		EPDGSource:         "derived",
		IdentityIMSISource: IMSISourceProfile,
		IdentityIMEISource: imeiSource,
		IMSIdentity: IMSIdentityResolution{
			RequestedSource:  IMSIdentitySourceProfile,
			ActualSource:     IMSIdentitySourceProfile,
			AKAAppPreference: AKAAppPreferenceUSIM,
			Applied:          true,
			IMPI:             profileIMPIWithNetwork(profile, effectiveCfg.Network),
			IMPU:             profileIMPUWithNetwork(profile, effectiveCfg.Network),
			Domain:           profileDomainWithNetwork(effectiveCfg.Network),
		},
		Fallbacks: fallbacks,
	}
	if override := strings.TrimSpace(in.RuntimeEPDGOverride); override != "" {
		prepared.EPDGAddr = override
		prepared.EPDGSource = "redirect"
	}
	if in.Access != nil {
		id, err := in.Access.GetISIMIdentity()
		if err != nil {
			meta := NewReadFallbackMetadata(IdentityFieldIMSIdentity, IMSIdentitySourceISIM, IMSIdentitySourceProfile, err)
			prepared.Fallbacks = append(prepared.Fallbacks, meta)
			prepared.IMSIdentity.RequestedSource = IMSIdentitySourceISIM
			prepared.IMSIdentity.ActualSource = IMSIdentitySourceProfile
			prepared.IMSIdentity.FallbackUsed = true
			prepared.IMSIdentity.FallbackReason = meta.Reason
			prepared.IMSIdentity.RecoveryClass = meta.RecoveryClass
		} else if strings.TrimSpace(id.IMPI) != "" || len(id.IMPU) > 0 || strings.TrimSpace(id.Domain) != "" {
			if strings.TrimSpace(id.IMPI) == "" || len(id.IMPU) == 0 || strings.TrimSpace(id.Domain) == "" {
				return PreparedSession{}, fmt.Errorf("ISIM 身份不完整: impi=%t impu=%d domain=%t",
					strings.TrimSpace(id.IMPI) != "", len(id.IMPU), strings.TrimSpace(id.Domain) != "")
			}
			prepared.IMSIdentity = IMSIdentityResolution{
				RequestedSource:  IMSIdentitySourceISIM,
				ActualSource:     IMSIdentitySourceISIM,
				AKAAppPreference: AKAAppPreferenceISIMStrict,
				Applied:          true,
				IMPI:             strings.TrimSpace(id.IMPI),
				IMPU:             selectISIMIMPU(id.IMPU, id.Domain, profile),
				Domain:           strings.TrimSpace(id.Domain),
			}
		}
	}
	return prepared, nil
}

func ExtractIMEI(value string) string {
	var digits []byte
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= '0' && b <= '9' {
			digits = append(digits, b)
			continue
		}
		if len(digits) == 15 {
			return string(digits)
		}
		digits = digits[:0]
	}
	if len(digits) == 15 {
		return string(digits)
	}
	return ""
}

func prepareProfile(p Profile) (Profile, []FallbackMetadata, error) {
	profile := Profile{
		IMSI: strings.TrimSpace(p.IMSI),
		MCC:  strings.TrimSpace(p.MCC),
		MNC:  strings.TrimSpace(p.MNC),
		IMEI: strings.TrimSpace(p.IMEI),
		SMSC: strings.TrimSpace(p.SMSC),
	}
	if profile.IMSI == "" {
		return Profile{}, nil, errors.New("IMSI is empty")
	}
	if normalized := normalizeIMSI(profile.IMSI); normalized != "" {
		profile.IMSI = normalized
	} else {
		return Profile{}, nil, fmt.Errorf("invalid IMSI %q: must be 5-15 decimal digits", profile.IMSI)
	}

	imsiMCC, imsiMNC := plmnFromIMSI(profile.IMSI)
	var fallbacks []FallbackMetadata
	if mcc := normalizeMCC(profile.MCC); mcc != "" {
		profile.MCC = mcc
	} else {
		fallbacks = append(fallbacks, profilePLMNFallbackMetadata(IdentityFieldMCC, profile.MCC))
		profile.MCC = imsiMCC
	}
	if mnc := normalizeMNC(profile.MNC); mnc != "" {
		profile.MNC = mnc
	} else {
		fallbacks = append(fallbacks, profilePLMNFallbackMetadata(IdentityFieldMNC, profile.MNC))
		profile.MNC = imsiMNC
	}
	return profile, fallbacks, nil
}

func profilePLMNFallbackMetadata(field, value string) FallbackMetadata {
	value = strings.TrimSpace(value)
	reason := fmt.Errorf("profile %s is empty; derived from IMSI", strings.ToUpper(field))
	if value != "" {
		reason = fmt.Errorf("profile %s %q is invalid; derived from IMSI", strings.ToUpper(field), value)
	}
	return NewReadFallbackMetadata(field, IMSISourceProfile, PLMNSourceIMSI, reason)
}

func normalizeIMSI(imsi string) string {
	imsi = strings.TrimSpace(imsi)
	if len(imsi) < 5 || len(imsi) > 15 || !isDecimalString(imsi) {
		return ""
	}
	return imsi
}

func normalizeMCC(mcc string) string {
	mcc = strings.TrimSpace(mcc)
	if len(mcc) != 3 || !isDecimalString(mcc) {
		return ""
	}
	return mcc
}

func normalizeMNC(mnc string) string {
	mnc = strings.TrimSpace(mnc)
	if !isDecimalString(mnc) {
		return ""
	}
	if len(mnc) == 2 {
		return "0" + mnc
	}
	if len(mnc) != 3 {
		return ""
	}
	return mnc
}

func plmnFromIMSI(imsi string) (string, string) {
	imsi = normalizeIMSI(imsi)
	if imsi == "" {
		return "", ""
	}
	mcc := normalizeMCC(imsi[:3])
	mnc := ""
	switch {
	case len(imsi) >= 6:
		mnc = normalizeMNC(imsi[3:6])
	case len(imsi) >= 5:
		mnc = normalizeMNC(imsi[3:5])
	}
	return mcc, mnc
}

func isDecimalString(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func selectISIMIMPU(impus []string, domain string, profile Profile) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	var firstSIP, firstAny string
	for _, impu := range impus {
		impu = strings.TrimSpace(impu)
		if impu == "" {
			continue
		}
		if firstAny == "" {
			firstAny = impu
		}
		if isSIPURI(impu) {
			if firstSIP == "" {
				firstSIP = impu
			}
			if domain != "" && strings.EqualFold(sipURIDomain(impu), domain) {
				return impu
			}
		}
	}
	if firstSIP != "" {
		return firstSIP
	}
	if firstAny != "" {
		return firstAny
	}
	return profileIMPU(profile)
}

func isSIPURI(uri string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(uri)), "sip:")
}

func sipURIDomain(uri string) string {
	uri = strings.TrimSpace(uri)
	if !isSIPURI(uri) {
		return ""
	}
	uri = uri[4:]
	if _, host, ok := strings.Cut(uri, "@"); ok {
		uri = host
	}
	if host, _, ok := strings.Cut(uri, ";"); ok {
		uri = host
	}
	if host, _, ok := strings.Cut(uri, ":"); ok {
		uri = host
	}
	return strings.ToLower(strings.TrimSpace(uri))
}

func profileIMPU(profile Profile) string {
	return profileIMPUWithNetwork(profile, profileNetwork(profile))
}

func profileIMPUWithNetwork(profile Profile, network carrier.NetworkConfig) string {
	imsi := normalizeIMSI(profile.IMSI)
	if imsi == "" {
		return ""
	}
	if impu := carrier.DeriveIMSPublicIdentityForNetwork(imsi, network); impu != "" {
		return impu
	}
	return ""
}

func profileIMPI(profile Profile) string {
	return profileIMPIWithNetwork(profile, profileNetwork(profile))
}

func profileIMPIWithNetwork(profile Profile, network carrier.NetworkConfig) string {
	imsi := normalizeIMSI(profile.IMSI)
	if imsi == "" {
		return ""
	}
	if impi := carrier.DeriveIMSPrivateIdentityForNetwork(imsi, network); impi != "" {
		return impi
	}
	return ""
}

func profileDomain(profile Profile) string {
	return profileDomainWithNetwork(profileNetwork(profile))
}

func profileDomainWithNetwork(network carrier.NetworkConfig) string {
	return strings.TrimSpace(network.IMSRealm)
}

func defaultEPDG(p Profile) string {
	return defaultEPDGWithNetwork(profileNetwork(p))
}

func defaultEPDGWithNetwork(network carrier.NetworkConfig) string {
	return strings.TrimSpace(network.EPDGFQDN)
}

func profileNetwork(profile Profile) carrier.NetworkConfig {
	return carrier.ResolveEffectiveCarrierConfig(carrier.EffectiveCarrierConfigInput{
		IMSI: profile.IMSI,
		MCC:  profile.MCC,
		MNC:  profile.MNC,
	}).Network
}

func ReadISIMIdentity(access interface {
	OpenLogicalChannel(aid string) (int, error)
	CloseLogicalChannel(channel int) error
	TransmitAPDU(channel int, hexAPDU string) (string, error)
}) (Identity, error) {
	if access == nil {
		return Identity{}, errors.New("nil ISIM access")
	}
	aid, _, err := simauth.ResolveAID(access, "isim", simauth.ISIMAIDPrefix, simauth.ISIMAIDPrefix)
	if err != nil {
		return Identity{}, err
	}
	channel, err := access.OpenLogicalChannel(aid)
	if err != nil {
		return Identity{}, fmt.Errorf("open ISIM logical channel: %w", err)
	}
	defer func() { _ = access.CloseLogicalChannel(channel) }()

	var id Identity
	var readErrs []error

	if raw, resp, err := simauth.ReadTransparentEF(access, channel, 0x6F02); err == nil {
		id.IMPI = decodeISIMString(raw)
	} else {
		readErrs = append(readErrs, classifyAPDUEFReadError("read EF_IMPI", resp, err))
	}

	if raw, resp, err := simauth.ReadTransparentEF(access, channel, 0x6F03); err == nil {
		id.Domain = decodeISIMString(raw)
	} else {
		readErrs = append(readErrs, classifyAPDUEFReadError("read EF_DOMAIN", resp, err))
	}

	if records, resp, err := simauth.ReadLinearFixedEF(access, channel, 0x6F04, 16); err == nil {
		for _, rec := range records {
			if impu := decodeISIMString(rec); impu != "" && !containsString(id.IMPU, impu) {
				id.IMPU = append(id.IMPU, impu)
			}
		}
	} else {
		readErrs = append(readErrs, classifyAPDUEFReadError("read EF_IMPU", resp, err))
	}

	if strings.TrimSpace(id.IMPI) != "" || strings.TrimSpace(id.Domain) != "" || len(id.IMPU) > 0 {
		return id, nil
	}
	return Identity{}, emptyISIMIdentityError(readErrs)
}

func ReadISIMIdentityCRSM(access interface {
	ReadCRSMBinary(fileID uint16, offset, length int, pathID string) (simtransport.CRSMResult, error)
	ReadCRSMRecord(fileID uint16, record, length int, pathID string) (simtransport.CRSMResult, error)
}, pathID string) (Identity, error) {
	if access == nil {
		return Identity{}, errors.New("nil ISIM CRSM access")
	}
	var id Identity
	var readErrs []error

	if raw, resp, err := readCRSMTransparentEF(access, 0x6F02, pathID); err == nil {
		id.IMPI = decodeISIMString(raw)
	} else {
		readErrs = append(readErrs, classifyCRSMEFReadError("CRSM read EF_IMPI", resp, err))
	}
	if raw, resp, err := readCRSMTransparentEF(access, 0x6F03, pathID); err == nil {
		id.Domain = decodeISIMString(raw)
	} else {
		readErrs = append(readErrs, classifyCRSMEFReadError("CRSM read EF_DOMAIN", resp, err))
	}
	if records, resp, err := readCRSMLinearFixedEF(access, 0x6F04, pathID, 16); err == nil {
		for _, rec := range records {
			if impu := decodeISIMString(rec); impu != "" && !containsString(id.IMPU, impu) {
				id.IMPU = append(id.IMPU, impu)
			}
		}
	} else {
		readErrs = append(readErrs, classifyCRSMEFReadError("CRSM read EF_IMPU", resp, err))
	}

	if strings.TrimSpace(id.IMPI) != "" || strings.TrimSpace(id.Domain) != "" || len(id.IMPU) > 0 {
		return id, nil
	}
	return Identity{}, emptyISIMIdentityError(readErrs)
}

func emptyISIMIdentityError(readErrs []error) error {
	if err := errors.Join(readErrs...); err != nil {
		return newISIMIdentityReadError(simtransport.ClassifyError(err), err)
	}
	return newISIMIdentityReadError(simtransport.RecoveryClassEmptyEF, ErrISIMIdentityDataEmpty)
}

func classifyAPDUEFReadError(context string, resp simauth.Response, err error) error {
	if err == nil {
		return nil
	}
	class := simtransport.StatusRecoveryClass(resp.SW1, resp.SW2)
	return newClassifiedReadError(class, fmt.Errorf("%s: %w", context, err))
}

func classifyCRSMEFReadError(context string, resp simtransport.CRSMResult, err error) error {
	if err == nil {
		return nil
	}
	return newClassifiedReadError(resp.RecoveryClass(), fmt.Errorf("%s: %w", context, err))
}

func readCRSMTransparentEF(access interface {
	ReadCRSMBinary(fileID uint16, offset, length int, pathID string) (simtransport.CRSMResult, error)
}, fid uint16, pathID string) ([]byte, simtransport.CRSMResult, error) {
	resp, err := access.ReadCRSMBinary(fid, 0, 256, pathID)
	if err != nil {
		return nil, resp, err
	}
	if !resp.Success() {
		return nil, resp, fmt.Errorf("READ BINARY %04X failed: SW=%s", fid, resp.StatusString())
	}
	raw, err := decodeCRSMHex(resp.Data)
	if err != nil {
		return nil, resp, err
	}
	return raw, resp, nil
}

func readCRSMLinearFixedEF(access interface {
	ReadCRSMRecord(fileID uint16, record, length int, pathID string) (simtransport.CRSMResult, error)
}, fid uint16, pathID string, maxRecords int) ([][]byte, simtransport.CRSMResult, error) {
	if maxRecords <= 0 {
		maxRecords = 16
	}
	var records [][]byte
	var last simtransport.CRSMResult
	for rec := 1; rec <= maxRecords; rec++ {
		resp, err := access.ReadCRSMRecord(fid, rec, 256, pathID)
		last = resp
		if err != nil {
			return nil, resp, err
		}
		if isCRSMRecordNotFound(resp.SW1, resp.SW2) {
			break
		}
		if !resp.Success() {
			return nil, resp, fmt.Errorf("READ RECORD %04X #%d failed: SW=%s", fid, rec, resp.StatusString())
		}
		raw, err := decodeCRSMHex(resp.Data)
		if err != nil {
			return nil, resp, err
		}
		if len(raw) == 0 {
			break
		}
		records = append(records, raw)
	}
	return records, last, nil
}

func decodeCRSMHex(data string) ([]byte, error) {
	if strings.TrimSpace(data) == "" {
		return nil, nil
	}
	raw, err := hex.DecodeString(strings.TrimSpace(data))
	if err != nil {
		return nil, fmt.Errorf("decode CRSM data: %w", err)
	}
	return raw, nil
}

func isCRSMRecordNotFound(sw1, sw2 byte) bool {
	return (sw1 == 0x6A && (sw2 == 0x82 || sw2 == 0x83)) ||
		(sw2 == 0x6A && (sw1 == 0x82 || sw1 == 0x83))
}

func decodeISIMString(raw []byte) string {
	data := trimISIMPadding(raw)
	if len(data) == 0 {
		return ""
	}
	if data[0] == 0x80 {
		if v, ok := decodeISIMDataObject(data[1:]); ok {
			return decodeISIMTextValue(v)
		}
	}
	if v, ok := simauth.FindTLV(data, 0x80); ok {
		if s := decodeISIMTextValue(v); s != "" {
			return s
		}
	}
	return decodeISIMStringValue(data)
}

func decodeISIMDataObject(data []byte) ([]byte, bool) {
	l, rest, ok := readISIMStringLength(data)
	if !ok || len(rest) < l {
		return nil, false
	}
	return rest[:l], true
}

func decodeISIMStringValue(data []byte) string {
	data = trimISIMPadding(data)
	if len(data) == 0 {
		return ""
	}
	if l, rest, ok := readISIMStringLength(data); ok && l > 0 && len(rest) >= l {
		return strings.TrimSpace(string(trimISIMPadding(rest[:l])))
	}
	return strings.TrimSpace(string(data))
}

func decodeISIMTextValue(data []byte) string {
	data = trimISIMPadding(data)
	if len(data) == 0 {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readISIMStringLength(data []byte) (int, []byte, bool) {
	if len(data) == 0 {
		return 0, nil, false
	}
	first := data[0]
	data = data[1:]
	if first&0x80 == 0 {
		return int(first), data, true
	}
	n := int(first & 0x7F)
	if n == 0 || n > 4 || len(data) < n {
		return 0, nil, false
	}
	length := 0
	for _, part := range data[:n] {
		if length > (math.MaxInt-int(part))/256 {
			return 0, nil, false
		}
		length = (length << 8) | int(part)
	}
	return length, data[n:], true
}

func trimISIMPadding(data []byte) []byte {
	start := 0
	for start < len(data) && (data[start] == 0x00 || data[start] == 0xFF) {
		start++
	}
	end := len(data)
	for end > start && (data[end-1] == 0x00 || data[end-1] == 0xFF) {
		end--
	}
	return data[start:end]
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
