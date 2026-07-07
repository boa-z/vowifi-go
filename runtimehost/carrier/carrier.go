package carrier

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

type E911Config struct {
	Enabled             bool   `json:"enabled"`
	Provider            string `json:"provider"`
	Websheet            string `json:"websheet"`
	EntitlementEndpoint string `json:"entitlement_endpoint"`
}

type NetworkConfig struct {
	IMSRealm             string   `json:"ims_realm"`
	PrivateIdentityRealm string   `json:"private_identity_realm"`
	NAIRealm             string   `json:"nai_realm"`
	IMSAPN               string   `json:"ims_apn,omitempty"`
	EmergencyAPN         string   `json:"emergency_apn,omitempty"`
	PCSCFFQDN            string   `json:"pcscf_fqdn"`
	PCSCFFQDNs           []string `json:"pcscf_fqdns,omitempty"`
	EPDGFQDN             string   `json:"epdg_fqdn"`
	EmergencyDomain      string   `json:"emergency_domain"`
	EmergencyServiceURNs []string `json:"emergency_service_urns,omitempty"`
	AccessNetworkInfo    string   `json:"access_network_info,omitempty"`
	VisitedNetworkID     string   `json:"visited_network_id,omitempty"`
}

type networkConfigJSON struct {
	IMSRealm              string          `json:"ims_realm"`
	IMSDomain             string          `json:"ims_domain"`
	PrivateIdentityRealm  string          `json:"private_identity_realm"`
	PrivateIdentityDomain string          `json:"private_identity_domain"`
	NAIRealm              string          `json:"nai_realm"`
	NAIDomain             string          `json:"nai_domain"`
	IMSAPN                string          `json:"ims_apn"`
	APN                   string          `json:"apn"`
	EmergencyAPN          string          `json:"emergency_apn"`
	SOSAPN                string          `json:"sos_apn"`
	PCSCFFQDN             string          `json:"pcscf_fqdn"`
	PCSCFFQDNs            json.RawMessage `json:"pcscf_fqdns"`
	PCSCFFQDNList         json.RawMessage `json:"pcscf_fqdn_list"`
	PCSCFList             json.RawMessage `json:"pcscf_list"`
	PCSCF                 json.RawMessage `json:"pcscf"`
	EPDGFQDN              string          `json:"epdg_fqdn"`
	EPDG                  string          `json:"epdg"`
	EmergencyDomain       string          `json:"emergency_domain"`
	EmergencyRealm        string          `json:"emergency_realm"`
	EmergencyServiceURNs  json.RawMessage `json:"emergency_service_urns"`
	ServiceURNs           json.RawMessage `json:"service_urns"`
	AccessNetworkInfo     string          `json:"access_network_info"`
	PAccessNetworkInfo    string          `json:"p_access_network_info"`
	PANI                  string          `json:"pani"`
	VisitedNetworkID      string          `json:"visited_network_id"`
	PVisitedNetworkID     string          `json:"p_visited_network_id"`
	VisitedNetwork        string          `json:"visited_network"`
}

func (raw networkConfigJSON) networkConfig() (NetworkConfig, error) {
	pcscf, err := stringsFromNetworkJSON(raw.PCSCFFQDNs, true)
	if err != nil {
		return NetworkConfig{}, err
	}
	pcscfList, err := stringsFromNetworkJSON(raw.PCSCFFQDNList, true)
	if err != nil {
		return NetworkConfig{}, err
	}
	pcscfLegacyList, err := stringsFromNetworkJSON(raw.PCSCFList, true)
	if err != nil {
		return NetworkConfig{}, err
	}
	pcscfAlias, err := stringsFromNetworkJSON(raw.PCSCF, false)
	if err != nil {
		return NetworkConfig{}, err
	}
	emergencyServiceURNs, err := stringsFromNetworkJSON(raw.EmergencyServiceURNs, true)
	if err != nil {
		return NetworkConfig{}, err
	}
	serviceURNs, err := stringsFromNetworkJSON(raw.ServiceURNs, true)
	if err != nil {
		return NetworkConfig{}, err
	}
	return NetworkConfig{
		IMSRealm:             firstNetworkString(raw.IMSRealm, raw.IMSDomain),
		PrivateIdentityRealm: firstNetworkString(raw.PrivateIdentityRealm, raw.PrivateIdentityDomain),
		NAIRealm:             firstNetworkString(raw.NAIRealm, raw.NAIDomain),
		IMSAPN:               firstNetworkString(raw.IMSAPN, raw.APN),
		EmergencyAPN:         firstNetworkString(raw.EmergencyAPN, raw.SOSAPN),
		PCSCFFQDN:            raw.PCSCFFQDN,
		PCSCFFQDNs:           append(append(append(pcscf, pcscfList...), pcscfLegacyList...), pcscfAlias...),
		EPDGFQDN:             firstNetworkString(raw.EPDGFQDN, raw.EPDG),
		EmergencyDomain:      firstNetworkString(raw.EmergencyDomain, raw.EmergencyRealm),
		EmergencyServiceURNs: append(emergencyServiceURNs, serviceURNs...),
		AccessNetworkInfo:    firstNetworkString(raw.AccessNetworkInfo, raw.PAccessNetworkInfo, raw.PANI),
		VisitedNetworkID:     firstNetworkString(raw.VisitedNetworkID, raw.PVisitedNetworkID, raw.VisitedNetwork),
	}, nil
}

func (cfg *NetworkConfig) UnmarshalJSON(data []byte) error {
	var raw networkConfigJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	network, err := raw.networkConfig()
	if err != nil {
		return err
	}
	*cfg = network
	return nil
}

type SubscriberProfileInput struct {
	IMSI string
	MCC  string
	MNC  string
}

type SubscriberProfile struct {
	IMSI               string
	MCC                string
	MNC                string
	PresetID           string
	Network            NetworkConfig
	IMSPrivateIdentity string
	IMSPublicIdentity  string
	PermanentNAI       string
}

type IMSAccessProfileInput struct {
	IMSI string
	MCC  string
	MNC  string
}

type IMSAccessProfile struct {
	IMSI                 string
	MCC                  string
	MNC                  string
	PresetID             string
	IMSAPN               string
	EmergencyAPN         string
	IMSRealm             string
	PrivateIdentityRealm string
	NAIRealm             string
	PCSCFFQDNs           []string
	EPDGFQDN             string
	EmergencyDomain      string
	EmergencyServiceURNs []string
	IMSPrivateIdentity   string
	IMSPublicIdentity    string
	PermanentNAI         string
	AccessNetworkInfo    string
	VisitedNetworkID     string
}

type EffectiveCarrierConfig struct {
	MCC      string        `json:"mcc"`
	MNC      string        `json:"mnc"`
	PresetID string        `json:"preset_id"`
	E911     E911Config    `json:"e911"`
	Network  NetworkConfig `json:"network"`
}

func (cfg *EffectiveCarrierConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		MCC      string        `json:"mcc"`
		MNC      string        `json:"mnc"`
		PresetID string        `json:"preset_id"`
		E911     E911Config    `json:"e911"`
		Network  NetworkConfig `json:"network"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var aliases networkConfigJSON
	if err := json.Unmarshal(data, &aliases); err != nil {
		return err
	}
	aliasNetwork, err := aliases.networkConfig()
	if err != nil {
		return err
	}
	*cfg = EffectiveCarrierConfig{
		MCC:      raw.MCC,
		MNC:      raw.MNC,
		PresetID: raw.PresetID,
		E911:     raw.E911,
		Network:  mergeNetworkAliasConfig(raw.Network, aliasNetwork),
	}
	return nil
}

type EffectiveCarrierConfigInput struct {
	IMSI string
	MCC  string
	MNC  string
}

type LoadResult struct {
	Path    string
	Missing bool
	Count   int
}

var (
	overridesMu sync.RWMutex
	overrides   = map[string]EffectiveCarrierConfig{}
)

var builtinCarriers = map[string]EffectiveCarrierConfig{
	"310280": {
		MCC:      "310",
		MNC:      "280",
		PresetID: "310280",
		E911: E911Config{
			Enabled:             true,
			Provider:            "att-ts43",
			Websheet:            "https://www.att.com/acctmgmt/wireless/e911",
			EntitlementEndpoint: "https://sentitlement2.mobile.att.net/WFC",
		},
	},
	"310410": {
		MCC:      "310",
		MNC:      "410",
		PresetID: "310410",
		E911: E911Config{
			Enabled:             true,
			Provider:            "att-ts43",
			Websheet:            "https://www.att.com/acctmgmt/wireless/e911",
			EntitlementEndpoint: "https://sentitlement2.mobile.att.net/WFC",
		},
	},
}

func LoadCarrierOverrides(path string) (LoadResult, error) {
	path = strings.TrimSpace(path)
	result := LoadResult{Path: path, Missing: true}
	if path == "" {
		return result, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return result, nil
		}
		return result, err
	}
	var decoded map[string]EffectiveCarrierConfig
	if err := json.Unmarshal(raw, &decoded); err != nil {
		var list []EffectiveCarrierConfig
		if err2 := json.Unmarshal(raw, &list); err2 != nil {
			return result, err
		}
		decoded = make(map[string]EffectiveCarrierConfig, len(list))
		for _, cfg := range list {
			if key := presetKey(cfg.MCC, cfg.MNC); key != "" {
				decoded[key] = normalizeConfig(cfg)
			}
		}
	}
	next := make(map[string]EffectiveCarrierConfig, len(decoded))
	for key, cfg := range decoded {
		cfg = normalizeConfig(cfg)
		if cfg.MCC == "" || cfg.MNC == "" {
			cfg.MCC, cfg.MNC = splitPresetKey(key)
			cfg = normalizeConfig(cfg)
		}
		if cfg.PresetID != "" {
			key = cfg.PresetID
		}
		key = strings.TrimSpace(key)
		if key != "" {
			next[key] = cfg
		}
	}
	overridesMu.Lock()
	overrides = next
	overridesMu.Unlock()
	result.Missing = false
	result.Count = len(next)
	return result, nil
}

func ClearCarrierOverrides() {
	overridesMu.Lock()
	overrides = map[string]EffectiveCarrierConfig{}
	overridesMu.Unlock()
}

func ResolveEffectiveCarrierConfig(in EffectiveCarrierConfigInput) EffectiveCarrierConfig {
	profile := NormalizeSubscriberProfile(SubscriberProfileInput{
		IMSI: in.IMSI,
		MCC:  in.MCC,
		MNC:  in.MNC,
	})
	mcc := profile.MCC
	mnc := profile.MNC
	key := presetKey(mcc, mnc)
	overridesMu.RLock()
	if cfg, ok := overrides[key]; ok {
		overridesMu.RUnlock()
		return normalizeConfig(cfg)
	}
	overridesMu.RUnlock()
	if cfg, ok := builtinCarriers[key]; ok {
		return normalizeConfig(cfg)
	}
	return normalizeConfig(EffectiveCarrierConfig{
		MCC:      mcc,
		MNC:      mnc,
		PresetID: mcc + mnc,
		E911: E911Config{
			Enabled:  false,
			Provider: "",
		},
	})
}

func NormalizeSubscriberProfile(in SubscriberProfileInput) SubscriberProfile {
	imsi := strings.TrimSpace(in.IMSI)
	mcc := normalizeMCC(in.MCC)
	mnc := normalizeMNC(in.MNC)
	if isDecimalString(imsi) && mcc == "" && len(imsi) >= 3 {
		mcc = normalizeMCC(imsi[:3])
	}
	if isDecimalString(imsi) && mnc == "" {
		switch {
		case len(imsi) >= 6:
			mnc = normalizeMNC(imsi[3:6])
		case len(imsi) >= 5:
			mnc = normalizeMNC(imsi[3:5])
		}
	}
	network := normalizeNetworkConfig(mcc, mnc, NetworkConfig{})
	return SubscriberProfile{
		IMSI:               imsi,
		MCC:                mcc,
		MNC:                mnc,
		PresetID:           presetKey(mcc, mnc),
		Network:            network,
		IMSPrivateIdentity: DeriveIMSPrivateIdentityForNetwork(imsi, network),
		IMSPublicIdentity:  DeriveIMSPublicIdentityForNetwork(imsi, network),
		PermanentNAI:       DerivePermanentNAIForNetwork(imsi, network),
	}
}

func IMSAccessProfileForSubscriber(in IMSAccessProfileInput) IMSAccessProfile {
	cfg := ResolveEffectiveCarrierConfig(EffectiveCarrierConfigInput{
		IMSI: in.IMSI,
		MCC:  in.MCC,
		MNC:  in.MNC,
	})
	profile := NormalizeSubscriberProfile(SubscriberProfileInput{
		IMSI: in.IMSI,
		MCC:  cfg.MCC,
		MNC:  cfg.MNC,
	})
	network := cfg.Network
	return IMSAccessProfile{
		IMSI:                 profile.IMSI,
		MCC:                  cfg.MCC,
		MNC:                  cfg.MNC,
		PresetID:             cfg.PresetID,
		IMSAPN:               network.IMSAPN,
		EmergencyAPN:         network.EmergencyAPN,
		IMSRealm:             network.IMSRealm,
		PrivateIdentityRealm: network.PrivateIdentityRealm,
		NAIRealm:             network.NAIRealm,
		PCSCFFQDNs:           PCSCFCandidates(network),
		EPDGFQDN:             network.EPDGFQDN,
		EmergencyDomain:      network.EmergencyDomain,
		EmergencyServiceURNs: append([]string(nil), network.EmergencyServiceURNs...),
		IMSPrivateIdentity:   DeriveIMSPrivateIdentityForNetwork(profile.IMSI, network),
		IMSPublicIdentity:    DeriveIMSPublicIdentityForNetwork(profile.IMSI, network),
		PermanentNAI:         DerivePermanentNAIForNetwork(profile.IMSI, network),
		AccessNetworkInfo:    network.AccessNetworkInfo,
		VisitedNetworkID:     network.VisitedNetworkID,
	}
}

var blockedMCC = map[string]struct{}{
	"460": {},
}

func IsVoWiFiBlockedMCC(mcc string) bool {
	_, ok := blockedMCC[normalizeMCC(mcc)]
	return ok
}

type VoWiFiBlockedMCCError struct {
	MCC string
}

func (e VoWiFiBlockedMCCError) Error() string {
	return fmt.Sprintf("vowifi blocked by carrier policy for MCC %s", e.MCC)
}

func NewVoWiFiBlockedMCCError(mcc string) error {
	return VoWiFiBlockedMCCError{MCC: normalizeMCC(mcc)}
}

func IsVoWiFiPolicyBlockedError(err error) bool {
	var target VoWiFiBlockedMCCError
	return errors.As(err, &target)
}

func normalizeConfig(cfg EffectiveCarrierConfig) EffectiveCarrierConfig {
	cfg.MCC = normalizeMCC(cfg.MCC)
	cfg.MNC = normalizeMNC(cfg.MNC)
	if cfg.PresetID == "" {
		cfg.PresetID = presetKey(cfg.MCC, cfg.MNC)
	} else {
		cfg.PresetID = strings.TrimSpace(cfg.PresetID)
	}
	cfg.E911.Provider = strings.ToLower(strings.TrimSpace(cfg.E911.Provider))
	cfg.E911.Websheet = strings.TrimSpace(cfg.E911.Websheet)
	cfg.E911.EntitlementEndpoint = strings.TrimSpace(cfg.E911.EntitlementEndpoint)
	cfg.Network = normalizeNetworkConfig(cfg.MCC, cfg.MNC, cfg.Network)
	return cfg
}

func DefaultIMSRealm(mcc, mnc string) string {
	mcc = normalizeMCC(mcc)
	mnc = normalizeMNC(mnc)
	if mcc == "" || mnc == "" {
		return ""
	}
	return fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
}

func DefaultPrivateIdentityRealm(mcc, mnc string) string {
	return DefaultIMSRealm(mcc, mnc)
}

func DefaultNAIRealm(mcc, mnc string) string {
	mcc = normalizeMCC(mcc)
	mnc = normalizeMNC(mnc)
	if mcc == "" || mnc == "" {
		return ""
	}
	return fmt.Sprintf("nai.epc.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
}

func DefaultPCSCFFQDN(mcc, mnc string) string {
	mcc = normalizeMCC(mcc)
	mnc = normalizeMNC(mnc)
	if mcc == "" || mnc == "" {
		return ""
	}
	return fmt.Sprintf("pcscf.ims.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
}

func DefaultEPDGFQDN(mcc, mnc string) string {
	mcc = normalizeMCC(mcc)
	mnc = normalizeMNC(mnc)
	if mcc == "" || mnc == "" {
		return ""
	}
	return fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", mnc, mcc)
}

func DefaultEmergencyDomain(mcc, mnc string) string {
	return DefaultIMSRealm(mcc, mnc)
}

func DefaultIMSAPN() string {
	return "ims"
}

func DefaultEmergencyAPN() string {
	return "sos"
}

func DefaultEmergencyServiceURNs() []string {
	return []string{"urn:service:sos"}
}

func DeriveIMSPrivateIdentity(imsi, mcc, mnc string) string {
	return deriveIMSPrivateIdentityWithRealm(imsi, DefaultPrivateIdentityRealm(mcc, mnc))
}

func DeriveIMSPublicIdentity(imsi, mcc, mnc string) string {
	return deriveIMSPublicIdentityWithRealm(imsi, DefaultIMSRealm(mcc, mnc))
}

func DerivePermanentNAI(imsi, mcc, mnc string) string {
	return derivePermanentNAIWithRealm(imsi, DefaultNAIRealm(mcc, mnc))
}

func DeriveIMSPrivateIdentityForNetwork(imsi string, network NetworkConfig) string {
	network = normalizeNetworkConfig("", "", network)
	return deriveIMSPrivateIdentityWithRealm(imsi, network.PrivateIdentityRealm)
}

func DeriveIMSPublicIdentityForNetwork(imsi string, network NetworkConfig) string {
	network = normalizeNetworkConfig("", "", network)
	return deriveIMSPublicIdentityWithRealm(imsi, network.IMSRealm)
}

func DerivePermanentNAIForNetwork(imsi string, network NetworkConfig) string {
	network = normalizeNetworkConfig("", "", network)
	return derivePermanentNAIWithRealm(imsi, network.NAIRealm)
}

func deriveIMSPrivateIdentityWithRealm(imsi, realm string) string {
	imsi = normalizeIMSI(imsi)
	realm = normalizeDomainName(realm)
	if imsi == "" || realm == "" {
		return ""
	}
	return imsi + "@" + realm
}

func deriveIMSPublicIdentityWithRealm(imsi, realm string) string {
	imsi = normalizeIMSI(imsi)
	realm = normalizeDomainName(realm)
	if imsi == "" || realm == "" {
		return ""
	}
	return "sip:" + imsi + "@" + realm
}

func derivePermanentNAIWithRealm(imsi, realm string) string {
	imsi = normalizeIMSI(imsi)
	realm = normalizeDomainName(realm)
	if imsi == "" || realm == "" {
		return ""
	}
	return "0" + imsi + "@" + realm
}

func normalizeNetworkConfig(mcc, mnc string, cfg NetworkConfig) NetworkConfig {
	cfg.IMSRealm = normalizeDomainName(cfg.IMSRealm)
	cfg.PrivateIdentityRealm = normalizeDomainName(cfg.PrivateIdentityRealm)
	cfg.NAIRealm = normalizeDomainName(cfg.NAIRealm)
	cfg.IMSAPN = normalizeAPN(cfg.IMSAPN)
	cfg.EmergencyAPN = normalizeAPN(cfg.EmergencyAPN)
	cfg.PCSCFFQDN = normalizeDomainName(cfg.PCSCFFQDN)
	pcscfList := normalizeNetworkStringList(cfg.PCSCFFQDNs...)
	cfg.PCSCFFQDNs = appendNetworkStrings(nil, cfg.PCSCFFQDN)
	cfg.PCSCFFQDNs = appendNetworkStrings(cfg.PCSCFFQDNs, pcscfList...)
	if cfg.PCSCFFQDN == "" && len(cfg.PCSCFFQDNs) > 0 {
		cfg.PCSCFFQDN = cfg.PCSCFFQDNs[0]
	}
	cfg.EPDGFQDN = normalizeDomainName(cfg.EPDGFQDN)
	cfg.EmergencyDomain = normalizeDomainName(cfg.EmergencyDomain)
	cfg.EmergencyServiceURNs = normalizeEmergencyServiceURNs(cfg.EmergencyServiceURNs...)
	cfg.AccessNetworkInfo = strings.TrimSpace(cfg.AccessNetworkInfo)
	cfg.VisitedNetworkID = strings.TrimSpace(cfg.VisitedNetworkID)
	if mcc == "" || mnc == "" {
		if cfg.PrivateIdentityRealm == "" {
			cfg.PrivateIdentityRealm = cfg.IMSRealm
		}
		if cfg.EmergencyDomain == "" {
			cfg.EmergencyDomain = cfg.IMSRealm
		}
		return cfg
	}
	if cfg.IMSRealm == "" {
		cfg.IMSRealm = DefaultIMSRealm(mcc, mnc)
	}
	if cfg.PrivateIdentityRealm == "" {
		cfg.PrivateIdentityRealm = cfg.IMSRealm
	}
	if cfg.NAIRealm == "" {
		cfg.NAIRealm = DefaultNAIRealm(mcc, mnc)
	}
	if cfg.IMSAPN == "" {
		cfg.IMSAPN = DefaultIMSAPN()
	}
	if cfg.EmergencyAPN == "" {
		cfg.EmergencyAPN = DefaultEmergencyAPN()
	}
	if cfg.PCSCFFQDN == "" {
		cfg.PCSCFFQDN = DefaultPCSCFFQDN(mcc, mnc)
	}
	cfg.PCSCFFQDNs = appendNetworkStrings(cfg.PCSCFFQDNs, cfg.PCSCFFQDN)
	if cfg.EPDGFQDN == "" {
		cfg.EPDGFQDN = DefaultEPDGFQDN(mcc, mnc)
	}
	if cfg.EmergencyDomain == "" {
		cfg.EmergencyDomain = DefaultEmergencyDomain(mcc, mnc)
	}
	if len(cfg.EmergencyServiceURNs) == 0 {
		cfg.EmergencyServiceURNs = DefaultEmergencyServiceURNs()
	}
	return cfg
}

func PCSCFCandidates(network NetworkConfig) []string {
	network = normalizeNetworkConfig("", "", network)
	return append([]string(nil), network.PCSCFFQDNs...)
}

func stringsFromNetworkJSON(raw json.RawMessage, strict bool) ([]string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err == nil {
		return values, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		return splitNetworkStringList(value), nil
	}
	if !strict {
		return nil, nil
	}
	return nil, errors.New("network P-CSCF candidates must be a string or string array")
}

func splitNetworkStringList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ','
	})
	if len(fields) == 0 {
		return nil
	}
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if field = strings.TrimSpace(field); field != "" {
			out = append(out, field)
		}
	}
	return out
}

func normalizeNetworkStringList(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if normalized := normalizeDomainName(value); normalized != "" {
			out = append(out, normalized)
		}
	}
	return out
}

func appendNetworkStrings(out []string, values ...string) []string {
	for _, value := range values {
		value = normalizeDomainName(value)
		if value == "" {
			continue
		}
		duplicate := false
		for _, existing := range out {
			if existing == value {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, value)
		}
	}
	return out
}

func firstNetworkString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func mergeNetworkAliasConfig(base, alias NetworkConfig) NetworkConfig {
	if strings.TrimSpace(base.IMSRealm) == "" {
		base.IMSRealm = alias.IMSRealm
	}
	if strings.TrimSpace(base.PrivateIdentityRealm) == "" {
		base.PrivateIdentityRealm = alias.PrivateIdentityRealm
	}
	if strings.TrimSpace(base.NAIRealm) == "" {
		base.NAIRealm = alias.NAIRealm
	}
	if strings.TrimSpace(base.IMSAPN) == "" {
		base.IMSAPN = alias.IMSAPN
	}
	if strings.TrimSpace(base.EmergencyAPN) == "" {
		base.EmergencyAPN = alias.EmergencyAPN
	}
	if strings.TrimSpace(base.PCSCFFQDN) == "" {
		base.PCSCFFQDN = alias.PCSCFFQDN
	}
	base.PCSCFFQDNs = append(base.PCSCFFQDNs, alias.PCSCFFQDNs...)
	if strings.TrimSpace(base.EPDGFQDN) == "" {
		base.EPDGFQDN = alias.EPDGFQDN
	}
	if strings.TrimSpace(base.EmergencyDomain) == "" {
		base.EmergencyDomain = alias.EmergencyDomain
	}
	base.EmergencyServiceURNs = append(base.EmergencyServiceURNs, alias.EmergencyServiceURNs...)
	if strings.TrimSpace(base.AccessNetworkInfo) == "" {
		base.AccessNetworkInfo = alias.AccessNetworkInfo
	}
	if strings.TrimSpace(base.VisitedNetworkID) == "" {
		base.VisitedNetworkID = alias.VisitedNetworkID
	}
	return base
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

func normalizeDomainName(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(domain, ".")
}

func normalizeAPN(apn string) string {
	return strings.ToLower(strings.TrimSpace(apn))
}

func normalizeEmergencyServiceURNs(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		urn := normalizeEmergencyServiceURN(value)
		if urn == "" {
			continue
		}
		duplicate := false
		for _, existing := range out {
			if existing == urn {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, urn)
		}
	}
	return out
}

func normalizeEmergencyServiceURN(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	value = strings.TrimPrefix(value, "service:")
	switch value {
	case "911", "112", "sos", "urn:service:sos":
		return "urn:service:sos"
	}
	if strings.HasPrefix(value, "urn:service:sos") {
		return value
	}
	if strings.Contains(value, ":") {
		return ""
	}
	return "urn:service:sos." + strings.TrimPrefix(value, ".")
}

func presetKey(mcc, mnc string) string {
	mcc = normalizeMCC(mcc)
	mnc = normalizeMNC(mnc)
	if mcc == "" || mnc == "" {
		return ""
	}
	return mcc + mnc
}

func splitPresetKey(key string) (string, string) {
	key = strings.TrimSpace(key)
	if len(key) < 5 {
		return "", ""
	}
	return key[:3], key[3:]
}

func normalizeIMSI(imsi string) string {
	imsi = strings.TrimSpace(imsi)
	if len(imsi) < 5 || len(imsi) > 15 || !isDecimalString(imsi) {
		return ""
	}
	return imsi
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
