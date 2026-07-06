package e911

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultEmergencyServiceURN = "urn:service:sos"

	IMSMMTelServiceIdentifier            = "urn:urn-7:3gpp-service.ims.icsi.mmtel"
	IMSEmergencyAcceptContact            = `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";require;explicit`
	EmergencySDPContentType              = "application/sdp"
	EmergencyPIDFLOContentType           = "application/pidf+xml"
	EmergencyMultipartRelatedContentType = "multipart/related"
	GeolocationRoutingYes                = "yes"
	GeolocationRoutingNo                 = "no"
)

const (
	defaultEmergencyPIDFLOEntity      = "pres:anonymous@invalid"
	defaultEmergencyPIDFLOTuple       = "e911-location"
	defaultEmergencyPIDFLOMethod      = "Manual"
	defaultEmergencyPIDFLOContentID   = "location-1"
	defaultEmergencySDPContentID      = "sdp"
	defaultEmergencyMultipartBoundary = "e911-pidf-lo"
)

type EmergencyServiceCategory uint8

const (
	EmergencyServiceCategoryPolice EmergencyServiceCategory = 1 << iota
	EmergencyServiceCategoryAmbulance
	EmergencyServiceCategoryFire
	EmergencyServiceCategoryMarine
	EmergencyServiceCategoryMountain
	EmergencyServiceCategoryManualECall
	EmergencyServiceCategoryAutomaticECall
)

type EmergencyAccessNetworkInfo struct {
	Raw        string
	AccessType string
	WLANNodeID string
}

type GeolocationHeaderValue struct {
	URI        string
	Parameters map[string]string
}

type EmergencyPIDFLOConfig struct {
	Entity    string
	TupleID   string
	Method    string
	Timestamp time.Time
	Address   EmergencyAddress
}

type EmergencyPIDFLOUsageRules struct {
	RetransmissionAllowed *bool
	RetentionExpiry       time.Time
	RulesetReference      string
	NoteWell              string
}

type EmergencyMultipartRelatedConfig struct {
	Boundary        string
	SDPContentID    string
	PIDFLOContentID string
}

type EmergencySIPHeaderConfig struct {
	ServiceURN         string
	AccessNetworkInfo  EmergencyAccessNetworkInfo
	GeolocationURI     string
	Address            EmergencyAddress
	GeolocationRouting bool
	PIDFLOContentID    string
	PIDFLOBody         []byte
}

type EmergencySIPRequestInfo struct {
	RequestURI      string
	Headers         map[string]string
	Routes          []EmergencyRoute
	RouteSet        []string
	PIDFLOContentID string
	PIDFLOBody      []byte
}

func NormalizeEmergencyServiceURN(s string) string {
	return normalizeEmergencyServiceURN(s)
}

func EmergencyRequestURI(service string) string {
	if urn := NormalizeEmergencyServiceURN(service); urn != "" {
		return urn
	}
	return DefaultEmergencyServiceURN
}

func EmergencyServiceURNsForCategory(category EmergencyServiceCategory) []string {
	if category == 0 {
		return []string{DefaultEmergencyServiceURN}
	}
	var out []string
	for _, mapping := range []struct {
		category EmergencyServiceCategory
		urn      string
	}{
		{EmergencyServiceCategoryPolice, "urn:service:sos.police"},
		{EmergencyServiceCategoryAmbulance, "urn:service:sos.ambulance"},
		{EmergencyServiceCategoryFire, "urn:service:sos.fire"},
		{EmergencyServiceCategoryMarine, "urn:service:sos.marine"},
		{EmergencyServiceCategoryMountain, "urn:service:sos.mountain"},
		{EmergencyServiceCategoryManualECall, "urn:service:sos.ecall.manual"},
		{EmergencyServiceCategoryAutomaticECall, "urn:service:sos.ecall.automatic"},
	} {
		if category&mapping.category != 0 {
			out = append(out, mapping.urn)
		}
	}
	if len(out) == 0 {
		return []string{DefaultEmergencyServiceURN}
	}
	return out
}

func BuildPAccessNetworkInfo(info EmergencyAccessNetworkInfo) string {
	if raw := strings.TrimSpace(info.Raw); raw != "" {
		return raw
	}
	accessType := strings.TrimSpace(info.AccessType)
	if accessType == "" {
		accessType = "IEEE-802.11"
	}
	if nodeID := strings.TrimSpace(info.WLANNodeID); nodeID != "" {
		return accessType + `;i-wlan-node-id=` + quoteSIPParamValue(nodeID)
	}
	return accessType
}

func BuildEmergencySIPHeaders(cfg EmergencySIPHeaderConfig) map[string]string {
	headers := map[string]string{
		"P-Preferred-Service":   IMSMMTelServiceIdentifier,
		"Accept-Contact":        IMSEmergencyAcceptContact,
		"P-Access-Network-Info": BuildPAccessNetworkInfo(cfg.AccessNetworkInfo),
	}
	if geolocation := emergencyGeolocationHeader(cfg); geolocation != "" {
		headers["Geolocation"] = geolocation
		if cfg.GeolocationRouting {
			headers["Geolocation-Routing"] = GeolocationRoutingYes
		}
	}
	return headers
}

func BuildEmergencySIPRequestInfo(cfg EmergencySIPHeaderConfig) EmergencySIPRequestInfo {
	return EmergencySIPRequestInfo{
		RequestURI:      EmergencyRequestURI(cfg.ServiceURN),
		Headers:         BuildEmergencySIPHeaders(cfg),
		PIDFLOContentID: strings.TrimSpace(cfg.PIDFLOContentID),
		PIDFLOBody:      append([]byte(nil), cfg.PIDFLOBody...),
	}
}

func ParseGeolocationHeader(header string) ([]GeolocationHeaderValue, error) {
	parts, err := splitSIPHeaderSegments(header, ',')
	if err != nil {
		return nil, err
	}
	var out []GeolocationHeaderValue
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		value, err := parseGeolocationHeaderValue(part)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

func NormalizeGeolocationRoutingHeader(header string) (string, error) {
	allowed, present, err := ParseGeolocationRoutingHeader(header)
	if err != nil || !present {
		return "", err
	}
	if allowed {
		return GeolocationRoutingYes, nil
	}
	return GeolocationRoutingNo, nil
}

func ParseGeolocationRoutingHeader(header string) (allowed bool, present bool, err error) {
	parts, err := splitSIPHeaderSegments(header, ',')
	if err != nil {
		return false, false, err
	}
	var normalized string
	for _, part := range parts {
		value, err := normalizeGeolocationRoutingValue(part)
		if err != nil {
			return false, false, err
		}
		if value == "" {
			continue
		}
		if normalized != "" && normalized != value {
			return false, false, errors.New("invalid geolocation-routing header: conflicting values")
		}
		normalized = value
	}
	switch normalized {
	case GeolocationRoutingYes:
		return true, true, nil
	case GeolocationRoutingNo:
		return false, true, nil
	default:
		return false, false, nil
	}
}

func BuildEmergencyPIDFLO(cfg EmergencyPIDFLOConfig) ([]byte, error) {
	return BuildEmergencyPIDFLOWithUsageRules(cfg, EmergencyPIDFLOUsageRules{})
}

func BuildEmergencyPIDFLOWithUsageRules(cfg EmergencyPIDFLOConfig, rules EmergencyPIDFLOUsageRules) ([]byte, error) {
	if !emergencyAddressHasPIDFLOLocation(cfg.Address) {
		return nil, errors.New("e911 pidf-lo requires emergency location")
	}
	if err := validateEmergencyPIDFLOUsageRules(cfg, rules); err != nil {
		return nil, err
	}
	entity := firstNonEmpty(cfg.Entity, defaultEmergencyPIDFLOEntity)
	tupleID := firstNonEmpty(cfg.TupleID, defaultEmergencyPIDFLOTuple)
	method := firstNonEmpty(cfg.Method, defaultEmergencyPIDFLOMethod)

	var body bytes.Buffer
	body.WriteString(xml.Header)
	enc := xml.NewEncoder(&body)
	enc.Indent("", "  ")

	if err := encodePIDFLOStart(enc, "presence",
		xml.Attr{Name: xml.Name{Local: "xmlns"}, Value: "urn:ietf:params:xml:ns:pidf"},
		xml.Attr{Name: xml.Name{Local: "xmlns:gp"}, Value: "urn:ietf:params:xml:ns:pidf:geopriv10"},
		xml.Attr{Name: xml.Name{Local: "xmlns:cl"}, Value: "urn:ietf:params:xml:ns:pidf:geopriv10:civicAddr"},
		xml.Attr{Name: xml.Name{Local: "xmlns:gml"}, Value: "http://www.opengis.net/gml"},
		xml.Attr{Name: xml.Name{Local: "entity"}, Value: entity},
	); err != nil {
		return nil, err
	}
	if err := encodePIDFLOStart(enc, "tuple", xml.Attr{Name: xml.Name{Local: "id"}, Value: tupleID}); err != nil {
		return nil, err
	}
	if err := encodePIDFLOStart(enc, "status"); err != nil {
		return nil, err
	}
	if err := encodePIDFLOStart(enc, "gp:geopriv"); err != nil {
		return nil, err
	}
	if err := encodePIDFLOStart(enc, "gp:location-info"); err != nil {
		return nil, err
	}
	if emergencyAddressHasGeolocation(cfg.Address) {
		if err := encodePIDFLOStart(enc, "gml:Point", xml.Attr{Name: xml.Name{Local: "srsName"}, Value: "urn:ogc:def:crs:EPSG::4326"}); err != nil {
			return nil, err
		}
		if err := encodePIDFLOTextElement(enc, "gml:pos", strings.TrimSpace(cfg.Address.Latitude)+" "+strings.TrimSpace(cfg.Address.Longitude)); err != nil {
			return nil, err
		}
		if err := encodePIDFLOEnd(enc, "gml:Point"); err != nil {
			return nil, err
		}
	}
	civicFields := emergencyAddressPIDFLOCivicFields(cfg.Address)
	if len(civicFields) > 0 {
		if err := encodePIDFLOStart(enc, "cl:civicAddress"); err != nil {
			return nil, err
		}
		for _, field := range civicFields {
			if err := encodePIDFLOTextElement(enc, "cl:"+field.name, field.value); err != nil {
				return nil, err
			}
		}
		if err := encodePIDFLOEnd(enc, "cl:civicAddress"); err != nil {
			return nil, err
		}
	}
	if err := encodePIDFLOEnd(enc, "gp:location-info"); err != nil {
		return nil, err
	}
	if err := encodePIDFLOUsageRules(enc, rules); err != nil {
		return nil, err
	}
	if err := encodePIDFLOTextElement(enc, "gp:method", method); err != nil {
		return nil, err
	}
	if err := encodePIDFLOEnd(enc, "gp:geopriv"); err != nil {
		return nil, err
	}
	if err := encodePIDFLOEnd(enc, "status"); err != nil {
		return nil, err
	}
	if !cfg.Timestamp.IsZero() {
		if err := encodePIDFLOTextElement(enc, "timestamp", cfg.Timestamp.UTC().Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
	}
	if err := encodePIDFLOEnd(enc, "tuple"); err != nil {
		return nil, err
	}
	if err := encodePIDFLOEnd(enc, "presence"); err != nil {
		return nil, err
	}
	if err := enc.Flush(); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func BuildEmergencyPIDFLOMultipartBody(sdp, pidfLO []byte, cfg EmergencyMultipartRelatedConfig) (string, []byte, error) {
	if len(pidfLO) == 0 {
		return "", nil, errors.New("e911 multipart body requires pidf-lo body")
	}
	sdpContentID, err := normalizeEmergencyContentID(cfg.SDPContentID, defaultEmergencySDPContentID)
	if err != nil {
		return "", nil, err
	}
	pidfContentID, err := normalizeEmergencyContentID(cfg.PIDFLOContentID, defaultEmergencyPIDFLOContentID)
	if err != nil {
		return "", nil, err
	}
	if strings.EqualFold(sdpContentID, pidfContentID) {
		return "", nil, errors.New("e911 multipart body requires distinct content ids")
	}
	boundary := strings.TrimSpace(cfg.Boundary)
	if boundary == "" {
		boundary = chooseEmergencyMultipartBoundary(sdp, pidfLO)
	}
	if err := validateEmergencyMultipartBoundary(boundary); err != nil {
		return "", nil, err
	}
	if emergencyMultipartBoundaryCollides(boundary, sdp, pidfLO) {
		return "", nil, errors.New("e911 multipart boundary collides with body")
	}

	var body bytes.Buffer
	appendEmergencyMultipartPart(&body, boundary, EmergencySDPContentType, sdpContentID, "session;handling=required", sdp)
	appendEmergencyMultipartPart(&body, boundary, EmergencyPIDFLOContentType, pidfContentID, "by-reference;handling=optional", pidfLO)
	body.WriteString("--")
	body.WriteString(boundary)
	body.WriteString("--\r\n")

	contentType := EmergencyMultipartRelatedContentType +
		`;boundary=` + boundary +
		`;type="` + EmergencySDPContentType + `"` +
		`;start="<` + sdpContentID + `>"`
	return contentType, body.Bytes(), nil
}

func ParseEmergencyPIDFLO(body []byte) (EmergencyAddress, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	var stack []pidfLOElement
	var result entitlementResult
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return EmergencyAddress{}, err
		}
		switch x := token.(type) {
		case xml.StartElement:
			key := ""
			if inPIDFLOCivicAddress(stack) {
				key = x.Name.Local
			} else if isPIDFLOGeodeticPositionElement(x.Name.Local) {
				key = pidfLOPositionKey
			}
			stack = append(stack, pidfLOElement{local: x.Name.Local, key: key})
		case xml.CharData:
			if len(stack) == 0 || stack[len(stack)-1].key == "" {
				continue
			}
			stack[len(stack)-1].text = append(stack[len(stack)-1].text, x...)
		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}
			elem := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			text := strings.TrimSpace(string(elem.text))
			if text == "" {
				continue
			}
			if elem.key == pidfLOPositionKey {
				collectPIDFLOGeodeticPosition(text, &result)
				continue
			}
			collectEmergencyAddressField(elem.key, text, &result)
		}
	}
	address := emergencyAddressFromFields(result.EmergencyAddress)
	if !emergencyAddressHasPIDFLOLocation(address) {
		return EmergencyAddress{}, errors.New("pidf-lo does not contain emergency location")
	}
	return address, nil
}

// UsableEmergencySIPRequestInfo builds runtime SIP request metadata from this
// snapshot when the cached entitlement data is still locally usable.
func (s EntitlementSnapshot) UsableEmergencySIPRequestInfo(cfg EmergencySIPHeaderConfig) (EmergencySIPRequestInfo, bool) {
	return buildUsableEmergencySIPRequestInfo(s, cfg)
}

func BuildUsableEmergencySIPRequestInfo(snapshot EntitlementSnapshot, cfg EmergencySIPHeaderConfig) (EmergencySIPRequestInfo, bool) {
	return buildUsableEmergencySIPRequestInfo(snapshot, cfg)
}

func buildUsableEmergencySIPRequestInfo(snapshot EntitlementSnapshot, cfg EmergencySIPHeaderConfig) (EmergencySIPRequestInfo, bool) {
	if !snapshot.Usable() {
		return EmergencySIPRequestInfo{}, false
	}
	serviceURN, routes, ok := usableEmergencySIPService(snapshot, cfg.ServiceURN)
	if !ok {
		return EmergencySIPRequestInfo{}, false
	}
	cfg.ServiceURN = serviceURN
	if strings.TrimSpace(cfg.GeolocationURI) == "" && !emergencyAddressHasGeolocation(cfg.Address) {
		cfg.Address = snapshot.Info.Address
	}
	info := BuildEmergencySIPRequestInfo(cfg)
	info.Routes = copyEmergencyRoutes(routes)
	info.RouteSet = EmergencySIPRouteSet(routes)
	return info, true
}

func EmergencySIPRouteSet(routes []EmergencyRoute) []string {
	var out []string
	for _, route := range routes {
		out = appendEmergencySIPRouteSet(out, route.PCSCF...)
		out = appendEmergencySIPRouteSet(out, route.ESRP...)
		out = appendEmergencySIPRouteSet(out, route.Endpoints...)
	}
	return out
}

func appendEmergencySIPRouteSet(dst []string, values ...string) []string {
	for _, value := range values {
		route := formatEmergencySIPRoute(value)
		if route == "" || containsSIPRoute(dst, route) {
			continue
		}
		dst = append(dst, route)
	}
	return dst
}

func formatEmergencySIPRoute(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "<") {
		return value
	}
	uri := value
	lower := strings.ToLower(uri)
	if !strings.HasPrefix(lower, "sip:") && !strings.HasPrefix(lower, "sips:") && !strings.Contains(uri, ":") {
		uri = "sip:" + uri
		lower = strings.ToLower(uri)
	}
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		uri = ensureLooseRoute(uri)
	}
	return "<" + uri + ">"
}

func ensureLooseRoute(uri string) string {
	base, suffix, ok := strings.Cut(uri, "?")
	if strings.Contains(strings.ToLower(base), ";lr") {
		return uri
	}
	if ok {
		return base + ";lr?" + suffix
	}
	return base + ";lr"
}

func containsSIPRoute(routes []string, route string) bool {
	for _, existing := range routes {
		if strings.EqualFold(existing, route) {
			return true
		}
	}
	return false
}

func emergencyGeolocationHeader(cfg EmergencySIPHeaderConfig) string {
	if uri := strings.TrimSpace(cfg.GeolocationURI); uri != "" {
		return formatGeolocationURI(uri)
	}
	if len(cfg.PIDFLOBody) > 0 || strings.TrimSpace(cfg.PIDFLOContentID) != "" {
		if contentID := emergencyContentIDForHeader(cfg.PIDFLOContentID, defaultEmergencyPIDFLOContentID); contentID != "" {
			return formatGeolocationURI("cid:" + contentID)
		}
	}
	lat := strings.TrimSpace(cfg.Address.Latitude)
	lon := strings.TrimSpace(cfg.Address.Longitude)
	if lat == "" || lon == "" {
		return ""
	}
	return formatGeolocationURI("geo:" + lat + "," + lon)
}

func usableEmergencySIPService(snapshot EntitlementSnapshot, requested string) (string, []EmergencyRoute, bool) {
	requested = normalizeEmergencyServiceURN(requested)
	if requested != "" {
		routes := snapshot.UsableRoutes(requested)
		if containsEmergencyServiceURN(snapshot.UsableServiceURNs(), requested) || len(routes) > 0 {
			return requested, routes, true
		}
		return "", nil, false
	}
	for _, urn := range snapshot.UsableServiceURNs() {
		urn = normalizeEmergencyServiceURN(urn)
		if urn != "" {
			return urn, snapshot.UsableRoutes(urn), true
		}
	}
	return "", nil, false
}

func containsEmergencyServiceURN(urns []string, urn string) bool {
	urn = normalizeEmergencyServiceURN(urn)
	if urn == "" {
		return false
	}
	for _, candidate := range urns {
		if strings.EqualFold(normalizeEmergencyServiceURN(candidate), urn) {
			return true
		}
	}
	return false
}

func emergencyAddressHasGeolocation(address EmergencyAddress) bool {
	return strings.TrimSpace(address.Latitude) != "" && strings.TrimSpace(address.Longitude) != ""
}

func formatGeolocationURI(uri string) string {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return ""
	}
	if strings.HasPrefix(uri, "<") {
		return uri
	}
	return "<" + uri + ">;inserted-by=endpoint"
}

func parseGeolocationHeaderValue(value string) (GeolocationHeaderValue, error) {
	var uri string
	var params string
	if strings.HasPrefix(value, "<") {
		end := strings.Index(value, ">")
		if end < 0 {
			return GeolocationHeaderValue{}, errors.New("invalid geolocation header: missing closing angle")
		}
		uri = strings.TrimSpace(value[1:end])
		params = strings.TrimSpace(value[end+1:])
		if params != "" && !strings.HasPrefix(params, ";") {
			return GeolocationHeaderValue{}, errors.New("invalid geolocation header: unexpected text after URI")
		}
	} else {
		uri, params, _ = strings.Cut(value, ";")
		uri = strings.TrimSpace(uri)
		if params != "" {
			params = ";" + params
		}
	}
	if uri == "" {
		return GeolocationHeaderValue{}, errors.New("invalid geolocation header: empty URI")
	}
	parsedParams, err := parseSIPHeaderParameters(params)
	if err != nil {
		return GeolocationHeaderValue{}, err
	}
	return GeolocationHeaderValue{URI: uri, Parameters: parsedParams}, nil
}

func normalizeGeolocationRoutingValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	key, params, hasParams := strings.Cut(value, ";")
	if hasParams && strings.TrimSpace(params) != "" {
		return "", errors.New("invalid geolocation-routing header: unexpected parameters")
	}
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, `"`) || strings.HasSuffix(key, `"`) {
		if len(key) < 2 || key[0] != '"' || key[len(key)-1] != '"' {
			return "", errors.New("invalid geolocation-routing header: unterminated quoted value")
		}
		key = unquoteSIPHeaderParameter(key)
	}
	key = strings.ToLower(strings.TrimSpace(key))
	switch key {
	case GeolocationRoutingYes:
		return GeolocationRoutingYes, nil
	case GeolocationRoutingNo:
		return GeolocationRoutingNo, nil
	default:
		return "", errors.New("invalid geolocation-routing header: expected yes or no")
	}
}

func splitSIPHeaderSegments(s string, sep rune) ([]string, error) {
	var out []string
	var b strings.Builder
	inQuote := false
	escaped := false
	angleDepth := 0
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if inQuote {
			b.WriteRune(r)
			if r == '\\' {
				escaped = true
			} else if r == '"' {
				inQuote = false
			}
			continue
		}
		switch r {
		case '"':
			inQuote = true
			b.WriteRune(r)
		case '<':
			angleDepth++
			b.WriteRune(r)
		case '>':
			if angleDepth == 0 {
				return nil, errors.New("invalid SIP header: unexpected closing angle")
			}
			angleDepth--
			b.WriteRune(r)
		default:
			if r == sep && angleDepth == 0 {
				out = append(out, b.String())
				b.Reset()
				continue
			}
			b.WriteRune(r)
		}
	}
	if escaped || inQuote {
		return nil, errors.New("invalid SIP header: unterminated quoted string")
	}
	if angleDepth != 0 {
		return nil, errors.New("invalid SIP header: unterminated angle URI")
	}
	out = append(out, b.String())
	return out, nil
}

func parseSIPHeaderParameters(params string) (map[string]string, error) {
	params = strings.TrimSpace(params)
	if params == "" {
		return nil, nil
	}
	params = strings.TrimPrefix(params, ";")
	parts, err := splitSIPHeaderSegments(params, ';')
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, hasValue := strings.Cut(part, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			return nil, errors.New("invalid SIP header parameter: empty name")
		}
		if !hasValue {
			out[key] = ""
			continue
		}
		out[key] = unquoteSIPHeaderParameter(value)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func unquoteSIPHeaderParameter(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return value
	}
	var b strings.Builder
	escaped := false
	for _, r := range value[1 : len(value)-1] {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		b.WriteRune(r)
	}
	if escaped {
		b.WriteByte('\\')
	}
	return b.String()
}

type pidfLOElement struct {
	local string
	key   string
	text  []byte
}

type pidfLOCivicField struct {
	name  string
	value string
}

const pidfLOPositionKey = "\x00pidf-lo-position"

func encodePIDFLOStart(enc *xml.Encoder, local string, attrs ...xml.Attr) error {
	return enc.EncodeToken(xml.StartElement{Name: xml.Name{Local: local}, Attr: attrs})
}

func encodePIDFLOEnd(enc *xml.Encoder, local string) error {
	return enc.EncodeToken(xml.EndElement{Name: xml.Name{Local: local}})
}

func encodePIDFLOTextElement(enc *xml.Encoder, local, value string) error {
	if err := encodePIDFLOStart(enc, local); err != nil {
		return err
	}
	if err := enc.EncodeToken(xml.CharData(value)); err != nil {
		return err
	}
	return encodePIDFLOEnd(enc, local)
}

func encodePIDFLOUsageRules(enc *xml.Encoder, rules EmergencyPIDFLOUsageRules) error {
	if !emergencyPIDFLOUsageRulesPresent(rules) {
		return nil
	}
	if err := encodePIDFLOStart(enc, "gp:usage-rules"); err != nil {
		return err
	}
	if rules.RetransmissionAllowed != nil {
		value := "false"
		if *rules.RetransmissionAllowed {
			value = "true"
		}
		if err := encodePIDFLOTextElement(enc, "gp:retransmission-allowed", value); err != nil {
			return err
		}
	}
	if !rules.RetentionExpiry.IsZero() {
		if err := encodePIDFLOTextElement(enc, "gp:retention-expiry", rules.RetentionExpiry.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	if ref := strings.TrimSpace(rules.RulesetReference); ref != "" {
		if err := encodePIDFLOTextElement(enc, "gp:ruleset-reference", ref); err != nil {
			return err
		}
	}
	if note := strings.TrimSpace(rules.NoteWell); note != "" {
		if err := encodePIDFLOTextElement(enc, "gp:note-well", note); err != nil {
			return err
		}
	}
	return encodePIDFLOEnd(enc, "gp:usage-rules")
}

func validateEmergencyPIDFLOUsageRules(cfg EmergencyPIDFLOConfig, rules EmergencyPIDFLOUsageRules) error {
	if rules.RetentionExpiry.IsZero() || cfg.Timestamp.IsZero() {
		return nil
	}
	if !rules.RetentionExpiry.After(cfg.Timestamp) {
		return errors.New("e911 pidf-lo retention-expiry must be after location timestamp")
	}
	return nil
}

func emergencyPIDFLOUsageRulesPresent(rules EmergencyPIDFLOUsageRules) bool {
	return rules.RetransmissionAllowed != nil ||
		!rules.RetentionExpiry.IsZero() ||
		strings.TrimSpace(rules.RulesetReference) != "" ||
		strings.TrimSpace(rules.NoteWell) != ""
}

func emergencyAddressHasPIDFLOLocation(address EmergencyAddress) bool {
	return emergencyAddressHasGeolocation(address) || len(emergencyAddressPIDFLOCivicFields(address)) > 0
}

func emergencyAddressPIDFLOCivicFields(address EmergencyAddress) []pidfLOCivicField {
	var fields []pidfLOCivicField
	fields = appendPIDFLOCivicField(fields, "country", firstNonEmpty(address.Country, address.Fields["country"]))
	fields = appendPIDFLOCivicField(fields, "A1", firstNonEmpty(address.State, address.Fields["state"]))
	fields = appendPIDFLOCivicField(fields, "A2", firstNonEmpty(address.County, address.Fields["county"]))
	fields = appendPIDFLOCivicField(fields, "A3", firstNonEmpty(address.City, address.Fields["city"]))
	fields = appendPIDFLOCivicField(fields, "A4", firstNonEmpty(address.District, address.Fields["district"]))
	fields = appendPIDFLOCivicField(fields, "A5", firstNonEmpty(address.Neighborhood, address.Fields["neighborhood"]))
	fields = appendPIDFLOCivicField(fields, "A6", firstNonEmpty(address.Street, address.Fields["street"]))
	fields = appendPIDFLOCivicField(fields, "PRD", firstNonEmpty(address.StreetDirection, address.Fields["street_direction"]))
	fields = appendPIDFLOCivicField(fields, "POD", firstNonEmpty(address.StreetPostDirection, address.Fields["street_post_direction"]))
	fields = appendPIDFLOCivicField(fields, "STS", firstNonEmpty(address.StreetSuffix, address.Fields["street_suffix"]))
	fields = appendPIDFLOCivicField(fields, "HNO", firstNonEmpty(address.HouseNumber, address.Fields["house_number"]))
	fields = appendPIDFLOCivicField(fields, "HNS", firstNonEmpty(address.HouseNumberSuffix, address.Fields["house_number_suffix"]))
	fields = appendPIDFLOCivicField(fields, "UNIT", firstNonEmpty(address.Unit, address.Fields["unit"]))
	fields = appendPIDFLOCivicField(fields, "BLD", firstNonEmpty(address.Building, address.Fields["building"]))
	fields = appendPIDFLOCivicField(fields, "FLR", firstNonEmpty(address.Floor, address.Fields["floor"]))
	fields = appendPIDFLOCivicField(fields, "ROOM", firstNonEmpty(address.Room, address.Fields["room"]))
	fields = appendPIDFLOCivicField(fields, "NAM", firstNonEmpty(address.Name, address.Fields["name"]))
	fields = appendPIDFLOCivicField(fields, "PC", firstNonEmpty(address.PostalCode, address.Fields["postal_code"]))
	fields = appendPIDFLOCivicField(fields, "LMK", firstNonEmpty(address.Landmark, address.Fields["landmark"]))
	fields = appendPIDFLOCivicField(fields, "LOC", firstNonEmpty(address.LocationDescription, address.Fields["location_description"]))
	fields = appendPIDFLOCivicField(fields, "PLC", firstNonEmpty(address.PlaceType, address.Fields["place_type"]))
	fields = appendPIDFLOCivicField(fields, "PRM", firstNonEmpty(address.Premise, address.Fields["premise"]))
	fields = appendPIDFLOCivicField(fields, "POBOX", firstNonEmpty(address.PostOfficeBox, address.Fields["post_office_box"]))
	fields = appendPIDFLOCivicField(fields, "ADDCODE", firstNonEmpty(address.AdditionalCode, address.Fields["additional_code"]))
	fields = appendPIDFLOCivicField(fields, "SEAT", firstNonEmpty(address.Seat, address.Fields["seat"]))
	fields = appendPIDFLOCivicField(fields, "RDSEC", firstNonEmpty(address.RoadSection, address.Fields["road_section"]))
	fields = appendPIDFLOCivicField(fields, "RDBR", firstNonEmpty(address.RoadBranch, address.Fields["road_branch"]))
	fields = appendPIDFLOCivicField(fields, "RDSUBBR", firstNonEmpty(address.RoadSubBranch, address.Fields["road_sub_branch"]))
	return fields
}

func appendPIDFLOCivicField(fields []pidfLOCivicField, name, value string) []pidfLOCivicField {
	if value = strings.TrimSpace(value); value != "" {
		fields = append(fields, pidfLOCivicField{name: name, value: value})
	}
	return fields
}

func inPIDFLOCivicAddress(stack []pidfLOElement) bool {
	for i := len(stack) - 1; i >= 0; i-- {
		if strings.EqualFold(stack[i].local, "civicAddress") {
			return true
		}
	}
	return false
}

func isPIDFLOGeodeticPositionElement(local string) bool {
	return strings.EqualFold(local, "pos") || strings.EqualFold(local, "coordinates")
}

func collectPIDFLOGeodeticPosition(text string, out *entitlementResult) {
	text = strings.ReplaceAll(text, ",", " ")
	parts := strings.Fields(text)
	if len(parts) < 2 {
		return
	}
	if out.EmergencyAddress == nil {
		out.EmergencyAddress = make(map[string]string)
	}
	if out.EmergencyAddress["latitude"] == "" {
		out.EmergencyAddress["latitude"] = parts[0]
	}
	if out.EmergencyAddress["longitude"] == "" {
		out.EmergencyAddress["longitude"] = parts[1]
	}
}

func appendEmergencyMultipartPart(dst *bytes.Buffer, boundary, contentType, contentID, disposition string, body []byte) {
	dst.WriteString("--")
	dst.WriteString(boundary)
	dst.WriteString("\r\nContent-Type: ")
	dst.WriteString(contentType)
	dst.WriteString("\r\nContent-ID: <")
	dst.WriteString(contentID)
	dst.WriteString(">")
	if disposition != "" {
		dst.WriteString("\r\nContent-Disposition: ")
		dst.WriteString(disposition)
	}
	dst.WriteString("\r\n\r\n")
	dst.Write(body)
	dst.WriteString("\r\n")
}

func chooseEmergencyMultipartBoundary(bodies ...[]byte) string {
	boundary := defaultEmergencyMultipartBoundary
	for i := 1; emergencyMultipartBoundaryCollides(boundary, bodies...); i++ {
		boundary = defaultEmergencyMultipartBoundary + "-" + strconv.Itoa(i)
	}
	return boundary
}

func emergencyMultipartBoundaryCollides(boundary string, bodies ...[]byte) bool {
	marker := []byte("--" + boundary)
	for _, body := range bodies {
		if bytes.Contains(body, marker) {
			return true
		}
	}
	return false
}

func normalizeEmergencyContentID(value, fallback string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(value), "cid:") {
		value = strings.TrimSpace(value[4:])
	}
	if strings.HasPrefix(value, "<") || strings.HasSuffix(value, ">") {
		if len(value) < 2 || value[0] != '<' || value[len(value)-1] != '>' {
			return "", errors.New("invalid e911 content-id")
		}
		value = strings.TrimSpace(value[1 : len(value)-1])
	}
	if value == "" {
		value = fallback
	}
	if value == "" || strings.ContainsAny(value, "\r\n<> \t") {
		return "", errors.New("invalid e911 content-id")
	}
	return value, nil
}

func emergencyContentIDForHeader(value, fallback string) string {
	contentID, err := normalizeEmergencyContentID(value, fallback)
	if err != nil {
		return ""
	}
	return contentID
}

func validateEmergencyMultipartBoundary(boundary string) error {
	if boundary == "" || len(boundary) > 70 {
		return errors.New("invalid e911 multipart boundary")
	}
	for _, r := range boundary {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '\'', '(', ')', '+', '_', ',', '-', '.', '/', ':', '=', '?':
			continue
		default:
			return errors.New("invalid e911 multipart boundary")
		}
	}
	return nil
}

func quoteSIPParamValue(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		if r == '\\' || r == '"' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}
