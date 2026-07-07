package voiceclient

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
)

const (
	DefaultSecurityProtocol        = "ipsec-3gpp"
	DefaultSecurityAlgorithm       = "hmac-sha-1-96"
	SecurityAlgorithmHMACMD596     = "hmac-md5-96"
	DefaultSecurityEAlg            = "null"
	SecurityEncryptionAlgorithmAES = "aes-cbc"
	DefaultSecurityPortC           = 5062
	DefaultSecurityPortS           = 5063

	defaultSecurityIPSecProtocol = "esp"
	defaultSecurityMode          = "trans"

	securityAgreementCompleteIPSecSABonus = 2000
)

type SecurityAgreement struct {
	Protocol            string
	Algorithm           string
	EncryptionAlgorithm string
	SPIClient           uint32
	SPIServer           uint32
	PortClient          int
	PortServer          int
	Parameters          map[string]string
	Raw                 string
}

type IMSSecurityAssociationPlan struct {
	Protocol            string
	Mode                string
	Algorithm           string
	EncryptionAlgorithm string
	SPIClient           uint32
	SPIServer           uint32
	PortClient          int
	PortServer          int
	Inbound             IMSSecurityAssociationDirection
	Outbound            IMSSecurityAssociationDirection
	QValue              string
	Source              string
}

type IMSSecurityAssociationDirection struct {
	Direction  string
	LocalPort  int
	RemotePort int
	SPI        uint32
}

type IMSSecurityAKAKeys struct {
	CK []byte
	IK []byte
}

type IMSSecurityAssociationEndpoint struct {
	Address string
	Port    int
}

type IMSSecurityAssociationInstallRequest struct {
	Plan               IMSSecurityAssociationPlan
	Agreement          SecurityAgreement
	AKA                IMSSecurityAKAKeys
	LocalEndpoint      IMSSecurityAssociationEndpoint
	RemoteEndpoint     IMSSecurityAssociationEndpoint
	SelectedParameters map[string]string
}

func DefaultSecurityClientAgreement(random io.Reader) SecurityAgreement {
	if random == nil {
		random = cryptorand.Reader
	}
	return SecurityAgreement{
		Protocol:            DefaultSecurityProtocol,
		Algorithm:           DefaultSecurityAlgorithm,
		EncryptionAlgorithm: DefaultSecurityEAlg,
		SPIClient:           randomSecuritySPI(random),
		SPIServer:           randomSecuritySPI(random),
		PortClient:          DefaultSecurityPortC,
		PortServer:          DefaultSecurityPortS,
	}
}

func DefaultSecurityClientAgreements(random io.Reader, algorithms ...string) []SecurityAgreement {
	if len(algorithms) == 0 {
		algorithms = []string{DefaultSecurityAlgorithm}
	}
	out := make([]SecurityAgreement, 0, len(algorithms))
	for _, algorithm := range algorithms {
		agreement := DefaultSecurityClientAgreement(random)
		if strings.TrimSpace(algorithm) != "" {
			agreement.Algorithm = strings.ToLower(strings.TrimSpace(algorithm))
		}
		out = append(out, completeSecurityAgreement(agreement))
	}
	return out
}

func BuildSecurityClientHeader(agreement SecurityAgreement) string {
	agreement = completeSecurityAgreement(agreement)
	return agreement.HeaderValue()
}

func BuildSecurityClientHeaderList(agreements []SecurityAgreement) string {
	parts := make([]string, 0, len(agreements))
	for _, agreement := range agreements {
		header := strings.TrimSpace(BuildSecurityClientHeader(agreement))
		if header != "" {
			parts = append(parts, header)
		}
	}
	return strings.Join(parts, ", ")
}

func ParseSecurityAgreements(values []string) []SecurityAgreement {
	var out []SecurityAgreement
	for _, value := range values {
		for _, item := range splitSIPHeaderValues(value) {
			agreement, ok := parseSecurityAgreement(item)
			if ok {
				out = append(out, agreement)
			}
		}
	}
	return out
}

func SelectSecurityAgreement(values []string, client SecurityAgreement) (SecurityAgreement, bool) {
	return SelectSecurityAgreementForClients(values, []SecurityAgreement{client})
}

func SelectSecurityAgreementForClients(values []string, clients []SecurityAgreement) (SecurityAgreement, bool) {
	offers := ParseSecurityAgreements(values)
	if len(offers) == 0 {
		return SecurityAgreement{}, false
	}
	if len(clients) == 0 {
		clients = []SecurityAgreement{{}}
	}
	completedClients := make([]SecurityAgreement, 0, len(clients))
	for _, client := range clients {
		completedClients = append(completedClients, completeSecurityAgreement(client))
	}
	bestIndex := -1
	bestClientIndex := len(completedClients)
	bestScore := -1
	var best SecurityAgreement
	for i, offer := range offers {
		offer = completeSecurityAgreement(offer)
		for j, client := range completedClients {
			if !securityAgreementCompatible(offer, client) {
				continue
			}
			score := securityAgreementScore(offer, client)
			if score > bestScore || (score == bestScore && j < bestClientIndex) {
				bestIndex = i
				bestClientIndex = j
				bestScore = score
				best = offer
			}
		}
	}
	if bestIndex < 0 {
		return SecurityAgreement{}, false
	}
	return best, true
}

func BuildIMSSecurityAssociationPlan(agreement SecurityAgreement) (IMSSecurityAssociationPlan, bool) {
	if isZeroSecurityAgreement(agreement) {
		return IMSSecurityAssociationPlan{}, false
	}
	agreement = completeSecurityAgreement(agreement)
	if agreement.SPIClient == 0 || agreement.SPIServer == 0 || agreement.PortClient == 0 || agreement.PortServer == 0 {
		return IMSSecurityAssociationPlan{}, false
	}
	mode := firstNonEmpty(agreement.Parameters["mode"], agreement.Parameters["mod"], defaultSecurityMode)
	return IMSSecurityAssociationPlan{
		Protocol:            agreement.Protocol,
		Mode:                strings.ToLower(strings.TrimSpace(mode)),
		Algorithm:           agreement.Algorithm,
		EncryptionAlgorithm: agreement.EncryptionAlgorithm,
		SPIClient:           agreement.SPIClient,
		SPIServer:           agreement.SPIServer,
		PortClient:          agreement.PortClient,
		PortServer:          agreement.PortServer,
		Inbound: IMSSecurityAssociationDirection{
			Direction:  "inbound",
			LocalPort:  agreement.PortClient,
			RemotePort: agreement.PortServer,
			SPI:        agreement.SPIClient,
		},
		Outbound: IMSSecurityAssociationDirection{
			Direction:  "outbound",
			LocalPort:  agreement.PortClient,
			RemotePort: agreement.PortServer,
			SPI:        agreement.SPIServer,
		},
		QValue: strings.TrimSpace(agreement.Parameters["q"]),
		Source: agreement.Raw,
	}, true
}

func (a SecurityAgreement) HeaderValue() string {
	a = completeSecurityAgreement(a)
	if strings.TrimSpace(a.Protocol) == "" {
		return ""
	}
	parts := []string{strings.TrimSpace(a.Protocol)}
	if a.Algorithm != "" {
		parts = append(parts, "alg="+a.Algorithm)
	}
	if a.EncryptionAlgorithm != "" {
		parts = append(parts, "ealg="+a.EncryptionAlgorithm)
	}
	if a.SPIClient > 0 {
		parts = append(parts, "spi-c="+strconv.FormatUint(uint64(a.SPIClient), 10))
	}
	if a.SPIServer > 0 {
		parts = append(parts, "spi-s="+strconv.FormatUint(uint64(a.SPIServer), 10))
	}
	if a.PortClient > 0 {
		parts = append(parts, "port-c="+strconv.Itoa(a.PortClient))
	}
	if a.PortServer > 0 {
		parts = append(parts, "port-s="+strconv.Itoa(a.PortServer))
	}
	parts = appendSecurityAgreementParameters(parts, a.Parameters)
	return strings.Join(parts, ";")
}

func completeSecurityAgreement(a SecurityAgreement) SecurityAgreement {
	if strings.TrimSpace(a.Protocol) == "" {
		a.Protocol = DefaultSecurityProtocol
	}
	a.Protocol = strings.ToLower(strings.TrimSpace(a.Protocol))
	if strings.TrimSpace(a.Algorithm) == "" {
		a.Algorithm = DefaultSecurityAlgorithm
	}
	a.Algorithm = strings.ToLower(strings.TrimSpace(a.Algorithm))
	if strings.TrimSpace(a.EncryptionAlgorithm) == "" {
		a.EncryptionAlgorithm = DefaultSecurityEAlg
	}
	a.EncryptionAlgorithm = strings.ToLower(strings.TrimSpace(a.EncryptionAlgorithm))
	if a.PortClient < 0 {
		a.PortClient = 0
	}
	if a.PortServer < 0 {
		a.PortServer = 0
	}
	return a
}

func completeSecurityClientAgreement(a SecurityAgreement, random io.Reader) SecurityAgreement {
	a = completeSecurityAgreement(a)
	if random == nil {
		random = cryptorand.Reader
	}
	if a.SPIClient == 0 {
		a.SPIClient = randomSecuritySPI(random)
	}
	if a.SPIServer == 0 {
		a.SPIServer = randomSecuritySPI(random)
	}
	if a.PortClient == 0 {
		a.PortClient = DefaultSecurityPortC
	}
	if a.PortServer == 0 {
		a.PortServer = DefaultSecurityPortS
	}
	return a
}

func completeSecurityClientAgreements(agreements []SecurityAgreement, random io.Reader) []SecurityAgreement {
	if len(agreements) == 0 {
		return nil
	}
	out := make([]SecurityAgreement, 0, len(agreements))
	for _, agreement := range agreements {
		out = append(out, completeSecurityClientAgreement(agreement, random))
	}
	return out
}

func isZeroSecurityAgreement(a SecurityAgreement) bool {
	return strings.TrimSpace(a.Protocol) == "" &&
		strings.TrimSpace(a.Algorithm) == "" &&
		strings.TrimSpace(a.EncryptionAlgorithm) == "" &&
		a.SPIClient == 0 &&
		a.SPIServer == 0 &&
		a.PortClient == 0 &&
		a.PortServer == 0 &&
		len(a.Parameters) == 0 &&
		strings.TrimSpace(a.Raw) == ""
}

func isZeroIMSSecurityAssociationPlan(plan IMSSecurityAssociationPlan) bool {
	return plan == IMSSecurityAssociationPlan{}
}

func buildIMSSecurityAssociationInstallRequest(plan IMSSecurityAssociationPlan, agreement SecurityAgreement, aka IMSSecurityAKAKeys, localAddr, remoteAddr, contactURI, registrarURI string) IMSSecurityAssociationInstallRequest {
	agreement = cloneSecurityAgreement(agreement)
	return IMSSecurityAssociationInstallRequest{
		Plan:               plan,
		Agreement:          agreement,
		AKA:                cloneIMSSecurityAKAKeys(aka),
		LocalEndpoint:      imssSecurityEndpoint(localAddr, contactURI, plan.PortClient),
		RemoteEndpoint:     imssSecurityEndpoint(remoteAddr, registrarURI, plan.PortServer),
		SelectedParameters: cloneSecurityParameters(agreement.Parameters),
	}
}

func cloneIMSSecurityAssociationInstallRequest(req IMSSecurityAssociationInstallRequest) IMSSecurityAssociationInstallRequest {
	req.Agreement = cloneSecurityAgreement(req.Agreement)
	req.AKA = cloneIMSSecurityAKAKeys(req.AKA)
	req.SelectedParameters = cloneSecurityParameters(req.SelectedParameters)
	return req
}

func cloneSecurityAgreement(agreement SecurityAgreement) SecurityAgreement {
	agreement.Parameters = cloneSecurityParameters(agreement.Parameters)
	return agreement
}

func cloneSecurityParameters(params map[string]string) map[string]string {
	if len(params) == 0 {
		return nil
	}
	out := make(map[string]string, len(params))
	for k, v := range params {
		out[k] = v
	}
	return out
}

func cloneIMSSecurityAKAKeys(keys IMSSecurityAKAKeys) IMSSecurityAKAKeys {
	return IMSSecurityAKAKeys{
		CK: append([]byte(nil), keys.CK...),
		IK: append([]byte(nil), keys.IK...),
	}
}

func imssSecurityEndpoint(addr, uri string, defaultPort int) IMSSecurityAssociationEndpoint {
	if endpoint, ok := parseIMSSecurityEndpointAddr(addr, defaultPort); ok {
		return endpoint
	}
	if endpoint, ok := parseIMSSecurityEndpointURI(uri, defaultPort); ok {
		return endpoint
	}
	if defaultPort > 0 {
		return IMSSecurityAssociationEndpoint{Port: defaultPort}
	}
	return IMSSecurityAssociationEndpoint{}
}

func parseIMSSecurityEndpointURI(uri string, defaultPort int) (IMSSecurityAssociationEndpoint, bool) {
	endpoint, err := parseSIPURIEndpoint(uri)
	if err != nil {
		return IMSSecurityAssociationEndpoint{}, false
	}
	port := parseSecurityPort(endpoint.Port)
	if defaultPort > 0 {
		port = defaultPort
	}
	return IMSSecurityAssociationEndpoint{
		Address: strings.TrimSpace(endpoint.Host),
		Port:    port,
	}, true
}

func parseIMSSecurityEndpointAddr(addr string, defaultPort int) (IMSSecurityAssociationEndpoint, bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return IMSSecurityAssociationEndpoint{}, false
	}
	lower := strings.ToLower(addr)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		return parseIMSSecurityEndpointURI(addr, defaultPort)
	}
	host, portText, ok := splitIMSSecurityEndpointAddr(addr)
	if !ok {
		return IMSSecurityAssociationEndpoint{}, false
	}
	port := parseSecurityPort(portText)
	if defaultPort > 0 {
		port = defaultPort
	}
	return IMSSecurityAssociationEndpoint{
		Address: host,
		Port:    port,
	}, true
}

func splitIMSSecurityEndpointAddr(addr string) (string, string, bool) {
	if host, port, err := net.SplitHostPort(addr); err == nil {
		host = strings.Trim(host, "[] ")
		return host, port, host != ""
	}
	if strings.HasPrefix(addr, "[") {
		end := strings.IndexByte(addr, ']')
		if end < 0 {
			return "", "", false
		}
		host := strings.TrimSpace(addr[1:end])
		rest := strings.TrimSpace(addr[end+1:])
		if strings.HasPrefix(rest, ":") {
			return host, strings.TrimSpace(rest[1:]), host != ""
		}
		return host, "", host != ""
	}
	if ip := net.ParseIP(strings.Trim(addr, "[] ")); ip != nil {
		return ip.String(), "", true
	}
	if idx := strings.LastIndex(addr, ":"); idx > 0 && !strings.Contains(addr[idx+1:], ":") {
		host := strings.Trim(addr[:idx], "[] ")
		return host, strings.TrimSpace(addr[idx+1:]), host != ""
	}
	host := strings.Trim(addr, "[] ")
	return host, "", host != ""
}

func parseSecurityAgreement(value string) (SecurityAgreement, bool) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return SecurityAgreement{}, false
	}
	parts := splitSemicolonParams(raw)
	if len(parts) == 0 {
		return SecurityAgreement{}, false
	}
	agreement := SecurityAgreement{
		Protocol:   strings.ToLower(strings.TrimSpace(parts[0])),
		Parameters: map[string]string{},
		Raw:        raw,
	}
	for _, part := range parts[1:] {
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = unquote(strings.TrimSpace(val))
		if key == "" {
			continue
		}
		agreement.Parameters[key] = val
		switch key {
		case "alg":
			agreement.Algorithm = strings.ToLower(strings.TrimSpace(val))
		case "ealg":
			agreement.EncryptionAlgorithm = strings.ToLower(strings.TrimSpace(val))
		case "spi-c":
			agreement.SPIClient = parseSecurityUint32(val)
		case "spi-s":
			agreement.SPIServer = parseSecurityUint32(val)
		case "port-c":
			agreement.PortClient = parseSecurityPort(val)
		case "port-s":
			agreement.PortServer = parseSecurityPort(val)
		}
	}
	return agreement, agreement.Protocol != ""
}

func splitSemicolonParams(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			cur.WriteRune(r)
			escaped = true
		case r == '"':
			cur.WriteRune(r)
			inQuote = !inQuote
		case r == ';' && !inQuote:
			if part := strings.TrimSpace(cur.String()); part != "" {
				out = append(out, part)
			}
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if part := strings.TrimSpace(cur.String()); part != "" {
		out = append(out, part)
	}
	return out
}

func securityAgreementScore(offer, client SecurityAgreement) int {
	score := 0
	if strings.EqualFold(offer.Protocol, client.Protocol) {
		score += 100
	}
	if strings.EqualFold(offer.Algorithm, client.Algorithm) {
		score += 20
	}
	if strings.EqualFold(offer.EncryptionAlgorithm, client.EncryptionAlgorithm) {
		score += 10
	}
	if offer.SPIClient > 0 && offer.SPIServer > 0 {
		score += 4
	}
	if offer.PortClient > 0 && offer.PortServer > 0 {
		score += 4
	}
	if securityAgreementHasCompleteIPSecSA(offer) {
		score += securityAgreementCompleteIPSecSABonus
	}
	if q, ok := offer.Parameters["q"]; ok {
		score += securityQValue(q)
	}
	return score
}

func securityAgreementHasCompleteIPSecSA(agreement SecurityAgreement) bool {
	agreement = completeSecurityAgreement(agreement)
	return strings.EqualFold(agreement.Protocol, DefaultSecurityProtocol) &&
		agreement.SPIClient > 0 &&
		agreement.SPIServer > 0 &&
		agreement.PortClient > 0 &&
		agreement.PortClient <= 65535 &&
		agreement.PortServer > 0 &&
		agreement.PortServer <= 65535
}

func securityAgreementCompatible(offer, client SecurityAgreement) bool {
	if !strings.EqualFold(offer.Protocol, client.Protocol) {
		return false
	}
	if !strings.EqualFold(offer.Algorithm, client.Algorithm) {
		return false
	}
	if !strings.EqualFold(offer.EncryptionAlgorithm, client.EncryptionAlgorithm) {
		return false
	}
	if strings.EqualFold(offer.Protocol, DefaultSecurityProtocol) {
		if !strings.EqualFold(securityAgreementIPSecProtocol(offer), securityAgreementIPSecProtocol(client)) {
			return false
		}
		if !strings.EqualFold(securityAgreementMode(offer), securityAgreementMode(client)) {
			return false
		}
	}
	return true
}

func securityQValue(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	raw, err := strconv.ParseFloat(value, 64)
	if err != nil || raw <= 0 {
		return 0
	}
	if raw > 1 {
		raw = 1
	}
	return int(raw*1000 + 0.5)
}

func securityAgreementIPSecProtocol(agreement SecurityAgreement) string {
	protocol := firstNonEmpty(agreement.Parameters["prot"], defaultSecurityIPSecProtocol)
	return strings.ToLower(strings.TrimSpace(protocol))
}

func securityAgreementMode(agreement SecurityAgreement) string {
	mode := firstNonEmpty(agreement.Parameters["mode"], agreement.Parameters["mod"], defaultSecurityMode)
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "trans", "transport":
		return defaultSecurityMode
	case "tun", "tunnel":
		return "tun"
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func appendSecurityAgreementParameters(parts []string, params map[string]string) []string {
	if len(params) == 0 {
		return parts
	}
	extras := make(map[string]string)
	for key, value := range params {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" || isSecurityAgreementStructuredParameter(key) {
			continue
		}
		extras[key] = strings.TrimSpace(value)
	}
	for _, key := range []string{"prot", "mod", "mode", "q"} {
		value, ok := extras[key]
		if !ok {
			continue
		}
		parts = append(parts, key+"="+securityAgreementParameterValue(value))
		delete(extras, key)
	}
	keys := make([]string, 0, len(extras))
	for key := range extras {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, key+"="+securityAgreementParameterValue(extras[key]))
	}
	return parts
}

func isSecurityAgreementStructuredParameter(key string) bool {
	switch key {
	case "alg", "ealg", "spi-c", "spi-s", "port-c", "port-s":
		return true
	default:
		return false
	}
}

func securityAgreementParameterValue(value string) string {
	if value == "" {
		return `""`
	}
	if strings.ContainsAny(value, " \t;,\"") {
		return `"` + quote(value) + `"`
	}
	return value
}

func parseSecurityUint32(value string) uint32 {
	n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

func parseSecurityPort(value string) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 0 || n > 65535 {
		return 0
	}
	return n
}

func randomSecuritySPI(random io.Reader) uint32 {
	var b [4]byte
	if _, err := io.ReadFull(random, b[:]); err != nil {
		return 1
	}
	spi := binary.BigEndian.Uint32(b[:])
	if spi == 0 {
		return 1
	}
	return spi
}

func validateSecurityClientHeader(header string) error {
	items := splitSIPHeaderValues(header)
	if len(items) == 0 {
		return fmt.Errorf("invalid Security-Client header")
	}
	for _, item := range items {
		agreement, ok := parseSecurityAgreement(item)
		if !ok {
			return fmt.Errorf("invalid Security-Client header")
		}
		if !strings.EqualFold(agreement.Protocol, DefaultSecurityProtocol) {
			return fmt.Errorf("unsupported Security-Client protocol %q", agreement.Protocol)
		}
	}
	return nil
}
