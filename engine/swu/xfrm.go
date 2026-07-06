package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"strconv"
	"strings"

	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

var ErrInvalidXFRMConfig = errors.New("invalid swu xfrm config")

const (
	xfrmAeadAESGCMRFC4106 = "rfc4106(gcm(aes))"
	xfrmAESGCMSaltLength  = 4
	xfrmAESGCMICVBits     = 128
)

type XFRMInterfaceConfig struct {
	Name           string
	OuterDev       string
	IfID           uint32
	MTU            int
	SkipCreateLink bool
}

type XFRMNATTraversalConfig struct {
	Enabled         bool
	LocalPort       uint16
	RemotePort      uint16
	OriginalAddress string
}

type KernelXFRMConfig struct {
	ChildSA              ikev2.ChildSAResult
	OuterLocalIP         string
	OuterRemoteIP        string
	InnerLocalPrefix     string
	InnerRemotePrefix    string
	ReqID                int
	Mark                 string
	InterfaceID          uint32
	IncludeForwardPolicy bool
	XFRMInterface        XFRMInterfaceConfig
	NATTraversal         XFRMNATTraversalConfig
}

// KernelXFRMConfigFromIKEConfig carries the negotiated IKE state needed to build a kernel XFRM config.
type KernelXFRMConfigFromIKEConfig struct {
	Tunnel               TunnelConfig
	Transport            IKETransportConfig
	Init                 ikev2.InitResult
	ChildSA              ikev2.ChildSAResult
	InnerLocalPrefix     string
	InnerRemotePrefix    string
	ReqID                int
	Mark                 string
	InterfaceID          uint32
	IncludeForwardPolicy bool
	XFRMInterface        XFRMInterfaceConfig
	NATTraversal         XFRMNATTraversalConfig
}

type KernelXFRMState struct {
	undo []ipCommand
}

type LinuxXFRMManager struct {
	Runner IPCommandRunner
}

func (m LinuxXFRMManager) Apply(ctx context.Context, cfg KernelXFRMConfig) (KernelXFRMState, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	runner := m.Runner
	if runner == nil {
		runner = ExecIPCommandRunner{}
	}
	commands, err := buildKernelXFRMCommands(cfg)
	if err != nil {
		return KernelXFRMState{}, err
	}
	var state KernelXFRMState
	for _, command := range commands {
		if err := runner.RunIP(ctx, command.args...); err != nil {
			rollbackErr := runIPUndo(ctx, runner, state.undo)
			if rollbackErr != nil {
				return state, errors.Join(err, rollbackErr)
			}
			return state, err
		}
		if len(command.undo) > 0 {
			state.undo = append(state.undo, ipCommand{args: append([]string(nil), command.undo...)})
		}
	}
	return state, nil
}

func (m LinuxXFRMManager) Cleanup(ctx context.Context, state KernelXFRMState) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runner := m.Runner
	if runner == nil {
		runner = ExecIPCommandRunner{}
	}
	return runIPUndo(ctx, runner, state.undo)
}

// KernelXFRMConfigFromIKE builds a validated XFRM config without applying kernel state.
func KernelXFRMConfigFromIKE(cfg KernelXFRMConfigFromIKEConfig) (KernelXFRMConfig, error) {
	outerLocal := xfrmIPString(cfg.Transport.LocalIP, tunnelAddressHost(cfg.Transport.LocalAddr), tunnelAddressHost(cfg.Tunnel.OuterLocalIP))
	if outerLocal == "" {
		return KernelXFRMConfig{}, fmt.Errorf("%w: outer local ip is empty", ErrInvalidXFRMConfig)
	}
	epdg := firstPacketNonEmpty(cfg.Transport.EPDGAddress, cfg.Tunnel.EPDGAddress, epdgAddressForTunnel(cfg.Tunnel))
	outerRemote := xfrmIPString(cfg.Transport.RemoteIP, tunnelAddressHost(cfg.Transport.RemoteAddr), tunnelAddressHost(epdg))
	if outerRemote == "" {
		return KernelXFRMConfig{}, fmt.Errorf("%w: outer remote ip is empty", ErrInvalidXFRMConfig)
	}
	innerLocal := firstPacketNonEmpty(
		cfg.InnerLocalPrefix,
		cfg.Tunnel.InnerLocalIP,
		childConfigurationAddress(cfg.ChildSA, ikev2.ConfigInternalIPv4Address),
		childConfigurationAddress(cfg.ChildSA, ikev2.ConfigInternalIPv6Address),
	)
	if innerLocal == "" {
		innerLocal = firstXFRMTrafficSelectorPrefix(cfg.ChildSA.TSi)
	}
	if innerLocal == "" {
		return KernelXFRMConfig{}, fmt.Errorf("%w: inner local prefix is empty", ErrInvalidXFRMConfig)
	}
	innerRemote := firstPacketNonEmpty(cfg.InnerRemotePrefix, cfg.Tunnel.RemoteInnerIP)
	if innerRemote == "" {
		innerRemote = firstXFRMTrafficSelectorPrefix(cfg.ChildSA.TSr)
	}
	if innerRemote == "" {
		return KernelXFRMConfig{}, fmt.Errorf("%w: inner remote prefix is empty", ErrInvalidXFRMConfig)
	}
	natt := cfg.NATTraversal
	if natt.Enabled || cfg.Init.NATDetected {
		natt.Enabled = true
		if natt.LocalPort == 0 {
			natt.LocalPort = xfrmTransportPort(cfg.Transport.LocalPort, cfg.Transport.LocalAddr)
		}
		if natt.RemotePort == 0 {
			natt.RemotePort = xfrmTransportPort(cfg.Transport.RemotePort, cfg.Transport.RemoteAddr)
		}
	}
	out := KernelXFRMConfig{
		ChildSA:              cfg.ChildSA,
		OuterLocalIP:         outerLocal,
		OuterRemoteIP:        outerRemote,
		InnerLocalPrefix:     innerLocal,
		InnerRemotePrefix:    innerRemote,
		ReqID:                cfg.ReqID,
		Mark:                 cfg.Mark,
		InterfaceID:          cfg.InterfaceID,
		IncludeForwardPolicy: cfg.IncludeForwardPolicy,
		XFRMInterface:        cfg.XFRMInterface,
		NATTraversal:         natt,
	}
	params, err := normalizeKernelXFRMConfig(out)
	if err != nil {
		return KernelXFRMConfig{}, err
	}
	out.OuterLocalIP = params.outerLocal
	out.OuterRemoteIP = params.outerRemote
	out.InnerLocalPrefix = params.innerLocal
	out.InnerRemotePrefix = params.innerRemote
	if params.natt.enabled {
		out.NATTraversal.Enabled = true
		out.NATTraversal.LocalPort = xfrmPortUint16(params.natt.localPort)
		out.NATTraversal.RemotePort = xfrmPortUint16(params.natt.remotePort)
		out.NATTraversal.OriginalAddress = params.natt.originalAddress
	}
	return out, nil
}

func buildKernelXFRMCommands(cfg KernelXFRMConfig) ([]ipCommand, error) {
	params, err := normalizeKernelXFRMConfig(cfg)
	if err != nil {
		return nil, err
	}
	var commands []ipCommand
	if params.xfrmiName != "" {
		if !cfg.XFRMInterface.SkipCreateLink {
			args := []string{"link", "add", params.xfrmiName, "type", "xfrm", "dev", params.xfrmiOuterDev, "if_id", params.ifID}
			commands = append(commands, ipCommand{
				args: args,
				undo: []string{"link", "del", params.xfrmiName},
			})
		}
		if params.xfrmiMTU > 0 {
			commands = append(commands, ipCommand{args: []string{"link", "set", "dev", params.xfrmiName, "mtu", strconv.Itoa(params.xfrmiMTU)}})
		}
		commands = append(commands, ipCommand{args: []string{"link", "set", "dev", params.xfrmiName, "up"}})
	}
	commands = append(commands,
		ipCommand{args: xfrmStateAddArgs(params, true), undo: xfrmStateDelArgs(params, true)},
		ipCommand{args: xfrmStateAddArgs(params, false), undo: xfrmStateDelArgs(params, false)},
		ipCommand{args: xfrmPolicyAddArgs(params, "out"), undo: xfrmPolicyDelArgs(params, "out")},
		ipCommand{args: xfrmPolicyAddArgs(params, "in"), undo: xfrmPolicyDelArgs(params, "in")},
	)
	if params.includeForward {
		commands = append(commands, ipCommand{args: xfrmPolicyAddArgs(params, "fwd"), undo: xfrmPolicyDelArgs(params, "fwd")})
	}
	return commands, nil
}

type kernelXFRMParams struct {
	child          ikev2.ChildSAResult
	outerLocal     string
	outerRemote    string
	innerLocal     string
	innerRemote    string
	reqID          string
	mark           string
	ifID           string
	includeForward bool
	xfrmiName      string
	xfrmiOuterDev  string
	xfrmiMTU       int
	natt           kernelXFRMNATTraversal
}

type kernelXFRMNATTraversal struct {
	enabled         bool
	localPort       string
	remotePort      string
	originalAddress string
}

func normalizeKernelXFRMConfig(cfg KernelXFRMConfig) (kernelXFRMParams, error) {
	outerLocal, err := normalizeIPAddress(cfg.OuterLocalIP, "outer local ip")
	if err != nil {
		return kernelXFRMParams{}, wrapXFRMError(err)
	}
	outerRemote, err := normalizeIPAddress(cfg.OuterRemoteIP, "outer remote ip")
	if err != nil {
		return kernelXFRMParams{}, wrapXFRMError(err)
	}
	innerLocal, err := normalizeIPPrefix(cfg.InnerLocalPrefix, "inner local prefix")
	if err != nil {
		return kernelXFRMParams{}, wrapXFRMError(err)
	}
	innerRemote, err := normalizeIPPrefix(cfg.InnerRemotePrefix, "inner remote prefix")
	if err != nil {
		return kernelXFRMParams{}, wrapXFRMError(err)
	}
	if err := validateChildSAForXFRM(cfg.ChildSA); err != nil {
		return kernelXFRMParams{}, err
	}
	reqID := cfg.ReqID
	if reqID < 0 {
		return kernelXFRMParams{}, fmt.Errorf("%w: reqid must be positive", ErrInvalidXFRMConfig)
	}
	if reqID == 0 {
		reqID = 1
	}
	mark := ""
	if strings.TrimSpace(cfg.Mark) != "" {
		mark, err = normalizeRoutingToken(cfg.Mark, "xfrm mark")
		if err != nil {
			return kernelXFRMParams{}, wrapXFRMError(err)
		}
	}
	ifID := cfg.InterfaceID
	xfrmiName := strings.TrimSpace(cfg.XFRMInterface.Name)
	xfrmiOuterDev := strings.TrimSpace(cfg.XFRMInterface.OuterDev)
	if cfg.XFRMInterface.IfID != 0 {
		ifID = cfg.XFRMInterface.IfID
	}
	if xfrmiName != "" {
		if err := validateRoutingInterfaceName(xfrmiName); err != nil {
			return kernelXFRMParams{}, fmt.Errorf("%w: xfrm interface name: %v", ErrInvalidXFRMConfig, err)
		}
		if xfrmiOuterDev == "" {
			return kernelXFRMParams{}, fmt.Errorf("%w: xfrm interface outer dev is empty", ErrInvalidXFRMConfig)
		}
		if err := validateRoutingInterfaceName(xfrmiOuterDev); err != nil {
			return kernelXFRMParams{}, fmt.Errorf("%w: xfrm interface outer dev: %v", ErrInvalidXFRMConfig, err)
		}
		if ifID == 0 {
			return kernelXFRMParams{}, fmt.Errorf("%w: xfrm interface if_id is zero", ErrInvalidXFRMConfig)
		}
		if cfg.XFRMInterface.MTU < 0 {
			return kernelXFRMParams{}, fmt.Errorf("%w: xfrm interface mtu must be positive", ErrInvalidXFRMConfig)
		}
	}
	natt, err := normalizeXFRMNATTraversal(cfg.NATTraversal)
	if err != nil {
		return kernelXFRMParams{}, err
	}
	return kernelXFRMParams{
		child:          cfg.ChildSA,
		outerLocal:     outerLocal,
		outerRemote:    outerRemote,
		innerLocal:     innerLocal,
		innerRemote:    innerRemote,
		reqID:          strconv.Itoa(reqID),
		mark:           mark,
		ifID:           xfrmID(ifID),
		includeForward: cfg.IncludeForwardPolicy,
		xfrmiName:      xfrmiName,
		xfrmiOuterDev:  xfrmiOuterDev,
		xfrmiMTU:       cfg.XFRMInterface.MTU,
		natt:           natt,
	}, nil
}

func normalizeXFRMNATTraversal(cfg XFRMNATTraversalConfig) (kernelXFRMNATTraversal, error) {
	if !cfg.Enabled {
		if cfg.LocalPort != 0 || cfg.RemotePort != 0 || strings.TrimSpace(cfg.OriginalAddress) != "" {
			return kernelXFRMNATTraversal{}, fmt.Errorf("%w: nat traversal parameters require nat traversal enabled", ErrInvalidXFRMConfig)
		}
		return kernelXFRMNATTraversal{}, nil
	}
	localPort := cfg.LocalPort
	if localPort == 0 {
		localPort = 4500
	}
	remotePort := cfg.RemotePort
	if remotePort == 0 {
		remotePort = 4500
	}
	originalAddress := "0.0.0.0"
	if strings.TrimSpace(cfg.OriginalAddress) != "" {
		addr, err := normalizeIPAddress(cfg.OriginalAddress, "xfrm nat original address")
		if err != nil {
			return kernelXFRMNATTraversal{}, wrapXFRMError(err)
		}
		originalAddress = addr
	}
	return kernelXFRMNATTraversal{
		enabled:         true,
		localPort:       strconv.Itoa(int(localPort)),
		remotePort:      strconv.Itoa(int(remotePort)),
		originalAddress: originalAddress,
	}, nil
}

func validateChildSAForXFRM(child ikev2.ChildSAResult) error {
	if _, err := xfrmSPI(child.RemoteSPI); err != nil {
		return fmt.Errorf("%w: remote spi: %v", ErrInvalidXFRMConfig, err)
	}
	if _, err := xfrmSPI(child.LocalSPI); err != nil {
		return fmt.Errorf("%w: local spi: %v", ErrInvalidXFRMConfig, err)
	}
	switch child.Keys.Profile.EncryptionID {
	case ikev2.ENCR_AES_CBC:
		if _, _, err := xfrmAuthAlgorithm(child.Keys.Profile.IntegrityID); err != nil {
			return err
		}
		if err := validateXFRMCBCKeys(child.Keys.Profile, child.Keys.Outbound, "outbound"); err != nil {
			return err
		}
		if err := validateXFRMCBCKeys(child.Keys.Profile, child.Keys.Inbound, "inbound"); err != nil {
			return err
		}
	case ikev2.ENCR_AES_GCM_16:
		if child.Keys.Profile.IntegrityID != 0 || child.Keys.Profile.IntegrityKeyLength != 0 {
			return fmt.Errorf("%w: AES-GCM ESP must not include integrity transform", ErrInvalidXFRMConfig)
		}
		if err := validateXFRMAEADKeys(child.Keys.Profile, child.Keys.Outbound, "outbound"); err != nil {
			return err
		}
		if err := validateXFRMAEADKeys(child.Keys.Profile, child.Keys.Inbound, "inbound"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unsupported ESP encryption %d", ErrInvalidXFRMConfig, child.Keys.Profile.EncryptionID)
	}
	return nil
}

func validateXFRMCBCKeys(profile ikev2.ESPKeyProfile, keys ikev2.ESPKeys, direction string) error {
	if len(keys.EncryptionKey) != 16 && len(keys.EncryptionKey) != 24 && len(keys.EncryptionKey) != 32 {
		return fmt.Errorf("%w: %s AES key length %d", ErrInvalidXFRMConfig, direction, len(keys.EncryptionKey))
	}
	if profile.EncryptionKeyLength > 0 && len(keys.EncryptionKey) != profile.EncryptionKeyLength {
		return fmt.Errorf("%w: %s encryption key length %d != %d", ErrInvalidXFRMConfig, direction, len(keys.EncryptionKey), profile.EncryptionKeyLength)
	}
	if len(keys.IntegrityKey) == 0 {
		return fmt.Errorf("%w: %s integrity key is empty", ErrInvalidXFRMConfig, direction)
	}
	if profile.IntegrityKeyLength > 0 && len(keys.IntegrityKey) != profile.IntegrityKeyLength {
		return fmt.Errorf("%w: %s integrity key length %d != %d", ErrInvalidXFRMConfig, direction, len(keys.IntegrityKey), profile.IntegrityKeyLength)
	}
	return nil
}

func validateXFRMAEADKeys(profile ikev2.ESPKeyProfile, keys ikev2.ESPKeys, direction string) error {
	if !validXFRMAESGCMKeyLength(len(keys.EncryptionKey)) {
		return fmt.Errorf("%w: %s AES-GCM key length %d", ErrInvalidXFRMConfig, direction, len(keys.EncryptionKey))
	}
	if profile.EncryptionKeyLength > 0 && len(keys.EncryptionKey) != profile.EncryptionKeyLength {
		return fmt.Errorf("%w: %s encryption key length %d != %d", ErrInvalidXFRMConfig, direction, len(keys.EncryptionKey), profile.EncryptionKeyLength)
	}
	if len(keys.IntegrityKey) != 0 {
		return fmt.Errorf("%w: %s AES-GCM integrity key must be empty", ErrInvalidXFRMConfig, direction)
	}
	return nil
}

func xfrmStateAddArgs(params kernelXFRMParams, outbound bool) []string {
	src, dst, spi, keys := xfrmDirection(params, outbound)
	args := []string{
		"xfrm", "state", "add",
		"src", src,
		"dst", dst,
		"proto", "esp",
		"spi", spi,
		"reqid", params.reqID,
		"mode", "tunnel",
	}
	args = append(args, xfrmStateCryptoArgs(params.child.Keys.Profile, keys)...)
	args = appendXFRMCommonSelectors(args, params)
	args = appendXFRMNATTraversal(args, params, outbound)
	return args
}

func xfrmStateCryptoArgs(profile ikev2.ESPKeyProfile, keys ikev2.ESPKeys) []string {
	switch profile.EncryptionID {
	case ikev2.ENCR_AES_GCM_16:
		return []string{"aead", xfrmAeadAESGCMRFC4106, xfrmHexKey(keys.EncryptionKey), strconv.Itoa(xfrmAESGCMICVBits)}
	default:
		authAlg, truncBits, _ := xfrmAuthAlgorithm(profile.IntegrityID)
		return []string{
			"auth-trunc", authAlg, xfrmHexKey(keys.IntegrityKey), strconv.Itoa(truncBits),
			"enc", "cbc(aes)", xfrmHexKey(keys.EncryptionKey),
		}
	}
}

func xfrmStateDelArgs(params kernelXFRMParams, outbound bool) []string {
	src, dst, spi, _ := xfrmDirection(params, outbound)
	args := []string{"xfrm", "state", "delete", "src", src, "dst", dst, "proto", "esp", "spi", spi}
	args = appendXFRMCommonSelectors(args, params)
	return args
}

func xfrmPolicyAddArgs(params kernelXFRMParams, dir string) []string {
	src, dst, tmplSrc, tmplDst := xfrmPolicyDirection(params, dir)
	args := []string{
		"xfrm", "policy", "add",
		"src", src,
		"dst", dst,
		"dir", dir,
	}
	args = appendXFRMCommonSelectors(args, params)
	args = append(args,
		"tmpl",
		"src", tmplSrc,
		"dst", tmplDst,
		"proto", "esp",
		"reqid", params.reqID,
		"mode", "tunnel",
	)
	return args
}

func xfrmPolicyDelArgs(params kernelXFRMParams, dir string) []string {
	src, dst, _, _ := xfrmPolicyDirection(params, dir)
	args := []string{
		"xfrm", "policy", "delete",
		"src", src,
		"dst", dst,
		"dir", dir,
	}
	args = appendXFRMCommonSelectors(args, params)
	return args
}

func xfrmDirection(params kernelXFRMParams, outbound bool) (src, dst, spi string, keys ikev2.ESPKeys) {
	if outbound {
		spi, _ = xfrmSPI(params.child.RemoteSPI)
		return params.outerLocal, params.outerRemote, spi, params.child.Keys.Outbound
	}
	spi, _ = xfrmSPI(params.child.LocalSPI)
	return params.outerRemote, params.outerLocal, spi, params.child.Keys.Inbound
}

func xfrmPolicyDirection(params kernelXFRMParams, dir string) (src, dst, tmplSrc, tmplDst string) {
	if dir == "out" {
		return params.innerLocal, params.innerRemote, params.outerLocal, params.outerRemote
	}
	return params.innerRemote, params.innerLocal, params.outerRemote, params.outerLocal
}

func appendXFRMCommonSelectors(args []string, params kernelXFRMParams) []string {
	if params.mark != "" {
		args = append(args, "mark", params.mark)
	}
	if params.ifID != "" {
		args = append(args, "if_id", params.ifID)
	}
	return args
}

func appendXFRMNATTraversal(args []string, params kernelXFRMParams, outbound bool) []string {
	if !params.natt.enabled {
		return args
	}
	sourcePort, destPort := params.natt.localPort, params.natt.remotePort
	if !outbound {
		sourcePort, destPort = destPort, sourcePort
	}
	return append(args, "encap", "espinudp", sourcePort, destPort, params.natt.originalAddress)
}

func xfrmSPI(spi []byte) (string, error) {
	if len(spi) != 4 {
		return "", fmt.Errorf("spi length %d", len(spi))
	}
	v := binary.BigEndian.Uint32(spi)
	if v == 0 {
		return "", errors.New("spi is zero")
	}
	return fmt.Sprintf("0x%08x", v), nil
}

func xfrmHexKey(key []byte) string {
	return "0x" + hex.EncodeToString(key)
}

func xfrmAuthAlgorithm(integrity uint16) (name string, truncBits int, err error) {
	switch integrity {
	case ikev2.INTEG_HMAC_SHA1_96:
		return "hmac(sha1)", 96, nil
	case ikev2.INTEG_HMAC_SHA2_256_128:
		return "hmac(sha256)", 128, nil
	default:
		return "", 0, fmt.Errorf("%w: unsupported ESP integrity %d", ErrInvalidXFRMConfig, integrity)
	}
}

func validXFRMAESGCMKeyLength(n int) bool {
	switch n {
	case 16 + xfrmAESGCMSaltLength, 24 + xfrmAESGCMSaltLength, 32 + xfrmAESGCMSaltLength:
		return true
	default:
		return false
	}
}

func xfrmIPString(primary net.IP, fallbacks ...string) string {
	if ip := normalizedMOBIKEIP(primary, fallbacks...); ip != nil {
		return ip.String()
	}
	return ""
}

func firstXFRMTrafficSelectorPrefix(ts ikev2.TrafficSelectors) string {
	for _, selector := range ts.Selectors {
		if prefix, ok := xfrmTrafficSelectorPrefix(selector); ok {
			return prefix
		}
	}
	return ""
}

func xfrmTrafficSelectorPrefix(selector ikev2.TrafficSelector) (string, bool) {
	var start, end net.IP
	switch selector.Type {
	case ikev2.TSIPv4AddressRange:
		start, end = selector.StartAddr.To4(), selector.EndAddr.To4()
	case ikev2.TSIPv6AddressRange:
		if selector.StartAddr.To4() != nil || selector.EndAddr.To4() != nil {
			return "", false
		}
		start, end = selector.StartAddr.To16(), selector.EndAddr.To16()
	default:
		return "", false
	}
	if start == nil || end == nil {
		return "", false
	}
	prefixLen, ok := xfrmSinglePrefixRange(start, end)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%s/%d", net.IP(start).String(), prefixLen), true
}

func xfrmSinglePrefixRange(start, end []byte) (int, bool) {
	if len(start) == 0 || len(start) != len(end) || bytes.Compare(start, end) > 0 {
		return 0, false
	}
	prefixLen := len(start) * 8
	for i := range start {
		diff := start[i] ^ end[i]
		if diff == 0 {
			continue
		}
		prefixLen = i*8 + bits.LeadingZeros8(diff)
		break
	}
	for bit := prefixLen; bit < len(start)*8; bit++ {
		if xfrmIPBit(start, bit) != 0 || xfrmIPBit(end, bit) != 1 {
			return 0, false
		}
	}
	return prefixLen, true
}

func xfrmIPBit(ip []byte, bit int) byte {
	return (ip[bit/8] >> (7 - uint(bit%8))) & 1
}

func xfrmPortUint16(value string) uint16 {
	port, _ := strconv.ParseUint(value, 10, 16)
	return uint16(port)
}

func xfrmTransportPort(port uint16, addr string) uint16 {
	if port != 0 {
		return port
	}
	_, rawPort, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return 0
	}
	parsed, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(parsed)
}

func xfrmID(id uint32) string {
	if id == 0 {
		return ""
	}
	return fmt.Sprintf("0x%x", id)
}

func wrapXFRMError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrInvalidXFRMConfig) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrInvalidXFRMConfig, err)
}
