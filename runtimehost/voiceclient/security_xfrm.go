package voiceclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// ErrInvalidIMSSecurityXFRMPlan marks an install request that cannot be mapped to Linux XFRM.
var ErrInvalidIMSSecurityXFRMPlan = errors.New("invalid IMS security XFRM plan")

// IMSSecurityAssociationXFRMInstallPlan is a pure-data model of the ip xfrm work
// needed for an IMS Security-Agree association. Building it does not touch the OS.
type IMSSecurityAssociationXFRMInstallPlan struct {
	ReqID         int
	Mode          string
	LocalAddress  string
	RemoteAddress string
	Commands      []IMSSecurityAssociationXFRMCommand
}

// IMSSecurityAssociationXFRMCommand contains ip(8) arguments and the matching
// reverse operation arguments for a future installer.
type IMSSecurityAssociationXFRMCommand struct {
	Args     []string
	UndoArgs []string
}

type IMSSecurityAssociationXFRMState struct {
	Plan IMSSecurityAssociationXFRMInstallPlan
	undo []IMSSecurityAssociationXFRMCommand
}

type IMSSecurityXFRMCommandRunner interface {
	RunIP(context.Context, ...string) error
}

type IMSSecurityXFRMCommandRunnerFunc func(context.Context, ...string) error

func (f IMSSecurityXFRMCommandRunnerFunc) RunIP(ctx context.Context, args ...string) error {
	return f(ctx, args...)
}

type ExecIMSSecurityXFRMCommandRunner struct {
	Path string
}

func (r ExecIMSSecurityXFRMCommandRunner) RunIP(ctx context.Context, args ...string) error {
	path := strings.TrimSpace(r.Path)
	if path == "" {
		path = "ip"
	}
	cmd := exec.CommandContext(ctx, path, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

type LinuxIMSSecurityXFRMInstaller struct {
	Runner IMSSecurityXFRMCommandRunner

	mu     sync.Mutex
	states []IMSSecurityAssociationXFRMState
}

var _ SecurityPlanRequestInstaller = (*LinuxIMSSecurityXFRMInstaller)(nil)

type imsSecurityXFRMParams struct {
	reqID         string
	mode          string
	localAddress  string
	remoteAddress string
	localPort     string
	remotePort    string
	spiClient     string
	spiServer     string
	authAlgorithm string
	authKey       string
	authTruncBits string
	encAlgorithm  string
	encKey        string
}

// BuildIMSSecurityAssociationXFRMInstallPlan converts an IMS Security-Agree
// install request into Linux XFRM state and policy command arguments.
func BuildIMSSecurityAssociationXFRMInstallPlan(req IMSSecurityAssociationInstallRequest) (IMSSecurityAssociationXFRMInstallPlan, error) {
	params, err := normalizeIMSSecurityAssociationXFRMRequest(req)
	if err != nil {
		return IMSSecurityAssociationXFRMInstallPlan{}, err
	}
	commands := []IMSSecurityAssociationXFRMCommand{
		imssSecurityXFRMStateCommand(params, true),
		imssSecurityXFRMStateCommand(params, false),
		imssSecurityXFRMPolicyCommand(params, "out"),
		imssSecurityXFRMPolicyCommand(params, "in"),
	}
	return IMSSecurityAssociationXFRMInstallPlan{
		ReqID:         1,
		Mode:          params.mode,
		LocalAddress:  params.localAddress,
		RemoteAddress: params.remoteAddress,
		Commands:      commands,
	}, nil
}

func (i *LinuxIMSSecurityXFRMInstaller) InstallSecurityPlanRequest(ctx context.Context, req IMSSecurityAssociationInstallRequest) error {
	_, err := i.Apply(ctx, req)
	return err
}

func (i *LinuxIMSSecurityXFRMInstaller) Apply(ctx context.Context, req IMSSecurityAssociationInstallRequest) (IMSSecurityAssociationXFRMState, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	plan, err := BuildIMSSecurityAssociationXFRMInstallPlan(req)
	if err != nil {
		return IMSSecurityAssociationXFRMState{}, err
	}
	state, err := applyIMSSecurityXFRMPlan(ctx, imssSecurityXFRMRunner(i.Runner), plan)
	if err != nil {
		return state, err
	}
	i.mu.Lock()
	i.states = append(i.states, state)
	i.mu.Unlock()
	return state, nil
}

func (i *LinuxIMSSecurityXFRMInstaller) Cleanup(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	i.mu.Lock()
	states := append([]IMSSecurityAssociationXFRMState(nil), i.states...)
	i.mu.Unlock()

	var err error
	runner := imssSecurityXFRMRunner(i.Runner)
	for idx := len(states) - 1; idx >= 0; idx-- {
		err = errors.Join(err, cleanupIMSSecurityXFRMState(ctx, runner, states[idx]))
	}
	if err != nil {
		return err
	}
	i.mu.Lock()
	if len(i.states) >= len(states) {
		i.states = append([]IMSSecurityAssociationXFRMState(nil), i.states[len(states):]...)
	} else {
		i.states = nil
	}
	i.mu.Unlock()
	return nil
}

func (i *LinuxIMSSecurityXFRMInstaller) StateCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.states)
}

func applyIMSSecurityXFRMPlan(ctx context.Context, runner IMSSecurityXFRMCommandRunner, plan IMSSecurityAssociationXFRMInstallPlan) (IMSSecurityAssociationXFRMState, error) {
	state := IMSSecurityAssociationXFRMState{Plan: plan}
	for _, command := range plan.Commands {
		if err := runner.RunIP(ctx, command.Args...); err != nil {
			rollbackErr := runIMSSecurityXFRMUndo(ctx, runner, state.undo)
			if rollbackErr != nil {
				return state, errors.Join(err, rollbackErr)
			}
			return state, err
		}
		if len(command.UndoArgs) > 0 {
			state.undo = append(state.undo, cloneIMSSecurityXFRMCommand(command, true))
		}
	}
	return state, nil
}

func cleanupIMSSecurityXFRMState(ctx context.Context, runner IMSSecurityXFRMCommandRunner, state IMSSecurityAssociationXFRMState) error {
	return runIMSSecurityXFRMUndo(ctx, runner, state.undo)
}

func runIMSSecurityXFRMUndo(ctx context.Context, runner IMSSecurityXFRMCommandRunner, undo []IMSSecurityAssociationXFRMCommand) error {
	var err error
	for idx := len(undo) - 1; idx >= 0; idx-- {
		if len(undo[idx].UndoArgs) == 0 {
			continue
		}
		err = errors.Join(err, runner.RunIP(ctx, undo[idx].UndoArgs...))
	}
	return err
}

func imssSecurityXFRMRunner(runner IMSSecurityXFRMCommandRunner) IMSSecurityXFRMCommandRunner {
	if runner != nil {
		return runner
	}
	return ExecIMSSecurityXFRMCommandRunner{}
}

func cloneIMSSecurityXFRMCommand(command IMSSecurityAssociationXFRMCommand, undoOnly bool) IMSSecurityAssociationXFRMCommand {
	out := IMSSecurityAssociationXFRMCommand{
		UndoArgs: append([]string(nil), command.UndoArgs...),
	}
	if !undoOnly {
		out.Args = append([]string(nil), command.Args...)
	}
	return out
}

func normalizeIMSSecurityAssociationXFRMRequest(req IMSSecurityAssociationInstallRequest) (imsSecurityXFRMParams, error) {
	plan := req.Plan
	if isZeroIMSSecurityAssociationPlan(plan) {
		var ok bool
		plan, ok = BuildIMSSecurityAssociationPlan(req.Agreement)
		if !ok && len(req.SelectedParameters) == 0 {
			return imsSecurityXFRMParams{}, fmt.Errorf("%w: missing Security-Agree plan", ErrInvalidIMSSecurityXFRMPlan)
		}
	}
	protocol := strings.ToLower(strings.TrimSpace(firstNonEmpty(plan.Protocol, req.Agreement.Protocol, DefaultSecurityProtocol)))
	if protocol != DefaultSecurityProtocol {
		return imsSecurityXFRMParams{}, fmt.Errorf("%w: unsupported protocol %q", ErrInvalidIMSSecurityXFRMPlan, protocol)
	}
	if err := imssSecurityXFRMProtocol(firstNonEmpty(req.Agreement.Parameters["prot"], req.SelectedParameters["prot"], defaultSecurityIPSecProtocol)); err != nil {
		return imsSecurityXFRMParams{}, err
	}
	mode, err := imssSecurityXFRMMode(firstNonEmpty(plan.Mode, req.Agreement.Parameters["mode"], req.Agreement.Parameters["mod"], req.SelectedParameters["mode"], req.SelectedParameters["mod"], defaultSecurityMode))
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	authAlgorithm, authTruncBits, err := imssSecurityXFRMAuthAlgorithm(firstNonEmpty(plan.Algorithm, req.Agreement.Algorithm, req.SelectedParameters["alg"], DefaultSecurityAlgorithm))
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	if len(req.AKA.IK) != 16 {
		return imsSecurityXFRMParams{}, fmt.Errorf("%w: IK length %d", ErrInvalidIMSSecurityXFRMPlan, len(req.AKA.IK))
	}
	encAlgorithm, encKey, err := imssSecurityXFRMEncryption(firstNonEmpty(plan.EncryptionAlgorithm, req.Agreement.EncryptionAlgorithm, req.SelectedParameters["ealg"], DefaultSecurityEAlg), req.AKA.CK)
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	localAddress, err := imssSecurityXFRMAddress(req.LocalEndpoint, "local")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	remoteAddress, err := imssSecurityXFRMAddress(req.RemoteEndpoint, "remote")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	localPort, err := imssSecurityXFRMPort(firstIMSSecurityPositiveInt(plan.PortClient, plan.Outbound.LocalPort, plan.Inbound.LocalPort, req.Agreement.PortClient, parseSecurityPort(req.SelectedParameters["port-c"]), req.LocalEndpoint.Port), "local")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	remotePort, err := imssSecurityXFRMPort(firstIMSSecurityPositiveInt(plan.PortServer, plan.Outbound.RemotePort, plan.Inbound.RemotePort, req.Agreement.PortServer, parseSecurityPort(req.SelectedParameters["port-s"]), req.RemoteEndpoint.Port), "remote")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	spiClient, err := imssSecurityXFRMSPI(firstIMSSecurityNonZeroUint32(plan.SPIClient, plan.Inbound.SPI, req.Agreement.SPIClient, parseSecurityUint32(req.SelectedParameters["spi-c"])), "client")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	spiServer, err := imssSecurityXFRMSPI(firstIMSSecurityNonZeroUint32(plan.SPIServer, plan.Outbound.SPI, req.Agreement.SPIServer, parseSecurityUint32(req.SelectedParameters["spi-s"])), "server")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	return imsSecurityXFRMParams{
		reqID:         "1",
		mode:          mode,
		localAddress:  localAddress,
		remoteAddress: remoteAddress,
		localPort:     localPort,
		remotePort:    remotePort,
		spiClient:     spiClient,
		spiServer:     spiServer,
		authAlgorithm: authAlgorithm,
		authKey:       imssSecurityXFRMHexKey(req.AKA.IK),
		authTruncBits: authTruncBits,
		encAlgorithm:  encAlgorithm,
		encKey:        encKey,
	}, nil
}

func imssSecurityXFRMStateCommand(params imsSecurityXFRMParams, outbound bool) IMSSecurityAssociationXFRMCommand {
	src, dst, spi, sport, dport := params.localAddress, params.remoteAddress, params.spiServer, params.localPort, params.remotePort
	if !outbound {
		src, dst, spi, sport, dport = params.remoteAddress, params.localAddress, params.spiClient, params.remotePort, params.localPort
	}
	args := []string{
		"xfrm", "state", "add",
		"src", src,
		"dst", dst,
		"proto", "esp",
		"spi", spi,
		"reqid", params.reqID,
		"mode", params.mode,
		"auth-trunc", params.authAlgorithm, params.authKey, params.authTruncBits,
		"enc", params.encAlgorithm, params.encKey,
		"sel",
		"src", src,
		"dst", dst,
		"proto", "udp",
		"sport", sport,
		"dport", dport,
	}
	undo := []string{"xfrm", "state", "delete", "src", src, "dst", dst, "proto", "esp", "spi", spi}
	return IMSSecurityAssociationXFRMCommand{Args: args, UndoArgs: undo}
}

func imssSecurityXFRMPolicyCommand(params imsSecurityXFRMParams, dir string) IMSSecurityAssociationXFRMCommand {
	src, dst, sport, dport := params.localAddress, params.remoteAddress, params.localPort, params.remotePort
	if dir == "in" {
		src, dst, sport, dport = params.remoteAddress, params.localAddress, params.remotePort, params.localPort
	}
	args := []string{
		"xfrm", "policy", "add",
		"src", src,
		"dst", dst,
		"proto", "udp",
		"sport", sport,
		"dport", dport,
		"dir", dir,
		"tmpl",
		"src", src,
		"dst", dst,
		"proto", "esp",
		"reqid", params.reqID,
		"mode", params.mode,
	}
	undo := []string{
		"xfrm", "policy", "delete",
		"src", src,
		"dst", dst,
		"proto", "udp",
		"sport", sport,
		"dport", dport,
		"dir", dir,
	}
	return IMSSecurityAssociationXFRMCommand{Args: args, UndoArgs: undo}
}

func imssSecurityXFRMProtocol(protocol string) error {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", defaultSecurityIPSecProtocol:
		return nil
	default:
		return fmt.Errorf("%w: unsupported ipsec protocol %q", ErrInvalidIMSSecurityXFRMPlan, protocol)
	}
}

func imssSecurityXFRMMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "trans", "transport":
		return "transport", nil
	default:
		return "", fmt.Errorf("%w: unsupported mode %q", ErrInvalidIMSSecurityXFRMPlan, mode)
	}
}

func imssSecurityXFRMAuthAlgorithm(algorithm string) (name, truncBits string, err error) {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case DefaultSecurityAlgorithm:
		return "hmac(sha1)", "96", nil
	case SecurityAlgorithmHMACMD596:
		return "hmac(md5)", "96", nil
	default:
		return "", "", fmt.Errorf("%w: unsupported auth algorithm %q", ErrInvalidIMSSecurityXFRMPlan, algorithm)
	}
}

func imssSecurityXFRMEncryption(algorithm string, ck []byte) (name, key string, err error) {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case DefaultSecurityEAlg:
		return "ecb(cipher_null)", "0x", nil
	case SecurityEncryptionAlgorithmAES:
		if len(ck) != 16 {
			return "", "", fmt.Errorf("%w: CK length %d for %s", ErrInvalidIMSSecurityXFRMPlan, len(ck), SecurityEncryptionAlgorithmAES)
		}
		return "cbc(aes)", imssSecurityXFRMHexKey(ck), nil
	default:
		return "", "", fmt.Errorf("%w: unsupported encryption algorithm %q", ErrInvalidIMSSecurityXFRMPlan, algorithm)
	}
}

func imssSecurityXFRMAddress(endpoint IMSSecurityAssociationEndpoint, label string) (string, error) {
	raw := strings.Trim(strings.TrimSpace(endpoint.Address), "[]")
	if raw == "" {
		return "", fmt.Errorf("%w: %s address is empty", ErrInvalidIMSSecurityXFRMPlan, label)
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %s address %q: %v", ErrInvalidIMSSecurityXFRMPlan, label, endpoint.Address, err)
	}
	return addr.Unmap().String(), nil
}

func imssSecurityXFRMPort(port int, label string) (string, error) {
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("%w: %s port %d", ErrInvalidIMSSecurityXFRMPlan, label, port)
	}
	return strconv.Itoa(port), nil
}

func imssSecurityXFRMSPI(spi uint32, label string) (string, error) {
	if spi == 0 {
		return "", fmt.Errorf("%w: %s spi is zero", ErrInvalidIMSSecurityXFRMPlan, label)
	}
	return fmt.Sprintf("0x%08x", spi), nil
}

func imssSecurityXFRMHexKey(key []byte) string {
	return "0x" + hex.EncodeToString(key)
}

func firstIMSSecurityPositiveInt(items ...int) int {
	for _, item := range items {
		if item > 0 {
			return item
		}
	}
	return 0
}

func firstIMSSecurityNonZeroUint32(items ...uint32) uint32 {
	for _, item := range items {
		if item != 0 {
			return item
		}
	}
	return 0
}
