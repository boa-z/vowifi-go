package simtransport

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type RecoveryClass string
type RecoveryAction string
type APDURecoveryAction string

const (
	RecoveryClassNone            RecoveryClass = ""
	RecoveryClassControlPortHung RecoveryClass = "control_port_hung"
	RecoveryClassSIMBusy         RecoveryClass = "sim_busy"
	RecoveryClassFileNotFound    RecoveryClass = "file_not_found"
	RecoveryClassEmptyEF         RecoveryClass = "empty_ef"
	RecoveryClassMalformedReply  RecoveryClass = "malformed_reply"
	RecoveryClassATError         RecoveryClass = "at_error"
)

const (
	RecoveryActionNone              RecoveryAction = ""
	RecoveryActionATControlRecovery RecoveryAction = "at_control_recovery"
	RecoveryActionRetryLater        RecoveryAction = "retry_later"
	RecoveryActionRefreshIdentity   RecoveryAction = "refresh_identity_source"
	RecoveryActionRepairAPDU        RecoveryAction = "repair_apdu_exchange"
	RecoveryActionInspectATError    RecoveryAction = "inspect_at_error"
)

const (
	APDURecoveryNone        APDURecoveryAction = ""
	APDURecoveryCorrectLe   APDURecoveryAction = "correct_le"
	APDURecoveryGetResponse APDURecoveryAction = "get_response"
)

// RecoveryRecommendation describes a non-executing recovery decision.
type RecoveryRecommendation struct {
	Class             RecoveryClass
	Action            RecoveryAction
	Recoverable       bool
	RetryAfter        time.Duration
	ATControlPlan     []ATRecoveryStep
	HardwareAffecting bool
}

type APDURecoveryPlan struct {
	Action APDURecoveryAction
	Le     int
}

// ATRecoveryStep describes one command in a planned AT control recovery sequence.
type ATRecoveryStep struct {
	Command         string
	Timeout         time.Duration
	DelayAfter      time.Duration
	ContinueOnError bool
	VendorSpecific  bool
}

// ATRecoveryOptions tunes execution of a planned AT control recovery sequence.
type ATRecoveryOptions struct {
	AllowVendorSpecific bool
	DryRun              bool
	Delay               ATRecoveryDelayFunc
}

// ATRecoveryDelayFunc waits between recovery steps and should return ctx.Err()
// when the context is canceled before the delay completes.
type ATRecoveryDelayFunc func(ctx context.Context, delay time.Duration) error

// ATRecoveryExecutor executes one AT recovery command.
type ATRecoveryExecutor interface {
	ExecuteATRecovery(ctx context.Context, command string, timeout time.Duration) error
}

// ATRecoveryExecutorFunc adapts a function to ATRecoveryExecutor.
type ATRecoveryExecutorFunc func(ctx context.Context, command string, timeout time.Duration) error

func (f ATRecoveryExecutorFunc) ExecuteATRecovery(ctx context.Context, command string, timeout time.Duration) error {
	if f == nil {
		return errors.New("nil AT recovery executor func")
	}
	return f(ctx, command, timeout)
}

type recoveryClassifier interface {
	RecoveryClass() RecoveryClass
}

type statusCarrier interface {
	Status() uint16
}

type timeoutCarrier interface {
	Timeout() bool
}

func (c RecoveryClass) Recoverable() bool {
	return c != RecoveryClassNone
}

func (p APDURecoveryPlan) Recoverable() bool {
	return p.Action != APDURecoveryNone
}

func (p APDURecoveryPlan) LeByte() (byte, error) {
	return apduLeByte(p.Le)
}

// RecommendRecovery maps a recovery class to operator-visible next steps.
//
// For AT control recovery, the returned plan is descriptive only; callers must
// pass it to RunATRecoveryPlan or ExecuteATControlRecovery to perform commands.
func RecommendRecovery(class RecoveryClass, attempt int) RecoveryRecommendation {
	rec := RecoveryRecommendation{
		Class:       class,
		Recoverable: class.Recoverable(),
	}
	switch class {
	case RecoveryClassControlPortHung:
		rec.Action = RecoveryActionATControlRecovery
		rec.ATControlPlan = PlanATControlRecovery(class, attempt)
		rec.HardwareAffecting = len(rec.ATControlPlan) > 0
	case RecoveryClassSIMBusy:
		rec.Action = RecoveryActionRetryLater
		rec.RetryAfter = 2 * time.Second
	case RecoveryClassEmptyEF, RecoveryClassFileNotFound:
		rec.Action = RecoveryActionRefreshIdentity
	case RecoveryClassMalformedReply:
		rec.Action = RecoveryActionRepairAPDU
	case RecoveryClassATError:
		rec.Action = RecoveryActionInspectATError
		rec.ATControlPlan = PlanATControlRecovery(class, attempt)
		rec.HardwareAffecting = len(rec.ATControlPlan) > 0
	default:
		rec.Action = RecoveryActionNone
	}
	return rec
}

// PlanATControlRecovery returns a non-executing recovery sequence for a stuck AT control path.
func PlanATControlRecovery(class RecoveryClass, attempt int) []ATRecoveryStep {
	if !needsATControlRecovery(class) {
		return nil
	}
	if attempt < 0 {
		attempt = 0
	}
	switch attempt {
	case 0:
		return []ATRecoveryStep{
			{
				Command:         "AT+CFUN=0",
				Timeout:         5 * time.Second,
				DelayAfter:      2 * time.Second,
				ContinueOnError: true,
			},
			{
				Command:    "AT+CFUN=1",
				Timeout:    10 * time.Second,
				DelayAfter: 5 * time.Second,
			},
		}
	case 1:
		return []ATRecoveryStep{
			{
				Command:    "AT+CFUN=1,1",
				Timeout:    10 * time.Second,
				DelayAfter: 20 * time.Second,
			},
		}
	default:
		return []ATRecoveryStep{
			{
				Command:        "AT!RESET",
				Timeout:        10 * time.Second,
				DelayAfter:     30 * time.Second,
				VendorSpecific: true,
			},
		}
	}
}

// ExecuteATControlRecovery runs planned AT control recovery steps through an ATCommander.
func ExecuteATControlRecovery(ctx context.Context, control ATCommander, steps []ATRecoveryStep, opts ATRecoveryOptions) error {
	if control == nil {
		return errors.New("nil AT control")
	}
	return RunATRecoveryPlan(ctx, ATRecoveryExecutorFunc(func(ctx context.Context, command string, timeout time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		out, err := control.ExecuteATSilent(command, timeout)
		if err != nil {
			return err
		}
		return parseATError(out)
	}), steps, opts)
}

// RunATRecoveryPlan executes a planned AT recovery sequence.
//
// Vendor-specific steps are skipped unless opts.AllowVendorSpecific is true.
// DryRun returns without executing commands or delays.
func RunATRecoveryPlan(ctx context.Context, executor ATRecoveryExecutor, steps []ATRecoveryStep, opts ATRecoveryOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.DryRun {
		return ctx.Err()
	}
	if executor == nil {
		return errors.New("nil AT recovery executor")
	}
	delay := opts.Delay
	if delay == nil {
		delay = sleepATRecoveryDelay
	}
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return err
		}
		if step.VendorSpecific && !opts.AllowVendorSpecific {
			continue
		}
		if err := executor.ExecuteATRecovery(ctx, step.Command, step.Timeout); err != nil {
			if !step.ContinueOnError {
				return fmt.Errorf("AT recovery command %q: %w", step.Command, err)
			}
		}
		if step.DelayAfter <= 0 {
			continue
		}
		if err := delay(ctx, step.DelayAfter); err != nil {
			return fmt.Errorf("AT recovery delay after %q: %w", step.Command, err)
		}
	}
	return nil
}

func PlanAPDUStatusRecovery(sw1, sw2 byte) APDURecoveryPlan {
	switch sw1 {
	case 0x6C:
		return APDURecoveryPlan{Action: APDURecoveryCorrectLe, Le: apduLeFromSW2(sw2)}
	case 0x61, 0x9F:
		return APDURecoveryPlan{Action: APDURecoveryGetResponse, Le: apduLeFromSW2(sw2)}
	default:
		return APDURecoveryPlan{}
	}
}

func CorrectAPDULe(apdu []byte, le int) ([]byte, error) {
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

func GetResponseAPDU(le int) ([]byte, error) {
	return GetResponseAPDUWithCLA(0x00, le)
}

func GetResponseAPDUWithCLA(cla byte, le int) ([]byte, error) {
	leByte, err := apduLeByte(le)
	if err != nil {
		return nil, err
	}
	return []byte{cla, 0xC0, 0x00, 0x00, leByte}, nil
}

func ClassifyError(err error) RecoveryClass {
	if err == nil {
		return RecoveryClassNone
	}
	var classifier recoveryClassifier
	if errors.As(err, &classifier) {
		if class := classifier.RecoveryClass(); class != RecoveryClassNone {
			return class
		}
	}
	var status statusCarrier
	if errors.As(err, &status) {
		if class := StatusUint16RecoveryClass(status.Status()); class != RecoveryClassNone {
			return class
		}
	}
	var timeout timeoutCarrier
	if errors.As(err, &timeout) && timeout.Timeout() {
		return RecoveryClassControlPortHung
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return RecoveryClassControlPortHung
	}
	return classifyErrorText(err.Error())
}

func StatusUint16RecoveryClass(status uint16) RecoveryClass {
	return StatusRecoveryClass(byte(status>>8), byte(status))
}

func StatusRecoveryClass(sw1, sw2 byte) RecoveryClass {
	switch {
	case sw1 == 0x90 && sw2 == 0x00:
		return RecoveryClassNone
	case PlanAPDUStatusRecovery(sw1, sw2).Recoverable():
		return RecoveryClassMalformedReply
	case isFileNotFoundStatus(sw1, sw2):
		return RecoveryClassFileNotFound
	case sw1 == 0x62 && sw2 == 0x82:
		return RecoveryClassEmptyEF
	case isSIMBusyStatus(sw1, sw2):
		return RecoveryClassSIMBusy
	case isMalformedAPDUStatus(sw1, sw2):
		return RecoveryClassMalformedReply
	default:
		return RecoveryClassNone
	}
}

func StatusStringRecoveryClass(status string) RecoveryClass {
	s := strings.TrimSpace(status)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s) != 4 || !looksHex(s) {
		return RecoveryClassNone
	}
	n, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return RecoveryClassNone
	}
	return StatusRecoveryClass(byte(n>>8), byte(n))
}

func (r APDUResult) RecoveryClass() RecoveryClass {
	return StatusRecoveryClass(r.SW1, r.SW2)
}

func (r CRSMResult) RecoveryClass() RecoveryClass {
	return StatusRecoveryClass(r.SW1, r.SW2)
}

func needsATControlRecovery(class RecoveryClass) bool {
	return class == RecoveryClassControlPortHung || class == RecoveryClassATError
}

func sleepATRecoveryDelay(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func classifyErrorText(text string) RecoveryClass {
	s := strings.ToLower(strings.TrimSpace(text))
	statusClass := statusTextRecoveryClass(s)
	cmeClass := cmeErrorRecoveryClass(s)
	switch {
	case s == "":
		return RecoveryClassNone
	case strings.Contains(s, "isim identity data empty") ||
		strings.Contains(s, "empty ef") ||
		strings.Contains(s, "ef data empty"):
		return RecoveryClassEmptyEF
	case s == "6a82" ||
		s == "6a83" ||
		strings.Contains(s, "sw=6a82") ||
		strings.Contains(s, "sw=6a83") ||
		strings.Contains(s, "status=6a82") ||
		strings.Contains(s, "status=6a83") ||
		strings.Contains(s, " 6a82") ||
		strings.Contains(s, " 6a83"):
		return RecoveryClassFileNotFound
	case statusClass != RecoveryClassNone:
		return statusClass
	case cmeClass != RecoveryClassNone:
		return cmeClass
	case strings.Contains(s, "sim busy") ||
		strings.Contains(s, "apdu busy") ||
		strings.Contains(s, "sim is busy") ||
		strings.Contains(s, "resource busy"):
		return RecoveryClassSIMBusy
	case strings.Contains(s, "context deadline exceeded") ||
		strings.Contains(s, "timeout") ||
		strings.Contains(s, "timed out") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "no response") ||
		strings.Contains(s, "hang") ||
		strings.Contains(s, "hung") ||
		strings.Contains(s, "control port") ||
		strings.Contains(s, "parse ccho channel") ||
		strings.Contains(s, "parse imei") ||
		strings.Contains(s, "parse imsi") ||
		strings.Contains(s, "parse crsm result") ||
		strings.Contains(s, "parse apdu response hex"):
		return RecoveryClassControlPortHung
	case strings.Contains(s, "invalid crsm data") ||
		strings.Contains(s, "invalid apdu response") ||
		strings.Contains(s, "apdu response too short"):
		return RecoveryClassMalformedReply
	case strings.Contains(s, "at cme error") ||
		strings.Contains(s, "at error"):
		return RecoveryClassATError
	default:
		return RecoveryClassNone
	}
}

func isFileNotFoundStatus(sw1, sw2 byte) bool {
	return (sw1 == 0x6A && (sw2 == 0x82 || sw2 == 0x83)) ||
		(sw2 == 0x6A && (sw1 == 0x82 || sw1 == 0x83)) ||
		(sw1 == 0x94 && (sw2 == 0x04 || sw2 == 0x08))
}

func isSIMBusyStatus(sw1, sw2 byte) bool {
	return sw1 == 0x93 ||
		(sw1 == 0x62 && sw2 == 0x83) ||
		(sw1 == 0x64 && sw2 == 0x00) ||
		sw1 == 0x65 ||
		(sw1 == 0x6F && sw2 == 0x00)
}

func isMalformedAPDUStatus(sw1, sw2 byte) bool {
	return sw1 == 0x67 ||
		sw1 == 0x6B ||
		sw1 == 0x6C ||
		sw1 == 0x6D ||
		sw1 == 0x6E ||
		(sw1 == 0x6A && sw2 == 0x86)
}

func cmeErrorRecoveryClass(text string) RecoveryClass {
	i := strings.Index(text, "at cme error:")
	if i < 0 {
		return RecoveryClassNone
	}
	detail := strings.TrimSpace(text[i+len("at cme error:"):])
	if detail == "" {
		return RecoveryClassATError
	}
	switch {
	case detail == "14" ||
		strings.Contains(detail, "sim busy") ||
		strings.Contains(detail, "busy") ||
		strings.Contains(detail, "temporarily not allowed"):
		return RecoveryClassSIMBusy
	default:
		return RecoveryClassATError
	}
}

func statusTextRecoveryClass(text string) RecoveryClass {
	for _, token := range strings.FieldsFunc(text, func(r rune) bool {
		return !('0' <= r && r <= '9' || 'a' <= r && r <= 'f' || 'A' <= r && r <= 'F')
	}) {
		if class := StatusStringRecoveryClass(token); class != RecoveryClassNone {
			return class
		}
	}
	return RecoveryClassNone
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
