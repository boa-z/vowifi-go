package voiceclient

import (
	"strings"
	"time"
)

const (
	defaultSIPTimerT1 = 500 * time.Millisecond
	defaultSIPTimerT2 = 4 * time.Second
	defaultSIPTimerT4 = 5 * time.Second
)

// SIPTransactionTimerConfig overrides the RFC 3261 transaction timer base values.
type SIPTransactionTimerConfig struct {
	T1 time.Duration
	T2 time.Duration
	T4 time.Duration
}

// SIPTransactionTimerPolicy describes the client transaction timers for a request method.
type SIPTransactionTimerPolicy struct {
	Method string
	Invite bool
	T1     time.Duration
	T2     time.Duration
	T4     time.Duration
	TimerA time.Duration
	TimerB time.Duration
	TimerD time.Duration
	TimerE time.Duration
	TimerF time.Duration
	TimerK time.Duration
}

// SIPTransactionRetrySchedule describes UDP retransmission timing before timeout.
type SIPTransactionRetrySchedule struct {
	Method      string
	Invite      bool
	Intervals   []time.Duration
	Timeout     time.Duration
	CleanupWait time.Duration
}

type SIPClientTransactionState string

const (
	SIPClientTransactionStateCalling    SIPClientTransactionState = "calling"
	SIPClientTransactionStateTrying     SIPClientTransactionState = "trying"
	SIPClientTransactionStateProceeding SIPClientTransactionState = "proceeding"
	SIPClientTransactionStateCompleted  SIPClientTransactionState = "completed"
	SIPClientTransactionStateTerminated SIPClientTransactionState = "terminated"
)

type SIPClientTransactionEvent string

const (
	SIPClientTransactionEventResponse        SIPClientTransactionEvent = "response"
	SIPClientTransactionEventRetransmitTimer SIPClientTransactionEvent = "retransmit-timer"
	SIPClientTransactionEventTimeoutTimer    SIPClientTransactionEvent = "timeout-timer"
	SIPClientTransactionEventCleanupTimer    SIPClientTransactionEvent = "cleanup-timer"
)

type SIPClientTransactionAction string

const (
	SIPClientTransactionActionNone               SIPClientTransactionAction = "none"
	SIPClientTransactionActionWait               SIPClientTransactionAction = "wait"
	SIPClientTransactionActionRetransmitRequest  SIPClientTransactionAction = "retransmit-request"
	SIPClientTransactionActionDeliverProvisional SIPClientTransactionAction = "deliver-provisional"
	SIPClientTransactionActionDeliverFinal       SIPClientTransactionAction = "deliver-final"
	SIPClientTransactionActionTimeout            SIPClientTransactionAction = "timeout"
	SIPClientTransactionActionTerminate          SIPClientTransactionAction = "terminate"
)

// SIPClientTransactionInput describes one response or timer event for the pure
// client transaction state machine. ReliableTransport should be true for TCP/TLS
// style transports where RFC 3261 cleanup timers D/K are zero.
type SIPClientTransactionInput struct {
	Method                   string
	State                    SIPClientTransactionState
	Event                    SIPClientTransactionEvent
	Response                 SIPResponse
	ReliableTransport        bool
	LastRetransmitInterval   time.Duration
	TimerConfig              SIPTransactionTimerConfig
	MaxRetransmits           int
	CompletedRetransmissions int
}

// SIPClientTransactionStep is a non-executing decision for one client
// transaction event.
type SIPClientTransactionStep struct {
	Method                 string
	Invite                 bool
	Event                  SIPClientTransactionEvent
	State                  SIPClientTransactionState
	NextState              SIPClientTransactionState
	Action                 SIPClientTransactionAction
	StatusCode             int
	Provisional            bool
	Final                  bool
	Success                bool
	Failure                bool
	DeliverResponse        bool
	RetransmitRequest      bool
	SendAck                bool
	TimedOut               bool
	Terminated             bool
	CleanupAfter           time.Duration
	NextRetransmitInterval time.Duration
	TimerName              string
}

// DefaultSIPTransactionTimerPolicy returns the default transaction timer policy.
func DefaultSIPTransactionTimerPolicy(method string) SIPTransactionTimerPolicy {
	return SIPTransactionTimerPolicyFor(method, SIPTransactionTimerConfig{})
}

// SIPTransactionTimerPolicyFor returns transaction timers using cfg base values.
func SIPTransactionTimerPolicyFor(method string, cfg SIPTransactionTimerConfig) SIPTransactionTimerPolicy {
	method = strings.ToUpper(strings.TrimSpace(method))
	t1 := cfg.T1
	if t1 <= 0 {
		t1 = defaultSIPTimerT1
	}
	t2 := cfg.T2
	if t2 <= 0 {
		t2 = defaultSIPTimerT2
	}
	if t2 < t1 {
		t2 = t1
	}
	t4 := cfg.T4
	if t4 <= 0 {
		t4 = defaultSIPTimerT4
	}
	policy := SIPTransactionTimerPolicy{
		Method: method,
		Invite: sipTransactionKindForMethod(method) == sipTransactionInvite,
		T1:     t1,
		T2:     t2,
		T4:     t4,
	}
	if policy.Invite {
		policy.TimerA = t1
		policy.TimerB = 64 * t1
		policy.TimerD = 64 * t1
		return policy
	}
	policy.TimerE = t1
	policy.TimerF = 64 * t1
	policy.TimerK = t4
	return policy
}

// SIPTransactionRetryScheduleFor returns the retry schedule for a UDP client transaction.
func SIPTransactionRetryScheduleFor(method string, cfg SIPTransactionTimerConfig) SIPTransactionRetrySchedule {
	policy := SIPTransactionTimerPolicyFor(method, cfg)
	interval := policy.TimerE
	timeout := policy.TimerF
	cleanupWait := policy.TimerK
	if policy.Invite {
		interval = policy.TimerA
		timeout = policy.TimerB
		cleanupWait = 0
	}
	schedule := SIPTransactionRetrySchedule{
		Method:      policy.Method,
		Invite:      policy.Invite,
		Timeout:     timeout,
		CleanupWait: cleanupWait,
	}
	for elapsed := time.Duration(0); interval > 0 && elapsed+interval < timeout; {
		schedule.Intervals = append(schedule.Intervals, interval)
		elapsed += interval
		interval = nextSIPRetransmitInterval(interval, policy.T2)
	}
	return schedule
}

// InitialSIPClientTransactionState returns the RFC 3261 client transaction
// start state for method.
func InitialSIPClientTransactionState(method string) SIPClientTransactionState {
	if sipTransactionKindForMethod(method) == sipTransactionInvite {
		return SIPClientTransactionStateCalling
	}
	return SIPClientTransactionStateTrying
}

// AdvanceSIPClientTransaction advances a pure RFC 3261 client transaction state
// machine by one response or timer event. It does not write to the network.
func AdvanceSIPClientTransaction(input SIPClientTransactionInput) SIPClientTransactionStep {
	policy := SIPTransactionTimerPolicyFor(input.Method, input.TimerConfig)
	state := normalizeSIPClientTransactionState(input.State, policy.Method)
	event := input.Event
	if event == "" {
		event = SIPClientTransactionEventResponse
	}
	step := SIPClientTransactionStep{
		Method:    policy.Method,
		Invite:    policy.Invite,
		Event:     event,
		State:     state,
		NextState: state,
		Action:    SIPClientTransactionActionNone,
	}
	if state == SIPClientTransactionStateTerminated {
		step.Terminated = true
		return step
	}
	switch event {
	case SIPClientTransactionEventResponse:
		return advanceSIPClientTransactionResponse(step, input.Response, input.ReliableTransport, policy)
	case SIPClientTransactionEventRetransmitTimer:
		return advanceSIPClientTransactionRetransmitTimer(step, input.ReliableTransport, input.LastRetransmitInterval, input.MaxRetransmits, input.CompletedRetransmissions, policy)
	case SIPClientTransactionEventTimeoutTimer:
		return advanceSIPClientTransactionTimeoutTimer(step)
	case SIPClientTransactionEventCleanupTimer:
		return advanceSIPClientTransactionCleanupTimer(step)
	default:
		step.Action = SIPClientTransactionActionWait
		return step
	}
}

func advanceSIPClientTransactionResponse(step SIPClientTransactionStep, resp SIPResponse, reliable bool, policy SIPTransactionTimerPolicy) SIPClientTransactionStep {
	code := resp.StatusCode
	step.StatusCode = code
	step.Provisional = isSIPProvisionalResponse(code)
	step.Success = isSIPSuccess(code)
	step.Final = code >= 200
	step.Failure = code >= 300
	if code == 0 {
		step.Action = SIPClientTransactionActionWait
		return step
	}
	if step.Invite {
		return advanceSIPInviteClientTransactionResponse(step, reliable, policy)
	}
	return advanceSIPNonInviteClientTransactionResponse(step, reliable, policy)
}

func advanceSIPInviteClientTransactionResponse(step SIPClientTransactionStep, reliable bool, policy SIPTransactionTimerPolicy) SIPClientTransactionStep {
	switch {
	case step.Provisional:
		if step.State == SIPClientTransactionStateCalling || step.State == SIPClientTransactionStateProceeding {
			step.NextState = SIPClientTransactionStateProceeding
			step.Action = SIPClientTransactionActionDeliverProvisional
			step.DeliverResponse = true
			return step
		}
	case step.Success:
		if step.State == SIPClientTransactionStateCalling || step.State == SIPClientTransactionStateProceeding {
			step.NextState = SIPClientTransactionStateTerminated
			step.Action = SIPClientTransactionActionDeliverFinal
			step.DeliverResponse = true
			step.Terminated = true
			return step
		}
	case step.Failure:
		if step.State == SIPClientTransactionStateCompleted {
			step.Action = SIPClientTransactionActionDeliverFinal
			step.SendAck = true
			return step
		}
		if step.State == SIPClientTransactionStateCalling || step.State == SIPClientTransactionStateProceeding {
			step.Action = SIPClientTransactionActionDeliverFinal
			step.DeliverResponse = true
			step.SendAck = true
			return completeSIPClientTransaction(step, reliable, policy.TimerD)
		}
	}
	step.Action = SIPClientTransactionActionWait
	return step
}

func advanceSIPNonInviteClientTransactionResponse(step SIPClientTransactionStep, reliable bool, policy SIPTransactionTimerPolicy) SIPClientTransactionStep {
	switch {
	case step.Provisional:
		if step.State == SIPClientTransactionStateTrying || step.State == SIPClientTransactionStateProceeding {
			step.NextState = SIPClientTransactionStateProceeding
			step.Action = SIPClientTransactionActionDeliverProvisional
			step.DeliverResponse = true
			return step
		}
	case step.Final:
		if step.State == SIPClientTransactionStateTrying || step.State == SIPClientTransactionStateProceeding {
			step.Action = SIPClientTransactionActionDeliverFinal
			step.DeliverResponse = true
			return completeSIPClientTransaction(step, reliable, policy.TimerK)
		}
	}
	step.Action = SIPClientTransactionActionWait
	return step
}

func advanceSIPClientTransactionRetransmitTimer(step SIPClientTransactionStep, reliable bool, last time.Duration, max, done int, policy SIPTransactionTimerPolicy) SIPClientTransactionStep {
	if reliable {
		step.Action = SIPClientTransactionActionWait
		return step
	}
	if step.Invite {
		if step.State != SIPClientTransactionStateCalling || !shouldSIPRetransmit(done, max) {
			step.Action = SIPClientTransactionActionWait
			return step
		}
		step.TimerName = "A"
	} else {
		if (step.State != SIPClientTransactionStateTrying && step.State != SIPClientTransactionStateProceeding) || !shouldSIPRetransmit(done, max) {
			step.Action = SIPClientTransactionActionWait
			return step
		}
		step.TimerName = "E"
	}
	interval := last
	if interval <= 0 {
		if step.Invite {
			interval = policy.TimerA
		} else {
			interval = policy.TimerE
		}
	}
	if !step.Invite && step.State == SIPClientTransactionStateProceeding && interval < policy.T2 {
		interval = policy.T2
	}
	step.Action = SIPClientTransactionActionRetransmitRequest
	step.RetransmitRequest = true
	step.NextRetransmitInterval = nextSIPRetransmitInterval(interval, policy.T2)
	return step
}

func advanceSIPClientTransactionTimeoutTimer(step SIPClientTransactionStep) SIPClientTransactionStep {
	if step.Invite {
		if step.State != SIPClientTransactionStateCalling {
			step.Action = SIPClientTransactionActionWait
			return step
		}
		step.TimerName = "B"
	} else {
		if step.State != SIPClientTransactionStateTrying && step.State != SIPClientTransactionStateProceeding {
			step.Action = SIPClientTransactionActionWait
			return step
		}
		step.TimerName = "F"
	}
	step.NextState = SIPClientTransactionStateTerminated
	step.Action = SIPClientTransactionActionTimeout
	step.TimedOut = true
	step.Terminated = true
	return step
}

func advanceSIPClientTransactionCleanupTimer(step SIPClientTransactionStep) SIPClientTransactionStep {
	if step.State != SIPClientTransactionStateCompleted {
		step.Action = SIPClientTransactionActionWait
		return step
	}
	if step.Invite {
		step.TimerName = "D"
	} else {
		step.TimerName = "K"
	}
	step.NextState = SIPClientTransactionStateTerminated
	step.Action = SIPClientTransactionActionTerminate
	step.Terminated = true
	return step
}

func completeSIPClientTransaction(step SIPClientTransactionStep, reliable bool, cleanupAfter time.Duration) SIPClientTransactionStep {
	if reliable || cleanupAfter <= 0 {
		step.NextState = SIPClientTransactionStateTerminated
		step.Terminated = true
		return step
	}
	step.NextState = SIPClientTransactionStateCompleted
	step.CleanupAfter = cleanupAfter
	return step
}

func normalizeSIPClientTransactionState(state SIPClientTransactionState, method string) SIPClientTransactionState {
	switch state {
	case SIPClientTransactionStateCalling:
		if sipTransactionKindForMethod(method) == sipTransactionInvite {
			return state
		}
	case SIPClientTransactionStateTrying:
		if sipTransactionKindForMethod(method) != sipTransactionInvite {
			return state
		}
	case SIPClientTransactionStateProceeding,
		SIPClientTransactionStateCompleted,
		SIPClientTransactionStateTerminated:
		return state
	}
	return InitialSIPClientTransactionState(method)
}
