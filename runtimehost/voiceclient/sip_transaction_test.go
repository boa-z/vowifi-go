package voiceclient

import (
	"testing"
	"time"
)

func TestAdvanceSIPClientTransactionInviteResponseFlow(t *testing.T) {
	cfg := SIPTransactionTimerConfig{
		T1: 100 * time.Millisecond,
		T2: 400 * time.Millisecond,
		T4: 900 * time.Millisecond,
	}
	provisional := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method: "invite",
		Event:  SIPClientTransactionEventResponse,
		Response: SIPResponse{
			StatusCode: 183,
			Reason:     "Session Progress",
		},
		TimerConfig: cfg,
	})
	if provisional.Method != "INVITE" ||
		!provisional.Invite ||
		provisional.State != SIPClientTransactionStateCalling ||
		provisional.NextState != SIPClientTransactionStateProceeding ||
		provisional.Action != SIPClientTransactionActionDeliverProvisional ||
		!provisional.DeliverResponse ||
		!provisional.Provisional ||
		provisional.Final ||
		provisional.RetransmitRequest {
		t.Fatalf("INVITE provisional step=%+v", provisional)
	}

	success := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:      "INVITE",
		State:       SIPClientTransactionStateProceeding,
		Event:       SIPClientTransactionEventResponse,
		Response:    SIPResponse{StatusCode: 200, Reason: "OK"},
		TimerConfig: cfg,
	})
	if success.NextState != SIPClientTransactionStateTerminated ||
		success.Action != SIPClientTransactionActionDeliverFinal ||
		!success.DeliverResponse ||
		!success.Success ||
		!success.Final ||
		!success.Terminated ||
		success.SendAck ||
		success.CleanupAfter != 0 {
		t.Fatalf("INVITE 2xx step=%+v", success)
	}

	failure := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:      "INVITE",
		State:       SIPClientTransactionStateProceeding,
		Event:       SIPClientTransactionEventResponse,
		Response:    SIPResponse{StatusCode: 486, Reason: "Busy Here"},
		TimerConfig: cfg,
	})
	if failure.NextState != SIPClientTransactionStateCompleted ||
		failure.Action != SIPClientTransactionActionDeliverFinal ||
		!failure.DeliverResponse ||
		!failure.Failure ||
		!failure.SendAck ||
		failure.CleanupAfter != 6400*time.Millisecond ||
		failure.Terminated {
		t.Fatalf("INVITE failure step=%+v", failure)
	}

	duplicateFailure := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:      "INVITE",
		State:       SIPClientTransactionStateCompleted,
		Event:       SIPClientTransactionEventResponse,
		Response:    SIPResponse{StatusCode: 486, Reason: "Busy Here"},
		TimerConfig: cfg,
	})
	if duplicateFailure.NextState != SIPClientTransactionStateCompleted ||
		duplicateFailure.Action != SIPClientTransactionActionDeliverFinal ||
		!duplicateFailure.SendAck ||
		duplicateFailure.DeliverResponse {
		t.Fatalf("duplicate INVITE failure step=%+v", duplicateFailure)
	}

	cleanup := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:      "INVITE",
		State:       SIPClientTransactionStateCompleted,
		Event:       SIPClientTransactionEventCleanupTimer,
		TimerConfig: cfg,
	})
	if cleanup.NextState != SIPClientTransactionStateTerminated ||
		cleanup.Action != SIPClientTransactionActionTerminate ||
		cleanup.TimerName != "D" ||
		!cleanup.Terminated {
		t.Fatalf("INVITE cleanup step=%+v", cleanup)
	}
}

func TestAdvanceSIPClientTransactionRetransmitAndTimeout(t *testing.T) {
	cfg := SIPTransactionTimerConfig{
		T1: 100 * time.Millisecond,
		T2: 400 * time.Millisecond,
	}
	inviteRetransmit := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:                   "INVITE",
		State:                    SIPClientTransactionStateCalling,
		Event:                    SIPClientTransactionEventRetransmitTimer,
		LastRetransmitInterval:   200 * time.Millisecond,
		MaxRetransmits:           3,
		CompletedRetransmissions: 1,
		TimerConfig:              cfg,
	})
	if inviteRetransmit.Action != SIPClientTransactionActionRetransmitRequest ||
		!inviteRetransmit.RetransmitRequest ||
		inviteRetransmit.NextRetransmitInterval != 400*time.Millisecond ||
		inviteRetransmit.TimerName != "A" {
		t.Fatalf("INVITE retransmit step=%+v", inviteRetransmit)
	}

	noRetransmitAfterProceeding := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:      "INVITE",
		State:       SIPClientTransactionStateProceeding,
		Event:       SIPClientTransactionEventRetransmitTimer,
		TimerConfig: cfg,
	})
	if noRetransmitAfterProceeding.Action != SIPClientTransactionActionWait ||
		noRetransmitAfterProceeding.RetransmitRequest {
		t.Fatalf("INVITE proceeding retransmit step=%+v", noRetransmitAfterProceeding)
	}

	reliableRetransmit := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:            "INVITE",
		Event:             SIPClientTransactionEventRetransmitTimer,
		ReliableTransport: true,
		TimerConfig:       cfg,
	})
	if reliableRetransmit.Action != SIPClientTransactionActionWait ||
		reliableRetransmit.RetransmitRequest {
		t.Fatalf("reliable INVITE retransmit step=%+v", reliableRetransmit)
	}

	timeout := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:      "INVITE",
		State:       SIPClientTransactionStateCalling,
		Event:       SIPClientTransactionEventTimeoutTimer,
		TimerConfig: cfg,
	})
	if timeout.NextState != SIPClientTransactionStateTerminated ||
		timeout.Action != SIPClientTransactionActionTimeout ||
		timeout.TimerName != "B" ||
		!timeout.TimedOut ||
		!timeout.Terminated {
		t.Fatalf("INVITE timeout step=%+v", timeout)
	}
}

func TestAdvanceSIPClientTransactionNormalizesInitialState(t *testing.T) {
	invite := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method: "INVITE",
		State:  SIPClientTransactionStateTrying,
		Event:  SIPClientTransactionEventResponse,
	})
	if invite.State != SIPClientTransactionStateCalling ||
		invite.NextState != SIPClientTransactionStateCalling ||
		invite.Action != SIPClientTransactionActionWait {
		t.Fatalf("normalized INVITE state step=%+v", invite)
	}

	message := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method: "MESSAGE",
		State:  SIPClientTransactionStateCalling,
		Event:  SIPClientTransactionEventResponse,
	})
	if message.State != SIPClientTransactionStateTrying ||
		message.NextState != SIPClientTransactionStateTrying ||
		message.Action != SIPClientTransactionActionWait {
		t.Fatalf("normalized MESSAGE state step=%+v", message)
	}
}

func TestAdvanceSIPClientTransactionNonInviteFlow(t *testing.T) {
	cfg := SIPTransactionTimerConfig{
		T1: 100 * time.Millisecond,
		T2: 400 * time.Millisecond,
		T4: 900 * time.Millisecond,
	}
	provisional := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:      "MESSAGE",
		Event:       SIPClientTransactionEventResponse,
		Response:    SIPResponse{StatusCode: 100, Reason: "Trying"},
		TimerConfig: cfg,
	})
	if provisional.Invite ||
		provisional.State != SIPClientTransactionStateTrying ||
		provisional.NextState != SIPClientTransactionStateProceeding ||
		provisional.Action != SIPClientTransactionActionDeliverProvisional ||
		!provisional.DeliverResponse {
		t.Fatalf("non-INVITE provisional step=%+v", provisional)
	}

	retransmitProceeding := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:                   "MESSAGE",
		State:                    SIPClientTransactionStateProceeding,
		Event:                    SIPClientTransactionEventRetransmitTimer,
		LastRetransmitInterval:   100 * time.Millisecond,
		TimerConfig:              cfg,
		CompletedRetransmissions: 1,
	})
	if retransmitProceeding.Action != SIPClientTransactionActionRetransmitRequest ||
		!retransmitProceeding.RetransmitRequest ||
		retransmitProceeding.TimerName != "E" ||
		retransmitProceeding.NextRetransmitInterval != 400*time.Millisecond {
		t.Fatalf("non-INVITE proceeding retransmit step=%+v", retransmitProceeding)
	}

	final := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:      "MESSAGE",
		State:       SIPClientTransactionStateProceeding,
		Event:       SIPClientTransactionEventResponse,
		Response:    SIPResponse{StatusCode: 202, Reason: "Accepted"},
		TimerConfig: cfg,
	})
	if final.NextState != SIPClientTransactionStateCompleted ||
		final.Action != SIPClientTransactionActionDeliverFinal ||
		!final.DeliverResponse ||
		!final.Success ||
		final.SendAck ||
		final.CleanupAfter != 900*time.Millisecond {
		t.Fatalf("non-INVITE final step=%+v", final)
	}

	reliableFinal := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:            "MESSAGE",
		State:             SIPClientTransactionStateProceeding,
		Event:             SIPClientTransactionEventResponse,
		Response:          SIPResponse{StatusCode: 503, Reason: "Service Unavailable"},
		ReliableTransport: true,
		TimerConfig:       cfg,
	})
	if reliableFinal.NextState != SIPClientTransactionStateTerminated ||
		!reliableFinal.Terminated ||
		reliableFinal.CleanupAfter != 0 {
		t.Fatalf("reliable non-INVITE final step=%+v", reliableFinal)
	}

	cleanup := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:      "MESSAGE",
		State:       SIPClientTransactionStateCompleted,
		Event:       SIPClientTransactionEventCleanupTimer,
		TimerConfig: cfg,
	})
	if cleanup.NextState != SIPClientTransactionStateTerminated ||
		cleanup.Action != SIPClientTransactionActionTerminate ||
		cleanup.TimerName != "K" ||
		!cleanup.Terminated {
		t.Fatalf("non-INVITE cleanup step=%+v", cleanup)
	}
}

func TestAdvanceSIPClientTransactionNonInviteTimeoutAndRetransmitLimit(t *testing.T) {
	cfg := SIPTransactionTimerConfig{T1: 100 * time.Millisecond, T2: 400 * time.Millisecond}
	noRetransmit := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:                   "REGISTER",
		State:                    SIPClientTransactionStateTrying,
		Event:                    SIPClientTransactionEventRetransmitTimer,
		MaxRetransmits:           2,
		CompletedRetransmissions: 2,
		TimerConfig:              cfg,
	})
	if noRetransmit.Action != SIPClientTransactionActionWait ||
		noRetransmit.RetransmitRequest {
		t.Fatalf("non-INVITE retransmit limit step=%+v", noRetransmit)
	}

	timeout := AdvanceSIPClientTransaction(SIPClientTransactionInput{
		Method:      "REGISTER",
		State:       SIPClientTransactionStateProceeding,
		Event:       SIPClientTransactionEventTimeoutTimer,
		TimerConfig: cfg,
	})
	if timeout.NextState != SIPClientTransactionStateTerminated ||
		timeout.Action != SIPClientTransactionActionTimeout ||
		timeout.TimerName != "F" ||
		!timeout.TimedOut ||
		!timeout.Terminated {
		t.Fatalf("non-INVITE timeout step=%+v", timeout)
	}
}
