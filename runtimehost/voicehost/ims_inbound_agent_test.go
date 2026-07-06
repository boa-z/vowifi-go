package voicehost

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

func TestIMSInboundAgentInviteAckAndBye(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":           {"<sip:user@ims.example>;tag=client-tag"},
				"Contact":      {"<sip:client@192.0.2.50:5060>"},
				"Record-Route": {"<sip:client-proxy1.example;lr>, <sip:client-proxy2.example;lr>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport: transport,
		Profile: voiceclient.IMSProfile{
			IMPU:      "sip:user@ims.example",
			Domain:    "ims.example",
			UserAgent: "VoHive",
		},
		Registration: voiceclient.RegistrationBinding{
			PublicIdentity: "sip:user@ims.example",
			ContactURI:     "sip:user@192.0.2.10:5060",
		},
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		DeviceID:  "dev-1",
		CallID:    "in-call-1",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RemoteTag: "ims-tag",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	})
	if err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	if !result.Accepted || result.StatusCode != 200 || result.LocalSDP.ConnectionIP != "192.0.2.50" || result.LocalSDP.MediaPort != 4002 {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 1 || transport.requests[0].Method != "INVITE" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	invite := transport.requests[0]
	if invite.URI != "sip:client@127.0.0.1:5070" || !strings.Contains(invite.Headers["From"], "ims-tag") || invite.Headers["Contact"] != "<sip:vowifi@127.0.0.1:5060>" {
		t.Fatalf("INVITE=%+v", invite)
	}
	if !strings.Contains(string(invite.Body), "m=audio 49170 RTP/AVP") {
		t.Fatalf("INVITE body=%q", invite.Body)
	}

	if err := agent.AckInboundCall(context.Background(), DialogInfo{CallID: "in-call-1"}); err != nil {
		t.Fatalf("AckInboundCall() error = %v", err)
	}
	if len(transport.writes) != 1 || transport.writes[0].Method != "ACK" {
		t.Fatalf("writes=%+v", transport.writes)
	}
	if transport.writes[0].URI != "sip:client@192.0.2.50:5060" || !strings.Contains(transport.writes[0].Headers["To"], "client-tag") {
		t.Fatalf("ACK=%+v", transport.writes[0])
	}
	if transport.writes[0].Headers["Route"] != "<sip:client-proxy2.example;lr>, <sip:client-proxy1.example;lr>" {
		t.Fatalf("ACK Route=%q", transport.writes[0].Headers["Route"])
	}

	if err := agent.EndInboundCall(context.Background(), DialogInfo{
		CallID:      "in-call-1",
		CSeq:        9,
		ContentType: "message/sipfrag",
		Body:        []byte("SIP/2.0 200 OK\r\n"),
		Headers:     map[string]string{"Reason": "SIP;cause=200;text=\"completed\"", "X-IMS": "bye"},
	}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
	if len(transport.requests) != 2 || transport.requests[1].Method != "BYE" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	bye := transport.requests[1]
	if bye.URI != "sip:client@192.0.2.50:5060" || bye.Headers["CSeq"] != "9 BYE" ||
		bye.Headers["Content-Type"] != "message/sipfrag" ||
		bye.Headers["Reason"] != "SIP;cause=200;text=\"completed\"" ||
		bye.Headers["X-IMS"] != "bye" ||
		string(bye.Body) != "SIP/2.0 200 OK\r\n" {
		t.Fatalf("BYE=%+v", bye)
	}
	if bye.Headers["Route"] != "<sip:client-proxy2.example;lr>, <sip:client-proxy1.example;lr>" {
		t.Fatalf("BYE Route=%q", bye.Headers["Route"])
	}
}

func TestIMSInboundAgentRejectedInvite(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{{
		StatusCode: 486,
		Reason:     "Busy Here",
		Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=busy-tag"}},
	}}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-2",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	})
	if err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	if result.Accepted || result.StatusCode != 486 || result.Reason != "Busy Here" {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 1 || transport.requests[0].Method != "INVITE" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	if len(transport.writes) != 1 || transport.writes[0].Method != "ACK" {
		t.Fatalf("ACK writes=%+v", transport.writes)
	}
	ack := transport.writes[0]
	if ack.Headers["CSeq"] != "1 ACK" || !strings.Contains(ack.Headers["To"], "busy-tag") {
		t.Fatalf("ACK=%+v", ack)
	}
	if ack.Headers["Via"] == "" || ack.Headers["Via"] != transport.requests[0].Headers["Via"] {
		t.Fatalf("ACK Via=%q INVITE Via=%q", ack.Headers["Via"], transport.requests[0].Headers["Via"])
	}
	if err := agent.AckInboundCall(context.Background(), DialogInfo{CallID: "in-call-2"}); err != nil {
		t.Fatalf("AckInboundCall(rejected) error = %v", err)
	}
	if len(transport.writes) != 1 {
		t.Fatalf("writes=%+v, want only rejected INVITE ACK", transport.writes)
	}
}

func TestIMSInboundAgentFollowsClientInviteRedirectContact(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 302,
			Reason:     "Moved Temporarily",
			Headers: map[string][]string{
				"To":      {"<sip:user@ims.example>;tag=redirect-tag"},
				"Contact": {"<sip:client2@127.0.0.1:5080>"},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:user@ims.example>;tag=client-tag"},
				"Contact": {"<sip:client2@192.0.2.60:5060>"},
			},
			Body: []byte(sampleSDP("192.0.2.60", 4004)),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-redirect",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		CSeq:      1,
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	})
	if err != nil || !result.Accepted || result.LocalSDP.ConnectionIP != "192.0.2.60" {
		t.Fatalf("HandleInboundInvite() result=%+v err=%v", result, err)
	}
	if len(transport.requests) != 2 || transport.requests[0].Method != "INVITE" || transport.requests[1].Method != "INVITE" {
		t.Fatalf("client INVITEs=%+v", transport.requests)
	}
	firstInvite := transport.requests[0]
	redirectInvite := transport.requests[1]
	if firstInvite.URI != "sip:client@127.0.0.1:5070" || firstInvite.Headers["CSeq"] != "1 INVITE" {
		t.Fatalf("first INVITE=%+v", firstInvite)
	}
	if redirectInvite.URI != "sip:client2@127.0.0.1:5080" ||
		redirectInvite.Headers["CSeq"] != "2 INVITE" ||
		strings.Contains(redirectInvite.Headers["To"], "redirect-tag") {
		t.Fatalf("redirect INVITE=%+v", redirectInvite)
	}
	if len(transport.writes) != 1 || transport.writes[0].Method != "ACK" {
		t.Fatalf("redirect ACK writes=%+v", transport.writes)
	}
	redirectAck := transport.writes[0]
	if redirectAck.Headers["CSeq"] != "1 ACK" ||
		!strings.Contains(redirectAck.Headers["To"], "redirect-tag") ||
		redirectAck.Headers["Via"] != firstInvite.Headers["Via"] {
		t.Fatalf("redirect ACK=%+v first INVITE Via=%q", redirectAck, firstInvite.Headers["Via"])
	}

	if err := agent.AckInboundCall(context.Background(), DialogInfo{CallID: "in-call-redirect"}); err != nil {
		t.Fatalf("AckInboundCall() error = %v", err)
	}
	if len(transport.writes) != 2 || transport.writes[1].URI != "sip:client2@192.0.2.60:5060" ||
		transport.writes[1].Headers["CSeq"] != "2 ACK" ||
		!strings.Contains(transport.writes[1].Headers["To"], "client-tag") {
		t.Fatalf("accepted ACKs=%+v", transport.writes)
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-redirect"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
	if len(transport.requests) != 3 || transport.requests[2].Method != "BYE" ||
		transport.requests[2].URI != "sip:client2@192.0.2.60:5060" ||
		transport.requests[2].Headers["CSeq"] != "3 BYE" {
		t.Fatalf("BYE after redirect=%+v", transport.requests)
	}
}

func TestIMSInboundAgentCancelEarlyInviteTerminatesRequest(t *testing.T) {
	transport := newCancelAwareInboundTransport()
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	type inviteResult struct {
		result InboundCallResult
		err    error
	}
	resultCh := make(chan inviteResult, 1)
	go func() {
		result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
			CallID:    "in-call-cancel",
			CallerURI: "sip:+18005551212@ims.example",
			CalleeURI: "sip:user@ims.example",
			CSeq:      1,
			RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
		})
		resultCh <- inviteResult{result: result, err: err}
	}()

	invite := transport.readInvite(t)
	if invite.Method != "INVITE" || invite.Headers["Via"] == "" {
		t.Fatalf("client INVITE=%+v", invite)
	}
	cancelCh := make(chan error, 1)
	go func() {
		cancelCh <- agent.CancelInboundCall(context.Background(), DialogInfo{
			CallID:      "in-call-cancel",
			ContentType: "message/sipfrag",
			Body:        []byte("SIP/2.0 487 Request Terminated\r\n"),
			Headers: map[string]string{
				"Reason": "SIP;cause=487;text=\"IMS canceled\"",
				"X-IMS":  "cancel",
				"Via":    "SIP/2.0/UDP 198.51.100.20:5060;branch=z9hG4bK-bad",
			},
		})
	}()
	cancel := transport.readCancel(t)
	if cancel.Method != "CANCEL" || cancel.Headers["CSeq"] != "1 CANCEL" || cancel.Headers["Via"] != invite.Headers["Via"] {
		t.Fatalf("client CANCEL=%+v INVITE Via=%q", cancel, invite.Headers["Via"])
	}
	if cancel.Headers["Reason"] != "SIP;cause=487;text=\"IMS canceled\"" ||
		cancel.Headers["X-IMS"] != "cancel" ||
		cancel.Headers["Content-Type"] != "message/sipfrag" ||
		string(cancel.Body) != "SIP/2.0 487 Request Terminated\r\n" {
		t.Fatalf("client CANCEL payload=%+v body=%q", cancel, cancel.Body)
	}
	transport.respondCancel(voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"})
	select {
	case err := <-cancelCh:
		if err != nil {
			t.Fatalf("CancelInboundCall() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CancelInboundCall() did not return")
	}

	transport.respondInvite(voiceclient.SIPResponse{
		StatusCode: 487,
		Reason:     "Request Terminated",
		Headers: map[string][]string{
			"To": {"<sip:user@ims.example>;tag=canceled"},
		},
	})
	select {
	case got := <-resultCh:
		if got.err != nil || got.result.Accepted || got.result.StatusCode != 487 || got.result.Reason != "Request Terminated" {
			t.Fatalf("HandleInboundInvite() result=%+v err=%v", got.result, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("HandleInboundInvite() did not return")
	}
	ack := transport.readWrite(t)
	if ack.Method != "ACK" || ack.Headers["CSeq"] != "1 ACK" || ack.Headers["Via"] != invite.Headers["Via"] ||
		!strings.Contains(ack.Headers["To"], "canceled") {
		t.Fatalf("client ACK=%+v", ack)
	}
}

func TestIMSInboundAgentCancelEstablishedDialogNoops(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:user@ims.example>;tag=client-tag"},
				"Contact": {"<sip:client@192.0.2.50:5060>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-cancel-established",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	})
	if err != nil || !result.Accepted {
		t.Fatalf("HandleInboundInvite() result=%+v err=%v", result, err)
	}
	if err := agent.CancelInboundCall(context.Background(), DialogInfo{CallID: "in-call-cancel-established"}); err != nil {
		t.Fatalf("CancelInboundCall(established) error = %v", err)
	}
	if len(transport.requests) != 1 {
		t.Fatalf("requests=%+v, want no established-dialog CANCEL", transport.requests)
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-cancel-established"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
}

func TestIMSInboundAgentCancelInboundCallWithResultReturnsClientResponse(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 481,
			Reason:     "Call/Transaction Does Not Exist",
			Headers: map[string][]string{
				"Content-Type": {"message/sipfrag"},
				"X-Client":     {"cancel-miss"},
			},
			Body: []byte("SIP/2.0 481 Call/Transaction Does Not Exist\r\n"),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{ClientTransport: transport}
	inviteVia := "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-inbound-invite;rport"
	agent.storeInboundDialog("in-call-cancel-result", imsInboundDialogState{
		early: true,
		invite: voiceclient.SIPRequestMessage{
			Headers: map[string]string{"Via": inviteVia},
		},
		clientCfg: voiceclient.DialogRequestConfig{
			Profile:         voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example"},
			LocalURI:        "sip:+18005551212@ims.example",
			RemoteURI:       "sip:user@ims.example",
			RemoteTargetURI: "sip:client@127.0.0.1:5070",
			CallID:          "in-call-cancel-result",
			LocalTag:        "ims-tag",
			CSeq:            1,
		},
	})

	result, err := agent.CancelInboundCallWithResult(context.Background(), DialogInfo{CallID: "in-call-cancel-result"})
	if err == nil || !strings.Contains(err.Error(), "client CANCEL rejected") {
		t.Fatalf("CancelInboundCallWithResult() err=%v, want client CANCEL rejection", err)
	}
	if result.Accepted || result.StatusCode != 481 || result.Reason != "Call/Transaction Does Not Exist" ||
		result.ContentType != "message/sipfrag" ||
		string(result.Body) != "SIP/2.0 481 Call/Transaction Does Not Exist\r\n" ||
		result.Headers["X-Client"] != "cancel-miss" {
		t.Fatalf("result=%+v body=%q", result, result.Body)
	}
	if len(transport.requests) != 1 || transport.requests[0].Method != "CANCEL" || transport.requests[0].Headers["Via"] != inviteVia {
		t.Fatalf("CANCEL requests=%+v", transport.requests)
	}
	state, ok := agent.inboundDialog("in-call-cancel-result")
	if !ok || state.canceled {
		t.Fatalf("dialog state after rejected CANCEL=%+v ok=%v", state, ok)
	}
	if err := agent.CancelInboundCall(context.Background(), DialogInfo{CallID: "in-call-cancel-result"}); err != nil {
		t.Fatalf("CancelInboundCall() retry error = %v", err)
	}
	state, ok = agent.inboundDialog("in-call-cancel-result")
	if !ok || !state.canceled {
		t.Fatalf("dialog state after accepted CANCEL=%+v ok=%v", state, ok)
	}
}

func TestIMSInboundAgentForwardsProvisionalInviteResponses(t *testing.T) {
	transport := &fakeIMSVoiceTransport{
		provisionals: []voiceclient.SIPResponse{
			{
				StatusCode: 183,
				Reason:     "Session Progress",
				Headers: map[string][]string{
					"Require": {"100rel"},
					"RSeq":    {"42"},
					"Contact": {"<sip:client@192.0.2.50:5060>"},
				},
				Body: []byte(sampleSDP("192.0.2.50", 4002)),
			},
		},
		responses: []voiceclient.SIPResponse{
			{
				StatusCode: 200,
				Reason:     "OK",
				Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=client-tag"}},
				Body:       []byte(sampleSDP("192.0.2.50", 4004)),
			},
		},
	}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	var provisionals []InboundCallResult
	result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-provisional",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
		onProvisional: func(result InboundCallResult) error {
			provisionals = append(provisionals, result)
			return nil
		},
	})
	if err != nil || !result.Accepted {
		t.Fatalf("HandleInboundInvite() result=%+v err=%v", result, err)
	}
	if len(provisionals) != 1 || provisionals[0].StatusCode != 183 ||
		provisionals[0].Headers["Require"] != "100rel" ||
		provisionals[0].Headers["RSeq"] != "42" ||
		provisionals[0].LocalSDP.MediaPort != 4002 ||
		!strings.Contains(string(provisionals[0].RawSDP), "m=audio 4002 RTP/AVP") {
		t.Fatalf("provisionals=%+v", provisionals)
	}
}

func TestIMSInboundAgentUsesReliableProvisionalSDPWhenFinalHasNoBody(t *testing.T) {
	transport := &fakeIMSVoiceTransport{
		provisionals: []voiceclient.SIPResponse{
			{
				StatusCode: 183,
				Reason:     "Session Progress",
				Headers: map[string][]string{
					"To":      {"<sip:user@ims.example>;tag=early-tag"},
					"Require": {"100rel"},
					"RSeq":    {"9"},
				},
				Body: []byte(sampleSDP("192.0.2.90", 4090)),
			},
		},
		responses: []voiceclient.SIPResponse{
			{
				StatusCode: 200,
				Reason:     "OK",
				Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=client-tag"}},
			},
		},
	}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-provisional-answer",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	})
	if err != nil || !result.Accepted {
		t.Fatalf("HandleInboundInvite() result=%+v err=%v", result, err)
	}
	if !result.sdpFromProvisional || result.LocalSDP.ConnectionIP != "192.0.2.90" || result.LocalSDP.MediaPort != 4090 {
		t.Fatalf("result=%+v", result)
	}
	if !strings.Contains(string(result.RawSDP), "m=audio 4090 RTP/AVP") {
		t.Fatalf("RawSDP=%q", result.RawSDP)
	}
}

func TestIMSInboundAgentUsesProvisionalDialogStateForPrack(t *testing.T) {
	transport := newReliableProvisionalInboundTransport([]voiceclient.SIPResponse{
		{
			StatusCode: 183,
			Reason:     "Session Progress",
			Headers: map[string][]string{
				"To":           {"<sip:user@ims.example>;tag=early-tag"},
				"Contact":      {"<sip:client@192.0.2.70:5060>"},
				"Record-Route": {"<sip:client-proxy1.example;lr>, <sip:client-proxy2.example;lr>"},
				"Require":      {"100rel"},
				"RSeq":         {"42"},
			},
			Body: []byte(sampleSDP("192.0.2.70", 4002)),
		},
	})
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	type inviteResult struct {
		result InboundCallResult
		err    error
	}
	resultCh := make(chan inviteResult, 1)
	go func() {
		result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
			CallID:    "in-call-provisional-prack",
			CallerURI: "sip:+18005551212@ims.example",
			CalleeURI: "sip:user@ims.example",
			CSeq:      1,
			RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
			onProvisional: func(result InboundCallResult) error {
				return nil
			},
		})
		resultCh <- inviteResult{result: result, err: err}
	}()
	if req := transport.readInvite(t); req.Method != "INVITE" {
		t.Fatalf("client INVITE=%+v", req)
	}
	transport.waitProvisionals(t)

	prackCh := make(chan struct {
		result InboundCallResult
		err    error
	}, 1)
	go func() {
		result, err := agent.HandleInboundPrack(context.Background(), InboundDialogRequest{
			CallID: "in-call-provisional-prack",
			CSeq:   2,
			RAck:   "42 1 INVITE",
		})
		prackCh <- struct {
			result InboundCallResult
			err    error
		}{result: result, err: err}
	}()
	prack := transport.readRequest(t)
	if prack.Method != "PRACK" || prack.URI != "sip:client@192.0.2.70:5060" ||
		prack.Headers["RAck"] != "42 1 INVITE" ||
		!strings.Contains(prack.Headers["To"], "early-tag") {
		t.Fatalf("PRACK=%+v", prack)
	}
	if prack.Headers["Route"] != "<sip:client-proxy2.example;lr>, <sip:client-proxy1.example;lr>" {
		t.Fatalf("PRACK Route=%q", prack.Headers["Route"])
	}
	transport.respondRequest(voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"})
	select {
	case got := <-prackCh:
		if got.err != nil || !got.result.Accepted || got.result.StatusCode != 200 {
			t.Fatalf("HandleInboundPrack() result=%+v err=%v", got.result, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("HandleInboundPrack() did not return")
	}

	transport.respondInvite(voiceclient.SIPResponse{
		StatusCode: 200,
		Reason:     "OK",
		Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=final-tag"}},
		Body:       []byte(sampleSDP("192.0.2.70", 4004)),
	})
	select {
	case got := <-resultCh:
		if got.err != nil || !got.result.Accepted {
			t.Fatalf("HandleInboundInvite() result=%+v err=%v", got.result, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("HandleInboundInvite() did not return")
	}
}

func TestIMSInboundAgentHandlesPrackAndUpdate(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":           {"<sip:user@ims.example>;tag=client-tag"},
				"Contact":      {"<sip:client@192.0.2.50:5060>"},
				"Record-Route": {"<sip:client-proxy1.example;lr>, <sip:client-proxy2.example;lr>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{StatusCode: 200, Reason: "OK"},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers:    map[string][]string{"Contact": {"<sip:client@192.0.2.60:5060>"}},
			Body:       []byte(sampleSDP("192.0.2.60", 5000)),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	if _, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-update",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	}); err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	if result, err := agent.HandleInboundPrack(context.Background(), InboundDialogRequest{
		CallID: "in-call-update",
		CSeq:   2,
		RAck:   "1 1 INVITE",
	}); err != nil || !result.Accepted {
		t.Fatalf("HandleInboundPrack() result=%+v err=%v", result, err)
	}
	if len(transport.requests) != 2 || transport.requests[1].Method != "PRACK" || transport.requests[1].Headers["RAck"] != "1 1 INVITE" {
		t.Fatalf("PRACK requests=%+v", transport.requests)
	}
	if transport.requests[1].Headers["Route"] != "<sip:client-proxy2.example;lr>, <sip:client-proxy1.example;lr>" {
		t.Fatalf("PRACK Route=%q", transport.requests[1].Headers["Route"])
	}
	if err := agent.AckInboundCall(context.Background(), DialogInfo{CallID: "in-call-update"}); err != nil {
		t.Fatalf("AckInboundCall() error = %v", err)
	}
	if len(transport.writes) != 1 || transport.writes[0].Method != "ACK" || transport.writes[0].Headers["CSeq"] != "1 ACK" {
		t.Fatalf("ACK writes=%+v", transport.writes)
	}
	result, err := agent.HandleInboundUpdate(context.Background(), InboundDialogRequest{
		CallID: "in-call-update",
		CSeq:   3,
		RawSDP: []byte(sampleSDP("203.0.113.11", 49172)),
	})
	if err != nil {
		t.Fatalf("HandleInboundUpdate() error = %v", err)
	}
	if !result.Accepted || result.LocalSDP.ConnectionIP != "192.0.2.60" || result.LocalSDP.MediaPort != 5000 {
		t.Fatalf("UPDATE result=%+v", result)
	}
	if len(transport.requests) != 3 || transport.requests[2].Method != "UPDATE" || !strings.Contains(string(transport.requests[2].Body), "m=audio 49172 RTP/AVP") {
		t.Fatalf("UPDATE requests=%+v", transport.requests)
	}
	if transport.requests[2].Headers["Route"] != "<sip:client-proxy2.example;lr>, <sip:client-proxy1.example;lr>" {
		t.Fatalf("UPDATE Route=%q", transport.requests[2].Headers["Route"])
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-update"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
	if len(transport.requests) != 4 || transport.requests[3].Method != "BYE" || transport.requests[3].Headers["CSeq"] != "4 BYE" {
		t.Fatalf("BYE after UPDATE=%+v", transport.requests)
	}
}

func TestIMSInboundAgentHandlesRefer(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":           {"<sip:user@ims.example>;tag=client-tag"},
				"Contact":      {"<sip:client@192.0.2.50:5060>"},
				"Record-Route": {"<sip:client-proxy1.example;lr>, <sip:client-proxy2.example;lr>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{StatusCode: 202, Reason: "Accepted", Headers: map[string][]string{"Contact": {"<sip:client@192.0.2.60:5060>"}, "X-Client": {"refer-ok"}}},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	if _, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-refer",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	}); err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	result, err := agent.HandleInboundRefer(context.Background(), InboundDialogRequest{
		CallID:     "in-call-refer",
		CSeq:       2,
		ReferTo:    "<sip:+18005551313@ims.example>",
		ReferredBy: "<sip:+18005551212@ims.example>",
		Headers: map[string][]string{
			"Refer-To":    {"<sip:wrong@ims.example>"},
			"Referred-By": {"<sip:wrong-referrer@ims.example>"},
			"Refer-Sub":   {"true"},
			"X-IMS":       {"refer"},
		},
	})
	if err != nil || !result.Accepted || result.StatusCode != 202 || result.Headers["X-Client"] != "refer-ok" {
		t.Fatalf("HandleInboundRefer() result=%+v err=%v", result, err)
	}
	if len(transport.requests) != 2 || transport.requests[1].Method != "REFER" {
		t.Fatalf("REFER requests=%+v", transport.requests)
	}
	refer := transport.requests[1]
	if refer.URI != "sip:client@192.0.2.50:5060" || refer.Headers["CSeq"] != "2 REFER" ||
		refer.Headers["Refer-To"] != "<sip:+18005551313@ims.example>" ||
		refer.Headers["Referred-By"] != "<sip:+18005551212@ims.example>" ||
		refer.Headers["Refer-Sub"] != "true" || refer.Headers["X-IMS"] != "refer" ||
		refer.Headers["Route"] != "<sip:client-proxy2.example;lr>, <sip:client-proxy1.example;lr>" {
		t.Fatalf("REFER=%+v", refer)
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-refer"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
	if len(transport.requests) != 3 || transport.requests[2].Method != "BYE" ||
		transport.requests[2].URI != "sip:client@192.0.2.60:5060" ||
		transport.requests[2].Headers["CSeq"] != "3 BYE" {
		t.Fatalf("BYE after REFER=%+v", transport.requests)
	}
}

func TestIMSInboundAgentHandlesNotify(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":           {"<sip:user@ims.example>;tag=client-tag"},
				"Contact":      {"<sip:client@192.0.2.50:5060>"},
				"Record-Route": {"<sip:client-proxy1.example;lr>, <sip:client-proxy2.example;lr>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{StatusCode: 200, Reason: "OK", Headers: map[string][]string{"Contact": {"<sip:client@192.0.2.60:5060>"}, "X-Client": {"notify-ok"}}},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	if _, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-notify",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	}); err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	result, err := agent.HandleInboundNotify(context.Background(), InboundDialogRequest{
		CallID:            "in-call-notify",
		CSeq:              2,
		Event:             "refer",
		SubscriptionState: "terminated;reason=noresource",
		ContentType:       "message/sipfrag",
		Body:              []byte("SIP/2.0 200 OK\r\n"),
		Headers: map[string][]string{
			"Event":              {"presence"},
			"Subscription-State": {"active"},
			"Allow-Events":       {"refer"},
			"X-IMS":              {"notify"},
		},
	})
	if err != nil || result.StatusCode != 200 || result.Headers["X-Client"] != "notify-ok" {
		t.Fatalf("HandleInboundNotify() result=%+v err=%v", result, err)
	}
	if len(transport.requests) != 2 || transport.requests[1].Method != "NOTIFY" {
		t.Fatalf("NOTIFY requests=%+v", transport.requests)
	}
	notify := transport.requests[1]
	if notify.URI != "sip:client@192.0.2.50:5060" || notify.Headers["CSeq"] != "2 NOTIFY" ||
		notify.Headers["Event"] != "refer" ||
		notify.Headers["Subscription-State"] != "terminated;reason=noresource" ||
		notify.Headers["Allow-Events"] != "refer" ||
		notify.Headers["Content-Type"] != "message/sipfrag" ||
		notify.Headers["X-IMS"] != "notify" ||
		notify.Headers["Route"] != "<sip:client-proxy2.example;lr>, <sip:client-proxy1.example;lr>" ||
		string(notify.Body) != "SIP/2.0 200 OK\r\n" {
		t.Fatalf("NOTIFY=%+v body=%q", notify, notify.Body)
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-notify"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
	if len(transport.requests) != 3 || transport.requests[2].Method != "BYE" ||
		transport.requests[2].URI != "sip:client@192.0.2.60:5060" ||
		transport.requests[2].Headers["CSeq"] != "3 BYE" {
		t.Fatalf("BYE after NOTIFY=%+v", transport.requests)
	}
}

func TestIMSInboundAgentHandlesSubscribe(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":           {"<sip:user@ims.example>;tag=client-tag"},
				"Contact":      {"<sip:client@192.0.2.50:5060>"},
				"Record-Route": {"<sip:client-proxy1.example;lr>, <sip:client-proxy2.example;lr>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{StatusCode: 202, Reason: "Accepted", Headers: map[string][]string{"Contact": {"<sip:client@192.0.2.70:5060>"}, "Expires": {"300"}, "X-Client": {"subscribe-ok"}}},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	if _, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-subscribe",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	}); err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	result, err := agent.HandleInboundSubscribe(context.Background(), InboundDialogRequest{
		CallID:      "in-call-subscribe",
		CSeq:        2,
		Event:       "refer",
		Expires:     "300",
		ContentType: "application/resource-lists+xml",
		Body:        []byte("<resource-lists/>"),
		Headers: map[string][]string{
			"Event":        {"presence"},
			"Expires":      {"0"},
			"Allow-Events": {"refer"},
			"X-IMS":        {"subscribe"},
		},
	})
	if err != nil || result.StatusCode != 202 || result.Headers["X-Client"] != "subscribe-ok" || result.Headers["Expires"] != "300" {
		t.Fatalf("HandleInboundSubscribe() result=%+v err=%v", result, err)
	}
	if len(transport.requests) != 2 || transport.requests[1].Method != "SUBSCRIBE" {
		t.Fatalf("SUBSCRIBE requests=%+v", transport.requests)
	}
	subscribe := transport.requests[1]
	if subscribe.URI != "sip:client@192.0.2.50:5060" || subscribe.Headers["CSeq"] != "2 SUBSCRIBE" ||
		subscribe.Headers["Event"] != "refer" ||
		subscribe.Headers["Expires"] != "300" ||
		subscribe.Headers["Accept"] != "message/sipfrag" ||
		subscribe.Headers["Allow-Events"] != "refer" ||
		subscribe.Headers["Content-Type"] != "application/resource-lists+xml" ||
		subscribe.Headers["X-IMS"] != "subscribe" ||
		subscribe.Headers["Route"] != "<sip:client-proxy2.example;lr>, <sip:client-proxy1.example;lr>" ||
		string(subscribe.Body) != "<resource-lists/>" {
		t.Fatalf("SUBSCRIBE=%+v body=%q", subscribe, subscribe.Body)
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-subscribe"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
	if len(transport.requests) != 3 || transport.requests[2].Method != "BYE" ||
		transport.requests[2].URI != "sip:client@192.0.2.70:5060" ||
		transport.requests[2].Headers["CSeq"] != "3 BYE" {
		t.Fatalf("BYE after SUBSCRIBE=%+v", transport.requests)
	}
}

func TestIMSInboundAgentHandlesMessage(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":           {"<sip:user@ims.example>;tag=client-tag"},
				"Contact":      {"<sip:client@192.0.2.50:5060>"},
				"Record-Route": {"<sip:client-proxy1.example;lr>, <sip:client-proxy2.example;lr>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Contact":      {"<sip:client@192.0.2.90:5060>"},
				"Content-Type": {"text/plain"},
				"X-Client":     {"message-ok"},
			},
			Body: []byte("delivered"),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	if _, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-message",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	}); err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	result, err := agent.HandleInboundMessage(context.Background(), IMSMessageRequest{
		CallID:      "in-call-message",
		CSeq:        2,
		ContentType: "text/plain",
		Body:        []byte("hello"),
		Headers: map[string][]string{
			"Content-Type": {"application/ignored"},
			"Accept":       {"message/cpim"},
			"X-IMS":        {"message"},
		},
	})
	if err != nil || result.StatusCode != 200 || result.ContentType != "text/plain" ||
		result.Headers["X-Client"] != "message-ok" || string(result.Body) != "delivered" {
		t.Fatalf("HandleInboundMessage() result=%+v err=%v", result, err)
	}
	if len(transport.requests) != 2 || transport.requests[1].Method != "MESSAGE" {
		t.Fatalf("MESSAGE requests=%+v", transport.requests)
	}
	message := transport.requests[1]
	if message.URI != "sip:client@192.0.2.50:5060" || message.Headers["CSeq"] != "2 MESSAGE" ||
		message.Headers["Content-Type"] != "text/plain" ||
		message.Headers["Accept"] != "message/cpim" ||
		message.Headers["P-Preferred-Service"] != "urn:urn-7:3gpp-service.ims.icsi.sms" ||
		message.Headers["Accept-Contact"] != "*;+g.3gpp.smsip" ||
		message.Headers["X-IMS"] != "message" ||
		message.Headers["Route"] != "<sip:client-proxy2.example;lr>, <sip:client-proxy1.example;lr>" ||
		string(message.Body) != "hello" {
		t.Fatalf("MESSAGE=%+v body=%q", message, message.Body)
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-message"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
	if len(transport.requests) != 3 || transport.requests[2].Method != "BYE" ||
		transport.requests[2].URI != "sip:client@192.0.2.90:5060" ||
		transport.requests[2].Headers["CSeq"] != "3 BYE" {
		t.Fatalf("BYE after MESSAGE=%+v", transport.requests)
	}
}

func TestIMSInboundAgentPropagatesSessionTimerHeaders(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":              {"<sip:user@ims.example>;tag=client-tag"},
				"Contact":         {"<sip:client@192.0.2.50:5060>"},
				"Session-Expires": {"1200;refresher=uac"},
				"Min-SE":          {"90"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Session-Expires": {"600;refresher=uas"},
				"Min-SE":          {"120"},
			},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-session-timer",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
		Headers: map[string][]string{
			"Session-Expires": {"1800;refresher=uas"},
			"Min-SE":          {"90"},
		},
	})
	if err != nil || !result.Accepted || result.Headers["Session-Expires"] != "1200;refresher=uac" || result.Headers["Min-SE"] != "90" {
		t.Fatalf("HandleInboundInvite() result=%+v err=%v", result, err)
	}
	if len(transport.requests) != 1 || transport.requests[0].Headers["Session-Expires"] != "1800;refresher=uas" ||
		transport.requests[0].Headers["Min-SE"] != "90" {
		t.Fatalf("client INVITE=%+v", transport.requests)
	}
	update, err := agent.HandleInboundUpdate(context.Background(), InboundDialogRequest{
		CallID: "in-call-session-timer",
		CSeq:   3,
		Headers: map[string][]string{
			"Session-Expires": {"600;refresher=uac"},
			"Min-SE":          {"120"},
		},
	})
	if err != nil || !update.Accepted || update.Headers["Session-Expires"] != "600;refresher=uas" || update.Headers["Min-SE"] != "120" {
		t.Fatalf("HandleInboundUpdate() result=%+v err=%v", update, err)
	}
	if len(transport.requests) != 2 || transport.requests[1].Method != "UPDATE" ||
		transport.requests[1].Headers["Session-Expires"] != "600;refresher=uac" ||
		transport.requests[1].Headers["Min-SE"] != "120" {
		t.Fatalf("client UPDATE=%+v", transport.requests)
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-session-timer"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
}

func TestIMSInboundAgentRetriesInviteSessionTimerMinSE(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 422,
			Reason:     "Session Interval Too Small",
			Headers: map[string][]string{
				"To":     {"<sip:user@ims.example>;tag=too-small"},
				"Min-SE": {"900"},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":              {"<sip:user@ims.example>;tag=client-tag"},
				"Contact":         {"<sip:client@192.0.2.50:5060>"},
				"Session-Expires": {"900;refresher=uas"},
				"Min-SE":          {"900"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{
			StatusCode: 422,
			Reason:     "Session Interval Too Small",
			Headers: map[string][]string{
				"To":     {"<sip:user@ims.example>;tag=too-small-reinvite"},
				"Min-SE": {"1200"},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Session-Expires": {"1200;refresher=uac"},
				"Min-SE":          {"1200"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4004)),
		},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-session-retry",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		CSeq:      1,
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
		Headers: map[string][]string{
			"Session-Expires": {"300;refresher=uas"},
			"Min-SE":          {"90"},
		},
	})
	if err != nil || !result.Accepted || result.Headers["Session-Expires"] != "900;refresher=uas" {
		t.Fatalf("HandleInboundInvite() result=%+v err=%v", result, err)
	}
	if len(transport.requests) != 2 || transport.requests[0].Headers["CSeq"] != "1 INVITE" ||
		transport.requests[0].Headers["Session-Expires"] != "300;refresher=uas" ||
		transport.requests[1].Headers["CSeq"] != "2 INVITE" ||
		transport.requests[1].Headers["Session-Expires"] != "900;refresher=uas" ||
		transport.requests[1].Headers["Min-SE"] != "900" {
		t.Fatalf("initial INVITEs=%+v", transport.requests)
	}
	if len(transport.writes) != 1 || transport.writes[0].Method != "ACK" ||
		transport.writes[0].Headers["CSeq"] != "1 ACK" ||
		!strings.Contains(transport.writes[0].Headers["To"], "too-small") {
		t.Fatalf("rejected INVITE ACKs=%+v", transport.writes)
	}
	if err := agent.AckInboundCall(context.Background(), DialogInfo{CallID: "in-call-session-retry"}); err != nil {
		t.Fatalf("AckInboundCall(initial) error = %v", err)
	}
	if len(transport.writes) != 2 || transport.writes[1].Headers["CSeq"] != "2 ACK" {
		t.Fatalf("accepted INVITE ACKs=%+v", transport.writes)
	}

	reinvite, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-session-retry",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		CSeq:      5,
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49172)),
		Headers: map[string][]string{
			"Session-Expires": {"600;refresher=uac"},
			"Min-SE":          {"90"},
		},
	})
	if err != nil || !reinvite.Accepted || reinvite.Headers["Session-Expires"] != "1200;refresher=uac" {
		t.Fatalf("HandleInboundInvite(re-INVITE) result=%+v err=%v", reinvite, err)
	}
	if len(transport.requests) != 4 || transport.requests[2].Headers["CSeq"] != "5 INVITE" ||
		transport.requests[2].Headers["Session-Expires"] != "600;refresher=uac" ||
		transport.requests[3].Headers["CSeq"] != "6 INVITE" ||
		transport.requests[3].Headers["Session-Expires"] != "1200;refresher=uac" ||
		transport.requests[3].Headers["Min-SE"] != "1200" {
		t.Fatalf("re-INVITEs=%+v", transport.requests)
	}
	if len(transport.writes) != 3 || transport.writes[2].Method != "ACK" ||
		transport.writes[2].Headers["CSeq"] != "5 ACK" ||
		!strings.Contains(transport.writes[2].Headers["To"], "too-small-reinvite") {
		t.Fatalf("rejected re-INVITE ACKs=%+v", transport.writes)
	}
	if err := agent.AckInboundCall(context.Background(), DialogInfo{CallID: "in-call-session-retry"}); err != nil {
		t.Fatalf("AckInboundCall(re-INVITE) error = %v", err)
	}
	if len(transport.writes) != 4 || transport.writes[3].Headers["CSeq"] != "6 ACK" {
		t.Fatalf("accepted re-INVITE ACKs=%+v", transport.writes)
	}
}

func TestIMSInboundAgentFollowsClientReinviteRedirectContact(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:user@ims.example>;tag=client-tag"},
				"Contact": {"<sip:client@192.0.2.50:5060>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{
			StatusCode: 302,
			Reason:     "Moved Temporarily",
			Headers: map[string][]string{
				"To":      {"<sip:user@ims.example>;tag=redirect-reinvite-tag"},
				"Contact": {"<sip:client2@127.0.0.1:5080>"},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Contact": {"<sip:client2@192.0.2.60:5060>"},
			},
			Body: []byte(sampleSDP("192.0.2.60", 4004)),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	if result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-reinvite-redirect",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		CSeq:      1,
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	}); err != nil || !result.Accepted {
		t.Fatalf("HandleInboundInvite() result=%+v err=%v", result, err)
	}
	if err := agent.AckInboundCall(context.Background(), DialogInfo{CallID: "in-call-reinvite-redirect"}); err != nil {
		t.Fatalf("AckInboundCall(initial) error = %v", err)
	}

	reinvite, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID: "in-call-reinvite-redirect",
		CSeq:   4,
		RawSDP: []byte(sampleSDP("203.0.113.10", 49172)),
	})
	if err != nil || !reinvite.Accepted || reinvite.LocalSDP.ConnectionIP != "192.0.2.60" {
		t.Fatalf("HandleInboundInvite(re-INVITE) result=%+v err=%v", reinvite, err)
	}
	if len(transport.requests) != 3 || transport.requests[1].Method != "INVITE" || transport.requests[2].Method != "INVITE" {
		t.Fatalf("client INVITEs=%+v", transport.requests)
	}
	firstReinvite := transport.requests[1]
	redirectReinvite := transport.requests[2]
	if firstReinvite.URI != "sip:client@192.0.2.50:5060" ||
		firstReinvite.Headers["CSeq"] != "4 INVITE" ||
		!strings.Contains(firstReinvite.Headers["To"], "client-tag") {
		t.Fatalf("first re-INVITE=%+v", firstReinvite)
	}
	if redirectReinvite.URI != "sip:client2@127.0.0.1:5080" ||
		redirectReinvite.Headers["CSeq"] != "5 INVITE" ||
		!strings.Contains(redirectReinvite.Headers["To"], "client-tag") {
		t.Fatalf("redirect re-INVITE=%+v", redirectReinvite)
	}
	if len(transport.writes) != 2 || transport.writes[1].Method != "ACK" ||
		transport.writes[1].Headers["CSeq"] != "4 ACK" ||
		!strings.Contains(transport.writes[1].Headers["To"], "redirect-reinvite-tag") ||
		transport.writes[1].Headers["Via"] != firstReinvite.Headers["Via"] {
		t.Fatalf("redirect re-INVITE ACKs=%+v first Via=%q", transport.writes, firstReinvite.Headers["Via"])
	}
	if err := agent.AckInboundCall(context.Background(), DialogInfo{CallID: "in-call-reinvite-redirect"}); err != nil {
		t.Fatalf("AckInboundCall(re-INVITE) error = %v", err)
	}
	if len(transport.writes) != 3 || transport.writes[2].URI != "sip:client2@192.0.2.60:5060" ||
		transport.writes[2].Headers["CSeq"] != "5 ACK" {
		t.Fatalf("accepted re-INVITE ACKs=%+v", transport.writes)
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-reinvite-redirect"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
	if len(transport.requests) != 4 || transport.requests[3].URI != "sip:client2@192.0.2.60:5060" ||
		transport.requests[3].Headers["CSeq"] != "6 BYE" {
		t.Fatalf("BYE after re-INVITE redirect=%+v", transport.requests)
	}
}

func TestIMSInboundAgentRetriesUpdateSessionTimerMinSE(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:user@ims.example>;tag=client-tag"},
				"Contact": {"<sip:client@192.0.2.50:5060>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{
			StatusCode: 422,
			Reason:     "Session Interval Too Small",
			Headers: map[string][]string{
				"Min-SE": {"900"},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Session-Expires": {"900;refresher=uas"},
				"Min-SE":          {"900"},
			},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	if result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-update-session-retry",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	}); err != nil || !result.Accepted {
		t.Fatalf("HandleInboundInvite() result=%+v err=%v", result, err)
	}
	update, err := agent.HandleInboundUpdate(context.Background(), InboundDialogRequest{
		CallID: "in-call-update-session-retry",
		CSeq:   3,
		Headers: map[string][]string{
			"Session-Expires": {"300;refresher=uac"},
			"Min-SE":          {"90"},
		},
	})
	if err != nil || !update.Accepted || update.Headers["Session-Expires"] != "900;refresher=uas" {
		t.Fatalf("HandleInboundUpdate() result=%+v err=%v", update, err)
	}
	if len(transport.requests) != 3 || transport.requests[1].Method != "UPDATE" ||
		transport.requests[1].Headers["CSeq"] != "3 UPDATE" ||
		transport.requests[1].Headers["Session-Expires"] != "300;refresher=uac" ||
		transport.requests[2].Method != "UPDATE" ||
		transport.requests[2].Headers["CSeq"] != "4 UPDATE" ||
		transport.requests[2].Headers["Session-Expires"] != "900;refresher=uac" ||
		transport.requests[2].Headers["Min-SE"] != "900" {
		t.Fatalf("client UPDATE retry=%+v", transport.requests)
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-update-session-retry"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
	if len(transport.requests) != 4 || transport.requests[3].Headers["CSeq"] != "5 BYE" {
		t.Fatalf("client BYE=%+v", transport.requests)
	}
}

func TestIMSInboundAgentForwardsInDialogInfoToClient(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:user@ims.example>;tag=client-tag"},
				"Contact": {"<sip:client@192.0.2.50:5060>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{StatusCode: 200, Reason: "OK", Headers: map[string][]string{"Contact": {"<sip:client@192.0.2.60:5060>"}, "X-Client": {"info-ok"}}},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	if _, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-info",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RemoteTag: "ims-tag",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	}); err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	result, err := agent.HandleInboundInfo(context.Background(), IMSInfoRequest{
		CallID:      "in-call-info",
		CSeq:        7,
		ContentType: "application/dtmf-relay",
		InfoPackage: "dtmf",
		Body:        []byte("Signal=5\r\nDuration=120\r\n"),
		Headers:     map[string][]string{"X-IMS": {"info"}},
	})
	if err != nil || !result.Handled || result.StatusCode != 200 || result.Headers["X-Client"] != "info-ok" {
		t.Fatalf("HandleInboundInfo() result=%+v err=%v", result, err)
	}
	if len(transport.requests) != 2 || transport.requests[1].Method != "INFO" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	info := transport.requests[1]
	if info.URI != "sip:client@192.0.2.50:5060" || info.Headers["CSeq"] != "7 INFO" ||
		info.Headers["Content-Type"] != "application/dtmf-relay" || info.Headers["Info-Package"] != "dtmf" ||
		info.Headers["X-IMS"] != "info" || !strings.Contains(string(info.Body), "Signal=5") {
		t.Fatalf("INFO=%+v body=%q", info, info.Body)
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-info"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
	if len(transport.requests) != 3 || transport.requests[2].Method != "BYE" || transport.requests[2].URI != "sip:client@192.0.2.60:5060" ||
		transport.requests[2].Headers["CSeq"] != "8 BYE" {
		t.Fatalf("BYE after INFO=%+v", transport.requests)
	}
}

func TestIMSInboundAgentHandlesReinviteAndTracksAckCSeq(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:user@ims.example>;tag=client-tag"},
				"Contact": {"<sip:client@192.0.2.50:5060>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers:    map[string][]string{"Contact": {"<sip:client@192.0.2.60:5060>"}},
			Body:       []byte(sampleSDP("192.0.2.60", 5000)),
		},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	if _, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-reinvite",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		CSeq:      1,
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	}); err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	if err := agent.AckInboundCall(context.Background(), DialogInfo{CallID: "in-call-reinvite"}); err != nil {
		t.Fatalf("AckInboundCall(initial) error = %v", err)
	}
	if len(transport.writes) != 1 || transport.writes[0].Headers["CSeq"] != "1 ACK" {
		t.Fatalf("initial ACK writes=%+v", transport.writes)
	}
	result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-reinvite",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		CSeq:      4,
		RawSDP:    []byte(sampleSDP("203.0.113.20", 49172)),
	})
	if err != nil {
		t.Fatalf("HandleInboundInvite(re-INVITE) error = %v", err)
	}
	if !result.Accepted || result.LocalSDP.ConnectionIP != "192.0.2.60" || result.LocalSDP.MediaPort != 5000 {
		t.Fatalf("re-INVITE result=%+v", result)
	}
	if len(transport.requests) != 2 || transport.requests[1].Method != "INVITE" || transport.requests[1].Headers["CSeq"] != "4 INVITE" || !strings.Contains(string(transport.requests[1].Body), "m=audio 49172 RTP/AVP") {
		t.Fatalf("re-INVITE requests=%+v", transport.requests)
	}
	if err := agent.AckInboundCall(context.Background(), DialogInfo{CallID: "in-call-reinvite"}); err != nil {
		t.Fatalf("AckInboundCall(re-INVITE) error = %v", err)
	}
	if len(transport.writes) != 2 || transport.writes[1].Headers["CSeq"] != "4 ACK" {
		t.Fatalf("re-INVITE ACK writes=%+v", transport.writes)
	}
}

func TestIMSInboundAgentRejectedReinviteAcksFinalResponse(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:user@ims.example>;tag=client-tag"},
				"Contact": {"<sip:client@192.0.2.50:5060>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{
			StatusCode: 488,
			Reason:     "Not Acceptable Here",
			Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=client-tag"}},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	if _, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-reinvite-reject",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		CSeq:      1,
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	}); err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	if err := agent.AckInboundCall(context.Background(), DialogInfo{CallID: "in-call-reinvite-reject"}); err != nil {
		t.Fatalf("AckInboundCall(initial) error = %v", err)
	}

	result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-reinvite-reject",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		CSeq:      4,
		RawSDP:    []byte(sampleSDP("203.0.113.20", 49172)),
	})
	if err != nil {
		t.Fatalf("HandleInboundInvite(re-INVITE) error = %v", err)
	}
	if result.Accepted || result.StatusCode != 488 || result.Reason != "Not Acceptable Here" {
		t.Fatalf("re-INVITE result=%+v", result)
	}
	if len(transport.requests) != 2 || transport.requests[1].Method != "INVITE" || transport.requests[1].Headers["CSeq"] != "4 INVITE" {
		t.Fatalf("re-INVITE requests=%+v", transport.requests)
	}
	if len(transport.writes) != 2 || transport.writes[1].Method != "ACK" {
		t.Fatalf("ACK writes=%+v", transport.writes)
	}
	ack := transport.writes[1]
	if ack.Headers["CSeq"] != "4 ACK" || !strings.Contains(ack.Headers["To"], "client-tag") {
		t.Fatalf("ACK=%+v", ack)
	}
	if ack.Headers["Via"] == "" || ack.Headers["Via"] != transport.requests[1].Headers["Via"] {
		t.Fatalf("ACK Via=%q INVITE Via=%q", ack.Headers["Via"], transport.requests[1].Headers["Via"])
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-reinvite-reject"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
	if len(transport.requests) != 3 || transport.requests[2].Method != "BYE" || transport.requests[2].Headers["CSeq"] != "5 BYE" {
		t.Fatalf("BYE requests=%+v", transport.requests)
	}
}

func TestIMSInboundAgentAdvancesByeCSeqAfterFailure(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:user@ims.example>;tag=client-tag"},
				"Contact": {"<sip:client@192.0.2.50:5060>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{StatusCode: 503, Reason: "Try Later"},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	if _, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-bye-retry",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	}); err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-bye-retry"}); err == nil {
		t.Fatal("EndInboundCall() err=nil, want failed BYE")
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-bye-retry"}); err != nil {
		t.Fatalf("EndInboundCall() retry error = %v", err)
	}
	if len(transport.requests) != 3 || transport.requests[1].Method != "BYE" || transport.requests[2].Method != "BYE" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	if transport.requests[1].Headers["CSeq"] != "2 BYE" || transport.requests[2].Headers["CSeq"] != "3 BYE" {
		t.Fatalf("BYE CSeqs=%q/%q", transport.requests[1].Headers["CSeq"], transport.requests[2].Headers["CSeq"])
	}
}

func TestIMSInboundAgentEndInboundCallWithResultReturnsClientResponse(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:user@ims.example>;tag=client-tag"},
				"Contact": {"<sip:client@192.0.2.50:5060>"},
			},
			Body: []byte(sampleSDP("192.0.2.50", 4002)),
		},
		{
			StatusCode: 486,
			Reason:     "Busy Here",
			Headers: map[string][]string{
				"Content-Type": {"message/sipfrag"},
				"X-Client":     {"busy"},
			},
			Body: []byte("SIP/2.0 486 Busy Here\r\n"),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	if _, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-bye-result",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RawSDP:    []byte(sampleSDP("203.0.113.10", 49170)),
	}); err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	result, err := agent.EndInboundCallWithResult(context.Background(), DialogInfo{CallID: "in-call-bye-result"})
	if err == nil || !strings.Contains(err.Error(), "client BYE rejected") {
		t.Fatalf("EndInboundCallWithResult() err=%v, want client BYE rejection", err)
	}
	if result.Accepted || result.StatusCode != 486 || result.Reason != "Busy Here" ||
		result.ContentType != "message/sipfrag" ||
		string(result.Body) != "SIP/2.0 486 Busy Here\r\n" ||
		result.Headers["X-Client"] != "busy" {
		t.Fatalf("result=%+v body=%q", result, result.Body)
	}
	if _, ok := agent.inboundDialog("in-call-bye-result"); !ok {
		t.Fatal("dialog should remain after rejected local BYE")
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-bye-result"}); err != nil {
		t.Fatalf("EndInboundCall() retry error = %v", err)
	}
	if _, ok := agent.inboundDialog("in-call-bye-result"); ok {
		t.Fatal("dialog should close after accepted local BYE")
	}
}

func TestIMSInboundAgentUsesRTPRelay(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=client-tag"}},
			Body:       []byte(sampleSDP("127.0.0.1", 4002)),
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	agent := &IMSInboundAgent{
		ClientTransport:  transport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		MediaRelay: &RTPRelayConfig{
			ClientListenIP:    "127.0.0.1",
			ClientAdvertiseIP: "127.0.0.1",
			IMSListenIP:       "127.0.0.1",
			IMSAdvertiseIP:    "127.0.0.1",
		},
	}
	result, err := agent.HandleInboundInvite(context.Background(), InboundCallRequest{
		CallID:    "in-call-relay",
		CallerURI: "sip:+18005551212@ims.example",
		CalleeURI: "sip:user@ims.example",
		RemoteSDP: SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 49170, Payloads: []int{0, 8, 101}, Direction: "sendrecv"},
		RawSDP:    []byte(sampleSDP("127.0.0.1", 49170)),
	})
	if err != nil {
		t.Fatalf("HandleInboundInvite() error = %v", err)
	}
	if len(transport.requests) != 1 || transport.requests[0].Method != "INVITE" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	clientOffer, err := ParseSDP(transport.requests[0].Body)
	if err != nil {
		t.Fatalf("ParseSDP(client offer) error = %v", err)
	}
	if clientOffer.ConnectionIP != "127.0.0.1" || clientOffer.MediaPort == 49170 || clientOffer.MediaPort <= 0 || clientOffer.RTCPPort <= 0 {
		t.Fatalf("client offer=%+v", clientOffer)
	}
	if result.LocalSDP.ConnectionIP != "127.0.0.1" || result.LocalSDP.MediaPort == 4002 || result.LocalSDP.MediaPort <= 0 || result.LocalSDP.RTCPPort <= 0 {
		t.Fatalf("IMS answer=%+v", result.LocalSDP)
	}
	if answer := string(result.RawSDP); !strings.Contains(answer, "c=IN IP4 127.0.0.1") || !strings.Contains(answer, "a=rtcp:") || strings.Contains(answer, "m=audio 4002") {
		t.Fatalf("IMS answer body=%q", answer)
	}
	if err := agent.EndInboundCall(context.Background(), DialogInfo{CallID: "in-call-relay"}); err != nil {
		t.Fatalf("EndInboundCall() error = %v", err)
	}
}

type cancelAwareInboundTransport struct {
	invites     chan voiceclient.SIPRequestMessage
	cancels     chan voiceclient.SIPRequestMessage
	writes      chan voiceclient.SIPRequestMessage
	inviteResps chan voiceclient.SIPResponse
	cancelResps chan voiceclient.SIPResponse
}

func newCancelAwareInboundTransport() *cancelAwareInboundTransport {
	return &cancelAwareInboundTransport{
		invites:     make(chan voiceclient.SIPRequestMessage, 8),
		cancels:     make(chan voiceclient.SIPRequestMessage, 8),
		writes:      make(chan voiceclient.SIPRequestMessage, 8),
		inviteResps: make(chan voiceclient.SIPResponse, 8),
		cancelResps: make(chan voiceclient.SIPResponse, 8),
	}
}

func (t *cancelAwareInboundTransport) RoundTripInvite(ctx context.Context, msg voiceclient.SIPRequestMessage, onProvisional voiceclient.ProvisionalResponseHandler) (voiceclient.SIPResponse, error) {
	if msg.Headers != nil && msg.Headers["Via"] == "" {
		msg.Headers["Via"] = "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-inbound-invite;rport"
	}
	t.invites <- msg
	select {
	case resp := <-t.inviteResps:
		return resp, nil
	case <-ctx.Done():
		return voiceclient.SIPResponse{}, ctx.Err()
	}
}

func (t *cancelAwareInboundTransport) RoundTripRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	if strings.EqualFold(msg.Method, "CANCEL") {
		t.cancels <- msg
		select {
		case resp := <-t.cancelResps:
			return resp, nil
		case <-ctx.Done():
			return voiceclient.SIPResponse{}, ctx.Err()
		}
	}
	t.invites <- msg
	select {
	case resp := <-t.inviteResps:
		return resp, nil
	case <-ctx.Done():
		return voiceclient.SIPResponse{}, ctx.Err()
	}
}

func (t *cancelAwareInboundTransport) WriteRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) error {
	t.writes <- msg
	return nil
}

func (t *cancelAwareInboundTransport) readInvite(tb testing.TB) voiceclient.SIPRequestMessage {
	tb.Helper()
	select {
	case msg := <-t.invites:
		return msg
	case <-time.After(time.Second):
		tb.Fatalf("timed out waiting for client INVITE")
		return voiceclient.SIPRequestMessage{}
	}
}

func (t *cancelAwareInboundTransport) readCancel(tb testing.TB) voiceclient.SIPRequestMessage {
	tb.Helper()
	select {
	case msg := <-t.cancels:
		return msg
	case <-time.After(time.Second):
		tb.Fatalf("timed out waiting for client CANCEL")
		return voiceclient.SIPRequestMessage{}
	}
}

func (t *cancelAwareInboundTransport) readWrite(tb testing.TB) voiceclient.SIPRequestMessage {
	tb.Helper()
	select {
	case msg := <-t.writes:
		return msg
	case <-time.After(time.Second):
		tb.Fatalf("timed out waiting for client write")
		return voiceclient.SIPRequestMessage{}
	}
}

func (t *cancelAwareInboundTransport) respondInvite(resp voiceclient.SIPResponse) {
	t.inviteResps <- resp
}

func (t *cancelAwareInboundTransport) respondCancel(resp voiceclient.SIPResponse) {
	t.cancelResps <- resp
}

type reliableProvisionalInboundTransport struct {
	invites          chan voiceclient.SIPRequestMessage
	requests         chan voiceclient.SIPRequestMessage
	writes           chan voiceclient.SIPRequestMessage
	inviteResps      chan voiceclient.SIPResponse
	requestResps     chan voiceclient.SIPResponse
	provisionals     []voiceclient.SIPResponse
	provisionalsDone chan struct{}
}

func newReliableProvisionalInboundTransport(provisionals []voiceclient.SIPResponse) *reliableProvisionalInboundTransport {
	return &reliableProvisionalInboundTransport{
		invites:          make(chan voiceclient.SIPRequestMessage, 8),
		requests:         make(chan voiceclient.SIPRequestMessage, 8),
		writes:           make(chan voiceclient.SIPRequestMessage, 8),
		inviteResps:      make(chan voiceclient.SIPResponse, 8),
		requestResps:     make(chan voiceclient.SIPResponse, 8),
		provisionals:     append([]voiceclient.SIPResponse(nil), provisionals...),
		provisionalsDone: make(chan struct{}),
	}
}

func (t *reliableProvisionalInboundTransport) RoundTripInvite(ctx context.Context, msg voiceclient.SIPRequestMessage, onProvisional voiceclient.ProvisionalResponseHandler) (voiceclient.SIPResponse, error) {
	t.invites <- msg
	for _, resp := range t.provisionals {
		if onProvisional != nil {
			if err := onProvisional(ctx, msg, resp); err != nil {
				close(t.provisionalsDone)
				return voiceclient.SIPResponse{}, err
			}
		}
	}
	close(t.provisionalsDone)
	select {
	case resp := <-t.inviteResps:
		return resp, nil
	case <-ctx.Done():
		return voiceclient.SIPResponse{}, ctx.Err()
	}
}

func (t *reliableProvisionalInboundTransport) RoundTripRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	t.requests <- msg
	select {
	case resp := <-t.requestResps:
		return resp, nil
	case <-ctx.Done():
		return voiceclient.SIPResponse{}, ctx.Err()
	}
}

func (t *reliableProvisionalInboundTransport) WriteRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) error {
	t.writes <- msg
	return nil
}

func (t *reliableProvisionalInboundTransport) readInvite(tb testing.TB) voiceclient.SIPRequestMessage {
	tb.Helper()
	select {
	case msg := <-t.invites:
		return msg
	case <-time.After(time.Second):
		tb.Fatalf("timed out waiting for client INVITE")
		return voiceclient.SIPRequestMessage{}
	}
}

func (t *reliableProvisionalInboundTransport) readRequest(tb testing.TB) voiceclient.SIPRequestMessage {
	tb.Helper()
	select {
	case msg := <-t.requests:
		return msg
	case <-time.After(time.Second):
		tb.Fatalf("timed out waiting for client request")
		return voiceclient.SIPRequestMessage{}
	}
}

func (t *reliableProvisionalInboundTransport) waitProvisionals(tb testing.TB) {
	tb.Helper()
	select {
	case <-t.provisionalsDone:
	case <-time.After(time.Second):
		tb.Fatalf("timed out waiting for provisionals")
	}
}

func (t *reliableProvisionalInboundTransport) respondInvite(resp voiceclient.SIPResponse) {
	t.inviteResps <- resp
}

func (t *reliableProvisionalInboundTransport) respondRequest(resp voiceclient.SIPResponse) {
	t.requestResps <- resp
}
