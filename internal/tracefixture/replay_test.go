package tracefixture

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestReplayDrainsRedactedSIPTranscriptInOrder(t *testing.T) {
	raw, err := os.ReadFile("testdata/register_401_redacted.transcript.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	replay, err := ParseReplayJSON(raw)
	if err != nil {
		t.Fatalf("ParseReplayJSON returned error: %v", err)
	}
	if replay.Len() != 4 || replay.Remaining() != 4 {
		t.Fatalf("unexpected replay size: len=%d remaining=%d", replay.Len(), replay.Remaining())
	}

	first, err := replay.NextOutbound()
	if err != nil {
		t.Fatalf("NextOutbound initial register: %v", err)
	}
	if first.Index != 0 || first.Label != "initial-register" || first.Transport != "udp" {
		t.Fatalf("unexpected first event: %#v", first)
	}
	if !strings.HasPrefix(string(first.Wire), "REGISTER sip:ims.example.invalid SIP/2.0\r\n") {
		t.Fatalf("first event did not preserve SIP request line and CRLFs: %q", string(first.Wire))
	}
	first.Wire[0] = 'X'

	challenge, err := replay.NextInbound()
	if err != nil {
		t.Fatalf("NextInbound challenge: %v", err)
	}
	if !strings.HasPrefix(string(challenge.Wire), "SIP/2.0 401 Unauthorized\r\n") {
		t.Fatalf("unexpected challenge wire: %q", string(challenge.Wire))
	}
	if _, err := replay.NextOutbound(); err != nil {
		t.Fatalf("NextOutbound authenticated register: %v", err)
	}
	if _, err := replay.NextInbound(); err != nil {
		t.Fatalf("NextInbound register ok: %v", err)
	}
	if replay.Remaining() != 0 {
		t.Fatalf("remaining after drain = %d, want 0", replay.Remaining())
	}
	if _, err := replay.Next(); !errors.Is(err, ErrReplayExhausted) {
		t.Fatalf("Next after drain error = %v, want ErrReplayExhausted", err)
	}

	replay.Reset()
	firstAgain, err := replay.NextOutbound()
	if err != nil {
		t.Fatalf("NextOutbound after reset: %v", err)
	}
	if !strings.HasPrefix(string(firstAgain.Wire), "REGISTER ") {
		t.Fatalf("replay returned mutated wire after reset: %q", string(firstAgain.Wire))
	}
}

func TestReplayDirectionMismatchDoesNotConsumeEvent(t *testing.T) {
	raw, err := os.ReadFile("testdata/register_401_redacted.transcript.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	replay, err := ParseReplayJSON(raw)
	if err != nil {
		t.Fatalf("ParseReplayJSON returned error: %v", err)
	}

	if _, err := replay.NextInbound(); !errors.Is(err, ErrReplayMismatch) {
		t.Fatalf("NextInbound first event error = %v, want ErrReplayMismatch", err)
	}
	if replay.Remaining() != replay.Len() {
		t.Fatalf("direction mismatch consumed event: len=%d remaining=%d", replay.Len(), replay.Remaining())
	}
	event, err := replay.NextOutbound()
	if err != nil {
		t.Fatalf("NextOutbound after mismatch: %v", err)
	}
	if event.Label != "initial-register" {
		t.Fatalf("unexpected event after mismatch: %q", event.Label)
	}
}

func TestReplayEventsValidatesTranscriptBeforeMaterializing(t *testing.T) {
	_, err := ReplayEvents(Transcript{
		Schema: TranscriptSchemaVersion,
		Name:   "leaky-replay",
		Events: []TranscriptEvent{
			{
				Direction: "inbound",
				Transport: "udp",
				Wire:      "Authorization: Digest nonce=\"secret\"",
			},
		},
	})
	if !errors.Is(err, ErrSensitiveFixture) {
		t.Fatalf("ReplayEvents error = %v, want ErrSensitiveFixture", err)
	}
}
