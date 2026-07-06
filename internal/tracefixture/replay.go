package tracefixture

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

var (
	ErrReplayExhausted = errors.New("trace replay exhausted")
	ErrReplayMismatch  = errors.New("trace replay mismatch")
)

type ReplayEvent struct {
	Index     int
	Label     string
	Direction string
	Transport string
	Wire      []byte
}

type Replay struct {
	events []ReplayEvent
	next   int
}

func ParseReplayJSON(raw []byte) (*Replay, error) {
	transcript, err := ParseTranscriptJSON(raw)
	if err != nil {
		return nil, err
	}
	return NewReplay(transcript)
}

func DecodeReplayJSON(r io.Reader) (*Replay, error) {
	transcript, err := DecodeTranscriptJSON(r)
	if err != nil {
		return nil, err
	}
	return NewReplay(transcript)
}

func NewReplay(transcript Transcript) (*Replay, error) {
	events, err := ReplayEvents(transcript)
	if err != nil {
		return nil, err
	}
	return &Replay{events: events}, nil
}

func ReplayEvents(transcript Transcript) ([]ReplayEvent, error) {
	if err := ValidateTranscript(transcript); err != nil {
		return nil, err
	}
	events := make([]ReplayEvent, len(transcript.Events))
	for i, event := range transcript.Events {
		events[i] = ReplayEvent{
			Index:     i,
			Label:     event.Label,
			Direction: event.Direction,
			Transport: event.Transport,
			Wire:      []byte(event.Wire),
		}
	}
	return events, nil
}

func (r *Replay) Len() int {
	if r == nil {
		return 0
	}
	return len(r.events)
}

func (r *Replay) Remaining() int {
	if r == nil || r.next >= len(r.events) {
		return 0
	}
	return len(r.events) - r.next
}

func (r *Replay) Reset() {
	if r != nil {
		r.next = 0
	}
}

func (r *Replay) Events() []ReplayEvent {
	if r == nil {
		return nil
	}
	return cloneReplayEvents(r.events)
}

func (r *Replay) Next() (ReplayEvent, error) {
	if r == nil || r.next >= len(r.events) {
		return ReplayEvent{}, ErrReplayExhausted
	}
	event := cloneReplayEvent(r.events[r.next])
	r.next++
	return event, nil
}

func (r *Replay) NextInbound() (ReplayEvent, error) {
	return r.nextDirection("inbound")
}

func (r *Replay) NextOutbound() (ReplayEvent, error) {
	return r.nextDirection("outbound")
}

func (r *Replay) nextDirection(direction string) (ReplayEvent, error) {
	if !validTranscriptDirection(direction) {
		return ReplayEvent{}, fmt.Errorf("%w: unsupported direction %q", ErrInvalidTranscript, direction)
	}
	if r == nil || r.next >= len(r.events) {
		return ReplayEvent{}, ErrReplayExhausted
	}
	event := r.events[r.next]
	if event.Direction != direction {
		return ReplayEvent{}, fmt.Errorf("%w: next event %d direction is %q, want %q", ErrReplayMismatch, event.Index, event.Direction, direction)
	}
	r.next++
	return cloneReplayEvent(event), nil
}

func cloneReplayEvents(events []ReplayEvent) []ReplayEvent {
	out := make([]ReplayEvent, len(events))
	for i, event := range events {
		out[i] = cloneReplayEvent(event)
	}
	return out
}

func cloneReplayEvent(event ReplayEvent) ReplayEvent {
	event.Wire = bytes.Clone(event.Wire)
	return event
}
