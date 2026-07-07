package tracefixture

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestTranscriptJSONSchemaIsValid(t *testing.T) {
	if !json.Valid([]byte(TranscriptJSONSchema)) {
		t.Fatal("transcript JSON schema is not valid JSON")
	}
	var schema map[string]any
	if err := json.Unmarshal([]byte(TranscriptJSONSchema), &schema); err != nil {
		t.Fatalf("unmarshal transcript JSON schema: %v", err)
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema properties missing: %#v", schema["properties"])
	}
	schemaProp, ok := props["schema"].(map[string]any)
	if !ok || schemaProp["const"] != TranscriptSchemaVersion {
		t.Fatalf("schema const mismatch: %#v", props["schema"])
	}
}

func TestParseTranscriptJSONAcceptsRedactedTranscript(t *testing.T) {
	raw := marshalTranscript(t, Transcript{
		Schema: TranscriptSchemaVersion,
		Name:   "register-401-redacted",
		Events: []TranscriptEvent{
			{
				Label:     "initial-register",
				Direction: "outbound",
				Transport: "udp",
				Wire: strings.Join([]string{
					"REGISTER sip:ims.example.invalid SIP/2.0",
					"Via: SIP/2.0/UDP redacted.invalid:5060;branch=z9hG4bKfixture",
					"From: <sip:redacted.invalid>;tag=fixture",
					"To: <sip:redacted.invalid>",
					"Call-ID: fixture-call",
					"CSeq: 1 REGISTER",
					"Authorization: <redacted>",
					"Content-Length: 0",
					"",
					"",
				}, "\r\n"),
			},
		},
	})

	transcript, err := ParseTranscriptJSON(raw)
	if err != nil {
		t.Fatalf("ParseTranscriptJSON returned error: %v", err)
	}
	if transcript.Name != "register-401-redacted" || len(transcript.Events) != 1 {
		t.Fatalf("unexpected transcript: %#v", transcript)
	}
}

func TestParseTranscriptJSONRejectsSensitiveFixture(t *testing.T) {
	tests := []struct {
		name     string
		wire     string
		secret   string
		wantKind string
	}{
		{
			name:     "imsi",
			wire:     "X-IMSI: 001010000000000",
			secret:   "001010000000000",
			wantKind: "subscriber",
		},
		{
			name:     "imei",
			wire:     "X-IMEI: 004999010640000",
			secret:   "004999010640000",
			wantKind: "subscriber",
		},
		{
			name:     "msisdn",
			wire:     "To: <tel:+15550101234>",
			secret:   "+15550101234",
			wantKind: "msisdn",
		},
		{
			name:     "msisdn sip uri user",
			wire:     "P-Preferred-Identity: <sip:15550101234@ims.example.invalid;user=phone>",
			secret:   "15550101234",
			wantKind: "sip uri user identity",
		},
		{
			name:     "prefixed imsi sip uri user",
			wire:     "P-Associated-URI: <sip:imsi-001-01-0000000000@ims.example.invalid>",
			secret:   "001-01-0000000000",
			wantKind: "sip uri user identity",
		},
		{
			name:     "auth",
			wire:     `Authorization: Digest username="<redacted-sip-user-1>", nonce="auth-secret", response="auth-response"`,
			secret:   "auth-secret",
			wantKind: "auth",
		},
		{
			name:     "aka",
			wire:     "X-AKA: rand=00112233445566778899AABBCCDDEEFF",
			secret:   "00112233445566778899AABBCCDDEEFF",
			wantKind: "aka",
		},
		{
			name:     "ip",
			wire:     "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKfixture",
			secret:   "192.0.2.10",
			wantKind: "ip",
		},
		{
			name:     "ipv6",
			wire:     "Via: SIP/2.0/TCP [2001:db8::10]:5060;branch=z9hG4bKfixture",
			secret:   "2001:db8::10",
			wantKind: "ip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := marshalTranscript(t, Transcript{
				Schema: TranscriptSchemaVersion,
				Name:   "sensitive-" + tt.name,
				Events: []TranscriptEvent{
					{
						Direction: "inbound",
						Transport: "udp",
						Wire:      tt.wire,
					},
				},
			})

			_, err := ParseTranscriptJSON(raw)
			if !errors.Is(err, ErrSensitiveFixture) {
				t.Fatalf("ParseTranscriptJSON error = %v, want ErrSensitiveFixture", err)
			}
			if strings.Contains(err.Error(), tt.secret) {
				t.Fatalf("redaction error leaked sensitive value %q: %v", tt.secret, err)
			}
			var redactionErr *RedactionError
			if !errors.As(err, &redactionErr) {
				t.Fatalf("error does not expose RedactionError: %T", err)
			}
			if len(redactionErr.Violations) == 0 {
				t.Fatal("redaction error had no violations")
			}
			if !strings.Contains(redactionErr.Violations[0].Kind, tt.wantKind) {
				t.Fatalf("violation kind = %q, want substring %q", redactionErr.Violations[0].Kind, tt.wantKind)
			}
		})
	}
}

func TestParseAndRedactTranscriptJSONSanitizesSensitiveFixture(t *testing.T) {
	raw := marshalTranscript(t, Transcript{
		Schema: TranscriptSchemaVersion,
		Name:   "register-001010123456789",
		Events: []TranscriptEvent{
			{
				Label:     "register-001010123456789",
				Direction: "outbound",
				Transport: "udp",
				Wire: strings.Join([]string{
					"REGISTER sip:ims.example.invalid SIP/2.0",
					"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKfixture1",
					"From: <sip:001010123456789@ims.example.invalid>;tag=fixture1",
					"To: <tel:+15550101234>",
					"Call-ID: fixture-call",
					"CSeq: 1 REGISTER",
					`Authorization: Digest username="001010123456789@ims.example.invalid", nonce="secret", response="0123456789abcdef0123456789abcdef"`,
					"Content-Length: 0",
					"",
					"",
				}, "\r\n"),
			},
			{
				Label:     "challenge-001010123456789",
				Direction: "inbound",
				Transport: "udp",
				Wire: strings.Join([]string{
					"SIP/2.0 401 Unauthorized",
					"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKfixture1",
					"From: <sip:001010123456789@ims.example.invalid>;tag=fixture1",
					"To: <tel:+15550101234>;tag=fixture2",
					"Call-ID: fixture-call",
					"CSeq: 1 REGISTER",
					`WWW-Authenticate: Digest realm="ims.example.invalid", nonce="secret"`,
					`Security-Server: ipsec-3gpp;alg=hmac-sha-1-96;spi-c=00112233;spi-s=44556677`,
					"Content-Length: 0",
					"",
					"",
				}, "\r\n"),
			},
		},
	})

	if _, err := ParseTranscriptJSON(raw); !errors.Is(err, ErrSensitiveFixture) {
		t.Fatalf("ParseTranscriptJSON error = %v, want ErrSensitiveFixture", err)
	}
	transcript, err := ParseAndRedactTranscriptJSON(raw)
	if err != nil {
		t.Fatalf("ParseAndRedactTranscriptJSON returned error: %v", err)
	}
	if err := ValidateTranscript(transcript); err != nil {
		t.Fatalf("redacted transcript did not validate: %v", err)
	}
	joined := transcript.Name + "\n" + transcript.Events[0].Label + "\n" + transcript.Events[0].Wire + "\n" + transcript.Events[1].Label + "\n" + transcript.Events[1].Wire
	for _, sensitive := range []string{
		"001010123456789",
		"+15550101234",
		"192.0.2.10",
		"0123456789abcdef0123456789abcdef",
		`nonce="secret"`,
		"00112233",
		"44556677",
	} {
		if strings.Contains(joined, sensitive) {
			t.Fatalf("redacted transcript still contains %q:\n%s", sensitive, joined)
		}
	}
	if strings.Count(joined, "sip:<redacted-sip-user-1>@<redacted-domain-1>.invalid") != 2 {
		t.Fatalf("shared SIP placeholder was not reused:\n%s", joined)
	}
	for _, want := range []string{
		"Authorization: <redacted>",
		"WWW-Authenticate: <redacted>",
		"Security-Server: <redacted>",
		"<redacted-id-1>",
		"tel:<redacted-msisdn-1>",
		"<redacted-ipv4-1>",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("redacted transcript missing %q:\n%s", want, joined)
		}
	}
}

func TestParseTranscriptJSONRejectsInvalidShape(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "unknown top-level field",
			raw:  `{"schema":"vowifi-go.tracefixture.transcript.v1","name":"x","events":[{"direction":"inbound","transport":"udp","wire":"SIP/2.0 200 OK\r\n\r\n"}],"extra":true}`,
		},
		{
			name: "wrong schema",
			raw:  `{"schema":"vowifi-go.tracefixture.transcript.v0","name":"x","events":[{"direction":"inbound","transport":"udp","wire":"SIP/2.0 200 OK\r\n\r\n"}]}`,
		},
		{
			name: "empty events",
			raw:  `{"schema":"vowifi-go.tracefixture.transcript.v1","name":"x","events":[]}`,
		},
		{
			name: "trailing json",
			raw:  `{"schema":"vowifi-go.tracefixture.transcript.v1","name":"x","events":[{"direction":"inbound","transport":"udp","wire":"SIP/2.0 200 OK\r\n\r\n"}]} {}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTranscriptJSON([]byte(tt.raw))
			if !errors.Is(err, ErrInvalidTranscript) {
				t.Fatalf("ParseTranscriptJSON error = %v, want ErrInvalidTranscript", err)
			}
		})
	}
}

func marshalTranscript(t *testing.T, transcript Transcript) []byte {
	t.Helper()
	raw, err := json.Marshal(transcript)
	if err != nil {
		t.Fatalf("marshal transcript: %v", err)
	}
	return raw
}
