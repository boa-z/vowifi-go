package e911

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/boa-z/vowifi-go/engine/sim"
	"github.com/boa-z/vowifi-go/runtimehost/carrier"
	"github.com/boa-z/vowifi-go/runtimehost/voiceclient"
)

func TestStartEmergencyAddressUpdateAnswersHTTPDigestAKAChallenge(t *testing.T) {
	rawNonce := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	challenge := `Digest realm="e911.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`
	client := &fakeHTTPClient{responses: []*HTTPResponse{
		{
			StatusCode: 401,
			Headers: []HeaderPair{{
				Key:   "WWW-Authenticate",
				Value: challenge,
			}},
		},
		{
			StatusCode: 200,
			Body:       []byte(`{"status":1000,"websheet-url":"https://example.test/address?ok=1"}`),
		},
	}}
	aka := &fakeAKAProvider{}

	ws, err := StartEmergencyAddressUpdate(context.Background(), Request{
		Carrier: carrier.EffectiveCarrierConfig{
			E911: carrier.E911Config{
				Provider:            "att-ts43",
				Websheet:            "https://example.test/websheet",
				EntitlementEndpoint: "https://example.test/entitlement?slot=1",
			},
		},
		Identity:    Identity{IMSI: "310280233641503", IMEI: "356306952701762", MCC: "310", MNC: "280", SIPUsername: "sip:user@example"},
		AKAProvider: aka,
		Client:      client,
		Random:      bytes.NewReader(bytes.Repeat([]byte{0x5c}, 16)),
	})
	if err != nil {
		t.Fatalf("StartEmergencyAddressUpdate() error = %v", err)
	}
	if ws.URL != "https://example.test/address?ok=1" {
		t.Fatalf("URL=%q", ws.URL)
	}
	if len(client.requests) != 2 {
		t.Fatalf("requests=%d, want initial request and digest retry", len(client.requests))
	}
	if client.requests[0].Headers[len(client.requests[0].Headers)-1].Key == "Authorization" {
		t.Fatalf("initial request unexpectedly carried Authorization: %+v", client.requests[0].Headers)
	}
	auth := headerValue(client.requests[1].Headers, "Authorization")
	if auth == "" || headerValue(client.requests[1].Headers, "Proxy-Authorization") != "" {
		t.Fatalf("auth headers=%+v", client.requests[1].Headers)
	}
	ch, err := voiceclient.ParseWWWAuthenticate(challenge)
	if err != nil {
		t.Fatalf("ParseWWWAuthenticate() error = %v", err)
	}
	want, err := voiceclient.BuildDigestAuthorization(ch, voiceclient.DigestAuthInput{
		Method:   "POST",
		URI:      "/entitlement?slot=1",
		Username: "sip:user@example",
		Password: string(e911AKAResult().RES),
		CNonce:   strings.Repeat("5c", 16),
		NC:       1,
		Body:     client.requests[0].Body,
	})
	if err != nil {
		t.Fatalf("BuildDigestAuthorization() error = %v", err)
	}
	if auth != want {
		t.Fatalf("Authorization=%s, want %s", auth, want)
	}
	if !bytes.Equal(aka.rand, bytesFrom(0x10, 16)) || !bytes.Equal(aka.autn, bytesFrom(0x40, 16)) {
		t.Fatalf("AKA RAND/AUTN=%x/%x", aka.rand, aka.autn)
	}
}

func TestStartEmergencyAddressUpdateHTTPDigestAKAResyncThenFreshNonce(t *testing.T) {
	staleNonce := append(bytesFrom(0x20, 16), bytesFrom(0x50, 16)...)
	freshNonce := append(bytesFrom(0x30, 16), bytesFrom(0x60, 16)...)
	staleChallenge := `Digest realm="e911.example", nonce="` + base64.StdEncoding.EncodeToString(staleNonce) + `", algorithm=AKAv1-MD5, qop="auth"`
	freshChallenge := `Digest realm="e911.example", nonce="` + base64.StdEncoding.EncodeToString(freshNonce) + `", algorithm=AKAv1-MD5, qop="auth"`
	client := &fakeHTTPClient{responses: []*HTTPResponse{
		{
			StatusCode: 401,
			Headers:    []HeaderPair{{Key: "WWW-Authenticate", Value: staleChallenge}},
		},
		{
			StatusCode: 401,
			Headers:    []HeaderPair{{Key: "WWW-Authenticate", Value: freshChallenge}},
		},
		{
			StatusCode: 200,
			Body:       []byte(`{"status":1000,"websheet-url":"https://example.test/address?ok=1"}`),
		},
	}}
	auts := []byte{0xde, 0xad, 0xbe, 0xef}
	aka := &sequenceE911AKAProvider{results: []sequenceE911AKAResult{
		{result: sim.AKAResult{AUTS: auts}, err: sim.ErrSyncFailure},
		{result: e911AKAResult()},
	}}

	_, err := StartEmergencyAddressUpdate(context.Background(), Request{
		Carrier: carrier.EffectiveCarrierConfig{
			E911: carrier.E911Config{
				Provider:            "att-ts43",
				Websheet:            "https://example.test/websheet",
				EntitlementEndpoint: "https://example.test/entitlement",
			},
		},
		Identity:    Identity{IMSI: "310280233641503", IMEI: "356306952701762", MCC: "310", MNC: "280"},
		AKAProvider: aka,
		Client:      client,
		Random:      bytes.NewReader(append(bytes.Repeat([]byte{0x66}, 16), bytes.Repeat([]byte{0x77}, 16)...)),
	})
	if err != nil {
		t.Fatalf("StartEmergencyAddressUpdate() error = %v", err)
	}
	if len(client.requests) != 3 || aka.calls != 2 {
		t.Fatalf("requests=%d AKA calls=%d", len(client.requests), aka.calls)
	}
	syncAuth := headerValue(client.requests[1].Headers, "Authorization")
	if !strings.Contains(syncAuth, `nonce="`+base64.StdEncoding.EncodeToString(staleNonce)+`"`) ||
		!strings.Contains(syncAuth, `auts="`+base64.StdEncoding.EncodeToString(auts)+`"`) ||
		!strings.Contains(syncAuth, `cnonce="`+strings.Repeat("66", 16)+`"`) {
		t.Fatalf("sync Authorization=%s", syncAuth)
	}
	finalAuth := headerValue(client.requests[2].Headers, "Authorization")
	if !strings.Contains(finalAuth, `nonce="`+base64.StdEncoding.EncodeToString(freshNonce)+`"`) ||
		strings.Contains(finalAuth, "auts=") ||
		!strings.Contains(finalAuth, `cnonce="`+strings.Repeat("77", 16)+`"`) {
		t.Fatalf("final Authorization=%s", finalAuth)
	}
	if !bytes.Equal(aka.rands[0], bytesFrom(0x20, 16)) || !bytes.Equal(aka.rands[1], bytesFrom(0x30, 16)) {
		t.Fatalf("AKA RANDs=%x", aka.rands)
	}
}

func TestStartEmergencyAddressUpdateAnswersProxyDigestAKAChallengeVariants(t *testing.T) {
	rawNonce := append(bytesFrom(0x12, 16), bytesFrom(0x42, 16)...)
	challenge := `dIgEsT realm="e911,proxy", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=akav2-md5, qop="AUTH-INT", qop=AUTH, opaque="opq,one", stale=TRUE`
	successResp := &HTTPResponse{
		StatusCode: 200,
		Headers: []HeaderPair{{
			Key:   "Proxy-Authentication-Info",
			Value: `qop=auth, nextnonce="next,proxy"`,
		}},
		Body: []byte(`{"status":1000,"websheet-url":"https://example.test/address?ok=proxy"}`),
	}
	client := &fakeHTTPClient{responses: []*HTTPResponse{
		{
			StatusCode: 407,
			Headers: []HeaderPair{{
				Key:   "proxy-authenticate",
				Value: challenge,
			}},
		},
		successResp,
	}}
	aka := &fakeAKAProvider{}

	ws, err := StartEmergencyAddressUpdate(context.Background(), Request{
		Carrier: carrier.EffectiveCarrierConfig{
			E911: carrier.E911Config{
				Provider:            "att-ts43",
				Websheet:            "https://example.test/websheet",
				EntitlementEndpoint: "https://example.test/entitlement",
			},
		},
		Identity:    Identity{IMSI: "310280233641503", IMEI: "356306952701762", MCC: "310", MNC: "280", SIPUsername: "sip:user@example"},
		AKAProvider: aka,
		Client:      client,
		Random:      bytes.NewReader(bytes.Repeat([]byte{0x88}, 16)),
	})
	if err != nil {
		t.Fatalf("StartEmergencyAddressUpdate() error = %v", err)
	}
	if ws.URL != "https://example.test/address?ok=proxy" {
		t.Fatalf("URL=%q", ws.URL)
	}
	if len(client.requests) != 2 {
		t.Fatalf("requests=%d, want initial request and proxy digest retry", len(client.requests))
	}
	if headerValue(client.requests[1].Headers, "Authorization") != "" {
		t.Fatalf("origin Authorization unexpectedly set: %+v", client.requests[1].Headers)
	}
	auth := headerValue(client.requests[1].Headers, "Proxy-Authorization")
	if auth == "" {
		t.Fatalf("missing Proxy-Authorization: %+v", client.requests[1].Headers)
	}
	parsed, err := voiceclient.ParseDigestAuthorization(auth)
	if err != nil {
		t.Fatalf("ParseDigestAuthorization() error = %v", err)
	}
	if parsed.Algorithm != "AKAv2-MD5" || parsed.QOP != "auth" || parsed.Opaque != "opq,one" ||
		parsed.Realm != "e911,proxy" || parsed.URI != "/entitlement" || parsed.CNonce != strings.Repeat("88", 16) {
		t.Fatalf("Proxy-Authorization=%+v", parsed)
	}
	if !bytes.Equal(aka.rand, bytesFrom(0x12, 16)) || !bytes.Equal(aka.autn, bytesFrom(0x42, 16)) {
		t.Fatalf("AKA RAND/AUTN=%x/%x", aka.rand, aka.autn)
	}
	if got := entitlementHTTPDigestNextNonce(successResp.Headers, "Proxy-Authorization"); got != "next,proxy" {
		t.Fatalf("nextnonce=%q, want next,proxy", got)
	}
}

func TestEntitlementHTTPDigestAuthenticationInfoNextNoncePriority(t *testing.T) {
	headers := []HeaderPair{
		{Key: "Authentication-Info", Value: `nextnonce="origin,next", qop=auth`},
		{Key: "Proxy-Authentication-Info", Value: `qop=auth, nextnonce="proxy,next"`},
	}
	if got := entitlementHTTPDigestNextNonce(headers, "Authorization"); got != "origin,next" {
		t.Fatalf("origin nextnonce=%q", got)
	}
	if got := entitlementHTTPDigestNextNonce(headers, "Proxy-Authorization"); got != "proxy,next" {
		t.Fatalf("proxy nextnonce=%q", got)
	}
}

type sequenceE911AKAResult struct {
	result sim.AKAResult
	err    error
}

type sequenceE911AKAProvider struct {
	results []sequenceE911AKAResult
	rands   [][]byte
	autns   [][]byte
	calls   int
}

func (p *sequenceE911AKAProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	p.calls++
	p.rands = append(p.rands, append([]byte(nil), rand16...))
	p.autns = append(p.autns, append([]byte(nil), autn16...))
	if len(p.results) == 0 {
		return sim.AKAResult{}, nil
	}
	next := p.results[0]
	p.results = p.results[1:]
	return next.result, next.err
}
