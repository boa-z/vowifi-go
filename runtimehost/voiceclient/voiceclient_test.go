package voiceclient

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/engine/sim"
)

func TestParseWWWAuthenticate(t *testing.T) {
	ch, err := ParseWWWAuthenticate(`Digest realm="ims.mnc280.mcc310.3gppnetwork.org", nonce="abc,123", algorithm=AKAv1-MD5, qop="auth,auth-int", opaque="opq"`)
	if err != nil {
		t.Fatalf("ParseWWWAuthenticate() error = %v", err)
	}
	if ch.Realm != "ims.mnc280.mcc310.3gppnetwork.org" || ch.Nonce != "abc,123" || ch.Algorithm != "AKAv1-MD5" || ch.QOP != "auth" || ch.Opaque != "opq" {
		t.Fatalf("challenge=%+v", ch)
	}
}

func TestExtractAKAChallengeNonce(t *testing.T) {
	raw := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	rand16, autn16, ok := ExtractAKAChallengeNonce(base64.StdEncoding.EncodeToString(raw))
	if !ok {
		t.Fatal("ExtractAKAChallengeNonce() ok=false")
	}
	if got := strings.ToUpper(hex.EncodeToString(rand16)); got != strings.ToUpper(hex.EncodeToString(bytesFrom(0x10, 16))) {
		t.Fatalf("RAND=%s", got)
	}
	if got := strings.ToUpper(hex.EncodeToString(autn16)); got != strings.ToUpper(hex.EncodeToString(bytesFrom(0x40, 16))) {
		t.Fatalf("AUTN=%s", got)
	}
}

func TestBuildDigestAuthorizationRFC2617Vector(t *testing.T) {
	ch := DigestChallenge{
		Realm:     "testrealm@host.com",
		Nonce:     "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		Algorithm: "MD5",
		QOP:       "auth",
		Opaque:    "5ccc069c403ebaf9f0171e9517f40e41",
	}
	got, err := BuildDigestAuthorization(ch, DigestAuthInput{
		Method:   "GET",
		URI:      "/dir/index.html",
		Username: "Mufasa",
		Password: "Circle Of Life",
		CNonce:   "0a4f113b",
		NC:       1,
	})
	if err != nil {
		t.Fatalf("BuildDigestAuthorization() error = %v", err)
	}
	if !strings.Contains(got, `response="6629fae49393a05397450978507c4ef1"`) {
		t.Fatalf("authorization=%s", got)
	}
	if !strings.Contains(got, `qop=auth`) || !strings.Contains(got, `nc=00000001`) {
		t.Fatalf("authorization missing qop/nc: %s", got)
	}
}

func TestBuildDigestAuthorizationAuthInt(t *testing.T) {
	ch := DigestChallenge{
		Realm:     "ims.example",
		Nonce:     "nonce-auth-int",
		Algorithm: "MD5",
		QOP:       "auth-int",
	}
	body := []byte("hello")
	got, err := BuildDigestAuthorization(ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce",
		NC:       9,
		Body:     body,
	})
	if err != nil {
		t.Fatalf("BuildDigestAuthorization(auth-int) error = %v", err)
	}
	ha1 := md5Hex("impi@example:ims.example:secret")
	ha2 := md5Hex("REGISTER:sip:ims.example:" + md5HexBytes(body))
	wantResponse := md5Hex(ha1 + ":nonce-auth-int:00000009:cnonce:auth-int:" + ha2)
	if !strings.Contains(got, `qop=auth-int`) || !strings.Contains(got, `nc=00000009`) || !strings.Contains(got, `response="`+wantResponse+`"`) {
		t.Fatalf("Authorization=%s", got)
	}
}

func TestBuildAKADigestPasswordAKAv2(t *testing.T) {
	aka := sim.AKAResult{
		RES: []byte{0x01, 0x02, 0x03, 0x04},
		IK:  bytesFrom(0x20, 16),
		CK:  bytesFrom(0x40, 16),
	}
	got, err := BuildAKADigestPassword("AKAv2-MD5", aka)
	if err != nil {
		t.Fatalf("BuildAKADigestPassword() error = %v", err)
	}
	key := append(append(append([]byte(nil), aka.RES...), aka.IK...), aka.CK...)
	mac := hmac.New(md5.New, key)
	_, _ = mac.Write([]byte("http-digest-akav2-password"))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("AKAv2 password=%q, want %q", got, want)
	}
}

func TestBuildDigestAuthorizationIncludesAUTS(t *testing.T) {
	ch := DigestChallenge{
		Realm:     "ims.example",
		Nonce:     "nonce-sync",
		Algorithm: "AKAv1-MD5",
		QOP:       "auth",
	}
	auts := bytesFrom(0xA0, 14)
	got, err := BuildDigestAuthorization(ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "ignored-for-sync-failure",
		CNonce:   "cnonce",
		NC:       1,
		AUTS:     auts,
	})
	if err != nil {
		t.Fatalf("BuildDigestAuthorization() error = %v", err)
	}
	ha1 := md5Hex("impi@example:ims.example:")
	ha2 := md5Hex("REGISTER:sip:ims.example")
	wantResponse := md5Hex(ha1 + ":nonce-sync:00000001:cnonce:auth:" + ha2)
	if !strings.Contains(got, `auts="`+base64.StdEncoding.EncodeToString(auts)+`"`) || !strings.Contains(got, `response="`+wantResponse+`"`) {
		t.Fatalf("Authorization=%s", got)
	}
}

func TestBuildRegisterHeaders(t *testing.T) {
	headers := BuildRegisterHeaders(IMSProfile{
		IMPI:      "310280233641503@private.att.net",
		IMPU:      "sip:310280233641503@one.att.net",
		Domain:    "one.att.net",
		UserAgent: "VoHive",
	}, "sip:310280233641503@192.0.2.10:5060", "call-1", "1")
	if headers["To"] != "<sip:310280233641503@one.att.net>" || headers["CSeq"] != "1 REGISTER" {
		t.Fatalf("headers=%+v", headers)
	}
	if !strings.Contains(headers["Security-Client"], "ipsec-3gpp") {
		t.Fatalf("Security-Client=%q", headers["Security-Client"])
	}
	if strings.Contains(headers["Security-Client"], "spi-c=0") || strings.Contains(headers["Security-Client"], "spi-s=0") ||
		!strings.Contains(headers["Security-Client"], "port-c=5062") || !strings.Contains(headers["Security-Client"], "port-s=5063") {
		t.Fatalf("Security-Client has invalid default proposal: %q", headers["Security-Client"])
	}
	if !strings.Contains(headers["Allow"], "INFO") {
		t.Fatalf("Allow=%q", headers["Allow"])
	}
}

func TestParseAndSelectSecurityAgreement(t *testing.T) {
	values := []string{`ipsec-3gpp;q=0.1;alg=hmac-sha-1-96;ealg=null;spi-c=111;spi-s=222;port-c=5062;port-s=5063, ipsec-3gpp;q=0.9;alg=hmac-md5-96;ealg=null;spi-c=333;spi-s=444;port-c=5064;port-s=5065`}
	selected, ok := SelectSecurityAgreement(values, SecurityAgreement{
		Protocol:            "ipsec-3gpp",
		Algorithm:           "hmac-md5-96",
		EncryptionAlgorithm: "null",
	})
	if !ok {
		t.Fatal("SelectSecurityAgreement() ok=false")
	}
	if selected.SPIClient != 333 || selected.SPIServer != 444 || selected.PortClient != 5064 || selected.PortServer != 5065 ||
		selected.Algorithm != "hmac-md5-96" || selected.Parameters["q"] != "0.9" {
		t.Fatalf("selected=%+v", selected)
	}
	client := BuildSecurityClientHeader(SecurityAgreement{SPIClient: 7001, SPIServer: 7002, PortClient: 6000, PortServer: 6001})
	if client != "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=7001;spi-s=7002;port-c=6000;port-s=6001" {
		t.Fatalf("Security-Client=%q", client)
	}
}

func TestSelectSecurityAgreementSkipsIncompatibleOffers(t *testing.T) {
	values := []string{
		`tls;q=1.0;alg=hmac-sha-1-96;ealg=null;spi-c=900;spi-s=901;port-c=5070;port-s=5071`,
		`ipsec-3gpp;q=0.1;alg=hmac-sha-1-96;ealg=null;spi-c=111;spi-s=222;port-c=5062;port-s=5063`,
		`ipsec-3gpp;q=0.9;alg=hmac-md5-96;ealg=null;spi-c=333;spi-s=444;port-c=5064;port-s=5065`,
	}
	selected, ok := SelectSecurityAgreement(values, SecurityAgreement{
		Protocol:            "ipsec-3gpp",
		Algorithm:           "hmac-sha-1-96",
		EncryptionAlgorithm: "null",
	})
	if !ok {
		t.Fatal("SelectSecurityAgreement() ok=false")
	}
	if selected.Protocol != "ipsec-3gpp" || selected.Algorithm != "hmac-sha-1-96" || selected.SPIClient != 111 {
		t.Fatalf("selected=%+v", selected)
	}

	if selected, ok := SelectSecurityAgreement([]string{
		`tls;q=1.0;alg=hmac-sha-1-96;ealg=null;spi-c=900;spi-s=901`,
		`ipsec-3gpp;q=0.9;alg=hmac-md5-96;ealg=null;spi-c=333;spi-s=444`,
	}, SecurityAgreement{Protocol: "ipsec-3gpp", Algorithm: "hmac-sha-1-96", EncryptionAlgorithm: "null"}); ok {
		t.Fatalf("SelectSecurityAgreement() selected incompatible offer: %+v", selected)
	}
}

func TestRegisterSessionHandlesAKAv1MD5Challenge(t *testing.T) {
	rawNonce := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	challenge := `Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {challenge},
				"Security-Server":  {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=111;spi-s=222;port-c=5062;port-s=5063`},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"P-Associated-URI": {`<sip:user@example>, <tel:+18005551212>`},
				"Service-Route":    {`<sip:pcscf1.example;lr>, <sip:pcscf2.example;lr>`},
				"Contact":          {`<sip:user@192.0.2.10:5060>;expires=1800`},
			},
		},
	}}
	aka := &registerAKAProvider{}
	result, err := RegisterSession{
		Transport:    transport,
		AKAProvider:  aka,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-1",
		CNonce:       "cnonce",
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !result.Registered || result.Attempts != 2 {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests=%d, want 2", len(transport.requests))
	}
	auth := transport.requests[1].Headers["Authorization"]
	if !strings.Contains(auth, `algorithm=AKAv1-MD5`) || !strings.Contains(auth, `username="impi@example"`) {
		t.Fatalf("Authorization=%s", auth)
	}
	ch, _ := ParseWWWAuthenticate(challenge)
	wantAuth, err := BuildDigestAuthorization(ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: string([]byte{0xAA, 0xBB, 0xCC, 0xDD}),
		CNonce:   "cnonce",
		NC:       1,
	})
	if err != nil {
		t.Fatalf("BuildDigestAuthorization() error = %v", err)
	}
	if auth != wantAuth {
		t.Fatalf("Authorization=%s, want binary RES digest %s", auth, wantAuth)
	}
	if got := transport.requests[1].Headers["Security-Verify"]; !strings.Contains(got, "spi-c=111") {
		t.Fatalf("Security-Verify=%q", got)
	}
	if first, second := transport.requests[0].Headers["Security-Client"], transport.requests[1].Headers["Security-Client"]; first == "" || first != second || strings.Contains(first, "spi-c=0") {
		t.Fatalf("Security-Client not stable/non-zero: first=%q second=%q", first, second)
	}
	if result.Binding.PublicIdentity != "sip:user@example" || result.Binding.Expires != 1800 || len(result.Binding.ServiceRoutes) != 2 {
		t.Fatalf("binding=%+v", result.Binding)
	}
	if result.Binding.SecurityClient != transport.requests[0].Headers["Security-Client"] ||
		len(result.Binding.SecurityServer) != 1 ||
		result.Binding.SecurityAgreement.SPIClient != 111 ||
		result.Binding.SecurityAgreement.SPIServer != 222 ||
		result.Binding.SecurityAgreement.PortClient != 5062 ||
		result.Binding.SecurityAgreement.PortServer != 5063 {
		t.Fatalf("security binding=%+v", result.Binding)
	}
	if got := strings.ToUpper(hex.EncodeToString(aka.rand)); got != strings.ToUpper(hex.EncodeToString(bytesFrom(0x10, 16))) {
		t.Fatalf("RAND=%s", got)
	}
}

func TestRegisterSessionHandlesAKASynchronizationFailure(t *testing.T) {
	firstNonce := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	secondNonce := append(bytesFrom(0x60, 16), bytesFrom(0x80, 16)...)
	firstChallenge := `Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(firstNonce) + `", algorithm=AKAv1-MD5, qop="auth"`
	secondChallenge := `Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(secondNonce) + `", algorithm=AKAv1-MD5, qop="auth"`
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {firstChallenge},
				"Security-Server":  {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=111;spi-s=222;port-c=5062;port-s=5063`},
			},
		},
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {secondChallenge},
				"Security-Server":  {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=333;spi-s=444;port-c=5064;port-s=5065`},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"P-Associated-URI": {`<sip:user@example>`},
				"Contact":          {`<sip:user@192.0.2.10:5060>;expires=1200`},
			},
		},
	}}
	auts := bytesFrom(0xC0, 14)
	aka := &syncFailureAKAProvider{auts: auts}
	result, err := RegisterSession{
		Transport:    transport,
		AKAProvider:  aka,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-sync",
		CNonce:       "cnonce",
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !result.Registered || result.Attempts != 3 || result.Binding.Expires != 1200 {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 3 {
		t.Fatalf("requests=%d, want 3", len(transport.requests))
	}
	syncAuth := transport.requests[1].Headers["Authorization"]
	if !strings.Contains(syncAuth, `auts="`+base64.StdEncoding.EncodeToString(auts)+`"`) || transport.requests[1].Headers["CSeq"] != "2 REGISTER" {
		t.Fatalf("sync REGISTER auth=%s headers=%+v", syncAuth, transport.requests[1].Headers)
	}
	finalAuth := transport.requests[2].Headers["Authorization"]
	if strings.Contains(finalAuth, `auts=`) || transport.requests[2].Headers["CSeq"] != "3 REGISTER" {
		t.Fatalf("final REGISTER auth=%s headers=%+v", finalAuth, transport.requests[2].Headers)
	}
	if got := transport.requests[2].Headers["Security-Verify"]; !strings.Contains(got, "spi-c=333") {
		t.Fatalf("Security-Verify=%q", got)
	}
	if result.Binding.SecurityAgreement.SPIClient != 333 || result.Binding.SecurityAgreement.SPIServer != 444 ||
		len(result.Binding.SecurityServer) != 1 || !strings.Contains(result.Binding.SecurityServer[0], "spi-c=333") {
		t.Fatalf("security binding=%+v", result.Binding)
	}
	if len(aka.rands) != 2 || !bytesEqual(aka.rands[1], bytesFrom(0x60, 16)) {
		t.Fatalf("AKA rands=%x", aka.rands)
	}
}

func TestRegisterSessionRetriesMinExpiresBeforeChallenge(t *testing.T) {
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 423,
			Reason:     "Interval Too Brief",
			Headers:    map[string][]string{"Min-Expires": {"1200"}},
		},
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce-min", algorithm=MD5, qop="auth"`},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
		},
	}}
	result, err := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-min",
		CNonce:       "cnonce",
		Expires:      600,
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !result.Registered || result.Attempts != 3 || result.Binding.Expires != 1200 {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 3 {
		t.Fatalf("requests=%d, want 3", len(transport.requests))
	}
	if transport.requests[0].Headers["Expires"] != "600" || transport.requests[0].Headers["CSeq"] != "1 REGISTER" {
		t.Fatalf("first request=%+v", transport.requests[0].Headers)
	}
	if transport.requests[1].Headers["Expires"] != "1200" || transport.requests[1].Headers["CSeq"] != "2 REGISTER" || transport.requests[1].Headers["Authorization"] != "" {
		t.Fatalf("min-expires retry=%+v", transport.requests[1].Headers)
	}
	if transport.requests[2].Headers["Expires"] != "1200" || transport.requests[2].Headers["CSeq"] != "3 REGISTER" || !strings.Contains(transport.requests[2].Headers["Authorization"], "Digest") {
		t.Fatalf("auth request=%+v", transport.requests[2].Headers)
	}
}

func TestRegisterSessionRetriesAuthenticatedMinExpires(t *testing.T) {
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce-auth-min", algorithm=MD5, qop="auth"`},
				"Security-Server":  {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=555;spi-s=666`},
			},
		},
		{
			StatusCode: 423,
			Reason:     "Interval Too Brief",
			Headers:    map[string][]string{"Min-Expires": {"900"}},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
		},
	}}
	result, err := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-auth-min",
		CNonce:       "cnonce",
		Expires:      600,
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !result.Registered || result.Attempts != 3 || result.Binding.Expires != 900 {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 3 {
		t.Fatalf("requests=%d, want 3", len(transport.requests))
	}
	if transport.requests[1].Headers["Expires"] != "600" || transport.requests[1].Headers["CSeq"] != "2 REGISTER" || !strings.Contains(transport.requests[1].Headers["Authorization"], "nc=00000001") {
		t.Fatalf("first auth request=%+v", transport.requests[1].Headers)
	}
	if transport.requests[2].Headers["Expires"] != "900" || transport.requests[2].Headers["CSeq"] != "3 REGISTER" || !strings.Contains(transport.requests[2].Headers["Authorization"], "nc=00000002") {
		t.Fatalf("min-expires auth retry=%+v", transport.requests[2].Headers)
	}
	if got := transport.requests[2].Headers["Security-Verify"]; !strings.Contains(got, "spi-c=555") {
		t.Fatalf("Security-Verify=%q", got)
	}
}

func TestRegisterSessionFallsBackToSupportedDigestChallenge(t *testing.T) {
	rawNonce := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {
					`Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv2-MD5, qop="auth-conf"`,
					`Digest realm="ims.example", nonce="md5nonce", algorithm=MD5, qop="auth"`,
				},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers:    map[string][]string{"Contact": {`<sip:user@192.0.2.10:5060>;expires=1800`}},
		},
	}}
	result, err := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-qop-fallback",
		CNonce:       "cnonce",
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !result.Registered || result.Challenge.Algorithm != "MD5" || result.Challenge.QOP != "auth" {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests=%d, want 2", len(transport.requests))
	}
	auth := transport.requests[1].Headers["Authorization"]
	if !strings.Contains(auth, `algorithm=MD5`) || !strings.Contains(auth, `nonce="md5nonce"`) || !strings.Contains(auth, `qop=auth`) {
		t.Fatalf("Authorization=%s", auth)
	}
}

func TestRegisterSessionHandlesAuthIntDigestChallenge(t *testing.T) {
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce-auth-int", algorithm=MD5, qop="auth-int"`},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers:    map[string][]string{"Contact": {`<sip:user@192.0.2.10:5060>;expires=1800`}},
		},
	}}
	result, err := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-auth-int",
		CNonce:       "cnonce",
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !result.Registered || result.Challenge.QOP != "auth-int" {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests=%d, want 2", len(transport.requests))
	}
	auth := transport.requests[1].Headers["Authorization"]
	ha1 := md5Hex("impi@example:ims.example:")
	ha2 := md5Hex("REGISTER:sip:ims.example:" + md5HexBytes(nil))
	wantResponse := md5Hex(ha1 + ":nonce-auth-int:00000001:cnonce:auth-int:" + ha2)
	if !strings.Contains(auth, `qop=auth-int`) || !strings.Contains(auth, `response="`+wantResponse+`"`) {
		t.Fatalf("Authorization=%s", auth)
	}
}

func TestRegisterSessionDeregisterRetriesDigestChallenge(t *testing.T) {
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce-dereg", algorithm=MD5, qop="auth"`},
				"Security-Server":  {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=701;spi-s=702;port-c=5068;port-s=5069`},
			},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	session := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-dereg",
		CNonce:       "cnonce",
	}
	result, err := session.Deregister(context.Background(), DeregisterRequest{
		Binding: RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			SecurityClient: "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=101;spi-s=102;port-c=5062;port-s=5063",
			SecurityVerify: []string{"ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=501;spi-s=502;port-c=5064;port-s=5065"},
		},
		CSeq: 9,
	})
	if err != nil {
		t.Fatalf("Deregister() error = %v", err)
	}
	if !result.Deregistered || result.Attempts != 2 || result.StatusCode != 200 {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests=%d, want 2", len(transport.requests))
	}
	first := transport.requests[0].Headers
	if first["Expires"] != "0" || first["CSeq"] != "9 REGISTER" || !strings.Contains(first["Contact"], "expires=0") ||
		first["Security-Client"] != "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=101;spi-s=102;port-c=5062;port-s=5063" ||
		!strings.Contains(first["Security-Verify"], "spi-c=501") {
		t.Fatalf("first deregister headers=%+v", first)
	}
	second := transport.requests[1].Headers
	if second["Expires"] != "0" || second["CSeq"] != "10 REGISTER" || !strings.Contains(second["Authorization"], `nonce="nonce-dereg"`) ||
		!strings.Contains(second["Security-Verify"], "spi-c=701") {
		t.Fatalf("second deregister headers=%+v", second)
	}
}

func TestRegisterSessionRefreshUsesExistingBindingAndAuth(t *testing.T) {
	transport := &fakeRegisterTransport{responses: []RegisterResponse{{
		StatusCode: 200,
		Reason:     "OK",
		Headers: map[string][]string{
			"Contact": {`<sip:user@192.0.2.10:5060>;expires=900`},
		},
	}}}
	session := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-refresh",
		CNonce:       "cnonce",
	}
	result, err := session.Refresh(context.Background(), RefreshRequest{
		Binding: RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			Expires:        1200,
			SecurityClient: "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=101;spi-s=102;port-c=5062;port-s=5063",
			SecurityVerify: []string{"ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=501;spi-s=502;port-c=5064;port-s=5065"},
		},
		CSeq:           7,
		AuthHeader:     `Digest username="impi@example"`,
		AuthHeaderName: "Authorization",
	})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if !result.Refreshed || result.NextCSeq != 8 || result.Binding.Expires != 900 || result.AuthHeader == "" {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 1 {
		t.Fatalf("requests=%d, want 1", len(transport.requests))
	}
	headers := transport.requests[0].Headers
	if headers["Expires"] != "1200" || headers["CSeq"] != "7 REGISTER" || headers["Authorization"] != `Digest username="impi@example"` ||
		!strings.Contains(headers["Security-Verify"], "spi-c=501") || headers["Security-Client"] == "" {
		t.Fatalf("refresh headers=%+v", headers)
	}
}

func TestRegisterSessionRefreshAndDeregisterAdvanceDigestNonceCount(t *testing.T) {
	rawNonce := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	challenge := `Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {challenge},
				"Security-Server":  {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=701;spi-s=702;port-c=5068;port-s=5069`},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"P-Associated-URI": {`<sip:user@example>`},
				"Contact":          {`<sip:user@192.0.2.10:5060>;expires=1200`},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Contact": {`<sip:user@192.0.2.10:5060>;expires=900`},
			},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	session := RegisterSession{
		Transport:    transport,
		AKAProvider:  &registerAKAProvider{},
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-auth-state",
		CNonce:       "cnonce",
	}
	registered, err := session.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !registered.Registered || !registered.AuthState.Usable() || registered.AuthState.nextNC != 2 {
		t.Fatalf("registered=%+v", registered)
	}
	refreshed, err := session.Refresh(context.Background(), RefreshRequest{
		Binding:        registered.Binding,
		CSeq:           registered.NextCSeq,
		AuthHeader:     registered.AuthHeader,
		AuthHeaderName: registered.AuthHeaderName,
		AuthState:      registered.AuthState,
	})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if !refreshed.Refreshed || !refreshed.AuthState.Usable() || refreshed.AuthState.nextNC != 3 {
		t.Fatalf("refreshed=%+v", refreshed)
	}
	deregistered, err := session.Deregister(context.Background(), DeregisterRequest{
		Binding:        refreshed.Binding,
		CSeq:           refreshed.NextCSeq,
		AuthHeader:     refreshed.AuthHeader,
		AuthHeaderName: refreshed.AuthHeaderName,
		AuthState:      refreshed.AuthState,
	})
	if err != nil {
		t.Fatalf("Deregister() error = %v", err)
	}
	if !deregistered.Deregistered {
		t.Fatalf("deregistered=%+v", deregistered)
	}
	if len(transport.requests) != 4 {
		t.Fatalf("requests=%d, want 4", len(transport.requests))
	}
	if auth := transport.requests[1].Headers["Authorization"]; !strings.Contains(auth, "nc=00000001") {
		t.Fatalf("register Authorization=%s", auth)
	}
	if auth := transport.requests[2].Headers["Authorization"]; !strings.Contains(auth, "nc=00000002") || auth == registered.AuthHeader {
		t.Fatalf("refresh Authorization=%s registered=%s", auth, registered.AuthHeader)
	}
	if auth := transport.requests[3].Headers["Authorization"]; !strings.Contains(auth, "nc=00000003") {
		t.Fatalf("deregister Authorization=%s", auth)
	}
	if transport.requests[2].Headers["CSeq"] != "3 REGISTER" || transport.requests[3].Headers["CSeq"] != "4 REGISTER" {
		t.Fatalf("CSeq refresh=%q deregister=%q", transport.requests[2].Headers["CSeq"], transport.requests[3].Headers["CSeq"])
	}
}

func TestRegisterSessionUsesAuthenticationInfoNextNonce(t *testing.T) {
	firstRspauth := mustTestDigestRspauth(t, DigestChallenge{Realm: "ims.example", Nonce: "nonce-one", Algorithm: "MD5", QOP: "auth"}, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		CNonce:   "cnonce",
		NC:       1,
	}, nil)
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce-one", algorithm=MD5, qop="auth"`},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Authentication-Info": {`nextnonce="nonce-two", qop=auth, rspauth="` + firstRspauth + `"`},
				"Contact":             {`<sip:user@192.0.2.10:5060>;expires=1200`},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Authentication-Info": {`nextnonce=nonce-three`},
				"Contact":             {`<sip:user@192.0.2.10:5060>;expires=900`},
			},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	session := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-nextnonce",
		CNonce:       "cnonce",
	}
	registered, err := session.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !registered.Registered || registered.AuthState.challenge.Nonce != "nonce-two" || registered.AuthState.nextNC != 1 {
		t.Fatalf("registered=%+v authState=%+v", registered, registered.AuthState)
	}
	refreshed, err := session.Refresh(context.Background(), RefreshRequest{
		Binding:        registered.Binding,
		CSeq:           registered.NextCSeq,
		AuthHeader:     registered.AuthHeader,
		AuthHeaderName: registered.AuthHeaderName,
		AuthState:      registered.AuthState,
	})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if !refreshed.Refreshed || refreshed.AuthState.challenge.Nonce != "nonce-three" || refreshed.AuthState.nextNC != 1 {
		t.Fatalf("refreshed=%+v authState=%+v", refreshed, refreshed.AuthState)
	}
	deregistered, err := session.Deregister(context.Background(), DeregisterRequest{
		Binding:        refreshed.Binding,
		CSeq:           refreshed.NextCSeq,
		AuthHeader:     refreshed.AuthHeader,
		AuthHeaderName: refreshed.AuthHeaderName,
		AuthState:      refreshed.AuthState,
	})
	if err != nil {
		t.Fatalf("Deregister() error = %v", err)
	}
	if !deregistered.Deregistered {
		t.Fatalf("deregistered=%+v", deregistered)
	}
	if len(transport.requests) != 4 {
		t.Fatalf("requests=%d, want 4", len(transport.requests))
	}
	if auth := transport.requests[1].Headers["Authorization"]; !strings.Contains(auth, `nonce="nonce-one"`) || !strings.Contains(auth, "nc=00000001") {
		t.Fatalf("register Authorization=%s", auth)
	}
	if auth := transport.requests[2].Headers["Authorization"]; !strings.Contains(auth, `nonce="nonce-two"`) || !strings.Contains(auth, "nc=00000001") {
		t.Fatalf("refresh Authorization=%s", auth)
	}
	if auth := transport.requests[3].Headers["Authorization"]; !strings.Contains(auth, `nonce="nonce-three"`) || !strings.Contains(auth, "nc=00000001") {
		t.Fatalf("deregister Authorization=%s", auth)
	}
}

func TestRegisterSessionRejectsInvalidRspauth(t *testing.T) {
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce-one", algorithm=MD5, qop="auth"`},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Authentication-Info": {`rspauth="bad"`},
				"Contact":             {`<sip:user@192.0.2.10:5060>;expires=1200`},
			},
		},
	}}
	result, err := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-bad-rspauth",
		CNonce:       "cnonce",
	}.Register(context.Background())
	if !errors.Is(err, ErrInvalidAuthenticationInfo) {
		t.Fatalf("Register() err=%v, want ErrInvalidAuthenticationInfo", err)
	}
	if result.Registered || result.StatusCode != 200 {
		t.Fatalf("result=%+v", result)
	}
}

func TestRegisterSessionRefreshRetriesDigestChallenge(t *testing.T) {
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce-refresh", algorithm=MD5, qop="auth"`},
				"Security-Server":  {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=701;spi-s=702;port-c=5068;port-s=5069`},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Contact": {`<sip:user@192.0.2.10:5060>;expires=600`},
			},
		},
	}}
	session := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-refresh-challenge",
		CNonce:       "cnonce",
	}
	result, err := session.Refresh(context.Background(), RefreshRequest{
		Binding: RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			Expires:        600,
			SecurityClient: "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=101;spi-s=102;port-c=5062;port-s=5063",
		},
		CSeq: 11,
	})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if !result.Refreshed || result.Attempts != 2 || result.NextCSeq != 13 || result.AuthHeaderName != "Authorization" ||
		result.Binding.SecurityAgreement.SPIClient != 701 {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests=%d, want 2", len(transport.requests))
	}
	first := transport.requests[0].Headers
	if first["Expires"] != "600" || first["CSeq"] != "11 REGISTER" || first["Authorization"] != "" {
		t.Fatalf("first refresh headers=%+v", first)
	}
	second := transport.requests[1].Headers
	if second["Expires"] != "600" || second["CSeq"] != "12 REGISTER" || !strings.Contains(second["Authorization"], `nonce="nonce-refresh"`) ||
		!strings.Contains(second["Security-Verify"], "spi-c=701") {
		t.Fatalf("second refresh headers=%+v", second)
	}
}

func TestRegisterSessionRefreshRetriesMinExpiresWithAuthState(t *testing.T) {
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 423,
			Reason:     "Interval Too Brief",
			Headers:    map[string][]string{"Min-Expires": {"1200"}},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Contact": {`<sip:user@192.0.2.10:5060>;expires=1200`},
			},
		},
	}}
	ch := DigestChallenge{Realm: "ims.example", Nonce: "nonce-refresh-min", Algorithm: "MD5", QOP: "auth"}
	authState := newDigestAuthState("Authorization", ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		CNonce:   "cnonce",
		NC:       1,
	}, "")
	session := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-refresh-min",
		CNonce:       "cnonce",
	}
	result, err := session.Refresh(context.Background(), RefreshRequest{
		Binding: RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			Expires:        600,
			SecurityVerify: []string{"ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=501;spi-s=502;port-c=5064;port-s=5065"},
		},
		CSeq:      7,
		AuthState: authState,
	})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if !result.Refreshed || result.Attempts != 2 || result.NextCSeq != 9 || result.Binding.Expires != 1200 || result.AuthState.nextNC != 4 {
		t.Fatalf("result=%+v authState=%+v", result, result.AuthState)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests=%d, want 2", len(transport.requests))
	}
	first := transport.requests[0].Headers
	if first["Expires"] != "600" || first["CSeq"] != "7 REGISTER" || !strings.Contains(first["Authorization"], "nc=00000002") {
		t.Fatalf("first refresh headers=%+v", first)
	}
	second := transport.requests[1].Headers
	if second["Expires"] != "1200" || second["CSeq"] != "8 REGISTER" ||
		!strings.Contains(second["Authorization"], "nc=00000003") ||
		!strings.Contains(second["Security-Verify"], "spi-c=501") {
		t.Fatalf("min-expires refresh retry headers=%+v", second)
	}
}

func TestRegisterSessionRefreshRetriesMinExpiresAfterChallenge(t *testing.T) {
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce-refresh-min-challenge", algorithm=MD5, qop="auth"`},
				"Security-Server":  {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=701;spi-s=702;port-c=5068;port-s=5069`},
			},
		},
		{
			StatusCode: 423,
			Reason:     "Interval Too Brief",
			Headers:    map[string][]string{"Min-Expires": {"900"}},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Contact": {`<sip:user@192.0.2.10:5060>;expires=900`},
			},
		},
	}}
	session := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-refresh-min-challenge",
		CNonce:       "cnonce",
	}
	result, err := session.Refresh(context.Background(), RefreshRequest{
		Binding: RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			Expires:        600,
			SecurityClient: "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=101;spi-s=102;port-c=5062;port-s=5063",
		},
		CSeq: 11,
	})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if !result.Refreshed || result.Attempts != 3 || result.NextCSeq != 14 || result.Binding.Expires != 900 || result.AuthState.nextNC != 3 {
		t.Fatalf("result=%+v authState=%+v", result, result.AuthState)
	}
	if len(transport.requests) != 3 {
		t.Fatalf("requests=%d, want 3", len(transport.requests))
	}
	if first := transport.requests[0].Headers; first["Expires"] != "600" || first["CSeq"] != "11 REGISTER" || first["Authorization"] != "" {
		t.Fatalf("first refresh headers=%+v", first)
	}
	second := transport.requests[1].Headers
	if second["Expires"] != "600" || second["CSeq"] != "12 REGISTER" ||
		!strings.Contains(second["Authorization"], "nc=00000001") ||
		!strings.Contains(second["Security-Verify"], "spi-c=701") {
		t.Fatalf("challenged refresh headers=%+v", second)
	}
	third := transport.requests[2].Headers
	if third["Expires"] != "900" || third["CSeq"] != "13 REGISTER" ||
		!strings.Contains(third["Authorization"], "nc=00000002") ||
		!strings.Contains(third["Security-Verify"], "spi-c=701") {
		t.Fatalf("min-expires challenged refresh retry headers=%+v", third)
	}
}

func TestRegisterSessionRefreshReturnsRetryAfter(t *testing.T) {
	transport := &fakeRegisterTransport{responses: []RegisterResponse{{
		StatusCode: 503,
		Reason:     "Service Unavailable",
		Headers:    map[string][]string{"Retry-After": {"4"}},
	}}}
	session := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-refresh-retry-after",
	}
	result, err := session.Refresh(context.Background(), RefreshRequest{
		Binding: RegistrationBinding{ContactURI: "sip:user@192.0.2.10:5060"},
		CSeq:    7,
	})
	if err == nil || !errors.Is(err, ErrRegistrationRejected) {
		t.Fatalf("Refresh() result=%+v err=%v, want registration rejection", result, err)
	}
	if result.StatusCode != 503 || result.RetryAfter != 4*time.Second {
		t.Fatalf("Refresh() result=%+v, want RetryAfter=4s", result)
	}
}

func TestSelectDigestChallengePrefersAKAv2(t *testing.T) {
	rawNonce := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	ch, err := SelectDigestChallenge(map[string][]string{
		"WWW-Authenticate": {
			`Digest realm="ims.example", nonce="md5nonce", algorithm=MD5`,
			`Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv2-MD5, qop="auth"`,
			`Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`,
		},
	}, "WWW-Authenticate")
	if err != nil {
		t.Fatalf("SelectDigestChallenge() error = %v", err)
	}
	if ch.Algorithm != "AKAv2-MD5" {
		t.Fatalf("challenge=%+v, want AKAv2-MD5", ch)
	}
}

func TestSelectDigestChallengeSupportsAuthInt(t *testing.T) {
	rawNonce := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	ch, err := SelectDigestChallenge(map[string][]string{
		"WWW-Authenticate": {
			`Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv2-MD5, qop="auth-int"`,
			`Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`,
		},
	}, "WWW-Authenticate")
	if err != nil {
		t.Fatalf("SelectDigestChallenge() error = %v", err)
	}
	if ch.Algorithm != "AKAv2-MD5" || ch.QOP != "auth-int" {
		t.Fatalf("challenge=%+v, want AKAv2-MD5 auth-int", ch)
	}
}

func TestSelectDigestChallengeSkipsUnsupportedQOP(t *testing.T) {
	rawNonce := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	ch, err := SelectDigestChallenge(map[string][]string{
		"WWW-Authenticate": {
			`Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv2-MD5, qop="auth-conf"`,
			`Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`,
			`Digest realm="ims.example", nonce="md5nonce", algorithm=MD5, qop="auth"`,
		},
	}, "WWW-Authenticate")
	if err != nil {
		t.Fatalf("SelectDigestChallenge() error = %v", err)
	}
	if ch.Algorithm != "AKAv1-MD5" || ch.QOP != "auth" {
		t.Fatalf("challenge=%+v, want AKAv1-MD5 auth", ch)
	}
}

func TestDigestInfoNextNoncePrefersProxyAuthenticationInfo(t *testing.T) {
	got := digestInfoNextNonce(map[string][]string{
		"Authentication-Info":       {`nextnonce="origin-next"`},
		"Proxy-Authentication-Info": {`qop=auth, nextnonce="proxy-next"`},
	}, "Proxy-Authorization")
	if got != "proxy-next" {
		t.Fatalf("nextnonce=%q, want proxy-next", got)
	}
}

func TestBuildRegistrationBindingParsesIMSHeaders(t *testing.T) {
	binding := BuildRegistrationBinding(IMSProfile{IMPU: "sip:fallback@example"}, "sip:user@192.0.2.10:5060", RegisterResponse{
		Headers: map[string][]string{
			"P-Associated-URI": {`"User, One" <sip:user@example>, <tel:+18005551212>`},
			"Service-Route":    {`<sip:pcscf1.example;lr>, <sip:pcscf2.example;lr>`},
			"Path":             {`<sip:path.example;lr>`},
			"Security-Server":  {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=1;spi-s=2`},
			"Expires":          {`3600`},
			"Contact":          {`<sip:other@192.0.2.20:5060>;expires=111, <sip:user@192.0.2.10:5060;transport=udp>;expires=777`},
		},
	}, 3600)
	if binding.PublicIdentity != "sip:user@example" || len(binding.AssociatedURIs) != 2 {
		t.Fatalf("associated binding=%+v", binding)
	}
	if len(binding.ServiceRoutes) != 2 || binding.ServiceRoutes[1] != "<sip:pcscf2.example;lr>" {
		t.Fatalf("routes=%+v", binding.ServiceRoutes)
	}
	if binding.Expires != 777 || len(binding.SecurityVerify) != 1 || !strings.Contains(binding.RegistrarContact, "transport=udp") {
		t.Fatalf("binding=%+v", binding)
	}
}

func TestBuildRegistrationBindingFallsBackToExpiresHeader(t *testing.T) {
	binding := BuildRegistrationBinding(IMSProfile{IMPU: "sip:fallback@example"}, "sip:user@192.0.2.10:5060", RegisterResponse{
		Headers: map[string][]string{
			"Expires": {"900"},
			"Contact": {`<sip:other@192.0.2.20:5060>;expires=111, ` +
				`<sip:user@192.0.2.10:5060;transport=udp>`},
		},
	}, 3600)
	if binding.Expires != 900 || !strings.Contains(binding.RegistrarContact, "transport=udp") {
		t.Fatalf("binding=%+v", binding)
	}
}

func TestBuildRegistrationBindingDoesNotUseOtherContactExpires(t *testing.T) {
	binding := BuildRegistrationBinding(IMSProfile{IMPU: "sip:fallback@example"}, "sip:user@192.0.2.10:5060", RegisterResponse{
		Headers: map[string][]string{
			"Expires": {"1200"},
			"Contact": {`<sip:other@192.0.2.20:5060>;expires=111, ` +
				`<sip:another@192.0.2.30:5060>;expires=222`},
		},
	}, 3600)
	if binding.Expires != 1200 || !strings.Contains(binding.RegistrarContact, "sip:other@192.0.2.20") {
		t.Fatalf("binding=%+v", binding)
	}
}

func TestBuildIMSDialogRequestsUseRegistrationRouteSet(t *testing.T) {
	cfg := DialogRequestConfig{
		Profile: IMSProfile{UserAgent: "VoHive"},
		Registration: RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@example",
			ServiceRoutes:  []string{"<sip:pcscf1.example;lr>", "<sip:pcscf2.example;lr>"},
			SecurityVerify: []string{"ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=111;spi-s=222;port-c=5062;port-s=5063"},
		},
		RemoteURI:       "sip:+18005551212@ims.example",
		RemoteTargetURI: "sip:+18005551212@pcscf.example",
		CallID:          "call-1",
		LocalTag:        "ltag",
		RemoteTag:       "rtag",
		CSeq:            3,
		SessionExpires:  1800,
		MinSE:           90,
	}
	invite, err := BuildInviteRequest(cfg, []byte("v=0\r\n"))
	if err != nil {
		t.Fatalf("BuildInviteRequest() error = %v", err)
	}
	if invite.URI != "sip:+18005551212@pcscf.example" || invite.Headers["Route"] != "<sip:pcscf1.example;lr>, <sip:pcscf2.example;lr>" {
		t.Fatalf("invite=%+v", invite)
	}
	if !strings.Contains(invite.Headers["Security-Verify"], "spi-c=111") {
		t.Fatalf("invite Security-Verify=%q", invite.Headers["Security-Verify"])
	}
	if invite.Headers["From"] != "<sip:user@example>;tag=ltag" || invite.Headers["To"] != "<sip:+18005551212@ims.example>;tag=rtag" {
		t.Fatalf("dialog headers=%+v", invite.Headers)
	}
	if invite.Headers["Content-Type"] != "application/sdp" || invite.Headers["Session-Expires"] != "1800" || invite.Headers["Min-SE"] != "90" {
		t.Fatalf("invite headers=%+v", invite.Headers)
	}
	bye, err := BuildByeRequest(cfg)
	if err != nil {
		t.Fatalf("BuildByeRequest() error = %v", err)
	}
	if bye.Method != "BYE" || bye.Headers["CSeq"] != "3 BYE" || bye.Headers["Contact"] != "" {
		t.Fatalf("bye=%+v", bye)
	}
	if !strings.Contains(bye.Headers["Security-Verify"], "spi-c=111") {
		t.Fatalf("bye Security-Verify=%q", bye.Headers["Security-Verify"])
	}
	byeBody, err := BuildByeRequestWithBody(cfg, "application/vnd.3gpp.ussd+xml", []byte("<ussd-data/>"))
	if err != nil {
		t.Fatalf("BuildByeRequestWithBody() error = %v", err)
	}
	if byeBody.Method != "BYE" || byeBody.Headers["Content-Type"] != "application/vnd.3gpp.ussd+xml" || string(byeBody.Body) != "<ussd-data/>" {
		t.Fatalf("bye with body=%+v body=%q", byeBody, byeBody.Body)
	}
	update, err := BuildUpdateRequest(cfg, []byte("v=0\r\n"))
	if err != nil {
		t.Fatalf("BuildUpdateRequest() error = %v", err)
	}
	if update.Method != "UPDATE" || update.Headers["Contact"] != "<sip:user@192.0.2.10:5060>" || update.Headers["Content-Type"] != "application/sdp" || update.Headers["Session-Expires"] != "1800" || update.Headers["Min-SE"] != "90" {
		t.Fatalf("update=%+v", update)
	}
	prack, err := BuildPrackRequest(cfg, "1 1 INVITE")
	if err != nil {
		t.Fatalf("BuildPrackRequest() error = %v", err)
	}
	if prack.Method != "PRACK" || prack.Headers["RAck"] != "1 1 INVITE" || prack.Headers["CSeq"] != "3 PRACK" {
		t.Fatalf("prack=%+v", prack)
	}
	info, err := BuildInfoRequest(cfg, "application/vnd.3gpp.ussd+xml", []byte("<ussd-data/>"))
	if err != nil {
		t.Fatalf("BuildInfoRequest() error = %v", err)
	}
	if info.Method != "INFO" || info.Headers["CSeq"] != "3 INFO" || info.Headers["Contact"] != "<sip:user@192.0.2.10:5060>" || info.Headers["Content-Type"] != "application/vnd.3gpp.ussd+xml" {
		t.Fatalf("info=%+v", info)
	}
	message, err := BuildMessageRequest(cfg, "text/plain;charset=UTF-8", []byte("hello"))
	if err != nil {
		t.Fatalf("BuildMessageRequest() error = %v", err)
	}
	if message.Method != "MESSAGE" || message.Headers["CSeq"] != "3 MESSAGE" || message.Headers["Contact"] != "<sip:user@192.0.2.10:5060>" {
		t.Fatalf("message=%+v", message)
	}
	if message.Headers["Content-Type"] != "text/plain;charset=UTF-8" || message.Headers["P-Preferred-Service"] == "" || message.Headers["Accept-Contact"] == "" {
		t.Fatalf("message headers=%+v", message.Headers)
	}
	if !strings.Contains(message.Headers["Security-Verify"], "spi-c=111") {
		t.Fatalf("message Security-Verify=%q", message.Headers["Security-Verify"])
	}
	options, err := BuildOptionsRequest(cfg)
	if err != nil {
		t.Fatalf("BuildOptionsRequest() error = %v", err)
	}
	if options.Method != "OPTIONS" || options.Headers["Accept"] != "application/sdp" || options.Headers["Supported"] == "" {
		t.Fatalf("options=%+v", options)
	}
	if !strings.Contains(options.Headers["Security-Verify"], "spi-c=111") {
		t.Fatalf("options Security-Verify=%q", options.Headers["Security-Verify"])
	}
}

func TestBuildIMSDialogRequestsIncludeSessionRefresher(t *testing.T) {
	cfg := DialogRequestConfig{
		Profile:          IMSProfile{IMPU: "sip:user@example"},
		Registration:     RegistrationBinding{ContactURI: "sip:user@192.0.2.10:5060"},
		RemoteURI:        "sip:+18005551212@ims.example",
		RemoteTargetURI:  "sip:+18005551212@pcscf.example",
		CallID:           "call-timer",
		SessionExpires:   1800,
		SessionRefresher: "UAS",
	}
	invite, err := BuildInviteRequest(cfg, []byte("v=0\r\n"))
	if err != nil {
		t.Fatalf("BuildInviteRequest() error = %v", err)
	}
	if invite.Headers["Session-Expires"] != "1800;refresher=uas" {
		t.Fatalf("INVITE Session-Expires=%q", invite.Headers["Session-Expires"])
	}
	cfg.SessionRefresher = "invalid"
	update, err := BuildUpdateRequest(cfg, nil)
	if err != nil {
		t.Fatalf("BuildUpdateRequest() error = %v", err)
	}
	if update.Headers["Session-Expires"] != "1800" {
		t.Fatalf("UPDATE Session-Expires=%q", update.Headers["Session-Expires"])
	}
}

func TestRegisterSessionRejectsFailedSecondRegister(t *testing.T) {
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce", algorithm=MD5`},
			},
		},
		{StatusCode: 403, Reason: "Forbidden"},
	}}
	result, err := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
	}.Register(context.Background())
	if err == nil {
		t.Fatal("Register() err=nil, want rejection")
	}
	if result.Registered || result.StatusCode != 403 || result.Attempts != 2 {
		t.Fatalf("result=%+v", result)
	}
}

type fakeRegisterTransport struct {
	requests  []RegisterMessage
	responses []RegisterResponse
}

func (f *fakeRegisterTransport) RoundTripRegister(ctx context.Context, msg RegisterMessage) (RegisterResponse, error) {
	f.requests = append(f.requests, msg)
	if len(f.responses) == 0 {
		return RegisterResponse{StatusCode: 500, Reason: "empty"}, nil
	}
	resp := f.responses[0]
	f.responses = f.responses[1:]
	return resp, nil
}

type registerAKAProvider struct {
	rand []byte
	autn []byte
}

func (p *registerAKAProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	p.rand = append([]byte(nil), rand16...)
	p.autn = append([]byte(nil), autn16...)
	return sim.AKAResult{RES: []byte{0xAA, 0xBB, 0xCC, 0xDD}}, nil
}

type syncFailureAKAProvider struct {
	auts  []byte
	rands [][]byte
	autns [][]byte
}

func (p *syncFailureAKAProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	p.rands = append(p.rands, append([]byte(nil), rand16...))
	p.autns = append(p.autns, append([]byte(nil), autn16...))
	if len(p.rands) == 1 {
		return sim.AKAResult{AUTS: append([]byte(nil), p.auts...)}, sim.ErrSyncFailure
	}
	return sim.AKAResult{RES: []byte{0x11, 0x22, 0x33, 0x44}}, nil
}

func bytesFrom(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustTestDigestRspauth(t *testing.T, ch DigestChallenge, input DigestAuthInput, body []byte) string {
	t.Helper()
	got, err := digestRspauth(newDigestAuthState("Authorization", ch, input, ""), firstNonEmpty(ch.QOP, "auth"), body)
	if err != nil {
		t.Fatalf("digestRspauth() error = %v", err)
	}
	return got
}
