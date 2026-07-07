package voiceclient

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/engine/sim"
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

func TestParseWWWAuthenticateUsesDigestFromCombinedChallenges(t *testing.T) {
	ch, err := ParseWWWAuthenticate(`Basic realm="legacy", Digest realm = "ims.example", nonce = "nonce-combined", algorithm = MD5, qop = "auth"`)
	if err != nil {
		t.Fatalf("ParseWWWAuthenticate() error = %v", err)
	}
	if ch.Realm != "ims.example" || ch.Nonce != "nonce-combined" || ch.Algorithm != "MD5" || ch.QOP != "auth" {
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

func TestBuildDigestAuthorizationMD5Sess(t *testing.T) {
	ch := DigestChallenge{
		Realm:     "ims.example",
		Nonce:     "nonce-md5-sess",
		Algorithm: "MD5-sess",
		QOP:       "auth",
		Opaque:    "opaque-md5-sess",
	}
	input := DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce-md5-sess",
		NC:       3,
	}
	got, err := BuildDigestAuthorization(ch, input)
	if err != nil {
		t.Fatalf("BuildDigestAuthorization(MD5-sess) error = %v", err)
	}
	ha1Base := md5Hex("impi@example:ims.example:secret")
	ha1 := md5Hex(ha1Base + ":nonce-md5-sess:cnonce-md5-sess")
	ha2 := md5Hex("REGISTER:sip:ims.example")
	wantResponse := md5Hex(ha1 + ":nonce-md5-sess:00000003:cnonce-md5-sess:auth:" + ha2)
	for _, want := range []string{
		`algorithm=MD5-sess`,
		`cnonce="cnonce-md5-sess"`,
		`qop=auth`,
		`response="` + wantResponse + `"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("Authorization missing %q: %s", want, got)
		}
	}
	parsed, ok, err := VerifyDigestAuthorization(got, ch, input)
	if err != nil || !ok || parsed.Response != wantResponse {
		t.Fatalf("VerifyDigestAuthorization(MD5-sess) parsed=%+v ok=%v err=%v header=%s", parsed, ok, err, got)
	}
}

func TestBuildDigestAuthorizationMD5SessWithoutQOPCarriesCNonce(t *testing.T) {
	ch := DigestChallenge{Realm: "ims.example", Nonce: "nonce-md5-sess-no-qop", Algorithm: "MD5-sess"}
	input := DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce-no-qop",
	}
	got, err := BuildDigestAuthorization(ch, input)
	if err != nil {
		t.Fatalf("BuildDigestAuthorization(MD5-sess no qop) error = %v", err)
	}
	if strings.Contains(got, `qop=`) || strings.Contains(got, `nc=`) || !strings.Contains(got, `cnonce="cnonce-no-qop"`) {
		t.Fatalf("Authorization no-qop fields wrong: %s", got)
	}
	if _, ok, err := VerifyDigestAuthorization(got, ch, input); err != nil || !ok {
		t.Fatalf("VerifyDigestAuthorization(MD5-sess no qop) ok=%v err=%v header=%s", ok, err, got)
	}
}

func TestBuildDigestAuthorizationMD5SessRequiresCNonce(t *testing.T) {
	_, err := BuildDigestAuthorization(DigestChallenge{
		Realm:     "ims.example",
		Nonce:     "nonce-md5-sess",
		Algorithm: "MD5-sess",
		QOP:       "auth",
	}, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
	})
	if err == nil || !strings.Contains(err.Error(), "cnonce") {
		t.Fatalf("BuildDigestAuthorization(MD5-sess no cnonce) error=%v, want cnonce error", err)
	}
}

func TestBuildDigestAuthorizationSHA256AuthInt(t *testing.T) {
	ch := DigestChallenge{
		Realm:     "ims.example",
		Nonce:     "nonce-sha256",
		Algorithm: "SHA-256",
		QOP:       "auth-int",
	}
	body := []byte("v=0\r\n")
	input := DigestAuthInput{
		Method:   "MESSAGE",
		URI:      "sip:user@example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce-sha256",
		NC:       4,
		Body:     body,
	}
	got, err := BuildDigestAuthorization(ch, input)
	if err != nil {
		t.Fatalf("BuildDigestAuthorization(SHA-256) error = %v", err)
	}
	ha1 := sha256Hex("impi@example:ims.example:secret")
	ha2 := sha256Hex("MESSAGE:sip:user@example:" + sha256HexBytes(body))
	wantResponse := sha256Hex(ha1 + ":nonce-sha256:00000004:cnonce-sha256:auth-int:" + ha2)
	if !strings.Contains(got, `algorithm=SHA-256`) || !strings.Contains(got, `qop=auth-int`) || !strings.Contains(got, `response="`+wantResponse+`"`) {
		t.Fatalf("Authorization=%s", got)
	}
	parsed, ok, err := VerifyDigestAuthorization(got, ch, input)
	if err != nil || !ok || parsed.Response != wantResponse {
		t.Fatalf("VerifyDigestAuthorization(SHA-256) parsed=%+v ok=%v err=%v header=%s", parsed, ok, err, got)
	}
}

func TestBuildDigestAuthorizationSHA256Sess(t *testing.T) {
	ch := DigestChallenge{
		Realm:     "ims.example",
		Nonce:     "nonce-sha256-sess",
		Algorithm: "SHA-256-sess",
		QOP:       "auth",
	}
	input := DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce-sha256-sess",
		NC:       2,
	}
	got, err := BuildDigestAuthorization(ch, input)
	if err != nil {
		t.Fatalf("BuildDigestAuthorization(SHA-256-sess) error = %v", err)
	}
	ha1Base := sha256Hex("impi@example:ims.example:secret")
	ha1 := sha256Hex(ha1Base + ":nonce-sha256-sess:cnonce-sha256-sess")
	ha2 := sha256Hex("REGISTER:sip:ims.example")
	wantResponse := sha256Hex(ha1 + ":nonce-sha256-sess:00000002:cnonce-sha256-sess:auth:" + ha2)
	if !strings.Contains(got, `algorithm=SHA-256-sess`) || !strings.Contains(got, `response="`+wantResponse+`"`) {
		t.Fatalf("Authorization=%s", got)
	}
	if _, ok, err := VerifyDigestAuthorization(got, ch, input); err != nil || !ok {
		t.Fatalf("VerifyDigestAuthorization(SHA-256-sess) ok=%v err=%v header=%s", ok, err, got)
	}
}

func TestDigestRspauthSHA512256(t *testing.T) {
	ch := DigestChallenge{
		Realm:     "ims.example",
		Nonce:     "nonce-sha512-256",
		Algorithm: "SHA-512-256",
		QOP:       "auth",
	}
	input := DigestAuthInput{
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce-sha512-256",
		NC:       5,
	}
	got := mustTestDigestRspauth(t, ch, input, nil)
	ha1 := sha512256Hex("impi@example:ims.example:secret")
	ha2 := sha512256Hex(":sip:ims.example")
	want := sha512256Hex(ha1 + ":nonce-sha512-256:00000005:cnonce-sha512-256:auth:" + ha2)
	if got != want {
		t.Fatalf("rspauth=%q, want %q", got, want)
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

func TestDigestAuthorizationRoundTripAKAv1(t *testing.T) {
	rawNonce := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	ch, err := ParseWWWAuthenticate(`Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth,auth-int", opaque="opq"`)
	if err != nil {
		t.Fatalf("ParseWWWAuthenticate() error = %v", err)
	}
	password, err := BuildAKADigestPassword(ch.Algorithm, sim.AKAResult{RES: []byte{0x11, 0x22, 0x33, 0x44}})
	if err != nil {
		t.Fatalf("BuildAKADigestPassword() error = %v", err)
	}
	authz, err := BuildDigestAuthorization(ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: password,
		CNonce:   "cnonce",
		NC:       7,
	})
	if err != nil {
		t.Fatalf("BuildDigestAuthorization() error = %v", err)
	}
	parsed, ok, err := VerifyDigestAuthorization(authz, ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: password,
	})
	if err != nil || !ok {
		t.Fatalf("VerifyDigestAuthorization() parsed=%+v ok=%v err=%v header=%s", parsed, ok, err, authz)
	}
	if parsed.Username != "impi@example" || parsed.NC != 7 || parsed.NCText != "00000007" ||
		parsed.QOP != "auth" || parsed.Opaque != "opq" || parsed.Response == "" {
		t.Fatalf("parsed Authorization=%+v", parsed)
	}
	if _, ok, err := VerifyDigestAuthorization(authz, ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "wrong-password",
	}); err != nil || ok {
		t.Fatalf("VerifyDigestAuthorization(wrong password) ok=%v err=%v", ok, err)
	}
}

func TestDigestAuthorizationRoundTripWithoutQOPIgnoresCallerNonceState(t *testing.T) {
	ch := DigestChallenge{
		Realm:     "ims.example",
		Nonce:     "nonce-no-qop",
		Algorithm: "MD5",
	}
	authz, err := BuildDigestAuthorization(ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce-not-emitted",
		NC:       9,
	})
	if err != nil {
		t.Fatalf("BuildDigestAuthorization() error = %v", err)
	}
	if strings.Contains(authz, "cnonce") || strings.Contains(authz, "nc=") {
		t.Fatalf("qop-less Authorization should not include nonce state: %s", authz)
	}
	parsed, ok, err := VerifyDigestAuthorization(authz, ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "caller-state",
		NC:       12,
	})
	if err != nil || !ok {
		t.Fatalf("VerifyDigestAuthorization(no qop) parsed=%+v ok=%v err=%v header=%s", parsed, ok, err, authz)
	}
}

func TestDigestAuthorizationRoundTripAUTS(t *testing.T) {
	ch := DigestChallenge{
		Realm:     "ims.example",
		Nonce:     base64.StdEncoding.EncodeToString(append(bytesFrom(0x20, 16), bytesFrom(0x50, 16)...)),
		Algorithm: "AKAv1-MD5",
		QOP:       "auth",
	}
	auts := bytesFrom(0xA0, 14)
	authz, err := BuildDigestAuthorization(ch, DigestAuthInput{
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
	parsed, ok, err := VerifyDigestAuthorization(authz, ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "wrong-password-is-ignored-when-auts-is-present",
		AUTS:     auts,
	})
	if err != nil || !ok {
		t.Fatalf("VerifyDigestAuthorization(AUTS) parsed=%+v ok=%v err=%v header=%s", parsed, ok, err, authz)
	}
	if !bytesEqual(parsed.AUTS, auts) {
		t.Fatalf("parsed AUTS=%x, want %x", parsed.AUTS, auts)
	}
	if _, ok, err := VerifyDigestAuthorization(authz, ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "wrong-password-is-not-ignored-without-expected-auts",
	}); err != nil || ok {
		t.Fatalf("VerifyDigestAuthorization(unexpected AUTS) ok=%v err=%v", ok, err)
	}
}

func TestParseDigestAuthorizationRejectsInvalidHeaders(t *testing.T) {
	for _, header := range []string{
		`Basic realm="ims.example"`,
		`Digest username="impi@example", realm="ims.example", nonce="nonce", uri="sip:ims.example"`,
		`Digest username="impi@example", realm="ims.example", nonce="nonce", uri="sip:ims.example", response="abcd", qop=auth, nc=1, cnonce="cnonce"`,
		`Digest username="impi@example", realm="ims.example", nonce="nonce", uri="sip:ims.example", response="abcd", auts="not-base64***"`,
	} {
		if _, err := ParseDigestAuthorization(header); !errors.Is(err, ErrInvalidAuthorization) {
			t.Fatalf("ParseDigestAuthorization(%q) error=%v, want ErrInvalidAuthorization", header, err)
		}
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
	if !strings.Contains(headers["Contact"], `+sip.instance="<urn:uuid:vowifi-go>"`) ||
		!strings.Contains(headers["Contact"], imsMMTelContactFeature) {
		t.Fatalf("Contact=%q", headers["Contact"])
	}
	if !strings.Contains(headers["Security-Client"], "ipsec-3gpp") {
		t.Fatalf("Security-Client=%q", headers["Security-Client"])
	}
	if strings.Contains(headers["Security-Client"], "spi-c=0") || strings.Contains(headers["Security-Client"], "spi-s=0") ||
		!strings.Contains(headers["Security-Client"], "port-c=5062") || !strings.Contains(headers["Security-Client"], "port-s=5063") {
		t.Fatalf("Security-Client has invalid default proposal: %q", headers["Security-Client"])
	}
	if strings.Contains(headers["Security-Client"], SecurityAlgorithmHMACMD596) || strings.Count(headers["Security-Client"], "ipsec-3gpp") != 1 {
		t.Fatalf("Security-Client default should stay SHA1-only: %q", headers["Security-Client"])
	}
	if !strings.Contains(headers["Allow"], "INFO") || !strings.Contains(headers["Allow"], "NOTIFY") || !strings.Contains(headers["Allow"], "SUBSCRIBE") {
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
	client = BuildSecurityClientHeader(SecurityAgreement{
		SPIClient:  7001,
		SPIServer:  7002,
		PortClient: 6000,
		PortServer: 6001,
		Parameters: map[string]string{
			"prot": "esp",
			"mod":  "trans",
			"q":    "0.5",
			"foo":  "bar baz",
		},
	})
	if client != `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=7001;spi-s=7002;port-c=6000;port-s=6001;prot=esp;mod=trans;q=0.5;foo="bar baz"` {
		t.Fatalf("Security-Client with params=%q", client)
	}
}

func TestParseSecurityAgreementsHandlesIMSParameters(t *testing.T) {
	agreements := ParseSecurityAgreements([]string{
		`IPSEC-3GPP;ALG="HMAC-SHA-1-96";EALG="NULL";SPI-C="111";SPI-S=222;PORT-C=5062;PORT-S=5063;Q=0.950;PROT=ESP;MOD=TRANS, ` +
			`ipsec-3gpp;alg=hmac-md5-96;ealg=aes-cbc;spi-c=333;spi-s=444;port-c=5064;port-s=5065;q=0.900;prot=esp;mod=trans`,
	})
	if len(agreements) != 2 {
		t.Fatalf("ParseSecurityAgreements() len=%d, want 2: %+v", len(agreements), agreements)
	}
	first := agreements[0]
	if first.Protocol != DefaultSecurityProtocol || first.Algorithm != DefaultSecurityAlgorithm || first.EncryptionAlgorithm != DefaultSecurityEAlg ||
		first.SPIClient != 111 || first.SPIServer != 222 || first.PortClient != 5062 || first.PortServer != 5063 ||
		first.Parameters["q"] != "0.950" || !strings.EqualFold(first.Parameters["prot"], "esp") || !strings.EqualFold(first.Parameters["mod"], "trans") {
		t.Fatalf("first agreement=%+v", first)
	}
	second := agreements[1]
	if second.Algorithm != SecurityAlgorithmHMACMD596 || second.EncryptionAlgorithm != SecurityEncryptionAlgorithmAES ||
		second.SPIClient != 333 || second.SPIServer != 444 || second.PortClient != 5064 || second.PortServer != 5065 {
		t.Fatalf("second agreement=%+v", second)
	}
}

func TestBuildAndSelectSecurityClientProposals(t *testing.T) {
	clients := []SecurityAgreement{
		{Algorithm: DefaultSecurityAlgorithm, SPIClient: 7001, SPIServer: 7002, PortClient: 6000, PortServer: 6001},
		{Algorithm: SecurityAlgorithmHMACMD596, SPIClient: 8001, SPIServer: 8002, PortClient: 6002, PortServer: 6003},
	}
	header := BuildSecurityClientHeaderList(clients)
	want := "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=7001;spi-s=7002;port-c=6000;port-s=6001, " +
		"ipsec-3gpp;alg=hmac-md5-96;ealg=null;spi-c=8001;spi-s=8002;port-c=6002;port-s=6003"
	if header != want {
		t.Fatalf("Security-Client=%q, want %q", header, want)
	}
	selected, ok := SelectSecurityAgreementForClients([]string{
		`ipsec-3gpp;q=0.9;alg=hmac-md5-96;ealg=null;spi-c=333;spi-s=444;port-c=5064;port-s=5065`,
	}, clients)
	if !ok {
		t.Fatal("SelectSecurityAgreementForClients() ok=false")
	}
	if selected.Algorithm != SecurityAlgorithmHMACMD596 || selected.SPIClient != 333 || selected.SPIServer != 444 {
		t.Fatalf("selected=%+v", selected)
	}
	if selected, ok := SelectSecurityAgreement([]string{
		`ipsec-3gpp;q=0.9;alg=hmac-md5-96;ealg=null;spi-c=333;spi-s=444;port-c=5064;port-s=5065`,
	}, clients[0]); ok {
		t.Fatalf("SelectSecurityAgreement() selected unoffered algorithm: %+v", selected)
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

func TestSelectSecurityAgreementUsesPreciseQAndRepeats(t *testing.T) {
	selected, ok := SelectSecurityAgreement([]string{
		`ipsec-3gpp;q=0.901;alg=hmac-sha-1-96;ealg=null;spi-c=111;spi-s=222;port-c=5062;port-s=5063;prot=esp;mod=trans`,
		`ipsec-3gpp;q=0.950;alg=hmac-sha-1-96;ealg=null;spi-c=333;spi-s=444;port-c=5064;port-s=5065;prot=esp;mod=trans`,
		`ipsec-3gpp;q=0.950;alg=hmac-sha-1-96;ealg=null;spi-c=555;spi-s=666;port-c=5066;port-s=5067;prot=esp;mod=trans`,
	}, SecurityAgreement{
		Protocol:            DefaultSecurityProtocol,
		Algorithm:           DefaultSecurityAlgorithm,
		EncryptionAlgorithm: DefaultSecurityEAlg,
	})
	if !ok {
		t.Fatal("SelectSecurityAgreement() ok=false")
	}
	if selected.SPIClient != 333 || selected.SPIServer != 444 || selected.Parameters["q"] != "0.950" {
		t.Fatalf("selected=%+v", selected)
	}
}

func TestSelectSecurityAgreementMatchesProtAndMode(t *testing.T) {
	selected, ok := SelectSecurityAgreement([]string{
		`ipsec-3gpp;q=1.0;alg=hmac-sha-1-96;ealg=null;spi-c=111;spi-s=222;port-c=5062;port-s=5063;prot=ah;mod=trans`,
		`ipsec-3gpp;q=0.9;alg=hmac-sha-1-96;ealg=null;spi-c=333;spi-s=444;port-c=5064;port-s=5065;prot=esp;mod=tun`,
		`ipsec-3gpp;q=0.1;alg=hmac-sha-1-96;ealg=null;spi-c=555;spi-s=666;port-c=5066;port-s=5067;prot=ESP;mod=TRANSPORT`,
	}, SecurityAgreement{
		Protocol:            DefaultSecurityProtocol,
		Algorithm:           DefaultSecurityAlgorithm,
		EncryptionAlgorithm: DefaultSecurityEAlg,
	})
	if !ok {
		t.Fatal("SelectSecurityAgreement() ok=false")
	}
	if selected.SPIClient != 555 || !strings.EqualFold(selected.Parameters["prot"], "esp") || !strings.EqualFold(selected.Parameters["mod"], "transport") {
		t.Fatalf("selected=%+v", selected)
	}
}

func TestSelectSecurityAgreementPrefersHigherQValue(t *testing.T) {
	selected, ok := SelectSecurityAgreement([]string{
		`ipsec-3gpp;q=0.2;alg=hmac-sha-1-96;ealg=null;spi-c=111;spi-s=222;port-c=5062;port-s=5063`,
		`ipsec-3gpp;q=0.8;alg=hmac-sha-1-96;ealg=null;spi-c=333;spi-s=444;port-c=5064;port-s=5065;mod=trans`,
	}, SecurityAgreement{
		Protocol:            "ipsec-3gpp",
		Algorithm:           "hmac-sha-1-96",
		EncryptionAlgorithm: "null",
	})
	if !ok {
		t.Fatal("SelectSecurityAgreement() ok=false")
	}
	if selected.SPIClient != 333 || selected.SPIServer != 444 || selected.Parameters["q"] != "0.8" {
		t.Fatalf("selected=%+v", selected)
	}
	plan, ok := BuildIMSSecurityAssociationPlan(selected)
	if !ok {
		t.Fatal("BuildIMSSecurityAssociationPlan() ok=false")
	}
	if plan.SPIClient != 333 || plan.SPIServer != 444 || plan.PortClient != 5064 || plan.PortServer != 5065 ||
		plan.Protocol != "ipsec-3gpp" || plan.Algorithm != "hmac-sha-1-96" || plan.EncryptionAlgorithm != "null" ||
		plan.Mode != "trans" || plan.QValue != "0.8" {
		t.Fatalf("plan=%+v", plan)
	}
	if plan.Inbound.Direction != "inbound" || plan.Inbound.LocalPort != 5064 || plan.Inbound.RemotePort != 5065 || plan.Inbound.SPI != 333 {
		t.Fatalf("inbound plan=%+v", plan.Inbound)
	}
	if plan.Outbound.Direction != "outbound" || plan.Outbound.LocalPort != 5064 || plan.Outbound.RemotePort != 5065 || plan.Outbound.SPI != 444 {
		t.Fatalf("outbound plan=%+v", plan.Outbound)
	}
}

func TestBuildIMSSecurityAssociationPlanRequiresPortsAndSPIs(t *testing.T) {
	if plan, ok := BuildIMSSecurityAssociationPlan(SecurityAgreement{
		Protocol:            "ipsec-3gpp",
		Algorithm:           "hmac-sha-1-96",
		EncryptionAlgorithm: "null",
		SPIClient:           111,
		SPIServer:           222,
	}); ok || !isZeroIMSSecurityAssociationPlan(plan) {
		t.Fatalf("BuildIMSSecurityAssociationPlan() plan=%+v ok=%v, want empty", plan, ok)
	}
	if plan, ok := BuildIMSSecurityAssociationPlan(SecurityAgreement{
		Protocol:            "ipsec-3gpp",
		Algorithm:           "hmac-sha-1-96",
		EncryptionAlgorithm: "null",
		PortClient:          5062,
		PortServer:          5063,
	}); ok || !isZeroIMSSecurityAssociationPlan(plan) {
		t.Fatalf("BuildIMSSecurityAssociationPlan() plan=%+v ok=%v, want empty", plan, ok)
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
	if result.Binding.AuthSession == nil || result.Binding.AuthHeaderName != "Authorization" || result.Binding.AuthHeader != result.AuthHeader {
		t.Fatalf("auth binding headerName=%q header=%q session=%v", result.Binding.AuthHeaderName, result.Binding.AuthHeader, result.Binding.AuthSession)
	}
	if result.Binding.SecurityClient != transport.requests[0].Headers["Security-Client"] ||
		len(result.Binding.SecurityServer) != 1 ||
		result.Binding.SecurityAgreement.SPIClient != 111 ||
		result.Binding.SecurityAgreement.SPIServer != 222 ||
		result.Binding.SecurityAgreement.PortClient != 5062 ||
		result.Binding.SecurityAgreement.PortServer != 5063 ||
		result.Binding.SecurityPlan.SPIClient != 111 ||
		result.Binding.SecurityPlan.SPIServer != 222 ||
		result.Binding.SecurityPlan.PortClient != 5062 ||
		result.Binding.SecurityPlan.PortServer != 5063 ||
		result.Binding.SecurityPlan.Inbound.SPI != 111 ||
		result.Binding.SecurityPlan.Inbound.LocalPort != 5062 ||
		result.Binding.SecurityPlan.Outbound.SPI != 222 ||
		result.Binding.SecurityPlan.Outbound.RemotePort != 5063 ||
		result.Binding.SecurityPlan.Mode != "trans" ||
		result.Binding.SecurityPlan.Protocol != "ipsec-3gpp" {
		t.Fatalf("security binding=%+v", result.Binding)
	}
	if got := strings.ToUpper(hex.EncodeToString(aka.rand)); got != strings.ToUpper(hex.EncodeToString(bytesFrom(0x10, 16))) {
		t.Fatalf("RAND=%s", got)
	}
}

func TestRegisterSessionUsesDigestFromCombinedWWWAuthenticate(t *testing.T) {
	rawNonce := append(bytesFrom(0x21, 16), bytesFrom(0x51, 16)...)
	challenge := `Basic realm="legacy", Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {challenge},
			},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	aka := &registerAKAProvider{}
	result, err := RegisterSession{
		Transport:    transport,
		AKAProvider:  aka,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-combined-auth",
		CNonce:       "cnonce",
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !result.Registered || result.Challenge.Algorithm != "AKAv1-MD5" || result.Attempts != 2 {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests=%d, want 2", len(transport.requests))
	}
	auth := transport.requests[1].Headers["Authorization"]
	if !strings.Contains(auth, `algorithm=AKAv1-MD5`) || !strings.Contains(auth, `nonce="`+base64.StdEncoding.EncodeToString(rawNonce)+`"`) {
		t.Fatalf("Authorization=%s", auth)
	}
	if !bytesEqual(aka.rand, bytesFrom(0x21, 16)) {
		t.Fatalf("AKA RAND=%x", aka.rand)
	}
}

func TestRegisterSessionInstallsSecurityPlanBeforeAuthenticatedRegister(t *testing.T) {
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce", algorithm=MD5, qop="auth"`},
				"Security-Server": {
					`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=111;spi-s=222;port-c=5062;port-s=5063;q=0.8`,
					`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=333;spi-s=444;port-c=5064;port-s=5065;q=0.4`,
				},
			},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	installer := &fakeSecurityPlanInstaller{transport: transport}
	result, err := RegisterSession{
		Transport:             transport,
		Profile:               IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI:          "sip:ims.example",
		ContactURI:            "sip:user@192.0.2.10:5060",
		CNonce:                "cnonce",
		SecurityPlanInstaller: installer,
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !result.Registered || len(transport.requests) != 2 {
		t.Fatalf("result=%+v requests=%d", result, len(transport.requests))
	}
	if len(installer.calls) != 1 || len(installer.requestsAtCall) != 1 || installer.requestsAtCall[0] != 1 {
		t.Fatalf("installer calls=%+v requestsAtCall=%+v", installer.calls, installer.requestsAtCall)
	}
	plan := installer.calls[0]
	if plan.SPIClient != 111 || plan.SPIServer != 222 || plan.PortClient != 5062 || plan.PortServer != 5063 ||
		plan.Inbound.SPI != 111 || plan.Outbound.SPI != 222 || plan.QValue != "0.8" {
		t.Fatalf("installed plan=%+v", plan)
	}
	if got := transport.requests[1].Headers["Security-Verify"]; !strings.Contains(got, "spi-c=111") {
		t.Fatalf("Security-Verify=%q", got)
	}
}

func TestRegisterSessionOffersMultipleSecurityClientProposals(t *testing.T) {
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce", algorithm=MD5, qop="auth"`},
				"Security-Server":  {`ipsec-3gpp;alg=hmac-md5-96;ealg=null;spi-c=333;spi-s=444;port-c=5064;port-s=5065;q=0.9`},
			},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	installer := &fakeSecurityPlanInstaller{transport: transport}
	result, err := RegisterSession{
		Transport:    transport,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CNonce:       "cnonce",
		SecurityClients: []SecurityAgreement{
			{Algorithm: DefaultSecurityAlgorithm},
			{Algorithm: SecurityAlgorithmHMACMD596},
		},
		SecurityPlanInstaller: installer,
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !result.Registered || len(transport.requests) != 2 {
		t.Fatalf("result=%+v requests=%d", result, len(transport.requests))
	}
	firstSecurityClient := transport.requests[0].Headers["Security-Client"]
	secondSecurityClient := transport.requests[1].Headers["Security-Client"]
	if firstSecurityClient == "" || firstSecurityClient != secondSecurityClient {
		t.Fatalf("Security-Client not stable: first=%q second=%q", firstSecurityClient, secondSecurityClient)
	}
	if strings.Count(firstSecurityClient, "ipsec-3gpp") != 2 ||
		!strings.Contains(firstSecurityClient, "alg=hmac-sha-1-96") || !strings.Contains(firstSecurityClient, "alg=hmac-md5-96") ||
		!strings.Contains(firstSecurityClient, "port-c=5062") || !strings.Contains(firstSecurityClient, "port-s=5063") ||
		strings.Contains(firstSecurityClient, "spi-c=0") || strings.Contains(firstSecurityClient, "spi-s=0") {
		t.Fatalf("Security-Client proposals=%q", firstSecurityClient)
	}
	if len(installer.calls) != 1 || installer.calls[0].Algorithm != SecurityAlgorithmHMACMD596 || installer.calls[0].SPIClient != 333 {
		t.Fatalf("installer calls=%+v", installer.calls)
	}
	if got := transport.requests[1].Headers["Security-Verify"]; !strings.Contains(got, "alg=hmac-md5-96") || !strings.Contains(got, "spi-c=333") {
		t.Fatalf("Security-Verify=%q", got)
	}
	if result.Binding.SecurityClient != firstSecurityClient || result.Binding.SecurityAgreement.Algorithm != SecurityAlgorithmHMACMD596 || result.Binding.SecurityPlan.Algorithm != SecurityAlgorithmHMACMD596 {
		t.Fatalf("security binding=%+v", result.Binding)
	}
}

func TestRegisterSessionInstallsRichSecurityPlanRequestWithAKAMaterial(t *testing.T) {
	rawNonce := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	ck := bytesFrom(0xA0, 16)
	ik := bytesFrom(0xB0, 16)
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv1-MD5, qop="auth"`},
				"Security-Server":  {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=111;spi-s=222;port-c=5062;port-s=5063;q=0.8;mode=trans`},
			},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	installer := &fakeRichSecurityPlanInstaller{transport: transport}
	result, err := RegisterSession{
		Transport:             transport,
		AKAProvider:           &sequenceAKAProvider{results: []sim.AKAResult{{RES: []byte{0xAA, 0xBB, 0xCC, 0xDD}, CK: ck, IK: ik}}},
		Profile:               IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI:          "sip:ims.example",
		ContactURI:            "sip:user@192.0.2.10:5060",
		CNonce:                "cnonce",
		SecurityPlanInstaller: installer,
		SecurityLocalAddr:     "192.0.2.20:45000",
		SecurityRemoteAddr:    "198.51.100.10:5060",
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !result.Registered || len(transport.requests) != 2 {
		t.Fatalf("result=%+v requests=%d", result, len(transport.requests))
	}
	if len(installer.requests) != 1 || len(installer.requestsAtCall) != 1 || installer.requestsAtCall[0] != 1 || len(installer.legacyCalls) != 0 {
		t.Fatalf("rich requests=%+v legacy=%+v requestsAtCall=%+v", installer.requests, installer.legacyCalls, installer.requestsAtCall)
	}
	req := installer.requests[0]
	if !bytesEqual(req.AKA.CK, ck) || !bytesEqual(req.AKA.IK, ik) {
		t.Fatalf("AKA keys CK=%x IK=%x", req.AKA.CK, req.AKA.IK)
	}
	if req.LocalEndpoint.Address != "192.0.2.20" || req.LocalEndpoint.Port != 5062 ||
		req.RemoteEndpoint.Address != "198.51.100.10" || req.RemoteEndpoint.Port != 5063 {
		t.Fatalf("endpoints local=%+v remote=%+v", req.LocalEndpoint, req.RemoteEndpoint)
	}
	if req.Plan.SPIClient != 111 || req.Plan.SPIServer != 222 || req.Plan.Inbound.LocalPort != 5062 || req.Plan.Outbound.RemotePort != 5063 {
		t.Fatalf("plan=%+v", req.Plan)
	}
	if req.Agreement.SPIClient != 111 || req.SelectedParameters["q"] != "0.8" || req.SelectedParameters["mode"] != "trans" {
		t.Fatalf("agreement=%+v selected=%+v", req.Agreement, req.SelectedParameters)
	}
}

func TestRegisterSessionPropagatesSecurityPlanInstallerError(t *testing.T) {
	installErr := errors.New("security plan install failed")
	transport := &fakeRegisterTransport{responses: []RegisterResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers: map[string][]string{
				"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce", algorithm=MD5, qop="auth"`},
				"Security-Server":  {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=111;spi-s=222;port-c=5062;port-s=5063`},
			},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	installer := &fakeSecurityPlanInstaller{transport: transport, err: installErr}
	result, err := RegisterSession{
		Transport:             transport,
		Profile:               IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI:          "sip:ims.example",
		ContactURI:            "sip:user@192.0.2.10:5060",
		SecurityPlanInstaller: installer,
	}.Register(context.Background())
	if !errors.Is(err, installErr) {
		t.Fatalf("Register() err=%v, want %v", err, installErr)
	}
	if result.Registered || result.StatusCode != 401 || result.Attempts != 1 || len(transport.requests) != 1 || len(installer.calls) != 1 {
		t.Fatalf("result=%+v requests=%d installerCalls=%d", result, len(transport.requests), len(installer.calls))
	}
	if result.AuthHeader == "" || result.AuthHeaderName != "Authorization" || result.Challenge.Nonce != "nonce" {
		t.Fatalf("result auth/challenge=%+v", result)
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

func TestRegisterSessionClassifiesRegisterFailures(t *testing.T) {
	tests := []struct {
		name             string
		responses        []RegisterResponse
		expires          int
		wantErr          error
		wantStatus       int
		wantAttempts     int
		wantRetryAfter   time.Duration
		wantRegistered   bool
		wantRequests     int
		wantAuthHeader   bool
		wantChallengeSet bool
	}{
		{
			name: "401 without valid challenge",
			responses: []RegisterResponse{{
				StatusCode: 401,
				Reason:     "Unauthorized",
			}},
			wantErr:        ErrInvalidChallenge,
			wantStatus:     401,
			wantAttempts:   1,
			wantRegistered: false,
			wantRequests:   1,
		},
		{
			name: "403 forbidden with retry-after",
			responses: []RegisterResponse{{
				StatusCode: 403,
				Reason:     "Forbidden",
				Headers:    map[string][]string{"Retry-After": {"7"}},
			}},
			wantErr:        ErrRegistrationRejected,
			wantStatus:     403,
			wantAttempts:   1,
			wantRetryAfter: 7 * time.Second,
			wantRegistered: false,
			wantRequests:   1,
		},
		{
			name: "423 invalid min-expires",
			responses: []RegisterResponse{{
				StatusCode: 423,
				Reason:     "Interval Too Brief",
				Headers:    map[string][]string{"Min-Expires": {"300"}},
			}},
			expires:        600,
			wantErr:        ErrRegistrationRejected,
			wantStatus:     423,
			wantAttempts:   1,
			wantRegistered: false,
			wantRequests:   1,
		},
		{
			name: "503 retry-after after challenge",
			responses: []RegisterResponse{
				{
					StatusCode: 401,
					Reason:     "Unauthorized",
					Headers: map[string][]string{
						"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce-retry", algorithm=MD5, qop="auth"`},
					},
				},
				{
					StatusCode: 503,
					Reason:     "Service Unavailable",
					Headers:    map[string][]string{"Retry-After": {"11"}},
				},
			},
			wantErr:          ErrRegistrationRejected,
			wantStatus:       503,
			wantAttempts:     2,
			wantRetryAfter:   11 * time.Second,
			wantRegistered:   false,
			wantRequests:     2,
			wantAuthHeader:   true,
			wantChallengeSet: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			transport := &fakeRegisterTransport{responses: tc.responses}
			result, err := RegisterSession{
				Transport:    transport,
				Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
				RegistrarURI: "sip:ims.example",
				ContactURI:   "sip:user@192.0.2.10:5060",
				CallID:       "call-register-failure",
				CNonce:       "cnonce",
				Expires:      tc.expires,
			}.Register(context.Background())
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Register() err=%v, want %v", err, tc.wantErr)
			}
			if result.Registered != tc.wantRegistered || result.StatusCode != tc.wantStatus ||
				result.Attempts != tc.wantAttempts || result.RetryAfter != tc.wantRetryAfter {
				t.Fatalf("Register() result=%+v, want status=%d attempts=%d retryAfter=%v registered=%v",
					result, tc.wantStatus, tc.wantAttempts, tc.wantRetryAfter, tc.wantRegistered)
			}
			if (result.AuthHeader != "") != tc.wantAuthHeader {
				t.Fatalf("AuthHeader present=%v, want %v: %q", result.AuthHeader != "", tc.wantAuthHeader, result.AuthHeader)
			}
			if (result.Challenge.Nonce != "") != tc.wantChallengeSet {
				t.Fatalf("Challenge=%+v, want set=%v", result.Challenge, tc.wantChallengeSet)
			}
			if len(transport.requests) != tc.wantRequests {
				t.Fatalf("requests=%d, want %d", len(transport.requests), tc.wantRequests)
			}
		})
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

func TestRegisterSessionDeregisterHandlesAKASynchronizationFailure(t *testing.T) {
	firstNonce := append(bytesFrom(0x12, 16), bytesFrom(0x42, 16)...)
	secondNonce := append(bytesFrom(0x62, 16), bytesFrom(0x82, 16)...)
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
		{StatusCode: 200, Reason: "OK"},
	}}
	auts := bytesFrom(0xC1, 14)
	aka := &syncFailureAKAProvider{auts: auts}
	session := RegisterSession{
		Transport:    transport,
		AKAProvider:  aka,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-dereg-sync",
		CNonce:       "cnonce",
	}
	result, err := session.Deregister(context.Background(), DeregisterRequest{
		Binding: RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			SecurityClient: "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=101;spi-s=102;port-c=5062;port-s=5063",
		},
		CSeq: 9,
	})
	if err != nil {
		t.Fatalf("Deregister() error = %v", err)
	}
	if !result.Deregistered || result.Attempts != 3 || result.StatusCode != 200 {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 3 {
		t.Fatalf("requests=%d, want 3", len(transport.requests))
	}
	if transport.requests[0].Headers["CSeq"] != "9 REGISTER" || transport.requests[1].Headers["CSeq"] != "10 REGISTER" ||
		transport.requests[2].Headers["CSeq"] != "11 REGISTER" {
		t.Fatalf("CSeqs=%q/%q/%q", transport.requests[0].Headers["CSeq"], transport.requests[1].Headers["CSeq"], transport.requests[2].Headers["CSeq"])
	}
	syncAuth := transport.requests[1].Headers["Authorization"]
	if !strings.Contains(syncAuth, `auts="`+base64.StdEncoding.EncodeToString(auts)+`"`) {
		t.Fatalf("sync deregister Authorization=%s", syncAuth)
	}
	finalAuth := transport.requests[2].Headers["Authorization"]
	if strings.Contains(finalAuth, `auts=`) || !strings.Contains(finalAuth, `nonce="`+base64.StdEncoding.EncodeToString(secondNonce)+`"`) {
		t.Fatalf("final deregister Authorization=%s", finalAuth)
	}
	if got := transport.requests[2].Headers["Security-Verify"]; !strings.Contains(got, "spi-c=333") {
		t.Fatalf("Security-Verify=%q", got)
	}
	if len(aka.rands) != 2 || !bytesEqual(aka.rands[1], bytesFrom(0x62, 16)) {
		t.Fatalf("AKA rands=%x", aka.rands)
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

func TestRegisterSessionRefreshHandlesAKASynchronizationFailure(t *testing.T) {
	firstNonce := append(bytesFrom(0x14, 16), bytesFrom(0x44, 16)...)
	secondNonce := append(bytesFrom(0x64, 16), bytesFrom(0x84, 16)...)
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
				"Contact": {`<sip:user@192.0.2.10:5060>;expires=900`},
			},
		},
	}}
	auts := bytesFrom(0xD1, 14)
	aka := &syncFailureAKAProvider{auts: auts}
	session := RegisterSession{
		Transport:    transport,
		AKAProvider:  aka,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@example", Domain: "example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "call-refresh-sync",
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
	if !result.Refreshed || result.Attempts != 3 || result.NextCSeq != 14 || result.Binding.Expires != 900 ||
		result.Binding.SecurityAgreement.SPIClient != 333 || !result.AuthState.Usable() {
		t.Fatalf("result=%+v", result)
	}
	if len(transport.requests) != 3 {
		t.Fatalf("requests=%d, want 3", len(transport.requests))
	}
	if transport.requests[0].Headers["CSeq"] != "11 REGISTER" || transport.requests[1].Headers["CSeq"] != "12 REGISTER" ||
		transport.requests[2].Headers["CSeq"] != "13 REGISTER" {
		t.Fatalf("CSeqs=%q/%q/%q", transport.requests[0].Headers["CSeq"], transport.requests[1].Headers["CSeq"], transport.requests[2].Headers["CSeq"])
	}
	syncAuth := transport.requests[1].Headers["Authorization"]
	if !strings.Contains(syncAuth, `auts="`+base64.StdEncoding.EncodeToString(auts)+`"`) {
		t.Fatalf("sync refresh Authorization=%s", syncAuth)
	}
	finalAuth := transport.requests[2].Headers["Authorization"]
	if strings.Contains(finalAuth, `auts=`) || !strings.Contains(finalAuth, `nonce="`+base64.StdEncoding.EncodeToString(secondNonce)+`"`) {
		t.Fatalf("final refresh Authorization=%s", finalAuth)
	}
	if got := transport.requests[2].Headers["Security-Verify"]; !strings.Contains(got, "spi-c=333") {
		t.Fatalf("Security-Verify=%q", got)
	}
	if len(aka.rands) != 2 || !bytesEqual(aka.rands[1], bytesFrom(0x64, 16)) {
		t.Fatalf("AKA rands=%x", aka.rands)
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

func TestSelectDigestChallengeParsesMultipleChallengesInSingleHeader(t *testing.T) {
	rawNonce := append(bytesFrom(0x22, 16), bytesFrom(0x52, 16)...)
	ch, err := SelectDigestChallenge(map[string][]string{
		"WWW-Authenticate": {
			`Basic realm="legacy", Digest realm="ims.example", nonce="md5nonce", algorithm=MD5, qop="auth", Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(rawNonce) + `", algorithm=AKAv2-MD5, qop="auth"`,
		},
	}, "WWW-Authenticate")
	if err != nil {
		t.Fatalf("SelectDigestChallenge() error = %v", err)
	}
	if ch.Algorithm != "AKAv2-MD5" || ch.Nonce != base64.StdEncoding.EncodeToString(rawNonce) {
		t.Fatalf("challenge=%+v, want AKAv2-MD5 from combined header", ch)
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

func TestSelectDigestChallengeSupportsMD5Sess(t *testing.T) {
	ch, err := SelectDigestChallenge(map[string][]string{
		"WWW-Authenticate": {
			`Digest realm="ims.example", nonce="nonce-md5", algorithm=MD5, qop="auth"`,
			`Digest realm="ims.example", nonce="nonce-md5-sess", algorithm=MD5-sess, qop="auth"`,
		},
	}, "WWW-Authenticate")
	if err != nil {
		t.Fatalf("SelectDigestChallenge() error = %v", err)
	}
	if ch.Algorithm != "MD5-sess" || ch.Nonce != "nonce-md5-sess" {
		t.Fatalf("challenge=%+v, want MD5-sess", ch)
	}
}

func TestSelectDigestChallengeSupportsSHAAlgorithms(t *testing.T) {
	ch, err := SelectDigestChallenge(map[string][]string{
		"WWW-Authenticate": {
			`Digest realm="ims.example", nonce="nonce-md5-sess", algorithm=MD5-sess, qop="auth"`,
			`Digest realm="ims.example", nonce="nonce-sha256", algorithm=SHA-256, qop="auth"`,
			`Digest realm="ims.example", nonce="nonce-sha512-256-sess", algorithm=SHA-512-256-sess, qop="auth"`,
		},
	}, "WWW-Authenticate")
	if err != nil {
		t.Fatalf("SelectDigestChallenge() error = %v", err)
	}
	if ch.Algorithm != "SHA-512-256-sess" || ch.Nonce != "nonce-sha512-256-sess" {
		t.Fatalf("challenge=%+v, want SHA-512-256-sess", ch)
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

func TestBuildRegistrationBindingLeavesPlanEmptyWithoutCompleteSA(t *testing.T) {
	binding := BuildRegistrationBinding(IMSProfile{IMPU: "sip:fallback@example"}, "sip:user@192.0.2.10:5060", RegisterResponse{
		Headers: map[string][]string{
			"Security-Server": {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=1;spi-s=2`},
		},
	}, 3600)
	if binding.SecurityAgreement.SPIClient != 1 || binding.SecurityAgreement.SPIServer != 2 {
		t.Fatalf("security agreement=%+v", binding.SecurityAgreement)
	}
	if !isZeroIMSSecurityAssociationPlan(binding.SecurityPlan) {
		t.Fatalf("security plan=%+v, want empty", binding.SecurityPlan)
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
	if invite.Headers["P-Preferred-Service"] != imsMMTelService || invite.Headers["Accept-Contact"] != imsMMTelAcceptContact {
		t.Fatalf("invite service headers=%+v", invite.Headers)
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
	cancelBody, err := BuildCancelRequestWithBody(cfg, "message/sipfrag", []byte("SIP/2.0 487 Request Terminated\r\n"))
	if err != nil {
		t.Fatalf("BuildCancelRequestWithBody() error = %v", err)
	}
	if cancelBody.Method != "CANCEL" || cancelBody.Headers["CSeq"] != "3 CANCEL" ||
		cancelBody.Headers["Content-Type"] != "message/sipfrag" ||
		string(cancelBody.Body) != "SIP/2.0 487 Request Terminated\r\n" {
		t.Fatalf("cancel with body=%+v body=%q", cancelBody, cancelBody.Body)
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
	prackBody, err := BuildPrackRequestWithBody(cfg, "2 3 INVITE", "application/sdp", []byte("v=0\r\n"))
	if err != nil {
		t.Fatalf("BuildPrackRequestWithBody() error = %v", err)
	}
	if prackBody.Method != "PRACK" || prackBody.Headers["RAck"] != "2 3 INVITE" ||
		prackBody.Headers["Content-Type"] != "application/sdp" || string(prackBody.Body) != "v=0\r\n" {
		t.Fatalf("prack with body=%+v body=%q", prackBody, prackBody.Body)
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
	dialogMessage, err := BuildDialogMessageRequest(cfg, "message/cpim", []byte("cpim"))
	if err != nil {
		t.Fatalf("BuildDialogMessageRequest() error = %v", err)
	}
	if dialogMessage.Method != "MESSAGE" || dialogMessage.Headers["CSeq"] != "3 MESSAGE" ||
		dialogMessage.Headers["Content-Type"] != "message/cpim" ||
		dialogMessage.Headers["Accept"] != DefaultDialogMessageAccept ||
		dialogMessage.Headers["Contact"] != "<sip:user@192.0.2.10:5060>" ||
		dialogMessage.Headers["P-Preferred-Service"] != "" ||
		dialogMessage.Headers["Accept-Contact"] != "" ||
		string(dialogMessage.Body) != "cpim" {
		t.Fatalf("dialog MESSAGE=%+v body=%q", dialogMessage, dialogMessage.Body)
	}
	refer, err := BuildReferRequest(cfg, "sip:+18005551313@ims.example", "sip:user@example")
	if err != nil {
		t.Fatalf("BuildReferRequest() error = %v", err)
	}
	if refer.Method != "REFER" || refer.Headers["CSeq"] != "3 REFER" ||
		refer.Headers["Refer-To"] != "<sip:+18005551313@ims.example>" ||
		refer.Headers["Referred-By"] != "<sip:user@example>" ||
		refer.Headers["Contact"] != "<sip:user@192.0.2.10:5060>" ||
		refer.Headers["Refer-Sub"] != "false" || refer.Headers["Supported"] == "" {
		t.Fatalf("refer=%+v", refer)
	}
	if !strings.Contains(refer.Headers["Security-Verify"], "spi-c=111") {
		t.Fatalf("refer Security-Verify=%q", refer.Headers["Security-Verify"])
	}
	referWithSubscription, err := BuildReferRequestWithOptions(cfg, "sip:+18005551313@ims.example", ReferRequestOptions{
		ReferredBy: "sip:user@example",
		ReferSub:   "true",
	})
	if err != nil {
		t.Fatalf("BuildReferRequestWithOptions() error = %v", err)
	}
	if referWithSubscription.Headers["Refer-Sub"] != "true" || referWithSubscription.Headers["Supported"] == "" {
		t.Fatalf("referWithSubscription=%+v", referWithSubscription)
	}
	if _, err := BuildReferRequestWithOptions(cfg, "sip:+18005551313@ims.example", ReferRequestOptions{ReferSub: "maybe"}); !errors.Is(err, ErrInvalidDialogConfig) {
		t.Fatalf("BuildReferRequestWithOptions(invalid Refer-Sub) err=%v, want ErrInvalidDialogConfig", err)
	}
	notify, err := BuildNotifyRequest(cfg, "refer", "terminated;reason=noresource", "message/sipfrag", []byte("SIP/2.0 200 OK\r\n"))
	if err != nil {
		t.Fatalf("BuildNotifyRequest() error = %v", err)
	}
	if notify.Method != "NOTIFY" || notify.Headers["CSeq"] != "3 NOTIFY" ||
		notify.Headers["Event"] != "refer" ||
		notify.Headers["Subscription-State"] != "terminated;reason=noresource" ||
		notify.Headers["Allow-Events"] != "refer" ||
		notify.Headers["Contact"] != "<sip:user@192.0.2.10:5060>" ||
		notify.Headers["Content-Type"] != "message/sipfrag" ||
		string(notify.Body) != "SIP/2.0 200 OK\r\n" {
		t.Fatalf("notify=%+v body=%q", notify, notify.Body)
	}
	if !strings.Contains(notify.Headers["Security-Verify"], "spi-c=111") {
		t.Fatalf("notify Security-Verify=%q", notify.Headers["Security-Verify"])
	}
	subscribe, err := BuildSubscribeRequest(cfg, "refer", "300", "application/resource-lists+xml", []byte("<resource-lists/>"))
	if err != nil {
		t.Fatalf("BuildSubscribeRequest() error = %v", err)
	}
	if subscribe.Method != "SUBSCRIBE" || subscribe.Headers["CSeq"] != "3 SUBSCRIBE" ||
		subscribe.Headers["Event"] != "refer" ||
		subscribe.Headers["Expires"] != "300" ||
		subscribe.Headers["Accept"] != "message/sipfrag" ||
		subscribe.Headers["Allow-Events"] != "refer" ||
		subscribe.Headers["Contact"] != "<sip:user@192.0.2.10:5060>" ||
		subscribe.Headers["Content-Type"] != "application/resource-lists+xml" ||
		string(subscribe.Body) != "<resource-lists/>" {
		t.Fatalf("subscribe=%+v body=%q", subscribe, subscribe.Body)
	}
	if !strings.Contains(subscribe.Headers["Security-Verify"], "spi-c=111") {
		t.Fatalf("subscribe Security-Verify=%q", subscribe.Headers["Security-Verify"])
	}
	defaultSubscribe, err := BuildSubscribeRequest(cfg, "refer", "", "", nil)
	if err != nil {
		t.Fatalf("BuildSubscribeRequest(default Expires) error = %v", err)
	}
	if defaultSubscribe.Headers["Expires"] != DefaultSubscribeExpires {
		t.Fatalf("default SUBSCRIBE Expires=%q", defaultSubscribe.Headers["Expires"])
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

func TestBuildIMSDialogINVITEAppliesEmergencyHeaders(t *testing.T) {
	cfg := DialogRequestConfig{
		Profile: IMSProfile{UserAgent: "VoHive"},
		Registration: RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@example",
		},
		RemoteURI:       "sip:911@ims.example",
		RemoteTargetURI: "urn:service:sos.fire",
		CallID:          "call-emergency",
		LocalTag:        "ltag",
		InviteHeaders: map[string]string{
			"P-Preferred-Service":   "urn:urn-7:3gpp-service.ims.icsi.mmtel",
			"Accept-Contact":        `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";require;explicit`,
			"P-Access-Network-Info": "IEEE-802.11;i-wlan-node-id=\"aa:bb\"",
			"Geolocation":           "<geo:47.6205,-122.3493>;inserted-by=endpoint",
			"Geolocation-Routing":   "yes",
			"To":                    "<sip:changed@example>",
			"Content-Type":          "text/plain",
		},
	}
	invite, err := BuildInviteRequest(cfg, []byte("v=0\r\n"))
	if err != nil {
		t.Fatalf("BuildInviteRequest() error = %v", err)
	}
	if invite.URI != "urn:service:sos.fire" || invite.Headers["To"] != "<sip:911@ims.example>" {
		t.Fatalf("emergency INVITE target headers=%+v uri=%q", invite.Headers, invite.URI)
	}
	if invite.Headers["P-Preferred-Service"] != "urn:urn-7:3gpp-service.ims.icsi.mmtel" ||
		invite.Headers["Accept-Contact"] != `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";require;explicit` ||
		invite.Headers["P-Access-Network-Info"] != "IEEE-802.11;i-wlan-node-id=\"aa:bb\"" ||
		invite.Headers["Geolocation"] != "<geo:47.6205,-122.3493>;inserted-by=endpoint" ||
		invite.Headers["Geolocation-Routing"] != "yes" {
		t.Fatalf("emergency INVITE headers=%+v", invite.Headers)
	}
	if invite.Headers["Content-Type"] != "application/sdp" {
		t.Fatalf("protected Content-Type=%q", invite.Headers["Content-Type"])
	}
	bye, err := BuildByeRequest(cfg)
	if err != nil {
		t.Fatalf("BuildByeRequest() error = %v", err)
	}
	if bye.URI != "urn:service:sos.fire" || bye.Headers["Geolocation"] != "" || bye.Headers["Accept-Contact"] != "" {
		t.Fatalf("BYE should not inherit INVITE-only emergency headers: %+v", bye)
	}
}

func TestBuildIMSDialogRequestsInjectCarrierHeaders(t *testing.T) {
	cfg := DialogRequestConfig{
		Profile: IMSProfile{IMPU: "sip:user@example"},
		Registration: RegistrationBinding{
			ContactURI: "sip:user@192.0.2.10:5060",
		},
		RemoteURI:         "sip:+18005551212@ims.example",
		RemoteTargetURI:   "sip:+18005551212@pcscf.example",
		CallID:            "call-carrier",
		LocalTag:          "ltag",
		PreferredIdentity: "tel:+15551234567",
		AccessNetworkInfo: `IEEE-802.11;i-wlan-node-id="node-1"`,
		Reason:            `SIP;cause=487;text="Request Terminated"`,
		CarrierHeaders: map[string]string{
			"P-Preferred-Identity":  "sip:preferred@example",
			"P-Access-Network-Info": `3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=0010100abcde`,
			"Reason":                `Q.850;cause=16;text="normal call clearing"`,
			"P-Charging-Vector":     "icid-value=call-carrier",
			"To":                    "<sip:changed@example>",
			"i":                     "changed-call-id",
		},
	}
	cancel, err := BuildCancelRequest(cfg)
	if err != nil {
		t.Fatalf("BuildCancelRequest() error = %v", err)
	}
	if cancel.Headers["P-Preferred-Identity"] != "<sip:preferred@example>" ||
		cancel.Headers["P-Access-Network-Info"] != `3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=0010100abcde` ||
		cancel.Headers["Reason"] != `Q.850;cause=16;text="normal call clearing"` ||
		cancel.Headers["P-Charging-Vector"] != "icid-value=call-carrier" {
		t.Fatalf("carrier CANCEL headers=%+v", cancel.Headers)
	}
	if cancel.Headers["To"] != "<sip:+18005551212@ims.example>" {
		t.Fatalf("protected To was overwritten: %+v", cancel.Headers)
	}
	if cancel.Headers["Call-ID"] != "call-carrier" {
		t.Fatalf("protected compact Call-ID was overwritten: %+v", cancel.Headers)
	}
	bye, err := BuildByeRequest(DialogRequestConfig{
		Profile:           cfg.Profile,
		RemoteURI:         cfg.RemoteURI,
		RemoteTargetURI:   cfg.RemoteTargetURI,
		CallID:            "call-carrier-bye",
		PreferredIdentity: cfg.PreferredIdentity,
		AccessNetworkInfo: cfg.AccessNetworkInfo,
		Reason:            cfg.Reason,
	})
	if err != nil {
		t.Fatalf("BuildByeRequest() error = %v", err)
	}
	if bye.Headers["P-Preferred-Identity"] != "<tel:+15551234567>" ||
		bye.Headers["P-Access-Network-Info"] != `IEEE-802.11;i-wlan-node-id="node-1"` ||
		bye.Headers["Reason"] != `SIP;cause=487;text="Request Terminated"` {
		t.Fatalf("carrier BYE headers=%+v", bye.Headers)
	}
}

func TestFormatDialogReasonHeader(t *testing.T) {
	sipReason, err := FormatDialogReasonHeader("SIP", 487, "")
	if err != nil {
		t.Fatalf("FormatDialogReasonHeader(SIP) error = %v", err)
	}
	if sipReason != `SIP;cause=487;text="Request Terminated"` {
		t.Fatalf("SIP Reason=%q", sipReason)
	}
	q850Reason, err := FormatDialogReasonHeader("Q.850", 16, `normal "clear"`)
	if err != nil {
		t.Fatalf("FormatDialogReasonHeader(Q.850) error = %v", err)
	}
	if q850Reason != `Q.850;cause=16;text="normal \"clear\""` {
		t.Fatalf("Q.850 Reason=%q", q850Reason)
	}
	if _, err := FormatDialogReasonHeader("SIP;bad", 487, ""); !errors.Is(err, ErrInvalidDialogConfig) {
		t.Fatalf("FormatDialogReasonHeader(invalid protocol) err=%v, want ErrInvalidDialogConfig", err)
	}
	if _, err := FormatDialogReasonHeader("SIP", 0, ""); !errors.Is(err, ErrInvalidDialogConfig) {
		t.Fatalf("FormatDialogReasonHeader(invalid cause) err=%v, want ErrInvalidDialogConfig", err)
	}
	if _, err := FormatDialogReasonHeader("SIP", 487, "bad\r\nReason: injected"); !errors.Is(err, ErrInvalidDialogConfig) {
		t.Fatalf("FormatDialogReasonHeader(invalid text) err=%v, want ErrInvalidDialogConfig", err)
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

func TestParseDialogSessionTimerInfoAndRefreshDelay(t *testing.T) {
	resp := SIPResponse{
		StatusCode: 200,
		Reason:     "OK",
		Headers: map[string][]string{
			"Session-Expires": {"1800;refresher=uac"},
			"Min-SE":          {"90"},
		},
	}
	info, err := ParseDialogSessionTimerInfo(resp)
	if err != nil {
		t.Fatalf("ParseDialogSessionTimerInfo() error = %v", err)
	}
	if !info.Active || info.Interval != 1800 || info.Refresher != "uac" || info.MinSE != 90 ||
		info.RefreshAfter != 900*time.Second || info.RetryRequired {
		t.Fatalf("timer info=%+v", info)
	}
	delay, ok, err := DialogSessionRefreshDelay(DialogRequestConfig{}, resp)
	if err != nil || !ok || delay != 900*time.Second {
		t.Fatalf("DialogSessionRefreshDelay() delay=%v ok=%v err=%v", delay, ok, err)
	}
}

func TestDialogSessionRefreshDelaySkipsRemoteRefresher(t *testing.T) {
	resp := SIPResponse{
		StatusCode: 200,
		Reason:     "OK",
		Headers:    map[string][]string{"Session-Expires": {"120;refresher=uas"}},
	}
	delay, ok, err := DialogSessionRefreshDelay(DialogRequestConfig{SessionRefresher: "uac"}, resp)
	if err != nil || ok || delay != 0 {
		t.Fatalf("DialogSessionRefreshDelay(uas) delay=%v ok=%v err=%v", delay, ok, err)
	}

	resp.Headers["Session-Expires"] = []string{"120"}
	delay, ok, err = DialogSessionRefreshDelay(DialogRequestConfig{SessionRefresher: "uas"}, resp)
	if err != nil || ok || delay != 0 {
		t.Fatalf("DialogSessionRefreshDelay(fallback uas) delay=%v ok=%v err=%v", delay, ok, err)
	}
	delay, ok, err = DialogSessionRefreshDelay(DialogRequestConfig{}, resp)
	if err != nil || !ok || delay != time.Minute {
		t.Fatalf("DialogSessionRefreshDelay(default uac) delay=%v ok=%v err=%v", delay, ok, err)
	}
}

func TestParseDialogSessionTimerInfoHandlesMinSEAndRejectsMalformedHeaders(t *testing.T) {
	info, err := ParseDialogSessionTimerInfo(SIPResponse{
		StatusCode: 422,
		Reason:     "Session Interval Too Small",
		Headers:    map[string][]string{"Min-SE": {"600"}},
	})
	if err != nil {
		t.Fatalf("ParseDialogSessionTimerInfo(422) error = %v", err)
	}
	if info.Active || !info.RetryRequired || info.MinSE != 600 {
		t.Fatalf("422 timer info=%+v", info)
	}
	for name, resp := range map[string]SIPResponse{
		"bad Session-Expires": {
			StatusCode: 200,
			Headers:    map[string][]string{"Session-Expires": {"zero;refresher=uac"}},
		},
		"bad refresher": {
			StatusCode: 200,
			Headers:    map[string][]string{"Session-Expires": {"1800;refresher=peer"}},
		},
		"bad Min-SE": {
			StatusCode: 422,
			Headers:    map[string][]string{"Min-SE": {"0"}},
		},
	} {
		if _, err := ParseDialogSessionTimerInfo(resp); !errors.Is(err, ErrInvalidSIPMessage) {
			t.Fatalf("%s error=%v, want ErrInvalidSIPMessage", name, err)
		}
	}
}

func TestDialogSessionTimerRetryConfigAppliesMinSE(t *testing.T) {
	cfg := DialogRequestConfig{
		Profile:         IMSProfile{IMPU: "sip:user@example"},
		Registration:    RegistrationBinding{ContactURI: "sip:user@192.0.2.10:5060"},
		RemoteURI:       "sip:+18005551212@ims.example",
		RemoteTargetURI: "sip:+18005551212@pcscf.example",
		CallID:          "call-min-se",
		CSeq:            8,
		SessionExpires:  90,
		MinSE:           60,
	}
	next, ok, err := DialogSessionTimerRetryConfig(cfg, SIPResponse{
		StatusCode: 422,
		Reason:     "Session Interval Too Small",
		Headers:    map[string][]string{"Min-SE": {"600"}},
	})
	if err != nil || !ok {
		t.Fatalf("DialogSessionTimerRetryConfig() ok=%v err=%v", ok, err)
	}
	if next.MinSE != 600 || next.SessionExpires != 600 || next.CallID != cfg.CallID || next.CSeq != cfg.CSeq {
		t.Fatalf("next config=%+v", next)
	}
	update, err := BuildUpdateRequest(next, nil)
	if err != nil {
		t.Fatalf("BuildUpdateRequest(retry) error = %v", err)
	}
	if update.Headers["Min-SE"] != "600" || update.Headers["Session-Expires"] != "600" {
		t.Fatalf("retry UPDATE headers=%+v", update.Headers)
	}

	unchanged, ok, err := DialogSessionTimerRetryConfig(cfg, SIPResponse{StatusCode: 200})
	if err != nil || ok || unchanged.MinSE != cfg.MinSE || unchanged.SessionExpires != cfg.SessionExpires {
		t.Fatalf("non-422 next=%+v ok=%v err=%v", unchanged, ok, err)
	}
	if _, ok, err := DialogSessionTimerRetryConfig(cfg, SIPResponse{StatusCode: 422}); !errors.Is(err, ErrInvalidSIPMessage) || ok {
		t.Fatalf("missing Min-SE ok=%v err=%v, want ErrInvalidSIPMessage", ok, err)
	}
}

func TestParseProvisionalResponseInfoReliableEarlyMedia(t *testing.T) {
	body := []byte("v=0\r\nm=audio 40000 RTP/AVP 0\r\n")
	resp := SIPResponse{
		StatusCode: 183,
		Reason:     "Session Progress",
		Headers: map[string][]string{
			"Require":      {"timer, 100rel"},
			"RSeq":         {"17"},
			"CSeq":         {"42 INVITE"},
			"To":           {`<sip:+18005551212@ims.example;user=phone>;tag=remote-1`},
			"Contact":      {`<sip:+18005551212@pcscf.example;transport=udp>`},
			"Content-Type": {"application/sdp; charset=utf-8"},
		},
		Body: body,
	}
	info, err := ParseProvisionalResponseInfo(resp)
	if err != nil {
		t.Fatalf("ParseProvisionalResponseInfo() error = %v", err)
	}
	if !info.Reliable || info.RSeq != 17 || info.CSeq != 42 || info.CSeqMethod != "INVITE" || info.RAck != "17 42 INVITE" {
		t.Fatalf("reliable info=%+v", info)
	}
	if !info.EarlyMedia || string(info.SDP) != string(body) || info.RemoteTag != "remote-1" ||
		info.RemoteTargetURI != "sip:+18005551212@pcscf.example;transport=udp" {
		t.Fatalf("media/dialog info=%+v", info)
	}
	body[0] = 'x'
	if string(info.SDP) == string(body) {
		t.Fatalf("SDP was not cloned: %q", info.SDP)
	}
}

func TestBuildPrackRequestForProvisionalResponse(t *testing.T) {
	resp := SIPResponse{
		StatusCode: 183,
		Reason:     "Session Progress",
		Headers: map[string][]string{
			"Require": {"100rel"},
			"RSeq":    {"9"},
			"CSeq":    {"3 INVITE"},
			"To":      {"<sip:+18005551212@ims.example>;tag=early"},
			"Contact": {"<sip:+18005551212@pcscf.example>"},
		},
	}
	prack, ok, err := BuildPrackRequestForProvisionalResponse(DialogRequestConfig{
		Profile:      IMSProfile{IMPU: "sip:user@ims.example"},
		Registration: RegistrationBinding{ContactURI: "sip:user@192.0.2.10:5060"},
		RemoteURI:    "sip:+18005551212@ims.example",
		CallID:       "call-prack",
		LocalTag:     "local",
		CSeq:         4,
	}, resp)
	if err != nil || !ok {
		t.Fatalf("BuildPrackRequestForProvisionalResponse() ok=%v err=%v", ok, err)
	}
	if prack.Method != "PRACK" || prack.URI != "sip:+18005551212@pcscf.example" ||
		prack.Headers["RAck"] != "9 3 INVITE" || prack.Headers["CSeq"] != "4 PRACK" ||
		prack.Headers["To"] != "<sip:+18005551212@ims.example>;tag=early" {
		t.Fatalf("PRACK=%+v", prack)
	}
}

func TestBuildPrackRequestForProvisionalResponseSkipsUnreliable(t *testing.T) {
	resp := SIPResponse{
		StatusCode: 180,
		Reason:     "Ringing",
		Headers:    map[string][]string{"CSeq": {"3 INVITE"}},
	}
	prack, ok, err := BuildPrackRequestForProvisionalResponse(DialogRequestConfig{}, resp)
	if err != nil || ok || prack.Method != "" {
		t.Fatalf("BuildPrackRequestForProvisionalResponse() msg=%+v ok=%v err=%v", prack, ok, err)
	}
	_, err = ParseProvisionalResponseInfo(SIPResponse{
		StatusCode: 183,
		Reason:     "Session Progress",
		Headers: map[string][]string{
			"Require": {"100rel"},
			"CSeq":    {"3 INVITE"},
		},
	})
	if !errors.Is(err, ErrInvalidSIPMessage) {
		t.Fatalf("ParseProvisionalResponseInfo(missing RSeq) err=%v, want ErrInvalidSIPMessage", err)
	}
}

func TestBuildAckRequestForInviteResponse(t *testing.T) {
	resp := SIPResponse{
		StatusCode: 200,
		Reason:     "OK",
		Headers: map[string][]string{
			"CSeq":    {"7 INVITE"},
			"To":      {"<sip:+18005551212@ims.example>;tag=remote-ack"},
			"Contact": {"<sip:+18005551212@pcscf.example>"},
		},
	}
	ack, ok, err := BuildAckRequestForInviteResponse(DialogRequestConfig{
		Profile:   IMSProfile{IMPU: "sip:user@example"},
		RemoteURI: "sip:+18005551212@ims.example",
		CallID:    "call-ack",
		LocalTag:  "local-ack",
	}, resp)
	if err != nil || !ok {
		t.Fatalf("BuildAckRequestForInviteResponse() ok=%v err=%v", ok, err)
	}
	if ack.Method != "ACK" || ack.URI != "sip:+18005551212@pcscf.example" ||
		ack.Headers["CSeq"] != "7 ACK" ||
		ack.Headers["To"] != "<sip:+18005551212@ims.example>;tag=remote-ack" {
		t.Fatalf("ACK=%+v", ack)
	}
	if !DialogResponseRequiresAck("INVITE", SIPResponse{StatusCode: 487}) ||
		DialogResponseRequiresAck("UPDATE", SIPResponse{StatusCode: 491}) ||
		!DialogResponseIsInviteTerminated(SIPResponse{StatusCode: 487}) ||
		!DialogResponseIsRequestPending(SIPResponse{StatusCode: 491}) {
		t.Fatalf("dialog response helpers returned unexpected values")
	}
	provisional, ok, err := BuildAckRequestForInviteResponse(DialogRequestConfig{}, SIPResponse{StatusCode: 183})
	if err != nil || ok || provisional.Method != "" {
		t.Fatalf("BuildAckRequestForInviteResponse(provisional) msg=%+v ok=%v err=%v", provisional, ok, err)
	}
	_, _, err = BuildAckRequestForInviteResponse(DialogRequestConfig{}, SIPResponse{
		StatusCode: 486,
		Headers:    map[string][]string{"CSeq": {"bad INVITE"}},
	})
	if !errors.Is(err, ErrInvalidSIPMessage) {
		t.Fatalf("BuildAckRequestForInviteResponse(invalid CSeq) err=%v, want ErrInvalidSIPMessage", err)
	}
}

func TestAdvanceDialogSessionStateInviteCancelBye(t *testing.T) {
	state := AdvanceDialogSessionState("", "INVITE", SIPResponse{StatusCode: 100})
	if state != DialogSessionStateCalling {
		t.Fatalf("100 INVITE state=%q", state)
	}
	state = AdvanceDialogSessionState(state, "INVITE", SIPResponse{StatusCode: 183})
	if state != DialogSessionStateEarly {
		t.Fatalf("183 INVITE state=%q", state)
	}
	state = AdvanceDialogSessionState(state, "PRACK", SIPResponse{StatusCode: 200})
	if state != DialogSessionStateEarly {
		t.Fatalf("200 PRACK state=%q", state)
	}
	state = AdvanceDialogSessionState(state, "INVITE", SIPResponse{StatusCode: 200})
	if state != DialogSessionStateConfirmed {
		t.Fatalf("200 INVITE state=%q", state)
	}
	state = AdvanceDialogSessionState(state, "BYE", SIPResponse{StatusCode: 200})
	if state != DialogSessionStateTerminated {
		t.Fatalf("200 BYE state=%q", state)
	}
	if rejected := AdvanceDialogSessionState(DialogSessionStateCalling, "INVITE", SIPResponse{StatusCode: 486}); rejected != DialogSessionStateTerminated {
		t.Fatalf("486 INVITE state=%q", rejected)
	}
	if canceling := AdvanceDialogSessionState(DialogSessionStateEarly, "CANCEL", SIPResponse{StatusCode: 200}); canceling != DialogSessionStateTerminating {
		t.Fatalf("200 CANCEL state=%q", canceling)
	}
	canceling := AdvanceDialogSessionState(DialogSessionStateEarly, "CANCEL", SIPResponse{StatusCode: 200})
	if terminated := AdvanceDialogSessionState(canceling, "INVITE", SIPResponse{StatusCode: 487}); terminated != DialogSessionStateTerminated {
		t.Fatalf("487 INVITE after CANCEL state=%q", terminated)
	}
	if pending := AdvanceDialogSessionState(DialogSessionStateConfirmed, "INVITE", SIPResponse{StatusCode: 491}); pending != DialogSessionStateConfirmed {
		t.Fatalf("491 re-INVITE state=%q", pending)
	}
	if gone := AdvanceDialogSessionState(DialogSessionStateConfirmed, "INVITE", SIPResponse{StatusCode: 481}); gone != DialogSessionStateTerminated {
		t.Fatalf("481 re-INVITE state=%q", gone)
	}
	if gone := AdvanceDialogSessionState(DialogSessionStateEarly, "UPDATE", SIPResponse{StatusCode: 481}); gone != DialogSessionStateTerminated {
		t.Fatalf("481 UPDATE state=%q", gone)
	}
}

func TestBuildIMSDialogRequestsUseRegistrationDigestAuthSession(t *testing.T) {
	ch := DigestChallenge{Scheme: "Digest", Realm: "ims.example", Nonce: "nonce-dialog", Algorithm: "MD5", QOP: "auth"}
	state := newDigestAuthState("Proxy-Authorization", ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce",
		NC:       1,
	}, "")
	cfg := DialogRequestConfig{
		Profile: IMSProfile{IMPU: "sip:user@ims.example", UserAgent: "VoHive"},
		Registration: RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
			AuthHeaderName: "Proxy-Authorization",
			AuthSession:    NewDigestAuthSession("Proxy-Authorization", "", state),
		},
		RemoteURI:       "sip:+18005551212@ims.example",
		RemoteTargetURI: "sip:+18005551212@pcscf.example",
		CallID:          "call-auth-dialog",
		LocalTag:        "ltag",
		RemoteTag:       "rtag",
		CSeq:            7,
	}
	invite, err := BuildInviteRequest(cfg, []byte("v=0\r\n"))
	if err != nil {
		t.Fatalf("BuildInviteRequest() error = %v", err)
	}
	auth := invite.Headers["Proxy-Authorization"]
	if auth == "" || invite.Headers["Authorization"] != "" ||
		!strings.Contains(auth, `uri="sip:+18005551212@pcscf.example"`) ||
		!strings.Contains(auth, `nc=00000002`) {
		t.Fatalf("INVITE auth headers=%+v", invite.Headers)
	}
	bye, err := BuildByeRequest(cfg)
	if err != nil {
		t.Fatalf("BuildByeRequest() error = %v", err)
	}
	if auth := bye.Headers["Proxy-Authorization"]; !strings.Contains(auth, `nc=00000003`) ||
		!strings.Contains(auth, `uri="sip:+18005551212@pcscf.example"`) {
		t.Fatalf("BYE auth=%q headers=%+v", auth, bye.Headers)
	}
}

func TestBuildIMSDialogRequestsDigestAuthIntUsesBody(t *testing.T) {
	ch := DigestChallenge{Scheme: "Digest", Realm: "ims.example", Nonce: "nonce-dialog-int", Algorithm: "MD5", QOP: "auth-int"}
	state := newDigestAuthState("Authorization", ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce",
		NC:       1,
	}, "")
	body := []byte("hello over IMS")
	cfg := DialogRequestConfig{
		Profile: IMSProfile{IMPU: "sip:user@ims.example"},
		Registration: RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
			AuthSession:    NewDigestAuthSession("Authorization", "", state),
		},
		RemoteURI:       "sip:+18005551212@ims.example",
		RemoteTargetURI: "sip:+18005551212@pcscf.example",
		CallID:          "call-auth-int-dialog",
		CSeq:            2,
	}
	msg, err := BuildMessageRequest(cfg, "text/plain;charset=UTF-8", body)
	if err != nil {
		t.Fatalf("BuildMessageRequest() error = %v", err)
	}
	want, _, err := state.BuildWithBody("MESSAGE", "sip:+18005551212@pcscf.example", body)
	if err != nil {
		t.Fatalf("BuildWithBody() error = %v", err)
	}
	if got := msg.Headers["Authorization"]; got != want {
		t.Fatalf("MESSAGE Authorization=%s, want %s", got, want)
	}
}

func TestApplyDigestAuthenticationInfoUpdatesDialogSession(t *testing.T) {
	ch := DigestChallenge{Scheme: "Digest", Realm: "ims.example", Nonce: "nonce-dialog-info", Algorithm: "MD5", QOP: "auth"}
	state := newDigestAuthState("Authorization", ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce",
		NC:       1,
	}, "")
	session := NewDigestAuthSession("Authorization", "", state)
	cfg := DialogRequestConfig{
		Profile: IMSProfile{IMPU: "sip:user@ims.example"},
		Registration: RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
			AuthSession:    session,
		},
		RemoteURI:       "sip:+18005551212@ims.example",
		RemoteTargetURI: "sip:+18005551212@pcscf.example",
		CallID:          "call-info-auth",
		CSeq:            4,
	}
	msg, err := BuildMessageRequest(cfg, "text/plain;charset=UTF-8", []byte("hello"))
	if err != nil {
		t.Fatalf("BuildMessageRequest() error = %v", err)
	}
	if !strings.Contains(msg.Headers["Authorization"], `nonce="nonce-dialog-info"`) || !strings.Contains(msg.Headers["Authorization"], `nc=00000002`) {
		t.Fatalf("initial MESSAGE Authorization=%s", msg.Headers["Authorization"])
	}
	_, _, snapshot := session.Snapshot()
	rspauth, err := digestRspauth(snapshot, "auth", []byte("accepted"))
	if err != nil {
		t.Fatalf("digestRspauth() error = %v", err)
	}
	if err := ApplyDigestAuthenticationInfo(msg, SIPResponse{
		StatusCode: 202,
		Reason:     "Accepted",
		Headers:    map[string][]string{"Authentication-Info": {`nextnonce="nonce-dialog-next", qop=auth, rspauth="` + rspauth + `"`}},
		Body:       []byte("accepted"),
	}); err != nil {
		t.Fatalf("ApplyDigestAuthenticationInfo() error = %v", err)
	}
	bye, err := BuildByeRequest(cfg)
	if err != nil {
		t.Fatalf("BuildByeRequest() error = %v", err)
	}
	if auth := bye.Headers["Authorization"]; !strings.Contains(auth, `nonce="nonce-dialog-next"`) || !strings.Contains(auth, `nc=00000001`) {
		t.Fatalf("BYE Authorization after nextnonce=%s", auth)
	}
}

func TestApplyDigestAuthenticationInfoRejectsRspauthMismatch(t *testing.T) {
	ch := DigestChallenge{Scheme: "Digest", Realm: "ims.example", Nonce: "nonce-dialog-bad", Algorithm: "MD5", QOP: "auth"}
	state := newDigestAuthState("Authorization", ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce",
		NC:       1,
	}, "")
	session := NewDigestAuthSession("Authorization", "", state)
	cfg := DialogRequestConfig{
		Profile: IMSProfile{IMPU: "sip:user@ims.example"},
		Registration: RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
			AuthSession:    session,
		},
		RemoteURI:       "sip:+18005551212@ims.example",
		RemoteTargetURI: "sip:+18005551212@pcscf.example",
		CallID:          "call-info-auth-bad",
		CSeq:            5,
	}
	msg, err := BuildInfoRequest(cfg, "application/dtmf-relay", []byte("Signal=1\r\n"))
	if err != nil {
		t.Fatalf("BuildInfoRequest() error = %v", err)
	}
	err = ApplyDigestAuthenticationInfo(msg, SIPResponse{
		StatusCode: 200,
		Reason:     "OK",
		Headers:    map[string][]string{"Authentication-Info": {`rspauth="bad"`}},
	})
	if !errors.Is(err, ErrInvalidAuthenticationInfo) {
		t.Fatalf("ApplyDigestAuthenticationInfo() error=%v, want ErrInvalidAuthenticationInfo", err)
	}
}

func TestDigestChallengeRetryRequestUpdatesSession(t *testing.T) {
	ch := DigestChallenge{Scheme: "Digest", Realm: "ims.example", Nonce: "nonce-dialog-old", Algorithm: "MD5", QOP: "auth"}
	state := newDigestAuthState("Authorization", ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce",
		NC:       1,
	}, "")
	session := NewDigestAuthSession("Authorization", "", state)
	msg := SIPRequestMessage{
		Method:      "MESSAGE",
		URI:         "sip:+18005551212@pcscf.example",
		Headers:     map[string]string{"Authorization": "Digest old", "Proxy-Authorization": "Digest old-proxy"},
		Body:        []byte("hello"),
		AuthSession: session,
	}
	retry, ok, err := DigestChallengeRetryRequest(msg, SIPResponse{
		StatusCode: 407,
		Reason:     "Proxy Authentication Required",
		Headers: map[string][]string{
			"Proxy-Authenticate": {`Digest realm="ims.example", nonce="nonce-dialog-new", algorithm=MD5, qop="auth"`},
		},
	})
	if err != nil || !ok {
		t.Fatalf("DigestChallengeRetryRequest() ok=%v err=%v", ok, err)
	}
	if retry.Headers["Authorization"] != "" {
		t.Fatalf("retry kept Authorization: %+v", retry.Headers)
	}
	auth := retry.Headers["Proxy-Authorization"]
	if !strings.Contains(auth, `nonce="nonce-dialog-new"`) ||
		!strings.Contains(auth, `uri="sip:+18005551212@pcscf.example"`) ||
		!strings.Contains(auth, `nc=00000001`) {
		t.Fatalf("retry Proxy-Authorization=%s", auth)
	}
	next, err := BuildByeRequest(DialogRequestConfig{
		Profile: IMSProfile{IMPU: "sip:user@ims.example"},
		Registration: RegistrationBinding{
			ContactURI:     "sip:user@192.0.2.10:5060",
			PublicIdentity: "sip:user@ims.example",
			AuthSession:    session,
		},
		RemoteURI:       "sip:+18005551212@ims.example",
		RemoteTargetURI: "sip:+18005551212@pcscf.example",
		CallID:          "call-rechallenge",
		CSeq:            3,
	})
	if err != nil {
		t.Fatalf("BuildByeRequest() error = %v", err)
	}
	if auth := next.Headers["Proxy-Authorization"]; !strings.Contains(auth, `nonce="nonce-dialog-new"`) || !strings.Contains(auth, `nc=00000002`) {
		t.Fatalf("next BYE auth=%s", auth)
	}
}

func TestDigestChallengeRetryRequestCleansAuthHeadersAndIncrementsCSeq(t *testing.T) {
	ch := DigestChallenge{Scheme: "Digest", Realm: "ims.example", Nonce: "nonce-update-old", Algorithm: "MD5", QOP: "auth"}
	state := newDigestAuthState("Authorization", ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce",
		NC:       1,
	}, "")
	msg := SIPRequestMessage{
		Method: "UPDATE",
		URI:    "sip:+18005551212@pcscf.example",
		Headers: map[string]string{
			"authorization":       "Digest old-origin",
			"Proxy-Authorization": "Digest old-proxy",
			"CSeq":                "4 UPDATE",
		},
		Body:        []byte("v=0\r\n"),
		AuthSession: NewDigestAuthSession("Authorization", "", state),
	}
	retry, ok, err := DigestChallengeRetryRequest(msg, SIPResponse{
		StatusCode: 401,
		Reason:     "Unauthorized",
		Headers: map[string][]string{
			"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce-update-new", algorithm=MD5, qop="auth"`},
		},
	})
	if err != nil || !ok {
		t.Fatalf("DigestChallengeRetryRequest() ok=%v err=%v", ok, err)
	}
	if retry.Headers["authorization"] != "" || retry.Headers["Proxy-Authorization"] != "" {
		t.Fatalf("retry kept stale auth headers: %+v", retry.Headers)
	}
	if retry.Headers["CSeq"] != "5 UPDATE" {
		t.Fatalf("retry CSeq=%q, want 5 UPDATE", retry.Headers["CSeq"])
	}
	auth := retry.Headers["Authorization"]
	if !strings.Contains(auth, `nonce="nonce-update-new"`) || !strings.Contains(auth, `uri="sip:+18005551212@pcscf.example"`) ||
		!strings.Contains(auth, `nc=00000001`) {
		t.Fatalf("retry Authorization=%s", auth)
	}
}

func TestRoundTripRequestWithDigestAuthRetriesChallenge(t *testing.T) {
	ch := DigestChallenge{Scheme: "Digest", Realm: "ims.example", Nonce: "nonce-roundtrip-old", Algorithm: "MD5", QOP: "auth"}
	state := newDigestAuthState("Authorization", ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce",
		NC:       1,
	}, "")
	transport := &fakeSIPRequestRoundTripTransport{responses: []SIPResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers:    map[string][]string{"WWW-Authenticate": {`Digest realm="ims.example", nonce="nonce-roundtrip-new", algorithm=MD5, qop="auth"`}},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	resp, err := RoundTripRequestWithDigestAuth(context.Background(), transport, SIPRequestMessage{
		Method:      "INFO",
		URI:         "sip:remote@ims.example",
		Headers:     map[string]string{"Authorization": "Digest old"},
		Body:        []byte("Signal=1\r\n"),
		AuthSession: NewDigestAuthSession("Authorization", "", state),
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRequestWithDigestAuth() resp=%+v err=%v", resp, err)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests=%+v", transport.requests)
	}
	if auth := transport.requests[1].Headers["Authorization"]; !strings.Contains(auth, `nonce="nonce-roundtrip-new"`) || !strings.Contains(auth, `nc=00000001`) {
		t.Fatalf("retry Authorization=%s", auth)
	}
}

func TestRoundTripRequestWithDigestAuthAcksAndRetriesInviteChallenge(t *testing.T) {
	ch := DigestChallenge{Scheme: "Digest", Realm: "ims.example", Nonce: "nonce-invite-old", Algorithm: "MD5", QOP: "auth"}
	state := newDigestAuthState("Authorization", ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      "sip:ims.example",
		Username: "impi@example",
		Password: "secret",
		CNonce:   "cnonce",
		NC:       1,
	}, "")
	transport := &fakeSIPRequestRoundTripTransport{responses: []SIPResponse{
		{
			StatusCode: 407,
			Reason:     "Proxy Authentication Required",
			Headers: map[string][]string{
				"Proxy-Authenticate": {`Digest realm="ims.example", nonce="nonce-invite-new", algorithm=MD5, qop="auth"`},
				"To":                 {`<sip:+18005551212@ims.example>;tag=remote`},
				"CSeq":               {"7 INVITE"},
			},
		},
		{StatusCode: 200, Reason: "OK"},
	}}
	resp, err := RoundTripRequestWithDigestAuth(context.Background(), transport, SIPRequestMessage{
		Method: "INVITE",
		URI:    "sip:+18005551212@pcscf.example",
		Headers: map[string]string{
			"To":            "<sip:+18005551212@ims.example>",
			"From":          "<sip:user@ims.example>;tag=local",
			"Call-ID":       "call-invite-auth",
			"CSeq":          "7 INVITE",
			"Route":         "<sip:pcscf.example;lr>",
			"Max-Forwards":  "70",
			"Authorization": "Digest old",
		},
		Body:        []byte("v=0\r\n"),
		AuthSession: NewDigestAuthSession("Authorization", "", state),
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("RoundTripRequestWithDigestAuth() resp=%+v err=%v", resp, err)
	}
	if len(transport.requests) != 3 {
		t.Fatalf("requests=%+v", transport.requests)
	}
	ack := transport.requests[1]
	if ack.Method != "ACK" || ack.URI != "sip:+18005551212@pcscf.example" ||
		ack.Headers["CSeq"] != "7 ACK" ||
		ack.Headers["To"] != "<sip:+18005551212@ims.example>;tag=remote" ||
		ack.Headers["Call-ID"] != "call-invite-auth" {
		t.Fatalf("ACK request=%+v", ack)
	}
	retry := transport.requests[2]
	if retry.Method != "INVITE" || retry.Headers["CSeq"] != "8 INVITE" || retry.Headers["Authorization"] != "" {
		t.Fatalf("retry INVITE=%+v", retry)
	}
	auth := retry.Headers["Proxy-Authorization"]
	if !strings.Contains(auth, `nonce="nonce-invite-new"`) ||
		!strings.Contains(auth, `uri="sip:+18005551212@pcscf.example"`) ||
		!strings.Contains(auth, `nc=00000001`) {
		t.Fatalf("retry Proxy-Authorization=%s", auth)
	}
}

func TestRoundTripRequestWithDigestAuthRecomputesAKAChallenge(t *testing.T) {
	registerNonce := append(bytesFrom(0x10, 16), bytesFrom(0x40, 16)...)
	dialogNonce := append(bytesFrom(0x60, 16), bytesFrom(0x80, 16)...)
	registerChallenge := `Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(registerNonce) + `", algorithm=AKAv1-MD5, qop="auth"`
	dialogChallenge := `Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(dialogNonce) + `", algorithm=AKAv1-MD5, qop="auth"`
	aka := &sequenceAKAProvider{results: []sim.AKAResult{
		{RES: []byte{0xAA, 0xBB, 0xCC, 0xDD}},
		{RES: []byte{0x11, 0x22, 0x33, 0x44}},
	}}
	registered, err := RegisterSession{
		Transport: &fakeRegisterTransport{responses: []RegisterResponse{
			{
				StatusCode: 401,
				Reason:     "Unauthorized",
				Headers:    map[string][]string{"WWW-Authenticate": {registerChallenge}},
			},
			{
				StatusCode: 200,
				Reason:     "OK",
				Headers:    map[string][]string{"Contact": {`<sip:user@192.0.2.10:5060>;expires=1800`}},
			},
		}},
		AKAProvider:  aka,
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@ims.example", Domain: "ims.example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "register-aka-dialog",
		CNonce:       "cnonce",
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !registered.Registered || registered.Binding.AuthSession == nil || len(aka.rands) != 1 {
		t.Fatalf("registered=%+v AKA rands=%x", registered, aka.rands)
	}
	msg, err := BuildMessageRequest(DialogRequestConfig{
		Profile:      IMSProfile{IMPI: "impi@example", IMPU: "sip:user@ims.example", Domain: "ims.example"},
		Registration: registered.Binding,
		RemoteURI:    "sip:+18005551212@ims.example",
		CallID:       "message-aka-dialog",
		CSeq:         2,
	}, "text/plain;charset=UTF-8", []byte("hello"))
	if err != nil {
		t.Fatalf("BuildMessageRequest() error = %v", err)
	}
	transport := &fakeSIPRequestRoundTripTransport{responses: []SIPResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers:    map[string][]string{"WWW-Authenticate": {dialogChallenge}},
		},
		{StatusCode: 202, Reason: "Accepted"},
	}}
	resp, err := RoundTripRequestWithDigestAuth(context.Background(), transport, msg)
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("RoundTripRequestWithDigestAuth() resp=%+v err=%v", resp, err)
	}
	if len(aka.rands) != 2 || !bytesEqual(aka.rands[1], bytesFrom(0x60, 16)) {
		t.Fatalf("AKA rands=%x", aka.rands)
	}
	ch, err := ParseWWWAuthenticate(dialogChallenge)
	if err != nil {
		t.Fatalf("ParseWWWAuthenticate() error = %v", err)
	}
	want, err := BuildDigestAuthorization(ch, DigestAuthInput{
		Method:   "MESSAGE",
		URI:      msg.URI,
		Username: "impi@example",
		Password: string([]byte{0x11, 0x22, 0x33, 0x44}),
		CNonce:   "cnonce",
		NC:       1,
		Body:     msg.Body,
	})
	if err != nil {
		t.Fatalf("BuildDigestAuthorization() error = %v", err)
	}
	if got := transport.requests[1].Headers["Authorization"]; got != want {
		t.Fatalf("retry Authorization=%s, want %s", got, want)
	}
}

func TestRoundTripRequestWithDigestAuthHandlesAKASyncFailureChallenge(t *testing.T) {
	staleNonce := append(bytesFrom(0x20, 16), bytesFrom(0x50, 16)...)
	freshNonce := append(bytesFrom(0x70, 16), bytesFrom(0x90, 16)...)
	staleChallenge := `Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(staleNonce) + `", algorithm=AKAv1-MD5, qop="auth"`
	freshChallenge := `Digest realm="ims.example", nonce="` + base64.StdEncoding.EncodeToString(freshNonce) + `", algorithm=AKAv1-MD5, qop="auth"`
	auts := bytesFrom(0xC0, 14)
	calls := 0
	session := NewDigestAuthSessionWithChallengeInput("Authorization", "Digest old", DigestAuthState{}, func(ch DigestChallenge, uri string) (DigestAuthInput, error) {
		calls++
		input := DigestAuthInput{
			Username: "impi@example",
			CNonce:   "cnonce",
		}
		switch calls {
		case 1:
			input.AUTS = append([]byte(nil), auts...)
		case 2:
			input.Password = string([]byte{0x11, 0x22, 0x33, 0x44})
		default:
			t.Fatalf("unexpected digest challenge call %d for %+v uri=%q", calls, ch, uri)
		}
		return input, nil
	})
	msg := SIPRequestMessage{
		Method:      "MESSAGE",
		URI:         "sip:+18005551212@ims.example",
		Headers:     map[string]string{"Authorization": "Digest old"},
		Body:        []byte("hello"),
		AuthSession: session,
	}
	transport := &fakeSIPRequestRoundTripTransport{responses: []SIPResponse{
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers:    map[string][]string{"WWW-Authenticate": {staleChallenge}},
		},
		{
			StatusCode: 401,
			Reason:     "Unauthorized",
			Headers:    map[string][]string{"WWW-Authenticate": {freshChallenge}},
		},
		{StatusCode: 202, Reason: "Accepted"},
	}}
	resp, err := RoundTripRequestWithDigestAuth(context.Background(), transport, msg)
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("RoundTripRequestWithDigestAuth() resp=%+v err=%v", resp, err)
	}
	if calls != 2 || len(transport.requests) != 3 {
		t.Fatalf("calls=%d requests=%+v", calls, transport.requests)
	}
	syncAuth := transport.requests[1].Headers["Authorization"]
	if !strings.Contains(syncAuth, `nonce="`+base64.StdEncoding.EncodeToString(staleNonce)+`"`) ||
		!strings.Contains(syncAuth, `auts="`+base64.StdEncoding.EncodeToString(auts)+`"`) {
		t.Fatalf("sync retry Authorization=%s", syncAuth)
	}
	finalAuth := transport.requests[2].Headers["Authorization"]
	if strings.Contains(finalAuth, `auts=`) {
		t.Fatalf("final retry kept AUTS: %s", finalAuth)
	}
	ch, err := ParseWWWAuthenticate(freshChallenge)
	if err != nil {
		t.Fatalf("ParseWWWAuthenticate() error = %v", err)
	}
	want, err := BuildDigestAuthorization(ch, DigestAuthInput{
		Method:   "MESSAGE",
		URI:      msg.URI,
		Username: "impi@example",
		Password: string([]byte{0x11, 0x22, 0x33, 0x44}),
		CNonce:   "cnonce",
		NC:       1,
		Body:     msg.Body,
	})
	if err != nil {
		t.Fatalf("BuildDigestAuthorization() error = %v", err)
	}
	if finalAuth != want {
		t.Fatalf("final retry Authorization=%s, want %s", finalAuth, want)
	}
}

func TestDigestChallengeRetryRequestSkipsInvite(t *testing.T) {
	retry, ok, err := DigestChallengeRetryRequest(SIPRequestMessage{
		Method:      "INVITE",
		AuthSession: NewDigestAuthSession("Authorization", "", DigestAuthState{}),
	}, SIPResponse{StatusCode: 401})
	if err != nil || ok || retry.Method != "" {
		t.Fatalf("DigestChallengeRetryRequest(INVITE) retry=%+v ok=%v err=%v", retry, ok, err)
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

type fakeSecurityPlanInstaller struct {
	transport      *fakeRegisterTransport
	calls          []IMSSecurityAssociationPlan
	requestsAtCall []int
	err            error
}

func (f *fakeSecurityPlanInstaller) InstallSecurityPlan(ctx context.Context, plan IMSSecurityAssociationPlan) error {
	f.calls = append(f.calls, plan)
	if f.transport != nil {
		f.requestsAtCall = append(f.requestsAtCall, len(f.transport.requests))
	}
	return f.err
}

type fakeRichSecurityPlanInstaller struct {
	transport      *fakeRegisterTransport
	requests       []IMSSecurityAssociationInstallRequest
	requestsAtCall []int
	legacyCalls    []IMSSecurityAssociationPlan
	err            error
}

func (f *fakeRichSecurityPlanInstaller) InstallSecurityPlan(ctx context.Context, plan IMSSecurityAssociationPlan) error {
	f.legacyCalls = append(f.legacyCalls, plan)
	return f.err
}

func (f *fakeRichSecurityPlanInstaller) InstallSecurityPlanRequest(ctx context.Context, req IMSSecurityAssociationInstallRequest) error {
	f.requests = append(f.requests, cloneIMSSecurityAssociationInstallRequest(req))
	if f.transport != nil {
		f.requestsAtCall = append(f.requestsAtCall, len(f.transport.requests))
	}
	return f.err
}

type fakeSIPRequestRoundTripTransport struct {
	requests  []SIPRequestMessage
	responses []SIPResponse
}

func (t *fakeSIPRequestRoundTripTransport) RoundTripRequest(ctx context.Context, msg SIPRequestMessage) (SIPResponse, error) {
	t.requests = append(t.requests, cloneSIPRequestMessage(msg))
	if len(t.responses) == 0 {
		return SIPResponse{StatusCode: 500, Reason: "empty"}, nil
	}
	resp := t.responses[0]
	t.responses = t.responses[1:]
	return resp, nil
}

func (t *fakeSIPRequestRoundTripTransport) WriteRequest(ctx context.Context, msg SIPRequestMessage) error {
	t.requests = append(t.requests, cloneSIPRequestMessage(msg))
	return nil
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

type sequenceAKAProvider struct {
	results []sim.AKAResult
	rands   [][]byte
	autns   [][]byte
}

func (p *sequenceAKAProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	p.rands = append(p.rands, append([]byte(nil), rand16...))
	p.autns = append(p.autns, append([]byte(nil), autn16...))
	if len(p.results) == 0 {
		return sim.AKAResult{RES: []byte{0xAA, 0xBB, 0xCC, 0xDD}}, nil
	}
	result := p.results[0]
	p.results = p.results[1:]
	result.RES = append([]byte(nil), result.RES...)
	result.CK = append([]byte(nil), result.CK...)
	result.IK = append([]byte(nil), result.IK...)
	result.AUTS = append([]byte(nil), result.AUTS...)
	return result, nil
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

func sha256Hex(value string) string {
	return sha256HexBytes([]byte(value))
}

func sha256HexBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func sha512256Hex(value string) string {
	sum := sha512.Sum512_256([]byte(value))
	return hex.EncodeToString(sum[:])
}
