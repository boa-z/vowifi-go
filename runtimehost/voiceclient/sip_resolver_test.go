package voiceclient

import "testing"

func TestNormalizeDNSServerAddrs(t *testing.T) {
	got := normalizeDNSServerAddrs([]string{
		"10.0.0.53",
		"10.0.0.53:5353",
		"[2001:db8::53]",
		"[2001:db8::54]:5353",
		"10.0.0.53",
		"",
	})
	want := []string{
		"10.0.0.53:53",
		"10.0.0.53:5353",
		"[2001:db8::53]:53",
		"[2001:db8::54]:5353",
	}
	if len(got) != len(want) {
		t.Fatalf("addrs=%+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("addrs[%d]=%q, want %q (all=%+v)", i, got[i], want[i], got)
		}
	}
}

func TestParseSIPURIEndpointDefaultsSIPSPort(t *testing.T) {
	endpoint, err := parseSIPURIEndpoint("sips:user@ims.example;transport=tcp")
	if err != nil {
		t.Fatalf("parseSIPURIEndpoint() error = %v", err)
	}
	if endpoint.addr() != "ims.example:5061" || !endpoint.Secure || endpoint.ExplicitPort {
		t.Fatalf("endpoint=%+v addr=%q", endpoint, endpoint.addr())
	}
}

func TestParseSIPURIEndpointAcceptsIMSHeaderForms(t *testing.T) {
	tests := []struct {
		name         string
		uri          string
		wantAddr     string
		wantSecure   bool
		wantExplicit bool
	}{
		{
			name:     "service route list",
			uri:      `<sip:pcscf1.ims.example;lr>, <sip:pcscf2.ims.example;lr>`,
			wantAddr: "pcscf1.ims.example:5060",
		},
		{
			name:       "quoted display name with sips ipv6",
			uri:        `"Proxy, Primary" <sips:user@[2001:db8::10];transport=tcp;lr>;q=1`,
			wantAddr:   "[2001:db8::10]:5061",
			wantSecure: true,
		},
		{
			name:         "userinfo parameters before host",
			uri:          `<sip:+18005551212;phone-context=+1@pcscf.ims.example:5070;user=phone>;expires=600`,
			wantAddr:     "pcscf.ims.example:5070",
			wantExplicit: true,
		},
		{
			name:     "uppercase scheme with headers",
			uri:      `SIP:user@pcscf.ims.example;transport=udp?Route=<sip:edge.ims.example;lr>`,
			wantAddr: "pcscf.ims.example:5060",
		},
		{
			name:     "header query contains at sign",
			uri:      `sip:pcscf.ims.example?Route=sip:user@edge.ims.example`,
			wantAddr: "pcscf.ims.example:5060",
		},
		{
			name:     "embedded name addr",
			uri:      `Route <sip:edge.ims.example;lr>;received=192.0.2.10`,
			wantAddr: "edge.ims.example:5060",
		},
		{
			name:     "unbracketed ipv6 literal without port",
			uri:      `sip:2001:db8::20`,
			wantAddr: "[2001:db8::20]:5060",
		},
		{
			name:     "skip tel candidate",
			uri:      `<tel:+18005551212>, <sip:pcscf3.ims.example;lr>`,
			wantAddr: "pcscf3.ims.example:5060",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint, err := parseSIPURIEndpoint(tt.uri)
			if err != nil {
				t.Fatalf("parseSIPURIEndpoint() error = %v", err)
			}
			if endpoint.addr() != tt.wantAddr || endpoint.Secure != tt.wantSecure || endpoint.ExplicitPort != tt.wantExplicit {
				t.Fatalf("endpoint=%+v addr=%q, want addr=%q secure=%t explicit=%t", endpoint, endpoint.addr(), tt.wantAddr, tt.wantSecure, tt.wantExplicit)
			}
		})
	}
}

func TestParseSIPURIEndpointRejectsMalformedIPv6Route(t *testing.T) {
	if _, err := parseSIPURIEndpoint(`<sip:user@[2001:db8::10;lr>`); err == nil {
		t.Fatal("parseSIPURIEndpoint() error = nil, want malformed IPv6 host error")
	}
}
