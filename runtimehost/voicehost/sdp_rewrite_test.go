package voicehost

import (
	"strings"
	"testing"
)

func TestRewriteSDPMediaEndpointPreservesCodecAttributes(t *testing.T) {
	raw := []byte("v=0\r\n" +
		"o=user 0 0 IN IP4 192.0.2.10\r\n" +
		"s=-\r\n" +
		"c=IN IP4 192.0.2.10\r\n" +
		"t=0 0\r\n" +
		"m=audio 4002 RTP/AVP 96 101\r\n" +
		"a=rtpmap:96 AMR/8000\r\n" +
		"a=fmtp:96 octet-align=1\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n")
	got := string(RewriteSDPMediaEndpoint(raw, SDPInfo{ConnectionIP: "198.51.100.20", MediaPort: 49170}))
	if !strings.Contains(got, "c=IN IP4 198.51.100.20\r\n") || !strings.Contains(got, "m=audio 49170 RTP/AVP 96 101\r\n") {
		t.Fatalf("rewritten SDP endpoint wrong:\n%s", got)
	}
	for _, want := range []string{"a=rtpmap:96 AMR/8000", "a=fmtp:96 octet-align=1", "a=rtpmap:101 telephone-event/8000"} {
		if !strings.Contains(got, want) {
			t.Fatalf("rewritten SDP missing %q:\n%s", want, got)
		}
	}
}

func TestRewriteSDPMediaEndpointUsesIPv6ConnectionLine(t *testing.T) {
	raw := []byte("v=0\r\nm=audio 4002 RTP/AVP 0\r\n")
	got := string(RewriteSDPMediaEndpoint(raw, SDPInfo{ConnectionIP: "2001:db8::1", MediaPort: 5004}))
	if !strings.Contains(got, "c=IN IP6 2001:db8::1\r\n") || !strings.Contains(got, "m=audio 5004 RTP/AVP 0\r\n") {
		t.Fatalf("rewritten IPv6 SDP:\n%s", got)
	}
}
