package voicehost

import (
	"net"
	"strconv"
	"strings"
)

func RewriteSDPMediaEndpoint(body []byte, endpoint SDPInfo) []byte {
	if len(body) == 0 || strings.TrimSpace(endpoint.ConnectionIP) == "" || endpoint.MediaPort <= 0 {
		return BuildSDPAnswer(endpoint)
	}
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	ipVersion := "IP4"
	if ip := net.ParseIP(endpoint.ConnectionIP); ip != nil && ip.To4() == nil {
		ipVersion = "IP6"
	}
	rewroteConnection := false
	rewroteAudio := false
	out := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "c=IN IP"):
			out = append(out, "c=IN "+ipVersion+" "+endpoint.ConnectionIP)
			rewroteConnection = true
		case strings.HasPrefix(line, "m=audio "):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				fields[1] = strconv.Itoa(endpoint.MediaPort)
				line = strings.Join(fields, " ")
				rewroteAudio = true
			}
			out = append(out, line)
		default:
			out = append(out, line)
		}
	}
	if !rewroteAudio {
		return BuildSDPAnswer(endpoint)
	}
	if !rewroteConnection {
		insertAt := len(out)
		for i, line := range out {
			if strings.HasPrefix(line, "m=audio ") {
				insertAt = i
				break
			}
		}
		out = append(out, "")
		copy(out[insertAt+1:], out[insertAt:])
		out[insertAt] = "c=IN " + ipVersion + " " + endpoint.ConnectionIP
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n")
}
