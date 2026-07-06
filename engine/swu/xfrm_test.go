package swu

import (
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/boa-z/vowifi-go/engine/swu/ikev2"
)

func TestLinuxXFRMManagerApplyAndCleanup(t *testing.T) {
	runner := &fakeIPRunner{}
	manager := LinuxXFRMManager{Runner: runner}
	state, err := manager.Apply(context.Background(), KernelXFRMConfig{
		ChildSA:              xfrmChildSA(ikev2.INTEG_HMAC_SHA2_256_128),
		OuterLocalIP:         "192.0.2.23",
		OuterRemoteIP:        "198.51.100.7",
		InnerLocalPrefix:     "10.10.0.2/32",
		InnerRemotePrefix:    "10.20.0.0/24",
		ReqID:                77,
		Mark:                 "0x1/0xffffffff",
		IncludeForwardPolicy: true,
		XFRMInterface: XFRMInterfaceConfig{
			Name:     "ipsec0",
			OuterDev: "wwan0",
			IfID:     42,
			MTU:      1360,
		},
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	wantApply := [][]string{
		{"link", "add", "ipsec0", "type", "xfrm", "dev", "wwan0", "if_id", "0x2a"},
		{"link", "set", "dev", "ipsec0", "mtu", "1360"},
		{"link", "set", "dev", "ipsec0", "up"},
		{"xfrm", "state", "add", "src", "192.0.2.23", "dst", "198.51.100.7", "proto", "esp", "spi", "0xdeadbeef", "reqid", "77", "mode", "tunnel", "auth-trunc", "hmac(sha256)", xfrmHexKey(bytes.Repeat([]byte{0x20}, 32)), "128", "enc", "cbc(aes)", xfrmHexKey(bytes.Repeat([]byte{0x10}, 16)), "mark", "0x1/0xffffffff", "if_id", "0x2a"},
		{"xfrm", "state", "add", "src", "198.51.100.7", "dst", "192.0.2.23", "proto", "esp", "spi", "0xcafebabe", "reqid", "77", "mode", "tunnel", "auth-trunc", "hmac(sha256)", xfrmHexKey(bytes.Repeat([]byte{0x40}, 32)), "128", "enc", "cbc(aes)", xfrmHexKey(bytes.Repeat([]byte{0x30}, 16)), "mark", "0x1/0xffffffff", "if_id", "0x2a"},
		{"xfrm", "policy", "add", "src", "10.10.0.2/32", "dst", "10.20.0.0/24", "dir", "out", "mark", "0x1/0xffffffff", "if_id", "0x2a", "tmpl", "src", "192.0.2.23", "dst", "198.51.100.7", "proto", "esp", "reqid", "77", "mode", "tunnel"},
		{"xfrm", "policy", "add", "src", "10.20.0.0/24", "dst", "10.10.0.2/32", "dir", "in", "mark", "0x1/0xffffffff", "if_id", "0x2a", "tmpl", "src", "198.51.100.7", "dst", "192.0.2.23", "proto", "esp", "reqid", "77", "mode", "tunnel"},
		{"xfrm", "policy", "add", "src", "10.20.0.0/24", "dst", "10.10.0.2/32", "dir", "fwd", "mark", "0x1/0xffffffff", "if_id", "0x2a", "tmpl", "src", "198.51.100.7", "dst", "192.0.2.23", "proto", "esp", "reqid", "77", "mode", "tunnel"},
	}
	if !reflect.DeepEqual(runner.commands, wantApply) {
		t.Fatalf("apply commands=\n%v\nwant\n%v", runner.commands, wantApply)
	}
	if err := manager.Cleanup(context.Background(), state); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	wantAll := append([][]string{}, wantApply...)
	wantAll = append(wantAll,
		[]string{"xfrm", "policy", "delete", "src", "10.20.0.0/24", "dst", "10.10.0.2/32", "dir", "fwd", "mark", "0x1/0xffffffff", "if_id", "0x2a"},
		[]string{"xfrm", "policy", "delete", "src", "10.20.0.0/24", "dst", "10.10.0.2/32", "dir", "in", "mark", "0x1/0xffffffff", "if_id", "0x2a"},
		[]string{"xfrm", "policy", "delete", "src", "10.10.0.2/32", "dst", "10.20.0.0/24", "dir", "out", "mark", "0x1/0xffffffff", "if_id", "0x2a"},
		[]string{"xfrm", "state", "delete", "src", "198.51.100.7", "dst", "192.0.2.23", "proto", "esp", "spi", "0xcafebabe", "mark", "0x1/0xffffffff", "if_id", "0x2a"},
		[]string{"xfrm", "state", "delete", "src", "192.0.2.23", "dst", "198.51.100.7", "proto", "esp", "spi", "0xdeadbeef", "mark", "0x1/0xffffffff", "if_id", "0x2a"},
		[]string{"link", "del", "ipsec0"},
	)
	if !reflect.DeepEqual(runner.commands, wantAll) {
		t.Fatalf("all commands=\n%v\nwant\n%v", runner.commands, wantAll)
	}
}

func TestLinuxXFRMManagerRollsBackOnFailure(t *testing.T) {
	wantErr := errors.New("policy failed")
	runner := &fakeIPRunner{failAt: 3, err: wantErr}
	manager := LinuxXFRMManager{Runner: runner}
	_, err := manager.Apply(context.Background(), KernelXFRMConfig{
		ChildSA:           xfrmChildSA(ikev2.INTEG_HMAC_SHA2_256_128),
		OuterLocalIP:      "192.0.2.23",
		OuterRemoteIP:     "198.51.100.7",
		InnerLocalPrefix:  "10.10.0.2/32",
		InnerRemotePrefix: "10.20.0.0/24",
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Apply() err=%v, want policy failure", err)
	}
	want := [][]string{
		{"xfrm", "state", "add", "src", "192.0.2.23", "dst", "198.51.100.7", "proto", "esp", "spi", "0xdeadbeef", "reqid", "1", "mode", "tunnel", "auth-trunc", "hmac(sha256)", xfrmHexKey(bytes.Repeat([]byte{0x20}, 32)), "128", "enc", "cbc(aes)", xfrmHexKey(bytes.Repeat([]byte{0x10}, 16))},
		{"xfrm", "state", "add", "src", "198.51.100.7", "dst", "192.0.2.23", "proto", "esp", "spi", "0xcafebabe", "reqid", "1", "mode", "tunnel", "auth-trunc", "hmac(sha256)", xfrmHexKey(bytes.Repeat([]byte{0x40}, 32)), "128", "enc", "cbc(aes)", xfrmHexKey(bytes.Repeat([]byte{0x30}, 16))},
		{"xfrm", "policy", "add", "src", "10.10.0.2/32", "dst", "10.20.0.0/24", "dir", "out", "tmpl", "src", "192.0.2.23", "dst", "198.51.100.7", "proto", "esp", "reqid", "1", "mode", "tunnel"},
		{"xfrm", "state", "delete", "src", "198.51.100.7", "dst", "192.0.2.23", "proto", "esp", "spi", "0xcafebabe"},
		{"xfrm", "state", "delete", "src", "192.0.2.23", "dst", "198.51.100.7", "proto", "esp", "spi", "0xdeadbeef"},
	}
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("commands=\n%v\nwant\n%v", runner.commands, want)
	}
}

func TestBuildKernelXFRMCommandsSupportsSHA1(t *testing.T) {
	commands, err := buildKernelXFRMCommands(KernelXFRMConfig{
		ChildSA:           xfrmChildSA(ikev2.INTEG_HMAC_SHA1_96),
		OuterLocalIP:      "192.0.2.23",
		OuterRemoteIP:     "198.51.100.7",
		InnerLocalPrefix:  "10.10.0.2",
		InnerRemotePrefix: "10.20.0.0/24",
	})
	if err != nil {
		t.Fatalf("buildKernelXFRMCommands() error = %v", err)
	}
	got := commands[0].args
	if !reflect.DeepEqual(got[15:19], []string{"auth-trunc", "hmac(sha1)", xfrmHexKey(bytes.Repeat([]byte{0x20}, 20)), "96"}) {
		t.Fatalf("auth args=%v", got[15:19])
	}
}

func TestBuildKernelXFRMCommandsSupportsAESGCM(t *testing.T) {
	child := xfrmAESGCMChildSA()
	commands, err := buildKernelXFRMCommands(KernelXFRMConfig{
		ChildSA:           child,
		OuterLocalIP:      "192.0.2.23",
		OuterRemoteIP:     "198.51.100.7",
		InnerLocalPrefix:  "10.10.0.2/32",
		InnerRemotePrefix: "10.20.0.0/24",
		NATTraversal: XFRMNATTraversalConfig{
			Enabled:    true,
			LocalPort:  55000,
			RemotePort: 4500,
		},
	})
	if err != nil {
		t.Fatalf("buildKernelXFRMCommands() error = %v", err)
	}
	wantOutbound := []string{
		"xfrm", "state", "add",
		"src", "192.0.2.23",
		"dst", "198.51.100.7",
		"proto", "esp",
		"spi", "0xdeadbeef",
		"reqid", "1",
		"mode", "tunnel",
		"aead", xfrmAeadAESGCMRFC4106, xfrmHexKey(child.Keys.Outbound.EncryptionKey), "128",
		"encap", "espinudp", "55000", "4500", "0.0.0.0",
	}
	if !reflect.DeepEqual(commands[0].args, wantOutbound) {
		t.Fatalf("outbound state args=%v, want %v", commands[0].args, wantOutbound)
	}
	wantInboundCrypto := []string{"aead", xfrmAeadAESGCMRFC4106, xfrmHexKey(child.Keys.Inbound.EncryptionKey), "128"}
	if got := commands[1].args[15:19]; !reflect.DeepEqual(got, wantInboundCrypto) {
		t.Fatalf("inbound crypto args=%v, want %v", got, wantInboundCrypto)
	}
}

func TestBuildKernelXFRMCommandsAddsNATTraversalEncapsulation(t *testing.T) {
	commands, err := buildKernelXFRMCommands(KernelXFRMConfig{
		ChildSA:           xfrmChildSA(ikev2.INTEG_HMAC_SHA2_256_128),
		OuterLocalIP:      "192.0.2.23",
		OuterRemoteIP:     "198.51.100.7",
		InnerLocalPrefix:  "10.10.0.2/32",
		InnerRemotePrefix: "10.20.0.0/24",
		NATTraversal: XFRMNATTraversalConfig{
			Enabled:         true,
			LocalPort:       55000,
			RemotePort:      4500,
			OriginalAddress: "203.0.113.9",
		},
	})
	if err != nil {
		t.Fatalf("buildKernelXFRMCommands() error = %v", err)
	}
	wantOutbound := []string{"encap", "espinudp", "55000", "4500", "203.0.113.9"}
	if got := commands[0].args[len(commands[0].args)-len(wantOutbound):]; !reflect.DeepEqual(got, wantOutbound) {
		t.Fatalf("outbound encap args=%v, want %v", got, wantOutbound)
	}
	wantInbound := []string{"encap", "espinudp", "4500", "55000", "203.0.113.9"}
	if got := commands[1].args[len(commands[1].args)-len(wantInbound):]; !reflect.DeepEqual(got, wantInbound) {
		t.Fatalf("inbound encap args=%v, want %v", got, wantInbound)
	}
}

func TestBuildKernelXFRMCommandsDefaultsNATTraversalEncapsulation(t *testing.T) {
	commands, err := buildKernelXFRMCommands(KernelXFRMConfig{
		ChildSA:           xfrmChildSA(ikev2.INTEG_HMAC_SHA2_256_128),
		OuterLocalIP:      "192.0.2.23",
		OuterRemoteIP:     "198.51.100.7",
		InnerLocalPrefix:  "10.10.0.2/32",
		InnerRemotePrefix: "10.20.0.0/24",
		NATTraversal:      XFRMNATTraversalConfig{Enabled: true},
	})
	if err != nil {
		t.Fatalf("buildKernelXFRMCommands() error = %v", err)
	}
	want := []string{"encap", "espinudp", "4500", "4500", "0.0.0.0"}
	if got := commands[0].args[len(commands[0].args)-len(want):]; !reflect.DeepEqual(got, want) {
		t.Fatalf("default encap args=%v, want %v", got, want)
	}
}

func TestKernelXFRMConfigFromIKENegotiation(t *testing.T) {
	child := xfrmChildSA(ikev2.INTEG_HMAC_SHA2_256_128)
	child.Configuration = &ikev2.Configuration{
		Type: ikev2.CFGReply,
		Attributes: []ikev2.ConfigurationAttribute{{
			Type:  ikev2.ConfigInternalIPv4Address,
			Value: []byte{10, 10, 0, 2},
		}},
	}
	child.TSr = ikev2.TrafficSelectors{Selectors: []ikev2.TrafficSelector{{
		Type:      ikev2.TSIPv4AddressRange,
		StartAddr: net.IPv4(0, 0, 0, 0),
		EndAddr:   net.IPv4(255, 255, 255, 255),
	}}}

	cfg, err := KernelXFRMConfigFromIKE(KernelXFRMConfigFromIKEConfig{
		Tunnel: TunnelConfig{
			DeviceID:     "dev-1",
			Mode:         DataplaneModeKernel,
			EPDGAddress:  "198.51.100.7",
			OuterLocalIP: "192.0.2.23",
			IMSI:         "310280233641503",
			MCC:          "310",
			MNC:          "280",
		},
		Transport: IKETransportConfig{
			EPDGAddress: "198.51.100.7",
			LocalIP:     net.IPv4(192, 0, 2, 23),
			RemoteIP:    net.IPv4(198, 51, 100, 7),
			LocalPort:   55000,
			RemotePort:  4500,
		},
		Init:                 ikev2.InitResult{NATDetected: true},
		ChildSA:              child,
		ReqID:                77,
		Mark:                 "0x1/0xffffffff",
		InterfaceID:          42,
		IncludeForwardPolicy: true,
		XFRMInterface: XFRMInterfaceConfig{
			Name:     "ipsec0",
			OuterDev: "wwan0",
			IfID:     42,
			MTU:      1360,
		},
	})
	if err != nil {
		t.Fatalf("KernelXFRMConfigFromIKE() error = %v", err)
	}
	if cfg.OuterLocalIP != "192.0.2.23" || cfg.OuterRemoteIP != "198.51.100.7" {
		t.Fatalf("outer addresses=%s/%s", cfg.OuterLocalIP, cfg.OuterRemoteIP)
	}
	if cfg.InnerLocalPrefix != "10.10.0.2/32" || cfg.InnerRemotePrefix != "0.0.0.0/0" {
		t.Fatalf("inner prefixes=%s/%s", cfg.InnerLocalPrefix, cfg.InnerRemotePrefix)
	}
	if !cfg.NATTraversal.Enabled || cfg.NATTraversal.LocalPort != 55000 || cfg.NATTraversal.RemotePort != 4500 || cfg.NATTraversal.OriginalAddress != "0.0.0.0" {
		t.Fatalf("nat traversal=%+v", cfg.NATTraversal)
	}
	if !reflect.DeepEqual(cfg.ChildSA, child) || cfg.ReqID != 77 || cfg.Mark != "0x1/0xffffffff" || cfg.InterfaceID != 42 || !cfg.IncludeForwardPolicy {
		t.Fatalf("xfrm config did not preserve child/options: %+v", cfg)
	}
	commands, err := buildKernelXFRMCommands(cfg)
	if err != nil {
		t.Fatalf("buildKernelXFRMCommands() error = %v", err)
	}
	wantEncap := []string{"encap", "espinudp", "55000", "4500", "0.0.0.0"}
	if got := commands[3].args[len(commands[3].args)-len(wantEncap):]; !reflect.DeepEqual(got, wantEncap) {
		t.Fatalf("derived outbound encap args=%v, want %v", got, wantEncap)
	}
}

func TestKernelXFRMConfigFromIKERejectsUnresolvedOuterRemote(t *testing.T) {
	_, err := KernelXFRMConfigFromIKE(KernelXFRMConfigFromIKEConfig{
		Tunnel: TunnelConfig{
			DeviceID:      "dev-1",
			EPDGAddress:   "epdg.example",
			OuterLocalIP:  "192.0.2.23",
			InnerLocalIP:  "10.10.0.2",
			RemoteInnerIP: "0.0.0.0/0",
			IMSI:          "310280233641503",
			MCC:           "310",
			MNC:           "280",
		},
		ChildSA: xfrmChildSA(ikev2.INTEG_HMAC_SHA2_256_128),
	})
	if !errors.Is(err, ErrInvalidXFRMConfig) {
		t.Fatalf("KernelXFRMConfigFromIKE() err=%v, want ErrInvalidXFRMConfig", err)
	}
}

func TestBuildKernelXFRMCommandsRejectsInvalidInput(t *testing.T) {
	base := KernelXFRMConfig{
		ChildSA:           xfrmChildSA(ikev2.INTEG_HMAC_SHA2_256_128),
		OuterLocalIP:      "192.0.2.23",
		OuterRemoteIP:     "198.51.100.7",
		InnerLocalPrefix:  "10.10.0.2/32",
		InnerRemotePrefix: "10.20.0.0/24",
	}
	cases := []struct {
		name string
		cfg  KernelXFRMConfig
	}{
		{name: "bad outer", cfg: withXFRM(base, func(c *KernelXFRMConfig) { c.OuterLocalIP = "bad" })},
		{name: "bad inner", cfg: withXFRM(base, func(c *KernelXFRMConfig) { c.InnerLocalPrefix = "bad" })},
		{name: "bad reqid", cfg: withXFRM(base, func(c *KernelXFRMConfig) { c.ReqID = -1 })},
		{name: "bad mark", cfg: withXFRM(base, func(c *KernelXFRMConfig) { c.Mark = "bad mark" })},
		{name: "bad local spi", cfg: withXFRM(base, func(c *KernelXFRMConfig) { c.ChildSA.LocalSPI = []byte{1, 2} })},
		{name: "bad encryption", cfg: withXFRM(base, func(c *KernelXFRMConfig) { c.ChildSA.Keys.Profile.EncryptionID = 0xffff })},
		{name: "bad gcm key shape", cfg: withXFRM(base, func(c *KernelXFRMConfig) { c.ChildSA.Keys.Profile.EncryptionID = ikev2.ENCR_AES_GCM_16 })},
		{name: "bad integrity", cfg: withXFRM(base, func(c *KernelXFRMConfig) { c.ChildSA.Keys.Profile.IntegrityID = ikev2.INTEG_AES_XCBC_96 })},
		{name: "bad key length", cfg: withXFRM(base, func(c *KernelXFRMConfig) { c.ChildSA.Keys.Outbound.EncryptionKey = []byte{1, 2, 3} })},
		{name: "xfrmi no ifid", cfg: withXFRM(base, func(c *KernelXFRMConfig) { c.XFRMInterface = XFRMInterfaceConfig{Name: "ipsec0", OuterDev: "wwan0"} })},
		{name: "xfrmi bad outer dev", cfg: withXFRM(base, func(c *KernelXFRMConfig) {
			c.XFRMInterface = XFRMInterfaceConfig{Name: "ipsec0", OuterDev: "bad dev", IfID: 1}
		})},
		{name: "natt disabled with params", cfg: withXFRM(base, func(c *KernelXFRMConfig) {
			c.NATTraversal = XFRMNATTraversalConfig{LocalPort: 4500}
		})},
		{name: "natt bad original address", cfg: withXFRM(base, func(c *KernelXFRMConfig) {
			c.NATTraversal = XFRMNATTraversalConfig{Enabled: true, OriginalAddress: "bad"}
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildKernelXFRMCommands(tc.cfg)
			if !errors.Is(err, ErrInvalidXFRMConfig) {
				t.Fatalf("buildKernelXFRMCommands() err=%v, want ErrInvalidXFRMConfig", err)
			}
		})
	}
}

func TestBuildKernelXFRMCommandsRejectsAESGCMWithIntegrityKey(t *testing.T) {
	child := xfrmAESGCMChildSA()
	child.Keys.Profile.IntegrityID = ikev2.INTEG_HMAC_SHA2_256_128
	child.Keys.Profile.IntegrityKeyLength = 32
	child.Keys.Outbound.IntegrityKey = bytes.Repeat([]byte{0x20}, 32)
	child.Keys.Inbound.IntegrityKey = bytes.Repeat([]byte{0x40}, 32)
	_, err := buildKernelXFRMCommands(KernelXFRMConfig{
		ChildSA:           child,
		OuterLocalIP:      "192.0.2.23",
		OuterRemoteIP:     "198.51.100.7",
		InnerLocalPrefix:  "10.10.0.2/32",
		InnerRemotePrefix: "10.20.0.0/24",
	})
	if !errors.Is(err, ErrInvalidXFRMConfig) {
		t.Fatalf("buildKernelXFRMCommands() err=%v, want ErrInvalidXFRMConfig", err)
	}
}

func xfrmChildSA(integrity uint16) ikev2.ChildSAResult {
	integLen := 32
	if integrity == ikev2.INTEG_HMAC_SHA1_96 {
		integLen = 20
	}
	return ikev2.ChildSAResult{
		LocalSPI:  []byte{0xca, 0xfe, 0xba, 0xbe},
		RemoteSPI: []byte{0xde, 0xad, 0xbe, 0xef},
		Keys: ikev2.ChildSAKeys{
			Profile: ikev2.ESPKeyProfile{
				EncryptionID:        ikev2.ENCR_AES_CBC,
				EncryptionKeyLength: 16,
				IntegrityID:         integrity,
				IntegrityKeyLength:  integLen,
			},
			Outbound: ikev2.ESPKeys{
				EncryptionKey: bytes.Repeat([]byte{0x10}, 16),
				IntegrityKey:  bytes.Repeat([]byte{0x20}, integLen),
			},
			Inbound: ikev2.ESPKeys{
				EncryptionKey: bytes.Repeat([]byte{0x30}, 16),
				IntegrityKey:  bytes.Repeat([]byte{0x40}, integLen),
			},
		},
	}
}

func xfrmAESGCMChildSA() ikev2.ChildSAResult {
	return ikev2.ChildSAResult{
		LocalSPI:  []byte{0xca, 0xfe, 0xba, 0xbe},
		RemoteSPI: []byte{0xde, 0xad, 0xbe, 0xef},
		Keys: ikev2.ChildSAKeys{
			Profile: ikev2.ESPKeyProfile{
				EncryptionID:        ikev2.ENCR_AES_GCM_16,
				EncryptionKeyLength: 20,
			},
			Outbound: ikev2.ESPKeys{
				EncryptionKey: append(bytes.Repeat([]byte{0x10}, 16), 0x01, 0x02, 0x03, 0x04),
			},
			Inbound: ikev2.ESPKeys{
				EncryptionKey: append(bytes.Repeat([]byte{0x30}, 16), 0x05, 0x06, 0x07, 0x08),
			},
		},
	}
}

func withXFRM(cfg KernelXFRMConfig, fn func(*KernelXFRMConfig)) KernelXFRMConfig {
	fn(&cfg)
	return cfg
}
