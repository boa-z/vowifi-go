package voiceclient

import "testing"

func TestSelectSecurityAgreementPrefersInstallableIPSecSA(t *testing.T) {
	const installable = `IPSEC-3GPP;Q="0.2";ALG="HMAC-SHA-1-96";EALG="NULL";SPI-C="333";SPI-S="444";PORT-C="5064";PORT-S="5065";PROT=ESP;MODE=TRANSPORT`
	cases := []struct {
		name string
		bad  string
	}{
		{
			name: "invalid client port",
			bad:  `ipsec-3gpp;q=1.0;alg=hmac-sha-1-96;ealg=null;spi-c=111;spi-s=222;port-c=70000;port-s=5063`,
		},
		{
			name: "zero client spi",
			bad:  `ipsec-3gpp;q=1.0;alg=hmac-sha-1-96;ealg=null;spi-c=0;spi-s=222;port-c=5062;port-s=5063`,
		},
		{
			name: "oversized server spi",
			bad:  `ipsec-3gpp;q=1.0;alg=hmac-sha-1-96;ealg=null;spi-c=111;spi-s=4294967296;port-c=5062;port-s=5063`,
		},
	}

	client := SecurityAgreement{
		Protocol:            DefaultSecurityProtocol,
		Algorithm:           DefaultSecurityAlgorithm,
		EncryptionAlgorithm: DefaultSecurityEAlg,
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			selected, ok := SelectSecurityAgreement([]string{tc.bad + ", " + installable}, client)
			if !ok {
				t.Fatal("SelectSecurityAgreement() ok=false")
			}
			if selected.SPIClient != 333 || selected.SPIServer != 444 ||
				selected.PortClient != 5064 || selected.PortServer != 5065 ||
				selected.Parameters["q"] != "0.2" ||
				selected.Parameters["mode"] != "TRANSPORT" ||
				selected.Raw == "" {
				t.Fatalf("selected=%+v", selected)
			}
			plan, ok := BuildIMSSecurityAssociationPlan(selected)
			if !ok {
				t.Fatalf("BuildIMSSecurityAssociationPlan(%+v) ok=false", selected)
			}
			if plan.SPIClient != 333 || plan.SPIServer != 444 ||
				plan.PortClient != 5064 || plan.PortServer != 5065 ||
				plan.Mode != "transport" || plan.QValue != "0.2" {
				t.Fatalf("plan=%+v", plan)
			}
		})
	}
}
