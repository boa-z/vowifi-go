package e911

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"testing"
	"time"
)

func TestEmergencyServiceURNsForCategory(t *testing.T) {
	got := EmergencyServiceURNsForCategory(
		EmergencyServiceCategoryPolice |
			EmergencyServiceCategoryAmbulance |
			EmergencyServiceCategoryFire |
			EmergencyServiceCategoryManualECall,
	)
	want := []string{
		"urn:service:sos.police",
		"urn:service:sos.ambulance",
		"urn:service:sos.fire",
		"urn:service:sos.ecall.manual",
	}
	if !sameStrings(got, want) {
		t.Fatalf("URNs=%+v, want %+v", got, want)
	}
	if fallback := EmergencyServiceURNsForCategory(0); !sameStrings(fallback, []string{DefaultEmergencyServiceURN}) {
		t.Fatalf("fallback URNs=%+v", fallback)
	}
}

func TestBuildEmergencySIPRequestInfoUsesIMSHeadersAndGeoURI(t *testing.T) {
	info := BuildEmergencySIPRequestInfo(EmergencySIPHeaderConfig{
		ServiceURN: "fire",
		AccessNetworkInfo: EmergencyAccessNetworkInfo{
			WLANNodeID: `aa:bb:cc:dd:ee:ff"lab`,
		},
		Address: EmergencyAddress{
			Latitude:  "47.6205",
			Longitude: "-122.3493",
		},
		GeolocationRouting: true,
	})
	if info.RequestURI != "urn:service:sos.fire" {
		t.Fatalf("RequestURI=%q", info.RequestURI)
	}
	headers := info.Headers
	if headers["P-Preferred-Service"] != IMSMMTelServiceIdentifier {
		t.Fatalf("P-Preferred-Service=%q", headers["P-Preferred-Service"])
	}
	if headers["Accept-Contact"] != IMSEmergencyAcceptContact {
		t.Fatalf("Accept-Contact=%q", headers["Accept-Contact"])
	}
	wantPANI := `IEEE-802.11;i-wlan-node-id="aa:bb:cc:dd:ee:ff\"lab"`
	if headers["P-Access-Network-Info"] != wantPANI {
		t.Fatalf("P-Access-Network-Info=%q, want %q", headers["P-Access-Network-Info"], wantPANI)
	}
	if headers["Geolocation"] != "<geo:47.6205,-122.3493>;inserted-by=endpoint" {
		t.Fatalf("Geolocation=%q", headers["Geolocation"])
	}
	if headers["Geolocation-Routing"] != "yes" {
		t.Fatalf("Geolocation-Routing=%q", headers["Geolocation-Routing"])
	}
}

func TestBuildEmergencySIPRequestInfoReferencesPIDFLOBodyByCID(t *testing.T) {
	pidfLO := []byte("<presence/>")
	info := BuildEmergencySIPRequestInfo(EmergencySIPHeaderConfig{
		ServiceURN:         "fire",
		PIDFLOContentID:    "location-inline",
		PIDFLOBody:         pidfLO,
		GeolocationRouting: true,
		Address: EmergencyAddress{
			Latitude:  "47.6205",
			Longitude: "-122.3493",
		},
	})
	if info.Headers["Geolocation"] != "<cid:location-inline>;inserted-by=endpoint" {
		t.Fatalf("Geolocation=%q", info.Headers["Geolocation"])
	}
	if info.Headers["Geolocation-Routing"] != GeolocationRoutingYes {
		t.Fatalf("Geolocation-Routing=%q", info.Headers["Geolocation-Routing"])
	}
	if info.PIDFLOContentID != "location-inline" || string(info.PIDFLOBody) != "<presence/>" {
		t.Fatalf("PIDF-LO info=%+v body=%q", info, info.PIDFLOBody)
	}
	pidfLO[0] = '['
	if string(info.PIDFLOBody) != "<presence/>" {
		t.Fatalf("PIDF-LO body should be copied, got %q", info.PIDFLOBody)
	}
}

func TestParsePAccessNetworkInfoParsesWLANAndCellularValues(t *testing.T) {
	values, err := ParsePAccessNetworkInfo(`IEEE-802.11;i-wlan-node-id="aa:bb:cc:dd:ee:ff";network-provided, 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=3102600abcdef`)
	if err != nil {
		t.Fatalf("ParsePAccessNetworkInfo() error = %v", err)
	}
	if len(values) != 2 {
		t.Fatalf("values=%+v", values)
	}
	if values[0].AccessType != "IEEE-802.11" ||
		values[0].WLANNodeID != "aa:bb:cc:dd:ee:ff" ||
		values[0].Parameters["network-provided"] != "" {
		t.Fatalf("first PANI value=%+v", values[0])
	}
	if values[1].AccessType != "3GPP-E-UTRAN-FDD" ||
		values[1].Parameters["utran-cell-id-3gpp"] != "3102600abcdef" {
		t.Fatalf("second PANI value=%+v", values[1])
	}
}

func TestNormalizePAccessNetworkInfoHandlesQuotedDelimiters(t *testing.T) {
	got, err := NormalizePAccessNetworkInfo(` IEEE-802.11 ; i-wlan-node-id = "aa:bb\,office" ; operator-specific = "alpha\;beta" , 3GPP-E-UTRAN-FDD ; utran-cell-id-3gpp = "3102600abc\;def" ; network-provided `)
	if err != nil {
		t.Fatalf("NormalizePAccessNetworkInfo() error = %v", err)
	}
	want := `IEEE-802.11;i-wlan-node-id="aa:bb,office";operator-specific="alpha;beta", 3GPP-E-UTRAN-FDD;network-provided;utran-cell-id-3gpp="3102600abc;def"`
	if got != want {
		t.Fatalf("NormalizePAccessNetworkInfo()=%q, want %q", got, want)
	}

	values, err := ParsePAccessNetworkInfo(got)
	if err != nil {
		t.Fatalf("ParsePAccessNetworkInfo(normalized) error = %v", err)
	}
	if len(values) != 2 ||
		values[0].WLANNodeID != "aa:bb,office" ||
		values[0].Parameters["operator-specific"] != "alpha;beta" ||
		values[1].Parameters["network-provided"] != "" ||
		values[1].Parameters["utran-cell-id-3gpp"] != "3102600abc;def" {
		t.Fatalf("normalized PANI values=%+v", values)
	}
}

func TestNormalizePAccessNetworkInfoRoundTripsCommonCarrierParameters(t *testing.T) {
	got, err := NormalizePAccessNetworkInfo(` 3GPP-E-UTRAN-FDD ; utran-cell-id-3gpp = "3102600abcdef" ; cgi-3gpp=310260ffff `)
	if err != nil {
		t.Fatalf("NormalizePAccessNetworkInfo() error = %v", err)
	}
	want := "3GPP-E-UTRAN-FDD;cgi-3gpp=310260ffff;utran-cell-id-3gpp=3102600abcdef"
	if got != want {
		t.Fatalf("NormalizePAccessNetworkInfo()=%q, want %q", got, want)
	}

	headers := BuildEmergencySIPHeaders(EmergencySIPHeaderConfig{
		AccessNetworkInfo: EmergencyAccessNetworkInfo{
			AccessType: "3GPP-E-UTRAN-FDD",
			Parameters: map[string]string{
				"utran-cell-id-3gpp": "3102600abcdef",
			},
		},
	})
	if headers["P-Access-Network-Info"] != "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=3102600abcdef" {
		t.Fatalf("P-Access-Network-Info=%q", headers["P-Access-Network-Info"])
	}
}

func TestParsePAccessNetworkInfoRejectsMalformedValues(t *testing.T) {
	for _, header := range []string{
		`;i-wlan-node-id="aa:bb:cc:dd:ee:ff"`,
		`IEEE-802.11;i-wlan-node-id="unterminated`,
		`IEEE-802.11;i-wlan-node-id="node"tail`,
		`IEEE-802.11;=value`,
	} {
		t.Run(header, func(t *testing.T) {
			if _, err := ParsePAccessNetworkInfo(header); err == nil {
				t.Fatal("ParsePAccessNetworkInfo() error = nil")
			}
			if _, err := NormalizePAccessNetworkInfo(header); err == nil {
				t.Fatal("NormalizePAccessNetworkInfo() error = nil")
			}
		})
	}
}

func TestParseGeolocationHeaderParsesMultipleLocationsAndParameters(t *testing.T) {
	values, err := ParseGeolocationHeader(`<cid:loc-1@example.test>;inserted-by=endpoint;purpose="emergency, callback", <geo:47.6205,-122.3493>;routing-allowed=yes`)
	if err != nil {
		t.Fatalf("ParseGeolocationHeader() error = %v", err)
	}
	if len(values) != 2 {
		t.Fatalf("values=%+v", values)
	}
	if values[0].URI != "cid:loc-1@example.test" ||
		values[0].Parameters["inserted-by"] != "endpoint" ||
		values[0].Parameters["purpose"] != "emergency, callback" {
		t.Fatalf("first value=%+v", values[0])
	}
	if values[1].URI != "geo:47.6205,-122.3493" || values[1].Parameters["routing-allowed"] != "yes" {
		t.Fatalf("second value=%+v", values[1])
	}
}

func TestNormalizeGeolocationHeaderHandlesQuotedDelimiters(t *testing.T) {
	got, err := NormalizeGeolocationHeader(` <cid:loc-1@example.test> ; purpose = "emergency\, callback" ; inserted-by = endpoint , <https://lis.example.test/location/abc> ; note = "floor\;unit\"7" `)
	if err != nil {
		t.Fatalf("NormalizeGeolocationHeader() error = %v", err)
	}
	want := `<cid:loc-1@example.test>;inserted-by=endpoint;purpose="emergency, callback", <https://lis.example.test/location/abc>;note="floor;unit\"7"`
	if got != want {
		t.Fatalf("NormalizeGeolocationHeader()=%q, want %q", got, want)
	}

	values, err := ParseGeolocationHeader(got)
	if err != nil {
		t.Fatalf("ParseGeolocationHeader(normalized) error = %v", err)
	}
	if len(values) != 2 ||
		values[0].Parameters["purpose"] != "emergency, callback" ||
		values[1].Parameters["note"] != `floor;unit"7` {
		t.Fatalf("normalized geolocation values=%+v", values)
	}
}

func TestBuildAndNormalizeGeolocationHeader(t *testing.T) {
	got := BuildGeolocationHeader(
		GeolocationHeaderValue{
			URI: "cid:loc-1@example.test",
			Parameters: map[string]string{
				"Purpose":     "emergency, callback",
				"Inserted-By": "endpoint",
			},
		},
		GeolocationHeaderValue{
			URI: "<geo:47.6205,-122.3493>;routing-allowed=yes",
		},
	)
	want := `<cid:loc-1@example.test>;inserted-by=endpoint;purpose="emergency, callback", <geo:47.6205,-122.3493>;routing-allowed=yes`
	if got != want {
		t.Fatalf("BuildGeolocationHeader()=%q, want %q", got, want)
	}

	normalized, err := NormalizeGeolocationHeader(` <cid:loc-1@example.test> ; Purpose = "emergency, callback" ; Inserted-By = endpoint , <geo:47.6205,-122.3493>;routing-allowed="yes" `)
	if err != nil {
		t.Fatalf("NormalizeGeolocationHeader() error = %v", err)
	}
	if normalized != want {
		t.Fatalf("NormalizeGeolocationHeader()=%q, want %q", normalized, want)
	}
}

func TestBuildEmergencySIPRequestInfoUsesStructuredGeolocationValues(t *testing.T) {
	info := BuildEmergencySIPRequestInfo(EmergencySIPHeaderConfig{
		ServiceURN: "police",
		GeolocationValues: []GeolocationHeaderValue{
			{
				URI: "cid:location-inline",
				Parameters: map[string]string{
					"inserted-by": "endpoint",
				},
			},
			{
				URI: "https://lis.example.test/location/abc",
				Parameters: map[string]string{
					"purpose": "emergency, callback",
				},
			},
		},
		Address: EmergencyAddress{
			Latitude:  "47.6205",
			Longitude: "-122.3493",
		},
		GeolocationRouting: true,
	})
	want := `<cid:location-inline>;inserted-by=endpoint, <https://lis.example.test/location/abc>;purpose="emergency, callback"`
	if info.RequestURI != "urn:service:sos.police" {
		t.Fatalf("RequestURI=%q", info.RequestURI)
	}
	if info.Headers["Geolocation"] != want {
		t.Fatalf("Geolocation=%q, want %q", info.Headers["Geolocation"], want)
	}
	if info.Headers["Geolocation-Routing"] != GeolocationRoutingYes {
		t.Fatalf("Geolocation-Routing=%q", info.Headers["Geolocation-Routing"])
	}
}

func TestNormalizeGeolocationHeaderRejectsMalformedValues(t *testing.T) {
	for _, header := range []string{
		`<cid:loc-1`,
		`<cid:loc-1> garbage`,
		`;inserted-by=endpoint`,
		`<cid:loc-1>;=endpoint`,
		`<cid:loc-1>;purpose="emergency"callback`,
		`<cid:loc-1>;purpose=emergency"callback`,
	} {
		t.Run(header, func(t *testing.T) {
			if _, err := NormalizeGeolocationHeader(header); err == nil {
				t.Fatal("NormalizeGeolocationHeader() error = nil")
			}
		})
	}
}

func TestParseGeolocationRoutingHeaderNormalizesValues(t *testing.T) {
	for _, tc := range []struct {
		name    string
		header  string
		allowed bool
		present bool
		normal  string
	}{
		{name: "yes", header: " YES ", allowed: true, present: true, normal: GeolocationRoutingYes},
		{name: "no", header: "\tno", allowed: false, present: true, normal: GeolocationRoutingNo},
		{name: "quoted", header: `"yes"`, allowed: true, present: true, normal: GeolocationRoutingYes},
		{name: "duplicate", header: "yes, YES", allowed: true, present: true, normal: GeolocationRoutingYes},
		{name: "empty", header: " , ", allowed: false, present: false, normal: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allowed, present, err := ParseGeolocationRoutingHeader(tc.header)
			if err != nil {
				t.Fatalf("ParseGeolocationRoutingHeader() error = %v", err)
			}
			if allowed != tc.allowed || present != tc.present {
				t.Fatalf("ParseGeolocationRoutingHeader() allowed=%v present=%v, want %v %v", allowed, present, tc.allowed, tc.present)
			}
			normal, err := NormalizeGeolocationRoutingHeader(tc.header)
			if err != nil {
				t.Fatalf("NormalizeGeolocationRoutingHeader() error = %v", err)
			}
			if normal != tc.normal {
				t.Fatalf("NormalizeGeolocationRoutingHeader()=%q, want %q", normal, tc.normal)
			}
		})
	}
}

func TestParseGeolocationRoutingHeaderRejectsAmbiguousValues(t *testing.T) {
	for _, header := range []string{
		"maybe",
		"yes, no",
		"yes;foo=bar",
		`"yes`,
	} {
		t.Run(header, func(t *testing.T) {
			if _, _, err := ParseGeolocationRoutingHeader(header); err == nil {
				t.Fatal("ParseGeolocationRoutingHeader() error = nil")
			}
			if _, err := NormalizeGeolocationRoutingHeader(header); err == nil {
				t.Fatal("NormalizeGeolocationRoutingHeader() error = nil")
			}
		})
	}
}

func TestBuildAndParseEmergencyPIDFLO(t *testing.T) {
	body, err := BuildEmergencyPIDFLO(EmergencyPIDFLOConfig{
		Entity:    "pres:device@example.test",
		TupleID:   "loc-1",
		Timestamp: time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC),
		Address: EmergencyAddress{
			Latitude:            "47.6205",
			Longitude:           "-122.3493",
			Country:             "US",
			State:               "WA",
			County:              "King",
			City:                "Seattle",
			Street:              "5th Ave",
			HouseNumber:         "100",
			Unit:                "2A",
			Floor:               "7",
			Room:                "701",
			StreetDirection:     "N",
			StreetPostDirection: "SW",
			StreetSuffix:        "St",
			LocationDescription: "Lobby",
			PlaceType:           "office",
		},
	})
	if err != nil {
		t.Fatalf("BuildEmergencyPIDFLO() error = %v", err)
	}
	xmlBody := string(body)
	for _, want := range []string{
		`entity="pres:device@example.test"`,
		`<gml:pos>47.6205 -122.3493</gml:pos>`,
		`<cl:HNO>100</cl:HNO>`,
		`<timestamp>2026-07-07T09:00:00Z</timestamp>`,
	} {
		if !strings.Contains(xmlBody, want) {
			t.Fatalf("PIDF-LO body missing %q:\n%s", want, xmlBody)
		}
	}
	if strings.Contains(xmlBody, "<gp:usage-rules>") {
		t.Fatalf("PIDF-LO body should omit empty usage-rules:\n%s", xmlBody)
	}

	address, err := ParseEmergencyPIDFLO(body)
	if err != nil {
		t.Fatalf("ParseEmergencyPIDFLO() error = %v", err)
	}
	if address.Latitude != "47.6205" || address.Longitude != "-122.3493" ||
		address.Country != "US" || address.State != "WA" || address.County != "King" ||
		address.City != "Seattle" || address.Street != "5th Ave" ||
		address.HouseNumber != "100" || address.Unit != "2A" ||
		address.Floor != "7" || address.Room != "701" ||
		address.StreetDirection != "N" || address.StreetPostDirection != "SW" ||
		address.StreetSuffix != "St" || address.LocationDescription != "Lobby" ||
		address.PlaceType != "office" {
		t.Fatalf("address=%+v fields=%+v", address, address.Fields)
	}
}

func TestBuildEmergencyPIDFLOMultipartBody(t *testing.T) {
	pidfLO, err := BuildEmergencyPIDFLO(EmergencyPIDFLOConfig{
		Entity: "pres:device@example.test",
		Address: EmergencyAddress{
			Latitude:  "47.6205",
			Longitude: "-122.3493",
		},
	})
	if err != nil {
		t.Fatalf("BuildEmergencyPIDFLO() error = %v", err)
	}
	contentType, body, err := BuildEmergencyPIDFLOMultipartBody([]byte("v=0\r\n"), pidfLO, EmergencyMultipartRelatedConfig{
		Boundary:        "e911-test-boundary",
		SDPContentID:    "sdp-1",
		PIDFLOContentID: "location-1@example.test",
	})
	if err != nil {
		t.Fatalf("BuildEmergencyPIDFLOMultipartBody() error = %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Fatalf("ParseMediaType(%q) error = %v", contentType, err)
	}
	if mediaType != EmergencyMultipartRelatedContentType ||
		params["boundary"] != "e911-test-boundary" ||
		params["type"] != EmergencySDPContentType ||
		params["start"] != "<sdp-1>" {
		t.Fatalf("multipart content type=%q params=%+v", mediaType, params)
	}

	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	part, err := reader.NextPart()
	if err != nil {
		t.Fatalf("first multipart part error = %v", err)
	}
	firstBody, err := io.ReadAll(part)
	if err != nil {
		t.Fatalf("read first multipart part error = %v", err)
	}
	if part.Header.Get("Content-Type") != EmergencySDPContentType ||
		part.Header.Get("Content-ID") != "<sdp-1>" ||
		part.Header.Get("Content-Disposition") != "session;handling=required" ||
		string(firstBody) != "v=0\r\n" {
		t.Fatalf("first part headers=%+v body=%q", part.Header, firstBody)
	}

	part, err = reader.NextPart()
	if err != nil {
		t.Fatalf("second multipart part error = %v", err)
	}
	secondBody, err := io.ReadAll(part)
	if err != nil {
		t.Fatalf("read second multipart part error = %v", err)
	}
	if part.Header.Get("Content-Type") != EmergencyPIDFLOContentType ||
		part.Header.Get("Content-ID") != "<location-1@example.test>" ||
		part.Header.Get("Content-Disposition") != "by-reference;handling=optional" {
		t.Fatalf("second part headers=%+v", part.Header)
	}
	if _, err := ParseEmergencyPIDFLO(secondBody); err != nil {
		t.Fatalf("second part PIDF-LO parse error = %v\n%s", err, secondBody)
	}
	if _, err := reader.NextPart(); err != io.EOF {
		t.Fatalf("extra multipart part err=%v", err)
	}
}

func TestBuildEmergencyPIDFLOUsageRules(t *testing.T) {
	allowRetransmission := true
	body, err := BuildEmergencyPIDFLOWithUsageRules(EmergencyPIDFLOConfig{
		Entity: "pres:device@example.test",
		Address: EmergencyAddress{
			Latitude:  "47.6205",
			Longitude: "-122.3493",
		},
	}, EmergencyPIDFLOUsageRules{
		RetransmissionAllowed: &allowRetransmission,
		RetentionExpiry:       time.Date(2026, 7, 7, 17, 30, 0, 123456789, time.FixedZone("PDT", -7*60*60)),
		RulesetReference:      "https://example.test/location-policy/e911",
		NoteWell:              "Emergency location for PSAP handling only",
	})
	if err != nil {
		t.Fatalf("BuildEmergencyPIDFLO() error = %v", err)
	}
	xmlBody := string(body)
	for _, want := range []string{
		`<gp:usage-rules>`,
		`<gp:retransmission-allowed>true</gp:retransmission-allowed>`,
		`<gp:retention-expiry>2026-07-08T00:30:00.123456789Z</gp:retention-expiry>`,
		`<gp:ruleset-reference>https://example.test/location-policy/e911</gp:ruleset-reference>`,
		`<gp:note-well>Emergency location for PSAP handling only</gp:note-well>`,
	} {
		if !strings.Contains(xmlBody, want) {
			t.Fatalf("PIDF-LO body missing usage rule %q:\n%s", want, xmlBody)
		}
	}

	allowRetransmission = false
	body, err = BuildEmergencyPIDFLOWithUsageRules(EmergencyPIDFLOConfig{
		Address: EmergencyAddress{Country: "US", State: "WA", City: "Seattle"},
	}, EmergencyPIDFLOUsageRules{
		RetransmissionAllowed: &allowRetransmission,
	})
	if err != nil {
		t.Fatalf("BuildEmergencyPIDFLO(false retransmission) error = %v", err)
	}
	if !strings.Contains(string(body), `<gp:retransmission-allowed>false</gp:retransmission-allowed>`) {
		t.Fatalf("PIDF-LO body missing explicit false retransmission rule:\n%s", body)
	}
}

func TestValidateEmergencyPIDFLOExtractsEnvelopeAndUsageRules(t *testing.T) {
	allowRetransmission := true
	body, err := BuildEmergencyPIDFLOWithUsageRules(EmergencyPIDFLOConfig{
		Entity:    "pres:device@example.test",
		TupleID:   "loc-1",
		Method:    "Derived",
		Timestamp: time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC),
		Address: EmergencyAddress{
			Latitude:    "47.6205",
			Longitude:   "-122.3493",
			Country:     "US",
			State:       "WA",
			City:        "Seattle",
			HouseNumber: "100",
		},
	}, EmergencyPIDFLOUsageRules{
		RetransmissionAllowed: &allowRetransmission,
		RetentionExpiry:       time.Date(2026, 7, 7, 9, 30, 0, 0, time.UTC),
		RulesetReference:      "https://example.test/location-policy/e911",
		NoteWell:              "Emergency location",
	})
	if err != nil {
		t.Fatalf("BuildEmergencyPIDFLOWithUsageRules() error = %v", err)
	}

	validation, err := ValidateEmergencyPIDFLO(body)
	if err != nil {
		t.Fatalf("ValidateEmergencyPIDFLO() error = %v", err)
	}
	if !validation.Valid || len(validation.Missing) != 0 {
		t.Fatalf("validation=%+v, want valid", validation)
	}
	if validation.Entity != "pres:device@example.test" || validation.TupleID != "loc-1" || validation.Method != "Derived" {
		t.Fatalf("envelope=%+v", validation)
	}
	if !validation.Timestamp.Equal(time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("Timestamp=%v", validation.Timestamp)
	}
	if validation.Address.Latitude != "47.6205" || validation.Address.Longitude != "-122.3493" ||
		validation.Address.Country != "US" || validation.Address.HouseNumber != "100" {
		t.Fatalf("Address=%+v", validation.Address)
	}
	if validation.UsageRules.RetransmissionAllowed == nil || !*validation.UsageRules.RetransmissionAllowed ||
		!validation.UsageRules.RetentionExpiry.Equal(time.Date(2026, 7, 7, 9, 30, 0, 0, time.UTC)) ||
		validation.UsageRules.RulesetReference != "https://example.test/location-policy/e911" ||
		validation.UsageRules.NoteWell != "Emergency location" {
		t.Fatalf("UsageRules=%+v", validation.UsageRules)
	}
}

func TestValidateEmergencyPIDFLORejectsLooseLegacyLocationXML(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<presence entity="pres:device@example.test">
  <tuple id="loc-1">
    <status>
      <gml:Point xmlns:gml="http://www.opengis.net/gml">
        <gml:pos>47.6205 -122.3493</gml:pos>
      </gml:Point>
    </status>
  </tuple>
</presence>`)
	address, err := ParseEmergencyPIDFLO(body)
	if err != nil {
		t.Fatalf("ParseEmergencyPIDFLO() legacy compatibility error = %v", err)
	}
	if address.Latitude != "47.6205" || address.Longitude != "-122.3493" {
		t.Fatalf("legacy parsed address=%+v", address)
	}

	validation, err := ValidateEmergencyPIDFLO(body)
	if err == nil {
		t.Fatal("ValidateEmergencyPIDFLO() error = nil")
	}
	if validation.Valid {
		t.Fatalf("validation should be invalid: %+v", validation)
	}
	for _, want := range []string{"geopriv", "location-info", "location", "method"} {
		if !sameStringsContains(validation.Missing, want) {
			t.Fatalf("missing=%+v, want %q", validation.Missing, want)
		}
	}
}

func TestValidateEmergencyPIDFLORejectsMalformedUsageRules(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "bad retransmission",
			body: `<?xml version="1.0"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:gp="urn:ietf:params:xml:ns:pidf:geopriv10" xmlns:gml="http://www.opengis.net/gml" entity="pres:device@example.test">
  <tuple id="loc-1"><status><gp:geopriv><gp:location-info><gml:Point><gml:pos>47.6205 -122.3493</gml:pos></gml:Point></gp:location-info><gp:usage-rules><gp:retransmission-allowed>sometimes</gp:retransmission-allowed></gp:usage-rules><gp:method>Manual</gp:method></gp:geopriv></status></tuple>
</presence>`,
			want: "retransmission-allowed",
		},
		{
			name: "expired retention",
			body: `<?xml version="1.0"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:gp="urn:ietf:params:xml:ns:pidf:geopriv10" xmlns:gml="http://www.opengis.net/gml" entity="pres:device@example.test">
  <tuple id="loc-1"><status><gp:geopriv><gp:location-info><gml:Point><gml:pos>47.6205 -122.3493</gml:pos></gml:Point></gp:location-info><gp:usage-rules><gp:retention-expiry>2026-07-07T08:59:59Z</gp:retention-expiry></gp:usage-rules><gp:method>Manual</gp:method></gp:geopriv></status><timestamp>2026-07-07T09:00:00Z</timestamp></tuple>
</presence>`,
			want: "retention-expiry",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateEmergencyPIDFLO([]byte(tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateEmergencyPIDFLO() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBuildEmergencyPIDFLORejectsExpiredRetentionExpiry(t *testing.T) {
	_, err := BuildEmergencyPIDFLOWithUsageRules(EmergencyPIDFLOConfig{
		Timestamp: time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC),
		Address: EmergencyAddress{
			Latitude:  "47.6205",
			Longitude: "-122.3493",
		},
	}, EmergencyPIDFLOUsageRules{
		RetentionExpiry: time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC),
	})
	if err == nil || !strings.Contains(err.Error(), "retention-expiry") {
		t.Fatalf("BuildEmergencyPIDFLOWithUsageRules() error = %v, want retention-expiry boundary", err)
	}
}

func TestBuildUsableEmergencySIPRequestInfoUsesEntitlementSnapshot(t *testing.T) {
	base := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	cache := NewEntitlementCache(EntitlementCachePolicy{RefreshBefore: time.Minute})
	snapshot := cache.Store(EntitlementInfo{
		Status:      1000,
		ServiceURNs: []string{"fire"},
		Routes: []EmergencyRoute{
			{ServiceURN: "fire", PCSCF: []string{"pcscf-fire.ims.example"}},
			{Endpoints: []string{"sips:any@example.test"}},
		},
		Address: EmergencyAddress{
			Latitude:  "47.6205",
			Longitude: "-122.3493",
		},
		CacheMaxAge: 5 * time.Minute,
	}, base)

	info, ok := BuildUsableEmergencySIPRequestInfo(snapshot, EmergencySIPHeaderConfig{
		ServiceURN: "fire",
		AccessNetworkInfo: EmergencyAccessNetworkInfo{
			WLANNodeID: "aa:bb:cc:dd:ee:ff",
		},
		GeolocationRouting: true,
	})
	if !ok {
		t.Fatalf("BuildUsableEmergencySIPRequestInfo() ok=false for usable snapshot: %+v", snapshot)
	}
	if info.RequestURI != "urn:service:sos.fire" {
		t.Fatalf("RequestURI=%q", info.RequestURI)
	}
	if info.Headers["Geolocation"] != "<geo:47.6205,-122.3493>;inserted-by=endpoint" {
		t.Fatalf("Geolocation=%q", info.Headers["Geolocation"])
	}
	if info.Headers["Geolocation-Routing"] != "yes" {
		t.Fatalf("Geolocation-Routing=%q", info.Headers["Geolocation-Routing"])
	}
	if got := info.Headers["P-Access-Network-Info"]; got != `IEEE-802.11;i-wlan-node-id="aa:bb:cc:dd:ee:ff"` {
		t.Fatalf("P-Access-Network-Info=%q", got)
	}
	if len(info.Routes) != 2 {
		t.Fatalf("routes=%+v, want service route plus generic route", info.Routes)
	}
	if !sameStrings(info.RouteSet, []string{"<sip:pcscf-fire.ims.example;lr>", "<sips:any@example.test;lr>"}) {
		t.Fatalf("RouteSet=%+v", info.RouteSet)
	}
	if info.Routes[0].ServiceURN != "urn:service:sos.fire" || !sameStrings(info.Routes[0].PCSCF, []string{"pcscf-fire.ims.example"}) {
		t.Fatalf("service route=%+v", info.Routes[0])
	}
	if !sameStrings(info.Routes[1].Endpoints, []string{"sips:any@example.test"}) {
		t.Fatalf("generic route=%+v", info.Routes[1])
	}
}

func TestEmergencySIPRouteSetFormatsEntitlementRoutes(t *testing.T) {
	got := EmergencySIPRouteSet([]EmergencyRoute{
		{
			PCSCF:     []string{"pcscf-emergency.ims.example", "sip:pcscf-emergency.ims.example;lr"},
			ESRP:      []string{"sips:esrp.ims.example"},
			Endpoints: []string{"<sip:psap.example;transport=tcp;lr>"},
		},
		{
			Endpoints: []string{"tel:+15551212", "pcscf-emergency.ims.example"},
		},
	})
	want := []string{
		"<sip:pcscf-emergency.ims.example;lr>",
		"<sips:esrp.ims.example;lr>",
		"<sip:psap.example;transport=tcp;lr>",
		"<tel:+15551212>",
	}
	if !sameStrings(got, want) {
		t.Fatalf("RouteSet=%+v, want %+v", got, want)
	}
}

func TestEntitlementCacheUsableEmergencySIPRequestInfoBuildsFromRefreshWindowSnapshot(t *testing.T) {
	base := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	cache := NewEntitlementCache(EntitlementCachePolicy{RefreshBefore: 2 * time.Minute})
	cache.Store(EntitlementInfo{
		Status:      1000,
		ServiceURNs: []string{"ambulance", "fire"},
		Routes: []EmergencyRoute{
			{ServiceURN: "ambulance", PCSCF: []string{"pcscf-ambulance.ims.example"}},
			{Endpoints: []string{"sips:any@example.test"}},
		},
		Address: EmergencyAddress{
			Latitude:  "40.7128",
			Longitude: "-74.0060",
		},
		CacheMaxAge: 5 * time.Minute,
	}, base)

	info, snapshot, ok := cache.UsableEmergencySIPRequestInfo(EmergencySIPHeaderConfig{
		AccessNetworkInfo:  EmergencyAccessNetworkInfo{Raw: "IEEE-802.11"},
		GeolocationRouting: true,
	}, base.Add(4*time.Minute))
	if !ok {
		t.Fatalf("UsableEmergencySIPRequestInfo() ok=false for refresh-window snapshot: %+v", snapshot)
	}
	if !snapshot.RefreshRequired || snapshot.RefreshReason != EntitlementRefreshReasonRefreshWindow {
		t.Fatalf("snapshot=%+v, want refresh-window but still usable", snapshot)
	}
	if info.RequestURI != "urn:service:sos.ambulance" {
		t.Fatalf("RequestURI=%q", info.RequestURI)
	}
	if info.Headers["P-Access-Network-Info"] != "IEEE-802.11" {
		t.Fatalf("P-Access-Network-Info=%q", info.Headers["P-Access-Network-Info"])
	}
	if info.Headers["Geolocation"] != "<geo:40.7128,-74.0060>;inserted-by=endpoint" {
		t.Fatalf("Geolocation=%q", info.Headers["Geolocation"])
	}
	if len(info.Routes) != 2 {
		t.Fatalf("routes=%+v, want selected service route plus generic route", info.Routes)
	}
	if !sameStrings(info.Routes[0].PCSCF, []string{"pcscf-ambulance.ims.example"}) {
		t.Fatalf("service route=%+v", info.Routes[0])
	}
	if !sameStrings(info.Routes[1].Endpoints, []string{"sips:any@example.test"}) {
		t.Fatalf("generic route=%+v", info.Routes[1])
	}

	info.Routes[0].PCSCF[0] = "changed.example"
	nextInfo, _, ok := cache.UsableEmergencySIPRequestInfo(EmergencySIPHeaderConfig{ServiceURN: "ambulance"}, base.Add(4*time.Minute))
	if !ok {
		t.Fatal("second UsableEmergencySIPRequestInfo() ok=false")
	}
	if !sameStrings(nextInfo.Routes[0].PCSCF, []string{"pcscf-ambulance.ims.example"}) {
		t.Fatalf("route copy leaked into cache helper: %+v", nextInfo.Routes[0])
	}

	_, expired, ok := cache.UsableEmergencySIPRequestInfo(EmergencySIPHeaderConfig{ServiceURN: "ambulance"}, base.Add(5*time.Minute))
	if ok {
		t.Fatalf("expired snapshot should not build runtime SIP request info: %+v", expired)
	}
	if expired.RefreshReason != EntitlementRefreshReasonExpired {
		t.Fatalf("expired snapshot reason=%q", expired.RefreshReason)
	}
}

func TestBuildUsableEmergencySIPRequestInfoRejectsStaleOrUnsupportedEntitlement(t *testing.T) {
	base := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	cache := NewEntitlementCache(EntitlementCachePolicy{})
	cache.Store(EntitlementInfo{
		Status:      1000,
		ServiceURNs: []string{"police"},
		Routes: []EmergencyRoute{
			{ServiceURN: "police", PCSCF: []string{"pcscf-police.ims.example"}},
		},
		CacheMaxAge: 5 * time.Minute,
	}, base)

	fresh := cache.Snapshot(base.Add(time.Minute))
	if _, ok := BuildUsableEmergencySIPRequestInfo(fresh, EmergencySIPHeaderConfig{ServiceURN: "fire"}); ok {
		t.Fatal("unsupported requested service should not build from usable entitlement")
	}
	if !sameStrings(fresh.AvailableServiceURNs(), []string{"urn:service:sos.police"}) {
		t.Fatalf("available service URNs=%+v", fresh.AvailableServiceURNs())
	}

	expired := cache.Snapshot(base.Add(5 * time.Minute))
	if _, ok := BuildUsableEmergencySIPRequestInfo(expired, EmergencySIPHeaderConfig{ServiceURN: "police"}); ok {
		t.Fatal("expired entitlement should not build runtime SIP request info")
	}
	if routes := expired.AvailableRoutes("police"); len(routes) != 1 {
		t.Fatalf("available routes should preserve legacy view, got %+v", routes)
	}
	if routes := expired.UsableRoutes("police"); len(routes) != 0 {
		t.Fatalf("expired usable routes=%+v, want none", routes)
	}
}

func TestBuildEmergencySIPHeadersAllowsCarrierOverrides(t *testing.T) {
	headers := BuildEmergencySIPHeaders(EmergencySIPHeaderConfig{
		AccessNetworkInfo: EmergencyAccessNetworkInfo{
			Raw: "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=3102600abcdef",
		},
		GeolocationURI: "<cid:location-1>;routing-allowed=yes",
	})
	if headers["P-Access-Network-Info"] != "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=3102600abcdef" {
		t.Fatalf("P-Access-Network-Info=%q", headers["P-Access-Network-Info"])
	}
	if headers["Geolocation"] != "<cid:location-1>;routing-allowed=yes" {
		t.Fatalf("Geolocation=%q", headers["Geolocation"])
	}
	if headers["Geolocation-Routing"] != "" {
		t.Fatalf("Geolocation-Routing=%q, want omitted", headers["Geolocation-Routing"])
	}
}

func TestEmergencyRequestURIFallsBackToSOS(t *testing.T) {
	if got := EmergencyRequestURI(""); got != DefaultEmergencyServiceURN {
		t.Fatalf("empty service RequestURI=%q", got)
	}
	if got := EmergencyRequestURI("unknown-private-service"); got != DefaultEmergencyServiceURN {
		t.Fatalf("unknown service RequestURI=%q", got)
	}
	if got := NormalizeEmergencyServiceURN("URN:SERVICE:SOS.POLICE"); got != "urn:service:sos.police" {
		t.Fatalf("normalized URN=%q", got)
	}
}

func sameStringsContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
