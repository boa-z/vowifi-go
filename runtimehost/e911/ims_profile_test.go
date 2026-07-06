package e911

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/runtimehost/voiceclient"
)

func TestBuildEmergencyRegisterHeadersMarksContactAndValidatesBinding(t *testing.T) {
	profile := voiceclient.IMSProfile{
		IMPI:      "001010123456789@ims.example",
		IMPU:      "sip:001010123456789@ims.example",
		Domain:    "ims.example",
		UserAgent: "vowifi-go-test",
	}
	headers, err := BuildEmergencyRegisterHeaders(profile, "sip:001010123456789@192.0.2.10:5060;transport=udp?Route=sip:pcscf.example", "call-1", "1")
	if err != nil {
		t.Fatalf("BuildEmergencyRegisterHeaders() error = %v", err)
	}
	contact := headers["Contact"]
	if !strings.Contains(contact, `<sip:001010123456789@192.0.2.10:5060;transport=udp;sos?Route=sip:pcscf.example>`) ||
		!strings.Contains(contact, `+sip.instance=`) ||
		!strings.Contains(contact, `+g.3gpp.icsi-ref=`) {
		t.Fatalf("emergency Contact=%q", contact)
	}

	binding := voiceclient.RegistrationBinding{
		ContactURI:       "sip:001010123456789@192.0.2.10:5060",
		RegistrarContact: `<sip:001010123456789@192.0.2.10:5060;reg-type=sos>;expires=1800`,
		ServiceRoutes:    []string{"<sip:pcscf-emergency.ims.example;lr>"},
		Expires:          1800,
	}
	if validation := EmergencyRegistrationBindingValidation(binding); !validation.Valid || !validation.ContactMarked || !validation.ServiceRoutePresent || !validation.ExpiresPresent {
		t.Fatalf("validation=%+v", validation)
	}
	if err := ValidateEmergencyRegistrationBinding(binding); err != nil {
		t.Fatalf("ValidateEmergencyRegistrationBinding() error = %v", err)
	}

	binding.ServiceRoutes = nil
	err = ValidateEmergencyRegistrationBinding(binding)
	if !errors.Is(err, ErrEmergencyRegistrationInvalid) || !strings.Contains(err.Error(), "Service-Route") {
		t.Fatalf("ValidateEmergencyRegistrationBinding(missing route) error = %v", err)
	}
}

func TestBuildEmergencyInviteRequestUsesURNRoutesHeadersAndContact(t *testing.T) {
	base := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	snapshot := NewEntitlementCache(EntitlementCachePolicy{}).Store(EntitlementInfo{
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
		ServiceURN:         "fire",
		AccessNetworkInfo:  EmergencyAccessNetworkInfo{Raw: "IEEE-802.11"},
		GeolocationRouting: true,
	})
	if !ok {
		t.Fatalf("BuildUsableEmergencySIPRequestInfo() ok=false")
	}

	msg, err := BuildEmergencyInviteRequest(voiceclient.DialogRequestConfig{
		Profile: voiceclient.IMSProfile{
			IMPI:      "001010123456789@ims.example",
			IMPU:      "sip:001010123456789@ims.example",
			Domain:    "ims.example",
			UserAgent: "vowifi-go-test",
		},
		Registration: voiceclient.RegistrationBinding{
			ContactURI:     "sip:001010123456789@192.0.2.10:5060",
			PublicIdentity: "sip:001010123456789@ims.example",
		},
		CallID:   "emergency-call-1",
		LocalTag: "local",
	}, info, []byte("v=0\r\n"))
	if err != nil {
		t.Fatalf("BuildEmergencyInviteRequest() error = %v", err)
	}
	if msg.Method != "INVITE" || msg.URI != "urn:service:sos.fire" {
		t.Fatalf("INVITE method/URI=%s %s", msg.Method, msg.URI)
	}
	if msg.Headers["Accept-Contact"] != IMSEmergencyAcceptContact ||
		msg.Headers["P-Preferred-Service"] != IMSMMTelServiceIdentifier ||
		msg.Headers["Geolocation-Routing"] != GeolocationRoutingYes {
		t.Fatalf("emergency headers=%+v", msg.Headers)
	}
	if msg.Headers["Contact"] != "<sip:001010123456789@192.0.2.10:5060;sos>" {
		t.Fatalf("Contact=%q", msg.Headers["Contact"])
	}
	if msg.Headers["Route"] != "<sip:pcscf-fire.ims.example;lr>, <sips:any@example.test;lr>" {
		t.Fatalf("Route=%q", msg.Headers["Route"])
	}
	if msg.Headers["Geolocation"] != "<geo:47.6205,-122.3493>;inserted-by=endpoint" {
		t.Fatalf("Geolocation=%q", msg.Headers["Geolocation"])
	}
	if msg.Headers["Content-Type"] != "application/sdp" || string(msg.Body) != "v=0\r\n" {
		t.Fatalf("body headers/body=%+v %q", msg.Headers, msg.Body)
	}
}

func TestBuildEmergencyInviteRequestEmbedsPIDFLOMultipartBody(t *testing.T) {
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
	info := BuildEmergencySIPRequestInfo(EmergencySIPHeaderConfig{
		ServiceURN:         "fire",
		AccessNetworkInfo:  EmergencyAccessNetworkInfo{Raw: "IEEE-802.11"},
		PIDFLOContentID:    "location-inline",
		PIDFLOBody:         pidfLO,
		GeolocationRouting: true,
	})

	msg, err := BuildEmergencyInviteRequest(voiceclient.DialogRequestConfig{
		Profile: voiceclient.IMSProfile{
			IMPI:      "001010123456789@ims.example",
			IMPU:      "sip:001010123456789@ims.example",
			Domain:    "ims.example",
			UserAgent: "vowifi-go-test",
		},
		Registration: voiceclient.RegistrationBinding{
			ContactURI:     "sip:001010123456789@192.0.2.10:5060",
			PublicIdentity: "sip:001010123456789@ims.example",
		},
		CallID:   "emergency-call-pidf",
		LocalTag: "local",
	}, info, []byte("v=0\r\n"))
	if err != nil {
		t.Fatalf("BuildEmergencyInviteRequest() error = %v", err)
	}
	if msg.Headers["Geolocation"] != "<cid:location-inline>;inserted-by=endpoint" ||
		msg.Headers["Geolocation-Routing"] != GeolocationRoutingYes {
		t.Fatalf("geolocation headers=%+v", msg.Headers)
	}
	if !strings.HasPrefix(msg.Headers["Content-Type"], EmergencyMultipartRelatedContentType+";") ||
		!strings.Contains(msg.Headers["Content-Type"], `type="application/sdp"`) ||
		!strings.Contains(msg.Headers["Content-Type"], `start="<sdp>"`) {
		t.Fatalf("Content-Type=%q", msg.Headers["Content-Type"])
	}
	body := string(msg.Body)
	for _, want := range []string{
		"Content-Type: application/sdp\r\nContent-ID: <sdp>",
		"Content-Type: application/pidf+xml\r\nContent-ID: <location-inline>",
		"<gml:pos>47.6205 -122.3493</gml:pos>",
		"--e911-pidf-lo--\r\n",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("multipart body missing %q:\n%s", want, body)
		}
	}
	if msg.Headers["Contact"] != "<sip:001010123456789@192.0.2.10:5060;sos>" {
		t.Fatalf("Contact=%q", msg.Headers["Contact"])
	}
}

func TestClassifyEmergencySIPFailureMapsLocationAlternativeAndRecovery(t *testing.T) {
	location := ClassifyEmergencySIPFailure(voiceclient.SIPResponse{
		StatusCode: 424,
		Reason:     "Bad Location Information",
		Headers: map[string][]string{
			"Retry-After": {"9"},
			"Warning":     {`399 ims.example "PIDF-LO rejected"`},
		},
	})
	if !location.Retryable || !location.LocationRefreshNeeded || !location.EntitlementRefreshNeeded || location.RetryAfter != 9*time.Second {
		t.Fatalf("location failure=%+v", location)
	}

	alternative := ClassifyEmergencySIPFailure(voiceclient.SIPResponse{
		StatusCode: 380,
		Reason:     "Alternative Service",
		Headers: map[string][]string{
			"Contact": {`<urn:service:sos.ambulance>, <sip:ecscf.example;lr>`},
		},
	})
	if !alternative.Retryable || !alternative.RouteRefreshNeeded || !alternative.AlternativeService ||
		!sameStrings(alternative.AlternativeServiceURNs, []string{"urn:service:sos.ambulance"}) ||
		!sameStrings(alternative.ContactURIs, []string{"urn:service:sos.ambulance", "sip:ecscf.example;lr"}) {
		t.Fatalf("alternative failure=%+v", alternative)
	}

	recoverable := ClassifyEmergencySIPFailure(voiceclient.SIPResponse{
		StatusCode: 503,
		Reason:     "Service Unavailable",
		Headers:    map[string][]string{"Retry-After": {"5"}},
	})
	if !recoverable.Retryable || !recoverable.RegistrationRecoveryNeeded || !recoverable.RouteRefreshNeeded || recoverable.RetryAfter != 5*time.Second {
		t.Fatalf("recoverable failure=%+v", recoverable)
	}

	success := ClassifyEmergencySIPFailure(voiceclient.SIPResponse{
		StatusCode: 200,
		Reason:     "OK",
		Headers:    map[string][]string{"Warning": {`399 ims.example "geolocation accepted"`}},
	})
	if success.Retryable || success.LocationRefreshNeeded || success.EntitlementRefreshNeeded {
		t.Fatalf("success response should not be classified as failure: %+v", success)
	}
}
