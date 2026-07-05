# vowifi-go

An independent, open implementation of the VoHive VoWiFi runtime boundary.

This repository intentionally starts with the public API surface consumed by
VoHive:

- SIM AKA contracts under `engine/sim`
- SWu dataplane mode, tunnel establishment, and MOBIKE contracts under
  `engine/swu`
- runtime lifecycle, state, modem access, and service wrappers under
  `runtimehost`
- carrier policy and E911 request contracts under `runtimehost/carrier` and
  `runtimehost/e911`
- SMS, USSD, event dispatch, and voice gateway integration helpers under
  `runtimehost/messaging`, `runtimehost/eventhost`, and `runtimehost/voicehost`

The current implementation includes the runtime boundary plus the first real
protocol layers needed by VoHive:

- logical-channel SIM/ISIM APDU helpers, FCP/TLV parsing, ISIM identity EF
  reading, and USIM/ISIM AKA AUTHENTICATE primitives
- carrier presets and JSON carrier overrides, including AT&T TS.43/E911
  configuration for native `310/280` and `310/410` profiles
- TS.43-style E911 entitlement bootstrap, token/websheet handling, RAND/AUTN
  challenge response through the AKA provider, and EAP-AKA relay packet
  response generation for entitlement challenges
- IMS SIP client primitives for REGISTER headers, `WWW-Authenticate` parsing,
  AKA nonce extraction, Digest/AKAv1-MD5 and AKAv2-MD5 authorization material,
  Security-Verify echoing, wire-level UDP/TCP REGISTER transport, and IMS
  registration binding parsing
- IMS REGISTER session flow with 401/407 authentication retry, associated URI,
  Service-Route, Path, Security-Server, and Contact expiry capture, plus a
  runtime `IMSRegistrar` adapter for the wire transport
- SMS segmentation, SIP transport hooks, inbound SMS, delivery report matching,
  and USSD session transport hooks
- outbound voice dialog bridging helpers, SDP parsing/building, IMS INVITE/ACK/
  BYE/CANCEL request construction, route-set application, UDP/TCP SIP request
  transport, outbound IMS voice agent, ACK/BYE dialog handling, RTP media relay
  endpoint allocation, SDP media rewriting, packet forwarding, and dialog
  termination hooks
- SWu tunnel manager/session contracts with startup validation, tunnel readiness
  state integration, shutdown cleanup, and MOBIKE delegation
- IKEv2 binary header/payload framing, Notify/KE/Nonce/EAP helpers, NAT
  detection hashes, MOBIKE notify helpers, and PRF+/SKEYSEED key derivation
  primitives for the SWu dataplane
- IKEv2 SA proposal/transform encoding, default IKE/ESP proposals,
  configuration payload requests, identity payloads, traffic selectors, and
  EAP-AKA/AKA' packet and attribute codecs
- IKE_SA_INIT initiator flow with UDP/NAT-T transport support, X25519 key
  exchange, NAT-D/MOBIKE notifications, responder parsing, SKEYSEED, and IKE SA
  key material derivation
- IKEv2 key material split into SK_d/SK_ai/SK_ar/SK_ei/SK_er/SK_pi/SK_pr plus
  AES-CBC/HMAC protected SK payload construction and verification
- encrypted IKE_AUTH EAP-Identity exchange scaffolding, including IDi, CP,
  CHILD_SA/TSi/TSr request payloads, responder EAP parsing, and
  EAP-Response/Identity transmission
- EAP-AKA full-auth key derivation, AT_MAC verification/generation,
  AT_RAND/AT_AUTN challenge extraction, SIM AKA RES response, and AUTS
  synchronization-failure response over encrypted IKE_AUTH
- final IKE_AUTH CHILD_SA result parsing with responder ESP SPI,
  configuration/traffic selector extraction, and RFC 7296 ESP outbound/inbound
  key material derivation from SK_d and IKE_SA_INIT nonces
- userspace ESP packet seal/open primitives with SPI/sequence handling,
  AES-CBC payload encryption, HMAC-SHA integrity checks, RFC 4303 padding,
  next-header restoration, and replay-window validation

Kernel/userspace ESP SA installation, packet routing transport, SRTP/RTCP media
features, and complete inbound IMS call handling are still implemented
incrementally behind these APIs.

## Development

```sh
go test ./...
```

VoHive can use this repository through its workspace:

```go
replace github.com/iniwex5/vowifi-go v1.1.2 => ../vowifi-go
```
