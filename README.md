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
- TS.43-style E911 entitlement bootstrap, token/websheet handling, and
  RAND/AUTN challenge response through the AKA provider
- IMS SIP client primitives for REGISTER headers, `WWW-Authenticate` parsing,
  AKA nonce extraction, and Digest/AKAv1-MD5 authorization generation
- IMS REGISTER session flow with 401/407 authentication retry
- SMS segmentation, SIP transport hooks, inbound SMS, delivery report matching,
  and USSD session transport hooks
- outbound voice dialog bridging helpers, SDP parsing/building, and dialog
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

The IKE_AUTH/EAP-AKA state machine, ESP packet transport, and RTP media
transport are still implemented incrementally behind these APIs.

## Development

```sh
go test ./...
```

VoHive can use this repository through its workspace:

```go
replace github.com/iniwex5/vowifi-go v1.1.2 => ../vowifi-go
```
