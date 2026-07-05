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
  challenge response through the AKA provider, and EAP-AKA/AKA' relay packet
  response generation with KDF negotiation for entitlement challenges
- IMS SIP client primitives for REGISTER headers, `WWW-Authenticate` parsing,
  AKA nonce extraction, Digest/AKAv1-MD5 and AKAv2-MD5 authorization material,
  Security-Verify echoing, wire-level UDP/TCP REGISTER transport, and IMS
  registration binding parsing
- SIP UDP client transaction retransmission for REGISTER and IMS dialog
  requests, with configurable T1/T2-style backoff and INVITE provisional
  response handling
- IMS REGISTER session flow with 401/407 authentication retry, associated URI,
  Service-Route, Path, Security-Server, and Contact expiry capture, plus a
  runtime `IMSRegistrar` adapter for the wire transport
- SMS segmentation, IMS SIP `MESSAGE` transport hooks, inbound SMS, delivery
  report matching, and USSD session transport hooks
- outbound voice dialog bridging helpers, SDP parsing/building, IMS INVITE/ACK/
  BYE/CANCEL request construction, route-set application, UDP/TCP SIP request
  transport, outbound IMS voice agent, ACK/BYE dialog handling, RTP/RTCP media
  relay endpoint allocation, SDP media/RTCP rewriting, packet forwarding, and
  dialog termination hooks
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
- IKEv2 encrypted INFORMATIONAL exchange runner for empty DPD liveness probes
  and DELETE payloads for IKE/ESP/AH SA teardown, plus SWu close-handler
  wiring for graceful CHILD_SA/IKE_SA deletion
- MOBIKE UPDATE_SA_ADDRESSES control-plane helpers with optional NAT-D and
  address-set notifications, response rejection handling, and packet-session
  state refresh on successful updates
- encrypted IKE_AUTH EAP-Identity exchange scaffolding, including IDi, CP,
  CHILD_SA/TSi/TSr request payloads, responder EAP parsing, and
  EAP-Response/Identity transmission
- EAP-AKA full-auth key derivation, EAP-AKA' CK'/IK' and PRF' key material,
  AT_KDF negotiation, AT_MAC verification/generation, AT_RAND/AT_AUTN challenge
  extraction, SIM AKA RES response, and AUTS synchronization-failure response
  over encrypted IKE_AUTH
- final IKE_AUTH CHILD_SA result parsing with responder ESP SPI,
  configuration/traffic selector extraction, and RFC 7296 ESP outbound/inbound
  key material derivation from SK_d and IKE_SA_INIT nonces
- userspace ESP packet seal/open primitives with SPI/sequence handling,
  AES-CBC payload encryption, HMAC-SHA integrity checks, RFC 4303 padding,
  next-header restoration, and replay-window validation
- SWu userspace packet tunnel session wiring that builds outbound/inbound ESP
  SAs from the CHILD_SA result, auto-selects IPv4/IPv6 next headers, sends ESP
  packets through a transport boundary, opens inbound ESP packets, tracks
  packet/byte/error/drop counters, and rejects replayed traffic
- UDP/NAT-T ESP packet transport for the userspace dataplane, including
  reusable UDP socket management, raw ESP send/receive, NAT keepalive and
  non-ESP marker filtering, deadline handling, and close semantics
- userspace dataplane packet pump and Linux TUN device integration, bridging
  inner IP packets from a TUN device into ESP and writing decrypted ESP payloads
  back to the TUN device
- Linux TUN dataplane routing helpers for MTU/link setup, inner address
  assignment, route installation, policy rule installation, cleanup, and
  best-effort rollback through the `ip` command boundary
- automatic ePDG route exclusion helpers that install protected host routes via
  the outer modem interface, including support for main and policy-routing
  tables before TUN default routes are applied
- Linux kernel XFRM/IPsec helpers that install ESP tunnel states, outbound/
  inbound/forward policies, optional marks, reqids, and XFRM interfaces from
  IKEv2 CHILD_SA key material with rollback and cleanup support
- SRTP/SRTCP media helpers and RTP relay transforms for protecting and
  unprotecting RTP/RTCP packets with AES-CM/HMAC-SHA1 and AEAD-AES-GCM
  profiles, independent client/IMS key material, replay protection, and
  authentication failure handling
- RTCP feedback inspection for RTP/SRTP relay paths, including Sender/Receiver
  Reports, PLI/FIR/rapid resynchronization requests, NACK, REMB, transport-wide
  congestion control, SLI, XR, SDES, BYE, application-defined packets,
  clear-relay counters, and SRTP plaintext-stage event callbacks
- inbound IMS voice agent helpers that bridge IMS-originated INVITEs to a local
  SIP client, parse SDP answers, forward ACK/BYE/CANCEL dialog requests, and
  support RTP relay allocation with IMS-offer/client-answer SDP rewriting
- wire-level inbound IMS SIP adapters for UDP/TCP listeners, SIP request
  parsing, provisional/final response construction, incoming INVITE/ACK/BYE/
  CANCEL dispatch, response To-tagging, transaction response caching for
  retransmitted requests, and loopback-tested socket handling
- IMS in-dialog interworking for UPDATE, PRACK, and OPTIONS, including SDP
  session refresh forwarding, RAck propagation, RTP relay endpoint rewriting
  for UPDATE offers/answers, and local OPTIONS capability responses
- in-dialog re-INVITE handling for IMS-originated media renegotiation, including
  local client forwarding, SDP answer rewriting, Contact refresh, and ACK CSeq
  tracking for the latest successful INVITE transaction

Full SIP transaction timer state machines and advanced IMS feature interworking
are still implemented incrementally behind these APIs.

## Development

```sh
go test ./...
```

VoHive can use this repository through its workspace:

```go
replace github.com/iniwex5/vowifi-go v1.1.2 => ../vowifi-go
```
