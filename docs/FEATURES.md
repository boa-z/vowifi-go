# Features

This document carries the detailed implementation inventory that used to live
in the README.

## Status Note

vowifi-go is still under active development. It does not yet implement the
complete feature set of the official closed-source VoWiFi implementation, and
it should not be treated as production-ready or feature-complete.

## Runtime API Surface

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

## Current Implementation

The current implementation includes the runtime boundary plus the first real
protocol layers needed by VoHive:

- logical-channel SIM/ISIM APDU helpers, FCP/TLV parsing, ISIM identity EF
  reading, and USIM/ISIM AKA AUTHENTICATE primitives
- carrier presets and JSON carrier overrides, including AT&T TS.43/E911
  configuration for native `310/280` and `310/410` profiles
- TS.43-style E911 entitlement bootstrap, token/websheet handling, RAND/AUTN
  challenge response through the AKA provider, and EAP-AKA/AKA' relay packet
  response generation with Identity/KDF negotiation, Notification ACK, and
  Client-Error handling for entitlement challenges
- IMS SIP client primitives for REGISTER headers, `WWW-Authenticate` parsing,
  AKA nonce extraction, Digest/AKAv1-MD5 and AKAv2-MD5 authorization material,
  IMS `Security-Client` proposal generation, `Security-Server` parsing/
  selection, Security-Verify echoing, folded/compact SIP header parsing, strict
  Content-Length body and duplicate-length validation, SIP response status-code
  range validation, wire-level UDP/TCP REGISTER transport, and IMS registration
  binding parsing
- SIP UDP client transaction retransmission for REGISTER and IMS dialog
  requests, with configurable T1/T2-style backoff, INVITE provisional response
  handling, non-INVITE 1xx handling that waits for final responses while
  stopping UDP retransmits after a provisional response, and response
  correlation filtering for `Call-ID`, `CSeq`, and Via branch headers when
  peers include transaction identifiers
- reusable SIP flow transport for REGISTER, MESSAGE, USSD, and voice dialog
  requests, preserving the REGISTER socket/local port for IMS NAT pinholes and
  offering explicit CRLF keepalive support, including sticky reuse of the
  selected P-CSCF after failover
- SIP server resolution with injectable policy hooks and default `_sip._udp` /
  `_sip._tcp` SRV lookup, A/AAAA expansion, ordered candidate lists, and
  REGISTER/dialog transport failover before direct host:port fallback,
  including REGISTER failover on recoverable P-CSCF final responses such as
  503 or other transient 5xx statuses
- SWu IKE configuration payload DNS extraction, exposing negotiated internal
  DNS servers to the runtime and using them for default IMS SRV/A/AAAA lookups
- IMS REGISTER session flow with 401/407 authentication retry, 423
  `Min-Expires` retry handling, associated URI, Service-Route, Path,
  Security-Server, and Contact expiry capture, plus a runtime `IMSRegistrar`
  adapter for the wire transport
- IMS REGISTER refresh maintenance on the reusable SIP flow, including
  expiry-based renewal, 423 `Min-Expires` retry handling, retry scheduling,
  binding/auth/CSeq state updates, full re-registration after recoverable
  refresh/flow failures, and shutdown de-registration with the latest
  registration state
- IMS recovery re-registration on reusable SIP flows can advance to the next
  resolved P-CSCF candidate after recoverable failures, preserving the candidate
  list instead of repeatedly selecting the same failed proxy
- IMS registration recovery hooks exposed from the wire registrar to the
  runtime, returning refreshed binding, voice, SMS, and USSD transports after
  re-registration
- automatic IMS SIP CRLF keepalive scheduling on the registered wire flow to
  preserve NAT/PCSCF pinholes between SIP transactions
- IMS de-registration flow for shutdown cleanup, sending `REGISTER` with
  `Expires: 0`, Contact `expires=0`, Security-Verify, and Digest/AKA retry on
  401/407 challenges
- SMS segmentation, IMS SIP `MESSAGE` transport hooks, inbound SMS, delivery
  report matching, and USSD session transport hooks, including recoverable IMS
  registration/route failure signals for MESSAGE, USSD INVITE/INFO, and USSD
  BYE failures
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
  and DELETE payloads for IKE/ESP/AH SA teardown, plus SWu close-handler wiring
  for graceful CHILD_SA/IKE_SA deletion
- MOBIKE UPDATE_SA_ADDRESSES control-plane helpers with optional NAT-D and
  address-set notifications, response rejection handling, and packet-session
  state refresh on successful updates
- IKEv2 CREATE_CHILD_SA initiator flow for additional or rekeyed ESP Child SAs,
  including SA/Nonce/TS request construction, REKEY_SA notify support,
  encrypted response validation, and per-exchange Ni/Nr key derivation
- encrypted IKE_AUTH EAP-Identity exchange scaffolding, including IDi, CP,
  CHILD_SA/TSi/TSr request payloads, responder EAP parsing, and
  EAP-Response/Identity transmission
- high-level encrypted IKE_AUTH EAP-AKA/AKA' orchestration that drives
  Identity, AKA' KDF negotiation, AKA challenge, EAP control follow-ups, and
  final CHILD_SA parsing as one flow
- SWu userspace IKE packet tunnel manager that derives ePDG/AKA identities,
  runs IKE_SA_INIT and full IKE_AUTH, requires a negotiated CHILD_SA, wires the
  CHILD_SA into a PacketSession, and attaches graceful close/MOBIKE control
  hooks when negotiated key material is available
- EAP-AKA full-auth key derivation, EAP-AKA' CK'/IK' and PRF' key material,
  AT_KDF negotiation, AT_MAC verification/generation, AT_RAND/AT_AUTN challenge
  extraction, SIM AKA RES response, AUTS synchronization-failure response,
  AUTN MAC-failure Authentication-Reject response, EAP-AKA Notification ACK,
  and Client-Error handling over encrypted IKE_AUTH
- final IKE_AUTH CHILD_SA result parsing with responder ESP SPI,
  configuration/traffic selector extraction, and RFC 7296 ESP outbound/inbound
  key material derivation from SK_d and IKE_SA_INIT nonces
- userspace ESP packet seal/open primitives with SPI/sequence handling, AES-CBC
  payload encryption, HMAC-SHA integrity checks, RFC 4303 padding, next-header
  restoration, and replay-window validation
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
- composable SWu TUN tunnel manager that wraps an IKE PacketSession, opens a
  TUN device, applies Linux routing/address setup, starts the bidirectional
  packet pump, and rolls back/cleans up routes, device, and session state
- runtime startup wiring that builds the default userspace SWu TUN/IKE manager
  for explicit userspace dataplane requests and forwards the negotiated tunnel
  inner address into IMS REGISTER Contact construction
- default userspace dataplane routing that installs a TUN default route while
  protecting ePDG outer UDP/ESP reachability with pre-tunnel host routes
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
  support RTP relay allocation with IMS-offer/client-answer SDP rewriting,
  including early-dialog CANCEL forwarding with original INVITE Via reuse and
  487 Request Terminated mapping for the canceled INVITE transaction, plus
  local 18x provisional response forwarding with early SDP/RTP relay rewriting
  and early-dialog To-tag, Contact, and Record-Route state capture for PRACK,
  while preserving bodyless final 2xx responses after a reliable provisional
  SDP answer
- wire-level inbound IMS SIP adapters for UDP/TCP listeners, SIP request
  parsing, provisional/final response construction, incoming INVITE/ACK/BYE/
  CANCEL dispatch, response To-tagging, transaction response caching for
  retransmitted requests, immediate `100 Trying` emission for socket-served
  INVITEs, forwarding of reliable provisional headers such as `Require: 100rel`
  and `RSeq`, in-progress INVITE transaction caching while local client final
  responses are pending, UDP final INVITE response retransmission until the
  matching ACK arrives or the transaction expires, UDP reliable provisional
  response retransmission for `Require: 100rel`/`RSeq` responses until matching
  PRACK receipt, mandatory RAck validation and reliable provisional state
  matching for inbound PRACK, core header and strict CSeq number/method
  validation, Max-Forwards loop rejection, and unsupported `Require` option-tag
  rejection for non-ACK requests, `481 Call/Transaction Does Not Exist` handling
  for CANCELs without a matching pending INVITE transaction, and loopback-tested
  socket handling
- IMS in-dialog interworking for UPDATE, PRACK, and OPTIONS, including SDP
  session refresh forwarding, RAck propagation, RTP relay endpoint rewriting
  for UPDATE offers/answers, and local OPTIONS capability responses
- IMS in-dialog SIP INFO forwarding for outbound and inbound voice dialogs,
  including DTMF-style payloads, Info-Package propagation, response body/header
  mapping, and dialog CSeq advancement
- runtime voice operations consume recoverable registration or route failures
  such as 481, 503, transport errors, and other transient IMS 5xx responses to
  trigger IMS re-registration, refresh voice/SMS/USSD transports, and retry an
  initial INVITE once after successful recovery
- recoverable IMS failures propagate SIP `Retry-After` delay hints from
  REGISTER refresh, voice dialogs, SMS MESSAGE, and USSD transactions so runtime
  recovery waits instead of immediately hammering a temporarily unavailable
  P-CSCF or registrar
- runtime SMS and USSD operations consume the same recoverable IMS failure
  signal, refresh IMS registration and message transports, and retry only the
  initial SMS part or USSD INVITE when the original attempt failed before a SIP
  final response was received
- local softphone in-dialog SIP UPDATE forwarding to IMS dialogs, including
  session refresh/media renegotiation SDP validation, RTP relay endpoint
  rewriting, response body/header mapping, remote Contact refresh, and dialog
  CSeq advancement
- local softphone in-dialog re-INVITE forwarding to IMS dialogs for media
  renegotiation, including SDP validation, RTP relay rewriting, final response
  ACK handling, remote Contact refresh, response header/body mapping, and CSeq
  advancement
- RTP relay media-direction enforcement for SDP hold/resume semantics, applying
  `sendonly`, `recvonly`, `inactive`, and legacy `c=0.0.0.0` hold handling to
  RTP forwarding while keeping RTCP feedback/report paths available, including
  disabled `m=audio 0` streams without leaking relay endpoints
- IMS Session-Expires timer negotiation across outbound and IMS-originated
  inbound initial INVITE, UPDATE, and re-INVITE paths, including
  `refresher=uac/uas` preservation, 422 Min-SE retry handling, dialog-state
  updates from 2xx responses, softphone response header propagation, and
  automatic empty UPDATE session refreshes when the negotiated refresher role
  is `uac`
- in-dialog re-INVITE handling for IMS-originated media renegotiation, including
  local client forwarding, SDP answer rewriting, Contact refresh, and ACK CSeq
  tracking for the latest successful INVITE transaction

## Known Gaps

- Complete parity with the official closed-source implementation is not
  available.
- Full SIP transaction timer state machines are still being expanded.
- Advanced IMS feature interworking and carrier-specific behavior are still
  implemented incrementally.
- Real hardware, modem, operator, and production-network compatibility require
  separate validation outside the loopback-heavy test suite.
