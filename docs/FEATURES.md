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

- CI and compatibility validation with a shared local/GitHub Actions `make ci`
  entry point, module-path and privacy guards, formatting/tidy/vet/test checks,
  opt-in race and coverage targets, a manual old-VoHive compatibility workflow,
  and a lightweight temporary-consumer self-test for the compatibility rewrite
  and local replace flow
- logical-channel SIM/ISIM APDU helpers, AT `CCHO`/`CGLA`/`CCHC` and basic
  `CSIM`/`CRSM` transport helpers, FCP/BER-TLV parsing with multi-byte
  definite length support, ISIM identity EF reading with long-form string
  length decoding
  over logical-channel APDUs or CRSM, runtime modem-access fallback from
  explicit identity readers to APDU/CRSM/AT+CRSM identity reads, AT `CGSN`/`GSN`
  IMEI reads with modem-access recovery retry, SIM/ISIM recovery error
  classification with opt-in hooks and default non-destructive AT control
  recovery plans and operator-visible recovery recommendations,
  human-readable APDU/CRSM status-word descriptions for common SIM/USIM/ISIM
  success, warning, procedure, and checking-error responses,
  reusable ISIM identity, USIM EF_IMSI decoding/encoding, and EF_AD MNC-length
  decoders, ISIM EF identity string TLV encoding and linear-fixed record
  padding helpers, short-APDU UPDATE BINARY/UPDATE RECORD EF write helpers,
  whitespace-tolerant APDU response hex parsing shared by logical-channel
  transmits, QMI UIM logical-channel APDU transport with slot, timeout,
  context-hook, and USIM/ISIM AID resolution options, and USIM/ISIM AKA
  AUTHENTICATE primitives with typed synchronization and MAC-failure errors
- carrier presets and JSON carrier overrides, including AT&T TS.43/E911
  configuration for native `310/280` and `310/410` profiles, plus normalized
  multi-candidate P-CSCF profile overrides for registrar failover
- TS.43-style E911 entitlement bootstrap, JSON/XML response parsing for common
  emergency address, PDN/APN/realm, service URN/route, endpoint, expiry/cache,
  and normalized location validation status variants, entitlement cache snapshots with
  refresh-window and route/service selection helpers, public entitlement parsing helpers,
  emergency service-category URN mapping, IMS emergency SIP Request-URI,
  `P-Access-Network-Info`, `Geolocation`, and MMTel service header helpers,
  inline PIDF-LO `multipart/related` emergency INVITE body construction with
  `cid:` Geolocation references, SDP/PIDF-LO Content-ID assignment and
  `start` parameter handling, strict PIDF-LO presence/tuple/geopriv envelope
  and usage-rule validation,
  token/websheet handling, RAND/AUTN challenge response through the AKA
  provider, and EAP-AKA/AKA' relay packet response generation with
  Any/FullAuth/Permanent Identity selection, KDF negotiation, Notification ACK,
  and terminal Success/Failure handling, plus Client-Error handling for
  entitlement challenges and HTTP `WWW-Authenticate`/`Proxy-Authenticate`
  challenge parsing/classification without leaking nonce material in errors,
  including HTTP Digest AKAv1-MD5/AKAv2-MD5 entitlement retry generation with
  mixed-case challenge normalization, unquoted `qop` token-list recovery,
  proxy digest handling, `Authentication-Info` nextnonce parsing helpers, and
  AUTS synchronization-failure retry handling
- IMS SIP client primitives for REGISTER headers, `WWW-Authenticate` parsing,
  AKA nonce extraction, Digest MD5/MD5-sess/SHA-256/SHA-512-256 plus
  AKAv1-MD5 and AKAv2-MD5 authorization material,
  IMS single- and multi-value `Security-Client` proposal generation,
  `Security-Server` parsing/selection against the offered client algorithms,
  direction-aware IMS IPsec SA plan extraction, Security-Verify
  echoing, Linux XFRM install planning for SHA1/MD5 96-bit HMAC IMS ESP
  transport SAs with null or AES-CBC ESP encryption and selected-parameter
  fallbacks for protocol, mode, SPI, ports, and algorithms, folded/compact SIP header parsing, strict
  Content-Length body and duplicate-length validation, SIP response status-code
  range validation, REGISTER/refresh/de-registration failure diagnostics for
  Retry-After/Warning/Reason headers, deterministic wire ordering for REFER/supplementary-service
  headers, wire-level UDP/TCP REGISTER transport, and IMS registration binding
  parsing
- SIP UDP client transaction retransmission for REGISTER and IMS dialog
  requests, with configurable T1/T2-style backoff, INVITE provisional response
  handling, non-INVITE 1xx handling that waits for final responses while
  stopping UDP retransmits after a provisional response, and response
  correlation filtering for `Call-ID`, `CSeq`, and Via branch headers when
  peers include transaction identifiers, including automatic branch insertion
  on caller-supplied Via headers that omit a branch on reused TCP flows
- reusable SIP flow transport for REGISTER, MESSAGE, USSD, and voice dialog
  requests, preserving the REGISTER socket/local port for IMS NAT pinholes and
  offering explicit CRLF keepalive support, including sticky reuse of the
  selected P-CSCF after failover
- SIP server resolution with injectable policy hooks and default `_sip._udp` /
  `_sip._tcp` SRV lookup, A/AAAA expansion, ordered candidate lists, and
  REGISTER/dialog transport failover before direct host:port fallback,
  including IMS header-style SIP URI extraction for name-addr,
  Route/Service-Route lists, IPv6 literals, and `sips` default ports,
  including REGISTER and dialog request failover on recoverable P-CSCF final
  responses such as 408/503 or other transient 5xx statuses, plus retryable
  transport failures such as timeouts and TCP connection resets
- SWu IKE configuration payload DNS extraction, exposing negotiated internal
  DNS servers to the runtime and using them for default IMS SRV/A/AAAA lookups
- IMS REGISTER session flow with MMTel Contact capability advertisement,
  401/407 authentication retry, 423 `Min-Expires` retry handling, associated
  URI, Service-Route, Path, Security-Server, optional IMS security-plan
  installer hook before authenticated REGISTER retries, and Contact expiry
  capture, plus a runtime `IMSRegistrar` adapter for the wire transport with
  prepared P-CSCF candidate fallback
- IMS REGISTER refresh maintenance on the reusable SIP flow, including
  expiry-based renewal, 423 `Min-Expires` retry handling, retry scheduling,
  binding/auth/CSeq state updates, registration result metadata for
  registered/expiry/refresh timing, full re-registration after recoverable
  refresh/flow failures, and shutdown de-registration with the latest
  registration state
- IMS recovery re-registration on reusable SIP flows can advance to the next
  resolved P-CSCF candidate after recoverable failures, preserving the candidate
  list instead of repeatedly selecting the same failed proxy, with optional
  bounded recovery backoff and public recovery-state snapshots
- IMS registration recovery hooks exposed from the wire registrar to the
  runtime, returning refreshed binding, voice, SMS, and USSD transports after
  re-registration
- automatic IMS SIP CRLF keepalive scheduling on the registered wire flow to
  preserve NAT/PCSCF pinholes between SIP transactions
- IMS de-registration flow for shutdown cleanup, sending `REGISTER` with
  `Expires: 0`, Contact `expires=0`, Security-Verify, and Digest/AKA retry on
  401/407 challenges
- SMS segmentation, IMS SIP `MESSAGE` transport hooks, inbound SMS, delivery
  report matching, CPIM content-type parameter recovery for lenient carrier
  headers, and CPIM and IMS `Content-Transfer-Encoding` decoding for
  base64/quoted-printable SMS payloads, nested multipart MESSAGE leaf
  selection for CPIM/3GPP SMS/IMDN payloads, strict UCS2/8-bit user-data
  length validation, optional outbound CPIM wrapping for 3GPP SMS with IMDN
  disposition request headers, and USSD session transport hooks, including 3xx Contact
  redirect retries with `q` preference and expired-target filtering, TP-SRR delivery-status requests, SMS RP-ERROR/
  STATUS-REPORT cause mapping, RP-ACK user-data STATUS-REPORT handling,
  RP-ERROR diagnostics/user-data preservation, SMS-DELIVER TP-PID/TP-DCS and
  first-octet metadata preservation, alphanumeric SMS-DELIVER originator address decoding,
  TP/RP address semi-octet support for `*`, `#`, `a`, `b`, and `c`,
  structured TP-DCS parsing for message class, auto-delete, compression, MWI,
  and reserved coding fallback, SMS-STATUS-REPORT TP-PI/PID/DCS/user-data optional parameter parsing,
  raw UDH IE preservation, inbound parsing and outbound construction of
  8-bit/16-bit application port addressing UDH, per-message SMS concatenation references with 8-bit and 16-bit UDH support,
  TS 23.038 national language single-shift and locking-shift table support via
  SMS UDH NLI IEs, inbound parsing of Special SMS Message Indication, SMSC
  Control Parameters, UDH Source Indicator, and RFC 822 email-header length IEs,
  ACK handling for control-only SMS-DELIVER payloads that carry UDH metadata
  without user-visible text,
  multipart IMS MESSAGE unwrapping for CPIM, 3GPP SMS, IMDN, and text/plain
  payload parts,
  SMS-SUBMIT relative and absolute validity-period
  encoding, SMS-SUBMIT TP-PID/TP-DCS overrides with alphabet validation,
  SMS-SUBMIT Reply-Path and Reject-Duplicates first-octet flags, USSD dialog
  target refresh, and recoverable IMS registration/route failure signals for
  MESSAGE, USSD INVITE/INFO, and USSD BYE failures
- outbound voice dialog bridging helpers, SDP parsing/building, optional SDP
  security parsing/building for RTP/SAVP/SAVPF, SDES crypto, DTLS fingerprint/
  setup attributes, IMS INVITE/ACK/BYE/CANCEL request construction with MMTel
  service identification headers,
  IMS audio SDP media parsing/validation for static PCMU/PCMA, AMR, AMR-WB,
  telephone-event, RTCP, and RTCP mux attributes,
  route-set application, UDP/TCP SIP request transport, outbound IMS voice
  agent, ACK/BYE/CANCEL dialog handling with release Reason/body forwarding,
  IMS BYE/CANCEL response status/body/header capture, dialog failure diagnostic
  extraction for Retry-After/Warning/Reason headers, and local softphone
  response propagation,
  RTP/RTCP media relay endpoint allocation, SDP media/RTCP rewriting,
  SDP `rtcp-fb`, `rtcp-mux`, `rtcp-rsize`, multi-crypto, fingerprint, and
  unknown audio attribute preservation helpers,
  audio-scoped SDP direction parsing/rewrite and answer-direction negotiation,
  packet forwarding, and dialog termination hooks
- SWu tunnel manager/session contracts with startup validation, tunnel readiness
  state integration, shutdown cleanup, and MOBIKE delegation
- IKEv2 binary header/payload framing, Notify/KE/Nonce/EAP helpers, NAT
  detection hashes, MOBIKE notify helpers, and PRF+/SKEYSEED key derivation
  primitives for the SWu dataplane
- IKEv2 SA proposal/transform encoding, default IKE/ESP proposals,
  configuration payload requests, identity payloads, traffic selectors, and
  EAP-AKA/AKA' packet and attribute codecs, including notification,
  client-error, counter-too-small, checkcode, result-indication, and
  reauthentication-state helpers, selected-SA validation
  plus key material/profile derivation for combined-mode AES-GCM proposals
  without separate INTEG transforms
- IKE_SA_INIT initiator flow with UDP/NAT-T transport support, X25519 key
  exchange, NAT-D/MOBIKE notifications, responder parsing, SKEYSEED, and IKE SA
  key material derivation
- IKEv2 key material split into SK_d/SK_ai/SK_ar/SK_ei/SK_er/SK_pi/SK_pr plus
  AES-CBC/HMAC and AES-GCM AEAD protected SK payload construction and
  verification
- IKEv2 encrypted INFORMATIONAL exchange runner for empty DPD liveness probes
  and DELETE payloads for IKE/ESP/AH SA teardown, plus SWu close-handler wiring
  for graceful CHILD_SA/IKE_SA deletion
- MOBIKE UPDATE_SA_ADDRESSES control-plane helpers with optional NAT-D and
  address-set notifications, response rejection handling, and packet-session
  state refresh on successful updates
- IKEv2 CREATE_CHILD_SA initiator flow for additional or rekeyed ESP Child SAs,
  including SA/Nonce/TS request construction, REKEY_SA notify support,
  encrypted response validation, and per-exchange Ni/Nr key derivation
- CHILD_SA rekey scheduling metadata for userspace packet sessions, including
  configured lifetime/lead time, established/due/expiry timestamps, time-to-
  rekey/time-to-expire windows, due/expired decisions, and snapshots exposed to
  tunnel managers and packet pumps
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
  AT_KDF negotiation, EAP-AKA Identity `AT_VERSION_LIST` /
  `AT_SELECTED_VERSION` handling, IKE_AUTH request-attribute based permanent,
  pseudonym, and reauthentication identity selection, `AT_BIDDING` downgrade protection,
  AT_MAC verification/generation, AT_RAND/AT_AUTN challenge extraction with
  AUTN field parsing, multi-vector challenge decoding, encrypted identity-state
  extraction, duplicate reauthentication control-attribute rejection,
  SIM AKA RES response, AUTS synchronization-failure response, AUTN MAC-failure
  Authentication-Reject response, EAP-AKA Notification ACK, and Client-Error
  handling over encrypted IKE_AUTH
- final IKE_AUTH CHILD_SA result parsing with responder ESP SPI,
  configuration/traffic selector extraction, and RFC 7296 ESP outbound/inbound
  key material derivation from SK_d and IKE_SA_INIT nonces
- userspace ESP packet seal/open primitives with SPI/sequence handling, AES-CBC
  payload encryption, HMAC-SHA integrity checks, combined-mode AES-GCM-16,
  RFC 4303 padding, next-header restoration, and replay-window validation
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
  IKEv2 CHILD_SA key material, including AES-CBC/HMAC and AES-GCM AEAD state
  arguments, with rollback and cleanup support
- SRTP/SRTCP media helpers and RTP relay transforms for protecting and
  unprotecting RTP/RTCP packets with AES-CM/HMAC-SHA1 and AEAD-AES-GCM
  profiles, independent direction-specific client/IMS key material for
  asymmetric SDES offer/answer keying, replay protection, and authentication
  failure handling, runtime relay transform replacement for post-SDP
  negotiation SRTP activation, outbound IMS SDES offer/answer crypto rewriting
  with live relay transform installation, plus SDP `a=crypto` tag, suite,
  inline key, lifetime, and MKI validation on parse/build boundaries
- RTCP feedback inspection for RTP/SRTP relay paths, including Sender/Receiver
  Reports, PLI/FIR/rapid resynchronization requests, NACK, REMB, transport-wide
  congestion control, SLI, XR, SDES, BYE, application-defined packets,
  clear-relay counters, generated RTCP packet send paths toward IMS or client
  media legs, and SRTP plaintext-stage event callbacks plus generated SRTCP
  protection during media transforms
- RTP stream quality helpers for per-SSRC packet/loss/duplicate/out-of-order,
  extended-sequence, RTP sequence-number rollover, timestamp rollover, and
  interarrival-jitter tracking, plus RTCP Receiver
  Report block generation from observed RTP streams, Sender Report and SDES
  packet construction, relay-side clear-RTP reception snapshots, SRTP plaintext
  observer integration for encrypted relay streams, and generated Receiver/
  Sender Report send paths toward IMS or client media legs, with optional
  relay lifecycle scheduling for periodic RTCP Receiver/Sender Reports
- RTP telephone-event DTMF helpers for RFC 4733-style packet construction,
  RFC 4733-style packet-train generation with marker/sequence/timestamp/end
  repetition semantics, SDP dynamic payload discovery, relay-side event
  inspection, direction-aware callbacks, dynamic payload type/duration
  remapping across relay legs, clear-relay DTMF event/end/remap/error counters,
  relay-level generated DTMF packet scheduling toward IMS or client media legs
  with per-direction sequence/timestamp/SSRC state, call-dialog RTP DTMF send
  entry points, and SRTP plaintext-stage DTMF inspection/remapping plus
  generated-packet protection during media transforms, plus a runtime automatic
  DTMF route helper, wired into the local voice gateway for softphone INFO
  DTMF requests, that prefers RTP telephone-event delivery and falls back to
  SIP INFO only when relay media configuration is unavailable
- inbound IMS voice agent helpers that bridge IMS-originated INVITEs to a local
  SIP client, parse SDP answers, forward ACK/BYE/CANCEL dialog requests, and
  support RTP relay allocation with IMS-offer/client-answer SDP rewriting,
  including BYE CSeq/Reason/body preservation, local BYE/CANCEL response
  status/body/header mapping, early-dialog CANCEL Reason/body preservation with
  original INVITE Via reuse and 487 Request Terminated mapping for the canceled
  INVITE transaction, plus local 18x provisional response forwarding with early
  SDP/RTP relay rewriting and early-dialog To-tag, Contact, and Record-Route
  state capture for PRACK, while preserving bodyless final 2xx responses after
  a reliable provisional SDP answer
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
  rejection for non-ACK requests, local softphone BYE/CANCEL response mapping
  back to IMS, `481 Call/Transaction Does Not Exist` handling for CANCELs
  without a matching pending INVITE transaction, and loopback-tested socket
  handling
- IMS in-dialog interworking for UPDATE, PRACK, and OPTIONS, including SDP
  session refresh forwarding, RAck propagation, RTP relay endpoint rewriting
  for PRACK/UPDATE offers and answers, softphone-originated and outbound
  OPTIONS capability probes, and local OPTIONS capability responses
- IMS in-dialog SIP INFO forwarding for outbound and inbound voice dialogs,
  including DTMF relay body construction/parsing helpers, Info-Package
  propagation, response body/header mapping, and dialog CSeq advancement
- IMS in-dialog SIP MESSAGE forwarding for outbound and inbound voice dialogs,
  including text/plain or IMS SMS-style bodies, response body/header mapping,
  remote Contact refresh, dialog CSeq advancement, dialog-specific MESSAGE
  request construction without SMS-only service feature tags, and preservation
  of the existing out-of-dialog SMS `MESSAGE` handler path
- IMS in-dialog SIP REFER forwarding for outbound voice dialogs, including
  structured `Refer-To`/`Referred-By` handling, explicit `Refer-Sub`
  subscription negotiation, Contact target-refresh advertisement, response
  header/body mapping, and dialog CSeq advancement
- IMS-originated in-dialog SIP REFER forwarding to the local softphone, including
  `norefersub` option-tag support, `Refer-Sub` propagation, response mapping,
  remote Contact refresh, accepted-response Contact advertisement, and dialog
  CSeq tracking
- local softphone in-dialog SIP NOTIFY forwarding to IMS dialogs for REFER
  subscription result reporting, including structured `Event` and
  `Subscription-State` handling, `message/sipfrag` bodies, response header/body
  mapping, remote Contact refresh, and dialog CSeq advancement
- IMS-originated in-dialog SIP NOTIFY forwarding to the local softphone,
  including `Event` and `Subscription-State` preservation, `message/sipfrag`
  body forwarding, `Allow-Events: refer` capability exposure, response mapping,
  remote Contact refresh, and dialog CSeq tracking
- local softphone in-dialog SIP SUBSCRIBE forwarding to IMS dialogs for
  supplementary service event packages, including structured `Event` and
  `Expires` handling with explicit default generation, 423 `Min-Expires` retry,
  `Allow-Events: refer` capability exposure, response header/body mapping,
  remote Contact refresh, and dialog CSeq advancement
- IMS-originated in-dialog SIP SUBSCRIBE forwarding to the local softphone,
  including structured `Event` and `Expires` preservation with explicit default
  generation, body forwarding, 423 `Min-Expires` retry, response mapping with
  fallback `Expires` generation for accepted responses, remote Contact refresh,
  and dialog CSeq tracking
- runtime voice operations consume recoverable registration or route failures
  such as 481, 503, transport errors, and other transient IMS 5xx responses to
  trigger IMS re-registration, refresh voice/SMS/USSD transports, and retry an
  initial INVITE once after successful recovery, including BYE/CANCEL result
  paths that terminate local softphone dialogs
- recoverable IMS failures propagate SIP `Retry-After` delay hints from
  REGISTER refresh, voice dialogs, SMS MESSAGE, and USSD transactions so runtime
  recovery waits instead of immediately hammering a temporarily unavailable
  P-CSCF or registrar
- runtime SMS and USSD operations consume the same recoverable IMS failure
  signal, refresh IMS registration and message transports, and retry only the
  initial SMS part or USSD INVITE when the original attempt failed before a SIP
  final response was received or when IMS returned a recoverable final response
  such as 408/503
- local softphone in-dialog SIP UPDATE forwarding to IMS dialogs, including
  session refresh/media renegotiation SDP validation, RTP relay endpoint
  rewriting, response body/header mapping, remote Contact refresh, and dialog
  CSeq advancement, plus outbound IMS hold/resume helpers that rewrite SDP
  media direction over UPDATE
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
- redacted trace fixture validation with reusable replay streams for ordered
  inbound/outbound SIP wire transcripts, preserving CRLF framing while checking
  sensitive data before materialization, plus lightweight SIP semantic parsing
  for request/status lines, compact headers, `CSeq`, and `Content-Length`
  assertions, including SIP URI user identity validation in fixture redaction
  checks

## Known Gaps

- Complete parity with the official closed-source implementation is not
  available.
- Full SIP transaction timer state machines are still being expanded.
- Advanced IMS feature interworking and carrier-specific behavior are still
  implemented incrementally.
- Real hardware, modem, operator, and production-network compatibility require
  separate validation outside the loopback-heavy test suite.
