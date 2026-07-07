# VoHive Readiness Gap Analysis

This document tracks what still has to be completed before `vowifi-go` should
be treated as usable inside VoHive beyond compile-time compatibility tests.

## Current Position

`vowifi-go` is already shaped around the runtime boundary that VoHive consumes.
The repository currently has local CI, GitHub Actions CI, module-path hygiene
checks, and a compatibility script that can rewrite an older VoHive consumer in
a temporary checkout and run a focused test set against this module.

That proves an important baseline: VoHive can resolve and compile against this
module in the covered package set, and the loopback/unit tests exercise many
SIM, SWu, IMS, messaging, E911, and voice helpers. It does not yet prove that a
real VoHive deployment can replace the closed-source runtime end to end.

## Readiness Levels

| Level | Meaning | Current Status |
| --- | --- | --- |
| Compile-compatible | VoHive resolves the module, selected packages build, and focused tests pass. | Mostly in place for the checked packages. |
| Loopback-functional | Runtime flows pass deterministic tests with fake transports, fixture traces, and local sockets. | Partially in place across SIM, SWu, IMS, SMS/USSD, E911, and voice. |
| Device-functional | A real modem/SIM/ePDG/IMS path can register, keep alive, send SMS/USSD, place calls, and recover from common failures. | Not proven yet. |
| Production-ready | Carrier variation, emergency behavior, long-running stability, observability, rollback, and operational hardening are validated. | Not complete. |

## P0: Required Before a VoHive Runtime Trial

These items are the minimum remaining work before this repository should be
used by VoHive as the primary runtime implementation in a controlled trial.

### 1. Full VoHive Consumer Coverage

Current compatibility testing now covers the known VoHive runtime consumer
matrix (`cmd/vohive`, API, CS call, device, E911, notify, SIM, and VoWiFi host
packages) and builds the main VoHive binary in the temporary compatibility
checkout. The remaining gap is to keep that package matrix current as VoHive
adds new `vowifi-go` consumers, and to expand beyond compile/build evidence
into real runtime trials.

Done means:

- The compatibility workflow runs the complete currently known VoHive package
  list.
- At least one job verifies a `go build ./cmd/vohive` pass for the temporary
  VoHive checkout using this module.
- The compatibility script has a documented package matrix and defaults to the
  current VoHive runtime consumers instead of a small focused subset.

### 2. Real Modem And SIM Access Path

The current SIM/ISIM and AKA layers include AT, APDU, QMI UIM, recovery
classification, and non-destructive recovery planning. The unproven gap is the
full device path under real modem contention, busy control ports, locked SIMs,
multi-slot devices, and vendor-specific recovery decisions.

Done means:

- IMEI, IMSI, ISIM identity, EF_AD, and AKA reads are validated on at least one
  target modem family used by VoHive.
- QMI UIM and AT logical-channel paths both have documented success/failure
  transcripts.
- Control-port recovery is wired into the runtime host with safe defaults and
  opt-in vendor commands.
- SIM busy, malformed reply, missing applet, no-card, PIN-required, and
  transport-hung cases produce actionable runtime errors.

### 3. SWu/ePDG End-To-End Tunnel

The SWu implementation has IKEv2, EAP-AKA/AKA', ESP, MOBIKE, CHILD_SA,
userspace packet sessions, TUN, routing, and NAT-T primitives. The gap is
proving a complete tunnel against a real ePDG and ensuring it survives real
network behavior.

Done means:

- IKE_SA_INIT, IKE_AUTH with EAP-AKA/AKA', CHILD_SA setup, DNS configuration,
  and packet forwarding are validated against a real ePDG.
- NAT-T, DPD, DELETE cleanup, MOBIKE address updates, and CHILD_SA rekey are
  exercised in integration tests or captured trace replays.
- TUN setup, route exclusion, policy rules, MTU handling, IPv4/IPv6 forwarding,
  and rollback are verified on the target Linux environment.
- Failure modes for authentication rejection, ePDG timeout, DNS failure,
  routing failure, and packet replay are surfaced to VoHive.

### 4. IMS Registration And Security-Agree Activation

REGISTER, Digest AKA, refresh, de-registration, P-CSCF failover, Security-Agree
selection, XFRM planning, and recovery plans are implemented in pieces. The gap
is proving that VoHive can complete a real IMS registration and keep it alive
through refresh and recovery.

Done means:

- Initial REGISTER succeeds with real AKA challenge material.
- 401/407, stale nonce, AUTS synchronization failure, 423 Min-Expires, 494
  Security Agreement Required, and 5xx/Retry-After recovery paths are exercised.
- Security-Client, Security-Server, Security-Verify, XFRM install, and selected
  SA usage are validated on the host where VoHive runs.
- P-CSCF failover and sticky selected-proxy behavior work across refresh and
  dialog requests.
- Registration refresh, CRLF keepalive, shutdown de-registration, and recovery
  re-registration are observable from VoHive.

### 5. VoHive Runtime Orchestration

The library exposes runtime hooks, but VoHive still needs a complete
orchestration contract around state transitions, retries, feature flags, and
operator-visible diagnostics.

Done means:

- VoHive can start, stop, recover, and report the runtime through stable APIs.
- Registration recovery refreshes the voice, SMS, USSD, and E911 transports
  without requiring a process restart.
- Long-running maintenance tasks have cancellation, timeout, and cleanup
  behavior that VoHive can control.
- Logs and structured state expose enough detail for user support without
  leaking identities, nonces, keys, or local machine details.

## P1: Required Before Broad VoHive Use

These items can follow the first controlled runtime trial, but they are needed
before recommending wider VoHive use.

### 6. SMS, USSD, And Messaging Recovery

SMS and USSD have substantial encoding, parsing, SIP MESSAGE, CPIM, redirect,
retry, and delivery-report support. The remaining gap is end-to-end carrier
validation and durable replay integration in the runtime.

Done means:

- Outbound SMS, multipart SMS, delivery reports, inbound SMS, USSD INVITE/INFO,
  USSD BYE, redirects, and authentication challenges are tested through VoHive.
- Durable retry envelopes are consumed by a runtime queue instead of remaining
  only as planning data.
- Duplicate-risk cases are clearly separated from safe replay cases.
- Carrier-specific content-type, CPIM, RP, TP-DCS, and UDH variations have
  trace fixtures.

### 7. Voice Call Parity

Voice has dialog construction, inbound/outbound agents, SDP rewriting, RTP/RTCP
relay, DTMF, PRACK, UPDATE, REFER, NOTIFY, SUBSCRIBE, re-INVITE, and session
timer helpers. The remaining gap is proving full call behavior through VoHive
with real IMS peers and local softphone interworking.

Done means:

- Outbound and inbound calls can complete setup, early media, answer, hold,
  resume, DTMF, transfer, and teardown.
- Reliable provisional responses and PRACK are wired through the full call
  path, not only helper APIs.
- UPDATE, re-INVITE, Session-Expires refresh, CANCEL, BYE, REFER/NOTIFY, and
  OPTIONS behavior are validated against fixture traces and at least one real
  IMS environment.
- RTP/RTCP relay quality events feed runtime recovery or user-visible
  diagnostics.
- SRTP/SRTCP negotiation and relay behavior are validated for the codecs and
  security profiles VoHive expects.

### 8. E911 And Emergency Calling

E911 entitlement, PIDF-LO construction, emergency headers, service URNs, 380
alternative service, and 424 location-refresh planning exist. The gap is
operator-safe emergency behavior, which needs stronger validation than normal
voice.

Done means:

- TS.43 entitlement bootstrap, token/websheet flow, address validation, cache
  refresh, and emergency profile selection are tested through VoHive.
- PIDF-LO, Geolocation, multipart body, emergency Request-URI, and
  service-category mapping are validated against trace fixtures.
- 380 Alternative Service and 424 Bad Location Information retries rebuild the
  emergency plan and PIDF-LO at runtime.
- Emergency call behavior is clearly marked experimental until validated with
  authorized test environments.

### 9. Carrier Profiles And Compatibility Matrix

Carrier presets and overrides exist, but production usefulness depends on
operator-specific quirks.

Done means:

- Each supported carrier has a documented profile: IMS domain, P-CSCF
  discovery, ePDG identity, access-network headers, emergency settings,
  supported codecs, SMS/USSD behavior, and known recovery behavior.
- Carrier overrides are loaded and reported without leaking sensitive data.
- Trace fixtures cover at least one successful and one recoverable failure path
  per supported carrier profile.

## P2: Hardening Before Production Claims

These items are needed before any production-readiness claim.

### 10. Security And Privacy Hardening

Done means:

- Nonces, keys, IMS identities, SIM material, APDU payloads, and local paths are
  redacted from logs and fixtures by default.
- XFRM, TUN, route, and command execution boundaries are privilege-minimized and
  rollback-safe.
- Long-running goroutines, sockets, file descriptors, TUN devices, routes, and
  XFRM state are cleaned up under normal shutdown and failure paths.
- CI includes leak-oriented fixture checks and negative tests for sensitive
  output.

### 11. Observability And Supportability

Done means:

- Runtime state exposes registration, tunnel, modem, messaging, E911, and voice
  health snapshots.
- Recovery decisions include reason codes, retry timing, and next actions.
- VoHive can present concise user-facing failures for modem control, SIM auth,
  ePDG, IMS registration, messaging, E911, and voice media.

### 12. Release Discipline

Done means:

- Semantic tags are cut only after compatibility gates pass.
- The supported VoHive version range is documented for each release.
- Breaking API changes are rejected unless VoHive migration work is completed
  first.
- Compatibility tests run on pull requests and release candidates.

## Acceptance Checklist For "Usable In VoHive"

The project should not be described as usable in VoHive until all of the
following evidence exists:

- A full VoHive compatibility job passes for the target VoHive branch or tag.
- A controlled runtime test completes modem/SIM identity, AKA, SWu/ePDG,
  IMS REGISTER, refresh, and shutdown cleanup.
- SMS and USSD work through VoHive with recovery behavior documented.
- At least one outbound and one inbound voice call complete through VoHive,
  including RTP/RTCP media and teardown.
- Emergency behavior is either validated in an authorized test environment or
  explicitly disabled/guarded in VoHive.
- Logs and traces pass redaction checks.
- Recovery behavior for modem hangs, SIM busy, ePDG failure, P-CSCF failure,
  IMS 401/407/423/494/5xx, and media failure is documented with expected
  runtime actions.

## Recommended Next Implementation Order

1. Keep the VoHive compatibility package matrix synchronized with VoHive
   consumers on every release candidate.
2. Wire registration recovery plans into VoHive-facing runtime state and logs.
3. Run and document a real modem/SIM identity and AKA validation pass.
4. Prove SWu/ePDG tunnel setup and cleanup in a controlled environment.
5. Prove IMS registration with Security-Agree and refresh maintenance.
6. Wire durable SMS/USSD retry envelopes into a runtime queue.
7. Connect PRACK/early-media planning into the outbound voice agent path.
8. Add carrier trace fixtures for registration, SMS/USSD, voice, and E911.

## Current Summary

`vowifi-go` is a strong compatibility and protocol reconstruction base, and it
is already useful for VoHive integration development. It is not yet proven as a
complete replacement runtime in VoHive. The shortest path to VoHive usability is
to broaden compatibility coverage, validate real modem/SIM and SWu/ePDG paths,
then drive IMS registration, messaging, voice, and E911 through VoHive with
captured evidence and redacted fixtures.
