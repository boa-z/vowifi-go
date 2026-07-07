# Architecture

vowifi-go is organized around the runtime boundary consumed by VoHive. The
library keeps modem, SIM, SWu, IMS, messaging, and voice concerns behind
package-level interfaces so VoHive can integrate the pieces without depending
on a single monolithic service.

## Scope

The project is an independent implementation, not a vendor or operator SDK.
It is still under active development and does not yet provide full parity with
the official closed-source VoWiFi implementation.

## Component Map

| Area | Packages | Responsibility |
| --- | --- | --- |
| SIM and AKA | `engine/sim`, `runtimehost/simauth` | SIM/ISIM APDU helpers, AT and QMI UIM transport adapters, identity reading, AKA challenge material, and typed SIM auth failures. |
| SWu and ePDG | `engine/swu` | IKEv2, EAP-AKA/AKA', MOBIKE, ESP, CHILD_SA rekey scheduling, TUN, routing, and XFRM boundaries for the SWu dataplane. |
| Runtime host | `runtimehost` | Lifecycle state, modem access boundaries, service wrappers, IMS registration wiring, refresh/recovery metadata, and dataplane startup. |
| Carrier and E911 | `runtimehost/carrier`, `runtimehost/e911` | Carrier policy presets, overrides, entitlement bootstrap, E911 request contracts, PIDF-LO validation, and emergency multipart body helpers. |
| Messaging | `runtimehost/messaging`, `runtimehost/eventhost` | SMS, USSD, inbound event dispatch, SIP MESSAGE hooks, and delivery report handling. |
| Voice | `runtimehost/voiceclient`, `runtimehost/voicehost` | IMS SIP transport, dialog helpers, SDP rewriting, RTP/RTCP relay and quality stats, SRTP/SRTCP helpers, and local SIP interworking. |

## High-Level Flow

1. VoHive configures the runtime host and supplies modem/SIM-facing boundaries.
2. SIM identity and AKA operations are resolved through the SIM/auth packages.
3. Carrier policy and optional E911/TS.43-style entitlement data are loaded.
4. SWu/ePDG tunnel setup negotiates IKEv2, EAP-AKA/AKA', CHILD_SA material, and
   userspace or Linux dataplane plumbing.
5. Negotiated tunnel details feed IMS registration and SIP transport setup.
6. Messaging, USSD, voice dialogs, and media relay helpers reuse the registered
   IMS flow where possible.

## Boundary Principles

- Prefer public runtime interfaces that VoHive can call directly.
- Keep hardware, modem, network, TUN, routing, and command execution boundaries
  injectable for tests and alternate hosts.
- Keep CI loopback-friendly: the current automated tests do not require a real
  modem, root privileges, or a real TUN device.
- Treat operator-specific and closed-source behavior as compatibility work to be
  implemented explicitly, not assumed.

## Incomplete Areas

The architecture is intentionally open-ended because full official
closed-source feature parity is not implemented yet. Advanced IMS
interworking, full SIP transaction timer state machines, carrier-specific
flows, hardware validation, and production hardening remain ongoing work.
