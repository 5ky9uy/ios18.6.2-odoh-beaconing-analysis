# Suspicious ODoH Beaconing Observed on iOS 18.6.2  

Date: 2025-08-20  

---

## TL;DR

A covert DNS beaconing pattern was observed on an iPhone 14 running iOS 18.6.2. The activity originated from the Apple-signed system process `revisiond`, leveraged Apple’s `xpc_activity_register` scheduling API, and used a non-Apple Oblivious DoH (ODoH) resolver. Beaconing occurred every 60 seconds and was consistently triggered alongside Bluetooth permission events. This strongly suggests covert telemetry or command-and-control (C2) signaling, likely from a commercial surveillance implant or SDK.

---

## Executive Summary

On August 20, 2025, an iPhone 14 (non-jailbroken) running iOS 18.6.2 exhibited anomalous network behavior involving encrypted DNS traffic via Oblivious DoH (ODoH). The traffic was initiated by the Apple-signed system process `revisiond`, scheduled using `xpc_activity_register`, and triggered on a 60-second interval.

Each beaconing event correlated with a Bluetooth TCC permission log entry (`CBMsgIdTCCDone`), suggesting a proximity or sensor-based trigger mechanism. The device had no sideloaded or enterprise apps and was in production use, increasing confidence that the activity was system-level and not user-initiated.

The DNS queries were routed through a non-Apple resolver dynamically registered on the device, which is inconsistent with standard Apple telemetry.

This activity is indicative of one of the following:

* A covert telemetry or analytics SDK
* An advanced commercial spyware implant
* A custom system-level beaconing framework leveraging ODoH for C2 evasion

---

## Technical Details

**Device:** iPhone 14 (non-jailbroken)
**OS Version:** iOS 18.6.2
**Transport Protocol:** Oblivious DoH (ODoH)
**Beacon Interval:** Every 60 seconds

**Trigger Process:** `revisiond` (spawned by `xpcproxy`)
**Scheduler:** `passd` via `xpc_activity_register`
**ODoH Resolver Name:** `BBsIQFhu`
**ODoH Resolver Path:** `BBRMSdku`
**DNS Query Hash:** `'UksLOXKMlXYHQDk4TlujBg=='`
**Bluetooth Trigger Log:** `CBMsgIdTCCDone` from `com.apple.passd-central-83-77`

---

## Event Timeline (Local System Time)

1. **18:08:01.127432** — `passd` registers background activity via `xpc_activity_register`
2. **18:08:01.126148** — `xpcproxy` spawns `revisiond` (PID 431)
3. **18:08:01.428864** — ODoH Resolver `BBsIQFhu` registered (path: `BBRMSdku`)
4. **18:08:01.429000** — DNS query issued for masked hash `'UksLOXKMlXYHQDk4TlujBg=='`
5. **18:08:01.430000** — 128-byte query sent via HTTPS
6. **18:08:01.496000** — Acceptable DNS response received
7. **18:08:01.651501** — Bluetooth event `CBMsgIdTCCDone` logged
8. **18:09:03.170000** — Pattern repeats with identical behavior

---

## MITRE ATT\&CK Mapping

| Technique ID | Technique Name                           | Observed Usage                                   |
| ------------ | ---------------------------------------- | ------------------------------------------------ |
| T1071.001    | Application Layer Protocol: Web Protocol | HTTPS-based ODoH for encrypted DNS beaconing     |
| T1205        | Traffic Signaling                        | DNS used for covert signaling                    |
| T1053        | Scheduled Task/Job                       | `xpc_activity_register` for persistent execution |
| T1001.003    | Protocol Impersonation                   | ODoH masks both query content and destination    |
| T1043        | Commonly Used Port                       | Communication via TCP/443                        |

---

## Indicators of Interest (IOIs)

| Type                 | Value                             |
| -------------------- | --------------------------------- |
| ODoH Resolver Name   | BBsIQFhu                          |
| ODoH Resolver Path   | BBRMSdku                          |
| DNS Query Hash       | 'UksLOXKMlXYHQDk4TlujBg=='        |
| System Process       | revisiond                         |
| Scheduler            | passd via `xpc_activity_register` |
| Bluetooth Permission | CBMsgIdTCCDone                    |
| Beacon Interval      | 60 seconds                        |

---

## Analysis & Threat Classification

The behavior:

* Occurred on a non-jailbroken device
* Used Apple-signed system processes
* Did not rely on any user-facing or third-party apps

This rules out most common forms of misconfiguration, app behavior, or debugging/test builds.

Such tradecraft aligns with commercial surveillance tools (e.g., NSO Pegasus, Bright SDK, Circles) or purpose-built implants leveraging trusted Apple services and encrypted protocols to remain undetected.

No exploit chain or binary payload was identified, though the use of Bluetooth triggers, XPC scheduling, and DNS obfuscation indicates high stealth and persistence intent.

---

## Recommendations

### For Incident Response / Forensics

* Monitor system logs for:

  * ODoH resolver registrations in `mDNSResponder`
  * `xpc_activity_register` calls from non-user apps
  * `revisiond` launches via `xpcproxy` or `launchd`
  * Bluetooth `CBMsgIdTCCDone` logs

* Review apps with:

  * Bluetooth/Location permissions
  * Background task capabilities
  * No DNS usage justification

* Cross-reference with MDM/EDR telemetry and device behavior history

### For Mobile Security / Detection Teams

* Add detection logic for:

  * ODoH resolver registration from untrusted sources
  * Periodic HTTPS DNS queries from non-browser processes
  * Bluetooth + DNS activity co-occurrence

* Perform binary analysis of high-permission apps on affected devices

* Enforce policy-based controls over resolver registration behavior

---

## Conclusion

This activity highlights a stealthy DNS beaconing pattern on iOS 18.6.2 devices, leveraging trusted Apple processes and encrypted DNS to evade detection.

Given the timing, system-level trust, and use of advanced triggers, this behavior should be classified as a **high-confidence indicator of covert telemetry or command-and-control**.

Organizations in sensitive environments (e.g., defense, government, R\&D) should consider this pattern highly relevant for threat hunting and retrospective analysis of mobile telemetry and DNS logs.

---

## Disclosure

No known affiliation exists between this report and Apple Inc. This research is provided for public defensive analysis and threat detection purposes.

---
