# iOS 18.6.2 – Suspicious ODoH Beaconing

This repository contains a threat intelligence report detailing the observation of covert DNS beaconing behavior on a non-jailbroken iOS 18.6.2 device. The activity used Oblivious DoH (ODoH), triggered system processes, and correlated with Bluetooth permission events — suggesting covert telemetry or command-and-control (C2) mechanisms.

## Overview

- **Date Observed:** August 20, 2025  
- **Device:** iPhone 14 (iOS 18.6.2, non-jailbroken)  
- **Technique:** ODoH-based DNS beaconing every 60 seconds  
- **Process Involved:** `revisiond`, scheduled via `xpc_activity_register`  
- **Trigger:** Bluetooth TCC permission log (`CBMsgIdTCCDone`)  
- **Resolver Used:** Non-Apple ODoH resolver dynamically registered on-device

## Summary

The traffic originated from Apple-signed system processes and occurred at a fixed interval, with no user interaction or third-party apps involved. Each DNS query was masked and routed via HTTPS to a non-standard resolver, indicating an attempt to hide both content and endpoint. This behavior aligns with advanced mobile spyware or surveillance frameworks.

## Key Findings

- System-level execution using Apple-trusted processes
- Masked DNS queries leveraging Oblivious DoH
- Periodic behavior (60s intervals) tied to Bluetooth sensor activity
- No known Apple telemetry or legitimate activity matches this pattern

## MITRE ATT&CK Techniques

- T1071.001: Application Layer Protocol (Web Protocols)
- T1205: Traffic Signaling
- T1053: Scheduled Task/Job
- T1001.003: Protocol Impersonation
- T1043: Commonly Used Port

## Indicators of Interest (IOIs)

- ODoH Resolver: `BBsIQFhu`
- Resolver Path: `BBRMSdku`
- Query Hash: `'UksLOXKMlXYHQDk4TlujBg=='`
- Trigger Process: `revisiond`
- Scheduler: `passd` via `xpc_activity_register`
- Bluetooth Log Event: `CBMsgIdTCCDone`

## Recommendations

- Monitor system logs for unexpected ODoH resolver registration
- Correlate Bluetooth events with network activity
- Flag periodic DNS queries from system daemons
- Apply mobile telemetry retroactive analysis in high-risk environments
