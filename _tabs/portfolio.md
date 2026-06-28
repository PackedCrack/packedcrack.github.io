---
layout: portfolio
title: Portfolio
icon: fas fa-laptop-code
order: 1
permalink: /portfolio/
---

## Reverse Engineering & Malware Analysis

### [Unpacking Morphine]({{ "/posts/unpacking-morphine/" | relative_url }})

Manual unpacking of a Morphine-packed Windows executable, including OEP discovery,
dumping, import reconstruction, PE repair, and analysis of Morphine's loader behavior.

**Type:** Blog post  
**Signals:** `PE analysis` `unpacking` `OEP recovery` `import restoration` `debugging`  
**Relevant to:** Reverse engineering, malware analysis, detection research

---

### [Malware Analysis: Multi-Stage Windows Spyware]({{ "/posts/google-sideloading/" | relative_url }})

Malware-analysis report covering a multi-stage Windows spyware sample abusing a
legitimate Google updater component for execution. Covers installation behavior,
persistence, payload behavior, registry artifacts, network behavior, and IOCs.

**Type:** Blog post + PDF report  
**Signals:** `malware analysis` `DLL side-loading` `persistence` `IOCs` `host artifacts`  
**Relevant to:** Malware analysis, reverse engineering, incident response, threat research

**Links:** [Writeup]({{ "/posts/google-sideloading/" | relative_url }}) · [PDF report]({{ "/assets/pdf/google_sideloading_report.pdf" | relative_url }})

---

### [Evading Static Detection with Compilation]({{ "/posts/copmilation-evasion-light/" | relative_url }})

Research writeup investigating whether compiler flags alone can generate functionally
equivalent malware binaries with enough machine-code variation to affect static detection.

**Type:** Research post  
**Signals:** `static detection` `compiler flags` `malware variation` `opcode analysis`  
**Relevant to:** Malware research, detection research, reverse engineering

---

### Compiler-Induced Feature Drift in Static Malware Analysis

Thesis project investigating how compiler settings affect static malware-analysis
features while preserving program functionality. Focuses on opcode 3-gram drift,
IDA-based feature extraction, and robustness implications for static detection pipelines.

**Type:** Thesis / research repository  
**Signals:** `static malware analysis` `opcode n-grams` `IDA Python` `feature drift` `MSVC`  
**Relevant to:** Malware research, detection engineering, security research

**Links:** [Repository](https://github.com/PackedCrack/master_thesis)


## Applied Cybersecurity Work

### Malware Injection Techniques

Four-part Windows internals and offensive-security series implementing common process
manipulation techniques in C/C++.

**Type:** Blog series + repository  
**Signals:** `Win32 API` `process memory` `code injection` `runtime patching` `C/C++`  
**Relevant to:** Offensive security, Windows internals, reverse-engineering-adjacent cybersecurity work

**Posts:**  
[Process Hollowing]({{ "/posts/malware-inject-proc-hollow/" | relative_url }}) ·
[DLL Injection]({{ "/posts/malware-inject-dll-inject/" | relative_url }}) ·
[Direct Injection]({{ "/posts/malware-inject-dir-inject/" | relative_url }}) ·
[Inline Hooking]({{ "/posts/malware-inject-inline-hook/" | relative_url }})

**Links:** [Repository](https://github.com/PackedCrack/malware-injection-techniques)

---

### [Custom BadUSB Firmware]({{ "/posts/badusb/" | relative_url }})

Offensive embedded-security project implementing custom BadUSB-style firmware using
ESP32-S3, TinyUSB, HID keyboard behavior, CDC serial communication, and custom firmware logic.

**Type:** Blog post  
**Signals:** `offensive security` `embedded security` `USB` `HID` `TinyUSB` `ESP32-S3`  
**Relevant to:** Offensive security, embedded security, product security, security research


## Low-Level Software & Tooling

### Odin Game Engine

Work-in-progress C++ game engine built for educational purposes. The renderer is
GPU-driven, uses Vulkan and compute shaders, and uses ECS for game logic and input handling.

**Type:** Repository  
**Signals:** `C++` `Vulkan` `GPU-driven rendering` `ECS` `engine architecture`  
**Relevant to:** C/C++ systems development, low-level software, performance-oriented development

**Links:** [Repository](https://github.com/PackedCrack/Odin-Game-Engine)

---

### Ubiquitous Chainsaw

Proximity-based authentication proof of concept using BLE communication between a desktop
client and a microcontroller access token, with RSSI-based proximity tracking.

**Type:** Repository  
**Signals:** `C++` `BLE` `ESP32-S3` `authentication` `embedded systems`  
**Relevant to:** Embedded systems, IoT security, security-sensitive software

**Links:** [Repository](https://github.com/PackedCrack/ubiquitous-chainsaw)

---

### FreeRADIUS Log Watcher

Debugging and operational visibility tool for FreeRADIUS logs, built to inspect
authentication behavior and troubleshoot RADIUS deployments.

**Type:** Repository  
**Signals:** `C++` `Linux tooling` `log parsing` `FreeRADIUS` `authentication infrastructure`  
**Relevant to:** Systems tooling, debugging, authentication infrastructure, security-adjacent development

**Links:** [Repository](https://github.com/PackedCrack/freeradius-log-watcher)