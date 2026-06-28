---
layout: page
title: Portfolio
icon: fas fa-laptop-code
order: 1
permalink: /portfolio/
---


## Reverse Engineering & Malware Analysis

<div class="card mb-3">
  <div class="card-body">
    <h3 class="h5 card-title">Unpacking Morphine</h3>

```
<p class="card-text">
  Manual unpacking of a Morphine-packed Windows executable, including OEP discovery,
  dumping, import reconstruction, PE repair, and analysis of Morphine's decryption
  and import-restoration routines.
</p>

<p class="mb-2">
 unpacking · OEP recovery · PE analysis · dynamic analysis · debugging · import restoration
</p>

<a href="{{ '/posts/unpacking-morphine/' | relative_url }}" class="btn btn-outline-primary btn-sm">
  Writeup
</a>
```

  </div>
</div>

<div class="card mb-3">
  <div class="card-body">
    <h3 class="h5 card-title">Malware Analysis: Multi-Stage Windows Spyware</h3>

```
<p class="card-text">
  Malware-analysis report covering a multi-stage Windows spyware sample that abuses
  a legitimate Google updater component for execution. The report covers installation
  behavior, persistence, payload behavior, registry and network artifacts, and IOCs.
</p>

<p class="mb-2">
  malware analysis · IDA Pro · IDA Python · DLL side-loading · persistence · IOCs · host artifacts · network behavior
</p>

<a href="{{ '/posts/google-sideloading/' | relative_url }}" class="btn btn-outline-primary btn-sm">
  Writeup
</a>
```

  </div>
</div>

<div class="card mb-3">
  <div class="card-body">
    <h3 class="h5 card-title">Evading Static Detection with Compilation</h3>

```
<p class="card-text">
  Research writeup investigating whether compiler flags alone can generate functionally
  equivalent malware binaries with enough machine-code variation to affect static
  detection. Focuses on compiler-generated variation, opcode-level changes, and static
  detection limitations.
</p>

<p class="mb-2">
  malware evasion · static detection · compiler flags · PE variation
</p>

<a href="{{ '/posts/copmilation-evasion-light/' | relative_url }}" class="btn btn-outline-primary btn-sm">
  Writeup
</a>
```

  </div>
</div>

<div class="card mb-3">
  <div class="card-body">
    <h3 class="h5 card-title">Compiler-Induced Feature Drift in Static Malware Analysis</h3>

```
<p class="card-text">
  Thesis project investigating whether compiler settings can change static malware-analysis
  features while preserving program functionality. The work focuses on opcode 3-gram drift,
  controlled Windows PE builds, IDA-based feature extraction, and robustness implications
  for static malware-analysis pipelines.
</p>

<p class="mb-2">
  static malware analysis · opcode n-grams · IDA Python · MSVC · feature drift · detection robustness
</p>


<a href="https://github.com/PackedCrack/master_thesis"
   class="btn btn-outline-primary btn-sm"
   target="_blank"
   rel="noopener noreferrer">
  Repository
</a>
```

  </div>
</div>

## Applied Cybersecurity Work

<div class="card mb-3">
  <div class="card-body">
    <h3 class="h5 card-title">Malware Injection Techniques</h3>

```
<p class="card-text">
  Windows internals and offensive-security series implementing common process
  manipulation techniques in C++.
</p>

<p class="mb-2">
  Windows internals · Win32 API · process memory · code injection · runtime patching · C++
</p>

<p class="mb-2">
  <strong>Includes:</strong>
</p>

<ul>
  <li>
    <a href="{{ '/posts/malware-inject-proc-hollow/' | relative_url }}">
      Process Hollowing
    </a>
  </li>
  <li>
    <a href="{{ '/posts/malware-inject-dll-inject/' | relative_url }}">
      DLL Injection
    </a>
  </li>
  <li>
    <a href="{{ '/posts/malware-inject-dir-inject/' | relative_url }}">
      Direct Injection
    </a>
  </li>
  <li>
    <a href="{{ '/posts/malware-inject-inline-hook/' | relative_url }}">
      Inline Hooking
    </a>
  </li>
</ul>
```

  </div>
</div>

<div class="card mb-3">
  <div class="card-body">
    <h3 class="h5 card-title">Custom BadUSB Firmware</h3>

```
<p class="card-text">
  Offensive embedded-security writeup implementing custom BadUSB-style firmware without
  a Rubber Ducky. The project uses an ESP32-S3 and implements a custom firmware to explore USB attack surface and device behavior.
</p>

<p class="mb-2">
  offensive security · embedded security · firmware · USB · HID · CDC · ESP32-S3
</p>

<a href="{{ '/posts/badusb/' | relative_url }}" class="btn btn-outline-primary btn-sm">
  Writeup
</a>
```

  </div>
</div>

## Low-Level Software & Tooling

<div class="card mb-3">
  <div class="card-body">
    <h3 class="h5 card-title">Odin Game Engine</h3>

```
<p class="card-text">
  Work-in-progress C++ game engine built for educational purposes. The renderer is
  GPU-driven, uses Vulkan and compute shaders, and relies on ECS for game logic and
  input handling.
</p>

<p class="mb-2">
  C++ · Vulkan · GPU-driven rendering · ECS · engine architecture · systems programming · GPGPU
</p>

<a href="https://github.com/PackedCrack/Odin-Game-Engine"
   class="btn btn-outline-primary btn-sm"
   target="_blank"
   rel="noopener noreferrer">
  Repository
</a>
```

  </div>
</div>

<div class="card mb-3">
  <div class="card-body">
    <h3 class="h5 card-title">Ubiquitous Chainsaw</h3>

```
<p class="card-text">
  Proximity-based authentication proof of concept that re-enables full-disk encryption
  if the user moves too far from the computer. The system uses BLE communication between
  a desktop client and a microcontroller access token, with RSSI-based proximity tracking.
</p>

<p class="mb-2">
  C++ · BLE · ESP32-S3 · authentication · embedded systems · ECC encryption · digital signatures · replay attack protection
</p>

<a href="https://github.com/PackedCrack/ubiquitous-chainsaw"
   class="btn btn-outline-primary btn-sm"
   target="_blank"
   rel="noopener noreferrer">
  Repository
</a>
```

  </div>
</div>

<div class="card mb-3">
  <div class="card-body">
    <h3 class="h5 card-title">FreeRADIUS Log Watcher</h3>

```
<p class="card-text">
  Debugging and operational visibility tool for FreeRADIUS logs, built to inspect authentication behavior and troubleshoot RADIUS deployments.
</p>

<p class="mb-2">
  C++ · Linux tooling · log parsing · FreeRADIUS · authentication infrastructure · debugging
</p>

<a href="https://github.com/PackedCrack/freeradius-log-watcher"
   class="btn btn-outline-primary btn-sm"
   target="_blank"
   rel="noopener noreferrer">
  Repository
</a>
```

  </div>
</div>
