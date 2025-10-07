QueryHardwareSecurity
=====================

[![azure devops](https://dev.azure.com/nexiom/QueryHardwareSecurity/_apis/build/status/QueryHardwareSecurity)](https://dev.azure.com/nexiom/QueryHardwareSecurity/_build/latest?definitionId=1)
[![license](https://img.shields.io/github/license/ralish/QueryHardwareSecurity)](https://choosealicense.com/licenses/mit/)

A work-in-progress utility to query Windows support for security features and mitigations with hardware dependencies.

- [Requirements](#requirements)
- [Resources](#resources)
  - [Microsoft](#microsoft)
  - [CPU vendors](#cpu-vendors)
  - [Miscellaneous](#miscellaneous)
- [Glossary](#glossary)
  - [General](#general)
  - [Firmware](#firmware)
  - [Processor features](#processor-features)
  - [Processor vulnerabilities](#processor-vulnerabilities)
  - [Windows features](#windows-features)
- [License](#license)

Requirements
------------

- Windows 7 or Server 2008 R2 (or newer)
- Windows PowerShell 3.0 (or newer)  
  *Built-in since Windows 8 and Server 2012*
- Supported .NET runtimes
  - .NET Framework 4.6.2 (or newer)  
    *Built-in since Windows 10 1607 and Server 2016*
  - .NET 8.0  

Resources
---------

### Microsoft

- [KB4072698: Windows Server guidance to protect against speculative execution side-channel vulnerabilities](https://support.microsoft.com/en-us/help/4072698)
- [KB4073119: Windows client guidance for IT Pros to protect against speculative execution side-channel vulnerabilities](https://support.microsoft.com/en-us/help/4073119)
- [KB4073757: Protect your Windows devices against speculative execution side-channel attacks](https://support.microsoft.com/en-us/help/4073757)
- [KB4457951: Windows guidance to protect against speculative execution side-channel vulnerabilities](https://support.microsoft.com/en-us/help/4457951)

### CPU vendors

- [AMD Product Security](https://www.amd.com/en/corporate/product-security)
- [ARM Security Updates](https://developer.arm.com/support/arm-security-updates)

### Miscellaneous

- [Transient Execution Attacks](https://transient.fail/)

Glossary
--------

### General

- **DMA**  
  Direct Memory Access
- **MMIO**  
  Memory-mapped I/O
- **PTE**  
  Page Table Entry
- **SMM**  
  System Management Mode
- **TPM**  
  Trusted Platform Module
- **VA**  
  Virtual Address
- **VMM**  
  Virtual Machine Monitor

### Firmware

- **BIOS**  
  Basic Input/Output System
- **MOR**  
  Memory Overwrite Request Control
- **PCR**  
  Platform Configuration Register
- **UEFI**  
  Unified Extensible Firmware Interface

### Processor features

- **APIC**  
  Advanced Programmable Interrupt Controller
- **AVIC**  
  Advanced Virtual Interrupt Controller
- **CET**  
  Control-Flow Enforcement Technology
- **IBRS**  
  Indirect Branch Restricted Speculation
  - **EIBRS**  
    Enhanced IBRS
- **INVPCID**  
  Invalidate Process-Context Identifier
- **MBE**  
  Mode-Based Execution Control
- **NX**  
  No-execute
- **PCID**  
  Process-Context Identifiers
- **SMEP**  
  Supervisor Mode Execution Protection
- **SSBD**  
  Speculative Store Bypass Disable
- **STIBP**  
  Single Thread Indirect Branch Predictor
- **TSX**  
  Transactional Synchronization Extensions
  - **HLE**  
    Hardware Lock Elision
  - **RTM**  
    Restricted Transactional Memory

### Processor vulnerabilities

- **Spectre**
  - **BCB**  
    Bounds Check Bypass
  - **BCBS**  
    Bounds Check Bypass Store
  - **BTI**  
    Branch Target Injection
  - **RDCL**  
    Rogue Data Cache Load
  - **RSRR**  
    Rogue System Register Read
  - **SSB**  
    Speculative Store Bypass
- **Foreshadow**
  - **L1TF**  
    L1 (Level 1 Data Cache) Terminal Fault
- **MDS**  
  Microarchitectural Data Sampling
  - **L1DES**  
    L1D Eviction Sampling
  - **MDSUM**  
    Microarchitectural Data Sampling Uncacheable Memory
  - **MFBDS**  
    Microarchitectural Fill Buffer Data Sampling
  - **MLPDS**  
    Microarchitectural Load Port Data Sampling
  - **MSBDS**  
    Microarchitectural Store Buffer Data Sampling
  - **TAA**  
    TSX Asynchronous Abort
  - **VRS**  
    Vector Register Sampling
- **MMIO Stale Data**  
  Memory-mapped I/O Stale Data
  - **DRPW**  
    Device Register Partial Write
  - **SBDR**  
    Shared Buffers Data Read
  - **SBDS**  
    Shared Buffers Data Sampling
  - **SRBDS Update**  
    Special Register Buffer Data Sampling Update

### Windows features

- **HVCI**  
  Hypervisor-protected code integrity
- **KMCI**  
  Kernel Mode Code Integrity
- **UMCI**  
  User Mode Code Integrity
- **VSM**  
  Virtual Secure Mode
- **WSMT**  
  Windows SMM Security Mitigations Table

License
-------

All content is licensed under the terms of [The MIT License](LICENSE).
