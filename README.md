QueryHardwareSecurity
=====================

![GitHub Release](https://img.shields.io/github/v/release/ralish/QueryHardwareSecurity?include_prereleases)
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
  - [Indirect branch control mechanisms](#indirect-branch-control-mechanisms)
  - [Indirect branch prediction mechanisms](#indirect-branch-prediction-mechanisms)
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
  - .NET 8 (or newer)  
    Install manually: [Download](https://dotnet.microsoft.com/en-us/download/dotnet)
    Install with WinGet: `winget install Microsoft.DotNet.Runtime.8`

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
- **IP**  
  Instruction Pointer
- **MMIO**  
  Memory-mapped I/O
- **PTE**  
  Page Table Entry
- **TPM**  
  Trusted Platform Module
- **VA**  
  Virtual Address
- **VMM**  
  Virtual Machine Monitor

### Firmware

- **BIOS**  
  Basic Input/Output System
- **UEFI**  
  Unified Extensible Firmware Interface
  - **MOR**  
    Memory Overwrite Request Control

### Indirect branch control mechanisms

- **BHB**  
  Branch History Barrier
- **BPB**  
  Branch Prediction Barrier
- **IBPB** (*AMD / Intel*)  
  Indirect Branch Predictor Barrier
- **IBRS** (*AMD / Intel*)  
  Indirect Branch Restricted Speculation
  - **Automatic IBRS** (*AMD*)  
    Automatic Indirect Branch Restricted Speculation
  - **eIBRS** (*Intel*)  
    Enhanced Indirect Branch Restricted Speculation
- **SSBD** (*AMD / ARM / Intel*)  
  Speculative Store Bypass Disable
- **SSBS** (*ARM*)  
  Speculative Store Bypass Safe
- **STIBP** (*AMD / Intel*)  
  Single Thread Indirect Branch Predictors

### Indirect branch prediction mechanisms

- `CALL` / `JMP`
  - **BHB** (*Intel*)  
    Branch History Buffer
  - **BTB** (*AMD / Intel*)  
    Branch Target Buffer
- `RET`
  - **RAP** (*AMD*)  
    Return Address Predictor
  - **RAS** (*AMD*)  
    Return Address Store
  - **RSB** (*Intel*)  
    Return Stack Buffer

### Processor features

- **APIC**  
  Advanced Programmable Interrupt Controller
  - **APICv** (*Intel*)  
    APIC Virtualization
  - **AVIC** (*AMD*)  
    Advanced Virtual Interrupt Controller
- **CET** (*Intel*)  
  Control-Flow Enforcement Technology
- **NX**  
  No-execute
- **PCID**  
  Process-Context Identifiers
  - **INVPCID**  
    Invalidate Process-Context Identifier
- **QARMA**  
  Qualcomm ARM Authenticator
- **SLAT**  
  Second Level Address Translation
  - **GMET** (*AMD*)  
    Guest Mode Execute Trap
  - **MBEC** (*Intel*)  
    Mode-Based Execution Control
- **SMEP**  
  Supervisor Mode Execution Protection
- **SMM**  
  System Management Mode
- **TSX** (*Intel*)  
  Transactional Synchronization Extensions
  - **HLE**  
    Hardware Lock Elision
  - **RTM**  
    Restricted Transactional Memory

### Processor vulnerabilities

- **BHI**  
  Branch History Injection
- **BTC** (*Phantom*, *Retbleed*)  
  Branch Type Confusion
- **FPVI**  
  Floating Point Value Injection
- **GDS** (*Downfall*)  
  Gather Data Sampling
- **L1TF** (*Foreshadow-NG*)  
  L1 (Level 1 Data Cache) Terminal Fault
- **LVI**  
  Load Value Injection
- **MDS**  
  Microarchitectural Data Sampling
  - **L1DES** (*CacheOut*)  
    L1D Eviction Sampling
  - **MDSUM** (*ZombieLoad*)  
    Microarchitectural Data Sampling Uncacheable Memory
  - **MFBDS** (*ZombieLoad*)  
    Microarchitectural Fill Buffer Data Sampling
  - **MLPDS**  
    Microarchitectural Load Port Data Sampling
  - **MSBDS** (*Fallout*)  
    Microarchitectural Store Buffer Data Sampling
  - **TAA** (*ZombieLoad v2*)  
    TSX Asynchronous Abort
  - **VRS**  
    Vector Register Sampling
- **MMIO Stale Data**  
  Memory-mapped I/O Stale Data
  - **DRPW**  
    Device Register Partial Write
  - **FBSDP**  
    Fill Buffer Stale Data Propagator
  - **PSDP**  
    Primary Stale Data Propagator
  - **SBDR**  
    Shared Buffers Data Read
  - **SBDS**  
    Shared Buffers Data Sampling
  - **SRBDS Update**  
    Special Register Buffer Data Sampling Update
  - **SSDP**  
    Sideband Stale Data Propagator
- **RFDS**  
  Register File Data Sampling
- **SCSB**
  Speculative Code Store Bypass
- **Spectre**
  - **BCB** (*Spectre: Variant 1*)  
    Bounds Check Bypass
  - **BCBS** (*Spectre-NG: Variant 1.1*)  
    Bounds Check Bypass Store
  - **BHB** (*Spectre-BHB*)  
    Branch History Buffer
  - **BTI** (*Spectre: Variant 2*)  
    Branch Target Injection
  - **RDCL** (*Spectre: Variant 3*, *Meltdown*)  
    Rogue Data Cache Load
  - **RSRR** (*Spectre-NG: Variant 3a*)  
    Rogue System Register Read
  - **SSB** (*Spectre-NG: Variant 4*)  
    Speculative Store Bypass
- **SRBDS** (*CROSSTalk*)  
  Special Register Buffer Data Sampling
- **SRSO** (*Inception*)  
  Speculative Return Stack Overflow

### Windows features

- **HVCI**  
  Hypervisor-protected Code Integrity
- **HVPT**  
  Hypervisor-enforced Paging Translation
- **IUM**  
  Isolated User Mode
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
