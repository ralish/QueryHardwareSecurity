QueryHardwareSecurity
=====================

[![azure devops](https://dev.azure.com/nexiom/QueryHardwareSecurity/_apis/build/status/QueryHardwareSecurity?branchName=stable)](https://dev.azure.com/nexiom/QueryHardwareSecurity/_build/latest?definitionId=1&branchName=stable)
[![license](https://img.shields.io/github/license/ralish/QueryHardwareSecurity)](https://choosealicense.com/licenses/mit/)

[![Open in Visual Studio Code](https://open.vscode.dev/badges/open-in-vscode.svg)](https://open.vscode.dev/ralish/QueryHardwareSecurity)

A work-in-progress utility to query Windows support for security features and mitigations with hardware dependencies.

- [Requirements](#requirements)
- [Resources](#resources)
  - [Microsoft](#microsoft)
  - [CPU Vendors](#cpu-vendors)
  - [Miscellaneous](#miscellaneous)
- [Glossary](#glossary)

Requirements
------------

- Windows 7 or Server 2008 R2 (or newer)
- Windows PowerShell 3.0 (or newer)  
  *Built-in since Windows 8 and Server 2012.*
- Supported .NET runtime
  - .NET Framework 4.6.2 (or newer)  
    *Built-in since Windows 10 1607 and Server 2016.*
  - .NET Core 3.1 (or newer)  

Resources
---------

### Microsoft

- [KB4072698: Windows Server guidance to protect against speculative execution side-channel vulnerabilities](https://support.microsoft.com/en-us/help/4072698)
- [KB4073119: Windows client guidance for IT Pros to protect against speculative execution side-channel vulnerabilities](https://support.microsoft.com/en-us/help/4073119)
- [KB4073757: Protect your Windows devices against speculative execution side-channel attacks](https://support.microsoft.com/en-us/help/4073757)
- [KB4457951: Windows guidance to protect against speculative execution side-channel vulnerabilities](https://support.microsoft.com/en-us/help/4457951)

### CPU Vendors

- [AMD Product Security](https://www.amd.com/en/corporate/product-security)
- [ARM Security Updates](https://developer.arm.com/support/arm-security-updates)

### Miscellaneous

- [Transient Execution Attacks](https://transient.fail/)

Glossary
--------

- **APIC**  
  Advanced Programmable Interrupt Controller
- **AVIC**  
  Advanced Virtual Interrupt Controller
- **BIOS**  
  Basic Input/Output System
- **BTI**  
  Branch Target Injection
- **DMA**  
  Direct Memory Access
- **EIBRS**  
  Enhanced Indirect Branch Restricted Speculation
- **HLE**
  Hardware Lock Elision
- **HVCI**  
  Hypervisor-protected code integrity
- **IBRS**  
  Indirect Branch Restricted Speculation
- **INVPCID**  
  Invalidate Process-Context Identifier
- **KMCI**  
  Kernel Mode Code Integrity
- **L1TF**  
  L1 (Level 1 Data Cache) Terminal Fault
- **MBE**  
  Mode-Based Execution Control
- **MDS**  
  Microarchitectural Data Sampling
- **MOR**  
  Memory Overwrite Request Control
- **NX**  
  No-execute
- **PCID**  
  Process-Context Identifiers
- **PCR**  
  Platform Configuration Register
- **PTE**  
  Page Table Entry
- **RTM**
  Restricted Transactional Memory
- **SMEP**  
  Supervisor Mode Execution Protection
- **SMM**  
  System Management Mode
- **SSBD**  
  Speculative Store Bypass Disable
- **STIBP**  
  Single Thread Indirect Branch Predictor
- **TAA**  
  TSX Asynchronous Abort
- **TSX**  
  Transactional Synchronization Extensions
- **UEFI**  
  Unified Extensible Firmware Interface
- **UMCI**  
  User Mode Code Integrity
- **VA**  
  Virtual Address
- **VMM**  
  Virtual Machine Monitor
- **WSMT**  
  Windows SMM Security Mitigations Table
