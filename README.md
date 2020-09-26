QueryHardwareSecurity
=====================

A work-in-progress utility to query Windows support for security features and mitigations with hardware dependencies.

- [Requirements](#requirements)
- [Glossary](#glossary)

Requirements
------------

- Windows 7 or Server 2008 R2 (or newer)
- Windows PowerShell 3.0 (or newer)  
  *Built-in since Windows 8 and Server 2012.*
- .NET Framework 4.6.2 (or newer)  
  *Built-in since Windows 10 1607 and Server 2016.*

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
