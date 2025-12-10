Changelog
=========

v0.3.1
------

- Output `NtQuerySystemInformation` errors as errors (not verbose)
- Fix `PointerAuth` collector on .NET runtimes (non-Framework)
- Fix uninitialised `fbClearEnabled` flag on ARM platforms

v0.3.0
------

- Added new collector for Isolated User Mode: `Ium`
- Added new collector for Pointer Authentication: `PointerAuth`
- Relevant collectors now include an additional `Secure` column  
  Indicates if the value is considered secure for the given system.
- `KernelDma` collector
  - Added description for field
  - Renamed collector from `DmaGuardPolicy`
- `KvaShadow` collector
  - Tweaks to field descriptions
  - Renamed collector from `KernelVaShadow`
- `SecureBoot` collector
  - Added descriptions for fields
- `ShadowStacks`
  - Added descriptions for fields
  - Renamed collector from `ShadowStack`
- `SkSpecCtrl`
  - Added support for 4 new fields
  - Added descriptions for existing fields
  - Renamed collector from `SecureSpeculationControl`
- `SpecCtrl`
  - Added support for 15 new fields with descriptions
  - Renamed collector from `SpeculationControl`
- `Vbs`
  - Added support for additional VBS security services
  - Renamed collector from `WindowsDefender`
- `Vsm`
  - Added descriptions for fields
  - Renamed collector from `VsmProtection`
- Added several sections to the `README.md`
- Overhauled the glossary section of `README.md`
- Huge number of code quality & tooling improvements
- Updated `System.CommandLine` to v2.0.0
- Updated all other NuGet dependencies

v0.2.1
------

- Update `System.CommandLine` to v2.0.0-beta1.21308.1
- Add .NET 5.0 build target
- Remove .NET CLI tool package support
- Miscellaneous code clean-up & tweaks

v0.2.0
------

- New collector for reporting on TPM hardware: `Tpm`
- New collector for miscellaneous checks: `Miscellaneous`  
  Initial check is for *Kernel DMA Protection* support.
- Add .NET Core 3.1 build target
- Add .NET CLI tool package support
- Numerous bug fixes & internal improvements

v0.1.0
------

- Initial stable release
