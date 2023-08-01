using System;
using System.Linq;
using System.Runtime.InteropServices;

using Microsoft.Management.Infrastructure;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    [JsonObject(MemberSerialization.OptIn)]
    internal sealed class SystemInfo : Collector {
        // Computer system
        [JsonProperty]
        public string Hostname { get; private set; }

        // Operating system
        [JsonProperty]
        public string OsName { get; private set; }

        [JsonProperty]
        public string OsVersion { get; private set; }

        // Processor
        [JsonProperty]
        public string CpuName { get; private set; }

        [JsonProperty]
        public string CpuModel { get; private set; }

        // Firmware
        [JsonProperty]
        public string FwType { get; private set; }

        // Hypervisor
        [JsonProperty]
        public string HvPresent { get; private set; }

        public SystemInfo() : base("System Info") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 72;

            RetrieveInfo();
        }

        private void RetrieveInfo() {
            Hostname = Environment.MachineName;
            OsName = OperatingSystem.CimInstanceProperties["Caption"].Value.ToString();
            OsVersion = OperatingSystem.CimInstanceProperties["Version"].Value.ToString();
            CpuName = ProcessorInfo.CimInstanceProperties["Name"].Value.ToString();
            CpuModel = ProcessorInfo.CimInstanceProperties["Description"].Value.ToString();
            FwType = FirmwareType.ToString();
            HvPresent = IsHypervisorPresent.ToString();
        }

        public override string ConvertToJson() {
            return JsonConvert.SerializeObject(this);
        }

        public override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(false);
            WriteConsoleEntry("Hostname", Hostname);
            WriteConsoleEntry("OS name", OsName);
            WriteConsoleEntry("OS version", OsVersion);
            WriteConsoleEntry("Processor name", CpuName);
            WriteConsoleEntry("Processor model", CpuModel);
            WriteConsoleEntry("Firmware type", FwType);
            WriteConsoleEntry("Hypervisor present", HvPresent);
        }

        #region Computer system

        private CimInstance _computerSystem;

        public CimInstance ComputerSystem {
            get {
                // ReSharper disable once InvertIf
                if (_computerSystem == null) {
                    WriteConsoleVerbose("Retrieving computer system info ...");
                    _computerSystem = EnumerateCimInstances("Win32_ComputerSystem").First();
                }

                return _computerSystem;
            }
        }

        #endregion

        #region Firmware

        private FirmwareType _firmwareType;
        private bool _firmwareTypeRetrieved;

        public FirmwareType FirmwareType {
            get {
                // ReSharper disable once InvertIf
                if (!_firmwareTypeRetrieved) {
                    WriteConsoleVerbose("Retrieving firmware type ...");
                    try {
                        if (!GetFirmwareType(out _firmwareType)) {
                            var err = Marshal.GetLastWin32Error();
                            WriteConsoleError($"Failure calling GetFirmwareType(): {err}");
                            Environment.Exit(-1);
                        }
                    } catch (EntryPointNotFoundException) {
                        // GetFirmwareType() is only available from Windows 8 / Server 2012
                        WriteConsoleVerbose("Unable to query firmware type as GetFirmwareType() API is unavailable.");
                        _firmwareType = FirmwareType.Unknown;
                    }

                    _firmwareTypeRetrieved = true;
                }

                return _firmwareType;
            }
        }

        #endregion

        #region Hypervisor

        private HypervisorPresent _hypervisorPresent;
        private bool _hypervisorPresentChecked;

        /*
         * The underlying property in the WMI class is a boolean but it
         * won't be present prior to Windows 8 / Server 2012. That's an
         * unknown state, so we'll use an enum to represent that third
         * possibility instead of having to deal with a nullable bool.
         */
        public enum HypervisorPresent {
            Unknown,
            False,
            True
        }

        public HypervisorPresent IsHypervisorPresent {
            get {
                // ReSharper disable once InvertIf
                if (!_hypervisorPresentChecked) {
                    WriteConsoleVerbose("Checking if hypervisor is present ...");
                    try {
                        var cimHypervisorPresent =
                            (bool)ComputerSystem.CimInstanceProperties["HypervisorPresent"].Value;
                        _hypervisorPresent = cimHypervisorPresent ? HypervisorPresent.True : HypervisorPresent.False;
                    } catch (NullReferenceException) {
                        // HypervisorPresent is only available from Windows 8 / Server 2012
                        WriteConsoleVerbose(
                            "Hypervisor presence unknown as HypervisorPresent WMI property is unavailable.");
                        _hypervisorPresent = HypervisorPresent.Unknown;
                    }

                    _hypervisorPresentChecked = true;
                }

                return _hypervisorPresent;
            }
        }

        #endregion

        #region Operating system

        private CimInstance _operatingSystem;

        public CimInstance OperatingSystem {
            get {
                // ReSharper disable once InvertIf
                if (_operatingSystem == null) {
                    WriteConsoleVerbose("Retrieving operating system info ...");
                    _operatingSystem = EnumerateCimInstances("Win32_OperatingSystem").First();
                }

                return _operatingSystem;
            }
        }

        #endregion

        #region Processor

        private CimInstance _processorInfo;

        // @formatter:int_align_fields true

        // ReSharper disable InconsistentNaming
        public enum ProcessorArchitecture {
            x86   = 0,
            ARM   = 5,
            x64   = 9,
            ARM64 = 12
        }
        // ReSharper enable InconsistentNaming

        // @formatter:int_align_fields false

        public CimInstance ProcessorInfo {
            get {
                // ReSharper disable once InvertIf
                if (_processorInfo == null) {
                    WriteConsoleVerbose("Retrieving processor info ...");
                    _processorInfo = EnumerateCimInstances("Win32_Processor").First();
                }

                return _processorInfo;
            }
        }

        public string ProcessorManufacturer {
            get {
                if (IsProcessorIntel) return "Intel";
                if (IsProcessorAmd) return "AMD";
                if (IsProcessorArm) return "ARM";

                throw new ArgumentOutOfRangeException(
                    $"Unknown processor manufacturer: {(string)ProcessorInfo.CimInstanceProperties["Manufacturer"].Value}");
            }
        }

        public bool IsProcessorX86 =>
            (int)ProcessorInfo.CimInstanceProperties["Architecture"].Value == (int)ProcessorArchitecture.x86;

        public bool IsProcessorX64 =>
            (int)ProcessorInfo.CimInstanceProperties["Architecture"].Value == (int)ProcessorArchitecture.x64;

        public bool IsProcessorAmd =>
            (string)ProcessorInfo.CimInstanceProperties["Manufacturer"].Value == "AuthenticAMD";

        public bool IsProcessorArm =>
            (int)ProcessorInfo.CimInstanceProperties["Architecture"].Value == (int)ProcessorArchitecture.ARM ||
            (int)ProcessorInfo.CimInstanceProperties["Architecture"].Value == (int)ProcessorArchitecture.ARM64;

        public bool IsProcessorIntel =>
            (string)ProcessorInfo.CimInstanceProperties["Manufacturer"].Value == "GenuineIntel";

        #endregion
    }
}
