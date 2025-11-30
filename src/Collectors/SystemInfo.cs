using System;
using System.Linq;
using System.Runtime.InteropServices;

using Microsoft.Management.Infrastructure;

using Newtonsoft.Json;

using static QueryHardwareSecurity.Utilities;

namespace QueryHardwareSecurity.Collectors {
    internal sealed class SystemInfo : Collector {
        public SystemInfo() : base("System Info", TableStyle.Basic) {
            RetrieveInfo();
        }

        [JsonProperty]
        public string Hostname { get; private set; }

        [JsonProperty]
        public string OsName { get; private set; }

        [JsonProperty]
        public string OsVersion { get; private set; }

        [JsonProperty]
        public string CpuName { get; private set; }

        [JsonProperty]
        public string CpuModel { get; private set; }

        [JsonProperty]
        public string FwType { get; private set; }

        [JsonProperty]
        public string HvPresent { get; private set; }

        private void RetrieveInfo() {
            Hostname = Environment.MachineName;
            OsName = OperatingSystem.CimInstanceProperties["Caption"].Value.ToString();
            OsVersion = OperatingSystem.CimInstanceProperties["Version"].Value.ToString();
            CpuName = ProcessorInfo.CimInstanceProperties["Name"].Value.ToString();
            CpuModel = ProcessorInfo.CimInstanceProperties["Description"].Value.ToString();
            FwType = FirmwareType.ToString();
            HvPresent = IsHypervisorPresent.ToString();
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(this);
        }

        internal override void WriteOutput(OutputFormat format, bool color) {
            SetOutputSettings(format, color);
            WriteOutputHeader();

            WriteOutputEntry("Hostname", Hostname);
            WriteOutputEntry("OS name", OsName);
            WriteOutputEntry("OS version", OsVersion);
            WriteOutputEntry("Processor name", CpuName);
            WriteOutputEntry("Processor model", CpuModel);
            WriteOutputEntry("Firmware type", FwType);
            WriteOutputEntry("Hypervisor present", HvPresent);
        }

        #region Computer system

        private CimInstance? _computerSystem;

        private CimInstance ComputerSystem {
            get {
                if (_computerSystem != null) return _computerSystem;

                WriteVerbose("Retrieving computer system info ...");
                _computerSystem = EnumerateCimInstances("Win32_ComputerSystem").First();
                return _computerSystem;
            }
        }

        #endregion

        #region Firmware

        private FirmwareTypes? _firmwareType;

        private FirmwareTypes FirmwareType {
            get {
                if (_firmwareType != null) return _firmwareType.Value;

                WriteVerbose("Retrieving firmware type ...");
                try {
                    if (!GetFirmwareType(out var firmwareType)) {
                        var err = Marshal.GetLastWin32Error();
                        WriteError($"Failure calling GetFirmwareType: {err}");
                        Environment.Exit(-1);
                    }
                    _firmwareType = firmwareType;
                } catch (EntryPointNotFoundException) {
                    // GetFirmwareType is only available from Windows 8 / Server 2012
                    WriteVerbose("Unable to query firmware type as GetFirmwareType API is unavailable.");
                    _firmwareType = FirmwareTypes.Unknown;
                }

                return _firmwareType.Value;
            }
        }

        #endregion

        #region Hypervisor

        private HypervisorPresent? _hypervisorPresent;

        private HypervisorPresent IsHypervisorPresent {
            get {
                if (_hypervisorPresent != null) return _hypervisorPresent.Value;

                WriteVerbose("Checking if hypervisor is present ...");
                try {
                    var cimHypervisorPresent = (bool)ComputerSystem.CimInstanceProperties["HypervisorPresent"].Value;
                    _hypervisorPresent = cimHypervisorPresent ? HypervisorPresent.True : HypervisorPresent.False;
                } catch (NullReferenceException) {
                    // HypervisorPresent is only available from Windows 8 / Server 2012
                    WriteVerbose("Hypervisor presence unknown as HypervisorPresent WMI property is unavailable.");
                    _hypervisorPresent = HypervisorPresent.Unknown;
                }

                return _hypervisorPresent.Value;
            }
        }

        private enum HypervisorPresent {
            Unknown,
            False,
            True
        }

        #endregion

        #region Operating system

        private CimInstance? _operatingSystem;

        private CimInstance OperatingSystem {
            get {
                if (_operatingSystem != null) return _operatingSystem;

                WriteVerbose("Retrieving operating system info ...");
                _operatingSystem = EnumerateCimInstances("Win32_OperatingSystem").First();
                return _operatingSystem;
            }
        }

        #endregion

        #region Processor

        private static CimInstance? _processorInfo;

        internal static CimInstance ProcessorInfo {
            get {
                if (_processorInfo != null) return _processorInfo;

                _processorInfo = EnumerateCimInstances("Win32_Processor").First();
                return _processorInfo;
            }
        }

        internal static string ProcessorManufacturer {
            get {
                if (IsProcessorIntel) return "Intel";
                if (IsProcessorAmd) return "AMD";
                // ReSharper disable once ConvertIfStatementToReturnStatement
                if (IsProcessorArm) return "ARM";

                throw new ArgumentOutOfRangeException($"Unknown processor manufacturer: {(string)ProcessorInfo.CimInstanceProperties["Manufacturer"].Value}");
            }
        }

        internal static bool IsProcessorX86 => (int)ProcessorInfo.CimInstanceProperties["Architecture"].Value == (int)ProcessorArchitecture.x86;

        internal static bool IsProcessorX64 => (int)ProcessorInfo.CimInstanceProperties["Architecture"].Value == (int)ProcessorArchitecture.x64;

        internal static bool IsProcessorAmd => (string)ProcessorInfo.CimInstanceProperties["Manufacturer"].Value == "AuthenticAMD";

        internal static bool IsProcessorArm =>
            (ushort)ProcessorInfo.CimInstanceProperties["Architecture"].Value == (ushort)ProcessorArchitecture.ARM ||
            (ushort)ProcessorInfo.CimInstanceProperties["Architecture"].Value == (ushort)ProcessorArchitecture.ARM64;

        internal static bool IsProcessorIntel => (string)ProcessorInfo.CimInstanceProperties["Manufacturer"].Value == "GenuineIntel";

        // ReSharper disable InconsistentNaming

        // @formatter:int_align_fields true

        private enum ProcessorArchitecture : ushort {
            x86   = 0,
            ARM   = 5,
            x64   = 9,
            ARM64 = 12
        }
        // @formatter:int_align_fields false

        // ReSharper enable InconsistentNaming

        #endregion

        #region P/Invoke

        [DllImport("kernel32", ExactSpelling = true, SetLastError = true)]
        private static extern bool GetFirmwareType(out FirmwareTypes firmwareType);


        // @formatter:int_align_fields true

        private enum FirmwareTypes {
            Unknown = 0,
            BIOS    = 1,
            UEFI    = 2
        }

        // @formatter:int_align_fields false

        #endregion
    }
}
