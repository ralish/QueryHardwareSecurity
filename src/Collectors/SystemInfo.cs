using System;
using System.Linq;
using System.Runtime.InteropServices;

using Microsoft.Management.Infrastructure;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;
using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    [JsonObject(MemberSerialization.OptIn)]
    internal class SystemInfo : Collector {
        [JsonProperty] internal string Hostname { get; private set; }
        [JsonProperty] internal string OsName { get; private set; }
        [JsonProperty] internal string OsVersion { get; private set; }
        [JsonProperty] internal string CpuName { get; private set; }
        [JsonProperty] internal string CpuModel { get; private set; }
        [JsonProperty] internal string FwType { get; private set; }
        [JsonProperty] internal string HvPresent { get; private set; }

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

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(this);
        }

        internal override void WriteConsole(ConsoleOutputStyle style) {
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

        #region Computer System

        private CimInstance _computerSystem;

        internal CimInstance ComputerSystem {
            get {
                if (_computerSystem == null) {
                    WriteConsoleVerbose("Retrieving computer system info ...");
                    _computerSystem = EnumerateCimInstances("Win32_ComputerSystem").First();
                }

                return _computerSystem;
            }
        }


        /*
         * The underlying property in the WMI class is a boolean but it
         * won't be present prior to Windows 8 / Server 2012. That's an
         * unknown state, so we'll use an enum to represent that third
         * possibility instead of having to deal with a nullable bool.
         */
        internal enum HypervisorPresent {
            Unknown,
            False,
            True
        }


        private HypervisorPresent _hypervisorPresent;
        private bool _hypervisorPresentChecked;

        internal HypervisorPresent IsHypervisorPresent {
            get {
                if (!_hypervisorPresentChecked) {
                    try {
                        var cimHypervisorPresent =
                            (bool)ComputerSystem.CimInstanceProperties["HypervisorPresent"].Value;
                        _hypervisorPresent = cimHypervisorPresent ? HypervisorPresent.True : HypervisorPresent.False;
                    } catch (NullReferenceException) {
                        // HypervisorPresent is only available from Windows 8 / Server 2012
                        WriteConsoleError(
                            "Hypervisor presence unknown as HypervisorPresent WMI property is unavailable.");
                        _hypervisorPresent = HypervisorPresent.Unknown;
                    }

                    _hypervisorPresentChecked = true;
                }

                return _hypervisorPresent;
            }
        }

        #endregion

        #region Firmware

        private FirmwareType _firmwareType;
        private bool _firmwareTypeRetrieved;

        internal FirmwareType FirmwareType {
            get {
                if (!_firmwareTypeRetrieved) {
                    WriteConsoleVerbose("Retrieving firmware type ...");
                    try {
                        if (!GetFirmwareType(out _firmwareType)) {
                            var err = Marshal.GetLastWin32Error();
                            Console.Error.WriteLine($"Failed to call GetFirmwareType() with error: {err}");
                            Environment.Exit(-1);
                        }
                    } catch (EntryPointNotFoundException) {
                        // GetFirmwareType() is only available from Windows 8 / Server 2012
                        WriteConsoleError("Unable to query firmware type as GetFirmwareType() API is unavailable.");
                        _firmwareType = FirmwareType.Unknown;
                    }

                    _firmwareTypeRetrieved = true;
                }

                return _firmwareType;
            }
        }

        #endregion

        #region Operating System

        private CimInstance _operatingSystem;

        internal CimInstance OperatingSystem {
            get {
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


        // ReSharper disable InconsistentNaming
        internal enum ProcessorArchitecture {
            x86 = 0,
            ARM = 5,
            x64 = 9,
            ARM64 = 12
        }
        // ReSharper enable InconsistentNaming


        internal CimInstance ProcessorInfo {
            get {
                if (_processorInfo == null) {
                    WriteConsoleVerbose("Retrieving processor info ...");
                    _processorInfo = EnumerateCimInstances("Win32_Processor").First();
                }

                return _processorInfo;
            }
        }

        internal string ProcessorManufacturer {
            get {
                if (IsProcessorIntel) {
                    return "Intel";
                }

                if (IsProcessorAmd) {
                    return "AMD";
                }

                if (IsProcessorArm) {
                    return "ARM";
                }

                throw new ArgumentOutOfRangeException(
                    $"Unknown processor manufacturer: {(string)ProcessorInfo.CimInstanceProperties["Manufacturer"].Value}");
            }
        }

        internal bool IsProcessorX86 =>
            (int)ProcessorInfo.CimInstanceProperties["Architecture"].Value == (int)ProcessorArchitecture.x86;

        internal bool IsProcessorX64 =>
            (int)ProcessorInfo.CimInstanceProperties["Architecture"].Value == (int)ProcessorArchitecture.x64;

        internal bool IsProcessorArm =>
            (int)ProcessorInfo.CimInstanceProperties["Architecture"].Value == (int)ProcessorArchitecture.ARM ||
            (int)ProcessorInfo.CimInstanceProperties["Architecture"].Value == (int)ProcessorArchitecture.ARM64;

        internal bool IsProcessorAmd =>
            (string)ProcessorInfo.CimInstanceProperties["Manufacturer"].Value == "AuthenticAMD";

        internal bool IsProcessorIntel =>
            (string)ProcessorInfo.CimInstanceProperties["Manufacturer"].Value == "GenuineIntel";

        #endregion
    }
}
