using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

using Newtonsoft.Json;

using Tpm2Lib;

namespace QueryHardwareSecurity.Collectors {
    [JsonObject(MemberSerialization.OptIn)]
    internal sealed class Tpm : Collector {
        [JsonProperty]
        public uint ManufacturerId { get; private set; }

        [JsonProperty]
        public string ManufacturerName { get; private set; }

        [JsonProperty]
        public uint ManufacturerModel { get; private set; }

        [JsonProperty]
        public string SpecificationVersion { get; private set; }

        [JsonProperty]
        public uint SpecificationLevel { get; private set; }

        [JsonProperty]
        public float SpecificationRevision { get; private set; }

        [JsonProperty]
        public DateTime SpecificationDate { get; private set; }

        [JsonProperty]
        public string PlatformSpecificFamily { get; private set; }

        [JsonProperty]
        public uint PlatformSpecificationLevel { get; private set; }

        [JsonProperty]
        public float PlatformSpecificationRevision { get; private set; }

        [JsonProperty]
        public DateTime PlatformSpecificationDate { get; private set; }

        [JsonProperty]
        public Version FirmwareVersion { get; private set; }

        [JsonProperty]
        public string PhysicalPresenceVersion { get; private set; }

        [JsonProperty]
        public string MemoryManagement { get; private set; }

        [JsonProperty]
        public string SupportedModes { get; private set; }

        [JsonProperty]
        public string PermanentAttributes { get; private set; }

        [JsonProperty]
        public string StartupAttributes { get; private set; }

        public Tpm() : base("Trusted Platform Module") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 72;

            RetrieveTpmProperties();
            RetrievePpiInfo();
        }

        private void RetrieveTpmProperties() {
            WriteConsoleVerbose("Retrieving TPM properties ...");

            using (var tpmDevice = new TbsDevice()) {
                WriteConsoleDebug("Connecting to TPM ...");
                tpmDevice.Connect();

                using (var tpm = new Tpm2(tpmDevice)) {
                    // ReSharper disable JoinDeclarationAndInitializer
                    uint tpmProperty;
                    TaggedTpmPropertyArray tpmProperties;
                    // ReSharper enable JoinDeclarationAndInitializer

                    WriteConsoleDebug("Retrieving TPM capability: TPM_PROPERTIES (Property: PT_FIXED)");
                    tpm.GetCapability(Cap.TpmProperties, (uint)Pt.PtFixed, 1000, out var capPropertiesFixed);
                    tpmProperties = (TaggedTpmPropertyArray)capPropertiesFixed;

                    #region Manufacturer

                    ManufacturerId = tpmProperties.tpmProperty[Pt.Manufacturer - Pt.PtFixed].value;

                    var tpmManufacturerBytes = BitConverter.GetBytes(ManufacturerId);
                    Array.Reverse(tpmManufacturerBytes); // Assumes little-endian
                    var tpmManufacturerName = new char[tpmManufacturerBytes.Length];
                    for (var index = 0; index < tpmManufacturerName.Length; index++) {
                        // Unprintable character or invalid 7-bit ASCII
                        if (tpmManufacturerBytes[index] < 32 || tpmManufacturerBytes[index] > 126) break;

                        tpmManufacturerName[index] = Convert.ToChar(tpmManufacturerBytes[index]);
                    }

                    ManufacturerName = new string(tpmManufacturerName).Trim();

                    ManufacturerModel = tpmProperties.tpmProperty[Pt.VendorTpmType - Pt.PtFixed].value;

                    #endregion

                    #region Specification

                    tpmProperty = tpmProperties.tpmProperty[Pt.FamilyIndicator - Pt.PtFixed].value;
                    var tpmFamilyIndicator = BitConverter.GetBytes(tpmProperty);
                    Array.Reverse(tpmFamilyIndicator); // Assumes little-endian
                    SpecificationVersion = Encoding.ASCII.GetString(tpmFamilyIndicator).Trim('\0');

                    SpecificationLevel = tpmProperties.tpmProperty[Pt.Level - Pt.PtFixed].value;

                    tpmProperty = tpmProperties.tpmProperty[Pt.Revision - Pt.PtFixed].value;
                    SpecificationRevision = (float)tpmProperty / 100;

                    tpmProperty = tpmProperties.tpmProperty[Pt.Year - Pt.PtFixed].value;
                    SpecificationDate = new DateTime((int)tpmProperty - 1, 12, 31);
                    tpmProperty = tpmProperties.tpmProperty[Pt.DayOfYear - Pt.PtFixed].value;
                    SpecificationDate = SpecificationDate.AddDays(tpmProperty);

                    #endregion

                    #region Platform-specific

                    tpmProperty = tpmProperties.tpmProperty[Pt.PsFamilyIndicator - Pt.PtFixed].value;
                    PlatformSpecificFamily = ((Ps)tpmProperty).ToString();

                    PlatformSpecificationLevel = tpmProperties.tpmProperty[Pt.PsLevel - Pt.PtFixed].value;

                    tpmProperty = tpmProperties.tpmProperty[Pt.PsRevision - Pt.PtFixed].value;
                    PlatformSpecificationRevision = (float)tpmProperty / 100;

                    tpmProperty = tpmProperties.tpmProperty[Pt.PsYear - Pt.PtFixed].value;
                    PlatformSpecificationDate = new DateTime((int)tpmProperty - 1, 12, 31);
                    tpmProperty = tpmProperties.tpmProperty[Pt.PsDayOfYear - Pt.PtFixed].value;
                    PlatformSpecificationDate = SpecificationDate.AddDays(tpmProperty);

                    #endregion

                    #region Firmware

                    var tpmFirmwareVersion = new uint[2];
                    tpmFirmwareVersion[0] = tpmProperties.tpmProperty[Pt.FirmwareVersion1 - Pt.PtFixed].value;
                    tpmFirmwareVersion[1] = tpmProperties.tpmProperty[Pt.FirmwareVersion2 - Pt.PtFixed].value;
                    FirmwareVersion = new Version((int)(tpmFirmwareVersion[0] >> 16),
                                                  (int)(tpmFirmwareVersion[0] & 0xFFFF),
                                                  (int)tpmFirmwareVersion[1] >> 16,
                                                  (int)tpmFirmwareVersion[1] & 0xFFFF);

                    #endregion

                    #region Characteristics

                    tpmProperty = tpmProperties.tpmProperty[Pt.Memory - Pt.PtFixed].value;
                    var tpmMemory = (MemoryAttr)tpmProperty;
                    MemoryManagement = tpmMemory.ToString();

                    tpmProperty = tpmProperties.tpmProperty[Pt.Modes - Pt.PtFixed].value;
                    var tpmModes = (ModesAttr)tpmProperty;
                    SupportedModes = tpmModes.ToString();

                    #endregion

                    WriteConsoleDebug("Retrieving TPM capability: TPM_PROPERTIES (Property: PT_VAR)");
                    tpm.GetCapability(Cap.TpmProperties, (uint)Pt.PtVar, 1000, out var capPropertiesVar);
                    tpmProperties = (TaggedTpmPropertyArray)capPropertiesVar;

                    #region Configuration

                    tpmProperty = tpmProperties.tpmProperty[Pt.Permanent - Pt.PtVar].value;
                    var tpmPermanent = (PermanentAttr)tpmProperty;
                    PermanentAttributes = tpmPermanent.ToString();

                    tpmProperty = tpmProperties.tpmProperty[Pt.StartupClear - Pt.PtVar].value;
                    var tpmStartupClear = (StartupClearAttr)tpmProperty;
                    StartupAttributes = tpmStartupClear.ToString();

                    #endregion
                }
            }
        }

        private void RetrievePpiInfo() {
            WriteConsoleDebug("Creating TBS context ...");
            var tbsContextParams = new TBS_CONTEXT_PARAMS2 {
                flags = TBS_CONTEXT_PARAMS2_FLAGS.includeTpm12 | TBS_CONTEXT_PARAMS2_FLAGS.includeTpm20
            };
            CheckTbsResult(Tbsi_Context_Create(tbsContextParams, out var tbsContext));

            WriteConsoleVerbose("Retrieving PPI version ...");
            var ppiVersionCommand = new byte[] { 0x01, 0x00, 0x00, 0x00 };
            var ppiVersionOutput = new byte[16];
            var ppiVersionLength = (uint)ppiVersionOutput.Length;
            CheckTbsResult(Tbsi_Physical_Presence_Command(tbsContext,
                                                          ppiVersionCommand,
                                                          (uint)ppiVersionCommand.Length,
                                                          ppiVersionOutput,
                                                          ref ppiVersionLength));
            PhysicalPresenceVersion = Encoding.ASCII.GetString(ppiVersionOutput).Trim('\0').Trim();

            WriteConsoleDebug("Closing TBS context ...");
            CheckTbsResult(Tbsip_Context_Close(tbsContext));
        }

        private static void CheckTbsResult(TBS_RESULT tbsResult) {
            if (tbsResult != TBS_RESULT.TBS_SUCCESS) throw new Win32Exception($"TBS API returned: {tbsResult}");
        }

        public override string ConvertToJson() {
            return JsonConvert.SerializeObject(this);
        }

        public override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(false);

            WriteConsoleEntry("Manufacturer ID", ManufacturerId.ToString());
            WriteConsoleEntry("Manufacturer Name", ManufacturerName);
            WriteConsoleEntry("Manufacturer Model", ManufacturerModel.ToString());

            WriteConsoleEntry("Specification version", SpecificationVersion);
            WriteConsoleEntry("Specification level", SpecificationLevel.ToString());
            WriteConsoleEntry("Specification revision", SpecificationRevision.ToString());
            WriteConsoleEntry("Specification date", SpecificationDate.ToString("d"));

            WriteConsoleEntry("Platform-specific family", PlatformSpecificFamily);
            WriteConsoleEntry("Platform specification level", PlatformSpecificationLevel.ToString());
            WriteConsoleEntry("Platform specification revision", PlatformSpecificationRevision.ToString());
            WriteConsoleEntry("Platform specification date", PlatformSpecificationDate.ToString("d"));

            WriteConsoleEntry("Firmware version", FirmwareVersion.ToString());
            WriteConsoleEntry("Physical presence version", PhysicalPresenceVersion);

            WriteConsoleEntry("Memory management", MemoryManagement);
            WriteConsoleEntry("Supported modes", SupportedModes);

            WriteConsoleEntry("Permanent attributes", PermanentAttributes);
            WriteConsoleEntry("Startup attributes", StartupAttributes);
        }

        #region P/Invoke

#pragma warning disable CS0649 // Field is never assigned to
        // ReSharper disable InconsistentNaming
        // ReSharper disable MemberCanBePrivate.Global

        // @formatter:int_align_fields true

        internal enum TBS_RESULT : uint {
            TBS_SUCCESS                    = 0x0,
            TBS_E_INTERNAL_ERROR           = 0x80284001,
            TBS_E_BAD_PARAMETER            = 0x80284002,
            TBS_E_INVALID_OUTPUT_POINTER   = 0x80284003,
            TBS_E_INVALID_CONTEXT          = 0x80284004,
            TBS_E_INSUFFICIENT_BUFFER      = 0x80284005,
            TBS_E_IOERROR                  = 0x80284006,
            TBS_E_INVALID_CONTEXT_PARAM    = 0x80284007,
            TBS_E_SERVICE_NOT_RUNNING      = 0x80284008,
            TBS_E_TOO_MANY_TBS_CONTEXTS    = 0x80284009,
            TBS_E_TOO_MANY_RESOURCES       = 0x8028400A,
            TBS_E_SERVICE_START_PENDING    = 0x8028400B,
            TBS_E_PPI_NOT_SUPPORTED        = 0x8028400C,
            TBS_E_COMMAND_CANCELED         = 0x8028400D,
            TBS_E_BUFFER_TOO_LARGE         = 0x8028400E,
            TBS_E_TPM_NOT_FOUND            = 0x8028400F,
            TBS_E_SERVICE_DISABLED         = 0x80284010,
            TBS_E_NO_EVENT_LOG             = 0x80284011,
            TBS_E_ACCESS_DENIED            = 0x80284012,
            TBS_E_PROVISIONING_NOT_ALLOWED = 0x80284013,
            TBS_E_PPI_FUNCTION_UNSUPPORTED = 0x80284014,
            TBS_E_OWNERAUTH_NOT_FOUND      = 0x80284015,
            TBS_E_PROVISIONING_INCOMPLETE  = 0x80284016
        }

        internal enum TBS_COMMAND_LOCALITY : uint {
            Zero  = 0,
            One   = 1,
            Two   = 2,
            Three = 3,
            Four  = 4
        }

        internal enum TBS_COMMAND_PRIORITY : uint {
            Low    = 100,
            Normal = 200,
            High   = 300,
            System = 400,
            Max    = 0x80000000
        }

        [Flags]
        internal enum TBS_CONTEXT_PARAMS2_FLAGS : uint {
            requestRaw   = 0x1,
            includeTpm12 = 0x2,
            includeTpm20 = 0x4
        }

        internal enum TPM_IFTYPE : uint {
            Unknown     = 0,
            OnePointTwo = 1,
            Trustzone   = 2,
            Hardware    = 3,
            Emulator    = 4,
            Spb         = 5
        }

        internal enum TPM_VERSION : uint {
            Unknown      = 0,
            OnePointTwo  = 1,
            TwoPointZero = 2
        }

        // @formatter:int_align_fields false

        internal struct TPM_DEVICE_INFO {
            internal uint structVersion;
            internal TPM_VERSION tpmVersion;
            internal TPM_IFTYPE tpmInterfaceType;
            internal uint tpmImpRevision;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal sealed class TBS_CONTEXT_PARAMS {
            internal uint version;

            public TBS_CONTEXT_PARAMS() {
                version = 1; // TBS_CONTEXT_VERSION_ONE
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal sealed class TBS_CONTEXT_PARAMS2 {
            internal uint version;
            internal TBS_CONTEXT_PARAMS2_FLAGS flags;

            public TBS_CONTEXT_PARAMS2() {
                version = 2; // TBS_CONTEXT_VERSION_TWO
            }
        }

        [DllImport("tbs", ExactSpelling = true)]
        internal static extern TBS_RESULT Tbsi_Context_Create(TBS_CONTEXT_PARAMS pContextParams, out IntPtr phContext);

        [DllImport("tbs", ExactSpelling = true)]
        internal static extern TBS_RESULT Tbsi_Context_Create(TBS_CONTEXT_PARAMS2 pContextParams, out IntPtr phContext);

        [DllImport("tbs", ExactSpelling = true)]
        internal static extern TBS_RESULT Tbsi_GetDeviceInfo(uint Size, out IntPtr Info);

        [DllImport("tbs", ExactSpelling = true)]
        internal static extern TBS_RESULT Tbsi_Physical_Presence_Command(IntPtr hContext,
                                                                         [System.Runtime.InteropServices.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)]
                                                                         byte[] pabInput,
                                                                         uint cbInput,
                                                                         [System.Runtime.InteropServices.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)]
                                                                         [In]
                                                                         [Out]
                                                                         byte[] pabOutput,
                                                                         ref uint pcbOutput);

        [DllImport("tbs", ExactSpelling = true)]
        internal static extern TBS_RESULT Tbsip_Cancel_Commands(IntPtr hContext);

        [DllImport("tbs", ExactSpelling = true)]
        internal static extern TBS_RESULT Tbsip_Context_Close(IntPtr hContext);

        [DllImport("tbs", ExactSpelling = true)]
        internal static extern TBS_RESULT Tbsip_Submit_Command(IntPtr hContext,
                                                               TBS_COMMAND_LOCALITY Locality,
                                                               TBS_COMMAND_PRIORITY Priority,
                                                               [System.Runtime.InteropServices.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)]
                                                               byte[] pabCommand,
                                                               uint cbCommand,
                                                               [System.Runtime.InteropServices.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6)] [In] [Out]
                                                               byte[] pabResult,
                                                               ref uint pcbResult);

        // ReSharper enable MemberCanBePrivate.Global
        // ReSharper enable InconsistentNaming
#pragma warning restore CS0649 // Field is never assigned to

        #endregion
    }
}
