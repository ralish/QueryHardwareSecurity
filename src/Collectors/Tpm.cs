using System;
using System.ComponentModel;
using System.Text;

using Newtonsoft.Json;

using Tpm2Lib;

using static QueryHardwareSecurity.NativeMethods;


namespace QueryHardwareSecurity.Collectors {
    [JsonObject(MemberSerialization.OptIn)]
    internal class Tpm : Collector {
        [JsonProperty] internal uint ManufacturerId { get; private set; }
        [JsonProperty] internal string ManufacturerName { get; private set; }
        [JsonProperty] internal uint ManufacturerModel { get; private set; }

        [JsonProperty] internal string SpecificationVersion { get; private set; }
        [JsonProperty] internal uint SpecificationLevel { get; private set; }
        [JsonProperty] internal float SpecificationRevision { get; private set; }
        [JsonProperty] internal DateTime SpecificationDate { get; private set; }

        [JsonProperty] internal string PlatformSpecificFamily { get; private set; }
        [JsonProperty] internal uint PlatformSpecificationLevel { get; private set; }
        [JsonProperty] internal float PlatformSpecificationRevision { get; private set; }
        [JsonProperty] internal DateTime PlatformSpecificationDate { get; private set; }

        [JsonProperty] internal Version FirmwareVersion { get; private set; }
        [JsonProperty] internal string PhysicalPresenceVersion { get; private set; }

        [JsonProperty] internal string MemoryManagement { get; private set; }
        [JsonProperty] internal string SupportedModes { get; private set; }

        [JsonProperty] internal string PermanentAttributes { get; private set; }
        [JsonProperty] internal string StartupAttributes { get; private set; }

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
                    uint tpmProperty;
                    TaggedTpmPropertyArray tpmProperties;

                    WriteConsoleDebug("Retrieving TPM capability: TPM_PROPERTIES (Property: PT_FIXED)");
                    tpm.GetCapability(Cap.TpmProperties, (uint)Pt.PtFixed, 1000, out var capPropertiesFixed);
                    tpmProperties = (TaggedTpmPropertyArray)capPropertiesFixed;

                    #region Manufacturer

                    ManufacturerId = tpmProperties.tpmProperty[Pt.Manufacturer - Pt.PtFixed].value;

                    var tpmManufacturerBytes = BitConverter.GetBytes(ManufacturerId);
                    Array.Reverse(tpmManufacturerBytes); // Assumes little-endian
                    var tpmManufacturerName = new char[tpmManufacturerBytes.Length];
                    for (int index = 0; index < tpmManufacturerName.Length; index++) {
                        // Unprintable character or invalid 7-bit ASCII
                        if (tpmManufacturerBytes[index] < 32 || tpmManufacturerBytes[index] > 126) {
                            break;
                        }

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
            var ppiVersionCommand = new byte[] {0x01, 0x00, 0x00, 0x00};
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
            if (tbsResult != TBS_RESULT.TBS_SUCCESS) {
                throw new Win32Exception($"TBS API returned: {tbsResult}");
            }
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(this);
        }

        internal override void WriteConsole(ConsoleOutputStyle style) {
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
    }
}
