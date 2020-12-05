using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

using Newtonsoft.Json;

using Tpm2Lib;

using static QueryHardwareSecurity.NativeMethods;


namespace QueryHardwareSecurity.Collectors {
    [JsonObject(MemberSerialization.OptIn)]
    internal class Tpm : Collector {
        [JsonProperty] internal string SpecificationVersion { get; private set; }
        [JsonProperty] internal uint SpecificationLevel { get; private set; }
        [JsonProperty] internal float SpecificationRevision { get; private set; }
        [JsonProperty] internal DateTime SpecificationDate { get; private set; }

        [JsonProperty] internal string PlatformSpecificFamily { get; private set; }
        [JsonProperty] internal uint PlatformSpecificationLevel { get; private set; }
        [JsonProperty] internal float PlatformSpecificationRevision { get; private set; }
        [JsonProperty] internal DateTime PlatformSpecificationDate { get; private set; }

        [JsonProperty] internal uint ManufacturerId { get; private set; }
        [JsonProperty] internal string ManufacturerName { get; private set; }

        [JsonProperty] internal Version FirmwareVersion { get; private set; }
        [JsonProperty] internal string PhysicalPresenceVersion { get; private set; }

        public Tpm() : base("Trusted Platform Module") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 72;

            RetrieveTpmInfo();
        }

        private void RetrieveTpmInfo() {
            WriteConsoleVerbose("Retrieving TPM info ...");
            RetrieveTpmProperties();
            RetrieveTpmPpiInfo();
        }

        private void RetrieveTpmProperties() {
            WriteConsoleVerbose("Retrieving TPM properties ...");

            using (var tpmDevice = new TbsDevice()) {
                WriteConsoleDebug("Connecting to TPM ...");
                tpmDevice.Connect();

                using (var tpm = new Tpm2(tpmDevice)) {
                    WriteConsoleDebug("Retrieving TPM capability: TPM_PROPERTIES");

                    uint tpmProperty;
                    const Pt tpmArrayOffset = Pt.PtFixed;

                    tpm.GetCapability(Cap.TpmProperties, (uint)Pt.PtFixed, 1000, out var capability);
                    var tpmProperties = (TaggedTpmPropertyArray)capability;

                    #region Specification

                    tpmProperty = tpmProperties.tpmProperty[Pt.FamilyIndicator - tpmArrayOffset].value;
                    var tpmFamilyIndicator = BitConverter.GetBytes(tpmProperty);

                    Array.Reverse(tpmFamilyIndicator);
                    SpecificationVersion = Encoding.ASCII.GetString(tpmFamilyIndicator).Trim('\0');

                    SpecificationLevel = tpmProperties.tpmProperty[Pt.Level - tpmArrayOffset].value;

                    tpmProperty = tpmProperties.tpmProperty[Pt.Revision - tpmArrayOffset].value;
                    SpecificationRevision = (float)tpmProperty / 100;

                    tpmProperty = tpmProperties.tpmProperty[Pt.Year - tpmArrayOffset].value;
                    SpecificationDate = new DateTime((int)tpmProperty - 1, 12, 31);
                    tpmProperty = tpmProperties.tpmProperty[Pt.DayOfYear - tpmArrayOffset].value;
                    SpecificationDate = SpecificationDate.AddDays(tpmProperty);

                    #endregion

                    #region Platform-specific

                    tpmProperty = tpmProperties.tpmProperty[Pt.PsFamilyIndicator - tpmArrayOffset].value;
                    PlatformSpecificFamily = ((Ps)tpmProperty).ToString();

                    PlatformSpecificationLevel = tpmProperties.tpmProperty[Pt.PsLevel - tpmArrayOffset].value;

                    tpmProperty = tpmProperties.tpmProperty[Pt.PsRevision - tpmArrayOffset].value;
                    PlatformSpecificationRevision = (float)tpmProperty / 100;

                    tpmProperty = tpmProperties.tpmProperty[Pt.PsYear - tpmArrayOffset].value;
                    PlatformSpecificationDate = new DateTime((int)tpmProperty - 1, 12, 31);
                    tpmProperty = tpmProperties.tpmProperty[Pt.PsDayOfYear - tpmArrayOffset].value;
                    PlatformSpecificationDate = SpecificationDate.AddDays(tpmProperty);

                    #endregion

                    #region Manufacturer

                    ManufacturerId = tpmProperties.tpmProperty[Pt.Manufacturer - tpmArrayOffset].value;

                    var tpmManufacturerBytes = BitConverter.GetBytes(ManufacturerId);
                    Array.Reverse(tpmManufacturerBytes);
                    var tpmManufacturerName = new char[tpmManufacturerBytes.Length];
                    for (int index = 0; index < tpmManufacturerName.Length; index++) {
                        // Unprintable character or invalid 7-bit ASCII
                        if (tpmManufacturerBytes[index] < 32 || tpmManufacturerBytes[index] > 126) {
                            break;
                        }

                        tpmManufacturerName[index] = Convert.ToChar(tpmManufacturerBytes[index]);
                    }
                    ManufacturerName = new string(tpmManufacturerName).Trim();

                    #endregion

                    #region Firmware

                    var tpmFirmwareVersion = new uint[2];
                    tpmFirmwareVersion[0] = tpmProperties.tpmProperty[Pt.FirmwareVersion1 - tpmArrayOffset].value;
                    tpmFirmwareVersion[1] = tpmProperties.tpmProperty[Pt.FirmwareVersion2 - tpmArrayOffset].value;
                    FirmwareVersion = new Version((int)(tpmFirmwareVersion[0] >> 16),
                                                  (int)(tpmFirmwareVersion[0] & 0xFFFF),
                                                  (int)tpmFirmwareVersion[1] >> 16,
                                                  (int)tpmFirmwareVersion[1] & 0xFFFF);

                    #endregion
                }
            }
        }

        private void RetrieveTpmPpiInfo() {
            WriteConsoleDebug("Creating TBS context ...");
            var tbsContextParams = new TBS_CONTEXT_PARAMS2 {
                flags = TBS_CONTEXT_PARAMS2_FLAGS.includeTpm12 | TBS_CONTEXT_PARAMS2_FLAGS.includeTpm20
            };
            CheckTbsResultSuccess(Tbsi_Context_Create(tbsContextParams, out var tbsContext));

            WriteConsoleVerbose("Retrieving PPI version ...");
            var ppiVersionCommand = new byte[] {0x01, 0x00, 0x00, 0x00};
            var ppiVersionOutput = new byte[16];
            var ppiVersionOutputLength = (uint)ppiVersionOutput.Length;
            CheckTbsResultSuccess(Tbsi_Physical_Presence_Command(tbsContext,
                                                                 ppiVersionCommand,
                                                                 (uint)ppiVersionCommand.Length,
                                                                 ppiVersionOutput,
                                                                 ref ppiVersionOutputLength));
            PhysicalPresenceVersion = Encoding.ASCII.GetString(ppiVersionOutput).Trim('\0');

            WriteConsoleDebug("Closing TBS context ...");
            CheckTbsResultSuccess(Tbsip_Context_Close(tbsContext));
        }

        private static void CheckTbsResultSuccess(TBS_RESULT tbsResult) {
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

            WriteConsoleEntry("Specification version", SpecificationVersion);
            WriteConsoleEntry("Specification level", SpecificationLevel.ToString());
            WriteConsoleEntry("Specification revision", SpecificationRevision.ToString());
            WriteConsoleEntry("Specification date", SpecificationDate.ToString("d"));

            WriteConsoleEntry("Platform-specific family", PlatformSpecificFamily);
            WriteConsoleEntry("Platform specification level", PlatformSpecificationLevel.ToString());
            WriteConsoleEntry("Platform specification revision", PlatformSpecificationRevision.ToString());
            WriteConsoleEntry("Platform specification date", PlatformSpecificationDate.ToString("d"));

            WriteConsoleEntry("Manufacturer ID", ManufacturerId.ToString());
            WriteConsoleEntry("Manufacturer Name", ManufacturerName);

            WriteConsoleEntry("Firmware version", FirmwareVersion.ToString());
            WriteConsoleEntry("Physical presence version", PhysicalPresenceVersion);
        }
    }
}
