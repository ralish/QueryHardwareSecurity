using System;
using System.Text;

using Newtonsoft.Json;

using Tpm2Lib;


namespace QueryHardwareSecurity.Collectors {
    [JsonObject(MemberSerialization.OptIn)]
    internal class Tpm : Collector {
        [JsonProperty] internal string SpecificationVersion { get; private set; }
        [JsonProperty] internal uint SpecificationLevel { get; private set; }
        [JsonProperty] internal float SpecificationRevision { get; private set; }
        [JsonProperty] internal DateTime SpecificationDate { get; private set; }

        [JsonProperty] internal uint ManufacturerId { get; private set; }
        [JsonProperty] internal string ManufacturerName { get; private set; }

        [JsonProperty] internal Version FirmwareVersion { get; private set; }

        public Tpm() : base("Trusted Platform Module") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 72;

            RetrieveTpmInfo();
        }

        private void RetrieveTpmInfo() {
            WriteConsoleVerbose("Retrieving TPM info ...");

            using (var tpmDevice = new TbsDevice()) {
                WriteConsoleVerbose("Connecting to TPM ...");
                tpmDevice.Connect();

                using (var tpm = new Tpm2(tpmDevice)) {
                    WriteConsoleVerbose("Retrieving TPM capability: TPM_PROPERTIES");
                    tpm.GetCapability(Cap.TpmProperties, (uint)Pt.PtFixed, 1000, out var capability);
                    var tpmProperties = (TaggedTpmPropertyArray)capability;
                    const Pt tpmArrayOffset = Pt.PtFixed;

                    var tpmProperty = tpmProperties.tpmProperty[Pt.FamilyIndicator - tpmArrayOffset].value;
                    var tpmFamilyIndicator = BitConverter.GetBytes(tpmProperty);
                    Array.Reverse(tpmFamilyIndicator);
                    SpecificationVersion = Encoding.ASCII.GetString(tpmFamilyIndicator).Trim('\0');

                    SpecificationLevel = tpmProperties.tpmProperty[Pt.Level - tpmArrayOffset].value;

                    tpmProperty = tpmProperties.tpmProperty[Pt.Revision - tpmArrayOffset].value;
                    SpecificationRevision = (float)tpmProperty / 100;

                    tpmProperty = tpmProperties.tpmProperty[Pt.Year - tpmArrayOffset].value;
                    SpecificationDate = new DateTime((int)tpmProperty, 1, 1);
                    tpmProperty = tpmProperties.tpmProperty[Pt.DayOfYear - tpmArrayOffset].value;
                    SpecificationDate = SpecificationDate.AddDays(tpmProperty);

                    ManufacturerId = tpmProperties.tpmProperty[Pt.Manufacturer - tpmArrayOffset].value;

                    var tpmManufacturerName = new byte[16];
                    for (int vendorStringIdx = 0; vendorStringIdx < 4; vendorStringIdx++) {
                        var tpmPropertyIdx = (int)(Pt.VendorString1 - tpmArrayOffset) + vendorStringIdx;
                        tpmProperty = tpmProperties.tpmProperty[tpmPropertyIdx].value;

                        var vendorString = BitConverter.GetBytes(tpmProperty);
                        Array.Reverse(vendorString);
                        vendorString.CopyTo(tpmManufacturerName, vendorStringIdx * 4);
                    }
                    ManufacturerName = Encoding.ASCII.GetString(tpmManufacturerName).Trim('\0');

                    var tpmFirmwareVersion = new uint[2];
                    tpmFirmwareVersion[0] = tpmProperties.tpmProperty[Pt.FirmwareVersion1 - tpmArrayOffset].value;
                    tpmFirmwareVersion[1] = tpmProperties.tpmProperty[Pt.FirmwareVersion2 - tpmArrayOffset].value;
                    FirmwareVersion = new Version((int)(tpmFirmwareVersion[0] >> 16),
                                                  (int)(tpmFirmwareVersion[0] & 0xFFFF),
                                                  (int)tpmFirmwareVersion[1] >> 16,
                                                  (int)tpmFirmwareVersion[1] & 0xFFFF);
                }
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
            WriteConsoleEntry("Manufacturer ID", ManufacturerId.ToString());
            WriteConsoleEntry("Manufacturer Name", ManufacturerName);
            WriteConsoleEntry("Firmware version", FirmwareVersion.ToString());
        }
    }
}
