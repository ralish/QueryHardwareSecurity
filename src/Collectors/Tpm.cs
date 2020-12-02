using System;

using Newtonsoft.Json;

using Tpm2Lib;


namespace QueryHardwareSecurity.Collectors {
    [JsonObject(MemberSerialization.OptIn)]
    internal class Tpm : Collector {
        [JsonProperty] internal string Manufacturer { get; private set; }
        [JsonProperty] internal DateTime ManufactureDate { get; private set; }
        [JsonProperty] internal Version FirmwareVersion { get; private set; }
        [JsonProperty] internal string SpecificationVersion { get; private set; }

        public Tpm() : base("TPM") {
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
                    WriteConsoleVerbose("Retrieving manufacturer info ...");
                    Tpm2.GetTpmInfo(tpm,
                                    out var tpmManufacturer,
                                    out var tpmManufactureYear,
                                    out var tpmManufactureDayOfYear);
                    Manufacturer = tpmManufacturer;
                    ManufactureDate = new DateTime((int)tpmManufactureYear, 1, 1).AddDays(tpmManufactureDayOfYear);

                    WriteConsoleVerbose("Retrieving version info ...");
                    var tpmFirmwareVersion = tpm.GetFirmwareVersionEx();
                    FirmwareVersion = new Version((int)(tpmFirmwareVersion[0] >> 16),
                                                  (int)(tpmFirmwareVersion[0] & 0xFFFF),
                                                  (int)tpmFirmwareVersion[1] >> 16,
                                                  (int)tpmFirmwareVersion[1] & 0xFFFF);
                    SpecificationVersion = ((double)tpmFirmwareVersion[2] / 100).ToString();
                }
            }
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(this);
        }

        internal override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(false);
            WriteConsoleEntry("Manufacturer", Manufacturer);
            WriteConsoleEntry("Manufacture date", ManufactureDate.ToString());
            WriteConsoleEntry("Firmware version", FirmwareVersion.ToString());
            WriteConsoleEntry("Specification version", SpecificationVersion);
        }
    }
}
