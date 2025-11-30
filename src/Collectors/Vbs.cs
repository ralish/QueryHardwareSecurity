using System.Collections.Generic;
using System.Linq;

using Microsoft.Management.Infrastructure;

using Newtonsoft.Json;

using static QueryHardwareSecurity.Utilities;

namespace QueryHardwareSecurity.Collectors {
    internal sealed class Vbs : Collector {
        private static readonly string[] CiStatuses = { "Disabled", "Audit mode", "Enforced" };

        private static readonly string[] VbsProperties = {
            "None",
            "Hypervisor support",
            "Secure Boot",
            "DMA protection",
            "Secure Memory Overwrite (MOR v2)",
            "UEFI code read-only (NX)",
            "SMM Security Mitigation Table (WSMT)",
            "Mode-Based Execution Control (MBEC/GMET)",
            "APIC Virtualisation (APICv/AVIC)"
        };

        private static readonly string[] VbsServices = {
            "None",
            "Credential Guard",
            "Memory integrity (HVCI)",
            "System Guard Secure Launch",
            "SMM Firmware Measurement",
            "Kernel-mode Hardware-enforced Stack Protection",
            "Kernel-mode Hardware-enforced Stack Protection (Audit mode)",
            "Hypervisor-enforced Paging Translation (HVPT)"
        };

        private static readonly string[] VbsStatuses = { "Disabled", "Enabled (inactive)", "Enabled (running)" };

        private static readonly List<string> NoneList = new List<string> { "None" };

        public Vbs() : base("Virtualisation-based Security", TableStyle.Basic) {
            RetrieveInfo();
        }

        [JsonProperty]
        public string VbsStatus { get; private set; } = "Unavailable";

        [JsonProperty]
        public List<string> VbsPropsRequired { get; private set; } = new List<string>();

        [JsonProperty]
        public List<string> VbsPropsAvailable { get; private set; } = new List<string>();

        [JsonProperty]
        public List<string> VbsPropsUnavailable { get; private set; } = new List<string>();

        [JsonProperty]
        public List<string> VbsServicesConfigured { get; private set; } = new List<string>();

        [JsonProperty]
        public List<string> VbsServicesRunning { get; private set; } = new List<string>();

        [JsonProperty]
        public List<string> VbsServicesNotConfigured { get; private set; } = new List<string>();

        [JsonProperty]
        public string KmciStatus { get; private set; } = "Unavailable";

        [JsonProperty]
        public string UmciStatus { get; private set; } = "Unavailable";

        private void RetrieveInfo() {
            WriteVerbose($"Retrieving {Name} info ...");

            CimInstance cimInstance;
            try {
                cimInstance = EnumerateCimInstances("Win32_DeviceGuard", "root/Microsoft/Windows/DeviceGuard").First();
            } catch (CimException ex) {
                const uint cimInvalidNamespace = 3;

                // Only available from Windows 10 / Server 2016 and subject to product edition
                if (ex.StatusCode == cimInvalidNamespace) NotSupportedFailure();

                throw;
            }

            var vbsStatusRaw = (uint)cimInstance.CimInstanceProperties["VirtualizationBasedSecurityStatus"].Value;
            VbsStatus = vbsStatusRaw < VbsStatuses.Length
                            ? VbsStatuses[vbsStatusRaw]
                            : $"Unknown security status: {vbsStatusRaw}";

            var vbsPropsRequiredRaw = (uint[])cimInstance.CimInstanceProperties["RequiredSecurityProperties"].Value;
            foreach (var vbsProp in vbsPropsRequiredRaw.Except(new uint[] { 0 })) {
                VbsPropsRequired.Add(vbsProp < VbsProperties.Length
                                         ? VbsProperties[vbsProp]
                                         : $"Unknown security property: {vbsProp}");
            }

            var vbsPropsAvailableRaw = (uint[])cimInstance.CimInstanceProperties["AvailableSecurityProperties"].Value;
            foreach (var vbsProp in vbsPropsAvailableRaw.Except(new uint[] { 0 })) {
                VbsPropsAvailable.Add(vbsProp < VbsProperties.Length
                                          ? VbsProperties[vbsProp]
                                          : $"Unknown security property: {vbsProp}");
            }

            for (uint vbsProp = 1; vbsProp < VbsProperties.Length; vbsProp++) {
                if (!vbsPropsAvailableRaw.Contains(vbsProp)) {
                    VbsPropsUnavailable.Add(VbsProperties[vbsProp]);
                }
            }

            var vbsServicesConfiguredRaw = (uint[])cimInstance.CimInstanceProperties["SecurityServicesConfigured"].Value;
            foreach (var vbsService in vbsServicesConfiguredRaw.Except(new uint[] { 0 })) {
                VbsServicesConfigured.Add(vbsService < VbsServices.Length
                                              ? VbsServices[vbsService]
                                              : $"Unknown security service: {vbsService}");
            }

            var vbsServicesRunningRaw = (uint[])cimInstance.CimInstanceProperties["SecurityServicesRunning"].Value;
            foreach (var vbsService in vbsServicesRunningRaw.Except(new uint[] { 0 })) {
                VbsServicesRunning.Add(vbsService < VbsServices.Length
                                           ? VbsServices[vbsService]
                                           : $"Unknown security service: {vbsService}");
            }

            for (uint vbsService = 1; vbsService < VbsServices.Length; vbsService++) {
                if (!vbsServicesConfiguredRaw.Contains(vbsService)) {
                    VbsServicesNotConfigured.Add(VbsServices[vbsService]);
                }
            }

            // Not present on earlier Windows 10 releases
            var kmciStatusProperty = cimInstance.CimInstanceProperties["CodeIntegrityPolicyEnforcementStatus"];
            if (kmciStatusProperty != null) {
                var kmciStatusRaw = (uint)kmciStatusProperty.Value;
                KmciStatus = kmciStatusRaw < CiStatuses.Length
                                 ? CiStatuses[kmciStatusRaw]
                                 : $"Unknown security status: {kmciStatusRaw}";
            }

            // Not present on earlier Windows 10 releases
            var umciStatusProperty = cimInstance.CimInstanceProperties["UsermodeCodeIntegrityPolicyEnforcementStatus"];
            // ReSharper disable once InvertIf
            if (umciStatusProperty != null) {
                var umciStatusRaw = (uint)umciStatusProperty.Value;
                UmciStatus = umciStatusRaw < CiStatuses.Length
                                 ? CiStatuses[umciStatusRaw]
                                 : $"Unknown security status: {umciStatusRaw}";
            }
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(this);
        }

        internal override void WriteOutput(OutputFormat format, bool color) {
            SetOutputSettings(format, color);
            WriteOutputHeader();

            WriteOutputEntry("VBS status", VbsStatus);
            WriteOutputEntry("Security properties required",
                             VbsPropsRequired.Count != 0 ? VbsPropsRequired : NoneList);
            WriteOutputEntry("Security properties available",
                             VbsPropsAvailable.Count != 0 ? VbsPropsAvailable : NoneList);
            WriteOutputEntry("Security properties unavailable",
                             VbsPropsUnavailable.Count != 0 ? VbsPropsUnavailable : NoneList);
            WriteOutputEntry("Security services configured",
                             VbsServicesConfigured.Count != 0 ? VbsServicesConfigured : NoneList);
            WriteOutputEntry("Security services running",
                             VbsServicesRunning.Count != 0 ? VbsServicesRunning : NoneList);
            WriteOutputEntry("Security services not configured",
                             VbsServicesNotConfigured.Count != 0 ? VbsServicesNotConfigured : NoneList);
            WriteOutputEntry("KMCI status", KmciStatus);
            WriteOutputEntry("UMCI status", UmciStatus);
        }
    }
}
