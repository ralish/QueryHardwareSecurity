using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Management.Infrastructure;

using Newtonsoft.Json;

using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    [JsonObject(MemberSerialization.OptIn)]
    internal class WindowsDefender : Collector {
        // @formatter:off
        private static readonly string[] CiStatuses = {
            "Disabled",
            "Audit mode",
            "Enforced"
        };

        private static readonly string[] VbsProperties = {
            "None",
            "Base Virtualisation Support",
            "Secure Boot",
            "DMA Protection",
            "Secure Memory Overwrite (MOR v2)",
            "UEFI Code Read-only (NX)",
            "SMM Security Mitigations (WSMT)",
            "Mode-Based Execution Control (MBE)",
            "APIC Virtualisation (APICv/AVIC)"
        };

        private static readonly string[] VbsServices = {
            "None",
            "Credential Guard",
            "Hypervisor-protected Code Integrity (HVCI)",
            "System Guard Secure Launch",
            "SMM Firmware Measurement"
        };

        private static readonly string[] VbsStatuses = {
            "Disabled",
            "Enabled (inactive)",
            "Enabled (running)"
        };
        // @formatter:on

        private static readonly List<string> NoneList = new List<string> { "None" };

        [JsonProperty] internal string VbsStatus { get; private set; } = "Unavailable";
        [JsonProperty] internal List<string> VbsPropsRequired { get; private set; } = new List<string>();
        [JsonProperty] internal List<string> VbsPropsAvailable { get; private set; } = new List<string>();
        [JsonProperty] internal List<string> VbsPropsUnavailable { get; private set; } = new List<string>();
        [JsonProperty] internal List<string> VbsServicesConfigured { get; private set; } = new List<string>();
        [JsonProperty] internal List<string> VbsServicesRunning { get; private set; } = new List<string>();
        [JsonProperty] internal List<string> VbsServicesNotConfigured { get; private set; } = new List<string>();
        [JsonProperty] internal string KmciStatus { get; private set; } = "Unavailable";
        [JsonProperty] internal string UmciStatus { get; private set; } = "Unavailable";

        public WindowsDefender() : base("Windows Defender") {
            ConsoleWidthName = 40;
            ConsoleWidthValue = 72;

            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteConsoleVerbose("Retrieving Device Guard info ...");

            CimInstance cimInstance;
            try {
                cimInstance = EnumerateCimInstances("Win32_DeviceGuard", "root/Microsoft/Windows/DeviceGuard").First();
            } catch (CimException ex) {
                if (ex.StatusCode == 3) { // InvalidNamespace
                    // Only available from Windows 10 / Server 2016 and subject to product edition
                    throw new NotImplementedException("DeviceGuard WMI namespace is unavailable.");
                }

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

            var vbsServicesConfiguredRaw =
                (uint[])cimInstance.CimInstanceProperties["SecurityServicesConfigured"].Value;
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

        internal override void WriteConsole(ConsoleOutputStyle style) {
            ConsoleOutputStyle = style;

            WriteConsoleHeader(false);
            WriteConsoleEntry("VBS status", VbsStatus);
            WriteConsoleEntry("Security properties required",
                              VbsPropsRequired.Count != 0 ? VbsPropsRequired : NoneList);
            WriteConsoleEntry("Security properties available",
                              VbsPropsAvailable.Count != 0 ? VbsPropsAvailable : NoneList);
            WriteConsoleEntry("Security properties unavailable",
                              VbsPropsUnavailable.Count != 0 ? VbsPropsUnavailable : NoneList);
            WriteConsoleEntry("Security services configured",
                              VbsServicesConfigured.Count != 0 ? VbsServicesConfigured : NoneList);
            WriteConsoleEntry("Security services running",
                              VbsServicesRunning.Count != 0 ? VbsServicesRunning : NoneList);
            WriteConsoleEntry("Security services not configured",
                              VbsServicesNotConfigured.Count != 0 ? VbsServicesNotConfigured : NoneList);
            WriteConsoleEntry("KMCI status", KmciStatus);
            WriteConsoleEntry("UMCI status", UmciStatus);
        }
    }
}
