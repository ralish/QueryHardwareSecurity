using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Management.Infrastructure;

using Newtonsoft.Json;

using static QueryHardwareSecurity.Utilities;

namespace QueryHardwareSecurity.Collectors {
    /*
     * Virtualisation-based Security
     *
     * Introduced:  Windows 10 1507, Windows Server 2016
     * Platforms:   ARM64, x86-64
     */
    internal sealed class Vbs : Collector {
        private static readonly List<string> NoneList = new List<string> { "None" };

        private static readonly string[] CiStatuses = { "Disabled", "Audit mode", "Enforced" };

        private static readonly string[] SecurityFeatures = { "None", "Return Address Signing (Kernel-mode)" };

        private static readonly string[] VbsStatuses = { "Disabled", "Enabled (inactive)", "Enabled (running)" };

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

        private static readonly string[] VmIsolationAllProperties = { "None", "AMD SEV-SNP", "Virtualization-based Security", "Intel TDX" };

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
        public bool? VmIsolationStatus { get; private set; }

        [JsonProperty]
        public List<string>? VmIsolationProperties { get; private set; }

        [JsonProperty]
        public List<string>? SecurityFeaturesEnabled { get; private set; }

        [JsonProperty]
        public string? SmmIsolationLevel { get; private set; }

        [JsonProperty]
        public string? KmciStatus { get; private set; }

        [JsonProperty]
        public string? UmciStatus { get; private set; }

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

            var classVersion = (string)cimInstance.CimInstanceProperties["Version"].Value;
            if (classVersion != "1.0") {
                var msg = $"Unexpected Win32_DeviceGuard class version: {classVersion}";
                WriteError(msg);
                throw new NotSupportedException(msg);
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

            // Introduced in later Windows releases
            var vmIsolationStatusProperty = cimInstance.CimInstanceProperties["VirtualMachineIsolation"];
            if (vmIsolationStatusProperty != null) {
                VmIsolationStatus = (bool)vmIsolationStatusProperty.Value;
                VmIsolationProperties = new List<string>();

                var vmIsolationPropertiesRaw = (uint[])cimInstance.CimInstanceProperties["VirtualMachineIsolationProperties"].Value;
                foreach (var vmIsolationProperty in vmIsolationPropertiesRaw.Except(new uint[] { 0 })) {
                    VmIsolationProperties.Add(vmIsolationProperty < VmIsolationAllProperties.Length
                                                  ? VmIsolationAllProperties[vmIsolationProperty]
                                                  : $"Unknown VM isolation property: {vmIsolationProperty}");
                }
            }

            // Introduced in later Windows releases
            var secFeatEnabledProperty = cimInstance.CimInstanceProperties["SecurityFeaturesEnabled"];
            if (secFeatEnabledProperty != null) {
                SecurityFeaturesEnabled = new List<string>();

                var secFeatEnabledRaw = (uint[])secFeatEnabledProperty.Value;
                foreach (var secFeatEnabled in secFeatEnabledRaw.Except(new uint[] { 0 })) {
                    SecurityFeaturesEnabled.Add(secFeatEnabled < SecurityFeatures.Length
                                                    ? SecurityFeatures[secFeatEnabled]
                                                    : $"Unknown security feature: {secFeatEnabled}");
                }
            }

            // Introduced in later Windows releases
            var smmIsolationLevelProperty = cimInstance.CimInstanceProperties["SmmIsolationLevel"];
            if (smmIsolationLevelProperty != null) {
                var level = (byte)smmIsolationLevelProperty.Value;

                switch (level) {
                    case 0:
                        SmmIsolationLevel = "None";
                        break;
                    case 10:
                    case 20:
                    case 30:
                        SmmIsolationLevel = $"Firmware Protection Version {level / 10}";
                        break;
                    default:
                        SmmIsolationLevel = $"Unknown Firmware Protection Version: {level}";
                        break;
                }
            }

            // Introduced in later Windows releases
            var kmciStatusProperty = cimInstance.CimInstanceProperties["CodeIntegrityPolicyEnforcementStatus"];
            if (kmciStatusProperty != null) {
                var kmciStatusRaw = (uint)kmciStatusProperty.Value;
                KmciStatus = kmciStatusRaw < CiStatuses.Length
                                 ? CiStatuses[kmciStatusRaw]
                                 : $"Unknown security status: {kmciStatusRaw}";
            }

            // Introduced in later Windows releases
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

        public bool ShouldSerializeVmIsolationStatus() => VmIsolationStatus != null;

        public bool ShouldSerializeVmIsolationProperties() => VmIsolationProperties != null;

        public bool ShouldSerializeSecurityFeaturesEnabled() => SecurityFeaturesEnabled != null;

        public bool ShouldSerializeSmmIsolationLevel() => SmmIsolationLevel != null;

        public bool ShouldSerializeKmciStatus() => KmciStatus != null;

        public bool ShouldSerializeUmciStatus() => UmciStatus != null;

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

            if (VmIsolationStatus != null) {
                WriteOutputEntry("VM isolation status", VmIsolationStatus);
                WriteOutputEntry("VM isolation properties",
                                 VmIsolationProperties!.Count != 0 ? VmIsolationProperties : NoneList);
            }

            if (SecurityFeaturesEnabled != null) {
                WriteOutputEntry("Security features enabled",
                                 SecurityFeaturesEnabled.Count != 0 ? SecurityFeaturesEnabled : NoneList);
            }

            if (SmmIsolationLevel != null) WriteOutputEntry("SMM isolation level", SmmIsolationLevel);
            if (KmciStatus != null) WriteOutputEntry("KMCI status", KmciStatus);
            if (UmciStatus != null) WriteOutputEntry("UMCI status", UmciStatus);
        }
    }
}
