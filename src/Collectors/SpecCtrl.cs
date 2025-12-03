using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace QueryHardwareSecurity.Collectors {
    internal sealed class SpecCtrl : Collector {
        private const int SpeculationControlInfoClass = 0xC9;

        private SpeculationControlInfo _specCtrlInfo;

        public SpecCtrl() : base("Speculation Control", TableStyle.Full) {
            RetrieveInfo();
        }

        private void RetrieveInfo() {
            WriteVerbose($"Retrieving {Name} info ...");

            var specCtrlInfoLength = Marshal.SizeOf<SpeculationControlInfo>();

            var ntStatus = NtQuerySystemInformation(SpeculationControlInfoClass, out var specCtrlInfo, (uint)specCtrlInfoLength, out var returnLength);
            if (ntStatus != 0) NtQsiFailure(ntStatus);
            WriteDebug($"Size of {nameof(SpeculationControlInfo)} structure: {returnLength} bytes");

            var specCtrlFlags = new SpeculationControlFlags { _RawBits = (uint)specCtrlInfo };
            WriteDebug($"Flags: 0x{specCtrlFlags._RawBits:X8}");

            var specCtrlFlags2 = returnLength == 8 ? new SpeculationControlFlags2 { _RawBits = (uint)(specCtrlInfo >> 32) } : new SpeculationControlFlags2();
            WriteDebug($"Flags2: 0x{specCtrlFlags2._RawBits:X8}");

            _specCtrlInfo = new SpeculationControlInfo { Flags = specCtrlFlags, Flags2 = specCtrlFlags2 };
        }

        internal override string ConvertToJson() {
            return JsonConvert.SerializeObject(_specCtrlInfo);
        }

        internal override void WriteOutput(OutputFormat format, bool color) {
            SetOutputSettings(format, color);
            WriteOutputHeader();

            /*
             * Branch Target Injection (BTI)
             * Aka. Spectre: Variant 2
             *
             * Affects:     AMD, ARM, Intel
             * CVE IDs:     CVE-2017-5715
             */

            var bpbEnabled = _specCtrlInfo.Flags.BpbEnabled;
            var bpbDisabledSystemPolicy = _specCtrlInfo.Flags.BpbDisabledSystemPolicy;
            var bpbDisabledNoHwSupport = _specCtrlInfo.Flags.BpbDisabledNoHardwareSupport;

            // Successfully calling the NtQuerySystemInformation API with the
            // SpeculationControl information class implies the system has at
            // least the initial support which covers Spectre: Variant 2. If
            // neither bpbDisabledSystemPolicy nor bpbDisabledNoHwSupport are
            // set we can thus safely assume the system is secure, even if the
            // bit for the mitigations themselves is not enabled.
            var bpbEnabledSecure = bpbEnabled || !(bpbDisabledSystemPolicy || bpbDisabledNoHwSupport);

            WriteOutputEntry("BpbEnabled", bpbEnabled, bpbEnabledSecure);
            WriteOutputEntry("BpbDisabledSystemPolicy", bpbDisabledSystemPolicy, !bpbDisabledSystemPolicy);
            WriteOutputEntry("BpbDisabledNoHardwareSupport", bpbDisabledNoHwSupport, !bpbDisabledNoHwSupport);

            /*
             * Speculation control processor features (Part 1)
             *
             * Affects:     AMD, Intel
             */

            var specCtrlEnumerated = _specCtrlInfo.Flags.SpecCtrlEnumerated;
            var specCmdEnumerated = _specCtrlInfo.Flags.SpecCmdEnumerated;
            var ibrsPresent = _specCtrlInfo.Flags.IbrsPresent;
            var stibpPresent = _specCtrlInfo.Flags.StibpPresent;
            var smepPresent = _specCtrlInfo.Flags.SmepPresent;

            // None of these features are applicable to ARM processors
            var specCtrlEnumeratedSecure = specCtrlEnumerated || SystemInfo.IsProcessorArm;
            var specCmdEnumeratedSecure = specCmdEnumerated || SystemInfo.IsProcessorArm;
            var ibrsPresentSecure = ibrsPresent || SystemInfo.IsProcessorArm;
            var stibpPresentSecure = stibpPresent || SystemInfo.IsProcessorArm;
            var smepPresentSecure = smepPresent || SystemInfo.IsProcessorArm;

            WriteOutputEntry("SpecCtrlEnumerated", specCtrlEnumerated, specCtrlEnumeratedSecure);
            WriteOutputEntry("SpecCmdEnumerated", specCmdEnumerated, specCmdEnumeratedSecure);
            WriteOutputEntry("IbrsPresent", ibrsPresent, ibrsPresentSecure);
            WriteOutputEntry("StibpPresent", stibpPresent, stibpPresentSecure);
            WriteOutputEntry("SmepPresent", smepPresent, smepPresentSecure);

            /*
             * Speculative Store Bypass (SSB)
             * Aka. Spectre-NG: Variant 4
             *
             * Affects:     AMD, ARM, Intel
             * CVE IDs:     CVE-2018-3639
             */

            var ssbdAvailable = _specCtrlInfo.Flags.SpeculativeStoreBypassDisableAvailable;
            var ssbdSupported = ssbdAvailable ? (bool?)_specCtrlInfo.Flags.SpeculativeStoreBypassDisableSupported : null;
            var ssbdRequired = ssbdAvailable ? (bool?)_specCtrlInfo.Flags.SpeculativeStoreBypassDisableRequired : null;
            var ssbdSystemWide = ssbdAvailable ? (bool?)_specCtrlInfo.Flags.SpeculativeStoreBypassDisabledSystemWide : null;
            var ssbdKernel = ssbdAvailable ? (bool?)_specCtrlInfo.Flags.SpeculativeStoreBypassDisabledKernel : null;

            var ssbdSupportedSecure = false;
            var ssbdRequiredSecure = false;
            var ssbdSystemWideSecure = false;
            var ssbdKernelSecure = false;

            if (ssbdAvailable) {
                ssbdSupportedSecure = ssbdSupported.Value;
                ssbdRequiredSecure = !ssbdRequired.Value;

                // ARM builds of Windows don't appear to ever set these bits,
                // but the mitigation is always enabled per Microsoft docs.
                ssbdSystemWideSecure = !ssbdRequired.Value || ssbdSystemWide.Value || SystemInfo.IsProcessorArm;
                ssbdKernelSecure = !ssbdRequired.Value || ssbdSystemWide.Value || ssbdKernel.Value || SystemInfo.IsProcessorArm;
            }

            WriteOutputEntry("SpeculativeStoreBypassDisableAvailable", ssbdAvailable, ssbdAvailable);
            WriteOutputEntry("SpeculativeStoreBypassDisableSupported", ssbdSupported, ssbdSupportedSecure);
            WriteOutputEntry("SpeculativeStoreBypassDisabledSystemWide", ssbdSystemWide, ssbdSystemWideSecure);
            WriteOutputEntry("SpeculativeStoreBypassDisabledKernel", ssbdKernel, ssbdKernelSecure);
            WriteOutputEntry("SpeculativeStoreBypassDisableRequired", ssbdRequired, ssbdRequiredSecure);

            /*
             * Additional BTI settings
             */

            var bpbDisabledKernelToUser = _specCtrlInfo.Flags.BpbDisabledKernelToUser;

            WriteOutputEntry("BpbDisabledKernelToUser", bpbDisabledKernelToUser, !bpbDisabledKernelToUser);

            /*
             * Performance optimisations
             */

            var specCtrlRetpolineEnabled = _specCtrlInfo.Flags.SpecCtrlRetpolineEnabled;
            var specCtrlImportOptimizationEnabled = _specCtrlInfo.Flags.SpecCtrlImportOptimizationEnabled;

            WriteOutputEntry("SpecCtrlRetpolineEnabled", specCtrlRetpolineEnabled);
            WriteOutputEntry("SpecCtrlImportOptimizationEnabled", specCtrlImportOptimizationEnabled);

            /*
             * Speculation control processor features (Part 2)
             *
             * Affects:     Intel
             */

            // Output after the L1TF mitigations but we need to retrieve the
            // value now so we can determine if EnhancedIbrs was actually set.
            var enhancedIbrsReported = _specCtrlInfo.Flags.EnhancedIbrsReported;

            var enhancedIbrs = enhancedIbrsReported ? (bool?)_specCtrlInfo.Flags.EnhancedIbrs : null;

            // Override the EIBRS secure status for non-Intel processors as the
            // feature is specific to Intel processors.
            var enhancedIbrsSecure = (enhancedIbrsReported && enhancedIbrs.Value) || !SystemInfo.IsProcessorIntel;

            WriteOutputEntry("EnhancedIbrs", enhancedIbrs, enhancedIbrsSecure);

            /*
             * L1 Terminal Fault
             * Aka. Foreshadow-NG: VMM
             *
             * Affects:     Intel
             * CVE IDs:     CVE-2018-3620
             *
             * Although this vulnerability isn't applicable to ARM builds of
             * Windows the bits are correctly set.
             *
             * See the comments on L1TF in the KvaShadow collector for
             * additional detection information.
             */

            var hvL1tfStatusAvailable = _specCtrlInfo.Flags.HvL1tfStatusAvailable;
            var hvL1tfProcessorNotAffected = hvL1tfStatusAvailable ? (bool?)_specCtrlInfo.Flags.HvL1tfProcessorNotAffected : null;
            var hvL1tfMitigationEnabled = hvL1tfStatusAvailable ? (bool?)_specCtrlInfo.Flags.HvL1tfMitigationEnabled : null;
            var hvL1tfMitigationNotEnabledHw = hvL1tfStatusAvailable ? (bool?)_specCtrlInfo.Flags.HvL1tfMigitationNotEnabled_Hardware : null;
            var hvL1tfMitigationNotEnabledLo = hvL1tfStatusAvailable ? (bool?)_specCtrlInfo.Flags.HvL1tfMigitationNotEnabled_LoadOption : null;
            var hvL1tfMitigationNotEnabledCore = hvL1tfStatusAvailable ? (bool?)_specCtrlInfo.Flags.HvL1tfMigitationNotEnabled_CoreScheduler : null;

            bool hvL1tfProcessorNotAffectedSecure;
            bool hvL1tfMitigationEnabledSecure;
            bool hvL1tfMitigationNotEnabledHwSecure;
            bool hvL1tfMitigationNotEnabledLoSecure;

            if (hvL1tfStatusAvailable) {
                hvL1tfProcessorNotAffectedSecure = hvL1tfProcessorNotAffected.Value || !SystemInfo.IsProcessorIntel;
                hvL1tfMitigationEnabledSecure = hvL1tfProcessorNotAffected.Value || hvL1tfMitigationEnabled.Value || !SystemInfo.IsProcessorIntel;
                hvL1tfMitigationNotEnabledHwSecure = !hvL1tfMitigationNotEnabledHw.Value;
                hvL1tfMitigationNotEnabledLoSecure = !hvL1tfMitigationNotEnabledLo.Value;
            } else {
                // For unpatched systems using a non-Intel processor be a
                // little cheeky and mark the status as secure anyway.
                hvL1tfProcessorNotAffectedSecure = !SystemInfo.IsProcessorIntel;
                hvL1tfMitigationEnabledSecure = !SystemInfo.IsProcessorIntel;
                hvL1tfMitigationNotEnabledHwSecure = !SystemInfo.IsProcessorIntel;
                hvL1tfMitigationNotEnabledLoSecure = !SystemInfo.IsProcessorIntel;
            }

            WriteOutputEntry("HvL1tfStatusAvailable", hvL1tfStatusAvailable, hvL1tfStatusAvailable);
            WriteOutputEntry("HvL1tfProcessorNotAffected", hvL1tfProcessorNotAffected, hvL1tfProcessorNotAffectedSecure);
            WriteOutputEntry("HvL1tfMitigationEnabled", hvL1tfMitigationEnabled, hvL1tfMitigationEnabledSecure);
            WriteOutputEntry("HvL1tfMigitationNotEnabled_Hardware", hvL1tfMitigationNotEnabledHw, hvL1tfMitigationNotEnabledHwSecure);
            WriteOutputEntry("HvL1tfMigitationNotEnabled_LoadOption", hvL1tfMitigationNotEnabledLo, hvL1tfMitigationNotEnabledLoSecure);
            WriteOutputEntry("HvL1tfMigitationNotEnabled_CoreScheduler", hvL1tfMitigationNotEnabledCore);

            /*
             * See earlier speculation control processor features (Part 2)
             *
             * Affects:     Intel
             */

            // Override the EIBRS reported secure status on ARM systems as
            // Windows never sets this bit (and the feature isn't applicable).
            var enhancedIbrsReportedSecure = enhancedIbrsReported || SystemInfo.IsProcessorArm;

            WriteOutputEntry("EnhancedIbrsReported", enhancedIbrsReported, enhancedIbrsReportedSecure);

            /*
             * Microarchitectural Data Sampling (MDS)
             * Aka. CacheOut, Fallout, RIDL, ZombieLoad
             *
             * Affects:     Intel
             * CVE IDs:     CVE-2018-12126, CVE-2018-12127, CVE-2018-12130, CVE-2019-11091, CVE-2019-11135, CVE-2020-0548, CVE-2020-0549
             *
             * Although this vulnerability isn't applicable to ARM builds of
             * Windows the bits are correctly set.
             */

            var mbClearReported = _specCtrlInfo.Flags.MbClearReported;
            var mdsHwProtected = mbClearReported ? (bool?)_specCtrlInfo.Flags.MdsHardwareProtected : null;
            var mbClearEnabled = mbClearReported ? (bool?)_specCtrlInfo.Flags.MbClearEnabled : null;

            bool mdsHwProtectedSecure;
            bool mbClearEnabledSecure;

            if (mbClearReported) {
                // The mdsHwProtected bit is not set on non-Intel processors
                // even when mbClearReported is set.
                mdsHwProtectedSecure = mdsHwProtected.Value || !SystemInfo.IsProcessorIntel;
                mbClearEnabledSecure = mdsHwProtected.Value || mbClearEnabled.Value || !SystemInfo.IsProcessorIntel;
            } else {
                // For unpatched systems using a non-Intel processor be a
                // little cheeky and mark the status as secure anyway.
                mdsHwProtectedSecure = !SystemInfo.IsProcessorIntel;
                mbClearEnabledSecure = !SystemInfo.IsProcessorIntel;
            }

            WriteOutputEntry("MdsHardwareProtected", mdsHwProtected, mdsHwProtectedSecure);
            WriteOutputEntry("MbClearEnabled", mbClearEnabled, mbClearEnabledSecure);
            WriteOutputEntry("MbClearReported", mbClearReported, mbClearReported);

            /*
             * TSX Asynchronous Abort (TAA)
             * Aka. RIDL, ZombieLoad v2
             *
             * Affects:     Intel
             * CVE IDs:     CVE-2019-11135
             */

            var tsxCtrlReported = _specCtrlInfo.Flags.TsxCtrlReported;
            var tsxCtrlRtmDisabled = tsxCtrlReported ? (bool?)_specCtrlInfo.Flags.TsxCtrlRtmDisabled : null;
            var tsxCtrlRtmAndHleEnumDisabled = tsxCtrlReported ? (bool?)_specCtrlInfo.Flags.TsxCtrlRtmAndHleEnumDisabled : null;
            var taaHwImmune = tsxCtrlReported ? (bool?)_specCtrlInfo.Flags.TaaHardwareImmune : null;

            bool tsxCtrlReportedSecure;
            bool tsxCtrlRtmDisabledSecure;
            bool tsxCtrlRtmAndHleEnumDisabledSecure;
            bool taaHwImmuneSecure;

            if (tsxCtrlReported) {
                tsxCtrlReportedSecure = true;
                tsxCtrlRtmDisabledSecure = tsxCtrlRtmDisabled.Value;
                tsxCtrlRtmAndHleEnumDisabledSecure = tsxCtrlRtmAndHleEnumDisabled.Value;
                taaHwImmuneSecure = taaHwImmune.Value;
            } else {
                // Never set on ARM systems so we need to override
                tsxCtrlReportedSecure = SystemInfo.IsProcessorArm;

                // For unpatched systems using a non-Intel processor be a
                // little cheeky and mark the status as secure anyway. Also
                // important for ARM systems as they never set these bits.
                tsxCtrlRtmDisabledSecure = !SystemInfo.IsProcessorIntel;
                tsxCtrlRtmAndHleEnumDisabledSecure = !SystemInfo.IsProcessorIntel;
                taaHwImmuneSecure = !SystemInfo.IsProcessorIntel;
            }

            WriteOutputEntry("TsxCtrlStatusRtm", tsxCtrlRtmDisabled, tsxCtrlRtmDisabledSecure);
            WriteOutputEntry("TsxCtrlStatusEnum", tsxCtrlRtmAndHleEnumDisabled, tsxCtrlRtmAndHleEnumDisabledSecure);
            WriteOutputEntry("TsxCtrlReported", tsxCtrlReported, tsxCtrlReportedSecure);
            WriteOutputEntry("TaaHardwareImmune", taaHwImmune, taaHwImmuneSecure);

            /*
             * MMIO Stale Data
             *
             * Affects:     Intel
             * CVE IDs:     CVE-2022-21123, CVE-2022-21125, CVE-2022-21127, CVE-2022-21166
             */

            var fbClearReported = _specCtrlInfo.Flags2.FbClearReported;
            var sbdrSsdpHwProtected = fbClearReported ? (bool?)_specCtrlInfo.Flags2.SbdrSsdpHardwareProtected : null;
            var fbsdpHwProtected = fbClearReported ? (bool?)_specCtrlInfo.Flags2.FbsdpHardwareProtected : null;
            var psdpHwProtected = fbClearReported ? (bool?)_specCtrlInfo.Flags2.PsdpHardwareProtected : null;
            var fbClearEnabled = fbClearReported ? (bool?)_specCtrlInfo.Flags2.FbClearEnabled : null;

            bool sbdrSsdpHwProtectedSecure;
            bool fbsdpHwProtectedSecure;
            bool psdpHwProtectedSecure;
            bool fbClearEnabledSecure;
            bool fbClearReportedSecure;

            if (fbClearReported) {
                // These bits aren't set on non-Intel processors even when
                // fbClearReported is set.
                sbdrSsdpHwProtectedSecure = sbdrSsdpHwProtected.Value || !SystemInfo.IsProcessorIntel;
                fbsdpHwProtectedSecure = fbsdpHwProtected.Value || !SystemInfo.IsProcessorIntel;
                psdpHwProtectedSecure = psdpHwProtected.Value || !SystemInfo.IsProcessorIntel;

                fbClearEnabledSecure = fbClearEnabled.Value ||
                                       (sbdrSsdpHwProtected.Value && fbsdpHwProtected.Value && psdpHwProtected.Value) ||
                                       !SystemInfo.IsProcessorIntel;
                fbClearReportedSecure = true;
            } else {
                // Never set on ARM systems so we need to override
                fbClearReportedSecure = SystemInfo.IsProcessorArm;

                // For unpatched systems using a non-Intel processor be a
                // little cheeky and mark the status as secure anyway. Also
                // important for ARM systems as they never set these bits.
                fbClearEnabledSecure = !SystemInfo.IsProcessorIntel;
                sbdrSsdpHwProtectedSecure = !SystemInfo.IsProcessorIntel;
                fbsdpHwProtectedSecure = !SystemInfo.IsProcessorIntel;
                psdpHwProtectedSecure = !SystemInfo.IsProcessorIntel;
            }

            WriteOutputEntry("SbdrSsdpHardwareProtected", sbdrSsdpHwProtected, sbdrSsdpHwProtectedSecure);
            WriteOutputEntry("FbsdpHardwareProtected", fbsdpHwProtected, fbsdpHwProtectedSecure);
            WriteOutputEntry("PsdpHardwareProtected", psdpHwProtected, psdpHwProtectedSecure);
            WriteOutputEntry("FbClearEnabled", fbClearEnabled, fbClearEnabledSecure);
            WriteOutputEntry("FbClearReported", fbClearReported, fbClearReportedSecure);

            /*
             * Branch History Injection (BHI)
             *
             * Affects:     Intel
             * CVE IDs:     CVE-2022-0001, CVE-2022-0002
             */

            // Oddly, this is set to true on ARM systems even though the
            // underlying vulnerability only affects Intel processors. In
            // contrast, it's set to false on AMD systems.
            var bhbEnabled = _specCtrlInfo.Flags2.BhbEnabled;

            var bhbDisabledSystemPolicy = _specCtrlInfo.Flags2.BhbDisabledSystemPolicy;
            var bhbDisabledNoHwSupport = _specCtrlInfo.Flags2.BhbDisabledNoHardwareSupport;

            // There's no "BhbReported" bit so we'll just set the status as
            // secure for non-Intel systems, even though the system may not
            // have the applicable Windows update.
            var bhbEnabledSecure = bhbEnabled || !SystemInfo.IsProcessorIntel;

            WriteOutputEntry("BhbEnabled", bhbEnabled, bhbEnabledSecure);
            WriteOutputEntry("BhbDisabledSystemPolicy", bhbDisabledSystemPolicy, !bhbDisabledSystemPolicy);
            WriteOutputEntry("BhbDisabledNoHardwareSupport", bhbDisabledNoHwSupport, !bhbDisabledNoHwSupport);

            /*
             * Branch Type Confusion (BTC)
             * Aka. Phantom, Retbleed
             *
             * Affects:     AMD, Intel
             * CVE IDs:     CVE-2022-23825, CVE-2022-29900, CVE-2022-29901
             */

            var btcReported = _specCtrlInfo.Flags2.BranchConfusionReported;
            var btcStatus = btcReported ? (SpeculationControlBranchConfusionStatus?)_specCtrlInfo.Flags2.BranchConfusionStatus : null;

            bool btcReportedSecure;
            bool btcStatusSecure;

            /*
             * The SpeculationControl PowerShell module implements custom logic
             * instead of simply using the value of BranchConfusionStatus when
             * BranchConfusionReported is set. It's unclear if it's necessary
             * so isn't implemented, but here's the logic used for reference:
             *
             * - For AMD CPUs, use BranchConfusionStatus.
             * - For Intel CPUs, ignore BranchConfusionStatus and:
             *   - Return HardwareImmune if neither SpecCtrlEnumerated or
             *     SpecCmdEnumerated are set.
             *   - Otherwise, return Mitigated if BpbEnabled is set.
             *   - Otherwise, return MitigationDisabled.
             * - For other CPUs, implicitly defaults to MitigationUnsupported.
             *
             * All of the above only applies if BranchConfusionReported is set.
             */
            if (btcReported) {
                btcReportedSecure = true;
                btcStatusSecure = btcStatus == SpeculationControlBranchConfusionStatus.HardwareImmune ||
                                  btcStatus == SpeculationControlBranchConfusionStatus.Mitigated;
            } else {
                // ARM builds of Windows don't appear to ever set these bits,
                // while on x86/64 builds we can't easily determine the secure
                // status given both AMD and Intel processors are affected.
                btcReportedSecure = SystemInfo.IsProcessorArm;
                btcStatusSecure = SystemInfo.IsProcessorArm;
            }

            WriteOutputEntry("BranchConfusionStatus", btcStatus, btcStatusSecure);
            WriteOutputEntry("BranchConfusionReported", btcReported, btcReportedSecure);

            /*
             * Rogue Data Cache Load (RDCL)
             * Aka. Spectre: Variant 3, Meltdown
             *
             * Affects:     ARM, Intel
             * CVE IDs:     CVE-2017-5754
             */

            var rdclHwProtectedReported = _specCtrlInfo.Flags2.RdclHardwareProtectedReported;
            var rdclHwProtected = rdclHwProtectedReported ? (bool?)_specCtrlInfo.Flags2.RdclHardwareProtected : null;

            bool rdclHwProtectedReportedSecure;
            bool rdclHwProtectedSecure;

            if (rdclHwProtectedReported) {
                rdclHwProtectedReportedSecure = true;
                rdclHwProtectedSecure = rdclHwProtected.Value;
            } else {
                // Although this vulnerability does apply to ARM systems, I've
                // yet to see one where Windows actually sets this bit. My best
                // guess is that by the time this flag was introduced, which
                // was years after the original mitigation was implemented,
                // there were no supported ARM processors on supported builds
                // of Windows which were affected by the vulnerability.
                rdclHwProtectedReportedSecure = SystemInfo.IsProcessorArm;

                // For unpatched systems using a non-Intel processor be a
                // little cheeky and mark the status as secure anyway. Also
                // important for ARM systems as they never appear to set this
                // bit (see comment directly above).
                rdclHwProtectedSecure = !SystemInfo.IsProcessorIntel;
            }

            WriteOutputEntry("RdclHardwareProtectedReported", rdclHwProtectedReported, rdclHwProtectedReportedSecure);
            WriteOutputEntry("RdclHardwareProtected", rdclHwProtected, rdclHwProtectedSecure);

            /*
             * Gather Data Sample (GDS)
             * Aka. Downfall
             *
             * Affects:     Intel
             * CVE IDs:     CVE-2022-40982
             */

            var gdsReported = _specCtrlInfo.Flags2.GdsReported;
            var gdsStatus = gdsReported ? (SpeculationControlGdsStatus?)_specCtrlInfo.Flags2.GdsStatus : null;

            bool gdsReportedSecure;
            bool gdsStatusSecure;

            if (gdsReported) {
                gdsReportedSecure = true;
                gdsStatusSecure = gdsStatus == SpeculationControlGdsStatus.HardwareImmune ||
                                  gdsStatus == SpeculationControlGdsStatus.Mitigated ||
                                  gdsStatus == SpeculationControlGdsStatus.MitigatedAndLocked;
            } else {
                // Never set on ARM systems so we need to override
                gdsReportedSecure = SystemInfo.IsProcessorArm;

                // For unpatched systems using a non-Intel processor be a
                // little cheeky and mark the status as secure anyway. Also
                // important for ARM systems as they never set this bit.
                gdsStatusSecure = !SystemInfo.IsProcessorIntel;
            }

            WriteOutputEntry("GdsReported", gdsReported, gdsReportedSecure);
            WriteOutputEntry("GdsStatus", gdsStatus, gdsStatusSecure);

            /*
             * Speculative Return Stack Overflow (SRSO)
             * Aka. Inception
             *
             * Affects:     AMD
             * CVE IDs:     CVE-2023-20569
             */

            var srsoReported = _specCtrlInfo.Flags2.SrsoReported;
            var srsoStatus = srsoReported ? (SpeculationControlSrsoStatus?)_specCtrlInfo.Flags2.SrsoStatus : null;

            bool srsoReportedSecure;
            bool srsoStatusSecure;

            if (srsoReported) {
                srsoReportedSecure = true;
                srsoStatusSecure = srsoStatus == SpeculationControlSrsoStatus.HardwareImmune ||
                                   srsoStatus == SpeculationControlSrsoStatus.Mitigated;
            } else {
                // Never set on ARM systems so we need to override
                srsoReportedSecure = SystemInfo.IsProcessorArm;

                // For unpatched systems using a non-AMD processor be a little
                // cheeky and mark the status as secure anyway. Also important
                // for ARM systems as they never set this bit.
                srsoStatusSecure = !SystemInfo.IsProcessorAmd;
            }

            WriteOutputEntry("SrsoReported", srsoReported, srsoReportedSecure);
            WriteOutputEntry("SrsoStatus", srsoStatus, srsoStatusSecure);

            /*
             * Division-by-Zero Speculative Leak
             *
             * Affects:     AMD
             * CVE IDs:     CVE-2023-20588
             */

            var dbzReported = _specCtrlInfo.Flags2.DivideByZeroReported;
            var dbzStatus = dbzReported ? (SpeculationControlDivideByZeroStatus?)_specCtrlInfo.Flags2.DivideByZeroStatus : null;

            bool dbzReportedSecure;
            bool dbzStatusSecure;

            if (dbzReported) {
                dbzReportedSecure = true;
                dbzStatusSecure = dbzStatus == SpeculationControlDivideByZeroStatus.HardwareImmune ||
                                  dbzStatus == SpeculationControlDivideByZeroStatus.Mitigated;
            } else {
                // Never set on ARM systems so we need to override
                dbzReportedSecure = SystemInfo.IsProcessorArm;

                // For unpatched systems using a non-AMD processor be a little
                // cheeky and mark the status as secure anyway. Also important
                // for ARM systems as they never set this bit.
                dbzStatusSecure = !SystemInfo.IsProcessorAmd;
            }

            WriteOutputEntry("DivideByZeroReported", dbzReported, dbzReportedSecure);
            WriteOutputEntry("DivideByZeroStatus", dbzStatus, dbzStatusSecure);

            /*
             * Register File Data Sampling (RFDS)
             *
             * Affects:     Intel
             * CVE IDs:     CVE-2023-28746
             */

            var rfdsReported = _specCtrlInfo.Flags2.RfdsReported;
            var rfdsStatus = rfdsReported ? (SpeculationControlRfdsStatus?)_specCtrlInfo.Flags2.RfdsStatus : null;

            bool rfdsReportedSecure;
            bool rfdsStatusSecure;

            if (rfdsReported) {
                rfdsReportedSecure = true;
                rfdsStatusSecure = rfdsStatus == SpeculationControlRfdsStatus.HardwareImmune ||
                                   rfdsStatus == SpeculationControlRfdsStatus.Mitigated;
            } else {
                // Never set on ARM systems so we need to override
                rfdsReportedSecure = SystemInfo.IsProcessorArm;

                // For unpatched systems using a non-Intel processor be a
                // little cheeky and mark the status as secure anyway. Also
                // important for ARM systems as they never set this bit.
                rfdsStatusSecure = !SystemInfo.IsProcessorIntel;
            }

            WriteOutputEntry("RfdsReported", rfdsReported, rfdsReportedSecure);
            WriteOutputEntry("RfdsStatus", rfdsStatus, rfdsStatusSecure);
        }

        #region P/Invoke

        [DllImport("ntdll", ExactSpelling = true)]
        private static extern int NtQuerySystemInformation(int systemInformationClass,
                                                           out ulong systemInformation,
                                                           uint systemInformationLength,
                                                           out uint returnLength);

        private struct SpeculationControlInfo {
            internal SpeculationControlFlags Flags;
            internal SpeculationControlFlags2 Flags2;
        }

#pragma warning disable IDE0251 // Member can be made readonly

        // ReSharper disable InconsistentNaming

        private struct SpeculationControlFlags {
            internal uint _RawBits;

            public bool BpbEnabled => (_RawBits & 0x1) == 1;                                       // Bit 0
            public bool BpbDisabledSystemPolicy => ((_RawBits >> 1) & 0x1) == 1;                   // Bit 1
            public bool BpbDisabledNoHardwareSupport => ((_RawBits >> 2) & 0x1) == 1;              // Bit 2
            public bool SpecCtrlEnumerated => ((_RawBits >> 3) & 0x1) == 1;                        // Bit 3
            public bool SpecCmdEnumerated => ((_RawBits >> 4) & 0x1) == 1;                         // Bit 4
            public bool IbrsPresent => ((_RawBits >> 5) & 0x1) == 1;                               // Bit 5
            public bool StibpPresent => ((_RawBits >> 6) & 0x1) == 1;                              // Bit 6
            public bool SmepPresent => ((_RawBits >> 7) & 0x1) == 1;                               // Bit 7
            public bool SpeculativeStoreBypassDisableAvailable => ((_RawBits >> 8) & 0x1) == 1;    // Bit 8
            public bool SpeculativeStoreBypassDisableSupported => ((_RawBits >> 9) & 0x1) == 1;    // Bit 9
            public bool SpeculativeStoreBypassDisabledSystemWide => ((_RawBits >> 10) & 0x1) == 1; // Bit 10
            public bool SpeculativeStoreBypassDisabledKernel => ((_RawBits >> 11) & 0x1) == 1;     // Bit 11
            public bool SpeculativeStoreBypassDisableRequired => ((_RawBits >> 12) & 0x1) == 1;    // Bit 12
            public bool BpbDisabledKernelToUser => ((_RawBits >> 13) & 0x1) == 1;                  // Bit 13
            public bool SpecCtrlRetpolineEnabled => ((_RawBits >> 14) & 0x1) == 1;                 // Bit 14
            public bool SpecCtrlImportOptimizationEnabled => ((_RawBits >> 15) & 0x1) == 1;        // Bit 15
            public bool EnhancedIbrs => ((_RawBits >> 16) & 0x1) == 1;                             // Bit 16
            public bool HvL1tfStatusAvailable => ((_RawBits >> 17) & 0x1) == 1;                    // Bit 17
            public bool HvL1tfProcessorNotAffected => ((_RawBits >> 18) & 0x1) == 1;               // Bit 18
            public bool HvL1tfMitigationEnabled => ((_RawBits >> 19) & 0x1) == 1;                  // Bit 19
            public bool HvL1tfMigitationNotEnabled_Hardware => ((_RawBits >> 20) & 0x1) == 1;      // Bit 20
            public bool HvL1tfMigitationNotEnabled_LoadOption => ((_RawBits >> 21) & 0x1) == 1;    // Bit 21
            public bool HvL1tfMigitationNotEnabled_CoreScheduler => ((_RawBits >> 22) & 0x1) == 1; // Bit 22
            public bool EnhancedIbrsReported => ((_RawBits >> 23) & 0x1) == 1;                     // Bit 23
            public bool MdsHardwareProtected => ((_RawBits >> 24) & 0x1) == 1;                     // Bit 24
            public bool MbClearEnabled => ((_RawBits >> 25) & 0x1) == 1;                           // Bit 25
            public bool MbClearReported => ((_RawBits >> 26) & 0x1) == 1;                          // Bit 26
            public bool TsxCtrlRtmDisabled => ((_RawBits >> 27) & 0x1) == 1;                       // Bit 27
            public bool TsxCtrlRtmAndHleEnumDisabled => ((_RawBits >> 28) & 0x1) == 1;             // Bit 28
            public bool TsxCtrlReported => ((_RawBits >> 29) & 0x1) == 1;                          // Bit 29
            public bool TaaHardwareImmune => ((_RawBits >> 30) & 0x1) == 1;                        // Bit 30
        }

        private struct SpeculationControlFlags2 {
            internal uint _RawBits;

            public bool SbdrSsdpHardwareProtected => (_RawBits & 0x1) == 1;             // Bit 0
            public bool FbsdpHardwareProtected => ((_RawBits >> 1) & 0x1) == 1;         // Bit 1
            public bool PsdpHardwareProtected => ((_RawBits >> 2) & 0x1) == 1;          // Bit 2
            public bool FbClearEnabled => ((_RawBits >> 3) & 0x1) == 1;                 // Bit 3
            public bool FbClearReported => ((_RawBits >> 4) & 0x1) == 1;                // Bit 4
            public bool BhbEnabled => ((_RawBits >> 5) & 0x1) == 1;                     // Bit 5
            public bool BhbDisabledSystemPolicy => ((_RawBits >> 6) & 0x1) == 1;        // Bit 6
            public bool BhbDisabledNoHardwareSupport => ((_RawBits >> 7) & 0x1) == 1;   // Bit 7
            public byte BranchConfusionStatus => (byte)((_RawBits >> 8) & 0x3);         // Bits 8-9
            public bool BranchConfusionReported => ((_RawBits >> 10) & 0x1) == 1;       // Bit 10
            public bool RdclHardwareProtectedReported => ((_RawBits >> 11) & 0x1) == 1; // Bit 11
            public bool RdclHardwareProtected => ((_RawBits >> 12) & 0x1) == 1;         // Bit 12
            public bool GdsReported => ((_RawBits >> 13) & 0x1) == 1;                   // Bit 13
            public byte GdsStatus => (byte)((_RawBits >> 14) & 0x7);                    // Bits 14-16
            public bool SrsoReported => ((_RawBits >> 17) & 0x1) == 1;                  // Bit 17
            public byte SrsoStatus => (byte)((_RawBits >> 18) & 0x3);                   // Bits 18-19
            public bool DivideByZeroReported => ((_RawBits >> 20) & 0x1) == 1;          // Bit 20
            public byte DivideByZeroStatus => (byte)((_RawBits >> 21) & 0x1);           // Bit 21
            public bool RfdsReported => ((_RawBits >> 22) & 0x1) == 1;                  // Bit 22
            public byte RfdsStatus => (byte)((_RawBits >> 23) & 0x3);                   // Bits 23-24
        }

        // ReSharper restore InconsistentNaming

        // @formatter:int_align_fields true

        private enum SpeculationControlBranchConfusionStatus : byte {
            MitigationUnsupported = 0x0,
            MitigationDisabled    = 0x1,
            HardwareImmune        = 0x2,
            Mitigated             = 0x3
        }

        private enum SpeculationControlDivideByZeroStatus : byte {
            HardwareImmune = 0x0,
            Mitigated      = 0x1
        }

        private enum SpeculationControlGdsStatus : byte {
            MitigationUnsupported = 0x0,
            MitigationDisabled    = 0x1,
            HardwareImmune        = 0x2,
            Mitigated             = 0x3,
            MitigatedAndLocked    = 0x4
        }

        private enum SpeculationControlRfdsStatus : byte {
            MitigationUnsupported = 0x0,
            MitigationDisabled    = 0x1,
            HardwareImmune        = 0x2,
            Mitigated             = 0x3
        }

        private enum SpeculationControlSrsoStatus : byte {
            MitigationUnsupported = 0x0,
            MitigationDisabled    = 0x1,
            HardwareImmune        = 0x2,
            Mitigated             = 0x3
        }

        // @formatter:int_align_fields false

#pragma warning restore IDE0251 // Member can be made readonly

        #endregion
    }
}
