// @formatter:off
// ReSharper disable InconsistentNaming

#pragma warning disable CS0649 // Field is never assigned to

using System;
using System.Runtime.InteropServices;


namespace QueryHardwareSecurity {
    internal static class NativeMethods {
        #region FormatMessage

        [DllImport("kernel32", EntryPoint = "FormatMessageW", ExactSpelling = true, SetLastError = true)]
        internal static extern uint FormatMessage(uint dwFlags,
                                                  IntPtr lpSource,
                                                  uint dwMessageId,
                                                  uint dwLanguageId,
                                                  out IntPtr lpBuffer,
                                                  uint nSize,
                                                  IntPtr arguments);

        [Flags]
        internal enum FormatMessageFlags {
            FORMAT_MESSAGE_ALLOCATE_BUFFER  = 0x100,
            FORMAT_MESSAGE_IGNORE_INSERTS   = 0x200,
            FORMAT_MESSAGE_FROM_STRING      = 0x400,
            FORMAT_MESSAGE_FROM_HMODULE     = 0x800,
            FORMAT_MESSAGE_FROM_SYSTEM      = 0x1000,
            FORMAT_MESSAGE_ARGUMENT_ARRAY   = 0x2000
        }

        #endregion

        #region GetFirmwareType

        [DllImport("kernel32", ExactSpelling = true, SetLastError = true)]
        internal static extern bool GetFirmwareType(out FirmwareType firmwareType);

        internal enum FirmwareType {
            Unknown = 0,
            BIOS    = 1,
            UEFI    = 2,
            Max     = 3
        }

        #endregion

        #region LoadLibrary

        [DllImport("kernel32", CharSet = CharSet.Unicode, EntryPoint = "LoadLibraryW", ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr LoadLibrary(string lpLibFileName);

        #endregion

        #region LocalFree

        [DllImport("kernel32", ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr LocalFree(IntPtr hMem);

        #endregion

        #region NtQuerySystemInformation

        [DllImport("ntdll", ExactSpelling = true)]
        internal static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                            IntPtr systemInformation,
                                                            uint systemInformationLength,
                                                            IntPtr returnLength);

        [DllImport("ntdll", ExactSpelling = true)]
        internal static extern int NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass,
                                                            IntPtr systemInformation,
                                                            uint systemInformationLength,
                                                            out uint returnLength);

        /*
         * NtQuerySystemInformation function
         * https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
         *
         * ZwQuerySystemInformation
         * https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/query.htm
         */
        internal enum SYSTEM_INFORMATION_CLASS {
            SystemCodeIntegrityInformation      = 103,
            SystemSecureBootInformation         = 145,
            SystemIsolatedUserModeInformation   = 165,
            SystemVsmProtectionInformation      = 169,
            SystemKernelVaShadowInformation     = 196,
            SystemSpeculationControlInformation = 201,
            SystemDmaGuardPolicyInformation     = 202,
            SystemSecurityModelInformation      = 208
        }

        #endregion

        #region NtQuerySystemInformation: CodeIntegrity

        [StructLayout(LayoutKind.Sequential)]
        internal class CodeIntegrityInformation {
            internal uint Length;
            internal CodeIntegrityFlags CodeIntegrityOptions;

            public CodeIntegrityInformation() {
                Length = (uint)Marshal.SizeOf(typeof(CodeIntegrityInformation));
            }
        }

        [Flags]
        internal enum CodeIntegrityFlags {
            CODEINTEGRITY_OPTION_ENABLED                        = 0x1,
            CODEINTEGRITY_OPTION_TESTSIGN                       = 0x2,
            CODEINTEGRITY_OPTION_UMCI_ENABLED                   = 0x4,
            CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED         = 0x8,
            CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED    = 0x10,
            CODEINTEGRITY_OPTION_TEST_BUILD                     = 0x20,
            CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD            = 0x40,
            CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED              = 0x80,
            CODEINTEGRITY_OPTION_FLIGHT_BUILD                   = 0x100,
            CODEINTEGRITY_OPTION_FLIGHTING_ENABLED              = 0x200,
            CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED              = 0x400,
            CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED    = 0x800,
            CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED   = 0x1000,
            CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED               = 0x2000
        }

        #endregion

        #region NtQuerySystemInformation: IsolatedUserMode

        internal struct IsolatedUserModeInformation {
            internal IsolatedUserModeFlags flags;
            internal int Spare0;
            internal long Spare1;
        }

        [Flags]
        internal enum IsolatedUserModeFlags {
            SecureKernelRunning     = 0x1,
            HvciEnabled             = 0x2,
            HvciStrictMode          = 0x4,
            DebugEnabled            = 0x8,
            FirmwarePageProtection  = 0x10,
            EncryptionKeyAvailable  = 0x20,
            SpareFlag1              = 0x40,
            SpareFlag2              = 0x80,
            TrustletRunning         = 0x100,
            HvciDisableAllowed      = 0x200,
            SpareFlag3              = 0x400,
            SpareFlag4              = 0x800,
            SpareFlag5              = 0x1000,
            SpareFlag6              = 0x2000,
            SpareFlag7              = 0x4000,
            SpareFlag8              = 0x8000
        }

        #endregion

        #region NtQuerySystemInformation: SecureBoot

        [Flags]
        internal enum SecureBootFlags {
            SecureBootEnabled   = 0x1,
            SecureBootCapable   = 0x2
        }

        #endregion

        #region NtQuerySystemInformation: SecurityModel

        [Flags]
        internal enum SecurityModelFlags {
            SModeAdminlessEnabled               = 0x1,
            AllowDeviceOwnerProtectionDowngrade = 0x2
        }

        #endregion

        #region NtQuerySystemInformation: VsmProtection

        [Flags]
        internal enum VsmProtectionFlags {
            DmaProtectionsAvailable = 0x1,
            DmaProtectionsInUse     = 0x2,
            HardwareMbecAvailable   = 0x4
        }

        #endregion

        #region TPM Base Services

        internal enum TBS_RESULT : uint {
            TBS_SUCCESS                     = 0x0,
            TBS_E_INTERNAL_ERROR            = 0x80284001,
            TBS_E_BAD_PARAMETER             = 0x80284002,
            TBS_E_INVALID_OUTPUT_POINTER    = 0x80284003,
            TBS_E_INVALID_CONTEXT           = 0x80284004,
            TBS_E_INSUFFICIENT_BUFFER       = 0x80284005,
            TBS_E_IOERROR                   = 0x80284006,
            TBS_E_INVALID_CONTEXT_PARAM     = 0x80284007,
            TBS_E_SERVICE_NOT_RUNNING       = 0x80284008,
            TBS_E_TOO_MANY_TBS_CONTEXTS     = 0x80284009,
            TBS_E_TOO_MANY_RESOURCES        = 0x8028400A,
            TBS_E_SERVICE_START_PENDING     = 0x8028400B,
            TBS_E_PPI_NOT_SUPPORTED         = 0x8028400C,
            TBS_E_COMMAND_CANCELED          = 0x8028400D,
            TBS_E_BUFFER_TOO_LARGE          = 0x8028400E,
            TBS_E_TPM_NOT_FOUND             = 0x8028400F,
            TBS_E_SERVICE_DISABLED          = 0x80284010,
            TBS_E_NO_EVENT_LOG              = 0x80284011,
            TBS_E_ACCESS_DENIED             = 0x80284012,
            TBS_E_PROVISIONING_NOT_ALLOWED  = 0x80284013,
            TBS_E_PPI_FUNCTION_UNSUPPORTED  = 0x80284014,
            TBS_E_OWNERAUTH_NOT_FOUND       = 0x80284015,
            TBS_E_PROVISIONING_INCOMPLETE   = 0x80284016
        }

        internal enum TBS_COMMAND_LOCALITY: uint {
            Zero            = 0,
            One             = 1,
            Two             = 2,
            Three           = 3,
            Four            = 4
        }

        internal enum TBS_COMMAND_PRIORITY : uint {
            Low             = 100,
            Normal          = 200,
            High            = 300,
            System          = 400,
            Max             = 0x80000000
        }

        [Flags]
        internal enum TBS_CONTEXT_PARAMS2_FLAGS : uint {
            requestRaw      = 0x1,
            includeTpm12    = 0x2,
            includeTpm20    = 0x4
        }

        internal enum TPM_IFTYPE : uint {
            Unknown         = 0,
            OnePointTwo     = 1,
            Trustzone       = 2,
            Hardware        = 3,
            Emulator        = 4,
            Spb             = 5
        }

        internal enum TPM_VERSION : uint {
            Unknown         = 0,
            OnePointTwo     = 1,
            TwoPointZero    = 2
        }

        internal struct TPM_DEVICE_INFO {
            internal uint structVersion;
            internal TPM_VERSION tpmVersion;
            internal TPM_IFTYPE tpmInterfaceType;
            internal uint tpmImpRevision;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal class TBS_CONTEXT_PARAMS {
            internal uint version;

            public TBS_CONTEXT_PARAMS() {
                version = 1; // TBS_CONTEXT_VERSION_ONE
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal class TBS_CONTEXT_PARAMS2 {
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
                                                                         [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)]
                                                                         byte[] pabInput,
                                                                         uint cbInput,
                                                                         [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)]
                                                                         [In, Out] byte[] pabOutput,
                                                                         ref uint pcbOutput);

        [DllImport("tbs", ExactSpelling = true)]
        internal static extern TBS_RESULT Tbsip_Cancel_Commands(IntPtr hContext);

        [DllImport("tbs", ExactSpelling = true)]
        internal static extern TBS_RESULT Tbsip_Context_Close(IntPtr hContext);

        [DllImport("tbs", ExactSpelling = true)]
        internal static extern TBS_RESULT Tbsip_Submit_Command(IntPtr hContext,
                                                               TBS_COMMAND_LOCALITY Locality,
                                                               TBS_COMMAND_PRIORITY Priority,
                                                               [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)]
                                                               byte[] pabCommand,
                                                               uint cbCommand,
                                                               [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6)]
                                                               [In, Out] byte[] pabResult,
                                                               ref uint pcbResult);

        #endregion
    }
}
