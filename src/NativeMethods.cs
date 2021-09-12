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
            // Implemented
            SystemSecureBootInformation               = 0x91, // Dec: 145, returns 2 bytes
            SystemVsmProtectionInformation            = 0xA9, // Dec: 169, returns 4 bytes
            SystemKernelVaShadowInformation           = 0xC4, // Dec: 196, returns 4 bytes
            SystemSpeculationControlInformation       = 0xC9, // Dec: 201, returns 4 bytes
            SystemDmaGuardPolicyInformation           = 0xCA, // Dec: 202, returns 1 byte
            SystemSecureSpeculationControlInformation = 0xD5, // Dec: 213, returns 4 bytes
            SystemShadowStackInformation              = 0xDD, // Dec: 221, returns 4 bytes
            // TODO
            SystemBootEnvironmentInformation          = 0x5A, // Dec: 90,  returns 32 bytes
            SystemHypervisorInformation               = 0x5B, // Dec: 91,  returns 16 bytes
            SystemCodeIntegrityInformation            = 0x67, // Dec: 103
            SystemHypervisorDetailInformation         = 0x9F, // Dec: 159, returns 112 bytes
            SystemIsolatedUserModeInformation         = 0xA5, // Dec: 165, returns 16 bytes
            SystemSecurityModelInformation            = 0xD0  // Dec: 208
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

        #region NtQuerySystemInformation: SecurityModel

        [Flags]
        internal enum SecurityModelFlags {
            SModeAdminlessEnabled               = 0x1,
            AllowDeviceOwnerProtectionDowngrade = 0x2
        }

        #endregion
    }
}
