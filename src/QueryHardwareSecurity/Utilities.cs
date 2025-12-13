using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;

namespace QueryHardwareSecurity {
    internal static class Utilities {
        #region Platform

#if NETCOREAPP
        /// <summary>Checks if the platform is supported and immediately exits with a non-zero exit code if not.</summary>
        /// <remarks>Currently only Windows is supported.</remarks>
        internal static void IsPlatformSupported() {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

            WriteError("Only Windows is currently supported.");
            Environment.Exit(1);
        }
#endif

        #endregion

        #region CIM

        private const string CimDefaultNamespace = "root/CIMV2";

        /// <summary>Enumerates CIM instances with the provided class name.</summary>
        /// <param name="className">The class name for which to enumerate CIM instances.</param>
        /// <param name="namespace">
        ///     The namespace under which to enumerate CIM instances. If not specified, defaults to
        ///     "root/CIMV2".
        /// </param>
        /// <returns>The enumerated CIM instances as a <see cref="List{T}" />.</returns>
        internal static IEnumerable<CimInstance> EnumerateCimInstances(string className, string @namespace = CimDefaultNamespace) {
            using var dcomSessionOptions = new DComSessionOptions();
            using var cimSession = CimSession.Create("localhost", dcomSessionOptions);
            return cimSession.EnumerateInstances(@namespace, className).ToList();
        }

        #endregion

        #region NTDLL

        private static IntPtr _hLibNtdll = IntPtr.Zero;

        /// <summary>Retrieves the symbolic name for the provided NTSTATUS value.</summary>
        /// <param name="status">The NTSTATUS value to retrieve the symbolic name for.</param>
        /// <returns>The symbolic name for the provided NTSTATUS value.</returns>
        internal static string GetSymbolicNtStatus(int status) {
            if (_hLibNtdll == IntPtr.Zero) {
                _hLibNtdll = LoadLibrary("ntdll.dll");

                if (_hLibNtdll == IntPtr.Zero) {
                    var err = Marshal.GetLastWin32Error();
                    WriteError($"Failure loading NTDLL library: {err}");
                    Environment.Exit(-1);
                }
            }

            const uint flags = (uint)(FormatMessageFlags.FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                      FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE |
                                      FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM) |
                               0xFF; // FORMAT_MESSAGE_MAX_WIDTH_MASK
            var msg = string.Empty;
            var res = FormatMessage(flags, _hLibNtdll, (uint)status, 0, out var msgPtr, 0, IntPtr.Zero);

            if (res != 0) {
                // ReSharper disable once PossibleNullReferenceException
                msg = Marshal.PtrToStringUni(msgPtr).TrimEnd();
                LocalFree(msgPtr);
            } else {
                var err = Marshal.GetLastWin32Error();
                WriteError($"Failure calling FormatMessage: {err}\n");
            }

            return msg;
        }

        #endregion

        #region Output

        private static readonly ConsoleColor DefaultForegroundColor = Console.ForegroundColor;

        /// <summary>Resets the console foreground colour to whichever colour was initially set.</summary>
        internal static void ResetColor() {
            Console.ForegroundColor = DefaultForegroundColor;
        }

        /// <summary>Writes a debug message to standard error.</summary>
        /// <param name="msg">The debug message to write to standard error.</param>
        /// <remarks>Debug messages are only displayed when debug mode is enabled.</remarks>
        internal static void WriteDebug(string msg) {
            if (Program.DebugOutput) Console.Error.WriteLine(msg);
        }

        /// <summary>Writes an error message to standard error.</summary>
        /// <param name="msg">The error message to write to standard error.</param>
        internal static void WriteError(string msg) {
            Console.Error.WriteLine(msg);
        }

        /// <summary>Writes a verbose message to standard error.</summary>
        /// <param name="msg">The verbose message to write to standard error.</param>
        /// <remarks>Verbose messages are only displayed when verbose or debug modes are enabled.</remarks>
        internal static void WriteVerbose(string msg) {
            if (Program.VerboseOutput) Console.Error.WriteLine(msg);
        }

        #endregion

        #region P/Invoke

        [DllImport("kernel32", EntryPoint = "FormatMessageW", ExactSpelling = true, SetLastError = true)]
        private static extern uint FormatMessage(uint dwFlags,
                                                 IntPtr lpSource,
                                                 uint dwMessageId,
                                                 uint dwLanguageId,
                                                 out IntPtr lpBuffer,
                                                 uint nSize,
                                                 IntPtr arguments);

        [DllImport("kernel32", CharSet = CharSet.Unicode, EntryPoint = "LoadLibraryW", ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpLibFileName);

        [DllImport("kernel32", ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        // @formatter:int_align_fields true

        private enum FormatMessageFlags {
            FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x100,
            FORMAT_MESSAGE_IGNORE_INSERTS  = 0x200,
            FORMAT_MESSAGE_FROM_STRING     = 0x400,
            FORMAT_MESSAGE_FROM_HMODULE    = 0x800,
            FORMAT_MESSAGE_FROM_SYSTEM     = 0x1000,
            FORMAT_MESSAGE_ARGUMENT_ARRAY  = 0x2000
        }

        // @formatter:int_align_fields false

        #endregion
    }
}
