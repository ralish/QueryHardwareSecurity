using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;

using Newtonsoft.Json;

using static QueryHardwareSecurity.NativeMethods;


namespace QueryHardwareSecurity {
    internal class Utilities {
        #region CIM

        private const string CimDefaultNamespace = "root/CIMV2";

        internal static List<CimInstance> EnumerateCimInstances(string className, string @namespace = null) {
            using (var dcomSessionOptions = new DComSessionOptions()) {
                using (var cimSession = CimSession.Create("localhost", dcomSessionOptions)) {
                    return cimSession.EnumerateInstances(@namespace ?? CimDefaultNamespace, className).ToList();
                }
            }
        }

        internal static CimInstance GetCimInstance(CimInstance instance, string @namespace = null) {
            using (var dcomSessionOptions = new DComSessionOptions()) {
                using (var cimSession = CimSession.Create("localhost", dcomSessionOptions)) {
                    return cimSession.GetInstance(@namespace ?? CimDefaultNamespace, instance);
                }
            }
        }

        #endregion

        #region Console

        private static readonly ConsoleColor DefaultForegroundColor = Console.ForegroundColor;

        internal static void ResetConsoleColor() {
            Console.ForegroundColor = DefaultForegroundColor;
        }

        internal static void WriteConsoleDebug(string msg) {
            if (Program.DebugOutput) {
                Console.Error.WriteLine(msg);
            }
        }

        internal static void WriteConsoleError(string msg) {
            Console.Error.WriteLine(msg);
        }

        internal static void WriteConsoleVerbose(string msg) {
            if (Program.VerboseOutput) {
                Console.Error.WriteLine(msg);
            }
        }

        #endregion

        #region DLR

        internal static ExpandoObject GetOrCreateDynamicObjectKey(dynamic @object, string key) {
            dynamic data;

            try {
                data = ((IDictionary<string, object>)@object)[key];
            } catch (KeyNotFoundException) {
                WriteConsoleVerbose($"No data for key: {key}");
                data = new ExpandoObject();
                ((IDictionary<string, object>)@object)[key] = data;
            }

            return data;
        }

        #endregion

        #region JSON

        internal static ExpandoObject LoadJsonResource(string resourceName) {
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"{resourceName}.json")) {
                if (stream == null) {
                    return new ExpandoObject();
                }

                using (var reader = new StreamReader(stream)) {
                    var resource = reader.ReadToEnd();
                    return JsonConvert.DeserializeObject<ExpandoObject>(resource);
                }
            }
        }

        #endregion

        #region NTDLL

        private static IntPtr _hLibNtdll = IntPtr.Zero;

        internal static string GetSymbolicNtStatus(int status) {
            if (_hLibNtdll == IntPtr.Zero) {
                _hLibNtdll = LoadLibrary("ntdll.dll");

                if (_hLibNtdll == IntPtr.Zero) {
                    var err = Marshal.GetLastWin32Error();
                    WriteConsoleError($"Failure loading NTDLL library: {err}");
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
                msg = Marshal.PtrToStringUni(msgPtr).TrimEnd();
                LocalFree(msgPtr);
            } else {
                var err = Marshal.GetLastWin32Error();
                WriteConsoleError($"Failure calling FormatMessage(): {err}\n");
            }

            return msg;
        }

        #endregion

        #region Platform

        internal static void IsPlatformSupported() {
#if NETCOREAPP
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                WriteConsoleError("Only Windows operating systems are currently supported.");
                Environment.Exit(1);
            }
#endif
        }

        #endregion
    }
}
