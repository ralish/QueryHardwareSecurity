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
                    Console.Error.WriteLine($"Failed to load NTDLL library with error: {err}");
                    Environment.Exit(-1);
                }
            }

            var fmFlags = (uint)(FormatMessageFlags.FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                 FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE |
                                 FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM) |
                          0xFF; // FORMAT_MESSAGE_MAX_WIDTH_MASK
            var res = FormatMessage(fmFlags, _hLibNtdll, (uint)status, 0, out var errMsg, 0, IntPtr.Zero);

            if (res == 0) {
                var err = Marshal.GetLastWin32Error();
                Console.Error.WriteLine($"Failed to call FormatMessage() with error: {err}\n");
            }

            return errMsg;
        }

        #endregion
    }
}
