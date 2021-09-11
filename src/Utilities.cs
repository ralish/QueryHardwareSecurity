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
    internal static class Utilities {
        #region CIM

        private const string CimDefaultNamespace = "root/CIMV2";

        /// <summary>
        ///     Enumerates CIM instances with the provided class name.
        /// </summary>
        /// <param name="className">The class name for which to enumerate CIM instances.</param>
        /// <param name="namespace">
        ///     The namespace under which to enumerate CIM instances. If not specified, defaults to
        ///     "root/CIMV2".
        /// </param>
        /// <returns>The enumerated CIM instances as a list.</returns>
        public static List<CimInstance> EnumerateCimInstances(string className, string @namespace = null) {
            using (var dcomSessionOptions = new DComSessionOptions()) {
                using (var cimSession = CimSession.Create("localhost", dcomSessionOptions)) {
                    return cimSession.EnumerateInstances(@namespace ?? CimDefaultNamespace, className).ToList();
                }
            }
        }

        /// <summary>
        ///     Retrieves a CIM instance with the provided instance ID.
        /// </summary>
        /// <param name="instance">The instance ID for which to retrieve a CIM instance for.</param>
        /// <param name="namespace">
        ///     The namespace under which the requested CIM instance should be retrieved. If not specified,
        ///     defaults to "root/CIMV2".
        /// </param>
        /// <returns>The requested CIM instance.</returns>
        public static CimInstance GetCimInstance(CimInstance instance, string @namespace = null) {
            using (var dcomSessionOptions = new DComSessionOptions()) {
                using (var cimSession = CimSession.Create("localhost", dcomSessionOptions)) {
                    return cimSession.GetInstance(@namespace ?? CimDefaultNamespace, instance);
                }
            }
        }

        #endregion

        #region Console

        private static readonly ConsoleColor DefaultForegroundColor = Console.ForegroundColor;

        /// <summary>
        ///     Resets the console foreground colour to whichever colour was initially set.
        /// </summary>
        public static void ResetConsoleColor() {
            Console.ForegroundColor = DefaultForegroundColor;
        }

        /// <summary>
        ///     Writes a debug message to the console.
        /// </summary>
        /// <param name="msg">The debug message to write to the console.</param>
        /// <remarks>Debug messages are only displayed when debug mode is enabled.</remarks>
        public static void WriteConsoleDebug(string msg) {
            if (Program.DebugOutput) {
                Console.Error.WriteLine(msg);
            }
        }

        /// <summary>
        ///     Writes an error message to the console.
        /// </summary>
        /// <param name="msg">The error message to write to the console.</param>
        /// <remarks>Error messages are written to the standard error output stream.</remarks>
        public static void WriteConsoleError(string msg) {
            Console.Error.WriteLine(msg);
        }

        /// <summary>
        ///     Writes a verbose message to the console.
        /// </summary>
        /// <param name="msg">The verbose message to write to the console.</param>
        /// <remarks>Verbose messages are only displayed when verbose mode is enabled. Debug mode implicitly enables verbose mode.</remarks>
        public static void WriteConsoleVerbose(string msg) {
            if (Program.VerboseOutput) {
                Console.Error.WriteLine(msg);
            }
        }

        #endregion

        #region DLR

        /// <summary>
        ///     Retrieves the data under the specified key for the provided ExpandoObject. If the key does not exist, it is created
        ///     and its value set to an empty ExpandoObject.
        /// </summary>
        /// <param name="object">The ExpandoObject on which to retrieve or create the specified key.</param>
        /// <param name="key">The key to retrieve or create on the provided ExpandoObject.</param>
        /// <returns>The ExpandoObject for the requested key if it exists, otherwise the newly created ExpandoObject.</returns>
        public static ExpandoObject GetOrCreateDynamicObjectKey(dynamic @object, string key) {
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

        /// <summary>
        ///     Loads the embedded resource with the specified name as a JSON object.
        /// </summary>
        /// <param name="resourceName">The name of the embedded resource to load as a JSON object.</param>
        /// <returns>The requested embedded JSON resource deserialized as an ExpandoObject.</returns>
        public static ExpandoObject LoadJsonResource(string resourceName) {
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

        /// <summary>
        ///     Retrieves the symbolic name for the provided NTSTATUS value.
        /// </summary>
        /// <param name="status">The NTSTATUS value to retrieve the symbolic name for.</param>
        /// <returns>The symbolic name for the provided NTSTATUS value.</returns>
        public static string GetSymbolicNtStatus(int status) {
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

        /// <summary>
        ///     Checks if the platform is supported. If the platform is unsupported, immediately exits with a non-zero exit code.
        /// </summary>
        /// <remarks>Currently only Windows is supported.</remarks>
        public static void IsPlatformSupported() {
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
