using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Dynamic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using QueryHardwareSecurity.Collectors;

using static QueryHardwareSecurity.Utilities;

// Mark assembly as not CLS compliant
[assembly: CLSCompliant(false)]

// For P/Invoke only search in %windir%\System32
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace QueryHardwareSecurity {
    internal static class Program {
        private static readonly string AssemblyName = Assembly.GetExecutingAssembly().GetName().Name;
        private static readonly Type CollectorsBaseClass = Type.GetType($"{AssemblyName}.Collector")!;
        private static readonly string CollectorsNamespace = $"{AssemblyName}.Collectors";

        private static readonly string[] AllCollectors = Assembly.GetExecutingAssembly()
                                                                 .GetTypes()
                                                                 .Where(type => type.IsSubclassOf(CollectorsBaseClass))
                                                                 .Select(collector => collector.Name)
                                                                 .ToArray();

        private static readonly string[] CollectorsSortExclusions = { nameof(SystemInfo) };

        internal static bool DebugOutput;
        internal static bool VerboseOutput;

        public static int Main(params string[] args) {
#if NETCOREAPP
            IsPlatformSupported();
#endif

            var rootCommand = new RootCommand("Query Windows support for security features and mitigations with hardware dependencies") {
                new Option<bool>("--verbose", "-v") { Description = "Verbose output" },
                new Option<bool>("--debug", "-d") { Description = "Debug output (implies verbose)" },
                new Option<bool>("--no-color", "-nc") { Description = "No color output" }
            };

#pragma warning disable CA1308 // Normalize strings to uppercase
            var validOutputs = Enum.GetNames(typeof(OutputFormat)).Select(format => format.ToLower(CultureInfo.InvariantCulture)).ToArray();
#pragma warning restore CA1308 // Normalize strings to uppercase

            var optOutput = new Option<string>("--output", "-o") {
                Description = "Output format", Arity = ArgumentArity.ExactlyOne, DefaultValueFactory = _ => "table"
            };
            optOutput.AcceptOnlyFromAmong(validOutputs);
            rootCommand.Options.Add(optOutput);

            var optCollectors = new Option<string[]>("--collectors", "-c") { Description = "Collectors to run", Arity = ArgumentArity.OneOrMore };
            optCollectors.AcceptOnlyFromAmong(AllCollectors);
            rootCommand.Options.Add(optCollectors);

            rootCommand.SetAction(Invoke);

            var parseResult = rootCommand.Parse(args);
            if (parseResult.Errors.Count == 0) return parseResult.Invoke();

            foreach (var parseError in parseResult.Errors) WriteError(parseError.Message);
            return 1;
        }

        private static void Invoke(ParseResult parseResult) {
            VerboseOutput = parseResult.GetValue<bool>("--verbose");

            DebugOutput = parseResult.GetValue<bool>("--debug");
            if (DebugOutput) VerboseOutput = true;

            var colorOutput = !parseResult.GetValue<bool>("--no-color");
            if (colorOutput) ResetColor();

            var outputOption = parseResult.GetValue<string>("--output");
            Enum.TryParse(outputOption, true, out OutputFormat outputFormat);

            var collectors = new Dictionary<string, Collector>();
            var collectorsSuppressed = new List<string>();
            var collectorsSelected = parseResult.GetValue<string[]>("--collectors").ToList();
            collectorsSelected = collectorsSelected.Count != 0 ? collectorsSelected : AllCollectors.ToList();

            // SkSpecCtrl collector requires KvaShadow collector
            if (collectorsSelected.Contains(nameof(SkSpecCtrl)) && !collectorsSelected.Contains(nameof(KvaShadow))) {
                collectorsSelected.Add(nameof(KvaShadow));
                collectorsSuppressed.Add(nameof(KvaShadow));
            }

            // Ensure order of execution is deterministic
            var collectorsToRun = collectorsSelected
                                  .Where(collector => !CollectorsSortExclusions.Contains(collector))
                                  .OrderBy(collector => collector)
                                  .ToList();

            // SystemInfo collector should always be first
            if (collectorsSelected.Contains(nameof(SystemInfo))) {
                collectorsToRun.Insert(0, nameof(SystemInfo));
            }

            // Initialise each selected collector
            // ReSharper disable once ForeachCanBePartlyConvertedToQueryUsingAnotherGetEnumerator
            foreach (var collectorName in collectorsToRun) {
                var collectorType = Type.GetType($"{CollectorsNamespace}.{collectorName}");
                try {
                    switch (collectorName) {
                        case nameof(SkSpecCtrl):
                            var kvaShadowRequired = true;
                            try {
                                var kvaShadowCollector = (KvaShadow)collectors[nameof(KvaShadow)];
                                kvaShadowRequired = kvaShadowCollector.IsKvaShadowRequired;
                            } catch (KeyNotFoundException) { }

                            collectors.Add(collectorName, (Collector)Activator.CreateInstance(collectorType!, new object[] { kvaShadowRequired }));
                            break;
                        default:
                            collectors.Add(collectorName, (Collector)Activator.CreateInstance(collectorType!));
                            break;
                    }
                } catch (TargetInvocationException) { }
            }

            // Determine which collectors to output
            var collectorsToOutput = collectorsToRun.Where(collector => !collectorsSuppressed.Contains(collector)).ToArray();

            // Return early if there's no output
            if (collectorsToOutput.Length == 0) return;

            // Add a blank line between verbose/debug output and main output
            if (VerboseOutput) Console.WriteLine();

            // Output collector results in JSON
            if (outputFormat == OutputFormat.Json) {
                var collectorsData = new ExpandoObject();

                /*
                 * The serialization and immediate deserialization provides a copy of the
                 * underlying collector metadata. Definitely not at all efficient, but it
                 * works and and we're not dealing with any large JSON data structures.
                 */
                foreach (var collectorName in collectorsToOutput) {
                    try {
                        var collector = collectors[collectorName];
                        ((IDictionary<string, object>)collectorsData)[collector.JsonName] = JsonConvert.DeserializeObject(collector.ConvertToJson());
                    } catch (KeyNotFoundException) { }
                }

                var collectorsJson = JsonConvert.SerializeObject(collectorsData, Formatting.Indented);
                Console.WriteLine(collectorsJson);
                return;
            }

            // Output collector results in raw or table format
            var consoleFirstOutput = true;
            foreach (var collectorName in collectorsToOutput) {
                try {
                    var collector = collectors[collectorName];
                    if (!consoleFirstOutput && outputFormat == OutputFormat.Raw) Console.WriteLine();
                    collector.WriteOutput(outputFormat, colorOutput);
                    consoleFirstOutput = false;
                } catch (KeyNotFoundException) { }
            }

            if (outputFormat == OutputFormat.Table) Console.WriteLine(new string('-', 159));
        }
    }
}
