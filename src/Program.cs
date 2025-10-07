using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Diagnostics;
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
        private static readonly string CollectorsNamespace = $"{Assembly.GetExecutingAssembly().GetName().Name}.Collectors";

        private static readonly Type CollectorsBaseClass = Type.GetType($"{CollectorsNamespace}.Collector");
        private static readonly string[] CollectorsSortExclusions = { "SystemInfo" };

        private static readonly string[] ValidCollectors = Assembly.GetExecutingAssembly()
                                                                   .GetTypes()
                                                                   .Where(type => type.IsSubclassOf(CollectorsBaseClass))
                                                                   .Select(collector => collector.Name)
                                                                   .ToArray();

        internal static bool DebugOutput;
        internal static bool VerboseOutput;

        public static int Main(params string[] args) {
            IsPlatformSupported();

            var rootCommand = new RootCommand("Query Windows support for security features and mitigations with hardware dependencies") {
                new Option<bool>("--verbose", "-v") { Description = "Verbose output" },
                new Option<bool>("--debug", "-d") { Description = "Debug output (implies verbose)" },
                new Option<bool>("--no-color", "-nc") { Description = "No colored output" }
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
            optCollectors.AcceptOnlyFromAmong(ValidCollectors);
            rootCommand.Options.Add(optCollectors);

            rootCommand.SetAction(Invoke);

            var parseResult = rootCommand.Parse(args);
            if (parseResult.Errors.Count == 0) {
                return parseResult.Invoke();
            }

            foreach (var parseError in parseResult.Errors) {
                WriteConsoleError(parseError.Message);
            }

            return 1;
        }

        private static void Invoke(ParseResult parseResult) {
            VerboseOutput = parseResult.GetValue<bool>("--verbose");

            DebugOutput = parseResult.GetValue<bool>("--debug");
            if (DebugOutput) VerboseOutput = true;

            var colorOutput = !parseResult.GetValue<bool>("--no-color");
            if (colorOutput) ResetConsoleColor();

            var outputOption = parseResult.GetValue<string>("--output");
            Enum.TryParse(outputOption, true, out OutputFormat outputFormat);
            Enum.TryParse(outputOption, true, out ConsoleOutputStyle consoleOutputStyle);

            var collectors = new List<Collector>();
            var collectorsSelected = parseResult.GetValue<string[]>("--collectors");
            collectorsSelected = collectorsSelected.Length != 0 ? collectorsSelected : ValidCollectors;

            // Ensure order of execution is deterministic
            var collectorsToRun = collectorsSelected
                                  .Where(collector => !CollectorsSortExclusions.Contains(collector))
                                  .OrderBy(collector => collector)
                                  .ToList();

            // SystemInfo collector should be first
            if (collectorsSelected.Contains("SystemInfo")) {
                collectorsToRun.Insert(0, "SystemInfo");
            }

            foreach (var collectorName in collectorsToRun) {
                var collectorType = Type.GetType($"{CollectorsNamespace}.{collectorName}");
                Debug.Assert(collectorType != null, nameof(collectorType) + " != null");

                try {
                    collectors.Add((Collector)Activator.CreateInstance(collectorType));
                } catch (TargetInvocationException ex) {
                    WriteConsoleError($"{collectorName} collector failed to initialize: {ex.InnerException?.Message}");
                }
            }

            if (outputFormat == OutputFormat.Json) {
                /*
                 * The serialization and immediate deserialization provides a copy of the
                 * underlying collector metadata. Definitely not at all efficient, but it
                 * works and and we're not dealing with any large JSON data structures.
                 */
                var collectorsData = new ExpandoObject();
                foreach (var collector in collectors) {
                    ((IDictionary<string, object>)collectorsData)[collector.JsonName] =
                        JsonConvert.DeserializeObject(collector.ConvertToJson());
                }

                var collectorsJson = JsonConvert.SerializeObject(collectorsData, Formatting.Indented);
                Console.WriteLine(collectorsJson);
                return;
            }

            var consoleFirstOutput = true;

            foreach (var collector in collectors) {
                if (!consoleFirstOutput && outputFormat == OutputFormat.Raw) {
                    Console.WriteLine();
                }

                collector.ConsoleColorOutput = colorOutput;
                collector.WriteConsole(consoleOutputStyle);
                consoleFirstOutput = false;
            }

            if (outputFormat == OutputFormat.Table) {
                Console.WriteLine(new string('-', 119));
            }
        }

        private enum OutputFormat {
            Raw,
            Table,
            Json
        }
    }
}
