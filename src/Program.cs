using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Dynamic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

using Newtonsoft.Json;

using QueryHardwareSecurity.Collectors;

using static QueryHardwareSecurity.Utilities;


// Mark assembly as not CLS compliant
[assembly: CLSCompliant(false)]

// For P/Invoke only search in %windir%\System32
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]


namespace QueryHardwareSecurity {
    internal class Program {
        private enum OutputFormat {
            Raw,
            Table,
            Json
        }


        private static readonly string CollectorsNamespace =
            $"{Assembly.GetExecutingAssembly().GetName().Name}.Collectors";

        private static readonly Type CollectorsBaseClass = Type.GetType($"{CollectorsNamespace}.Collector");
        private static readonly string[] CollectorsSortExclusions = {"SystemInfo", "Miscellaneous"};

        internal static bool DebugOutput;
        internal static bool VerboseOutput;

        public static async Task<int> Main(params string[] args) {
            IsPlatformSupported();

            var validOutputs = Enum.GetNames(typeof(OutputFormat)).Select(format => format.ToLower()).ToArray();

            var validCollectors = Assembly.GetExecutingAssembly().GetTypes()
                                          .Where(type => type.IsSubclassOf(CollectorsBaseClass))
                                          .Select(collector => collector.Name)
                                          .ToArray();

            var rootCommand = new RootCommand {
                new Option<bool>(new[] {"-v", "--verbose"}, "Verbose output"),
                new Option<bool>(new[] {"-d", "--debug"}, "Debug output (implies verbose)"),
                new Option<bool>(new[] {"-nc", "--no-color"}, "No colored output"),
                new Option<string>(new[] {"-o", "--output"}, "Output format") {
                    Name = "outputFormatString",
                    Argument = new Argument<string>(() => "table") {Arity = ArgumentArity.ExactlyOne}
                }.FromAmong(validOutputs),
                new Option<string[]>(new[] {"-c", "--collectors"}, "Collectors to run") {
                    Name = "collectorsSelected", Argument = new Argument<string[]> {Arity = ArgumentArity.OneOrMore}
                }.FromAmong(validCollectors)
            };

            rootCommand.Handler = CommandHandler.Create<bool, bool, bool, string, string[]>(
                (verbose, debug, noColor, outputFormatString, collectorsSelected) => {
                    VerboseOutput = verbose;
                    DebugOutput = debug;
                    if (DebugOutput) {
                        VerboseOutput = true;
                    }

                    var colorOutput = !noColor;
                    if (colorOutput) {
                        ResetConsoleColor();
                    }

                    Enum.TryParse(outputFormatString, true, out OutputFormat outputFormat);

                    var collectors = new List<Collector>();
                    collectorsSelected = collectorsSelected ?? validCollectors;

                    // Ensure order of execution is deterministic
                    var collectorsToRun = collectorsSelected
                                         .Where(collector => !CollectorsSortExclusions.Contains(collector))
                                         .OrderBy(collector => collector).ToList();

                    // SystemInfo collector should be first
                    if (collectorsSelected.Contains("SystemInfo")) {
                        collectorsToRun.Insert(0, "SystemInfo");
                    }

                    // Miscellaneous collector should be last
                    if (collectorsSelected.Contains("Miscellaneous")) {
                        collectorsToRun.Add("Miscellaneous");
                    }

                    foreach (var collectorName in collectorsToRun) {
                        var collectorType = Type.GetType($"{CollectorsNamespace}.{collectorName}");
                        try {
                            collectors.Add((Collector)Activator.CreateInstance(collectorType));
                        } catch (TargetInvocationException ex) {
                            WriteConsoleError(
                                $"{collectorName} collector failed to initialize: {ex.InnerException.Message}");
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
                    Enum.TryParse(outputFormatString, true, out ConsoleOutputStyle consoleOutputStyle);

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
                });

            return await rootCommand.InvokeAsync(args).ConfigureAwait(false);
        }
    }
}
