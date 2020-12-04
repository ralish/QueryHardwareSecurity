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

// For P/Invoke only search for native libraries in %windir%\System32
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]


namespace QueryHardwareSecurity {
    internal class Program {
        internal static bool VerboseOutput;


        private enum OutputFormat {
            Raw,
            Table,
            Json
        }


        private static readonly string CollectorsNamespace =
            $"{Assembly.GetExecutingAssembly().GetName().Name}.Collectors";

        private static readonly Type CollectorsBaseClass = Type.GetType($"{CollectorsNamespace}.Collector");
        private static readonly string[] CollectorsRequired = {"SystemInfo"};

        public static async Task<int> Main(params string[] args) {
            var validCollectors = Assembly.GetExecutingAssembly().GetTypes()
                                          .Where(type => type.IsSubclassOf(CollectorsBaseClass) &&
                                                         !CollectorsRequired.Contains(type.Name))
                                          .Select(collector => collector.Name)
                                          .ToArray();
            var validOutputs = Enum.GetNames(typeof(OutputFormat)).Select(format => format.ToLower()).ToArray();

            var rootCommand = new RootCommand {
                new Option<bool>(new[] {"-v", "--verbose"}, "Verbose output"),
                new Option<bool>(new[] {"-nc", "--no-color"}, "No colored output"),
                new Option<string[]>(new[] {"-c", "--collectors"}, "Collectors to run") {
                    Name = "collectorsToRun", Argument = new Argument<string[]> {Arity = ArgumentArity.OneOrMore}
                }.FromAmong(validCollectors),
                new Option<string>(new[] {"-o", "--output"}, "Output format") {
                    Name = "outputFormatString",
                    Argument = new Argument<string>(() => "table") {Arity = ArgumentArity.ExactlyOne}
                }.FromAmong(validOutputs)
            };

            rootCommand.Handler = CommandHandler.Create<bool, bool, string[], string>(
                (verbose, noColor, collectorsToRun, outputFormatString) => {
                    VerboseOutput = verbose;

                    var colorOutput = !noColor;
                    if (colorOutput) {
                        ResetConsoleColor();
                    }

                    Enum.TryParse(outputFormatString, true, out OutputFormat outputFormat);

                    var collectors = new List<Collector>();
                    collectorsToRun = collectorsToRun ?? validCollectors;

                    var systemInfo = new SystemInfo();
                    collectors.Add(systemInfo);

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
