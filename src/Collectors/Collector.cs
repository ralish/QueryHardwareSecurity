using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;

using Microsoft.CSharp.RuntimeBinder;

using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    internal enum ConsoleOutputStyle {
        Raw,
        Table
    }


    internal abstract class Collector {
        internal string Name { get; }
        internal string ModuleName { get; }

        // Console output
        internal bool ConsoleColorOutput { get; set; } = true;
        protected ConsoleOutputStyle ConsoleOutputStyle { get; set; } = ConsoleOutputStyle.Table;
        private string ConsolePrefix { get; }

        // Console table output
        protected int ConsoleWidthName { get; set; } = 25;
        protected int ConsoleWidthValue { get; set; } = 25;
        protected int ConsoleWidthDescription { get; set; }

        // JSON output
        internal string JsonName { get; }

        protected Collector(string name) {
            Name = name;
            ModuleName = GetType().Name;
            ConsolePrefix = $"[{ModuleName}]";
            JsonName = char.ToLower(ModuleName[0]) + ModuleName.Substring(1);
            WriteConsoleVerbose("Initializing collector ...");
        }

        internal abstract string ConvertToJson();

        internal abstract void WriteConsole(ConsoleOutputStyle style);

        #region Console helpers

        protected void WriteConsoleEntry(string name, string value, string description = null) {
            if (ConsoleOutputStyle == ConsoleOutputStyle.Raw) {
                Console.WriteLine($"{name.PadRight(ConsoleWidthName)} : {value}");
                return;
            }

            Console.Write($"| {name.PadRight(ConsoleWidthName)} | {value.PadRight(ConsoleWidthValue)} |");
            if (description != null) {
                Console.Write($" {description.PadRight(ConsoleWidthDescription)} |");
            }

            Console.WriteLine();
        }

        protected void WriteConsoleEntry(string name, List<string> values) {
            if (ConsoleOutputStyle == ConsoleOutputStyle.Raw) {
                Console.WriteLine($"{name.PadRight(ConsoleWidthName)} : {string.Join(", ", values)}");
                return;
            }

            Console.WriteLine($"| {name.PadRight(ConsoleWidthName)} | {values.First().PadRight(ConsoleWidthValue)} |");
            foreach (var value in values.Skip(1)) {
                Console.WriteLine($"| {new string(' ', ConsoleWidthName)} | {value.PadRight(ConsoleWidthValue)} |");
            }
        }

        protected void WriteConsoleEntry(string name, bool value, bool invert = false, string description = null) {
            Console.Write(ConsoleOutputStyle == ConsoleOutputStyle.Table
                              ? $"| {name.PadRight(ConsoleWidthName)} | "
                              : $"{name.PadRight(ConsoleWidthName)} : ");

            WriteConsoleFlag(value, invert);

            if (ConsoleOutputStyle == ConsoleOutputStyle.Table) {
                Console.Write(" |");
                if (description != null) {
                    Console.Write($" {description.PadRight(ConsoleWidthDescription)} |");
                }
            }

            Console.WriteLine();
        }

        protected void WriteConsoleEntry(string name, dynamic metadata) {
            var data = GetOrCreateDynamicObjectKey(metadata, name);

            string value;
            try {
                value = data.value;
            } catch (RuntimeBinderException) {
                throw new ArgumentNullException($"Dynamic object missing value for key: {name}");
            }

            string description = null;
            try {
                description = data.description;
            } catch (RuntimeBinderException) { }

            WriteConsoleEntry(name, value, description);
        }

        protected void WriteConsoleFlags(Enum flags, dynamic metadata, List<string> ignored = null) {
            foreach (Enum flag in Enum.GetValues(flags.GetType())) {
                var flagName = flag.ToString();

                if (ignored != null && ignored.Contains(flagName)) {
                    continue;
                }

                if (ConsoleOutputStyle == ConsoleOutputStyle.Raw) {
                    Console.WriteLine($"{flagName.PadRight(ConsoleWidthName)} : {flags.HasFlag(flag)}");
                    continue;
                }

                var flagData = GetOrCreateDynamicObjectKey(metadata, flagName);

                var description = string.Empty;
                try {
                    description = flagData.description;
                } catch (RuntimeBinderException) { }

                var invert = false;
                try {
                    invert = flagData.invert;
                } catch (RuntimeBinderException) { }

                WriteConsoleEntry(flagName, flags.HasFlag(flag), invert, description);
            }
        }

        protected void WriteConsoleHeader(bool withDescription) {
            if (ConsoleOutputStyle == ConsoleOutputStyle.Raw) {
                WriteConsoleTitle();
                Console.WriteLine();
                return;
            }

            var tableDivider = new string('-', ConsoleWidthName + ConsoleWidthValue + 7); // Separators & spacing
            if (withDescription) {
                tableDivider += new string('-', ConsoleWidthDescription + 3); // Separators & spacing
            }

            var extraSpace = (tableDivider.Length - Name.Length) % 2 == 1;
            var titlePadding = new string(' ', (tableDivider.Length - (Name.Length + 2)) / 2);

            Console.WriteLine(tableDivider);
            Console.Write($"|{titlePadding}");
            WriteConsoleTitle();

            if (extraSpace) {
                Console.Write(" ");
            }

            Console.WriteLine($"{titlePadding}|");
            Console.WriteLine(tableDivider);
        }

        private void WriteConsoleFlag(bool value, bool invert) {
            if (ConsoleColorOutput) {
                var colorTrue = invert ? ConsoleColor.Red : ConsoleColor.Green;
                var colorFalse = invert ? ConsoleColor.Green : ConsoleColor.Red;
                Console.ForegroundColor = value ? colorTrue : colorFalse;
            }

            Console.Write($"{value.ToString().PadRight(ConsoleWidthValue)}");

            if (ConsoleColorOutput) {
                ResetConsoleColor();
            }
        }

        private void WriteConsoleTitle() {
            if (ConsoleColorOutput) {
                Console.ForegroundColor = ConsoleColor.Magenta;
            }

            Console.Write(Name);

            if (ConsoleColorOutput) {
                ResetConsoleColor();
            }
        }

        #endregion

        #region Data parsing

        protected void ParseFlags(Enum flags, dynamic metadata, List<string> ignored = null) {
            WriteConsoleVerbose($"Parsing {flags.GetType().Name} flags ...");

            foreach (Enum flag in Enum.GetValues(flags.GetType())) {
                var flagName = flag.ToString();

                if (ignored != null && ignored.Contains(flagName)) {
                    continue;
                }

                var flagData = GetOrCreateDynamicObjectKey(metadata, flagName);
                flagData.value = flags.HasFlag(flag);
            }
        }

        #endregion

        #region Utility wrappers

        protected ExpandoObject LoadMetadata() {
            return LoadJsonResource(GetType().ToString());
        }

        protected void WriteConsoleError(string msg, bool prefix = true) {
            Utilities.WriteConsoleError(prefix ? $"{ConsolePrefix,-20} {msg}" : $"{new string(' ', 20)} {msg}");
        }

        protected void WriteConsoleVerbose(string msg, bool prefix = true) {
            Utilities.WriteConsoleVerbose(prefix ? $"{ConsolePrefix,-20} {msg}" : $"{new string(' ', 20)} {msg}");
        }

        #endregion
    }
}
