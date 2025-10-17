using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;

using Microsoft.CSharp.RuntimeBinder;

using Newtonsoft.Json;

using static QueryHardwareSecurity.Utilities;


namespace QueryHardwareSecurity.Collectors {
    internal enum ConsoleOutputStyle {
        Raw,
        Table
    }

    internal abstract class Collector {
        private Dictionary<string, MetadataEntry> _metadata = new Dictionary<string, MetadataEntry>();


        protected Collector(string name) {
            Name = name;
            ModuleName = GetType().Name;
            ConsolePrefix = $"[{ModuleName}]";
            JsonName = char.ToLower(ModuleName[0], CultureInfo.InvariantCulture) + ModuleName.Substring(1);

            WriteConsoleVerbose("Initializing collector ...");
            LoadMetadata();
        }

        // ReSharper disable once MemberCanBeProtected.Global
        public string Name { get; }

        // ReSharper disable once MemberCanBePrivate.Global
        public string ModuleName { get; }

        // Console output
        public bool ConsoleColorOutput { get; set; } = true;
        protected ConsoleOutputStyle ConsoleOutputStyle { get; set; } = ConsoleOutputStyle.Table;
        private string ConsolePrefix { get; }

        // Console table output
        protected int ConsoleWidthName { get; set; } = 25;
        protected int ConsoleWidthValue { get; set; } = 25;
        protected int ConsoleWidthDescription { get; set; }

        // JSON output
        public string JsonName { get; }

        /// <summary>Serialize the collector results to JSON.</summary>
        /// <returns>The collector results as a serialized JSON string.</returns>
        public abstract string ConvertToJson();

        /// <summary>Write the collector results to the console.</summary>
        /// <param name="style">The <see cref="ConsoleOutputStyle" /> to use for the output.</param>
        public abstract void WriteConsole(ConsoleOutputStyle style);

        #region Data parsing

        /// <summary>
        ///     Parses a bit field and stores each flag name and its value as a key-value pair in the provided metadata
        ///     object.
        /// </summary>
        /// <param name="flags">The bit field to parse.</param>
        /// <param name="metadata">The metadata object in which to store the key-value pairs.</param>
        /// <param name="ignored">An optional list of flag names to ignore when parsing the bit field.</param>
        protected void ParseFlags(Enum flags, dynamic metadata, List<string> ignored = null) {
            WriteConsoleVerbose($"Parsing {flags.GetType().Name} flags ...");

            foreach (Enum flag in Enum.GetValues(flags.GetType())) {
                var flagName = flag.ToString();
                if (ignored != null && ignored.Contains(flagName)) continue;

                var flagData = GetOrCreateDynamicObjectKey(metadata, flagName);
                flagData.value = flags.HasFlag(flag);
            }
        }

        #endregion

        private sealed class MetadataEntry {
            public string description;
            public bool invert;
        }

        #region Console helpers

        /// <summary>Writes the provided key-value pair to the console.</summary>
        /// <param name="name">The name of the key.</param>
        /// <param name="value">The value of the key.</param>
        /// <remarks>The output style depends on the configured <see cref="ConsoleOutputStyle" />.</remarks>
        protected void WriteConsoleEntry(string name, string value, ConsoleColor? valueColor = null) {
            if (ConsoleOutputStyle == ConsoleOutputStyle.Raw) {
                Console.WriteLine($"{name.PadRight(ConsoleWidthName)} : {value}");
                return;
            }

            Console.Write($"| {name.PadRight(ConsoleWidthName)} | ");

            if (ConsoleColorOutput && valueColor != null) Console.ForegroundColor = (ConsoleColor)valueColor;
            Console.Write(value.PadRight(ConsoleWidthValue));
            if (ConsoleColorOutput && valueColor != null) ResetConsoleColor();

            if (ConsoleWidthDescription != 0) {
                var description = _metadata.TryGetValue(name, out var metadata) ? metadata.description : string.Empty;
                Console.Write($" | {description.PadRight(ConsoleWidthDescription)}");
            }

            Console.WriteLine(" |");
        }

        /// <summary>Writes the provided key and its boolean value to the console.</summary>
        /// <param name="name">The name of the key.</param>
        /// <param name="value">The boolean value of the key.</param>
        /// <param name="invert">Switch the colours used when colour output is enabled.</param>
        /// <param name="description">An optional description.</param>
        /// <remarks>
        ///     If <see cref="ConsoleColorOutput" /> is enabled the boolean value will be written in colour. By default, green
        ///     is used for true and red for false. The <paramref name="invert" /> parameter can be used to switch these colours.
        ///     The output style depends on the configured <see cref="ConsoleOutputStyle" />.
        /// </remarks>
        protected void WriteConsoleEntry(string name, bool value) {
            var invert = _metadata.TryGetValue(name, out var metadata) && metadata.invert;

            var colorTrue = invert ? ConsoleColor.Red : ConsoleColor.Green;
            var colorFalse = invert ? ConsoleColor.Green : ConsoleColor.Red;

            WriteConsoleEntry(name, value.ToString(), value ? colorTrue : colorFalse);
        }

        /// <summary>Writes the provided key and list of values to the console.</summary>
        /// <param name="name">The name of the key.</param>
        /// <param name="values">The list of values.</param>
        /// <remarks>The output style depends on the configured <see cref="ConsoleOutputStyle" />.</remarks>
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

        /// <summary>
        ///     Parses a bit field, stores each flag name and its value as a key-value pair in the provided metadata object,
        ///     and writes the output to the console.
        /// </summary>
        /// <param name="flags">The bit field to parse and write to the console.</param>
        /// <param name="metadata">The metadata object in which to store the key-value pairs.</param>
        /// <param name="ignored">An optional list of flag names to ignore when parsing the bit field.</param>
        /// <remarks>
        ///     If the flag has a description it will be output. If <see cref="ConsoleColorOutput" /> is enabled the flag
        ///     values will be written in colour. The output style depends on the configured <see cref="ConsoleOutputStyle" />.
        /// </remarks>
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

                //WriteConsoleEntry(flagName, flags.HasFlag(flag), invert, description);
            }
        }

        /// <summary>Writes a header for the collector to the console.</summary>
        /// <param name="withDescription">
        ///     If a description field is used alongside the key-value pairs, must be set to true to
        ///     ensure the header is correctly aligned to the rest of the subsequent output. Only used when
        ///     <see cref="ConsoleOutputStyle" /> is Table.
        /// </param>
        /// <remarks>
        ///     If <see cref="ConsoleColorOutput" /> is enabled the header will be written in colour. The output style depends
        ///     on the configured <see cref="ConsoleOutputStyle" />.
        /// </remarks>
        protected void WriteConsoleHeader(bool withDescription) {
            if (ConsoleOutputStyle == ConsoleOutputStyle.Raw) {
                WriteConsoleTitle();
                Console.WriteLine();
                return;
            }

            // Separators & spacing
            var tableDivider = new string('-', ConsoleWidthName + ConsoleWidthValue + 7);
            if (withDescription) tableDivider += new string('-', ConsoleWidthDescription + 3);

            var extraSpace = (tableDivider.Length - Name.Length) % 2 == 1;
            var titlePadding = new string(' ', (tableDivider.Length - (Name.Length + 2)) / 2);

            Console.WriteLine(tableDivider);
            Console.Write($"|{titlePadding}");
            WriteConsoleTitle();
            if (extraSpace) Console.Write(" ");
            Console.WriteLine($"{titlePadding}|");
            Console.WriteLine(tableDivider);
        }

        /// <summary>Writes the provided boolean value to the console.</summary>
        /// <param name="value">The boolean value to write to the console.</param>
        /// <param name="invert">Switch the colours used when colour output is enabled.</param>
        /// <remarks>
        ///     No newline is written. If <see cref="ConsoleColorOutput" /> is enabled the boolean value will be written in
        ///     colour. By default, green is used for true and red for false. The <paramref name="invert" /> parameter can be used
        ///     to switch these colours.
        /// </remarks>
        internal void WriteConsoleFlag(object value, ConsoleColor colour) {
            if (ConsoleColorOutput) Console.ForegroundColor = colour;
            Console.Write($"{value.ToString().PadRight(ConsoleWidthValue)}");
            if (ConsoleColorOutput) ResetConsoleColor();
        }

        /// <summary>Writes the provided boolean value to the console.</summary>
        /// <param name="value">The boolean value to write to the console.</param>
        /// <param name="invert">Switch the colours used when colour output is enabled.</param>
        /// <remarks>
        ///     No newline is written. If <see cref="ConsoleColorOutput" /> is enabled the boolean value will be written in
        ///     colour. By default, green is used for true and red for false. The <paramref name="invert" /> parameter can be used
        ///     to switch these colours.
        /// </remarks>
        internal void WriteConsoleFlag(bool value, bool invert = false) {
            var colorTrue = invert ? ConsoleColor.Red : ConsoleColor.Green;
            var colorFalse = invert ? ConsoleColor.Green : ConsoleColor.Red;
            WriteConsoleFlag(value, value ? colorTrue : colorFalse);
        }

        /// <summary>Writes the title of the collector to the console.</summary>
        /// <remarks>No newline is written. If <see cref="ConsoleColorOutput" /> is enabled the title will be written in colour.</remarks>
        private void WriteConsoleTitle() {
            if (ConsoleColorOutput) Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write(Name);
            if (ConsoleColorOutput) ResetConsoleColor();
        }

        #endregion

        #region Utility wrappers

        /// <summary>Loads any metadata for the collector.</summary>
        /// <returns>The collector metadata as an ExpandoObject. If no metadata was found, an empty ExpandoObject.</returns>
        /// <remarks>Metadata for a collector must be stored as an embedded JSON resource with the same name as the collector.</remarks>
        private void LoadMetadata() {
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"{GetType()}.json")) {
                if (stream == null) return;

                using (var reader = new StreamReader(stream)) {
                    var resource = reader.ReadToEnd();
                    _metadata = JsonConvert.DeserializeObject<Dictionary<string, MetadataEntry>>(resource);
                }
            }
        }

        /// <summary>Writes a debug message to the console with correct alignment.</summary>
        /// <param name="msg">The debug message to write to the console.</param>
        /// <param name="prefix">Prefix the message with the name of the collector. Defaults to true.</param>
        /// <remarks>Debug messages are only displayed when debug mode is enabled.</remarks>
        protected void WriteConsoleDebug(string msg, bool prefix = true) {
            Utilities.WriteConsoleDebug(prefix ? $"{ConsolePrefix,-20} {msg}" : $"{new string(' ', 20)} {msg}");
        }

        /// <summary>Writes an error message to the console with correct alignment.</summary>
        /// <param name="msg">The error message to write to the console.</param>
        /// <param name="prefix">Prefix the message with the name of the collector. Defaults to true.</param>
        /// <remarks>Error messages are written to the standard error output stream.</remarks>
        protected void WriteConsoleError(string msg, bool prefix = true) {
            Utilities.WriteConsoleError(prefix ? $"{ConsolePrefix,-20} {msg}" : $"{new string(' ', 20)} {msg}");
        }

        /// <summary>Writes a verbose message to the console with correct alignment.</summary>
        /// <param name="msg">The verbose message to write to the console.</param>
        /// <param name="prefix">Prefix the message with the name of the collector. Defaults to true.</param>
        /// <remarks>Verbose messages are only displayed when verbose mode is enabled. Debug mode implicitly enables verbose mode.</remarks>
        protected void WriteConsoleVerbose(string msg, bool prefix = true) {
            Utilities.WriteConsoleVerbose(prefix ? $"{ConsolePrefix,-20} {msg}" : $"{new string(' ', 20)} {msg}");
        }

        #endregion
    }
}
