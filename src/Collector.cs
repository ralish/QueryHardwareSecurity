using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;

using Newtonsoft.Json;

using static QueryHardwareSecurity.Utilities;

namespace QueryHardwareSecurity {
    internal enum OutputFormat {
        Raw,
        Table,
        Json
    }

    internal enum TableStyle {
        Basic,
        Full
    }

    internal abstract class Collector {
        private const int RawNameWidth = 40;
        private const int TableFullWidth = 159;
        private const int TableNameWidth = 40;
        private const int TableValueMinWidth = 21;
        private const int TableSecureWidth = 6; // "Secure"

        private Dictionary<string, MetadataEntry> _metadata = new Dictionary<string, MetadataEntry>();

        protected Collector(string name, TableStyle tableStyle) {
            Name = name;
            TableStyle = tableStyle;

            var moduleName = GetType().Name;
            JsonName = char.ToLower(moduleName[0], CultureInfo.InvariantCulture) + moduleName.Substring(1);
            OutputPrefix = $"[{Name}]";

            switch (tableStyle) {
                case TableStyle.Basic:
                    TableValueWidth = TableFullWidth - TableNameWidth - 7; // 7 is for pipes and padding
                    break;
                case TableStyle.Full:
                    TableValueWidth = TableValueMinWidth;
                    TableDescWidth = TableFullWidth - TableNameWidth - TableValueWidth - TableSecureWidth - 13; // 13 is for pipes and padding
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(tableStyle), tableStyle, "Unexpected value for table style.");
            }

            WriteVerbose("Initializing collector ...");
            LoadMetadata();
        }

        internal string Name { get; }
        internal string JsonName { get; }

        private string OutputPrefix { get; }
        private OutputFormat OutputFormat { get; set; } = OutputFormat.Raw;
        private bool OutputColor { get; set; }

        private TableStyle TableStyle { get; }
        private int TableValueWidth { get; }
        private int TableDescWidth { get; }

        /// <summary>Serialize the collector results to JSON.</summary>
        /// <returns>The collector results as a serialized JSON string.</returns>
        internal abstract string ConvertToJson();

        /// <summary>Write the collector results to standard output.</summary>
        /// <param name="format">The <see cref="OutputFormat" /> to use.</param>
        /// <param name="color">Whether the output should use colour.</param>
        internal abstract void WriteOutput(OutputFormat format, bool color);

        /// <summary>Configures the output format and colour settings for the collector.</summary>
        /// <param name="format">The output format to use. Must not be <see cref="OutputFormat.Json" />.</param>
        /// <param name="color">A boolean which indicates if output should use colour.</param>
        /// <exception cref="ArgumentException">Thrown if <paramref name="format" /> is <see cref="OutputFormat.Json" />.</exception>
        protected void SetOutputSettings(OutputFormat format, bool color) {
            if (format == OutputFormat.Json) throw new ArgumentException("Output format cannot be JSON.", nameof(format));
            OutputFormat = format;
            OutputColor = color;
        }

        #region Error handling

        /// <summary>
        ///     Writes a generic error message to standard error indicating that the operating system does not support the feature
        ///     this collector pertains to and throws a <see cref="NotImplementedException" />.
        /// </summary>
        /// <exception cref="NotImplementedException">Always thrown with the same message output to standard error.</exception>
        /// <remarks>>Only intended to be called from the constructor of a collector on initialisation failure.</remarks>
        protected void NotSupportedFailure() {
            var msg = $"Operating system does not support {Name}.";
            WriteError(msg);
            throw new NotImplementedException(msg);
        }

        /// <summary>
        ///     Handles a non-zero exit code from NtQuerySystemInformation. Subject to the provided NTSTATUS code, either calls
        ///     <see cref="NotSupportedFailure" /> or throws a <see cref="Win32Exception" />.
        /// </summary>
        /// <param name="ntStatus">The NTSTATUS error code returned by the earlier call to NtQuerySystemInformation.</param>
        /// <exception cref="Win32Exception">
        ///     Thrown if the provided NTSTATUS code does not correspond to an error which indicates the requested information
        ///     class is unsupported.
        /// </exception>
        /// <remarks>
        ///     Only intended to be called from the constructor of a collector if a required call to NtQuerySystemInformation
        ///     returns a non-zero exit code.
        /// </remarks>
        protected void NtQsiFailure(int ntStatus) {
            switch (ntStatus) {
                case 0: return;   // STATUS_SUCCESS
                case -1073741822: // STATUS_NOT_IMPLEMENTED (0xC0000002)
                case -1073741821: // STATUS_INVALID_INFO_CLASS (0xC0000003)
                case -1073741637: // STATUS_NOT_SUPPORTED (0xC00000BB)
                    NotSupportedFailure();
                    break;
                default:
                    var symbolicNtStatus = GetSymbolicNtStatus(ntStatus);
                    WriteError($"Error requesting {Name} information: {ntStatus} ({symbolicNtStatus})");
                    throw new Win32Exception(symbolicNtStatus);
            }
        }

        #endregion

        #region Metadata loading

#pragma warning disable CS0649 // Field is never assigned to

        // ReSharper disable once ClassNeverInstantiated.Local
        private sealed class MetadataEntry {
            // ReSharper disable once InconsistentNaming
            // ReSharper disable once NotNullOrRequiredMemberIsNotInitialized
            public string description;
        }

#pragma warning restore CS0649 // Field is never assigned to

        /// <summary>Loads any available metadata for the collector.</summary>
        /// <remarks>Metadata must be an embedded JSON resource with the same name as the collector.</remarks>
        private void LoadMetadata() {
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"{GetType()}.json");
            if (stream == null) return;

            using var reader = new StreamReader(stream);
            var resource = reader.ReadToEnd();
            _metadata = JsonConvert.DeserializeObject<Dictionary<string, MetadataEntry>>(resource);
        }

        #endregion

        #region Output helpers

        /// <summary>Write a header for the collector to standard output.</summary>
        /// <remarks>The output format depends on the configured <see cref="OutputFormat" />.</remarks>
        protected void WriteOutputHeader() {
            if (OutputFormat == OutputFormat.Raw) {
                WriteOutputTitle();
                Console.WriteLine();
                return;
            }

            // Separators & spacing
            var tableDivider = new string('-', TableFullWidth);
            var extraSpace = (tableDivider.Length - Name.Length) % 2 == 1;
            var titlePadding = new string(' ', (tableDivider.Length - (Name.Length + 2)) / 2);

            // Table title
            Console.WriteLine(tableDivider);
            Console.Write($"|{titlePadding}");
            WriteOutputTitle();
            if (extraSpace) Console.Write(" ");
            Console.WriteLine($"{titlePadding}|");
            Console.WriteLine(tableDivider);

            // Column headers
            Console.Write($"| {"Name",-TableNameWidth} | {"Value".PadRight(TableValueWidth)} |");
            if (TableStyle == TableStyle.Full) {
                Console.Write($" {"Secure",-TableSecureWidth} | {"Description".PadRight(TableDescWidth)} |");
            }
            Console.WriteLine($"\n{tableDivider}");
        }

        /// <summary>Write the title of the collector to standard output.</summary>
        /// <remarks>No newline is written. The use of colour depends on the <see cref="OutputColor" /> setting.</remarks>
        private void WriteOutputTitle() {
            if (OutputColor) Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write(Name);
            if (OutputColor) ResetColor();
        }

        /// <summary>Write the provided key-value pair to standard output.</summary>
        /// <param name="name">The name of the key.</param>
        /// <param name="value">The value of the key.</param>
        /// <param name="secure">
        ///     A boolean which represents if the <see cref="value" /> is considered secure. This parameter is
        ///     only used with the Table <see cref="OutputFormat" /> and is otherwise ignored.
        /// </param>
        /// <param name="valueColor">
        ///     The <see cref="ConsoleColor" /> for the <see cref="secure" /> boolean value. If null, the foreground colour will
        ///     not be modified. If the <see cref="OutputColor" /> setting is disabled this parameter is ignored.
        /// </param>
        /// <remarks>The output format depends on the configured <see cref="OutputFormat" />.</remarks>
        protected void WriteOutputEntry(string name, string value, bool? secure = null, ConsoleColor? valueColor = null) {
            if (OutputFormat == OutputFormat.Raw) {
                Console.WriteLine($"{name,-RawNameWidth} {value}");
                return;
            }

            // Name
            Console.Write($"| {name,-TableNameWidth} | ");

            // Value
            if (OutputColor && valueColor != null) Console.ForegroundColor = (ConsoleColor)valueColor;
            Console.Write(value.PadRight(TableValueWidth));
            if (OutputColor && valueColor != null) ResetColor();

            if (TableStyle == TableStyle.Full) {
                // Secure
                Console.Write(" | ");
                if (secure != null) {
                    if (OutputColor) Console.ForegroundColor = secure.Value ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.Write(secure.ToString().PadRight(TableSecureWidth));
                    if (OutputColor) ResetColor();
                } else {
                    Console.Write(new string('-', TableSecureWidth));
                }

                // Description
                var description = _metadata.TryGetValue(name, out var metadata) ? metadata.description : string.Empty;
                Console.Write($" | {description.PadRight(TableDescWidth)}");
            }

            Console.WriteLine(" |");
        }

        /// <summary>Write the provided key and its boolean value to standard output.</summary>
        /// <param name="name">The name of the key.</param>
        /// <param name="value">
        ///     The value of the key. If not null, the string representation of the boolean value will be output. If null and using
        ///     the Table <see cref="OutputFormat" />, the value will be "-" characters that fill the column.
        /// </param>
        /// <param name="secure">
        ///     A boolean which represents if the <see cref="value" /> is considered secure. This parameter is
        ///     only used with the Table <see cref="OutputFormat" /> and is otherwise ignored.
        /// </param>
        /// <remarks>The output format depends on the configured <see cref="OutputFormat" />.</remarks>
        protected void WriteOutputEntry(string name, bool? value, bool? secure = null) {
            var valStr = value != null ? value.ToString() : new string('-', TableValueWidth);
            WriteOutputEntry(name, valStr, secure);
        }

        /// <summary>Write the provided key and its byte value to standard output.</summary>
        /// <param name="name">The name of the key.</param>
        /// <param name="value">
        ///     The value of the key. If not null, the string representation of the byte value will be output. If null and using
        ///     the Table <see cref="OutputFormat" />, the value will be "-" characters that fill the column.
        /// </param>
        /// <param name="secure">
        ///     A boolean which represents if the <see cref="value" /> is considered secure. This parameter is
        ///     only used with the Table <see cref="OutputFormat" /> and is otherwise ignored.
        /// </param>
        /// <remarks>The output format depends on the configured <see cref="OutputFormat" />.</remarks>
        protected void WriteOutputEntry(string name, byte? value, bool? secure = null) {
            var valStr = value != null ? value.ToString() : new string('-', TableValueWidth);
            WriteOutputEntry(name, valStr, secure);
        }

        /// <summary>Write the provided key and enumeration value to standard output.</summary>
        /// <param name="name">The name of the key.</param>
        /// <param name="value">
        ///     The value of the key. If not null, the symbolic name of the enumeration value will be output. If null and using
        ///     the Table <see cref="OutputFormat" />, the value will be "-" characters that fill the column.
        /// </param>
        /// <param name="secure">
        ///     A boolean which represents if the <see cref="value" /> is considered secure. This parameter is
        ///     only used with the Table <see cref="OutputFormat" /> and is otherwise ignored.
        /// </param>
        /// <remarks>The output format depends on the configured <see cref="OutputFormat" />.</remarks>
        protected void WriteOutputEntry(string name, Enum? value, bool? secure = null) {
            var valStr = value != null ? value.ToString() : new string('-', TableValueWidth);
            WriteOutputEntry(name, valStr, secure);
        }

        /// <summary>Writes the provided key and <see cref="List{string}" /> values to standard output.</summary>
        /// <param name="name">The name of the key.</param>
        /// <param name="values">The <see cref="List{string}" /> of values.</param>
        /// <remarks>The output format depends on the configured <see cref="OutputFormat" />.</remarks>
        protected void WriteOutputEntry(string name, List<string> values) {
            if (OutputFormat == OutputFormat.Raw) {
                Console.WriteLine($"{name,-RawNameWidth} : {string.Join(", ", values)}");
                return;
            }

            Console.WriteLine($"| {name,-TableNameWidth} | {values.First().PadRight(TableValueWidth)} |");
            foreach (var value in values.Skip(1)) {
                Console.WriteLine($"| {new string(' ', TableNameWidth)} | {value.PadRight(TableValueWidth)} |");
            }
        }

        #endregion

        #region Utility wrappers

        private const int OutputPrefixPadding = -40;

        /// <summary>Writes a debug message with appropriate padding to standard error.</summary>
        /// <param name="msg">The debug message to write to standard error.</param>
        /// <param name="prefix">Prefix the message with the name of the collector. Defaults to <see langword="true" />.</param>
        /// <remarks>Debug messages are only displayed when debug mode is enabled.</remarks>
        protected void WriteDebug(string msg, bool prefix = true) {
            Utilities.WriteDebug(prefix ? $"{OutputPrefix,OutputPrefixPadding} {msg}" : $"{new string(' ', OutputPrefixPadding)} {msg}");
        }

        /// <summary>Writes an error message with appropriate padding to standard error.</summary>
        /// <param name="msg">The error message to write to standard error.</param>
        /// <param name="prefix">Prefix the message with the name of the collector. Defaults to <see langword="true" />.</param>
        protected void WriteError(string msg, bool prefix = true) {
            Utilities.WriteError(prefix ? $"{OutputPrefix,OutputPrefixPadding} {msg}" : $"{new string(' ', OutputPrefixPadding)} {msg}");
        }

        /// <summary>Writes a verbose message with appropriate padding to standard error.</summary>
        /// <param name="msg">The verbose message to write to standard error.</param>
        /// <param name="prefix">Prefix the message with the name of the collector. Defaults to <see langword="true" />.</param>
        /// <remarks>Verbose messages are only displayed when verbose or debug modes are enabled.</remarks>
        protected void WriteVerbose(string msg, bool prefix = true) {
            Utilities.WriteVerbose(prefix ? $"{OutputPrefix,OutputPrefixPadding} {msg}" : $"{new string(' ', OutputPrefixPadding)} {msg}");
        }

        #endregion
    }
}
