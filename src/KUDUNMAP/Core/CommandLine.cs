using System;
using System.Collections.Generic;

namespace Kudunmap.Core
{
    /// <summary>
    /// KUDUNMAP.exe 192.168.1.0/24                  open with this target filled in
    /// KUDUNMAP.exe --preset quick 192.168.1.10     choose a scan type (quick, ping, common, all, services, os, intense, udp, vuln)
    /// KUDUNMAP.exe --scan --preset quick 10.0.0.1  start scanning straight away
    /// KUDUNMAP.exe --history                       open with the History window
    /// --options &lt;file&gt; is used internally when KUDUNMAP restarts itself as administrator.
    /// --scheduled &lt;id&gt; [--data &lt;folder&gt;] is what Windows' Task Scheduler runs for a scheduled scan (no window).
    /// --remove-schedules is run when KUDUNMAP is uninstalled.
    /// </summary>
    public sealed class CommandLine
    {
        public List<string> Targets { get; } = new List<string>();
        public string Preset { get; private set; }
        public bool ScanNow { get; private set; }
        public bool SelfTest { get; private set; }
        public bool ShowHistory { get; private set; }

        /// <summary>The scheduled scan to run without a window.</summary>
        public string Scheduled { get; private set; }

        /// <summary>Another data folder (the self-test's own), passed on by its scheduled scans.</summary>
        public string DataFolder { get; private set; }

        public bool RemoveSchedules { get; private set; }

        /// <summary>Options saved by the copy that restarted as administrator. Only files in KUDUNMAP's own folder are accepted.</summary>
        public string OptionsFile { get; private set; }

        public string TargetText => string.Join(" ", Targets);

        public static CommandLine Parse(string[] args)
        {
            var cmd = new CommandLine();
            args = args ?? new string[0];
            for (var i = 0; i < args.Length; i++)
            {
                var arg = (args[i] ?? string.Empty).Trim();
                if (arg.Length == 0) continue;

                if (arg.Equals("--preset", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    var id = args[++i];
                    if (Core.Presets.Find(id) != null) cmd.Preset = id;
                    continue;
                }
                if (arg.Equals("--options", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    var file = args[++i];
                    try
                    {
                        var full = System.IO.Path.GetFullPath(file);
                        var root = System.IO.Path.GetFullPath(AppPaths.Running).TrimEnd('\\') + "\\";
                        if (full.StartsWith(root, StringComparison.OrdinalIgnoreCase) && System.IO.File.Exists(full)) cmd.OptionsFile = full;
                    }
                    catch
                    {
                        // ignore a bad path
                    }
                    continue;
                }
                if (arg.Equals("--scheduled", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    var id = args[++i];
                    if (System.Text.RegularExpressions.Regex.IsMatch(id ?? string.Empty, "^[0-9a-fA-F]{32}$")) cmd.Scheduled = id;
                    continue;
                }
                if (arg.Equals("--data", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    var folder = args[++i];
                    try
                    {
                        if (System.IO.Path.IsPathRooted(folder) && System.IO.Directory.Exists(folder)) cmd.DataFolder = System.IO.Path.GetFullPath(folder);
                    }
                    catch
                    {
                        // ignore a bad path
                    }
                    continue;
                }
                if (arg.Equals("--remove-schedules", StringComparison.OrdinalIgnoreCase))
                {
                    cmd.RemoveSchedules = true;
                    continue;
                }
                if (arg.Equals("--history", StringComparison.OrdinalIgnoreCase))
                {
                    cmd.ShowHistory = true;
                    continue;
                }
                if (arg.Equals("--scan", StringComparison.OrdinalIgnoreCase))
                {
                    cmd.ScanNow = true;
                    continue;
                }
                if (arg.Equals("--self-test", StringComparison.OrdinalIgnoreCase))
                {
                    cmd.SelfTest = true;
                    continue;
                }
                if (arg.StartsWith("-", StringComparison.Ordinal)) continue; // unknown option: ignore

                cmd.Targets.Add(arg);
            }

            // Only accept targets that pass the same check as the target box.
            if (cmd.Targets.Count > 0 && CommandBuilder.ValidateTargets(cmd.TargetText) != null)
            {
                cmd.Targets.Clear();
                cmd.ScanNow = false;
            }
            return cmd;
        }
    }
}
