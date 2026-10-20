using System;
using System.Collections.Generic;

namespace Kudunmap.Core
{
    /// <summary>
    /// KUDUNMAP.exe 192.168.1.0/24                  open with this target filled in
    /// KUDUNMAP.exe --preset quick 192.168.1.10     choose a scan type (quick, ping, common, all, services, os, intense, udp, vuln)
    /// KUDUNMAP.exe --scan --preset quick 10.0.0.1  start scanning straight away
    /// --options &lt;file&gt; is used internally when KUDUNMAP restarts itself as administrator.
    /// </summary>
    public sealed class CommandLine
    {
        public List<string> Targets { get; } = new List<string>();
        public string Preset { get; private set; }
        public bool ScanNow { get; private set; }
        public bool SelfTest { get; private set; }

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
