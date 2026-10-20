using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text.RegularExpressions;

namespace Kudunmap.Core
{
    public enum ScanKind { Tcp, Udp, Ping }

    public enum PortMode { Default, Fast, All, Custom }

    /// <summary>Everything the user chose on the New scan screen. Saved as JSON for "My presets".</summary>
    [DataContract]
    public sealed class ScanOptions
    {
        public static readonly string[] SafeCategories = { "default", "safe", "discovery", "version", "vuln" };
        public static readonly string[] AdvancedCategories = { "auth", "broadcast", "brute", "dos", "exploit", "external", "fuzzer", "intrusive", "malware" };

        [DataMember] public string PresetId { get; set; } = "services";
        [DataMember] public string Title { get; set; } = "Services & versions";
        [DataMember] public string Targets { get; set; } = string.Empty;
        [DataMember] public string TargetFile { get; set; }
        [DataMember] public ScanKind Kind { get; set; } = ScanKind.Tcp;
        [DataMember] public PortMode Ports { get; set; } = PortMode.Default;
        [DataMember] public string CustomPorts { get; set; } = string.Empty;
        [DataMember] public int Timing { get; set; } = 4;
        [DataMember] public bool SkipPing { get; set; }
        [DataMember] public bool ResolveNames { get; set; } = true;
        [DataMember] public bool OnlyOpen { get; set; } = true;
        [DataMember] public bool DetectVersions { get; set; }
        [DataMember] public bool DetectOs { get; set; }
        [DataMember] public bool Traceroute { get; set; }
        [DataMember] public List<string> Scripts { get; set; } = new List<string>();
        [DataMember] public bool Vulners { get; set; }

        public ScanOptions Clone()
        {
            var copy = (ScanOptions)MemberwiseClone();
            copy.Scripts = new List<string>(Scripts ?? new List<string>());
            return copy;
        }

        public bool UsesScripts => (Scripts?.Count ?? 0) > 0 || Vulners;

        /// <summary>Version detection is needed by the vuln and vulners scripts, so it is switched on with them.</summary>
        public bool EffectiveVersions => Kind != ScanKind.Ping && (DetectVersions || Vulners || HasScript("vuln"));

        public bool HasScript(string category) => Scripts != null && Scripts.Contains(category, StringComparer.OrdinalIgnoreCase);

        public bool UsesAdvancedScripts => Scripts != null && Scripts.Any(s => AdvancedCategories.Contains(s, StringComparer.OrdinalIgnoreCase));

        /// <summary>The reasons this scan needs administrator rights, empty if it doesn't.</summary>
        public List<string> AdminReasons()
        {
            var reasons = new List<string>();
            if (Kind == ScanKind.Udp) reasons.Add("UDP scans");
            if (DetectOs && Kind != ScanKind.Ping) reasons.Add("operating system detection");
            if (Traceroute) reasons.Add("traceroute");
            return reasons;
        }

        public bool NeedsAdmin => AdminReasons().Count > 0;
    }

    /// <summary>One piece of the Nmap command, with a plain-English meaning for the command preview.</summary>
    public sealed class CommandPart
    {
        public CommandPart(string[] args, string meaning, bool internalOnly = false)
        {
            Args = args;
            Meaning = meaning;
            Internal = internalOnly;
        }

        public string[] Args { get; }
        public string Meaning { get; }

        /// <summary>Added by KUDUNMAP for live progress and results. Left out of the copied command.</summary>
        public bool Internal { get; }

        public string Text => string.Join(" ", Args.Select(CommandBuilder.QuoteForDisplay));
    }

    public static class CommandBuilder
    {
        // Host names, IPv4/IPv6 addresses, ranges (10.0.0.1-50, 10.0.0-2.*), CIDR (10.0.0.0/24) and IPv6 scopes (fe80::1%eth0).
        private static readonly Regex TargetToken = new Regex(@"^[A-Za-z0-9\[][A-Za-z0-9.\-:/,*\[\]%_]*$", RegexOptions.CultureInvariant);
        private static readonly Regex PortSpec = new Regex(@"^[0-9TUSPtusp:,\-]+$", RegexOptions.CultureInvariant);

        public static List<string> SplitTargets(string text) =>
            (text ?? string.Empty).Split(new[] { ' ', '\t', '\r', '\n', ';' }, StringSplitOptions.RemoveEmptyEntries).ToList();

        /// <summary>Returns a message explaining what's wrong with the target, or null when it's fine.</summary>
        public static string ValidateTargets(string text)
        {
            var tokens = SplitTargets(text);
            if (tokens.Count == 0) return "Type an IP address, host name, range or network to scan.";
            foreach (var t in tokens)
            {
                if (!TargetToken.IsMatch(t))
                    return $"\"{t}\" doesn't look like an address, name, range or network.\n\n" +
                           "Examples: 192.168.1.10, router.lan, 192.168.1.1-50, 192.168.1.0/24";
            }
            return null;
        }

        /// <summary>
        /// Roughly how many addresses the targets cover: CIDR blocks and octet ranges are counted, names count as one.
        /// Returns -1 if it can't tell (for example IPv6 networks).
        /// </summary>
        public static long CountAddresses(string text)
        {
            long total = 0;
            foreach (var t in SplitTargets(text))
            {
                var slash = t.IndexOf('/');
                if (slash > 0 && int.TryParse(t.Substring(slash + 1), out var bits))
                {
                    if (t.Contains(":") || bits < 0 || bits > 32) return -1;
                    total += 1L << (32 - bits);
                    continue;
                }

                var octets = t.Split('.');
                if (octets.Length == 4 && octets.All(o => Regex.IsMatch(o, @"^[0-9,\-*]+$")))
                {
                    long count = 1;
                    foreach (var o in octets) count *= OctetCount(o);
                    total += count;
                }
                else
                {
                    total += 1;
                }
            }
            return total;
        }

        private static long OctetCount(string octet)
        {
            if (octet.Contains("*")) return 256;
            long count = 0;
            foreach (var part in octet.Split(','))
            {
                var range = part.Split('-');
                if (range.Length == 2)
                {
                    var from = range[0].Length == 0 ? 0 : int.TryParse(range[0], out var f) ? f : 0;
                    var to = range[1].Length == 0 ? 255 : int.TryParse(range[1], out var t) ? t : 255;
                    count += Math.Max(0, Math.Min(255, to) - from + 1);
                }
                else
                {
                    count += 1;
                }
            }
            return Math.Max(1, count);
        }

        public static string NormalizePorts(string text) => Regex.Replace(text ?? string.Empty, @"\s+", string.Empty);

        public static string ValidatePorts(string text)
        {
            var ports = NormalizePorts(text);
            if (ports.Length == 0) return "Type the ports to scan, for example 22,80,443 or 1-1024.";
            return ports == "-" || (PortSpec.IsMatch(ports) && !ports.StartsWith("-", StringComparison.Ordinal))
                ? null
                : $"\"{text}\" isn't a valid port list. Use numbers, commas and ranges, for example 22,80,443 or 1-1024.";
        }

        /// <summary>The options the user chose, as Nmap arguments with explanations (targets not included).</summary>
        public static List<CommandPart> Describe(ScanOptions o, bool isAdmin)
        {
            var parts = new List<CommandPart>();
            void Add(string meaning, params string[] args) => parts.Add(new CommandPart(args, meaning));

            switch (o.Kind)
            {
                case ScanKind.Ping:
                    Add("find hosts only, no port scan", "-sn");
                    break;
                case ScanKind.Udp:
                    Add("UDP scan", "-sU");
                    break;
                default:
                    if (isAdmin) Add("fast SYN scan", "-sS");
                    else Add("connect scan (works without admin)", "-sT");
                    break;
            }

            if (o.Kind != ScanKind.Ping)
            {
                switch (o.Ports)
                {
                    case PortMode.Fast:
                        Add("top 100 ports", "-F");
                        break;
                    case PortMode.All:
                        Add("all 65,535 ports", "-p-");
                        break;
                    case PortMode.Custom:
                        Add("only these ports", "-p", NormalizePorts(o.CustomPorts));
                        break;
                }
            }

            if (o.EffectiveVersions) Add("detect versions", "-sV");
            if (o.DetectOs && o.Kind != ScanKind.Ping) Add("detect operating system", "-O");

            var scripts = new List<string>(o.Scripts ?? new List<string>());
            if (o.Vulners) scripts.Add("vulners");
            if (scripts.Count == 1 && scripts[0] == "default") Add("default scripts", "-sC");
            else if (scripts.Count > 0) Add("run these scripts", "--script", string.Join(",", scripts));

            if (o.Traceroute) Add("trace the route", "--traceroute");
            if (o.SkipPing) Add("treat every host as online", "-Pn");
            if (!o.ResolveNames) Add("don't look up names", "-n");
            if (o.OnlyOpen && o.Kind != ScanKind.Ping) Add("only show open ports", "--open");
            Add(Presets.TimingMeaning(o.Timing), "-T" + Math.Max(0, Math.Min(5, o.Timing)));
            return parts;
        }

        /// <summary>The arguments KUDUNMAP adds so it can show live progress and read the results.</summary>
        public static List<CommandPart> Internal(string xmlPath) => new List<CommandPart>
        {
            new CommandPart(new[] { "-v" }, "list ports as they're found", true),
            new CommandPart(new[] { "--stats-every", "2s" }, "progress updates", true),
            new CommandPart(new[] { "-oX", xmlPath }, "results for KUDUNMAP", true)
        };

        public static List<string> TargetArgs(ScanOptions o) =>
            !string.IsNullOrEmpty(o.TargetFile) ? new List<string> { "-iL", o.TargetFile } : SplitTargets(o.Targets);

        /// <summary>The full argument list KUDUNMAP passes to nmap.exe.</summary>
        public static List<string> BuildArguments(ScanOptions o, bool isAdmin, string xmlPath)
        {
            var args = new List<string>();
            foreach (var p in Describe(o, isAdmin)) args.AddRange(p.Args);
            foreach (var p in Internal(xmlPath)) args.AddRange(p.Args);
            args.AddRange(TargetArgs(o));
            return args;
        }

        /// <summary>A command the user can paste into a terminal. Leaves out KUDUNMAP's own progress options.</summary>
        public static string CopyableCommand(ScanOptions o, bool isAdmin)
        {
            var args = new List<string>();
            foreach (var p in Describe(o, isAdmin)) args.AddRange(p.Args);
            args.AddRange(TargetArgs(o));
            return "nmap " + string.Join(" ", args.Select(QuoteForDisplay));
        }

        public static string QuoteForDisplay(string arg) =>
            arg.IndexOfAny(new[] { ' ', '\t', '"' }) >= 0 ? QuoteArgument(arg) : arg;

        /// <summary>Joins arguments the way Windows programs split them again (CommandLineToArgvW rules).</summary>
        public static string JoinArguments(IEnumerable<string> args) => string.Join(" ", args.Select(QuoteArgument));

        public static string QuoteArgument(string arg)
        {
            if (string.IsNullOrEmpty(arg)) return "\"\"";
            if (arg.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0) return arg;

            var sb = new System.Text.StringBuilder("\"");
            var backslashes = 0;
            foreach (var c in arg)
            {
                if (c == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (c == '"')
                {
                    sb.Append('\\', backslashes * 2 + 1);
                    sb.Append('"');
                }
                else
                {
                    sb.Append('\\', backslashes);
                    sb.Append(c);
                }
                backslashes = 0;
            }
            sb.Append('\\', backslashes * 2);
            sb.Append('"');
            return sb.ToString();
        }
    }
}
