// Follows a scan as it goes, from Nmap's output: which part it's on, how far, how long is left; and a way to sort
// addresses by number.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace Kudunmap.Core
{
    /// <summary>The parts of a scan, in order.</summary>
    public enum Phase { Starting, FindHosts, ScanPorts, Versions, Os, Scripts, Traceroute, Finishing }

    /// <summary>Reads Nmap's normal text output line by line and keeps track of what it's doing.</summary>
    public sealed class ProgressTracker
    {
        /// <summary>Nmap's "About 40% done; ETC ... (0:01:20 remaining)" lines.</summary>
        private static readonly Regex Timing = new Regex(
            @"^(?<what>.+?) Timing: About (?<pct>[\d.]+)% done(?:; ETC: \S+ \((?<left>[\d:]+) remaining\))?",
            RegexOptions.CultureInvariant);
        /// <summary>Nmap's "Initiating ... scan" lines, saying a new part starts.</summary>
        private static readonly Regex Initiating = new Regex(@"^Initiating (?<what>.+?)(?: at \d|\s*\(|$)", RegexOptions.CultureInvariant);
        /// <summary>Nmap's "Discovered open port" lines.</summary>
        private static readonly Regex Discovered = new Regex(
            @"^Discovered open port (?<port>\d+)/(?<proto>\w+) on (?<host>\S+)", RegexOptions.CultureInvariant);
        /// <summary>Nmap's "Nmap scan report for" lines, one per host found.</summary>
        private static readonly Regex HostUp = new Regex(@"^Nmap scan report for (?<name>\S+)(?: \((?<ip>[^)]+)\))?", RegexOptions.CultureInvariant);

        /// <summary>The part of the scan it's on.</summary>
        public Phase Phase { get; private set; } = Phase.Starting;
        /// <summary>How far the scan is, 0 to 100.</summary>
        public double Percent { get; private set; }
        /// <summary>About how long is left, when Nmap says.</summary>
        public TimeSpan? Remaining { get; private set; }
        /// <summary>What it's doing now, in words.</summary>
        public string Activity { get; private set; } = "Starting Nmap…";

        /// <summary>Host address → open ports seen so far ("80/tcp"), in the order they were found.</summary>
        public SortedDictionary<string, List<string>> Found { get; } = new SortedDictionary<string, List<string>>(new AddressComparer());

        /// <summary>Returns true when something visible changed.</summary>
        public bool Feed(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return false;
            line = line.Trim();

            var m = Discovered.Match(line);
            if (m.Success)
            {
                var host = m.Groups["host"].Value;
                if (!Found.TryGetValue(host, out var ports)) Found[host] = ports = new List<string>();
                var key = m.Groups["port"].Value + "/" + m.Groups["proto"].Value;
                if (!ports.Contains(key)) ports.Add(key);
                return true;
            }

            m = Timing.Match(line);
            if (m.Success)
            {
                SetPhase(m.Groups["what"].Value);
                Percent = double.TryParse(m.Groups["pct"].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var p) ? p : Percent;
                Remaining = ParseRemaining(m.Groups["left"].Value);
                return true;
            }

            m = Initiating.Match(line);
            if (m.Success)
            {
                SetPhase(m.Groups["what"].Value);
                Percent = 0;
                Remaining = null;
                return true;
            }

            if (line.StartsWith("NSE: Script scanning", StringComparison.Ordinal))
            {
                Phase = Phase.Scripts;
                Activity = "Running scripts";
                Percent = 0;
                return true;
            }

            m = HostUp.Match(line);
            if (m.Success)
            {
                var ip = m.Groups["ip"].Success ? m.Groups["ip"].Value : m.Groups["name"].Value;
                if (!Found.ContainsKey(ip)) Found[ip] = new List<string>();
                Phase = Phase.Finishing;
                Activity = "Collecting results";
                return true;
            }

            if (line.StartsWith("Read data files from", StringComparison.Ordinal) || line.StartsWith("Nmap done", StringComparison.Ordinal))
            {
                Phase = Phase.Finishing;
                Activity = "Finishing";
                Percent = 100;
                Remaining = null;
                return true;
            }
            return false;
        }

        /// <summary>Works out the part of the scan from an "Initiating" line.</summary>
        private void SetPhase(string what)
        {
            var w = what.ToLowerInvariant();
            if (w.Contains("ping") || w.Contains("dns") || w.Contains("arp") || w.Contains("host discovery"))
            {
                Phase = Phase.FindHosts;
                Activity = "Finding hosts";
            }
            else if (w.Contains("service"))
            {
                Phase = Phase.Versions;
                Activity = "Detecting versions";
            }
            else if (w.Contains("os detection"))
            {
                Phase = Phase.Os;
                Activity = "Detecting operating systems";
            }
            else if (w.Contains("nse") || w.Contains("script"))
            {
                Phase = Phase.Scripts;
                Activity = "Running scripts";
            }
            else if (w.Contains("traceroute"))
            {
                Phase = Phase.Traceroute;
                Activity = "Tracing routes";
            }
            else if (w.Contains("scan"))
            {
                Phase = Phase.ScanPorts;
                Activity = "Scanning ports";
            }
        }

        /// <summary>A time like "0:01:20" as a TimeSpan.</summary>
        private static TimeSpan? ParseRemaining(string s)
        {
            if (string.IsNullOrEmpty(s)) return null;
            var parts = s.Split(':').Select(x => int.TryParse(x, out var v) ? v : 0).ToArray();
            if (parts.Length == 3) return new TimeSpan(parts[0], parts[1], parts[2]);
            if (parts.Length == 2) return new TimeSpan(0, parts[0], parts[1]);
            return null;
        }

        /// <summary>The steps this scan will go through, for the step row under the progress bar.</summary>
        public static List<(Phase Phase, string Name)> StepsFor(ScanOptions o)
        {
            var steps = new List<(Phase, string)>();
            if (!o.SkipPing) steps.Add((Phase.FindHosts, "Find hosts"));
            if (o.Kind != ScanKind.Ping) steps.Add((Phase.ScanPorts, "Scan ports"));
            if (o.EffectiveVersions) steps.Add((Phase.Versions, "Detect versions"));
            if (o.DetectOs && o.Kind != ScanKind.Ping) steps.Add((Phase.Os, "Detect OS"));
            if (o.UsesScripts) steps.Add((Phase.Scripts, o.HasScript("vuln") || o.Vulners ? "Vulnerability scripts" : "Scripts"));
            if (o.Traceroute) steps.Add((Phase.Traceroute, "Traceroute"));
            return steps;
        }
    }

    /// <summary>Sorts IPv4 addresses numerically (192.168.1.2 before 192.168.1.10), other text alphabetically.</summary>
    public sealed class AddressComparer : IComparer<string>
    {
        /// <summary>Sorts two addresses.</summary>
        public int Compare(string a, string b)
        {
            var ka = Key(a);
            var kb = Key(b);
            if (ka != null && kb != null) return ka.Value.CompareTo(kb.Value);
            if (ka != null) return -1;
            if (kb != null) return 1;
            return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>An IPv4 address as one number, or null when it isn't one.</summary>
        private static long? Key(string s)
        {
            var parts = (s ?? string.Empty).Split('.');
            if (parts.Length != 4) return null;
            long key = 0;
            foreach (var p in parts)
            {
                if (!byte.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out var b)) return null;
                key = key * 256 + b;
            }
            return key;
        }
    }
}
