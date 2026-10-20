using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Kudunmap.Core
{
    public enum Severity { Critical, High, Medium, Low, Unrated }

    public sealed class Vulnerability
    {
        public Severity Severity { get; set; } = Severity.Unrated;
        public double? Score { get; set; }
        public string Title { get; set; } = string.Empty;
        public string HostAddress { get; set; } = string.Empty;
        public string HostName { get; set; } = string.Empty;

        /// <summary>"445/tcp", or empty for findings about the whole host.</summary>
        public string Port { get; set; } = string.Empty;
        public List<string> Cves { get; } = new List<string>();
        public string ScriptId { get; set; } = string.Empty;

        /// <summary>True for vulners matches: the software version is listed as affected, nothing was tested.</summary>
        public bool MatchedByVersion { get; set; }
        public string State { get; set; } = string.Empty;
        public string Output { get; set; } = string.Empty;

        public string SeverityText => Severity.ToString();
        public string FirstCve => Cves.FirstOrDefault() ?? string.Empty;
        public string Where => string.IsNullOrEmpty(Port) ? "host" : Port;

        public string Note
        {
            get
            {
                if (MatchedByVersion)
                    return "Matched by version" + (Score.HasValue ? " · CVSS " + Score.Value.ToString("0.0", CultureInfo.InvariantCulture) : string.Empty);
                var note = State.IndexOf("LIKELY", StringComparison.OrdinalIgnoreCase) >= 0
                    ? "Likely vulnerable, reported by the script"
                    : "Reported as vulnerable by the script";
                return Score.HasValue ? note + " · CVSS " + Score.Value.ToString("0.0", CultureInfo.InvariantCulture) : note;
            }
        }
    }

    /// <summary>
    /// Turns script results into a list of findings. Understands the standard "vulns" output used by
    /// Nmap's vuln scripts (State: VULNERABLE …) and the CVE list from the vulners script.
    /// </summary>
    public static class VulnerabilityFinder
    {
        private static readonly Regex CveRegex = new Regex(@"CVE-\d{4}-\d{4,7}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex RiskRegex = new Regex(@"Risk factor:\s*(?<r>[A-Za-z]+)", RegexOptions.IgnoreCase);
        private static readonly Regex CvssRegex = new Regex(@"CVSS(?:v[23](?:\.\d)?)?\s*(?:Base Score)?\s*[:=]?\s*(?<s>\d{1,2}(?:\.\d)?)", RegexOptions.IgnoreCase);
        private static readonly Regex TextBlock = new Regex(
            @"^[ \t]*(?:LIKELY )?VULNERABLE:[ \t]*\r?\n[ \t]*(?<title>[^\r\n]+?)[ \t]*\r?\n[ \t]*State:[ \t]*(?<state>[^\r\n]+)",
            RegexOptions.Multiline | RegexOptions.CultureInvariant);
        private static readonly Regex VulnersLine = new Regex(
            @"^[ \t]*(?<id>[A-Za-z0-9_:\-\.]+)[ \t]+(?<cvss>\d{1,2}(?:\.\d)?)[ \t]+(?:https?://\S+)?",
            RegexOptions.Multiline | RegexOptions.CultureInvariant);

        public static List<Vulnerability> Find(ScanResult result)
        {
            var list = new List<Vulnerability>();
            foreach (var host in result.UpHosts)
            {
                foreach (var s in host.Scripts) list.AddRange(FromScript(host, null, s));
                foreach (var p in host.Ports)
                {
                    foreach (var s in p.Scripts) list.AddRange(FromScript(host, p, s));
                }
            }

            // The same CVE can be reported by more than one script; keep the most severe copy.
            return list
                .GroupBy(v => v.HostAddress + "|" + v.Port + "|" + (v.Cves.Count > 0 ? v.FirstCve.ToUpperInvariant() : v.ScriptId + ":" + v.Title))
                .Select(g => g.OrderBy(v => v.Severity).ThenByDescending(v => v.Score ?? 0).First())
                .OrderBy(v => v.Severity)
                .ThenByDescending(v => v.Score ?? 0)
                .ThenBy(v => v.HostAddress, StringComparer.Ordinal)
                .ToList();
        }

        public static Severity FromScore(double score)
        {
            if (score >= 9.0) return Severity.Critical;
            if (score >= 7.0) return Severity.High;
            if (score >= 4.0) return Severity.Medium;
            return Severity.Low;
        }

        public static Severity FromRisk(string risk)
        {
            switch ((risk ?? string.Empty).Trim().ToUpperInvariant())
            {
                case "CRITICAL": return Severity.Critical;
                case "HIGH": return Severity.High;
                case "MEDIUM": return Severity.Medium;
                case "LOW": return Severity.Low;
                default: return Severity.Unrated;
            }
        }

        private static IEnumerable<Vulnerability> FromScript(HostInfo host, PortInfo port, ScriptResult script)
        {
            if (string.Equals(script.Id, "vulners", StringComparison.OrdinalIgnoreCase))
                return FromVulners(host, port, script);
            return FromVulnsLibrary(host, port, script);
        }

        private static Vulnerability New(HostInfo host, PortInfo port, ScriptResult script) => new Vulnerability
        {
            HostAddress = host.Address,
            HostName = host.Name,
            Port = port?.Key ?? string.Empty,
            ScriptId = script.Id ?? string.Empty,
            Output = script.Output ?? string.Empty
        };

        // ----- "vulns" library output (smb-vuln-ms17-010, ssl-dh-params, http-vuln-*, …) -----

        private static List<Vulnerability> FromVulnsLibrary(HostInfo host, PortInfo port, ScriptResult script)
        {
            var found = new List<Vulnerability>();
            var output = script.Output ?? string.Empty;

            // Structured output: any table with a "state" element.
            var tables = script.Element?.Descendants("table")
                .Where(t => t.Elements("elem").Any(e => (string)e.Attribute("key") == "state"))
                .ToList() ?? new List<XElement>();

            foreach (var t in tables)
            {
                var state = Elem(t, "state");
                if (!IsVulnerable(state)) continue;

                var v = New(host, port, script);
                v.State = state;
                v.Title = Elem(t, "title");
                if (string.IsNullOrEmpty(v.Title)) v.Title = script.Id;

                var ids = t.Elements("table").FirstOrDefault(x => (string)x.Attribute("key") == "ids");
                foreach (var id in ids?.Elements("elem") ?? Enumerable.Empty<XElement>()) AddCves(v, id.Value);
                AddCves(v, (string)t.Attribute("key"));

                var section = Section(output, v.Title);
                var cvss = t.Descendants("elem").FirstOrDefault(e => ((string)e.Attribute("key") ?? string.Empty).StartsWith("CVSS", StringComparison.OrdinalIgnoreCase));
                v.Score = ParseScore(cvss?.Value) ?? ParseScore(CvssRegex.Match(section).Groups["s"].Value);
                Rate(v, section);
                found.Add(v);
            }

            if (tables.Count > 0) return found;

            // Text only: "VULNERABLE:\n  <title>\n    State: VULNERABLE".
            foreach (Match m in TextBlock.Matches(output))
            {
                var state = m.Groups["state"].Value.Trim();
                if (!IsVulnerable(state)) continue;

                var v = New(host, port, script);
                v.State = state;
                v.Title = m.Groups["title"].Value.Trim();
                var section = Section(output, v.Title);
                AddCves(v, section);
                v.Score = ParseScore(CvssRegex.Match(section).Groups["s"].Value);
                Rate(v, section);
                found.Add(v);
            }
            return found;
        }

        private static bool IsVulnerable(string state) =>
            !string.IsNullOrEmpty(state) &&
            state.IndexOf("VULNERABLE", StringComparison.OrdinalIgnoreCase) >= 0 &&
            state.IndexOf("NOT VULNERABLE", StringComparison.OrdinalIgnoreCase) < 0;

        /// <summary>The part of the script output that belongs to one finding.</summary>
        private static string Section(string output, string title)
        {
            var start = string.IsNullOrEmpty(title) ? -1 : output.IndexOf(title, StringComparison.Ordinal);
            if (start < 0) return output;
            var next = output.IndexOf("VULNERABLE:", start + title.Length, StringComparison.Ordinal);
            return next < 0 ? output.Substring(start) : output.Substring(start, next - start);
        }

        private static void Rate(Vulnerability v, string section)
        {
            var risk = FromRisk(RiskRegex.Match(section).Groups["r"].Value);
            v.Severity = v.Score.HasValue ? FromScore(v.Score.Value) : risk;
        }

        // ----- vulners: CVEs listed for the detected software version -----

        private static List<Vulnerability> FromVulners(HostInfo host, PortInfo port, ScriptResult script)
        {
            var found = new List<Vulnerability>();
            var software = port == null
                ? host.DisplayName
                : string.Join(" ", new[] { port.Product, port.Version }.Where(x => !string.IsNullOrEmpty(x)));
            if (string.IsNullOrEmpty(software)) software = port?.Service ?? "Detected software";

            var entries = script.Element?.Descendants("table")
                .Where(t => t.Elements("elem").Any(e => (string)e.Attribute("key") == "id"))
                .ToList() ?? new List<XElement>();

            if (entries.Count > 0)
            {
                foreach (var e in entries)
                {
                    var type = Elem(e, "type");
                    var id = Elem(e, "id");
                    if (!string.Equals(type, "cve", StringComparison.OrdinalIgnoreCase) && !CveRegex.IsMatch(id)) continue;
                    found.Add(VulnersEntry(host, port, script, software, id, ParseScore(Elem(e, "cvss")),
                        string.Equals(Elem(e, "is_exploit"), "true", StringComparison.OrdinalIgnoreCase)));
                }
                return found;
            }

            foreach (Match m in VulnersLine.Matches(script.Output ?? string.Empty))
            {
                var id = m.Groups["id"].Value;
                if (!CveRegex.IsMatch(id)) continue;
                found.Add(VulnersEntry(host, port, script, software, id, ParseScore(m.Groups["cvss"].Value),
                    m.Value.IndexOf("*EXPLOIT*", StringComparison.Ordinal) >= 0));
            }
            return found;
        }

        private static Vulnerability VulnersEntry(HostInfo host, PortInfo port, ScriptResult script, string software, string id, double? score, bool exploit)
        {
            var v = New(host, port, script);
            v.MatchedByVersion = true;
            v.State = "Matched by version";
            AddCves(v, id);
            v.Title = $"{software}: known vulnerability {v.FirstCve}" + (exploit ? " (public exploit exists)" : string.Empty);
            v.Score = score;
            v.Severity = score.HasValue ? FromScore(score.Value) : Severity.Unrated;
            return v;
        }

        // ----- helpers -----

        private static string Elem(XElement table, string key) =>
            table.Elements("elem").FirstOrDefault(e => (string)e.Attribute("key") == key)?.Value?.Trim() ?? string.Empty;

        private static void AddCves(Vulnerability v, string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            foreach (Match m in CveRegex.Matches(text))
            {
                var cve = m.Value.ToUpperInvariant();
                if (!v.Cves.Contains(cve)) v.Cves.Add(cve);
            }
        }

        private static double? ParseScore(string s) =>
            double.TryParse((s ?? string.Empty).Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && d >= 0 && d <= 10
                ? d
                : (double?)null;

        public static bool IsCve(string id) => !string.IsNullOrEmpty(id) && CveRegex.IsMatch(id) && CveRegex.Match(id).Value.Length == id.Length;
    }
}
