using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace Kudunmap.Core
{
    /// <summary>
    /// Saves results as an HTML report or CSV. Everything that came from the network (names, banners,
    /// script output) is escaped, so a hostile device can't inject HTML or spreadsheet formulas.
    /// </summary>
    public static class Exporter
    {
        public static void SaveCsv(ScanResult r, string path) => File.WriteAllText(path, Csv(r), new UTF8Encoding(true));

        public static string Csv(ScanResult r)
        {
            var sb = new StringBuilder();
            Row(sb, "Address", "Name", "MAC", "Vendor", "OS", "Port", "Protocol", "State", "Service", "Version");
            foreach (var h in r.UpHosts)
            {
                var ports = h.Ports.ToList();
                if (ports.Count == 0) Row(sb, h.Address, h.Name, h.Mac, h.Vendor, h.OsGuess, "", "", "", "", "");
                foreach (var p in ports)
                    Row(sb, h.Address, h.Name, h.Mac, h.Vendor, h.OsGuess, p.Number.ToString(CultureInfo.InvariantCulture), p.Protocol, p.State, p.ServiceText, p.VersionText);
            }
            return sb.ToString();
        }

        public static void SaveVulnerabilitiesCsv(ScanResult r, string path)
        {
            var sb = new StringBuilder();
            Row(sb, "Severity", "CVSS", "Finding", "Address", "Name", "Port", "CVE", "Script", "Note");
            foreach (var v in r.Vulnerabilities)
                Row(sb, v.SeverityText, v.Score?.ToString("0.0", CultureInfo.InvariantCulture) ?? "", v.Title, v.HostAddress, v.HostName, v.Port,
                    string.Join(" ", v.Cves), v.ScriptId, v.Note);
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
        }

        public static void SaveChangesCsv(IEnumerable<Change> changes, string path)
        {
            var sb = new StringBuilder();
            Row(sb, "Change", "Address", "Name", "Details");
            foreach (var c in changes) Row(sb, c.KindText, c.Address, c.Name, c.Details);
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
        }

        private static void Row(StringBuilder sb, params string[] cells)
        {
            sb.Append(string.Join(",", cells.Select(CsvCell)));
            sb.Append("\r\n");
        }

        public static string CsvCell(string value)
        {
            value = value ?? string.Empty;
            // Spreadsheets run cells starting with these characters as formulas.
            if (value.Length > 0 && "=+-@\t\r".IndexOf(value[0]) >= 0) value = "'" + value;
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }

        public static void SaveHtml(ScanResult r, string title, string path) =>
            File.WriteAllText(path, Html(r, title), new UTF8Encoding(false));

        public static string Html(ScanResult r, string title)
        {
            string E(string s) => WebUtility.HtmlEncode(s ?? string.Empty);
            var vulns = r.Vulnerabilities;
            var sb = new StringBuilder();
            sb.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
            sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
            sb.Append("<title>").Append(E(title)).Append(" · KUDUNMAP report</title><style>");
            sb.Append("body{font:14px/1.5 'Segoe UI',system-ui,sans-serif;margin:0;background:#F3F3F3;color:#1B1B1B}");
            sb.Append("main{max-width:1100px;margin:0 auto;padding:24px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}");
            sb.Append(".sub{color:#5C5C5C}.card{background:#fff;border:1px solid #E0E0E0;border-radius:10px;padding:16px 18px;margin:12px 0}");
            sb.Append(".stats{display:flex;gap:32px;flex-wrap:wrap}.stats b{display:block;font-size:22px}");
            sb.Append("table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #E0E0E0;vertical-align:top}");
            sb.Append("th{font-size:12px;color:#5C5C5C}code,pre{font-family:Consolas,monospace;font-size:12px}pre{white-space:pre-wrap;margin:6px 0 0;color:#5C5C5C}");
            sb.Append(".chip{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600}");
            sb.Append(".Critical,.High{background:#FDE7E9;color:#C42B1C}.Medium{background:#FFF4CE;color:#8A5300}.Low,.Unrated{background:#F0F0F0;color:#5C5C5C}");
            sb.Append(".open{background:#DFF6DD;color:#107C10}footer{color:#5C5C5C;font-size:12px;margin-top:32px}");
            sb.Append("@media (prefers-color-scheme:dark){body{background:#202020;color:#F2F2F2}.card{background:#2B2B2B;border-color:#3A3A3A}.sub,th,pre,footer{color:#B4B4B4}th,td{border-color:#3A3A3A}}");
            sb.Append("</style></head><body><main>");

            sb.Append("<h1>").Append(E(title)).Append("</h1>");
            sb.Append("<div class=\"sub\">").Append(E(r.Started == DateTime.MinValue ? "" : r.Started.ToString("f", CultureInfo.CurrentCulture)))
              .Append(" · Nmap ").Append(E(r.NmapVersion)).Append("</div>");
            sb.Append("<div class=\"card\"><code>").Append(E(r.Args)).Append("</code></div>");
            sb.Append("<div class=\"card stats\">");
            Stat(sb, r.HostsUp.ToString(CultureInfo.InvariantCulture), "hosts online");
            Stat(sb, r.OpenPortCount.ToString(CultureInfo.InvariantCulture), "open ports");
            Stat(sb, vulns.Count.ToString(CultureInfo.InvariantCulture), "findings");
            Stat(sb, Duration(r.ElapsedSeconds), "scan time");
            sb.Append("</div>");

            if (vulns.Count > 0)
            {
                sb.Append("<h2>Vulnerabilities</h2><div class=\"card\"><p class=\"sub\">These are checks for known problems. ")
                  .Append("\"Matched by version\" means the software version is listed as affected; the fix may already be applied. ")
                  .Append("A clean result doesn't guarantee a system is safe.</p><table><tr><th>Severity</th><th>Finding</th><th>Host</th><th>CVE</th><th>Found by</th></tr>");
                foreach (var v in vulns)
                {
                    sb.Append("<tr><td><span class=\"chip ").Append(v.SeverityText).Append("\">").Append(E(v.SeverityText)).Append("</span></td><td><b>")
                      .Append(E(v.Title)).Append("</b><div class=\"sub\">").Append(E(v.Note)).Append("</div></td><td><code>")
                      .Append(E(v.HostAddress)).Append("</code><div class=\"sub\">").Append(E(v.HostName)).Append(" ").Append(E(v.Where)).Append("</div></td><td>");
                    foreach (var cve in v.Cves)
                        sb.Append("<a href=\"https://www.cve.org/CVERecord?id=").Append(E(cve)).Append("\">").Append(E(cve)).Append("</a><br>");
                    sb.Append("</td><td><code>").Append(E(v.ScriptId)).Append("</code></td></tr>");
                }
                sb.Append("</table></div>");
            }

            sb.Append("<h2>Hosts</h2>");
            foreach (var h in r.UpHosts)
            {
                sb.Append("<div class=\"card\"><b>").Append(E(h.DisplayName)).Append("</b> <code>").Append(E(h.Address)).Append("</code>");
                var info = new[] { h.OsGuess, h.Mac == null ? null : h.Mac + (string.IsNullOrEmpty(h.Vendor) ? "" : " (" + h.Vendor + ")"), h.LatencyText }
                    .Where(s => !string.IsNullOrEmpty(s));
                sb.Append("<div class=\"sub\">").Append(E(string.Join(" · ", info))).Append("</div>");
                var ports = h.Ports.ToList();
                if (ports.Count == 0)
                {
                    sb.Append("<p class=\"sub\">No open ports found.</p>");
                }
                else
                {
                    sb.Append("<table><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>");
                    foreach (var p in ports)
                    {
                        sb.Append("<tr><td><code>").Append(E(p.Key)).Append("</code></td><td><span class=\"chip ").Append(p.IsOpen ? "open" : "Low").Append("\">")
                          .Append(E(p.State)).Append("</span></td><td>").Append(E(p.ServiceText)).Append("</td><td>").Append(E(p.VersionText));
                        foreach (var s in p.Scripts)
                            sb.Append("<pre>").Append(E(s.Id)).Append(": ").Append(E(s.Output)).Append("</pre>");
                        sb.Append("</td></tr>");
                    }
                    sb.Append("</table>");
                }
                foreach (var s in h.Scripts)
                    sb.Append("<pre>").Append(E(s.Id)).Append(": ").Append(E(s.Output)).Append("</pre>");
                sb.Append("</div>");
            }

            sb.Append("<footer>Made with KUDUNMAP ").Append(E(AppVersion)).Append(". Scans performed by Nmap (nmap.org). ")
              .Append("KUDUNMAP is not affiliated with or endorsed by the Nmap Project.</footer></main></body></html>");
            return sb.ToString();
        }

        /// <summary>Set by the app at startup so reports show the KUDUNMAP version.</summary>
        public static string AppVersion { get; set; } = string.Empty;

        private static void Stat(StringBuilder sb, string value, string label) =>
            sb.Append("<div><b>").Append(WebUtility.HtmlEncode(value)).Append("</b><span class=\"sub\">").Append(WebUtility.HtmlEncode(label)).Append("</span></div>");

        public static string Duration(double seconds)
        {
            if (seconds <= 0) return "–";
            var t = TimeSpan.FromSeconds(seconds);
            if (t.TotalHours >= 1) return $"{(int)t.TotalHours} h {t.Minutes} min";
            if (t.TotalMinutes >= 1) return $"{t.Minutes} min {t.Seconds} s";
            return $"{Math.Max(1, (int)Math.Round(t.TotalSeconds))} s";
        }
    }
}
