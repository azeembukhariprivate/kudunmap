using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Kudunmap.Core;

namespace Kudunmap.Tests
{
    /// <summary>A tiny test runner: each check prints PASS or FAIL, and the exit code is the number of failures.</summary>
    internal static class Program
    {
        private static int _failures;
        private static int _passes;

        private static int Main()
        {
            Run("Parses hosts and ports", ParsesHostsAndPorts);
            Run("Finds vulnerabilities", FindsVulnerabilities);
            Run("Reads text-only vuln output", ReadsTextOnlyVulnOutput);
            Run("Builds commands for presets", BuildsCommands);
            Run("Validates targets and ports", ValidatesInput);
            Run("Quotes arguments like Windows", QuotesArguments);
            Run("Tracks progress", TracksProgress);
            Run("Compares scans", ComparesScans);
            Run("Escapes exports", EscapesExports);
            Run("Saves history and presets", SavesHistoryAndPresets);
            Run("Explains common Nmap errors", ExplainsErrors);

            Console.WriteLine();
            Console.WriteLine($"{_passes} passed, {_failures} failed");
            return _failures;
        }

        private static void Run(string name, Action test)
        {
            try
            {
                test();
                _passes++;
                Console.WriteLine("PASS  " + name);
            }
            catch (Exception ex)
            {
                _failures++;
                Console.WriteLine("FAIL  " + name + "\n      " + ex.Message);
            }
        }

        private static void Check(bool condition, string what)
        {
            if (!condition) throw new Exception(what);
        }

        private static void Equal<T>(T expected, T actual, string what)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
                throw new Exception($"{what}: expected <{expected}> but got <{actual}>");
        }

        private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

        private static ScanResult Sample() => NmapXml.Load(Fixture("vuln-scan.xml"));

        // ---------------------------------------------------------------------------------------

        private static void ParsesHostsAndPorts()
        {
            var r = Sample();
            Equal("7.95", r.NmapVersion, "Nmap version");
            Equal(4, r.HostsUp, "hosts up");
            Equal(256, r.HostsTotal, "hosts total");
            Equal(5, r.Hosts.Count, "host elements");
            Equal(4, r.UpHosts.Count(), "up hosts");
            Check(r.Completed, "scan should be complete");
            Equal(106, (int)r.ElapsedSeconds, "elapsed");

            var nas = r.UpHosts.Single(h => h.Address == "192.168.1.20");
            Equal("nas.lan", nas.Name, "name");
            Equal("00:11:32:AB:CD:EF", nas.Mac, "MAC");
            Equal("Synology Incorporated", nas.Vendor, "vendor");
            Equal("Linux", nas.OsGuess, "OS guess from services");
            Equal(5, nas.OpenPorts.Count(), "nas open ports");
            Equal("0.4 ms", nas.LatencyText, "latency");

            var ssh = nas.Ports.Single(p => p.Number == 22);
            Equal("OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)", ssh.VersionText, "version text");

            var https = r.UpHosts.Single(h => h.Address == "192.168.1.1").Ports.Single(p => p.Number == 443);
            Equal("ssl/http", https.ServiceText, "ssl service");
            Check(https.LooksLikeWeb && https.IsHttps, "443 should open as https");
            Equal(11, r.OpenPortCount, "open ports"); // router 3 + nas 5 + old-server 3 + phone 0
        }

        private static void FindsVulnerabilities()
        {
            var v = Sample().Vulnerabilities;
            foreach (var x in v) Console.WriteLine($"      {x.Severity,-8} {x.Score?.ToString() ?? "-",-4} {x.HostAddress,-13} {x.Where,-8} {x.FirstCve,-15} {x.Title}");

            Equal(6, v.Count, "number of findings (PACKETSTORM and non-vulnerable results ignored)");
            Equal(Severity.Critical, v[0].Severity, "first is critical");
            Equal("CVE-2023-38408", v[0].FirstCve, "critical CVE");
            Check(v[0].MatchedByVersion, "vulners finding is matched by version");
            Equal("22/tcp", v[0].Port, "port");

            var ms17 = v.Single(x => x.ScriptId == "smb-vuln-ms17-010");
            Equal(Severity.High, ms17.Severity, "ms17-010 uses the script's risk factor");
            Equal("CVE-2017-0143", ms17.FirstCve, "ms17-010 CVE");
            Equal("", ms17.Port, "host script has no port");
            Check(!ms17.MatchedByVersion, "ms17-010 was reported by the script");
            Equal("Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)", ms17.Title, "title");

            var dh = v.Single(x => x.ScriptId == "ssl-dh-params");
            Equal(Severity.Unrated, dh.Severity, "no score or risk factor");
            Equal(0, dh.Cves.Count, "no CVE");

            Equal(Severity.High, v.Single(x => x.FirstCve == "CVE-2021-23017").Severity, "7.7 is high");
            Equal(Severity.Medium, v.Single(x => x.FirstCve == "CVE-2023-51385").Severity, "6.5 is medium");
            Check(v.Select(x => x.Severity).SequenceEqual(v.Select(x => x.Severity).OrderBy(s => s)), "sorted by severity");
        }

        private static void ReadsTextOnlyVulnOutput()
        {
            const string xml = @"<?xml version=""1.0""?><nmaprun version=""7.80"" args=""nmap"" start=""1"">
<host><status state=""up""/><address addr=""10.0.0.5"" addrtype=""ipv4""/><ports>
<port protocol=""tcp"" portid=""443""><state state=""open""/><service name=""https""/>
<script id=""ssl-poodle"" output=""&#xa;  VULNERABLE:&#xa;  SSL POODLE information leak&#xa;    State: LIKELY VULNERABLE&#xa;    IDs:  CVE:CVE-2014-3566  BID:70574&#xa;    Risk factor: Medium&#xa;""/>
<script id=""http-vuln-x"" output=""&#xa;  NOT VULNERABLE:&#xa;  Something&#xa;    State: NOT VULNERABLE&#xa;""/>
<script id=""vulners"" output=""&#xa;  cpe:/a:x:y:1.0: &#xa;    &#x9;CVE-2020-1111&#x9;5.0&#x9;https://vulners.com/cve/CVE-2020-1111&#xa;""/>
</port></ports></host><runstats><finished time=""2"" elapsed=""1"" exit=""success""/><hosts up=""1"" down=""0"" total=""1""/></runstats></nmaprun>";
            var v = NmapXml.Parse(xml).Vulnerabilities;
            Equal(2, v.Count, "findings");
            var poodle = v.Single(x => x.ScriptId == "ssl-poodle");
            Equal(Severity.Medium, poodle.Severity, "risk factor");
            Equal("CVE-2014-3566", poodle.FirstCve, "CVE from text");
            Check(poodle.Note.StartsWith("Likely"), "likely vulnerable note");
            Equal("CVE-2020-1111", v.Single(x => x.ScriptId == "vulners").FirstCve, "vulners text fallback");
        }

        private static string Cmd(string presetId, bool admin, Action<ScanOptions> change = null)
        {
            var o = Presets.CreateOptions(Presets.Find(presetId));
            o.Targets = "192.168.1.0/24";
            change?.Invoke(o);
            return CommandBuilder.CopyableCommand(o, admin);
        }

        private static void BuildsCommands()
        {
            Equal("nmap -sT -sV --open -T4 192.168.1.0/24", Cmd("services", false), "services, standard user");
            Equal("nmap -sS -sV --open -T4 192.168.1.0/24", Cmd("services", true), "services, admin");
            Equal("nmap -sT -F --open -T4 192.168.1.0/24", Cmd("quick", false), "quick");
            Equal("nmap -sn -T4 192.168.1.0/24", Cmd("ping", false), "ping sweep has no port options");
            Equal("nmap -sT -p- --open -T4 192.168.1.0/24", Cmd("all", false), "all ports");
            Equal("nmap -sS -sV -O -sC --traceroute --open -T4 192.168.1.0/24", Cmd("intense", true), "intense");
            Equal("nmap -sU -F -T4 192.168.1.0/24", Cmd("udp", true), "udp");
            Equal("nmap -sT -sV --script vuln,vulners --open -T4 192.168.1.0/24", Cmd("vuln", false, o => o.Vulners = true), "vuln + vulners");
            Equal("nmap -sT -p 22,80,443 -sV -Pn -n -T2 192.168.1.0/24",
                Cmd("services", false, o => { o.Ports = PortMode.Custom; o.CustomPorts = "22, 80, 443"; o.SkipPing = true; o.ResolveNames = false; o.OnlyOpen = false; o.Timing = 2; }),
                "custom options");
            Equal("nmap -sT -sV --open -T4 -iL \"C:\\My targets\\list.txt\"",
                Cmd("services", false, o => o.TargetFile = @"C:\My targets\list.txt"), "target file");

            Check(Presets.Find("os").NeedsAdmin && Presets.Find("udp").NeedsAdmin && Presets.Find("intense").NeedsAdmin, "admin presets");
            Check(!Presets.Find("quick").NeedsAdmin && !Presets.Find("vuln").NeedsAdmin, "non-admin presets");

            var o2 = Presets.CreateOptions(Presets.Find("services"));
            o2.Targets = "10.0.0.1 10.0.0.2";
            var args = CommandBuilder.BuildArguments(o2, false, @"C:\Temp\x y\scan.xml");
            Check(args.Contains("-v") && args.Contains("--stats-every") && args.Contains("-oX"), "internal arguments added");
            Equal("10.0.0.2", args.Last(), "targets last");
            Equal(@"C:\Temp\x y\scan.xml", args[args.IndexOf("-oX") + 1], "xml path");
        }

        private static void ValidatesInput()
        {
            foreach (var ok in new[] { "192.168.1.1", "192.168.1.0/24", "10.0.0-2.1-254", "router.lan", "scanme.nmap.org", "fe80::1%eth0", "10.0.0.1 10.0.0.2", "192.168.1.1,2,3" })
                Equal(null, CommandBuilder.ValidateTargets(ok), "valid target " + ok);
            foreach (var bad in new[] { "", "   ", "-oN out.txt", "192.168.1.1 --script=x", "a\"b", "$(x)", "host&calc", "x|y" })
                Check(CommandBuilder.ValidateTargets(bad) != null, "invalid target accepted: " + bad);

            Equal(256L, CommandBuilder.CountAddresses("192.168.1.0/24"), "CIDR count");
            Equal(50L + 1, CommandBuilder.CountAddresses("192.168.1.1-50 router.lan"), "range + name");
            Equal(3L * 254, CommandBuilder.CountAddresses("10.0.0-2.1-254"), "two ranges");
            Equal(3L, CommandBuilder.CountAddresses("192.168.1.1,2,3"), "comma list");
            Equal(-1L, CommandBuilder.CountAddresses("fe80::/64"), "IPv6 network unknown");

            Equal(null, CommandBuilder.ValidatePorts("22,80,443"), "ports list");
            Equal(null, CommandBuilder.ValidatePorts("1-1024, U:53"), "ports with spaces and protocol");
            Equal(null, CommandBuilder.ValidatePorts("-"), "all ports");
            Check(CommandBuilder.ValidatePorts("-oN x") != null, "ports option injection");
            Check(CommandBuilder.ValidatePorts("abc") != null, "letters rejected");
        }

        private static void QuotesArguments()
        {
            Equal("abc", CommandBuilder.QuoteArgument("abc"), "plain");
            Equal("\"a b\"", CommandBuilder.QuoteArgument("a b"), "space");
            Equal("\"C:\\x y\\\\\"", CommandBuilder.QuoteArgument("C:\\x y\\"), "trailing backslash doubled");
            Equal("\"a\\\"b c\"", CommandBuilder.QuoteArgument("a\"b c"), "embedded quote");
            Equal("\"\"", CommandBuilder.QuoteArgument(""), "empty");
        }

        private static void TracksProgress()
        {
            var t = new ProgressTracker();
            t.Feed("Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-20 19:41 W. Europe Daylight Time");
            t.Feed("Initiating Ping Scan at 19:41");
            Equal(Phase.FindHosts, t.Phase, "ping phase");
            t.Feed("Initiating Connect Scan at 19:41");
            Equal(Phase.ScanPorts, t.Phase, "port phase");
            t.Feed("Discovered open port 445/tcp on 192.168.1.50");
            t.Feed("Discovered open port 80/tcp on 192.168.1.20");
            t.Feed("Discovered open port 22/tcp on 192.168.1.20");
            t.Feed("Discovered open port 53/tcp on 192.168.1.1");
            Equal("192.168.1.1|192.168.1.20|192.168.1.50", string.Join("|", t.Found.Keys), "hosts sorted numerically");
            Equal("80/tcp,22/tcp", string.Join(",", t.Found["192.168.1.20"]), "ports in order found");
            t.Feed("Service scan Timing: About 45.00% done; ETC: 19:43 (0:00:41 remaining)");
            Equal(Phase.Versions, t.Phase, "service phase");
            Equal(45.0, t.Percent, "percent");
            Equal(TimeSpan.FromSeconds(41), t.Remaining, "remaining");
            t.Feed("NSE Timing: About 12.50% done; ETC: 19:44 (0:01:10 remaining)");
            Equal(Phase.Scripts, t.Phase, "script phase");
            t.Feed("Nmap done: 256 IP addresses (7 hosts up) scanned in 106.21 seconds");
            Equal(Phase.Finishing, t.Phase, "done");

            var steps = ProgressTracker.StepsFor(Presets.CreateOptions(Presets.Find("vuln")));
            Equal("Find hosts,Scan ports,Detect versions,Vulnerability scripts", string.Join(",", steps.Select(s => s.Name)), "steps");
        }

        private static void ComparesScans()
        {
            var newer = Sample();
            var older = Sample();
            // Older scan: phone.lan wasn't there, nas.lan had no port 5000 and an older OpenSSH, router had port 8080 open.
            older.Hosts.RemoveAll(h => h.Address == "192.168.1.42");
            var oldNas = older.Hosts.Single(h => h.Address == "192.168.1.20");
            oldNas.Ports.RemoveAll(p => p.Number == 5000);
            oldNas.Ports.Single(p => p.Number == 22).Version = "8.2p1";
            older.Hosts.Single(h => h.Address == "192.168.1.1").Ports.Add(new PortInfo { Number = 8080, State = "open", Service = "http-proxy" });
            older.Hosts.Add(new HostInfo { State = "up", Ipv4 = "192.168.1.61" });

            var changes = ScanComparer.Compare(older, newer);
            foreach (var c in changes) Console.WriteLine($"      {c.KindText,-16} {c.Address,-13} {c.Details}");
            Equal(5, changes.Count, "changes");
            Check(changes.Any(c => c.Kind == ChangeKind.NewHost && c.Address == "192.168.1.42"), "new host");
            Check(changes.Any(c => c.Kind == ChangeKind.HostGone && c.Address == "192.168.1.61"), "host gone");
            Check(changes.Any(c => c.Kind == ChangeKind.PortOpened && c.Details.StartsWith("5000/tcp")), "port opened");
            Check(changes.Any(c => c.Kind == ChangeKind.PortClosed && c.Details.StartsWith("8080/tcp")), "port closed");
            Check(changes.Any(c => c.Kind == ChangeKind.VersionChanged && c.Details.Contains("8.2p1") && c.Details.Contains("8.4p1")), "version changed");
            Equal("192.168.1.1", changes[0].Address, "sorted by address");

            var withSame = ScanComparer.Compare(older, newer, includeUnchanged: true);
            Check(withSame.Any(c => c.Kind == ChangeKind.Unchanged && c.Address == "192.168.1.50"), "unchanged host listed on request");
        }

        private static void EscapesExports()
        {
            var r = Sample();
            var evil = r.UpHosts.First();
            evil.Hostnames.Insert(0, "<script>alert(1)</script>");
            evil.Ports[0].Product = "=HYPERLINK(\"http://x\")";

            var html = Exporter.Html(r, "Report <b>test</b>");
            Check(!html.Contains("<script>alert"), "HTML escaped");
            Check(html.Contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "escaped text kept");
            Check(html.Contains("Report &lt;b&gt;test&lt;/b&gt;"), "title escaped");
            Check(html.Contains("https://www.cve.org/CVERecord?id=CVE-2017-0143"), "CVE link");

            var csv = Exporter.Csv(r);
            Check(csv.Contains("\"'=HYPERLINK(\"\"http://x\"\")"), "formula neutralised and quotes doubled");
            Equal("\"'-1\"", Exporter.CsvCell("-1"), "minus prefixed");
            Equal("\"a,b\"", Exporter.CsvCell("a,b"), "comma quoted");
            Equal("1 min 46 s", Exporter.Duration(106.21), "duration");
        }

        private static void SavesHistoryAndPresets()
        {
            var root = Path.Combine(Path.GetTempPath(), "kudunmap-tests-" + Guid.NewGuid().ToString("N"));
            AppPaths.Root = root;
            try
            {
                var o = Presets.CreateOptions(Presets.Find("vuln"));
                o.Targets = "192.168.1.0/24";
                o.Vulners = true;
                var r = Sample();
                var entry = History.Save(o, r, Fixture("vuln-scan.xml"), "raw output");

                var list = History.List();
                Equal(1, list.Count, "history count");
                var e = list[0];
                Equal("Vulnerability check", e.Title, "title");
                Equal(4, e.HostsUp, "hosts up");
                Equal(6, e.Findings, "findings");
                Check(e.Options != null && e.Options.Vulners && e.Options.HasScript("vuln"), "options saved");
                Equal("raw output", History.LoadOutput(e), "output saved");
                Equal(4, History.Load(e).HostsUp, "results reload");

                History.Delete(e);
                Equal(0, History.List().Count, "deleted");

                var p = CustomPresets.Save("Home network weekly", o);
                CustomPresets.Save("Home network weekly", o); // same name replaces
                Equal(1, CustomPresets.List().Count, "one preset");
                Equal("Home network weekly", CustomPresets.List()[0].Name, "preset name");
                Equal("Vulnerability check · 192.168.1.0/24", CustomPresets.List()[0].Description, "preset description");
                CustomPresets.Delete(CustomPresets.List()[0]);
                Equal(0, CustomPresets.List().Count, "preset deleted");

                Equal("a_b_c", AppPaths.SafeFileName("a/b\\c"), "safe file name");
            }
            finally
            {
                try { Directory.Delete(root, true); } catch { }
            }
        }

        private static void ExplainsErrors()
        {
            Check(NmapRunner.Explain("You requested a scan type which requires root privileges.\nQUITTING!")?.Contains("administrator") == true, "root");
            Check(NmapRunner.Explain("Failed to resolve \"nosuchhost\".")?.Contains("look up") == true, "resolve");
            Equal(null, NmapRunner.Explain("Nmap done: 1 IP address (1 host up) scanned in 0.5 seconds"), "no hint");
        }
    }
}
