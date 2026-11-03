using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using Kudunmap.Core;

namespace Kudunmap.Views
{
    /// <summary>
    /// KUDUNMAP.exe --self-test: builds every window and screen with sample results in both themes, then exits.
    /// Exit code 0 means everything loaded. Used by the GitHub build; writes self-test.log next to the exe.
    /// Uses a temporary folder, so the user's History and presets are never touched.
    /// </summary>
    public static class SelfTest
    {
        public static bool Running { get; private set; }
        public static List<string> Errors { get; } = new List<string>();

        private const string SampleXml = @"<?xml version=""1.0"" encoding=""UTF-8""?>
<!DOCTYPE nmaprun>
<nmaprun scanner=""nmap"" args=""nmap -sT -sV --script vuln,vulners --open -T4 192.168.1.0/24"" start=""1760982060"" version=""7.95"" xmloutputversion=""1.05"">
<host><status state=""up"" reason=""syn-ack""/><address addr=""192.168.1.20"" addrtype=""ipv4""/><address addr=""00:11:32:AB:CD:EF"" addrtype=""mac"" vendor=""Synology""/>
<hostnames><hostname name=""nas.lan"" type=""PTR""/></hostnames><ports>
<port protocol=""tcp"" portid=""22""><state state=""open"" reason=""syn-ack""/><service name=""ssh"" product=""OpenSSH"" version=""8.4p1"" ostype=""Linux""/>
<script id=""vulners"" output=""&#xa;  cpe:/a:openbsd:openssh:8.4p1: &#xa;    &#x9;CVE-2023-38408&#x9;9.8&#x9;https://vulners.com/cve/CVE-2023-38408&#xa;""><table key=""cpe:/a:openbsd:openssh:8.4p1""><table>
<elem key=""id"">CVE-2023-38408</elem><elem key=""cvss"">9.8</elem><elem key=""type"">cve</elem><elem key=""is_exploit"">false</elem></table></table></script></port>
<port protocol=""tcp"" portid=""443""><state state=""open"" reason=""syn-ack""/><service name=""http"" product=""nginx"" version=""1.18.0"" tunnel=""ssl""/>
<script id=""http-title"" output=""Synology DiskStation""/></port>
</ports><times srtt=""412"" rttvar=""150"" to=""100000""/></host>
<host><status state=""up"" reason=""syn-ack""/><address addr=""192.168.1.50"" addrtype=""ipv4""/><hostnames><hostname name=""old-server.lan"" type=""PTR""/></hostnames>
<ports><port protocol=""tcp"" portid=""445""><state state=""open"" reason=""syn-ack""/><service name=""microsoft-ds"" ostype=""Windows""/></port></ports>
<hostscript><script id=""smb-vuln-ms17-010"" output=""&#xa;  VULNERABLE:&#xa;  Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)&#xa;    State: VULNERABLE&#xa;    IDs:  CVE:CVE-2017-0143&#xa;    Risk factor: HIGH&#xa;"">
<table key=""CVE-2017-0143""><elem key=""title"">Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)</elem><elem key=""state"">VULNERABLE</elem>
<table key=""ids""><elem>CVE:CVE-2017-0143</elem></table></table></script></hostscript>
<trace><hop ttl=""1"" ipaddr=""192.168.1.50"" rtt=""2.21"" host=""old-server.lan""/></trace></host>
<host><status state=""down"" reason=""no-response""/><address addr=""192.168.1.2"" addrtype=""ipv4""/></host>
<runstats><finished time=""1760982166"" elapsed=""106.21"" summary=""Nmap done; 256 IP addresses (2 hosts up) scanned in 106.21 seconds"" exit=""success""/>
<hosts up=""2"" down=""254"" total=""256""/></runstats></nmaprun>";

        public static int Run()
        {
            Running = true;
            var log = new StringBuilder();
            void Step(string name, Action action)
            {
                try
                {
                    var before = Errors.Count;
                    action();
                    Pump();
                    Screenshots.All(name);
                    if (Errors.Count > before) throw new Exception(string.Join(" | ", Errors.Skip(before)));
                    log.AppendLine("ok    " + name);
                }
                catch (Exception ex)
                {
                    if (!Errors.Any(x => ex.Message.Contains(x))) Errors.Add(name + ": " + ex);
                    log.AppendLine("FAIL  " + name + ": " + ex.GetType().Name + ": " + ex.Message);
                }
            }

            var temp = Path.Combine(Path.GetTempPath(), "kudunmap-selftest-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            AppPaths.Root = temp;
            MainWindow main = null;

            Step("Load themes and styles", () => ThemeManager.Init(ThemeMode.Light));
            Step("Theme keys exist", () =>
            {
                foreach (var key in new[] { "WindowBg", "SurfaceBg", "Text", "SubtleText", "Accent", "OkBg", "BadText", "MonoBg", "UiFont", "MonoFont",
                                            "PrimaryButton", "SecondaryButton", "GhostButton", "LinkButton", "Card", "PresetRadio", "SegmentRadio",
                                            "TabRadio", "ChipToggle", "ChipRadio", "Switch", "TableList", "MonoBox", "IconBolt", "IconShield" })
                    Application.Current.FindResource(key);
            });

            Step("Main window", () =>
            {
                main = new MainWindow(new CommandLine());
                OffScreen(main);
                Application.Current.MainWindow = main;
                main.Show();
            });

            HistoryEntry first = null, second = null;
            Step("Save sample results", () =>
            {
                var xml = Path.Combine(AppPaths.Running, "sample.xml");
                File.WriteAllText(xml, SampleXml);
                var result = NmapXml.Load(xml);
                if (result.Vulnerabilities.Count != 2) throw new Exception("expected 2 findings, got " + result.Vulnerabilities.Count);
                var o = Presets.CreateOptions(Presets.Find("vuln"));
                o.Targets = "192.168.1.0/24";
                o.Vulners = true;
                first = History.Save(o, result, xml, "Starting Nmap 7.95\nNmap done");
                result.Hosts.RemoveAt(1);
                second = History.Save(o, result, xml, "second");
                second.Started = first.Started.AddDays(1);
            });

            Step("Setup screen with every preset", () =>
            {
                main.ShowSetup();
                foreach (var p in Presets.All)
                {
                    main.SelectPreset(p);
                    Pump();
                }
                main.SetTarget("192.168.1.0/24");
                main.Options.Ports = PortMode.Custom;
                main.Options.CustomPorts = "22,80";
                main.Options.Scripts = new List<string> { "default", "brute" };
                main.Options.Vulners = true;
                main.Setup.LoadOptions(main.Options, null);
                main.Setup.RefreshRecent();
            });

            Step("Custom preset", () =>
            {
                var cp = CustomPresets.Save("Self-test preset", main.Options);
                main.Setup.RefreshCustomPresets(cp);
                main.SelectCustomPreset(cp);
            });

            Step("Scan progress screen", () =>
            {
                var o = Presets.CreateOptions(Presets.Find("vuln"));
                o.Targets = "192.168.1.0/24";
                main.Results.BeginScan(o);
                var t = new ProgressTracker();
                foreach (var line in new[] { "Initiating Connect Scan at 19:41", "Discovered open port 22/tcp on 192.168.1.20",
                                             "Service scan Timing: About 45.00% done; ETC: 19:43 (0:00:41 remaining)" })
                    t.Feed(line);
                main.Results.AppendOutput("Starting Nmap\nDiscovered open port 22/tcp on 192.168.1.20\n");
                main.Results.UpdateProgress(t);
                main.Results.ShowStopped(o, "Scan cancelled", "Self-test", false);
            });

            Step("Results screen, every tab", () =>
            {
                main.OpenHistory(first);
                Pump();
                main.OpenHistory(second); // opening results twice reuses the same screen
                for (var i = 0; i < 4; i++)
                {
                    main.Results.SelectTab(i);
                    Pump();
                }
            });

            Step("Dark theme", () =>
            {
                ThemeManager.Apply(ThemeMode.Dark);
                Pump();
                Screenshots.All("Dark theme");
                main.Results.SelectTab(1);
                Pump();
                Screenshots.All("Dark theme");
                ThemeManager.Apply(ThemeMode.Light);
            });

            Step("Port notes, Worth a look and Map tabs", () =>
            {
                main.OpenHistory(first);
                Pump();
                var r = History.Load(first);
                var look = PortNotes.WorthALook(r);
                if (look.Count == 0 || look[0].Port.Number != 445) throw new Exception("expected port 445 first in Worth a look, got " + string.Join(", ", look.Select(f => f.Port.Number)));
                main.Results.SelectTab(4);
                Pump();
                main.Results.SelectTab(5);
                Pump();
                if (main.Results.MapDevices.Count != 2) throw new Exception("expected 2 devices on the map, got " + main.Results.MapDevices.Count);
                if (main.Results.MapDevices.All(d => d.Kind != DeviceKind.Storage)) throw new Exception("the Synology NAS wasn't seen as storage");
                var png = main.Results.SaveMap(Path.Combine(temp, "map.png"));
                if (png == null || new FileInfo(png).Length < 2000) throw new Exception("the map picture wasn't saved");
                ThemeManager.Apply(ThemeMode.Dark);
                Pump();
                Screenshots.All("Map dark");
                main.Results.SelectTab(4);
                Pump();
                Screenshots.All("Worth a look dark");
                ThemeManager.Apply(ThemeMode.Light);
                main.Results.SelectTab(0);
            });

            Step("Scheduled scans (a real Windows task)", () =>
            {
                var parsed = CommandLine.Parse(new[] { "--scheduled", "0123456789abcdef0123456789abcdef", "--data", temp });
                if (parsed.Scheduled == null || parsed.DataFolder == null) throw new Exception("--scheduled wasn't read");
                if (CommandLine.Parse(new[] { "--scheduled", "..\\evil" }).Scheduled != null) throw new Exception("a bad --scheduled id was accepted");

                var o = Presets.CreateOptions(Presets.Find("quick"));
                o.Targets = "127.0.0.1";
                var sc = new ScheduledScan { Name = "Self-test schedule", Options = o, Every = ScanEvery.Daily, Minutes = 3 * 60 };
                var problem = ScheduledScans.Apply(sc, AppInfo.ExePath, Admin.IsAdmin, temp);
                if (problem != null) throw new Exception(problem);
                ScheduledScans.Save(sc);
                try
                {
                    if (!ScheduledScans.TaskExists(sc)) throw new Exception("the Windows task wasn't made");
                    var window = new SchedulesWindow(main);
                    OffScreen(window);
                    window.Show();
                    Pump();
                    if (window.Shown.Count != 1) throw new Exception("expected 1 scheduled scan in the window, got " + window.Shown.Count);
                    Screenshots.One(window, window.Title);

                    if (!ScheduledScans.RunNow(sc)) throw new Exception("the task didn't start");
                    var until = DateTime.Now.AddSeconds(120);
                    ScheduledScan after = null;
                    while (DateTime.Now < until)
                    {
                        System.Threading.Thread.Sleep(500);
                        Pump();
                        after = ScheduledScans.Find(sc.Id);
                        if (after != null && after.LastRun != DateTime.MinValue) break;
                    }
                    if (after == null || after.LastRun == DateTime.MinValue) throw new Exception("the scheduled scan didn't run by itself within 2 minutes");
                    // CI has no Nmap: then the run says so. With Nmap, the run is kept in History under this schedule.
                    if (!after.LastResult.Contains("Nmap") && !History.List().Any(h => h.ScheduleId == sc.Id))
                        throw new Exception("the run isn't in History: " + after.LastResult);
                    window.Fill(sc.Id);
                    Pump();
                    Screenshots.One(window, window.Title + " after a run");
                    window.Close();
                }
                finally
                {
                    if (!ScheduledScans.Remove(sc)) Errors.Add("Scheduled scans: the Windows task wasn't removed");
                    ScheduledScans.Delete(sc);
                }
                if (ScheduledScans.TaskExists(sc)) throw new Exception("the Windows task is still there");
            });

            Step("History window", () => ShowAndClose(new HistoryWindow(main)));
            Step("Compare window", () => ShowAndClose(new CompareWindow(main, History.List(), null)));
            Step("Settings window", () => ShowAndClose(new SettingsWindow(main, () => null, () => { })));
            Step("Exports", () =>
            {
                var r = History.Load(first);
                Exporter.SaveHtml(r, "Self-test", Path.Combine(temp, "report.html"));
                Exporter.SaveCsv(r, Path.Combine(temp, "hosts.csv"));
                Exporter.SaveVulnerabilitiesCsv(r, Path.Combine(temp, "vulns.csv"));
            });
            Step("Close main window", () => main?.Close());

            log.AppendLine(Errors.Count == 0 ? "SELF-TEST PASSED" : "SELF-TEST FAILED (" + Errors.Count + ")");
            try { File.WriteAllText(Path.Combine(Path.GetDirectoryName(AppInfo.ExePath) ?? ".", "self-test.log"), log.ToString()); }
            catch { /* read-only folder */ }
            try { Directory.Delete(temp, true); } catch { /* ignore */ }
            return Errors.Count == 0 ? 0 : 1;
        }

        private static void OffScreen(Window w)
        {
            w.WindowStartupLocation = WindowStartupLocation.Manual;
            w.WindowState = WindowState.Normal;
            w.Left = -20000;
            w.Top = -20000;
            w.ShowActivated = false;
            w.ShowInTaskbar = false;
        }

        private static void ShowAndClose(Window w)
        {
            OffScreen(w);
            w.Show();
            Pump();
            Screenshots.One(w, w.Title);
            w.Close();
        }

        /// <summary>Lets WPF finish layout and pending work.</summary>
        private static void Pump()
        {
            foreach (Window w in Application.Current.Windows) w.UpdateLayout();
            Application.Current.Dispatcher.Invoke(() => { }, DispatcherPriority.ContextIdle);
        }
    }
}
