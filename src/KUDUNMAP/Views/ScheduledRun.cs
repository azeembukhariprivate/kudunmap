using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Threading;
using Kudunmap.Core;

namespace Kudunmap.Views
{
    /// <summary>
    /// "KUDUNMAP.exe --scheduled &lt;id&gt;", started by Windows' Task Scheduler: runs the saved scan without a window, keeps
    /// it in History, and shows a Windows notification when something changed since the last run.
    /// </summary>
    public static class ScheduledRun
    {
        /// <summary>Starts the scan; the app shuts down by itself when it's done (exit code 0, or 1 when it failed).</summary>
        public static void Start(Application app, string id)
        {
            var schedule = ScheduledScans.Find(id);
            if (schedule == null)
            {
                app.Shutdown(2);
                return;
            }
            // The task runs with administrator rights: only use an nmap.exe chosen by hand when it's in Program Files
            // (which needs administrator rights to change), not one anywhere a normal program could put it.
            var custom = Settings.NmapPath;
            if (!string.IsNullOrEmpty(custom) && !InProgramFiles(custom)) custom = null;
            var nmap = NmapLocator.Find(custom);
            if (nmap == null)
            {
                Finish(app, schedule, null, "Nmap wasn't found.", true);
                return;
            }

            var o = schedule.Options.Clone();
            o.Title = schedule.Name;
            var invalid = string.IsNullOrEmpty(o.TargetFile) ? CommandBuilder.ValidateTargets(o.Targets) : File.Exists(o.TargetFile) ? null : "The target file can't be found.";
            if (invalid == null && o.Kind != ScanKind.Ping && o.Ports == PortMode.Custom) invalid = CommandBuilder.ValidatePorts(o.CustomPorts);
            if (invalid != null)
            {
                Finish(app, schedule, null, invalid, true);
                return;
            }
            var xml = Path.Combine(AppPaths.Running, "scan-" + Guid.NewGuid().ToString("N") + ".xml");
            var runner = new NmapRunner();
            runner.Exited += code => app.Dispatcher.BeginInvoke(new Action(() =>
            {
                var output = runner.Output;
                runner.Dispose();
                HistoryEntry entry = null;
                string problem = null;
                try
                {
                    var result = NmapXml.Load(xml);
                    if (!result.Completed) problem = string.IsNullOrEmpty(result.ErrorMessage) ? "Nmap reported an error." : result.ErrorMessage;
                    else entry = History.Save(o, result, xml, output, schedule.Id);
                }
                catch (Exception ex)
                {
                    problem = NmapRunner.Explain(output) ?? $"Nmap stopped without results (exit code {code}). " + ex.Message;
                }
                finally
                {
                    try { File.Delete(xml); }
                    catch { /* ignore */ }
                }
                Finish(app, schedule, entry, problem, problem != null);
            }));
            try
            {
                runner.Start(nmap.Path, CommandBuilder.BuildArguments(o, Admin.IsAdmin, xml), AppPaths.Running);
            }
            catch (Exception ex)
            {
                Finish(app, schedule, null, "Nmap couldn't start: " + ex.Message, true);
            }
        }

        private static bool InProgramFiles(string path)
        {
            try
            {
                var full = Path.GetFullPath(path);
                foreach (var root in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
                    if (!string.IsNullOrEmpty(root) && full.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)) return true;
            }
            catch
            {
                // a bad path
            }
            return false;
        }

        private static void Finish(Application app, ScheduledScan schedule, HistoryEntry entry, string problem, bool failed)
        {
            string alert = null;
            if (entry != null)
            {
                try
                {
                    var previous = ScheduledScans.PreviousRun(History.List(), schedule.Id, entry);
                    if (previous != null)
                        alert = ScheduledScans.Alert(ScanComparer.Compare(History.Load(previous), History.Load(entry)));
                    schedule.LastResult = previous == null ? "First run · " + entry.Summary : (alert ?? "Nothing changed") + " · " + entry.Summary;
                }
                catch (Exception ex)
                {
                    schedule.LastResult = entry.Summary + " · couldn't compare: " + ex.Message;
                }
            }
            else schedule.LastResult = "Didn't finish: " + problem;
            schedule.LastRun = DateTime.Now;
            try { ScheduledScans.Save(schedule); }
            catch { /* the result is still in History */ }

            var text = failed ? "The scan didn't finish. " + problem : alert;
            if (text == null)
            {
                app.Shutdown(0);
                return;
            }
            Notify(app, failed ? schedule.Name + " didn't finish" : schedule.Name + ": something changed", text, () =>
            {
                try { Process.Start(new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName, "--history") { UseShellExecute = false }); }
                catch { /* the notification was still shown */ }
            }, failed ? 1 : 0);
        }

        /// <summary>A Windows notification; the app ends when it's closed or clicked (or after a minute).</summary>
        private static void Notify(Application app, string title, string text, Action clicked, int exitCode)
        {
            System.Drawing.Icon icon = null;
            System.Windows.Forms.NotifyIcon notify = null;
            var done = false;
            void Done()
            {
                if (done) return;
                done = true;
                try
                {
                    if (notify != null)
                    {
                        notify.Visible = false;
                        notify.Dispose();
                    }
                    icon?.Dispose();
                }
                catch { /* already gone */ }
                app.Shutdown(exitCode);
            }
            try
            {
                using (var stream = Dialogs.AppIconStream()) icon = new System.Drawing.Icon(stream);
                notify = new System.Windows.Forms.NotifyIcon { Icon = icon, Text = "KUDUNMAP", Visible = true };
                notify.BalloonTipClicked += (s, e) =>
                {
                    clicked();
                    Done();
                };
                notify.Click += (s, e) =>
                {
                    clicked();
                    Done();
                };
                notify.BalloonTipClosed += (s, e) => Done();
                notify.ShowBalloonTip(15000, title, text, System.Windows.Forms.ToolTipIcon.Info);
                var timer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(1) };
                timer.Tick += (s, e) =>
                {
                    timer.Stop();
                    Done();
                };
                timer.Start();
            }
            catch
            {
                Done();
            }
        }
    }
}
