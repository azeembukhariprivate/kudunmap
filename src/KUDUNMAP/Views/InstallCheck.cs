// KUDUNMAP.exe --install-check: checks after an install for all users that scheduled scans get the right rights, and
// writes what it found to a log (run by the build on Windows).
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using Kudunmap.Core;

namespace Kudunmap.Views
{
    /// <summary>
    /// "KUDUNMAP.exe --install-check": run by the build on a copy installed for all users (in Program Files), to check
    /// by itself what would otherwise be checked by hand: that such a copy may schedule a scan needing administrator
    /// rights, that Windows' task gets those rights, and that the scheduled run is let through. Writes what it found to
    /// %TEMP%\kudunmap-install-check.log and ends with 0 (all good) or 1. It uses its own data folder and removes its task.
    /// </summary>
    public static class InstallCheck
    {
        /// <summary>Runs the checks and returns 0 when all passed.</summary>
        public static int Run()
        {
            var log = new StringBuilder();
            var failed = 0;
            void Expect(bool ok, string what)
            {
                log.AppendLine((ok ? "ok    " : "FAIL  ") + what);
                if (!ok) failed++;
            }

            var exe = AppInfo.ExePath;
            var data = Path.Combine(Path.GetTempPath(), "kudunmap-install-check-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(data);
            AppPaths.Root = data;
            log.AppendLine("KUDUNMAP " + AppInfo.VersionText + " at " + exe + (Admin.IsAdmin ? " (with administrator rights)" : string.Empty));
            ScheduledScan sc = null;
            try
            {
                Expect(InstallPlace.IsProtected(exe), "installed for all users, in Program Files");
                Expect(ScheduledScans.AdminAllowed(exe), "so scheduled scans may have administrator rights");

                // A scan that needs administrator rights (operating system detection) can be scheduled from here.
                var o = Presets.CreateOptions(Presets.Find("quick"));
                o.Targets = "127.0.0.1";
                o.DetectOs = true;
                Expect(o.NeedsAdmin, "the scan needs administrator rights");
                Expect(ScheduledScans.CantSchedule(o, exe) == null, "it may be scheduled");
                sc = new ScheduledScan { Name = "Install check", Options = o, Every = ScanEvery.Daily, Minutes = 3 * 60 };
                var problem = ScheduledScans.Apply(sc, exe, Admin.IsAdmin, data);
                Expect(problem == null, "scheduled" + (problem == null ? string.Empty : ": " + problem));
                ScheduledScans.Save(sc);
                Expect(ScheduledScans.TaskExists(sc), "Windows' task is there");
                var level = ScheduledScans.TaskRunLevel(sc);
                Expect(level == "HighestAvailable" && sc.WithAdmin == true, "the task has administrator rights (" + level + ")");

                // Run it now: the run must get past the rights check (without Nmap on the build machine, it then says
                // Nmap wasn't found; refused, it would say it needs administrator rights or that it's installed just for you).
                var started = DateTime.Now;
                Expect(ScheduledScans.RunNow(sc), "the task started");
                ScheduledScan after = null;
                var until = DateTime.Now.AddSeconds(150);
                while (DateTime.Now < until)
                {
                    Thread.Sleep(500);
                    after = ScheduledScans.Find(sc.Id);
                    if (after != null && after.LastRun != DateTime.MinValue) break;
                }
                var result = after?.LastResult ?? "(it didn't run)";
                log.AppendLine("      the run said: " + result);
                Expect(after != null && after.LastRun != DateTime.MinValue, "the scheduled scan ran by itself");
                Expect(!result.Contains("administrator rights") && !result.Contains("just for you"), "the run was let through with administrator rights");
                Expect(result.Contains("Nmap") || History.List().Any(h => h.ScheduleId == sc.Id), "it went on to the scan");
            }
            catch (Exception ex)
            {
                Expect(false, "the check: " + ex);
            }
            finally
            {
                if (sc != null)
                {
                    try
                    {
                        Expect(ScheduledScans.Remove(sc), "the task removed");
                        ScheduledScans.Delete(sc);
                    }
                    catch (Exception ex) { Expect(false, "removing the task: " + ex.Message); }
                }
                try { Directory.Delete(data, true); } catch { /* ignore */ }
                log.AppendLine(failed == 0 ? "INSTALL CHECK PASSED" : $"INSTALL CHECK FAILED ({failed})");
                try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "kudunmap-install-check.log"), log.ToString()); } catch { /* ignore */ }
            }
            return failed == 0 ? 0 : 1;
        }
    }
}
