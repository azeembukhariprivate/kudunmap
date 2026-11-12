using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Security;
using System.Text;

namespace Kudunmap.Core
{
    public enum ScanEvery { Hourly, Daily, Weekly }

    /// <summary>A scan that runs by itself (through Windows' Task Scheduler) and says when something changed.</summary>
    [DataContract]
    public sealed class ScheduledScan
    {
        [DataMember] public string Id { get; set; } = Guid.NewGuid().ToString("N");
        [DataMember] public string Name { get; set; } = string.Empty;
        [DataMember] public ScanOptions Options { get; set; }
        [DataMember] public ScanEvery Every { get; set; } = ScanEvery.Daily;
        /// <summary>For hourly scans: every this many hours (1 to 12).</summary>
        [DataMember] public int Hours { get; set; } = 1;
        /// <summary>For daily and weekly scans: the time, in minutes after midnight.</summary>
        [DataMember] public int Minutes { get; set; } = 2 * 60;
        /// <summary>For weekly scans: 0 = Sunday to 6 = Saturday.</summary>
        [DataMember] public int Day { get; set; } = 1;
        [DataMember] public DateTime LastRun { get; set; }
        [DataMember] public string LastResult { get; set; } = string.Empty;
        public string File { get; set; }

        private static readonly string[] DayNames = { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };

        public string When
        {
            get
            {
                var time = $"{Minutes / 60:00}:{Minutes % 60:00}";
                switch (Every)
                {
                    case ScanEvery.Hourly: return Hours <= 1 ? "Every hour" : $"Every {Hours} hours";
                    case ScanEvery.Weekly: return $"Every {DayNames[Math.Max(0, Math.Min(6, Day))]} at {time}";
                    default: return $"Every day at {time}";
                }
            }
        }

        public string Targets => string.IsNullOrEmpty(Options?.TargetFile) ? Options?.Targets?.Trim() ?? string.Empty : Path.GetFileName(Options.TargetFile);
    }

    /// <summary>
    /// The scheduled scans: kept as JSON files in KUDUNMAP's folder, each with a Windows task that starts
    /// "KUDUNMAP.exe --scheduled &lt;id&gt;" with administrator rights (asked for once, when the task is made).
    /// </summary>
    public static class ScheduledScans
    {
        public const string Prefix = "KUDUNMAP - ";

        public static string Folder
        {
            get
            {
                var dir = Path.Combine(AppPaths.Root, "Schedules");
                Directory.CreateDirectory(dir);
                return dir;
            }
        }

        public static List<ScheduledScan> List()
        {
            var list = new List<ScheduledScan>();
            foreach (var file in Directory.GetFiles(Folder, "*.json"))
            {
                var s = Json.Read<ScheduledScan>(file);
                if (s?.Options == null || string.IsNullOrEmpty(s.Id)) continue;
                s.File = file;
                list.Add(s);
            }
            return list.OrderBy(s => s.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        }

        public static ScheduledScan Find(string id) => List().FirstOrDefault(s => s.Id == id);

        public static void Save(ScheduledScan s)
        {
            s.File = Path.Combine(Folder, s.Id + ".json");
            Json.Write(s.File, s);
        }

        public static void Delete(ScheduledScan s)
        {
            var file = Path.Combine(Folder, s.Id + ".json");
            if (System.IO.File.Exists(file)) System.IO.File.Delete(file);
        }

        public static string TaskName(ScheduledScan s) =>
            Prefix + AppPaths.SafeFileName(s.Name, 40) + " (" + s.Id.Substring(0, Math.Min(8, s.Id.Length)) + ")";

        /// <summary>The command line the task runs (another data folder is passed on, for the self-test).</summary>
        public static string Arguments(ScheduledScan s, string dataFolder = null) =>
            "--scheduled " + s.Id + (string.IsNullOrEmpty(dataFolder) ? string.Empty : " --data " + CommandBuilder.JoinArguments(new[] { dataFolder }));

        /// <summary>The task, in Task Scheduler's XML: runs as you, when you're signed in, with administrator rights.</summary>
        public static string TaskXml(ScheduledScan s, string exe, string user, DateTime today, string dataFolder = null)
        {
            var at = today.Date.AddMinutes(Math.Max(0, Math.Min(24 * 60 - 1, s.Minutes))).ToString("yyyy-MM-ddTHH:mm:ss");
            string trigger;
            switch (s.Every)
            {
                case ScanEvery.Hourly:
                    var hours = Math.Max(1, Math.Min(12, s.Hours));
                    trigger = $"<CalendarTrigger><Repetition><Interval>PT{hours}H</Interval><Duration>P1D</Duration><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>" +
                              $"<StartBoundary>{today.Date:yyyy-MM-ddTHH:mm:ss}</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>";
                    break;
                case ScanEvery.Weekly:
                    string[] names = { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };
                    trigger = $"<CalendarTrigger><StartBoundary>{at}</StartBoundary><Enabled>true</Enabled><ScheduleByWeek><DaysOfWeek><{names[Math.Max(0, Math.Min(6, s.Day))]} /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek></CalendarTrigger>";
                    break;
                default:
                    trigger = $"<CalendarTrigger><StartBoundary>{at}</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>";
                    break;
            }
            return "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n" +
                   "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" +
                   "<RegistrationInfo><Author>KUDUNMAP</Author><Description>" + Escape($"Runs the KUDUNMAP scan \"{s.Name}\" ({s.When.ToLowerInvariant()}) and says if anything changed.") + "</Description></RegistrationInfo>" +
                   "<Triggers>" + trigger + "</Triggers>" +
                   "<Principals><Principal id=\"Author\"><UserId>" + Escape(user) + "</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>" +
                   "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" +
                   "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable>" +
                   "<RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>" +
                   "<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun>" +
                   "<ExecutionTimeLimit>PT6H</ExecutionTimeLimit><Priority>7</Priority></Settings>" +
                   "<Actions Context=\"Author\"><Exec><Command>" + Escape(exe) + "</Command><Arguments>" + Escape(Arguments(s, dataFolder)) + "</Arguments></Exec></Actions>" +
                   "</Task>";
        }

        private static string Escape(string text) => SecurityElement.Escape(text ?? string.Empty);

        /// <summary>
        /// In plain words, what changed since the scheduled scan's last run, or null when nothing worth telling did.
        /// </summary>
        public static string Alert(IList<Change> changes)
        {
            if (changes == null) return null;
            int Count(ChangeKind k) => changes.Count(c => c.Kind == k);
            var parts = new List<string>();
            void Add(int n, string one, string many)
            {
                if (n > 0) parts.Add(n == 1 ? Lang.T(one) : Lang.T(many, n)); // shown in a notification, in the language in use
            }
            Add(Count(ChangeKind.NewHost), "a new device", "{0} new devices");
            Add(Count(ChangeKind.PortOpened), "a port opened", "{0} ports opened");
            Add(Count(ChangeKind.HostGone), "a device went away", "{0} devices went away");
            Add(Count(ChangeKind.PortClosed), "a port closed", "{0} ports closed");
            Add(Count(ChangeKind.VersionChanged), "a service changed version", "{0} services changed version");
            if (parts.Count == 0) return null;
            var text = string.Join(", ", parts);
            return char.ToUpperInvariant(text[0]) + text.Substring(1) + ".";
        }

        /// <summary>The run of the same scheduled scan just before this one, if any.</summary>
        public static HistoryEntry PreviousRun(IEnumerable<HistoryEntry> history, string scheduleId, HistoryEntry current) =>
            history.Where(e => e.ScheduleId == scheduleId && e.Folder != current.Folder && e.Started < current.Started)
                .OrderByDescending(e => e.Started).FirstOrDefault();

        // ================================================================ Windows' Task Scheduler

        /// <summary>
        /// Creates or replaces the scan's task. Making a task that runs with administrator rights needs them, so Windows
        /// asks here when KUDUNMAP isn't already running with them. Returns null, or what went wrong.
        /// </summary>
        public static string Apply(ScheduledScan s, string exe, bool isAdmin, string dataFolder = null)
        {
            var file = Path.Combine(AppPaths.Running, "task-" + Guid.NewGuid().ToString("N") + ".xml");
            try
            {
                System.IO.File.WriteAllText(file, TaskXml(s, exe, CurrentUser(), DateTime.Today, dataFolder), Encoding.Unicode);
                var (code, output) = SchTasks(!isAdmin, "/Create", "/TN", TaskName(s), "/XML", file, "/F");
                if (code == 1223) return "Windows' question about administrator rights was answered No, so the scan wasn't scheduled.";
                return code == 0 ? null : "Windows Task Scheduler said: " + (string.IsNullOrWhiteSpace(output) ? "error " + code : output.Trim());
            }
            finally
            {
                try { System.IO.File.Delete(file); }
                catch { /* ignore */ }
            }
        }

        /// <summary>
        /// Removes the scan's task. Windows may want administrator rights for a task that runs with them; it asks only then.
        /// Returns false when it's still there.
        /// </summary>
        public static bool Remove(ScheduledScan s) => DeleteTask(TaskName(s));

        /// <summary>True when the scan's task is in Task Scheduler.</summary>
        public static bool TaskExists(ScheduledScan s) => SchTasks(false, "/Query", "/TN", TaskName(s)).Code == 0;

        private static bool DeleteTask(string name)
        {
            if (SchTasks(false, "/Delete", "/TN", name, "/F").Code == 0) return true;
            if (SchTasks(false, "/Query", "/TN", name).Code != 0) return true; // already gone
            return SchTasks(true, "/Delete", "/TN", name, "/F").Code == 0;
        }

        /// <summary>Starts the scan's task now.</summary>
        public static bool RunNow(ScheduledScan s) => SchTasks(false, "/Run", "/TN", TaskName(s)).Code == 0;

        /// <summary>Removes every KUDUNMAP task (used when uninstalling).</summary>
        public static void RemoveAll()
        {
            var (code, output) = SchTasks(false, "/Query", "/FO", "CSV", "/NH");
            if (code != 0) return;
            foreach (var line in output.Split('\n'))
            {
                if (!line.StartsWith("\"")) continue;
                var end = line.IndexOf('"', 1);
                if (end < 0) continue;
                var name = line.Substring(1, end - 1).TrimStart('\\');
                if (name.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)) DeleteTask(name);
            }
        }

        private static string CurrentUser()
        {
            try { return System.Security.Principal.WindowsIdentity.GetCurrent().Name; }
            catch { return Environment.UserDomainName + "\\" + Environment.UserName; }
        }

        private static (int Code, string Output) SchTasks(bool elevate, params string[] args)
        {
            try
            {
                var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "schtasks.exe"), CommandBuilder.JoinArguments(args)) { CreateNoWindow = true };
                if (elevate)
                {
                    // Windows asks for administrator rights; the output can't be read this way, only the exit code.
                    info.UseShellExecute = true;
                    info.Verb = "runas";
                    info.WindowStyle = ProcessWindowStyle.Hidden;
                    using (var p = Process.Start(info))
                    {
                        p.WaitForExit(60000);
                        return (p.HasExited ? p.ExitCode : 1, string.Empty);
                    }
                }
                info.UseShellExecute = false;
                info.RedirectStandardOutput = true;
                info.RedirectStandardError = true;
                using (var p = Process.Start(info))
                {
                    var stdout = p.StandardOutput.ReadToEndAsync();
                    var stderr = p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(30000)) return (1, "Task Scheduler didn't respond.");
                    return (p.ExitCode, stdout.Result + stderr.Result);
                }
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                return (1223, string.Empty);
            }
            catch (Exception ex) when (ex is Win32Exception || ex is InvalidOperationException || ex is IOException)
            {
                return (1, ex.Message);
            }
        }
    }
}
