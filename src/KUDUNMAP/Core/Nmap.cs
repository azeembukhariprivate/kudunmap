// Finding the user's own Nmap, and running it: the command, its output line by line, stopping it.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Kudunmap.Core
{
    public sealed class NmapInstall
    {
        /// <summary>Where nmap.exe is.</summary>
        public string Path { get; set; }
        /// <summary>Nmap's version, as it says itself.</summary>
        public string Version { get; set; }
        /// <summary>The folder nmap.exe is in.</summary>
        public string Folder => System.IO.Path.GetDirectoryName(Path);
    }

    /// <summary>Finds the nmap.exe the user installed. KUDUNMAP never downloads or installs Nmap itself.</summary>
    public static class NmapLocator
    {
        /// <summary>The places looked in last time (shown when Nmap isn't found).</summary>
        public static List<string> SearchedPlaces { get; } = new List<string>();

        /// <summary>
        /// The places nmap.exe may be: the path set in Settings, the Nmap folder in Program Files, and the folders on
        /// the PATH.
        /// </summary>
        public static IEnumerable<string> Candidates(string customPath)
        {
            SearchedPlaces.Clear();
            if (!string.IsNullOrWhiteSpace(customPath))
            {
                SearchedPlaces.Add(customPath);
                yield return customPath;
            }

            foreach (var folder in new[]
                     {
                         Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                         Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                         Environment.GetEnvironmentVariable("ProgramW6432")
                     }.Where(f => !string.IsNullOrEmpty(f)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var dir = System.IO.Path.Combine(folder, "Nmap");
                SearchedPlaces.Add(dir);
                yield return System.IO.Path.Combine(dir, "nmap.exe");
            }

            SearchedPlaces.Add("PATH");
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(System.IO.Path.PathSeparator))
            {
                if (string.IsNullOrWhiteSpace(dir)) continue;
                string candidate;
                try { candidate = System.IO.Path.Combine(dir.Trim().Trim('"'), "nmap.exe"); }
                catch { continue; }
                yield return candidate;
            }
        }

        /// <summary>The first nmap.exe found that answers with its version, or null.</summary>
        public static NmapInstall Find(string customPath)
        {
            foreach (var path in Candidates(customPath))
            {
                try
                {
                    if (!File.Exists(path)) continue;
                    if (!string.Equals(System.IO.Path.GetFileName(path), "nmap.exe", StringComparison.OrdinalIgnoreCase)) continue;
                    var version = ReadVersion(path);
                    if (version != null) return new NmapInstall { Path = path, Version = version };
                }
                catch
                {
                    // Try the next place.
                }
            }
            return null;
        }

        /// <summary>The same, without holding up the window.</summary>
        public static Task<NmapInstall> FindAsync(string customPath) => Task.Run(() => Find(customPath));

        /// <summary>Runs "nmap --version" and returns e.g. "7.95", or null if it isn't Nmap.</summary>
        public static string ReadVersion(string path)
        {
            var psi = new ProcessStartInfo(path, "--version")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (var p = Process.Start(psi))
            {
                if (p == null) return null;
                var text = p.StandardOutput.ReadToEnd();
                if (!p.WaitForExit(10000))
                {
                    try { p.Kill(); } catch { }
                    return null;
                }
                var m = Regex.Match(text, @"Nmap version (?<v>[0-9][0-9A-Za-z.\-]*)");
                return m.Success ? m.Groups["v"].Value : null;
            }
        }
    }

    /// <summary>Runs one Nmap scan and reports its text output line by line.</summary>
    public sealed class NmapRunner : IDisposable
    {
        /// <summary>All the output so far.</summary>
        private readonly StringBuilder _output = new StringBuilder();
        /// <summary>Guards the output, which is added to from Nmap's output threads.</summary>
        private readonly object _lock = new object();
        /// <summary>The Nmap process running.</summary>
        private Process _process;
        /// <summary>True once the person stopped the scan.</summary>
        private bool _cancelled;

        /// <summary>Each line Nmap writes, as it comes.</summary>
        public event Action<string> Line;
        /// <summary>Nmap finished, with its exit code.</summary>
        public event Action<int> Exited;

        public string Output
        {
            get { lock (_lock) return _output.ToString(); }
        }

        /// <summary>True when the scan was stopped by the person.</summary>
        public bool Cancelled => _cancelled;

        /// <summary>
        /// The arguments with Nmap's own folder as the place for its files (scripts, the lists of ports and services).
        /// Otherwise Nmap also looks in your own folders first, where any program could put a script that would then run
        /// with the scan's rights.
        /// </summary>
        public static List<string> WithOwnFiles(string nmapPath, IEnumerable<string> args, Func<string, bool> fileExists = null)
        {
            var list = new List<string>();
            var path = nmapPath ?? string.Empty;
            var dir = path.Substring(0, Math.Max(0, Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'))));
            if (!string.IsNullOrEmpty(dir) && (fileExists ?? File.Exists)(Path.Combine(dir, "nse_main.lua")))
            {
                list.Add("--datadir");
                list.Add(dir);
            }
            list.AddRange(args);
            return list;
        }

        /// <summary>
        /// Starts Nmap with these arguments (each quoted safely, and Nmap's own data folder added) in the folder given,
        /// without a window.
        /// </summary>
        public void Start(string nmapPath, IEnumerable<string> args, string workingFolder)
        {
            var psi = new ProcessStartInfo(nmapPath, CommandBuilder.JoinArguments(WithOwnFiles(nmapPath, args)))
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = workingFolder
            };
            psi.EnvironmentVariables.Remove("NMAPDIR"); // another place Nmap would look for its files

            _process = new Process { StartInfo = psi, EnableRaisingEvents = true };
            _process.OutputDataReceived += (s, e) => OnLine(e.Data);
            _process.ErrorDataReceived += (s, e) => OnLine(e.Data);
            _process.Exited += (s, e) =>
            {
                // Let the output readers drain before reporting the end.
                try { _process.WaitForExit(); } catch { }
                int code;
                try { code = _process.ExitCode; } catch { code = -1; }
                Exited?.Invoke(code);
            };

            _process.Start();
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
        }

        /// <summary>Keeps a line of output and passes it on.</summary>
        private void OnLine(string line)
        {
            if (line == null) return;
            lock (_lock) _output.AppendLine(line);
            Line?.Invoke(line);
        }

        /// <summary>Stops Nmap.</summary>
        public void Cancel()
        {
            _cancelled = true;
            try
            {
                if (_process != null && !_process.HasExited) _process.Kill();
            }
            catch
            {
                // Already finished.
            }
        }

        /// <summary>Stops Nmap if it's still running.</summary>
        public void Dispose()
        {
            try { _process?.Dispose(); } catch { }
        }

        /// <summary>A plain-English hint for common problems in Nmap's output, or null.</summary>
        public static string Explain(string output)
        {
            if (string.IsNullOrEmpty(output)) return null;
            if (Regex.IsMatch(output, @"requires root privileges|requires (?:administrator|root)", RegexOptions.IgnoreCase))
                return "This scan needs administrator rights. Use \"Restart as administrator\" and run it again.";
            if (Regex.IsMatch(output, @"Npcap|WinPcap|pcap_open|dnet: Failed to open device", RegexOptions.IgnoreCase))
                return "Nmap couldn't use Npcap, the network driver it needs on Windows. Re-run the Nmap installer from nmap.org " +
                       "and keep the Npcap option ticked, or restart KUDUNMAP as administrator.";
            if (Regex.IsMatch(output, @"Failed to resolve|Unable to split netmask", RegexOptions.IgnoreCase))
                return "Nmap couldn't understand or look up one of the targets. Check the spelling of the address or name.";
            if (Regex.IsMatch(output, @"No targets were specified", RegexOptions.IgnoreCase))
                return "No targets were given to scan.";
            return null;
        }
    }
}
