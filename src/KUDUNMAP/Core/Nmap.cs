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
        public string Path { get; set; }
        public string Version { get; set; }
        public string Folder => System.IO.Path.GetDirectoryName(Path);
    }

    /// <summary>Finds the nmap.exe the user installed. KUDUNMAP never downloads or installs Nmap itself.</summary>
    public static class NmapLocator
    {
        public static List<string> SearchedPlaces { get; } = new List<string>();

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
        private readonly StringBuilder _output = new StringBuilder();
        private readonly object _lock = new object();
        private Process _process;
        private bool _cancelled;

        public event Action<string> Line;
        public event Action<int> Exited;

        public string Output
        {
            get { lock (_lock) return _output.ToString(); }
        }

        public bool Cancelled => _cancelled;

        public void Start(string nmapPath, IEnumerable<string> args, string workingFolder)
        {
            var psi = new ProcessStartInfo(nmapPath, CommandBuilder.JoinArguments(args))
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = workingFolder
            };

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

        private void OnLine(string line)
        {
            if (line == null) return;
            lock (_lock) _output.AppendLine(line);
            Line?.Invoke(line);
        }

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
