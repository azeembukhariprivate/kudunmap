using System;
using System.Diagnostics;
using System.Reflection;
using System.Text.RegularExpressions;

namespace Kudunmap.Core
{
    public static class AppInfo
    {
        public const string Name = "KUDUNMAP";
        public const string Author = "Azeem Bukhari";
        public const string RepoOwner = "azeembukhariprivate";
        public const string RepoName = "kudunmap";
        public const string NmapDownloadUrl = "https://nmap.org/download.html#windows";
        public const string NmapLicenseUrl = "https://nmap.org/npsl/";

        public static string RepoUrl => $"https://github.com/{RepoOwner}/{RepoName}";
        public static string ReleasesUrl => RepoUrl + "/releases";

        public static Version Version
        {
            get
            {
                var v = Assembly.GetExecutingAssembly().GetName().Version;
                return new Version(v.Major, v.Minor, Math.Max(v.Build, 0));
            }
        }

        public static string VersionText => Version.ToString(3);

        public static string ExePath
        {
            get
            {
                try { return Process.GetCurrentProcess().MainModule.FileName; }
                catch { return Assembly.GetExecutingAssembly().Location; }
            }
        }

        /// <summary>Opens a web page in the default browser. Only http and https links are opened.</summary>
        public static void OpenUrl(string url)
        {
            if (string.IsNullOrEmpty(url) || !Regex.IsMatch(url, @"^https?://", RegexOptions.IgnoreCase)) return;
            try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
            catch { /* no browser available */ }
        }

        public static void OpenFolder(string folder)
        {
            try { Process.Start(new ProcessStartInfo("explorer.exe", "\"" + folder + "\"") { UseShellExecute = true }); }
            catch { /* ignore */ }
        }

        public static string CveUrl(string cve) =>
            VulnerabilityFinder.IsCve(cve) ? "https://www.cve.org/CVERecord?id=" + cve.ToUpperInvariant() : null;

        public static string ScriptDocUrl(string scriptId) =>
            !string.IsNullOrEmpty(scriptId) && Regex.IsMatch(scriptId, @"^[a-z0-9][a-z0-9\-]*$")
                ? "https://nmap.org/nsedoc/scripts/" + scriptId + ".html"
                : null;
    }
}
