using System.Text.RegularExpressions;

namespace Kudunmap.Core
{
    /// <summary>This app's own details, next to the shared AppInfo from kudu-common.</summary>
    public static partial class AppInfo
    {
        public const string Name = "KUDUNMAP";
        public const string RepoName = "kudunmap";
        public const string NmapDownloadUrl = "https://nmap.org/download.html#windows";
        public const string NmapLicenseUrl = "https://nmap.org/npsl/";

        public static string CveUrl(string cve) =>
            VulnerabilityFinder.IsCve(cve) ? "https://www.cve.org/CVERecord?id=" + cve.ToUpperInvariant() : null;

        public static string ScriptDocUrl(string scriptId) =>
            !string.IsNullOrEmpty(scriptId) && Regex.IsMatch(scriptId, @"^[a-z0-9][a-z0-9\-]*$")
                ? "https://nmap.org/nsedoc/scripts/" + scriptId + ".html"
                : null;
    }
}
