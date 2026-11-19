using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Kudunmap.Core
{
    /// <summary>
    /// Whether KUDUNMAP's own files can be changed only by administrators. Installed for all users (in Program Files),
    /// they can; installed just for you (in your own folder), any program running as you could change them, so nothing
    /// may run them with administrator rights without Windows asking first.
    /// </summary>
    public static class InstallPlace
    {
        public static IEnumerable<string> ProtectedRoots() =>
            new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 }
                .Select(Environment.GetFolderPath).Where(p => !string.IsNullOrEmpty(p)).Distinct(StringComparer.OrdinalIgnoreCase);

        /// <summary>True when KUDUNMAP (this exe) is installed for all users.</summary>
        public static bool IsProtected(string exePath) => IsUnder(exePath, ProtectedRoots());

        /// <summary>True when <paramref name="path"/> is inside one of <paramref name="roots"/> (not the root itself).</summary>
        public static bool IsUnder(string path, IEnumerable<string> roots)
        {
            var full = Normal(path);
            if (full == null) return false;
            foreach (var root in roots)
            {
                var r = Normal(root);
                if (r != null && full.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        /// <summary>A whole Windows path with "." and ".." worked out and no ending \, or null when it isn't a whole path.</summary>
        private static string Normal(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return null;
            var p = path.Trim().Replace('/', '\\');
            string start;
            if (p.StartsWith("\\\\")) start = "\\\\";
            else if (p.Length >= 3 && char.IsLetter(p[0]) && p[1] == ':' && p[2] == '\\') start = p.Substring(0, 2);
            else return null;
            var parts = new List<string>();
            foreach (var part in p.Substring(start.Length).Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (part == ".") continue;
                if (part == "..")
                {
                    if (parts.Count == 0) return null;
                    parts.RemoveAt(parts.Count - 1);
                    continue;
                }
                parts.Add(part);
            }
            return start == "\\\\" ? start + string.Join("\\", parts) : start + "\\" + string.Join("\\", parts);
        }

        /// <summary>
        /// True when one of <paramref name="folders"/> is a link to somewhere else (a junction or symbolic link): written to
        /// with administrator rights, files could land anywhere.
        /// </summary>
        public static bool HasRedirect(IEnumerable<string> folders)
        {
            foreach (var f in folders)
            {
                try
                {
                    if (Directory.Exists(f) && (File.GetAttributes(f) & FileAttributes.ReparsePoint) != 0) return true;
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return true; }
            }
            return false;
        }
    }
}
