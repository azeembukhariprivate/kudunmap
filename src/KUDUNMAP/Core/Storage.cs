using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Text.RegularExpressions;

namespace Kudunmap.Core
{
    /// <summary>Where KUDUNMAP keeps its files: %LOCALAPPDATA%\KUDUNMAP, for the current Windows user only.</summary>
    public static class AppPaths
    {
        private static string _root;

        public static string Root
        {
            get
            {
                if (_root == null)
                {
                    var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                    if (string.IsNullOrEmpty(local)) local = Path.GetTempPath();
                    _root = Path.Combine(local, "KUDUNMAP");
                }
                return _root;
            }
            set => _root = value;
        }

        public static string History => Ensure(Path.Combine(Root, "History"));
        public static string Presets => Ensure(Path.Combine(Root, "Presets"));
        public static string Running => Ensure(Path.Combine(Root, "Running"));

        private static string Ensure(string dir)
        {
            Directory.CreateDirectory(dir);
            return dir;
        }

        /// <summary>Turns any text into something safe to use in a file name.</summary>
        public static string SafeFileName(string text, int max = 40)
        {
            var s = Regex.Replace(text ?? string.Empty, @"[^A-Za-z0-9._ -]+", "_").Trim(' ', '.', '_');
            if (s.Length > max) s = s.Substring(0, max).Trim();
            return s.Length == 0 ? "scan" : s;
        }
    }

    public static class Json
    {
        public static void Write<T>(string path, T value)
        {
            var serializer = new DataContractJsonSerializer(typeof(T));
            var temp = path + ".tmp";
            using (var stream = File.Create(temp)) serializer.WriteObject(stream, value);
            if (File.Exists(path)) File.Delete(path);
            File.Move(temp, path);
        }

        public static T Read<T>(string path) where T : class
        {
            try
            {
                var serializer = new DataContractJsonSerializer(typeof(T));
                using (var stream = File.OpenRead(path)) return serializer.ReadObject(stream) as T;
            }
            catch
            {
                return null;
            }
        }
    }

    [DataContract]
    public sealed class HistoryEntry
    {
        [DataMember] public string Title { get; set; } = string.Empty;
        [DataMember] public string Targets { get; set; } = string.Empty;
        [DataMember] public string PresetId { get; set; } = string.Empty;
        [DataMember] public DateTime Started { get; set; }
        [DataMember] public int HostsUp { get; set; }
        [DataMember] public int OpenPorts { get; set; }
        [DataMember] public int Findings { get; set; }
        [DataMember] public string NmapVersion { get; set; } = string.Empty;

        /// <summary>The options used, so "Scan again" repeats the same scan.</summary>
        [DataMember] public ScanOptions Options { get; set; }

        public string Folder { get; set; }
        public string XmlPath => Path.Combine(Folder, "scan.xml");
        public string OutputPath => Path.Combine(Folder, "output.txt");

        public string Summary => $"{HostsUp} host{(HostsUp == 1 ? "" : "s")} · {OpenPorts} open port{(OpenPorts == 1 ? "" : "s")}" +
                                 (Findings > 0 ? $" · {Findings} finding{(Findings == 1 ? "" : "s")}" : string.Empty);

        public string WhenText => FriendlyDate(Started);

        public string Display => $"{Title} · {Targets} · {WhenText}";

        public override string ToString() => Display;

        public static string FriendlyDate(DateTime when)
        {
            if (when == DateTime.MinValue) return string.Empty;
            var today = DateTime.Today;
            if (when.Date == today) return "Today, " + when.ToString("HH:mm");
            if (when.Date == today.AddDays(-1)) return "Yesterday, " + when.ToString("HH:mm");
            return when.ToString(when.Year == today.Year ? "d MMM, HH:mm" : "d MMM yyyy, HH:mm");
        }
    }

    /// <summary>Every finished scan is kept in its own folder: scan.xml (Nmap's results), output.txt and info.json.</summary>
    public static class History
    {
        public static HistoryEntry Save(ScanOptions options, ScanResult result, string xmlFile, string output)
        {
            var started = result.Started == DateTime.MinValue ? DateTime.Now : result.Started;
            var name = started.ToString("yyyyMMdd-HHmmss") + " " + AppPaths.SafeFileName(options.Title, 30);
            var folder = Path.Combine(AppPaths.History, name);
            var i = 2;
            while (Directory.Exists(folder)) folder = Path.Combine(AppPaths.History, name + " (" + i++ + ")");
            Directory.CreateDirectory(folder);

            var entry = new HistoryEntry
            {
                Title = options.Title,
                Targets = string.IsNullOrEmpty(options.TargetFile) ? options.Targets.Trim() : Path.GetFileName(options.TargetFile),
                PresetId = options.PresetId,
                Started = started,
                HostsUp = result.HostsUp,
                OpenPorts = result.OpenPortCount,
                Findings = result.Vulnerabilities.Count,
                NmapVersion = result.NmapVersion,
                Options = options.Clone(),
                Folder = folder
            };

            File.Copy(xmlFile, entry.XmlPath, true);
            File.WriteAllText(entry.OutputPath, output ?? string.Empty, Encoding.UTF8);
            Json.Write(Path.Combine(folder, "info.json"), entry);
            return entry;
        }

        public static List<HistoryEntry> List()
        {
            var list = new List<HistoryEntry>();
            foreach (var dir in Directory.GetDirectories(AppPaths.History))
            {
                var entry = Json.Read<HistoryEntry>(Path.Combine(dir, "info.json"));
                if (entry == null || !File.Exists(Path.Combine(dir, "scan.xml"))) continue;
                entry.Folder = dir;
                list.Add(entry);
            }
            return list.OrderByDescending(e => e.Started).ToList();
        }

        public static ScanResult Load(HistoryEntry entry) => NmapXml.Load(entry.XmlPath);

        public static string LoadOutput(HistoryEntry entry)
        {
            try { return File.ReadAllText(entry.OutputPath); }
            catch { return string.Empty; }
        }

        public static void Delete(HistoryEntry entry)
        {
            // Only ever delete folders inside our own History folder.
            var root = Path.GetFullPath(AppPaths.History).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var folder = Path.GetFullPath(entry.Folder);
            if (folder.StartsWith(root, StringComparison.OrdinalIgnoreCase) && Directory.Exists(folder))
                Directory.Delete(folder, true);
        }
    }

    [DataContract]
    public sealed class CustomPreset
    {
        [DataMember] public string Name { get; set; } = string.Empty;
        [DataMember] public ScanOptions Options { get; set; }
        public string File { get; set; }

        public string Description
        {
            get
            {
                var basePreset = Core.Presets.Find(Options?.PresetId ?? string.Empty);
                var kind = basePreset?.Title ?? "Custom";
                var target = string.IsNullOrEmpty(Options?.TargetFile) ? Options?.Targets?.Trim() : Path.GetFileName(Options.TargetFile);
                return string.IsNullOrEmpty(target) ? kind : kind + " · " + target;
            }
        }
    }

    /// <summary>"My presets": saved option sets, one JSON file each.</summary>
    public static class CustomPresets
    {
        public static List<CustomPreset> List()
        {
            var list = new List<CustomPreset>();
            foreach (var file in Directory.GetFiles(AppPaths.Presets, "*.json"))
            {
                var preset = Json.Read<CustomPreset>(file);
                if (preset?.Options == null || string.IsNullOrWhiteSpace(preset.Name)) continue;
                preset.File = file;
                list.Add(preset);
            }
            return list.OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        }

        public static CustomPreset Save(string name, ScanOptions options)
        {
            name = (name ?? string.Empty).Trim();
            var existing = List().FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.CurrentCultureIgnoreCase));
            var file = existing?.File ?? Path.Combine(AppPaths.Presets, AppPaths.SafeFileName(name) + "-" + Guid.NewGuid().ToString("N").Substring(0, 6) + ".json");
            var preset = new CustomPreset { Name = name, Options = options.Clone(), File = file };
            Json.Write(file, preset);
            return preset;
        }

        public static void Delete(CustomPreset preset)
        {
            if (preset?.File != null && File.Exists(preset.File) &&
                Path.GetDirectoryName(Path.GetFullPath(preset.File)) == Path.GetFullPath(AppPaths.Presets).TrimEnd(Path.DirectorySeparatorChar))
                File.Delete(preset.File);
        }
    }
}
