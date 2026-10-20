using System;
using System.Collections.Generic;
using System.Linq;

namespace Kudunmap.Core
{
    public sealed class Preset
    {
        public string Id { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }

        /// <summary>A longer sentence shown above the options.</summary>
        public string Summary { get; set; }

        /// <summary>Name of the icon geometry in Styles.xaml.</summary>
        public string Icon { get; set; }

        public Func<ScanOptions> Create { get; set; }

        public bool NeedsAdmin => Create().NeedsAdmin;
    }

    public static class Presets
    {
        public static readonly string[] TimingNames = { "Paranoid", "Sneaky", "Polite", "Normal", "Fast", "Insane" };

        public static string TimingMeaning(int timing)
        {
            switch (timing)
            {
                case 0: return "paranoid speed (very slow, quiet)";
                case 1: return "sneaky speed (slow, quiet)";
                case 2: return "polite speed (gentle on the network)";
                case 3: return "normal speed";
                case 5: return "insane speed (may miss ports)";
                default: return "fast speed";
            }
        }

        public static readonly IReadOnlyList<Preset> All = new List<Preset>
        {
            new Preset
            {
                Id = "quick", Title = "Quick scan", Description = "Top 100 ports, fast", Icon = "IconBolt",
                Summary = "Checks the 100 most common ports on each host. A good first look.",
                Create = () => new ScanOptions { Ports = PortMode.Fast }
            },
            new Preset
            {
                Id = "ping", Title = "Ping sweep", Description = "Who's online? No port scan", Icon = "IconPing",
                Summary = "Finds which devices are switched on and answering. Doesn't look at ports.",
                Create = () => new ScanOptions { Kind = ScanKind.Ping }
            },
            new Preset
            {
                Id = "common", Title = "Common ports", Description = "Top 1,000 ports", Icon = "IconPorts",
                Summary = "Checks the 1,000 most common ports on each host. Nmap's standard scan.",
                Create = () => new ScanOptions()
            },
            new Preset
            {
                Id = "all", Title = "All ports", Description = "All 65,535 TCP ports · slow", Icon = "IconPorts",
                Summary = "Checks every TCP port. Finds services on unusual ports, but takes much longer.",
                Create = () => new ScanOptions { Ports = PortMode.All }
            },
            new Preset
            {
                Id = "services", Title = "Services & versions", Description = "What software runs on each port", Icon = "IconServer",
                Summary = "Finds open ports and asks each one what software and version it runs.",
                Create = () => new ScanOptions { DetectVersions = true }
            },
            new Preset
            {
                Id = "os", Title = "OS detection", Description = "Guess the operating system", Icon = "IconMonitor",
                Summary = "Guesses each host's operating system from how it answers. Needs administrator rights.",
                Create = () => new ScanOptions { DetectOs = true }
            },
            new Preset
            {
                Id = "intense", Title = "Intense", Description = "Versions, OS, scripts, traceroute", Icon = "IconTarget",
                Summary = "Versions, operating system, default scripts and traceroute in one go. Needs administrator rights.",
                Create = () => new ScanOptions
                {
                    DetectVersions = true, DetectOs = true, Traceroute = true, Scripts = new List<string> { "default" }
                }
            },
            new Preset
            {
                Id = "udp", Title = "UDP scan", Description = "Top 100 UDP ports · slow", Icon = "IconWave",
                Summary = "Checks the 100 most common UDP ports (DNS, DHCP, SNMP and more). Slow. Needs administrator rights.",
                Create = () => new ScanOptions { Kind = ScanKind.Udp, Ports = PortMode.Fast, OnlyOpen = false }
            },
            new Preset
            {
                Id = "vuln", Title = "Vulnerability check", Description = "Known problems & CVEs", Icon = "IconBug",
                Summary = "Finds versions, then runs Nmap's vuln scripts to check for well-known problems. Some checks send unusual traffic.",
                Create = () => new ScanOptions { DetectVersions = true, Scripts = new List<string> { "vuln" } }
            }
        };

        public static Preset Find(string id) =>
            All.FirstOrDefault(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase));

        public static ScanOptions CreateOptions(Preset preset)
        {
            var o = preset.Create();
            o.PresetId = preset.Id;
            o.Title = preset.Title;
            return o;
        }
    }
}
