using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;

namespace Kudunmap.Core
{
    /// <summary>Everything read from one Nmap XML results file.</summary>
    public sealed class ScanResult
    {
        public string NmapVersion { get; set; } = string.Empty;
        public string Args { get; set; } = string.Empty;
        public DateTime Started { get; set; }
        public DateTime Finished { get; set; }
        public double ElapsedSeconds { get; set; }
        public int HostsUp { get; set; }
        public int HostsDown { get; set; }
        public int HostsTotal { get; set; }
        public string Summary { get; set; } = string.Empty;
        public bool Completed { get; set; }
        public string ErrorMessage { get; set; }
        public List<HostInfo> Hosts { get; } = new List<HostInfo>();

        public IEnumerable<HostInfo> UpHosts => Hosts.Where(h => h.IsUp);

        public int OpenPortCount => UpHosts.Sum(h => h.OpenPorts.Count());

        public List<Vulnerability> Vulnerabilities => VulnerabilityFinder.Find(this);
    }

    public sealed class HostInfo
    {
        public string State { get; set; } = "unknown";
        public string Ipv4 { get; set; }
        public string Ipv6 { get; set; }
        public string Mac { get; set; }
        public string Vendor { get; set; }
        public List<string> Hostnames { get; } = new List<string>();
        public List<OsMatch> OsMatches { get; } = new List<OsMatch>();
        public List<PortInfo> Ports { get; } = new List<PortInfo>();
        public List<ScriptResult> Scripts { get; } = new List<ScriptResult>();
        public List<TraceHop> Trace { get; } = new List<TraceHop>();

        /// <summary>Smoothed round-trip time in microseconds, or 0 when unknown.</summary>
        public long LatencyMicroseconds { get; set; }
        public int Distance { get; set; }

        public bool IsUp => string.Equals(State, "up", StringComparison.OrdinalIgnoreCase);
        public string Address => Ipv4 ?? Ipv6 ?? Mac ?? string.Empty;
        public string Name => Hostnames.FirstOrDefault() ?? string.Empty;
        public string DisplayName => string.IsNullOrEmpty(Name) ? Address : Name;
        public IEnumerable<PortInfo> OpenPorts => Ports.Where(p => p.IsOpen);

        /// <summary>Best OS guess: OS detection when it ran, otherwise what the services reported.</summary>
        public string OsGuess
        {
            get
            {
                var best = OsMatches.OrderByDescending(m => m.Accuracy).FirstOrDefault();
                if (best != null) return best.Name;
                var fromServices = Ports.Select(p => p.OsType).FirstOrDefault(t => !string.IsNullOrEmpty(t));
                return fromServices ?? string.Empty;
            }
        }

        public string LatencyText => LatencyMicroseconds <= 0
            ? string.Empty
            : LatencyMicroseconds < 1000 ? $"{LatencyMicroseconds / 1000.0:0.0} ms" : $"{LatencyMicroseconds / 1000.0:0} ms";
    }

    public sealed class OsMatch
    {
        public string Name { get; set; }
        public int Accuracy { get; set; }
    }

    public sealed class TraceHop
    {
        public int Ttl { get; set; }
        public string Address { get; set; }
        public string Host { get; set; }
        public string Rtt { get; set; }
    }

    public sealed class PortInfo
    {
        public string Protocol { get; set; } = "tcp";
        public int Number { get; set; }
        public string State { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
        public string Service { get; set; } = string.Empty;
        public string Product { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string ExtraInfo { get; set; } = string.Empty;
        public string Tunnel { get; set; } = string.Empty;
        public string OsType { get; set; } = string.Empty;
        public List<ScriptResult> Scripts { get; } = new List<ScriptResult>();

        public bool IsOpen => State.StartsWith("open", StringComparison.OrdinalIgnoreCase);
        public string Key => Number + "/" + Protocol;

        public string ServiceText => Tunnel == "ssl" && !Service.StartsWith("ssl", StringComparison.OrdinalIgnoreCase) && Service != "https"
            ? "ssl/" + Service
            : Service;

        public string VersionText
        {
            get
            {
                var text = string.Join(" ", new[] { Product, Version }.Where(s => !string.IsNullOrEmpty(s)));
                if (!string.IsNullOrEmpty(ExtraInfo)) text = (text + " (" + ExtraInfo + ")").Trim();
                return text;
            }
        }

        public bool LooksLikeWeb
        {
            get
            {
                var s = Service.ToLowerInvariant();
                return s.StartsWith("http") || s == "https" || s.Contains("http-proxy") || (Tunnel == "ssl" && s.Contains("http"));
            }
        }

        public bool IsHttps => Tunnel == "ssl" || Service.Equals("https", StringComparison.OrdinalIgnoreCase) || Number == 443 || Number == 8443;
    }

    public sealed class ScriptResult
    {
        public string Id { get; set; }
        public string Output { get; set; }

        /// <summary>The structured &lt;table&gt;/&lt;elem&gt; output, when the script provides it.</summary>
        public XElement Element { get; set; }
    }
}
