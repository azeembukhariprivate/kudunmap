// A scan's results as read from Nmap's XML: the hosts, their ports and services, operating system guesses, route and
// script output.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;

namespace Kudunmap.Core
{
    /// <summary>Everything read from one Nmap XML results file.</summary>
    public sealed class ScanResult
    {
        /// <summary>Nmap's version.</summary>
        public string NmapVersion { get; set; } = string.Empty;
        /// <summary>The command Nmap was run with.</summary>
        public string Args { get; set; } = string.Empty;
        /// <summary>When the scan started.</summary>
        public DateTime Started { get; set; }
        /// <summary>When it finished.</summary>
        public DateTime Finished { get; set; }
        /// <summary>How long it took, in seconds.</summary>
        public double ElapsedSeconds { get; set; }
        /// <summary>How many devices answered.</summary>
        public int HostsUp { get; set; }
        /// <summary>How many didn't.</summary>
        public int HostsDown { get; set; }
        /// <summary>How many were looked at.</summary>
        public int HostsTotal { get; set; }
        /// <summary>Nmap's own summary line.</summary>
        public string Summary { get; set; } = string.Empty;
        /// <summary>True when the scan finished (not stopped part way).</summary>
        public bool Completed { get; set; }
        /// <summary>Nmap's error, when it had one.</summary>
        public string ErrorMessage { get; set; }
        /// <summary>Every device looked at.</summary>
        public List<HostInfo> Hosts { get; } = new List<HostInfo>();

        /// <summary>The devices that answered.</summary>
        public IEnumerable<HostInfo> UpHosts => Hosts.Where(h => h.IsUp);

        /// <summary>How many ports are open on all the devices together.</summary>
        public int OpenPortCount => UpHosts.Sum(h => h.OpenPorts.Count());

        /// <summary>The known problems found by the scripts.</summary>
        public List<Vulnerability> Vulnerabilities => VulnerabilityFinder.Find(this);
    }

    public sealed class HostInfo
    {
        /// <summary>"up" when the device answered, else "down" or "unknown".</summary>
        public string State { get; set; } = "unknown";
        /// <summary>Its IPv4 address.</summary>
        public string Ipv4 { get; set; }
        /// <summary>Its IPv6 address.</summary>
        public string Ipv6 { get; set; }
        /// <summary>Its network card's MAC address (only for devices on the same network).</summary>
        public string Mac { get; set; }
        /// <summary>Who made the network card, from the MAC address.</summary>
        public string Vendor { get; set; }
        /// <summary>Its names.</summary>
        public List<string> Hostnames { get; } = new List<string>();
        /// <summary>Nmap's guesses at its operating system, best first.</summary>
        public List<OsMatch> OsMatches { get; } = new List<OsMatch>();
        /// <summary>Its ports that were looked at.</summary>
        public List<PortInfo> Ports { get; } = new List<PortInfo>();
        /// <summary>Scripts run on the device as a whole.</summary>
        public List<ScriptResult> Scripts { get; } = new List<ScriptResult>();
        /// <summary>The route to it, a hop at a time.</summary>
        public List<TraceHop> Trace { get; } = new List<TraceHop>();

        /// <summary>Smoothed round-trip time in microseconds, or 0 when unknown.</summary>
        public long LatencyMicroseconds { get; set; }
        /// <summary>How many hops away it is.</summary>
        public int Distance { get; set; }

        /// <summary>True when it answered.</summary>
        public bool IsUp => string.Equals(State, "up", StringComparison.OrdinalIgnoreCase);
        /// <summary>Its best address: IPv4, else IPv6, else MAC.</summary>
        public string Address => Ipv4 ?? Ipv6 ?? Mac ?? string.Empty;
        /// <summary>Its first name, or empty.</summary>
        public string Name => Hostnames.FirstOrDefault() ?? string.Empty;
        /// <summary>Its name, or its address when it has none.</summary>
        public string DisplayName => string.IsNullOrEmpty(Name) ? Address : Name;
        /// <summary>Its open ports.</summary>
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

        /// <summary>How quickly it answers, like "1.2 ms".</summary>
        public string LatencyText => LatencyMicroseconds <= 0
            ? string.Empty
            : LatencyMicroseconds < 1000 ? $"{LatencyMicroseconds / 1000.0:0.0} ms" : $"{LatencyMicroseconds / 1000.0:0} ms";
    }

    public sealed class OsMatch
    {
        /// <summary>The operating system's name.</summary>
        public string Name { get; set; }
        /// <summary>How sure Nmap is, in percent.</summary>
        public int Accuracy { get; set; }
    }

    public sealed class TraceHop
    {
        /// <summary>How many hops away.</summary>
        public int Ttl { get; set; }
        /// <summary>The hop's address.</summary>
        public string Address { get; set; }
        /// <summary>The hop's name.</summary>
        public string Host { get; set; }
        /// <summary>How long it took to answer.</summary>
        public string Rtt { get; set; }
    }

    public sealed class PortInfo
    {
        /// <summary>"tcp" or "udp".</summary>
        public string Protocol { get; set; } = "tcp";
        /// <summary>The port's number.</summary>
        public int Number { get; set; }
        /// <summary>"open", "closed", "filtered"...</summary>
        public string State { get; set; } = string.Empty;
        /// <summary>Why Nmap thinks so.</summary>
        public string Reason { get; set; } = string.Empty;
        /// <summary>The service's name, like "http".</summary>
        public string Service { get; set; } = string.Empty;
        /// <summary>The program answering, like "nginx".</summary>
        public string Product { get; set; } = string.Empty;
        /// <summary>Its version.</summary>
        public string Version { get; set; } = string.Empty;
        /// <summary>More details Nmap found.</summary>
        public string ExtraInfo { get; set; } = string.Empty;
        /// <summary>"ssl" when the service is behind encryption.</summary>
        public string Tunnel { get; set; } = string.Empty;
        /// <summary>The operating system the service says it runs on.</summary>
        public string OsType { get; set; } = string.Empty;
        /// <summary>Scripts run on this port.</summary>
        public List<ScriptResult> Scripts { get; } = new List<ScriptResult>();

        /// <summary>True when the port is open (also "open|filtered").</summary>
        public bool IsOpen => State.StartsWith("open", StringComparison.OrdinalIgnoreCase);
        /// <summary>The port as "443/tcp".</summary>
        public string Key => Number + "/" + Protocol;

        /// <summary>The service in words (with "ssl/" when encrypted).</summary>
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

        /// <summary>True when it's a web page with encryption (https).</summary>
        public bool IsHttps => Tunnel == "ssl" || Service.Equals("https", StringComparison.OrdinalIgnoreCase) || Number == 443 || Number == 8443;
    }

    public sealed class ScriptResult
    {
        /// <summary>The script's name.</summary>
        public string Id { get; set; }
        /// <summary>What it found, as text.</summary>
        public string Output { get; set; }

        /// <summary>The structured &lt;table&gt;/&lt;elem&gt; output, when the script provides it.</summary>
        public XElement Element { get; set; }
    }
}
