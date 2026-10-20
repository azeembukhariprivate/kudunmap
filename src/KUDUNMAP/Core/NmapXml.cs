using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Xml;
using System.Xml.Linq;

namespace Kudunmap.Core
{
    /// <summary>Reads Nmap's XML output (-oX). Only the results file is read, never Nmap's own data files.</summary>
    public static class NmapXml
    {
        public static ScanResult Load(string path)
        {
            using (var stream = File.OpenRead(path)) return Load(stream);
        }

        public static ScanResult Parse(string xml)
        {
            using (var reader = new StringReader(xml)) return Load(XmlReader.Create(reader, ReaderSettings));
        }

        public static ScanResult Load(Stream stream) => Load(XmlReader.Create(stream, ReaderSettings));

        // Nmap writes a DOCTYPE line; ignore it and never fetch anything external.
        private static XmlReaderSettings ReaderSettings => new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Ignore,
            XmlResolver = null,
            IgnoreComments = true
        };

        private static ScanResult Load(XmlReader reader)
        {
            XDocument doc;
            using (reader) doc = XDocument.Load(reader);

            var root = doc.Root;
            if (root == null || root.Name.LocalName != "nmaprun")
                throw new InvalidDataException("This isn't an Nmap results file.");

            var result = new ScanResult
            {
                NmapVersion = Attr(root, "version"),
                Args = Attr(root, "args"),
                Started = FromUnix(Attr(root, "start"))
            };

            foreach (var h in root.Elements("host")) result.Hosts.Add(ParseHost(h));

            var finished = root.Element("runstats")?.Element("finished");
            var hosts = root.Element("runstats")?.Element("hosts");
            if (finished != null)
            {
                result.Completed = Attr(finished, "exit") != "error";
                result.Finished = FromUnix(Attr(finished, "time"));
                result.ElapsedSeconds = Double(Attr(finished, "elapsed"));
                result.Summary = Attr(finished, "summary");
                if (!result.Completed) result.ErrorMessage = Attr(finished, "errormsg");
            }
            if (hosts != null)
            {
                result.HostsUp = Int(Attr(hosts, "up"));
                result.HostsDown = Int(Attr(hosts, "down"));
                result.HostsTotal = Int(Attr(hosts, "total"));
            }
            else
            {
                result.HostsUp = result.Hosts.Count(x => x.IsUp);
                result.HostsTotal = result.Hosts.Count;
            }
            return result;
        }

        private static HostInfo ParseHost(XElement h)
        {
            var host = new HostInfo { State = Attr(h.Element("status"), "state", "unknown") };

            foreach (var a in h.Elements("address"))
            {
                switch (Attr(a, "addrtype"))
                {
                    case "ipv4": host.Ipv4 = Attr(a, "addr"); break;
                    case "ipv6": host.Ipv6 = Attr(a, "addr"); break;
                    case "mac":
                        host.Mac = Attr(a, "addr");
                        host.Vendor = Attr(a, "vendor");
                        break;
                }
            }

            foreach (var n in h.Element("hostnames")?.Elements("hostname") ?? Enumerable.Empty<XElement>())
            {
                var name = Attr(n, "name");
                if (name.Length > 0 && !host.Hostnames.Contains(name)) host.Hostnames.Add(name);
            }

            foreach (var p in h.Element("ports")?.Elements("port") ?? Enumerable.Empty<XElement>())
            {
                var state = p.Element("state");
                var svc = p.Element("service");
                var port = new PortInfo
                {
                    Protocol = Attr(p, "protocol", "tcp"),
                    Number = Int(Attr(p, "portid")),
                    State = Attr(state, "state"),
                    Reason = Attr(state, "reason"),
                    Service = Attr(svc, "name"),
                    Product = Attr(svc, "product"),
                    Version = Attr(svc, "version"),
                    ExtraInfo = Attr(svc, "extrainfo"),
                    Tunnel = Attr(svc, "tunnel"),
                    OsType = Attr(svc, "ostype")
                };
                foreach (var s in p.Elements("script")) port.Scripts.Add(ParseScript(s));
                host.Ports.Add(port);
            }

            foreach (var m in h.Element("os")?.Elements("osmatch") ?? Enumerable.Empty<XElement>())
                host.OsMatches.Add(new OsMatch { Name = Attr(m, "name"), Accuracy = Int(Attr(m, "accuracy")) });

            foreach (var s in h.Element("hostscript")?.Elements("script") ?? Enumerable.Empty<XElement>())
                host.Scripts.Add(ParseScript(s));

            foreach (var hop in h.Element("trace")?.Elements("hop") ?? Enumerable.Empty<XElement>())
            {
                host.Trace.Add(new TraceHop
                {
                    Ttl = Int(Attr(hop, "ttl")),
                    Address = Attr(hop, "ipaddr"),
                    Host = Attr(hop, "host"),
                    Rtt = Attr(hop, "rtt")
                });
            }

            host.LatencyMicroseconds = (long)Double(Attr(h.Element("times"), "srtt"));
            host.Distance = Int(Attr(h.Element("distance"), "value"));
            return host;
        }

        private static ScriptResult ParseScript(XElement s) => new ScriptResult
        {
            Id = Attr(s, "id"),
            Output = (Attr(s, "output") ?? string.Empty).Trim('\r', '\n'),
            Element = s
        };

        private static string Attr(XElement e, string name, string fallback = "") =>
            (string)e?.Attribute(name) ?? fallback;

        private static int Int(string s) => int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;

        private static double Double(string s) =>
            double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : 0;

        private static DateTime FromUnix(string s) =>
            long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) && v > 0
                ? new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(v).ToLocalTime()
                : DateTime.MinValue;
    }
}
