using System;
using System.Collections.Generic;
using System.Linq;

namespace Kudunmap.Core
{
    /// <summary>What a device on the map probably is.</summary>
    public enum DeviceKind { ThisPc, Router, Computer, Server, Phone, Printer, Tv, Camera, Storage, SmartHome, NetworkDevice, Unknown }

    /// <summary>One device on the map: what it is, where it's drawn, and how its open ports look.</summary>
    public sealed class MapDevice
    {
        public HostInfo Host { get; set; }
        public DeviceKind Kind { get; set; }
        public string Label { get; set; }
        public double X { get; set; }
        public double Y { get; set; }
        public int Risky { get; set; }
        public int WorthALook { get; set; }
        public int Open { get; set; }

        public string KindText => NetworkMap.KindName(Kind);
    }

    /// <summary>
    /// A drawing of the network: this PC and the router in the middle, and every device found around them, each with a
    /// guess of what it is (from its maker, its operating system, its name and what it answers on).
    /// </summary>
    public static class NetworkMap
    {
        public static string KindName(DeviceKind k)
        {
            switch (k)
            {
                case DeviceKind.ThisPc: return "This PC";
                case DeviceKind.Router: return "Router";
                case DeviceKind.Computer: return "Computer";
                case DeviceKind.Server: return "Server";
                case DeviceKind.Phone: return "Phone or tablet";
                case DeviceKind.Printer: return "Printer";
                case DeviceKind.Tv: return "TV or media player";
                case DeviceKind.Camera: return "Camera";
                case DeviceKind.Storage: return "Storage (NAS)";
                case DeviceKind.SmartHome: return "Smart-home device";
                case DeviceKind.NetworkDevice: return "Network device";
                default: return "Device";
            }
        }

        private static bool Has(string text, params string[] words) =>
            !string.IsNullOrEmpty(text) && words.Any(w => text.IndexOf(w, StringComparison.OrdinalIgnoreCase) >= 0);

        /// <summary>
        /// What a device probably is. <paramref name="ownAddresses"/> are this PC's addresses; <paramref name="gateways"/>
        /// the router's (this PC's default gateways).
        /// </summary>
        public static DeviceKind Guess(HostInfo h, ICollection<string> ownAddresses, ICollection<string> gateways)
        {
            if (h.Ipv4 != null && ownAddresses != null && ownAddresses.Contains(h.Ipv4)) return DeviceKind.ThisPc;
            if (h.Ipv4 != null && gateways != null && gateways.Contains(h.Ipv4)) return DeviceKind.Router;
            var ports = new HashSet<int>(h.OpenPorts.Select(p => p.Number));
            var services = string.Join(" ", h.OpenPorts.Select(p => p.Service + " " + p.Product + " " + p.OsType));
            var os = h.OsGuess ?? string.Empty;
            var vendor = h.Vendor ?? string.Empty;
            var name = h.Name ?? string.Empty;
            var all = vendor + " " + os + " " + name + " " + services;

            if (ports.Contains(9100) || ports.Contains(631) || ports.Contains(515) || Has(all, "printer", "laserjet", "officejet", "deskjet", "epson", "brother", "canon", "kyocera", "xerox", "ricoh", "lexmark"))
                return DeviceKind.Printer;
            if (ports.Contains(554) || ports.Contains(37777) || Has(all, "hikvision", "dahua", "axis comm", "reolink", "amcrest", "camera", "ipcam", "foscam", "ring "))
                return DeviceKind.Camera;
            if (Has(all, "synology", "qnap", "netgear readynas", "western digital", "wd my cloud", "truenas", "freenas", "nas"))
                return DeviceKind.Storage;
            if (ports.Contains(8008) || ports.Contains(8009) || ports.Contains(32400) || Has(all, "chromecast", "roku", "samsung tv", "lg tv", "smart tv", "bravia", "apple tv", "fire tv", "amazon fire", "sonos", "nvidia shield", "vizio", "tizen", "webos", "android tv"))
                return DeviceKind.Tv;
            if (Has(all, "iphone", "ipad", "android", "pixel", "galaxy", "oneplus", "xiaomi", "huawei", "oppo", "vivo", "motorola", "mobile"))
                return DeviceKind.Phone;
            if (ports.Contains(1883) || Has(all, "espressif", "tuya", "shelly", "philips lighting", "hue", "nest", "ecobee", "tp-link smart", "kasa", "amazon echo", "google home", "sonoff"))
                return DeviceKind.SmartHome;
            if (Has(all, "routeros", "mikrotik", "ubiquiti", "unifi", "cisco", "juniper", "aruba", "netgear", "tp-link", "d-link", "zyxel", "asus router", "fritz", "avm", "switch", "access point", "openwrt"))
                return DeviceKind.NetworkDevice;
            if (Has(os, "windows server") || ports.Contains(88) || ports.Contains(389) || ports.Contains(1433) || ports.Contains(3306) || ports.Contains(5432) || ports.Contains(25))
                return DeviceKind.Server;
            if (Has(all, "windows", "microsoft", "mac os", "macos", "apple", "linux", "ubuntu", "debian", "dell", "lenovo", "hewlett", "intel corporate", "asustek", "micro-star", "gigabyte")
                || ports.Contains(445) || ports.Contains(3389) || ports.Contains(22) || ports.Contains(5900))
                return DeviceKind.Computer;
            return DeviceKind.Unknown;
        }

        /// <summary>
        /// The map of a scan: the router (or this PC) in the middle, and the rest on rings around it, grouped by kind, in a
        /// drawing <paramref name="size"/> wide and high.
        /// </summary>
        public static List<MapDevice> Build(ScanResult result, ICollection<string> ownAddresses, ICollection<string> gateways, double size = 1000)
        {
            var devices = result.UpHosts.Select(h =>
            {
                var notes = h.OpenPorts.Select(PortNotes.For).ToList();
                return new MapDevice
                {
                    Host = h,
                    Kind = Guess(h, ownAddresses, gateways),
                    Label = string.IsNullOrEmpty(h.Name) ? h.Address : ShortName(h.Name),
                    Open = notes.Count,
                    Risky = notes.Count(n => n.Level == PortLevel.Risky),
                    WorthALook = notes.Count(n => n.Level == PortLevel.WorthALook)
                };
            }).ToList();

            var center = size / 2;
            var hub = devices.FirstOrDefault(d => d.Kind == DeviceKind.Router) ?? devices.FirstOrDefault(d => d.Kind == DeviceKind.ThisPc);
            var others = devices.Where(d => d != hub)
                .OrderBy(d => d.Kind == DeviceKind.ThisPc ? -1 : (int)d.Kind)
                .ThenBy(d => AddressKey(d.Host.Address))
                .ToList();
            if (hub != null)
            {
                hub.X = center;
                hub.Y = center;
            }
            // Rings: up to 10 on the first, 16 on the second, 22 on the third...
            var index = 0;
            for (var ring = 1; index < others.Count; ring++)
            {
                var capacity = 4 + 6 * ring;
                var count = Math.Min(capacity, others.Count - index);
                var radius = size * 0.42 * ring / Math.Max(1, Rings(others.Count));
                for (var i = 0; i < count; i++)
                {
                    var angle = -Math.PI / 2 + 2 * Math.PI * i / count + (ring % 2 == 0 ? Math.PI / count : 0);
                    others[index + i].X = center + radius * Math.Cos(angle);
                    others[index + i].Y = center + radius * Math.Sin(angle);
                }
                index += count;
            }
            return devices;
        }

        /// <summary>How many rings <paramref name="count"/> devices need.</summary>
        public static int Rings(int count)
        {
            var rings = 0;
            for (var placed = 0; placed < count; rings++) placed += 4 + 6 * (rings + 1);
            return rings;
        }

        private static string ShortName(string name)
        {
            var dot = name.IndexOf('.');
            var s = dot > 0 ? name.Substring(0, dot) : name;
            return s.Length > 22 ? s.Substring(0, 21) + "…" : s;
        }

        /// <summary>Sorts 192.168.1.9 before 192.168.1.10.</summary>
        private static string AddressKey(string address)
        {
            var parts = (address ?? string.Empty).Split('.');
            return parts.Length == 4 && parts.All(p => int.TryParse(p, out _)) ? string.Concat(parts.Select(p => p.PadLeft(3, '0'))) : address ?? string.Empty;
        }
    }
}
