using System;
using System.Collections.Generic;
using System.Linq;

namespace Kudunmap.Core
{
    public enum ChangeKind { NewHost, HostGone, PortOpened, PortClosed, VersionChanged, Unchanged }

    public sealed class Change
    {
        public ChangeKind Kind { get; set; }
        public string Address { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;

        public string KindText
        {
            get
            {
                switch (Kind)
                {
                    case ChangeKind.NewHost: return "New host";
                    case ChangeKind.HostGone: return "Host gone";
                    case ChangeKind.PortOpened: return "Port opened";
                    case ChangeKind.PortClosed: return "Port closed";
                    case ChangeKind.VersionChanged: return "Version changed";
                    default: return "Unchanged";
                }
            }
        }
    }

    /// <summary>Finds what changed between an older and a newer scan.</summary>
    public static class ScanComparer
    {
        public static List<Change> Compare(ScanResult older, ScanResult newer, bool includeUnchanged = false)
        {
            var changes = new List<Change>();
            var before = older.UpHosts.GroupBy(h => h.Address).ToDictionary(g => g.Key, g => g.First());
            var after = newer.UpHosts.GroupBy(h => h.Address).ToDictionary(g => g.Key, g => g.First());

            foreach (var address in before.Keys.Union(after.Keys).OrderBy(a => a, new AddressComparer()))
            {
                before.TryGetValue(address, out var b);
                after.TryGetValue(address, out var a);
                var name = (a ?? b).Name;

                if (b == null)
                {
                    var ports = a.OpenPorts.Select(p => p.Number.ToString()).ToList();
                    changes.Add(new Change
                    {
                        Kind = ChangeKind.NewHost, Address = address, Name = name,
                        Details = ports.Count == 0 ? "Appeared · no open ports" : "Appeared · open ports " + string.Join(", ", ports)
                    });
                    continue;
                }
                if (a == null)
                {
                    changes.Add(new Change { Kind = ChangeKind.HostGone, Address = address, Name = name, Details = "Did not reply in the newer scan" });
                    continue;
                }

                var oldPorts = b.OpenPorts.GroupBy(p => p.Key).ToDictionary(g => g.Key, g => g.First());
                var newPorts = a.OpenPorts.GroupBy(p => p.Key).ToDictionary(g => g.Key, g => g.First());
                var hostChanged = false;

                foreach (var key in oldPorts.Keys.Union(newPorts.Keys).OrderBy(k => k, new PortKeyComparer()))
                {
                    oldPorts.TryGetValue(key, out var op);
                    newPorts.TryGetValue(key, out var np);
                    if (op == null)
                    {
                        changes.Add(new Change { Kind = ChangeKind.PortOpened, Address = address, Name = name, Details = Describe(np) });
                        hostChanged = true;
                    }
                    else if (np == null)
                    {
                        changes.Add(new Change { Kind = ChangeKind.PortClosed, Address = address, Name = name, Details = Describe(op) });
                        hostChanged = true;
                    }
                    else if (!string.IsNullOrEmpty(op.VersionText) && !string.IsNullOrEmpty(np.VersionText) &&
                             !string.Equals(Short(op), Short(np), StringComparison.Ordinal))
                    {
                        changes.Add(new Change
                        {
                            Kind = ChangeKind.VersionChanged, Address = address, Name = name,
                            Details = $"{key}  {Short(op)} → {Short(np)}"
                        });
                        hostChanged = true;
                    }
                }

                if (!hostChanged && includeUnchanged)
                {
                    changes.Add(new Change
                    {
                        Kind = ChangeKind.Unchanged, Address = address, Name = name,
                        Details = newPorts.Count == 0 ? "No open ports" : "Open ports " + string.Join(", ", newPorts.Values.Select(p => p.Number))
                    });
                }
            }
            return changes;
        }

        private static string Describe(PortInfo p)
        {
            var what = string.IsNullOrEmpty(p.VersionText) ? p.ServiceText : $"{p.ServiceText} ({p.VersionText})";
            return $"{p.Key}  {what}".TrimEnd();
        }

        private static string Short(PortInfo p) => string.Join(" ", new[] { p.Product, p.Version }.Where(s => !string.IsNullOrEmpty(s)));

        private sealed class PortKeyComparer : IComparer<string>
        {
            public int Compare(string x, string y)
            {
                int Num(string k) => int.TryParse(k.Split('/')[0], out var n) ? n : 0;
                var c = Num(x).CompareTo(Num(y));
                return c != 0 ? c : string.CompareOrdinal(x, y);
            }
        }
    }
}
