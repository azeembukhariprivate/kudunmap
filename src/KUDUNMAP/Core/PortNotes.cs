using System;
using System.Collections.Generic;
using System.Linq;

namespace Kudunmap.Core
{
    /// <summary>How much an open port matters.</summary>
    public enum PortLevel
    {
        /// <summary>Normal for this kind of device.</summary>
        Fine,

        /// <summary>Usually fine, but check it's meant to be open.</summary>
        WorthALook,

        /// <summary>Often abused: close it unless you need it, and never leave it open to the internet.</summary>
        Risky
    }

    /// <summary>What an open port is, in plain words, and what it could risk.</summary>
    public sealed class PortNote
    {
        public PortLevel Level { get; set; }
        /// <summary>What it is, like "Remote Desktop".</summary>
        public string What { get; set; }
        /// <summary>What it means for you, in a sentence or two.</summary>
        public string Text { get; set; }

        public string LevelText => Level == PortLevel.Risky ? "Risky" : Level == PortLevel.WorthALook ? "Worth a look" : "Fine";
    }

    /// <summary>One open port that's worth knowing about, with the device it's on.</summary>
    public sealed class PortFinding
    {
        public HostInfo Host { get; set; }
        public PortInfo Port { get; set; }
        public PortNote Note { get; set; }
    }

    /// <summary>
    /// Plain-words notes for open ports: what each is and what it could risk. Known ports are matched by number (and by
    /// the service Nmap found, for ones moved to another number); others get a general note.
    /// </summary>
    public static class PortNotes
    {
        private static PortNote N(PortLevel level, string what, string text) => new PortNote { Level = level, What = what, Text = text };

        private const string CloseIt = " Close it if you don't use it, and never let it be reached from the internet.";

        // Numbers for TCP (and both, where the service is the same).
        private static readonly Dictionary<int, PortNote> Tcp = new Dictionary<int, PortNote>
        {
            [20] = N(PortLevel.Risky, "FTP (file transfer, data)", "Old file sharing that sends names, passwords and files without any protection." + CloseIt),
            [21] = N(PortLevel.Risky, "FTP (file transfer)", "Old file sharing that sends names and passwords without any protection, so anyone on the network can read them." + CloseIt),
            [22] = N(PortLevel.WorthALook, "SSH (remote command line)", "Lets someone control this device by typing commands, after signing in. Safe with strong passwords or keys; often attacked if it can be reached from the internet."),
            [23] = N(PortLevel.Risky, "Telnet (old remote command line)", "Lets someone control this device with no protection at all: everything, passwords included, can be read on the network. Common on old routers and cameras." + CloseIt),
            [25] = N(PortLevel.WorthALook, "Email sending (SMTP)", "A mail server. Expected on a mail server; anywhere else, check what it is."),
            [53] = N(PortLevel.Fine, "Name lookup (DNS)", "Turns names like example.com into addresses. Normal on routers and DNS servers."),
            [67] = N(PortLevel.Fine, "Address handout (DHCP)", "Gives devices their network address. Normal on routers."),
            [69] = N(PortLevel.Risky, "TFTP (simple file transfer)", "Hands out files to anyone who asks, with no password. Used to set up phones and network devices." + CloseIt),
            [80] = N(PortLevel.Fine, "Web page (HTTP)", "A web page, often a device's settings page. Pages are sent without protection, so don't type passwords on it over Wi-Fi you don't trust."),
            [88] = N(PortLevel.Fine, "Windows domain sign-in (Kerberos)", "Normal on a company's domain controller."),
            [110] = N(PortLevel.WorthALook, "Email collection (POP3)", "Collects email; without protection, passwords can be read on the network."),
            [111] = N(PortLevel.WorthALook, "RPC port mapper", "Used by Linux and storage devices for file sharing (NFS). Often abused if it can be reached from the internet."),
            [123] = N(PortLevel.Fine, "Time (NTP)", "Keeps clocks right. Normal on routers and servers."),
            [135] = N(PortLevel.WorthALook, "Windows remote calls (RPC)", "Windows uses it to talk to other Windows PCs. Normal inside a home or office network; it should never be reachable from the internet."),
            [137] = N(PortLevel.WorthALook, "Windows names (NetBIOS)", "Old Windows name sharing. Normal on older networks; it should never be reachable from the internet."),
            [139] = N(PortLevel.WorthALook, "Windows file sharing (old)", "Shares files and printers the old Windows way. Fine at home if you share files on purpose; never from the internet."),
            [143] = N(PortLevel.WorthALook, "Email reading (IMAP)", "Reads email on a mail server; without protection, passwords can be read on the network."),
            [161] = N(PortLevel.WorthALook, "Device monitoring (SNMP)", "Lets other devices read this one's details. Old versions use a shared word like \"public\" instead of a password; check it's changed."),
            [389] = N(PortLevel.WorthALook, "Directory (LDAP)", "Company address books and sign-in. Normal on a domain controller; not expected elsewhere."),
            [443] = N(PortLevel.Fine, "Secure web page (HTTPS)", "A web page with protection, often a device's settings page."),
            [445] = N(PortLevel.WorthALook, "Windows file sharing (SMB)", "Shares files and printers between Windows PCs. Fine at home if you share files on purpose. It's been behind some of the worst attacks, so keep Windows up to date and never let it be reached from the internet."),
            [465] = N(PortLevel.Fine, "Secure email sending", "Sends email with protection. Normal on a mail server."),
            [515] = N(PortLevel.Fine, "Printing (LPD)", "Old printing. Normal on printers."),
            [548] = N(PortLevel.WorthALook, "Mac file sharing (AFP)", "Shares files the old Mac way. Fine if you share files on purpose."),
            [554] = N(PortLevel.WorthALook, "Video stream (RTSP)", "Streams video, usually from a camera. Check the camera has a password and its own, not the one it came with."),
            [587] = N(PortLevel.Fine, "Email sending", "Sends email after signing in. Normal on a mail server."),
            [631] = N(PortLevel.Fine, "Printing (IPP)", "Normal on printers and PCs that share a printer."),
            [636] = N(PortLevel.Fine, "Secure directory (LDAPS)", "Company address books with protection. Normal on a domain controller."),
            [873] = N(PortLevel.WorthALook, "File copying (rsync)", "Copies files between devices; some set-ups need no password. Check it's meant to be on."),
            [993] = N(PortLevel.Fine, "Secure email reading (IMAPS)", "Reads email with protection. Normal on a mail server."),
            [995] = N(PortLevel.Fine, "Secure email collection (POP3S)", "Collects email with protection. Normal on a mail server."),
            [1433] = N(PortLevel.Risky, "Microsoft SQL Server (database)", "A database that answers on the network. Databases are a top target: keep it to the computers that need it." + CloseIt),
            [1521] = N(PortLevel.Risky, "Oracle database", "A database that answers on the network." + CloseIt),
            [1723] = N(PortLevel.Risky, "PPTP (old VPN)", "An old VPN with known weaknesses. Use a newer VPN instead."),
            [1883] = N(PortLevel.WorthALook, "Smart-home messages (MQTT)", "Smart-home and sensor devices talk through it; often without a password. Check it needs one."),
            [1900] = N(PortLevel.WorthALook, "Device discovery (UPnP)", "Lets devices find each other, and lets programs open ports on the router by themselves. Turn UPnP off on the router if you don't need it."),
            [2049] = N(PortLevel.WorthALook, "NFS file sharing", "Linux and storage-device file sharing. Check which folders it shares and with whom."),
            [3306] = N(PortLevel.Risky, "MySQL / MariaDB (database)", "A database that answers on the network." + CloseIt),
            [3389] = N(PortLevel.Risky, "Remote Desktop", "Lets someone sign in and use this PC from another one. It's one of the most attacked doors on the internet: use a strong password, turn it off if you don't use it, and never let it be reached from the internet."),
            [5000] = N(PortLevel.WorthALook, "Web service (often a NAS or developer tool)", "Often a storage device's settings page or a program being written. Check what it is."),
            [5060] = N(PortLevel.WorthALook, "Internet phone (SIP)", "Phone calls over the network. Normal on phone boxes and routers with phone sockets; often attacked from the internet."),
            [5353] = N(PortLevel.Fine, "Device discovery (Bonjour)", "Lets devices find printers and speakers. Normal at home."),
            [5432] = N(PortLevel.Risky, "PostgreSQL (database)", "A database that answers on the network." + CloseIt),
            [5900] = N(PortLevel.Risky, "VNC (remote screen)", "Lets someone see and control this screen. Often set up without a password or with a weak one." + CloseIt),
            [5985] = N(PortLevel.WorthALook, "Windows remote management", "Lets administrators run commands on this PC. Normal in companies; not expected at home."),
            [6379] = N(PortLevel.Risky, "Redis (data store)", "A data store that often has no password at all." + CloseIt),
            [7547] = N(PortLevel.Risky, "Router remote management (TR-069)", "Lets an internet provider manage the router. Weak versions have been used to take routers over; it should only be reachable by your provider."),
            [8000] = N(PortLevel.WorthALook, "Web service", "Often a camera, recorder or a program being written. Check what it is and that it has its own password."),
            [8080] = N(PortLevel.WorthALook, "Web service (alternative)", "Often a settings page, a proxy or a program being written. Check what it is."),
            [8443] = N(PortLevel.Fine, "Secure web service (alternative)", "A web page with protection on another number, often a settings page."),
            [9100] = N(PortLevel.WorthALook, "Printing (raw)", "Anyone on the network can send pages straight to this printer. Normal for printers; never from the internet."),
            [9200] = N(PortLevel.Risky, "Elasticsearch (search database)", "A search database that often has no password." + CloseIt),
            [11211] = N(PortLevel.Risky, "Memcached", "A memory cache with no password, abused for attacks." + CloseIt),
            [27017] = N(PortLevel.Risky, "MongoDB (database)", "A database that often has no password." + CloseIt),
            [32400] = N(PortLevel.Fine, "Plex media server", "Shares films and music. Fine if you use Plex."),
            [37777] = N(PortLevel.Risky, "Camera recorder (Dahua)", "A security-camera recorder; old ones have known weaknesses. Keep it updated and never let it be reached from the internet."),
            [49152] = N(PortLevel.Fine, "Windows (changing numbers)", "Windows and other systems use numbers from here up for their own services. Normal on Windows PCs."),
        };

        // Services that run on any number, matched by the name Nmap reports.
        private static readonly Dictionary<string, int> ByService = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["ftp"] = 21, ["ssh"] = 22, ["telnet"] = 23, ["ms-wbt-server"] = 3389, ["vnc"] = 5900, ["mysql"] = 3306, ["postgresql"] = 5432,
            ["ms-sql-s"] = 1433, ["redis"] = 6379, ["mongodb"] = 27017, ["microsoft-ds"] = 445, ["netbios-ssn"] = 139, ["rtsp"] = 554,
            ["mqtt"] = 1883, ["upnp"] = 1900, ["snmp"] = 161, ["tftp"] = 69, ["memcache"] = 11211, ["elasticsearch"] = 9200, ["pptp"] = 1723
        };

        /// <summary>The note for an open port.</summary>
        public static PortNote For(PortInfo port)
        {
            if (port == null) return null;
            var udp = string.Equals(port.Protocol, "udp", StringComparison.OrdinalIgnoreCase);
            // Moved to another number: the service Nmap found decides.
            if (!string.IsNullOrEmpty(port.Service) && ByService.TryGetValue(port.Service, out var number) && number != port.Number && Tcp.TryGetValue(number, out var moved))
                return N(moved.Level, moved.What + " on port " + port.Number, moved.Text);
            if (Tcp.TryGetValue(port.Number, out var note)) return note;
            if (port.Number >= 49152 && port.Number <= 49800 && !udp) return Tcp[49152];
            if (port.LooksLikeWeb)
                return port.IsHttps
                    ? N(PortLevel.Fine, "Secure web service", "A web page with protection, often a device's settings page.")
                    : N(PortLevel.WorthALook, "Web service", "A web page, often a device's settings page or a program's. Check what it is and that it has its own password.");
            return N(PortLevel.WorthALook, string.IsNullOrEmpty(port.Service) ? "Unknown service" : "\"" + port.Service + "\"",
                "Something on this device answers here. If you don't know what it is, find out (the version Nmap found may help), and close it if it isn't needed.");
        }

        /// <summary>The open ports that are risky or worth a look, riskiest first.</summary>
        public static List<PortFinding> WorthALook(ScanResult result) =>
            result.UpHosts.SelectMany(h => h.OpenPorts.Select(p => new PortFinding { Host = h, Port = p, Note = For(p) }))
                .Where(f => f.Note.Level != PortLevel.Fine)
                .OrderByDescending(f => f.Note.Level).ThenBy(f => f.Host.Address, StringComparer.Ordinal).ThenBy(f => f.Port.Number)
                .ToList();
    }
}
