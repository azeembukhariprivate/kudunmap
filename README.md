<p align="center">
  <img src="docs/logo-512.png" alt="KUDUNMAP logo" width="128">
</p>

<h1 align="center">KUDUNMAP</h1>

<p align="center">A visual front-end for Nmap on Windows. Scan your network without typing or remembering commands.</p>

---

## Features

- **Nine ready-made scans**, each with a plain-English description: Quick scan, Ping sweep, Common ports, All ports, Services & versions, OS detection, Intense, UDP scan and Vulnerability check.
- **Options as buttons and tick-boxes**: what to scan (TCP, UDP or hosts only), speed (Paranoid to Insane), ports, skip ping, name lookup, version and OS detection, traceroute, and Nmap script categories.
- **Live command preview**: the real `nmap` command updates as you click, with each part explained. Copy it to run it yourself.
- **Live progress**: progress bar, the step Nmap is on, time left, and open ports as they're found.
- **Clear results**: hosts with their name, operating system guess and MAC vendor; ports with service and version; script output; route.
- **Vulnerability check**: runs Nmap's `vuln` scripts and shows findings by severity with CVE links. Optionally looks up known CVEs for the detected versions (vulners, off by default).
- **History and Compare**: every scan is saved on your computer. Compare two scans to see new hosts, hosts that disappeared, ports that opened or closed, and changed versions.
- **My presets**: save your own options and target, and repeat a scan with one click.
- **Export**: HTML report, CSV (hosts and ports, or vulnerabilities), Nmap XML and text output.
- **Right-click actions**: copy, open in a browser, ping, or scan just that host.
- **Windows notification** when a long scan finishes.
- **Light and dark mode**, following your Windows setting.

## You need Nmap

KUDUNMAP is the window, Nmap does the scanning. **Nmap is not included.** Install it for free from the Nmap Project:

1. Go to [nmap.org/download.html](https://nmap.org/download.html#windows) and download the *Latest stable release self-installer* for Windows.
2. Run it and keep the **Npcap** option ticked.
3. Start KUDUNMAP. It finds Nmap automatically (or choose `nmap.exe` in Settings).

## Download

Get the latest version from the [Releases page](https://github.com/azeembukhariprivate/kudunmap/releases/latest):

- `KUDUNMAP-x.y.z-setup.exe`: installs for your user account and adds a Start menu entry.
- `KUDUNMAP-x.y.z-portable.zip`: unzip anywhere and run `KUDUNMAP.exe`. Nothing is installed.

Requires Windows 10 or 11. The .NET Framework 4.8 it uses is already part of Windows.

Windows SmartScreen may warn about a new app from an unknown publisher. Choose **More info → Run anyway**.

## Only scan what you're allowed to

**Only scan networks and devices you own or have permission to scan.** Scanning other people's systems without permission may be illegal where you live, and can be noticed as an attack. KUDUNMAP shows this notice the first time it starts.

## Administrator rights

KUDUNMAP starts as a normal user. Most scans work that way. A few need administrator rights on Windows:

- **OS detection**, **UDP scans** and **traceroute**.

Those are marked with a 🛡️ shield. When you start one, KUDUNMAP offers to restart itself as administrator and carry on with the same options. As administrator, TCP scans also use Nmap's faster SYN scan instead of a connect scan.

## About the vulnerability check

The Vulnerability check runs Nmap's `vuln` scripts, which test for well-known problems such as MS17-010 ("EternalBlue") and weak TLS settings.

- It's a quick check for **known** problems, not a full vulnerability scanner. A clean result doesn't guarantee a system is safe.
- "**Matched by version**" (from the optional vulners lookup) means the software version is listed as affected. The fix may already be applied.
- Some checks send unusual traffic that can occasionally upset old or fragile devices.
- The optional **CVE lookup** sends the names and versions of the services found to vulners.com. It's off by default and says so next to the switch.

Aggressive script groups (brute, exploit, dos, fuzzer, intrusive and others) are hidden behind an **Advanced** switch and ask before running.

## Privacy

- Scans, history and presets stay on your computer, in `%LOCALAPPDATA%\KUDUNMAP`. Settings are in `HKEY_CURRENT_USER\Software\KUDUNMAP`.
- KUDUNMAP only goes online to check GitHub for a newer version (can be turned off in Settings), and, if you switch it on, for the vulners CVE lookup.

## Command line

```
KUDUNMAP.exe 192.168.1.0/24                     open with this target filled in
KUDUNMAP.exe --preset quick 192.168.1.10        choose a scan type
KUDUNMAP.exe --scan --preset ping 192.168.1.0/24  start scanning straight away
```

Scan types: `quick`, `ping`, `common`, `all`, `services`, `os`, `intense`, `udp`, `vuln`.

## Build from source

You need the [.NET SDK](https://dotnet.microsoft.com/download) (8 or later). The app builds on Windows; the core tests run anywhere.

```
git clone https://github.com/azeembukhariprivate/kudunmap.git
cd kudunmap
dotnet run --project tests/KUDUNMAP.Tests
dotnet build src/KUDUNMAP/KUDUNMAP.csproj -c Release -o out/KUDUNMAP
out\KUDUNMAP\KUDUNMAP.exe --self-test
```

The app is in `out/KUDUNMAP`. `--self-test` opens every window with sample results in both themes, writes `self-test.log` and exits. To build the installer, install [Inno Setup 6](https://jrsoftware.org/isinfo.php) and compile `installer/KUDUNMAP.iss`.

## Publishing a new version

1. Change `<Version>` in `src/KUDUNMAP/KUDUNMAP.csproj` (and `MyAppVersion` in `installer/KUDUNMAP.iss`).
2. Commit and push to `main`.
3. GitHub Actions tests and builds the app. When no release exists yet for that version, it creates the `v` tag and publishes the installer and portable zip on the Releases page. Pushes that keep the same version only build.

## License

KUDUNMAP is free and open source software by Azeem Bukhari, released under the [Nmap Public Source License (NPSL) 0.95](LICENSE).

Nmap is a separate program by the Nmap Project ([nmap.org](https://nmap.org)), installed by you and not included with KUDUNMAP. KUDUNMAP is not affiliated with, sponsored or endorsed by the Nmap Project or Nmap Software LLC. "Nmap" is their trademark. See [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt).
