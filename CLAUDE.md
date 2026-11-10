# KUDUNMAP

A visual front-end for Nmap on Windows: scan a network without typing commands.
Part of the KUDU family of free, open-source Windows apps by Azeem Bukhari.
KUDUNMAP itself is released under the Nmap Public Source License (see LICENSE), not MIT like the other apps.

## Working with Azeem (the owner)

- **Branches:** work on `main` and push to `main`. Ask before creating any other branch.
- **New features:** first say what you understood, and ask your doubts and suggestions, one question at a time.
  Only start building when Azeem says "build".
- **Look:** keep the app's current look. No redesigns unless asked.
- **About window credit:** "Made by Azeem, with Claude and ♥" (the heart in the accent colour). Keep it.
- **Commits:** author `Azeem Bukhari <12558389+azeembukhariprivate@users.noreply.github.com>`. Clear messages that say
  what changed and why. Don't put AI model names or versions in commits, code or docs.
- **Words:** the app's text, README and release notes use plain everyday words, not technical jargon.
- **Before pushing:** build and run the tests locally, and re-read the diff. After pushing, watch the GitHub Actions
  build until it's green; fix failures, never skip or disable a test to get green.

## How the app is built

- .NET Framework 4.8 WPF app. The screens are built in C# (no XAML compiler); the themes (`Themes/Light.xaml`,
  `Dark.xaml`, `Styles.xaml`) are XAML loaded at startup as embedded resources, using resource keys such as `Accent`,
  `Text`, `SurfaceBg`. Use the helpers in `Controls/Ui.cs` and existing keys rather than hard-coded colours.
- It builds with the plain .NET SDK on any OS (Microsoft.NETFramework.ReferenceAssemblies); it runs on Windows 10/11.
- Logic that doesn't need Windows lives in `Core/` and is tested by `tests/KUDUNMAP.Tests` (a .NET 8 console program).
- `KUDUNMAP.exe --self-test` drives the real app on Windows (GitHub Actions runs it, keeping screenshots of every window as
  a build download). Add a self-test step for new screens and features.
- Settings live in `HKEY_CURRENT_USER\Software\KUDUNMAP`. The Inno Setup installer (`installer/KUDUNMAP.iss`) installs per
  user, without administrator rights.

```
dotnet run --project tests/KUDUNMAP.Tests -c Release
dotnet build src/KUDUNMAP/KUDUNMAP.csproj -c Release -o out/KUDUNMAP
out\KUDUNMAP\KUDUNMAP.exe --self-test        (Windows only)
```

## Notes

- 1.1: `Core/PortNotes.cs` (a plain-words note and level, Fine / Worth a look / Risky, per open port; shown under ports, in
  the "Worth a look" tab and the HTML report), `Core/NetworkMap.cs` (guesses each device's kind; rings around the router;
  drawn by `Views/ResultsExtras.cs`, saved as PNG), `Core/ScheduledScans.cs` (JSON in `Schedules\`, a Task Scheduler task
  "KUDUNMAP - name (id)" made from XML with RunLevel HighestAvailable, so Windows asks once at setup). The task runs
  `KUDUNMAP.exe --scheduled <id>` (`Views/ScheduledRun.cs`: no window, History with `ScheduleId`, compares with the run
  before and notifies when something changed). The uninstaller runs `--remove-schedules`.

## Shared code (kudu-common)

The files listed in `.kudu-common` (the look and controls in `Controls/`, `Core/Admin.cs`, `AppInfo.cs`, `Args.cs`,
`ThemeManager.cs`, `Unelevated.cs`, `UpdateChecker.cs`, `Views/Dialogs.cs`, `Views/Screenshots.cs`, ...) are copied from
[kudu-common](https://github.com/azeembukhariprivate/kudu-common) and start with a comment saying so.
**Don't edit them here**: change them in kudu-common, then run `python sync.py ../kudunmap` there and commit both repos.
The build fails when a copy differs from kudu-common. App-specific details go in `Core/AppDetails.cs`.

## Releasing

1. Raise `<Version>` in `src/KUDUNMAP/KUDUNMAP.csproj` (and `MyAppVersion` in `installer/KUDUNMAP.iss`).
2. Commit and push to `main`.
3. GitHub Actions (`.github/workflows/build.yml`, Windows) tests and builds the app. When no release exists yet for that
   version it creates the `v` tag and publishes the installer and portable zip on the Releases page, plus a copy named
   `KUDUNMAP-setup.exe` that the README's download button links to (`releases/latest/download/KUDUNMAP-setup.exe`).
   Pushes that keep the same version only build.
