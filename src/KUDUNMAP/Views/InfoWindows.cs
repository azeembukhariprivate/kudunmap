using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using Kudunmap.Controls;
using Kudunmap.Core;

namespace Kudunmap.Views
{
    public static class InfoWindows
    {
        public const string NotAffiliated =
            "Nmap is a separate program by the Nmap Project (nmap.org), installed by you and not included with KUDUNMAP. " +
            "KUDUNMAP is not affiliated with, sponsored or endorsed by the Nmap Project or Nmap Software LLC. " +
            "\"Nmap\" is their trademark.";

        public const string PermissionRule = "Only scan networks and devices you own or have permission to scan.";

        /// <summary>The one-time responsible-use notice. Returns false if the window was closed without agreeing.</summary>
        public static bool ShowNotice(Window owner, bool firstRun)
        {
            var warning = Ui.Banner("IconWarn", Ui.Column(
                    Ui.Text(PermissionRule, 13, bold: true, wrap: true),
                    Ui.Text("Scanning other people's systems without permission may be illegal where you live, and can be noticed as an attack.",
                        13, wrap: true).Margin(0, 2, 0, 0)),
                "WarnBg", "WarnText");

            var header = Ui.Row(new LogoMark(44).Res(TextElement.ForegroundProperty, "Accent"),
                Ui.Column(Ui.Heading("Welcome to KUDUNMAP", 18), Ui.Subtle("A visual way to use Nmap", 13)).Margin(14, 0, 0, 0));

            var content = Ui.Column(
                header,
                warning.Margin(0, 16, 0, 0),
                Ui.Subtle("KUDUNMAP runs Nmap on your computer and shows its results. Nmap is a separate program made by the Nmap Project. " +
                          "KUDUNMAP is not affiliated with or endorsed by them.", 12.5).Margin(0, 14, 0, 0),
                Ui.Subtle(firstRun ? "Shown once. You can read it again in Settings → About." : string.Empty, 11.5).Margin(0, 10, 0, 0));

            var ok = Ui.Button(firstRun ? "I understand" : "Close", null, "PrimaryButton");
            ok.IsDefault = true;
            var window = Dialogs.Dialog(owner, "KUDUNMAP", content, 540, ok);
            var agreed = false;
            ok.Click += (s, e) =>
            {
                agreed = true;
                window.Close();
            };
            window.ShowDialog();
            return agreed;
        }

        public static void ShowAbout(Window owner, NmapInstall nmap)
        {
            Window window = null;
            var tile = new Border
            {
                Width = 64,
                Height = 64,
                CornerRadius = new CornerRadius(15),
                Child = new LogoMark(44) { Margin = new Thickness(10) }.Res(TextElement.ForegroundProperty, "AccentText")
            }.Res(Border.BackgroundProperty, "Accent");

            var header = Ui.Row(tile, Ui.Column(
                Ui.Text("KUDUNMAP", 20, bold: true),
                Ui.Subtle("Version " + AppInfo.VersionText + " · Network scanning made visual", 12.5)).Margin(16, 0, 0, 0));
            header.Children[1].SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);

            var rows = new StackPanel { Margin = new Thickness(0, 18, 0, 0) };
            void Row(string label, UIElement value)
            {
                var g = Ui.Columns(Ui.Px(120), Ui.Star());
                g.Children.Add(Ui.Subtle(label, 12.5, false).At(0, 0));
                g.Children.Add(value.At(0, 1));
                rows.Children.Add(new Border { BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(0, 7, 0, 7), Child = g }
                    .Res(Border.BorderBrushProperty, "BorderBrush"));
            }

            var madeBy = Ui.Text("Azeem, with Claude and ", 12.5);
            var heart = new Run("♥");
            heart.SetResourceReference(TextElement.ForegroundProperty, "Accent");
            madeBy.Inlines.Add(heart);
            Row("Made by", madeBy);
            Row("Licence", Ui.Row(Ui.Text("Nmap Public Source License (NPSL) 0.95 · free and open source  ", 12.5),
                Ui.Link("View", (s, e) => OpenLocalFile("LICENSE.txt", AppInfo.NmapLicenseUrl))));
            Row("Source code", Ui.Link("github.com/" + AppInfo.RepoOwner + "/" + AppInfo.RepoName, (s, e) => AppInfo.OpenUrl(AppInfo.RepoUrl)));
            Row("Nmap in use", Ui.Text(nmap == null ? "Not found" : "Nmap " + nmap.Version + " · " + nmap.Path, 12.5).Tip(nmap?.Path));
            Row("Third-party", Ui.Link("Third-party notices", (s, e) => OpenLocalFile("THIRD-PARTY-NOTICES.txt", AppInfo.RepoUrl)));
            rows.Children.Add(Ui.Divider());

            var content = Ui.Column(header, rows,
                Ui.Subtle(NotAffiliated + " " + PermissionRule, 11.5).Margin(0, 14, 0, 0),
                Ui.Link("Show the first-start notice again", (s, e) => ShowNotice(window, false)).Margin(0, 8, 0, 0));

            var updates = Ui.Button("Check for updates");
            var close = Ui.Button("Close", null, "PrimaryButton");
            close.IsCancel = true;
            close.IsDefault = true;
            window = Dialogs.Dialog(owner, "About KUDUNMAP", content, 580, updates, close);
            close.Click += (s, e) => window.Close();
            updates.Click += async (s, e) =>
            {
                updates.IsEnabled = false;
                try
                {
                    var info = await UpdateChecker.CheckAsync();
                    if (info == null) Dialogs.Info(window, "Couldn't find any published version yet.");
                    else if (info.IsNewer)
                    {
                        if (Dialogs.Confirm(window, $"KUDUNMAP {info.Latest.ToString(3)} is available. Open the download page?"))
                            AppInfo.OpenUrl(info.Url);
                    }
                    else Dialogs.Info(window, "You have the latest version.");
                }
                catch
                {
                    Dialogs.Error(window, "Couldn't check for updates. Check your internet connection and try again.");
                }
                finally
                {
                    updates.IsEnabled = true;
                }
            };
            window.ShowDialog();
        }

        private static void OpenLocalFile(string name, string fallbackUrl)
        {
            var path = Path.Combine(Path.GetDirectoryName(AppInfo.ExePath) ?? string.Empty, name);
            try
            {
                if (File.Exists(path))
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path) { UseShellExecute = true });
                    return;
                }
            }
            catch
            {
                // fall back to the web page
            }
            AppInfo.OpenUrl(fallbackUrl);
        }
    }

    public sealed class SettingsWindow : Window
    {
        private readonly Func<NmapInstall> _currentNmap;
        private readonly Action _nmapChanged;
        private readonly TextBlock _nmapText = Ui.Text(string.Empty, 12.5, wrap: true);

        public SettingsWindow(Window owner, Func<NmapInstall> currentNmap, Action nmapChanged)
        {
            _currentNmap = currentNmap;
            _nmapChanged = nmapChanged;
            Width = 560;
            SizeToContent = SizeToContent.Height;
            ResizeMode = ResizeMode.NoResize;
            ShowInTaskbar = false;
            Dialogs.Prepare(this, "Settings", owner);

            var root = new StackPanel { Margin = new Thickness(26, 22, 26, 22) };
            root.Children.Add(Ui.Heading("Settings", 20).Margin(0, 0, 0, 14));

            // Appearance
            root.Children.Add(Ui.Heading("Appearance", 14).Margin(0, 0, 0, 8));
            var themes = new WrapPanel();
            foreach (var mode in new[] { ThemeMode.System, ThemeMode.Light, ThemeMode.Dark })
            {
                var chip = new RadioButton
                {
                    Content = mode == ThemeMode.System ? "Same as Windows" : mode.ToString(),
                    GroupName = "theme",
                    IsChecked = Settings.Theme == mode
                }.Styled("ChipRadio");
                chip.Checked += (s, e) =>
                {
                    Settings.Theme = mode;
                    ThemeManager.Apply(mode);
                };
                themes.Children.Add(chip);
            }
            root.Children.Add(themes);

            // Nmap
            root.Children.Add(Ui.Heading("Nmap", 14).Margin(0, 12, 0, 6));
            root.Children.Add(_nmapText);
            var nmapButtons = Ui.Row(
                Ui.Small(Ui.Button("Choose nmap.exe…", "IconFile", click: (s, e) => ChooseNmap())),
                Ui.Small(Ui.Button("Find automatically", "IconRefresh", click: (s, e) => ResetNmap())).Margin(8, 0, 0, 0),
                Ui.Link("Get Nmap from nmap.org", (s, e) => AppInfo.OpenUrl(AppInfo.NmapDownloadUrl)).Margin(14, 0, 0, 0));
            root.Children.Add(nmapButtons.Margin(0, 8, 0, 0));
            UpdateNmapText();

            // Scans
            root.Children.Add(Ui.Heading("Scans", 14).Margin(0, 18, 0, 4));
            var notify = new CheckBox { Content = "Show a Windows notification when a scan finishes", IsChecked = Settings.NotifyWhenDone };
            notify.Click += (s, e) => Settings.NotifyWhenDone = notify.IsChecked == true;
            root.Children.Add(notify);
            root.Children.Add(Ui.Subtle("Scans are saved in History on this computer only (" + AppPaths.Root + ").", 12).Margin(27, 0, 0, 0));
            root.Children.Add(Ui.Link("Open the History folder", (s, e) => AppInfo.OpenFolder(AppPaths.History)).Margin(27, 2, 0, 0));

            // Updates
            root.Children.Add(Ui.Heading("Updates", 14).Margin(0, 16, 0, 4));
            var updates = new CheckBox { Content = "Check for a new KUDUNMAP version when it starts", IsChecked = Settings.CheckForUpdates };
            updates.Click += (s, e) => Settings.CheckForUpdates = updates.IsChecked == true;
            root.Children.Add(updates);
            root.Children.Add(Ui.Subtle("Only asks GitHub for the latest version number. Nothing is downloaded without asking.", 12).Margin(27, 0, 0, 0));

            root.Children.Add(Ui.Divider().Margin(0, 18, 0, 0));
            var bottom = Ui.Columns(Ui.Star(), Ui.Auto);
            bottom.Children.Add(Ui.Link("About KUDUNMAP", (s, e) => InfoWindows.ShowAbout(this, _currentNmap())).At(0, 0));
            var close = Ui.Button("Close", null, "PrimaryButton");
            close.IsCancel = true;
            close.Click += (s, e) => Close();
            bottom.Children.Add(close.At(0, 1));
            root.Children.Add(bottom.Margin(0, 14, 0, 0));
            Content = root;
        }

        private void UpdateNmapText()
        {
            var nmap = _currentNmap();
            var custom = Settings.NmapPath;
            _nmapText.Text = nmap == null
                ? "Nmap wasn't found. Install it from nmap.org, or choose nmap.exe if it's somewhere else."
                : $"Using Nmap {nmap.Version}: {nmap.Path}" + (string.IsNullOrEmpty(custom) ? " (found automatically)" : " (chosen by you)");
        }

        private void ChooseNmap()
        {
            var file = Dialogs.PickFile(this, "Choose nmap.exe", "nmap.exe|nmap.exe");
            if (file == null) return;
            string version = null;
            try { version = NmapLocator.ReadVersion(file); }
            catch { /* handled below */ }
            if (version == null)
            {
                Dialogs.Error(this, "That file didn't answer like Nmap. Choose the nmap.exe from your Nmap folder.");
                return;
            }
            Settings.NmapPath = file;
            _nmapChanged();
            UpdateNmapText();
        }

        private void ResetNmap()
        {
            Settings.NmapPath = string.Empty;
            _nmapChanged();
            UpdateNmapText();
        }
    }
}
