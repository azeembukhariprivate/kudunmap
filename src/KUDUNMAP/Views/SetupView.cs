using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Media;
using Kudunmap.Controls;
using Kudunmap.Core;

namespace Kudunmap.Views
{
    /// <summary>The New scan screen: scan types on the left, options, command preview and recent scans on the right.</summary>
    public sealed class SetupView : Grid
    {
        private readonly MainWindow _main;
        private readonly Dictionary<string, RadioButton> _presetButtons = new Dictionary<string, RadioButton>();
        private readonly StackPanel _customPanel = new StackPanel();
        private readonly StackPanel _recentPanel = new StackPanel();
        private readonly Border _recentCard;
        private bool _loading;

        // Options
        private readonly TextBlock _title = Ui.Heading(string.Empty, 15);
        private readonly Border _chipHost = new Border { Margin = new Thickness(10, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
        private readonly TextBlock _summary = Ui.Subtle(string.Empty, 12);
        private readonly List<RadioButton> _kind = new List<RadioButton>();
        private readonly List<RadioButton> _speed = new List<RadioButton>();
        private readonly TextBlock _speedHint = Ui.Subtle(string.Empty, 11.5);
        private readonly List<RadioButton> _ports = new List<RadioButton>();
        private readonly TextBox _customPorts = new TextBox { MinHeight = 32 };
        private readonly TextBlock _portsHint = Ui.Subtle(string.Empty, 11.5);
        private readonly CheckBox _skipPing = new CheckBox { Content = "Skip ping (treat every host as online)" };
        private readonly CheckBox _resolve = new CheckBox { Content = "Resolve host names" };
        private readonly CheckBox _onlyOpen = new CheckBox { Content = "Show only open ports" };
        private readonly CheckBox _versions = new CheckBox { Content = "Detect service versions" };
        private readonly CheckBox _os = new CheckBox { Content = "Detect operating system" };
        private readonly CheckBox _trace = new CheckBox { Content = "Traceroute" };
        private readonly Dictionary<string, ToggleButton> _scripts = new Dictionary<string, ToggleButton>();
        private readonly CheckBox _advanced = new CheckBox { Content = "Advanced" }.Styled("Switch");
        private readonly StackPanel _advancedPanel = new StackPanel();
        private readonly CheckBox _vulners = new CheckBox { Content = "Look up known CVEs online (vulners)" }.Styled("Switch");

        // Command and status
        private readonly TextBlock _command = new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = 12.5, LineHeight = 20 };
        private readonly WrapPanel _explain = new WrapPanel { Margin = new Thickness(0, 10, 0, 0) };
        private readonly TextBlock _readyTitle = Ui.Text(string.Empty, 14, bold: true);
        private readonly TextBlock _readyText = Ui.Subtle(string.Empty, 12);
        private readonly TextBlock _nmapText = Ui.Subtle(string.Empty, 12, false);
        private readonly Border _adminBanner;
        private readonly TextBlock _adminText = Ui.Text(string.Empty, 12.5, wrap: true);
        private readonly Border _warnBanner;
        private readonly TextBlock _warnText = Ui.Text(string.Empty, 12.5, wrap: true);

        public SetupView(MainWindow main)
        {
            _main = main;
            ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(300) });
            ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(12) });
            ColumnDefinitions.Add(new ColumnDefinition());

            Children.Add(BuildPresetList().At(0, 0));

            _adminBanner = Ui.Banner("IconShield", Ui.Column(_adminText,
                    Ui.Small(Ui.Button("Restart as administrator", "IconShield", click: (s, e) => _main.RestartAsAdmin())).Margin(0, 8, 0, 0)),
                "WarnBg", "WarnText").Margin(0, 12, 0, 0);
            _adminBanner.HorizontalAlignment = HorizontalAlignment.Stretch;
            _warnBanner = Ui.Banner("IconWarn", _warnText, "WarnBg", "WarnText").Margin(0, 12, 0, 0);

            _recentCard = BuildRecentCard();
            var right = new StackPanel();
            right.Children.Add(BuildOptionsCard());
            right.Children.Add(BuildCommandCard().Margin(0, 12, 0, 0));
            right.Children.Add(BuildReadyCard().Margin(0, 12, 0, 0));
            right.Children.Add(_recentCard.Margin(0, 12, 0, 0));
            var scroll = new ScrollViewer { Content = right, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Padding = new Thickness(0, 0, 2, 0) };
            Children.Add(scroll.At(0, 2));

            HookEvents();
        }

        // ------------------------------------------------------------------ building

        private UIElement BuildPresetList()
        {
            var list = new StackPanel();
            list.Children.Add(Ui.Heading("Scan type", 13).Margin(6, 0, 0, 8));
            foreach (var p in Presets.All)
            {
                var rb = PresetButton(p.Icon, p.Title, p.Description, p.NeedsAdmin, false);
                rb.Checked += (s, e) => { if (!_loading) _main.SelectPreset(p); };
                _presetButtons[p.Id] = rb;
                list.Children.Add(rb);
            }

            list.Children.Add(Ui.Heading("My presets", 13).Margin(6, 14, 0, 6));
            list.Children.Add(_customPanel);
            var scroll = new ScrollViewer { Content = list, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            return Ui.Card(scroll, 10);
        }

        private RadioButton PresetButton(string icon, string title, string description, bool needsAdmin, bool custom)
        {
            var g = Ui.Columns(Ui.Auto, Ui.Star(), Ui.Auto);
            var tile = new Border
            {
                Width = 30,
                Height = 30,
                CornerRadius = new CornerRadius(6),
                Child = Ui.Icon(icon, 16),
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(0, 1, 10, 0)
            }.Res(Border.BackgroundProperty, custom ? "NeutralChipBg" : "ChipBg");
            tile.Res(TextElement.ForegroundProperty, custom ? "SubtleText" : "ChipText");
            ((FrameworkElement)tile.Child).HorizontalAlignment = HorizontalAlignment.Center;
            g.Children.Add(tile.At(0, 0));
            g.Children.Add(Ui.Column(Ui.Text(title, 13, bold: true), Ui.Subtle(description, 11.5, false)).At(0, 1));
            if (needsAdmin)
            {
                var shield = Ui.Icon("IconShield", 16).Margin(6, 2, 0, 0).Tip("Needs administrator rights");
                shield.VerticalAlignment = VerticalAlignment.Top;
                shield.Res(TextElement.ForegroundProperty, "WarnText");
                g.Children.Add(shield.At(0, 2));
            }
            return new RadioButton { Content = g, GroupName = "preset" }.Styled("PresetRadio");
        }

        private static Border Segments(List<RadioButton> into, string group, params string[] labels)
        {
            var panel = new UniformGrid { Rows = 1 };
            for (var i = 0; i < labels.Length; i++)
            {
                var rb = new RadioButton { Content = labels[i], GroupName = group }.Styled("SegmentRadio");
                if (i == labels.Length - 1) rb.BorderThickness = new Thickness(0);
                into.Add(rb);
                panel.Children.Add(rb);
            }
            var border = new Border { BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Child = panel, ClipToBounds = true }
                .Res(Border.BorderBrushProperty, "InputBorder");
            // Clip the square segment corners to the rounded border.
            border.SizeChanged += (s, e) =>
                panel.Clip = new RectangleGeometry(new Rect(0, 0, Math.Max(0, border.ActualWidth - 2), Math.Max(0, border.ActualHeight - 2)), 5, 5);
            return border;
        }

        private static FrameworkElement Field(string label, UIElement content, UIElement hint = null)
        {
            var p = new StackPanel();
            p.Children.Add(Ui.Subtle(label, 12, false).Margin(0, 0, 0, 6));
            p.Children.Add(content);
            if (hint != null) p.Children.Add(((FrameworkElement)hint).Margin(0, 5, 0, 0));
            return p;
        }

        private Border BuildOptionsCard()
        {
            var header = new DockPanel { Margin = new Thickness(0, 0, 0, 14), LastChildFill = true };
            var titleRow = Ui.Row(_title, _chipHost);
            DockPanel.SetDock(titleRow, Dock.Top);
            header.Children.Add(titleRow);
            header.Children.Add(_summary.Margin(0, 4, 0, 0));

            var grid = Ui.Columns(Ui.Star(), Ui.Px(28), Ui.Star());
            for (var i = 0; i < 4; i++) grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            grid.Children.Add(Field("What to scan", Segments(_kind, "kind", "TCP ports", "UDP ports", "Hosts only")).At(0, 0));
            grid.Children.Add(Field("Speed", Segments(_speed, "speed", Presets.TimingNames), _speedHint).At(0, 2));

            var portsRow = Ui.Columns(Ui.Star(), Ui.Px(150));
            portsRow.Children.Add(Segments(_ports, "ports", "Top 100", "Top 1,000", "All", "Custom").At(0, 0));
            _customPorts.Res(Control.FontFamilyProperty, "MonoFont");
            _customPorts.Margin = new Thickness(8, 0, 0, 0);
            _customPorts.ToolTip = "For example 22,80,443 or 1-1024";
            portsRow.Children.Add(_customPorts.At(0, 1));
            grid.Children.Add(Field("Ports", portsRow, _portsHint).At(1, 0, 3).Margin(0, 16, 0, 0));

            grid.Children.Add(Field("Discovery", Ui.Column(_skipPing, _resolve, _onlyOpen)).At(2, 0).Margin(0, 16, 0, 0));
            grid.Children.Add(Field("Detection", Ui.Column(
                _versions,
                Ui.Row(_os, Ui.Chip("Needs admin", Tone.Warn, "IconShield").Margin(8, 0, 0, 0)),
                Ui.Row(_trace, Ui.Chip("Needs admin", Tone.Warn, "IconShield").Margin(8, 0, 0, 0)))).At(2, 2).Margin(0, 16, 0, 0));

            // Scripts
            var safe = new WrapPanel();
            foreach (var c in ScanOptions.SafeCategories) safe.Children.Add(ScriptChip(c));
            var scriptsRow = Ui.Columns(Ui.Star(), Ui.Auto);
            scriptsRow.Children.Add(safe.At(0, 0));
            scriptsRow.Children.Add(_advanced.At(0, 1).Margin(12, 0, 0, 0));

            var advancedChips = new WrapPanel();
            foreach (var c in ScanOptions.AdvancedCategories) advancedChips.Children.Add(ScriptChip(c));
            _advancedPanel.Children.Add(Ui.Banner("IconWarn",
                Ui.Text("These scripts can log in with guessed passwords, try exploits or overload services. Only use them on systems you are allowed to test.",
                    12, wrap: true), "WarnBg", "WarnText"));
            _advancedPanel.Children.Add(advancedChips.Margin(0, 8, 0, 0));

            var scripts = Ui.Column(scriptsRow, _advancedPanel.Margin(0, 6, 0, 0), _vulners.Margin(0, 6, 0, 0),
                Ui.Subtle("When on, the names and versions of the services found are sent to vulners.com to look up known CVEs. Off by default.", 11.5)
                    .Margin(46, 0, 0, 0));
            grid.Children.Add(Field("Scripts (NSE)", scripts).At(3, 0, 3).Margin(0, 16, 0, 0));

            return Ui.Card(Ui.Column(header, grid));
        }

        private ToggleButton ScriptChip(string category)
        {
            var t = new ToggleButton { Content = category }.Styled("ChipToggle");
            t.ToolTip = ScriptTip(category);
            _scripts[category] = t;
            return t;
        }

        private static string ScriptTip(string category)
        {
            switch (category)
            {
                case "default": return "Nmap's standard set of useful, safe scripts (same as -sC).";
                case "safe": return "Scripts that won't crash services or use lots of bandwidth.";
                case "discovery": return "Find out more about the network: names, shares, directories.";
                case "version": return "Extra version detection.";
                case "vuln": return "Check for well-known vulnerabilities. Some checks send unusual traffic.";
                case "auth": return "Check for weak or missing authentication.";
                case "broadcast": return "Discover hosts by broadcasting on the local network.";
                case "brute": return "Guess passwords. Can lock accounts.";
                case "dos": return "Denial-of-service tests. Can crash services.";
                case "exploit": return "Actively try to exploit vulnerabilities.";
                case "external": return "Send data to third-party services on the internet.";
                case "fuzzer": return "Send unexpected data. Can crash services.";
                case "intrusive": return "Risky scripts that may crash services or be seen as attacks.";
                case "malware": return "Check for signs of backdoors and malware.";
                default: return category;
            }
        }

        private Border BuildCommandCard()
        {
            var header = Ui.Columns(Ui.Auto, Ui.Star(), Ui.Auto, Ui.Auto);
            header.Children.Add(Ui.Heading("Command", 13).At(0, 0));
            header.Children.Add(Ui.Subtle("Updates as you change options. You never need to type it.", 12, false).Margin(10, 0, 0, 0).At(0, 1));
            header.Children.Add(Ui.Small(Ui.Button("Copy", "IconCopy", click: (s, e) => _main.CopyCommand())).At(0, 2));
            header.Children.Add(Ui.Small(Ui.Button("Save as preset", "IconSave", "GhostButton", (s, e) => SaveAsPreset())).Margin(6, 0, 0, 0).At(0, 3));

            _command.Res(TextBlock.FontFamilyProperty, "MonoFont");
            var box = new Border { CornerRadius = new CornerRadius(6), BorderThickness = new Thickness(1), Padding = new Thickness(12, 10, 12, 10), Child = _command }
                .Res(Border.BackgroundProperty, "MonoBg").Res(Border.BorderBrushProperty, "BorderBrush");

            return Ui.Card(Ui.Column(header, box.Margin(0, 10, 0, 0), _explain), 16);
        }

        private Border BuildReadyCard()
        {
            var g = Ui.Columns(Ui.Auto, Ui.Star(), Ui.Auto);
            g.Children.Add(new LogoMark(40).Res(TextElement.ForegroundProperty, "Accent").Margin(0, 0, 16, 0).At(0, 0));
            g.Children.Add(Ui.Column(_readyTitle, _readyText.Margin(0, 2, 0, 0)).At(0, 1));
            g.Children.Add(_nmapText.Margin(12, 0, 0, 0).At(0, 2));
            return Ui.Card(Ui.Column(g, _adminBanner, _warnBanner), 16);
        }

        private Border BuildRecentCard()
        {
            var header = Ui.Columns(Ui.Star(), Ui.Auto);
            header.Children.Add(Ui.Heading("Recent scans", 13).At(0, 0));
            header.Children.Add(Ui.Link("See all history", (s, e) => _main.ShowHistory()).At(0, 1));
            return Ui.Card(Ui.Column(header, _recentPanel.Margin(0, 6, 0, 0)), 16);
        }

        private void HookEvents()
        {
            void Changed(object s, RoutedEventArgs e) => OnChanged();
            foreach (var rb in _kind.Concat(_speed).Concat(_ports)) rb.Checked += Changed;
            foreach (var cb in new[] { _skipPing, _resolve, _onlyOpen, _versions, _os, _trace, _vulners })
            {
                cb.Checked += Changed;
                cb.Unchecked += Changed;
            }
            foreach (var t in _scripts.Values)
            {
                t.Checked += Changed;
                t.Unchecked += Changed;
            }
            _customPorts.TextChanged += (s, e) => OnChanged();
            _advanced.Checked += (s, e) => { Settings.ShowAdvancedScripts = true; UpdateAdvancedVisibility(); };
            _advanced.Unchecked += (s, e) => { Settings.ShowAdvancedScripts = false; UpdateAdvancedVisibility(); };
        }

        private void UpdateAdvancedVisibility()
        {
            var anyAdvancedOn = ScanOptions.AdvancedCategories.Any(c => _scripts[c].IsChecked == true);
            _advancedPanel.Visibility = _advanced.IsChecked == true || anyAdvancedOn ? Visibility.Visible : Visibility.Collapsed;
        }

        // ------------------------------------------------------------------ options <-> controls

        /// <summary>Shows the options on screen. presetKey is a built-in preset id, or null for a custom preset.</summary>
        public void LoadOptions(ScanOptions o, string presetKey, CustomPreset custom = null)
        {
            _loading = true;
            try
            {
                foreach (var pair in _presetButtons) pair.Value.IsChecked = pair.Key == presetKey;
                foreach (var rb in _customPanel.Children.OfType<RadioButton>())
                    rb.IsChecked = custom != null && (string)rb.Tag == custom.File;

                var preset = Presets.Find(o.PresetId);
                _title.Text = custom != null ? custom.Name : o.Title;
                _summary.Text = preset?.Summary ?? "Your own saved options.";
                SetChip(custom != null ? "My preset" : "Preset", custom != null ? Tone.Neutral : Tone.Accent);

                _kind[o.Kind == ScanKind.Udp ? 1 : o.Kind == ScanKind.Ping ? 2 : 0].IsChecked = true;
                _speed[Math.Max(0, Math.Min(5, o.Timing))].IsChecked = true;
                _ports[o.Ports == PortMode.Fast ? 0 : o.Ports == PortMode.All ? 2 : o.Ports == PortMode.Custom ? 3 : 1].IsChecked = true;
                _customPorts.Text = o.CustomPorts ?? string.Empty;
                _skipPing.IsChecked = o.SkipPing;
                _resolve.IsChecked = o.ResolveNames;
                _onlyOpen.IsChecked = o.OnlyOpen;
                _versions.IsChecked = o.DetectVersions;
                _os.IsChecked = o.DetectOs;
                _trace.IsChecked = o.Traceroute;
                foreach (var pair in _scripts) pair.Value.IsChecked = o.HasScript(pair.Key);
                _vulners.IsChecked = o.Vulners;
                _advanced.IsChecked = Settings.ShowAdvancedScripts;
            }
            finally
            {
                _loading = false;
            }
            UpdateAdvancedVisibility();
            Refresh();
        }

        private void SetChip(string text, Tone tone) => _chipHost.Child = Ui.Chip(text, tone);

        private void OnChanged()
        {
            if (_loading) return;
            var o = _main.Options;
            o.Kind = _kind[1].IsChecked == true ? ScanKind.Udp : _kind[2].IsChecked == true ? ScanKind.Ping : ScanKind.Tcp;
            o.Timing = Math.Max(0, _speed.FindIndex(r => r.IsChecked == true));
            o.Ports = _ports[0].IsChecked == true ? PortMode.Fast
                : _ports[2].IsChecked == true ? PortMode.All
                : _ports[3].IsChecked == true ? PortMode.Custom
                : PortMode.Default;
            o.CustomPorts = _customPorts.Text;
            o.SkipPing = _skipPing.IsChecked == true;
            o.ResolveNames = _resolve.IsChecked == true;
            o.OnlyOpen = _onlyOpen.IsChecked == true;
            o.DetectVersions = _versions.IsChecked == true;
            o.DetectOs = _os.IsChecked == true;
            o.Traceroute = _trace.IsChecked == true;
            o.Scripts = _scripts.Where(p => p.Value.IsChecked == true).Select(p => p.Key).ToList();
            o.Vulners = _vulners.IsChecked == true;
            SetChip("Changed", Tone.Neutral);
            UpdateAdvancedVisibility();
            Refresh();
        }

        /// <summary>Updates the command preview, hints and warnings from the current options and target.</summary>
        public void Refresh()
        {
            var o = _main.Options;
            var isAdmin = Admin.IsAdmin;
            var ping = o.Kind == ScanKind.Ping;

            foreach (var rb in _ports) rb.IsEnabled = !ping;
            _customPorts.IsEnabled = !ping && o.Ports == PortMode.Custom;
            _onlyOpen.IsEnabled = !ping;
            _versions.IsEnabled = !ping;
            _os.IsEnabled = !ping;

            _speedHint.Text = SpeedHint(o.Timing);
            _portsHint.Text = ping ? "Hosts only: no ports are scanned."
                : o.Ports == PortMode.Custom ? (CommandBuilder.ValidatePorts(o.CustomPorts) ?? "Numbers, commas and ranges. Add U: for UDP, e.g. U:53.")
                : o.Ports == PortMode.All ? "All 65,535 ports. Much slower, but finds services on unusual ports."
                : o.Ports == PortMode.Fast ? "The 100 most common ports. Quickest."
                : "The 1,000 most common ports. Nmap's standard.";

            // Command preview
            _command.Inlines.Clear();
            _command.Inlines.Add(Run("nmap", "LinkText", bold: true));
            foreach (var p in CommandBuilder.Describe(o, isAdmin)) _command.Inlines.Add(Run(" " + p.Text, "Text"));
            foreach (var p in CommandBuilder.Internal("scan.xml")) _command.Inlines.Add(Run(" " + p.Text, "SubtleText"));
            var targets = !string.IsNullOrEmpty(o.TargetFile)
                ? "-iL " + CommandBuilder.QuoteForDisplay(o.TargetFile)
                : string.IsNullOrWhiteSpace(o.Targets) ? "<target>" : o.Targets.Trim();
            _command.Inlines.Add(Run(" " + targets, "Text", bold: true));

            _explain.Children.Clear();
            foreach (var p in CommandBuilder.Describe(o, isAdmin))
            {
                var t = new TextBlock { FontSize = 12, Margin = new Thickness(0, 0, 16, 4) };
                t.Inlines.Add(Run(p.Args[0], "Text", bold: true));
                t.Inlines.Add(Run(" " + p.Meaning, "SubtleText"));
                _explain.Children.Add(t);
            }
            var internalNote = new TextBlock { FontSize = 12, Margin = new Thickness(0, 0, 16, 4) };
            internalNote.Inlines.Add(Run("grey", "SubtleText", bold: true));
            internalNote.Inlines.Add(Run(" added by KUDUNMAP for live progress (left out when you copy)", "SubtleText"));
            _explain.Children.Add(internalNote);

            // Ready card
            var targetError = string.IsNullOrEmpty(o.TargetFile) ? CommandBuilder.ValidateTargets(o.Targets) : null;
            if (!string.IsNullOrEmpty(o.TargetFile))
            {
                _readyTitle.Text = "Ready to scan the targets in " + System.IO.Path.GetFileName(o.TargetFile);
                _readyText.Text = "You can cancel at any time.";
            }
            else if (string.IsNullOrWhiteSpace(o.Targets))
            {
                _readyTitle.Text = "Type a target to scan";
                _readyText.Text = "An IP address (192.168.1.10), name (router.lan), range (192.168.1.1-50) or network (192.168.1.0/24).";
            }
            else if (targetError != null)
            {
                _readyTitle.Text = "Check the target";
                _readyText.Text = targetError.Split('\n')[0];
            }
            else
            {
                var count = CommandBuilder.CountAddresses(o.Targets);
                _readyTitle.Text = count < 0 ? "Ready to scan"
                    : count == 1 ? "Ready to scan 1 address"
                    : "Ready to scan " + count.ToString("N0", CultureInfo.CurrentCulture) + " addresses";
                _readyText.Text = (count > 4096 ? "That's a lot of addresses. This may take a long time. " : string.Empty) + "You can cancel at any time.";
            }

            var nmap = _main.Nmap;
            _nmapText.Text = nmap == null ? string.Empty : "Nmap " + nmap.Version + " found · " + nmap.Folder;

            var reasons = o.AdminReasons();
            if (reasons.Count > 0 && !isAdmin)
            {
                _adminText.Text = "This scan needs administrator rights for " + Join(reasons) + ". " +
                                  "Restart KUDUNMAP as administrator, or turn those options off.";
                _adminBanner.Visibility = Visibility.Visible;
            }
            else
            {
                _adminBanner.Visibility = Visibility.Collapsed;
            }

            var warnings = new List<string>();
            if (o.UsesAdvancedScripts) warnings.Add("Advanced scripts are on. They can lock accounts, crash services or be seen as an attack.");
            if (o.HasScript("vuln")) warnings.Add("Vulnerability scripts send unusual traffic that can occasionally upset old or fragile devices.");
            if (o.Vulners) warnings.Add("CVE lookup is on: service names and versions will be sent to vulners.com.");
            _warnText.Text = string.Join("\n", warnings);
            _warnBanner.Visibility = warnings.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private static string Join(List<string> items) =>
            items.Count == 1 ? items[0] : string.Join(", ", items.Take(items.Count - 1)) + " and " + items.Last();

        private static string SpeedHint(int timing)
        {
            switch (timing)
            {
                case 0:
                case 1: return "Very slow and quiet. Can take hours on a network.";
                case 2: return "Gentle on slow networks and old devices.";
                case 3: return "Nmap's normal speed.";
                case 5: return "Fastest. On busy or slow networks it can miss ports.";
                default: return "Fast is right for most home and office networks.";
            }
        }

        private static Run Run(string text, string brush, bool bold = false)
        {
            var run = new Run(text) { FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal };
            run.SetResourceReference(TextElement.ForegroundProperty, brush);
            return run;
        }

        // ------------------------------------------------------------------ my presets and recent scans

        public void RefreshCustomPresets(CustomPreset selected = null)
        {
            _customPanel.Children.Clear();
            var presets = CustomPresets.List();
            if (presets.Count == 0)
            {
                _customPanel.Children.Add(Ui.Subtle("Save your own with \"Save as preset\" under the command.", 11.5).Margin(6, 0, 6, 0));
                return;
            }

            foreach (var cp in presets)
            {
                var rb = PresetButton("IconSave", cp.Name, cp.Description, cp.Options.NeedsAdmin, true);
                rb.Tag = cp.File;
                rb.IsChecked = selected != null && selected.File == cp.File;
                rb.Checked += (s, e) => { if (!_loading) _main.SelectCustomPreset(cp); };
                var menu = new ContextMenu();
                var delete = new MenuItem { Header = "Delete this preset" };
                delete.Click += (s, e) =>
                {
                    if (!Dialogs.Confirm(Window.GetWindow(this), $"Delete the preset \"{cp.Name}\"?")) return;
                    CustomPresets.Delete(cp);
                    RefreshCustomPresets();
                };
                menu.Items.Add(delete);
                rb.ContextMenu = menu;
                rb.ToolTip = "Right-click to delete";
                _customPanel.Children.Add(rb);
            }
        }

        private void SaveAsPreset()
        {
            var name = Dialogs.Ask(Window.GetWindow(this), "Save as preset",
                "Give these options a name. The target is saved too, so you can repeat this scan with one click.", _main.Options.Title);
            if (name == null) return;
            var saved = CustomPresets.Save(name, _main.Options);
            RefreshCustomPresets(saved);
            _loading = true;
            foreach (var rb in _presetButtons.Values) rb.IsChecked = false;
            _loading = false;
            _title.Text = saved.Name;
            SetChip("My preset", Tone.Neutral);
        }

        public void RefreshRecent()
        {
            _recentPanel.Children.Clear();
            List<HistoryEntry> entries;
            try { entries = History.List().Take(3).ToList(); }
            catch { entries = new List<HistoryEntry>(); }

            if (entries.Count == 0)
            {
                _recentPanel.Children.Add(Ui.Subtle("Finished scans appear here, and in History.", 12).Margin(0, 6, 0, 0));
                return;
            }

            foreach (var e in entries)
            {
                var g = Ui.Columns(Ui.Px(150), Ui.Px(190), Ui.Star(), Ui.Auto);
                g.Children.Add(Ui.Subtle(e.WhenText, 12.5, false).At(0, 0));
                g.Children.Add(Ui.Text(e.Title, 12.5).At(0, 1));
                g.Children.Add(Ui.Mono(e.Targets, 12.5).At(0, 2));
                g.Children.Add(Ui.Subtle(e.Summary, 12.5, false).At(0, 3));
                var row = new Button { Content = g, HorizontalContentAlignment = HorizontalAlignment.Stretch, MinHeight = 34, Padding = new Thickness(0) }
                    .Styled("GhostButton");
                row.Margin = new Thickness(-6, 0, -6, 0);
                row.Padding = new Thickness(6, 0, 6, 0);
                row.ToolTip = "Open these results";
                var entry = e;
                row.Click += (s, a) => _main.OpenHistory(entry);
                _recentPanel.Children.Add(Ui.Divider());
                _recentPanel.Children.Add(row);
            }
        }
    }
}
