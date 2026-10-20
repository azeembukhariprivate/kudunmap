using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using Kudunmap.Controls;
using Kudunmap.Core;

namespace Kudunmap.Views
{
    /// <summary>Shows a running scan (progress and live output) and finished results (hosts, ports, vulnerabilities).</summary>
    public sealed class ResultsView : Grid
    {
        private readonly MainWindow _main;
        private readonly Border _top = new Border();
        private readonly Border _content = new Border();
        private readonly List<RadioButton> _tabs = new List<RadioButton>();
        private readonly Border _vulnChipHost = new Border { Margin = new Thickness(6, 0, 0, 0) };

        // Hosts & ports
        private readonly Grid _hostsPanel;
        private readonly TextBox _filter = new TextBox { MinHeight = 32, FontSize = 12 };
        private readonly ListBox _hostList = new ListBox().Styled("TableList");
        private readonly StackPanel _hostDetail = new StackPanel();

        // Vulnerabilities
        private readonly Grid _vulnPanel;
        private readonly WrapPanel _vulnFilters = new WrapPanel();
        private readonly TextBlock _vulnersNote = Ui.Subtle(string.Empty, 12, false);
        private readonly ListBox _vulnList = new ListBox().Styled("TableList");
        private readonly Grid _vulnDetail = Ui.Columns(Ui.Star(), Ui.Px(12), Ui.Px(330));
        private readonly Border _vulnEmpty = new Border { Padding = new Thickness(24) };
        private Severity? _severityFilter;

        // Raw output
        private readonly Grid _rawPanel;
        private readonly TextBox _raw = Ui.MonoBox(false);
        private readonly ListBox _foundList = new ListBox().Styled("TableList");
        private readonly TextBlock _foundTitle = Ui.Heading("Found so far", 13);

        // Details
        private readonly StackPanel _details = new StackPanel { Margin = new Thickness(18, 14, 18, 14) };

        // Progress
        private readonly TextBlock _progressTitle = Ui.Heading(string.Empty, 14);
        private readonly TextBlock _progressLeft = Ui.Subtle(string.Empty, 12.5, false);
        private readonly TextBlock _progressPercent = Ui.Text(string.Empty, 20, bold: true);
        private readonly ProgressBar _progressBar = new ProgressBar { Height = 6, Minimum = 0, Maximum = 100 };
        private readonly StackPanel _steps = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 10, 0, 0) };
        private List<(Phase Phase, string Name)> _stepList = new List<(Phase, string)>();

        private ScanResult _result;
        private ScanOptions _options;
        private HistoryEntry _entry;
        private List<Vulnerability> _vulns = new List<Vulnerability>();

        public ResultsView(MainWindow main)
        {
            _main = main;
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            RowDefinitions.Add(new RowDefinition { Height = new GridLength(12) });
            RowDefinitions.Add(new RowDefinition());

            Children.Add(_top.At(0));

            var tabBar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(12, 0, 12, 0) };
            AddTab(tabBar, "Hosts & ports");
            AddTab(tabBar, Ui.Row(new TextBlock { Text = "Vulnerabilities", VerticalAlignment = VerticalAlignment.Center }, _vulnChipHost));
            AddTab(tabBar, "Raw output");
            AddTab(tabBar, "Scan details");

            _hostsPanel = BuildHostsPanel();
            _vulnPanel = BuildVulnPanel();
            _rawPanel = BuildRawPanel();

            var card = new Grid();
            card.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            card.RowDefinitions.Add(new RowDefinition());
            card.Children.Add(new Border { BorderThickness = new Thickness(0, 0, 0, 1), Child = tabBar }.Res(Border.BorderBrushProperty, "BorderBrush").At(0));
            card.Children.Add(_content.At(1));
            var cardBorder = Ui.Card(card, 0);
            cardBorder.ClipToBounds = true;
            Children.Add(cardBorder.At(2));

            SelectTab(0);
        }

        private void AddTab(Panel bar, object header)
        {
            var index = _tabs.Count;
            var tab = new RadioButton { Content = header, GroupName = "resultTabs" }.Styled("TabRadio");
            tab.Checked += (s, e) => ShowTab(index);
            _tabs.Add(tab);
            bar.Children.Add(tab);
        }

        public void SelectTab(int index) => _tabs[index].IsChecked = true;

        private void ShowTab(int index)
        {
            switch (index)
            {
                case 0: _content.Child = _hostsPanel; break;
                case 1: _content.Child = _vulnPanel; break;
                case 2: _content.Child = _rawPanel; break;
                default: _content.Child = new ScrollViewer { Content = _details, VerticalScrollBarVisibility = ScrollBarVisibility.Auto }; break;
            }
        }

        // ================================================================== building the tabs

        private Grid BuildHostsPanel()
        {
            var grid = Ui.Columns(Ui.Px(430), Ui.Star());

            var left = new Grid();
            left.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            left.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            left.RowDefinitions.Add(new RowDefinition());
            var filterBox = new Grid { Margin = new Thickness(12, 10, 12, 8) };
            filterBox.Children.Add(_filter);
            var hint = Ui.Subtle("Filter hosts…", 12, false).Margin(10, 0, 0, 0);
            hint.IsHitTestVisible = false;
            filterBox.Children.Add(hint);
            _filter.TextChanged += (s, e) =>
            {
                hint.Visibility = _filter.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
                FillHosts();
            };
            left.Children.Add(filterBox.At(0));
            left.Children.Add(Header(new[] { Ui.Px(26), Ui.Px(130), Ui.Star(), Ui.Px(56) }, "", "Address", "Name / OS", "Open").At(1));
            _hostList.SelectionChanged += (s, e) => ShowHost((_hostList.SelectedItem as ListBoxItem)?.Tag as HostInfo);
            left.Children.Add(_hostList.At(2));

            grid.Children.Add(new Border { BorderThickness = new Thickness(0, 0, 1, 0), Child = left }.Res(Border.BorderBrushProperty, "BorderBrush").At(0, 0));
            grid.Children.Add(new ScrollViewer { Content = _hostDetail, VerticalScrollBarVisibility = ScrollBarVisibility.Auto }.At(0, 1));
            return grid;
        }

        private static Grid Header(GridLength[] widths, params string[] titles)
        {
            var g = Ui.Columns(widths);
            for (var i = 0; i < titles.Length; i++)
                g.Children.Add(Ui.Text(titles[i], 12, "SubtleText", bold: true).Margin(i == 0 ? 12 : 0, 8, 8, 8).At(0, i));
            return g.WithBottomLine();
        }

        private Grid BuildVulnPanel()
        {
            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { MinHeight = 120 });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var note = Ui.Text("These are checks for known problems. \"Matched by version\" means the software version is listed as affected; " +
                               "the fix may already be applied. A clean result doesn't guarantee a system is safe.", 12, wrap: true);
            grid.Children.Add(Ui.Banner("IconInfo", note).Margin(16, 12, 16, 4).At(0));

            var filterRow = Ui.Columns(Ui.Star(), Ui.Auto);
            filterRow.Children.Add(_vulnFilters.At(0, 0));
            filterRow.Children.Add(_vulnersNote.At(0, 1));
            grid.Children.Add(filterRow.Margin(16, 8, 16, 2).At(1));

            grid.Children.Add(Header(VulnColumns, "Severity", "Finding", "Host", "CVE", "Found by").At(2));
            _vulnList.SelectionChanged += (s, e) => ShowVulnerability((_vulnList.SelectedItem as ListBoxItem)?.Tag as Vulnerability);
            grid.Children.Add(_vulnList.At(3));
            grid.Children.Add(_vulnEmpty.At(3));
            grid.Children.Add(_vulnDetail.Margin(16, 12, 16, 16).At(4));
            return grid;
        }

        private static readonly GridLength[] VulnColumns = { Ui.Px(100), Ui.Star(), Ui.Px(170), Ui.Px(160), Ui.Px(150) };

        private Grid BuildRawPanel()
        {
            var grid = Ui.Columns(Ui.Star(), Ui.Px(420));
            grid.Children.Add(_raw.At(0, 0));
            var right = new Grid();
            right.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            right.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            right.RowDefinitions.Add(new RowDefinition());
            right.Children.Add(_foundTitle.Margin(12, 12, 12, 6).At(0));
            right.Children.Add(Header(new[] { Ui.Px(26), Ui.Px(130), Ui.Star() }, "", "Address", "Open ports").At(1));
            right.Children.Add(_foundList.At(2));
            grid.Children.Add(new Border { BorderThickness = new Thickness(1, 0, 0, 0), Child = right }.Res(Border.BorderBrushProperty, "BorderBrush").At(0, 1));
            return grid;
        }

        // ================================================================== running scan

        public void BeginScan(ScanOptions options)
        {
            _options = options;
            _result = null;
            _entry = null;
            _vulns = new List<Vulnerability>();
            _raw.Clear();
            _foundList.Items.Clear();
            _foundTitle.Text = "Found so far";
            _hostList.Items.Clear();
            _hostDetail.Children.Clear();
            _hostDetail.Children.Add(Placeholder("Results appear here when the scan finishes. Live output is on the Raw output tab."));
            _vulnChipHost.Child = null;
            FillVulnerabilities();
            FillDetails();

            _stepList = ProgressTracker.StepsFor(options);
            _progressTitle.Text = options.Title + " · " + TargetText(options);
            _progressPercent.Text = string.Empty;
            _progressLeft.Text = "Starting…";
            _progressBar.Value = 0;
            _progressBar.IsIndeterminate = true;
            UpdateSteps(Phase.Starting);

            var head = Ui.Columns(Ui.Auto, Ui.Auto, Ui.Star(), Ui.Auto, Ui.Auto);
            head.Children.Add(_progressTitle.At(0, 0));
            head.Children.Add(Ui.Chip("Scanning…").Margin(12, 0, 0, 0).At(0, 1));
            head.Children.Add(_progressLeft.Margin(0, 0, 14, 0).At(0, 3));
            head.Children.Add(_progressPercent.At(0, 4));
            _top.Child = Ui.Card(Ui.Column(head, _progressBar.Margin(0, 10, 0, 0), _steps), 16);
            SelectTab(2);
        }

        private static string TargetText(ScanOptions o) =>
            string.IsNullOrEmpty(o.TargetFile) ? o.Targets.Trim() : Path.GetFileName(o.TargetFile);

        public void AppendOutput(string text)
        {
            var atEnd = _raw.VerticalOffset + _raw.ViewportHeight >= _raw.ExtentHeight - 4;
            _raw.AppendText(text);
            if (atEnd) _raw.ScrollToEnd();
        }

        public void UpdateProgress(ProgressTracker t)
        {
            _progressLeft.Text = t.Remaining.HasValue
                ? t.Activity + " · about " + FriendlyTime(t.Remaining.Value) + " left"
                : t.Activity + "…";
            if (t.Percent > 0 && t.Phase != Phase.Finishing)
            {
                _progressBar.IsIndeterminate = false;
                _progressBar.Value = t.Percent;
                _progressPercent.Text = Math.Round(t.Percent).ToString(CultureInfo.CurrentCulture) + "%";
            }
            else
            {
                _progressBar.IsIndeterminate = true;
                _progressPercent.Text = string.Empty;
            }
            UpdateSteps(t.Phase);

            _foundList.Items.Clear();
            foreach (var pair in t.Found)
            {
                var g = Ui.Columns(Ui.Px(26), Ui.Px(130), Ui.Star());
                g.Children.Add(Ui.Dot().Margin(12, 0, 0, 0).At(0, 0));
                g.Children.Add(Ui.Mono(pair.Key, 12.5).At(0, 1));
                g.Children.Add(Ui.Mono(pair.Value.Count == 0 ? "–" : string.Join(", ", pair.Value.Select(p => p.Split('/')[0])), 12, "SubtleText").At(0, 2));
                _foundList.Items.Add(new ListBoxItem { Content = g, MinHeight = 32 });
            }
        }

        private void UpdateSteps(Phase current)
        {
            _steps.Children.Clear();
            var currentIndex = _stepList.FindIndex(s => s.Phase == current);
            if (current == Phase.Finishing) currentIndex = _stepList.Count;
            for (var i = 0; i < _stepList.Count; i++)
            {
                string brush, mark;
                if (i < currentIndex) { brush = "OkText"; mark = "✓"; }
                else if (i == currentIndex) { brush = "LinkText"; mark = "●"; }
                else { brush = "SubtleText"; mark = "○"; }
                if (i > 0) _steps.Children.Add(Ui.Subtle("›", 12, false).Margin(10, 0, 10, 0));
                var t = new TextBlock { FontSize = 12, VerticalAlignment = VerticalAlignment.Center };
                t.Inlines.Add(new Run(mark + " ") { FontWeight = FontWeights.Bold });
                t.Inlines.Add(new Run(_stepList[i].Name));
                t.Res(TextBlock.ForegroundProperty, brush);
                _steps.Children.Add(t);
            }
        }

        private static string FriendlyTime(TimeSpan t)
        {
            if (t.TotalHours >= 1) return $"{(int)t.TotalHours} h {t.Minutes} min";
            if (t.TotalMinutes >= 1) return $"{(int)t.TotalMinutes} min {t.Seconds} s";
            return $"{Math.Max(1, t.Seconds)} seconds";
        }

        /// <summary>The scan stopped without results (cancelled or failed). The raw output stays visible.</summary>
        public void ShowStopped(ScanOptions options, string title, string message, bool failed)
        {
            _options = options;
            var g = Ui.Columns(Ui.Star(), Ui.Auto, Ui.Auto);
            g.Children.Add(Ui.Column(Ui.Row(Ui.Heading(title, 14), Ui.Chip(failed ? "Failed" : "Cancelled", failed ? Tone.Bad : Tone.Neutral).Margin(12, 0, 0, 0)),
                Ui.Text(message, 12.5, wrap: true).Margin(0, 6, 0, 0)).At(0, 0));
            g.Children.Add(Ui.Small(Ui.Button("Change options", "IconBack", click: (s, e) => _main.ShowSetup())).Margin(12, 0, 0, 0).At(0, 1));
            g.Children.Add(Ui.Small(Ui.Button("Try again", "IconRefresh", "PrimaryButton", (s, e) => _main.ScanAgain(_options))).Margin(8, 0, 0, 0).At(0, 2));
            _top.Child = Ui.Card(g, 16);
            _foundTitle.Text = "Found before stopping";
            SelectTab(2);
        }

        // ================================================================== finished results

        public void ShowResult(ScanResult result, ScanOptions options, HistoryEntry entry, string output)
        {
            _result = result;
            _options = options;
            _entry = entry;
            _vulns = result.Vulnerabilities;
            if (output != null && _raw.Text.Length == 0) _raw.Text = output;
            _foundTitle.Text = "Hosts";
            FillFoundFromResult();

            BuildSummary();
            _filter.Text = string.Empty;
            FillHosts();
            _severityFilter = null;
            FillVulnerabilities();
            FillDetails();
            _vulnChipHost.Child = _vulns.Count > 0
                ? Ui.Chip(_vulns.Count.ToString(CultureInfo.CurrentCulture), _vulns.Any(v => v.Severity <= Severity.High) ? Tone.Bad : Tone.Warn)
                : null;

            SelectTab(_vulns.Count > 0 && (options.HasScript("vuln") || options.Vulners) ? 1 : 0);
        }

        private void FillFoundFromResult()
        {
            _foundList.Items.Clear();
            foreach (var h in _result.UpHosts.OrderBy(h => h.Address, new AddressComparer()))
            {
                var g = Ui.Columns(Ui.Px(26), Ui.Px(130), Ui.Star());
                g.Children.Add(Ui.Dot().Margin(12, 0, 0, 0).At(0, 0));
                g.Children.Add(Ui.Mono(h.Address, 12.5).At(0, 1));
                var ports = h.OpenPorts.Select(p => p.Number.ToString(CultureInfo.InvariantCulture)).ToList();
                g.Children.Add(Ui.Mono(ports.Count == 0 ? "–" : string.Join(", ", ports), 12, "SubtleText").At(0, 2));
                _foundList.Items.Add(new ListBoxItem { Content = g, MinHeight = 32 });
            }
        }

        private void BuildSummary()
        {
            var r = _result;
            var g = Ui.Columns(Ui.Star(), Ui.Auto, Ui.Auto, Ui.Auto, Ui.Auto, Ui.Auto, Ui.Auto, Ui.Auto, Ui.Auto);
            var title = Ui.Column(Ui.Text(_options.Title + " · " + TargetText(_options), 14, bold: true),
                Ui.Mono(r.Args, 11.5, "SubtleText").Tip(r.Args));
            g.Children.Add(title.At(0, 0));

            var col = 1;
            void Stat(UIElement e) => g.Children.Add(((FrameworkElement)e).Margin(26, 0, 0, 0).At(0, col++));
            if (_options.HasScript("vuln") || _options.Vulners)
            {
                var critical = _vulns.Count(v => v.Severity == Severity.Critical);
                var high = _vulns.Count(v => v.Severity == Severity.High);
                var medium = _vulns.Count(v => v.Severity == Severity.Medium);
                if (critical > 0) Stat(Ui.Stat(critical.ToString(CultureInfo.CurrentCulture), "critical", "BadText"));
                Stat(Ui.Stat(high.ToString(CultureInfo.CurrentCulture), "high", high > 0 ? "BadText" : "Text"));
                Stat(Ui.Stat(medium.ToString(CultureInfo.CurrentCulture), "medium", medium > 0 ? "WarnText" : "Text"));
                Stat(Ui.Stat(_vulns.Select(v => v.HostAddress).Distinct().Count().ToString(CultureInfo.CurrentCulture), "hosts affected"));
            }
            else
            {
                Stat(Ui.Stat(r.HostsUp.ToString(CultureInfo.CurrentCulture), "hosts online"));
                Stat(Ui.Stat(Math.Max(0, r.HostsTotal - r.HostsUp).ToString(CultureInfo.CurrentCulture), "no reply"));
                Stat(Ui.Stat(r.OpenPortCount.ToString(CultureInfo.CurrentCulture), "open ports"));
                Stat(Ui.Stat(Exporter.Duration(r.ElapsedSeconds), "scan time"));
            }

            var finished = r.Finished == DateTime.MinValue ? r.Started : r.Finished;
            g.Children.Add(Ui.Chip("✓ Finished · " + HistoryEntry.FriendlyDate(finished), Tone.Ok).Margin(26, 0, 0, 0).At(0, 5));

            var export = Ui.Small(Ui.Button("Export", "IconExport"));
            export.Click += (s, e) => ShowExportMenu(export);
            g.Children.Add(Ui.Small(Ui.Button("New scan", "IconBack", click: (s, e) => _main.ShowSetup())).Margin(16, 0, 0, 0).At(0, 6));
            g.Children.Add(Ui.Small(Ui.Button("Scan again", "IconRefresh", click: (s, e) => _main.ScanAgain(_options))).Margin(8, 0, 0, 0).At(0, 7));
            g.Children.Add(export.Margin(8, 0, 0, 0).At(0, 8));
            _top.Child = Ui.Card(g, 14);
        }

        private void ShowExportMenu(FrameworkElement anchor)
        {
            var menu = new ContextMenu { PlacementTarget = anchor, Placement = PlacementMode.Bottom };
            void Item(string header, Action action)
            {
                var mi = new MenuItem { Header = header };
                mi.Click += (s, e) => Export(action);
                menu.Items.Add(mi);
            }

            var baseName = AppPaths.SafeFileName(_options.Title + " " + TargetText(_options).Replace('/', '-'), 50) + " " +
                           (_result.Started == DateTime.MinValue ? DateTime.Now : _result.Started).ToString("yyyy-MM-dd HHmm");
            Item("HTML report…", () => Save("HTML report", baseName + ".html", "HTML report|*.html",
                p => Exporter.SaveHtml(_result, _options.Title + " · " + TargetText(_options), p), true));
            Item("Hosts and ports (CSV)…", () => Save("CSV", baseName + ".csv", "CSV file|*.csv", p => Exporter.SaveCsv(_result, p), false));
            if (_vulns.Count > 0)
                Item("Vulnerabilities (CSV)…", () => Save("CSV", baseName + " vulnerabilities.csv", "CSV file|*.csv",
                    p => Exporter.SaveVulnerabilitiesCsv(_result, p), false));
            menu.Items.Add(new Separator());
            Item("Nmap XML…", () => Save("Nmap XML", baseName + ".xml", "Nmap XML|*.xml", p => File.Copy(_entry.XmlPath, p, true), false));
            Item("Nmap text output…", () => Save("Text", baseName + ".txt", "Text file|*.txt", p => File.WriteAllText(p, _raw.Text), false));
            menu.IsOpen = true;
        }

        private void Export(Action action)
        {
            try { action(); }
            catch (Exception ex) { Dialogs.Error(Window.GetWindow(this), "Couldn't save the file:\n\n" + ex.Message); }
        }

        private void Save(string what, string fileName, string filter, Action<string> write, bool open)
        {
            var path = Dialogs.SaveFile(Window.GetWindow(this), "Export " + what, fileName, filter);
            if (path == null) return;
            write(path);
            if (open)
            {
                try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
                catch { /* no default program */ }
            }
            _main.SetStatus("Saved " + Path.GetFileName(path));
        }

        // ------------------------------------------------------------------ hosts & ports

        private void FillHosts()
        {
            if (_result == null) return;
            var previous = (_hostList.SelectedItem as ListBoxItem)?.Tag as HostInfo;
            _hostList.Items.Clear();
            var filter = _filter.Text.Trim();
            var hosts = _result.UpHosts.OrderBy(h => h.Address, new AddressComparer())
                .Where(h => filter.Length == 0 || Matches(h, filter)).ToList();

            foreach (var h in hosts)
            {
                var g = Ui.Columns(Ui.Px(26), Ui.Px(130), Ui.Star(), Ui.Px(56));
                g.Children.Add(Ui.Dot().Margin(12, 0, 0, 0).At(0, 0));
                g.Children.Add(Ui.Mono(h.Address, 12.5).At(0, 1));
                var name = Ui.Column(Ui.Text(string.IsNullOrEmpty(h.Name) ? "(no name)" : h.Name, 13, string.IsNullOrEmpty(h.Name) ? "SubtleText" : "Text"));
                if (!string.IsNullOrEmpty(h.OsGuess)) name.Children.Add(Ui.Subtle(h.OsGuess, 11.5, false));
                g.Children.Add(name.Margin(0, 6, 8, 6).At(0, 2));
                var open = h.OpenPorts.Count();
                g.Children.Add(Ui.Text(open == 0 ? "–" : open.ToString(CultureInfo.CurrentCulture), 13, open == 0 ? "SubtleText" : "Text")
                    .Margin(0, 0, 12, 0).At(0, 3));
                ((TextBlock)g.Children[3]).TextAlignment = TextAlignment.Right;
                var item = new ListBoxItem { Content = g, Tag = h, MinHeight = 40, ContextMenu = HostMenu(h) };
                _hostList.Items.Add(item);
            }

            if (hosts.Count == 0)
            {
                _hostDetail.Children.Clear();
                _hostDetail.Children.Add(Placeholder(_result.HostsUp == 0
                    ? "No hosts answered. They may be switched off, or blocking pings. Try \"Skip ping\" in the options."
                    : "No hosts match the filter."));
                return;
            }

            var select = _hostList.Items.Cast<ListBoxItem>().FirstOrDefault(i => i.Tag == previous) ?? (ListBoxItem)_hostList.Items[0];
            _hostList.SelectedItem = select;
        }

        private static bool Matches(HostInfo h, string filter)
        {
            bool Has(string s) => !string.IsNullOrEmpty(s) && s.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0;
            return Has(h.Address) || Has(h.Name) || Has(h.OsGuess) || Has(h.Vendor) || Has(h.Mac) ||
                   h.Ports.Any(p => Has(p.Number.ToString(CultureInfo.InvariantCulture)) || Has(p.Service) || Has(p.VersionText));
        }

        private void ShowHost(HostInfo h)
        {
            _hostDetail.Children.Clear();
            if (h == null) return;

            var head = Ui.Columns(Ui.Auto, Ui.Star(), Ui.Auto, Ui.Auto);
            head.Children.Add(Ui.Dot().Margin(0, 0, 12, 0).At(0, 0));
            var title = new TextBlock { VerticalAlignment = VerticalAlignment.Center };
            title.Inlines.Add(new Run(h.DisplayName) { FontSize = 16, FontWeight = FontWeights.SemiBold });
            if (!string.IsNullOrEmpty(h.Name)) title.Inlines.Add(new Run("  " + h.Address) { FontSize = 13 });
            title.Res(TextBlock.ForegroundProperty, "Text");
            var info = new[]
            {
                h.OsGuess,
                h.Mac == null ? null : "MAC " + h.Mac + (string.IsNullOrEmpty(h.Vendor) ? string.Empty : " (" + h.Vendor + ")"),
                h.LatencyText,
                h.Distance > 0 ? h.Distance + (h.Distance == 1 ? " hop" : " hops") : null
            }.Where(s => !string.IsNullOrEmpty(s));
            head.Children.Add(Ui.Column(title, Ui.Subtle(string.Join(" · ", info), 12, false)).At(0, 1));
            var web = h.OpenPorts.FirstOrDefault(p => p.LooksLikeWeb);
            if (web != null)
                head.Children.Add(Ui.Small(Ui.Button("Open in browser", "IconExternal", click: (s, e) => OpenWeb(h, web))).Margin(8, 0, 0, 0).At(0, 2));
            head.Children.Add(Ui.Small(Ui.Button("Scan this host…", "IconPlay", click: (s, e) => _main.ScanHost(h.Address))).Margin(8, 0, 0, 0).At(0, 3));
            _hostDetail.Children.Add(head.Margin(16, 14, 16, 12));

            var ports = h.Ports.OrderBy(p => p.Protocol).ThenBy(p => p.Number).ToList();
            if (ports.Count == 0)
            {
                _hostDetail.Children.Add(Placeholder(_options?.Kind == ScanKind.Ping
                    ? "This was a ping sweep, so ports weren't scanned."
                    : "No open ports found on this host."));
            }
            else
            {
                var widths = new[] { Ui.Px(84), Ui.Px(60), Ui.Px(92), Ui.Px(140), Ui.Star() };
                _hostDetail.Children.Add(Header(widths, "Port", "Proto", "State", "Service", "Version"));
                foreach (var p in ports)
                {
                    var g = Ui.Columns(widths);
                    g.Children.Add(Ui.Mono(p.Number.ToString(CultureInfo.InvariantCulture), 12.5).Margin(16, 0, 0, 0).At(0, 0));
                    ((TextBlock)g.Children[0]).FontWeight = FontWeights.SemiBold;
                    g.Children.Add(Ui.Subtle(p.Protocol, 12.5, false).At(0, 1));
                    g.Children.Add(Ui.Chip(p.State, p.IsOpen ? Tone.Ok : Tone.Neutral).At(0, 2));
                    g.Children.Add(Ui.Text(p.ServiceText, 12.5).At(0, 3));
                    var version = Ui.Column(Ui.Text(p.VersionText, 12.5, wrap: true));
                    foreach (var script in p.Scripts.Where(x => x.Id != "vulners"))
                        version.Children.Add(ScriptOutput(script).Margin(0, 4, 0, 0));
                    g.Children.Add(version.Margin(0, 8, 16, 8).At(0, 4));
                    _hostDetail.Children.Add(new Border { Child = g, BorderThickness = new Thickness(0, 0, 0, 1), MinHeight = 36, ContextMenu = PortMenu(h, p) }
                        .Res(Border.BorderBrushProperty, "BorderBrush"));
                }
            }

            if (h.Scripts.Count > 0)
            {
                _hostDetail.Children.Add(Ui.Heading("Host script results", 13).Margin(16, 16, 16, 6));
                foreach (var s in h.Scripts) _hostDetail.Children.Add(ScriptOutput(s).Margin(16, 0, 16, 6));
            }

            if (h.Trace.Count > 0)
            {
                _hostDetail.Children.Add(Ui.Heading("Route", 13).Margin(16, 16, 16, 6));
                foreach (var hop in h.Trace)
                    _hostDetail.Children.Add(Ui.Mono($"{hop.Ttl,3}  {hop.Rtt,8} ms  {hop.Address}  {hop.Host}", 12, "SubtleText").Margin(16, 0, 16, 2));
            }

            _hostDetail.Children.Add(Ui.Banner("IconInfo",
                Ui.Text("Right-click a host or port to copy it, open it in a browser, ping it, or start a new scan on just that host.", 12, wrap: true))
                .Margin(16, 16, 16, 16));
        }

        private static FrameworkElement ScriptOutput(ScriptResult s)
        {
            var t = new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = 11.5 };
            t.Res(TextBlock.FontFamilyProperty, "MonoFont");
            t.Inlines.Add(new Run(s.Id + ": ") { FontWeight = FontWeights.SemiBold });
            t.Inlines.Add(new Run(s.Output));
            t.Res(TextBlock.ForegroundProperty, "SubtleText");
            return t;
        }

        private ContextMenu HostMenu(HostInfo h)
        {
            var menu = new ContextMenu();
            Add(menu, "Copy address", () => Ui.Copy(h.Address));
            if (!string.IsNullOrEmpty(h.Name)) Add(menu, "Copy name", () => Ui.Copy(h.Name));
            var web = h.OpenPorts.FirstOrDefault(p => p.LooksLikeWeb);
            if (web != null) Add(menu, "Open in browser", () => OpenWeb(h, web));
            Add(menu, "Ping", () => Ping(h.Address));
            menu.Items.Add(new Separator());
            Add(menu, "Scan this host…", () => _main.ScanHost(h.Address));
            return menu;
        }

        private ContextMenu PortMenu(HostInfo h, PortInfo p)
        {
            var menu = new ContextMenu();
            Add(menu, "Copy " + HostPort(h.Address, p.Number), () => Ui.Copy(HostPort(h.Address, p.Number)));
            if (!string.IsNullOrEmpty(p.VersionText)) Add(menu, "Copy version", () => Ui.Copy(p.VersionText));
            if (p.LooksLikeWeb) Add(menu, "Open in browser", () => OpenWeb(h, p));
            return menu;
        }

        private static void Add(ContextMenu menu, string header, Action action)
        {
            var mi = new MenuItem { Header = header };
            mi.Click += (s, e) => action();
            menu.Items.Add(mi);
        }

        private static string HostPort(string address, int port) => (address.Contains(":") ? "[" + address + "]" : address) + ":" + port;

        private static void OpenWeb(HostInfo h, PortInfo p)
        {
            var scheme = p.IsHttps ? "https" : "http";
            var port = (scheme == "http" && p.Number == 80) || (scheme == "https" && p.Number == 443) ? string.Empty : ":" + p.Number;
            var host = h.Address.Contains(":") ? "[" + h.Address + "]" : h.Address;
            AppInfo.OpenUrl(scheme + "://" + host + port + "/");
        }

        private static void Ping(string address)
        {
            // Only plain IP addresses are passed to ping.
            if (!Regex.IsMatch(address ?? string.Empty, @"^[0-9A-Fa-f:.]+$")) return;
            try { Process.Start(new ProcessStartInfo("cmd.exe", "/k ping " + address) { UseShellExecute = true }); }
            catch { /* ignore */ }
        }

        private static FrameworkElement Placeholder(string text) =>
            Ui.Subtle(text, 13).Margin(20, 24, 20, 24);

        // ------------------------------------------------------------------ vulnerabilities

        private void FillVulnerabilities()
        {
            _vulnFilters.Children.Clear();
            _vulnList.Items.Clear();
            _vulnDetail.Children.Clear();

            var ranVulnChecks = _options != null && (_options.HasScript("vuln") || _options.Vulners);
            _vulnersNote.Inlines.Clear();
            if (_options != null)
            {
                _vulnersNote.Inlines.Add(new Run("CVE lookup (vulners) was "));
                _vulnersNote.Inlines.Add(new Run(_options.Vulners ? "on" : "off") { FontWeight = FontWeights.SemiBold });
                _vulnersNote.Inlines.Add(new Run(" for this scan"));
            }

            if (_result == null || _vulns.Count == 0)
            {
                _vulnList.Visibility = Visibility.Collapsed;
                _vulnEmpty.Visibility = Visibility.Visible;
                _vulnEmpty.Child = Ui.Subtle(_result == null
                        ? "Findings appear here when the scan finishes."
                        : ranVulnChecks
                            ? "No known vulnerabilities were reported. That doesn't guarantee these systems are safe: only well-known problems are checked."
                            : "This scan didn't check for vulnerabilities. Choose \"Vulnerability check\" on the New scan screen, or switch on the vuln scripts.",
                    13);
                return;
            }

            _vulnList.Visibility = Visibility.Visible;
            _vulnEmpty.Visibility = Visibility.Collapsed;

            void Filter(string label, Severity? severity, int count)
            {
                var t = new ToggleButton { Content = label + " · " + count.ToString(CultureInfo.CurrentCulture), IsChecked = _severityFilter == severity }.Styled("ChipToggle");
                t.Click += (s, e) =>
                {
                    _severityFilter = severity;
                    FillVulnerabilities();
                };
                _vulnFilters.Children.Add(t);
            }

            Filter("All", null, _vulns.Count);
            foreach (Severity s in Enum.GetValues(typeof(Severity)))
            {
                var c = _vulns.Count(v => v.Severity == s);
                if (c > 0 || s == Severity.High || s == Severity.Medium) Filter(s.ToString(), s, c);
            }

            foreach (var v in _vulns.Where(v => _severityFilter == null || v.Severity == _severityFilter))
            {
                var g = Ui.Columns(VulnColumns);
                g.Children.Add(Ui.Chip(v.SeverityText, Ui.ToneFor(v.Severity)).Margin(12, 0, 0, 0).At(0, 0));
                g.Children.Add(Ui.Column(Ui.Text(v.Title, 13, bold: true, wrap: true), Ui.Subtle(v.Note, 11.5, false)).Margin(0, 8, 12, 8).At(0, 1));
                g.Children.Add(Ui.Column(Ui.Mono(v.HostAddress, 12.5), Ui.Subtle((string.IsNullOrEmpty(v.HostName) ? "" : v.HostName + " · ") + v.Where, 11.5, false)).At(0, 2));
                var cves = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                if (v.Cves.Count == 0) cves.Children.Add(Ui.Subtle("no CVE", 12, false));
                foreach (var cve in v.Cves.Take(3))
                {
                    var id = cve;
                    cves.Children.Add(Ui.Link(id + " ↗", (s, e) => AppInfo.OpenUrl(AppInfo.CveUrl(id))));
                }
                g.Children.Add(cves.At(0, 3));
                g.Children.Add(Ui.Mono(v.ScriptId, 11.5, "SubtleText").At(0, 4));
                var item = new ListBoxItem { Content = g, Tag = v, MinHeight = 44 };
                var menu = new ContextMenu();
                Add(menu, "Copy finding", () => Ui.Copy($"{v.SeverityText}: {v.Title} ({v.HostAddress} {v.Where}) {string.Join(" ", v.Cves)}"));
                if (v.Cves.Count > 0) Add(menu, "Copy CVE", () => Ui.Copy(string.Join(" ", v.Cves)));
                item.ContextMenu = menu;
                _vulnList.Items.Add(item);
            }
            if (_vulnList.Items.Count > 0) _vulnList.SelectedIndex = 0;
        }

        private void ShowVulnerability(Vulnerability v)
        {
            _vulnDetail.Children.Clear();
            if (v == null) return;

            var output = Ui.MonoBox(true);
            output.Text = string.IsNullOrWhiteSpace(v.Output) ? "(no text output)" : v.Output.Trim('\r', '\n');
            output.MaxHeight = 180;
            output.Padding = new Thickness(0);
            output.Background = null;
            var left = Ui.Card(Ui.Column(Ui.Heading("What Nmap reported · " + v.ScriptId, 13).Margin(0, 0, 0, 8), output), 14);
            left.Res(Border.BackgroundProperty, "SurfaceAltBg");
            _vulnDetail.Children.Add(left.At(0, 0));

            var links = new StackPanel();
            links.Children.Add(Ui.Heading("Learn more", 13).Margin(0, 0, 0, 6));
            foreach (var cve in v.Cves)
            {
                var id = cve;
                links.Children.Add(Ui.Link(id + " on cve.org ↗", (s, e) => AppInfo.OpenUrl(AppInfo.CveUrl(id))));
            }
            var doc = AppInfo.ScriptDocUrl(v.ScriptId);
            if (doc != null) links.Children.Add(Ui.Link("About the " + v.ScriptId + " script ↗", (s, e) => AppInfo.OpenUrl(doc)));
            links.Children.Add(Ui.Subtle("Links come from the CVE and script names in Nmap's results. Severity is the CVSS score when there is one, " +
                                         "otherwise the script's risk factor.", 11.5).Margin(0, 8, 0, 0));
            var right = Ui.Card(links, 14);
            right.Res(Border.BackgroundProperty, "SurfaceAltBg");
            _vulnDetail.Children.Add(right.At(0, 2));
        }

        // ------------------------------------------------------------------ details

        private void FillDetails()
        {
            _details.Children.Clear();
            if (_result == null)
            {
                _details.Children.Add(Ui.Subtle("Details appear here when the scan finishes.", 13));
                return;
            }

            void Row(string label, string value, bool mono = false)
            {
                var g = Ui.Columns(Ui.Px(160), Ui.Star());
                g.Children.Add(Ui.Subtle(label, 12.5, false).At(0, 0));
                var t = mono ? Ui.Mono(value, 12.5) : Ui.Text(value, 12.5, wrap: true);
                t.TextWrapping = TextWrapping.Wrap;
                g.Children.Add(t.At(0, 1));
                _details.Children.Add(new Border { BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(0, 8, 0, 8), Child = g }
                    .Res(Border.BorderBrushProperty, "BorderBrush"));
            }

            var r = _result;
            Row("Scan type", _options.Title);
            Row("Target", TargetText(_options), true);
            Row("Command", r.Args, true);
            Row("Nmap version", r.NmapVersion);
            Row("Started", r.Started == DateTime.MinValue ? "–" : r.Started.ToString("F", CultureInfo.CurrentCulture));
            Row("Finished", r.Finished == DateTime.MinValue ? "–" : r.Finished.ToString("F", CultureInfo.CurrentCulture));
            Row("Scan time", Exporter.Duration(r.ElapsedSeconds));
            Row("Hosts", $"{r.HostsUp} online, {Math.Max(0, r.HostsTotal - r.HostsUp)} no reply, {r.HostsTotal} scanned");
            Row("Open ports", r.OpenPortCount.ToString(CultureInfo.CurrentCulture));
            if (!string.IsNullOrEmpty(r.Summary)) Row("Nmap's summary", r.Summary);
            Row("Run as", Admin.IsAdmin ? "Administrator" : "Standard user");
            if (_entry != null)
            {
                Row("Saved in", _entry.Folder, true);
                _details.Children.Add(Ui.Small(Ui.Button("Open folder", "IconFolder", click: (s, e) => AppInfo.OpenFolder(_entry.Folder))).Margin(0, 12, 0, 0));
                ((FrameworkElement)_details.Children[_details.Children.Count - 1]).HorizontalAlignment = HorizontalAlignment.Left;
            }
        }
    }

    internal static class GridExtensions
    {
        public static Grid WithBottomLine(this Grid g)
        {
            var line = Ui.Divider();
            line.VerticalAlignment = VerticalAlignment.Bottom;
            Grid.SetColumnSpan(line, Math.Max(1, g.ColumnDefinitions.Count));
            g.Children.Add(line);
            return g;
        }
    }
}
