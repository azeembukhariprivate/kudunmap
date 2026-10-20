using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Threading;
using Kudunmap.Controls;
using Kudunmap.Core;

namespace Kudunmap.Views
{
    public sealed class MainWindow : Window
    {
        private readonly CommandLine _cmd;
        private readonly Grid _body = new Grid { Margin = new Thickness(16, 0, 16, 16) };
        private readonly SetupView _setup;
        private readonly ResultsView _results;
        private readonly UIElement _missing;

        // Toolbar
        private readonly TextBox _target = new TextBox { BorderThickness = new Thickness(0), Background = null, FontSize = 13.5, Padding = new Thickness(0) };
        private readonly TextBlock _targetHint = Ui.Subtle("IP, name, range or network", 11.5, false);
        private readonly Border _fileChip = new Border { Visibility = Visibility.Collapsed };
        private readonly Button _scanButton;
        private readonly Button _cancelButton;
        private readonly Button _fromFile;

        // Status bar
        private readonly TextBlock _status = Ui.Subtle(string.Empty, 12, false);
        private readonly System.Windows.Shapes.Ellipse _statusDot = Ui.Dot("OffDot");
        private readonly StackPanel _statusRight = new StackPanel { Orientation = Orientation.Horizontal };

        // Running scan
        private NmapRunner _runner;
        private ProgressTracker _tracker;
        private ScanOptions _running;
        private string _xmlPath;
        private readonly ConcurrentQueue<string> _lines = new ConcurrentQueue<string>();
        private readonly DispatcherTimer _flush = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        private DateTime _scanStarted;

        public NmapInstall Nmap { get; private set; }
        public ScanOptions Options { get; private set; }
        private CustomPreset _customPreset;

        public bool IsScanning => _runner != null;

        internal SetupView Setup => _setup;
        internal ResultsView Results => _results;

        public MainWindow(CommandLine cmd)
        {
            _cmd = cmd ?? new CommandLine();
            Dialogs.Prepare(this, "KUDUNMAP");
            Width = 1240;
            Height = 800;
            MinWidth = 980;
            MinHeight = 640;
            if (SystemParameters.WorkArea.Height < 840) WindowState = WindowState.Maximized;

            _scanButton = Ui.Button("Scan", "IconPlay", "PrimaryButton", (s, e) => StartScan());
            _scanButton.Padding = new Thickness(22, 0, 22, 0);
            _cancelButton = Ui.Button("Cancel", "IconStop", click: (s, e) => CancelScan());
            _cancelButton.Res(ForegroundProperty, "BadText");
            _cancelButton.Visibility = Visibility.Collapsed;
            _fromFile = Ui.Button("From file…", "IconFile", click: (s, e) => PickTargetFile());

            var preset = Presets.Find(_cmd.Preset ?? Settings.LastPreset) ?? Presets.Find("services");
            Options = Presets.CreateOptions(preset);
            Options.Targets = _cmd.Targets.Count > 0 ? _cmd.TargetText : Settings.LastTarget;
            var restored = _cmd.OptionsFile != null ? Json.Read<ScanOptions>(_cmd.OptionsFile) : null;
            if (restored != null)
            {
                Options = restored;
                Options.Scripts = Options.Scripts ?? new List<string>();
                try { File.Delete(_cmd.OptionsFile); } catch { /* ignore */ }
            }

            _setup = new SetupView(this);
            _results = new ResultsView(this);
            _missing = BuildMissingView();

            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition());
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.Children.Add(BuildToolbar().At(0));
            root.Children.Add(_body.At(1));
            root.Children.Add(BuildStatusBar().At(2));
            Content = root;

            _target.Text = Options.Targets ?? string.Empty;
            _target.TextChanged += (s, e) => OnTargetChanged();
            _target.KeyDown += (s, e) =>
            {
                if (e.Key == Key.Enter) StartScan();
            };
            UpdateTargetFile();

            _flush.Tick += (s, e) => FlushOutput();
            Closing += OnClosing;
            Loaded += OnLoaded;
            InputBindings.Add(new KeyBinding(new RelayCommand(StartScan), Key.F5, ModifierKeys.None));
        }

        // ================================================================== layout

        private UIElement BuildToolbar()
        {
            var targetGrid = Ui.Columns(Ui.Auto, Ui.Star(), Ui.Auto, Ui.Auto);
            targetGrid.Children.Add(Ui.Subtle("Target", 12, false).Margin(0, 0, 10, 0).At(0, 0));
            _target.Res(Control.FontFamilyProperty, "MonoFont");
            _target.Res(Control.ForegroundProperty, "Text");
            _target.VerticalContentAlignment = VerticalAlignment.Center;
            targetGrid.Children.Add(_target.At(0, 1));
            targetGrid.Children.Add(_fileChip.At(0, 2));
            targetGrid.Children.Add(_targetHint.Margin(10, 0, 0, 0).At(0, 3));

            var targetBox = new Border
            {
                BorderThickness = new Thickness(1, 1, 1, 2),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(12, 0, 12, 0),
                MinHeight = 38,
                Child = targetGrid
            }.Res(Border.BackgroundProperty, "InputBg").Res(Border.BorderBrushProperty, "InputBorder");
            targetBox.MouseLeftButtonDown += (s, e) => _target.Focus();
            _target.GotKeyboardFocus += (s, e) => targetBox.Res(Border.BorderBrushProperty, "Accent");
            _target.LostKeyboardFocus += (s, e) => targetBox.Res(Border.BorderBrushProperty, "InputBorder");

            var grid = Ui.Columns(Ui.Star(), Ui.Auto, Ui.Auto, Ui.Auto, Ui.Auto, Ui.Auto, Ui.Auto, Ui.Auto);
            grid.Margin = new Thickness(16, 12, 16, 12);
            grid.Children.Add(targetBox.At(0, 0));
            grid.Children.Add(_fromFile.Margin(8, 0, 0, 0).At(0, 1));
            var run = new Grid();
            run.Children.Add(_scanButton);
            run.Children.Add(_cancelButton);
            grid.Children.Add(run.Margin(8, 0, 0, 0).At(0, 2));
            grid.Children.Add(Ui.Divider(true).Margin(12, 6, 8, 6).At(0, 3));

            var role = Admin.IsAdmin
                ? Ui.Chip("Administrator", Tone.Ok, "IconShield").Tip("KUDUNMAP is running as administrator, so every scan type is available.")
                : Ui.Chip("Standard user", Tone.Neutral).Tip("Some scans (OS detection, UDP, traceroute) need administrator rights. KUDUNMAP offers to restart when they do.");
            grid.Children.Add(role.Margin(0, 0, 6, 0).At(0, 4));
            grid.Children.Add(Ui.Button("History", "IconHistory", "GhostButton", (s, e) => ShowHistory()).At(0, 5));
            grid.Children.Add(Ui.Button("Compare", "IconCompare", "GhostButton", (s, e) => ShowCompare(null)).At(0, 6));
            grid.Children.Add(Ui.Button("Settings", "IconSettings", "GhostButton", (s, e) => ShowSettings()).At(0, 7));
            return grid;
        }

        private UIElement BuildStatusBar()
        {
            var g = Ui.Columns(Ui.Auto, Ui.Star(), Ui.Auto);
            g.Children.Add(_statusDot.Margin(0, 0, 10, 0).At(0, 0));
            g.Children.Add(_status.At(0, 1));
            g.Children.Add(_statusRight.At(0, 2));
            return new Border { BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(16, 7, 16, 7), Child = g }
                .Res(Border.BorderBrushProperty, "BorderBrush").Res(Border.BackgroundProperty, "SurfaceAltBg");
        }

        private UIElement BuildMissingView()
        {
            var steps = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
            void Step(string n, string title, string text)
            {
                var g = Ui.Columns(Ui.Auto, Ui.Star());
                var num = Ui.Chip(n);
                num.MinWidth = 24;
                num.VerticalAlignment = VerticalAlignment.Top;
                g.Children.Add(num.Margin(0, 1, 12, 0).At(0, 0));
                g.Children.Add(Ui.Column(Ui.Text(title, 13, bold: true), Ui.Subtle(text, 12)).At(0, 1));
                steps.Children.Add(g.Margin(0, 10, 0, 0));
            }
            Step("1", "Download Nmap from nmap.org", "Choose the \"Latest stable release self-installer\" for Windows.");
            Step("2", "Run the Nmap installer", "Keep the Npcap option ticked. Nmap needs it to scan on Windows.");
            Step("3", "Come back and press Check again", "KUDUNMAP finds Nmap automatically. No restart needed.");

            var buttons = Ui.Columns(Ui.Auto, Ui.Auto, Ui.Star(), Ui.Auto);
            buttons.Children.Add(Ui.Button("Open nmap.org download page", "IconExternal", "PrimaryButton", (s, e) => AppInfo.OpenUrl(AppInfo.NmapDownloadUrl)).At(0, 0));
            buttons.Children.Add(Ui.Button("Check again", "IconRefresh", click: (s, e) => FindNmap()).Margin(8, 0, 0, 0).At(0, 1));
            buttons.Children.Add(Ui.Button("Locate nmap.exe…", null, "GhostButton", (s, e) => LocateNmap()).At(0, 3));

            var header = Ui.Row(new LogoMark(52).Res(TextElement.ForegroundProperty, "Accent"),
                Ui.Column(Ui.Heading("Nmap isn't installed yet", 19),
                    Ui.Subtle("KUDUNMAP is the window, Nmap does the scanning. It's free, from the Nmap Project.", 13)).Margin(16, 0, 0, 0));

            var card = Ui.Card(Ui.Column(header, steps, buttons.Margin(0, 22, 0, 0),
                Ui.Divider().Margin(0, 18, 0, 12),
                Ui.Subtle("KUDUNMAP never downloads or installs Nmap itself. The download page opens in your browser, " +
                          "so you get Nmap straight from the Nmap Project.", 11.5)), 30);
            card.Width = 660;
            card.HorizontalAlignment = HorizontalAlignment.Center;
            card.VerticalAlignment = VerticalAlignment.Center;
            return card;
        }

        // ================================================================== startup

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            if (!Settings.NoticeAccepted && !SelfTest.Running)
            {
                if (!InfoWindows.ShowNotice(this, true))
                {
                    Close();
                    return;
                }
                Settings.NoticeAccepted = true;
            }

            _setup.RefreshCustomPresets();
            _setup.RefreshRecent();
            _setup.LoadOptions(Options, Presets.Find(Options.PresetId) != null ? Options.PresetId : null);
            FindNmap();
            if (!SelfTest.Running) CheckForUpdatesQuietly();

            if (_cmd.ScanNow && Nmap != null) Dispatcher.BeginInvoke(new Action(StartScan), DispatcherPriority.ApplicationIdle);
            else _target.Focus();
        }

        public void FindNmap()
        {
            Nmap = NmapLocator.Find(Settings.NmapPath);
            if (IsScanning) return;
            if (Nmap == null)
            {
                Show(_missing);
                SetStatus("Nmap not found · looked in " + string.Join(", ", NmapLocator.SearchedPlaces), "OffDot");
                SetInputsEnabled(false);
            }
            else
            {
                if (_body.Children.Count == 0 || _body.Children[0] == _missing) ShowSetup();
                SetStatus("Ready", "OkText");
                SetInputsEnabled(true);
            }
            SetStatusRight(Nmap == null ? "Nmap not found" : "Nmap " + Nmap.Version);
            _setup.Refresh();
        }

        private void LocateNmap()
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
            FindNmap();
        }

        private async void CheckForUpdatesQuietly()
        {
            if (!Settings.CheckForUpdates) return;
            try
            {
                var info = await UpdateChecker.CheckAsync();
                if (info == null || !info.IsNewer || Settings.SkippedVersion == info.Latest.ToString(3)) return;
                var link = Ui.Link($"KUDUNMAP {info.Latest.ToString(3)} is available", (s, e) => AppInfo.OpenUrl(info.Url));
                var skip = Ui.Link("Skip", (s, e) =>
                {
                    Settings.SkippedVersion = info.Latest.ToString(3);
                    SetStatusRight(Nmap == null ? "Nmap not found" : "Nmap " + Nmap.Version);
                });
                _statusRight.Children.Insert(0, Ui.Row(link, skip.Margin(10, 0, 18, 0)));
            }
            catch
            {
                // Offline or GitHub unavailable: try again next time.
            }
        }

        // ================================================================== navigation

        private void Show(UIElement view)
        {
            if (_body.Children.Count == 1 && _body.Children[0] == view) return;
            _body.Children.Clear();
            _body.Children.Add(view);
        }

        public void ShowSetup()
        {
            if (Nmap == null && !SelfTest.Running)
            {
                Show(_missing);
                return;
            }
            _setup.RefreshRecent();
            _setup.Refresh();
            Show(_setup);
        }

        private void SetInputsEnabled(bool enabled)
        {
            _target.IsEnabled = enabled;
            _fromFile.IsEnabled = enabled;
            _scanButton.IsEnabled = enabled;
        }

        public void SetStatus(string text, string dot = null)
        {
            _status.Text = text;
            if (dot != null) _statusDot.Res(System.Windows.Shapes.Shape.FillProperty, dot);
        }

        private void SetStatusRight(string text)
        {
            _statusRight.Children.Clear();
            _statusRight.Children.Add(Ui.Subtle(text, 12, false));
        }

        // ================================================================== target

        private void OnTargetChanged()
        {
            Options.Targets = _target.Text;
            _setup.Refresh();
        }

        private void PickTargetFile()
        {
            var file = Dialogs.PickFile(this, "Choose a list of targets (one per line)", "Text files|*.txt;*.lst;*.csv|All files|*.*");
            if (file == null) return;
            Options.TargetFile = file;
            UpdateTargetFile();
            _setup.Refresh();
        }

        private void UpdateTargetFile()
        {
            var hasFile = !string.IsNullOrEmpty(Options.TargetFile);
            _target.Visibility = hasFile ? Visibility.Collapsed : Visibility.Visible;
            _targetHint.Visibility = hasFile ? Visibility.Collapsed : Visibility.Visible;
            _fileChip.Visibility = hasFile ? Visibility.Visible : Visibility.Collapsed;
            if (!hasFile)
            {
                _fileChip.Child = null;
                return;
            }

            var clear = Ui.Button(string.Empty, "IconClose", "GhostButton", (s, e) =>
            {
                Options.TargetFile = null;
                UpdateTargetFile();
                _setup.Refresh();
            });
            clear.MinHeight = 24;
            clear.Padding = new Thickness(4, 0, 4, 0);
            clear.ToolTip = "Stop using this file";
            _fileChip.Child = Ui.Row(Ui.Chip(Path.GetFileName(Options.TargetFile), Tone.Accent, "IconFile").Tip(Options.TargetFile), clear.Margin(4, 0, 0, 0));
        }

        public void SetTarget(string target)
        {
            Options.TargetFile = null;
            UpdateTargetFile();
            _target.Text = target;
            _target.CaretIndex = _target.Text.Length;
        }

        // ================================================================== presets

        public void SelectPreset(Preset p)
        {
            var targets = Options.Targets;
            var file = Options.TargetFile;
            Options = Presets.CreateOptions(p);
            Options.Targets = targets;
            Options.TargetFile = file;
            _customPreset = null;
            Settings.LastPreset = p.Id;
            _setup.LoadOptions(Options, p.Id);
        }

        public void SelectCustomPreset(CustomPreset cp)
        {
            var targets = Options.Targets;
            var file = Options.TargetFile;
            Options = cp.Options.Clone();
            Options.Title = cp.Name;
            if (string.IsNullOrWhiteSpace(Options.Targets) && string.IsNullOrEmpty(Options.TargetFile))
            {
                Options.Targets = targets;
                Options.TargetFile = file;
            }
            _customPreset = cp;
            _target.Text = Options.Targets ?? string.Empty;
            UpdateTargetFile();
            _setup.LoadOptions(Options, null, cp);
        }

        public void CopyCommand()
        {
            Ui.Copy(CommandBuilder.CopyableCommand(Options, Admin.IsAdmin));
            SetStatus("Command copied. Paste it into a terminal to run the same scan with Nmap directly.");
        }

        // ================================================================== admin

        public void RestartAsAdmin(bool scanNow = false)
        {
            if (IsScanning && !Dialogs.Confirm(this, "A scan is running. Stop it and restart KUDUNMAP as administrator?")) return;

            var args = new List<string>();
            try
            {
                var file = Path.Combine(AppPaths.Running, "restart-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".json");
                Json.Write(file, Options);
                args.Add("--options");
                args.Add(file);
            }
            catch
            {
                args.Add("--preset");
                args.Add(Options.PresetId);
            }
            if (string.IsNullOrEmpty(Options.TargetFile) && CommandBuilder.ValidateTargets(Options.Targets) == null)
                args.AddRange(CommandBuilder.SplitTargets(Options.Targets));
            if (scanNow) args.Add("--scan");

            if (!Admin.RestartElevated(args))
            {
                SetStatus("Restart as administrator was cancelled.");
                return;
            }
            _runner?.Cancel();
            _runner = null;
            Application.Current.Shutdown();
        }

        // ================================================================== scanning

        public void StartScan()
        {
            if (IsScanning) return;
            if (Nmap == null)
            {
                FindNmap();
                if (Nmap == null) return;
            }

            var o = Options.Clone();
            if (!string.IsNullOrEmpty(o.TargetFile))
            {
                if (!File.Exists(o.TargetFile))
                {
                    Dialogs.Error(this, "The target file can't be found:\n\n" + o.TargetFile);
                    return;
                }
            }
            else
            {
                var error = CommandBuilder.ValidateTargets(o.Targets);
                if (error != null)
                {
                    Dialogs.Error(this, error);
                    _target.Focus();
                    return;
                }
            }

            if (o.Kind != ScanKind.Ping && o.Ports == PortMode.Custom)
            {
                var portError = CommandBuilder.ValidatePorts(o.CustomPorts);
                if (portError != null)
                {
                    Dialogs.Error(this, portError);
                    return;
                }
            }

            var reasons = o.AdminReasons();
            if (reasons.Count > 0 && !Admin.IsAdmin)
            {
                if (Dialogs.Confirm(this, "This scan needs administrator rights for " + string.Join(", ", reasons) + ".\n\n" +
                                          "Restart KUDUNMAP as administrator and start the scan?"))
                    RestartAsAdmin(true);
                return;
            }

            if (o.UsesAdvancedScripts &&
                !Dialogs.Confirm(this, "Advanced scripts are on (" + string.Join(", ", o.Scripts.Where(s => ScanOptions.AdvancedCategories.Contains(s))) + ").\n\n" +
                                       "They can lock accounts, crash services or be seen as an attack. " + InfoWindows.PermissionRule + "\n\nStart the scan?"))
                return;

            Settings.LastTarget = o.Targets ?? string.Empty;
            _xmlPath = Path.Combine(AppPaths.Running, "scan-" + Guid.NewGuid().ToString("N") + ".xml");
            var args = CommandBuilder.BuildArguments(o, Admin.IsAdmin, _xmlPath);

            _running = o;
            _tracker = new ProgressTracker();
            while (_lines.TryDequeue(out _)) { }
            _runner = new NmapRunner();
            _runner.Line += line => _lines.Enqueue(line);
            _runner.Exited += code => Dispatcher.BeginInvoke(new Action(() => OnScanExited(code)));

            _results.BeginScan(o);
            Show(_results);
            _scanButton.Visibility = Visibility.Collapsed;
            _cancelButton.Visibility = Visibility.Visible;
            _target.IsEnabled = false;
            _fromFile.IsEnabled = false;
            _scanStarted = DateTime.Now;
            SetStatus("Scanning · started " + _scanStarted.ToString("HH:mm"), "LinkText");
            SetStatusRight(Settings.NotifyWhenDone ? "You'll get a Windows notification when it finishes" : "Nmap " + Nmap.Version);

            try
            {
                _runner.Start(Nmap.Path, args, AppPaths.Running);
                _flush.Start();
            }
            catch (Exception ex)
            {
                _runner = null;
                RestoreToolbar();
                _results.ShowStopped(o, "Nmap couldn't start", ex.Message, true);
                SetStatus("Nmap couldn't start", "BadText");
            }
        }

        public void CancelScan()
        {
            if (!IsScanning) return;
            _cancelButton.IsEnabled = false;
            SetStatus("Stopping Nmap…");
            _runner.Cancel();
        }

        private void FlushOutput()
        {
            if (_tracker == null) return;
            var sb = new StringBuilder();
            var changed = false;
            while (_lines.TryDequeue(out var line))
            {
                sb.AppendLine(line);
                changed |= _tracker.Feed(line);
            }
            if (sb.Length > 0) _results.AppendOutput(sb.ToString());
            if (changed) _results.UpdateProgress(_tracker);
            if (IsScanning)
                SetStatus($"Scanning · {_tracker.Found.Count} host{(_tracker.Found.Count == 1 ? "" : "s")} found so far · started {_scanStarted:HH:mm}", "LinkText");
        }

        private void OnScanExited(int code)
        {
            var runner = _runner;
            if (runner == null) return;
            _flush.Stop();
            FlushOutput();
            _runner = null;
            RestoreToolbar();

            var options = _running;
            var output = runner.Output;
            runner.Dispose();

            if (runner.Cancelled)
            {
                _results.ShowStopped(options, "Scan cancelled", "Nmap was stopped. The output so far is below.", false);
                SetStatus("Scan cancelled", "OffDot");
                TryDelete(_xmlPath);
                return;
            }

            ScanResult result = null;
            string problem = null;
            try
            {
                result = NmapXml.Load(_xmlPath);
                if (!result.Completed) problem = string.IsNullOrEmpty(result.ErrorMessage) ? "Nmap reported an error." : result.ErrorMessage;
            }
            catch (Exception)
            {
                problem = $"Nmap stopped without results (exit code {code}).";
            }

            if (problem != null)
            {
                var hint = NmapRunner.Explain(output);
                _results.ShowStopped(options, "The scan didn't finish", (hint ?? problem) + " Nmap's output is below.", true);
                SetStatus("The scan didn't finish", "BadText");
                TryDelete(_xmlPath);
                Notifier.Show(this, "Scan didn't finish", options.Title + " · " + (hint ?? problem));
                return;
            }

            HistoryEntry entry = null;
            try { entry = History.Save(options, result, _xmlPath, output); }
            catch (Exception ex) { SetStatus("Couldn't save to History: " + ex.Message); }
            TryDelete(_xmlPath);

            _results.ShowResult(result, options, entry, output);
            var vulns = result.Vulnerabilities.Count;
            var summary = $"{result.HostsUp} host{(result.HostsUp == 1 ? "" : "s")} online · {result.OpenPortCount} open port{(result.OpenPortCount == 1 ? "" : "s")}" +
                          (vulns > 0 ? $" · {vulns} finding{(vulns == 1 ? "" : "s")}" : string.Empty);
            SetStatus("Done · " + summary, "OkText");
            SetStatusRight("Nmap " + Nmap?.Version);
            Notifier.Show(this, options.Title + " finished", summary);
        }

        private void RestoreToolbar()
        {
            _flush.Stop();
            _scanButton.Visibility = Visibility.Visible;
            _cancelButton.Visibility = Visibility.Collapsed;
            _cancelButton.IsEnabled = true;
            _target.IsEnabled = true;
            _fromFile.IsEnabled = true;
        }

        private static void TryDelete(string path)
        {
            try { if (path != null && File.Exists(path)) File.Delete(path); }
            catch { /* ignore */ }
        }

        public void ScanAgain(ScanOptions o)
        {
            Options = o.Clone();
            _target.Text = Options.Targets ?? string.Empty;
            UpdateTargetFile();
            _setup.LoadOptions(Options, Presets.Find(Options.PresetId) != null && _customPreset == null ? Options.PresetId : null, _customPreset);
            StartScan();
        }

        public void ScanHost(string address)
        {
            SetTarget(address);
            ShowSetup();
            _target.Focus();
            SetStatus("Target set to " + address + ". Pick a scan type and press Scan.");
        }

        // ================================================================== history, compare, settings

        public void ShowHistory()
        {
            var window = new HistoryWindow(this);
            window.Show();
        }

        public void ShowCompare(HistoryEntry newer)
        {
            var entries = History.List();
            if (entries.Count < 2)
            {
                Dialogs.Info(this, "Compare needs at least two saved scans. Run the same scan again later to see what changed.");
                return;
            }
            new CompareWindow(this, entries, newer).Show();
        }

        public void OpenHistory(HistoryEntry entry)
        {
            if (IsScanning)
            {
                Dialogs.Info(this, "Wait for the running scan to finish, or cancel it, before opening saved results.");
                return;
            }
            try
            {
                var result = History.Load(entry);
                var options = entry.Options ?? Presets.CreateOptions(Presets.Find(entry.PresetId) ?? Presets.Find("services"));
                options.Title = entry.Title;
                if (string.IsNullOrEmpty(options.Targets) && string.IsNullOrEmpty(options.TargetFile)) options.Targets = entry.Targets;
                _results.BeginScan(options);
                _results.ShowResult(result, options, entry, History.LoadOutput(entry));
                Show(_results);
                SetStatus("Saved scan from " + entry.WhenText + " · " + entry.Summary, "OkText");
                Activate();
            }
            catch (Exception ex)
            {
                Dialogs.Error(this, "Couldn't open these results:\n\n" + ex.Message);
            }
        }

        private void ShowSettings()
        {
            new SettingsWindow(this, () => Nmap, FindNmap).ShowDialog();
        }

        // ================================================================== closing

        private void OnClosing(object sender, CancelEventArgs e)
        {
            if (!IsScanning) return;
            if (!Dialogs.Confirm(this, "A scan is still running. Stop it and close KUDUNMAP?"))
            {
                e.Cancel = true;
                return;
            }
            _runner.Cancel();
            _runner = null;
        }
    }

    /// <summary>A minimal ICommand for keyboard shortcuts.</summary>
    public sealed class RelayCommand : ICommand
    {
        private readonly Action _action;
        public RelayCommand(Action action) => _action = action;
        public event EventHandler CanExecuteChanged { add { } remove { } }
        public bool CanExecute(object parameter) => true;
        public void Execute(object parameter) => _action();
    }
}
