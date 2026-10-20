using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using Kudunmap.Controls;
using Kudunmap.Core;

namespace Kudunmap.Views
{
    /// <summary>All saved scans: open, compare, delete.</summary>
    public sealed class HistoryWindow : Window
    {
        private readonly MainWindow _main;
        private readonly ListBox _list = new ListBox().Styled("TableList");
        private readonly TextBlock _count = Ui.Subtle(string.Empty, 12, false);
        private readonly Button _open;
        private readonly Button _compare;
        private readonly Button _delete;
        private static readonly GridLength[] Widths = { Ui.Px(170), Ui.Px(200), Ui.Star(), Ui.Px(260) };

        public HistoryWindow(MainWindow main)
        {
            _main = main;
            Width = 960;
            Height = 600;
            MinWidth = 720;
            MinHeight = 400;
            ShowInTaskbar = false;
            Dialogs.Prepare(this, "History", main);

            _open = Ui.Button("Open", "IconFolder", "PrimaryButton", (s, e) => OpenSelected());
            _compare = Ui.Button("Compare with an earlier scan", "IconCompare", click: (s, e) => CompareSelected());
            _delete = Ui.Button("Delete", "IconTrash", "GhostButton", (s, e) => DeleteSelected());

            var header = Ui.Columns(Ui.Star(), Ui.Auto);
            header.Children.Add(Ui.Column(Ui.Heading("History", 20), _count.Margin(0, 2, 0, 0)).At(0, 0));
            header.Children.Add(Ui.Link("Open the History folder", (s, e) => AppInfo.OpenFolder(AppPaths.History)).At(0, 1));

            var cols = Ui.Columns(Widths);
            var titles = new[] { "When", "Scan type", "Target", "Result" };
            for (var i = 0; i < titles.Length; i++) cols.Children.Add(Ui.Text(titles[i], 12, "SubtleText", bold: true).Margin(i == 0 ? 14 : 0, 8, 8, 8).At(0, i));

            var table = new Grid();
            table.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            table.RowDefinitions.Add(new RowDefinition());
            table.Children.Add(new Border { BorderThickness = new Thickness(0, 0, 0, 1), Child = cols }.Res(Border.BorderBrushProperty, "BorderBrush").At(0));
            table.Children.Add(_list.At(1));
            var card = Ui.Card(table, 0);
            card.ClipToBounds = true;

            var buttons = Ui.Row(_open, _compare.Margin(8, 0, 0, 0), _delete.Margin(8, 0, 0, 0));
            var root = new Grid { Margin = new Thickness(20) };
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition());
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.Children.Add(header.Margin(0, 0, 0, 14).At(0));
            root.Children.Add(card.At(1));
            root.Children.Add(buttons.Margin(0, 14, 0, 0).At(2));
            Content = root;

            _list.SelectionChanged += (s, e) => UpdateButtons();
            _list.MouseDoubleClick += (s, e) => OpenSelected();
            _list.KeyDown += (s, e) =>
            {
                if (e.Key == Key.Enter) OpenSelected();
                if (e.Key == Key.Delete) DeleteSelected();
            };
            Fill();
        }

        private HistoryEntry Selected => (_list.SelectedItem as ListBoxItem)?.Tag as HistoryEntry;

        private void Fill()
        {
            _list.Items.Clear();
            List<HistoryEntry> entries;
            try { entries = History.List(); }
            catch { entries = new List<HistoryEntry>(); }

            foreach (var e in entries)
            {
                var g = Ui.Columns(Widths);
                g.Children.Add(Ui.Text(e.WhenText, 12.5).Margin(14, 0, 0, 0).At(0, 0));
                g.Children.Add(Ui.Text(e.Title, 12.5).At(0, 1));
                g.Children.Add(Ui.Mono(e.Targets, 12.5).Margin(0, 0, 8, 0).At(0, 2));
                var result = Ui.Row(Ui.Subtle(e.Summary, 12.5, false));
                g.Children.Add(result.At(0, 3));
                _list.Items.Add(new ListBoxItem { Content = g, Tag = e, MinHeight = 38 });
            }
            _count.Text = entries.Count == 0
                ? "No saved scans yet. Every finished scan is saved here automatically."
                : $"{entries.Count} saved scan{(entries.Count == 1 ? "" : "s")} on this computer";
            if (_list.Items.Count > 0) _list.SelectedIndex = 0;
            UpdateButtons();
        }

        private void UpdateButtons()
        {
            var has = Selected != null;
            _open.IsEnabled = has;
            _delete.IsEnabled = has;
            _compare.IsEnabled = has && _list.Items.Count > 1;
        }

        private void OpenSelected()
        {
            var e = Selected;
            if (e == null) return;
            _main.OpenHistory(e);
        }

        private void CompareSelected()
        {
            var e = Selected;
            if (e == null) return;
            _main.ShowCompare(e);
        }

        private void DeleteSelected()
        {
            var e = Selected;
            if (e == null) return;
            if (!Dialogs.Confirm(this, $"Delete the saved scan \"{e.Title}\" of {e.Targets} from {e.WhenText}?")) return;
            try { History.Delete(e); }
            catch (Exception ex) { Dialogs.Error(this, "Couldn't delete it:\n\n" + ex.Message); }
            Fill();
        }
    }

    /// <summary>Shows what changed between two saved scans.</summary>
    public sealed class CompareWindow : Window
    {
        private readonly MainWindow _main;
        private readonly ComboBox _older = new ComboBox();
        private readonly ComboBox _newer = new ComboBox();
        private readonly TextBlock _olderInfo = Ui.Subtle(string.Empty, 12, false);
        private readonly TextBlock _newerInfo = Ui.Subtle(string.Empty, 12, false);
        private readonly UniformGrid _counts = new UniformGrid { Rows = 1 };
        private readonly ListBox _list = new ListBox().Styled("TableList");
        private readonly CheckBox _showSame = new CheckBox { Content = "Show unchanged hosts" };
        private readonly TextBlock _empty = Ui.Subtle(string.Empty, 13);
        private List<Change> _changes = new List<Change>();
        private static readonly GridLength[] Widths = { Ui.Px(160), Ui.Px(140), Ui.Px(170), Ui.Star(), Ui.Px(120) };

        public CompareWindow(MainWindow main, List<HistoryEntry> entries, HistoryEntry newer)
        {
            _main = main;
            Width = 1040;
            Height = 700;
            MinWidth = 820;
            MinHeight = 480;
            ShowInTaskbar = false;
            Dialogs.Prepare(this, "Compare scans", main);

            _older.ItemsSource = entries;
            _newer.ItemsSource = entries;
            newer = newer ?? entries[0];
            _newer.SelectedItem = entries.FirstOrDefault(e => e.Folder == newer.Folder) ?? entries[0];
            var newerEntry = (HistoryEntry)_newer.SelectedItem;
            // Default to the previous scan of the same target, otherwise the one before.
            var older = entries.Where(e => e.Started < newerEntry.Started)
                            .FirstOrDefault(e => string.Equals(e.Targets, newerEntry.Targets, StringComparison.OrdinalIgnoreCase))
                        ?? entries.FirstOrDefault(e => e.Started < newerEntry.Started)
                        ?? entries.First(e => e != newerEntry);
            _older.SelectedItem = older;

            var pickers = Ui.Columns(Ui.Star(), Ui.Px(48), Ui.Star());
            pickers.Children.Add(Ui.Card(Ui.Column(Ui.Subtle("Older scan", 12, false).Margin(0, 0, 0, 6), _older, _olderInfo.Margin(0, 6, 0, 0)), 14).At(0, 0));
            var arrow = Ui.Icon("IconBack", 20);
            arrow.RenderTransformOrigin = new Point(0.5, 0.5);
            arrow.RenderTransform = new System.Windows.Media.RotateTransform(180);
            arrow.HorizontalAlignment = HorizontalAlignment.Center;
            arrow.Res(System.Windows.Documents.TextElement.ForegroundProperty, "SubtleText");
            pickers.Children.Add(arrow.At(0, 1));
            pickers.Children.Add(Ui.Card(Ui.Column(Ui.Subtle("Newer scan", 12, false).Margin(0, 0, 0, 6), _newer, _newerInfo.Margin(0, 6, 0, 0)), 14).At(0, 2));

            var listHeader = Ui.Columns(Ui.Auto, Ui.Star(), Ui.Auto, Ui.Auto);
            listHeader.Children.Add(Ui.Heading("What changed", 13).At(0, 0));
            listHeader.Children.Add(Ui.Subtle("Hosts and ports that are the same in both scans are hidden.", 12, false).Margin(10, 0, 0, 0).At(0, 1));
            listHeader.Children.Add(_showSame.At(0, 2));
            listHeader.Children.Add(Ui.Small(Ui.Button("Export", "IconExport", click: (s, e) => Export())).Margin(12, 0, 0, 0).At(0, 3));

            var cols = Ui.Columns(Widths);
            var titles = new[] { "Change", "Address", "Name", "Details", "" };
            for (var i = 0; i < titles.Length; i++) cols.Children.Add(Ui.Text(titles[i], 12, "SubtleText", bold: true).Margin(i == 0 ? 16 : 0, 8, 8, 8).At(0, i));

            var table = new Grid();
            table.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            table.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            table.RowDefinitions.Add(new RowDefinition());
            table.Children.Add(listHeader.Margin(16, 12, 16, 8).At(0));
            table.Children.Add(new Border { BorderThickness = new Thickness(0, 0, 0, 1), Child = cols }.Res(Border.BorderBrushProperty, "BorderBrush").At(1));
            table.Children.Add(_list.At(2));
            table.Children.Add(_empty.Margin(16, 18, 16, 18).At(2));
            var card = Ui.Card(table, 0);
            card.ClipToBounds = true;

            var root = new Grid { Margin = new Thickness(20) };
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition());
            root.Children.Add(pickers.At(0));
            root.Children.Add(_counts.Margin(0, 12, 0, 0).At(1));
            root.Children.Add(card.Margin(0, 12, 0, 0).At(2));
            Content = root;

            _older.SelectionChanged += (s, e) => Run();
            _newer.SelectionChanged += (s, e) => Run();
            _showSame.Click += (s, e) => Run();
            Loaded += (s, e) => Run();
        }

        private void Run()
        {
            var older = _older.SelectedItem as HistoryEntry;
            var newer = _newer.SelectedItem as HistoryEntry;
            _list.Items.Clear();
            _counts.Children.Clear();
            if (older == null || newer == null) return;

            _olderInfo.Text = older.Summary;
            _newerInfo.Text = newer.Summary;
            if (older.Folder == newer.Folder)
            {
                _empty.Text = "Choose two different scans.";
                _empty.Visibility = Visibility.Visible;
                return;
            }
            if (older.Started > newer.Started)
            {
                var swap = older;
                older = newer;
                newer = swap;
            }

            try
            {
                _changes = ScanComparer.Compare(History.Load(older), History.Load(newer), _showSame.IsChecked == true);
            }
            catch (Exception ex)
            {
                _empty.Text = "Couldn't read one of the scans: " + ex.Message;
                _empty.Visibility = Visibility.Visible;
                return;
            }

            void Count(ChangeKind kind, string label, Tone tone)
            {
                var n = _changes.Count(c => c.Kind == kind);
                _counts.Children.Add(Ui.Card(Ui.Column(Ui.Text(n.ToString(CultureInfo.CurrentCulture), 22, bold: true),
                    Ui.Chip(label, n > 0 ? tone : Tone.Neutral).Margin(0, 4, 0, 0)), 14).Margin(0, 0, 10, 0));
            }
            Count(ChangeKind.NewHost, "new hosts", Tone.Ok);
            Count(ChangeKind.HostGone, "hosts gone", Tone.Neutral);
            Count(ChangeKind.PortOpened, "ports opened", Tone.Bad);
            Count(ChangeKind.PortClosed, "ports closed", Tone.Neutral);
            Count(ChangeKind.VersionChanged, "versions changed", Tone.Warn);
            ((FrameworkElement)_counts.Children[_counts.Children.Count - 1]).Margin = new Thickness(0);

            foreach (var c in _changes)
            {
                var tone = c.Kind == ChangeKind.NewHost ? Tone.Ok
                    : c.Kind == ChangeKind.PortOpened ? Tone.Bad
                    : c.Kind == ChangeKind.VersionChanged ? Tone.Warn
                    : Tone.Neutral;
                var g = Ui.Columns(Widths);
                g.Children.Add(Ui.Chip(c.KindText, tone).Margin(16, 0, 0, 0).At(0, 0));
                g.Children.Add(Ui.Mono(c.Address, 12.5).At(0, 1));
                g.Children.Add(Ui.Text(c.Name, 12.5).At(0, 2));
                g.Children.Add(Ui.Mono(c.Details, 12).Margin(0, 0, 8, 0).At(0, 3));
                if (c.Kind != ChangeKind.HostGone)
                {
                    var address = c.Address;
                    g.Children.Add(Ui.Link("Scan this host", (s, e) =>
                    {
                        _main.ScanHost(address);
                        _main.Activate();
                    }).At(0, 4));
                }
                _list.Items.Add(new ListBoxItem { Content = g, MinHeight = 38 });
            }

            _empty.Text = "Nothing changed between these two scans.";
            _empty.Visibility = _changes.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void Export()
        {
            if (_changes.Count == 0) return;
            var path = Dialogs.SaveFile(this, "Export changes", "KUDUNMAP changes " + DateTime.Now.ToString("yyyy-MM-dd HHmm") + ".csv", "CSV file|*.csv");
            if (path == null) return;
            try { Exporter.SaveChangesCsv(_changes, path); }
            catch (Exception ex) { Dialogs.Error(this, "Couldn't save the file:\n\n" + ex.Message); }
        }
    }

    /// <summary>A Windows notification when a scan ends while KUDUNMAP isn't the active window.</summary>
    public static class Notifier
    {
        public static void Show(Window owner, string title, string text)
        {
            if (!Settings.NotifyWhenDone || owner.IsActive) return;
            try
            {
                System.Drawing.Icon icon;
                using (var stream = Dialogs.AppIconStream()) icon = new System.Drawing.Icon(stream);
                var notify = new System.Windows.Forms.NotifyIcon { Icon = icon, Text = "KUDUNMAP", Visible = true };
                var done = false;
                void Done()
                {
                    if (done) return;
                    done = true;
                    notify.Visible = false;
                    notify.Dispose();
                    icon.Dispose();
                }
                notify.BalloonTipClicked += (s, e) =>
                {
                    owner.Dispatcher.BeginInvoke(new Action(() =>
                    {
                        if (owner.WindowState == WindowState.Minimized) owner.WindowState = WindowState.Normal;
                        owner.Activate();
                    }));
                    Done();
                };
                notify.BalloonTipClosed += (s, e) => Done();
                notify.ShowBalloonTip(8000, title, text, System.Windows.Forms.ToolTipIcon.Info);

                // Remove the tray icon even if Windows never reports the balloon closing.
                var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
                timer.Tick += (s, e) =>
                {
                    timer.Stop();
                    try { Done(); } catch { /* already disposed */ }
                };
                timer.Start();
            }
            catch
            {
                // Notifications are a nice-to-have.
            }
        }
    }
}
