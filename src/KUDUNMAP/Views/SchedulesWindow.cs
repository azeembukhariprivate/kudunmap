using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Kudunmap.Controls;
using Kudunmap.Core;

namespace Kudunmap.Views
{
    /// <summary>Scans that run by themselves (through Windows' Task Scheduler) and tell you when something changed.</summary>
    public sealed class SchedulesWindow : Window
    {
        private readonly MainWindow _main;
        private readonly ListBox _list = new ListBox().Styled("TableList");
        private readonly TextBlock _count = Ui.Subtle(string.Empty, 12, false);
        private readonly Button _change;
        private readonly Button _runNow;
        private readonly Button _remove;
        private static readonly GridLength[] Widths = { Ui.Px(210), Ui.Px(190), Ui.Star() };

        /// <summary>The data folder the tasks pass on (the self-test's own, so its scans don't mix with yours).</summary>
        public static string DataFolder { get; set; }

        public SchedulesWindow(MainWindow main)
        {
            _main = main;
            Width = 900;
            Height = 560;
            MinWidth = 700;
            MinHeight = 380;
            ShowInTaskbar = false;
            Dialogs.Prepare(this, "Scheduled scans", main);

            var add = Ui.Button("Schedule the scan set up now…", "IconClock", "PrimaryButton", (s, e) => Add());
            _change = Ui.Button("Change…", null, click: (s, e) => ChangeSelected());
            _runNow = Ui.Button("Run now", "IconPlay", click: (s, e) => RunSelected());
            _remove = Ui.Button("Remove", "IconTrash", "GhostButton", (s, e) => RemoveSelected());

            var header = Ui.Columns(Ui.Star(), Ui.Auto);
            header.Children.Add(Ui.Column(Ui.Heading("Scheduled scans", 20), _count.Margin(0, 2, 0, 0)).At(0, 0));
            header.Children.Add(Ui.Link("Open History", (s, e) => _main.ShowHistory()).At(0, 1));

            var cols = Ui.Columns(Widths);
            var titles = new[] { "Scan", "When", "Last run" };
            for (var i = 0; i < titles.Length; i++) cols.Children.Add(Ui.Text(titles[i], 12, "SubtleText", bold: true).Margin(i == 0 ? 14 : 0, 8, 8, 8).At(0, i));
            var table = new Grid();
            table.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            table.RowDefinitions.Add(new RowDefinition());
            table.Children.Add(new Border { BorderThickness = new Thickness(0, 0, 0, 1), Child = cols }.Res(Border.BorderBrushProperty, "BorderBrush").At(0));
            table.Children.Add(_list.At(1));
            var card = Ui.Card(table, 0);
            card.ClipToBounds = true;

            var note = Ui.Subtle("Each scheduled scan runs by itself, even when KUDUNMAP is closed (you need to be signed in to Windows). " +
                                 "Every run is kept in History, and a Windows notification tells you when a device or open port appears or goes away. " +
                                 "Windows asks for administrator rights once, when a scan is scheduled, so it can use every scan type.", 12, true);

            var buttons = Ui.Row(add, _change.Margin(8, 0, 0, 0), _runNow.Margin(8, 0, 0, 0), _remove.Margin(8, 0, 0, 0));
            var root = new Grid { Margin = new Thickness(20) };
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition());
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.Children.Add(header.Margin(0, 0, 0, 8).At(0));
            root.Children.Add(note.Margin(0, 0, 0, 12).At(1));
            root.Children.Add(card.At(2));
            root.Children.Add(buttons.Margin(0, 14, 0, 0).At(3));
            Content = root;

            _list.SelectionChanged += (s, e) => UpdateButtons();
            _list.MouseDoubleClick += (s, e) => ChangeSelected();
            _list.KeyDown += (s, e) =>
            {
                if (e.Key == Key.Delete) RemoveSelected();
            };
            Fill();
        }

        private ScheduledScan Selected => (_list.SelectedItem as ListBoxItem)?.Tag as ScheduledScan;

        /// <summary>The scheduled scans shown (for the self-test).</summary>
        public List<ScheduledScan> Shown => _list.Items.OfType<ListBoxItem>().Select(i => (ScheduledScan)i.Tag).ToList();

        public void Fill(string select = null)
        {
            _list.Items.Clear();
            List<ScheduledScan> all;
            try { all = ScheduledScans.List(); }
            catch { all = new List<ScheduledScan>(); }
            foreach (var sc in all)
            {
                var g = Ui.Columns(Widths);
                g.Children.Add(Ui.Column(Ui.Text(sc.Name, 13, bold: true), Ui.Mono(sc.Targets, 11.5, "SubtleText")).Margin(14, 0, 8, 0).At(0, 0));
                g.Children.Add(Ui.Text(sc.When, 12.5).At(0, 1));
                FrameworkElement last = sc.LastRun == DateTime.MinValue
                    ? (FrameworkElement)Ui.Subtle("Not run yet", 12.5, false)
                    : Ui.Column(Ui.Text(HistoryEntry.FriendlyDate(sc.LastRun), 12.5), Ui.Subtle(sc.LastResult, 12, true));
                g.Children.Add(last.Margin(0, 0, 8, 0).At(0, 2));
                var item = new ListBoxItem { Content = g, Tag = sc, MinHeight = 46 };
                _list.Items.Add(item);
                if (sc.Id == select) _list.SelectedItem = item;
            }
            _count.Text = all.Count == 0
                ? "None yet. Set up a scan in the main window, then schedule it here."
                : Format.Count(all.Count, "scheduled scan");
            if (_list.SelectedItem == null && _list.Items.Count > 0) _list.SelectedIndex = 0;
            UpdateButtons();
        }

        private void UpdateButtons()
        {
            var has = Selected != null;
            _change.IsEnabled = has;
            _runNow.IsEnabled = has;
            _remove.IsEnabled = has;
        }

        private static string Exe => Process.GetCurrentProcess().MainModule.FileName;

        private void Add()
        {
            var o = _main.Options.Clone();
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
                    Dialogs.Error(this, "Type what to scan in the main window first.\n\n" + error);
                    return;
                }
            }
            if (o.UsesAdvancedScripts &&
                !Dialogs.Confirm(this, "This scan uses advanced scripts, which can lock accounts, crash services or be seen as an attack. " +
                                       "Running them again and again by themselves isn't a good idea.\n\nSchedule it anyway?"))
                return;
            var sc = new ScheduledScan { Name = o.Title + " of " + (string.IsNullOrEmpty(o.TargetFile) ? o.Targets.Trim() : Path.GetFileName(o.TargetFile)), Options = o };
            if (sc.Name.Length > 60) sc.Name = sc.Name.Substring(0, 59) + "…";
            if (Edit(sc, true)) Fill(sc.Id);
        }

        private void ChangeSelected()
        {
            var sc = Selected;
            if (sc != null && Edit(sc, false)) Fill(sc.Id);
        }

        /// <summary>Asks for the name and when it runs, then saves the scan and its Windows task.</summary>
        private bool Edit(ScheduledScan sc, bool isNew)
        {
            var name = new TextBox { Text = sc.Name, MinHeight = 36 };
            var every = Combo(new[] { "Every hour (or every few hours)", "Every day", "Every week" }, (int)sc.Every);
            var hourChoices = new[] { 1, 2, 3, 4, 6, 8, 12 };
            var hours = Combo(hourChoices.Select(h => h == 1 ? "Every hour" : $"Every {h} hours").ToArray(), Math.Max(0, Array.IndexOf(hourChoices, sc.Hours)));
            var times = Enumerable.Range(0, 48).Select(i => $"{i / 2:00}:{i % 2 * 30:00}").ToArray();
            var time = Combo(times, Math.Max(0, Math.Min(47, sc.Minutes / 30)));
            var day = Combo(new[] { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" }, Math.Max(0, Math.Min(6, sc.Day)));

            var hoursField = Field("How often", hours);
            var timeField = Field("At", time);
            var dayField = Field("On", day);
            void ShowFields()
            {
                var e = (ScanEvery)every.SelectedIndex;
                hoursField.Visibility = e == ScanEvery.Hourly ? Visibility.Visible : Visibility.Collapsed;
                timeField.Visibility = e == ScanEvery.Hourly ? Visibility.Collapsed : Visibility.Visible;
                dayField.Visibility = e == ScanEvery.Weekly ? Visibility.Visible : Visibility.Collapsed;
            }
            every.SelectionChanged += (s, e) => ShowFields();
            ShowFields();

            var whenRow = Ui.Columns(Ui.Star(), Ui.Px(12), Ui.Star(), Ui.Px(12), Ui.Star());
            whenRow.Children.Add(Field("Runs", every).At(0, 0));
            whenRow.Children.Add(hoursField.At(0, 2));
            whenRow.Children.Add(dayField.At(0, 2));
            whenRow.Children.Add(timeField.At(0, 4));

            var what = Ui.Subtle(sc.Options.Title + " · " + sc.Targets, 12.5, true);
            var content = Ui.Column(
                Ui.Heading(isNew ? "Schedule this scan" : "Change this scheduled scan", 17),
                what.Margin(0, 4, 0, 14),
                Field("Name", name),
                whenRow.Margin(0, 12, 0, 0),
                Ui.Subtle("If the PC is off or asleep at that time, the scan runs as soon as it can.", 12, true).Margin(0, 12, 0, 0));
            var ok = Ui.Button(isNew ? "Schedule" : "Save", null, "PrimaryButton");
            var cancel = Ui.Button("Cancel");
            var window = Dialogs.Dialog(this, isNew ? "Schedule a scan" : "Change a scheduled scan", content, 560, cancel, ok);
            ok.IsDefault = true;
            cancel.IsCancel = true;
            var saved = false;
            ok.Click += (s, e) =>
            {
                if (string.IsNullOrWhiteSpace(name.Text))
                {
                    name.Focus();
                    return;
                }
                var before = new { sc.Name, sc.Every, sc.Hours, sc.Minutes, sc.Day };
                var oldTask = isNew ? null : ScheduledScans.TaskName(sc);
                sc.Name = name.Text.Trim();
                sc.Every = (ScanEvery)every.SelectedIndex;
                sc.Hours = hourChoices[Math.Max(0, hours.SelectedIndex)];
                sc.Minutes = Math.Max(0, time.SelectedIndex) * 30;
                sc.Day = Math.Max(0, day.SelectedIndex);
                Cursor = Cursors.Wait;
                string problem;
                try { problem = ScheduledScans.Apply(sc, Exe, Admin.IsAdmin, DataFolder); }
                finally { Cursor = null; }
                if (problem != null)
                {
                    sc.Name = before.Name;
                    sc.Every = before.Every;
                    sc.Hours = before.Hours;
                    sc.Minutes = before.Minutes;
                    sc.Day = before.Day;
                    Dialogs.Error(window, problem);
                    return;
                }
                // A new name is a new task name: remove the old task.
                if (oldTask != null && oldTask != ScheduledScans.TaskName(sc))
                {
                    var renamed = new ScheduledScan { Id = sc.Id, Name = before.Name };
                    ScheduledScans.Remove(renamed);
                }
                ScheduledScans.Save(sc);
                saved = true;
                window.DialogResult = true;
            };
            window.Loaded += (s, e) =>
            {
                name.Focus();
                name.SelectAll();
            };
            window.ShowDialog();
            return saved;
        }

        private static ComboBox Combo(string[] items, int selected)
        {
            var c = new ComboBox { MinHeight = 34 };
            foreach (var i in items) c.Items.Add(i);
            c.SelectedIndex = Math.Max(0, Math.Min(items.Length - 1, selected));
            return c;
        }

        private static FrameworkElement Field(string label, UIElement content)
        {
            var p = new StackPanel();
            p.Children.Add(Ui.Subtle(label, 12, false).Margin(0, 0, 0, 6));
            p.Children.Add(content);
            return p;
        }

        private void RunSelected()
        {
            var sc = Selected;
            if (sc == null) return;
            if (ScheduledScans.RunNow(sc))
                Dialogs.Info(this, $"\"{sc.Name}\" is running now, without a window. It will be in History when it finishes, and you'll get a notification if something changed.");
            else if (Dialogs.Confirm(this, $"Windows' task for \"{sc.Name}\" is missing. Make it again?"))
            {
                var problem = ScheduledScans.Apply(sc, Exe, Admin.IsAdmin, DataFolder);
                if (problem != null) Dialogs.Error(this, problem);
                else ScheduledScans.RunNow(sc);
            }
        }

        private void RemoveSelected()
        {
            var sc = Selected;
            if (sc == null) return;
            if (!Dialogs.Confirm(this, $"Stop running \"{sc.Name}\" by itself?\n\nIts earlier runs stay in History.")) return;
            if (!ScheduledScans.Remove(sc))
            {
                Dialogs.Error(this, "Windows didn't remove the task. You can remove it in Task Scheduler: it's called\n\n" + ScheduledScans.TaskName(sc));
                return;
            }
            ScheduledScans.Delete(sc);
            Fill();
        }
    }
}
