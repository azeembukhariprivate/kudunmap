using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using Kudunmap.Controls;
using Kudunmap.Core;

namespace Kudunmap.Views
{
    /// <summary>The "Worth a look" and "Map" tabs, and the plain-words note under each open port.</summary>
    public sealed partial class ResultsView
    {
        private const int LookTab = 4;
        private const int MapTab = 5;
        private readonly Border _lookChipHost = new Border { Margin = new Thickness(6, 0, 0, 0) };
        private Canvas _mapCanvas;

        /// <summary>The devices drawn on the map last (for the self-test).</summary>
        public List<MapDevice> MapDevices { get; private set; } = new List<MapDevice>();

        private static string LevelBrush(PortLevel level) => level == PortLevel.Risky ? "BadText" : level == PortLevel.WorthALook ? "WarnText" : "OkText";

        private static Tone LevelTone(PortLevel level) => level == PortLevel.Risky ? Tone.Bad : level == PortLevel.WorthALook ? Tone.Warn : Tone.Ok;

        /// <summary>A port's note: its level and what it means.</summary>
        private static FrameworkElement NoteLine(PortNote note)
        {
            var row = Ui.Columns(Ui.Auto, Ui.Star());
            row.Children.Add(Ui.Chip(note.LevelText, LevelTone(note.Level)).Margin(0, 1, 8, 0).At(0, 0));
            ((FrameworkElement)row.Children[0]).VerticalAlignment = VerticalAlignment.Top;
            var text = Ui.Text(note.What + ": " + note.Text, 12, "SubtleText", wrap: true);
            row.Children.Add(text.At(0, 1));
            return row;
        }

        // ================================================================== worth a look

        private UIElement BuildLookPanel()
        {
            var panel = new StackPanel { Margin = new Thickness(18, 14, 18, 14) };
            if (_result == null)
            {
                panel.Children.Add(Ui.Subtle("This appears when the scan finishes.", 13));
                return panel;
            }
            var look = PortNotes.WorthALook(_result);
            var risky = look.Count(f => f.Note.Level == PortLevel.Risky);
            var heading = look.Count == 0 ? "Nothing worth a look"
                : Lang.T("{0} worth a look", Format.Count(look.Count, "open port")) + (risky > 0 ? Lang.T(" ({0} risky)", risky) : string.Empty);
            panel.Children.Add(Ui.Heading(heading, 16));
            panel.Children.Add(Ui.Subtle(look.Count == 0
                ? "Every open port found is normal for its kind of device."
                : "What each open port is, in plain words, and what it could risk. Risky ones are often used by attackers: close them if they aren't needed, and never let them be reached from the internet.", 12.5, true).Margin(0, 4, 0, 12));
            foreach (var f in look)
            {
                var finding = f;
                var g = Ui.Columns(Ui.Px(170), Ui.Px(90), Ui.Star());
                g.Children.Add(Ui.Column(Ui.Text(f.Host.DisplayName, 13, bold: true), Ui.Mono(f.Host.Address, 11.5, "SubtleText")).At(0, 0));
                g.Children.Add(Ui.Mono(f.Port.Number + "/" + f.Port.Protocol, 12.5).At(0, 1));
                g.Children.Add(NoteLine(f.Note).At(0, 2));
                var b = new Border { Child = g, Padding = new Thickness(0, 8, 0, 8), BorderThickness = new Thickness(0, 0, 0, 1), Cursor = System.Windows.Input.Cursors.Hand }
                    .Res(Border.BorderBrushProperty, "BorderBrush");
                b.ToolTip = "Show this device";
                b.MouseLeftButtonUp += (s, e) => GoToHost(finding.Host);
                panel.Children.Add(b);
            }
            return new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        }


        /// <summary>Opens the Hosts tab on a device.</summary>
        public void GoToHost(HostInfo host)
        {
            SelectTab(0);
            var item = _hostList.Items.OfType<ListBoxItem>().FirstOrDefault(i => ReferenceEquals(i.Tag, host));
            if (item != null)
            {
                _hostList.SelectedItem = item;
                _hostList.ScrollIntoView(item);
            }
        }

        // ================================================================== the map

        /// <summary>This PC's addresses and its routers' (default gateways), to place them on the map.</summary>
        public static (HashSet<string> Own, HashSet<string> Gateways) LocalAddresses()
        {
            var own = new HashSet<string>();
            var gateways = new HashSet<string>();
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up))
                {
                    var ip = nic.GetIPProperties();
                    foreach (var a in ip.UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)) own.Add(a.Address.ToString());
                    foreach (var g in ip.GatewayAddresses.Where(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(System.Net.IPAddress.Any)))
                        gateways.Add(g.Address.ToString());
                }
            }
            catch (NetworkInformationException)
            {
                // No details: the map just doesn't mark this PC and the router.
            }
            return (own, gateways);
        }

        private static string Glyph(DeviceKind kind)
        {
            // Segoe MDL2 Assets / Segoe Fluent Icons, which come with Windows 10 and 11.
            switch (kind)
            {
                case DeviceKind.ThisPc: return "\uE7F8";
                case DeviceKind.Router: return "\uE704";
                case DeviceKind.Computer: return "\uE977";
                case DeviceKind.Server: return "\uE968";
                case DeviceKind.Phone: return "\uE8EA";
                case DeviceKind.Printer: return "\uE749";
                case DeviceKind.Tv: return "\uE7F4";
                case DeviceKind.Camera: return "\uE722";
                case DeviceKind.Storage: return "\uEDA2";
                case DeviceKind.SmartHome: return "\uE80F";
                case DeviceKind.NetworkDevice: return "\uE839";
                default: return "\uE9CE";
            }
        }

        private UIElement BuildMapPanel()
        {
            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition());
            if (_result == null || !_result.UpHosts.Any())
            {
                root.Children.Add(Ui.Subtle(_result == null ? "The map appears when the scan finishes." : "No devices replied, so there's nothing to draw.", 13).Margin(18, 14, 18, 14).At(0));
                return root;
            }
            var (own, gateways) = LocalAddresses();
            const double size = 1000;
            MapDevices = NetworkMap.Build(_result, own, gateways, size);

            var bar = Ui.Columns(Ui.Star(), Ui.Auto);
            bar.Children.Add(Ui.Subtle("Each device found, with a guess of what it is. Red and orange marks are open ports that are risky or worth a look. Click a device to see its details.", 12.5, true).At(0, 0));
            bar.Children.Add(Ui.Small(Ui.Button("Save as a picture…", "IconExport", click: (s, e) => SaveMap())).Margin(12, 0, 0, 0).At(0, 1));
            root.Children.Add(bar.Margin(18, 12, 18, 6).At(0));

            var canvas = new Canvas { Width = size, Height = size };
            canvas.Res(Panel.BackgroundProperty, "SurfaceBg");
            var hub = MapDevices.FirstOrDefault(d => d.Kind == DeviceKind.Router) ?? MapDevices.FirstOrDefault(d => d.Kind == DeviceKind.ThisPc);
            var center = hub != null ? new Point(hub.X, hub.Y) : new Point(size / 2, size / 2);
            foreach (var d in MapDevices.Where(d => d != hub))
            {
                var line = new Line { X1 = center.X, Y1 = center.Y, X2 = d.X, Y2 = d.Y, StrokeThickness = 1.5 };
                line.SetResourceReference(Shape.StrokeProperty, "BorderBrush");
                canvas.Children.Add(line);
            }
            foreach (var d in MapDevices) canvas.Children.Add(DeviceMark(d, d == hub));
            _mapCanvas = canvas;
            root.Children.Add(new Viewbox { Child = canvas, Stretch = Stretch.Uniform, Margin = new Thickness(12, 0, 12, 12) }.At(1));
            return root;
        }

        private FrameworkElement DeviceMark(MapDevice d, bool hub)
        {
            var diameter = hub ? 74.0 : 58.0;
            var circle = new Border
            {
                Width = diameter,
                Height = diameter,
                CornerRadius = new CornerRadius(diameter / 2),
                BorderThickness = new Thickness(d.Risky > 0 ? 3 : 2),
                HorizontalAlignment = HorizontalAlignment.Center,
                Child = new TextBlock
                {
                    Text = Glyph(d.Kind),
                    FontFamily = new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets"),
                    FontSize = hub ? 30 : 24,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                }.Res(TextBlock.ForegroundProperty, "Text")
            };
            circle.Res(Border.BackgroundProperty, hub ? "ChipBg" : "SurfaceAltBg");
            circle.Res(Border.BorderBrushProperty, d.Risky > 0 ? "BadText" : d.WorthALook > 0 ? "WarnText" : hub ? "Accent" : "BorderBrush");

            var marks = Ui.Row();
            marks.HorizontalAlignment = HorizontalAlignment.Center;
            if (d.Risky > 0) marks.Children.Add(Ui.Chip(d.Risky + " risky", Tone.Bad).Margin(0, 0, 3, 0));
            if (d.WorthALook > 0) marks.Children.Add(Ui.Chip(d.WorthALook + " to check", Tone.Warn));
            var label = Ui.Column(circle,
                Ui.Text(d.Label, 13, bold: true).Margin(0, 4, 0, 0),
                Ui.Subtle(d.KindText + (string.IsNullOrEmpty(d.Host.Name) ? string.Empty : " · " + d.Host.Address), 11, false),
                marks.Margin(0, 3, 0, 0));
            foreach (FrameworkElement c in label.Children) c.HorizontalAlignment = HorizontalAlignment.Center;
            label.Width = 170;
            var mark = new Border { Child = label, Background = Brushes.Transparent, Cursor = System.Windows.Input.Cursors.Hand };
            mark.ToolTip = d.Host.DisplayName + " · " + Lang.T(d.KindText) + (d.Open > 0 ? " · " + Format.Count(d.Open, "open port") : string.Empty);
            mark.MouseLeftButtonUp += (s, e) => GoToHost(d.Host);
            Canvas.SetLeft(mark, d.X - 85);
            Canvas.SetTop(mark, d.Y - diameter / 2);
            return mark;
        }

        /// <summary>Saves the map as a PNG picture. Returns the file, or null.</summary>
        public string SaveMap(string file = null)
        {
            if (_mapCanvas == null) return null;
            if (file == null)
            {
                var name = AppPaths.SafeFileName("Network map " + (_options?.Targets ?? string.Empty).Replace('/', '-'), 50) + ".png";
                file = Dialogs.SaveFile(_main, "Save the map as a picture", name, "PNG picture|*.png");
                if (file == null) return null;
            }
            _mapCanvas.Measure(new Size(_mapCanvas.Width, _mapCanvas.Height));
            _mapCanvas.Arrange(new Rect(0, 0, _mapCanvas.Width, _mapCanvas.Height));
            var bitmap = new RenderTargetBitmap((int)_mapCanvas.Width, (int)_mapCanvas.Height, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(_mapCanvas);
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using (var stream = File.Create(file)) encoder.Save(stream);
            return file;
        }
    }
}
