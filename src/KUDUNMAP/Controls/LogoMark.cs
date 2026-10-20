using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Shapes;

namespace Kudunmap.Controls
{
    /// <summary>The KUDUNMAP radar mark: two rings, a sweep line and one found device. Uses the text colour.</summary>
    public class LogoMark : Viewbox
    {
        public LogoMark(double size = 40, double strokeThickness = 3.5)
        {
            Width = size;
            Height = size;
            Focusable = false;
            IsHitTestVisible = false;

            var canvas = new Canvas { Width = 64, Height = 64 };
            canvas.Children.Add(Stroke(new EllipseGeometry(new Point(32, 32), 22, 22), strokeThickness));
            canvas.Children.Add(Stroke(new EllipseGeometry(new Point(32, 32), 11, 11), strokeThickness));
            canvas.Children.Add(Stroke(new LineGeometry(new Point(32, 32), new Point(44.4, 19.6)), strokeThickness));
            canvas.Children.Add(Fill(new EllipseGeometry(new Point(32, 32), 2.8, 2.8)));
            canvas.Children.Add(Fill(new EllipseGeometry(new Point(19.3, 42.6), 3, 3)));
            Child = canvas;
        }

        private Path Stroke(Geometry g, double thickness)
        {
            var p = new Path
            {
                Data = g,
                StrokeThickness = thickness,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round
            };
            p.SetBinding(Shape.StrokeProperty, ForegroundBinding());
            return p;
        }

        private Path Fill(Geometry g)
        {
            var p = new Path { Data = g };
            p.SetBinding(Shape.FillProperty, ForegroundBinding());
            return p;
        }

        private Binding ForegroundBinding() => new Binding
        {
            Path = new PropertyPath(TextElement.ForegroundProperty),
            Source = this
        };
    }
}
