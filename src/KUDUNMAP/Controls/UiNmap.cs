using Kudunmap.Core;

namespace Kudunmap.Controls
{
    /// <summary>KUDUNMAP's own additions to the shared Ui helpers from kudu-common.</summary>
    public static partial class Ui
    {
        public static Tone ToneFor(Severity s)
        {
            switch (s)
            {
                case Severity.Critical:
                case Severity.High: return Tone.Bad;
                case Severity.Medium: return Tone.Warn;
                default: return Tone.Neutral;
            }
        }
    }
}
