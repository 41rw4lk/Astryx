// LED.cs
using System;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace CMDownloaderUI
{
    [ToolboxItem(true)]
    [DefaultProperty(nameof(On))]
    [DefaultEvent(nameof(Click))]
    public sealed class ActivityLed : Control
    {
        private bool _on;
        // field
        private readonly System.Windows.Forms.Timer _pulse = new System.Windows.Forms.Timer();
        private int _alpha = 180, _dir = -12; // start bright and decay a bit slower

        [Category("Behavior")]
        [Description("Turns the LED on/off.")]
        public bool On
        {
            get => _on;
            set { if (_on == value) return; _on = value; Invalidate(); }
        }

        [Category("Behavior")]
        [Description("Enable pulsing glow to indicate background activity.")]
        public bool Pulse
        {
            get => _pulse.Enabled;
            set { _pulse.Enabled = value; }
        }

        [Category("Behavior")]
        [Description("Pulse period in milliseconds.")]
        public int PulseMs
        {
            get => _pulse.Interval;
            set { _pulse.Interval = Math.Max(30, value); }
        }

        [Category("Appearance")]
        public Color OnColor { get; set; } = Color.LimeGreen;

        [Category("Appearance")]
        public Color OffColor { get; set; } = Color.DimGray;

        public ActivityLed()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint, true);
            SetStyle(ControlStyles.SupportsTransparentBackColor, true);
            BackColor = Color.Transparent;

            Size = new Size(14, 14);
            _pulse.Interval = 150; // slower tick so the flash is readable
            _pulse.Enabled = true; // default-on; drawing still depends on On==true
            _pulse.Tick += (_, __) =>
            {
                _alpha += _dir;
                if (_alpha > 220 || _alpha < 80) _dir = -_dir; // wider, brighter range
                Invalidate();
            };
        }


        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

            // Outer circle used for halo & ring (stay inside bounds)
            var outer = this.ClientRectangle;
            outer.Inflate(-1, -1);

            // 1) HALO FIRST so it shows
            var baseColor = _on ? OnColor : OffColor;
            if (_on)
            {
                using var glow = new SolidBrush(Color.FromArgb(_alpha, baseColor));
                g.FillEllipse(glow, outer);
            }

            // 2) CORE disc (smaller so halo remains visible around it)
            var core = outer; core.Inflate(-3, -3);
            using (var br = new SolidBrush(baseColor))
                g.FillEllipse(br, core);

            // 3) Subtle ring for definition on dark UI
            using (var ring = new Pen(Color.FromArgb(110, 255, 255, 255), 1f))
                g.DrawEllipse(ring, outer);
        }



        protected override Size DefaultSize => new Size(14, 14);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                _pulse?.Dispose();

            base.Dispose(disposing);
        }
    }
}
