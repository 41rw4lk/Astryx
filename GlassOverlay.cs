// GlassOverlay.cs
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace AstroFetch
{
    /// <summary>
    /// Lightweight glass overlay for the whole form.
    /// - Double-buffered, click-through (via WM_NCHITTEST)
    /// - No WS_EX_TRANSPARENT (so it actually paints)
    /// - Subtle glass, brand strip, accent underline, optional logo pocket
    /// </summary>
    public sealed class GlassOverlay : Control
    {
        // ---- Public knobs ----------------------------------------------------
        public Color AccentColor { get; set; } = Color.FromArgb(0xCF, 0xFF, 0x04);
        public string WordmarkText { get; set; } = "AstroFetch";
        public int BrandHeight { get; set; } = 22;             // top “brand strip” height
        public float GlassOpacity { get; set; } = 0.10f;       // 0..1 background glass
        public bool ShowLogoPocket { get; set; } = true;       // right-side decorative pocket

        public GlassOverlay()
        {
            SetStyle(ControlStyles.UserPaint
                   | ControlStyles.AllPaintingInWmPaint
                   | ControlStyles.OptimizedDoubleBuffer
                   | ControlStyles.ResizeRedraw
                   | ControlStyles.SupportsTransparentBackColor, true);

            BackColor = Color.Transparent;
            Enabled = true;       // must be true so OnPaint fires
            TabStop = false;
        }

        // Paint without WS_EX_TRANSPARENT (that kills visibility in many layouts).
        // Keep click-through via WM_NCHITTEST instead.
        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                // DO NOT set WS_EX_TRANSPARENT here.
                return cp;
            }
        }

        // Click-through: let mouse go to underlying controls.
        protected override void WndProc(ref Message m)
        {
            const int WM_NCHITTEST = 0x84;
            const int HTTRANSPARENT = -1;
            if (m.Msg == WM_NCHITTEST) { m.Result = (IntPtr)HTTRANSPARENT; return; }
            base.WndProc(ref m);
        }

        // Prevent WinForms from erasing the background before we paint.
        protected override void OnPaintBackground(PaintEventArgs e) { /* no-op for overlay */ }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            Rectangle rc = ClientRectangle;
            if (rc.Width <= 2 || rc.Height <= 2) return;

            // 1) Very subtle full-form glass
            using (var glass = new SolidBrush(Color.FromArgb((int)(GlassOpacity * 255), 0, 0, 0)))
                g.FillRectangle(glass, rc);

            // 2) Brand strip (top ribbon)
            var strip = new Rectangle(rc.Left, rc.Top, rc.Width, Math.Max(16, Math.Min(48, BrandHeight)));
            using (var lg = new LinearGradientBrush(strip, Color.FromArgb(36, Color.White), Color.FromArgb(8, Color.Black), 90f))
                g.FillRectangle(lg, strip);
            using (var p = new Pen(Color.FromArgb(80, Color.White), 1f))
                g.DrawLine(p, strip.Left, strip.Top + 1, strip.Right, strip.Top + 1);

            // 3) Accent underline
            using (var p = new Pen(Color.FromArgb(170, AccentColor), 2f))
                g.DrawLine(p, rc.Left + 12, strip.Bottom + 3, rc.Right - 12, strip.Bottom + 3);

            // 4) Wordmark (center-left)
            if (!string.IsNullOrWhiteSpace(WordmarkText))
            {
                using var f = new Font("Segoe UI Semibold", 18f, GraphicsUnit.Point);
                var bounds = new Rectangle(12, strip.Top + 2, rc.Width / 2, strip.Height - 4);

                // soft glow pass
                using (var path = new GraphicsPath())
                using (var glowPen = new Pen(Color.FromArgb(90, AccentColor), 3f))
                using (var sf = new StringFormat { Alignment = StringAlignment.Near, LineAlignment = StringAlignment.Center, Trimming = StringTrimming.EllipsisCharacter })
                {
                    path.AddString(WordmarkText, f.FontFamily, (int)FontStyle.Bold, g.DpiY * f.Size / 72f, bounds, sf);
                    g.DrawPath(glowPen, path);
                }
                // foreground
                using var textBrush = new SolidBrush(Color.White);
                using var sf2 = new StringFormat { Alignment = StringAlignment.Near, LineAlignment = StringAlignment.Center, Trimming = StringTrimming.EllipsisCharacter };
                g.DrawString(WordmarkText, f, textBrush, bounds, sf2);
            }

            // 5) Optional logo pocket on the right
            if (ShowLogoPocket)
            {
                int pad = 12;
                int zoneW = Math.Min(260, Math.Max(180, rc.Width / 4));
                var zone = new Rectangle(rc.Right - zoneW - pad, strip.Bottom + 8, zoneW, Math.Max(84, strip.Height + 56));

                DrawPocket(g, zone, AccentColor);
                DrawLaserCurves(g, zone, AccentColor);
            }
        }

        private static GraphicsPath RoundedRect(Rectangle r, int radius)
        {
            int d = radius * 2;
            var gp = new GraphicsPath();
            gp.AddArc(r.Left, r.Top, d, d, 180, 90);
            gp.AddArc(r.Right - d, r.Top, d, d, 270, 90);
            gp.AddArc(r.Right - d, r.Bottom - d, d, d, 90, 90);
            gp.AddArc(r.Left, r.Bottom - d, d, d, 180, 90);
            gp.CloseFigure();
            return gp;
        }

        private static void DrawPocket(Graphics g, Rectangle zone, Color accent)
        {
            using var gp = RoundedRect(zone, 12);
            using (var fill = new LinearGradientBrush(zone, Color.FromArgb(32, Color.Black), Color.FromArgb(12, Color.White), 90f))
                g.FillPath(fill, gp);
            using (var border = new Pen(Color.FromArgb(120, Color.Black), 1f))
                g.DrawPath(border, gp);
            using (var inner = new Pen(Color.FromArgb(70, accent), 1.5f))
                g.DrawPath(inner, gp);

            // subtle outer bloom
            using var glow = new Pen(Color.FromArgb(40, accent), 8f) { LineJoin = LineJoin.Round };
            g.DrawPath(glow, gp);
        }

        private static void DrawLaserCurves(Graphics g, Rectangle zone, Color accent)
        {
            using var path = new GraphicsPath();
            float midY = zone.Top + zone.Height / 2f;
            float x0 = zone.Left + 18f, x1 = zone.Left + zone.Width * 0.42f, x2 = zone.Right - 18f;

            path.AddBezier(new PointF(x0, midY + 10), new PointF(x1, midY - 28), new PointF(x1, midY + 24), new PointF(x2, midY - 6));
            path.AddBezier(new PointF(x0, midY + 26), new PointF(x1, midY - 10), new PointF(x1, midY + 42), new PointF(x2, midY + 8));
            path.AddBezier(new PointF(x0, midY - 8), new PointF(x1, midY - 36), new PointF(x1, midY + 10), new PointF(x2, midY - 22));

            using var beam = new Pen(Color.FromArgb(215, accent), 2.2f) { StartCap = LineCap.Round, EndCap = LineCap.Round };
            g.DrawPath(beam, path);

            using var bloom = new Pen(Color.FromArgb(36, accent), 8f) { LineJoin = LineJoin.Round };
            g.DrawPath(bloom, path);
        }

        protected override void OnResize(EventArgs e) { base.OnResize(e); Invalidate(); }
        protected override void OnVisibleChanged(EventArgs e) { base.OnVisibleChanged(e); Invalidate(); }
    }
}
