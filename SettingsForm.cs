// Astryx DL — SettingsForm & AppSettings
// WinForms settings dialog and JSON-backed config for the Astryx downloader.
// Public-clean version: line tags removed for sharing.

// (c) Astryx project. See repository LICENSE for terms.

using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Forms;
using System.Drawing;
using System.Linq;

namespace CMDownloaderUI
{
    internal sealed class AppSettings
    {
        // ---- Tunables ---- //
        public int MaxDownloadAttempts { get; set; } = 4;
        public int JitterDelayMs { get; set; } = 750;
        public int NavQuickRetries { get; set; } = 3;
        public int NavQuickBaseDelayMs { get; set; } = 500;
        public int NavMaxRetries { get; set; } = 10;

        // ---- Storage ---- //
        [JsonIgnore] public static string AppCacheDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CMDownloaderUI");
        [JsonIgnore] public static string SettingsPath => Path.Combine(AppCacheDir, "settings.json");

        public static AppSettings LoadOrDefault()
        {
            try
            {
                if (File.Exists(SettingsPath))
                {
                    var json = File.ReadAllText(SettingsPath);
                    var loaded = JsonSerializer.Deserialize<AppSettings>(json);
                    return loaded ?? new AppSettings();
                }
            }
            catch { }
            return new AppSettings();
        }

        public void Save()
        {
            try { Directory.CreateDirectory(AppCacheDir); } catch { }
            var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(SettingsPath, json);
        }

        public static AppSettings Defaults() => new AppSettings();
    }

    internal sealed class SettingsForm : Form
    {
        private readonly AppSettings _settings;

        private NumericUpDown nudMaxAttempts;
        private NumericUpDown nudJitter;
        private NumericUpDown nudQuickRetries;
        private NumericUpDown nudQuickBaseMs;
        private NumericUpDown nudNavMax;

        private Button btnOk;
        private Button btnCancel;
        private Button btnDefaults;

        public SettingsForm(AppSettings settings)
        {
            _settings = Clone(settings);
            Text = "Settings";
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false; MinimizeBox = false;
            ClientSize = new Size(520, 300);

            var tip = new ToolTip { AutomaticDelay = 200, AutoPopDelay = 8000, ReshowDelay = 100 };

            var table = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 7,
                Padding = new Padding(12),
                AutoSize = false
            };
            table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 60));
            table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));

            // ---- Rows ---- //
            AddRow(table, "Max download attempts:", out nudMaxAttempts, 1, 20, _settings.MaxDownloadAttempts);
            tip.SetToolTip(nudMaxAttempts, "Number of GET retries per file before giving up.");

            AddRow(table, "Jitter delay (ms):", out nudJitter, 0, 10000, _settings.JitterDelayMs);
            tip.SetToolTip(nudJitter, "Random 0..N ms added to backoff waits to avoid thundering herds.");

            AddRow(table, "Quick nav retries:", out nudQuickRetries, 0, 20, _settings.NavQuickRetries);
            tip.SetToolTip(nudQuickRetries, "Number of quick retries for navigation timeouts/errors.");

            AddRow(table, "Quick base delay (ms):", out nudQuickBaseMs, 0, 10000, _settings.NavQuickBaseDelayMs);
            tip.SetToolTip(nudQuickBaseMs, "Base for exponential backoff in quick retries (e.g., 500, 1000, 2000...).");

            AddRow(table, "Max nav retries (cap):", out nudNavMax, 0, 50, _settings.NavMaxRetries);
            tip.SetToolTip(nudNavMax, "Optional global cap if you implement longer navigation backoff.");

            // Spacer //
            table.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            table.Controls.Add(new Label() { AutoSize = true }, 0, 5);
            table.SetColumnSpan(table.GetControlFromPosition(0, 5)!, 2);


            // ---- Buttons ---- //
            var pnlButtons = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.RightToLeft,
                Padding = new Padding(0),
            };

            btnOk = new Button { Text = "OK", Width = 90, DialogResult = DialogResult.OK };
            btnCancel = new Button { Text = "Cancel", Width = 90, DialogResult = DialogResult.Cancel };
            btnDefaults = new Button { Text = "Restore Defaults", AutoSize = true };
            btnDefaults.Click += (_, __) => ApplyToUI(AppSettings.Defaults());

            pnlButtons.Controls.Add(btnOk);
            pnlButtons.Controls.Add(btnCancel);
            pnlButtons.Controls.Add(btnDefaults);

            table.Controls.Add(pnlButtons, 0, 6);
            table.SetColumnSpan(pnlButtons, 2);

            Controls.Add(table);

            btnOk.Click += (_, __) =>
            {
                PushFromUI(_settings);
                _settings.Save();
                DialogResult = DialogResult.OK;
                Close();
            };

            btnCancel.Click += (_, __) => Close();
        }

        public static bool Edit(IWin32Window owner, AppSettings settings)
        {
            using var dlg = new SettingsForm(settings);
            var r = dlg.ShowDialog(owner);
            if (r == DialogResult.OK)
            {
                // Copy back what was saved in the dialog //
                var reloaded = AppSettings.LoadOrDefault();
                settings.MaxDownloadAttempts = reloaded.MaxDownloadAttempts;
                settings.JitterDelayMs = reloaded.JitterDelayMs;
                settings.NavQuickRetries = reloaded.NavQuickRetries;
                settings.NavQuickBaseDelayMs = reloaded.NavQuickBaseDelayMs;
                settings.NavMaxRetries = reloaded.NavMaxRetries;
                return true;
            }
            return false;
        }

        // ---- Helpers ---- //
        private static void AddRow(TableLayoutPanel table, string label, out NumericUpDown nud, int min, int max, int value)
        {
            var row = table.RowCount - 1;
            table.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            var lbl = new Label
            {
                Text = label,
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleLeft,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 6, 6, 6)
            };
            nud = new NumericUpDown
            {
                Minimum = min,
                Maximum = max,
                Value = Coerce(value, min, max),
                Increment = 1,
                Dock = DockStyle.Left,
                Width = 120
            };

            table.Controls.Add(lbl, 0, row);
            table.Controls.Add(nud, 1, row);
            table.RowCount++;
        }

        private static int Coerce(int value, int min, int max)
        {
            if (value < min) return min; if (value > max) return max; return value;
        }

        private static AppSettings Clone(AppSettings s)
        {
            return new AppSettings
            {
                MaxDownloadAttempts = s.MaxDownloadAttempts,
                JitterDelayMs = s.JitterDelayMs,
                NavQuickRetries = s.NavQuickRetries,
                NavQuickBaseDelayMs = s.NavQuickBaseDelayMs,
                NavMaxRetries = s.NavMaxRetries
            };
        }

        private void ApplyToUI(AppSettings s)
        {
            nudMaxAttempts.Value = Coerce(s.MaxDownloadAttempts, (int)nudMaxAttempts.Minimum, (int)nudMaxAttempts.Maximum);
            nudJitter.Value = Coerce(s.JitterDelayMs, (int)nudJitter.Minimum, (int)nudJitter.Maximum);
            nudQuickRetries.Value = Coerce(s.NavQuickRetries, (int)nudQuickRetries.Minimum, (int)nudQuickRetries.Maximum);
            nudQuickBaseMs.Value = Coerce(s.NavQuickBaseDelayMs, (int)nudQuickBaseMs.Minimum, (int)nudQuickBaseMs.Maximum);
            nudNavMax.Value = Coerce(s.NavMaxRetries, (int)nudNavMax.Minimum, (int)nudNavMax.Maximum);
        }

        private void PushFromUI(AppSettings s)
        {
            s.MaxDownloadAttempts = (int)nudMaxAttempts.Value;
            s.JitterDelayMs = (int)nudJitter.Value;
            s.NavQuickRetries = (int)nudQuickRetries.Value;
            s.NavQuickBaseDelayMs = (int)nudQuickBaseMs.Value;
            s.NavMaxRetries = (int)nudNavMax.Value;
        }
    }
}
