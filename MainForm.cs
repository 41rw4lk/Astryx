// Astryx DL — MainForm
// WinForms .NET 8 front-end for the Astryx downloader.
// Public-clean version: patch tags removed for sharing.

// (c) Astryx project. See repository LICENSE for terms.

using System;
using System.Buffers.Binary;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using System.Text.Json; // (+) for on-disk de-dup index
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Forms.VisualStyles;
using System.Xml.Linq;
using CMDownloaderUI.Net;
using MaterialSkin2DotNet;
using MaterialSkin2DotNet.Controls;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Playwright;
using Microsoft.VisualBasic.Logging;
using Microsoft.Win32.SafeHandles;
using static System.Net.Mime.MediaTypeNames;
using static System.Net.WebRequestMethods;
using ContentAlignment = System.Drawing.ContentAlignment;
// Alias the tuple type so you don’t repeat it everywhere:
using DownloadItem =
    (System.Uri url, CMDownloaderUI.MainForm.Naming naming, int idx, string kind, string? referer, string? matchKey);
using File = System.IO.File;
using Font = System.Drawing.Font; // resolve ambiguity vs System.Net.Mime.MediaTypeNames
using MSkin = MaterialSkin2DotNet;
using NetCookie = System.Net.Cookie;



namespace CMDownloaderUI
{
    internal sealed partial class MainForm : MaterialForm
    {

        // — hold-first-then-match knobs
        private const long MIN_LARGE_BYTES = 8L * 1024 * 1024; // 8 MiB
        private const long TINY_BYTES = 256L * 1024; // 256 KiB (micro-clip only)
        private const long MIN_VIDEO_BYTES = 3L * 1024 * 1024; // 3 MiB
        private static readonly int[] SIZE_BACKOFFS = new[] { 10_000, 20_000, 30_000, 60_000 }; // ~2 min cap

        // Apply to ANY body-carrying GET (SS + SEG)
        // Apply to ANY body-carrying GET (SS + SEG)
        private static void NormalizeDownloadRequest(HttpRequestMessage req)
        {
            // Don't force protocol || connection reuse here — callers decide.
            // Just ensure we don't get compressed bodies (resume-unfriendly).
            try
            {
                if (req.Headers.AcceptEncoding.Count == 0)
                    req.Headers.AcceptEncoding.ParseAdd("identity");
                else
                {
                    // Normalize to identity if anything else leaked in
                    req.Headers.AcceptEncoding.Clear();
                    req.Headers.AcceptEncoding.ParseAdd("identity");
                }
            }
            catch { /* best-effort */ }
            // DO NOT touch:
            // - req.Version
            // - req.VersionPolicy
            // - req.Headers.ConnectionClose
        }


        private void LogQuarantine(string reason, string finalPath, string qPath)
        {
            // existing QUAR summary
            try
            {
                string action;
                try
                {
                    if (!string.IsNullOrEmpty(qPath) && File.Exists(qPath))
                        action = "moved";
                    else if (!string.IsNullOrEmpty(finalPath) && !File.Exists(finalPath))
                        action = "deleted";
                    else
                        action = "unknown";
                }
                catch { action = "unknown"; }

                string refUrl = "";
                try { refUrl = _curRef.Value ?? ""; } catch { }

                Log($"[QUAR] {reason} action={action} file={Path.GetFileName(finalPath)} q={qPath}" +
                    (!string.IsNullOrWhiteSpace(refUrl) ? $" ref={refUrl}" : ""));

                if (action == "deleted")
                {
                    Log($"[MISS] {reason} file={Path.GetFileName(finalPath)}" +
                        (!string.IsNullOrWhiteSpace(refUrl) ? $" ref={refUrl}" : ""));
                }
            }
            catch { }


            // per-video FS trace for anything that ends up in quarantine
            try
            {
                long len = 0;
                try
                {
                    if (!string.IsNullOrWhiteSpace(qPath) && File.Exists(qPath))
                        len = new FileInfo(qPath).Length;
                }
                catch { }

                TraceVidFs("QUAR", qPath, len, reason);
            }
            catch { }

            // reason counters
            try
            {
                _quarByReason[reason] = (_quarByReason.TryGetValue(reason, out var n) ? n + 1 : 1);
            }
            catch { }
        }

        private void LogAccept(string kind, string finalPath, long size)
        {
            // existing ACCEPT summary
            try
            {
                Log($"[ACCEPT] {kind} {Path.GetFileName(finalPath)} size={size:N0}");
            }
            catch { }

            // per-video FS trace for anything we accept
            try
            {
                TraceVidFs("ACCEPT", finalPath, size, kind);
            }
            catch { }

            // accept counters
            try
            {
                if (string.Equals(kind, "VID", StringComparison.OrdinalIgnoreCase)) _accVid++;
                else if (string.Equals(kind, "IMG", StringComparison.OrdinalIgnoreCase)) _accImg++;
            }
            catch { }
        }

        private void LogVerifySummary()
        {
            try
            {
                var parts = new List<string>();
                foreach (var kv in _quarByReason) parts.Add($"{kv.Key}={kv.Value}");
                var reasons = parts.Count > 0 ? string.Join(", ", parts) : "none";
                Log($"[VERIFY.SUMMARY] accept: VID={_accVid}, IMG={_accImg}  |  quarantined: total={_qBad}  reasons: {reasons}");
            }
            catch { }
        }



        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, object> _pmapLock = new();
        private readonly System.Threading.AsyncLocal<string?> _curRef = new();
        private readonly object _ssSendLock = new();

        // ===== UI ===== //
        private MaterialTextBox2 txtUrl = null!;
        private MaterialTextBox2 txtFolder = null!;
        private Button btnBrowse = null!;
        private MaterialButton btnStart = null!;
        private MaterialButton btnStop = null!;
        private CheckBox chkOpenOnDone = null!;
        private TextBox txtLog = null!;
        private MaterialProgressBar pbOverall = null!;
        private MaterialProgressBar pbCurrent = null!;
        private NotifyIcon? _trayIcon;
        private ContextMenuStrip? _trayMenu;

        // INSERT AFTER
        private sealed class AccentProgressBar : MaterialProgressBar
        {
            public Color FillColor { get; set; } = Color.Empty; // Empty = use Accent //

            protected override void OnPaint(PaintEventArgs e)
            {
                base.OnPaint(e); // draw default first, then overlay our color

                int max = Math.Max(1, Maximum);
                float pct = Math.Min(1f, Math.Max(0f, Value / (float)max));

                var inner = new Rectangle(2, 2, Width - 4, Height - 4);
                var fill = new Rectangle(inner.X, inner.Y, (int)(inner.Width * pct), inner.Height);

                var color = FillColor.IsEmpty
                    ? MSkin.MaterialSkinManager.Instance.ColorScheme.AccentColor // overall = accent
                    : FillColor; // current = custom

                using var b = new SolidBrush(color);
                e.Graphics.FillRectangle(b, fill);
            }
        }
        // Settings items (add once near your other menu fields)
        // === noise/redo suppression (safe, no content skipping) ===
        private readonly HashSet<string> _knownGone = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _segSafeHosts = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _noRangeHosts = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _rangeSafeHosts = new();
        private DateTime _lastSegGateLogUtc = DateTime.MinValue;
        private static bool _webUiStarted;


        // per-host health scoring + cooldowns
        private readonly System.Collections.Generic.Dictionary<string, int> _hostScore = new();
        private readonly System.Collections.Generic.Dictionary<string, System.DateTime> _hostScoreAt = new();
        private readonly System.Collections.Generic.Dictionary<string, System.DateTime> _hostCooldown = new();
        private const int SCORE_MAX = 8, SCORE_MIN = -8;
        private const int SCORE_DECAY_SEC = 60; // decay toward 0 every 60s
        private const int COOLDOWN_SEC = 45; // backoff after a penalty
        private System.Windows.Forms.Timer? _webUiHostTimer;

        // fields
        private volatile bool _simpleMode;
        private DateTime _simpleModeUntil;
        private int _simpleModeFlakes;
        // Nudge the planner after an SS transport flake
        private volatile bool __preferSegmentedNextTry;

        // cooldown for sick edges
        private readonly Dictionary<string, DateTime> _edgeCooldownUntil = new(StringComparer.OrdinalIgnoreCase);

        private readonly Dictionary<string, DateTime> _dupNoticeUntil = new(StringComparer.OrdinalIgnoreCase);
        // soft TTL for per-host "no-range" bans (cleared on 206)

        // response cache hints
        private readonly Dictionary<string, System.Net.Http.Headers.EntityTagHeaderValue> _etagByUrl = new();
        private readonly Dictionary<string, DateTimeOffset> _lastModByUrl = new();


        // LED: small network-activity indicator -------------------------------
        private ActivityLed _netLed = null!;
        private System.Windows.Forms.Timer _ledIdleTimer = null!;
        private Label lblOverall = null!;
        private Label lblCurrent = null!;
        private Label lblHealth = null!;
        private Label lblHealthState = null!;
        private CheckBox chkAdblockOn = null!;
        private Button btnAdblockUpdate = null!;
        private Label lblAdblockUpdate = null!;
        private CheckBox chkParallel = null!;
        private NumericUpDown nudNV = null!;
        private NumericUpDown nudVID = null!;
        private Label lblParallel = null!;
        private Label lblSpeed = null!;
        private ActivityLed _led = null!;
        private System.Windows.Forms.Timer _ledIdle = new();
        private System.Windows.Forms.Timer _ledHeartbeat = new();
        private PaintEventHandler? _modeUnderlinePaint;
        private long _lastLedKickMs = 0;

        // — draw banner in the Windows title bar (non-client area)
        private Bitmap _captionBanner = null; // disable NC banner
        [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern IntPtr GetWindowDC(IntPtr hWnd);
        [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);
        [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern int GetSystemMetrics(int nIndex);

        private const int WM_NCPAINT = 0x0085;
        private const int WM_NCACTIVATE = 0x0086;
        private const int SM_CXFRAME = 32, SM_CYFRAME = 33, SM_CXPADDEDBORDER = 92, SM_CYCAPTION = 4;
        private const bool NATURAL_URL_ONLY = false;


        // --- Edge selector integration (fields) ---
        private CMDownloaderUI.Net.EdgeSelector? _edge;
        private CancellationTokenSource? _edgeCts;

        // keep this inside the MainForm class (once only)
        private static readonly string[] MEDIA_HOST_CANDIDATES = new[]
        {
            "n3.coomer.st",
            "n2.coomer.st",
            "n4.coomer.st",
            "n1.coomer.st",

};      private static readonly SemaphoreSlim _pwInstallLock = new(1, 1);
        private static volatile bool _pwChromiumReady = false;

        private string[] GetMediaHostsSafe()
        {
            try
            {
                var cfg = Path.Combine(_appDir, "hosts.txt");
                if (File.Exists(cfg))
                {
                    var list = File.ReadAllLines(cfg)
                                   .Select(l => l.Trim())
                                   .Where(s => !string.IsNullOrWhiteSpace(s) && !s.StartsWith("#"))
                                   .Distinct(StringComparer.OrdinalIgnoreCase)
                                   .ToArray();
                    if (list.Length > 0) return list;
                }
            }
            catch (Exception ex)
            {
                Log($"[EDGE] host list load failed: {ex.Message}");
            }
            return MEDIA_HOST_CANDIDATES; // fallback to your built-ins
        }
        private DateTime _edgeStickUntil = DateTime.MinValue;
        private readonly Dictionary<string, DateTime> _edgeCooldown = new();
        // run-scoped ranged host pin + rotation cursor
        private string? _pinnedRangeHost;
        private int _rrCursor = 0;
        private readonly HashSet<string> _range200 = new(StringComparer.OrdinalIgnoreCase);

        // Edge selector state
        private bool _edgeValidatedOnce = false; // run candidate validation once per run
                                                 // one-shot flag: when true, btnAdd click must NOT auto-start
        private bool _addCameFromWeb = false;



        private string? _runId;
        private CancellationTokenSource? _cts;
        private static volatile bool s_StopRequested = false;
        // backing state for WebUI tuners + mode
        private volatile int _nvWorkersLimit = 0; // 0 = use UI/auto
        private volatile int _vidWorkersLimit = 0; // 0 = use UI/auto
        private volatile string _modeLane = "all"; // "img" | "vid" | "all"

        // run-scoped soft pause (WebUI)
        private static volatile bool s_PauseRequested = false;
        private IPlaywright? _pw;
        private IBrowser? _browser;
        private IBrowserContext? _context;
        private IPage? _page;

        // ===== Paths ===== //
        private string _userRootFolder = string.Empty;
        private string ImagesRoot => Path.Combine(_userRootFolder, "Images");
        private string VideoRoot => Path.Combine(_userRootFolder, "VideoAudio");
        // Central quarantine roots (unified; no per-post folders)
        private string ImagesQuarantine => Path.Combine(ImagesRoot, "_Quarantine");
        private string VideoQuarantine => Path.Combine(VideoRoot, "_Quarantine");

        private bool _hadDownloads = false;
        // segmented download knobs
        private const int RANGE_POOL_MAX = 16;
        private const int RANGE_PER_FILE_MAX = 5; // up to 8 lanes per file
        private const long SEGMENT_BYTES = 8L * 1024 * 1024; // 8 MiB segments
        private const long MIN_SEGMENT_BYTES = 8L * 1024 * 1024; // 8 MB
        private const long SS_FASTPATH_MAX = 48L * 1024 * 1024; // ≤48 MB → single-stream
        private const long FIRST_CHUNK_BYTES = 4L << 20; // 4 MiB slab canary
        private const long SS_RESUME_MIN_BYTES = 64L * 1024 * 1024; // 64 MB – min SS partial to resume


        // size tiers
        private const long SEG_TIER_SMALL_MAX = 200L * 1024 * 1024; // 50–200 MB → x3-ish
        private const long SEG_TIER_MED_MAX = 600L * 1024 * 1024; // 200–600 MB → x4–x5

        // image thresholds
        private const long SMALL_IMAGE_BYTES = 512L * 1024; // tiny image threshold

        // Quick de-dupe: in-flight guard + temp fingerprint storage
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _inflightQuick
            = new System.Collections.Concurrent.ConcurrentDictionary<string, string>();


        // Clean, no-reflection fallback. Keep this inside the MainForm class.
        private void TryStartSingleStreamFallback()
        {
            try { Log("[SEG.FALLBACK] Falling back to single-stream (outer flow)."); } catch { }
        }

        // Typed quick add: O(1) insert, no sweeping
        // Typed quick add: O(1) insert, but prefer videos over images to avoid collisions
        private void IndexAddQuick(long len, string hash64k, string path)
        {
            if (len <= 0) return;
            if (string.IsNullOrWhiteSpace(hash64k)) return;
            if (string.IsNullOrWhiteSpace(path)) return;

            string ext = Path.GetExtension(path)?.ToLowerInvariant() ?? string.Empty;
            bool isVid = ext == ".mp4" || ext == ".m4v" || ext == ".mov" ||
                         ext == ".avi" || ext == ".mkv" || ext == ".webm";

            string bare = $"{len}:{hash64k}";
            string key = (isVid ? "V:" : "I:") + bare;

            lock (_idxQuick)
            {
                if (isVid)
                {
                    // Video wins: nuke any image entry for this len+hash
                    _idxQuick.Remove("I:" + bare);
                    _idxQuick.Remove(bare); // cleanup legacy if present
                    _idxQuick[key] = path; // record video as the winner
                    _quickAddedThisRun[key] = path;
                }
                else
                {
                    // Image: only add if there is NOT already a video indexed for this len+hash
                    if (_idxQuick.ContainsKey("V:" + bare))
                    {
                        // We already have a video with this fingerprint; don’t create an image collision.
                        // (Optional log, if you ever want it)
                        // try { Log($"[INDEX] skip image quick-entry; video already indexed for {bare}"); } catch { }
                        return;
                    }

                    _idxQuick[key] = path;
                    _quickAddedThisRun[key] = path;
                }
            }
        }

        private bool IndexTryGetByQuickSameKind(long len, string hash64k, string assetKind, out string path)
        {
            path = string.Empty;

            if (!IndexTryGetByQuick(len, hash64k, out path))
                return false;

            bool wantVid = string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase);
            bool existingIsVid = IsVideoPath(path);

            if (wantVid != existingIsVid)
            {
                // Cross-type quick hit: treat as "no match"
                path = string.Empty;
                return false;
            }

            return true;
        }



        // Remove a quick-index entry by (len, hash). Clears both typed namespaces.
        private void IndexRemoveQuick(long len, string hash64k)
        {
            string bare = $"{len}:{hash64k ?? string.Empty}";
            lock (_idxQuick)
            {
                // current typed keys
                _idxQuick.Remove("V:" + bare);
                _idxQuick.Remove("I:" + bare);

                // legacy/untyped (if any persisted)
                _idxQuick.Remove(bare);
            }
        }
        // Delete a bad quick-hit video and purge it from the quick index
        private void DeleteBadQuickVideo(string path, long len, string? hash64k, string reason)
        {
            try
            {
                Log($"[DEL.BAD] {reason} file={Path.GetFileName(path)} len={len:N0}");
            }
            catch { /* logging best-effort */ }

            // Evict quick entry so this ghost can’t be reused
            try
            {
                if (!string.IsNullOrEmpty(hash64k))
                    IndexRemoveQuick(len, hash64k);
            }
            catch { }

            // Nuke the file itself
            try
            {
                if (System.IO.File.Exists(path))
                    System.IO.File.Delete(path);
            }
            catch { /* best-effort delete */ }

            try { _qBad++; } catch { } // still count toward VERIFY.SUMMARY, but no quarantine folder
        }

        private void IndexRemove(string key)
        {
            if (string.IsNullOrWhiteSpace(key)) return;

            _inflightQuick.TryRemove(key, out _);
            _inflightQuick.TryRemove("V:" + key, out _);
            _inflightQuick.TryRemove("I:" + key, out _);
            if (key.StartsWith("V:") || key.StartsWith("I:"))
                _inflightQuick.TryRemove(key, out _);

            // NEW: persistent quick eviction
            try
            {
                var b = (key.StartsWith("V:") || key.StartsWith("I:")) ? key[2..] : key;
                var p = b.Split(':');
                if (p.Length == 2 && long.TryParse(p[0], out var l)) IndexRemoveQuick(l, p[1]);
            }
            catch { }
        }





        private bool _qRegistered = false;
        private string? _qKey = null;
        private long _qLen = 0;
        private string? _qHash64k = null;

        private long _probeInteresting;



        private static int ChooseSegmentCount(long sizeBytes, int poolFree)
        {
            if (sizeBytes > 0 && sizeBytes <= SS_FASTPATH_MAX) return 1;
            // Hard short-circuit: no segmentation below 64 MB
            if (sizeBytes > 0 && sizeBytes < MIN_SEGMENT_BYTES) return 1;

            // SuggestSegments already caps by poolAvailable internally.
            return SuggestSegments(sizeBytes, Math.Max(1, poolFree), _activeSegVideos);
        }






        // === PATCH START: Playwright recovery & DONE drain (no nullable-awaitables) =================
        private async Task ExecWithPlaywrightRecoveryAsync(
    Func<IPage, Task> action,
    string tag,
    int maxAttempts,
    CancellationToken ct)
        {
            if (maxAttempts < 1) maxAttempts = 1;

            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    await action(_page!).ConfigureAwait(false);
                    return;
                }
                catch (OperationCanceledException) { throw; }

                // Page/browser closed → recreate page (your existing logic)
                catch (PlaywrightException pwx) when (
                       (pwx.Message?.IndexOf("Execution context was destroyed", StringComparison.Ordinal) ?? -1) >= 0
                    || (pwx.Message?.IndexOf("Target closed", StringComparison.Ordinal) ?? -1) >= 0
                    || (pwx.Message?.IndexOf("Navigation failed because page was closed", StringComparison.Ordinal) ?? -1) >= 0
                    || (pwx.Message?.IndexOf("Underlying browser has been closed", StringComparison.Ordinal) ?? -1) >= 0)
                {
                    try { Log($"[PW-RECOVER] {tag}: {pwx.Message?.Trim()}"); } catch { }
                    await RecreatePageAsync(ct).ConfigureAwait(false);

                    int backoff = Math.Min(1200, 200 * attempt);
                    int jitter = (attempt <= 5) ? Random.Shared.Next(0, 100) : 0;
                    await Task.Delay(backoff + jitter, ct).ConfigureAwait(false);
                    continue;
                }

                // Plain timeouts / slow site → try reload (NetworkIdle), then recreate if needed
                catch (TimeoutException tex)
                {
                    try { Log($"[PW-TIMEOUT] {tag}: {tex.Message?.Trim()} — reload→retry"); } catch { }

                    var reloaded = false;
                    try
                    {
                        await _page!.ReloadAsync(new()
                        {
                            WaitUntil = WaitUntilState.NetworkIdle,
                            Timeout = 45000
                        }).ConfigureAwait(false);
                        reloaded = true;
                    }
                    catch
                    {
                        try { Log("[PW-TIMEOUT] reload failed — recreating page"); } catch { }
                        await RecreatePageAsync(ct).ConfigureAwait(false);
                    }

                    int backoff = Math.Min(2000, 300 * attempt);
                    int jitter = (attempt <= 5) ? Random.Shared.Next(0, 200) : 0;
                    await Task.Delay(backoff + jitter, ct).ConfigureAwait(false);
                    continue;
                }

                // Some providers throw PlaywrightException with timeout text instead of TimeoutException
                catch (PlaywrightException pwx) when (
                       (pwx.Message?.IndexOf("Timeout", StringComparison.OrdinalIgnoreCase) ?? -1) >= 0
                    || (pwx.Message?.IndexOf("timed out", StringComparison.OrdinalIgnoreCase) ?? -1) >= 0)
                {
                    try { Log($"[PW-TIMEOUT] {tag}: {pwx.Message?.Trim()} — reload→retry"); } catch { }

                    try
                    {
                        await _page!.ReloadAsync(new()
                        {
                            WaitUntil = WaitUntilState.NetworkIdle,
                            Timeout = 45000
                        }).ConfigureAwait(false);
                    }
                    catch
                    {
                        try { Log("[PW-TIMEOUT] reload failed — recreating page"); } catch { }
                        await RecreatePageAsync(ct).ConfigureAwait(false);
                    }

                    int backoff = Math.Min(2000, 300 * attempt);
                    int jitter = (attempt <= 5) ? Random.Shared.Next(0, 200) : 0;
                    await Task.Delay(backoff + jitter, ct).ConfigureAwait(false);
                    continue;
                }
            }

            try { Log($"[PW-RECOVER] {tag}: attempts exhausted ({maxAttempts})"); } catch { }

        }

        private async Task<bool> EnsurePlaywrightChromiumAsync()
        {
            if (_pwChromiumReady) return false;
            bool pwInstallClaimsLogin = false;


            await _pwInstallLock.WaitAsync();
            try
            {
                if (_pwChromiumReady) return false;

                var baseDir = AppContext.BaseDirectory;
                var pwDir = Path.Combine(baseDir, "pw-browsers");
                Directory.CreateDirectory(pwDir);

                // IMPORTANT: Playwright .NET needs the shipped driver bits (.playwright) alongside the app.
                var shippedDriverDir = Path.Combine(baseDir, ".playwright");
                if (!Directory.Exists(shippedDriverDir))
                {
                    try { Log("[PW] Install blocked: missing .playwright folder next to the app (publish output)."); } catch { }
                    return false;
                }

                bool present =
                    Directory.Exists(pwDir) &&
                    (Directory.EnumerateFiles(pwDir, "chrome.exe", SearchOption.AllDirectories).Any() ||
                     Directory.EnumerateFiles(pwDir, "headless_shell.exe", SearchOption.AllDirectories).Any());

                if (present)
                {
                    _pwChromiumReady = true;
                    try { Log("[PW] OK (browsers present)"); } catch { }
                    return false;
                }
                // [PW.INSTALL] reuse existing autologin spinner (treat install as "login busy")
                if (System.Threading.Interlocked.CompareExchange(ref _coomerLoginInFlight, 1, 0) == 0)
                    pwInstallClaimsLogin = true;

                _pwInstalling = true;
                try { Log("[PW] First run — installing Playwright browsers… (one-time)"); } catch { }

                Task? spinTask = null;
                System.Threading.CancellationTokenSource? spinCts = null;

                // Always show *some* spinner during Playwright install.
                



                int codeChromium = -1, codeHeadless = -1;

                // Run installs off-thread so we don’t hard-block an async request/thread.
                await Task.Run(() =>
                {
                    codeChromium = Microsoft.Playwright.Program.Main(new[] { "install", "chromium" });
                    codeHeadless = Microsoft.Playwright.Program.Main(new[] { "install", "chromium-headless-shell" });
                }).ConfigureAwait(false);


                // Re-check presence
                present =
                    Directory.Exists(pwDir) &&
                    (Directory.EnumerateFiles(pwDir, "chrome.exe", SearchOption.AllDirectories).Any() ||
                     Directory.EnumerateFiles(pwDir, "headless_shell.exe", SearchOption.AllDirectories).Any());

                try { Log($"[PW] Install exit codes: chromium={codeChromium}, headless={codeHeadless}"); } catch { }

                if (!present)
                {
                    try { Log("[PW] Install failed — pw-browsers still empty (check internet / firewall / .playwright shipped)."); } catch { }
                    return false;
                }

                _pwChromiumReady = true;
                try { Log("[PW] Install complete (pw-browsers populated)"); } catch { }
                return true; // <-- tells caller we JUST installed
            }
            catch (Exception ex)
            {
                try { Log("[PW] Install failed: " + ex.Message); } catch { }
                throw;
            }
            finally
            {
                if (pwInstallClaimsLogin)
                    System.Threading.Interlocked.Exchange(ref _coomerLoginInFlight, 0);
                _pwInstalling = false;
                _pwInstallLock.Release();
            }
        }







        private async Task RecreatePageAsync(CancellationToken ct)
        {
            try { Log("[PW-RECOVER] Recreating page/context…"); } catch { }

            // Close old page safely (no nullable-awaitable)
            try
            {
                var pg = _page;
                if (pg != null)
                    await pg.CloseAsync().ConfigureAwait(false);
            }
            catch { /* ignore */ }

            if (_context == null || _browser == null || _pw == null)
            {
                // rebuild fully using your existing init
                await SetupPlaywrightAsync(ct).ConfigureAwait(false);
            }
            else
            {
                _page = await _context.NewPageAsync().ConfigureAwait(false);
            }

            // restore cookies/headers/etc. if you mirror them to HttpClient
            try { await SyncCookiesFromPlaywrightAsync().ConfigureAwait(false); } catch { }

            try { Log((_context != null) ? "[PW-RECOVER] New page created." : "[PW-RECOVER] Playwright reinitialized."); } catch { }
        }

        // put this INSIDE MainForm (e.g., right after CountLike)

        private void WriteLog(string message) => Log(message);
        // head+tail window scan for moov/moof (front- || end-placed)
        private static bool HasMoovOrMoofHeadTail(string path, int windowBytes = 4 * 1024 * 1024)
        {
            // For small files (≤4 MiB), scan the entire file for moov/moof.
            try
            {
                var fi = new FileInfo(path);
                long len = fi.Length;
                if (len > 0 && len <= 4L * 1024 * 1024)
                {
                    byte[] data = File.ReadAllBytes(path);
                    for (int i = 0; i <= data.Length - 4; i++)
                    {
                        byte b0 = data[i], b1 = data[i + 1], b2 = data[i + 2], b3 = data[i + 3];
                        // ASCII "moov" or "moof"
                        if ((b0 == (byte)'m' && b1 == (byte)'o' && b2 == (byte)'o' && b3 == (byte)'v') ||
                            (b0 == (byte)'m' && b1 == (byte)'o' && b2 == (byte)'o' && b3 == (byte)'f'))
                            return true;
                    }
                    return false; // full scan and no moov/moof → treat as missing
                }
            }
            catch { /* fall back to existing head/tail logic */ }

            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                long len = fs.Length;
                if (len < 12) return false;

                int w = (int)Math.Min(Math.Max(4096, windowBytes), Math.Min(len, 8L * 1024 * 1024)); // 4KB..8MB
                static bool HasTag(ReadOnlySpan<byte> buf, ReadOnlySpan<byte> tag)
                {
                    for (int i = 0; i <= buf.Length - 4; i++)
                        if (buf[i] == tag[0] && buf[i + 1] == tag[1] && buf[i + 2] == tag[2] && buf[i + 3] == tag[3])
                            return true;
                    return false;
                }

                // HEAD window
                byte[] head = new byte[w];
                int hn = fs.Read(head, 0, head.Length);
                if (hn >= 4 && (HasTag(head.AsSpan(0, hn), "moov"u8) || HasTag(head.AsSpan(0, hn), "moof"u8)))
                    return true;

                // TAIL window
                fs.Seek(Math.Max(0, len - w), SeekOrigin.Begin);
                byte[] tail = new byte[w];
                int tn = fs.Read(tail, 0, tail.Length);
                if (tn >= 4 && (HasTag(tail.AsSpan(0, tn), "moov"u8) || HasTag(tail.AsSpan(0, tn), "moof"u8)))
                    return true;

                return false;
            }
            catch { return false; }
        }


        // quick head/tail scan for a playable track ('vide' or 'soun')
        private static bool HasPlayableTrackQuick(string path)
        {
            // For small files (≤4 MiB), run a full-file scan for hdlr + vide/soun.
            try
            {
                var fi = new FileInfo(path);
                long len = fi.Length;
                if (len > 0 && len <= 4L * 1024 * 1024)
                {
                    byte[] data = File.ReadAllBytes(path);
                    bool sawHdlr = false;

                    for (int i = 0; i <= data.Length - 4; i++)
                    {
                        byte b0 = data[i], b1 = data[i + 1], b2 = data[i + 2], b3 = data[i + 3];

                        if (!sawHdlr)
                        {
                            // ASCII "hdlr"
                            if (b0 == (byte)'h' && b1 == (byte)'d' && b2 == (byte)'l' && b3 == (byte)'r')
                                sawHdlr = true;
                        }
                        else
                        {
                            // ASCII "vide" or "soun"
                            if (b0 == (byte)'v' && b1 == (byte)'i' && b2 == (byte)'d' && b3 == (byte)'e')
                                return true;
                            if (b0 == (byte)'s' && b1 == (byte)'o' && b2 == (byte)'u' && b3 == (byte)'n')
                                return true;
                        }
                    }

                    // No playable handler found in full scan
                    return false;
                }
            }
            catch { /* fall back to existing partial scan */ }

            try
            {
                var fi = new System.IO.FileInfo(path);
                if (!fi.Exists || fi.Length < 24) return false;

                const int WIN = 1024 * 1024; // 1 MiB
                int headLen = (int)System.Math.Min(WIN, fi.Length);
                int tailLen = (int)System.Math.Min(WIN, System.Math.Max(0, fi.Length - headLen));

                byte[] head = new byte[headLen];
                byte[] tail = tailLen > 0 ? new byte[tailLen] : System.Array.Empty<byte>();

                using (var fs = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read))
                {
                    fs.Read(head, 0, headLen);
                    if (tailLen > 0)
                    {
                        fs.Seek(fi.Length - tailLen, System.IO.SeekOrigin.Begin);
                        fs.Read(tail, 0, tailLen);
                    }
                }

                // byte signatures
                byte[] hdlr = { (byte)'h', (byte)'d', (byte)'l', (byte)'r' };
                byte[] vide = { (byte)'v', (byte)'i', (byte)'d', (byte)'e' };
                byte[] soun = { (byte)'s', (byte)'o', (byte)'u', (byte)'n' };

                static bool Find(byte[] buf, byte[] sig)
                {
                    if (buf.Length < sig.Length) return false;
                    int last = buf.Length - sig.Length;
                    for (int i = 0; i <= last; i++)
                    {
                        // manual compare is fastest and avoids Span features if not available
                        if (buf[i] == sig[0] && buf[i + 1] == sig[1] && buf[i + 2] == sig[2] && buf[i + 3] == sig[3])
                            return true;
                    }
                    return false;
                }

                bool hasHdlr = Find(head, hdlr) || (tailLen > 0 && Find(tail, hdlr));
                if (!hasHdlr) return false; // no handler box seen anywhere → not playable

                bool hasVide = Find(head, vide) || (tailLen > 0 && Find(tail, vide));
                bool hasSoun = Find(head, soun) || (tailLen > 0 && Find(tail, soun));

                // at least one playable handler ('vide' or 'soun') must be present
                return hasVide || hasSoun;
            }
            catch
            {
                return false; // on any IO/read error, treat as not playable
            }
        }


        // === PATCH END =============================================================================


        // ===== HTTP client (static, reused) ===== //
        // Fast media extension check (no ToLowerInvariant in hot path)
        private static readonly string[] MEDIA_EXTS = new[]
        {
    ".mp4",".m4v",".mov",".webm",".mkv",".avi",".mp3",".m4a",".flac"
};
        private static bool HasMediaExt(string s)
        {
            int dot = s.LastIndexOf('.');
            if (dot < 0 || dot >= s.Length) return false;
            ReadOnlySpan<char> ext = s.AsSpan(dot);
            foreach (var e in MEDIA_EXTS)
                if (ext.Equals(e.AsSpan(), StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        // AFTER (Note the new handler and CookieContainer)
        private static readonly CookieContainer _cookieContainer = new CookieContainer();
        // Replace the old _http field with this:
        private static readonly HttpClient _http = CreateHttpClient_();

        // Small factory keeps init tidy and avoids top-level statements.
        private static HttpClient CreateHttpClient_()
        {
            // Use SocketsHttpHandler so we can enable H/2 hardening.
            var handler = new System.Net.Http.SocketsHttpHandler
            {
                AllowAutoRedirect = true,
                AutomaticDecompression = System.Net.DecompressionMethods.GZip
                                        | System.Net.DecompressionMethods.Deflate
                                        | System.Net.DecompressionMethods.Brotli,
                CookieContainer = _cookieContainer,
                MaxConnectionsPerServer = Math.Max(RANGE_POOL_MAX, 8),
                EnableMultipleHttp2Connections = true,
                PooledConnectionLifetime = TimeSpan.FromMinutes(8),
                PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
            };

            // Best-effort H/2 keepalive pings (older frameworks may not have these; that’s fine)
            try
            {
                handler.KeepAlivePingDelay = TimeSpan.FromSeconds(20);
                handler.KeepAlivePingTimeout = TimeSpan.FromSeconds(5);
            }
            catch { /* property not supported; ignore */ }

            var client = new HttpClient(handler)
            {
                Timeout = Timeout.InfiniteTimeSpan
            };

            // Prefer HTTP/2 by default (your per-request overrides still win)
            client.DefaultRequestVersion = System.Net.HttpVersion.Version20;
            client.DefaultVersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionOrHigher;

            return client;
        }

        // set a desktop UA and common accept headers once (global)
        static MainForm()
        {
            const string UA =
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                "(KHTML, like Gecko) Chrome/126.0 Safari/537.36";

            try { _http.DefaultRequestHeaders.Remove("User-Agent"); } catch { /* no-op */ }
            _http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", UA);

            _http.DefaultRequestHeaders.Accept.Clear();
            _http.DefaultRequestHeaders.Accept.ParseAdd("*/*");

            _http.DefaultRequestHeaders.AcceptLanguage.Clear();
            _http.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en-US,en;q=0.9");

            _http.DefaultRequestHeaders.AcceptEncoding.Clear();
            _http.DefaultRequestHeaders.AcceptEncoding.ParseAdd("gzip, deflate, br");

            // Keep persistent connections unless you deliberately want Connection: close
            _http.DefaultRequestHeaders.ConnectionClose = false;
        }


        private async Task SyncCookiesFromPlaywrightAsync()
        {
            if (_context == null) return;

            // rate-limit cookie sync to once every 30s
            if (_lastCookieSyncUtc.HasValue && (DateTime.UtcNow - _lastCookieSyncUtc.Value).TotalSeconds < 30)
                return;

            var cookies = await _context.CookiesAsync().ConfigureAwait(false);

            // Use txtUrl if present; otherwise default to coomer
            Uri baseUri;
            try
            {
                var t = (txtUrl?.Text ?? string.Empty).Trim();
                if (!Uri.TryCreate(t, UriKind.Absolute, out baseUri))
                    baseUri = new Uri("https://coomer.st/");
            }
            catch
            {
                baseUri = new Uri("https://coomer.st/");
            }

            foreach (var c in cookies)
            {
                var path = string.IsNullOrEmpty(c.Path) ? "/" : c.Path!;
                var net = new NetCookie(c.Name, c.Value, path)
                {
                    Secure = c.Secure,
                    HttpOnly = c.HttpOnly
                };
                net.Domain = string.IsNullOrWhiteSpace(c.Domain) ? baseUri.Host : c.Domain;
                _cookieContainer.Add(net);

            }

            // Always update counters so WebUI can see login state immediately
            var now = DateTime.UtcNow;

            if (cookies.Count != _lastCookieCount)
            {
                Log($"[SESSION] Synced {cookies.Count} cookies to HttpClient.");
            }

            _lastCookieCount = cookies.Count;
            _lastCookieSyncUtc = now;

        }




        // ===== Adblock state ===== //
        private bool _adblockOn = true;
        private bool _adblockAutoUpdateOnStart = true; // default ON
        private bool _adblockStartupChecked = false; // prevents duplicate refresh
        private string _appDir = string.Empty;
        private string _easyListPath = string.Empty;
        private HashSet<string> _adblockRules = new(StringComparer.OrdinalIgnoreCase);
        private string _prefsPath = string.Empty;
        private string _uiPrefsPath = string.Empty;
        bool _loadingPrefs = false;
        // [COOMER.REMEMBER] persisted creds (DPAPI → ui.ini)
        bool _coomerRemember = false;
        string _coomerRememberUser = "";
        string _coomerRememberPass = "";
        private DateTime? _adblockLastUpdateUtc = null;
        private DateTime? _lastCookieSyncUtc = null;

        private const int ADBLOCK_UPDATE_DAYS = 7;
        private async Task EnsureEasyListFreshAsync(CancellationToken ct = default)
        {
            try
            {
                if (!_adblockAutoUpdateOnStart) return;
                var path = _easyListPath;
                bool need = string.IsNullOrWhiteSpace(path) ||
                            !File.Exists(path) ||
                            new FileInfo(path).Length < 1024;
                if (!need && _adblockLastUpdateUtc.HasValue)
                    need = (DateTime.UtcNow - _adblockLastUpdateUtc.Value).TotalDays >= ADBLOCK_UPDATE_DAYS;

                if (!need) return;

                Log("[ADBLOCK] Refreshing filter list on startup…");
                await RefreshAdblockRulesAsync(ct).ConfigureAwait(false); // uses your existing fetcher
                _adblockLastUpdateUtc = DateTime.UtcNow;
                Log($"[ADBLOCK] Loaded {_adblockRules.Count:N0} rules.");
                SaveUIPrefs(); // persist _adblockLastUpdateUtc
                ApplyAdblockUpdateVisibility(); // hide chip if we just updated

                // If rules are present || the menu is ON, make sure the runtime flag is ON //
                if (_miAdblock?.Checked == true) _adblockOn = true;
                if (_adblockRules.Count > 0 && !_adblockOn) _adblockOn = true;

            }
            catch (Exception ex)
            {
                Log("[ADBLOCK] refresh failed on startup: " + ex.Message);
            }
        }
        private async Task RefreshAdblockRulesAsync(CancellationToken ct = default)
        {
            try
            {
                // Where to save rules
                if (string.IsNullOrWhiteSpace(_easyListPath))
                {
                    if (string.IsNullOrWhiteSpace(_appDir))
                        _appDir = AppDomain.CurrentDomain.BaseDirectory; // fallback
                    _easyListPath = Path.Combine(_appDir, "easylist.txt");
                }

                // Download EasyList (streaming)
                var easyUrl = "https://easylist-downloads.adblockplus.org/easylist.txt";
                using var req = new HttpRequestMessage(HttpMethod.Get, easyUrl);

                using var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                // early abort for non-video responses (scope-safe)
                {
                    var __u = req.RequestUri;
                    var __ct = res.Content.Headers.ContentType?.MediaType?.ToLowerInvariant() ?? "";

                    // Heuristic: URL or Content-Disposition looks like video, but CT is obviously non-video
                    bool __urlLooksVideo =
                        __u != null && (
                            __u.AbsolutePath.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".mov", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".webm", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".mkv", StringComparison.OrdinalIgnoreCase)
                        );

                    var __cd = res.Content.Headers.ContentDisposition;
                    var __cdName = __cd?.FileNameStar ?? __cd?.FileName ?? "";
                    bool __cdLooksVideo =
                        !string.IsNullOrEmpty(__cdName) && (
                            __cdName.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".mov", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".webm", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".mkv", StringComparison.OrdinalIgnoreCase)
                        );

                    bool __isObviouslyNonVideo =
                        __ct.StartsWith("image/") || __ct.StartsWith("text/") ||
                        __ct == "application/json" || __ct == "application/xml";

                    if ((__urlLooksVideo || __cdLooksVideo) && __isObviouslyNonVideo)
                    {
                        res.Dispose();
                        try { Log("[CT→RETRY] SS non-video — nudging segmented on next attempt"); } catch { }
                        System.Threading.Volatile.Write(ref __preferSegmentedNextTry, true);
                        // If the segmented retry label is in scope here, use it and delete the throw:
                        // goto __SEG_RETRY_ONCE;
                        throw new IOException("Non-video content-type on SS; retry segmented");

                    }
                }

                // early non-video abort (scope-safe: no assetKind/remoteUrl)
                {
                    var __u = req.RequestUri;
                    var __mt = res.Content.Headers.ContentType?.MediaType?.ToLowerInvariant() ?? "";

                    // Heuristics: only fire if the request/filename clearly looks like a video,
                    // but the server is returning an obviously non-video type.
                    bool __urlLooksVideo =
                        __u != null && (
                            __u.AbsolutePath.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".mov", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".webm", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".mkv", StringComparison.OrdinalIgnoreCase)
                        );

                    var __cd = res.Content.Headers.ContentDisposition;
                    var __cdName = __cd?.FileNameStar ?? __cd?.FileName ?? "";
                    bool __cdLooksVideo =
                        !string.IsNullOrEmpty(__cdName) && (
                            __cdName.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".mov", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".webm", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".mkv", StringComparison.OrdinalIgnoreCase)
                        );

                    bool __isObviouslyNonVideo =
                        __mt.StartsWith("image/") || __mt.StartsWith("text/") ||
                        __mt == "application/json" || __mt == "application/xml";

                    if ((__urlLooksVideo || __cdLooksVideo) && __isObviouslyNonVideo)
                    {
                        res.Dispose();
                        try { Log("[CT→RETRY] SS non-video — nudging segmented on next attempt"); } catch { }
                        System.Threading.Volatile.Write(ref __preferSegmentedNextTry, true);
                        // If the segmented retry label is in scope here, use it and delete the throw:
                        // goto __SEG_RETRY_ONCE;
                        throw new IOException("Non-video content-type on SS; retry segmented");

                    }
                }

                // replace the bad line with this:
                try { Log($"[PROTO] phase=ADBLOCK v={res.Version} host={(req.RequestUri?.Host ?? "?")}"); } catch { }

                res.EnsureSuccessStatusCode();
                long __expectedLen = res.Content.Headers.ContentLength ?? -1;

                // Persist to disk (stream to a temp, then atomic-ish move)
                var dir = Path.GetDirectoryName(_easyListPath)!;
                Directory.CreateDirectory(dir);
                var tmpPath = _easyListPath + ".tmp";
                TraceAnyWrite(tmpPath, -1, "TMP.CREATE");
                await using (var fs = new FileStream(tmpPath, FileMode.Create, FileAccess.Write, FileShare.None, 128 * 1024, useAsync: true))
                {

                    using (var s = await res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
                    {
                        byte[] buf = new byte[1 << 16];
                        int n = await s.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
                        if (n == 0)
                        {
                            try { await Task.Delay(150, ct).ConfigureAwait(false); } catch (OperationCanceledException) { throw; }
                            n = await s.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
                            if (n == 0) throw new IOException("[SEG.ZERO]");
                        }
                        await fs.WriteAsync(buf, 0, n, ct).ConfigureAwait(false);
                        await s.CopyToAsync(fs, 1 << 16, ct).ConfigureAwait(false);
                    }
                }
                try
                {
#if NET6_0_OR_GREATER
                    File.Move(tmpPath, _easyListPath, overwrite: true);
#else
            if (File.Exists(_easyListPath)) File.Delete(_easyListPath);
            File.Move(tmpPath, _easyListPath);
#endif
                }
                catch
                {
                    try { File.Copy(tmpPath, _easyListPath, overwrite: true); File.Delete(tmpPath); } catch { /* best-effort */ }
                }

                // Parse minimal from disk (streaming): keep non-empty, non-comment, non-section lines
                _adblockRules.Clear();
                using (var sr = new StreamReader(new FileStream(_easyListPath, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, useAsync: true)))
                {
                    string? line;
                    while ((line = await sr.ReadLineAsync().ConfigureAwait(false)) != null)
                    {
                        line = line.Trim();
                        if (line.Length == 0) continue;
                        if (line.StartsWith("!")) continue; // comments
                        if (line.StartsWith("[")) continue; // section headers
                        _adblockRules.Add(line);
                    }
                }
            }
            catch (Exception ex)
            {
                Log("[ADBLOCK] refresh failed: " + ex.Message);
                throw;
            }
            // --- END OF RUN SUMMARY ---
            try { Log($"[SUMMARY] Rejected = {_sumRejects}"); } catch { }

        }


        private const string BUYME_URL = "https://buymeacoffee.com/airwalk";
        private LinkLabel _lnkCoffee;
        private ToolStripMenuItem? _miWrapLog;
        private bool _prefWrapLog = true; // default: wrapped (no horiz bar) //
        private Panel? _pnlLogScroll;
        private System.Windows.Forms.Timer? _tmrLogScroll;
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern int SendMessage(IntPtr h, int msg, int w, int l);
        private const int EM_GETFIRSTVISIBLELINE = 0x00CE, EM_GETLINECOUNT = 0x00BA;




        // --- de-dup index (on-disk) ---
        private string _mediaIndexPath = string.Empty; // (+)
        private string _mediaFailIndexPath = string.Empty;

        private readonly Dictionary<string, string> _idxQuick = new(StringComparer.OrdinalIgnoreCase); // key: "len:sha64k" -> canonical path (+)
        private readonly Dictionary<string, string> _idxFull = new(StringComparer.OrdinalIgnoreCase); // key: sha256_full -> canonical path (+)
        private static readonly SemaphoreSlim _idxLock = new(1, 1); // (+) //
                                                                    // tracks hard-failed media across runs (keyed by matchKey or fallback)
        private readonly Dictionary<string, FailMeta> _failIndex = new(StringComparer.OrdinalIgnoreCase);

        // ---- index save/prune options (optional) ----
        private bool _optSaveIndexPerFile = false; // default: coalesced/timer + exit save
        private bool _optSaveIndexOnExit = true;

        // ---- auto-prune (optional) ----
        private bool _optAutoPrune = false; // toggle in Settings
        private int _optAutoPruneMinutes = 60; // 15/30/60/180 via menu
        private System.Windows.Forms.Timer? _pruneTimer;
        private int _pruneRunning = 0; // 0/1 — guard to prevent overlap
                                       // ---- index auto-flush (coalesced) ---- //
        private volatile int _idxDirty = 0; // 0/1 — set when index changed
        private DateTime _idxLastSaveUtc = DateTime.MinValue;
        private System.Windows.Forms.Timer? _idxFlushTimer;
        private volatile bool _pwInstalling;

        private void IndexMarkDirty()
        {
            System.Threading.Interlocked.Exchange(ref _idxDirty, 1);
        }

        private void EnsureIndexFlushTimer()
        {
            if (_idxFlushTimer != null) return;
            _idxFlushTimer = new System.Windows.Forms.Timer { Interval = 30000 }; // 30s
            _idxFlushTimer.Tick += async (_, __) =>
            {
                if (System.Threading.Interlocked.Exchange(ref _idxDirty, 0) == 1)
                {
                    try
                    {
                        await SaveMediaIndexAsync().ConfigureAwait(false);
                        _idxLastSaveUtc = DateTime.UtcNow;
                        // optional, quiet by default:
                        // Log("[INDEX] auto-saved (flush timer).");
                    }
                    catch { /* best-effort */ }
                }
            };
            _idxFlushTimer.Start();
        }

        private void StopIndexFlushTimer()
        {
            try { _idxFlushTimer?.Stop(); _idxFlushTimer?.Dispose(); } catch { }
            _idxFlushTimer = null;
        }


        private readonly Random _rnd = new();
        private int _jitterScore = 0;
        private DateTime _rlLastDecayUtc = DateTime.UtcNow;


        // v1_0_4 health/cooldown //
        private int _rlScore = 0;
        private DateTime _cooldownUntilUtc = DateTime.MinValue;
        private string _healthState = "OK";

        // ===== Regex helpers ===== //
        private bool _brandStickyHooked;

        private static readonly Regex RX_OF_SUFFIX = new(@"(?:^|\s)by\s+[_\p{L}\p{N}\.\-]+?\s+from\s+OnlyFans\s*$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex RX_POST_PREFIX = new(@"^\s*Post\s+", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex RX_MULTI_WS = new(@"\s{2,}", RegexOptions.Compiled);
        // Only strip obvious downscaled variants; do NOT match by extension (e.g., webp)
        private static readonly Regex RX_IMG_TOKENS = new(@"(?:\d{3,4}x\d{3,4}|\bsize\d+|\bthumb\b|\bpreview\b|\bsmall\b|\bmedium\b|\blarge\b|\boriginal\b)(?=$|[_\-.])", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private DateTime _lastEdgeLogAt = DateTime.MinValue;

        private readonly Dictionary<string, Uri> _videoBestChoice = new(StringComparer.OrdinalIgnoreCase);

        // --- Active connections per host (lightweight, thread-safe) ---
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _activeByHost
            = new System.Collections.Concurrent.ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        private int CountActiveForHost(string host)
            => (!string.IsNullOrEmpty(host) && _activeByHost.TryGetValue(host, out var n)) ? n : 0;

        private int GetHostLimit(string host)
            => 4; // TODO: return your real per-host cap if you have one
        private int _autoLoginAttempted = 0;
        private int _autoLoginDeferred = 0;



        // ===== Parallel config & speed ===== //

        private bool _parallelOn = true;
        // guard writes so only one task touches a given finalPath at a time
        private static readonly ConcurrentDictionary<string, SemaphoreSlim> PathLocks =
            new ConcurrentDictionary<string, SemaphoreSlim>(StringComparer.OrdinalIgnoreCase);
        private int _maxNV = 4; // non-video lane workers //
        private int _maxVID = 3; // video lane workers (items) — segmented download uses its own internal sizing //

        // Hard caps for user-tunable concurrency //
        private const int MAX_IMG_CONC = 8; // non-video lanes cap (images/aux) //
        private const int MAX_VID_CONC = 6; // video lanes cap //

        private readonly Stopwatch _sessionSw = new();

        private int _qBad = 0;
        private long _sessionBytes = 0;
        private readonly Stopwatch _speedUiSw = new();
        private readonly Stopwatch _logUiSw = new();
        private string? _lastLogMsg;
        private long _lastLogTicksUtc; // Environment.TickCount64-ish; use DateTime.UtcNow.Ticks if preferred
        private long _lastUiUpdateTick;
        private static volatile bool s_Draining = false; // block new enqueues during graceful drain
        private static volatile bool s_NoRangeThisRun;

        private static volatile bool _segOverflowOpen;
        private static long _segGateBurstT0Ms;
        private static int _segGateBurst;


        private volatile bool _cancelSignaled = false;
        private static readonly System.Threading.SemaphoreSlim _rangeSlots = new System.Threading.SemaphoreSlim(RANGE_POOL_MAX, RANGE_POOL_MAX);
        private static int _slotDiagTicker = 0;
        private static int _activeSegVideos = 0; // number of videos currently in segmented mode
                                                 // summary counters
        private readonly ConcurrentDictionary<string, byte> _inProgress = new(StringComparer.OrdinalIgnoreCase);
        // Host-level cache for Range support (true = supports Range, false = no Range)
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> _rangeSupportByHost = new(StringComparer.OrdinalIgnoreCase);

        // Per-host "no Range" log de-duplication


        private string _lastEdgeHost = string.Empty;

        private int _sumPosts, _sumImgsOk, _sumVidsOk, _sumVidsFailed, _sumTinyRefreshes, _sumDedupLinks;
        // optional failed names (top few)
        private readonly List<string> _failedVidNames = new();
        // per-post asset counts + cross-post dupes
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, (int img, int vid)> _postAssetCounts
            = new(StringComparer.OrdinalIgnoreCase);

        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, System.Collections.Generic.HashSet<string>> _assetPostIds
            = new(StringComparer.OrdinalIgnoreCase);

        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _assetSampleNames
            = new(StringComparer.OrdinalIgnoreCase);

        // INSERT AFTER
        private static int _lastCookieCount = -1;

        private static int SuggestSegments(long sizeBytes, int poolAvailable, int activeVideos)
        {
            if (sizeBytes > 0 && sizeBytes <= SS_FASTPATH_MAX) return 1;
            if (System.Threading.Volatile.Read(ref s_Draining)) return 1; // snap to single-stream during drain

            // ...existing logic...

            if (sizeBytes < MIN_SEGMENT_BYTES) return 1;

            int target;
            if (sizeBytes <= SEG_TIER_SMALL_MAX) target = 2 + (activeVideos == 1 ? 1 : 0); // 2–3
            else if (sizeBytes <= SEG_TIER_MED_MAX) target = 4 + (activeVideos == 1 ? 2 : 0); // 4–6
            else target = 8 + (activeVideos <= 1 ? 4 : 0); // 8–12

            // Bias lone active video when pool has slack (+3 lanes)
            int free = Math.Max(0, poolAvailable - target);
            if (activeVideos <= 1 && free >= 3) { target += 3; try { if (s_ShouldLogOnce?.Invoke("seg.bias", 60) == true) s_Log?.Invoke($"[SEG] lone-video bias +3 (free={free})"); } catch { } }


            // Respect pool and per-file caps
            target = Math.Min(target, Math.Max(1, poolAvailable));
            target = Math.Min(target, RANGE_PER_FILE_MAX);

            // Cap smallish files to 2 segments max
            if (sizeBytes <= 160L * 1024 * 1024 && target > 2) target = 2;

            // Do not exceed what size can support given MIN_SEGMENT_BYTES
            target = Math.Min(target, (int)Math.Max(1, (sizeBytes + MIN_SEGMENT_BYTES - 1) / MIN_SEGMENT_BYTES));
            if (sizeBytes > SS_FASTPATH_MAX && sizeBytes <= 320L * 1024 * 1024 && target > 2)
                target = 2;
            return Math.Max(1, target);
        }

        private readonly System.Collections.Concurrent.ConcurrentQueue<(Uri url, Naming naming, int idx, string kind, string? referer, string? matchKey)> _retryQ = new();
        private readonly HashSet<string> _retrySeen = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _completedKeys = new(StringComparer.OrdinalIgnoreCase);
        private int _wdEnqueued = 0, _wdSucceeded = 0;
        private const int WD_MAX_PASSES = 2;
        private const int WD_PER_ITEM_ATTEMPTS = 2;

        // ====== De-dup helpers (index + hashing) ======

        private static string Hex2FromStableHash(string s)
        {
            using var sha = SHA256.Create();
            var b = sha.ComputeHash(Encoding.UTF8.GetBytes(s ?? string.Empty));
            return b[0].ToString("x2");
        }

        private static async Task<string?> ComputeSha256First64kAsync(Stream s, CancellationToken ct)
        {
            using var sha = SHA256.Create();
            byte[] buf = new byte[8192];
            int total = 0;

            while (total < 65536)
            {
                int need = 65536 - total;
                int want = Math.Min(buf.Length, need); // don't over-read past 64 KB
                int n = await s.ReadAsync(buf.AsMemory(0, want), ct).ConfigureAwait(false);
                if (n <= 0) break;

                sha.TransformBlock(buf, 0, n, null, 0);
                total += n;
            }

            if (total == 0) return null;
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return Convert.ToHexString(sha.Hash!).ToLowerInvariant();
        }


        private (long Len, string? Hash64k)? _lastQuickProbe; // optional for debugging

        private void EnsurePruneTimer()
        {
            if (_pruneTimer != null) return;
            _pruneTimer = new System.Windows.Forms.Timer();
            _pruneTimer.Interval = Math.Max(1, _optAutoPruneMinutes) * 60 * 1000;
            _pruneTimer.Tick += async (_, __) =>
            {
                if (System.Threading.Interlocked.Exchange(ref _pruneRunning, 1) == 1) return;
                try
                {
                    int n = await PruneMediaIndexAsync().ConfigureAwait(false);
                    if (n > 0) Log($"[INDEX] Auto-prune removed {n} dead entr{(n == 1 ? "y" : "ies")}.");
                }
                catch (Exception ex)
                {
                    Log($"[INDEX] Auto-prune error: {ex.Message}");
                }
                finally
                {
                    System.Threading.Volatile.Write(ref _pruneRunning, 0);
                }
            };
        }

        private void ApplyPruneInterval(int minutes)
        {
            _optAutoPruneMinutes = minutes;
            if (_pruneTimer != null) _pruneTimer.Interval = minutes * 60 * 1000;
            SaveUIPrefs();
            Log($"[INDEX] Auto-prune interval set to {minutes} min.");
        }


        private async Task<(long Len, string? Hash64k)?> TryQuickFingerprintAsync(Uri url, string? referer, CancellationToken ct)
        {
            long len = -1;
            bool __isImg = IsImagePath(url.AbsolutePath);
            int __headSecs = __isImg ? 3 : 12; // was 12
            int __getSecs = __isImg ? 5 : 20; // was 20

            // 1) HEAD (short timeout for images)
            try
            {
                using var head = new HttpRequestMessage(HttpMethod.Head, url);
                var refUri = PickReferer(url, referer);
                if (refUri != null) head.Headers.Referrer = refUri;

                using var headCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                headCts.CancelAfter(TimeSpan.FromSeconds(__headSecs));

                // HEAD: size only
                using var res = await _http.SendAsync(head, HttpCompletionOption.ResponseHeadersRead, headCts.Token).ConfigureAwait(false);
                if (!res.IsSuccessStatusCode)
                {
                    var sc = (int)res.StatusCode;
                    try
                    {
                        var __ar = (res.Headers.AcceptRanges?.FirstOrDefault() ?? "");
                        var __cl = (res.Content.Headers.ContentLength ?? -1);
                        System.Threading.Interlocked.Increment(ref _probeHeadTotal);

                        bool __boring = ((int)res.StatusCode == 200) &&
                                        (__ar.IndexOf("bytes", StringComparison.OrdinalIgnoreCase) >= 0) &&
                                        (__cl > 0);

                        if (__boring) System.Threading.Interlocked.Increment(ref _probeHeadSupp);
                        else
                        {
                            System.Threading.Interlocked.Increment(ref _probeHeadInteresting);
                            Log($"[PROBE.HEAD] {(int)res.StatusCode} v={res.Version} ar=[{__ar}] cl={__cl}");
                        }
                    }
                    catch { }


                    if (res.StatusCode == System.Net.HttpStatusCode.NotFound || res.StatusCode == System.Net.HttpStatusCode.Gone)
                    {
                        try { EdgeCooldown(url.Host, TimeSpan.FromSeconds(90)); } catch { }
                        try { if (string.Equals(_pinnedRangeHost, url.Host, StringComparison.OrdinalIgnoreCase)) { _pinnedRangeHost = null; Log("[PIN.DROP] due to 404/410"); } } catch { }
                    }

                    // don’t throw; let caller continue with SS paths
                }

                if (res.IsSuccessStatusCode && res.Content?.Headers?.ContentLength.HasValue == true)
                    len = res.Content.Headers.ContentLength.Value;
                try
                {
                    var __ar = (res.Headers.AcceptRanges?.FirstOrDefault() ?? "");
                    var __cl = (res.Content.Headers.ContentLength ?? -1);

                    System.Threading.Interlocked.Increment(ref _probeHeadTotal);

                    bool __boring = ((int)res.StatusCode == 200) &&
                                    (__ar.IndexOf("bytes", StringComparison.OrdinalIgnoreCase) >= 0) &&
                                    (__cl > 0);

                    if (__boring) System.Threading.Interlocked.Increment(ref _probeHeadSupp);
                    else
                    {
                        System.Threading.Interlocked.Increment(ref _probeHeadInteresting);
                        Log($"[PROBE.HEAD] {(int)res.StatusCode} v={res.Version} ar=[{__ar}] cl={__cl}");
                    }

                    // keep this block unchanged
                    try
                    {
                        var clVal = res.Content.Headers.ContentLength ?? 0;
                        if (url.Host.StartsWith("img.", StringComparison.OrdinalIgnoreCase) && clVal > 0 && clVal <= 300 * 1024)
                        {
                            Log("[RANGE] tiny image — SS bias for 10s");
                            _lastSegZeroUtc = DateTime.UtcNow;
                            s_NoRangeThisRun = true;
                        }
                    }
                    catch { }
                }
                catch { }


                // Soft signal from HEAD (do NOT pin on this alone)
                bool headSaysBytes = res.Headers?.AcceptRanges?.Any(v => v.Equals("bytes", StringComparison.OrdinalIgnoreCase)) == true;
                if (headSaysBytes)
                {
                    // DIAG ONLY
                    // if (s_ShouldLogOnce?.Invoke("range.head.bytes", 60) == true)
                    //     Log($"[RANGE.HEAD] {url.Host} advertises bytes");
                }


                // VALIDATE: tiny ranged GET (0–0) — this is where we pin/ban
                using var rangeProbe = new HttpRequestMessage(HttpMethod.Get, url);
                rangeProbe.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 0);
                rangeProbe.Headers.ConnectionClose = true;
                rangeProbe.Version = System.Net.HttpVersion.Version11;

                using var resProbe = await _http.SendAsync(rangeProbe, HttpCompletionOption.ResponseHeadersRead, headCts.Token).ConfigureAwait(false);
                try
                {
                    var cr = resProbe.Content.Headers.ContentRange;
                    string crs = (cr != null)
                        ? $"{cr.Unit} {cr.From}-{cr.To}/{(cr.HasLength ? cr.Length.ToString() : "?")}"
                        : "-";
                    System.Threading.Interlocked.Increment(ref _probeR00Total);

                    bool __boring =
                        ((int)resProbe.StatusCode == 206) &&
                        !string.IsNullOrEmpty(crs) &&
                        crs.IndexOf("bytes", StringComparison.OrdinalIgnoreCase) >= 0 &&
                        crs.IndexOf("0-0", StringComparison.OrdinalIgnoreCase) >= 0 &&
                        crs.IndexOf("/", StringComparison.OrdinalIgnoreCase) >= 0;

                    if (__boring) System.Threading.Interlocked.Increment(ref _probeR00Supp);
                    else
                    {
                        System.Threading.Interlocked.Increment(ref _probeR00Interesting);
                        Log($"[PROBE.R0-0] {(int)resProbe.StatusCode} v={resProbe.Version} cr={crs}");
                    }

                }
                catch { }

                if (resProbe.StatusCode == System.Net.HttpStatusCode.PartialContent)
                {
                    // Unban host on 206 + throttled recovery log
                    var h = url.Host;
                    if (_noRangeHosts.Remove(h) && (s_ShouldLogOnce?.Invoke($"range.recover:{h}", 60) == true))
                        try { Log($"[RANGE.RECOVER] {h} 206 probe OK — re-enabling segmentation"); } catch { }
                    try { s_NoRangeThisRun = false; lock (_noRangeHosts) { _noRangeHosts.Remove(h); _noRangeHosts.Remove("*.coomer.st"); } } catch { }

                    // B4A: clear TTL ban on recovery (exact paste line)
                    try { _rangeBanUntil.Remove(h); } catch { }



                    // Good-probe bookkeeping
                    try { BumpHostScore(h, +2); _hostCooldown.Remove(h); } catch { }

                    // DIAG ONLY
                    // ProbeLogThrottled(h, true, $"[RANGE.PROBE] {h} → OK (Range honored)");


                    // 206 observed → nudge host toward range-safe
                    HostRangeScore_Add(h, +1);

                    // Optional pin on first 206 — skip if host is cooling/temp-banned
                    if (!NATURAL_URL_ONLY
                        && string.IsNullOrEmpty(_pinnedRangeHost)
                        && !_noRangeHosts.Contains(h)
                        && !HostInCooldown(h))
                    {
                        _pinnedRangeHost = h;
                        try
                        {
                            if (s_ShouldLogOnce?.Invoke("edge.pin", 60) == true)
                                Log($"[EDGE.PIN] pin → {_pinnedRangeHost} (0–0 probe)");
                        }
                        catch { /* best-effort log */ }
                    }


                }





                else if (resProbe.StatusCode == HttpStatusCode.OK)
                {
                    // Host ignored Range
                    /* rangeSafe retired */ // lock (_rangeSafeHosts) _rangeSafeHosts.Remove(url.Host);

                    // DIAG ONLY
                    // Log($"[RANGE.PROBE] {url.Host} → IGNORED (200 OK)");
                }



            }
            catch (Exception ex)
            {
                var h = url?.Host;
                if (!string.IsNullOrEmpty(h) && _qfFailSeen.Add(h))
                    LogEx("[QF] HEAD failed", ex);
            }


            // 2) 64k hash via GET (short timeout for images)
            string? h64 = null;
            try
            {
                var refUri = PickReferer(url, referer);
                bool __minBytesForRange = _qLen >= MIN_SEGMENT_BYTES;
                bool tryRange = !_noRangeHosts.Contains(url.Host) && !s_NoRangeThisRun && __minBytesForRange;





                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                if (refUri != null) req.Headers.Referrer = refUri;
                // 4 MiB slab canary (matches edge slabs)
                if (tryRange) req.Headers.Range = new RangeHeaderValue(0, (4L << 20) - 1);
                EnsureIdentityIfRanged(req);
                if (tryRange) { req.Version = new System.Version(1, 1); }

                using var getCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                getCts.CancelAfter(TimeSpan.FromSeconds(__getSecs));

                using var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, getCts.Token).ConfigureAwait(false);

                if (tryRange
                    && res.StatusCode == System.Net.HttpStatusCode.PartialContent
                    && string.IsNullOrEmpty(_pinnedRangeHost))
                {
                    if (!NATURAL_URL_ONLY)
                    {
                        _pinnedRangeHost = url.Host;
                        try { if (s_ShouldLogOnce?.Invoke("edge.pin", 60) == true) Log($"[EDGE.PIN] pin → {_pinnedRangeHost} (quick fingerprint)"); } catch { }
                    }
                }


                if (tryRange && res.StatusCode == HttpStatusCode.OK)
                {
                    // Only ban/rotate if seg-eligible; small files keep quiet
                    bool __segEligibleQF = (_qLen >= MIN_SEGMENT_BYTES);

                    if (__segEligibleQF)
                    {
                        try { BumpHostScore(url.Host, -3); StartCooldown(url.Host); } catch { }
                    }

                    if (string.Equals(_pinnedRangeHost, url.Host, StringComparison.OrdinalIgnoreCase))
                        _pinnedRangeHost = null;

                    if (false) /* range200 retired */
                    {
                        var oldHost = url.Host;

                        if (__segEligibleQF && _edge is { } e)
                        {
                            e.HopNext();
                            var nh = e.ResolveHostForNewDownload();
                            if (!string.IsNullOrEmpty(nh) && !string.Equals(nh, oldHost, StringComparison.OrdinalIgnoreCase))
                            {
                                try { url = e.RewriteUriHost(url, nh); } catch { /* best-effort */ }
                                try { Log($"[RANGE] 200 on Range — rotating away from {oldHost} → {nh}"); } catch { }
                                // Range ignored → nudge host toward ss-only
                                HostRangeScore_Add(oldHost, -1);
                            }
                            else
                            {
                                try { Log($"[RANGE] 200 on Range — rotating away from {oldHost} (no alternate)"); } catch { }
                                // Range ignored → nudge host toward ss-only
                                HostRangeScore_Add(oldHost, -1);
                            }
                        }
                        else
                        {
                            // Small file: do not rotate; keep quiet
                            // (was: [RANGE] 200 on Range (small file) — not rotating)

                            // Range ignored (small) → slight nudge toward ss-only
                            HostRangeScore_Add(oldHost, -1);
                        }

                    }


                    await using var s = await res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                    h64 = await ComputeSha256First64kAsync(s, ct).ConfigureAwait(false);
                }

                else if (tryRange && res.StatusCode != HttpStatusCode.PartialContent)
                {
                    if (string.Equals(_pinnedRangeHost, url.Host, StringComparison.OrdinalIgnoreCase)) _pinnedRangeHost = null;
                    res.Dispose();

                    using var req2 = new HttpRequestMessage(HttpMethod.Get, url);
                    if (refUri != null) req2.Headers.Referrer = refUri;
                    try { req2.Headers.AcceptEncoding.Clear(); req2.Headers.AcceptEncoding.ParseAdd("identity"); } catch { }

                    using var res2 = await _http.SendAsync(req2, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                    if (res2.IsSuccessStatusCode)
                    {
                        await using var s2 = await res2.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                        h64 = await ComputeSha256First64kAsync(s2, ct).ConfigureAwait(false);
                    }
                }
                else if (res.IsSuccessStatusCode)
                {
                    await using var s = await res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                    h64 = await ComputeSha256First64kAsync(s, ct).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                var h = url?.Host;
                if (!string.IsNullOrEmpty(h) && _qfFailSeen.Add(h))
                    LogEx("[QF] Range GET failed", ex);
            }


            if (len <= 0 || string.IsNullOrEmpty(h64)) return null;
            _lastQuickProbe = (len, h64);
            return (len, h64);
        }



        private void LogEx(string prefix, Exception ex) => Log($"{prefix}: {ex.GetType().Name}: {ex.Message}");

        // ------------------------------------------------------------
        // quick capability/taste profile for a host/URL
        // ------------------------------------------------------------
        // ------------------------------------------------------------
        // quick capability/taste profile for a host/URL
        // ------------------------------------------------------------
        private async Task ProbeEdgeAsync(Uri url, CancellationToken ct)
        {
            // Skip probe if this run/host is already SS-only
            try
            {
                if (s_NoRangeThisRun && _lastSegZeroUtc.AddSeconds(20) > DateTime.UtcNow) return;
                s_NoRangeThisRun = false; // cap expired → allow seg again
                var __h = url?.Host;
                if (!string.IsNullOrEmpty(__h) && _noRangeHosts.Contains(__h)) return;
            }
            catch { /* best-effort */ }

            try
            {
                // DIAG ONLY
                // Log($"[PROBE] host={url.Host} path={url.AbsolutePath}");


                // DNS
                try
                {
                    var ips = await System.Net.Dns.GetHostAddressesAsync(url.Host);
                    Log($"[PROBE.DNS] {string.Join(", ", ips.Select(x => x.ToString()))}");
                }
                catch (Exception ex)
                {
                    Log($"[PROBE.DNS] fail: {ex.GetType().Name} {ex.Message}");
                }

                // HEAD (baseline headers; latency)
                using (var head = new HttpRequestMessage(HttpMethod.Head, url))
                {
                    var t = System.Diagnostics.Stopwatch.StartNew();
                    using var res = await _http.SendAsync(head, HttpCompletionOption.ResponseHeadersRead, ct);
                    t.Stop();
                    res.EnsureSuccessStatusCode();

                    var acceptRanges = string.Join(",", res.Headers.AcceptRanges);
                    var enc = string.Join(",", res.Content.Headers.ContentEncoding);
                    var cl = res.Content.Headers.ContentLength?.ToString() ?? "?";
                    // gate PROBE.HEAD spam (only log when "interesting")
                    System.Threading.Interlocked.Increment(ref _probeHeadTotal);

                    long __clNum = -1;
                    try { _ = long.TryParse(cl, out __clNum); } catch { __clNum = -1; }

                    bool __boring = ((int)res.StatusCode == 200) &&
                                    ((acceptRanges ?? "").IndexOf("bytes", StringComparison.OrdinalIgnoreCase) >= 0) &&
                                    (__clNum > 0);

                    if (__boring) System.Threading.Interlocked.Increment(ref _probeHeadSupp);
                    else
                    {
                        System.Threading.Interlocked.Increment(ref _probeHeadInteresting);
                        Log($"[PROBE.HEAD] {(int)res.StatusCode} in {t.ElapsedMilliseconds} ms ar=[{acceptRanges}] ce=[{enc}] cl={cl} v={res.Version} " +
                            $"server={GetHeader(res, "server")} via={GetHeader(res, "via")} cf-ray={GetHeader(res, "cf-ray")}");
                    }

                }

                // Range 0-0 (does it honor 206 + Content-Range?)
                using (var r00 = new HttpRequestMessage(HttpMethod.Get, url))
                {
                    r00.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 0);
                    EnsureIdentityIfRanged(r00);
                    r00.Version = new System.Version(1, 1);


                    var t = System.Diagnostics.Stopwatch.StartNew();
                    using var res = await _http.SendAsync(r00, HttpCompletionOption.ResponseHeadersRead, ct);
                    t.Stop();
                    var enc = string.Join(",", res.Content.Headers.ContentEncoding);
                    System.Threading.Interlocked.Increment(ref _probeR00Total);

                    var __cr = res.Content.Headers.ContentRange?.ToString() ?? "";
                    bool __boring =
                        ((int)res.StatusCode == 206) &&
                        __cr.IndexOf("bytes", StringComparison.OrdinalIgnoreCase) >= 0 &&
                        __cr.IndexOf("0-0", StringComparison.OrdinalIgnoreCase) >= 0 &&
                        __cr.IndexOf("/", StringComparison.OrdinalIgnoreCase) >= 0;

                    if (__boring) System.Threading.Interlocked.Increment(ref _probeR00Supp);
                    else
                    {
                        System.Threading.Interlocked.Increment(ref _probeR00Interesting);
                        Log($"[PROBE.R0-0] {(int)res.StatusCode} v={res.Version} {res.Content.Headers.ContentRange} ce=[{enc}] in {t.ElapsedMilliseconds} ms");
                    }

                }

                // Small range (0-65535) throughput + encodings
                using (var r64k = new HttpRequestMessage(HttpMethod.Get, url))
                {
                    r64k.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 65535);
                    EnsureIdentityIfRanged(r64k);
                    r64k.Version = new System.Version(1, 1);


                    var t = System.Diagnostics.Stopwatch.StartNew();
                    using var res = await _http.SendAsync(r64k, HttpCompletionOption.ResponseHeadersRead, ct);
                    res.EnsureSuccessStatusCode();
                    await DrainBytesAsync(res.Content, 65536, ct);
                    t.Stop();
                    var enc = string.Join(",", res.Content.Headers.ContentEncoding);
                    Log($"[PROBE.R64K] {(int)res.StatusCode} v={res.Version} ce=[{enc}] {res.Content.Headers.ContentRange} in {t.ElapsedMilliseconds} ms");
                }

                // SS with default encodings vs identity, measure TTFB + body rate (256 KiB)
                await ProbeSingleStreamVariant(url, useIdentity: false, ct);
                await ProbeSingleStreamVariant(url, useIdentity: true, ct);

                // HTTP/2 single-stream taste (some edges regress on h2)
                await ProbeSingleStreamProtocol(url, HttpVersion.Version20, "h2", ct);
                await ProbeSingleStreamProtocol(url, HttpVersion.Version11, "h1.1", ct);

                // DIAG ONLY
                // Log("[PROBE] done");

            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                try { Log($"[PROBE] fail: {ex.GetType().Name} {ex.Message}"); } catch { }
            }

            // --- local helpers ---
            static string GetHeader(HttpResponseMessage res, string name)
                => res.Headers.TryGetValues(name, out var v) ? v.FirstOrDefault() ?? "" :
                   res.Content.Headers.TryGetValues(name, out var vc) ? vc.FirstOrDefault() ?? "" : "";

            static async Task DrainBytesAsync(HttpContent content, int maxBytes, CancellationToken ct)
            {
                using var s = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                var buf = new byte[8192];
                int remaining = maxBytes;
                while (remaining > 0)
                {
                    var toRead = Math.Min(buf.Length, remaining);
                    var n = await s.ReadAsync(buf.AsMemory(0, toRead), ct);
                    if (n <= 0) break;
                    remaining -= n;
                }
            }

            async Task ProbeSingleStreamVariant(Uri u, bool useIdentity, CancellationToken ct)
            {
                using var req = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, u);
                if (useIdentity)
                {
                    try { req.Headers.AcceptEncoding.Clear(); req.Headers.AcceptEncoding.ParseAdd("identity"); } catch { }
                }
                // Pin to HTTP/1.1 (compat: use System.Version)
                req.Version = new System.Version(1, 1);


                var t = System.Diagnostics.Stopwatch.StartNew();
                using var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
                var ttfbMs = t.ElapsedMilliseconds;
                res.EnsureSuccessStatusCode();

                var sw = System.Diagnostics.Stopwatch.StartNew();
                await DrainBytesAsync(res.Content, 256 * 1024, ct);
                sw.Stop();

                var enc = string.Join(",", res.Content.Headers.ContentEncoding);
                Log($"[PROBE.SS.{(useIdentity ? "identity" : "default")}] {(int)res.StatusCode} v={res.Version} ce=[{enc}] ttfb={ttfbMs}ms sample={sw.ElapsedMilliseconds}ms");
            }

            async Task ProbeSingleStreamProtocol(Uri u, Version ver, string tag, CancellationToken ct)
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, u);
                req.Headers.AcceptEncoding.Clear();
                req.Headers.AcceptEncoding.ParseAdd("identity");
                req.Version = ver; // keep 'ver' but drop VersionPolicy for compatibility


                var t = System.Diagnostics.Stopwatch.StartNew();
                using var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
                var ttfbMs = t.ElapsedMilliseconds;
                res.EnsureSuccessStatusCode();

                await DrainBytesAsync(res.Content, 64 * 1024, ct);

                var enc = string.Join(",", res.Content.Headers.ContentEncoding);
                Log($"[PROBE.SS.{tag}] {(int)res.StatusCode} v={res.Version} ce=[{enc}] ttfb={ttfbMs}ms");
            }
        }




        private async Task<string> ComputeFirst64kSha256FromFileAsync(string path, CancellationToken ct)
        {
            using var sha = SHA256.Create();
            await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, useAsync: true);
            byte[] buf = new byte[65536];
            int total = 0, n;
            while ((n = await fs.ReadAsync(buf.AsMemory(0, buf.Length), ct).ConfigureAwait(false)) > 0 && total < 65536)
            {
                int toHash = Math.Min(n, 65536 - total);
                sha.TransformBlock(buf, 0, toHash, null, 0);
                total += toHash;
                if (toHash < n) break;
            }
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return Convert.ToHexString(sha.Hash!).ToLowerInvariant();
        }


        // Final pass to collapse same-content files (len + first64k sha) //
        private async Task<int> FinalQuickDedupSweepAsync(CancellationToken ct)
        {
            int removed = 0, groups = 0;

            async Task SweepRootAsync(string root)
            {
                if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) return;

                var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

                foreach (var f in Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        var fi = new FileInfo(f);
                        if (!fi.Exists || fi.Length <= 0) continue;

                        string h64 = await ComputeFirst64kSha256FromFileAsync(f, ct).ConfigureAwait(false);
                        string ext = fi.Extension.ToLowerInvariant();
                        string t = (ext == ".mp4" || ext == ".m4v" || ext == ".mov" || ext == ".avi" || ext == ".mkv" || ext == ".webm") ? "V" : "I";
                        string key = $"{t}:{fi.Length}:{h64}";

                        if (!map.TryGetValue(key, out var list)) map[key] = list = new List<string>();
                        list.Add(f);
                    }
                    catch { /* ignore */ }
                }

                foreach (var kv in map)
                {
                    var list = kv.Value;
                    if (list.Count <= 1) continue;
                    groups++;
                    list.Sort(StringComparer.OrdinalIgnoreCase);
                    var canonical = list[0];

                    for (int i = 1; i < list.Count; i++)
                    {
                        var p = list[i];
                        try { File.Delete(p); removed++; } catch { }
                        try { var jpg = Path.ChangeExtension(p, ".jpg"); if (File.Exists(jpg)) File.Delete(jpg); } catch { }
                        TryDeleteIfEmpty(Path.GetDirectoryName(p) ?? "");
                    }

                    // Make quick index point to canonical (typed only)
                    lock (_idxQuick)
                    {
                        _idxQuick[kv.Key] = canonical;
                    }
                }

            }

            await SweepRootAsync(ImagesRoot).ConfigureAwait(false);
            await SweepRootAsync(VideoRoot).ConfigureAwait(false);

            if (removed > 0) Log($"[SWEEP] removed {removed} duplicate files across {groups} groups.");
            return removed;
        }
        // Run-end quarantine sweep for images
        private async Task RunEndQuarantineSweep(CancellationToken ct)
        {
            // Collect quarantine roots (global + per-set)
            var roots = new List<string>();
            try
            {
                var imgRoot = ImagesRoot; // Path.Combine(_userRootFolder, "Images")
                if (Directory.Exists(imgRoot))
                {
                    var globQ = Path.Combine(imgRoot, "_quarantine");
                    if (Directory.Exists(globQ)) roots.Add(globQ);

                    foreach (var d in Directory.EnumerateDirectories(imgRoot, "*_set", SearchOption.TopDirectoryOnly))
                    {
                        var q = Path.Combine(d, "_quarantine");
                        if (Directory.Exists(q)) roots.Add(q);
                    }
                }
            }
            catch { /* ignore */ }

            int found = 0, requeued = 0, gone = 0, remain = 0;

            foreach (var root in roots)
            {
                string[] metas;
                try { metas = Directory.GetFiles(root, "*.qmeta.json", SearchOption.AllDirectories); }
                catch { continue; }

                foreach (var metaPath in metas)
                {
                    ct.ThrowIfCancellationRequested();
                    found++;

                    var filePath = Path.ChangeExtension(metaPath, null); // drop .qmeta.json
                    if (!File.Exists(filePath))
                    {
                        try { File.Delete(metaPath); } catch { }
                        continue;
                    }

                    // Read metadata
                    string postUrl = null, cdnUrl = null;
                    long qLen = -1, localLen = -1;
                    try
                    {
                        using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(metaPath));
                        if (doc.RootElement.TryGetProperty("postUrl", out var p)) postUrl = p.GetString();
                        if (doc.RootElement.TryGetProperty("cdnUrl", out var c)) cdnUrl = c.GetString();
                        if (doc.RootElement.TryGetProperty("qLen", out var qv)) qLen = qv.ValueKind == System.Text.Json.JsonValueKind.Number ? qv.GetInt64() : -1;
                        if (doc.RootElement.TryGetProperty("localLen", out var lv)) localLen = lv.ValueKind == System.Text.Json.JsonValueKind.Number ? lv.GetInt64() : -1;
                    }
                    catch { /* malformed meta; leave quarantined */ }

                    bool headOk = false; long cl = -1;

                    // Prefer probing the recorded CDN URL (same host) to avoid nav
                    if (!string.IsNullOrWhiteSpace(cdnUrl) && Uri.TryCreate(cdnUrl, UriKind.Absolute, out var cdnUri))
                    {
                        using var head = new HttpRequestMessage(HttpMethod.Head, cdnUri);
                        try { head.Headers.AcceptEncoding.Clear(); head.Headers.AcceptEncoding.ParseAdd("identity"); } catch { }

                        HttpResponseMessage res = null;
                        try
                        {
                            res = await _http.SendAsync(head, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

                            if ((int)res.StatusCode == 404 || (int)res.StatusCode == 410)
                            {
                                gone++;
                                try { Log($"[QSWEEP.GONE] {Path.GetFileName(filePath)} → {(int)res.StatusCode}"); } catch { }
                                continue; // leave quarantined; do not enqueue
                            }

                            if ((int)res.StatusCode >= 200 && (int)res.StatusCode < 400)
                            {
                                var mt = res.Content.Headers.ContentType?.MediaType ?? "";
                                bool isImg = mt.StartsWith("image/", StringComparison.OrdinalIgnoreCase);
                                cl = res.Content.Headers.ContentLength ?? -1;

                                // Loosen gate when qLen is unknown: treat as OK if server reports >= 90% of localLen
                                const double SIZE_OK_FLOOR = 0.90;
                                bool sizeOk =
                                    (qLen > 0 && cl == qLen) ||
                                    (qLen <= 0 && localLen > 0 && cl >= (long)Math.Round(localLen * SIZE_OK_FLOOR));

                                headOk = isImg && sizeOk;

                            }
                        }
                        catch { /* network hiccup; fall through */ }
                        finally { res?.Dispose(); }
                    }

                    // Requeue by CDN if probe looked sane
                    if (headOk && Uri.TryCreate(cdnUrl, UriKind.Absolute, out var goodCdn))
                    {
                        try
                        {
                            var fname = Path.GetFileName(filePath);
                            var naming = default(Naming); // reuse default naming; writer will derive set/folder from referer/name
                            EnqueueIfOpen(_imgQ, (goodCdn, naming, 0, "IMG", postUrl, null), _cts?.Token ?? CancellationToken.None);
                            requeued++;
                            try { Log($"[QSWEEP.REQUEUE] IMG {fname} → {goodCdn.Host} len={cl}"); } catch { }
                            continue;
                        }
                        catch { /* leave for next run */ }
                    }
                    try
                    {
                        var fn = System.IO.Path.GetFileName(filePath);
                        Log($"[QSWEEP.SKIP] {fn} qLen={qLen} local={localLen} cl={cl} headOk={headOk}");
                    }
                    catch { /* non-fatal */ }


                    // If CDN missing or inconclusive, punt for now (keep quarantined)
                    remain++;
                }
            }

            try { Log($"[QSWEEP.SUMMARY] found={found} requeued={requeued} gone={gone} remain={remain}"); } catch { }
        }



        private static Uri? PickReferer(Uri url)
        {
            try
            {
                var host = url.Host.ToLowerInvariant();
                if (host.Contains("coomer.st")) return new Uri("https://coomer.st/");
                if (host.Contains("kemono.su")) return new Uri("https://kemono.su/");
                if (host.Contains("onlyfans")) return new Uri("https://onlyfans.com/");
                return new Uri($"{url.Scheme}://{url.Host}/");
            }
            catch { return null; }
        }

        private static string QuickKey(long len, string hash64k) => $"{len}:{hash64k}";
        private static bool IsVideoPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            var ext = Path.GetExtension(path).ToLowerInvariant();
            return ext == ".mp4" || ext == ".m4v" || ext == ".mov";
        }

        private bool IndexTryGetVideoByQuick(long len, string hash64k, out string path)
        {
            path = string.Empty;
            string bare = $"{len}:{hash64k}";

            lock (_idxQuick)
            {
                // 1) Prefer the typed video namespace
                if (_idxQuick.TryGetValue("V:" + bare, out path) && IsVideoPath(path))
                    return true;

                // 2) If we only have an image entry for this len+hash, treat it as a collision, not a hit
                if (_idxQuick.TryGetValue("I:" + bare, out path) && !IsVideoPath(path))
                {
                    try { Log($"[INDEX] quick collision (video probe vs image) — removing {path}"); } catch { }
                    _idxQuick.Remove("I:" + bare);
                    path = string.Empty;
                    return false;
                }

                // 3) Legacy/untagged entry: only accept if it really is a video; otherwise nuke it
                if (_idxQuick.TryGetValue(bare, out path))
                {
                    if (IsVideoPath(path)) return true;

                    try { Log($"[INDEX] quick collision (video probe vs non-video) — removing {path}"); } catch { }
                    _idxQuick.Remove(bare);
                    path = string.Empty;
                    return false;
                }
            }

            return false;
        }

        private bool IndexTryGetByQuick(long len, string hash64k, out string path)
        {
            string bare = $"{len}:{hash64k}";
            lock (_idxQuick)
            {
                // 1) Try typed keys first (no collisions by kind)
                if (_idxQuick.TryGetValue("V:" + bare, out path!) || _idxQuick.TryGetValue("I:" + bare, out path!))
                    return true;

                // 2) Legacy (untyped) key → migrate to typed based on ext, then remove legacy
                if (_idxQuick.TryGetValue(bare, out path!))
                {
                    string ext = Path.GetExtension(path)?.ToLowerInvariant() ?? "";
                    string t = ext switch
                    {
                        ".mp4" or ".m4v" or ".mov" or ".avi" or ".mkv" or ".webm" => "V",
                        _ => "I"
                    };

                    _idxQuick[$"{t}:{bare}"] = path!;
                    _idxQuick.Remove(bare);
                    return true;
                }

                return false;
            }
        }





        private bool IndexTryGetByFull(string fullHash, out string path)
        {
            lock (_idxFull) { return _idxFull.TryGetValue(fullHash, out path!); }
        }

        private void IndexUpsert(long len, string hash64k, string fullHash, string canonicalPath)
        {
            // FULL INDEX ONLY — quick index is handled exclusively in the unified post-save block

            lock (_idxFull)
            {
                if (!_idxFull.TryGetValue(fullHash, out var oldF) ||
                    !string.Equals(oldF, canonicalPath, StringComparison.OrdinalIgnoreCase))
                {
                    _idxFull[fullHash] = canonicalPath;
                }
            }
        }





        private void LoadMediaIndex()
        {
            try
            {
                // per-album boundary: start with clean in-memory maps
                lock (_idxQuick) _idxQuick.Clear();
                lock (_idxFull) _idxFull.Clear();

                if (!File.Exists(_mediaIndexPath)) return;

                using var fs = new FileStream(
                    _mediaIndexPath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    256 * 1024,
                    FileOptions.SequentialScan);

                var blob = JsonSerializer.Deserialize<MediaIndexBlob>(fs);

                // Clean + load QUICK (I:/V: keys only, no empty hashes, file must exist)
                if (blob?.Quick != null && blob.Quick.Count > 0)
                {
                    // 1) basic cleaning (quiet)
                    var cleanedQuick = CleanMediaIndex(blob.Quick, null);

                    // 2) HARD prune: length-match + no quarantine + dedupe-by-path
                    var prunedQuick = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                    foreach (var kv in cleanedQuick)
                    {
                        var key = kv.Key;
                        var path = kv.Value;
                        if (string.IsNullOrWhiteSpace(path)) continue;

                        // skip quarantine buckets
                        var lp = path.ToLowerInvariant();
                        if (lp.Contains("quarantine")) continue;

                        if (!File.Exists(path)) continue;

                        long realLen;
                        try { realLen = new FileInfo(path).Length; }
                        catch { continue; }

                        // parse typed key "I:len:hash" or "V:len:hash"
                        if (key.Length < 4 || key[1] != ':') continue;
                        var parts = key.Split(':');
                        if (parts.Length != 3) continue;
                        if (!long.TryParse(parts[1], out var keyLen)) continue;

                        // drop bogus len variants
                        if (keyLen != realLen) continue;

                        // dedupe by final path (keep first good key)
                        if (!seenPaths.Add(path)) continue;

                        prunedQuick[key] = path;
                    }

                    lock (_idxQuick)
                    {
                        foreach (var kv in prunedQuick)
                            _idxQuick[kv.Key] = kv.Value;
                    }

                    Log($"[DEDUP] Quick hard-prune: in={cleanedQuick.Count} kept={prunedQuick.Count} dropped={cleanedQuick.Count - prunedQuick.Count}");
                }


                // FULL — prune dead paths too (light version)
                if (blob?.Full != null && blob.Full.Count > 0)
                {
                    foreach (var kv in blob.Full)
                    {
                        var path = kv.Value;
                        if (string.IsNullOrWhiteSpace(path)) continue;
                        if (!File.Exists(path)) continue; // << prune dead
                        _idxFull[kv.Key] = path;
                    }
                }


                Log($"[DEDUP] Index loaded: quick={_idxQuick.Count} full={_idxFull.Count}");
            }
            catch (Exception ex)
            {
                Log($"[DEDUP] Index load failed: {ex.Message}");
            }
        }
        // load fail-index sidecar (best-effort)
        private void LoadFailIndex()
        {
            try
            {
                lock (_failIndex) _failIndex.Clear();

                if (string.IsNullOrWhiteSpace(_mediaFailIndexPath)) return;
                if (!File.Exists(_mediaFailIndexPath)) return;

                var json = File.ReadAllText(_mediaFailIndexPath);
                if (string.IsNullOrWhiteSpace(json)) return;

                var map = JsonSerializer.Deserialize<Dictionary<string, FailMeta>>(json);
                if (map == null || map.Count == 0) return;

                lock (_failIndex)
                {
                    foreach (var kv in map)
                    {
                        if (kv.Key == null || kv.Value == null) continue;
                        _failIndex[kv.Key] = kv.Value;
                    }
                }
            }
            catch { /* best-effort */ }
        }


        private async Task SaveMediaIndexAsync()
        {
            if (Interlocked.Exchange(ref _idxDirty, 0) == 0) return;


            try
            {
                // take cleaned snapshots before writing
                Dictionary<string, string> quickSnapshot;
                Dictionary<string, string> fullSnapshot;
                Dictionary<string, FailMeta> failSnapshot;


                lock (_idxQuick)
                {
                    quickSnapshot = CleanMediaIndex(_idxQuick, null);

                }

                lock (_idxFull)
                {
                    fullSnapshot = new Dictionary<string, string>(_idxFull, StringComparer.OrdinalIgnoreCase);
                }
                lock (_failIndex)
                {
                    failSnapshot = new Dictionary<string, FailMeta>(_failIndex, StringComparer.OrdinalIgnoreCase);
                }

                var blob = new MediaIndexBlob
                {
                    Quick = quickSnapshot,
                    Full = fullSnapshot
                };

                var json = JsonSerializer.Serialize(blob, new JsonSerializerOptions { WriteIndented = false });
                await _idxLock.WaitAsync();
                try
                {
                    // TraceAnyWrite(_mediaIndexPath, json?.Length ?? -1, "INDEX.JSON"); // quiet index saves

                    await File.WriteAllTextAsync(_mediaIndexPath, json);
                    _idxDirty = 0;
                    // persist fail-index sidecar
                    if (!string.IsNullOrWhiteSpace(_mediaFailIndexPath))
                    {
                        var failJson = JsonSerializer.Serialize(
                            failSnapshot,
                            new JsonSerializerOptions { WriteIndented = false }
                        );
                        await File.WriteAllTextAsync(_mediaFailIndexPath, failJson);
                    }
                }
                finally { _idxLock.Release(); }
            }
            catch (Exception ex) { Log($"[DEDUP] Index save failed: {ex.Message}"); }
        }


        private async Task<int> PruneMediaIndexAsync()
        {
            int removed = 0;

            await _idxLock.WaitAsync().ConfigureAwait(false);
            try
            {
                // snapshot counts before cleaning
                var beforeQuick = _idxQuick.Count;

                // run both maps through the same cleaner used on load/save
                var cleanedQuick = CleanMediaIndex(_idxQuick, null); // no extra logs here
                var cleanedFull = CleanMediaIndex(_idxFull, null);

                // overwrite in-place so references stay valid
                _idxQuick.Clear();
                foreach (var kv in cleanedQuick)
                    _idxQuick[kv.Key] = kv.Value;

                _idxFull.Clear();
                foreach (var kv in cleanedFull)
                    _idxFull[kv.Key] = kv.Value;

                // report how many quick entries we actually dropped
                removed = beforeQuick - cleanedQuick.Count;
            }
            finally
            {
                _idxLock.Release();
            }

            // Mark dirty; timer will coalesce and persist shortly
            if (removed > 0)
                IndexMarkDirty();

            return removed;
        }




        internal sealed class MediaIndexBlob
        {
            public Dictionary<string, string>? Quick { get; set; }
            public Dictionary<string, string>? Full { get; set; }
        }
        // persistent info about hard-failed media
        class FailMeta
        {
            public int AttemptsTotal { get; set; }
            public DateTime LastAttemptUtc { get; set; }
        }

        [SupportedOSPlatform("windows")]
        private static bool TryCreateHardLink(string linkPath, string existingPath)
        {
            try
            {
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    return false;

                if (File.Exists(linkPath))
                    return true;

                // Hard links must be on the same volume
                var rootA = Path.GetPathRoot(linkPath);
                var rootB = Path.GetPathRoot(existingPath);
                if (!string.Equals(rootA, rootB, StringComparison.OrdinalIgnoreCase))
                    return false;

                // H2: use centralized, safe parent creation
                EnsureParent(linkPath);

                if (CreateHardLinkW(linkPath, existingPath, IntPtr.Zero))
                    return true;

                const int ERROR_ALREADY_EXISTS = 183;
                int err = Marshal.GetLastWin32Error();
                if (err == ERROR_ALREADY_EXISTS && File.Exists(linkPath))
                    return true;

                return false;
            }
            catch
            {
                return false;
            }
        }
        private static bool __LooksLikeVideo(HttpResponseMessage res, Uri remoteUrl)
        {
            // Content-Type
            var mt = res.Content.Headers.ContentType?.MediaType?.ToLowerInvariant() ?? "";

            // Some edges send octet-stream for MP4s; allow it.
            if (mt.StartsWith("video/") || mt == "application/octet-stream" || mt == "application/mp4" || mt == "binary/octet-stream")
                return true;

            // Obvious non-video → reject early
            if (mt.StartsWith("image/") || mt.StartsWith("text/") || mt == "application/json" || mt == "application/xml")
                return false;

            // Content-Disposition filename hint
            var cd = res.Content.Headers.ContentDisposition;
            var cdName = cd?.FileNameStar ?? cd?.FileName ?? "";
            if (!string.IsNullOrEmpty(cdName))
            {
                var n = cdName.ToLowerInvariant();
                if (n.EndsWith(".mp4") || n.EndsWith(".m4v") || n.EndsWith(".mov") || n.EndsWith(".webm") || n.EndsWith(".mkv"))
                    return true;
            }

            // URL path hint (last resort)
            var p = remoteUrl.AbsolutePath.ToLowerInvariant();
            if (p.EndsWith(".mp4") || p.EndsWith(".m4v") || p.EndsWith(".mov") || p.EndsWith(".webm") || p.EndsWith(".mkv"))
                return true;

            // Default: permissive (don’t false-negative on weird servers)
            return true;
        }

        // Add near other helpers (class scope)
        private static bool IsImagePath(string path)
        {
            var ext = System.IO.Path.GetExtension(path);
            return ext.Equals(".jpg", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".jpeg", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".png", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".gif", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".webp", StringComparison.OrdinalIgnoreCase);
        }


        [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateHardLinkW(string lpFileName, string lpExistingFileName, IntPtr lpSecurityAttributes);




        // Global queues (IMG/ZIP lane + VID lane) //
        private BlockingCollection<DownloadItem>? _imgQ;
        private BlockingCollection<DownloadItem>? _vidQ;
        // Safe enqueue that respects cancellation and closed queues //
        // cap = current VID lanes + 2 “elastic” room
        private int CapVideoBacklog(int want)
        {
            int hard = Math.Max(1, _maxVID);
            int soft = hard * 16;
            return Math.Max(0, Math.Min(want, soft));
        }

        // REPLACE [0124.9] helper
        // REPLACE ENTIRE METHOD with this:
        private static void EnqueueIfOpen(BlockingCollection<DownloadItem>? q, DownloadItem item, CancellationToken ct)
        {
            if (string.Equals(item.kind, "ZIP", StringComparison.OrdinalIgnoreCase)) return; // ZIP disabled

            // Block new IMG/VID enqueues during graceful drain
            if (System.Threading.Volatile.Read(ref s_Draining) &&
                (string.Equals(item.kind, "VID", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(item.kind, "IMG", StringComparison.OrdinalIgnoreCase))) return;

            // — live gate using active + queued (recompute each enqueue)
            if (string.Equals(item.kind, "VID", StringComparison.OrdinalIgnoreCase))
            {
                int hard = Math.Max(1, (s_GetMaxVID?.Invoke() ?? 1));
                int soft = hard * 16; // elastic room (hard + 2)
                int active = Math.Max(0, (s_GetInflightVID?.Invoke() ?? 0)); // current workers
                int queued = q?.Count ?? 0; // items waiting

                if (active + queued >= soft)
                {
                    if (s_ShouldLogOnce?.Invoke("gate.vid", 10) == true)
                        s_Log?.Invoke($"[GATE] video backlog full; deferring new video adds. active={active} q={queued} cap={soft}");
                    return;
                }
            }

            try
            {
                if (q is null || q.IsAddingCompleted || ct.IsCancellationRequested) return;
                q.Add(item, ct);
            }
            catch (InvalidOperationException) { /* queue closed – ignore */ }
            catch (OperationCanceledException) { /* stopping – ignore */ }
        }


        // lazy parent + safe prune
        private static void EnsureParent(string path) { var d = Path.GetDirectoryName(path); if (!string.IsNullOrEmpty(d)) { try { Directory.CreateDirectory(d); } catch { } } }
        // Never delete media roots (…\Images, …\VideoAudio) || drive roots, even if empty
        private static void TryDeleteIfEmpty(string dir)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) return;

                // Protect drive roots
                var full = Path.GetFullPath(dir);
                if (string.Equals(full, Path.GetPathRoot(full), StringComparison.OrdinalIgnoreCase)) return;

                // Protect common top-level media roots by name (instance-safe, static method)
                var name = Path.GetFileName(full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                if (string.Equals(name, "Images", StringComparison.OrdinalIgnoreCase)) return;
                if (string.Equals(name, "VideoAudio", StringComparison.OrdinalIgnoreCase)) return;

                if (!Directory.EnumerateFileSystemEntries(full).Any())
                    Directory.Delete(full, false);
            }
            catch { /* best-effort */ }
        }
        // remove stray .ok sidecars under Video root
        private static void DeleteOkSidecars(string videoRoot)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(videoRoot) || !Directory.Exists(videoRoot)) return;
                foreach (var p in Directory.EnumerateFiles(videoRoot, "*.ok", SearchOption.AllDirectories))
                {
                    try { File.Delete(p); } catch { /* best-effort */ }
                }
            }
            catch { /* best-effort */ }
        }

        // --- MP4/M4V quick integrity helpers ---
        private static bool LooksLikeMp4(string path)
        {
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists || fi.Length < 24) return false;

                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                Span<byte> head = stackalloc byte[12];
                if (fs.Read(head) < 12) return false;

                // MP4 family files should start with: size(4) + "ftyp"(4)
                if (!(head[4] == (byte)'f' && head[5] == (byte)'t' && head[6] == (byte)'y' && head[7] == (byte)'p'))
                    return false;

                // make sure we can read a tiny tail (catches many truncated files)
                long tail = Math.Min(32L, fi.Length);
                fs.Seek(fi.Length - tail, SeekOrigin.Begin);
                Span<byte> tailBuf = stackalloc byte[(int)tail];
                return fs.Read(tailBuf) > 0;
            }
            catch { return false; }
        }

        private static string ComputeFirst64kSha256FromFile(string path)
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            byte[] buf = new byte[8192];
            int total = 0, n;
            while (total < 65536 && (n = fs.Read(buf, 0, Math.Min(buf.Length, 65536 - total))) > 0)
            {
                sha.TransformBlock(buf, 0, n, null, 0);
                total += n;
            }
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return Convert.ToHexString(sha.Hash!).ToLowerInvariant();
        }

        private void TryRemoveQuickByFile(string path)
        {
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists) return;
                var h64 = ComputeFirst64kSha256FromFile(path);
                IndexRemoveQuick(fi.Length, h64);
            }
            catch { /* best effort */ }
        }
        // — INSERT AFTER TryRemoveQuickByFile(...)
        private void PurgeCorrupt(string path)
        {
            try { TryRemoveQuickByFile(path); } catch { /* best effort */ }
            try { if (File.Exists(path)) File.Delete(path); } catch { /* in use? ignore */ }
        }

        private void UnbanHostOnSuccess(Uri? u)
        {
            try
            {
                var h = u?.Host;
                if (string.IsNullOrEmpty(h)) return;

                lock (_noRangeHosts) _noRangeHosts.Remove(h);
                /* range200 retired */
                if (ShouldLogOnce("unban:" + h, 60))
                    Log($"[UNBAN] {h} (single-stream success)");
            }
            catch { /* best-effort */ }
        }



        private readonly bool _globalQueueMode = true;
        private int _inflightNV = 0;
        private int _inflightVID = 0;
        // static delegates so static helpers can reach instance state
        private static Action<string>? s_Log;
        private static Func<string, int, bool>? s_ShouldLogOnce;
        private static Func<int>? s_GetInflightVID;
        private static Func<int>? s_GetMaxVID;


        // INSERT ANYWHERE IN MainForm class (near other small helpers)
        // Locks the form to whatever size it is when first shown
        private void LockFormToCurrentSize()
        {
            var sz = this.Size;
            this.MinimumSize = sz;
            this.MaximumSize = sz;
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;
            this.MinimizeBox = true;
        }

        private bool ShouldLogVideoLines() => _mediaMode != MediaMode.Images;
        // INSERT AFTER
        private bool ShouldLogOnce(string key, int seconds = 45)
        {
            var now = DateTime.UtcNow;
            if (_dupNoticeUntil.TryGetValue(key, out var until) && until > now) return false;
            _dupNoticeUntil[key] = now.AddSeconds(Math.Max(5, seconds));
            return true;
        }
        private void LogStopOnce(string msg) { if (ShouldLogOnce("stop", 10)) Log(msg); }

        private void LogSkipExists(string finalPath)
        {
            var name = Path.GetFileName(finalPath);
            if (ShouldLogOnce("skip:" + name)) Log($"[SKIP] Exists → {name}");

            // Unpeg the current progress bar after a skip
            if (pbCurrent != null && !pbCurrent.IsDisposed)
            {
                if (InvokeRequired)
                {
                    BeginInvoke(new Action(() =>
                    {
                        try { pbCurrent.Value = 0; pbCurrent.Invalidate(); } catch { }
                        // reset progress
                        try
                        {
                            var __id = _qKey ?? "";
                            CMDownloaderUI.QueueTap.UpdateWorking(__id, 0, 0);
                        }
                        catch { }

                    }));
                }
                else
                {
                    try { pbCurrent.Value = 0; pbCurrent.Invalidate(); } catch { }
                    // reset progress
                    try
                    {
                        var __id = _qKey ?? "";
                        CMDownloaderUI.QueueTap.UpdateWorking(__id, 0, 0);
                    }
                    catch { }

                }
            }
        }


        private bool ShouldLogImageLines() => _mediaMode != MediaMode.VideoAudio;
        private bool _tinyOff = false; // default off







        public MainForm()
        {
            _loadingPrefs = true;
            Text = "CMDownloaderUI Gold (WinForms .NET 8 + Playwright 1.54.0)";
            Width = 763; Height = 616; // startup size ≈ screenshot //
            StartPosition = FormStartPosition.CenterScreen;
            MainFormAccessor.Set(this);
            


            _appDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CMDownloaderUI");
            try { Directory.CreateDirectory(_appDir); } catch { }
            _easyListPath = Path.Combine(_appDir, "easylist.txt");
            _prefsPath = Path.Combine(_appDir, "prefs.txt");
            _uiPrefsPath = Path.Combine(_appDir, "ui.ini");
            _mediaIndexPath = Path.Combine(_appDir, "media-index.json"); // (+) //
            _mediaFailIndexPath = Path.Combine(_appDir, "media-fail-index.json");

            try { _http.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"); } catch { }
            // --- MaterialSkin2 setup (theme & colors) ----------------------------------- //
            var skin = MSkin.MaterialSkinManager.Instance;
            skin.AddFormToManage(this);
            skin.EnforceBackcolorOnAllComponents = true;
            skin.Theme = MSkin.MaterialSkinManager.Themes.DARK;
            // REPLACE [0141.6]-
            skin.ColorScheme = new MSkin.ColorScheme(
                Color.FromArgb(0x42, 0x42, 0x42), // primary ≈ Grey800
                Color.FromArgb(0x21, 0x21, 0x21), // dark ≈ Grey900
                Color.FromArgb(0x61, 0x61, 0x61), // light ≈ Grey700
                ColorTranslator.FromHtml("#5F7396"), // accent Pantone
                MSkin.TextShade.WHITE

            );
            var accent = skin.ColorScheme.AccentColor;
            // INSERT AFTER
            // REPLACE
            var amber600 = Color.FromArgb(0xFF, 0xB3, 0x00); // Amber 600

            var textMain = Color.White;




            var pnlTop = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 240, FlowDirection = FlowDirection.LeftToRight, WrapContents = true, Padding = new Padding(8) };
            var pnlMain = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8) };
            pnlMain.Padding = new Padding(8, -20, 8, 8); // was (8,8,8,8) → nudge log up


            var lblUrl = new Label { Text = "URL:", AutoSize = true, TextAlign = ContentAlignment.MiddleLeft, Width = 40, Margin = new Padding(0, 8, 4, 0) };
            txtUrl = new MaterialTextBox2 { Width = 640, Text = string.Empty, UseTallSize = false }; // // REPLACE
            var lblFolder = new Label { Text = "Dir:", AutoSize = true, Width = 36, Margin = new Padding(12, 8, 4, 0) };
            txtFolder = new MaterialTextBox2 { Width = 420, Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "CMDownloads"), UseTallSize = false };
            btnBrowse = new Button { Text = "⋯", AutoSize = false, Size = new Size(28, 24), Font = new Font("Segoe UI Symbol", 11f, FontStyle.Bold), Margin = new Padding(4, 4, 0, 0) };
            // — insert right after btnBrowse = new Button { … };
            btnBrowse.Image = null;


            btnStart = new MaterialButton
            {
                Text = "START",
                HighEmphasis = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Type = MaterialButton.MaterialButtonType.Contained,
                UseAccentColor = true
            };

            btnStop = new MaterialButton
            {
                Text = "STOP",
                HighEmphasis = false,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Type = MaterialButton.MaterialButtonType.Outlined,
                Enabled = false
            };
            // chips: fixed slim size + outlined look
            btnStart.AutoSize = btnStop.AutoSize = false;
            btnStart.Type = MaterialSkin2DotNet.Controls.MaterialButton.MaterialButtonType.Contained;
            btnStart.UseAccentColor = true; btnStart.HighEmphasis = true;
            btnStop.Type = MaterialSkin2DotNet.Controls.MaterialButton.MaterialButtonType.Contained;
            btnStop.UseAccentColor = false; btnStop.HighEmphasis = false;
            btnStart.Size = btnStop.Size = new Size(132, 24);


            chkOpenOnDone = new CheckBox { Text = "Open folder when done", Checked = true, AutoSize = true, Margin = new Padding(12, 8, 4, 0) };
            chkAdblockOn = new CheckBox { Text = "Enable Adblock", Checked = true, AutoSize = true, Margin = new Padding(12, 8, 4, 0) };
            // chip-style accent button
            btnAdblockUpdate = new Button { Name = "btnAdblockUpdate", AutoSize = false, Text = "⟳ Update filters", Height = 24, Width = 136, Margin = new Padding(8, 4, 0, 0), FlatStyle = FlatStyle.Flat };
            btnAdblockUpdate.FlatAppearance.BorderSize = 0;
            btnAdblockUpdate.BackColor = accent;
            btnAdblockUpdate.ForeColor = Color.White;
            btnAdblockUpdate.Padding = new Padding(10, 2, 10, 2);
            lblAdblockUpdate = new Label { Text = "Not updated", AutoSize = true, Margin = new Padding(8, 8, 0, 0) };

            chkParallel = new CheckBox { Text = "Enable parallel downloads", Checked = true, AutoSize = true, Margin = new Padding(12, 8, 4, 0) };
            lblParallel = new Label { Text = "Max (non-video / video):", AutoSize = true, Margin = new Padding(12, 12, 4, 0) };
            var tip = new ToolTip();
            tip.SetToolTip(lblParallel, "Video lanes are capped; during drain we go single-stream. Lone video may get +3 segments when pool has slack.");

            nudNV = new NumericUpDown { Minimum = 1, Maximum = MAX_IMG_CONC, Value = Math.Min(_maxNV, MAX_IMG_CONC), Width = 60, Margin = new Padding(4, 8, 4, 0) };
            nudVID = new NumericUpDown { Minimum = 1, Maximum = MAX_VID_CONC, Value = Math.Min(_maxVID, MAX_VID_CONC), Width = 60, Margin = new Padding(4, 8, 4, 0) };
            lblHealth = new Label { Text = "HEALTH:", AutoSize = true, Margin = new Padding(12, 8, 0, 0), ForeColor = Color.White };
            lblHealthState = new Label { Text = " OK", AutoSize = true, Margin = new Padding(1, 8, 0, 0), ForeColor = Color.ForestGreen };
            lblSpeed = new Label { Text = "SPEED: 0.0 MB/s (0.0 MB)", AutoSize = true, Margin = new Padding(12, 8, 0, 0), ForeColor = Color.DarkSlateGray };

            // REPLACE [0162.20]-
            var chkLockSize = new CheckBox
            {
                Name = "chkLockSize",
                Text = "Lock window size",
                AutoSize = true,
                Checked = true, // ← default ON
                Margin = new Padding(12, 8, 4, 0)
            };


            // Make it visible in the top panel //

            // Live apply + persist //
            chkLockSize.CheckedChanged += (s, e) =>
            {
                if (chkLockSize.Checked) LockFormToCurrentSize(); else UnlockFormSize();
                SaveUIPrefs();
            };

            // LED: instance + idle timer
            _netLed = new ActivityLed { /* keep your existing initializer unchanged */ };
            _netLed.Size = new Size(16, 16);
            _netLed.Pulse = false;

            _netLed.OnColor = accent; // follow accent
            _netLed.OffColor = Color.FromArgb(20, accent); // (if you made this darker)
            _ledIdleTimer = new System.Windows.Forms.Timer { Interval = 1400 }; // (if you bumped linger)
            _ledIdleTimer.Tick += (_, __) => { _netLed.On = false; _ledIdleTimer.Stop(); _netLed.Invalidate(); };
            _ledHeartbeat.Interval = 1000; // 1 Hz heartbeat
            _ledHeartbeat.Tick += (_, __) =>
            {
                // scrub any leftover glyphs (just in case an old handler ran)
                if (lblHealthState.Text.EndsWith(" ▮") || lblHealthState.Text.EndsWith(" •"))
                    lblHealthState.Text = lblHealthState.Text[..^2];

                // color-pulse ONLY (no text changes)
                bool ok = lblHealthState.Text.TrimStart().StartsWith("OK", StringComparison.OrdinalIgnoreCase);
                lblHealthState.ForeColor =
                    (_sessionSw?.IsRunning == true && ok && ((Environment.TickCount64 / 1000) & 1) == 0)
                    ? ControlPaint.Light(Color.ForestGreen)
                    : Color.ForestGreen;
            };


            _ledHeartbeat.Start();
            // bind static delegates to this instance
            s_Log ??= Log;
            s_ShouldLogOnce ??= ShouldLogOnce;
            s_GetInflightVID ??= () => _inflightVID;
            s_GetMaxVID ??= () => _maxVID;







            // Base sizes to match current.cs //
            var baseSize = this.Font.Size + 2f;
            var fMain = new Font(this.Font.FontFamily, baseSize, FontStyle.Bold);
            var fSmall = new Font(this.Font.FontFamily, baseSize * 0.5f, FontStyle.Bold);

            // --- Brand overlay (create || reuse) ---------------------------------------- //
            var brandPanel = this.Controls["pnlBrand"] as Panel
                             ?? new Panel
                             {
                                 Name = "pnlBrand",
                                 Dock = DockStyle.None,
                                 AutoSize = true,
                                 AutoSizeMode = AutoSizeMode.GrowAndShrink,
                                 Padding = new Padding(0),
                                 Margin = new Padding(0)
                             };

            var row = brandPanel.Controls["brandRow"] as FlowLayoutPanel
                      ?? new FlowLayoutPanel
                      {
                          Name = "brandRow",
                          Dock = DockStyle.None,
                          AutoSize = true,
                          AutoSizeMode = AutoSizeMode.GrowAndShrink,
                          FlowDirection = FlowDirection.LeftToRight,
                          WrapContents = false,
                          Padding = new Padding(0),
                          Margin = new Padding(0)
                      };

            // Create-or-reuse split labels (hidden after wordmark is painted) //
            var lblAstro = row.Controls["lblBrandAstro"] as Label
                           ?? new Label { Name = "lblBrandAstro", AutoSize = true, Text = "Astro" };
            var lblFetch = row.Controls["lblBrandFetch"] as Label
                           ?? new Label { Name = "lblBrandFetch", AutoSize = true, Text = "Fetch" };
            var lblDL = row.Controls["lblBrandDL"] as Label
                           ?? new Label { Name = "lblBrandDL", AutoSize = true, Text = "DL" };

            // Apply fonts/colors (Astro = accent; Fetch = white; DL = half-size) //
            lblAstro.Font = fMain; lblAstro.ForeColor = accent;
            lblFetch.Font = fMain; lblFetch.ForeColor = textMain;
            lblDL.Font = fSmall; lblDL.ForeColor = textMain;

            // Tight spacing so it reads as “AstroFetch” //
            lblAstro.Margin = new Padding(0, 0, 0, 0);
            lblFetch.Margin = new Padding(0, 0, 0, 0);
            lblDL.Margin = new Padding(4, (int)Math.Round(baseSize * 0.35), 0, 0);

            // Compose once //
            if (!row.Controls.Contains(lblAstro)) row.Controls.Add(lblAstro);
            if (!row.Controls.Contains(lblFetch)) row.Controls.Add(lblFetch);
            if (!row.Controls.Contains(lblDL)) row.Controls.Add(lblDL);
            if (row.Parent != brandPanel) brandPanel.Controls.Add(row);
            if (brandPanel.Parent != pnlTop) pnlTop.Controls.Add(brandPanel);

            // === Single wordmark: draw “AstroFetch” contiguous (Astro=accent, Fetch=white) === //
            var wordmark = brandPanel.Controls["lblBrandWordmark"] as Label;
            if (wordmark == null)
            {
                wordmark = new Label { Name = "lblBrandWordmark", AutoSize = false, BackColor = Color.Transparent };
                brandPanel.Controls.Add(wordmark);
                brandPanel.Controls.SetChildIndex(wordmark, 0);

                wordmark.Paint += (s, e) =>
                {
                    e.Graphics.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
                    const string left = "Astro";
                    const string right = "Fetch";
                    var flags = TextFormatFlags.NoPadding | TextFormatFlags.NoClipping;

                    var sz = TextRenderer.MeasureText(e.Graphics, left + right, fMain, Size.Empty, flags);
                    if (wordmark.Size != sz) wordmark.Size = sz;
                    var wLeft = TextRenderer.MeasureText(e.Graphics, left, fMain, Size.Empty, flags).Width;

                    TextRenderer.DrawText(e.Graphics, left, fMain, new Point(0, 0), accent, flags);
                    TextRenderer.DrawText(e.Graphics, right, fMain, new Point(wLeft, 0), textMain, flags);
                };
            }


            // Place the overlay at the top-left of the toolbar row (parent = Form) //
            brandPanel.BackColor = Color.Transparent;
            row.BackColor = Color.Transparent;

            // Make sure the overlay is NOT inside pnlTop (FlowLayout/TableLayout overrides Location)
            if (brandPanel.Parent != this)
            {
                brandPanel.Parent?.Controls.Remove(brandPanel);
                this.Controls.Add(brandPanel);
            }

            brandPanel.Dock = DockStyle.None;
            brandPanel.Margin = Padding.Empty;
            brandPanel.Padding = Padding.Empty;
            brandPanel.Anchor = AnchorStyles.Top | AnchorStyles.Left;

            // Pre-size the wordmark so we can place DL
            var flags = TextFormatFlags.NoPadding | TextFormatFlags.NoClipping;
            var astroFetchSize = TextRenderer.MeasureText("AstroFetch", fMain, Size.Empty, flags);
            wordmark.Size = astroFetchSize;
            wordmark.Location = new Point(0, 0);

            // Ensure "DL" is not inside the FlowLayout (so manual Location sticks)
            if (lblDL.Parent != brandPanel)
            {
                row.Controls.Remove(lblDL);
                brandPanel.Controls.Add(lblDL);
            }

            // Style & place DL (half-size, baseline-aligned)
            lblDL.AutoSize = true;
            lblDL.BackColor = Color.Transparent;
            int gap = 2;
            lblDL.Location = new Point(wordmark.Width + gap, (int)Math.Round(fMain.Height * 0.35));
            lblDL.BringToFront(); lblDL.Visible = true;

            // Hide split labels (wordmark paints both) //
            lblAstro.Visible = false;
            lblFetch.Visible = false;

            // ---- FORCE DL to half-size of the wordmark and baseline-align ------------- //
            lblDL.AutoSize = true;
            lblDL.BackColor = Color.Transparent;
            lblDL.Font = new Font(
                wordmark.Font.FontFamily,
                wordmark.Font.SizeInPoints * 0.5f,
                FontStyle.Bold,
                GraphicsUnit.Point);

            const int GAP_AFTER_WORDMARK = 2;
            var textFlags = TextFormatFlags.NoPadding | TextFormatFlags.NoClipping;
            var dlSz = TextRenderer.MeasureText("DL", lblDL.Font, Size.Empty, textFlags);
            // Baseline align DL to the wordmark (nudge for ClearType) //
            int dlY = wordmark.Height - dlSz.Height + (int)Math.Round(wordmark.Font.Height * 0.08);
            lblDL.Location = new Point(wordmark.Width + GAP_AFTER_WORDMARK, dlY);
            lblDL.BringToFront();
            lblDL.Visible = true;

            // ---- BACKPLATE SIZE TUNING (adjust these to change width/height) ----------- //
            const int BRAND_PAD_X = 10; // ⬅ widen/narrow the plate (left+right) //
            const int BRAND_PAD_Y = 3; // ⬅ taller/shorter plate (top+bottom) //

            // Compute content bounds //
            int contentW = Math.Max(wordmark.Right, lblDL.Right);
            int contentH = Math.Max(wordmark.Bottom, lblDL.Bottom);

            // Apply padding to the *panel* size //
            brandPanel.AutoSize = false;
            brandPanel.Size = new Size(
                contentW + BRAND_PAD_X * 2,
                contentH + BRAND_PAD_Y * 2);

            // Shift children inward so padding shows as background //
            wordmark.Location = new Point(BRAND_PAD_X, BRAND_PAD_Y);
            lblDL.Location = new Point(
                BRAND_PAD_X + wordmark.Width + GAP_AFTER_WORDMARK,
                BRAND_PAD_Y + dlY);

            // --- Pin brand overlay relative to pnlTop (drift-proof) -------------------- //
            if (brandPanel.Parent != this)
            {
                brandPanel.Parent?.Controls.Remove(brandPanel);
                this.Controls.Add(brandPanel);
            }
            brandPanel.Anchor = AnchorStyles.Top | AnchorStyles.Left;

            // Local offsets for fine tuning //
            const int BRAND_X_OFFSET = -4; // move fully left
            const int BRAND_Y_OFFSET = -65; // pull up into the corner (nudge -3..-6 to taste)



            // Robust pin: use screen→client so dock/layout/DPI can't move it //
            void RepositionBrand()
            {
                var tl = this.PointToClient(pnlTop.PointToScreen(Point.Empty));
                brandPanel.Location = new Point(tl.X + BRAND_X_OFFSET,
                                                tl.Y + BRAND_Y_OFFSET);
                brandPanel.BringToFront();
            }

            // Initial position //
            RepositionBrand();

            // Hook once (guarded) //
            if (!_brandStickyHooked)
            {
                this.Shown += (_, __) => RepositionBrand();
                this.Layout += (_, __) => RepositionBrand();
                this.Resize += (_, __) => RepositionBrand();
                pnlTop.LocationChanged += (_, __) => RepositionBrand();
                pnlTop.SizeChanged += (_, __) => RepositionBrand();
                _brandStickyHooked = true;
            }

            // Run once more after the first full layout pass //
            this.BeginInvoke((Action)RepositionBrand);

            // Keep the flow row around (hidden) //
            row.Visible = false;


            // simple tray icon with Open Web UI + Exit
            try
            {
                _trayMenu = new ContextMenuStrip();
                _trayMenu.Items.Add("Open Web UI", null, (_, __) => OpenWebUiFromTray());
                _trayMenu.Items.Add(new ToolStripSeparator());
                _trayMenu.Items.Add("Exit Astryx", null, (_, __) =>
                {
                    try
                    {
                        if (_trayIcon != null)
                        {
                            _trayIcon.Visible = false;
                            _trayIcon.Dispose();
                            _trayIcon = null;
                        }
                    }
                    catch { }

                    System.Windows.Forms.Application.Exit();

                });

                var icoPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "wwwroot", "Astryx.ico");

                _trayIcon = new NotifyIcon
                {
                    Text = "ASTRYX DL (running)",
                    Icon = File.Exists(icoPath) ? new Icon(icoPath) : (this.Icon ?? System.Drawing.SystemIcons.Application),
                    Visible = true,
                    ContextMenuStrip = _trayMenu
                };

                _trayIcon.DoubleClick += (_, __) => OpenWebUiFromTray();
            }
            catch
            {
                // best-effort; if tray fails, app still runs fine
            }










            lblOverall = new Label { Text = "OVERALL:", AutoSize = true, Margin = new Padding(0, 8, 4, 0) };
            // REPLACE
            pbOverall = new AccentProgressBar
            {
                Width = 520,
                Height = 16,
                AutoSize = false,
                Margin = new Padding(8, 8, 4, 0),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };


            // REPLACE [0166]..
            pbCurrent = new AccentProgressBar
            {
                Width = 520,
                Height = 16,
                AutoSize = false,
                Margin = new Padding(8, 8, 4, 0),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            ((AccentProgressBar)pbCurrent).FillColor = Color.FromArgb(0xFF, 0xB3, 0x00); // Amber 600 //






            btnStart.Click += async (_, __) =>
            {
                await StartRunAsync();
                SweepEmptySetFolders(); // clean stray empty *_set folders at run end
            };
            btnStop.Click += (_, __) =>
            {
                // Second click any time after a Graceful stop was requested => Immediate (hard stop). No timer.
                if (_stopRequested && _stopMode == StopMode.Graceful)
                {
                    _stopRequested = true; _stopMode = StopMode.Immediate;
                    s_StopRequested = true;

                    try { FlushQueuesOnStop(); } catch { } // keep nuking pending items
                    try { _edgeCts?.Cancel(); } catch { }
                    try { StopEdgeSelector(); } catch { }

                    try { _cts?.Cancel(); } catch { }
                    Log("[STOP] Immediate stop requested — canceling now.");
                    return;
                }

                // First click => Graceful immediately (no timer)
                _stopRequested = true; _stopMode = StopMode.Graceful;
                _imgQ?.CompleteAdding(); _vidQ?.CompleteAdding();
                try { FlushQueuesOnStop(); } catch { } // nuke pending items now
                try { _edgeCts?.Cancel(); } catch { }
                try { StopEdgeSelector(); } catch { }
                s_Draining = true;
                s_NoRangeThisRun = true; // snap remaining vids to SS
                Log("[STOP] Graceful: Edge selector stopped.");

                Log("[STOP] Graceful stop requested — finishing active downloads. Click Stop again to force cancel.");
            };

            btnBrowse.Click += (_, __) => { using var d = new FolderBrowserDialog { SelectedPath = Directory.Exists(txtFolder.Text) ? txtFolder.Text : Environment.GetFolderPath(Environment.SpecialFolder.Desktop), ShowNewFolderButton = true, Description = "Choose download folder" }; if (d.ShowDialog(this) == DialogResult.OK) { txtFolder.Text = d.SelectedPath; try { File.WriteAllText(_prefsPath, d.SelectedPath); } catch { } } };

            chkAdblockOn.CheckedChanged += (_, __) =>
            {
                _adblockOn = chkAdblockOn.Checked;
                if (_miAdblock != null) _miAdblock.Checked = chkAdblockOn.Checked; // keep menu in sync
            };
            btnAdblockUpdate.Click += async (_, __) =>
            {
                await UpdateFiltersAsync();
                _adblockLastUpdateUtc = DateTime.UtcNow;
                SaveUIPrefs();
                ApplyAdblockUpdateVisibility();
            };


            chkParallel.CheckedChanged += (_, __) => { _parallelOn = chkParallel.Checked; SaveUIPrefs(); };
            nudNV.ValueChanged += (_, __) => { _maxNV = (int)Math.Min(nudNV.Value, MAX_IMG_CONC); SaveUIPrefs(); };
            nudVID.ValueChanged += (_, __) => { _maxVID = (int)Math.Min(nudVID.Value, MAX_VID_CONC); SaveUIPrefs(); };


            LoadAdblockRulesFromDisk(); _adblockOn = chkAdblockOn.Checked;
            LoadMediaIndex(); // (+) de-dup index
            LoadFailIndex();
            LoadUIPrefs();
            _loadingPrefs = false;
            // [COOMER.REMEMBER] auto-login if remembered and not already logged in
            try
            {
                if (_coomerRemember &&
                    !string.IsNullOrWhiteSpace(_coomerRememberUser) &&
                    !string.IsNullOrWhiteSpace(_coomerRememberPass) &&
                    !CoomerHasSession())
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            Log("[COOMER] Auto-login…");
                            var r = await CoomerLoginAsync(_coomerRememberUser, _coomerRememberPass).ConfigureAwait(false);
                            Log(r.ok ? "[COOMER] Auto-login OK" : "[COOMER] Auto-login failed");
                            if (!r.ok)
                            {
                                _coomerRemember = false;
                                _coomerRememberUser = "";
                                _coomerRememberPass = "";
                                try { SaveUIPrefs(); } catch { }
                            }
                        }
                        catch { }
                    });
                }
            }
            catch { }

            _optSaveIndexPerFile = false; // HARD LOCK: per-file index saving always OFF

            // Keep runtime + menu in sync with anything LoadUIPrefs() might have changed
            // If the saved pref is old/low, bump to 3 and persist.
            if (_maxVID < 4)
            {
                _maxVID = 4;
                try { if (nudVID.Maximum < 4) nudVID.Maximum = 4; nudVID.Value = Math.Min(_maxVID, MAX_VID_CONC); } catch { /* best effort */ }
                SaveUIPrefs(); // writes "vid=4" to ui.ini
            }

            _adblockOn = chkAdblockOn.Checked;
            if (_miAdblock != null) _miAdblock.Checked = chkAdblockOn.Checked;
            ApplyAdblockUpdateVisibility();
            nudNV.ValueChanged += (_, __) => RememberModeLanes();
            nudVID.ValueChanged += (_, __) => RememberModeLanes();

            // Create "Buy me a coffee" link under the Astro badge at runtime //
            // auto-prune: start on launch if enabled
            if (_optAutoPrune) { EnsurePruneTimer(); _pruneTimer!.Start(); }

            this.Load += (_, __) =>
            {
                try
                {
                    if (_lnkCoffee != null) return;

                    // Target your actual badge first: picSide (falls back to prior guesses)
                    var logo = this.Controls.Find("picSide", true).OfType<PictureBox>().FirstOrDefault()
                               ?? this.Controls.Find("picAstro", true).OfType<PictureBox>().FirstOrDefault()
                               ?? this.Controls.Find("pbAstro", true).OfType<PictureBox>().FirstOrDefault()
                               ?? this.Controls.Find("imgAstro", true).OfType<PictureBox>().FirstOrDefault();

                    var parent = (logo?.Parent) ?? this;

                    _lnkCoffee = new LinkLabel
                    {
                        Name = "lnkCoffee",
                        Text = "☕ Buy me a coffee",
                        AutoSize = true,
                        BackColor = Color.Transparent,
                        LinkColor = MSkin.MaterialSkinManager.Instance.ColorScheme.AccentColor,
                        ActiveLinkColor = Color.White,
                        VisitedLinkColor = MSkin.MaterialSkinManager.Instance.ColorScheme.AccentColor,
                        TabStop = true
                    };
                    _lnkCoffee.LinkClicked += (_, e) =>
                    {
                        try
                        {
                            System.Diagnostics.Process.Start(
                                new System.Diagnostics.ProcessStartInfo(BUYME_URL) { UseShellExecute = true });
                        }
                        catch { }
                    };

                    parent.Controls.Add(_lnkCoffee);
                    _lnkCoffee.BringToFront();

                    void Place()
                    {
                        if (logo != null)
                        {
                            int x = logo.Left + (logo.Width - _lnkCoffee.PreferredWidth) / 2;
                            int y = logo.Bottom + 6;
                            _lnkCoffee.Location = new Point(x, y);
                            _lnkCoffee.Anchor = AnchorStyles.Top | AnchorStyles.Left;
                        }
                        else
                        {
                            int x = this.ClientSize.Width - _lnkCoffee.PreferredWidth - 18;
                            int y = (this.MainMenuStrip?.Bottom ?? 0) + 6;
                            _lnkCoffee.Location = new Point(x, y);
                            _lnkCoffee.Anchor = AnchorStyles.Top | AnchorStyles.Right;
                        }
                    }
                    // Move the “Update list” chip above the badge
                    var update = btnAdblockUpdate;
                    if (update != null)
                    {
                        parent.Controls.Add(update); // reparent (removes from rowRun automatically)
                        update.BringToFront();

                        void PlaceUpdate()
                        {
                            if (logo != null)
                            {
                                int x = logo.Left + (logo.Width - update.PreferredSize.Width) / 2;
                                int y = logo.Top - update.PreferredSize.Height + 2; // lowered a bit
                                update.Location = new Point(x, y);
                                update.Anchor = AnchorStyles.Top | AnchorStyles.Left;
                            }
                        }

                        PlaceUpdate();
                        this.Resize += (_, __) => PlaceUpdate();
                        if (logo != null) { logo.LocationChanged += (_, __) => PlaceUpdate(); logo.SizeChanged += (_, __) => PlaceUpdate(); }
                    }

                    Place();
                    this.Resize += (_, __) => Place();
                    if (logo != null) { logo.LocationChanged += (_, __) => Place(); logo.SizeChanged += (_, __) => Place(); }
                }
                catch { }
            };



            try { if (File.Exists(_prefsPath)) { var last = File.ReadAllText(_prefsPath).Trim(); if (!string.IsNullOrWhiteSpace(last) && Directory.Exists(last)) txtFolder.Text = last; } } catch { }

            // REPLACE [0181]-

            // URL row (label + textbox stay together)
            var rowUrl = new FlowLayoutPanel
            {
                AutoSize = true,
                WrapContents = false,
                FlowDirection = FlowDirection.LeftToRight,
                Margin = new Padding(12, 4, 0, 0)
            };
            lblUrl.Margin = new Padding(0, 8, 4, 0);
            rowUrl.Controls.Add(lblUrl);
            rowUrl.Controls.Add(txtUrl);

            // Dir row (short label + folder box + Browse)
            var rowDir = new FlowLayoutPanel
            {
                AutoSize = true,
                WrapContents = false,
                FlowDirection = FlowDirection.LeftToRight,
                Margin = new Padding(12, 4, 0, 0)
            };
            lblFolder.Text = "DIR:"; // 3-letter label
            lblFolder.AutoSize = false;
            lblFolder.Width = 36;
            lblFolder.Margin = new Padding(0, 8, 4, 0);
            rowDir.Controls.Add(lblFolder);
            rowDir.Controls.Add(txtFolder);
            rowDir.Controls.Add(btnBrowse);

            var colLock = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Margin = new Padding(6, 0, 0, 0) };
            chkLockSize.Margin = new Padding(0, 0, 0, 0); chkOpenOnDone.Margin = new Padding(0, 6, 0, 0);
            colLock.Controls.Add(chkLockSize); colLock.Controls.Add(chkOpenOnDone);
            chkAdblockOn.Margin = new Padding(0, 6, 0, 0);
            chkParallel.Margin = new Padding(0, 6, 0, 0);
            colLock.Controls.Add(chkAdblockOn);
            colLock.Controls.Add(chkParallel);

            // LEFT column stack: URL, DIR, then RUN row
            var leftStack = new FlowLayoutPanel { AutoSize = true, WrapContents = false, FlowDirection = FlowDirection.TopDown, Margin = new Padding(12, 0, 0, 0) };
            leftStack.Controls.Add(rowUrl);
            leftStack.Controls.Add(rowDir);

            // RUN row directly under DIR
            var rowRun = new FlowLayoutPanel { AutoSize = true, WrapContents = false, FlowDirection = FlowDirection.LeftToRight, Margin = new Padding(0, 0, 0, 0) };
            btnStart.Margin = new Padding(0, 0, 6, 0);
            btnStop.Margin = new Padding(0, 0, 0, 0);

            rowRun.Controls.Add(btnStart);
            rowRun.Controls.Add(btnStop);
            rowRun.Controls.Add(_netLed);
            _netLed.Margin = new Padding(6, 4, 0, 0); // small gap; visually centered with buttons
            _netLed.Visible = false; // retire the ring

            var cmbMode = new ComboBox
            {
                Name = "cmbMode",
                DropDownStyle = ComboBoxStyle.DropDownList,
                FlatStyle = FlatStyle.Flat,
                Width = 140,
                Margin = new Padding(12, 0, 0, 0),
                DrawMode = DrawMode.OwnerDrawFixed,
                IntegralHeight = false,
                ItemHeight = 18
            };

            // compact + readable
            cmbMode.AutoSize = false;
            cmbMode.Height = 22;
            cmbMode.MinimumSize = new Size(0, 22);
            cmbMode.Font = new Font("Segoe UI", 9f);
            cmbMode.BackColor = Color.FromArgb(32, 34, 38);
            cmbMode.ForeColor = Color.White;

            cmbMode.Items.AddRange(new object[] { "All", "Images only", "Video+Audio only" });
            cmbMode.SelectedIndex = 0; // All
            cmbMode.DropDownWidth = cmbMode.Width + 40;


            // owner-draw (handles both dropdown rows and closed state)
            cmbMode.DrawItem += (s, e) =>
            {
                var cb = (ComboBox)s;
                e.DrawBackground();

                string text = (e.Index >= 0 ? cb.Items[e.Index]?.ToString() : cb.Text) ?? "";
                bool selected = (e.State & DrawItemState.Selected) != 0;

                var bg = selected ? Color.FromArgb(36, 44, 56) : cb.BackColor;
                using (var b = new SolidBrush(bg)) e.Graphics.FillRectangle(b, e.Bounds);

                var r = new Rectangle(e.Bounds.X + 6, e.Bounds.Y, e.Bounds.Width - 12, e.Bounds.Height);
                TextRenderer.DrawText(e.Graphics, text, cb.Font, r, cb.ForeColor,
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter);

                using (var pen = new Pen(Color.FromArgb(64, 64, 64)))
                    e.Graphics.DrawRectangle(pen, e.Bounds.X, e.Bounds.Y, e.Bounds.Width - 1, e.Bounds.Height - 1);

                e.DrawFocusRectangle();
            };



            cmbMode.SelectedIndexChanged += (_, __) =>
            {
                _mediaMode = cmbMode.SelectedIndex switch
                {
                    1 => MediaMode.Images,
                    2 => MediaMode.VideoAudio,
                    _ => MediaMode.All
                };
                ApplyMediaModeLanes();
                RememberModeLanes(); // capture NV/VID for this mode
                try { SaveUIPrefs(); } catch { }
            };
            cmbMode.LocationChanged += (_, __) => rowRun.Invalidate(cmbMode.Bounds);
            cmbMode.SizeChanged += (_, __) => rowRun.Invalidate(cmbMode.Bounds);
            rowRun.Paint += (_, e) =>
            {
                if (!cmbMode.Visible) return;
                var r = cmbMode.Bounds; r.Inflate(0, 0);
                using var pen = new Pen(Color.FromArgb(64, 64, 64));
                e.Graphics.DrawRectangle(pen, r.X - 1, r.Y - 1, r.Width + 1, r.Height + 1);
            };


            rowRun.Controls.Add(cmbMode);
            cmbMode.Visible = false; // retire the dropdown
            cmbMode.TabIndex = btnStop.TabIndex + 1; // tidy tab order

            // ------Text-only selector (All | Img | Vid)--------------------------//
            var segAll = new MaterialSkin2DotNet.Controls.MaterialLabel
            {
                Text = "All",
                AutoSize = true,
                Margin = new Padding(6, -1, 0, 0),
                Cursor = Cursors.Hand,
                TabStop = false
            };
            var segImg = new MaterialSkin2DotNet.Controls.MaterialLabel
            {
                Text = "Img",
                AutoSize = true,
                Margin = new Padding(10, -1, 0, 0),
                Cursor = Cursors.Hand,
                TabStop = false
            };
            var segVid = new MaterialSkin2DotNet.Controls.MaterialLabel
            {
                Text = "Vid",
                AutoSize = true,
                Margin = new Padding(10, -1, 0, 0),
                Cursor = Cursors.Hand,
                TabStop = false
            };

            MaterialSkin2DotNet.Controls.MaterialLabel _sel = segAll;
            void Pick(MaterialSkin2DotNet.Controls.MaterialLabel l)
            {
                _sel = l;
                segAll.ForeColor = (l == segAll) ? accent : Color.Gainsboro;
                segImg.ForeColor = (l == segImg) ? accent : Color.Gainsboro;
                segVid.ForeColor = (l == segVid) ? accent : Color.Gainsboro;
                rowRun.Invalidate();
            }

            segAll.Click += (_, __) =>
            {
                _modeLane = "all";
                _mediaMode = MediaMode.All;
                ApplyMediaModeLanes();
                RememberModeLanes();
                Pick(segAll);
            };

            segImg.Click += (_, __) =>
            {
                _modeLane = "img";
                _mediaMode = MediaMode.Images;
                ApplyMediaModeLanes();
                RememberModeLanes();
                Pick(segImg);
            };

            segVid.Click += (_, __) =>
            {
                _modeLane = "vid";
                _mediaMode = MediaMode.VideoAudio;
                ApplyMediaModeLanes();
                RememberModeLanes();
                Pick(segVid);
            };


            // add to row + default
            rowRun.Controls.Add(segAll);
            rowRun.Controls.Add(segImg);
            rowRun.Controls.Add(segVid);
            Pick(segAll);

            // subtle hover feedback
            void WireHover(MaterialSkin2DotNet.Controls.MaterialLabel l)
            {
                l.MouseEnter += (_, __) => { if (l != _sel) l.ForeColor = ControlPaint.Light(Color.Gainsboro); };
                l.MouseLeave += (_, __) => { l.ForeColor = (l == _sel) ? accent : Color.Gainsboro; };
            }
            WireHover(segAll); WireHover(segImg); WireHover(segVid);

            // underline current selection (safe replace)
            if (_modeUnderlinePaint != null) rowRun.Paint -= _modeUnderlinePaint;
            _modeUnderlinePaint = (object? s, PaintEventArgs e) =>
            {
                var b = _sel.Bounds; int y = b.Bottom + 1; int h = 2;
                using var th = new SolidBrush(Color.FromArgb(180, accent));
                e.Graphics.FillRectangle(th, new Rectangle(b.Left, y, b.Width, h));
            };
            rowRun.Paint += _modeUnderlinePaint;
            // ------End text-only selector---------------------------------------//






            ApplyMediaModeLanes();




            // Reserve a permanent slot for the ring overlay (decouples from chip visibility) //
            var pnlLedOverlay = this.Controls["pnlLedOverlay"] as Panel
                ?? new Panel
                {
                    Name = "pnlLedOverlay",
                    Size = _netLed.Size,
                    Margin = _netLed.Margin,
                    BackColor = Color.Transparent,
                    TabStop = false
                };
            if (pnlLedOverlay.Parent != rowRun) rowRun.Controls.Add(pnlLedOverlay);

            rowRun.Margin = new Padding(rowDir.Margin.Left + lblFolder.Width + lblFolder.Margin.Right, 0, 0, 0);
            leftStack.Controls.Add(rowRun);

            btnAdblockUpdate.Height = 32; // match START/STOP height
            btnAdblockUpdate.Margin = new Padding(40, 0, 0, 0); // small gap after STOP
            rowRun.Controls.Add(btnAdblockUpdate);








            // align columns + match field widths
            lblUrl.AutoSize = false; lblUrl.Width = 36;
            txtUrl.Width = txtFolder.Width;

            // add rows to the panel
            pnlTop.Controls.Add(leftStack);
            pnlTop.SetFlowBreak(leftStack, true);












            // REPLACE [0185]-


            // OVERALL stacked like SPEED: label over its bar (no LED)
            if (lblOverall.Parent != pnlTop) pnlTop.Controls.Add(lblOverall);
            lblOverall.Margin = lblSpeed.Margin; // match SPEED label spacing
            lblOverall.Margin = new Padding(lblOverall.Margin.Left, lblOverall.Margin.Top + 6, lblOverall.Margin.Right, lblOverall.Margin.Bottom);
            pnlTop.SetFlowBreak(lblOverall, true); // next control on a new row

            if (pbOverall.Parent != pnlTop) pnlTop.Controls.Add(pbOverall);
            pbOverall.Size = pbCurrent.Size; // match SPEED bar size
            pbOverall.Margin = pbCurrent.Margin; // match SPEED bar spacing
            pnlTop.SetFlowBreak(pbOverall, true); // bar gets its own full-width row

            // Next rows (unchanged)
            pnlTop.Controls.Add(lblSpeed);
            pnlTop.Controls.Add(lblHealth);
            pnlTop.Controls.Add(lblHealthState);

            pnlTop.Controls.Add(lblCurrent);
            pnlTop.Controls.Add(pbCurrent);



            // Material-styled log: TextBox inside a MaterialCard //
            var cardLog = new MaterialSkin2DotNet.Controls.MaterialCard
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(8),
                Margin = new Padding(8, 8, 8, 8)
            };

            txtLog = new TextBox
            {
                BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical, // temporary; overlay hides later //
                WordWrap = _prefWrapLog, // persisted preference //
                Font = new Font("Consolas", 10f)
            };

            cardLog.Controls.Add(txtLog);
            pnlMain.Controls.Add(cardLog);
            // Slim accent overlay scrollbar (replaces native bar) //
            txtLog.ScrollBars = ScrollBars.None; // hide native //
            _pnlLogScroll = new Panel
            {
                Dock = DockStyle.Right,
                Width = 6,
                BackColor = Color.Transparent,
                Margin = new Padding(0)
            };
            cardLog.Controls.Add(_pnlLogScroll);
            _pnlLogScroll.BringToFront();

            _pnlLogScroll.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.HighQuality;

                int lines = Math.Max(1, SendMessage(txtLog.Handle, EM_GETLINECOUNT, 0, 0));
                int first = Math.Max(0, SendMessage(txtLog.Handle, EM_GETFIRSTVISIBLELINE, 0, 0));
                int visible = Math.Max(1, txtLog.ClientSize.Height / Math.Max(1, (int)txtLog.Font.GetHeight()));
                int trackH = _pnlLogScroll.ClientSize.Height;
                if (trackH <= 0) return;

                // track
                var track = new Rectangle(0, 0, _pnlLogScroll.Width, trackH);
                using (var trackBr = new SolidBrush(Color.FromArgb(28, 255, 255, 255))) g.FillRectangle(trackBr, track);

                // thumb
                int maxPos = Math.Max(1, lines - visible);
                int thumbH = Math.Max(18, (int)Math.Round(trackH * (visible / (double)Math.Max(visible, lines))));
                int thumbY = (int)Math.Round((trackH - thumbH) * (first / (double)maxPos));
                var thumb = new Rectangle(0, thumbY, _pnlLogScroll.Width, thumbH);

                var accent = MaterialSkin2DotNet.MaterialSkinManager.Instance.ColorScheme.AccentColor;
                using (var th = new SolidBrush(Color.FromArgb(180, accent))) g.FillRectangle(th, thumb);
            };

            // refresh thumb when things change
            _tmrLogScroll = new System.Windows.Forms.Timer { Interval = 100, Enabled = true };
            _tmrLogScroll.Tick += (_, __) => { if (_pnlLogScroll?.IsHandleCreated == true) _pnlLogScroll.Invalidate(); };
            txtLog.Resize += (_, __) => _pnlLogScroll.Invalidate();
            txtLog.TextChanged += (_, __) => _pnlLogScroll.Invalidate();


            // after Controls.Add(pnlTop); Controls.Add(pnlMain); (either order)
            BuildMenu(pnlTop);



            // apply Material accent + force Professional renderer
            ToolStripManager.RenderMode = ToolStripManagerRenderMode.Professional;
            ToolStripManager.Renderer = new ThemedRenderer(accent);
            ToolStripManager.RenderMode = ToolStripManagerRenderMode.Professional;
            ToolStripManager.Renderer = new ThemedRenderer(accent);

            // also set it on the actual MenuStrip instance (in case it defaulted to System)
            var ms = this.Controls.OfType<MenuStrip>().FirstOrDefault()
                  ?? this.Controls.Find("menuStrip1", true).OfType<MenuStrip>().FirstOrDefault();
            if (ms != null) { ms.RenderMode = ToolStripRenderMode.Professional; ms.Renderer = new ThemedRenderer(accent); }
            // Ensure no leftover coffee label on the menu (we draw it elsewhere) //
            if (ms != null)
            {
                var old = ms.Items.OfType<ToolStripLabel>().FirstOrDefault(i => i.Name == "tslCoffee");
                if (old != null) ms.Items.Remove(old);
            }





            this.SuspendLayout();
            Controls.Add(pnlMain);
            Controls.Add(pnlTop);

            this.SuspendLayout();
            Controls.Add(pnlMain);
            Controls.Add(pnlTop);

            // --- SIDE ART (top-right) ---
            var picSide = new PictureBox
            {
                Name = "picSide",
                Size = new Size(160, 140), // tweak to fit your box
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Color.Transparent,
                Image = null
                // add PNG to Resources as SideArt
            };
            this.Controls.Add(picSide);
            picSide.BringToFront();

            void PositionSide()
            {
                int margin = 12;
                int x = this.ClientSize.Width - picSide.Width - margin;
                int y = (this.MainMenuStrip?.Bottom ?? 0) + 120;
                picSide.Location = new Point(x, y);
            }
            PositionSide();
            this.Resize += (_, __) => PositionSide();
            // --- END SIDE ART ---

            this.ResumeLayout(true);

            this.ResumeLayout(true);



            // hide default title text; first draw will come via WM_NCPAINT
            this.Text = string.Empty;
            this.Refresh();





            AcceptButton = btnStart;
            CancelButton = btnStop; // // -------- Settings: toggles --------
            _miLock = new ToolStripMenuItem("Lock window size")
            {
                CheckOnClick = true,
                Checked = chkLockSize.Checked
            };
            _miLock.Click += (_, __) =>
            {
                chkLockSize.Checked = _miLock.Checked;
                if (_miLock.Checked) LockFormToCurrentSize(); else UnlockFormSize();
                try { SaveUIPrefs(); } catch { }
            };

            _miOpenOnDone = new ToolStripMenuItem("Open folder when done")
            {
                CheckOnClick = true,
                Checked = chkOpenOnDone.Checked
            };
            _miOpenOnDone.Click += (_, __) =>
            {
                chkOpenOnDone.Checked = _miOpenOnDone.Checked;
                try { SaveUIPrefs(); } catch { }
            };

            _miAdblock = new ToolStripMenuItem("Enable Adblock")
            {
                CheckOnClick = true,
                Checked = chkAdblockOn.Checked
            };
            _miAdblock.Click += (_, __) =>
            {
                chkAdblockOn.Checked = _miAdblock.Checked;
                try { SaveUIPrefs(); } catch { }
            };

            _miParallel = new ToolStripMenuItem("Enable parallel downloads")
            {
                CheckOnClick = true,
                Checked = chkParallel.Checked
            };
            _miParallel.Click += (_, __) =>
            {
                chkParallel.Checked = _miParallel.Checked;
                try { SaveUIPrefs(); } catch { }
            };

            // ======== Settings: NV / VID pickers ========

            // Ensure spinners have correct caps
            nudNV.Minimum = 1; nudNV.Maximum = MAX_IMG_CONC;
            nudVID.Minimum = 1; nudVID.Maximum = MAX_VID_CONC;

            _miNv = new ToolStripMenuItem($"Non-video workers: {nudNV.Value}");
            _miVid = new ToolStripMenuItem($"Video workers: {nudVID.Value}");

            void RebuildCounts()
            {
                _miNv.DropDownItems.Clear();
                _miVid.DropDownItems.Clear();

                // ---- NV menu ----
                for (int i = 1; i <= MAX_IMG_CONC; i++)
                {
                    int pick = i; // <<< capture value for the handler
                    var it = new ToolStripMenuItem(pick.ToString())
                    { Checked = pick == (int)nudNV.Value };

                    it.Click += (_, __) =>
                    {
                        decimal val = pick;
                        nudNV.Value = Math.Min(nudNV.Maximum, Math.Max(nudNV.Minimum, val));
                        _miNv.Text = $"Non-video workers: {nudNV.Value}";
                        try { SaveUIPrefs(); } catch { }
                        RebuildCounts();
                    };

                    _miNv.DropDownItems.Add(it);
                }

                // ---- VID menu ----
                for (int i = 1; i <= MAX_VID_CONC; i++)
                {
                    int pick = i; // <<< capture value for the handler
                    var it = new ToolStripMenuItem(pick.ToString())
                    { Checked = pick == (int)nudVID.Value };

                    it.Click += (_, __) =>
                    {
                        decimal val = pick;
                        nudVID.Value = Math.Min(nudVID.Maximum, Math.Max(nudVID.Minimum, val));
                        _miVid.Text = $"Video workers: {nudVID.Value}";
                        try { SaveUIPrefs(); } catch { }
                        RebuildCounts();
                    };

                    _miVid.DropDownItems.Add(it);
                }
            }

            // keep menu text in sync if user uses the spinners
            nudNV.ValueChanged += (_, __) => { _miNv.Text = $"Non-video workers: {nudNV.Value}"; };
            nudVID.ValueChanged += (_, __) => { _miVid.Text = $"Video workers: {nudVID.Value}"; };

            // NEW: keep per-mode presets in sync with NV spinner
            nudNV.ValueChanged += (_, __) =>
            {

                switch (_mediaMode)
                {
                    case MediaMode.Images:
                        _nvImg = (int)nudNV.Value;
                        break;

                    case MediaMode.VideoAudio:
                        _nvVid = (int)nudNV.Value;
                        break;

                    default: // All
                        _nvAll = (int)nudNV.Value;
                        break;
                }
            };

            // NEW: keep per-mode presets in sync with VID spinner
            nudVID.ValueChanged += (_, __) =>
            {

                switch (_mediaMode)
                {
                    case MediaMode.Images:
                        _vidImg = (int)nudVID.Value;
                        break;

                    case MediaMode.VideoAudio:
                        _vidVid = (int)nudVID.Value;
                        break;

                    default: // All
                        _vidAll = (int)nudVID.Value;
                        break;
                }
            };

            RebuildCounts();



            // Settings menu items: tidy order + Wrap log lines //
            _miSettings.DropDownItems.Clear();

            // ensure Wrap Log item exists (default OFF = Both scrollbars) //
            if (_miWrapLog == null)
            {
                _miWrapLog = new ToolStripMenuItem("Wrap log lines")
                {
                    Name = "miWrapLog",
                    CheckOnClick = true,
                    Checked = txtLog?.WordWrap ?? false
                };
                _miWrapLog.CheckedChanged += (_, __) =>
                {
                    bool wrap = _miWrapLog.Checked;
                    _prefWrapLog = wrap; // persist this choice
                    txtLog.WordWrap = wrap;
                    if (_pnlLogScroll != null) // overlay present → keep natives hidden
                        txtLog.ScrollBars = ScrollBars.None;
                    else
                        txtLog.ScrollBars = wrap ? ScrollBars.Vertical : ScrollBars.Both;
                    SaveUIPrefs();
                    txtLog.Invalidate();

                };
            }

            // grouped layout: Window ▸ Adblock ▸ Concurrency ▸ Log //
            _miSettings.DropDownItems.AddRange(new ToolStripItem[] {
    _miLock, _miOpenOnDone,
    new ToolStripSeparator(),
    _miAdblock,
    new ToolStripSeparator(),
    _miParallel, _miNv, _miVid,
    new ToolStripSeparator(),
    _miWrapLog
});



            var miSaveOnExit = new ToolStripMenuItem("Save index on exit")
            {
                CheckOnClick = true,
                Checked = _optSaveIndexOnExit
            };
            miSaveOnExit.CheckedChanged += (_, __) => { _optSaveIndexOnExit = miSaveOnExit.Checked; SaveUIPrefs(); };
            _miSettings.DropDownItems.Add(miSaveOnExit);

            // File menu extras
            var miSaveIdx = new ToolStripMenuItem("Save de-dup index now");
            miSaveIdx.Click += async (_, __) => { await SaveMediaIndexAsync().ConfigureAwait(false); Log("[INDEX] Saved index."); };
            _miFile.DropDownItems.Add(miSaveIdx);

            var miPruneIdx = new ToolStripMenuItem("Prune dead index entries");
            miPruneIdx.Click += async (_, __) =>
            {
                var pruned = await PruneMediaIndexAsync().ConfigureAwait(false);
                if (pruned > 0) Log($"[INDEX] Pruned {pruned} dead entr{(pruned == 1 ? "y" : "ies")}.");
            };
            _miFile.DropDownItems.Add(miPruneIdx);

            _miFile.DropDownItems.Add(new ToolStripSeparator());
            _miSettings.DropDownItems.Add(miSaveOnExit);
            _miSettings.DropDownItems.Add(new ToolStripSeparator());

            var miAutoPrune = new ToolStripMenuItem("Auto-prune index")
            {
                CheckOnClick = true,
                Checked = _optAutoPrune
            };
            miAutoPrune.CheckedChanged += (_, __) =>
            {
                _optAutoPrune = miAutoPrune.Checked;
                if (_optAutoPrune) { EnsurePruneTimer(); _pruneTimer!.Start(); }
                else { _pruneTimer?.Stop(); }
                SaveUIPrefs();
            };
            _miSettings.DropDownItems.Add(miAutoPrune);

            var miAutoPruneEvery = new ToolStripMenuItem("Auto-prune interval");
            foreach (var m in new[] { 15, 30, 60, 180 })
            {
                var item = new ToolStripMenuItem($"{m} minutes") { Checked = (_optAutoPruneMinutes == m) };
                item.Click += (_, __) =>
                {
                    foreach (ToolStripMenuItem sib in miAutoPruneEvery.DropDownItems)
                        sib.Checked = false;
                    item.Checked = true;
                    ApplyPruneInterval(m);
                };
                miAutoPruneEvery.DropDownItems.Add(item);
            }
            _miSettings.DropDownItems.Add(miAutoPruneEvery);


            // File ▸ Exit //
            var miExit = new ToolStripMenuItem("Exit");
            miExit.Click += (_, __) => this.Close();
            _miFile.DropDownItems.Add(miExit);






            // stop edge selector on app exit
            this.FormClosing += async (_, __) =>
            {
                try
                {
                    // PATCH 5 — stop/dispose prune timer first
                    _pruneTimer?.Stop();
                    _pruneTimer?.Dispose();
                    _pruneTimer = null;
                    s_StopRequested = true;

                    _cts?.Cancel(); // stop workers
                    StopEdgeSelector(); // stop edge loop
                    await TeardownPlaywrightAsync(); // close page/context/browser, dispose _pw

                    // PATCH 7 — save de-dup index on exit (optional)
                    if (_optSaveIndexOnExit)
                    {
                        try
                        {
                            await SaveMediaIndexAsync().ConfigureAwait(false);
                            Log("[INDEX] Saved index on exit.");
                        }
                        catch (Exception ix)
                        {
                            Log("[INDEX] Save-on-exit failed: " + ix.Message);
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogStopOnce("[SHUTDOWN] Closing…");
                }
            };
            this.Shown += async (_, __) =>
            {
                if (_adblockOn && !_adblockStartupChecked)
                {
                    _adblockStartupChecked = true;
                    await EnsureEasyListFreshAsync().ConfigureAwait(false);
                    Log($"[ADBLOCK] ON — rules={_adblockRules.Count:N0} (auto-refresh at startup)");
                }
                else
                {
                    if (ShouldLogOnce("adblock:on", 300))
                        Log(_adblockOn
                            ? $"[ADBLOCK] ON — rules={_adblockRules.Count:N0}"
                            : "[ADBLOCK] OFF");
                }
            };






        }

        // ========================== Core Flow ========================== //
        private async Task StartRunAsync()
        {
            try
            {
                _sessionSw.Reset(); _sessionBytes = 0; _speedUiSw.Restart();
                _cancelSignaled = false;
                _hadDownloads = false; _videoBestChoice.Clear();
                _postAssetCounts.Clear();
                _assetPostIds.Clear();
                _assetSampleNames.Clear();

                var ct = System.Threading.CancellationToken.None; // local token for this run
                var url = (txtUrl.Text ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var u) || !(u.Host.Contains("coomer.st") && (u.AbsolutePath.Contains("/onlyfans/user/") || u.AbsolutePath.Contains("/fansly/user/") || u.AbsolutePath.Contains("/post/"))))
                { MessageBox.Show(this, "Enter a valid Coomer user || post URL.", "Invalid URL", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }

                var userSlug = ExtractUserFromUrl(txtUrl.Text ?? string.Empty) ?? "User";
                var albumName = userSlug; // //

                // Prefer the Fansly profile display name via a tiny Playwright pass (reusing _browser) //
                // Convenience overload for call sites without a CancellationToken

                if ((txtUrl.Text ?? string.Empty).Contains("/fansly/user/", StringComparison.OrdinalIgnoreCase))
                {
                    // Make sure we have a live browser before probing the display name
                    if (_browser is null || !_browser.IsConnected)
                    {
                        await TeardownPlaywrightAsync();
                        await SetupPlaywrightAsync(ct);
                    }

                    string? __nm = null;

                    // Normalize to the base user URL (strip any /post/<id> || paging)
                    var __u = new Uri(txtUrl.Text!);
                    var __path = __u.AbsolutePath;
                    var __ix = __path.IndexOf("/post/", StringComparison.OrdinalIgnoreCase);
                    if (__ix >= 0) __path = __path.Substring(0, __ix);
                    var __base = $"{__u.Scheme}://{__u.Host}{__path}";


                    // Try up to 2 attempts; if we see a disposed/stale browser, rebuild once
                    for (var __attempt = 0; __attempt < 2 && string.IsNullOrWhiteSpace(__nm); __attempt++)
                    {
                        try
                        {
                            await using var __ctx = await _browser!.NewContextAsync();
                            await __ctx.AddInitScriptAsync("try{Math.Max=Math.Max||Math.max.bind(Math);Math.Min=Math.Min||Math.min.bind(Math);}catch{}");

                            var __pg = await __ctx.NewPageAsync();
                            try
                            {
                                await __pg.GotoAsync(__base, new() { WaitUntil = WaitUntilState.NetworkIdle, Timeout = 60000 });

                                __nm = await __pg.EvalOnSelectorAsync<string>(
                                    "span[itemprop='name'], a.post__user-name, a.fancy-link.post__user-name",
                                    "el => el.textContent?.trim()");

                                if (string.IsNullOrWhiteSpace(__nm))
                                {
                                    var __title = await __pg.TitleAsync();
                                    var __mt = Regex.Match(__title ?? string.Empty, @"^\s*([^|\-–]+)");
                                    if (__mt.Success) __nm = __mt.Groups[1].Value.Trim();
                                }
                            }
                            finally
                            {
                                try { await __pg.CloseAsync(); } catch { /* best effort */ }
                            }
                        }

                        catch (Microsoft.Playwright.PlaywrightException ex) when (
                            ex.Message.IndexOf("Target closed", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            ex.Message.IndexOf("Connection disposed", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            ex.Message.IndexOf("has been closed", StringComparison.OrdinalIgnoreCase) >= 0
)
                        {
                            await TeardownPlaywrightAsync();
                            await SetupPlaywrightAsync(ct);
                            continue; // retry the probe once more
                        }

                        catch (PlaywrightException ex)
                        {
                            Log($"[ALBUM] Name probe failed: {ex.Message}");
                            break;
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(__nm) && !Regex.IsMatch(__nm, @"^\d+$"))
                        albumName = __nm!;
                    else if (!string.IsNullOrWhiteSpace(__nm))
                        Log($"[ALBUM] Name probe returned empty/numeric; keeping slug: {albumName}");
                }

                Log($"[ALBUM] Using display name: {albumName}");





                // Choose/normalize user folder (prevents duplicate numeric + friendly folders)
                var root = txtFolder.Text;
                var id = userSlug; // numeric id string you already have (use albumId here instead if that's your variable)
                var name = albumName; // preferred display name (may equal id if probe failed)

                // Guard: if albumName is missing, fall back to id
                if (string.IsNullOrWhiteSpace(name)) name = id;

                string byId = Path.Combine(root, id);
                string friendly = Path.Combine(root, SanitizeForPath(name));

                if (!string.Equals(name, id, StringComparison.Ordinal) && Directory.Exists(friendly))
                {
                    _userRootFolder = friendly;
                }
                else if (!string.Equals(name, id, StringComparison.Ordinal) &&
                         Directory.Exists(byId) &&
                         !byId.Equals(friendly, StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        Directory.Move(byId, friendly);
                        Log($"[INIT] Renamed user folder {Path.GetFileName(byId)} → {Path.GetFileName(friendly)}");
                        _userRootFolder = friendly;
                    }
                    catch
                    {
                        _userRootFolder = byId;
                    }
                }
                else
                {
                    // first run || no display name yet
                    _userRootFolder = friendly; // equals byId when name == id
                }

                // If album folder is missing at start, delete stale index
                try
                {
                    if (!Directory.Exists(_userRootFolder))
                    {
                        if (!string.IsNullOrEmpty(_mediaIndexPath) && File.Exists(_mediaIndexPath))
                        {
                            try { File.Delete(_mediaIndexPath); } catch { /* ignore */ }
                            try { _idxQuick.Clear(); _idxFull.Clear(); } catch { /* ignore */ }
                            Log("[INDEX] Album folder missing — deleted stale index.");
                        }
                    }
                }
                catch (Exception ix)
                {
                    Log("[INDEX] Failed to delete stale index: " + ix.Message);
                }

                // Ensure the folder exists (idempotent)
                try { Directory.CreateDirectory(_userRootFolder); } catch { /* ignore */ }

                // keep this log line
                Log($"[INIT] User root: {_userRootFolder}");
                bool _openOnDone = false; // local to the run method

                Ui(() =>
                {
                    btnStart.Enabled = false;
                    btnStop.Enabled = true;
                });


                // Per-album index @ album root
                _mediaIndexPath = Path.Combine(_userRootFolder, "media-index.json");
                _idxQuick.Clear();
                _idxFull.Clear();
                LoadMediaIndex();
                lock (_idxQuick)
                {
                    foreach (var k in _idxQuick.Keys.Where(k => !(k.StartsWith("V:") || k.StartsWith("I:"))).ToList())
                        _idxQuick.Remove(k);
                } // drop legacy bare keys

                var pruned = await PruneMediaIndexAsync().ConfigureAwait(false);
                if (pruned > 0)
                    Log($"[INDEX] pruned {pruned} stale entr{(pruned == 1 ? "y" : "ies")}.");









                Directory.CreateDirectory(ImagesRoot);
                Directory.CreateDirectory(VideoRoot);
                try { CleanStrayPartArtifacts(VideoRoot); } catch { }
                try { Directory.CreateDirectory(_appDir); await File.WriteAllTextAsync(_prefsPath, txtFolder.Text); } catch { }

                btnStart.Enabled = false; btnStop.Enabled = true;
                // [STOP.R1] reset graceful-stop state at run start
                _stopRequested = false;
                _stopMode = StopMode.Immediate;
                // clear leftover drain flags from prior run
                s_Draining = false;
                s_NoRangeThisRun = false;

                // clear any pending 3s 'Stop Now' timer from last run
                if (btnStop.Tag is Tuple<System.Windows.Forms.Timer, string> p)
                {
                    try { p.Item1.Stop(); p.Item1.Dispose(); } catch { }
                    btnStop.Tag = null;
                    btnStop.Text = p.Item2;
                }
                // reflect run-start in the local dashboard
                try
                {
                    CMDownloaderUI.Status.SetRunState("Running");
                    try
                    {
                        CMDownloaderUI.WebUiStatus.StartRun();
                        WebUiPublishCooldowns(); // NEW — push host states immediately
                    }
                    catch { }

                    CMDownloaderUI.Status.SetStartedAt(DateTime.UtcNow);
                }
                catch { }


                var hosts = GetMediaHostsSafe(); // uses hosts.txt if present, else built-ins
                if (_noRangeHosts.Count >= hosts.Length && !s_NoRangeThisRun)

                {
                    s_NoRangeThisRun = true;
                    Log("[RANGE] All edges ignored Range; remainder will be single-stream.");
                }




                _cts = new CancellationTokenSource();
                s_StopRequested = false;

                // [STOP.R2] fresh edge selector CTS per run
                try { _edgeCts?.Dispose(); } catch { }
                _edgeCts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);




                // Start EdgeSelector loop tied to this run's CancellationToken
                if (!NATURAL_URL_ONLY)
                {
                    try
                    {
                        _edgeCts?.Cancel();
                        _edgeCts?.Dispose();

                        // instantiate selector if needed (uses your required ctor signature)
                        _edge ??= new CMDownloaderUI.Net.EdgeSelector(
                            new CMDownloaderUI.Net.EdgeSelectorOptions
                            {
                                CandidateHosts = GetMediaHostsSafe(), // <-- use your n1..n4 list
                                                                      // (keep other defaults for now)
                            },
                            _http,
                            s => Log("[EDGE] " + s),
                            null
                        );

                        _edgeCts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                        _edge.Start(_edgeCts.Token);
                        Log("[EDGE] selector loop started");
                    }
                    catch (Exception ex)
                    {
                        Log("[EDGE] selector start failed: " + ex.Message);
                    }
                }




                // start global workers //
                var _pulsarWorkers = new List<Task>();

                if (_parallelOn && _globalQueueMode)
                {
                    _imgQ = new BlockingCollection<DownloadItem>(new ConcurrentQueue<DownloadItem>()); // -
                    _vidQ = new BlockingCollection<DownloadItem>(new ConcurrentQueue<DownloadItem>()); // -
                    var effNV = Math.Max(1, Math.Min(_maxNV, MAX_IMG_CONC));
                    var effVID = Math.Max(1, Math.Min(_maxVID, MAX_VID_CONC));
                    for (int i = 0; i < effNV; i++)
                    {
                        int wid = Interlocked.Increment(ref _nextWorkerId);
                        _pulsarWorkers.Add(Task.Run(() => WorkerLoop(_imgQ!, isVideo: false, wid, _cts.Token)));
                    }

                    for (int i = 0; i < effVID; i++)
                    {
                        int wid = Interlocked.Increment(ref _nextWorkerId);
                        _pulsarWorkers.Add(Task.Run(() => WorkerLoop(_vidQ!, isVideo: true, wid, _cts.Token)));
                    }


                    // INSERT AFTER
                    _cts.Token.Register(() => { try { _imgQ?.CompleteAdding(); _vidQ?.CompleteAdding(); } catch { } });

                }


                // compute the effective worker limits we are actually using for this run
                var cfgNV = _parallelOn && _globalQueueMode ? Math.Max(1, Math.Min(_maxNV, MAX_IMG_CONC)) : _maxNV;
                var cfgVID = _parallelOn && _globalQueueMode ? Math.Max(1, Math.Min(_maxVID, MAX_VID_CONC)) : _maxVID;

                Log($"[CFG] Parallel={_parallelOn} GlobalQ={_globalQueueMode} NV={cfgNV} VID={cfgVID} Adblock={_adblockOn} Mode={(_mediaMode == MediaMode.Images ? "Images" : _mediaMode == MediaMode.VideoAudio ? "Video+Audio" : "All")}");

                _qBad = 0;

                try
                {
                    _noRangeHosts.Clear();
                    // DIAG ONLY
                    // Log("[SEG.gate] cleared no-range host bans; zero-read cap reset");
                }

                catch { }
                _segZeroTs = null; // lazy-recreated on first zero-read


                Log($"[INIT] Start URL: {txtUrl.Text}");
                Status.SetRunState("Running");
                Status.SetStartedAt(DateTime.UtcNow);

                // per-run
                _segOverflowOpen = false;
                _segGateBurst = 0;
                _segGateBurstT0Ms = 0;
                ResetHealth(); UpdateSpeedLabel(0); _sessionSw.Start();

                _segAutoPoolFull = false;
                _segAutoConsecFull = 0;
                _segAutoConsecFree = 0;
                _segAutoLastLogKey = -1;

                // REPLACE
                if (_browser is null) await SetupPlaywrightAsync(_cts.Token);
                if ((txtUrl.Text ?? string.Empty).Contains("/post/", StringComparison.OrdinalIgnoreCase))
                {
                    SetOverallProgress(0, 1);
                    await ProcessSinglePostAsync(txtUrl.Text ?? string.Empty, _cts.Token);
                    SetOverallProgress(1, 1);
                }
                else
                {
                    var links = await CollectAllPostLinksAsync(txtUrl.Text ?? string.Empty, _cts.Token);
                    Log($"[INFO] Total posts discovered: {links.Count}");
                    if (_stopRequested && _stopMode == StopMode.Graceful)
                    {
                        Log("[STOP] Graceful: not enqueuing posts; finishing active downloads only.");
                        return; // exit this run path so active downloads can drain
                    }

                    SetOverallProgress(0, Math.Max(1, links.Count));
                    int idx = 0;
                    foreach (var link in links)
                    {
                        // S3.c — top of foreach (post in discoveredPosts)
                        if (_stopRequested && _stopMode == StopMode.Graceful) { Log("[STOP] Graceful: stopping before post navigation."); break; }
                        _cts.Token.ThrowIfCancellationRequested();
                        if (!(_parallelOn && _globalQueueMode)) await CooldownIfNeededAsync(_cts.Token);
                        try
                        {
                            await ProcessSinglePostAsync(link, _cts.Token);
                        }
                        catch (TimeoutException)
                        {
                            try { Log($"[POST.SKIP] Timeout navigating to {link} — skipping"); } catch { }
                            idx++; SetOverallProgress(idx, links.Count);
                            continue;
                        }
                        catch (PlaywrightException ex)
                        {
                            var m = ex.Message ?? string.Empty;
                            if (m.IndexOf("Timeout", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                m.IndexOf("domcontentloaded", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                try { Log($"[POST.SKIP] Nav error at {link} — skipping"); } catch { }
                                idx++; SetOverallProgress(idx, links.Count);
                                continue;
                            }
                            throw;
                        }
                        if (!(_parallelOn && _globalQueueMode)) await JitterAsync("POST", _cts.Token);

                        idx++; SetOverallProgress(idx, links.Count);
                    }
                    if (_stopRequested && _stopMode == StopMode.Graceful && (!_parallelOn || !_globalQueueMode))
                        if (s_ShouldLogOnce?.Invoke("stop.graceful", 60) == true) try { Log("[STOP] Graceful stop completed."); } catch { }

                }

                if (_parallelOn && _globalQueueMode && _imgQ is not null && _vidQ is not null)
                {
                    _imgQ.CompleteAdding(); _vidQ.CompleteAdding();
                    try { await Task.WhenAll(_pulsarWorkers); } catch { }
                    if (_stopRequested && _stopMode == StopMode.Graceful)
                        if (s_ShouldLogOnce?.Invoke("stop.graceful", 60) == true) try { Log("[STOP] Graceful stop completed."); } catch { }

                    try { _imgQ?.Dispose(); _vidQ?.Dispose(); } catch { }
                    _imgQ = null; _vidQ = null;
                    _pulsarWorkers.Clear();

                }
                CleanStrayPartArtifacts(VideoRoot);
                try { await FinalQuickDedupSweepAsync(CancellationToken.None); } catch { }
                try { await RunEndQuarantineSweep(_cts?.Token ?? CancellationToken.None); } catch { }


                bool _postRunCleanupDone = false;


                await RunWatchdogPassesAsync(_cts?.Token ?? CancellationToken.None);


                // Gate DONE until workers are idle (IMG/VID queues drained)
                if (_parallelOn)
                {
                    var __sw = System.Diagnostics.Stopwatch.StartNew();
                    while ((_imgQ?.Count ?? 0) > 0 || (_vidQ?.Count ?? 0) > 0)
                    {
                        await Task.Delay(250);
                        if (__sw.ElapsedMilliseconds > 300000) break; // safety net: 5 min
                    }
                }


                if (_qBad > 0) try { Log($"[VERIFY.SUMMARY] {_qBad} quarantined file(s) — likely truncated || header-only"); } catch { }
                if (s_ShouldLogOnce?.Invoke("run.done", 60) == true)
                    try { if (_qBad > 0) Log($"[VERIFY.SUMMARY] {_qBad} quarantined file(s)"); } catch { }

                // per-post counts + cross-post dupes
                try
                {
                    if (_postAssetCounts.Count > 0)
                    {
                        int totalImgs = 0, totalVids = 0;

                        foreach (var kv in _postAssetCounts)
                        {
                            var postId = kv.Key;
                            var stats = kv.Value;
                            int img = stats.Item1;
                            int vid = stats.Item2;
                            totalImgs += img;
                            totalVids += vid;

                            // Log($"[ASSET.POST] post={postId} img={img} vid={vid} total={img + vid}");
                        }

                        int totalAssets = totalImgs + totalVids;

                        foreach (var kv in _assetPostIds)
                        {
                            var key = kv.Key;
                            var posts = kv.Value;
                            if (posts == null) continue;

                            string[] postList;
                            lock (posts)
                            {
                                if (posts.Count <= 1) continue; // only care about cross-post dupes
                                postList = posts.ToArray();
                            }

                            _assetSampleNames.TryGetValue(key, out var sampleName);
                            Log($"[ASSET.DUPE] asset={(string.IsNullOrEmpty(sampleName) ? key : sampleName)} key={key} posts={string.Join(",", postList)}");

                        }

                        Log($"[ASSET.SUMMARY] posts={_postAssetCounts.Count} assets={totalAssets} img={totalImgs} vid={totalVids}");
                    }
                }
                catch { }

                // --- Run-end summary (user-facing) ---
                try { Log($"[RUN] new img={_sumImgsOk} vid={_sumVidsOk}"); } catch { }

                // --- DIAG/STATS (suppressed) ---
                // try { Log($"[HTTP] SS sends total={_ssSendTotal:N0} suppressed={_ssSendSuppressed:N0}"); } catch { }
                // try { Log($"[WRITER.GUARD] suppressed total={_writerGuardTotal}"); } catch { }
                // try { Log($"[FS] write total={_fsWriteTotal} suppressed={_fsWriteSupp} interesting={_fsWriteInteresting}"); } catch { }
                // try { Log($"[NAME.IDX] total={_nameIdxTotal:N0} suppressed={_nameIdxSupp:N0} (sampled first 3 per post)"); } catch { }
                // try { Log($"[SEG.PLAN] total={_segPlanTotal:N0} suppressed={_segPlanSupp:N0} interesting={_segPlanInteresting:N0}"); } catch { }







                // optional one-line summary of hard video failures
                try
                {
                    if (_sumVidsFailed > 0)
                        Log($"[RUN.SUMMARY] failed vids={_sumVidsFailed} (see media-fail-index.json)");
                }
                catch { }
                try { Log((_sumImgsOk + _sumVidsOk) > 0 ? "[DONE] Completed run." : "[DONE] Completed run (no downloads)."); } catch { }
                try { LogVerifySummary(); } catch { }

                try
                {
                    foreach (var ok in Directory.EnumerateFiles(_userRootFolder, "*.ok", SearchOption.AllDirectories))
                        try { File.Delete(ok); } catch { }
                }
                catch { }


                // cleanup/flatten BEFORE opening Explorer
                if (_hadDownloads)
                {
                    try
                    {
                        SweepEmptySetFolders();
                        // remove empty _quarantine dirs (global + per-set)
                        try
                        {
                            var imgRoot = ImagesRoot;
                            if (Directory.Exists(imgRoot))
                            {
                                foreach (var q in Directory.GetDirectories(imgRoot, "_quarantine", SearchOption.AllDirectories))
                                {
                                    if (!Directory.EnumerateFileSystemEntries(q).Any())
                                    {
                                        try { Directory.Delete(q, false); } catch { /* best-effort */ }
                                    }
                                }
                            }
                        }
                        catch { /* best-effort */ }

                        FlattenSingletonSetFolders(); // collapse single-file set folders to root
                        DeleteOkSidecars(VideoRoot); // remove stray .ok sidecars

                    }
                    catch { }
                }


                // open Explorer only if not canceled and the checkbox is on
                if (_hadDownloads && _cts is { IsCancellationRequested: false } && _openOnDone)
                {
                    try { Process.Start(new ProcessStartInfo("explorer.exe", _userRootFolder) { UseShellExecute = true }); } catch { }
                }
            }

            catch (OperationCanceledException) { Log("[CANCEL] Stopped by user."); }
            catch (Exception ex) { Log($"[ERR] {ex.GetType().Name}: {ex.Message}"); }
            finally
            {
                // always bracket run end
                try { if (_qBad > 0) Log($"[VERIFY.SUMMARY] {_qBad} quarantined file(s)"); } catch { }
                try { Log($"[DONE] run {_runId}"); } catch { }
                // let workers exit cleanly on graceful drain
                try { _imgQ?.CompleteAdding(); } catch { }
                try { _vidQ?.CompleteAdding(); } catch { }

                try { await SaveMediaIndexAsync().ConfigureAwait(false); } catch { }
                try { await TeardownPlaywrightAsync(); } catch { }

                Ui(() =>
                {
                    btnStart.Enabled = true;
                    btnStop.Enabled = false;
                    SetOverallProgress(0, 1);
                    EndCurrentFileProgress();
                    pbOverall.Style = ProgressBarStyle.Continuous;
                    pbOverall.MarqueeAnimationSpeed = 0;
                    _sessionSw.Stop();
                });

                // reflect run-stop in the local dashboard
                try
                {
                    CMDownloaderUI.Status.SetRunState("Idle");
                    try { CMDownloaderUI.WebUiStatus.StopRun(); } catch { }

                    CMDownloaderUI.Status.SetStartedAt(null);
                }
                catch { }

            }

            // always bracket run end
            try { FlattenSingletonSetFolders(); SweepEmptySetFolders(); } catch { }
            try { StopIndexFlushTimer(); } catch { }
            try { await SaveMediaIndexAsync().ConfigureAwait(false); } catch { }

        }

        private void OpenWebUiFromTray()
        {
            try
            {
                var url = "http://127.0.0.1:5088/";

                Process.Start(new ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
            }
            catch
            {
                // ignore; tray is just convenience
            }
        }



        private DateTime _lastSegZeroUtc = DateTime.MinValue;

        private void StopRun()
        {
            try { Log("[CANCEL] StopRun() called (programmatic)."); } catch { /* logging should never break stop */ }
            try { EndCurrentFileProgress(); } catch { /* best-effort */ }

            _cancelSignaled = true;
            s_StopRequested = true;
            try { _cts?.Cancel(); } catch { }
            try { StopEdgeSelector(); } catch { } // <— ensure the edge loop is stopped too
        }
        // called by WebUiHost (reflection)
        public void PauseFromWebUi()
        {
            s_PauseRequested = true;
            try { Log("[PAUSE] WebUI pause requested."); } catch { }
            try { CMDownloaderUI.Status.SetRunState("Paused"); } catch { }
        }
        public void PickFolderFromWebUi()
        {
            try { this.BeginInvoke(new Action(() => btnBrowse.PerformClick())); } catch { }
        }


        public void ResumeFromWebUi()
        {
            s_PauseRequested = false;
            try { Log("[PAUSE] WebUI resume requested."); } catch { }
            try { CMDownloaderUI.Status.SetRunState("Running"); } catch { }
        }


        // worker limits + mode
        public int GetNonVideoWorkerLimit() => _maxNV;
        public int GetVideoWorkerLimit() => _maxVID;


        public string GetModeFromWebUi()
        {
            if (!string.IsNullOrWhiteSpace(_modeLane))
                return _modeLane;

            return _mediaMode switch
            {
                MediaMode.Images => "img",
                MediaMode.VideoAudio => "vid",
                _ => "all"
            };
        }


        public void SetNonVideoWorkerLimit(int nv)
        {
            if (nv <= 0) return;

            if (InvokeRequired)
            {
                BeginInvoke((Action)(() => SetNonVideoWorkerLimit(nv)));
                return;
            }

            // clamp against our hard max for IMG workers
            var clamped = Math.Max(1, Math.Min(nv, MAX_IMG_CONC));

            // this is what the run startup code uses
            _maxNV = clamped;

            // keep the WinForms UI in sync
            try
            {
                if (nudNV != null)
                    nudNV.Value = clamped;
            }
            catch { }

            try { Log($"[TUNE] NV workers → {clamped}"); } catch { }
        }


        public void SetVideoWorkerLimit(int vid)
        {
            if (vid <= 0) return;

            if (InvokeRequired)
            {
                BeginInvoke((Action)(() => SetVideoWorkerLimit(vid)));
                return;
            }

            // clamp against our hard max for VID workers
            var clamped = Math.Max(1, Math.Min(vid, MAX_VID_CONC));

            // this is what the run startup code uses
            _maxVID = clamped;

            // keep the WinForms UI in sync
            try
            {
                if (nudVID != null)
                    nudVID.Value = clamped;
            }
            catch { }

            try { Log($"[TUNE] VID workers → {clamped}"); } catch { }
        }


        // expects "all" | "img" | "vid"
        public void SetModeFromWebUi(string mode)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new Action<string>(SetModeFromWebUi), mode);
                return;
            }

            mode = (mode ?? "all").Trim().ToLowerInvariant();
            if (mode != "img" && mode != "vid") mode = "all";

            _modeLane = mode;

            // Drive the real media mode the same way the desktop combo does
            switch (mode)
            {
                case "img":
                    _mediaMode = MediaMode.Images;
                    _vidWorkersLimit = 0; // WebUI Img-only → kill video lane
                    break;

                case "vid":
                    _mediaMode = MediaMode.VideoAudio;
                    _nvWorkersLimit = 0; // WebUI Vid-only → kill NV lane
                    break;

                default:
                    _mediaMode = MediaMode.All;
                    break;
            }

            ApplyMediaModeLanes();
            RememberModeLanes(); // keep NV/VID caps in sync

            try { Log($"[MODE] WebUI mode → {_modeLane} / {_mediaMode}"); } catch { }
        }






        // ========================== Playwright ========================== //
        private async Task SetupPlaywrightAsync(CancellationToken ct)
        {
            _pwFullyReady = false;
            Log("[PW] Starting Playwright…");
            var installedNow = await EnsurePlaywrightChromiumAsync();
            if (installedNow) await TeardownPlaywrightAsync();



            // --- [PW.RETRY] tolerate a just-closed browser/context once ---
            try
            {
                _pw = await Playwright.CreateAsync();
                _browser = await _pw.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
                {
                    // your existing options...
                });
            }
            catch (Microsoft.Playwright.PlaywrightException ex) when (
                ex.Message != null && ex.Message.Contains("Executable doesn't exist", StringComparison.OrdinalIgnoreCase))
            {
                try { Log("[PW] Browser missing — running one-time install…"); } catch { }
                var installedNow2 = await EnsurePlaywrightChromiumAsync();
                if (installedNow2) await TeardownPlaywrightAsync();

                _pw = await Playwright.CreateAsync();
                _browser = await _pw.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
                {
                    // same options again
                });
            }

            // --------------------------------------------------------------


            // create context
            _context = await _browser.NewContextAsync(new BrowserNewContextOptions
            {
                UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"
            }); // ← close the call, then semicolon

            // add once per context, AFTER the call above
            await _context.AddInitScriptAsync("try{Math.Max=Math.Max||Math.max.bind(Math);Math.Min=Math.Min||Math.min.bind(Math);}catch{}");

            // now your routing, unchanged
            await _context.RouteAsync("**/*", async route =>
            {
                var req = route.Request;
                // kill non-essential assets on page load
                if (req.ResourceType == "font" || req.ResourceType == "image" || req.ResourceType == "media" || req.ResourceType == "stylesheet" || req.ResourceType == "websocket")
                { await route.AbortAsync(); return; }
                var lower = req.Url.ToLowerInvariant();
                if (_adblockOn && _adblockRules.Count > 0 && IsBlockedByAdblock(lower)) { await route.AbortAsync(); return; }
                if (lower.Contains("doubleclick") || lower.Contains("googletag") || lower.Contains("metrics")) { await route.AbortAsync(); return; }
                await route.ContinueAsync();
            });


            _page = await _context.NewPageAsync();
            // 60s defaults
            try { _context!.SetDefaultTimeout(60000); _context!.SetDefaultNavigationTimeout(60000); } catch { }
            try { _page!.SetDefaultTimeout(60000); _page!.SetDefaultNavigationTimeout(60000); } catch { }
            _pwFullyReady = true;
            try { Log("[PW] READY (context+page OK)"); } catch { }

            // If SSE tried autologin before PW was ready, run it once now
            if (Interlocked.Exchange(ref _autoLoginDeferred, 0) == 1)
            {
                try { BeginInvoke(new Action(() => TryAutoLoginFromWebUi())); } catch { }
            }


        }

        private Task SetupPlaywrightAsync() => SetupPlaywrightAsync(System.Threading.CancellationToken.None);
        private Task<long> WaitForSettledLengthAsync(Uri url, CancellationToken ct)
    => WaitForSettledLengthAsync(url.ToString(), ct);

        // Teardown Playwright and ignore all errors (best-effort)
        // INSERT: focused nav retry helper (3 tries, short backoff)
        // jittered backoff + brief settle on success
        // jittered backoff + settle + DOMContentLoaded fallback
        private static async Task NavigateWithRetryAsync(IPage page, string url, CancellationToken ct, int maxAttempts = 3)
        {
            var delay = 350; // ms
            var rng = new Random();

            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    await page.GotoAsync(url, new PageGotoOptions
                    {
                        WaitUntil = WaitUntilState.DOMContentLoaded,
                        Timeout = 30000
                    }).ConfigureAwait(false);

                    try { await page.WaitForLoadStateAsync(LoadState.NetworkIdle, new() { Timeout = 2500 }).ConfigureAwait(false); } catch { }
                    return;
                }
                catch (PlaywrightException) when (!ct.IsCancellationRequested && attempt < maxAttempts)
                {
                    try { await page.WaitForLoadStateAsync(LoadState.Load, new() { Timeout = 2000 }).ConfigureAwait(false); } catch { }
                    try { await page.WaitForLoadStateAsync(LoadState.NetworkIdle, new() { Timeout = 1500 }).ConfigureAwait(false); } catch { }
                    try { await page.WaitForSelectorAsync("article, .post, .container", new() { Timeout = 1500 }).ConfigureAwait(false); } catch { }

                    try { await Task.Delay(delay + rng.Next(0, 300), ct).ConfigureAwait(false); } catch (OperationCanceledException) { throw; }
                    delay = Math.Min(delay * 2, 2000);
                }
            }

            await page.GotoAsync(url, new PageGotoOptions
            {
                WaitUntil = WaitUntilState.DOMContentLoaded,
                Timeout = 30000
            }).ConfigureAwait(false);
        }




        private async Task TeardownPlaywrightAsync()
        {
            _pwFullyReady = false;
            try { if (_page != null && !_page.IsClosed) await _page.CloseAsync(); }
            catch { }
            finally { _page = null; }

            try { if (_context != null) await _context.CloseAsync(); }
            catch { }
            finally { _context = null; }

            try { if (_browser != null) await _browser.CloseAsync(); }
            catch { }
            finally { _browser = null; }

            try { _pw?.Dispose(); }
            catch { }
            finally { _pw = null; }
        }


        // ========================== Pagination & Collection ==================== //
        private async Task<List<string>> CollectAllPostLinksAsync(string userUrl, CancellationToken ct)
        {
            var all = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            await _page!.GotoAsync(userUrl, new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded, Timeout = 12000 }); // [0373}
                                                                                                                                   // ensure the grid (or footer) is present before pageSize detection
            await _page!.WaitForSelectorAsync("div[class*=post-card], footer", new() { Timeout = 15000 }).ConfigureAwait(false);

            try { await _page.WaitForSelectorAsync("a[href*='/post/']", new PageWaitForSelectorOptions { Timeout = 6000 }); } catch { }
            var (pageSize, total) = await ReadShowingCountsAsync(_page); if (pageSize == 0) pageSize = 50; if (total == 0) total = pageSize;
            Log($"[PAGE] Collecting posts pageSize={pageSize} this can take a min...");
            // REPLACE
            int pages = (int)Math.Ceiling(total / (double)pageSize);
            for (int p = 0; p < pages; p++)
            {
                if (_stopRequested && _stopMode == StopMode.Graceful)
                {
                    Log($"[STOP] Graceful: aborting pagination at {p + 1}/{pages}.");
                    break;
                }

                // -[0386] DROP-IN (no timers)
                ct.ThrowIfCancellationRequested();
                int offset = p * pageSize; var url = BuildOffsetUrl(userUrl, offset);

                await _page.GotoAsync(url, new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded, Timeout = 12000 });
                try { await _page.WaitForSelectorAsync("a[href*='/post/']", new PageWaitForSelectorOptions { Timeout = 6000 }); } catch { }

                var links = await CollectPostLinksAsync(_page); foreach (var l in links) all.Add(l);
                if (links.Length == 0)
                {
                    try { await _page.WaitForSelectorAsync("a[href*='/post/']", new PageWaitForSelectorOptions { Timeout = 2000 }); } catch { }
                    links = await CollectPostLinksAsync(_page); foreach (var l in links) all.Add(l);
                }


                if (all.Count >= total) break;
            }
            Log($"[PAGE] Collected posts={all.Count}/{total} pages={pages}");
            return all.ToList();
        }

        private static string BuildOffsetUrl(string baseUrl, int offset) { var u = new Uri(baseUrl); var root = u.GetLeftPart(UriPartial.Path).TrimEnd('/'); return $"{root}/?o={offset}"; }

        private static async Task<(int pageSize, int total)> ReadShowingCountsAsync(IPage page)
        {
            var text = await page.EvaluateAsync<string>("() => { const rx=/Showing\\s*(\\d+)\\s*[-–]\\s*(\\d+)\\s*of\\s*(\\d+)/i; for (const el of document.querySelectorAll('small, p, div, span')) { const t=(el.innerText||el.textContent||'').trim(); if (rx.test(t)) return t;} return '';}");
            if (string.IsNullOrWhiteSpace(text)) return (0, 0);
            var m = Regex.Match(text, @"Showing\s*(\d+)\s*[-–]\s*(\d+)\s*of\s*(\d+)", RegexOptions.IgnoreCase);
            if (!m.Success) return (0, 0);
            int lo = int.Parse(m.Groups[1].Value), hi = int.Parse(m.Groups[2].Value), tot = int.Parse(m.Groups[3].Value);
            int size = Math.Max(1, hi - lo + 1); return (size, tot);
        }

        private static async Task<string[]> CollectPostLinksAsync(IPage page)
        {
            return await page.EvaluateAsync<string[]>("() => { const seen=new Set(); [...document.querySelectorAll('a[href*=\"/post/\"]')].forEach(a=>seen.add(a.href)); [...document.querySelectorAll('article a[href]')].forEach(a=>{ if(a.href.includes('/post/')) seen.add(a.href);}); return [...seen]; }");
        }

        // ========================== Single Post ========================== //
        private async Task ProcessSinglePostAsync(string postUrl, CancellationToken ct)
        {
            try
            {
                await NavigateWithRetryAsync(_page, postUrl, ct); // REPLACE
                                                                  // before moving to the next post, summarize the previous one
                if (!string.IsNullOrEmpty(_lastNavPostUrl))
                    TryLogPerPostSummary(_lastNavPostUrl);

                _lastNavPostUrl = postUrl;

                Log($"[NAV] {postUrl}");

                _sumPosts++;

                await SyncCookiesFromPlaywrightAsync(); // keep HttpClient in lockstep with the page

                try { await _page.WaitForLoadStateAsync(LoadState.NetworkIdle, new PageWaitForLoadStateOptions { Timeout = 5000 }); } catch { }
                try { await _page.WaitForSelectorAsync("article, .post, .post__files, a[href*=\"/data/\"]", new PageWaitForSelectorOptions { Timeout = 3000 }); } catch { }

                var rawTitle = await FirstNonEmptyAsync(_page, new[] { "document.querySelector('h1, h2')?.textContent ?? ''", "document.querySelector('meta[property=\"og:title\"]')?.content ?? ''", "document.title || ''" });
                string usernameHint = ExtractUserFromUrl(postUrl) ?? ExtractUserFromUrl(txtUrl.Text ?? string.Empty) ?? string.Empty;

                // Coomer: only treat post attachments as real content images
                var imgExts = new[] { ".jpg", ".jpeg", ".png", ".gif", ".webp" };
                var imageUrlStrings = await CollectByExtensionsFromSelectorAsync(
                    _page,
                    "div.post__files a.fileThumb.image-link[href]",
                    imgExts); // Coomer image attachments only

                // prefer canonical *_source.mp4 links first
                string[] directVids;
                bool videoFromFallback = false;
                try
                {
                    directVids = await _page.EvaluateAsync<string[]>(@"() => {
                    const out = new Set();
                    document.querySelectorAll('.post__files a[href], a[href*=""_source.mp4""]').forEach(a=>{
                      const href = a.getAttribute('href') || '';
                      if (/_source\.mp4/i.test(href)) out.add(a.href || href);
                    });
                    return Array.from(out);
                }");
                }
                catch { directVids = Array.Empty<string>(); }





                var zipUrls = new List<string>(); // [ZIP.DISABLED.SCAN] don't enumerate ZIPs at all
                var videoUrlStrings = directVids?.ToList() ?? new List<string>();
                var directVidSet = new HashSet<string>(videoUrlStrings, StringComparer.OrdinalIgnoreCase);

                // attachments first, then <video><source> if nothing else
                try
                {
                    var vidExts = new[] { ".mp4", ".m4v", ".mov" };

                    // Wait for attachments or confirm they don't exist before scanning <video><source>
                    // Try up to 1500ms because Coomer is slow as hell
                    try
                    {
                        await _page.WaitForSelectorAsync("ul.post__attachments",
                            new() { Timeout = 1500 });
                    }
                    catch { /* ignore — means no attachments appeared */ }

                    // 1) Real downloads: attachment links (the ?f=7120…mp4 style URLs)
                    var attachVids = await CollectByExtensionsFromSelectorAsync(
                        _page,
                        "ul.post__attachments a.post__attachment-link[href]",
                        vidExts);

                    foreach (var v in attachVids)
                    {
                        if (!videoUrlStrings.Any(x =>
                                string.Equals(x, v, StringComparison.OrdinalIgnoreCase)))
                        {
                            videoUrlStrings.Add(v);

                            // treat attachment vids as direct-legit too (even if tiny)
                            try { directVidSet.Add(v); } catch { }
                        }
                    }


                    // 2) If we still have nothing (no *_source + no attachments),
                    // fall back to <video><source src="...mp4"> under the post body.
                    if (videoUrlStrings.Count == 0)
                    {
                        var vidSrcs = await CollectVideoSourcesFromSelectorAsync(
                            _page,
                            ".post__body",
                            vidExts);

                        foreach (var v in vidSrcs.Distinct(StringComparer.OrdinalIgnoreCase))
                        {
                            videoUrlStrings.Add(v);

                            // treat <video><source> fallback as direct-legit too (even if tiny)
                            try { directVidSet.Add(v); } catch { }
                        }
                    }

                }
                catch { }




                var bestImages = await SelectBestImagesAsync(imageUrlStrings, ct);
                var bestVids = await SelectBestVideosAsync(videoUrlStrings, ct, directVidSet);
                // Count uniques using the same keys you use for dedup / matchKey
                // respect image-only / video-only modes for this post
                if (_mediaMode == MediaMode.Images)
                {
                    bestVids.Clear(); // image-only → drop all videos for this post
                }
                else if (_mediaMode == MediaMode.VideoAudio)
                {
                    bestImages.Clear(); // video-only → drop all images for this post
                }

                int uniqImgCount = bestImages
                    .Select(u => ImageKey(u.ToString()))

                                    .Where(k => k != null)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count();

                int uniqVidCount = bestVids
                    .Select(v => VideoKeyFromUrl(v))
                    .Where(k => k != null)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count();

                // Feed *unique* counts into BuildNaming so singletons don't get a set folder
                int imgCountAll = bestImages.Count; // raw count
                int vidCountAll = bestVids.Count; // raw count
                var nameIMG = BuildNaming(rawTitle, ImagesRoot, uniqImgCount, usernameHint);
                var nameVID = BuildNaming(rawTitle, VideoRoot, uniqVidCount, usernameHint);
                // ZIPs disabled — build a dummy name under VideoRoot with 0 items
                var nameZIP = BuildNaming(rawTitle, VideoRoot, 0, usernameHint);


                // Fansly: short set folder names → "{last6}-{hash2}" //
                // Fansly set-folder naming rules (2025-08-19): titled → "<truncated-clean-title>-ab12"; untitled → ID-based short. //
                bool __isFansly = postUrl.Contains("/fansly/", StringComparison.OrdinalIgnoreCase);
                if (__isFansly)
                {
                    // Extract post ID (for untitled fallback) //
                    var __m = Regex.Match(postUrl ?? string.Empty, @"/post/(\d+)");
                    string? __pid = __m.Success ? __m.Groups[1].Value : null;
                    string __last6 = string.IsNullOrEmpty(__pid) ? "" : (__pid.Length > 6 ? __pid[^6..] : __pid); // -

                    // Title-based short name for sets with a non-empty CleanTitle not equal to "untitled" //
                    string __clean = nameIMG.CleanTitle?.Trim() ?? "";
                    bool __hasTitle = !string.IsNullOrWhiteSpace(__clean) && !__clean.Equals("untitled", StringComparison.OrdinalIgnoreCase);
                    string __hx = Hex2FromStableHash(__hasTitle ? __clean : (__pid ?? __clean));
                    string __short =
                        __hasTitle
                            ? $"{TruncateFolder(SanitizeForPath(__clean), 24)}-{__hx}" // e.g., "gym-shoot-day-1-a3" //
                            : (!string.IsNullOrEmpty(__last6) ? $"{__last6}-{__hx}" : $"{TruncateFolder(SanitizeForPath(__clean), 8)}-{__hx}"); // -

                    static Naming ApplyShort(Naming n, string s) =>
                        n.UseSetFolder ? new Naming { CleanTitle = n.CleanTitle, UseSetFolder = true, SetFolderName = s, CategoryFolder = n.CategoryFolder } : n; // -

                    nameIMG = ApplyShort(nameIMG, __short);
                    nameVID = ApplyShort(nameVID, __short);
                    nameZIP = ApplyShort(nameZIP, __short);
                }

                if (bestImages.Count == 0 && bestVids.Count == 0 && zipUrls.Count == 0)
                {
                    try
                    {
                        Log($"[POST.EMPTY] No assets detected for \"{nameIMG.CleanTitle}\" → {postUrl}");
                    }
                    catch { }
                }




                if (_parallelOn && _globalQueueMode && _imgQ is not null && _vidQ is not null)
                {
                    if (_stopRequested && _stopMode == StopMode.Graceful)
                    {
                        Log("[STOP] Graceful: blocking new queue items.");
                        return;
                    }
                    var referer = postUrl ?? string.Empty;

                    int i = 0;
                    foreach (var u in bestImages)
                    {
                        if (!ShouldKeepKind("IMG")) continue;

                        var __imgKeyCore = ImageKey(u.ToString()) ?? u.ToString();
                        var __imgQKey = "I:" + __imgKeyCore; // kind-prefix

                        if (!_inflightQ.TryAdd(__imgQKey, 1))
                        {
                            System.Threading.Interlocked.Increment(ref _writerGuardTotal);
                            System.Threading.Interlocked.Increment(ref _writerGuardBurst);
                            _writerGuardSample ??= __imgQKey;

                            // Log at most once per 15s (but keep counting everything)
                            if (s_ShouldLogOnce?.Invoke("writer.guard", 60) == true)
                            {
                                var n = System.Threading.Interlocked.Exchange(ref _writerGuardBurst, 0);
                                try { Log($"[WRITER.GUARD] already inflight x{n} (sample → {_writerGuardSample})"); } catch { }
                            }

                            continue;
                        }

                        DownloadItem imgItem = (u, nameIMG, ++i, "IMG", referer, __imgKeyCore);
                        EnqueueIfOpen(_imgQ, imgItem, _cts.Token);
                    }


                    WebUiStatus.SetQueue((_imgQ?.Count ?? 0) + (_vidQ?.Count ?? 0) + _retryQ.Count);

                    int v = 0;


                    // allow only a small backlog above active VID lanes
                    int backlog = _vidQ?.Count ?? 0;
                    int allowed = Math.Max(1, CapVideoBacklog(Math.Max(0, bestVids.Count - backlog))); // never clamp to 0

                    if (allowed > 0)
                    {
                        int j = 0; // <-- add this

                        foreach (var vurl in bestVids)
                        {
                            var __qKey = "V:" + VideoKeyFromUrl(vurl); // kind-prefix
                            if (!_inflightQ.TryAdd(__qKey, 1))

                            {
                                System.Threading.Interlocked.Increment(ref _writerGuardTotal);
                                System.Threading.Interlocked.Increment(ref _writerGuardBurst);
                                _writerGuardSample ??= __qKey;

                                if (s_ShouldLogOnce?.Invoke("writer.guard", 15) == true)
                                {
                                    var n = System.Threading.Interlocked.Exchange(ref _writerGuardBurst, 0);
                                    try { Log($"[WRITER.GUARD] already inflight x{n} (sample → {_writerGuardSample})"); } catch { }
                                }

                                continue;
                            }

                            DownloadItem vidItem = (vurl, nameVID, ++j, "VID", referer, null);
                            EnqueueIfOpen(_vidQ, vidItem, _cts.Token);
                        }


                        WebUiStatus.SetQueue((_imgQ?.Count ?? 0) + (_vidQ?.Count ?? 0) + _retryQ.Count);
                    }

                    else
                    {
                        if (Environment.TickCount64 - (long)(AppContext.GetData("astrofetch.gate.full.last") ?? 0L) > 30000)
                        {
                            Log("[STOP] Gate: video backlog full; deferring new video adds.");
                            AppContext.SetData("astrofetch.gate.full.last", Environment.TickCount64);
                        }
                    }



                    int z = 0;
                    foreach (var s in zipUrls)
                    {
                        if (ShouldKeepKind("ZIP"))
                        {
                            DownloadItem zipItem = (new Uri(s!), nameZIP, ++z, "ZIP", referer, null);
                            EnqueueIfOpen(_imgQ, zipItem, _cts.Token);
                        }
                    }


                    return;
                }
                // REPLACE [0476]..


                if (_parallelOn)
                {
                    await RunParallelDownloadsAsync(
                        bestImages.Select((u, i) => (url: u, naming: nameIMG, idx: i + 1, kind: "IMG", referer: postUrl, matchKey: (string?)ImageKey(u.ToString()))),
                        bestVids.Select((v, i) => (url: v, naming: nameVID, idx: i + 1, kind: "VID", referer: postUrl, matchKey: (string?)VideoKeyFromUrl(v))),
                        zipUrls.Select((s, i) => (url: new Uri(s), naming: nameZIP, idx: i + 1, kind: "ZIP", referer: postUrl, matchKey: (string?)null)), ct);
                }
                else
                {
                    int iIndex = 0;
                    foreach (var u in bestImages)
                    {
                        ct.ThrowIfCancellationRequested();
                        iIndex++;

                        string __edgeHost = null; try { __edgeHost = u?.Host; } catch { }
                        if (!string.IsNullOrEmpty(__edgeHost))
                            _activeByHost.AddOrUpdate(__edgeHost, 1, static (_, v) => v + 1);
                        try
                        {
                            _ = await DownloadWithNamingAsync(u, nameIMG, iIndex, "IMG", postUrl, ct, ImageKey(u.ToString()));
                        }
                        finally
                        {
                            if (!string.IsNullOrEmpty(__edgeHost))
                                _activeByHost.AddOrUpdate(__edgeHost, 0, static (_, v) => (v > 1 ? v - 1 : 0));
                        }

                        await JitterAsync("IMG", ct);
                    }

                    int vIndex = 0;
                    foreach (var v in bestVids)
                    {
                        ct.ThrowIfCancellationRequested();
                        vIndex++;

                        string __edgeHost = null; try { __edgeHost = v?.Host; } catch { }
                        if (!string.IsNullOrEmpty(__edgeHost))
                            _activeByHost.AddOrUpdate(__edgeHost, 1, static (_, vv) => vv + 1);
                        try
                        {
                            _ = await DownloadWithNamingAsync(v, nameVID, vIndex, "VID", postUrl, ct, VideoKeyFromUrl(v));
                        }
                        finally
                        {
                            if (!string.IsNullOrEmpty(__edgeHost))
                                _activeByHost.AddOrUpdate(__edgeHost, 0, static (_, vv) => (vv > 1 ? vv - 1 : 0));
                        }

                        await JitterAsync("VID", ct);
                    }

                    int zIndex = 0;
                    foreach (var z in zipUrls)
                    {
                        ct.ThrowIfCancellationRequested();
                        zIndex++;

                        string __edgeHost = null; try { __edgeHost = new Uri(z).Host; } catch { }
                        if (!string.IsNullOrEmpty(__edgeHost))
                            _activeByHost.AddOrUpdate(__edgeHost, 1, static (_, zv) => zv + 1);
                        try
                        {
                            _ = await DownloadWithNamingAsync(new Uri(z), nameZIP, zIndex, "ZIP", postUrl, ct, null);
                        }
                        finally
                        {
                            if (!string.IsNullOrEmpty(__edgeHost))
                                _activeByHost.AddOrUpdate(__edgeHost, 0, static (_, zv) => (zv > 1 ? zv - 1 : 0));
                        }

                        await JitterAsync("ZIP", ct);
                    }

                }
            } // close try (A2)
            catch (Microsoft.Playwright.PlaywrightException pw) when (
                pw.Message?.IndexOf("Execution context was destroyed", StringComparison.OrdinalIgnoreCase) >= 0
            )
            {
                Log("[PW] Context lost during nav — retrying current post.");
                await Task.Delay(400);
                return; // swallow this post hiccup; caller continues to next post
            }

        }

        // ===== Parallel Scheduler ===== //

        private async Task RunParallelDownloadsAsync(IEnumerable<(Uri url, Naming naming, int idx, string kind, string? referer, string? matchKey)> imgs,
                                                     IEnumerable<(Uri url, Naming naming, int idx, string kind, string? referer, string? matchKey)> vids,
                                                     IEnumerable<(Uri url, Naming naming, int idx, string kind, string? referer, string? matchKey)> zips,
                                                     CancellationToken ct)
        {
            var all = new List<(Uri url, Naming naming, int idx, string kind, string? referer, string? matchKey)>();
            all.AddRange(imgs);
            all.AddRange(vids);
            // guard in case anything slipped in
            all = all.Where(it => !string.Equals(it.kind, "ZIP", StringComparison.OrdinalIgnoreCase)).ToList();

            // all.AddRange(zips); // [ZIP.DISABLED] temporarily disable ZIP processing
            // PATCH 2B — drop duplicate videos by matchKey before enqueuing
            {
                var seenVideoKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                all = all.Where(it =>
                {
                    if (string.Equals(it.kind, "VID", StringComparison.OrdinalIgnoreCase))
                    {
                        var k = it.matchKey ?? it.url.ToString();
                        if (!seenVideoKeys.Add(k)) return false; // duplicate video → drop
                    }
                    return true;
                }).ToList();
            }

            int total = all.Count; int done = 0; SetOverallProgress(0, Math.Max(1, total));
            int inflightNV = 0, inflightVID = 0;
            var tasks = new List<Task>();
            var q = new Queue<(Uri url, Naming naming, int idx, string kind, string? referer, string? matchKey)>(all);
            // === [LANES] per-asset isolation: start tasks with per-kind counters & swallow failures ===
            // === [LANES] per-asset isolation: start tasks with per-kind counters & swallow failures ===
            Task StartOne((Uri url, Naming naming, int idx, string kind, string? referer, string? matchKey) it)
            {
                // Count inflight by kind: VID vs non-video (IMG)
                if (string.Equals(it.kind, "VID", StringComparison.OrdinalIgnoreCase))
                {
                    inflightVID++;
                    Log($"[VID.ACTIVE] {inflightVID}");
                }
                else
                {
                    inflightNV++;
                }

                return Task.Run(async () =>
                {
                    try
                    {
                        // Per-asset download+verify. Any quarantine/accept happens inside.
                        string __edgeHostLane = null;
                        try { __edgeHostLane = it.url?.Host; } catch { }

                        if (!string.IsNullOrEmpty(__edgeHostLane))
                            _activeByHost.AddOrUpdate(__edgeHostLane, 1, static (_, v) => v + 1);
                        WebUiPublishActiveThrottled(); // smooth UI update

                        try
                        {
                            await DownloadWithNamingAsync(it.url, it.naming, it.idx, it.kind, it.referer, ct, it.matchKey)
                                .ConfigureAwait(false);
                        }
                        finally
                        {
                            if (!string.IsNullOrEmpty(__edgeHostLane))
                                _activeByHost.AddOrUpdate(__edgeHostLane, 0, static (_, v) => (v > 1 ? v - 1 : 0));
                            WebUiPublishActiveThrottled(); // smooth UI update
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex)
                    {
                        try { Log($"[LANE.{it.kind}] task failed: {ex.Message}"); } catch { }
                        // swallow so other lane keeps moving
                    }
                    finally
                    {
                        if (string.Equals(it.kind, "VID", StringComparison.OrdinalIgnoreCase))
                        {
                            inflightVID = Math.Max(0, inflightVID - 1);
                            Log($"[VID.ACTIVE] {inflightVID}");
                        }
                        else
                        {
                            inflightNV = Math.Max(0, inflightNV - 1);
                        }

                        done++;
                        try { SetOverallProgress(done, Math.Max(1, total)); } catch { }
                    }
                });
            }


            while (q.Count > 0 || tasks.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                while (q.Count > 0)
                {
                    int rotations = q.Count;
                    // === Fair scheduler: rotate until a lane has room, otherwise break to await tasks ===
                    int guard = rotations;
                    bool launched = false;
                    var limits = CurrentLimits(); // reuse your method

                    while (q.Count > 0 && guard-- > 0)
                    {
                        var peek = q.Peek();
                        bool isVid2 = string.Equals(peek.kind, "VID", StringComparison.OrdinalIgnoreCase);

                        int capNv = Math.Max(1, limits.nv);
                        int capVid = Math.Max(1, limits.vid);

                        bool laneHasRoom = isVid2 ? (inflightVID < capVid) : (inflightNV < capNv);
                        if (laneHasRoom)
                        {
                            var it = q.Dequeue();
                            tasks.Add(StartOne(it));
                            launched = true;
                            break;
                        }
                        else
                        {
                            // rotate this item so the other lane can proceed
                            q.Enqueue(q.Dequeue());
                        }
                    }

                    // If neither lane could launch anything right now, leave inner loop to drain a task
                    if (!launched) break;

                }
                if (tasks.Count > 0)
                {
                    var finished = tasks.Where(t => t.IsCompleted).ToList();
                    foreach (var f in finished) tasks.Remove(f);
                    if (finished.Count == 0) await Task.Delay(50, ct);
                }
            }
        }
        // After you finish writing a segmented file:
        // await RepairTailIfNeededAsync(destFullPath, sourceUrl, ct);

        private async Task RepairTailIfNeededAsync(string path, string url, CancellationToken ct)
        {
            try
            {
                // 1) Get the true remote length (HEAD if available, otherwise Range 0-0)
                long remoteLen = await GetRemoteLengthAsync(url, ct);
                if (remoteLen <= 0) return; // can't verify; bail quietly

                var fi = new FileInfo(path);
                long localLen = fi.Exists ? fi.Length : 0;
                if (localLen >= remoteLen) return; // already complete
                                                   // 2) Pull just the missing tail and append
                using var req = new HttpRequestMessage(HttpMethod.Get, url);

                // Byte-true Range (open-ended if remoteLen unknown)
                if (remoteLen > 0)
                    req.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(localLen, remoteLen - 1); // inclusive end
                else
                    req.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(localLen, null);

                NormalizeDownloadRequest(req);

                // SS = H/1.1 + identity for stable tails/resumes
                try { req.Headers.AcceptEncoding.Clear(); req.Headers.AcceptEncoding.ParseAdd("identity"); } catch { }
                req.Version = System.Net.HttpVersion.Version11;
                req.VersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionOrLower;
                req.Headers.ConnectionClose = true; // force H/1.1 close to avoid mid-stream upgrades


                // Tail is tiny; prefer a fresh socket to avoid flaky pooled conns
                req.Headers.ConnectionClose = true;

                // [SS.SEND] log-on-change (thread-safe)
                try
                {
                    System.Threading.Interlocked.Increment(ref _ssSendTotal);

                    var ae = string.Join(",", req.Headers.AcceptEncoding);
                    bool keepAlive = req.Headers.ConnectionClose != true;

                    string sig = $"v={req.Version} policy={req.VersionPolicy} ae={ae} keepalive={keepAlive}";

                    bool logIt = false;
                    lock (_ssSendLock)
                    {
                        if (!string.Equals(sig, _lastSsSig, StringComparison.Ordinal))
                        {
                            _lastSsSig = sig;
                            logIt = true;
                        }
                        else
                        {
                            System.Threading.Interlocked.Increment(ref _ssSendSuppressed);
                        }
                    }

                    if (logIt)
                        Log($"[SS.SEND] {sig}");
                }
                catch { }


                // --- robust single-stream writer (atomic, guarded) ---
                using (var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
                {
                    try { Log($"[PROTO] phase=SS v={res.Version} host={(req.RequestUri?.Host ?? "?")}"); } catch { }
                    // Expect a 206 for a valid Range tail; treat others as an edge flip/misbehaving proxy
                    if (res.StatusCode != System.Net.HttpStatusCode.PartialContent)
                    {
                        try { res.Dispose(); } catch { }
                        throw new HttpRequestException("Expected 206 for ranged tail");
                    }

                    // – sniff first chunk for obviously-wrong types (MP4/MOV require 'ftyp'; MKV/WEBM require EBML)
                    var cl = res.Content.Headers.ContentLength ?? -1;
                    if (cl > 0)
                    {
                        using (var peek = await res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
                        {
                            // Don’t consume: buffer then replay
                            byte[] head = new byte[12];
                            int n = await peek.ReadAsync(head, 0, head.Length, ct).ConfigureAwait(false);
                            // rebuild content as concatenation of 'head' + remainder
                            var tailStream = new System.IO.MemoryStream();
                            if (n > 0) tailStream.Write(head, 0, n);
                            await peek.CopyToAsync(tailStream, 1 << 16, ct).ConfigureAwait(false);
                            tailStream.Position = 0;

                            // Basic magic checks
                            bool looksMp4 = n >= 8 && head[4] == (byte)'f' && head[5] == (byte)'t' && head[6] == (byte)'y' && head[7] == (byte)'p';
                            bool looksEbml = n >= 4 && head[0] == 0x1A && head[1] == 0x45 && head[2] == 0xDF && head[3] == 0xA3;

                            var ext = Path.GetExtension(path)?.ToLowerInvariant();
                            bool okKind =
                                (ext == ".mp4" || ext == ".m4v" || ext == ".mov") ? looksMp4 :
                                (ext == ".webm" || ext == ".mkv") ? looksEbml :
                                true; // other types: don’t enforce

                            if (!okKind)
                            {
                                try { Log("[SS.HEAD.CHECK] rejecting tail: header magic mismatch"); } catch { }
                                res.Dispose();
                                throw new IOException("[SEG.ZERO]");
                            }

                            // Replace content with replayable stream
                            var replay = new StreamContent(tailStream);
                            foreach (var h in res.Content.Headers) replay.Headers.TryAddWithoutValidation(h.Key, h.Value);
                            res.Content.Dispose();
                            typeof(HttpResponseMessage).GetProperty("Content")!.SetValue(res, replay);
                        }
                    }

                    res.EnsureSuccessStatusCode();

                    var expected = res.Content.Headers.ContentLength ?? -1;
                    long written = 0;
                    string tempPath = path + $".part.{_runId}.{Environment.CurrentManagedThreadId}.{DateTime.UtcNow.Ticks:x}";

                    await using (var fs = new FileStream(
                        tempPath,
                        FileMode.Create,
                        FileAccess.Write,
                        FileShare.None,
                        bufferSize: 128 * 1024,
                        options: FileOptions.Asynchronous | FileOptions.WriteThrough))
                    {
                        using var src = await res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                        byte[] buf = System.Buffers.ArrayPool<byte>.Shared.Rent(256 * 1024);
                        try
                        {
                            int zeroReads = 0;
                            const int ZERO_LIMIT = 3;
                            var deadline = DateTime.UtcNow.AddSeconds(60);
                            bool __firstChunk = true;
                            bool __isMp4 =
                                path.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) ||
                                path.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase) ||
                                path.EndsWith(".mov", StringComparison.OrdinalIgnoreCase);

                            while (true)
                            {
                                ct.ThrowIfCancellationRequested();
                                if (DateTime.UtcNow > deadline)
                                    throw new TimeoutException("stream stalled (>60s)");

                                int n = await src.ReadAsync(buf.AsMemory(0, buf.Length), ct).ConfigureAwait(false);

                                if (n == 0)
                                {
                                    if (expected >= 0 && written >= expected) break;
                                    if (++zeroReads >= ZERO_LIMIT)
                                        throw new IOException("premature end of response stream");
                                    await Task.Delay(120, ct).ConfigureAwait(false);
                                    continue;
                                }

                                zeroReads = 0;
                                await fs.WriteAsync(buf.AsMemory(0, n), ct).ConfigureAwait(false);
                                written += n;

                                if (expected >= 0 && written == expected) break;
                                if (expected >= 0 && written > expected)
                                    throw new IOException($"wrote more than Content-Length ({written} > {expected})");
                            }

                            await fs.FlushAsync(ct).ConfigureAwait(false);
                        }
                        finally
                        {
                            System.Buffers.ArrayPool<byte>.Shared.Return(buf);
                        }
                    }

                    if (expected >= 0 && written != expected)
                        throw new IOException($"short write: {written} / {expected} bytes");

                    try { File.Move(tempPath, path, overwrite: true); }
                    catch
                    {
                        try
                        {
                            TraceAnyWrite(path, -1, "GEN.COPY.COMMIT");
                            File.Copy(tempPath, path, overwrite: true);
                            File.Delete(tempPath);
                        }
                        catch { }

                    }

                    try { Log($"[SS.DONE] saved OK → {path}"); } catch { }
                    try { if (!string.IsNullOrEmpty(_qKey)) _inflightQ.TryRemove(_qKey, out _); } catch { }

                    try
                    {
                        var h = res.RequestMessage?.RequestUri?.Host;
                        if (!string.IsNullOrEmpty(h))
                            lock (_noRangeHosts) _noRangeHosts.Remove(h);
                    }
                    catch { }
                }
                // --- end robust writer ---




                // 4) Verify length
                var fi2 = new FileInfo(path);
                if (fi2.Length != remoteLen)
                {
                    Log($"[FIXTAIL] Expected {remoteLen} bytes but have {fi2.Length} for {Path.GetFileName(path)}");
                }
                else
                {
                    Log($"[FIXTAIL] Patched tail ({remoteLen - localLen} bytes) → {Path.GetFileName(path)}");
                }
            }
            catch (Exception ex)
            {
                Log($"[FIXTAIL] tail repair failed: {ex.GetType().Name} {ex.Message}");
            }
        }


        private async Task<long> GetRemoteLengthAsync(string url, CancellationToken ct)
        {
            try
            {
                // Try HEAD first
                using (var head = new HttpRequestMessage(HttpMethod.Head, url))
                using (var hr = await _http.SendAsync(head, HttpCompletionOption.ResponseHeadersRead, ct))
                {
                    if (hr.IsSuccessStatusCode && hr.Content.Headers.ContentLength.HasValue)
                        return hr.Content.Headers.ContentLength.Value;
                }
            }
            catch { /* some hosts reject HEAD */ }

            try
            {
                // Fallback: GET 0-0 to read Content-Range: bytes 0-0/1234567
                using var probe = new HttpRequestMessage(HttpMethod.Get, url);
                probe.Headers.Range = new RangeHeaderValue(0, 0);
                using var pr = await _http.SendAsync(probe, HttpCompletionOption.ResponseHeadersRead, ct);
                if (pr.StatusCode == HttpStatusCode.PartialContent)
                {
                    var cr = pr.Content.Headers.ContentRange;
                    if (cr != null && cr.HasLength) return cr.Length.Value;
                }
            }
            catch { }

            return -1;
        }

        // lightweight GET + warmup to ensure edge can deliver bytes
        private async Task<(bool ok, int ttfbMs)> TtfbWarmupGateAsync(Uri url, string? referer, CancellationToken ct)
        {
            const int TtfbTimeoutMs = 5_000; // hard cap for "no first byte" (ms)
            const int WarmupDeadlineMs = 8_000; // overall warmup window (ms)
            const int WarmupBytesMin = 64 * 1024; // require at least 64 KiB streamed

            var sw = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, url);

                if (Uri.TryCreate(referer, UriKind.Absolute, out var ref1))
                    req.Headers.Referrer = ref1;

                // Small front slice; we only care about liveness + stable stream
                req.Headers.Range = new RangeHeaderValue(0, 1024 * 1024 - 1);

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(WarmupDeadlineMs);

                using var res = await _http
                    .SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token)
                    .ConfigureAwait(false);

                res.EnsureSuccessStatusCode();

                await using var body = await res.Content
                    .ReadAsStreamAsync(cts.Token)
                    .ConfigureAwait(false);

                var buf = new byte[16 * 1024];
                var total = 0;

                while (true)
                {
                    // If we still have 0 bytes and we’ve blown the TTFB window → fail this edge
                    if (total == 0 && sw.ElapsedMilliseconds > TtfbTimeoutMs)
                        return (false, (int)sw.ElapsedMilliseconds);

                    var read = await body.ReadAsync(buf, 0, buf.Length, cts.Token)
                                         .ConfigureAwait(false);
                    if (read <= 0)
                        break;

                    total += read;

                    if (total >= WarmupBytesMin)
                        break; // stream is real and awake

                    if (sw.ElapsedMilliseconds > WarmupDeadlineMs)
                        break;
                }

                var ms = (int)sw.ElapsedMilliseconds;

                if (total <= 0)
                    return (false, ms); // never really started

                return (true, ms);
            }
            catch
            {
                return (false, (int)sw.ElapsedMilliseconds);
            }
        }
        // ---- Edge selector glue ----
        // helpers
        private Uri RewriteHost(Uri u, string host)
            => _edge?.RewriteUriHost(u, host) ?? new UriBuilder(u) { Host = host }.Uri;

        private string? NextEdgeHost(string current)
        {
            var hosts = GetMediaHostsSafe();
            if (hosts.Length == 0) return null;
            var i = Array.FindIndex(hosts, h => string.Equals(h, current, StringComparison.OrdinalIgnoreCase));
            // advance cursor per 200-event; try “next” once
            var next = hosts[(i >= 0 ? i + 1 : _rrCursor + 1) % hosts.Length];
            _rrCursor = (i >= 0 ? i + 1 : _rrCursor + 1) % hosts.Length;
            try { Log($"[RR] cursor={_rrCursor}"); } catch { }

            return next;
        }

        private void StartEdgeSelector(CancellationToken outer)
        {
            // clean any previous run
            try { _edgeCts?.Cancel(); } catch { }
            try { _edge?.Stop(); } catch { }
            try { _edge?.Dispose(); } catch { }

            _edgeCts = CancellationTokenSource.CreateLinkedTokenSource(outer);

            // ensure instance exists (uses your existing _http and Log)
            _edge ??= new CMDownloaderUI.Net.EdgeSelector(
                new CMDownloaderUI.Net.EdgeSelectorOptions(), // || fill with your hosts/options
                _http, // your shared HttpClient
                s => Log("[EDGE] " + s), // logging hook (optional)
                null // request preprocessor (optional)
            );


            _edge.Start(_edgeCts.Token);
            Log($"[EDGE] Host auto-select enabled ({MEDIA_HOST_CANDIDATES.Length} candidates).");
        }
        // Compact one-line telemetry for video verify decisions
        private void LogVidVerifyTelemetry(string stage, string path, long sizeBytes, bool hasMoovOrMoof, bool playableQuick, string reason = "")
        {
            try
            {
                // Only log telemetry when it indicates a problem (otherwise it's diag noise)
                if (hasMoovOrMoof && playableQuick && string.IsNullOrEmpty(reason)) return;

                Log($"[TEL.VID] {stage} size={sizeBytes:N0} moov/moof={(hasMoovOrMoof ? 1 : 0)} playable={(playableQuick ? 1 : 0)}{(string.IsNullOrEmpty(reason) ? "" : $" reason={reason}")} path={Path.GetFileName(path)}");
            }
            catch { }
        }
        // basic file-system trace for video files
        private void TraceVidFs(string op, string path, long lenBytes, string? note = null)
        {
            try
            {
                if (string.IsNullOrEmpty(path)) return;

                string ext = System.IO.Path.GetExtension(path)?.ToLowerInvariant() ?? "";
                if (ext != ".mp4" && ext != ".m4v" && ext != ".mov") return;

                // suppress normal “success” noise; keep only interesting events
                if (string.Equals(op, "final-ok", StringComparison.OrdinalIgnoreCase)) return;

                string name = System.IO.Path.GetFileName(path);
                string msg = $"[VID.FS] op={op} len={lenBytes:N0} path={name}";
                if (!string.IsNullOrEmpty(note))
                    msg += $" note={note}";

                Log(msg);
            }
            catch { }
        }
        // Traces any file write attempt (diagnostic only)
        private void TraceAnyWrite(string path, long plannedLen, string note)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path)) return;
                System.Threading.Interlocked.Increment(ref _fsWriteTotal);

                string __n = note ?? "";

                // suppress steady-state create chatter (these often have plannedLen=-1)
                if (__n.StartsWith("SS.CREATE", StringComparison.OrdinalIgnoreCase) ||
                    __n.StartsWith("SEG.CREATE", StringComparison.OrdinalIgnoreCase) ||
                    __n.StartsWith("SIDE.OK", StringComparison.OrdinalIgnoreCase))
                {
                    System.Threading.Interlocked.Increment(ref _fsWriteSupp);
                    return;
                }

                // “interesting” if note indicates trouble/state change (do NOT trigger on plannedLen<=0)
                bool __interesting =
                    __n.IndexOf("FAIL", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    __n.IndexOf("ERR", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    __n.IndexOf("MISMATCH", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    __n.IndexOf("QUAR", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    __n.IndexOf("VERIFY", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    __n.IndexOf("ACCEPT", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    __n.IndexOf("FINAL", StringComparison.OrdinalIgnoreCase) >= 0;

                if (__interesting)
                {
                    System.Threading.Interlocked.Increment(ref _fsWriteInteresting);
                    Log($"[FS.WRITE] len={plannedLen:N0} path={path} note={note}");
                }
                else
                {
                    System.Threading.Interlocked.Increment(ref _fsWriteSupp);
                }
            }
            catch { }
        }


        private void StopEdgeSelector()
        {
            // take local copies and clear fields to avoid races with StartRunAsync
            var cts = Interlocked.Exchange(ref _edgeCts, null);
            var edge = Interlocked.Exchange(ref _edge, null);

            try { cts?.Cancel(); } catch { }
            try { edge?.Stop(); } catch { }
            try { edge?.Dispose(); } catch { }
            try { cts?.Dispose(); } catch { }

            try { Log("[EDGE] Host auto-select stopped."); } catch { }
        }

        public string? CurrentFolderPath()
        {
            try { return txtFolder?.Text; } catch { return null; }
        }

        // ========================== Global queue workers ========================== //
        async Task WorkerLoop(BlockingCollection<DownloadItem> q, bool isVideo, int workerId, CancellationToken ct)

        {
            var _workerIdLocal = workerId;

            foreach (var it in q.GetConsumingEnumerable(ct))
            {
                // — drop any queued item during graceful stop (IMG/ZIP/VID)
                if (_stopRequested && _stopMode == StopMode.Graceful)
                {
                    if (_stopImmediate)
                    {
                        FlushQueuesOnStop(); // clears other queues + UI list
                        break; // exit worker loop
                    }
                    Log("[STOP] Dropping queued item during graceful stop.");
                    continue;
                }
                // soft pause from WebUI — halt before taking inflight slot
                while (s_PauseRequested && !s_StopRequested && !ct.IsCancellationRequested)
                {
                    try { await Task.Delay(200, ct).ConfigureAwait(false); }
                    catch { break; }
                }

                try
                {
                    while (true)
                    {
                        var lim = CurrentLimits();
                        if (!isVideo)
                        {
                            if (System.Threading.Interlocked.CompareExchange(ref _inflightNV, 0, 0) < lim.nv)
                            { System.Threading.Interlocked.Increment(ref _inflightNV); break; }
                        }
                        else
                        {
                            if (System.Threading.Interlocked.CompareExchange(ref _inflightVID, 0, 0) < lim.vid)
                            { System.Threading.Interlocked.Increment(ref _inflightVID); break; }
                        }
                        await Task.Delay(50, ct);
                    }

                    await CooldownIfNeededAsync(ct);

                    // DASH: mark current item (use filename-ish fallback)
                    var __disp = System.IO.Path.GetFileName(it.url.LocalPath);
                    try { WebUiStatus.SetCurrent(string.IsNullOrWhiteSpace(__disp) ? it.url.ToString() : __disp); } catch { }

                    {
                        string __edgeHost = null; try { __edgeHost = it.url?.Host; } catch { }
                        if (!string.IsNullOrEmpty(__edgeHost))
                            _activeByHost.AddOrUpdate(__edgeHost, 1, static (_, v) => v + 1);
                        WebUiPublishActiveThrottled(); // NEW

                        try
                        {
                            await DownloadWithNamingAsync(it.url, it.naming, it.idx, it.kind, it.referer, ct, it.matchKey);
                        }
                        finally
                        {
                            if (!string.IsNullOrEmpty(__edgeHost))
                                _activeByHost.AddOrUpdate(__edgeHost, 0, static (_, v) => (v > 1 ? v - 1 : 0));
                            WebUiPublishActiveThrottled(); // NEW
                        }
                    }

                    // try { WebUiStatus.PushRecent(string.IsNullOrWhiteSpace(__disp) ? it.url.ToString() : __disp); } catch { }

                    await JitterAsync(isVideo ? "VID" : (it.kind == "ZIP" ? "ZIP" : "IMG"), ct);
                }
                catch (OperationCanceledException) { break; }
                finally
                {
                    if (!isVideo) System.Threading.Interlocked.Decrement(ref _inflightNV);
                    else System.Threading.Interlocked.Decrement(ref _inflightVID);

                    try { WebUiStatus.SetCurrent(null); } catch { }

                    // Queue = OUTSTANDING (pending + retry + inflight NV+VID)
                    try
                    {
                        int __pending = (_imgQ?.Count ?? 0) + (_vidQ?.Count ?? 0) + _retryQ.Count;
                        int __inflight = System.Threading.Interlocked.CompareExchange(ref _inflightNV, 0, 0)
                                       + System.Threading.Interlocked.CompareExchange(ref _inflightVID, 0, 0);
                        WebUiStatus.SetQueue(__pending + __inflight);
                    }
                    catch { }
                }
            }
        }


        private static void TryDeleteWithRetry(string path)
        {
            if (PathLocks.ContainsKey(path)) return;
            for (int i = 0; i < 3; i++)
            {
                try { System.IO.File.Delete(path); return; }
                catch when (i < 2) { System.Threading.Thread.Sleep(150 * (i + 1)); }
                catch { return; }
            }
        }



        private void CleanStrayPartArtifacts(string root)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(root) || !System.IO.Directory.Exists(root)) return;
                int n = 0;
                foreach (var p in System.IO.Directory.EnumerateFiles(root, "*.mp4.part*", System.IO.SearchOption.AllDirectories))
                    try { System.IO.File.Delete(p); n++; } catch { }
                foreach (var p in System.IO.Directory.EnumerateFiles(root, "*.seg.*", System.IO.SearchOption.AllDirectories))
                    try { System.IO.File.Delete(p); n++; } catch { }
                if (n > 0) Log($"[PART.SWEEP] Removed {n} stray temp segment/part files.");
            }
            catch { }
        }
        // expose Start/Stop for WebUI (UI thread-safe)
        public void StartFromWebUi()
        {
            try
            {
                WebUiStatus.StartRun();
                try { WebUiPublishCooldowns(); } catch { } // NEW — immediate host push

                // kick a hosts snapshot now
                try { _edge?.PublishHostsToWebUi(); } catch { }

                // start periodic host updates (every 15s)
                if (_webUiHostTimer == null)
                {
                    _webUiHostTimer = new System.Windows.Forms.Timer();
                    _webUiHostTimer.Interval = 15000; // 15s
                    _webUiHostTimer.Tick += (s, e) =>
                    {
                        // 1) keep hosts pushed to the WebUI
                        try { _edge?.PublishHostsToWebUi(); } catch { }

                        // 2) HEARTBEAT auto-exit if no tabs pinged recently
                        try
                        {
                            var last = CMDownloaderUI.WebUiHost.LastPingUtc;
                            if (last != DateTime.MinValue &&
                                (DateTime.UtcNow - last) > TimeSpan.FromSeconds(45))
                            {
                                _webUiHostTimer.Stop();

                                // close safely on UI thread
                                if (this.IsHandleCreated)
                                {
                                    this.BeginInvoke(new Action(() =>
                                    {
                                        try { this.Close(); } catch { }
                                    }));
                                }
                                else
                                {
                                    try { this.Close(); } catch { }
                                }
                            }
                        }
                        catch { }
                    };
                }
                _webUiHostTimer.Start();

                this.BeginInvoke(new Action(() => btnStart.PerformClick()));
            }
            catch { }
        }

        public bool CoomerHasSession()
        {
            try
            {
                var ck = _cookieContainer.GetCookies(new Uri("https://coomer.st/"));
                foreach (System.Net.Cookie c in ck)
                {
                    if (string.Equals(c.Name, "session", StringComparison.OrdinalIgnoreCase) &&
                        !string.IsNullOrWhiteSpace(c.Value))
                        return true;
                }
                return false;
            }
            catch { return false; }
        }

        private string CoomerCookieNames()
        {
            try
            {
                var ck = _cookieContainer.GetCookies(new Uri("https://coomer.st/"));
                var names = new List<string>();
                foreach (System.Net.Cookie c in ck)
                {
                    if (!string.IsNullOrWhiteSpace(c?.Name))
                        names.Add(c.Name);
                }
                names.Sort(StringComparer.OrdinalIgnoreCase);
                return string.Join(",", names);
            }
            catch { return ""; }
        }

        // [COOMER.REMEMBER] WebUI entrypoint: set remember + optionally persist on success
        public void SetCoomerRememberFromWebUi(string user, string pass, bool remember)
        {
            try
            {
                _coomerRemember = remember;
                _coomerRememberUser = user ?? "";
                _coomerRememberPass = pass ?? "";

                // Persist preference immediately (password stored encrypted; cleared if remember==false)
                try { SaveUIPrefs(); } catch { }
            }
            catch { }
        }

        public async Task<(bool ok, string message)> CoomerLoginAsync(string user, string pass)
        {
            // single-flight gate
            if (System.Threading.Interlocked.Exchange(ref _coomerLoginInFlight, 1) == 1)
                return (false, "Login already in progress");

            try
            {
                if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(pass))
                    return (false, "Missing username/password");

                // Ensure Playwright objects exist
                if (_pw == null) _pw = await Microsoft.Playwright.Playwright.CreateAsync();
                if (_browser == null) _browser = await _pw.Chromium.LaunchAsync(new BrowserTypeLaunchOptions { Headless = true });
                if (_context == null) _context = await _browser.NewContextAsync();
                if (_page == null) _page = await _context.NewPageAsync();

                // Go to login page
                await _page.GotoAsync(
                    "https://coomer.st/authentication/login?location=%2Fartists",
                    new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded, Timeout = 45_000 }
                );

                // Fill creds
                await _page.FillAsync("input[name='username']", user);
                await _page.FillAsync("input[name='password']", pass);

                // Submit
                await _page.ClickAsync("button[type='submit'], input[type='submit']");
                await _page.WaitForLoadStateAsync(LoadState.NetworkIdle, new PageWaitForLoadStateOptions { Timeout = 45_000 });

                // Sync cookies into HttpClient jar
                await SyncCookiesFromPlaywrightAsync();

                if (!CoomerHasSession())
                {
                    // One retry: sometimes cookies land late or the first submit doesn't stick.
                    try { CMDownloaderUI.LogTap.Append("[COOMER.LOGIN] no session → retry once"); } catch { }

                    try { await Task.Delay(650); } catch { }

                    // First: re-sync once after a short delay (cheap retry)
                    await SyncCookiesFromPlaywrightAsync();

                    if (!CoomerHasSession())
                    {
                        // Second: re-run the submit flow once (bounded retry)
                        try
                        {
                            await _page.GotoAsync(
                            "https://coomer.st/authentication/login?location=%2Fartists",
                            new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded, Timeout = 45_000 }
                        );
                        }
                        catch { }

                        await _page.FillAsync("input[name='username']", user);
                        await _page.FillAsync("input[name='password']", pass);

                        await _page.ClickAsync("button[type='submit'], input[type='submit']");
                        await _page.WaitForLoadStateAsync(LoadState.NetworkIdle, new PageWaitForLoadStateOptions { Timeout = 45_000 });

                        await SyncCookiesFromPlaywrightAsync();
                    }
                }

                if (CoomerHasSession())
                {
                    // [COOMER.REMEMBER] only commit saved creds after verified session
                    if (_coomerRemember)
                    {
                        _coomerRememberUser = user ?? "";
                        _coomerRememberPass = pass ?? "";
                        try { SaveUIPrefs(); } catch { }
                    }
                    else
                    {
                        _coomerRemember = false;
                        _coomerRememberUser = "";
                        _coomerRememberPass = "";
                        try { SaveUIPrefs(); } catch { }
                    }

                    try { CMDownloaderUI.LogTap.Append("[COOMER.LOGIN] OK"); } catch { }
                    return (true, "ok");
                }
                try { CMDownloaderUI.LogTap.Append("[COOMER.LOGIN] missing session cookie: expected=session got=[" + CoomerCookieNames() + "]"); } catch { }

                try { CMDownloaderUI.LogTap.Append("[COOMER.LOGIN] FAIL (no session)"); } catch { }
                return (false, "Login did not yield a session cookie");

            }
            catch (Exception ex)
            {
                try { CMDownloaderUI.LogTap.Append("[COOMER.LOGIN] FAIL (exception)"); } catch { }
                return (false, ex.Message);
            }
            finally
            {
                System.Threading.Interlocked.Exchange(ref _coomerLoginInFlight, 0);
            }
        }





        public void StopFromWebUi()
        {
            try
            {
                WebUiStatus.StopRun(); // <— tell the dashboard run ended
                this.BeginInvoke(new Action(() => btnStop.PerformClick()));
            }
            catch { }
        }
        // second-stop from WebUI = immediate cancel
        public void HardStopFromWebUi()
        {
            try
            {
                _stopImmediate = true; // workers will flush & bail
                s_StopRequested = true; // global stop gate
                try { _cts?.Cancel(); } catch { } // kill active awaits
                try { FlushQueuesOnStop(); } catch { } // clear queued items now
                try { WebUiStatus.StopRun(); } catch { }
                this.BeginInvoke(new Action(() => btnStop.PerformClick()));
                try { Log("[STOP] HARD stop requested from WebUI."); } catch { }
            }
            catch { }
        }

        public void EnqueueUrlFromWeb(string url)
        {
            try
            {
                this.BeginInvoke(new Action(() =>
                {
                    // reflect in the desktop UI, do NOT start the run
                    txtUrl.Text = url?.Trim() ?? string.Empty;
                    try { txtUrl.SelectionStart = txtUrl.TextLength; txtUrl.SelectionLength = 0; } catch { }

                    // optional local log line so you see it land
                    try { Log($"[WEBUI] URL set → {url}"); } catch { }
                }));
            }
            catch { }
        }




        public void SetFolderFromWeb(string folder)
        {
            try
            {
                this.BeginInvoke(new Action(() =>
                {
                    txtFolder.Text = folder?.Trim();
                    btnBrowse.PerformClick(); // same as clicking browse/apply
                }));
            }
            catch { }
        }






        private (int nv, int vid) CurrentLimits()
        {
            string s = _healthState;

            // Clamp to UI maxima / global caps
            int nvMax = Math.Max(1, Math.Min(_maxNV, MAX_IMG_CONC));
            int vidMax = Math.Max(1, Math.Min(_maxVID, MAX_VID_CONC));

            if (s == "COOLDOWN")
                return (1, 1);

            if (s == "WARN")
            {
                // Ease off, but keep some parallelism and at least one video lane.
                int nvWarn = Math.Max(1, (int)Math.Ceiling(nvMax * 0.6)); // ~60% of NV
                int vidWarn = Math.Max(1, vidMax - 1); // drop one video lane
                return (nvWarn, vidWarn);
            }

            return (nvMax, vidMax);
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        private void LogSegPlan(string label, long sizeBytes, int poolAvail, int activeVids, int chosen)
        {
            try
            {
                // DIAG ONLY — suppress for user logs
                // double mb = sizeBytes / (1024d * 1024d);
                // Log($"[SEG PLAN] {label}: size={mb:0.0} MB pool={poolAvail} activeVids={activeVids} → x{chosen}");
            }
            catch { /* best-effort logging */ }
        }


        // ========================== Collectors & Helpers ======================= //
        private static async Task<List<string>> CollectImagesAsync(IPage page)
        {
            // anchors that look like images (null-safe + balanced JS)
            var ahrefs = (await page.EvaluateAsync<string[]>(
                @"() => {
            const out = new Set();
            const add = u => { try { if (!u) return; out.add(new URL(u, location.href).href); } catch {} };
            document.querySelectorAll('a[href]').forEach(a => {
                const h = a.getAttribute('href') || '';
                if (/\.(?:jpe?g|png|webp|gif|bmp)(?:\?|#|$)/i.test(h) || h.includes('/data/')) add(h);
            });
            return [...out];
        }"
            )) ?? Array.Empty<string>();

            // images (src / data-src), null-safe
            var imgs = (await page.EvaluateAsync<string[]>(
                @"() => {
            const out = new Set();
            const add = u => { try { if (!u) return; out.add(new URL(u, location.href).href); } catch {} };
            document.querySelectorAll('img').forEach(img => {
                const u = img.getAttribute('src') || img.getAttribute('data-src') || '';
                if (u) add(u);
            });
            return [...out];
        }"
            )) ?? Array.Empty<string>();

            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var u in ahrefs) if (!string.IsNullOrWhiteSpace(u) && LooksLikeImage(u)) set.Add(u);
            foreach (var u in imgs) if (!string.IsNullOrWhiteSpace(u) && LooksLikeImage(u)) set.Add(u);
            return set.ToList();
        }


        private async Task<List<string>> CollectByExtensionsAsync(IPage page, string[] exts)
        {
            var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var anchors = await page.EvaluateAsync<string[]>(
                "() => [...new Set([...document.querySelectorAll('a')].map(a=>a.href))]") ?? Array.Empty<string>();

            foreach (var a in anchors)
            {
                if (string.IsNullOrWhiteSpace(a)) continue;
                var low = a.ToLowerInvariant();
                if (_adblockOn && _adblockRules.Count > 0 &&
                    (IsBlockedByAdblock(low) || low.Contains("/ads/") || low.Contains("/promo/")))
                    continue;

                var cut = a;
                var q = cut.IndexOf('?'); var h = cut.IndexOf('#');
                var ix = (q >= 0 && h >= 0) ? Math.Min(q, h) : (q >= 0 ? q : h);
                if (ix >= 0) cut = cut.Substring(0, ix);

                if (exts.Any(e => cut.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                    urls.Add(a);
            }

            var vids = await page.EvaluateAsync<string[]>(
                "() => [...new Set([...document.querySelectorAll('video, source')].map(v=>v.src).filter(Boolean))]") ?? Array.Empty<string>();

            foreach (var v in vids)
            {
                if (string.IsNullOrWhiteSpace(v)) continue;
                var low = v.ToLowerInvariant();
                if (_adblockOn && _adblockRules.Count > 0 &&
                    (IsBlockedByAdblock(low) || low.Contains("/ads/") || low.Contains("/promo/")))
                    continue;

                var cut = v;
                var q = cut.IndexOf('?'); var h = cut.IndexOf('#');
                var ix = (q >= 0 && h >= 0) ? Math.Min(q, h) : (q >= 0 ? q : h);
                if (ix >= 0) cut = cut.Substring(0, ix);

                if (exts.Any(e => cut.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                    urls.Add(v);
            }

            return urls.ToList();
        }

        // Collect only links from anchors within a container and filter by extensions.
        private async Task<List<string>> CollectByExtensionsFromSelectorAsync(IPage page, string selector, string[] exts)
        {
            var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string[] raw;
            try
            {
                raw = await page.Locator(selector).EvaluateAllAsync<string[]>(
                @"els => {
            const out = new Set();
            for (const el of els) {
                const u = el.href || el.src || el.getAttribute('href') || el.getAttribute('src') || '';
                if (u) out.add(u);
            }
            return [...out];
        }");
            }
            catch { raw = Array.Empty<string>(); }

            foreach (var u in raw)
            {
                if (string.IsNullOrWhiteSpace(u)) continue;

                var low = u.ToLowerInvariant();
                if (_adblockOn && _adblockRules.Count > 0 &&
                    (IsBlockedByAdblock(low) || low.Contains("/ads/") || low.Contains("/promo/")))
                    continue;

                // Strip ?query/#hash for extension match
                var cut = u;
                var q = cut.IndexOf('?'); var h = cut.IndexOf('#');
                var ix = (q >= 0 && h >= 0) ? Math.Min(q, h) : (q >= 0 ? q : h);
                if (ix >= 0) cut = cut.Substring(0, ix);

                if (exts.Any(ext => cut.EndsWith(ext, StringComparison.OrdinalIgnoreCase)))
                    urls.Add(u);
            }
            return urls.ToList();
        }


        // Collect <video>/<source> srcs within a container and filter by extensions.



        private static bool LooksLikeImage(string url) { var u = url.ToLowerInvariant(); return u.Contains(".jpg") || u.Contains(".jpeg") || u.Contains(".png") || u.Contains(".webp") || u.Contains(".gif") || u.Contains(".bmp"); }

        private async Task<List<Uri>> SelectBestImagesAsync(List<string> imgUrls, CancellationToken ct)
        {
            var groups = imgUrls.GroupBy(ImageKey, StringComparer.OrdinalIgnoreCase);
            var best = new List<Uri>();
            var tasks = new List<Task>();

            foreach (var g in groups)
            {
                tasks.Add(Task.Run(async () =>
                {
                    ct.ThrowIfCancellationRequested();
                    var cands = g.Select(s => new Uri(s)).ToList();
                    var top = cands.Select(u => new { Url = u, Score = ImageHeuristicScore(u) })
                                   .OrderByDescending(x => x.Score)
                                   .Take(3)
                                   .Select(x => x.Url)
                                   .ToList();

                    var probeTasks = top.Select(async u => new { Url = u, Size = await TryProbeSizeAsync(u, ct) });
                    var results = await Task.WhenAll(probeTasks).ConfigureAwait(false);

                    var pick = results.Where(r => r.Size.HasValue && r.Size.Value > 0)
                                      .OrderByDescending(r => r.Size.Value)
                                      .Select(r => r.Url)
                                      .FirstOrDefault()
                               ?? top.FirstOrDefault()
                               ?? cands.First();

                    lock (best) best.Add(pick);
                }));
            }


            await Task.WhenAll(tasks).ConfigureAwait(false);
            return best;
        }



        private static string ImageKey(string url)
        {
            try
            {
                var u = new Uri(url);
                var name = Path.GetFileNameWithoutExtension(u.LocalPath);
                name = RX_IMG_TOKENS.Replace(name, "");
                name = Regex.Replace(name, @"[-_.]+", "-").Trim('-');
                if (string.IsNullOrEmpty(name)) name = Path.GetFileNameWithoutExtension(u.LocalPath);
                return name;
            }
            catch
            {
                var name = Path.GetFileNameWithoutExtension(url);
                name = RX_IMG_TOKENS.Replace(name, "");
                name = Regex.Replace(name, @"[-_.]+", "-").Trim('-');
                return string.IsNullOrEmpty(name) ? "img" : name;
            }
        }

        private static int ImageHeuristicScore(Uri u) { var s = u.ToString().ToLowerInvariant(); int score = 0; if (s.Contains("/data/") || s.Contains("download")) score += 5; if (s.EndsWith(".jpg") || s.EndsWith(".jpeg") || s.EndsWith(".png")) score += 2; if (s.EndsWith(".webp")) score -= 1; if (s.Contains("thumbnail") || s.Contains("thumb") || s.Contains("preview")) score -= 4; return score; }

        private async Task<List<Uri>> SelectBestVideosAsync(
        List<string> videoUrls,
        CancellationToken ct,
        HashSet<string>? directVidSet = null)

        {
            var groups = videoUrls
                .Select(u => new Uri(u))
                .GroupBy(u => VideoKeyFromUrl(u), StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

            var result = new List<Uri>();
            const long __MIN_VIDEO_BYTES = MIN_VIDEO_BYTES;
            bool __IsDirect(Uri u) =>
            directVidSet != null &&
            (directVidSet.Contains(u.OriginalString) ||
             directVidSet.Contains(u.AbsoluteUri) ||
             directVidSet.Contains(u.ToString()));



            // Filter obvious overlay / promo / preview variants
            static bool __IsTrash(Uri u)
            {
                var s = u.ToString().ToLowerInvariant();
                return s.Contains("/ol_") || s.Contains("overlay") || s.Contains("promo")
                    || s.Contains("teaser") || s.Contains("preview") || s.Contains("_thumb")
                    || s.Contains("autoplay=1") || s.Contains("type=promo");
            }

            // For Coomer, let borderline sizes "settle" before we trust them
            async Task<long?> __HydrateSizeAsync(Uri u, CancellationToken token)
            {
                var first = await TryProbeSizeAsync(u, token).ConfigureAwait(false);
                if (!first.HasValue) return first;

                long len = first.Value;
                var host = u.Host ?? string.Empty;
                bool isCoomer = host.IndexOf("coomer.st", StringComparison.OrdinalIgnoreCase) >= 0;

                const long SUSPICIOUS_LOW = 256 * 1024; // 0.25 MiB
                const long SUSPICIOUS_HIGH = 8L * 1024 * 1024; // 8 MiB

                // Non-Coomer or clearly tiny/clearly large → trust first probe
                if (!isCoomer || len <= SUSPICIOUS_LOW || len >= SUSPICIOUS_HIGH)
                    return len;

                long maxSize = len;
                int[] delaysMs = { 500, 1000, 2000, 4000, 8000 }; // ~15.5s total

                foreach (var d in delaysMs)
                {
                    token.ThrowIfCancellationRequested();

                    try
                    {
                        var probe = await TryProbeSizeAsync(u, token).ConfigureAwait(false);
                        if (probe.HasValue && probe.Value > 0 && probe.Value > maxSize)
                            maxSize = probe.Value;
                    }
                    catch
                    {
                        // best-effort; keep previous maxSize
                    }

                    try { await Task.Delay(d, token).ConfigureAwait(false); }
                    catch (TaskCanceledException) { throw; }
                }

                if (ShouldLogVideoLines())
                {
                    double firstMb = len / (1024.0 * 1024.0);
                    double maxMb = maxSize / (1024.0 * 1024.0);

                    if (maxSize != len)
                    {
                        Log($"[SIZE.HYDRATE] coomer {Path.GetFileName(u.LocalPath)} {firstMb:0.0}→{maxMb:0.0} MB");
                    }
                    else if (maxSize < __MIN_VIDEO_BYTES)
                    {
                        Log($"[SIZE.HYDRATE.TINY] coomer {Path.GetFileName(u.LocalPath)} ~{maxMb:0.0} MB");
                    }
                }

                return maxSize;
            }

            foreach (var kv in groups)
            {
                ct.ThrowIfCancellationRequested();
                var key = kv.Key; var candidates = kv.Value;
                var nonWebm = candidates.Where(u => !u.LocalPath.EndsWith(".webm", StringComparison.OrdinalIgnoreCase)).ToList(); if (nonWebm.Count > 0) candidates = nonWebm;

                // filter out overlay/promo/preview URLs and tiny videos locally //
                candidates = candidates.Where(u => __IsDirect(u) || !__IsTrash(u)).ToList();
                if (candidates.Count == 0) { if (ShouldLogVideoLines()) Log("[VIDEO] all candidates filtered (trash urls)"); continue; }

                var sized = new List<Uri>();
                foreach (var u in candidates)
                {
                    var sz = await __HydrateSizeAsync(u, ct).ConfigureAwait(false);
                    if (__IsDirect(u))
                    {
                        // direct vids are always legit even if small OR size-probe failed
                        if (!sz.HasValue || sz.Value > 0) sized.Add(u);
                    }

                    else
                    {
                        if (sz.HasValue && sz.Value >= __MIN_VIDEO_BYTES) sized.Add(u);
                    }

                }
                if (sized.Count == 0) { if (ShouldLogVideoLines()) Log("[VIDEO] all candidates < min-bytes"); continue; }
                candidates = sized;


                if (_videoBestChoice.TryGetValue(key, out var already))
                {
                    if (ShouldLogVideoLines()) Log($"[VIDEO] duplicate skipped, reuse {Path.GetFileName(already.LocalPath)}");
                    result.Add(already);
                    continue;
                }
                var chosen = await ChooseBestVideoAsync(candidates, ct);
                _videoBestChoice[key] = chosen; result.Add(chosen);
            }
            return result;
        }



        private static (int Score, string Reason) QualityHintScore(Uri u)
        {
            string s = u.ToString().ToLowerInvariant();
            string path = u.AbsolutePath.ToLowerInvariant();
            int score = 0;
            var why = new List<string>();

            // container preference (tweak weights to taste)
            if (path.EndsWith(".m4v")) { score += 3; why.Add("+m4v"); }
            else if (path.EndsWith(".mp4")) { score += 2; why.Add("+mp4"); }

            if (s.Contains("source")) { score += 5; why.Add("+source"); }

            // resolution hints (also catches "1080p", "1080")
            var m = System.Text.RegularExpressions.Regex.Match(s, @"(?<h>2160|1440|1080|720|480|360)p?");
            if (m.Success)
            {
                int h = int.Parse(m.Groups["h"].Value);
                score += h switch { 2160 => 6, 1440 => 5, 1080 => 4, 720 => 3, 480 => 2, 360 => 1, _ => 0 };
                why.Add($"+{h}p");
            }
            var file = System.IO.Path.GetFileName(path);
            if (file.StartsWith("ol_", StringComparison.OrdinalIgnoreCase) && file.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase))
            { score -= 2; why.Add("-ol"); }

            return (score, string.Join(" ", why));
        }


        private async Task<Uri> ChooseBestVideoAsync(IEnumerable<Uri> urls, CancellationToken ct)
        {
            var list = urls.Distinct()
                           .Select(u => { var qs = QualityHintScore(u); return new { Url = u, qs.Score, qs.Reason }; })
                           .OrderByDescending(x => x.Score)
                           .ToList();

            if (list.Count == 0) throw new InvalidOperationException("No video URLs provided.");

            var top = list.Take(3).ToList();


            // Probe sizes in parallel for the top candidates
            var probes = await Task.WhenAll(top.Select(async c => new
            {
                c.Url,
                c.Score,
                c.Reason,
                Size = await TryProbeSizeAsync(c.Url, ct) // HEAD then Range fallback
            })).ConfigureAwait(false);

            // Size-probe gate: need ≥2 successes OR one big enough (≥ ~9 MB)
            var ok = probes.Where(p => p.Size.HasValue && p.Size.Value > 0)
                           .OrderByDescending(p => p.Size!.Value)
                           .ToList();
            int okCount = ok.Count;
            const long SIZE_FLOOR_BYTES = 9L * 1024 * 1024; // ≈9 MB //
            var bestBySize = (okCount >= 2 || (okCount == 1 &&
                               ok[0].Size!.Value >= SIZE_FLOOR_BYTES)) ? ok[0] : null;

            if (bestBySize != null)
            {
                var mb = bestBySize.Size!.Value / (1024d * 1024d);

                // DIAG ONLY — silence for user logs
                // Log($"[VIDEO] pick={Path.GetFileName(bestBySize.Url.LocalPath)} size={mb:0.0} MB reason={bestBySize.Reason}");

                return bestBySize.Url;
            }




            // Fallback: take the highest-scoring URL (original behavior)
            var chosen = list.First();

            // DIAG ONLY — silence for user logs
            // Log($"[VIDEO] pick-fallback={Path.GetFileName(chosen.Url.LocalPath)} score={chosen.Score} reason={chosen.Reason}");

            return chosen.Url;

        }
        private static int? TryStatusCodeFromException(Exception ex)
        {
            try
            {
                if (ex is HttpRequestException hre)
                {
                    // HttpStatusCode? → int?
                    return hre.StatusCode.HasValue ? (int)hre.StatusCode.Value : null;
                }
            }
            catch { }
            return null;
        }



        private async Task<long?> TryProbeSizeAsync(Uri url, CancellationToken ct)
        {
            try
            {
                // HEAD first ---------------------------------------------------------
                using (var head = new HttpRequestMessage(HttpMethod.Head, url))
                {
                    head.Version = HttpVersion.Version11;
                    head.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
                    var __ref = new Uri(url.GetLeftPart(UriPartial.Authority) + "/");
                    head.Headers.Referrer = __ref;
                    head.Headers.TryAddWithoutValidation(
                        "Accept", "video/*,image/*,application/octet-stream;q=0.8,*/*;q=0.5");

                    using var res = await _http.SendAsync(
                        head, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

                    if (res.IsSuccessStatusCode &&
                        res.Content?.Headers?.ContentLength is long len && len > 0)
                        return len;
                }




                // Range 0–0 to force Content-Range (bytes 0-0/total) -----------------
                using var get = new HttpRequestMessage(HttpMethod.Get, url);
                get.Version = HttpVersion.Version11;
                get.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
                var __ref2 = new Uri(url.GetLeftPart(UriPartial.Authority) + "/");
                get.Headers.Referrer = __ref2;
                get.Headers.TryAddWithoutValidation("Accept",
                    "video/*,image/*,application/octet-stream;q=0.8,*/*;q=0.5");
                get.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 0);
                using var res2 = await _http.SendAsync(get, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                if (res2.Headers.TryGetValues("Content-Range", out var crVals))
                {
                    var cr = crVals.FirstOrDefault();
                    if (!string.IsNullOrEmpty(cr))
                    {
                        var slash = cr.LastIndexOf('/');
                        if (slash > 0 && long.TryParse(cr[(slash + 1)..], out var total)) return (total > 0) ? total : (long?)null;
                    }
                }
                return null;
            }
            catch { return null; }
        }



        private static string VideoKeyFromUrl(Uri url) { var seg = Path.GetFileName(url.LocalPath); seg = Regex.Replace(seg, @"(?i)(1080|720|480|360|source|hd|sd)", ""); seg = Regex.Replace(seg, @"[-_.]+", "-"); seg = seg.Trim('-'); return string.IsNullOrEmpty(seg) ? url.Host : seg; }

        // extract numeric post ID from a Coomer/Fansly post URL
        private static string? ExtractPostIdFromUrlLoose(string? url)
        {
            if (string.IsNullOrWhiteSpace(url)) return null;
            try
            {
                var m = System.Text.RegularExpressions.Regex.Match(url, @"/post/(\d+)");
                return m.Success ? m.Groups[1].Value : null;
            }
            catch
            {
                return null;
            }
        }

        // per-asset tracking: per-post counts + cross-post dupes by matchKey
        private void TrackAssetForPost(string? referer, string assetKind, string? matchKey, string finalPath)
        {
            try
            {
                var postId = ExtractPostIdFromUrlLoose(referer);
                if (string.IsNullOrEmpty(postId))
                    return;

                bool isVid = string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase);

                bool counted = false;

                if (!string.IsNullOrEmpty(matchKey))
                {
                    var key = matchKey!;
                    var set = _assetPostIds.GetOrAdd(
                        key,
                        _ => new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase));

                    bool isNewForPost;
                    lock (set)
                    {
                        // Only count once per (assetKey, postId)
                        isNewForPost = set.Add(postId);
                    }

                    if (isNewForPost)
                    {
                        counted = true;
                    }

                    // Remember a sample filename for logging dupes
                    var name = System.IO.Path.GetFileName(finalPath);
                    if (!string.IsNullOrEmpty(name))
                    {
                        _assetSampleNames.TryAdd(key, name);
                    }
                }
                else
                {
                    // No matchKey → we can’t dedupe logically, but still count
                    counted = true;
                }

                if (counted)
                {
                    _postAssetCounts.AddOrUpdate(
                        postId,
                        isVid ? (0, 1) : (1, 0),
                        (id, prev) => isVid
                            ? (prev.Item1, prev.Item2 + 1)
                            : (prev.Item1 + 1, prev.Item2));
                }
            }
            catch
            {
                // best-effort only; don’t break the run
            }
        }
        // ========================== Download + Progress ======================== //
        // HTTP-only URL refresh for tiny images (no Playwright/page access)
        private async Task<Uri?> RefreshAssetUrlAsync_HTTP(
            Uri remoteUrl, string referer, string? matchKey, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();

            // Prefer rotating to a fresh edge host; fallback to same host with cache-buster.
            Uri candidate = remoteUrl;
            try
            {
                if (!NATURAL_URL_ONLY && (remoteUrl.AbsolutePath.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) || remoteUrl.AbsolutePath.EndsWith(".mov", StringComparison.OrdinalIgnoreCase) || remoteUrl.AbsolutePath.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase)) && _edge is { } es)
                {
                    var chosen = es.ResolveHostForNewDownload();
                    if (!string.IsNullOrEmpty(chosen))
                    {
                        // Skip hosts banned for segmented this run (or known 200-on-Range); hop until clean.
                        int __ssFailCountLocal = 0;
                        for (int guard = 0; guard < 2 && _noRangeHosts.Contains(chosen); guard++)
                        {
                            try { Log($"[HOST.SKIP] {chosen} banned for Range — hop"); } catch { }

                            // On the second SS failure for this file, do NOT rotate once; retry on the same host.
                            if ((++__ssFailCountLocal) == 2)
                            {
                                try { Log("[SS] second fail — not rotating host"); } catch { }
                                break; // keep current host this attempt
                            }

                            es.HopNext();
                            chosen = es.ResolveHostForNewDownload();
                            if (string.IsNullOrEmpty(chosen)) break;
                        }

                        if (!string.IsNullOrEmpty(chosen))
                        {
                            var alt = es.RewriteUriHost(remoteUrl, chosen);
                            if (!string.Equals(alt.Host, remoteUrl.Host, StringComparison.OrdinalIgnoreCase))
                                candidate = alt;
                        }

                    }

                }
            }
            catch { /* non-fatal */ }

            // Add a cache-busting token to avoid stale CDN previews.
            var s = candidate.ToString();
            var token = DateTime.UtcNow.Ticks.ToString("x");
            var uri = new Uri(s + (s.Contains("?") ? "&" : "?") + "r=" + token);

            // No Playwright here; caller will reattempt the download with this URI.
            await Task.Yield();
            return uri;
        }


        private async Task<bool> DownloadWithNamingAsync(Uri remoteUrl, Naming naming, int assetIndex, string assetKind, string? referer, CancellationToken ct, string? matchKey = null)
        {

            bool __preferSegLocal = false; // per-asset nudge, visible to all branches and retries

            bool __segCapHit = false;
            int __segRetryOnce = 1; // [0677.2] allow 1 extra segmented try
            bool __segRetryDueToWriteFail = false;
            bool progressStarted = false;
            // [DONE.HELPER] per-run completion marker
            void MarkDone()
            {
                if (!string.IsNullOrEmpty(matchKey))
                    lock (_completedKeys) _completedKeys.Add(matchKey!);
            }

            // NOTE: CDN on coomer.st appears to cache first 4 MiB (x-cache-range bytes=0-4194303). //
            // Lowered MIN_SEGMENT_BYTES to 12 MiB so segmented mode is used more often. //
            // Default _maxVID raised to 2 to improve throughput on large files. //
            const int BUF = 1 << 22; // 4 MB buffer for better I/O throughput // [0682
                                     // // [ZIP.SKIP] globally disabled
            if (string.Equals(assetKind, "ZIP", StringComparison.OrdinalIgnoreCase))
            {
                try { Log("[ZIP] disabled — skipping"); } catch { }
                return true; // treat as handled so nothing re-queues
            }


            // NOVASTRIKE: route media to the currently-best edge
            if (!NATURAL_URL_ONLY && _edge is { } es)
            {
                var chosen = es.ResolveHostForNewDownload();
                if (!string.IsNullOrEmpty(chosen))
                {
                    // Skip hosts banned for segmented this run (or known 200-on-Range); hop until clean.
                    // If we still only have banned hosts after hopping, don't clear bans.
                    // Just don't rewrite the host; proceed single-stream on the original URL.
                    if (!string.IsNullOrEmpty(chosen))
                    {
                        bool __ban;
                        lock (_noRangeHosts) __ban = _noRangeHosts.Contains(chosen);
                        if (__ban)
                        {
                            try { Log("[RANGE] all edges banned across domain — keeping bans; proceeding without edge hop"); } catch { }
                            chosen = null;
                        }
                    }



                    if (!string.IsNullOrEmpty(chosen))
                    {
                        var before = remoteUrl.Host;
                        remoteUrl = es.RewriteUriHost(remoteUrl, chosen);
                        if (!before.Equals(remoteUrl.Host, StringComparison.OrdinalIgnoreCase))
                            EdgeLogIfMeaningful(remoteUrl.Host); // keep your existing log
                    }
                }

            }


            // Compute target directory based on UseSetFolder only //
            string targetDir = naming.CategoryFolder; // //

            // Include set folder whenever UseSetFolder is true //
            if (naming.UseSetFolder && !string.IsNullOrWhiteSpace(naming.SetFolderName))
            {
                targetDir = Path.Combine(naming.CategoryFolder, naming.SetFolderName!); // //

            }


            // NOVASTRIKE/EDGE: prefer fastest media host for NEW downloads


            // Only apply to non-Fansly; Fansly uses short-set naming above //
            if (naming.UseSetFolder
                && string.Equals(naming.CleanTitle, "untitled", StringComparison.OrdinalIgnoreCase)
                && !(referer?.Contains("/fansly/", StringComparison.OrdinalIgnoreCase) ?? false))
            {
                var __mset = Regex.Match(referer ?? string.Empty, @"/post/(\d+)");
                if (__mset.Success)
                    targetDir = Path.Combine(naming.CategoryFolder, __mset.Groups[1].Value); // //
            } // //



            // … keep the rest (including [0582.1] singleton suffix + [0583] baseName) as you have it //
            string ext = Path.GetExtension(remoteUrl.LocalPath); if (string.IsNullOrWhiteSpace(ext)) ext = ".bin";
            // Suffix for untitled singletons: last 6 of postId //
            string __nameTail = "";
            if (!naming.UseSetFolder && string.Equals(naming.CleanTitle, "untitled", StringComparison.OrdinalIgnoreCase))
            {
                var __m = Regex.Match(referer ?? string.Empty, @"/post/(\d+)");
                if (__m.Success)
                {
                    var __pid = __m.Groups[1].Value;
                    if (!string.IsNullOrEmpty(__pid))
                        __nameTail = "_" + (__pid.Length > 6 ? __pid.Substring(__pid.Length - 6) : __pid);
                }
            }
            string baseName = TruncateFile(
                $"{SanitizeForPath(naming.CleanTitle)}{__nameTail}" +
                ((!naming.UseSetFolder && assetIndex > 1) ? $"_{assetIndex}" : "")
            );



            baseName = TruncateFile(baseName);

            // route by extension (keeps container speed; fixes IMG↔VID collisions)
            if (assetKind == "IMG" && (ext.Equals(".mp4", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".m4v", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".mov", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".webm", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".mkv", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".avi", StringComparison.OrdinalIgnoreCase)))
            { assetKind = "VID"; targetDir = VideoRoot; }

            string finalPath = Path.Combine(targetDir, baseName + ext.ToLowerInvariant());
            // Prefix a 2-digit ordinal for multi-asset posts to avoid IMG↔VID collisions.
            // Only applies when this post is a set and the name isn't already indexed.
            {
                var currExt = Path.GetExtension(finalPath) ?? string.Empty;
                bool currIsVideo =
                    string.Equals(currExt, ".mp4", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(currExt, ".m4v", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(currExt, ".mov", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(currExt, ".webm", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(currExt, ".mkv", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(currExt, ".avi", StringComparison.OrdinalIgnoreCase);

                if (naming.UseSetFolder)
                {
                    var folderNow = Path.GetDirectoryName(finalPath) ?? string.Empty;
                    var fileNoExt = Path.GetFileNameWithoutExtension(finalPath);

                    bool hasIndexPrefix =
                        fileNoExt.Length >= 5 &&
                        char.IsDigit(fileNoExt, 0) && char.IsDigit(fileNoExt, 1) &&
                        fileNoExt[2] == ' ' && fileNoExt[3] == '-' && fileNoExt[4] == ' ';

                    if (!hasIndexPrefix)
                    {
                        // Use the asset's position within the post (1-based). Falls back to 1.
                        int ordinal = assetIndex <= 0 ? 1 : assetIndex;
                        var indexed = $"{ordinal:D2} - {SanitizeForPath(naming.CleanTitle)}{currExt}";
                        finalPath = Path.Combine(folderNow, indexed);
                        System.Threading.Interlocked.Increment(ref _nameIdxTotal);
                        // user mode: no per-asset name/index chatter
                        System.Threading.Interlocked.Increment(ref _nameIdxSupp);

                    }
                }


            }

            // safeguard: video extensions must route to VideoRoot
            if (".mp4 .m4v .mov .avi .mkv .webm".Contains(Path.GetExtension(finalPath).ToLowerInvariant())
                && finalPath.StartsWith(ImagesRoot, StringComparison.OrdinalIgnoreCase))
            {
                finalPath = Path.Combine(VideoRoot, Path.GetFileName(finalPath));
            }

            // skip if target already exists (videos only)
            if (remoteUrl.AbsolutePath.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) || remoteUrl.AbsolutePath.EndsWith(".mov", StringComparison.OrdinalIgnoreCase) || remoteUrl.AbsolutePath.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var __fi = new FileInfo(finalPath);
                    if (__fi.Exists && __fi.Length > 0)
                    {
                        if (ShouldLogVideoLines()) LogSkipExists(finalPath);
                        return true; // method returns Task<bool)
                    }

                }
                catch { /* ignore and proceed */ }
            }

            // another worker is writing this path
            if (!_inProgress.TryAdd(finalPath, 0))
            {
                try { Log($"[WRITER] another worker is writing → {Path.GetFileName(finalPath)}"); } catch { }

                // For videos, don't blindly skip: wait for writer to finish, then validate.
                var __ext = (Path.GetExtension(finalPath) ?? "").ToLowerInvariant();
                bool __isVid = __ext == ".mp4" || __ext == ".m4v" || __ext == ".mov" || __ext == ".mkv" || __ext == ".webm";

                if (__isVid)
                {
                    // Wait up to ~30s for the active writer to clear (success || fail removes key)
                    for (int __i = 0; __i < 60 && _inProgress.ContainsKey(finalPath); __i++)
                        System.Threading.Thread.Sleep(500);

                    // Still writing? let caller retry this item later
                    if (_inProgress.ContainsKey(finalPath))
                        return false; // retry later

                    // Writer finished: validate on-disk file; if bad → quarantine and refetch
                    try
                    {
                        var __fi = new FileInfo(finalPath);
                        if (!__fi.Exists) return false; // nothing written → refetch

                        bool __ok = __fi.Length >= 64; // basic sanity
                        if (__ok)
                        {
                            using var __fs = new FileStream(finalPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                            // header check
                            Span<byte> __head = stackalloc byte[12];
                            int __n = __fs.Read(__head);
                            if (__n < 4)
                            {
                                __ok = false;
                                try { Log("[INTEGRITY] header/tail read too small (__n < 4)"); } catch { }
                            }

                            else if (__ext == ".mp4" || __ext == ".m4v" || __ext == ".mov")
                                __ok = (__n >= 8 && __head[4] == (byte)'f' && __head[5] == (byte)'t' && __head[6] == (byte)'y' && __head[7] == (byte)'p');
                            else
                                __ok = (__head[0] == 0x1A && __head[1] == 0x45 && __head[2] == 0xDF && __head[3] == 0xA3); // EBML

                            // tail readable
                            if (__ok)
                            {
                                long __tail = Math.Min(16L, __fi.Length);
                                __fs.Seek(__fi.Length - __tail, SeekOrigin.Begin);
                                Span<byte> __tailBuf = stackalloc byte[(int)__tail];
                                __ok = __fs.Read(__tailBuf) > 0;
                            }
                            // DASHBOARD: count accepted video
                            if (__ok && (__ext == ".mp4" || __ext == ".m4v" || __ext == ".mov"))
                                try { Status.IncVidsOk(); } catch { }

                            // insist on length≈expected, moov, and mdat
                            if (__ok && (__ext == ".mp4" || __ext == ".m4v" || __ext == ".mov"))
                            {
                                // 1) length sanity against expected (_qLen from quick fingerprint)
                                long expected = _qLen > 0 ? _qLen : -1;
                                if (expected > 0)
                                {
                                    // ≥99% || within 64 KiB
                                    long floor = Math.Max((long)(expected * 0.99), expected - 64 * 1024);
                                    if (__fi.Length < floor)
                                    {
                                        __ok = false;
                                        try { Log($"[INTEGRITY] too small vs expected (have {__fi.Length}, need ≥ {floor})"); } catch { }
                                    }
                                }


                                // 2) require moov and mdat atoms; cheap head/tail scan (≤8 MiB total)
                                if (__ok)
                                {
                                    static bool TryFindAtom(ReadOnlySpan<byte> sp, ReadOnlySpan<byte> fourcc, out uint sizeBE)
                                    {
                                        sizeBE = 0;
                                        int i = 0;
                                        while (true)
                                        {
                                            int rel = sp.Slice(i).IndexOf(fourcc);
                                            if (rel < 0) return false;
                                            int idx = i + rel; // absolute index of type
                                            if (idx >= 4)
                                            {
                                                sizeBE = BinaryPrimitives.ReadUInt32BigEndian(sp.Slice(idx - 4, 4));
                                                if (sizeBE >= 8) return true;
                                            }
                                            i = idx + 1; // continue search
                                        }
                                    }

                                    // require at least one real track (vide/soun) and non-zero duration
                                    static bool SpanHasTrackKind(ReadOnlySpan<byte> sp)
                                    {
                                        int i = 0;
                                        while (true)
                                        {
                                            int rel = sp.Slice(i).IndexOf("hdlr"u8);
                                            if (rel < 0) return false;
                                            int idx = i + rel;
                                            int handlerPos = idx + 4 + 8; // 'hdlr' + version/flags(4) + pre_defined(4)
                                            if (handlerPos + 4 <= sp.Length)
                                            {
                                                var ht = sp.Slice(handlerPos, 4);
                                                if (ht.SequenceEqual("vide"u8) || ht.SequenceEqual("soun"u8)) return true;
                                            }
                                            i = idx + 1;
                                        }
                                    }

                                    static bool TryGetDuration(ReadOnlySpan<byte> sp, out double seconds)
                                    {
                                        seconds = 0;
                                        int i = sp.IndexOf("mvhd"u8); if (i < 0) return false;
                                        int pos = i + 4; if (pos + 4 > sp.Length) return false;
                                        byte ver = sp[pos]; pos += 4; // version+flags
                                        if (ver == 0)
                                        {
                                            pos += 8; if (pos + 8 > sp.Length) return false;
                                            uint timescale = BinaryPrimitives.ReadUInt32BigEndian(sp.Slice(pos, 4)); pos += 4;
                                            uint duration = BinaryPrimitives.ReadUInt32BigEndian(sp.Slice(pos, 4));
                                            if (timescale > 0 && duration > 0) { seconds = (double)duration / timescale; return true; }
                                        }
                                        else if (ver == 1)
                                        {
                                            pos += 16; if (pos + 12 > sp.Length) return false;
                                            uint timescale = BinaryPrimitives.ReadUInt32BigEndian(sp.Slice(pos, 4)); pos += 4;
                                            ulong duration = BinaryPrimitives.ReadUInt64BigEndian(sp.Slice(pos, 8));
                                            if (timescale > 0 && duration > 0) { seconds = (double)duration / timescale; return true; }
                                        }
                                        return false;
                                    }

                                    const int SLAB = 4 * 1024 * 1024;
                                    int headLen = (int)Math.Min(SLAB, __fi.Length);

                                    // HEAD
                                    byte[] bufH = System.Buffers.ArrayPool<byte>.Shared.Rent(headLen);
                                    __fs.Seek(0, SeekOrigin.Begin);
                                    int nH = __fs.Read(bufH, 0, headLen);
                                    var spanH = new ReadOnlySpan<byte>(bufH, 0, nH);

                                    bool hasMoov = TryFindAtom(spanH, "moov"u8, out _);
                                    bool hasMdat = TryFindAtom(spanH, "mdat"u8, out uint mdatSize);
                                    // allow fragmented MP4 (moof + mdat)
                                    bool hasMoof = TryFindAtom(spanH, "moof"u8, out _);

                                    // TAIL (if needed)
                                    byte[]? bufT = null;
                                    ReadOnlySpan<byte> spanT = default;
                                    if ((!hasMoov || !hasMdat) && __fi.Length > headLen)
                                    {
                                        int tailLen = (int)Math.Min(SLAB, __fi.Length - headLen);
                                        bufT = System.Buffers.ArrayPool<byte>.Shared.Rent(tailLen);
                                        __fs.Seek(__fi.Length - tailLen, SeekOrigin.Begin);
                                        int nT = __fs.Read(bufT, 0, tailLen);
                                        spanT = new ReadOnlySpan<byte>(bufT, 0, nT);

                                        if (!hasMoov && TryFindAtom(spanT, "moov"u8, out _)) hasMoov = true;
                                        if (!hasMdat && TryFindAtom(spanT, "mdat"u8, out mdatSize)) hasMdat = true;
                                        if (!hasMoof && TryFindAtom(spanT, "moof"u8, out _)) hasMoof = true;

                                    }
                                    // require at least one real track and a >0 duration
                                    bool __hasTrack = SpanHasTrackKind(spanH) || (spanT.Length != 0 && SpanHasTrackKind(spanT));
                                    if (!__hasTrack) __ok = false;
                                    try { Log("[INTEGRITY] no vide/soun track (missing hdlr)"); } catch { }

                                    double __dur = 0;
                                    bool __gotDur = TryGetDuration(spanH, out __dur) || (spanT.Length != 0 && TryGetDuration(spanT, out __dur));
                                    if (!__gotDur || __dur <= 0.2) __ok = false;
                                    try { Log($"[INTEGRITY] bad duration ({__dur:F3}s)"); } catch { }


                                    // Return buffers
                                    System.Buffers.ArrayPool<byte>.Shared.Return(bufH);
                                    if (bufT != null) System.Buffers.ArrayPool<byte>.Shared.Return(bufT);

                                    if (!((hasMoov || hasMoof) && hasMdat)) __ok = false; // accept fMP4 (moof+mdat) too
                                    try { Log("[INTEGRITY] missing moov/moof + mdat"); } catch { }

                                    // 3) mdat size plausibility + unknown-length fallback (no hard 4 MiB floor)
                                    if (__ok && expected <= 0)
                                    {
                                        // Only reject if BOTH are tiny: file and mdat payload.
                                        // (mdatSize includes the 8-byte header; this guards 600–1500 KB stubs.)
                                        if (__fi.Length < 1_500_000 && mdatSize < 256 * 1024) __ok = false;
                                        try { Log($"[INTEGRITY] tiny stub (len={__fi.Length}, mdat={mdatSize})"); } catch { }

                                    }
                                }
                            }


                        }
                        // — only “finished” if sidecar matches
                        if (__ok && (__ext == ".mp4" || __ext == ".m4v" || __ext == ".mov"))

                        {
                            bool __markerOk = false;
                            try
                            {
                                string __okp = finalPath + ".ok";
                                if (File.Exists(__okp))
                                {
                                    string s = File.ReadAllText(__okp, Encoding.UTF8);
                                    long __len = -1, __exp = -1;
                                    foreach (var kv in s.Split(';'))
                                    {
                                        var p = kv.Split('=', 2);
                                        if (p.Length != 2) continue;
                                        if (p[0].Equals("len", StringComparison.OrdinalIgnoreCase)) long.TryParse(p[1], out __len);
                                        else if (p[0].Equals("expected", StringComparison.OrdinalIgnoreCase)) long.TryParse(p[1], out __exp);
                                    }

                                    long __actual = new FileInfo(finalPath).Length;
                                    if (__len == __actual)
                                    {
                                        if (__exp > 0)
                                        {
                                            long floor = Math.Max((long)(__exp * 0.99), __exp - 64 * 1024);
                                            __markerOk = (__actual >= floor);
                                        }
                                        else __markerOk = true; // expected unknown is fine if len matches
                                    }
                                }
                            }
                            catch { /* treat as not finished */ }

                            if (!__markerOk) __ok = false; // no valid marker → do NOT link to existing
                            try { Log("[DEDUP] writer-finished refused: missing/invalid .ok"); } catch { }

                        }

                        if (__ok)
                        {
                            // For small videos, don't short-circuit on quick-hit; force verify instead
                            if (assetKind == "VID" && _qLen > 0 && _qLen < 4L * 1024 * 1024)
                            {
                                try { Log("[DEDUP] Small video quick-hit → forcing verify (skip early link)"); } catch { }
                                // fall through to normal download + verify (no return)
                            }
                            else
                            {
                                if (ShouldLogVideoLines())
                                {
                                    Log("[DEDUP] Linked to existing (writer finished) → " + finalPath);
                                    try { CMDownloaderUI.WebUiHost.PushRecent(finalPath, delayMs: 1200); } catch { }
                                    // hardlink → credit bytes saved
                                    try
                                    {
                                        long __bs4 = 0;
                                        try { if (_qLen > 0) __bs4 = _qLen; } catch { }
                                        if (__bs4 <= 0)
                                            try
                                            {
                                                if (!string.IsNullOrEmpty(finalPath) && System.IO.File.Exists(finalPath))
                                                    __bs4 = new System.IO.FileInfo(finalPath).Length;
                                            }
                                            catch { }
                                        if (__bs4 > 0) CMDownloaderUI.Status.AddBytesSaved(__bs4);
                                    }
                                    catch { }

                                    LogSkipExists(finalPath);
                                }
                                return true; // accept finished file
                            }
                        }

                        // Not OK → delete and re-fetch (no quarantine folder)
                        try { Log("[INTEGRITY] writer-produced file looks bad — deleting & re-fetching"); } catch { }


                        try
                        {
                            // delete bad file and sidecar; no quarantine
                            try { File.Delete(finalPath); } catch { /* best-effort */ }
                            try
                            {
                                var _m = finalPath + ".ok";
                                if (File.Exists(_m)) File.Delete(_m);
                            }
                            catch { /* best-effort */ }
                        }
                        catch { /* best-effort */ }

                        try { _qBad++; } catch { }

                        return false; // let caller re-download

                    }
                    catch
                    {
                        return false; // any validation error → retry later
                    }
                }

                // Non-video: original behavior (skip)
                return true;
            }
            try
            {

                string tempPath = assetKind == "VID"
                ? finalPath + $".part.{_runId}.{Environment.CurrentManagedThreadId}.{DateTime.UtcNow.Ticks:x}"
                : finalPath; // // [0722] images write directly


                bool smallImage = false;
                bool refreshedOnce = false;


                if (File.Exists(finalPath))
                {
                    if (assetKind == "IMG")
                    {
                        try
                        {
                            long existBytes = new FileInfo(finalPath).Length;
                            // nuke placeholder images by title hint
                            // only treat small "restricted" cards as placeholders
                            var _bn = Path.GetFileNameWithoutExtension(finalPath);
                            bool nameLooksRestricted =
                                _bn.IndexOf("restricted", StringComparison.OrdinalIgnoreCase) >= 0;

                            const long RestrictedPlaceholderMaxBytes = 300_000; // ~300 KB, tune if needed
                            bool looksLikeRestrictedPlaceholder =
                                nameLooksRestricted &&
                                existBytes > 0 &&
                                existBytes <= RestrictedPlaceholderMaxBytes;

                            if (looksLikeRestrictedPlaceholder)
                            {
                                try { File.Delete(finalPath); } catch { }
                                TryDeleteIfEmpty(targetDir);
                                if (ShouldLogImageLines())
                                    Log($"[TRASH] removed small 'restricted' image ({existBytes} bytes)");
                                return true;
                            }


                            // —— tiny-image refresh disabled; container-time selection already picks best ——
                            const bool ENABLE_TINY_REFRESH_IMG = false; // flip to true if you ever want the old behavior

                            if (ENABLE_TINY_REFRESH_IMG && !_tinyOff && existBytes < SMALL_IMAGE_BYTES)
                            {
                                if (ShouldLogImageLines()) Log($"[TINY] existing {existBytes:N0} B — keep (no refresh)");
                                LogSkipExists(finalPath);
                                TryDeleteIfEmpty(targetDir);
                                return true;

                            }


                            else
                            {
                                if (ShouldLogImageLines())
                                {
                                    Log("[DEDUP] Linked to existing → " + finalPath);
                                    try { CMDownloaderUI.WebUiHost.PushRecent(finalPath, delayMs: 1200); } catch { }
                                    // hardlink → credit bytes saved
                                    try
                                    {
                                        long __bs4 = 0;
                                        try { if (_qLen > 0) __bs4 = _qLen; } catch { }
                                        if (__bs4 <= 0)
                                            try
                                            {
                                                if (!string.IsNullOrEmpty(finalPath) && System.IO.File.Exists(finalPath))
                                                    __bs4 = new System.IO.FileInfo(finalPath).Length;
                                            }
                                            catch { }
                                        if (__bs4 > 0) CMDownloaderUI.Status.AddBytesSaved(__bs4);
                                    }
                                    catch { }

                                    LogSkipExists(finalPath);
                                }
                                TryDeleteIfEmpty(targetDir);
                                return true;
                            }
                        }
                        catch
                        {
                            if (ShouldLogImageLines())
                            {
                                Log("[DEDUP] Linked to existing → " + finalPath);
                                try { CMDownloaderUI.WebUiHost.PushRecent(finalPath, delayMs: 1200); } catch { }
                                // hardlink → credit bytes saved
                                try
                                {
                                    long __bs4 = 0;
                                    try { if (_qLen > 0) __bs4 = _qLen; } catch { }
                                    if (__bs4 <= 0)
                                        try
                                        {
                                            if (!string.IsNullOrEmpty(finalPath) && System.IO.File.Exists(finalPath))
                                                __bs4 = new System.IO.FileInfo(finalPath).Length;
                                        }
                                        catch { }
                                    if (__bs4 > 0) CMDownloaderUI.Status.AddBytesSaved(__bs4);
                                }
                                catch { }

                                LogSkipExists(finalPath);
                            }
                            return true;
                        }
                    }
                    else
                    {
                        // Non-image: for videos, verify integrity before skipping
                        string fileExt = Path.GetExtension(finalPath);
                        string extL = fileExt?.ToLowerInvariant() ?? string.Empty;
                        bool isVideoExt = extL == ".mp4" || extL == ".m4v" || extL == ".mov" || extL == ".mkv" || extL == ".webm";

                        if (isVideoExt)
                        {
                            // Verify existing video before skipping; if bad, quarantine and re-fetch.
                            bool __keepExisting = false;

                            try
                            {
                                var __fi = new FileInfo(finalPath);
                                if (__fi.Length >= 24) // basic sanity
                                {
                                    using var __fs = new FileStream(finalPath, FileMode.Open, FileAccess.Read, FileShare.Read);

                                    // Header check (ftyp for MP4/MOV; EBML for MKV/WEBM)
                                    Span<byte> __head = stackalloc byte[12];
                                    int __n = __fs.Read(__head);
                                    bool __headerOk =
                                        ((extL == ".mp4" || extL == ".m4v" || extL == ".mov")
                                            ? (__n >= 8 && __head[4] == (byte)'f' && __head[5] == (byte)'t' && __head[6] == (byte)'y' && __head[7] == (byte)'p')
                                            : (__n >= 4 && __head[0] == 0x1A && __head[1] == 0x45 && __head[2] == 0xDF && __head[3] == 0xA3)); // EBML

                                    if (__headerOk)
                                    {
                                        // Tail readable?
                                        long __tail = Math.Min(16L, __fi.Length);
                                        __fs.Seek(__fi.Length - __tail, SeekOrigin.Begin);
                                        Span<byte> __tailBuf = stackalloc byte[(int)__tail];
                                        bool __tailOk = __fs.Read(__tailBuf) > 0;

                                        if (__tailOk)
                                        {
                                            // Look for 'moov' || 'mdat' in head and tail (up to 256 KiB each)
                                            bool __good = false;
                                            int __win = (int)Math.Min(256 * 1024, Math.Min(__fi.Length, int.MaxValue));
                                            byte[] __buf = System.Buffers.ArrayPool<byte>.Shared.Rent(__win);
                                            try
                                            {
                                                // head scan
                                                __fs.Seek(0, SeekOrigin.Begin);
                                                int __r1 = __fs.Read(__buf, 0, Math.Min(__win, (int)__fi.Length));
                                                for (int i = 0; i <= __r1 - 4 && !__good; i++)
                                                {
                                                    byte b0 = __buf[i], b1 = __buf[i + 1], b2 = __buf[i + 2], b3 = __buf[i + 3];
                                                    // accept if we see 'moov' OR 'mdat' in head
                                                    __good = (b0 == (byte)'m' && b1 == (byte)'o' && b2 == (byte)'o' && b3 == (byte)'v')
                                                          || (b0 == (byte)'m' && b1 == (byte)'d' && b2 == (byte)'a' && b3 == (byte)'t');
                                                }


                                                // tail scan if not found in head
                                                if (!__good)
                                                {
                                                    long __scan = Math.Min(256 * 1024L, __fi.Length); // widen to 256 KiB
                                                    __fs.Seek(__fi.Length - __scan, SeekOrigin.Begin);
                                                    int __r2 = __fs.Read(__buf, 0, (int)__scan);
                                                    for (int i = 0; i <= __r2 - 4 && !__good; i++)
                                                    {
                                                        byte b0 = __buf[i], b1 = __buf[i + 1], b2 = __buf[i + 2], b3 = __buf[i + 3];
                                                        __good = (b0 == (byte)'m' && b1 == (byte)'o' && b2 == (byte)'o' && b3 == (byte)'v')
                                                              || (b0 == (byte)'m' && b1 == (byte)'d' && b2 == (byte)'a' && b3 == (byte)'t');
                                                    }
                                                }

                                            }
                                            finally
                                            {
                                                System.Buffers.ArrayPool<byte>.Shared.Return(__buf);
                                            }

                                            // Optional tiny-file guard: header-only ghosts are usually <512 KiB
                                            if (__good || __fi.Length >= 512 * 1024) __keepExisting = __good;
                                        }
                                    }
                                }
                            }
                            catch
                            {
                                __keepExisting = false;
                            }

                            if (!__keepExisting)
                            {
                                // Central quarantine & re-fetch (VideoAudio\_Quarantine)
                                try
                                {
                                    var __qDir = Path.Combine(VideoRoot, "_Quarantine");
                                    Directory.CreateDirectory(__qDir);

                                    string __qPath = MakeQuarantinePath(__qDir, finalPath, "TRUNC");

                                    // if same-hash already exists in quarantine, reuse it
                                    bool __skipMove = false;
                                    try
                                    {
                                        var __h = QuickHash64k(finalPath);
                                        var __hit = FindQuarantineByHash(__qDir, __h);
                                        if (__hit != null && !__hit.Equals(__qPath, StringComparison.OrdinalIgnoreCase))
                                        {
                                            __qPath = __hit; // reuse existing canonical file
                                            __skipMove = true; // skip moving duplicate bytes
                                        }
                                    }
                                    catch { }

                                    // media: try move; else copy+delete (only if not dedup-hit)
                                    if (!__skipMove)
                                    {
                                        try { File.Move(finalPath, __qPath, true); }
                                        catch { try { File.Copy(finalPath, __qPath, true); File.Delete(finalPath); } catch { } }
                                    }
                                    else
                                    {
                                        try { File.Delete(finalPath); } catch { } // drop duplicate bytes
                                    }

                                    // sidecar: try move; else copy+delete
                                    var _m = finalPath + ".ok";
                                    if (File.Exists(_m))
                                    {
                                        var _mq = __qPath + ".ok";
                                        try { File.Move(_m, _mq, true); }
                                        catch { try { File.Copy(_m, _mq, true); File.Delete(_m); } catch { } }
                                    }

                                    try { Log($"[INTEGRITY] existing video appears truncated — moved to quarantine: {__qPath}"); } catch { }
                                    LogVidVerifyTelemetry("QUAR", finalPath, new FileInfo(finalPath).Length, /*moov*/ false, /*playable*/ false, "TRUNC");

                                    LogQuarantine(__skipMove ? "TRUNC_DEDUP" : "TRUNC", finalPath, __qPath);
                                    _qBad++;
                                    if (!string.IsNullOrEmpty(_qKey)) { try { IndexRemoveTyped(assetKind, _qKey); } catch { } }

                                }
                                catch { /* best-effort */ }

                                // fall through to normal download (do NOT return)
                            }

                            else
                            {
                                if (ShouldLogVideoLines())
                                {
                                    Log("[DEDUP] Linked to existing → " + finalPath);
                                    try { CMDownloaderUI.WebUiHost.PushRecent(finalPath, delayMs: 1200); } catch { }
                                    // hardlink → credit bytes saved
                                    try
                                    {
                                        long __bs4 = 0;
                                        try { if (_qLen > 0) __bs4 = _qLen; } catch { }
                                        if (__bs4 <= 0)
                                            try
                                            {
                                                if (!string.IsNullOrEmpty(finalPath) && System.IO.File.Exists(finalPath))
                                                    __bs4 = new System.IO.FileInfo(finalPath).Length;
                                            }
                                            catch { }
                                        if (__bs4 > 0) CMDownloaderUI.Status.AddBytesSaved(__bs4);
                                    }
                                    catch { }

                                    LogSkipExists(finalPath);
                                }
                                return true; // keep existing file
                            }
                        }

                        else
                        {
                            if (ShouldLogVideoLines())
                            {
                                Log("[DEDUP] Linked to existing → " + finalPath);
                                try { CMDownloaderUI.WebUiStatus.PushRecent(System.IO.Path.GetFileName(finalPath)); } catch { }

                                // hardlink → credit bytes saved
                                try
                                {
                                    long __bs4 = 0;
                                    try { if (_qLen > 0) __bs4 = _qLen; } catch { }
                                    if (__bs4 <= 0)
                                        try
                                        {
                                            if (!string.IsNullOrEmpty(finalPath) && System.IO.File.Exists(finalPath))
                                                __bs4 = new System.IO.FileInfo(finalPath).Length;
                                        }
                                        catch { }
                                    if (__bs4 > 0) CMDownloaderUI.Status.AddBytesSaved(__bs4);
                                }
                                catch { }

                                LogSkipExists(finalPath);
                            }
                            return true;
                        }
                    }

                }



                // (+) PRE-DOWNLOAD DE-DUP: quick fingerprint (Content-Length + SHA256(first 64KB))
                if (!NATURAL_URL_ONLY)
                {
                    try
                    {
                        var qf = await TryQuickFingerprintAsync(remoteUrl, referer, ct).ConfigureAwait(false);

                        if (qf.HasValue && qf.Value.Len > 0 && !string.IsNullOrEmpty(qf.Value.Hash64k))
                        {
                            _qLen = qf.Value.Len;
                            _qHash64k = qf.Value.Hash64k!;
                            // typed in-flight key so IMG and VID never collide
                            _qKey = $"{(assetKind == "VID" ? "V" : "I")}:{_qLen}:{_qHash64k}";
                            // learn+skip placeholder images this run
                            if (assetKind == "IMG")
                            {
                                var name = Path.GetFileNameWithoutExtension(finalPath);
                                bool nameLooksRestricted =
                                    name.IndexOf("restricted", StringComparison.OrdinalIgnoreCase) >= 0;

                                // Only treat "restricted" images as trash when they're tiny
                                const long RestrictedTrashMaxBytes = 300_000; // ~300 KB, adjust if needed
                                bool tiny = _qLen > 0 && _qLen <= RestrictedTrashMaxBytes;

                                if (nameLooksRestricted && tiny)
                                {
                                    AddTrashQuick(_qLen, _qHash64k!);
                                    Log($"[TRASH.LEARN] {_qLen}:{_qHash64k} ← '{name}'");
                                }

                                if (IsTrashQuick(_qLen, _qHash64k!))
                                {
                                    Log("[TRASH] Placeholder image detected — skip");
                                    TryDeleteIfEmpty(targetDir);
                                    return true; // do NOT download / link
                                }
                            }



                            // If we already have it on disk (from earlier runs), decide skip/link now
                            if (IndexTryGetByQuickSameKind(_qLen, _qHash64k!, assetKind, out var existing))

                            {
                                // If quick-index points to a non-existent file → purge and redownload
                                if (!File.Exists(existing))
                                {
                                    IndexRemoveQuick(_qLen, _qHash64k!);
                                    try { if (_qLen > 0) CMDownloaderUI.Status.AddBytesSaved(_qLen); } catch { }

                                    // quarantine any leftover artifact from stale index (best-effort)
                                    try
                                    {
                                        if (File.Exists(existing))
                                        {
                                            var qdir = Path.Combine(_userRootFolder, "Quarantine", "stale-index");
                                            Directory.CreateDirectory(qdir);
                                            var qdst = Path.Combine(qdir, Path.GetFileName(existing));
                                            File.Move(existing, qdst, true);
                                        }
                                    }
                                    catch { /* best-effort quarantine */ }


                                    // 20s rate-limit for this noisy line (no extra fields needed)
                                    var __k = "astrofetch.index.stalequick.last";
                                    var __now = Environment.TickCount64;
                                    var __lastObj = AppContext.GetData(__k);
                                    var __last = (__lastObj is long v) ? v : 0L;

                                    // fall through (do NOT return)
                                }

                                else
                                {
                                    // HEAD gate + tail-repair for existing videos (any common container) //
                                    {
                                        var vExt = Path.GetExtension(existing);
                                        bool isVideo = string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase)
                                            || vExt.Equals(".mp4", StringComparison.OrdinalIgnoreCase)
                                            || vExt.Equals(".m4v", StringComparison.OrdinalIgnoreCase)
                                            || vExt.Equals(".mov", StringComparison.OrdinalIgnoreCase)
                                            || vExt.Equals(".mkv", StringComparison.OrdinalIgnoreCase);


                                        if (isVideo)
                                        {
                                            try
                                            {
                                                long localLen = new FileInfo(existing).Length;
                                                long serverLen = 0;

                                                // HEAD for size + profile
                                                using (var head = new HttpRequestMessage(HttpMethod.Head, remoteUrl))
                                                {
                                                    if (!string.IsNullOrEmpty(referer))
                                                        head.Headers.Referrer = new Uri(referer);

                                                    using var headRes = await _http.SendAsync(head, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                                                    if (headRes.IsSuccessStatusCode)
                                                        serverLen = headRes.Content?.Headers?.ContentLength ?? 0;

                                                    // INSERT — concise probe log
                                                    try
                                                    {
                                                        var cl = headRes.Content?.Headers?.ContentLength ?? -1;
                                                        var ar = headRes.Headers?.AcceptRanges?.FirstOrDefault() ?? "";
                                                        Log($"[SS.TAIL.HEAD] {(int)headRes.StatusCode} v={headRes.Version} ar=[{ar}] cl={cl} ref={(string.IsNullOrEmpty(referer) ? "N" : "Y")}");
                                                    }
                                                    catch { }
                                                }


                                                if (serverLen > 0 && localLen < serverLen)
                                                {
                                                    long gap = serverLen - localLen;

                                                    if (gap >= 512 * 1024) // only bother if missing ≥512KB
                                                    {
                                                        try { await RepairTailIfNeededAsync(existing, remoteUrl.AbsoluteUri, ct).ConfigureAwait(false); } catch { /* best-effort */ }
                                                        localLen = new FileInfo(existing).Length;

                                                        if (localLen < serverLen)
                                                        {
                                                            try { Log("[INTEGRITY] truncated video in quick-index — quarantining & re-fetching"); } catch { }

                                                            // move the bad file out of the way first
                                                            try
                                                            {
                                                                var __dir = Path.GetDirectoryName(existing) ?? "";
                                                                var __qDir = Path.Combine(__dir, "_quarantine");
                                                                Directory.CreateDirectory(__qDir);

                                                                var __qBase = Path.GetFileNameWithoutExtension(existing);
                                                                var __qExt = Path.GetExtension(existing);
                                                                string __qPath = Path.Combine(__qDir, Path.GetFileName(existing));
                                                                int __n = 0;
                                                                while (File.Exists(__qPath) && __n < 50)
                                                                {
                                                                    __n++;
                                                                    __qPath = Path.Combine(__qDir, $"{__qBase} (bad{__n}){__qExt}");
                                                                }

                                                                try { File.Move(existing, __qPath, true); }
                                                                catch
                                                                {
                                                                    // cross-volume || locked fallback
                                                                    try { File.Copy(existing, __qPath, true); } catch { }
                                                                    try { File.Delete(existing); } catch { }
                                                                }

                                                                try { _qBad++; } catch { } // count quarantines for end-of-run summary
                                                                try { Log($"[VERIFY.FAIL] moved truncated file to quarantine: {__qPath}"); } catch { }
                                                            }
                                                            catch { /* best-effort quarantine */ }

                                                            // purge any temp/index state and fall through to normal download
                                                            try { PurgeCorrupt(existing); } catch { }
                                                            try { IndexRemoveQuick(_qLen, _qHash64k!); } catch { /* best-effort */ }
                                                            try { if (_qLen > 0) CMDownloaderUI.Status.AddBytesSaved(_qLen); } catch { }

                                                            // fall through to normal download (DO NOT return)
                                                        }

                                                        else
                                                        {
                                                            if (ShouldLogVideoLines()) Log("[DEDUP] Linked to existing → " + existing);
                                                            try { CMDownloaderUI.WebUiStatus.PushRecent(System.IO.Path.GetFileName(finalPath)); } catch { }

                                                            // hardlink → credit bytes saved
                                                            try
                                                            {
                                                                long __bs4 = 0;
                                                                try { if (_qLen > 0) __bs4 = _qLen; } catch { }
                                                                if (__bs4 <= 0)
                                                                    try
                                                                    {
                                                                        if (!string.IsNullOrEmpty(existing) && System.IO.File.Exists(existing))
                                                                            __bs4 = new System.IO.FileInfo(existing).Length;
                                                                    }
                                                                    catch { }
                                                                if (__bs4 <= 0)
                                                                    try
                                                                    {
                                                                        if (!string.IsNullOrEmpty(finalPath) && System.IO.File.Exists(finalPath))
                                                                            __bs4 = new System.IO.FileInfo(finalPath).Length;
                                                                    }
                                                                    catch { }
                                                                if (__bs4 > 0) CMDownloaderUI.Status.AddBytesSaved(__bs4);
                                                            }
                                                            catch { }

                                                            LogSkipExists(existing);
                                                            return true;
                                                        }
                                                    }
                                                    else
                                                    {
                                                        // Tiny gap — keep existing, skip repair/purge.
                                                        if (ShouldLogVideoLines()) Log($"[INTEGRITY] tiny gap ({gap:N0} B) — keeping existing");
                                                        LogSkipExists(existing);
                                                        return true;
                                                    }
                                                }

                                            }
                                            catch
                                            {
                                                // ignore; we’ll still do your existing local 'ftyp' probe below
                                            }
                                        }
                                    }

                                    // If the quick-index points to a video, verify it; if bad, purge and redownload.
                                    var existingExt = Path.GetExtension(existing);
                                    string extL = existingExt?.ToLowerInvariant() ?? string.Empty;

                                    bool existingIsVideo =
                                        string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase) ||
                                        extL == ".mp4" || extL == ".mov" || extL == ".m4v" || extL == ".mkv" || extL == ".webm";


                                    if (existingIsVideo)
                                    {
                                        bool ok = false;
                                        try
                                        {
                                            var fi = new FileInfo(existing);
                                            if (fi.Length >= 24)
                                            {
                                                using var fs = new FileStream(existing, FileMode.Open, FileAccess.Read, FileShare.Read);
                                                Span<byte> head = stackalloc byte[12];
                                                if (fs.Read(head) >= 12 &&
                                                    head[4] == (byte)'f' && head[5] == (byte)'t' && head[6] == (byte)'y' && head[7] == (byte)'p')
                                                {
                                                    long tail = Math.Min(16L, fi.Length);
                                                    fs.Seek(fi.Length - tail, SeekOrigin.Begin);
                                                    Span<byte> tailBuf = stackalloc byte[(int)tail];
                                                    ok = fs.Read(tailBuf) > 0;
                                                }
                                            }
                                        }
                                        catch { ok = false; }

                                        if (!ok)
                                        {
                                            try { Log("[INTEGRITY] quick-index pointed at bad video — quarantining & re-fetching"); } catch { }

                                            // Quarantine the bad file first (unique name; best-effort)
                                            try
                                            {
                                                var qdir = Path.Combine(_userRootFolder, "Quarantine", "stale-index");
                                                Directory.CreateDirectory(qdir);

                                                var qBase = Path.GetFileNameWithoutExtension(existing);
                                                var qExt = Path.GetExtension(existing);
                                                string qdst = Path.Combine(qdir, Path.GetFileName(existing));
                                                int qn = 0;
                                                while (File.Exists(qdst) && qn < 50)
                                                {
                                                    qn++;
                                                    qdst = Path.Combine(qdir, $"{qBase} (bad{qn}){qExt}");
                                                }

                                                try { File.Move(existing, qdst, true); }
                                                catch
                                                {
                                                    try { File.Copy(existing, qdst, true); } catch { }
                                                    try { File.Delete(existing); } catch { }
                                                }

                                                try { _qBad++; } catch { }
                                                try { Log($"[VERIFY.FAIL] moved to quarantine: {qdst}"); } catch { }
                                            }
                                            catch { /* best-effort quarantine */ }

                                            // Purge any artifacts and remove stale quick-index entry
                                            try { PurgeCorrupt(existing); } catch { }
                                            try { IndexRemoveQuick(_qLen, _qHash64k!); } catch { /* best-effort */ }
                                            try { if (_qLen > 0) CMDownloaderUI.Status.AddBytesSaved(_qLen); } catch { }

                                            // fall through to normal download (DO NOT return)
                                        }

                                        else
                                        {
                                            if (ShouldLogVideoLines())
                                                Log($"[DEDUP] Exists → {Path.GetFileName(existing)} (linked)");
                                            return true;
                                        }
                                    }
                                    else
                                    {
                                        // Non-video (zip/etc) → keep old skip behavior
                                        if (ShouldLogVideoLines())
                                            Log($"[DEDUP] Exists → {Path.GetFileName(existing)} (linked)");
                                        return true;

                                    }

                                }
                            }


                            else
                            {
                                // Non-video (z

                                {
                                    // Current candidate type (by destination path)

                                    var currExt = Path.GetExtension(finalPath) ?? string.Empty;
                                    bool currIsVideo =
                                        string.Equals(currExt, ".mp4", StringComparison.OrdinalIgnoreCase) ||
                                        string.Equals(currExt, ".m4v", StringComparison.OrdinalIgnoreCase) ||
                                        string.Equals(currExt, ".mov", StringComparison.OrdinalIgnoreCase);
                                    // Prefix a 2-digit ordinal for multi-asset posts to avoid IMG↔VID collisions.
                                    // Uses currIsVideo (in scope) to choose 01 for images, 02 for videos.
                                    // Only rewrites when this post is a set and the name isn't already indexed.
                                    try
                                    {
                                        var folderNow = Path.GetDirectoryName(finalPath) ?? string.Empty;
                                        var fileNoExt = Path.GetFileNameWithoutExtension(finalPath);

                                        bool isSet = naming?.UseSetFolder == true; // multi-asset post
                                        bool hasIndexPrefix =
                                            fileNoExt.Length >= 5 &&
                                            char.IsDigit(fileNoExt, 0) && char.IsDigit(fileNoExt, 1) &&
                                            fileNoExt[2] == ' ' && fileNoExt[3] == '-' && fileNoExt[4] == ' ';

                                        if (isSet && !hasIndexPrefix)
                                        {
                                            var baseName2 = naming!.CleanTitle;

                                            int ordinal = 1;
                                            try
                                            {
                                                var pat = $"?? - {baseName2}*";
                                                int existingCount = Directory.EnumerateFiles(folderNow, pat, SearchOption.TopDirectoryOnly).Count();
                                                ordinal = Math.Min(existingCount + 1, 99);
                                            }
                                            catch { ordinal = 1; }

                                            var indexed = $"{ordinal:D2} - {baseName2}{currExt}";
                                            finalPath = Path.Combine(folderNow, indexed);
                                            System.Threading.Interlocked.Increment(ref _nameIdxTotal);
                                            // user mode: no per-asset name/index chatter
                                            System.Threading.Interlocked.Increment(ref _nameIdxSupp);

                                        }


                                    }
                                    catch { /* best-effort; do not block */ }
                                    currExt = Path.GetExtension(finalPath) ?? string.Empty; // refresh in case finalPath changed
                                    currIsVideo =
                                        string.Equals(currExt, ".mp4", StringComparison.OrdinalIgnoreCase) ||
                                        string.Equals(currExt, ".m4v", StringComparison.OrdinalIgnoreCase) ||
                                        string.Equals(currExt, ".mov", StringComparison.OrdinalIgnoreCase);

                                    // Existing file type (by quick hit path)
                                    var existExt = Path.GetExtension(existing) ?? string.Empty;
                                    bool existIsVideo =
                                        string.Equals(existExt, ".mp4", StringComparison.OrdinalIgnoreCase) ||
                                        string.Equals(existExt, ".m4v", StringComparison.OrdinalIgnoreCase) ||
                                        string.Equals(existExt, ".mov", StringComparison.OrdinalIgnoreCase);


                                    // If quick hit is a different media class (e.g., JPG vs MP4) → remove bad index and download fresh
                                    if (currIsVideo != existIsVideo) // any class mismatch → purge quick and re-fetch
                                    {
                                        IndexRemoveQuick(_qLen, _qHash64k!);
                                        try { if (_qLen > 0) CMDownloaderUI.Status.AddBytesSaved(_qLen); } catch { }
                                        // drop any stale quick expectations for this slot
                                        _qRegistered = false;
                                        _qKey = null;
                                        _qHash64k = null;
                                        _qLen = 0;
                                        if (ShouldLogVideoLines() && (s_ShouldLogOnce?.Invoke("idx.quick.collision:" + (_qHash64k ?? ""), 10) == true))
                                            Log("[INDEX] quick collision (video↔image) — removed; will re-fetch");
                                        // quick collision → credit bytes saved
                                        try
                                        {
                                            long __bs = 0;
                                            try { if (_qLen > 0) __bs = _qLen; } catch { } // expected bytes from the quick-index
                                            if (__bs > 0) CMDownloaderUI.Status.AddBytesSaved(__bs);
                                        }
                                        catch { }

                                        // fall through
                                    }
                                    else
                                    {
                                        // If it's a video, sanity-check the existing file; delete if bad, else skip
                                        if (existIsVideo)
                                        {
                                            try
                                            {
                                                var efi = new FileInfo(existing);
                                                if (efi.Length < 64) throw new IOException("too small");

                                                using var efs = new FileStream(existing, FileMode.Open, FileAccess.Read, FileShare.Read);
                                                Span<byte> head = stackalloc byte[12];
                                                if (efs.Read(head) < 12) throw new IOException("no head");
                                                if (!(head[4] == (byte)'f' && head[5] == (byte)'t' && head[6] == (byte)'y' && head[7] == (byte)'p'))
                                                    throw new IOException("missing ftyp");

                                                // look for 'moov' somewhere early (up to 2MB)
                                                efs.Seek(0, SeekOrigin.Begin);
                                                int scan = (int)Math.Min(2 * 1024 * 1024L, efi.Length);
                                                byte[] buf = new byte[scan];
                                                int rd = efs.Read(buf, 0, scan);
                                                bool hasMoov = false;
                                                for (int i = 0; i <= rd - 4; i++)
                                                    if (buf[i] == (byte)'m' && buf[i + 1] == (byte)'o' && buf[i + 2] == (byte)'o' && buf[i + 3] == (byte)'v')
                                                    { hasMoov = true; break; }
                                                if (!hasMoov) throw new IOException("no moov");

                                                // tail readable
                                                long tail = Math.Min(16L, efi.Length);
                                                efs.Seek(efi.Length - tail, SeekOrigin.Begin);
                                                Span<byte> tailBuf = stackalloc byte[(int)tail];
                                                if (efs.Read(tailBuf) <= 0) throw new IOException("unreadable tail");
                                            }
                                            catch
                                            {
                                                try { File.Delete(existing); } catch { /* ignore */ }
                                                IndexRemoveQuick(_qLen, _qHash64k!); if (ShouldLogVideoLines()) Log("[INTEGRITY] bad quick-hit video — deleted; will re-fetch");
                                                try { if (_qLen > 0) CMDownloaderUI.Status.AddBytesSaved(_qLen); } catch { }

                                                // fall through to download
                                            }
                                        }
                                        else
                                        {
                                            // Non-video quick hit → ONLY "stale" if we actually had a quick entry
                                            string __bare = $"{_qLen}:{_qHash64k}";
                                            string __qkey = "I:" + __bare;

                                            bool __hadQuick = false;
                                            string __path = existing;

                                            try
                                            {
                                                lock (_idxQuick)
                                                {
                                                    if (_idxQuick.TryGetValue(__qkey, out var __p))
                                                    {
                                                        __hadQuick = true;
                                                        __path = __p;
                                                    }
                                                    else if (_idxQuick.TryGetValue(__bare, out var __p2)) // legacy (just in case)
                                                    {
                                                        __hadQuick = true;
                                                        __path = __p2;
                                                    }
                                                }
                                            }
                                            catch { }

                                            // If we didn't have a quick entry, this is normal first-time download. No stale log.
                                            if (!__hadQuick)
                                            {
                                                // fall through to normal download (do nothing here)
                                            }
                                            else if (string.IsNullOrEmpty(__path) || !File.Exists(__path))
                                            {
                                                // true stale quick-entry (we HAD an entry but the file is gone)
                                                try
                                                {
                                                    if (ShouldLogOnce("idx:stale:" + __qkey, 20))
                                                    {
                                                        bool wasCreated = !string.IsNullOrEmpty(__path) && _pathsCreatedThisRun.ContainsKey(__path);
                                                        Log($"[INDEX.STALE] key={__qkey} missing={__path} wasCreatedThisRun={wasCreated}");
                                                    }
                                                }
                                                catch { }

                                                try { IndexRemoveQuick(_qLen, _qHash64k!); } catch { }
                                                // fall through: DO NOT return; caller proceeds to normal download
                                            }
                                            else
                                            {
                                                Log($"[DEDUP] Duplicate detected — skipping new file; already have {Path.GetFileName(__path)}");
                                                AdjustHealthOnSuccess();
                                                EndCurrentFileProgress();
                                                return true;
                                            }





                                        }

                                    }
                                }
                            }




                            // Extra safety for videos: probe any existing video by len+64k under VideoAudio tree
                            var extLocal2 = Path.GetExtension(finalPath);
                            bool looksVideo =
                                string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(extLocal2, ".mp4", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(extLocal2, ".mov", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(extLocal2, ".m4v", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(extLocal2, ".mkv", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(extLocal2, ".webm", StringComparison.OrdinalIgnoreCase);

                            if (looksVideo)
                            {
                                // Find the VideoAudio root (walk up); fallback to current directory.
                                var probe = Path.GetDirectoryName(finalPath);
                                var videoRoot = probe!;
                                while (probe != null)
                                {
                                    var name = Path.GetFileName(probe);
                                    if (string.Equals(name, "VideoAudio", StringComparison.OrdinalIgnoreCase))
                                    {
                                        videoRoot = probe; break;
                                    }
                                    probe = Path.GetDirectoryName(probe);
                                }

                                foreach (var cand in Directory.EnumerateFiles(videoRoot, "*.*", SearchOption.AllDirectories)
                                                              .Where(p => p.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase)
                                                                  || p.EndsWith(".mov", StringComparison.OrdinalIgnoreCase)
                                                                  || p.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase)
                                                                  || p.EndsWith(".mkv", StringComparison.OrdinalIgnoreCase)
                                                                  || p.EndsWith(".webm", StringComparison.OrdinalIgnoreCase)))

                                {
                                    try
                                    {
                                        var fi = new System.IO.FileInfo(cand);
                                        if (fi.Length != _qLen) continue;

                                        // Don't treat the target as a duplicate of itself.
                                        if (string.Equals(cand, finalPath, StringComparison.OrdinalIgnoreCase))
                                            continue;

                                        using var fs = new System.IO.FileStream(
                                            cand,
                                            System.IO.FileMode.Open,
                                            System.IO.FileAccess.Read,
                                            System.IO.FileShare.Read);

                                        int bufLen = (int)Math.Min(64 * 1024L, fi.Length);
                                        var buf = new byte[bufLen];
                                        int read = fs.Read(buf, 0, bufLen);

                                        using var sha = System.Security.Cryptography.SHA256.Create();
                                        var local64kHex = BitConverter.ToString(sha.ComputeHash(buf, 0, read))
                                                                      .Replace("-", "").ToLowerInvariant();
                                        // kind mismatch (video↔image) → purge and ignore this hit
                                        bool __vid = cand.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) || cand.EndsWith(".mov", StringComparison.OrdinalIgnoreCase) || cand.EndsWith(".mkv", StringComparison.OrdinalIgnoreCase) || cand.EndsWith(".webm", StringComparison.OrdinalIgnoreCase);
                                        if (__vid != (assetKind == "VID")) { if (_qRegistered && _qKey != null) _inflightQuick.TryRemove(_qKey, out _); try { Log("[INDEX] quick collision (video↔image) — purged key"); } catch { } continue; }

                                        if (string.Equals(local64kHex, _qHash64k!, StringComparison.OrdinalIgnoreCase))
                                        {
                                            // Ensure destination exists (hardlink if possible, else copy)
                                            if (!System.IO.File.Exists(finalPath))
                                            {
                                                var dir = System.IO.Path.GetDirectoryName(finalPath) ?? "";
                                                System.IO.Directory.CreateDirectory(dir);
                                                if (!TryCreateHardLink(finalPath, cand))
                                                {
                                                    try
                                                    {
                                                        TraceAnyWrite(finalPath, -1, "DEDUP.COPY.CAND");
                                                        System.IO.File.Copy(cand, finalPath, overwrite: false);
                                                    }
                                                    catch { /* ignore */ }

                                                }
                                            }

                                            Log($"[DEDUP] Duplicate video (len+64k) — skipping; already have {System.IO.Path.GetFileName(cand)}");
                                            if (_qRegistered && _qKey != null) _inflightQuick.TryRemove(_qKey, out _);
                                            AdjustHealthOnSuccess();
                                            EndCurrentFileProgress();
                                            try { _noRangeHosts.Remove(remoteUrl.Host); _segSafeHosts.Add(remoteUrl.Host); } catch { }
                                            return true;
                                        }

                                    }
                                    catch
                                    {
                                        /* ignore local probe issues */
                                    }

                                }
                            }
                        }
                    }
                    catch { /* ignore de-dup probe errors */ }
                }




                // stash current post ref for downstream QUAR/MISS logs
                _curRef.Value = referer;


                // Include the post URL we queued from (aka referer) so mixed logs are traceable
                Log($"[DL] ref={referer} {assetKind} #{assetIndex} → {Path.GetFileName(finalPath)}");





                const int MaxAttempts = 3;
                int attempt = 0;
                int server5xxCount = 0;
                int notFoundCount = 0; // consecutive 404/410s
                bool bailNotFound = false; // cut attempts to 2 & skip watchdog


                for (; attempt < MaxAttempts; attempt++)
                {
                    ct.ThrowIfCancellationRequested();
                    bool was5xxThisAttempt = false;

                    try
                    {
                        // (+) PRE-DOWNLOAD DE-DUP: quick fingerprint (Content-Length + SHA256(first 64KB))
                        if (!NATURAL_URL_ONLY)
                        {

                            try

                            {
                                var qf = await TryQuickFingerprintAsync(remoteUrl, referer, ct).ConfigureAwait(false);

                                if (qf.HasValue && qf.Value.Len > 0 && !string.IsNullOrEmpty(qf.Value.Hash64k))
                                {
                                    _qLen = qf.Value.Len;
                                    _qHash64k = qf.Value.Hash64k!;
                                    _qKey = $"{(assetKind == "VID" ? "V" : "I")}:{_qLen}:{_qHash64k}";

                                    // Already have it? (by quick fingerprint) — also prune stale index entries
                                    string __t = (assetKind == "VID") ? "V" : "I";
                                    string __keyT = $"{__t}:{_qLen}:{_qHash64k}";
                                    string existingQuick;
                                    bool __hit;
                                    lock (_idxQuick)
                                    {
                                        // First try typed key (e.g. "V:12345:abcd…")
                                        __hit = _idxQuick.TryGetValue(__keyT, out existingQuick);

                                        // If not found, check legacy bare key (e.g. "12345:abcd…")
                                        if (!__hit)
                                        {
                                            bool legacyHit = _idxQuick.TryGetValue($"{_qLen}:{_qHash64k}", out var legacyVal);
                                            if (legacyHit)
                                            {
                                                try { Log("[QIDX.MIGRATE] migrating legacy quick key → typed key"); } catch { }
                                                _idxQuick[__keyT] = legacyVal; // promote to typed key
                                                existingQuick = legacyVal;
                                                __hit = true;
                                            }
                                        }
                                    }


                                    if (__hit)
                                    {
                                        // Guard: only dedupe within the same kind (video vs image)
                                        string __extQuick = Path.GetExtension(existingQuick)?.ToLowerInvariant() ?? string.Empty;
                                        bool __existingIsVideo = __extQuick == ".mp4" || __extQuick == ".mov" || __extQuick == ".m4v" || __extQuick == ".mkv" || __extQuick == ".webm";
                                        bool __newIsVideo = string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase);

                                        if (__existingIsVideo != __newIsVideo)
                                        {
                                            // Different kinds → ignore this quick hit; fall through to normal download
                                            __hit = false;
                                            existingQuick = null;
                                        }
                                        else

                                                                            if (!File.Exists(existingQuick))
                                        {
                                            // Stale pointer: drop it and fall through to a normal download
                                            IndexRemoveQuick(_qLen, _qHash64k!);
                                            if (!File.Exists(existingQuick))
                                            {
                                                // credit bytes saved when stale quick prevented a re-download
                                                try { if (_qLen > 0) CMDownloaderUI.Status.AddBytesSaved(_qLen); } catch { }

                                                // quarantine any leftover artifact from stale index (best-effort)
                                                try
                                                {
                                                    if (!string.IsNullOrEmpty(existingQuick) && File.Exists(existingQuick))
                                                    {
                                                        var qdir = Path.Combine(_userRootFolder, "Quarantine", "stale-index");
                                                        Directory.CreateDirectory(qdir);
                                                        var qdst = Path.Combine(qdir, Path.GetFileName(existingQuick));
                                                        if (!string.Equals(existingQuick, qdst, StringComparison.OrdinalIgnoreCase))
                                                            File.Move(existingQuick, qdst, true);
                                                    }
                                                }
                                                catch { /* best-effort quarantine */ }

                                                
                                            }


                                            else
                                            {
                                                string existingQuickExt = Path.GetExtension(existingQuick);
                                                string extQL = existingQuickExt?.ToLowerInvariant() ?? string.Empty;

                                                bool existingIsVideo =
                                                    extQL == ".mp4" || extQL == ".mov" || extQL == ".m4v" || extQL == ".mkv" || extQL == ".webm";
                                                if (string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase) && existingIsVideo)
                                                {
                                                    // Verify the existing video; if corrupt, purge and re-fetch.
                                                    bool ok = false;
                                                    try
                                                    {
                                                        var fi = new FileInfo(existingQuick);
                                                        if (fi.Exists && fi.Length >= 24)
                                                        {
                                                            using var fs = new FileStream(existingQuick, FileMode.Open, FileAccess.Read, FileShare.Read);
                                                            Span<byte> head = stackalloc byte[12];
                                                            int n = fs.Read(head);

                                                            if (n >= 8)
                                                            {
                                                                if (extQL == ".mp4" || extQL == ".mov" || extQL == ".m4v")
                                                                {
                                                                    // MP4/MOV: look for "ftyp" at bytes 4..7
                                                                    ok = head[4] == (byte)'f' && head[5] == (byte)'t' &&
                                                                         head[6] == (byte)'y' && head[7] == (byte)'p';
                                                                }
                                                                else if (extQL == ".mkv" || extQL == ".webm")
                                                                {
                                                                    // MKV/WEBM (EBML) magic: 1A 45 DF A3
                                                                    ok = head[0] == 0x1A && head[1] == 0x45 &&
                                                                         head[2] == 0xDF && head[3] == 0xA3;
                                                                }
                                                            }

                                                            if (ok)
                                                            {
                                                                // MP4 family: require a 'moov' atom either near head (faststart) || tail.
                                                                if (extQL == ".mp4" || extQL == ".mov" || extQL == ".m4v")
                                                                {
                                                                    bool hasMoov = false;
                                                                    long window = Math.Min(2 * 1024 * 1024L, fi.Length);

                                                                    var pool = System.Buffers.ArrayPool<byte>.Shared;
                                                                    byte[] buf = pool.Rent((int)window);
                                                                    try
                                                                    {
                                                                        // Scan first window
                                                                        fs.Seek(0, SeekOrigin.Begin);
                                                                        int r1 = fs.Read(buf, 0, (int)window);
                                                                        for (int i = 0; i <= r1 - 4 && !hasMoov; i++)
                                                                        {
                                                                            if (buf[i] == (byte)'m' && buf[i + 1] == (byte)'o' &&
                                                                                buf[i + 2] == (byte)'o' && buf[i + 3] == (byte)'v')
                                                                                hasMoov = true;
                                                                        }

                                                                        // If not found, scan last window
                                                                        if (!hasMoov)
                                                                        {
                                                                            long tailScan = Math.Min(window, fi.Length);
                                                                            fs.Seek(fi.Length - tailScan, SeekOrigin.Begin);
                                                                            int r2 = fs.Read(buf, 0, (int)tailScan);
                                                                            for (int i = 0; i <= r2 - 4 && !hasMoov; i++)
                                                                            {
                                                                                if (buf[i] == (byte)'m' && buf[i + 1] == (byte)'o' &&
                                                                                    buf[i + 2] == (byte)'o' && buf[i + 3] == (byte)'v')
                                                                                    hasMoov = true;
                                                                            }
                                                                        }
                                                                    }
                                                                    finally { pool.Return(buf); }

                                                                    ok = hasMoov;
                                                                }
                                                            }

                                                            if (ok)
                                                            {
                                                                // Also make sure we can read the tail (catches some truncations)
                                                                long tail = Math.Min(16L, fi.Length);
                                                                fs.Seek(fi.Length - tail, SeekOrigin.Begin);
                                                                Span<byte> tailBuf = stackalloc byte[(int)tail];
                                                                ok = fs.Read(tailBuf) > 0;
                                                            }
                                                        }
                                                    }
                                                    catch { ok = false; }


                                                    if (!ok)
                                                    {
                                                        Log("[INTEGRITY] quick-index pointed at bad video — purging and re-fetching");

                                                        // evict and fall through to normal download (do NOT return)
                                                        IndexRemoveQuick(_qLen, _qHash64k!);
                                                        try { if (_qLen > 0) CMDownloaderUI.Status.AddBytesSaved(_qLen); } catch { }

                                                        // best-effort quarantine of the stale artifact
                                                        try
                                                        {
                                                            if (!string.IsNullOrEmpty(existingQuick) && File.Exists(existingQuick))
                                                            {
                                                                var qdir = Path.Combine(_userRootFolder, "Quarantine", "stale-index");
                                                                Directory.CreateDirectory(qdir);
                                                                var qdst = Path.Combine(qdir, Path.GetFileName(existingQuick));
                                                                if (!string.Equals(existingQuick, qdst, StringComparison.OrdinalIgnoreCase))
                                                                    File.Move(existingQuick, qdst, true);
                                                            }
                                                        }
                                                        catch { /* best-effort quarantine */ }
                                                    }

                                                    else
                                                    {
                                                        if (ShouldLogVideoLines())
                                                        {
                                                            Log($"[DEDUP] Duplicate video — skipping; already have {Path.GetFileName(existingQuick)}");
                                                        }
                                                        // allow previously no-range host back after successful SS
                                                        try
                                                        {
                                                            var host = remoteUrl?.Host;
                                                            if (!string.IsNullOrEmpty(host))
                                                            {
                                                                lock (_noRangeHosts)
                                                                {
                                                                    if (_noRangeHosts.Remove(host))
                                                                        Log($"[EDGE.UNBAN] {host} removed from no-range list (SS success)");

                                                                }
                                                                /* range200 retired */
                                                            }
                                                            try { BumpHostScore(remoteUrl?.Host, +1); } catch { }
                                                        }
                                                        catch { /* best effort */ }

                                                        AdjustHealthOnSuccess(); EndCurrentFileProgress();
                                                        return true;

                                                    }
                                                }

                                                Directory.CreateDirectory(targetDir);

                                                // If the paths are identical, nothing to do (don’t skew link/copy counters).
                                                // purge stale quick pointer and fall through to normal download
                                                if (!string.IsNullOrEmpty(existingQuick) && !File.Exists(existingQuick))
                                                {
                                                    try
                                                    {
                                                        var __k = $"I:{_qLen}:{_qHash64k}";
                                                        if (ShouldLogOnce("idx:stale:" + __k, 20))
                                                        {
                                                            bool wasCreated = _pathsCreatedThisRun.ContainsKey(existingQuick);
                                                            Log($"[INDEX.STALE] key={__k} missing={existingQuick} wasCreatedThisRun={wasCreated}");
                                                        }
                                                    }
                                                    catch { }

                                                    try { IndexRemoveQuick(_qLen, _qHash64k!); } catch { }
                                                    // fall through to normal download
                                                }


                                                try { if (_qLen > 0) CMDownloaderUI.Status.AddBytesSaved(_qLen); } catch { }

                                                if (string.Equals(
                                                        Path.GetFullPath(existingQuick),
                                                        Path.GetFullPath(finalPath),
                                                        StringComparison.OrdinalIgnoreCase))
                                                {
                                                    Log($"[DEDUP] Exists → {Path.GetFileName(finalPath)}");
                                                    _hadDownloads = true;
                                                    AdjustHealthOnSuccess();
                                                    EndCurrentFileProgress();

                                                    TryDeleteIfEmpty(targetDir); // <-- INSERT THIS LINE

                                                    return true;
                                                }

                                                // For small videos, don't short-circuit via quick dedup; force full verify instead
                                                if (assetKind == "VID" && _qLen > 0 && _qLen < 4L * 1024 * 1024)
                                                {
                                                    try { Log("[DEDUP] Small video quick-hit → forcing verify (skip early link)"); } catch { }
                                                    // fall through to normal download + verify (no link, no return)
                                                }
                                                else if (TryCreateHardLink(finalPath, existingQuick))
                                                {
                                                    Log($"[DEDUP] Linked to existing ({Path.GetFileName(existingQuick)}) → {Path.GetFileName(finalPath)}");
                                                    try { CMDownloaderUI.WebUiStatus.PushRecent(System.IO.Path.GetFileName(finalPath)); } catch { }

                                                    // hardlink → credit bytes saved
                                                    try
                                                    {
                                                        long __bs4 = 0;
                                                        try { if (_qLen > 0) __bs4 = _qLen; } catch { }
                                                        if (__bs4 <= 0)
                                                            try
                                                            {
                                                                if (!string.IsNullOrEmpty(existingQuick) && System.IO.File.Exists(existingQuick))
                                                                    __bs4 = new System.IO.FileInfo(existingQuick).Length;
                                                            }
                                                            catch { }
                                                        if (__bs4 <= 0)
                                                            try
                                                            {
                                                                if (!string.IsNullOrEmpty(finalPath) && System.IO.File.Exists(finalPath))
                                                                    __bs4 = new System.IO.FileInfo(finalPath).Length;
                                                            }
                                                            catch { }
                                                        if (__bs4 > 0) CMDownloaderUI.Status.AddBytesSaved(__bs4);
                                                    }
                                                    catch { }

                                                    _sumDedupLinks++; // links only
                                                    _hadDownloads = true;
                                                    AdjustHealthOnSuccess();
                                                    EndCurrentFileProgress();
                                                    // ensure a thumbnail exists at the destination for videos
                                                    try
                                                    {
                                                        var vExt = Path.GetExtension(finalPath)?.ToLowerInvariant();
                                                        if (vExt == ".mp4" || vExt == ".m4v" || vExt == ".mov" || vExt == ".webm" || vExt == ".mkv")
                                                        {
                                                            // Thumbnails disabled — intentional no-op.
                                                        }
                                                    }
                                                    catch { /* no-op */ }
                                                    MarkDone();

                                                    return true;
                                                }


                                                // Fallback: copy when hardlink isn’t possible (e.g., different volume)
                                                try
                                                {
                                                    if (!File.Exists(finalPath))
                                                    {
                                                        TraceAnyWrite(finalPath, -1, "DEDUP.COPY.EXISTINGQUICK");
                                                        File.Copy(existingQuick, finalPath, overwrite: false);

                                                        Log($"[DEDUP] Copied from existing ({Path.GetFileName(existingQuick)}) → {Path.GetFileName(finalPath)}");
                                                        _sumDedupCopies++; // copies only
                                                        _hadDownloads = true;
                                                        AdjustHealthOnSuccess();
                                                        EndCurrentFileProgress();
                                                        return true;
                                                    }
                                                    else
                                                    {
                                                        Log($"[DEDUP] Destination already present → {Path.GetFileName(finalPath)}");
                                                        _hadDownloads = true;
                                                        AdjustHealthOnSuccess();
                                                        EndCurrentFileProgress();
                                                        return true;
                                                    }
                                                }
                                                catch
                                                {
                                                    Log($"[DEDUP] Hardlink and copy failed — will re-fetch {Path.GetFileName(finalPath)}");
                                                    // fall through to normal download (do NOT return)
                                                }



                                            }

                                        } // ← closes the injected 'else {'
                                    } // <— closes the outer if that this else belongs to






                                    // In-flight guard (with short log suppression)
                                    if (!_inflightQuick.TryAdd(_qKey, finalPath))
                                    {
                                        // ownerPath is whichever caller registered this key first
                                        if (_inflightQuick.TryGetValue(_qKey, out var ownerPath))
                                        {
                                            var noticeKey = ownerPath ?? finalPath ?? _qKey;
                                            var now = DateTime.UtcNow;
                                            if (!_dupNoticeUntil.TryGetValue(noticeKey, out var untilUtc) || now >= untilUtc)
                                            {
                                                _dupNoticeUntil[noticeKey] = now.AddMilliseconds(800);
                                                Log($"[DEDUP] In-flight duplicate — skipping; owner {Path.GetFileName(ownerPath ?? "owner")}");

                                                // dedup skip → credit bytes saved
                                                try
                                                {
                                                    long __bs = 0;
                                                    try { if (_qLen > 0) __bs = _qLen; } catch { }
                                                    if (__bs <= 0)
                                                        try
                                                        {
                                                            if (!string.IsNullOrEmpty(ownerPath) && System.IO.File.Exists(ownerPath))
                                                                __bs = new System.IO.FileInfo(ownerPath).Length;
                                                        }
                                                        catch { }
                                                    if (__bs <= 0)
                                                        try
                                                        {
                                                            if (!string.IsNullOrEmpty(finalPath) && System.IO.File.Exists(finalPath))
                                                                __bs = new System.IO.FileInfo(finalPath).Length;
                                                        }
                                                        catch { }
                                                    if (__bs > 0) CMDownloaderUI.Status.AddBytesSaved(__bs);
                                                }
                                                catch { }
                                            }
                                            // else: within debounce window; suppress this duplicate notice
                                        }
                                        else
                                        {
                                            var noticeKey = finalPath ?? _qKey;
                                            var now = DateTime.UtcNow;
                                            if (!_dupNoticeUntil.TryGetValue(noticeKey, out var untilUtc) || now >= untilUtc)
                                            {
                                                _dupNoticeUntil[noticeKey] = now.AddMilliseconds(800);
                                                Log("[DEDUP] In-flight duplicate — skipping.");

                                                // dedup skip → credit bytes saved
                                                try
                                                {
                                                    long __bs = 0;
                                                    try { if (_qLen > 0) __bs = _qLen; } catch { }
                                                    if (__bs <= 0)
                                                        try
                                                        {
                                                            if (!string.IsNullOrEmpty(finalPath) && System.IO.File.Exists(finalPath))
                                                                __bs = new System.IO.FileInfo(finalPath).Length;
                                                        }
                                                        catch { }
                                                    if (__bs > 0) CMDownloaderUI.Status.AddBytesSaved(__bs);
                                                }
                                                catch { }
                                            }
                                            // else: within debounce window; suppress this duplicate notice
                                        }


                                        AdjustHealthOnSuccess();
                                        EndCurrentFileProgress();
                                        TryDeleteIfEmpty(Path.GetDirectoryName(finalPath)!); // <-- add this line
                                        return true;

                                    }
                                    _qRegistered = true;
                                    // show item in Queued list
                                    try
                                    {
                                        var __id = _qKey ?? finalPath ?? Guid.NewGuid().ToString("n");
                                        var __kind = string.IsNullOrEmpty(assetKind) ? "" : assetKind.ToUpperInvariant();
                                        string __name = System.IO.Path.GetFileName(finalPath ?? _qKey ?? __id);
                                        string __host = "";
                                        try { __host = remoteUrl?.Host ?? ""; } catch { }

                                        CMDownloaderUI.QueueTap.UpsertQueued(__id, __kind, __name, __host);
                                    }
                                    catch { /* never break worker */ }



                                    // Extra safety: if it's a video, scan VideoAudio by len+first64k
                                    var ext2 = Path.GetExtension(finalPath);
                                    bool looksVideo = string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase)
                                                   || string.Equals(ext2, ".mp4", StringComparison.OrdinalIgnoreCase)
                                                   || string.Equals(ext2, ".mov", StringComparison.OrdinalIgnoreCase)
                                                   || string.Equals(ext2, ".m4v", StringComparison.OrdinalIgnoreCase);

                                    // Video quick-dedupe: only treat quick hits that actually point at a video as valid
                                    string onDisk = string.Empty;
                                    bool quickHit = _qHash64k != null &&
                                                    IndexTryGetByQuick(_qLen, _qHash64k!, out onDisk);

                                    if (looksVideo && quickHit && IsVideoPath(onDisk) && File.Exists(onDisk))
                                    {
                                        // Ensure the requested finalPath exists (link/copy from canonical if needed)
                                        if (!string.Equals(onDisk, finalPath, StringComparison.OrdinalIgnoreCase))
                                        {
                                            EnsureParent(finalPath);
                                            if (!File.Exists(finalPath))
                                            {
                                                if (!TryCreateHardLink(finalPath, onDisk))
                                                {
                                                    try
                                                    {
                                                        TraceAnyWrite(finalPath, -1, "DEDUP.COPY.ONDISK");
                                                        File.Copy(onDisk, finalPath, overwrite: false);
                                                    }
                                                    catch { /* best-effort */ }
                                                }
                                            }
                                        }

                                        Log($"[DEDUP] Duplicate video (index) — skipping; already have {Path.GetFileName(onDisk)}");
                                        if (_qRegistered && _qKey != null) _inflightQuick.TryRemove(_qKey, out _);
                                        AdjustHealthOnSuccess();
                                        EndCurrentFileProgress();
                                        return true;
                                    }
                                    else if (looksVideo && quickHit && !IsVideoPath(onDisk))
                                    {
                                        // Quick entry points at a non-video (image/other) — log and ignore for VID
                                        try { Log($"[INDEX] quick collision (video probe vs non-video) — ignoring {onDisk}"); } catch { }
                                    }




                                }
                            }
                            catch { /* ignore de-dup probe errors */ }
                        }

                        // Images: detect "small" and keep per-attempt timeout shorter //
                        if (attempt == 0 && assetKind == "IMG")
                        { try { var sz = await TryProbeSizeAsync(remoteUrl, ct).ConfigureAwait(false); smallImage = sz.HasValue && sz.Value <= SMALL_IMAGE_BYTES; } catch { smallImage = false; } }

                        // For videos we try segmented download first (if supported) //
                        if (assetKind == "VID")
                        {

                            // Prefer last proven 206 edge before probing
                            if (!string.IsNullOrEmpty(_pinnedRangeHost)
                                && !_noRangeHosts.Contains(_pinnedRangeHost)
                                && !string.Equals(remoteUrl.Host, _pinnedRangeHost, StringComparison.OrdinalIgnoreCase))
                            {
                                try { remoteUrl = new UriBuilder(remoteUrl) { Host = _pinnedRangeHost }.Uri; Log($"[EDGE.PREF] using pinned 206 host: {_pinnedRangeHost}"); } catch { }
                            }
                            // ensure chosen edge can actually stream before probes/locks
                            {
                                int ttfbMs = -1;
                                int attempts = 0;
                                bool ok = false;

                                while (!ok && attempts < 3 && !ct.IsCancellationRequested)
                                {
                                    attempts++;

                                    var gate = await TtfbWarmupGateAsync(remoteUrl, referer, ct).ConfigureAwait(false);
                                    ok = gate.ok;
                                    ttfbMs = gate.ttfbMs;

                                    if (ok)
                                    {
                                        try { if (ttfbMs >= 1500) Log($"[TTFB.SLOW] host={remoteUrl.Host} ms={ttfbMs} attempt={attempts}"); } catch { }
                                        break;
                                    }

                                    try { if (ttfbMs >= 1500) Log($"[TTFB.FAIL] host={remoteUrl.Host} ms={ttfbMs} attempt={attempts}"); } catch { }

                                    // Rotate to next media edge; if none or same, stop trying
                                    var nextHost = NextEdgeHost(remoteUrl.Host);
                                    if (string.IsNullOrEmpty(nextHost) ||
                                        string.Equals(nextHost, remoteUrl.Host, StringComparison.OrdinalIgnoreCase))
                                    {
                                        break;
                                    }

                                    try
                                    {
                                        remoteUrl = RewriteHost(remoteUrl, nextHost);
                                    }
                                    catch
                                    {
                                        break;
                                    }
                                }

                                // If gate never succeeded, we still fall through and let ProbeRangeSupportAsync
                                // decide whether to bail; this preserves existing behavior but with a strong bias
                                // toward alive edges.
                            }

                            // Probe Range and size up-front
                            var probe = await ProbeRangeSupportAsync(remoteUrl, referer, ct).ConfigureAwait(false);

                            // Prefer single-stream resume if a .part exists — unify known size from probe || quick hint //
                            long __knownLen = (probe.totalSize > 0) ? probe.totalSize : (_qLen > 0 ? _qLen : -1);

                            // Decide segmentation strictly from Range support + size threshold
                            bool __allowSeg = probe.supportsRange && __knownLen >= MIN_SEGMENT_BYTES;
                            // tighten segmented: only if host is pinned OK || not known-bad this run
                            {
                                var _host = remoteUrl.Host;
                                bool hostPinned = !string.IsNullOrEmpty(_pinnedRangeHost)
                                                  && _pinnedRangeHost.Equals(_host, StringComparison.OrdinalIgnoreCase);
                                bool notKnownBad = !_noRangeHosts.Contains(_host);

                                __allowSeg = __allowSeg && (hostPinned || notKnownBad);

                                // DIAG ONLY
                                // if (!__allowSeg && !_segSafeHosts.Contains(remoteUrl.Host))
                                //     Log("[075.MODE] Segments denied → single-stream (host not pinned/safe)");
                            }


                            var __smallFileNoEdge = (__knownLen >= 0 && __knownLen < MIN_SEGMENT_BYTES);
                            // — must be above any gate/goto __SEG_RETRY_ONCE
                            bool __resumePreferred = false;

                            // Also respect per-run and per-host no-range knowledge
                            if (__allowSeg && (s_NoRangeThisRun || _noRangeHosts.Contains(remoteUrl.Host)))
                            {
                                __allowSeg = false;

                                // DIAG ONLY — suppress seg gate chatter
                                // var key = "seg.gate:" + remoteUrl.Host;
                                // if (s_ShouldLogOnce?.Invoke(key, 30) == true)
                                //     if (s_ShouldLogOnce?.Invoke("seg.ss_only.host", 1) == true)
                                //         SegPlanLogOncePerHost(remoteUrl?.Host ?? "?",
                                //             $"[SEG.gate] {(remoteUrl?.Host ?? "?")} range disabled ({(_noRangeHosts.Contains(remoteUrl?.Host ?? "?") ? "no-range host" : "per-run state")}); using single-stream");
                            }




                            if (File.Exists(tempPath))
                            {
                                long __have = 0; try { __have = new FileInfo(tempPath).Length; } catch { }
                                Log($"[RESUME] .part found ({__have / (1024.0 * 1024.0):0.0} MB) — prefer single-stream resume");
                                __allowSeg = false;
                                __resumePreferred = true;
                            }

                            // — early gate to avoid plan→gate chatter
                            {
                                int __actGate = System.Threading.Volatile.Read(ref _activeSegVideos);
                                int __maxGate = Math.Max(1, _maxVID);

                                // stagger by size: 1 huge, 2 upper-mid, else default
                                try
                                {
                                    // __knownLen is set earlier from the probe; -1 if unknown
                                    if (__knownLen >= 320L * 1024 * 1024) // ≥ 320 MiB → only 1 big segmented at a time
                                        __maxGate = 1;
                                    else if (__knownLen >= 200L * 1024 * 1024) // 200–319 MiB → at most 2 concurrently
                                        __maxGate = Math.Min(__maxGate, 2);
                                    // else: leave __maxGate as computed (NV/VID config)
                                }
                                catch { /* best-effort */ }

                                // force SS during simple window
                                if (InSimpleMode())
                                {
                                    __segCapHit = true;
                                    __allowSeg = false;
                                    try { Log("[SIMPLE] window → single-stream (skip seg plan)"); } catch { }
                                    // fall through to SS
                                }
                                // if segmentation isn’t allowed, make sure overflow is closed
                                if (!__allowSeg && _segOverflowOpen)
                                {
                                    _segOverflowOpen = false;
                                    _segGateBurst = 0;
                                }
                                // Only consider the seg gate when segmentation is allowed for this file/run.
                                if (__allowSeg && __actGate >= __maxGate)
                                {
                                    // if segs are disallowed, skip the gate entirely
                                    var __gateHost = remoteUrl?.Host ?? string.Empty;

                                    bool __gateRangeBanned = false;
                                    try
                                    {
                                        lock (_noRangeHosts)
                                            __gateRangeBanned = __gateHost.Length > 0 &&
                                                                (_noRangeHosts.Contains(__gateHost) || _noRangeHosts.Contains("*.coomer.st")); // drop wildcard if unused
                                    }
                                    catch { /* best-effort */ }

                                    if (s_NoRangeThisRun || __gateRangeBanned)
                                    {
                                        // DIAG ONLY
                                        // if (s_ShouldLogOnce?.Invoke($"seg.ss_only:{(__gateRangeBanned ? __gateHost : "run")}", 1) == true)
                                        //     Log($"[SEG.AUTOSCALE] {(__gateRangeBanned ? __gateHost : "run")} SS-only — skipping seg gate");



                                        // require TWO zero-reads within 20s before banning Range for the host
                                        string __host = remoteUrl?.Host ?? "?";
                                        if (_segZeroTs == null) _segZeroTs = new(StringComparer.OrdinalIgnoreCase);

                                        if (_segZeroTs.TryGetValue(__host, out var __last) && (DateTime.UtcNow - __last).TotalSeconds < 20)
                                        {
                                            _noRangeHosts.Add(__host);

                                            // DIAG ONLY — suppress noisy gate log
                                            // SegPlanLogOncePerHost(__host,
                                            //   $"[SEG.gate] {__host} range disabled (second zero-read <20s); using single-stream");
                                        }
                                        else
                                        {
                                            _segZeroTs[__host] = DateTime.UtcNow;

                                            // DIAG ONLY — suppress grace log
                                            // try { Log($"[SEG.grace] {__host} first zero-read — grace 20s before host ban"); } catch { }
                                        }


                                        s_NoRangeThisRun = true; // bias to SS for remainder of run
                                        __allowSeg = false; // force planner to SS
                                        __segCapHit = true; // tell planner we’re not waiting for segs
                                        goto __SEG_RETRY_ONCE; // re-plan as SS immediately
                                    }


                                    // (keep the rest of your existing gate logic below this point)


                                    // If overflow is already open, don't wait—let the second seg job start now.
                                    if (_segOverflowOpen)
                                    {
                                        var __asHost = remoteUrl?.Host ?? string.Empty; // no 'url' in this scope

                                        // Honor soft TTL bans as well as legacy sets
                                        bool __ttlBan = false;
                                        if (__asHost.Length > 0 && _rangeBanUntil.TryGetValue(__asHost, out var __until))
                                            __ttlBan = __until > DateTime.UtcNow;

                                        bool __rangeBanned = __asHost.Length > 0 &&
                                                             (__ttlBan || _noRangeHosts.Contains(__asHost) || _noRangeHosts.Contains("*.coomer.st"));

                                        // If range-banned, allow the nudge to override ONCE; otherwise force SS
                                        if (__rangeBanned)
                                        {
                                            if (System.Threading.Volatile.Read(ref __preferSegmentedNextTry))
                                            {
                                                System.Threading.Volatile.Write(ref __preferSegmentedNextTry, false);
                                                // DIAG ONLY
                                                // Log("[SEG.NUDGE] overriding autoscale ban for one segmented attempt");
                                                // FALL THROUGH into segmented path
                                            }
                                            else
                                            {
                                                // DIAG ONLY
                                                // if (s_ShouldLogOnce?.Invoke($"seg.range_banned:{__asHost}", 1) == true)
                                                //     Log($"[SEG.AUTOSCALE] {__asHost} range-banned — skipping segmented retry; staying on SS");

                                                s_NoRangeThisRun = true;
                                                if (!string.IsNullOrEmpty(__asHost))
                                                    _rangeBanUntil[__asHost] = DateTime.UtcNow.AddSeconds(RANGE_BAN_TTL_SECONDS);

                                                goto __SEG_RETRY_ONCE;
                                            }
                                        }


                                        // Hysteresis guard: if pool-full forces SS, let nudge override ONCE; else force SS
                                        if (s_StopRequested) throw new OperationCanceledException("stop");
                                        ct.ThrowIfCancellationRequested();

                                        var __forceSS = ShouldFallbackToSSWhenPoolFull(_activeSegVideos, RANGE_POOL_MAX);

                                        // DIAG ONLY
                                        // LogAutoscaleIfChanged(_activeSegVideos, RANGE_POOL_MAX, __forceSS);

                                        if (__forceSS)
                                        {
                                            if (System.Threading.Volatile.Read(ref __preferSegmentedNextTry))
                                            {
                                                System.Threading.Volatile.Write(ref __preferSegmentedNextTry, false);
                                                // DIAG ONLY
                                                // Log("[SEG.NUDGE] overriding autoscale hysteresis for one segmented attempt");
                                                // FALL THROUGH
                                            }
                                            else
                                            {
                                                // DIAG ONLY
                                                // Log("[SEG.AUTOSCALE] forcing SS (hysteresis reached)");

                                                s_NoRangeThisRun = true;
                                                if (!string.IsNullOrEmpty(__asHost))
                                                    _rangeBanUntil[__asHost] = DateTime.UtcNow.AddSeconds(RANGE_BAN_TTL_SECONDS);

                                                goto __SEG_RETRY_ONCE;
                                            }
                                        }


                                        // Otherwise, fall through into segmented path
                                    }



                                    if (s_ShouldLogOnce?.Invoke("seg.gate.hit", 2) == true)
                                        try
                                        {
                                            var __hostRB = remoteUrl?.Host ?? string.Empty;

                                            if (_lastSegGateLogUtc.AddSeconds(5) <= DateTime.UtcNow)
                                            {
                                                _lastSegGateLogUtc = DateTime.UtcNow;

                                                // DIAG ONLY
                                                // if (s_ShouldLogOnce?.Invoke($"seg.range_banned:{__hostRB}", 1) == true)
                                                //     Log($"[SEG.AUTOSCALE] {__hostRB} range-banned — skipping segmented retry; staying on SS");
                                            }
                                        }
                                        catch { }


                                    await Task.Delay(800, ct).ConfigureAwait(false);
                                    __actGate = Math.Max(0, System.Threading.Volatile.Read(ref _activeSegVideos));

                                    const int __maxSpins = 2; // ~0.8s total
                                    for (int __spin = 0; __spin < __maxSpins; __spin++)
                                    {
                                        await Task.Delay(400, ct).ConfigureAwait(false);
                                        __actGate = System.Threading.Volatile.Read(ref _activeSegVideos);
                                        __maxGate = Math.Max(1, _maxVID);

                                        // Slot freed OR overflow opened mid-loop → start segmented now.
                                        if (__actGate < __maxGate || _segOverflowOpen)
                                        {
                                            try
                                            {
                                                // Respect STOP/cancel immediately — no more autoscale spin after stop
                                                if (s_StopRequested) throw new OperationCanceledException("stop");
                                                ct.ThrowIfCancellationRequested();

                                                try
                                                {
                                                    // 3-strike hysteresis (no user log here)
                                                    const int HYST = 3;
                                                    bool fullNow = _segOverflowOpen;

                                                    if (fullNow) { __autoFreeStreak = 0; if (__autoFullStreak < HYST) __autoFullStreak++; }
                                                    else { __autoFullStreak = 0; __autoFreeStreak++; }

                                                    bool forceSS = (__autoFullStreak >= HYST);
                                                    if (forceSS != __autoForceSS) // state transition only
                                                    {
                                                        __autoForceSS = forceSS;

                                                        // DIAG ONLY — suppress autoscale chatter
                                                        // Log(forceSS
                                                        //     ? "[SEG.AUTOSCALE] forcing SS (hysteresis reached)"
                                                        //     : "[SEG.GATE] capacity detected — re-attempting segmented plan");
                                                    }
                                                }
                                                catch { /* best-effort */ }



                                                // burst gate with 10s window
                                                try
                                                {
                                                    long now = Environment.TickCount64;
                                                    if (now - _segGateBurstT0Ms > 10000) { _segGateBurstT0Ms = now; _segGateBurst = 0; }
                                                    if (++_segGateBurst >= 5 && !_segOverflowOpen)
                                                    {
                                                        _segOverflowOpen = true;

                                                        // DIAG ONLY
                                                        // if (s_ShouldLogOnce?.Invoke("seg.ovf.open", 2) == true)
                                                        //     Log("[SEG.AUTOSCALE] opening overflow seg slot (1 → 2)");

                                                        goto __SEG_RETRY_ONCE;
                                                    }
                                                }
                                                catch { }

                                            }
                                            catch { /* outer best-effort */ }


                                            // Calm period → close overflow (if it had been opened and things settled)
                                            try
                                            {
                                                long now = Environment.TickCount64;
                                                if (_segOverflowOpen && __actGate <= 1 && (now - _segGateBurstT0Ms) > 30_000)
                                                {
                                                    _segOverflowOpen = false;
                                                    _segGateBurst = 0;

                                                    // DIAG ONLY
                                                    // if (s_ShouldLogOnce?.Invoke("seg.ovf.close", 2) == true)
                                                    //     Log("[SEG.AUTOSCALE] closing overflow seg slot (2 → 1)");
                                                }
                                            }
                                            catch { /* best-effort */ }

                                            goto __SEG_RETRY_ONCE;

                                        }

                                        // burst of gate hits → open overflow
                                        try
                                        {
                                            long now = Environment.TickCount64;
                                            if (now - _segGateBurstT0Ms > 10_000) { _segGateBurstT0Ms = now; _segGateBurst = 0; }
                                            if (++_segGateBurst >= 5 && !_segOverflowOpen)
                                            {
                                                _segOverflowOpen = true; // allow one extra segmented job to pass the gate

                                                // DIAG ONLY
                                                // Log("[SEG.AUTOSCALE] opening overflow seg slot (1 → 2)");

                                                goto __SEG_RETRY_ONCE;
                                            }
                                        }
                                        catch { /* best-effort */ }

                                    }

                                    // No slot freed — orderly stagger (no demotion)
                                    if (_stopRequested && _stopMode == StopMode.Graceful)
                                    {
                                        __segCapHit = true;
                                        __allowSeg = false;
                                        try { Log("[SEG.GATE] graceful stop → handoff to single-stream"); } catch { }
                                        // fall through to SS path (no more gate spins)
                                    }
                                    else
                                    {
                                        // longer waits for bigger files so they naturally serialize
                                        int waitMs =
                                            (__knownLen >= 320L * 1024 * 1024) ? 2500 :
                                            (__knownLen >= 200L * 1024 * 1024) ? 1800 :
                                                                                 1200;

                                        await Task.Delay(waitMs, ct).ConfigureAwait(false);
                                        goto __SEG_RETRY_ONCE;

                                    }
                                }

                            }
                        __SEG_RETRY_ONCE:
                            if (probe.totalSize <= 0) probe.totalSize = -1;


                            {
                                var __pgHost = remoteUrl?.Host ?? string.Empty;
                                bool __pgRangeBanned = false;
                                try { lock (_noRangeHosts) __pgRangeBanned = __pgHost.Length > 0 && _noRangeHosts.Contains(__pgHost); } catch { }

                                if (s_NoRangeThisRun || __pgRangeBanned)
                                {
                                    _segOverflowOpen = false;
                                    _segGateBurst = 0;
                                    _segGateBurstT0Ms = 0;
                                    // (__allowSeg will recompute false on this pass)
                                }
                            }

                            if (probe.totalSize <= 0) probe.totalSize = -1; // belt-and-suspenders

                            // bias plan from per-host profile
                            var __hostPlan = remoteUrl?.Host;
                            int __score = HostRangeScore_Get(__hostPlan);

                            if (__score <= RANGE_BAD_MAX)
                            {
                                __allowSeg = false;
                                // DIAG ONLY
                                // Log($"[PLAN] host={__hostPlan} prof={__score} → SS-only");
                            }
                            else if (__score >= RANGE_SAFE_MIN)
                            {
                                __allowSeg = __allowSeg || (probe.totalSize >= MIN_SEGMENT_BYTES);
                                // DIAG ONLY
                                // Log($"[PLAN] host={__hostPlan} prof={__score} → range-safe (seg OK)");
                            }


                            // If we know size and it's below threshold, don't pretend Range is missing.
                            if (probe.totalSize >= 0 && probe.totalSize < MIN_SEGMENT_BYTES)
                            {
                                // DIAG ONLY — suppress min-bytes gate log
                                // Log($"[SEG.gate] segmented disabled (min-bytes); using single-stream (...)");
                            }

                            // was: else if (probe.supportsRange && probe.totalSize >= MIN_SEGMENT_BYTES) //
                            else if (__allowSeg)
                            {
                                // snapshot & clear cross-asset hint (use per-asset local only)
                                __preferSegLocal |= System.Threading.Volatile.Read(ref __preferSegmentedNextTry);
                                System.Threading.Volatile.Write(ref __preferSegmentedNextTry, false);

                                int __segments = ChooseSegmentCountTuned(probe.totalSize);

                                // prior SS transport flake → force segmented once (local-only)
                                if (__preferSegLocal)
                                {
                                    // respect short hold after autoscale/range-banned to avoid flapping
                                    if (s_NoRangeThisRun || (DateTime.UtcNow - _lastSegZeroUtc) < TimeSpan.FromSeconds(10))
                                    {
                                        // DIAG ONLY
                                        // Log("[SEG.HOLD] keeping single-stream briefly to avoid flapping");
                                        // do NOT consume the nudge
                                    }
                                    else
                                    {
                                        __preferSegLocal = false;      // consume local nudge
                                        __segments = Math.Max(__segments, 2);
                                        // DIAG ONLY
                                        // Log("[SEG.NUDGE] forcing segmented due to prior SS transport error");
                                    }
                                }






                                // ensure VID × per-file never exceeds the pool
                                {
                                    int __byPool = Math.Max(1, RANGE_POOL_MAX / Math.Max(1, _maxVID));
                                    __segments = Math.Min(__segments, Math.Min(RANGE_PER_FILE_MAX, __byPool));
                                }
                                // prefer segmentation for 8–128 MB when Range is OK
                                {
                                    const long __baseCap = 64L * 1024 * 1024;
                                    bool __recentSegZero = (DateTime.UtcNow - _lastSegZeroUtc) < TimeSpan.FromMinutes(1);
                                    long __ssCap = __recentSegZero ? 130L * 1024 * 1024 : __baseCap;

                                    bool __poolFullSmall = (_activeSegVideos >= RANGE_POOL_MAX) && (probe.totalSize <= __baseCap);
                                    bool __adaptSmall = (probe.totalSize <= __ssCap);

                                    // If the asset is video-sized and Range is honored, keep segmentation (2+)
                                    // instead of collapsing to SS for these sizes.
                                    bool __inSweetSpot = (probe.totalSize >= 8L * 1024 * 1024) && (probe.totalSize <= 128L * 1024 * 1024);

                                    if ((__poolFullSmall || __adaptSmall) && !__inSweetSpot)
                                    {
                                        int __preSeg2 = __segments;
                                        __segments = 1; // force single-stream only outside the sweet spot
                                        try { Log($"[SEG.cap] → SS (was {__preSeg2}), poolFullSmall={__poolFullSmall}, cap={__ssCap / (1024 * 1024)}MB, size={probe.totalSize / (1024 * 1024.0):0.0}MB"); } catch { }
                                    }
                                    else
                                    {
                                        // keep at least two segments in the sweet spot
                                        __segments = Math.Max(__segments, 2);
                                    }
                                }



                                int __preSeg = __segments;

                                if (probe.totalSize <= 160L * 1024 * 1024) __segments = Math.Min(__segments, 2);
                                if (__segments < __preSeg) Log($"[SEG.cap] reduced segments {__preSeg}→{__segments} (≤160 MiB policy)");

                                // Allow heavier parallelism on big files
                                if (probe.totalSize >= 600L * 1024 * 1024) __segments = Math.Max(__segments, 4);
                                __segments = Math.Max(1, Math.Min(__segments, 4));

                                LogSegPlan(Path.GetFileName(finalPath), probe.totalSize, RANGE_POOL_MAX, _activeSegVideos, __segments);

                                // if planner says x1, route to single-stream path instead of burning a segmented slot
                                int __preSSRotations = 0;

                                if (__segments <= 1)
                                {
                                    Log("[SEG.plan] x1 → SS fallback");

                                    goto SS_FALLBACK;
                                    // allow one pre-SS rotate max
                                    if (__preSSRotations++ >= 1) { goto SS_FALLBACK; }
                                    // planner chose SS — skip pre-SS rotation
                                    goto SS_FALLBACK;

                                    // try alternate edges for THIS asset before falling back
                                    {
                                        string __cur = remoteUrl.Host;
                                        for (int __rot = 0; __rot < 6; __rot++)
                                        {
                                            var __next = NextEdgeHost(__cur);
                                            if (string.IsNullOrEmpty(__next) || __next.Equals(__cur, StringComparison.OrdinalIgnoreCase))
                                                break;

                                            try
                                            {
                                                var __ub = new UriBuilder(remoteUrl) { Host = __next };
                                                remoteUrl = __ub.Uri;
                                                Log($"[SEG.ROTATE] {__cur} → {__next} (asset-scope, pre-SS)");

                                                // Re-enter your segmented probe/plan path
                                                goto __SEG_RETRY_ONCE;
                                            }
                                            catch { /* try next edge */ }

                                            __cur = __next;
                                        }

                                        // no viable edge → proceed to your existing single-stream path
                                        goto SS_FALLBACK;
                                    }
                                }

                                Log($"[SEG x{__segments}] Using segmented download — {probe.totalSize / (1024 * 1024.0):0.0} MB (active {_activeSegVideos}/{RANGE_POOL_MAX}{(__segments < __preSeg ? "; capped" : "")})");


                                if (!progressStarted) { BeginCurrentFileProgress(probe.totalSize, Path.GetFileName(finalPath)); progressStarted = true; }
                                CMDownloaderUI.WebUiStatus.SetCurrent(Path.GetFileName(finalPath));
                                CMDownloaderUI.WebUiStatus.SetCurrentProgress(0, 0, probe.totalSize, null, remoteUrl?.Host);

                                if (!progressStarted)
                                {
                                    BeginCurrentFileProgress(probe.totalSize, Path.GetFileName(finalPath));
                                    progressStarted = true;

                                    // reset seg autoscale state so prior file’s burst/overflow doesn’t leak in
                                    _segOverflowOpen = false;
                                    _segGateBurst = 0;
                                    _segGateBurstT0Ms = 0;
                                }



                                bool segOk;
                                try
                                {
                                    bool __forceSSPlan = (__segments <= 1) || !__allowSeg || (probe.totalSize >= 0 && probe.totalSize < MIN_SEGMENT_BYTES);
                                    segOk = await DownloadVideoSegmentedAsync(remoteUrl, tempPath, finalPath, probe.totalSize, referer, ct, BUF, __forceSSPlan).ConfigureAwait(false);
                                }
                                catch (Exception ex)
                                {
                                    // If we're stopping/canceled, don't rotate || fall back — just exit
                                    if (ct.IsCancellationRequested || ex is OperationCanceledException || ex is TaskCanceledException)
                                    {
                                        try { EndCurrentFileProgress(); } catch { /* best-effort */ }
                                        Log("[CANCEL] Segmented download canceled");
                                        return false;
                                    }

                                    Log($"[SEG] Exception during segmented path: {ex.GetType().Name} {ex.Message} — falling back to single-stream");
                                    // count transport flakes (no throw, no flow changes)
                                    try
                                    {
                                        var _msg = ex?.ToString() ?? string.Empty;
                                        if (_msg.IndexOf("ResponseEnded", StringComparison.OrdinalIgnoreCase) >= 0
                                         || _msg.IndexOf("unexpected EOF", StringComparison.OrdinalIgnoreCase) >= 0
                                         || _msg.IndexOf("0 bytes from the transport", StringComparison.OrdinalIgnoreCase) >= 0)
                                        {
                                            NoteTransportFlake();
                                        }
                                    }
                                    catch { /* best-effort only */ }
                                    // H2 first-read/reset → mark host SS-only for this run (no more segments)
                                    try
                                    {
                                        var msg = ex?.ToString() ?? string.Empty;
                                        var h = remoteUrl.Host;
                                        bool h2Flake =
                                            msg.IndexOf("Http2ReadStream", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                            msg.IndexOf("RST_STREAM", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                            msg.IndexOf("HTTP/2 server reset", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                            msg.IndexOf("unexpected EOF", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                            msg.IndexOf("ResponseEnded", StringComparison.OrdinalIgnoreCase) >= 0;

                                        if (!string.IsNullOrEmpty(h) && h2Flake)
                                        {
                                            lock (_noRangeHosts) _noRangeHosts.Add(h);
                                            s_NoRangeThisRun = true;

                                            // DIAG ONLY
                                            // Log($"[075.MODE] Demote host for this run → SS only: {h}");
                                        }

                                    }
                                    catch { /* best-effort */ }

                                    // Mark that we can try a one-time retry on a different edge
                                    if (ex.Message.IndexOf("rotate host", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                        ex.Message.IndexOf("segmented write failed", StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        __segRetryDueToWriteFail = true; // E1: mark single retry on rotated host
                                    }

                                    segOk = false;

                                    // E2 — one-time segmented retry on the opposite family (then next host) before falling back
                                    if (__segRetryDueToWriteFail && __segRetryOnce > 0 && _edge is { } esRetry)
                                    {
                                        var oldHostRetry = remoteUrl.Host;
                                        string? nextRetry = null;

                                        // 1) Prefer opposite-family host
                                        var opp = esRetry.ResolveOppositeFamilyHost(oldHostRetry);
                                        if (!string.IsNullOrEmpty(opp) && !string.Equals(opp, oldHostRetry, StringComparison.OrdinalIgnoreCase))
                                        {
                                            nextRetry = opp;
                                        }

                                        // 2) Fallback: rotate until we get a different host (guard a few spins)
                                        if (string.IsNullOrEmpty(nextRetry))
                                        {
                                            var guard = 0;
                                            do
                                            {
                                                esRetry.HopNext();
                                                nextRetry = esRetry.ResolveHostForNewDownload();
                                            }
                                            while (!string.IsNullOrEmpty(nextRetry)
                                                && string.Equals(nextRetry, oldHostRetry, StringComparison.OrdinalIgnoreCase)
                                                && ++guard < 4);
                                        }

                                        if (!string.IsNullOrEmpty(nextRetry)
                                            && !string.Equals(nextRetry, oldHostRetry, StringComparison.OrdinalIgnoreCase))
                                        {
                                            remoteUrl = esRetry.RewriteUriHost(remoteUrl, nextRetry);
                                            try { Log($"[SEG] retrying once on opposite/next host ({oldHostRetry} → {remoteUrl.Host}) before single-stream"); } catch { }
                                            __segRetryOnce--;
                                            __segRetryDueToWriteFail = false; // consume the retry
                                            goto __SEG_RETRY_ONCE; // jump back to re-probe/re-plan
                                        }
                                    }


                                }

                                if (segOk)
                                {
                                    try { BumpHostScore(remoteUrl.Host, +1); } catch { }

                                    // POST-CHECK: header/tail sanity before we call it a win
                                    bool postOk = false;
                                    // — accept if exact size matches (no probe) BUT MP4-family must pass structure/playable
                                    try
                                    {
                                        var fi = new FileInfo(finalPath);
                                        long __expected = probe.totalSize > 0 ? probe.totalSize : _qLen; // safe fallback to pre-known quick length
                                        if (__expected > 0 && fi.Length == __expected)
                                        {
                                            // MP4-family gate (.mp4/.m4v/.mov/…)
                                            string __ext2 = Path.GetExtension(finalPath)?.ToLowerInvariant() ?? "";
                                            bool __mp4fam2 = __ext2 is ".mp4" or ".m4v" or ".mov" or ".3gp" or ".3g2" or ".ismv" or ".f4v";

                                            if (!__mp4fam2)
                                            {
                                                postOk = true; // non-MP4: size-match is enough
                                            }
                                            else
                                            {
                                                bool __ok = false;
                                                try
                                                {
                                                    bool __moov = HasMoovOrMoofHeadTail(finalPath); // index present (front or tail)
                                                    if (__moov)
                                                    {
                                                        __ok = HasPlayableTrackQuick(finalPath); // require vide/soun handler

                                                        // Optional extra guard for tiny MP4-family: confirm 'mdat' exists in head window
                                                        if (__ok && fi.Length < 12L * 1024 * 1024)
                                                        {
                                                            using var fs = new FileStream(finalPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                                                            int scan = (int)Math.Min(1024 * 1024, fi.Length);
                                                            byte[] buf = new byte[scan];
                                                            int n = fs.Read(buf, 0, scan);
                                                            bool mdatFound = false;
                                                            for (int i = 0; i <= n - 4 && !mdatFound; i++)
                                                                if (buf[i] == (byte)'m' && buf[i + 1] == (byte)'d' && buf[i + 2] == (byte)'a' && buf[i + 3] == (byte)'t')
                                                                    mdatFound = true;
                                                            if (!mdatFound) __ok = false;
                                                        }
                                                    }
                                                }
                                                catch { __ok = false; }

                                                // REPLACE THIS WHOLE BLOCK
                                                if (!__ok)
                                                {
                                                    // Structure check failed (no moov/moof or no playable track):
                                                    // delete & retry once on the opposite CDN family (no quarantine)
                                                    try { Log("[VERIFY] mp4 structure not playable — deleting & retrying on opposite family"); } catch { }
                                                    try { System.IO.File.Delete(finalPath); } catch { }

                                                    if (_edge is { } es2)
                                                    {
                                                        var oldHost2 = remoteUrl.Host;
                                                        var opp2 = es2.ResolveOppositeFamilyHost(oldHost2);
                                                        if (!string.IsNullOrEmpty(opp2) && !string.Equals(opp2, oldHost2, StringComparison.OrdinalIgnoreCase))
                                                        {
                                                            remoteUrl = es2.RewriteUriHost(remoteUrl, opp2);
                                                            try { Log($"[SHELL] structure fail — switch family: {oldHost2} → {remoteUrl.Host}"); } catch { }
                                                        }
                                                    }

                                                    // One retry path you already have in this method
                                                    goto __SEG_RETRY_ONCE;
                                                }
                                                else
                                                {
                                                    postOk = true;
                                                }

                                            }
                                        }
                                    }
                                    catch { /* ignore here; fall back to local sanity */ }
                                    // reject “range-probe shells” for MP4-family
                                    try
                                    {
                                        if (!postOk) // still undecided after
                                        {
                                            var __fi = new FileInfo(finalPath);
                                            string __ext_tb = Path.GetExtension(finalPath)?.ToLowerInvariant() ?? "";
                                            bool __mp4fam_tb = __ext_tb is ".mp4" or ".m4v" or ".mov" or ".3gp" or ".3g2" or ".ismv" or ".f4v";

                                            if (__mp4fam_tb && __fi.Length < 8L * 1024 * 1024) // short MP4-family (<8 MiB) — eligible for shell check
                                            {
                                                // Re-learn best server-reported length now (HEAD first, then Range 0–0 fallback)
                                                long __bestHeadLen_tb = -1;

                                                var __ruS = remoteUrl?.ToString(); // use string form; url is not in scope here
                                                if (!string.IsNullOrEmpty(__ruS))
                                                {
                                                    using (var __h2 = new HttpRequestMessage(HttpMethod.Head, __ruS))
                                                    {
                                                        try { __h2.Headers.AcceptEncoding.Clear(); } catch { }
                                                        using var __hr2 = await _http.SendAsync(__h2, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                                                        __bestHeadLen_tb = __hr2.Content.Headers.ContentLength ?? -1;
                                                    }

                                                    if (__bestHeadLen_tb <= 0)
                                                    {
                                                        using var __r2 = new HttpRequestMessage(HttpMethod.Get, __ruS);
                                                        __r2.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 0);
                                                        try { __r2.Headers.AcceptEncoding.Clear(); } catch { }
                                                        using var __rr2 = await _http.SendAsync(__r2, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                                                        if ((int)__rr2.StatusCode == 206)
                                                        {
                                                            var __cr2 = __rr2.Content.Headers.ContentRange; // bytes 0-0/N
                                                            if (__cr2 != null && __cr2.Unit == "bytes" && __cr2.HasLength)
                                                                __bestHeadLen_tb = __cr2.Length.Value;
                                                        }
                                                    }
                                                }

                                                // Use the best known total: seg planner → quick len → fresh HEAD/0-0
                                                long __bestLen_tb = Math.Max(Math.Max(probe.totalSize, _qLen), __bestHeadLen_tb);

                                                // If CDN says the file is at least ~1 MB bigger than what we saved → treat ours as a stub
                                                if (__bestLen_tb > __fi.Length + 1_000_000)
                                                {
                                                    try { Log($"[VERIFY] tiny save vs large expected ({__fi.Length:N0}B << {__bestLen_tb:N0}B) — rejecting shell"); } catch { }
                                                    postOk = false; // force quarantine/retry path
                                                }
                                            }
                                        }
                                    }
                                    catch { /* best-effort */ }





                                    // — Local MP4 sanity (ftyp + moov + readable tail) if still undecided
                                    if (!postOk)
                                    {
                                        try
                                        {
                                            var vext = Path.GetExtension(finalPath).ToLowerInvariant();
                                            if (vext == ".mp4" || vext == ".m4v" || vext == ".mov")
                                            {
                                                using var fs = new FileStream(finalPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                                                long len = fs.Length;
                                                if (len >= 24)
                                                {
                                                    // scan head & tail windows: min(4MB, len/8)
                                                    int win = (int)Math.Min(4 * 1024 * 1024, Math.Max(4096, len / 8));
                                                    var head = new byte[Math.Min(win, (int)Math.Min(len, int.MaxValue))];
                                                    var tail = new byte[Math.Min(win, (int)Math.Min(len, int.MaxValue))];

                                                    int hn = fs.Read(head, 0, head.Length);
                                                    fs.Seek(Math.Max(0, len - tail.Length), SeekOrigin.Begin);
                                                    int tn = fs.Read(tail, 0, tail.Length);

                                                    bool ftypOk = (hn >= 12 && head[4] == (byte)'f' && head[5] == (byte)'t' && head[6] == (byte)'y' && head[7] == (byte)'p');
                                                    // accept only common brands we consider OK
                                                    bool brandOk = ftypOk && (
                                                        (hn >= 12 && (
                                                            head[8] == (byte)'i' && head[9] == (byte)'s' && head[10] == (byte)'o' && (head[11] == (byte)'m' || head[11] == (byte)'2')) // isom/iso2
                                                        || (hn >= 12 && head[8] == (byte)'m' && head[9] == (byte)'p' && head[10] == (byte)'4' && (head[11] == (byte)'1' || head[11] == (byte)'2')) // mp41/mp42
                                                        || (hn >= 12 && head[8] == (byte)'M' && head[9] == (byte)'4' && head[10] == (byte)'V' && head[11] == (byte)' ') // "M4V "
                                                        || (hn >= 12 && head[8] == (byte)'q' && head[9] == (byte)'t' && head[10] == (byte)' ' && head[11] == (byte)' ') // "qt "
                                                    ));

                                                    // cheap 'moov' presence probe: look for ascii "moov" near either end
                                                    static bool hasFourCC(byte[] buf, int n, byte a, byte b, byte c, byte d)
                                                    {
                                                        for (int i = 0; i <= n - 4; i++)
                                                            if (buf[i] == a && buf[i + 1] == b && buf[i + 2] == c && buf[i + 3] == d) return true;
                                                        return false;
                                                    }
                                                    bool moovOk = hasFourCC(head, hn, (byte)'m', (byte)'o', (byte)'o', (byte)'v') || hasFourCC(tail, tn, (byte)'m', (byte)'o', (byte)'o', (byte)'v');
                                                    bool tailReadable = tn > 0;

                                                    postOk = brandOk && moovOk && tailReadable; // ACCEPT via local sanity
                                                }
                                            }
                                        }
                                        catch { /* keep postOk = false */ }
                                    }

                                    try
                                    {
                                        var fi = new FileInfo(finalPath);
                                        if (fi.Length >= 64)
                                        {
                                            using var fs = new FileStream(finalPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                                            Span<byte> head = stackalloc byte[12];
                                            int n = fs.Read(head);
                                            string extPost = Path.GetExtension(finalPath).ToLowerInvariant();

                                            bool headOk = (extPost == ".mp4" || extPost == ".m4v" || extPost == ".mov")
                                                ? (n >= 8 && head[4] == (byte)'f' && head[5] == (byte)'t' && head[6] == (byte)'y' && head[7] == (byte)'p')
                                                : (n >= 4 && head[0] == 0x1A && head[1] == 0x45 && head[2] == 0xDF && head[3] == 0xA3); // MKV/WEBM EBML


                                            if (headOk)
                                            {
                                                long tail = Math.Min(16L, fi.Length);
                                                fs.Seek(fi.Length - tail, SeekOrigin.Begin);
                                                Span<byte> t = stackalloc byte[(int)tail];
                                                int tr = fs.Read(t);
                                                // Compare to probed size when we have it; allow small container padding
                                                long expectedLen = probe.totalSize > 0 ? probe.totalSize : _qLen;
                                                if (expectedLen > 0)
                                                {
                                                    long diff = Math.Abs(fi.Length - expectedLen);
                                                    postOk = tr > 0 && fi.Length > 0; // accept if tail readable + non-zero
                                                }
                                                else
                                                {
                                                    postOk = tr > 0; // no size info; trust header/tail
                                                }
                                            }
                                        }
                                    }
                                    catch { postOk = false; }

                                    if (!postOk)
                                    {
                                        if (!postOk)
                                        {
                                            // move bad file out of the way, then retry via throw
                                            try
                                            {
                                                // Centralized quarantine (by kind)
                                                string __rootQ = string.Equals(assetKind, "IMG", StringComparison.OrdinalIgnoreCase)
                                                                    ? ImagesRoot
                                                                    : VideoRoot;
                                                var __qDir = Path.Combine(__rootQ, "_Quarantine");
                                                Directory.CreateDirectory(__qDir);

                                                // Build reasoned path with embedded 64k-hash and collision guard
                                                string __qPath = MakeQuarantinePath(__qDir, finalPath, "POSTCHECK_FAIL");

                                                // reuse existing same-hash file if present (cheap filename scan)
                                                bool __skipMove = false;
                                                try
                                                {
                                                    var __h = ExtractHashFromQPath(__qPath) ?? QuickHash64k(finalPath);
                                                    var __hit = FindQuarantineByHashName(__qDir, __h);
                                                    if (__hit != null && !__hit.Equals(__qPath, StringComparison.OrdinalIgnoreCase))
                                                    {
                                                        __qPath = __hit;
                                                        __skipMove = true;
                                                    }
                                                }
                                                catch { /* best-effort */ }

                                                // media: move/copy only if not dedup-hit
                                                if (!__skipMove)
                                                {
                                                    try { File.Move(finalPath, __qPath, true); }
                                                    catch { try { File.Copy(finalPath, __qPath, true); File.Delete(finalPath); } catch { } }
                                                }
                                                else
                                                {
                                                    try { File.Delete(finalPath); } catch { }
                                                }

                                                // sidecar .ok
                                                var _m = finalPath + ".ok";
                                                if (File.Exists(_m))
                                                {
                                                    var _mq = __qPath + ".ok";
                                                    try { File.Move(_m, _mq, true); }
                                                    catch { try { File.Copy(_m, _mq, true); File.Delete(_m); } catch { } }
                                                }
                                                if (string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase))
                                                    LogVidVerifyTelemetry("QUAR", finalPath, new FileInfo(finalPath).Length, false, false, "POSTCHECK_FAIL");

                                                LogQuarantine(__skipMove ? "POSTCHECK_FAIL_DEDUP" : "POSTCHECK_FAIL", finalPath, __qPath);
                                                _qBad++;
                                                if (!string.IsNullOrEmpty(_qKey)) { try { IndexRemoveTyped(assetKind, _qKey); } catch { } }
                                            }
                                            catch { /* best-effort */ }


                                            // now fail out so the caller requeues/falls back
                                            throw new IOException("Post-save verification failed");
                                        }



                                        // Mirror inflight/quick-index cleanup so state is sane before fallback
                                        try
                                        {
                                            if (_qRegistered && _qKey != null) _inflightQuick.TryRemove(_qKey, out _);
                                        }
                                        finally
                                        {
                                            _qRegistered = false;
                                            _qKey = null;
                                            _qLen = 0;
                                            _qHash64k = null;
                                        }

                                        // Nudge health downward for a segmented failure
                                        const bool __soft = true; // no 'ex' in this scope → treat as soft to avoid cooldown storms
                                        if (!__soft) { try { AdjustHealthOnFailure(null, null); } catch { /* optional */ } }

                                        // only ban host if current file is seg-eligible
                                        if (!string.IsNullOrEmpty(remoteUrl?.Host))
                                        {
                                            bool __segElig_local = (_qLen >= MIN_SEGMENT_BYTES); // use best hint available in this scope

                                            if (__segElig_local)
                                            {
                                                lock (_noRangeHosts) { _noRangeHosts.Add(remoteUrl.Host); }
                                            }

                                            // still unpin regardless
                                            if (string.Equals(_pinnedRangeHost, remoteUrl.Host, StringComparison.OrdinalIgnoreCase))
                                                _pinnedRangeHost = null;
                                        }




                                        // Keep the log, but use a timed cooldown instead of a per-run ban in _noRangeHosts
                                        Log("[SEG] write failed — edge cooled; switching to single-stream.");
                                        // switching plan → reset watchdog baseline
                                        _lastProgressUtc = DateTime.UtcNow; // use the same timestamp your watchdog compares against

                                        try
                                        {
                                            var h = remoteUrl?.Host;
                                            if (!string.IsNullOrEmpty(h))
                                            {
                                                // cool the edge briefly so the next ranged attempt later in the run can pick a different host
                                                try { EdgeCooldown(h, TimeSpan.FromMinutes(5)); } catch { }
                                                // do NOT add to _noRangeHosts here; avoid per-run stickiness
                                                try { _range200?.Add(h); } catch { /* best-effort */ } // remember this incident for metrics/once-logs only
                                                if (string.Equals(_pinnedRangeHost, h, StringComparison.OrdinalIgnoreCase)) _pinnedRangeHost = null;
                                            }
                                        }
                                        catch { }
                                        return false;



                                        // Fall through: segmented disabled; continue to same-host single-stream below (no rotate, no early return).

                                    }

                                    else
                                    {
                                        // ---- Success branch ----
                                        try
                                        {
                                            // Thumbnails disabled — intentional no-op.

                                        }
                                        catch { /* non-fatal */ }
                                        // ensure segmented save produced a valid frame; else delete & retry
                                        try
                                        {
                                            // Segmented path succeeded — fully unban this host
                                            if (!string.IsNullOrEmpty(remoteUrl?.Host))
                                            {
                                                lock (_noRangeHosts)
                                                {
                                                    var h = remoteUrl.Host;
                                                    _noRangeHosts.Remove(h);
                                                    /* range200 retired */
                                                    try { Log($"[EDGE.ROTATE] unban → {h} (segmented success)"); } catch { }
                                                }
                                            }
                                            return true;



                                        }

                                        catch { /* best-effort */ }

                                        bool haveSize = false;
                                        string human = "";
                                        try
                                        {
                                            long bytes = new FileInfo(finalPath).Length;
                                            human = bytes >= (1024 * 1024)
                                                ? $"{bytes / (1024.0 * 1024.0):0.0} MB"
                                                : $"{bytes / 1024.0:0} KB";
                                            haveSize = true;
                                        }
                                        catch { /* best-effort */ }

                                        Log($"[VID.FINISH] segmented join/verify OK{(haveSize ? " " + human : "")} → {finalPath}");
                                        // cleanup any quarantined copy
                                        try { var bad = finalPath + ".bad"; if (System.IO.File.Exists(bad)) System.IO.File.Delete(bad); } catch { }
                                        // robust cleanup of leftover temp parts (segmented)
                                        try
                                        {
                                            var dir = System.IO.Path.GetDirectoryName(finalPath) ?? "";
                                            var leaf = System.IO.Path.GetFileName(finalPath);

                                            // common temp patterns from segmented writes
                                            foreach (var p in System.IO.Directory.EnumerateFiles(dir, leaf + ".part*", System.IO.SearchOption.TopDirectoryOnly))
                                                TryDeleteWithRetry(p);

                                            foreach (var p in System.IO.Directory.EnumerateFiles(dir, leaf + ".seg.*", System.IO.SearchOption.TopDirectoryOnly))
                                                TryDeleteWithRetry(p);
                                        }
                                        catch { /* ignore */ }


                                        _sumVidsOk++;
                                        _hadDownloads = true;
                                        _jitterScore = Math.Max(0, _jitterScore - 2);
                                        AdjustHealthOnSuccess();
                                        EndCurrentFileProgress();

                                        // Post-save inflight cleanup (no quick index here; de-dup/IndexUpsert handles canonical)
                                        try
                                        {
                                            // intentionally empty
                                        }
                                        finally
                                        {
                                            if (_qRegistered && _qKey != null) _inflightQuick.TryRemove(_qKey, out _);
                                            _qRegistered = false; _qKey = null; _qLen = 0; _qHash64k = null;
                                            // clear global-queue inflight guard for this item
                                            try
                                            {
                                                if (_globalQueueMode)
                                                {
                                                    var __core = matchKey
                                                    ?? (assetKind == "VID" ? VideoKeyFromUrl(remoteUrl)
                                                                           : (ImageKey(remoteUrl.ToString()) ?? remoteUrl.ToString()));

                                                    var __qk = (assetKind == "VID" ? "V:" : "I:") + __core;
                                                    _inflightQ.TryRemove(__qk, out _);
                                                }
                                            }
                                            catch { }

                                        }

                                        // Temp-only: delete staging file if present (robust cleaner already purged *.part*/.seg.*)
                                        try
                                        {
                                            if (!string.IsNullOrEmpty(tempPath) && System.IO.File.Exists(tempPath))
                                            {
                                                try { System.IO.File.Delete(tempPath); }
                                                catch
                                                {
                                                    // optional: mild retry if you added TryDeleteWithRetry
                                                    // TryDeleteWithRetry(tempPath);
                                                }
                                            }
                                        }
                                        catch { /* ignore */ }


                                        // (+) POST-DOWNLOAD DE-DUP (segmented): mirror single-stream behavior
                                        try
                                        {
                                            string full = await ComputeFileSha256Async(finalPath, ct).ConfigureAwait(false);
                                            long len = new FileInfo(finalPath).Length;
                                            string h64k = await ComputeFirst64kSha256FromFileAsync(finalPath, ct).ConfigureAwait(false);
                                            string canonical = finalPath;

                                            if (IndexTryGetByFull(full, out var existing) && File.Exists(existing) &&
                                                !string.Equals(existing, finalPath, StringComparison.OrdinalIgnoreCase))
                                            {
                                                // Duplicate of an existing file — drop the new one; keep the canonical
                                                try { File.Delete(finalPath); } catch { }
                                                TryDeleteIfEmpty(System.IO.Path.GetDirectoryName(finalPath) ?? "");
                                                _sumDedupLinks++;
                                                canonical = existing;
                                                Log($"[DEDUP] Duplicate detected — skipping new file; already have {System.IO.Path.GetFileName(existing)}");
                                            }

                                            // Upsert/refresh FULL map only if changed; then dirty/save
                                            bool __idxChanged = false;
                                            try
                                            {
                                                lock (_idxFull)
                                                {
                                                    if (!_idxFull.TryGetValue(full, out var __oldF) ||
                                                        !string.Equals(__oldF, canonical, StringComparison.OrdinalIgnoreCase))
                                                    {
                                                        __idxChanged = true;
                                                    }
                                                }

                                                if (__idxChanged)
                                                {
                                                    // IndexUpsert should update FULL ONLY (no quick writes)
                                                    IndexUpsert(len, h64k, full, canonical);

                                                    IndexMarkDirty();
                                                    if (_optSaveIndexPerFile)
                                                        await SaveMediaIndexAsync().ConfigureAwait(false);
                                                }
                                            }
                                            catch { /* ignore index errors */ }


                                        }
                                        catch { /* ignore index errors */ }

                                        return true;
                                    }



                                }

                            }
                            else
                            {
                                if (__resumePreferred)
                                {
                                    // We are choosing single-stream ONLY to resume .part; Range may still be supported.
                                    Log("[SEG] .part present — single-stream resume (keeping Range enabled for host).");
                                    // Do NOT add host to _noRangeHosts here.
                                }
                                else
                                {
                                    // Log once per host to avoid spam (HashSet + lock for thread safety).
                                    var host = remoteUrl?.Host;

                                    if (string.IsNullOrWhiteSpace(host))
                                    {
                                        if (!_loggedNoRangeOnce)
                                        {
                                            Log("[SEG] Server has no Range support || size unknown — single-stream fallback.");
                                            _loggedNoRangeOnce = true;
                                        }
                                    }
                                    else
                                    {
                                        bool firstForHost;
                                        lock (_noRangeHosts)
                                        {
                                            // DO NOT add here; just detect if we've ever banned this host
                                            firstForHost = !_noRangeHosts.Contains(host);
                                            if (firstForHost && string.Equals(_pinnedRangeHost, host, StringComparison.OrdinalIgnoreCase))
                                                _pinnedRangeHost = null;
                                        }


                                        // PATCH C — capacity-aware fallback: don't ban on cap-hit
                                        if (__segCapHit)
                                        {
                                            try { Log("[SEG] cap-hit → single-stream (no ban)"); } catch { }
                                        }
                                        else
                                        {
                                            if (firstForHost)
                                            {
                                                // If we recently proved Range OK, don't print the scary message
                                                if (!(_rangeSupportByHost.TryGetValue(host, out var __rangeOK) && __rangeOK))
                                                    try { Log($"[SEG] {host} has no Range support || size unknown — single-stream fallback."); } catch { }
                                                else
                                                    try { if (s_ShouldLogOnce?.Invoke($"seg.msg.cap:{host}", 20) == true) Log($"[SEG] {host} Range OK recently — single-stream due to capacity/policy"); } catch { }
                                            }

                                            // No ban here — this path is policy/capacity, not a Range failure.
                                        }

                                        // (then continue into your single-stream path)

                                    }
                                }
                            }

                            // R1: rotation disabled — keep same host for SS
                            // REPLACE your block with this (no `url` needed)
                            if (__segRetryDueToWriteFail)
                            {
                                __segRetryDueToWriteFail = false; // consume the flag

                                // Hop to next edge and pin it for the immediate retry
                                if (_edge is { } e)
                                {
                                    try { e.HopNext(); } catch { }
                                    var nh = e.ResolveHostForNewDownload();
                                    if (!string.IsNullOrEmpty(nh))
                                    {
                                        try { _pinnedRangeHost = nh; Log($"[SEG] write-fail: pin retry to {nh}"); } catch { }
                                    }
                                }

                                goto __SEG_RETRY_ONCE; // label must exist above
                            }




                        }



                    // Single-stream path (IMG/ZIP, || video fallback) //
                    SS_FALLBACK:;

                        int perAttemptSeconds =
                            assetKind == "VID" ? Math.Max(120, 75 + (attempt * 30)) :
                            smallImage ? Math.Min(60, 45 + (attempt * 15)) :
                            Math.Min(150, 75 + (attempt * 30));

                        // compute resume offset from temp file

                        long resumeOffset = 0;
                        // expected size for single-stream; used if we cancel mid-download
                        long __ssExpected = Math.Max(_qLen, 0);

                        bool wantResume = assetKind == "VID" && File.Exists(tempPath);
                        if (wantResume)
                        {
                            try { resumeOffset = new System.IO.FileInfo(tempPath).Length; }
                            catch { resumeOffset = 0; }

                            // Only resume if we already have at least 100 MB on disk.
                            if (resumeOffset > 0 && resumeOffset < SS_RESUME_MIN_BYTES)
                            {
                                try
                                {
                                    Log($"[SS.RESUME] partial {resumeOffset:N0}B below {SS_RESUME_MIN_BYTES:N0}B — restarting from scratch");
                                }
                                catch { }

                                try { System.IO.File.Delete(tempPath); } catch { }
                                resumeOffset = 0;
                                wantResume = false;
                            }
                        }
                        // align resume to 4 MiB CDN window //
                        const long WINDOW = 4L * 1024 * 1024;
                        if (resumeOffset > 0) resumeOffset = (resumeOffset / WINDOW) * WINDOW;


                        // Quick preflight for GIFs to avoid queuing placeholders that 404 //
                        if (assetKind == "IMG" && string.Equals(Path.GetExtension(finalPath), ".gif", StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                using var head = new HttpRequestMessage(HttpMethod.Head, remoteUrl);
                                using var headRes = await _http.SendAsync(head, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                                if (!headRes.IsSuccessStatusCode)
                                {
                                    Log($"[GONE] GIF HEAD {((int)headRes.StatusCode)} → {Path.GetFileName(finalPath)} (skip enqueue)");
                                    bailNotFound = headRes.StatusCode == System.Net.HttpStatusCode.NotFound
                                                   || headRes.StatusCode == System.Net.HttpStatusCode.Gone;
                                    return false; // don’t waste retries on preview GIFs
                                }
                                var len = headRes.Content?.Headers?.ContentLength ?? 0;
                                var ctype = headRes.Content?.Headers?.ContentType?.MediaType ?? "";
                                if (len <= 0 || !ctype.Contains("gif", StringComparison.OrdinalIgnoreCase))
                                {
                                    Log($"[TRASH] GIF preflight rejected (len={len}, type={ctype}) → {Path.GetFileName(finalPath)}");
                                    return false;
                                }
                            }
                            catch (Exception hx)
                            {
                                Log("[GIF] preflight failed: " + hx.Message); // proceed; main GET path will handle //
                            }
                        }


                        if (_stopImmediate || ct.IsCancellationRequested) { try { Log("[STOP] immediate — abort single-stream"); } catch { } return false; }
                        // if current host is tagged no-range, hop once before SS GET
                        if (!string.IsNullOrEmpty(remoteUrl?.Host) && (_noRangeHosts.Contains(remoteUrl.Host) || HostInCooldown(remoteUrl.Host) || GetHostScore(remoteUrl.Host) <= -2))
                        {
                            var oldHost = remoteUrl.Host;
                            if (_edge is { } edgePre)
                            {
                                edgePre.HopNext();
                                var nextHost = edgePre.ResolveHostForNewDownload();
                                if (!string.IsNullOrEmpty(nextHost) && !string.Equals(nextHost, oldHost, StringComparison.OrdinalIgnoreCase))
                                {
                                    try { remoteUrl = edgePre.RewriteUriHost(remoteUrl, nextHost); } catch { }
                                    try { Log($"[SS.PREHOP] {oldHost} → {nextHost} (no-range tag)"); } catch { }
                                }
                            }
                        }
                        // if current host is tagged no-range, hop once before SS GET (IMG/ZIP/VID fallback)
                        if (!string.IsNullOrEmpty(remoteUrl?.Host) && (_noRangeHosts.Contains(remoteUrl.Host) || HostInCooldown(remoteUrl.Host) || GetHostScore(remoteUrl.Host) <= -2))
                        {
                            var oldHost = remoteUrl.Host;
                            if (_edge is { } edgePre)
                            {
                                edgePre.HopNext();
                                var nextHost = edgePre.ResolveHostForNewDownload();
                                if (!string.IsNullOrEmpty(nextHost) && !string.Equals(nextHost, oldHost, StringComparison.OrdinalIgnoreCase))
                                {
                                    try { remoteUrl = edgePre.RewriteUriHost(remoteUrl, nextHost); } catch { }
                                    try { Log($"[SS.PREHOP] {oldHost} → {nextHost} (no-range tag)"); } catch { }
                                }
                                // SS path is about to begin → mark Working once
                                try
                                {
                                    var __id = _qKey ?? finalPath ?? Guid.NewGuid().ToString("n");
                                    CMDownloaderUI.QueueTap.MoveToWorking(__id, 0, 0);
                                }
                                catch { }

                            }
                        }
                        // after repeated SS failures for mid-size vids, hop once before the next try
                        // Trigger: attempt == 3 (after two SS fails), size in 64–200 MiB, and we have an edge to hop.
                        if (string.Equals(assetKind, "VID", StringComparison.Ordinal))
                        {
                            long sz = Math.Max(_qLen, 0); // known length if available
                            if (attempt == 3 && sz >= (64L << 20) && sz <= (200L << 20) &&
                                !string.IsNullOrEmpty(remoteUrl?.Host) && _edge is { } edgeRetry)
                            {
                                var oldHost = remoteUrl.Host;
                                try { edgeRetry.HopNext(); } catch { }
                                var nextHost = edgeRetry.ResolveHostForNewDownload();
                                if (!string.IsNullOrEmpty(nextHost) &&
                                    !string.Equals(nextHost, oldHost, StringComparison.OrdinalIgnoreCase))
                                {
                                    try { remoteUrl = edgeRetry.RewriteUriHost(remoteUrl, nextHost); } catch { }
                                    try { Log($"[SS.MID.HOP] {oldHost} → {nextHost} after {attempt - 1} SS failures ({sz >> 20} MiB)"); } catch { }
                                }
                            }
                        }

                        // capture server behavior before 3rd SS try (mid-size vids)
                        try
                        {
                            if (string.Equals(assetKind, "VID", StringComparison.Ordinal) && attempt == 3 && Math.Max(_qLen, 0) >= (64L << 20))
                                if (!s_NoRangeThisRun)
                                {
                                    try
                                    {
                                        var __h = remoteUrl.Host;
                                        if (!_noRangeHosts.Contains(__h))
                                            await ProbeEdgeAsync(remoteUrl, ct);
                                    }
                                    catch { /* best-effort */ }
                                }
                        }
                        catch { /* best-effort */ }
                        using var req = new HttpRequestMessage(HttpMethod.Get, remoteUrl);

                        // force single-stream to H/1.1 (avoid H/2 resets)
                        req.Version = System.Net.HttpVersion.Version11;
                        req.VersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionOrLower;

                        // SS: identity encoding (resume-friendly), default keep-alive
                        try { req.Headers.AcceptEncoding.Clear(); req.Headers.AcceptEncoding.ParseAdd("identity"); } catch { }
                        req.Headers.ConnectionClose = false; // keep-alive

                        // Only add Range on resume (byte-true)
                        if (resumeOffset > 0 && req.Headers.Range == null)
                            req.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(resumeOffset, null);

                        // Normalize after we set our knobs
                        NormalizeDownloadRequest(req);

                        // Single log (event-only) + counters (thread-safe)
                        var ssAe = string.Join(",", req.Headers.AcceptEncoding);
                        bool keepAlive = req.Headers.ConnectionClose != true;

                        System.Threading.Interlocked.Increment(ref _ssSendTotal);

                        var sig = $"{req.Version}|{req.VersionPolicy}|{ssAe}|{keepAlive}";

                        bool logIt = false;
                        lock (_ssSendLock)
                        {
                            if (!string.Equals(sig, _lastSsSig, StringComparison.Ordinal))
                            {
                                _lastSsSig = sig;
                                logIt = true;
                            }
                            else
                            {
                                System.Threading.Interlocked.Increment(ref _ssSendSuppressed);
                            }
                        }

                        if (logIt)
                        {
                            Log($"[SS.SEND] v={req.Version} policy={req.VersionPolicy} ae={ssAe} keepalive={keepAlive}");
                        }



                        // On retries, don’t reuse a flaky pooled conn
                        if (attempt >= 2) req.Headers.ConnectionClose = true;



                        // If 'attempt' is definitely in scope here, keep the guard:
                        if (attempt > 1 && req.Headers.Range == null) EnsureIdentity(req);

                        // If you ever see 'attempt' not in scope on this build, use this instead:
                        // EnsureIdentity(req);


                        req.Version = (attempt >= 2 ? HttpVersion.Version11 : HttpVersion.Version20);
                        req.VersionPolicy = (attempt >= 2 ? HttpVersionPolicy.RequestVersionOrLower : HttpVersionPolicy.RequestVersionOrHigher);

                        try { req.Headers.AcceptEncoding.Clear(); req.Headers.AcceptEncoding.ParseAdd("identity"); } catch { }

                        // apply Range only when resuming a single-lane GET
                        if (resumeOffset > 0)
                            req.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(resumeOffset, null);

                        NormalizeDownloadRequest(req);

                        // avoid compressed range bodies
                        req.Headers.AcceptEncoding.Clear();

                        var refUri = PickReferer(remoteUrl, referer);
                        if (refUri != null) req.Headers.Referrer = refUri;

                        // unified Range handling
                        bool tryRange = assetKind == "VID" && !_noRangeHosts.Contains(remoteUrl.Host) && !s_NoRangeThisRun;
                        if (tryRange && resumeOffset > 0) { req.Headers.Range = new RangeHeaderValue(resumeOffset, null); }
                        else if (tryRange && attempt > 0 && resumeOffset == 0) { req.Headers.Range = new RangeHeaderValue(0, null); }

                        // stabilize large single-stream video downloads
                        if (assetKind == "VID" && (!tryRange || _noRangeHosts.Contains(remoteUrl.Host) || s_NoRangeThisRun))
                        {
                            try
                            {
                                // H/2 first for SS; single fallback to H/1.1 on retry
                                req.Version = (attempt >= 2 ? System.Net.HttpVersion.Version11 : System.Net.HttpVersion.Version20);
                                req.VersionPolicy = (attempt >= 2 ? System.Net.Http.HttpVersionPolicy.RequestVersionOrLower
                                                                  : System.Net.Http.HttpVersionPolicy.RequestVersionOrHigher);

                                // Avoid compressed responses on big binaries (length accounting & stalls)
                                req.Headers.AcceptEncoding.Clear();
                                req.Headers.AcceptEncoding.ParseAdd("identity");

                                // Keep connection alive; don’t force Connection: close
                                req.Headers.ConnectionClose = false;

                                // Optional: avoid 100-Continue delays
                                req.Headers.ExpectContinue = false;
                            }
                            catch { /* best-effort; safe to ignore if a property isn't supported */ }
                        }


                        // Size-based timeout for large, single-stream video pulls (no probe needed)
                        if (assetKind == "VID" && (!tryRange || _noRangeHosts.Contains(remoteUrl?.Host ?? "") || s_NoRangeThisRun))
                        {
                            const double SS_MBPS_FLOOR = 1.2; // ~1.2 MB/s floor
                            const int SS_TIMEOUT_MAX = 3600; // cap at 1 hour
                            const int SS_TIMEOUT_BASE = 8; // base seconds

                            long __len = (_qLen > 0 ? _qLen : 0); // use quick-length hint if available
                            if (__len > 0)
                            {
                                double __mb = __len / (1024d * 1024d);
                                int __min = (int)Math.Ceiling(SS_TIMEOUT_BASE + (__mb / SS_MBPS_FLOOR));
                                if (perAttemptSeconds < __min) perAttemptSeconds = Math.Min(SS_TIMEOUT_MAX, __min);
                            }
                        }

                        // one-time segmented retry support
                        bool __segZeroRetryOnce = false;

                        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                        linkedCts.CancelAfter(TimeSpan.FromSeconds(perAttemptSeconds));
                        using var res = await _http.SendAsync(
                            req, HttpCompletionOption.ResponseHeadersRead, linkedCts.Token
                        ).ConfigureAwait(false);
                        // early non-video abort on first slice (scope-safe)


                        {
                            var __u = req.RequestUri; // per-slice request you just sent
                            var __ct = res.Content.Headers.ContentType?.MediaType?.ToLowerInvariant() ?? "";

                            // First-slice detection via Content-Range (or absent CR = some edges reply 200)
                            var __cr = res.Content.Headers.ContentRange;
                            bool __firstSlice = (__cr == null) || ((__cr.From ?? 0) == 0);

                            if (__firstSlice)
                            {
                                bool __urlLooksVideo =
                                    __u != null && (
                                        __u.AbsolutePath.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) ||
                                        __u.AbsolutePath.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase) ||
                                        __u.AbsolutePath.EndsWith(".mov", StringComparison.OrdinalIgnoreCase) ||
                                        __u.AbsolutePath.EndsWith(".webm", StringComparison.OrdinalIgnoreCase) ||
                                        __u.AbsolutePath.EndsWith(".mkv", StringComparison.OrdinalIgnoreCase)
                                    );

                                var __cd = res.Content.Headers.ContentDisposition;
                                var __cdName = __cd?.FileNameStar ?? __cd?.FileName ?? "";
                                bool __cdLooksVideo =
                                    !string.IsNullOrEmpty(__cdName) && (
                                        __cdName.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) ||
                                        __cdName.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase) ||
                                        __cdName.EndsWith(".mov", StringComparison.OrdinalIgnoreCase) ||
                                        __cdName.EndsWith(".webm", StringComparison.OrdinalIgnoreCase) ||
                                        __cdName.EndsWith(".mkv", StringComparison.OrdinalIgnoreCase)
                                    );

                                bool __isObviouslyNonVideo =
                                    __ct.StartsWith("image/") || __ct.StartsWith("text/") ||
                                    __ct == "application/json" || __ct == "application/xml";

                                if ((__urlLooksVideo || __cdLooksVideo) && __isObviouslyNonVideo)
                                {
                                    res.Dispose();
                                    try { Log("[CT→RETRY] SEG non-video on first slice — nudging segmented on next attempt"); } catch { }
                                    System.Threading.Volatile.Write(ref __preferSegmentedNextTry, true);
                                    // If the segmented retry label is in scope here, use it and delete the throw:
                                    // goto __SEG_RETRY_ONCE;
                                    throw new IOException("Non-video content-type on SEG; retry segmented");

                                }
                            }
                        }

                        // Refine timeout using actual Content-Length if available
                        var __hdrLen = res.Content?.Headers?.ContentLength ?? -1L;
                        if (assetKind == "VID" && __hdrLen > 0 && (!tryRange || _noRangeHosts.Contains(remoteUrl.Host) || s_NoRangeThisRun))
                        {
                            double __mb = __hdrLen / (1024d * 1024d);
                            int __min = (int)Math.Ceiling(8 + (__mb / 1.2));
                            int __target = Math.Min(3600, Math.Max(perAttemptSeconds, __min));
                            linkedCts.CancelAfter(TimeSpan.FromSeconds(__target)); // OK to update
                        }

                        // detect hosts that ignore Range with 200
                        bool __rotateOn200 = tryRange && res.StatusCode == HttpStatusCode.OK;
                        if (__rotateOn200)
                        {
                            // Only rotate/ban if seg-eligible; use best hint available here: _qLen
                            long __lenHint = (_qLen > 0) ? _qLen : 0;
                            bool __segEligible = __lenHint >= MIN_SEGMENT_BYTES;
                            var __h = remoteUrl?.Host; // host (null-safe)

                            if (__segEligible)
                            {
                                // ban this host for range this run + edge scoring
                                lock (_noRangeHosts) _noRangeHosts.Add(remoteUrl.Host);
                                try { BumpHostScore(remoteUrl.Host, -3); StartCooldown(remoteUrl.Host); } catch { }
                                try { if (!string.IsNullOrEmpty(__h)) HostRangeScore_Add(__h, -1); } catch { } // ss-only nudge (optional)

                                if (string.Equals(_pinnedRangeHost, remoteUrl.Host, StringComparison.OrdinalIgnoreCase))
                                    _pinnedRangeHost = null;

                                if (false) /* range200 retired */
                                {
                                    _edge?.HopNext(); // force the next rewrite to a different edge
                                    Log("[RANGE] 200 on Range — rotating away from this host");
                                    try { if (!string.IsNullOrEmpty(__h)) HostRangeScore_Add(__h, -1); } catch { } // (optional)
                                }
                            }
                            else
                            {
                                // Small file: don't rotate || ban
                                if (string.Equals(_pinnedRangeHost, remoteUrl.Host, StringComparison.OrdinalIgnoreCase))
                                    _pinnedRangeHost = null;

                                // (was: Log("[RANGE] 200 on Range (small file) — not rotating");)

                                try { if (!string.IsNullOrEmpty(__h)) HostRangeScore_Add(__h, -1); } catch { } // (optional)
                            }

                        }




                        // Minimal fix B — Single fallback swap on 404
                        if (assetKind == "VID" && res.StatusCode == HttpStatusCode.NotFound)
                        {
                            try { BumpHostScore(remoteUrl.Host, -2); StartCooldown(remoteUrl.Host); } catch { }

                            // If the pinned host 404'd, drop the pin
                            if (res.StatusCode == System.Net.HttpStatusCode.NotFound &&
                                !string.IsNullOrEmpty(_pinnedRangeHost) &&
                                string.Equals(_pinnedRangeHost, remoteUrl.Host, StringComparison.OrdinalIgnoreCase))
                            {
                                _pinnedRangeHost = null;
                                try { if (s_ShouldLogOnce?.Invoke("edge.unpin404", 60) == true) Log("[EDGE.PIN] unpin ← 404 on pinned host"); } catch { }
                            }

                            var alt = SwapCoomerEdgeOnce(remoteUrl);
                            if (alt != null)
                            {
                                // Only ban on 200-on-Range when this asset qualifies for segmentation
                                bool __minBytesForRange = false;
                                try { __minBytesForRange = _qLen >= MIN_SEGMENT_BYTES; } catch { /* best-effort */ }

                                if (__rotateOn200 && __minBytesForRange)
                                {
                                    try
                                    {
                                        if (_qLen >= MIN_SEGMENT_BYTES) { lock (_noRangeHosts) _noRangeHosts.Add(remoteUrl.Host); }
                                    }
                                    catch { /* best-effort */ }
                                }

                                Log($"[FALLBACK] {(__rotateOn200 ? "200-on-Range" : "404")} on {remoteUrl.Host} → retrying on {alt.Host}");

                                // size-gate the fallback candidate before issuing GET
                                const long __MIN_VIDEO_BYTES = MIN_VIDEO_BYTES;
                                var __sz = await TryProbeSizeAsync(alt, linkedCts.Token).ConfigureAwait(false);
                                if (!__sz.HasValue || __sz.Value < __MIN_VIDEO_BYTES)
                                {
                                    double __mb = __sz.HasValue ? (__sz.Value / (1024.0 * 1024.0)) : 0.0;
                                    Log($"[FALLBACK] reject tiny candidate {__mb:0.0} MB; skipping.");
                                    res.Dispose();
                                    return false; // skip this asset: fallback candidate is too small
                                }




                                res.Dispose();

                                using var req2 = new HttpRequestMessage(HttpMethod.Get, alt);
                                var ref2 = PickReferer(alt, referer);
                                if (ref2 != null) req2.Headers.Referrer = ref2;

                                // only send Range on alt host if it's not flagged
                                if (resumeOffset > 0 && !_noRangeHosts.Contains(alt.Host))
                                    req2.Headers.Range = new RangeHeaderValue(resumeOffset, null);
                                else if (attempt > 0 && !_noRangeHosts.Contains(alt.Host))
                                    req2.Headers.Range = new RangeHeaderValue(0, null);
                                EnsureIdentityIfRanged(req2);

                                req2.Version = HttpVersion.Version20;
                                req2.VersionPolicy = HttpVersionPolicy.RequestVersionOrHigher;


                                // reissue the request once on the alternate edge
                                var resAlt = await _http.SendAsync(req2, HttpCompletionOption.ResponseHeadersRead, linkedCts.Token).ConfigureAwait(false);

                                // rebind `res` so the rest of the method flows as-is
                                res.Dispose(); // safeguard (res already disposed above; harmless if called twice)
                                               // NOTE: we can’t write `using var` here because we’re replacing an existing using-var.
                                               // So just reassign; the using-dispose at scope end will run on the current `res`.
                                System.Runtime.CompilerServices.Unsafe.AsRef(res) = resAlt; // minimal trick to rebind using-var
                                remoteUrl = alt; // so later logs/handlers reflect the URL we actually used
                            }
                        }


                        // If we asked for Range but server replied 200 OK, it ignored Range → remember that host
                        if (req.Headers.Range != null && res.StatusCode == HttpStatusCode.OK)
                        {
                            // Only disable Range for seg-eligible files; tiny files keep it quiet.
                            bool __segElig_local = (_qLen >= MIN_SEGMENT_BYTES);

                            if (__segElig_local)
                            {
                                try { Log($"[RANGE] Host ignored Range; disabling Range for {remoteUrl.Host}"); } catch { }
                            }
                            else
                            {
                                try { Log("[RANGE] Host ignored Range (small file) — not disabling"); } catch { }
                            }

                            // Track the 200-on-Range event either way
                            /* range200 retired */
                            // Unpin if the pinned edge just ignored Range (200)
                            if (string.Equals(_pinnedRangeHost, remoteUrl.Host, StringComparison.OrdinalIgnoreCase))
                            {
                                _pinnedRangeHost = null;
                                try { if (s_ShouldLogOnce?.Invoke("edge.unpin200", 60) == true) Log($"[EDGE.PIN] unpin ← {remoteUrl.Host} (ignored Range)"); } catch { }
                            }
                        }


                        // Pin on first positive 206 response (confirms real Range support)
                        if (req.Headers.Range != null
                            && res.StatusCode == HttpStatusCode.PartialContent
                            && string.IsNullOrEmpty(_pinnedRangeHost)
                            && !_noRangeHosts.Contains(remoteUrl.Host)) // skip hosts we've gated as no-range
                        {
                            if (!NATURAL_URL_ONLY)
                            {
                                _pinnedRangeHost = remoteUrl.Host;
                                try { if (s_ShouldLogOnce?.Invoke("edge.pin", 60) == true) Log($"[EDGE.PIN] pin → {_pinnedRangeHost} (download path)"); } catch { }
                            }
                        }









                        int statusInt = (int)res.StatusCode;
                        if (statusInt >= 500 && statusInt <= 599) { was5xxThisAttempt = true; throw new HttpRequestException($"Server error {statusInt}", null, res.StatusCode); }

                        if (res.StatusCode == HttpStatusCode.RequestedRangeNotSatisfiable && assetKind == "VID" && resumeOffset > 0)
                        {
                            var head = await TryProbeSizeAsync(remoteUrl, ct).ConfigureAwait(false);
                            // safeguard: video extensions must route to VideoRoot
                            if (".mp4 .m4v .mov .avi .mkv .webm".Contains(Path.GetExtension(finalPath).ToLowerInvariant())
                                && finalPath.StartsWith(ImagesRoot, StringComparison.OrdinalIgnoreCase))
                            {
                                finalPath = Path.Combine(VideoRoot, Path.GetFileName(finalPath));
                            }

                            if (head.HasValue && head.Value == resumeOffset && File.Exists(tempPath))
                            {
                                await MoveWithSmallRetriesAsync(tempPath, finalPath, 4, ct).ConfigureAwait(false);


                                // Quick integrity check for videos when server length is unknown //
                                if (assetKind == "VID")
                                {
                                    // 1) HEAD for Content-Length //
                                    var _h = await TryProbeSizeAsync(remoteUrl, ct).ConfigureAwait(false);
                                    long __len = new FileInfo(finalPath).Length;
                                    bool __ok = _h.HasValue && _h.Value == __len;

                                    // 2) If HEAD didn't help, try a 0-0 Range probe to learn total from Content-Range //
                                    if (!__ok)
                                    {
                                        try
                                        {
                                            using var __req = new HttpRequestMessage(HttpMethod.Get, remoteUrl);
                                            if (attempt > 1 && __req.Headers.Range == null) EnsureIdentity(__req);

                                            __req.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 0);
                                            using var __res = await _http.SendAsync(__req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                                            var __cr = __res.Content?.Headers?.ContentRange;
                                            if (__res.StatusCode == System.Net.HttpStatusCode.PartialContent && __cr?.Length is long L && L > 0)
                                                __ok = (L == __len);
                                        }
                                        catch { /* ignore */ }
                                    }

                                    // 3) MP4 sanity: 'ftyp' at offset 4, readable tail, and (for MP4) moov/moof present
                                    try
                                    {
                                        using var __fs = new FileStream(finalPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                                        if (__fs.Length >= 24)
                                        {
                                            // cheap header: 'ftyp' at offset 4
                                            byte[] __head = new byte[12];
                                            bool __hasFtyp = __fs.Read(__head, 0, __head.Length) >= __head.Length &&
                                                             __head[4] == (byte)'f' && __head[5] == (byte)'t' &&
                                                             __head[6] == (byte)'y' && __head[7] == (byte)'p';

                                            // cheap tail: ensure we can read a few bytes at the end
                                            __fs.Seek(Math.Max(0, __fs.Length - 16), SeekOrigin.Begin);
                                            byte[] __tailBytes = new byte[16];
                                            bool __tailReadable = __fs.Read(__tailBytes, 0, __tailBytes.Length) > 0;

                                            // structure: for MP4-family, require moov/moof (front || tail)
                                            var __fe = Path.GetExtension(finalPath);
                                            bool __isMp4Fam = string.Equals(__fe, ".mp4", StringComparison.OrdinalIgnoreCase)
                                                           || string.Equals(__fe, ".m4v", StringComparison.OrdinalIgnoreCase)
                                                           || string.Equals(__fe, ".mov", StringComparison.OrdinalIgnoreCase)
                                                           || string.Equals(__fe, ".ismv", StringComparison.OrdinalIgnoreCase);
                                            bool __structureOk = !__isMp4Fam || HasMoovOrMoofHeadTail(finalPath);
                                            if (__isMp4Fam && !__structureOk)
                                                try { Log("[VERIFY] mp4/m4v/mov missing moov/moof — rejecting"); } catch { }


                                            // final verdict for this stage — AND into __ok so failures stick
                                            bool __sanityOk = __hasFtyp && __tailReadable && __structureOk;
                                            __ok = __ok && __sanityOk;
                                        }
                                    }
                                    catch
                                    {
                                        __ok = false;
                                        try { Log("[INTEGRITY] exception during sanity check"); } catch { }
                                    }



                                    if (!__ok)
                                    {
                                        // give FS/AV a moment, then re-check size parity once
                                        if (_qLen > 0)
                                        {
                                            await Task.Delay(750).ConfigureAwait(false);
                                            try
                                            {
                                                var __fi = new FileInfo(finalPath);
                                                if (__fi.Exists && __fi.Length == _qLen) __ok = true; // size-parity backstop (restat)
                                            }
                                            catch { /* ignore */ }
                                        }

                                        if (!__ok && _qLen > 0)
                                        {
                                            // if we're only missing a *small* tail, try a single Range-append heal (≤8 MiB)
                                            try
                                            {
                                                long __actual = 0;
                                                try { __actual = new FileInfo(finalPath).Length; } catch { __actual = 0; }
                                                long __missing = _qLen - __actual;

                                                if (__actual >= 0 && __missing > 0 && __missing <= (8L * 1024 * 1024) && remoteUrl is { } && _http is { })
                                                {
                                                    using var __req = new HttpRequestMessage(HttpMethod.Get, remoteUrl);
                                                    __req.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(__actual, null); // tail
                                                    try { __req.Headers.AcceptEncoding.Clear(); __req.Headers.AcceptEncoding.ParseAdd("identity"); } catch { }
                                                    __req.Version = System.Net.HttpVersion.Version11;
                                                    __req.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;

                                                    using var __res = await _http.SendAsync(__req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                                                    if ((int)__res.StatusCode == 206 || (int)__res.StatusCode == 200) // some edges ignore Range but still send whole body
                                                    {
                                                        TraceAnyWrite(finalPath, -1, "VID.APPEND.MERGE");
                                                        await using (var __dst = new FileStream(finalPath, FileMode.Append, FileAccess.Write, FileShare.Read, 1 << 16, useAsync: true))
                                                        await using (var __src = await __res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
                                                        {
                                                            await __src.CopyToAsync(__dst, 1 << 16, ct).ConfigureAwait(false);
                                                        }
                                                        // quick re-verify by size
                                                        try
                                                        {
                                                            var __after = new FileInfo(finalPath).Length;
                                                            if (__after == _qLen) __ok = true;
                                                        }
                                                        catch { /* ignore */ }
                                                    }
                                                }
                                            }
                                            catch { /* swallow heal attempt; we'll fall back */ }
                                        }

                                        if (!__ok)
                                        {
                                            await Task.Delay(250).ConfigureAwait(false); // let FS/AV settle

                                            // move bad file out of the way first
                                            try
                                            {
                                                var __dir = Path.GetDirectoryName(finalPath) ?? "";
                                                var __qDir = Path.Combine(__dir, "_quarantine");
                                                Directory.CreateDirectory(__qDir);

                                                var __qPath = Path.Combine(__qDir, Path.GetFileName(finalPath));

                                                // media: try move; else copy+delete
                                                try { File.Move(finalPath, __qPath, true); }
                                                catch { try { File.Copy(finalPath, __qPath, true); File.Delete(finalPath); } catch { } }

                                                // sidecar: try move; else copy+delete
                                                var _m = finalPath + ".ok";
                                                if (File.Exists(_m))
                                                {
                                                    var _mq = __qPath + ".ok";
                                                    try { File.Move(_m, _mq, true); }
                                                    catch { try { File.Copy(_m, _mq, true); File.Delete(_m); } catch { } }
                                                }

                                                try { Log($"[VERIFY.FAIL] SS tail appears bad — moved to quarantine: {__qPath}"); } catch { }
                                            }
                                            catch { /* best-effort quarantine */ }


                                            // (optional) plan next-hop here BEFORE throwing, if you want:
                                            // try {
                                            // if (_edge is { } edgeHopIF2b)
                                            // {
                                            // var oldHost = remoteUrl?.Host;
                                            // edgeHopIF2b.HopNext();
                                            // var nextHost = edgeHopIF2b.ResolveHostForNewDownload();
                                            // if (!string.IsNullOrEmpty(nextHost)) remoteUrl = edgeHopIF2b.RewriteUriHost(remoteUrl, nextHost);
                                            // Log($"[INTEGRITY] hop for next attempt: {oldHost} → {remoteUrl.Host}");
                                            // }
                                            // } catch { }

                                            throw new IOException("integrity verify failed");
                                        }

                                    }


                                }
                                long len = new FileInfo(finalPath).Length; string sizeStr = len >= (1024 * 1024) ? $"{len / (1024.0 * 1024.0):0.0} MB" : $"{len / 1024.0:0} KB";

                                Log($"[OK] {assetKind} saved (resumed, completed) {sizeStr} → {Path.GetFileName(finalPath)}");
                                // mark Done (OK – resumed/completed)
                                try
                                {
                                    var __id = _qKey ?? finalPath ?? Guid.NewGuid().ToString("n");
                                    CMDownloaderUI.QueueTap.MoveToDone(__id, ok: true);
                                }
                                catch { }

                                // mirror accept → web status
                                try
                                {
                                    if (string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase))
                                        CMDownloaderUI.Status.IncVidsOk();
                                    else if (string.Equals(assetKind, "IMG", StringComparison.OrdinalIgnoreCase))
                                        CMDownloaderUI.Status.IncImgsOk();

                                    long __bytes = 0;
                                    try { __bytes = new System.IO.FileInfo(finalPath).Length; } catch { }
                                    if (__bytes > 0) CMDownloaderUI.Status.AddBytesFetched(__bytes);
                                }
                                catch { }


                                long __okLen = new FileInfo(finalPath).Length;
                                if (string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase))
                                {
                                    try
                                    {
                                        var __okPath = finalPath + ".ok";
                                        TraceAnyWrite(__okPath, -1, "SIDE.OK.VID.META");

                                        File.WriteAllText(__okPath,
                                            $"len={__okLen};expected={(_qLen > 0 ? _qLen : -1)};h64={_qHash64k ?? string.Empty};ts={DateTime.UtcNow:O}",
                                            Encoding.UTF8);
                                    }
                                    catch { }

                                }

                                // — publish a sidecar "finished" marker
                                try
                                {
                                    long __actual = new FileInfo(finalPath).Length;
                                    long __expected = (_qLen > 0 ? _qLen : -1);
                                    string __h64 = _qHash64k ?? string.Empty;

                                    var __okPath = finalPath + ".ok";
                                    TraceAnyWrite(__okPath, -1, "SIDE.OK.FINAL");

                                    File.WriteAllText(__okPath,
                                        $"len={__actual};expected={__expected};h64={__h64};ts={DateTime.UtcNow:O}",
                                        Encoding.UTF8);
                                }
                                catch { /* best-effort */ }


                                // phase-2 quick-add winners only
                                try
                                {
                                    if (__okLen > 0 && !string.IsNullOrEmpty(_qHash64k))
                                        IndexAddQuick(__okLen, _qHash64k!, finalPath);
                                }
                                catch { /* best-effort */ }




                                // Unpeg current progress bar for images
                                if (string.Equals(assetKind, "IMG", StringComparison.OrdinalIgnoreCase))
                                {
                                    try { ResetCurrentProgressUI(); } catch { /* best-effort */ }
                                }

                                if (assetKind == "VID")
                                {
                                    try
                                    {
                                        // Post-save path no longer generates thumbnails || runs probes.

                                        try
                                        {
                                            var __h = remoteUrl?.Host; // if `remoteUrl` isn't in scope here, use the local `host`
                                            if (!string.IsNullOrEmpty(__h) &&
                                                _noRangeHosts.Remove(__h) &&
                                                (s_ShouldLogOnce?.Invoke($"range.recover:{__h}", 60) == true))
                                            {
                                                Log($"[RANGE.RECOVER] {__h} SS success — re-enabling segmentation");
                                                try { s_NoRangeThisRun = false; lock (_noRangeHosts) { _noRangeHosts.Remove(__h); _noRangeHosts.Remove("*.coomer.st"); } } catch { }

                                            }

                                            // Always remove the sidecar on SS success, regardless of unban/log-once
                                            try { File.Delete(finalPath + ".ok"); } catch { }
                                        }
                                        catch { /* best-effort */ }



                                        // Pin current edge after successful video save
                                        try { if (remoteUrl != null) { _pinnedRangeHost = remoteUrl.Host; Log($"[EDGE.PIN] seg-success → {_pinnedRangeHost}"); } } catch { }


                                        // heal short SS files if expected size is known (HEAD-based)
                                        try
                                        {
                                            long actual = new System.IO.FileInfo(finalPath).Length;
                                            long expected = -1;

                                            // Try to get the expected size via HEAD
                                            try
                                            {
                                                using var headReq = new HttpRequestMessage(HttpMethod.Head, remoteUrl);
                                                headReq.Headers.ConnectionClose = true;
                                                headReq.Version = System.Net.HttpVersion.Version11;
                                                headReq.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
                                                headReq.Headers.AcceptEncoding.Clear();

                                                using var headRes = await _http.SendAsync(headReq, HttpCompletionOption.ResponseHeadersRead, _cts.Token).ConfigureAwait(false);
                                                if (headRes.IsSuccessStatusCode)
                                                    expected = headRes.Content.Headers.ContentLength ?? -1;
                                            }
                                            catch { /* ignore HEAD failures */ }

                                            long missing = (expected > 0) ? (expected - actual) : 0;

                                            if (expected > 0 && missing > 0 && missing <= (8L * 1024 * 1024))
                                            {
                                                using var tailReq = new HttpRequestMessage(HttpMethod.Get, remoteUrl);

                                                tailReq.Version = System.Net.HttpVersion.Version11;
                                                tailReq.VersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionOrLower;
                                                try { tailReq.Headers.AcceptEncoding.Clear(); tailReq.Headers.AcceptEncoding.ParseAdd("identity"); } catch { }
                                                if (attempt >= 2) tailReq.Headers.ConnectionClose = true;
                                                try { Log($"[SS.TAIL.SEND] v={tailReq.Version} close={tailReq.Headers.ConnectionClose}"); } catch { }
                                                tailReq.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(actual, null);
                                                tailReq.Headers.ConnectionClose = true;
                                                tailReq.Version = System.Net.HttpVersion.Version11;
                                                tailReq.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
                                                tailReq.Headers.AcceptEncoding.Clear();

                                                using var tailRes = await _http.SendAsync(tailReq, HttpCompletionOption.ResponseHeadersRead, _cts.Token).ConfigureAwait(false);
                                                tailRes.EnsureSuccessStatusCode();

                                                using var tailStream = await tailRes.Content.ReadAsStreamAsync(_cts.Token).ConfigureAwait(false);
                                                using (var fs = new System.IO.FileStream(finalPath, System.IO.FileMode.Append, System.IO.FileAccess.Write, System.IO.FileShare.Read))
                                                {
                                                    await tailStream.CopyToAsync(fs, 128 * 1024, _cts.Token).ConfigureAwait(false);
                                                }

                                                try { Log($"[SS.TAIL] healed {missing} bytes"); } catch { }
                                            }
                                        }
                                        catch { /* best-effort heal; ignore */ }
                                        return true;


                                        return true;
                                    }
                                    catch { /* no-op */ }

                                    // best-effort cleanup of leftover single-stream parts
                                    try
                                    {
                                        var dir = System.IO.Path.GetDirectoryName(finalPath) ?? "";
                                        var leafName = System.IO.Path.GetFileName(finalPath);
                                        foreach (var p in System.IO.Directory.EnumerateFiles(dir, leafName + ".part*", System.IO.SearchOption.TopDirectoryOnly))
                                        {
                                            try
                                            {
                                                if (!string.Equals(p, finalPath, StringComparison.OrdinalIgnoreCase))
                                                    System.IO.File.Delete(p);
                                            }
                                            catch { /* ignore */ }
                                        }
                                    }
                                    catch { /* ignore */ }
                                }


                                _hadDownloads = true; _jitterScore = Math.Max(0, _jitterScore - 2); AdjustHealthOnSuccess(); EndCurrentFileProgress();
                                if (_noRangeHosts.Remove(remoteUrl.Host))
                                    try { Log($"[RANGE.RECOVER] {remoteUrl.Host} SS success — re-enabling segmentation"); } catch { }
                                try { s_NoRangeThisRun = false; var __h = remoteUrl.Host; lock (_noRangeHosts) { if (!string.IsNullOrEmpty(__h)) _noRangeHosts.Remove(__h); _noRangeHosts.Remove("*.coomer.st"); } } catch { }

                                try { File.Delete(finalPath + ".ok"); } catch { } // B1: remove sidecar on SS success

                                // PATCH 2 — POST-SAVE inflight cleanup (quick add already done on accept paths)
                                try { /* no-op */ }
                                finally
                                {
                                    if (_qRegistered && _qKey != null) _inflightQuick.TryRemove(_qKey, out _);
                                    _qRegistered = false; _qKey = null; _qLen = 0; _qHash64k = null;
                                }


                                if (assetKind == "VID") _sumVidsOk++; else if (assetKind == "IMG") _sumImgsOk++;
                                try { TrackAssetForPost(referer, assetKind, matchKey, finalPath); } catch { }
                                try { TrackAssetBytesForPost(referer, assetKind, finalPath); } catch { }
                                try { CMDownloaderUI.WebUiStatus.PushRecent(System.IO.Path.GetFileName(finalPath)); } catch { }


                                // Thumbnails were a legacy integrity proxy; acceptance is finalized without spawning ffmpeg.
                                // On successful save, remove any per-run "no range" ban for this host
                                if (!string.IsNullOrEmpty(remoteUrl?.Host))
                                {
                                    lock (_noRangeHosts)
                                    {
                                        if (_noRangeHosts.Remove(remoteUrl.Host))
                                            Log($"[EDGE.ROTATE] unban → {remoteUrl.Host} (success)");
                                    }
                                    // If this host was pinned for a previous file, leave pinning to 206 logic elsewhere.
                                }

                                return true;


                            }
                            // safeguard: video extensions must route to VideoRoot
                            if (".mp4 .m4v .mov .avi .mkv .webm".Contains(Path.GetExtension(finalPath).ToLowerInvariant())
                                && finalPath.StartsWith(ImagesRoot, StringComparison.OrdinalIgnoreCase))
                            {
                                finalPath = Path.Combine(VideoRoot, Path.GetFileName(finalPath));
                            }

                            try { File.Delete(tempPath); } catch { }
                            resumeOffset = 0; throw new HttpRequestException("416 Range Not Satisfiable; restarting", null, res.StatusCode);
                        }

                        res.EnsureSuccessStatusCode();
                        long total = -1;
                        if (res.StatusCode == System.Net.HttpStatusCode.PartialContent)
                        {
                            var cr = res.Content.Headers.ContentRange;
                            if (cr != null && cr.HasLength) total = (long)cr.Length!;
                            else if (res.Content.Headers.ContentLength.HasValue) total = resumeOffset + res.Content.Headers.ContentLength.Value;
                        }
                        else if (res.StatusCode == System.Net.HttpStatusCode.RequestedRangeNotSatisfiable)
                        {
                            // server says the requested range is already satisfied
                            long expected = -1;
                            var cr416 = res.Content.Headers.ContentRange; // often "bytes */<len>" on 416
                            if (cr416 != null && cr416.HasLength) expected = (long)cr416.Length!;
                            if (expected <= 0) expected = resumeOffset; // fallback if server didn't include length

                            long local = 0;
                            try { local = new System.IO.FileInfo(tempPath).Length; } catch { }

                            if (expected > 0 && local >= expected)
                            {
                                try { Log("[SS.RESUME] 416 — already complete; accepting"); } catch { }
                                // mark Done (OK – 416 accept)
                                try
                                {
                                    var __id = _qKey ?? finalPath ?? Guid.NewGuid().ToString("n");
                                    CMDownloaderUI.QueueTap.MoveToDone(__id, ok: true);
                                }
                                catch { }
                                return true;

                                return true; // treat as success
                                             // (If you use a success label instead of return: goto SS_DONE_SUCCESS;)
                            }

                            // not actually complete — fall back to your normal non-range path below
                            total = res.Content.Headers.ContentLength ?? -1L;
                            if (assetKind == "VID" && resumeOffset > 0) { try { System.IO.File.Delete(tempPath); } catch { } resumeOffset = 0; }
                        }
                        else
                        {
                            total = res.Content.Headers.ContentLength ?? -1L;
                            if (assetKind == "VID" && resumeOffset > 0) { try { System.IO.File.Delete(tempPath); } catch { } resumeOffset = 0; }
                        }


                        if (!progressStarted)
                        {
                            BeginCurrentFileProgress(total, Path.GetFileName(finalPath));
                            progressStarted = true;

                            // seed current file + host + size for WebUI
                            try
                            {
                                CMDownloaderUI.WebUiStatus.SetCurrent(Path.GetFileName(finalPath));
                                CMDownloaderUI.WebUiStatus.SetCurrentProgress(0, 0, total, null, _lastEdgeHost ?? remoteUrl?.Host);
                            }
                            catch { /* non-fatal for UI */ }

                            // reset seg autoscale state so prior file’s burst/overflow doesn’t leak in
                            _segOverflowOpen = false;
                            _segGateBurst = 0;
                            _segGateBurstT0Ms = 0;
                        }


                        progressStarted = true;
                        await using var src = await res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                        EnsureParent(tempPath);
                        FileStream dstStream;
                        if (assetKind == "VID" && resumeOffset > 0 && res.StatusCode == HttpStatusCode.PartialContent)
                        {
                            TraceAnyWrite(tempPath, -1, "SEG.APPEND");
                            dstStream = new FileStream(tempPath, FileMode.Append, FileAccess.Write, FileShare.None, BUF, useAsync: true);
                        }
                        else
                        {
                            var __note = (tryRange && assetKind == "VID") ? "SEG.CREATE" : "SS.CREATE";
                            TraceAnyWrite(tempPath, -1, __note);
                            dstStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, BUF, useAsync: true);
                        }


                        await using (dstStream)
                        {
                            int idleMs = (assetKind == "VID" ? 45000 : 15000);
                            var buf = System.Buffers.ArrayPool<byte>.Shared.Rent(BUF);
                            long readTotal = 0;
                            var tpSw = Stopwatch.StartNew();
                            long tpBytes = 0;
                            const int TP_FLOOR = 64 * 1024; // bytes/sec //
                            const int TP_WINDOW_MS = 30000;

                            var __healed = false;

                            try
                            {
                                while (true)
                                {
                                    var rt = src.ReadAsync(buf.AsMemory(0, BUF), ct).AsTask();
                                    var done = await Task.WhenAny(rt, Task.Delay(idleMs, ct));
                                    if (done != rt) throw new IOException("read idle timeout");
                                    int n = rt.Result; if (n == 0) break;
                                    await dstStream.WriteAsync(buf.AsMemory(0, n), ct).ConfigureAwait(false);

                                    readTotal += n;
                                    UpdateCurrentFileProgress(resumeOffset + readTotal, total);
                                    UpdateSpeedLabel(n);

                                    tpBytes += n;
                                    if (tpSw.ElapsedMilliseconds >= TP_WINDOW_MS)
                                    {
                                        var secs = Math.Max(1.0, tpSw.ElapsedMilliseconds / 1000.0);
                                        var rate = tpBytes / secs;

                                        // SS gets a grace window; SEG still throws
                                        if (rate < TP_FLOOR)
                                        {
                                            if (tryRange) // segmented
                                                throw new IOException("throughput watchdog");
                                            // single-stream: allow one slow window (no throw)
                                        }

                                        tpBytes = 0;
                                        tpSw.Restart();
                                    }

                                }
                            }
                            catch (Exception ex) when (!(ex is OperationCanceledException))
                            {
                                // best-effort heal small missing tail (≤ 8 MiB) || accept 416 as complete
                                try
                                {
                                    long expected = total > 0 ? total : -1;
                                    long have = 0; try { have = new System.IO.FileInfo(tempPath).Length; } catch { }
                                    long missing = (expected > 0) ? (expected - have) : -1;

                                    if (expected > 0 && missing > 0 && missing <= (8L * 1024 * 1024))
                                    {
                                        using var tailReq = new HttpRequestMessage(HttpMethod.Get, remoteUrl);

                                        tailReq.Version = System.Net.HttpVersion.Version11;
                                        tailReq.VersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionOrLower;
                                        try { tailReq.Headers.AcceptEncoding.Clear(); tailReq.Headers.AcceptEncoding.ParseAdd("identity"); } catch { }
                                        if (attempt >= 2) tailReq.Headers.ConnectionClose = true;
                                        try { Log($"[SS.TAIL.SEND] v={tailReq.Version} close={tailReq.Headers.ConnectionClose}"); } catch { }
                                        tailReq.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(have, null);
                                        tailReq.Version = System.Net.HttpVersion.Version11;
                                        tailReq.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
                                        try { tailReq.Headers.AcceptEncoding.Clear(); } catch { }

                                        using var tailRes = await _http.SendAsync(tailReq, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

                                        if (tailRes.StatusCode == System.Net.HttpStatusCode.RequestedRangeNotSatisfiable)
                                        {
                                            if (have >= expected)
                                            {
                                                __healed = true;
                                                try { Log("[SS.TAIL] 416 — already complete; accepting"); } catch { }
                                                // mark Done (OK – tail 416 accept)
                                                try
                                                {
                                                    var __id = _qKey ?? finalPath ?? Guid.NewGuid().ToString("n");
                                                    CMDownloaderUI.QueueTap.MoveToDone(__id, ok: true);
                                                }
                                                catch { }

                                            }
                                        }
                                        else
                                        {
                                            tailRes.EnsureSuccessStatusCode();
                                            await using var tailStream = await tailRes.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                                            TraceAnyWrite(tempPath, -1, "SEG.APPEND.EXTRA");
                                            using (var fs2 = new FileStream(tempPath, FileMode.Append, FileAccess.Write, FileShare.None, BUF, useAsync: true))
                                            {
                                                await tailStream.CopyToAsync(fs2, BUF, ct).ConfigureAwait(false);
                                            }
                                            __healed = true;
                                            try { Log($"[SS.TAIL] healed {missing} bytes"); } catch { }
                                        }
                                    }
                                }
                                catch { /* best-effort */ }

                                if (!__healed) throw; // let existing retry logic handle it
                            }
                            finally
                            {
                                try { System.Buffers.ArrayPool<byte>.Shared.Return(buf); } catch { }
                            }
                        }



                        await MoveWithSmallRetriesAsync(tempPath, finalPath, 4, ct).ConfigureAwait(false);

                        // ---- Tail-mend for videos if the file is shorter than the server says ---- //
                        if (assetKind == "VID")
                        {
                            long __len = new FileInfo(finalPath).Length;

                            // Ask server for the expected total length //
                            long? __srv = await TryProbeSizeAsync(remoteUrl, ct).ConfigureAwait(false);
                            if (!__srv.HasValue)
                            {
                                try
                                {
                                    using var __req0 = new HttpRequestMessage(HttpMethod.Get, remoteUrl);

                                    __req0.Version = System.Net.HttpVersion.Version11;
                                    __req0.VersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionOrLower;
                                    try { __req0.Headers.AcceptEncoding.Clear(); __req0.Headers.AcceptEncoding.ParseAdd("identity"); } catch { }
                                    if (attempt >= 2) __req0.Headers.ConnectionClose = true;
                                    if (attempt > 1 && __req0.Headers.Range == null) EnsureIdentity(__req0);

                                    __req0.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 0); // probe //
                                    using var __res0 = await _http.SendAsync(__req0, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                                    var __cr0 = __res0.Content?.Headers?.ContentRange;
                                    if (__res0.StatusCode == System.Net.HttpStatusCode.PartialContent && __cr0?.Length is long L0 && L0 > 0)
                                        __srv = L0;
                                }
                                catch { /* ignore */ }
                            }

                            // If we know the server size and we're short, append the missing tail //
                            if (__srv.HasValue && __srv.Value > __len)
                            {
                                try
                                {
                                    using var __req = new HttpRequestMessage(HttpMethod.Get, remoteUrl);

                                    __req.Version = System.Net.HttpVersion.Version11;
                                    __req.VersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionOrLower;
                                    try { __req.Headers.AcceptEncoding.Clear(); __req.Headers.AcceptEncoding.ParseAdd("identity"); } catch { }
                                    if (attempt >= 2) __req.Headers.ConnectionClose = true;
                                    if (attempt > 1 && __req.Headers.Range == null) EnsureIdentity(__req);

                                    __req.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(__len, null); // bytes=__len- //
                                    using var __res = await _http.SendAsync(__req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

                                    var __cr = __res.Content?.Headers?.ContentRange;
                                    if (__res.StatusCode == System.Net.HttpStatusCode.PartialContent && __cr?.From == __len)
                                    {
                                        using var __rs = await __res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                                        using var __fs = new FileStream(finalPath, FileMode.Append, FileAccess.Write, FileShare.Read);
                                        await __rs.CopyToAsync(__fs, 81920, ct).ConfigureAwait(false);
                                    }
                                    else
                                    {
                                        // Server refused ranges || restarted from the beginning—don’t corrupt the file //
                                        Log("[INTEGRITY] tail mend skipped — no valid 206/Content-Range");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Log($"[INTEGRITY] tail mend failed: {ex.Message}");
                                }

                                // Re-check length after mend; if still short, force a retry //
                                __len = new FileInfo(finalPath).Length;
                                if (__len < __srv.Value)
                                {
                                    Log($"[INTEGRITY] still short after mend ({__len} < {__srv.Value}) — deleting and retrying");
                                    try { File.Delete(finalPath); } catch { }
                                    throw new IOException("incomplete video after tail mend");
                                }
                            }
                        }
                        // ---- end tail-mend ---- //

                        if (assetKind == "IMG" && File.Exists(finalPath))
                        {
                            long size = new FileInfo(finalPath).Length;
                            if (refreshedOnce && size >= SMALL_IMAGE_BYTES)
                            { if (ShouldLogImageLines()) Log($"[TINY] upgraded to {size:N0} B"); }
                            const bool ENABLE_TINY_REFRESH_IMG = false;
                            if (ENABLE_TINY_REFRESH_IMG && !_tinyOff && size < SMALL_IMAGE_BYTES)
                            {
                                if (!refreshedOnce)

                                {
                                    bool __TINY_HTTP_ONLY = true; // guard: tiny refresh must NOT touch _page/Playwright

                                    if (ShouldLogImageLines()) Log($"[TINY] saved {size:N0} B — refreshing once");
                                    try { File.Delete(finalPath); } catch { }
                                    if (!string.IsNullOrEmpty(_qKey)) { try { IndexRemove(_qKey); } catch { } } // drop stale quick-index entry
                                    var newUrl = await RefreshAssetUrlAsync_HTTP(remoteUrl, referer ?? string.Empty, matchKey, ct).ConfigureAwait(false);
                                    if (newUrl != null) remoteUrl = newUrl;
                                    refreshedOnce = true;
                                    _sumTinyRefreshes++; // (count this path too)
                                    continue; // retry current attempt with the rotated URL //
                                }
                                else
                                {
                                    if (ShouldLogImageLines()) Log($"[TINY] keeping original ({size:N0} B) after single refresh attempt");
                                }
                            }

                        }



                        // POST-CHECK (header/tail + _qLen) — parity with segmented
                        bool __svOk = true;
                        bool __quarOk = true; // visible to the whole verify block
                        try
                        {
                            // Skip heavy verify logic for images (they don't need MP4 moov/moof scans)
                            if (string.Equals(assetKind, "IMG", StringComparison.OrdinalIgnoreCase))
                                goto VERIFY_DONE;

                            var __svFi = new FileInfo(finalPath);
                            __svFi.Refresh();
                            // — reject small/truncated MP4s (<4 MiB) lacking core atoms/tracks
                            {
                                long __saved = __svFi.Length;
                                const long __SUSPECT_LIMIT = 4L * 1024 * 1024; // 4 MiB

                                if (__saved < __SUSPECT_LIMIT)
                                {
                                    int __read = (int)Math.Min(__saved, 2 * 1024 * 1024); // scan up to first 2 MiB
                                    byte[] __head = new byte[__read];
                                    using (var __fs = new FileStream(finalPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                                    {
                                        __fs.Read(__head, 0, __read);
                                    }

                                    // quick ASCII scans
                                    string __hs = System.Text.Encoding.ASCII.GetString(__head);
                                    bool __hasFtyp = __hs.Contains("ftyp", StringComparison.Ordinal);
                                    bool __hasMoovOrMoof =
                                        __hs.Contains("moov", StringComparison.Ordinal) ||
                                        __hs.Contains("moof", StringComparison.Ordinal) ||
                                        HasMoovOrMoofHeadTail(finalPath); // full-file head/tail scan
                                    bool __hasMdat = __hs.Contains("mdat", StringComparison.Ordinal);


                                    // look for at least one handler declaring a playable track
                                    bool __hasPlayable = false;
                                    int __pos = 0;
                                    while (!__hasPlayable && (__pos = __hs.IndexOf("hdlr", __pos, StringComparison.Ordinal)) >= 0)
                                    {
                                        int __winStart = __pos;
                                        int __winLen = Math.Min(128, __hs.Length - __winStart);
                                        if (__winLen > 0)
                                        {
                                            string __win = __hs.Substring(__winStart, __winLen);
                                            if (__win.Contains("vide", StringComparison.Ordinal) ||
                                                __win.Contains("soun", StringComparison.Ordinal))
                                            {
                                                __hasPlayable = true;
                                            }
                                        }
                                        __pos += 4;
                                    }

                                    // fall back to robust head/tail scan if ASCII window didn’t find it
                                    if (!__hasPlayable)
                                    {
                                        __hasPlayable = HasPlayableTrackQuick(finalPath);
                                    }


                                    if (!(__hasFtyp && __hasMoovOrMoof && __hasMdat && __hasPlayable))
                                    {
                                        try { Log($"[VERIFY] mp4 reject (<4MiB): ftyp={__hasFtyp} moov/moof={__hasMoovOrMoof} mdat={__hasMdat} playable={__hasPlayable} — quarantining"); } catch { }

                                        // inline quarantine (no helpers)
                                        var __dir = Path.GetDirectoryName(finalPath) ?? "";
                                        var __qdir = Path.Combine(__dir, "_quarantine");
                                        Directory.CreateDirectory(__qdir);
                                        var __qpath = Path.Combine(__qdir, Path.GetFileName(finalPath));

                                        try { File.Move(finalPath, __qpath, true); }
                                        catch
                                        {
                                            try { File.Copy(finalPath, __qpath, true); } catch { }
                                            try { File.Delete(finalPath); } catch { }
                                        }
                                        try { File.Move(finalPath, __qpath, true); }
                                        catch
                                        {
                                            try { File.Copy(finalPath, __qpath, true); } catch { }
                                            try { File.Delete(finalPath); } catch { }
                                        }

                                        // trace where small/truncated MP4s end up
                                        try
                                        {
                                            long __lenAfter = 0;
                                            try { __lenAfter = new FileInfo(__qpath).Length; } catch { }
                                            TraceVidFs("quarantine-small", __qpath, __lenAfter, "mp4_small_core_atoms");
                                        }
                                        catch { }

                                        goto VERIFY_DONE; // exit verify path cleanly

                                        goto VERIFY_DONE; // exit verify path cleanly
                                    }
                                    // — require minimal duration or samples for <4 MiB MP4/M4V
                                    {
                                        long __saved2 = __svFi.Length;
                                        const long __SMALL_MAX = 4L * 1024 * 1024; // 4 MiB
                                        const double __MIN_SEC = 0.30; // minimal quick duration

                                        // Only check very small MP4-family files
                                        string __ext = Path.GetExtension(finalPath) ?? "";
                                        bool __isMp4Fam = __ext.Equals(".mp4", StringComparison.OrdinalIgnoreCase)
                                                       || __ext.Equals(".m4v", StringComparison.OrdinalIgnoreCase)
                                                       || __ext.Equals(".mov", StringComparison.OrdinalIgnoreCase);

                                        if (__isMp4Fam && __saved > 0 && __saved < __SMALL_MAX)
                                        {
                                            int __read2 = (int)Math.Min(__saved, 2 * 1024 * 1024); // read up to first 2 MiB
                                            byte[] __head2 = new byte[__read];
                                            using (var __fs = new FileStream(finalPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                                            {
                                                __fs.Read(__head, 0, __read);
                                            }

                                            // ---- helpers ----
                                            static int ByteIndexOf(byte[] buf, byte a, byte b, byte c, byte d, int start)
                                            {
                                                for (int i = start, lim = buf.Length - 4; i <= lim; i++)
                                                    if (buf[i] == a && buf[i + 1] == b && buf[i + 2] == c && buf[i + 3] == d) return i;
                                                return -1;
                                            }
                                            static uint ReadU32BE(byte[] b, int o)
                                            {
                                                if (o < 0 || o + 4 > b.Length) return 0;
                                                return (uint)((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | (b[o + 3]));
                                            }
                                            // --- NEW: mdat size floor for tiny MP4/M4V (<4 MiB) using __head2 ---
                                            const int __MDAT_MIN_BYTES = 128 * 1024; // 128 KiB payload floor

                                            int __mdat2 = ByteIndexOf(__head2, (byte)'m', (byte)'d', (byte)'a', (byte)'t', 0);
                                            if (__mdat2 >= 4) // 4 bytes before 'mdat' is the 32-bit box size
                                            {
                                                uint __boxSize2 = ReadU32BE(__head2, __mdat2 - 4);
                                                // size includes 8-byte header; size==1 => 64-bit extended size (treat as suspicious for tiny files)
                                                if ((__boxSize2 > 8 && (__boxSize2 - 8) < __MDAT_MIN_BYTES) || __boxSize2 == 1)
                                                {
                                                    try { Log($"[VERIFY] small mp4: mdat payload too small (box={__boxSize2}B) — quarantining"); } catch { }

                                                    var __dir = Path.GetDirectoryName(finalPath) ?? "";
                                                    var __qdir = Path.Combine(__dir, "_quarantine");
                                                    Directory.CreateDirectory(__qdir);
                                                    var __qpath = Path.Combine(__qdir, Path.GetFileName(finalPath));

                                                    try { File.Move(finalPath, __qpath, true); }
                                                    catch { try { File.Copy(finalPath, __qpath, true); } catch { } try { File.Delete(finalPath); } catch { } }

                                                    goto VERIFY_DONE;
                                                }
                                            }
                                            else
                                            {
                                                // head missed 'mdat' — try tail/structure before quarantining
                                                bool tailOk = false;
                                                try
                                                {
                                                    tailOk = HasMoovOrMoofHeadTail(finalPath) || HasPlayableTrackQuick(finalPath);
                                                }
                                                catch { /* best-effort */ }

                                                if (tailOk)
                                                {
                                                    try { Log("[VERIFY] small mp4: head miss, tail/structure OK — accepted"); } catch { }
                                                    goto VERIFY_DONE;
                                                }

                                                // Original path: no tail proof either → quarantine
                                                try { Log("[VERIFY] small mp4: no 'mdat' found in head — quarantining"); } catch { }

                                                var __dir = Path.GetDirectoryName(finalPath) ?? "";
                                                var __qdir = Path.Combine(__dir, "_quarantine");
                                                Directory.CreateDirectory(__qdir);
                                                var __qpath = Path.Combine(__qdir, Path.GetFileName(finalPath));

                                                try { File.Move(finalPath, __qpath, true); }
                                                catch { try { File.Copy(finalPath, __qpath, true); } catch { } try { File.Delete(finalPath); } catch { } }

                                                goto VERIFY_DONE;
                                            }


                                            bool __hasMinimalDuration = false;
                                            bool __hasSamples = false;

                                            // Try mvhd duration (version 0 only; version 1 will fall back)
                                            int __mvhd = ByteIndexOf(__head, (byte)'m', (byte)'v', (byte)'h', (byte)'d', 0);
                                            if (__mvhd >= 0)
                                            {
                                                // mvhd layout: size(4) type(4) version(1) flags(3) creation(4) mod(4) timescale(4) duration(4)
                                                byte __ver = (__mvhd + 8 < __head.Length) ? __head[__mvhd + 8] : (byte)0xFF;
                                                if (__ver == 0 && __mvhd + 24 < __head.Length)
                                                {
                                                    uint __timescale = ReadU32BE(__head, __mvhd + 16);
                                                    uint __duration = ReadU32BE(__head, __mvhd + 20);
                                                    if (__timescale > 0)
                                                    {
                                                        double __sec = (double)__duration / (double)__timescale;
                                                        if (__sec >= __MIN_SEC) __hasMinimalDuration = true;
                                                    }
                                                }
                                            }

                                            // Fallback: stsz sample_count > 0
                                            int __stsz = ByteIndexOf(__head, (byte)'s', (byte)'t', (byte)'s', (byte)'z', 0);
                                            if (__stsz >= 0 && !__hasMinimalDuration)
                                            {
                                                // stsz: size(4) type(4) version(1) flags(3) sample_size(4) sample_count(4)
                                                uint __sampleSize = ReadU32BE(__head, __stsz + 12);
                                                uint __sampleCount = ReadU32BE(__head, __stsz + 16);
                                                if (__sampleCount > 0)
                                                {
                                                    // If sample_size==0, table follows; we won't parse the table here—count>0 is good enough.
                                                    // If sample_size>0, a constant-size sample exists -> treat as having samples.
                                                    __hasSamples = true;
                                                }
                                            }

                                            if (!(__hasMinimalDuration || __hasSamples))
                                            {
                                                try { Log("[VERIFY] small mp4 no samples/duration — quarantining"); } catch { }

                                                var __dir = Path.GetDirectoryName(finalPath) ?? "";
                                                var __qdir = Path.Combine(__dir, "_quarantine");
                                                Directory.CreateDirectory(__qdir);
                                                var __qpath = Path.Combine(__qdir, Path.GetFileName(finalPath));

                                                try { File.Move(finalPath, __qpath, true); }
                                                catch
                                                {
                                                    try { File.Copy(finalPath, __qpath, true); } catch { }
                                                    try { File.Delete(finalPath); } catch { }
                                                }

                                                goto VERIFY_DONE;
                                            }
                                        }
                                    }

                                }
                            }


                            // optional early kill for HTML/JSON mislabeled as MP4
                            if (__svFi.Length < 2 * 1024 * 1024)
                            {
                                using var __svFs = new FileStream(finalPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                                Span<byte> __peek = stackalloc byte[(int)Math.Min(2048, __svFi.Length)];
                                int __n = __svFs.Read(__peek);

                                int __texty = 0;
                                for (int i = 0; i < __n; i++)
                                {
                                    byte b = __peek[i];
                                    if (b == (byte)'<' || b == (byte)'>' || b == (byte)'{' || b == (byte)'}' || b == (byte)'"' || b == (byte)'\'')
                                        __texty++;
                                }

                                if (__texty > 32)
                                {
                                    try { Log("[VERIFY] text/HTML body detected — rejecting"); } catch { }
                                    __svOk = false; // keep failing; later code will throw if needed
                                }
                            }
                            // head/tail + tiny rules + length parity + playable quick (central quarantine)
                            __svOk = true;
                            try
                            {
                                __svFi = new FileInfo(finalPath);
                                // guard for tiny videos when no expected length is known
                                if (_qLen <= 0 &&
                                    string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase) &&
                                    __svFi.Length > 0 &&
                                    __svFi.Length < MIN_VIDEO_BYTES) // e.g. < 3 MiB
                                {
                                    try { DeleteBadQuickVideo(finalPath, __svFi.Length, _qHash64k, "TINY_VID_NO_CL"); } catch { }
                                    throw new IOException("tiny video with no length; treating as truncated");
                                }

                                // Fast structure scans
                                bool __hasMoovOrMoof = HasMoovOrMoofHeadTail(finalPath); // front/tail moov/moof
                                bool __isTinyVid = __svFi.Length <= 8L * 1024 * 1024; // FAST path threshold (≤8 MiB)
                                bool __playableQuick = __hasMoovOrMoof || (!__isTinyVid && HasPlayableTrackQuick(finalPath)); // skip deep scan on FAST path

                                // 1) TINY hard gate (≤8 MiB must have moov/moof)
                                if (__svFi.Length <= 8L * 1024 * 1024 && !__hasMoovOrMoof)
                                {
                                    try { Log("[VERIFY] tiny MP4 lacked moov/moof — quarantine"); } catch { }
                                    try
                                    {
                                        var __qDir = Path.Combine(VideoRoot, "_Quarantine");
                                        Directory.CreateDirectory(__qDir);
                                        string __qPath = MakeQuarantinePath(__qDir, finalPath, "NO_MOOV_TINY");

                                        // reuse existing same-hash file if present
                                        bool __skipMove = false;
                                        try
                                        {
                                            var __h = QuickHash64k(finalPath);
                                            var __hit = FindQuarantineByHash(__qDir, __h);
                                            if (__hit != null && !__hit.Equals(__qPath, StringComparison.OrdinalIgnoreCase))
                                            {
                                                __qPath = __hit;
                                                __skipMove = true;
                                            }
                                        }
                                        catch { }

                                        // media: move/copy only if not dedup-hit
                                        if (!__skipMove)
                                        {
                                            try { File.Move(finalPath, __qPath, true); }
                                            catch { try { File.Copy(finalPath, __qPath, true); File.Delete(finalPath); } catch { } }
                                        }
                                        else
                                        {
                                            try { File.Delete(finalPath); } catch { }
                                        }

                                        // sidecar .ok
                                        var _m = finalPath + ".ok";
                                        if (File.Exists(_m))
                                        {
                                            var _mq = __qPath + ".ok";
                                            try { File.Move(_m, _mq, true); }
                                            catch { try { File.Copy(_m, _mq, true); File.Delete(_m); } catch { } }
                                        }
                                        LogVidVerifyTelemetry("QUAR", finalPath, __svFi.Length, __hasMoovOrMoof, __playableQuick, "NO_MOOV_TINY");

                                        LogQuarantine(__skipMove ? "NO_MOOV_TINY_DEDUP" : "NO_MOOV_TINY", finalPath, __qPath);
                                        _qBad++;
                                        if (!string.IsNullOrEmpty(_qKey)) { try { IndexRemoveTyped(assetKind, _qKey); } catch { } }

                                    }
                                    catch { /* best-effort */ }

                                    __svOk = false;
                                }

                                // 2) Length parity (when expected size is known)
                                if (__svOk && _qLen > 0 && __svFi.Length != _qLen)
                                {
                                    long delta = Math.Abs(__svFi.Length - _qLen);
                                    // If big mismatch, give the server a chance to publish the real size (CDN lag)
                                    // Re-probe HEAD a few times (≤ ~60s total) and update _qLen if it stabilizes.
                                    if (delta > 4L * 1024) // only when we actually disagree
                                    {
                                        try
                                        {
                                            // Use the same URL you HEADed to get _qLen the first time:
                                            var settled = WaitForSettledLengthAsync(remoteUrl, ct).GetAwaiter().GetResult();
                                            if (settled > 0 && settled != _qLen)
                                            {
                                                bool __varHandled = false;

                                                // huge CL change → treat as variant swap-style change
                                                if (string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase)
                                                    && _qLen >= MIN_VIDEO_BYTES)
                                                {
                                                    var big = Math.Max(_qLen, settled);
                                                    var small = Math.Min(_qLen, settled);

                                                    if (small > 0 && big >= small * 20)
                                                    {
                                                        try { Log($"[VERIFY.VAR.MISMATCH] VID HEAD changed drastically: {_qLen:N0} ↔ {settled:N0}"); } catch { }
                                                        _qLen = settled;
                                                        delta = Math.Abs(__svFi.Length - _qLen);
                                                        __varHandled = true;
                                                    }
                                                }

                                                if (!__varHandled)
                                                {
                                                    // For videos: don’t trust a drastic “shrink” in reported size.
                                                    // If we already had a sane video length, and the new HEAD is
                                                    // <90% of that, assume it’s a stub node lying to us.
                                                    if (string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase)
                                                        && _qLen >= MIN_VIDEO_BYTES
                                                        && settled < (long)(_qLen * 0.90))
                                                    {
                                                        try { Log($"[VERIFY] HEAD shrink ignored for video; had {_qLen:N0}, probe {settled:N0}"); } catch { }
                                                        // keep old _qLen; delta stays large so LEN_OFF path will fire
                                                    }
                                                    else
                                                    {
                                                        try { Log($"[VERIFY] HEAD settled: expected {_qLen:N0} → {settled:N0}"); } catch { }
                                                        _qLen = settled;
                                                        delta = Math.Abs(__svFi.Length - _qLen);
                                                    }
                                                }
                                            }
                                        }
                                        catch { /* best-effort */ }

                                    }

                                    // Tolerate small drift (≤4 KiB) — accept
                                    if (delta <= 4L * 1024)
                                    {
                                        try { Log($"[VERIFY] length drift {delta:N0} bytes — tolerated"); } catch { }
                                    }
                                    // If file is playable AND (for videos) not severely smaller than probed size, accept despite parity
                                    else if (
                                        (__svFi.Length >= (long)Math.Round(_qLen * 0.90) // ≥90% of expected for videos
                                         || !string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase))
                                        && (HasMoovOrMoofHeadTail(finalPath) || HasPlayableTrackQuick(finalPath)))
                                    {
                                        try { Log($"[VERIFY] length off but playable — accepting; have {__svFi.Length:N0} vs expected {_qLen:N0}"); } catch { }
                                    }

                                    else
                                    {
                                        // drop bad file and let retry loop handle it (no quarantine)
                                        try { Log($"[VERIFY] length off — have {__svFi.Length:N0} vs expected {_qLen:N0} — drop & retry"); } catch { }

                                        try
                                        {
                                            // delete the bad main file
                                            try { File.Delete(finalPath); } catch { }

                                            // delete any .ok sidecar that might have been written
                                            try
                                            {
                                                var _m = finalPath + ".ok";
                                                if (File.Exists(_m))
                                                {
                                                    File.Delete(_m);
                                                }
                                            }
                                            catch { }

                                            // telemetry: record this as a LEN_OFF drop, not a keep
                                            try
                                            {
                                                LogVidVerifyTelemetry("DROP", finalPath, __svFi.Length, __hasMoovOrMoof, __playableQuick, "LEN_OFF_DROP");

                                            }
                                            catch { }

                                            // still count as bad verify
                                            try { _qBad++; } catch { }

                                            // don’t reuse this expectation on the next attempt
                                            try
                                            {
                                                if (!string.IsNullOrEmpty(_qKey))
                                                {
                                                    try { IndexRemoveTyped(assetKind, _qKey); } catch { }
                                                }

                                                _qLen = 0;
                                                _qHash64k = null;
                                                _qKey = null;
                                            }
                                            catch { }

                                            // mark this save as not-ok so the outer logic treats it as a failure
                                            __svOk = false;
                                        }
                                        catch { /* best-effort */ }
                                    }

                                }


                                // 3) Non-tiny but not playable: neither moov/moof nor handler hits
                                if (__svOk && !__playableQuick)
                                {
                                    try { Log("[VERIFY] mp4 not playable (no moov/moof & no vide/soun) — quarantine"); } catch { }
                                    try
                                    {
                                        var __qDir = Path.Combine(VideoRoot, "_Quarantine");
                                        Directory.CreateDirectory(__qDir);
                                        string __qPath = MakeQuarantinePath(__qDir, finalPath, "NO_MOOV_NOPLAY");

                                        // reuse existing same-hash file if present
                                        bool __skipMove = false;
                                        try
                                        {
                                            // Use the hash already embedded in __qPath; fallback to hashing only if missing
                                            var __h = ExtractHashFromQPath(__qPath) ?? QuickHash64k(finalPath);
                                            var __hit = FindQuarantineByHashName(__qDir, __h);

                                            if (__hit != null && !__hit.Equals(__qPath, StringComparison.OrdinalIgnoreCase))
                                            {
                                                __qPath = __hit;
                                                __skipMove = true;
                                            }
                                        }
                                        catch { }

                                        // media: move/copy only if not dedup-hit
                                        if (!__skipMove)
                                        {
                                            try { File.Move(finalPath, __qPath, true); }
                                            catch { try { File.Copy(finalPath, __qPath, true); File.Delete(finalPath); } catch { } }
                                        }
                                        else
                                        {
                                            try { File.Delete(finalPath); } catch { }
                                        }

                                        // sidecar .ok
                                        var _m = finalPath + ".ok";
                                        if (File.Exists(_m))
                                        {
                                            var _mq = __qPath + ".ok";
                                            try { File.Move(_m, _mq, true); }
                                            catch { try { File.Copy(_m, _mq, true); File.Delete(_m); } catch { } }
                                        }
                                        LogVidVerifyTelemetry("QUAR", finalPath, __svFi.Length, __hasMoovOrMoof, __playableQuick, "NO_MOOV_NOPLAY");

                                        LogQuarantine(__skipMove ? "NO_MOOV_NOPLAY_DEDUP" : "NO_MOOV_NOPLAY", finalPath, __qPath);
                                        _qBad++;
                                        if (!string.IsNullOrEmpty(_qKey)) { try { IndexRemoveTyped(assetKind, _qKey); } catch { } }

                                    }
                                    catch { /* best-effort */ }

                                    __svOk = false;
                                }
                                // Final tiny-stub guard: tiny mp4s must be playable
                                if (__svOk && __svFi.Length <= 512L * 1024) // ≤512 KiB
                                {
                                    if (!HasPlayableTrackQuick(finalPath))
                                    {
                                        try { Log("[VERIFY] small mp4 non-playable — quarantine"); } catch { }
                                        try
                                        {
                                            var __qDir = Path.Combine(VideoRoot, "_Quarantine");
                                            Directory.CreateDirectory(__qDir);
                                            string __qPath = MakeQuarantinePath(__qDir, finalPath, "NO_MOOV_NOPLAY");


                                            bool __skipMove = false;
                                            try
                                            {
                                                var __h = ExtractHashFromQPath(__qPath) ?? QuickHash64k(finalPath);
                                                var __hit = FindQuarantineByHashName(__qDir, __h);
                                                if (__hit != null && !__hit.Equals(__qPath, StringComparison.OrdinalIgnoreCase))
                                                { __qPath = __hit; __skipMove = true; }
                                            }
                                            catch { }

                                            if (!__skipMove)
                                            {
                                                try { File.Move(finalPath, __qPath, true); }
                                                catch { try { File.Copy(finalPath, __qPath, true); File.Delete(finalPath); } catch { } }
                                            }
                                            else
                                            {
                                                try { File.Delete(finalPath); } catch { }
                                            }

                                            var _m = finalPath + ".ok";
                                            if (File.Exists(_m))
                                            {
                                                var _mq = __qPath + ".ok";
                                                try { File.Move(_m, _mq, true); }
                                                catch { try { File.Copy(_m, _mq, true); File.Delete(_m); } catch { } }
                                            }
                                            LogVidVerifyTelemetry("QUAR", finalPath, __svFi.Length, __hasMoovOrMoof, /*post-write playableQuick is false here*/ false, "NO_MOOV_NOPLAY");

                                            LogQuarantine(__skipMove ? "NO_MOOV_NOPLAY_DEDUP" : "NO_MOOV_NOPLAY", finalPath, __qPath);
                                            _qBad++;
                                            if (!string.IsNullOrEmpty(_qKey)) { try { IndexRemoveTyped(assetKind, _qKey); } catch { } }

                                            __svOk = false;
                                        }
                                        catch { /* best-effort */ }
                                    }
                                }
                                // Post-write playable barrier: after writer finished, file must still be playable
                                if (__svOk)
                                {
                                    bool __playableAfterWrite = HasPlayableTrackQuick(finalPath);
                                    if (!__playableAfterWrite)
                                    {
                                        // Telemetry before quarantining
                                        LogVidVerifyTelemetry("QUAR", finalPath, __svFi.Length, __hasMoovOrMoof, false, "POSTWRITE_FAIL");

                                        try
                                        {
                                            var __qDir = Path.Combine(VideoRoot, "_Quarantine");
                                            Directory.CreateDirectory(__qDir);
                                            string __qPath = MakeQuarantinePath(__qDir, finalPath, "POSTWRITE_FAIL");


                                            bool __skipMove = false;
                                            try
                                            {
                                                var __h = ExtractHashFromQPath(__qPath) ?? QuickHash64k(finalPath);
                                                var __hit = FindQuarantineByHashName(__qDir, __h);
                                                if (__hit != null && !__hit.Equals(__qPath, StringComparison.OrdinalIgnoreCase))
                                                { __qPath = __hit; __skipMove = true; }
                                            }
                                            catch { }

                                            if (!__skipMove)
                                            {
                                                try { File.Move(finalPath, __qPath, true); }
                                                catch { try { File.Copy(finalPath, __qPath, true); File.Delete(finalPath); } catch { } }
                                            }
                                            else
                                            {
                                                try { File.Delete(finalPath); } catch { }
                                            }

                                            // sidecar .ok
                                            var _m = finalPath + ".ok";
                                            if (File.Exists(_m))
                                            {
                                                var _mq = __qPath + ".ok";
                                                try { File.Move(_m, _mq, true); }
                                                catch { try { File.Copy(_m, _mq, true); File.Delete(_m); } catch { } }
                                            }
                                            LogVidVerifyTelemetry("QUAR", finalPath, __svFi.Length, __hasMoovOrMoof, /*post-write playableQuick is false*/ false, "POSTWRITE_FAIL");

                                            LogQuarantine(__skipMove ? "POSTWRITE_FAIL_DEDUP" : "POSTWRITE_FAIL", finalPath, __qPath);
                                            _qBad++;
                                            if (!string.IsNullOrEmpty(_qKey)) { try { IndexRemoveTyped(assetKind, _qKey); } catch { } }
                                        }
                                        catch { /* best-effort */ }

                                        __svOk = false; // block acceptance
                                    }
                                }

                                // 4) Accept if all checks pass (leave __svOk = true)
                                if (__svOk)
                                {
                                    LogVidVerifyTelemetry("ACCEPT", finalPath, __svFi.Length, __hasMoovOrMoof, __playableQuick);
                                    PostAcceptCleanup(finalPath);
                                    try { LogAccept("VID", finalPath, __svFi.Length); } catch { }
                                }


                            }
                            catch { /* best-effort */ }
                            // basic sanity + header signature → central Images\_Quarantine
                            if (string.Equals(assetKind, "IMG", StringComparison.OrdinalIgnoreCase) ||
                                assetKind?.ToString().Equals("Image", StringComparison.OrdinalIgnoreCase) == true)
                            {
                                bool __imgOk = true;
                                var __fiImg = new FileInfo(finalPath);
                                bool __isTinyImg = __fiImg.Length <= 256L * 1024; // FAST path for small images (≤256 KiB)

                                // 0) Empty / trivially small images → quarantine
                                if (__fiImg.Length <= 0 || __fiImg.Length < 4 * 1024) // < 4 KiB
                                {
                                    try { Log("[VERIFY] image too small/empty — quarantine"); } catch { }
                                    try
                                    {
                                        var __qDir = Path.Combine(ImagesRoot, "_Quarantine");
                                        Directory.CreateDirectory(__qDir);
                                        string __qPath = MakeQuarantinePath(__qDir, finalPath, "EMPTY_IMG");

                                        // reuse existing same-hash file if present
                                        bool __skipMove = false;
                                        try
                                        {
                                            // Use the hash already embedded in __qPath; fallback to hashing only if missing
                                            var __h = ExtractHashFromQPath(__qPath) ?? QuickHash64k(finalPath);
                                            var __hit = FindQuarantineByHashName(__qDir, __h);

                                            if (__hit != null && !__hit.Equals(__qPath, StringComparison.OrdinalIgnoreCase))
                                            {
                                                __qPath = __hit;
                                                __skipMove = true;
                                            }
                                        }
                                        catch { }

                                        // media: move/copy only if not dedup-hit
                                        if (!__skipMove)
                                        {
                                            try { File.Move(finalPath, __qPath, true); }
                                            catch { try { File.Copy(finalPath, __qPath, true); File.Delete(finalPath); } catch { } }
                                        }
                                        else
                                        {
                                            try { File.Delete(finalPath); } catch { } // drop duplicate bytes
                                        }

                                        // sidecar .ok (if you create these for images)
                                        var _m = finalPath + ".ok";
                                        if (File.Exists(_m))
                                        {
                                            var _mq = __qPath + ".ok";
                                            try { File.Move(_m, _mq, true); }
                                            catch { try { File.Copy(_m, _mq, true); File.Delete(_m); } catch { } }
                                        }

                                        LogQuarantine(__skipMove ? "EMPTY_IMG_DEDUP" : "EMPTY_IMG", finalPath, __qPath);
                                        _qBad++;
                                        if (!string.IsNullOrEmpty(_qKey)) { try { IndexRemoveTyped(assetKind, _qKey); } catch { } }

                                    }
                                    catch { /* best-effort */ }

                                    __imgOk = false;
                                }

                                // 1) Length parity for images when expected size known
                                if (__imgOk && !__isTinyImg && _qLen > 0 && __fiImg.Length != _qLen)
                                {
                                    try { Log($"[VERIFY] image length off — have {__fiImg.Length:N0} vs expected {_qLen:N0} — quarantine"); } catch { }
                                    try
                                    {
                                        var __qDir = Path.Combine(ImagesRoot, "_Quarantine");
                                        Directory.CreateDirectory(__qDir);
                                        string __qPath = MakeQuarantinePath(__qDir, finalPath, "LEN_OFF_IMG");

                                        // reuse existing same-hash file if present
                                        bool __skipMove = false;
                                        try
                                        {
                                            // Use the hash already embedded in __qPath; fallback to hashing only if missing
                                            var __h = ExtractHashFromQPath(__qPath) ?? QuickHash64k(finalPath);
                                            var __hit = FindQuarantineByHashName(__qDir, __h);

                                            if (__hit != null && !__hit.Equals(__qPath, StringComparison.OrdinalIgnoreCase))
                                            {
                                                __qPath = __hit;
                                                __skipMove = true;
                                            }
                                        }
                                        catch { }

                                        // media: move/copy only if not dedup-hit
                                        if (!__skipMove)
                                        {
                                            try { File.Move(finalPath, __qPath, true); }
                                            catch { try { File.Copy(finalPath, __qPath, true); File.Delete(finalPath); } catch { } }
                                        }
                                        else
                                        {
                                            try { File.Delete(finalPath); } catch { }
                                        }

                                        // sidecar .ok
                                        var _m = finalPath + ".ok";
                                        if (File.Exists(_m))
                                        {
                                            var _mq = __qPath + ".ok";
                                            try { File.Move(_m, _mq, true); }
                                            catch { try { File.Copy(_m, _mq, true); File.Delete(_m); } catch { } }
                                        }

                                        LogQuarantine(__skipMove ? "LEN_OFF_IMG_DEDUP" : "LEN_OFF_IMG", finalPath, __qPath);
                                        _qBad++;
                                        if (!string.IsNullOrEmpty(_qKey)) { try { IndexRemoveTyped(assetKind, _qKey); } catch { } }

                                    }
                                    catch { /* best-effort */ }

                                    __imgOk = false;
                                }

                                // 2) Header signature sanity (JPEG/PNG/GIF/WEBP)
                                if (__imgOk)
                                {
                                    try
                                    {
                                        Span<byte> __hdr = stackalloc byte[12];
                                        using var __fsProbe = new FileStream(finalPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                                        int __hn = __fsProbe.Read(__hdr);

                                        bool __isJpg = __hn >= 2 && __hdr[0] == 0xFF && __hdr[1] == 0xD8; // FF D8
                                        bool __isPng = __hn >= 4 && __hdr[0] == 0x89 && __hdr[1] == 0x50 && __hdr[2] == 0x4E && __hdr[3] == 0x47; // 89 50 4E 47
                                        bool __isGif = __hn >= 6 && __hdr[0] == 'G' && __hdr[1] == 'I' && __hdr[2] == 'F' && (__hdr[3] == '8') &&
                                                                      (__hdr[4] == '7' || __hdr[4] == '9') && __hdr[5] == 'a'; // GIF87a/89a
                                        bool __isWebp = __hn >= 12 && __hdr[0] == 'R' && __hdr[1] == 'I' && __hdr[2] == 'F' && __hdr[3] == 'F' &&
                                                                      __hdr[8] == 'W' && __hdr[9] == 'E' && __hdr[10] == 'B' && __hdr[11] == 'P';

                                        if (!(__isJpg || __isPng || __isGif || __isWebp))
                                        {
                                            try { Log("[VERIFY] image header not recognized — quarantine"); } catch { }
                                            var __qDir = Path.Combine(ImagesRoot, "_Quarantine");
                                            Directory.CreateDirectory(__qDir);
                                            string __qPath = MakeQuarantinePath(__qDir, finalPath, "BAD_SIG");

                                            // reuse existing same-hash file if present
                                            bool __skipMove = false;
                                            try
                                            {
                                                // Use the hash already embedded in __qPath; fallback to hashing only if missing
                                                var __h = ExtractHashFromQPath(__qPath) ?? QuickHash64k(finalPath);
                                                var __hit = FindQuarantineByHashName(__qDir, __h);

                                                if (__hit != null && !__hit.Equals(__qPath, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    __qPath = __hit;
                                                    __skipMove = true;
                                                }
                                            }
                                            catch { }

                                            // media: move/copy only if not dedup-hit
                                            if (!__skipMove)
                                            {
                                                try { File.Move(finalPath, __qPath, true); }
                                                catch { try { File.Copy(finalPath, __qPath, true); File.Delete(finalPath); } catch { } }
                                            }
                                            else
                                            {
                                                try { File.Delete(finalPath); } catch { }
                                            }

                                            var _m = finalPath + ".ok";
                                            if (File.Exists(_m))
                                            {
                                                var _mq = __qPath + ".ok";
                                                try { File.Move(_m, _mq, true); }
                                                catch { try { File.Copy(_m, _mq, true); File.Delete(_m); } catch { } }
                                            }

                                            LogQuarantine(__skipMove ? "BAD_SIG_DEDUP" : "BAD_SIG", finalPath, __qPath);
                                            _qBad++;
                                            if (!string.IsNullOrEmpty(_qKey)) { try { IndexRemoveTyped(assetKind, _qKey); } catch { } }
                                            __imgOk = false;
                                        }

                                    }
                                    catch
                                    {
                                        // On any read error, err on safety: quarantine
                                        try { Log("[VERIFY] image read error — quarantine"); } catch { }
                                        try
                                        {
                                            var __qDir = Path.Combine(ImagesRoot, "_Quarantine");
                                            Directory.CreateDirectory(__qDir);
                                            string __qPath = MakeQuarantinePath(__qDir, finalPath, "READ_ERR");

                                            // reuse existing same-hash file if present
                                            bool __skipMove = false;
                                            try
                                            {
                                                // Use the hash already embedded in __qPath; fallback to hashing only if missing
                                                var __h = ExtractHashFromQPath(__qPath) ?? QuickHash64k(finalPath);
                                                var __hit = FindQuarantineByHashName(__qDir, __h);

                                                if (__hit != null && !__hit.Equals(__qPath, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    __qPath = __hit;
                                                    __skipMove = true;
                                                }
                                            }
                                            catch { }

                                            // media: move/copy only if not dedup-hit
                                            if (!__skipMove)
                                            {
                                                try { File.Move(finalPath, __qPath, true); }
                                                catch { try { File.Copy(finalPath, __qPath, true); File.Delete(finalPath); } catch { } }
                                            }
                                            else
                                            {
                                                try { File.Delete(finalPath); } catch { }
                                            }

                                            // sidecar .ok
                                            var _m = finalPath + ".ok";
                                            if (File.Exists(_m))
                                            {
                                                var _mq = __qPath + ".ok";
                                                try { File.Move(_m, _mq, true); }
                                                catch { try { File.Copy(_m, _mq, true); File.Delete(_m); } catch { } }
                                            }

                                            LogQuarantine(__skipMove ? "READ_ERR_DEDUP" : "READ_ERR", finalPath, __qPath);
                                            _qBad++;
                                            if (!string.IsNullOrEmpty(_qKey)) { try { IndexRemoveTyped(assetKind, _qKey); } catch { } }

                                        }
                                        catch { /* best-effort */ }

                                        __imgOk = false;
                                    }
                                }

                                __svOk = __imgOk; // feed the existing flow
                                if (__imgOk) { PostAcceptCleanup(finalPath); }
                            }


                            // ignore obviously stale tiny expected vs large file
                            if (_qLen > 0 && __svFi.Length > (_qLen * 4)) _qLen = -1;

                            // hard gate for small ISO BMFF videos unless structure is present
                            // We set the threshold to ≤ 3 MB to catch the 0.9–1.9 MB failures you saw.
                            {
                                var __ext = Path.GetExtension(finalPath);
                                bool __mp4fam =
                                    __ext.Equals(".mp4", StringComparison.OrdinalIgnoreCase) ||
                                    __ext.Equals(".m4v", StringComparison.OrdinalIgnoreCase) ||
                                    __ext.Equals(".mov", StringComparison.OrdinalIgnoreCase) ||
                                    __ext.Equals(".ismv", StringComparison.OrdinalIgnoreCase);

                                if (__mp4fam && __svOk && __svFi.Length <= 3L * 1024 * 1024) // ≤ 3 MB
                                {
                                    if (!HasMoovOrMoofHeadTail(finalPath))
                                    {
                                        try { Log("[VERIFY] small mp4/m4v/mov without moov/moof — quarantine"); } catch { }
                                        try
                                        {
                                            var __qDir = Path.Combine(VideoRoot, "_Quarantine");
                                            Directory.CreateDirectory(__qDir);
                                            string __qPath = MakeQuarantinePath(__qDir, finalPath, "NO_MOOV_SMALL");

                                            // reuse existing same-hash file if present
                                            bool __skipMove = false;
                                            try
                                            {
                                                // Use the hash already embedded in __qPath; fallback to hashing only if missing
                                                var __h = ExtractHashFromQPath(__qPath) ?? QuickHash64k(finalPath);
                                                var __hit = FindQuarantineByHashName(__qDir, __h);

                                                if (__hit != null && !__hit.Equals(__qPath, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    __qPath = __hit;
                                                    __skipMove = true;
                                                }
                                            }
                                            catch { }

                                            // media: move/copy only if not dedup-hit
                                            if (!__skipMove)
                                            {
                                                try { File.Move(finalPath, __qPath, true); }
                                                catch { try { File.Copy(finalPath, __qPath, true); File.Delete(finalPath); } catch { } }
                                            }
                                            else
                                            {
                                                try { File.Delete(finalPath); } catch { }
                                            }

                                            // sidecar .ok
                                            var _m = finalPath + ".ok";
                                            if (File.Exists(_m))
                                            {
                                                var _mq = __qPath + ".ok";
                                                try { File.Move(_m, _mq, true); }
                                                catch { try { File.Copy(_m, _mq, true); File.Delete(_m); } catch { } }
                                            }
                                            LogVidVerifyTelemetry(
                                                "QUAR",
                                                finalPath,
                                                new FileInfo(finalPath).Length,
                                                HasMoovOrMoofHeadTail(finalPath),
                                                HasPlayableTrackQuick(finalPath),
                                                "NO_MOOV_SMALL"
                                            );

                                            LogQuarantine(__skipMove ? "NO_MOOV_SMALL_DEDUP" : "NO_MOOV_SMALL", finalPath, __qPath);
                                            _qBad++;
                                            if (!string.IsNullOrEmpty(_qKey)) { try { IndexRemoveTyped(assetKind, _qKey); } catch { } }

                                        }
                                        catch { /* best-effort */ }

                                        __svOk = false; // trigger re-fetch path
                                    }
                                }
                            }



                            if (string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase))
                            {
                                if (__svFi.Length < 24) __svOk = false;
                                else
                                {
                                    using var __svFs = new FileStream(finalPath, FileMode.Open, FileAccess.Read, FileShare.Read);

                                    // Quick header check (ftyp)
                                    Span<byte> __svHead = stackalloc byte[12];
                                    int __svN = __svFs.Read(__svHead);
                                    bool __svHeadOk = __svN >= 8
                                        && __svHead[4] == (byte)'f' && __svHead[5] == (byte)'t'
                                        && __svHead[6] == (byte)'y' && __svHead[7] == (byte)'p';
                                    if (!__svHeadOk) __svOk = false;
                                    // If _qLen is unknown, require moov/moof in file; otherwise reject.
                                    // This catches tiny SS fallbacks that wrote OK markers but are not playable.
                                    if (__svOk && _qLen <= 0)
                                    {
                                        bool __hasIndex = false;

                                        // Scan first and last up to 512 KB for 'moov' or 'moof'
                                        long __tail = Math.Min(512 * 1024, __svFi.Length);
                                        int __headScan = (int)Math.Min(512 * 1024, __svFi.Length);

                                        // First chunk
                                        byte[] __buf = new byte[__headScan];
                                        __svFs.Seek(0, System.IO.SeekOrigin.Begin);
                                        int __a = __svFs.Read(__buf, 0, __buf.Length);
                                        if (__a > 0)
                                        {
                                            string __s1 = System.Text.Encoding.ASCII.GetString(__buf, 0, __a);
                                            if (__s1.IndexOf("moov", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                __s1.IndexOf("moof", StringComparison.OrdinalIgnoreCase) >= 0)
                                                __hasIndex = true;
                                        }

                                        // Tail chunk (if not found in head)
                                        if (!__hasIndex && __tail > 0)
                                        {
                                            int __tlen = (int)__tail;
                                            if (__buf.Length < __tlen) __buf = new byte[__tlen];
                                            __svFs.Seek(Math.Max(0, __svFi.Length - __tail), System.IO.SeekOrigin.Begin);
                                            int __b = __svFs.Read(__buf, 0, __tlen);
                                            if (__b > 0)
                                            {
                                                string __s2 = System.Text.Encoding.ASCII.GetString(__buf, 0, __b);
                                                if (__s2.IndexOf("moov", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                    __s2.IndexOf("moof", StringComparison.OrdinalIgnoreCase) >= 0)
                                                    __hasIndex = true;
                                            }
                                        }


                                    }

                                    // tiny MP4 guard without killing legit shorts
                                    // Only run if MP4 family header already passed.
                                    if (__svHeadOk && __svFi.Length < 2_000_000)
                                    {
                                        bool __hasMoov = false;

                                        try
                                        {
                                            // Scan the first 256 KiB (or file length if smaller) for the 'moov' atom.
                                            int __scanLen = (int)Math.Min(__svFi.Length, 262_144);
                                            if (__scanLen > 8)
                                            {
                                                using (var __fs = __svFi.OpenRead())
                                                {
                                                    byte[] __buf = new byte[__scanLen];
                                                    int __n = __fs.Read(__buf, 0, __buf.Length);
                                                    for (int i = 0; i <= __n - 4; i++)
                                                    {
                                                        if (__buf[i] == (byte)'m' && __buf[i + 1] == (byte)'o' &&
                                                            __buf[i + 2] == (byte)'o' && __buf[i + 3] == (byte)'v')
                                                        {
                                                            __hasMoov = true;
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        catch { /* best-effort sniff; fall through */ }

                                        if (!__hasMoov)
                                        {
                                            __svOk = false;
                                            try { Log($"[REJECT] {assetKind} {Path.GetFileName(finalPath)} (no playable track)"); _sumRejects++; } catch { }
                                            try { Log($"[VERIFY] tiny mp4 rejected (no 'moov' atom; len={__svFi.Length})"); } catch { }
                                        }
                                    }
                                    // reject tiny SS result when HEAD/Range expected big
                                    // Uses _qLen (expected size) if known.
                                    long __exp = _qLen; // may be <= 0 if unknown
                                    if (__exp > 0 && __svFi.Length < 1_000_000 && __exp >= 16_000_000)
                                    {
                                        __svOk = false;
                                        try { Log($"[REJECT] {assetKind} {Path.GetFileName(finalPath)} (no playable track)"); _sumRejects++; } catch { }
                                        try { Log($"[VERIFY] tiny file vs expected — rejecting (have={__svFi.Length}, expected≈{__exp})"); } catch { }
                                    }

                                    else
                                    {
                                        // Tail is readable?
                                        long __svTail = Math.Min(16L, __svFi.Length);
                                        __svFs.Seek(__svFi.Length - __svTail, SeekOrigin.Begin);
                                        Span<byte> __svTailBuf = stackalloc byte[(int)__svTail];
                                        __svOk = __svFs.Read(__svTailBuf) > 0; // readable tail

                                        if (__svOk)
                                        {
                                            var __ext = Path.GetExtension(finalPath)?.ToLowerInvariant();
                                            if (__ext == ".mp4" || __ext == ".m4v" || __ext == ".mov")
                                            {
                                                // Optional tiny-file guard: header-only/ghost clips are almost always <512 KiB
                                                if (__svFi.Length < 2 * 1024 * 1024) // stricter: <2 MB without moov → fail
                                                {
                                                    __svOk = false;
                                                }
                                                else
                                                {
                                                    bool __hasMoov = false, __hasMoof = false, __hasMdat = false;

                                                    // Adaptive scan window: up to 4 MiB || file/8 (min 256 KiB)
                                                    int __win = (int)Math.Min(
                                                        Math.Max(256 * 1024, __svFi.Length / 8),
                                                        4L * 1024 * 1024);

                                                    int __bufLen = (int)Math.Min(__win, Math.Min(__svFi.Length, int.MaxValue));
                                                    byte[] __buf = System.Buffers.ArrayPool<byte>.Shared.Rent(__bufLen);
                                                    try
                                                    {
                                                        // Head scan
                                                        __svFs.Seek(0, SeekOrigin.Begin);
                                                        int __r = __svFs.Read(__buf, 0, Math.Min(__bufLen, (int)__svFi.Length));
                                                        for (int i = 0; i <= __r - 4 && !(__hasMoov || __hasMoof || __hasMdat); i++)
                                                        {
                                                            byte b0 = __buf[i], b1 = __buf[i + 1], b2 = __buf[i + 2], b3 = __buf[i + 3];
                                                            if (!__hasMoov && b0 == (byte)'m' && b1 == (byte)'o' && b2 == (byte)'o' && b3 == (byte)'v') __hasMoov = true;
                                                            if (!__hasMoof && b0 == (byte)'m' && b1 == (byte)'o' && b2 == (byte)'o' && b3 == (byte)'f') __hasMoof = true;
                                                            if (!__hasMdat && b0 == (byte)'m' && b1 == (byte)'d' && b2 == (byte)'a' && b3 == (byte)'t') __hasMdat = true;
                                                        }


                                                        // Tail scan if not found in head
                                                        if (!(__hasMoov || __hasMoof))
                                                        {
                                                            long __tailScan = Math.Min(256 * 1024L, __svFi.Length); // 256 KiB tail
                                                            __svFs.Seek(__svFi.Length - __tailScan, SeekOrigin.Begin);
                                                            int __r2 = __svFs.Read(__buf, 0, (int)__tailScan);
                                                            for (int i = 0; i <= __r2 - 4 && !(__hasMoov || __hasMoof || __hasMdat); i++)
                                                            {
                                                                byte b0 = __buf[i], b1 = __buf[i + 1], b2 = __buf[i + 2], b3 = __buf[i + 3];
                                                                if (!__hasMoov && b0 == (byte)'m' && b1 == (byte)'o' && b2 == (byte)'o' && b3 == (byte)'v') __hasMoov = true;
                                                                if (!__hasMoof && b0 == (byte)'m' && b1 == (byte)'o' && b2 == (byte)'o' && b3 == (byte)'f') __hasMoof = true;
                                                                if (!__hasMdat && b0 == (byte)'m' && b1 == (byte)'d' && b2 == (byte)'a' && b3 == (byte)'t') __hasMdat = true;
                                                            }
                                                        }


                                                    }
                                                    finally
                                                    {
                                                        System.Buffers.ArrayPool<byte>.Shared.Return(__buf);
                                                    }

                                                    // Guard: run ONLY for MP4-family video containers (.mp4/.m4v/.mov/…)
                                                    string __verExt = Path.GetExtension(finalPath)?.ToLowerInvariant() ?? "";
                                                    bool __isoBmffGate = __verExt is ".mp4" or ".m4v" or ".mov" or ".3gp" or ".3g2" or ".ismv" or ".f4v";

                                                    if (string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase) && __isoBmffGate)
                                                    {
                                                        // front-OR-tail scan so we don’t miss front-loaded moov
                                                        bool __hasMoovOrMoof = HasMoovOrMoofHeadTail(finalPath);

                                                        // require at least one playable track (vide/soun)
                                                        bool __hasPlayable = __hasMoovOrMoof && HasPlayableTrackQuick(finalPath);

                                                        if (!__hasPlayable)
                                                        {
                                                            // Hard gate for small MP4s (kills “thumbnail shells”)
                                                            if (__svFi.Length <= 8L * 1024 * 1024)
                                                                try { Log("[VERIFY] tiny MP4 lacked moov/playable — rejecting"); } catch { }
                                                            else
                                                                try { Log("[VERIFY] mp4 missing moov/playable — rejecting"); } catch { }

                                                            __svOk = false;
                                                            try { Log($"[REJECT] {assetKind} {Path.GetFileName(finalPath)} (verify fail)"); _sumRejects++; } catch { }
                                                        }
                                                        else
                                                        {
                                                            // veto only — reject tiny MP4s missing moov/moof (head/tail)
                                                            if (string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase)
                                                                && __svFi.Length < 4L * 1024 * 1024
                                                                && !HasMoovOrMoofHeadTail(finalPath))
                                                            {
                                                                try { Log("[VERIFY] small MP4 lacked moov/moof (head/tail) — rejecting"); } catch { }
                                                                __svOk = false; // veto
                                                                try { Log($"[REJECT] {assetKind} {Path.GetFileName(finalPath)} (small no moov/moof)"); _sumRejects++; } catch { }
                                                            }
                                                            else
                                                            {
                                                                __svOk = true; // accept only when moov/moof AND playable track are present
                                                                __quarOk = false;
                                                            }
                                                        }



                                                    }



                                                    // extra hardening: reject very small MP4s that have moov/moof but no 'mdat'
                                                    try
                                                    {
                                                        if (__svOk && __svFi.Length < 12L * 1024 * 1024) // < 12 MiB
                                                        {
                                                            var __mdatExt = System.IO.Path.GetExtension(finalPath)?.ToLowerInvariant();
                                                            if (__mdatExt == ".mp4" || __mdatExt == ".m4v" || __mdatExt == ".mov")
                                                            {
                                                                bool __mdatFound = false;
                                                                using (var __mdatFs = new System.IO.FileStream(finalPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                                                                {
                                                                    int __mdatScanWin = (int)System.Math.Min(1024 * 1024, __svFi.Length); // scan first 1 MiB
                                                                    byte[] __mdatBuf = new byte[__mdatScanWin];
                                                                    int __mdatN = __mdatFs.Read(__mdatBuf, 0, __mdatScanWin);

                                                                    ReadOnlySpan<byte> __sig = stackalloc byte[] { (byte)'m', (byte)'d', (byte)'a', (byte)'t' };
                                                                    for (int __j = 0; __j <= __mdatN - 4 && !__mdatFound; __j++)
                                                                    {
                                                                        if (new ReadOnlySpan<byte>(__mdatBuf, __j, 4).SequenceEqual(__sig))
                                                                            __mdatFound = true;
                                                                    }
                                                                }

                                                                if (!__mdatFound)
                                                                {
                                                                    try { Log($"[VERIFY] tiny MP4 had no 'mdat' — rejecting ({__svFi.Length:N0} bytes)"); } catch { }
                                                                    __svOk = false;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    catch { /* best-effort */ }






                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // No _qLen? Then tiny files must still prove they are real media.
                            if (!__svOk && _qLen <= 0)
                            {
                                if (__svFi.Length < 2 * 1024 * 1024)
                                {
                                    try { Log($"[VERIFY] tiny file without expected length — rejecting ({__svFi.Length:N0} bytes)"); } catch { }
                                    __svOk = false; // keep failing
                                }
                                // else leave __svOk as-is (must have passed moov/moof + mdat above)
                            }




                        }

                        catch { __svOk = false; }
                        if (!__svOk)
                        {
                            var __svFi = new FileInfo(finalPath);

                            __svFi.Refresh();
                            // optional early kill for HTML/JSON mislabeled as MP4
                            if (__svFi.Length < 2 * 1024 * 1024)
                            {
                                using var __svFs = new FileStream(finalPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                                Span<byte> __peek = stackalloc byte[(int)Math.Min(2048, __svFi.Length)];
                                int __n = __svFs.Read(__peek);

                                int __texty = 0;
                                for (int i = 0; i < __n; i++)
                                {
                                    byte b = __peek[i];
                                    if (b == (byte)'<' || b == (byte)'>' || b == (byte)'{' || b == (byte)'}' || b == (byte)'"' || b == (byte)'\'')
                                        __texty++;
                                }

                                if (__texty > 32)
                                {
                                    try { Log("[VERIFY] text/HTML body detected — rejecting"); } catch { }
                                    __svOk = false; // keep failing; later code will throw if needed
                                }
                            }

                            // Cache extension safely (no clash with quarantine's __ext) and treat ISO BMFF family
                            string __fileExt = Path.GetExtension(finalPath);
                            bool __isMp4Family =
                                string.Equals(__fileExt, ".mp4", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(__fileExt, ".m4v", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(__fileExt, ".mov", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(__fileExt, ".ismv", StringComparison.OrdinalIgnoreCase);

                            // hard gate for tiny ISO BMFF videos unless structure is present
                            if (__isMp4Family && __svFi.Length < 1L * 1024 * 1024) // < 1 MB
                            {
                                if (!HasMoovOrMoofHeadTail(finalPath))
                                {
                                    try { Log("[VERIFY] sub-1MB mp4/m4v/mov without moov/moof — rejecting"); } catch { }
                                    __svOk = false; // fall through to failure/quarantine path
                                }
                            }

                            // Size-parity accept — but require structure for small MP4-family videos
                            if (_qLen > 0 && __svFi.Length == _qLen)
                            {
                                bool __isSmall = __svFi.Length <= 8L * 1024 * 1024;

                                if (__isMp4Family && __isSmall)
                                {
                                    bool structOk = HasMoovOrMoofHeadTail(finalPath);
                                    __svOk = structOk;
                                    try { Log($"[VERIFY.PARITY.SMALL.MP4FAM] size matched, structure={(structOk ? "ok" : "missing")}"); } catch { }
                                }
                                else
                                {
                                    __svOk = true;
                                    try { Log("[VERIFY.PARITY] size matched — accepting"); } catch { }
                                }
                            }

                            // Short-circuit if any check above verified OK
                            if (__svOk)
                                return true;

                            // ignore obviously stale tiny expected vs large file
                            if (_qLen > 0 && __svFi.Length > (_qLen * 4)) _qLen = -1;

                            // re-HEAD same host with short backoff; accept when CL == file len
                            if (_qLen > 0 && __svFi.Length != _qLen)
                            {
                                try
                                {
                                    // Local helper (compile-safe: fully-qualified types)
                                    static bool __HasCdnRangeHint(System.Net.Http.HttpResponseMessage r)
                                        => r.Headers.TryGetValues("x-cache-range", out var v) && v.Any(); // coomer slices (e.g., 4MB)

                                    // Late-size propagation is common on coomer.*. Poll a few times before giving up.
                                    // Total wait ≈ 2+4+8+8 = 22s (bounded). Tune if needed.
                                    int[] __delays = new[] { 2000, 4000, 8000, 8000 };

                                    for (int __try = 0; __try < __delays.Length + 1; __try++)
                                    {
                                        using (var head2 = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Head, remoteUrl))
                                        {
                                            try { head2.Headers.AcceptEncoding.Clear(); } catch { } // no gzip

                                            using var res2 = await _http.SendAsync(
                                                head2, System.Net.Http.HttpCompletionOption.ResponseHeadersRead, ct
                                            ).ConfigureAwait(false);

                                            long cl2 = res2.Content.Headers.ContentLength ?? -1;

                                            // CDN slicing hint — prefer segmented (log-only here to keep compile-safe if hint flag isn't in scope)
                                            if (__HasCdnRangeHint(res2))
                                            {
                                                // DIAG ONLY
                                                // Log("[HEAD] cdn range slicing detected — prefer segmented");

                                                // Optional behavior (unchanged):
                                                // System.Threading.Volatile.Write(ref __preferSegmentedNextTry, true);
                                            }


                                            // Accept if CDN now agrees with our file
                                            if (cl2 > 0 && cl2 == __svFi.Length)
                                            {
                                                try { Log("[VERIFY] corrected stale expected by same-host HEAD; accepting"); } catch { }
                                                var __h = remoteUrl?.Host;
                                                if (!string.IsNullOrEmpty(__h)) { lock (_noRangeHosts) _noRangeHosts.Remove(__h); }
                                                return true;
                                            }

                                            // If HEAD still returns clearly stale (0 or far smaller), wait and retry
                                            bool __clearlyStale = (cl2 <= 0) || (__svFi.Length > (cl2 * 2L));
                                            if (__try < __delays.Length && __clearlyStale)
                                            {
                                                try { Log($"[VERIFY.HEAD.RETRY] stale CL={cl2} vs len={__svFi.Length} — backing off {(__delays[__try] / 1000)}s"); } catch { }
                                                await Task.Delay(__delays[__try], ct).ConfigureAwait(false);
                                                continue;
                                            }
                                        }

                                        // Not stale enough to justify more polling
                                        break;
                                    }

                                    // last resort: Range 0-0 to learn authoritative total (fast 206 with Content-Range)
                                    using (var r0 = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, remoteUrl))
                                    {
                                        // Force H/1.1 + identity for the probe
                                        try
                                        {
                                            r0.Version = new System.Version(1, 1); // old frameworks: use System.Version
                                                                                   // r0.VersionPolicy not available on older frameworks — intentionally omitted
                                            r0.Headers.AcceptEncoding.Clear();
                                            r0.Headers.AcceptEncoding.ParseAdd("identity");
                                            r0.Headers.ConnectionClose = true;
                                        }
                                        catch { }


                                        r0.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 0); // bytes=0-0

                                        using var res0 = await _http.SendAsync(
                                            r0, System.Net.Http.HttpCompletionOption.ResponseHeadersRead, ct
                                        ).ConfigureAwait(false);

                                        if ((int)res0.StatusCode == 206)
                                        {
                                            var cr = res0.Content.Headers.ContentRange;
                                            if (cr != null && cr.HasLength && cr.Length.HasValue && cr.Length.Value > 0)
                                            {
                                                long __total = cr.Length.Value;
                                                try { Log($"[SIZE.PROBE] content-range total={__total} (was expected={_qLen})"); } catch { }
                                                _qLen = __total;

                                                if (__total == __svFi.Length)
                                                {
                                                    try { Log("[VERIFY] size reconciled via Range 0-0; accepting"); } catch { }
                                                    var __h2 = remoteUrl?.Host;
                                                    if (!string.IsNullOrEmpty(__h2)) { lock (_noRangeHosts) _noRangeHosts.Remove(__h2); }
                                                    return true;
                                                }
                                            }
                                        }
                                    }
                                }
                                catch
                                {
                                    // best-effort; fall through to your existing failure path
                                }
                            }




                            // No expected length → enforce structure gate (mp4/m4v/mov)
                            if (_qLen <= 0 && !__svOk && __isMp4Family)
                            {
                                bool structOk = HasMoovOrMoofHeadTail(finalPath);
                                if (!structOk)
                                    try { Log("[VERIFY] mp4/m4v/mov (unknown len) missing moov/moof — rejecting"); } catch { }
                                __svOk = structOk;
                            }

                            // If verified OK by any of the checks above, stop here.
                            if (__svOk)
                                return true;

                            await Task.Delay(250).ConfigureAwait(false); // settle FS/AV
                            Log($"[VERIFY] fail sizeKnown={_qLen > 0} len={__svFi.Length} expect={_qLen}");

                            // move bad file out of the way, then retry via throw
                            try
                            {
                                var __dir = Path.GetDirectoryName(finalPath) ?? "";
                                var __qDir = Path.Combine(__dir, "_quarantine");
                                Directory.CreateDirectory(__qDir);

                                // build a unique quarantine path (avoid overwriting an older bad file)
                                var __base = Path.GetFileNameWithoutExtension(finalPath);
                                var __ext = Path.GetExtension(finalPath);
                                string __qPath = Path.Combine(__qDir, Path.GetFileName(finalPath));
                                int __n = 0;
                                while (File.Exists(__qPath) && __n < 50)
                                {
                                    __n++;
                                    __qPath = Path.Combine(__qDir, $"{__base} (bad{__n}){__ext}");
                                }

                                __quarOk = false; // was: bool __quarOk = false;
                                                  // media: try move; else copy+delete
                                try { File.Move(finalPath, __qPath, true); __quarOk = true; }
                                catch
                                {
                                    try { File.Copy(finalPath, __qPath, true); __quarOk = true; } catch { }
                                    try { if (__quarOk) File.Delete(finalPath); } catch { }
                                }

                                // sidecar: try move; else copy+delete
                                if (__quarOk)
                                {
                                    var _m = finalPath + ".ok";
                                    if (File.Exists(_m))
                                    {
                                        var _mq = __qPath + ".ok";
                                        try { File.Move(_m, _mq, true); }
                                        catch { try { File.Copy(_m, _mq, true); File.Delete(_m); } catch { } }
                                    }
                                }

                                if (__quarOk)
                                {
                                    // tiny settle to avoid false "truncated" on freshly closed files
                                    try
                                    {
                                        await Task.Delay(300).ConfigureAwait(false);
                                        __svFi.Refresh();
                                        const double VERIFY_IMG_FLOOR = 0.92; // accept if >=92% of expected
                                        if (_qLen > 0 && __svFi.Length >= (long)Math.Round(_qLen * VERIFY_IMG_FLOOR))
                                        {
                                            try { Log($"[VERIFY.RESTAT] IMG length caught up ({__svFi.Length}/{_qLen}) — accepting"); } catch { }
                                            __svOk = true; // finalize accept
                                            __quarOk = false; // skip quarantine path below
                                            try { Status.IncImgsOk(); } catch { }
                                            // remove identical twin in _quar (keeps library tidy)
                                            try
                                            {
                                                var __dir2 = Path.GetDirectoryName(finalPath);
                                                if (!string.IsNullOrEmpty(__dir2))
                                                {
                                                    var __quarPath2 = Path.Combine(__dir2, "_quar", Path.GetFileName(finalPath));
                                                    if (File.Exists(__quarPath2))
                                                    {
                                                        long __quarLen2 = new FileInfo(__quarPath2).Length;
                                                        if (__quarLen2 == __svFi.Length)
                                                        {
                                                            try { File.Delete(__quarPath2); Log($"[QUAR.CLEANUP] removed duplicate {Path.GetFileName(__quarPath2)}"); } catch { }
                                                        }
                                                    }
                                                }
                                            }
                                            catch { /* best-effort cleanup */ }

                                        }
                                    }
                                    catch { /* ignore */ }


                                    if (__quarOk)
                                    {
                                        try { Log($"[VERIFY.FAIL] {assetKind} appears truncated — moved to quarantine: {__qPath}"); } catch { }

                                        // write sidecar for run-end sweep
                                        try
                                        {
                                            var __qm = new
                                            {
                                                kind = assetKind, // "IMG" here
                                                postUrl = referer, // best-effort breadcrumb (referer is in scope)
                                                cdnUrl = remoteUrl?.ToString(), // CDN URL of quarantined image
                                                qLen = _qLen, // expected length (if known)
                                                localLen = __svFi.Length, // actual file length of quarantined file
                                                whenUtc = DateTime.UtcNow // timestamp of quarantine
                                            };

                                            var __qmetaPath = System.IO.Path.ChangeExtension(__qPath, ".qmeta.json");
                                            System.IO.File.WriteAllText(
                                                __qmetaPath,
                                                System.Text.Json.JsonSerializer.Serialize(__qm)
                                            );
                                        }
                                        catch { /* non-fatal */ }

                                        try { _qBad++; } catch { }

                                        // don’t reuse stale expectation/lock on retry
                                        try
                                        {
                                            _qLen = 0;
                                            _qHash64k = null;
                                            _qKey = null;
                                        }
                                        catch { }
                                    }

                                }


                            }
                            catch { /* best-effort quarantine */ }

                            throw new IOException("integrity verify failed");
                        }


                    VERIFY_DONE:
                        ;



                        long bytes2 = new FileInfo(finalPath).Length;
                        string human2 = bytes2 >= (1024 * 1024)
                            ? $"{bytes2 / (1024.0 * 1024.0):0.0} MB"
                            : $"{bytes2 / 1024.0:0} KB";


                        if (string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase))
                        {
                            TraceVidFs("final-ok", finalPath, bytes2, "verify-path");
                        }

                        Log($"[OK] {assetKind} saved {human2} → {Path.GetFileName(finalPath)}");

                        // mark Done (OK – verify path)
                        try
                        {
                            var __id = _qKey ?? finalPath ?? Guid.NewGuid().ToString("n");
                            CMDownloaderUI.QueueTap.MoveToDone(__id, ok: true);
                        }
                        catch { }

                        // add finalized file to recent list
                        try
                        {
                            CMDownloaderUI.WebUiHost.PushRecent(finalPath, delayMs: 1200);
                        }
                        catch { /* ignore UI sync errors */ }



                        // mirror accept → web status
                        try
                        {
                            if (string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase))
                                CMDownloaderUI.Status.IncVidsOk();
                            else if (string.Equals(assetKind, "IMG", StringComparison.OrdinalIgnoreCase))
                                CMDownloaderUI.Status.IncImgsOk();

                            long __bytes = 0;
                            try { __bytes = new System.IO.FileInfo(finalPath).Length; } catch { }
                            if (__bytes > 0) CMDownloaderUI.Status.AddBytesFetched(__bytes);
                        }
                        catch { }


                        long __okLenB = new FileInfo(finalPath).Length;
                        if (string.Equals(assetKind, "VID", StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                var __okPath = finalPath + ".ok";
                                TraceAnyWrite(__okPath, -1, "SIDE.OK.VID.META.B");

                                File.WriteAllText(__okPath,
                                    $"len={__okLenB};expected={(_qLen > 0 ? _qLen : -1)};h64={_qHash64k ?? string.Empty};ts={DateTime.UtcNow:O}",
                                    Encoding.UTF8);
                            }
                            catch { }
                        }

                        // no else here — quick add happens only in unified post-save block



                        // (duplicate removed)


                        if (assetKind == "VID") _sumVidsOk++; else if (assetKind == "IMG") _sumImgsOk++;
                        try { TrackAssetForPost(referer, assetKind, matchKey, finalPath); } catch { }
                        try { TrackAssetBytesForPost(referer, assetKind, finalPath); } catch { }


                        // Thumbnails were a legacy integrity proxy; acceptance is finalized without spawning ffmpeg.

                        // Unpeg the current progress bar for images
                        if (assetKind == "IMG")
                        {
                            try { ResetCurrentProgressUI(); } catch { /* best-effort */ }
                        }

                        if (assetKind == "VID")
                        {
                            try
                            {
                                // Post-save path no longer generates thumbnails || runs probes.

                                try
                                {
                                    var __h = remoteUrl?.Host; // if not in scope here, change to: var __h = host;
                                    if (!string.IsNullOrEmpty(__h) &&
                                        _noRangeHosts.Remove(__h) &&
                                        (s_ShouldLogOnce?.Invoke($"range.recover:{__h}", 60) == true))
                                    {
                                        Log($"[RANGE.RECOVER] {__h} SS success — re-enabling segmentation");
                                        try { s_NoRangeThisRun = false; lock (_noRangeHosts) { _noRangeHosts.Remove(__h); _noRangeHosts.Remove("*.coomer.st"); } } catch { }

                                    }
                                }
                                catch { /* best-effort */ }

                                // B1: always remove the sidecar on SS success (even if no unban/log printed)
                                try { File.Delete(finalPath + ".ok"); } catch { }

                                return true;
                            }

                            catch { /* swallow */ }
                        }



                        // (+) POST-DOWNLOAD DE-DUP: quick check first, then (if needed) full-hash
                        try
                        {
                            long len = bytes2; // already computed above
                            string h64k = await ComputeFirst64kSha256FromFileAsync(finalPath, ct).ConfigureAwait(false);
                            string canonical = finalPath;
                            var __ext = Path.GetExtension(canonical).ToLowerInvariant();
                            string qkey = ((__ext == ".mp4" || __ext == ".m4v" || __ext == ".mov" || __ext == ".avi" || __ext == ".mkv" || __ext == ".webm") ? "V" : "I") + $":{len}:{h64k}";

                            // Quick-index short-circuit
                            string? existingQuick = null;
                            lock (_idxQuick)
                            {
                                if (!_idxQuick.TryGetValue(qkey, out existingQuick)) ;
                            }
                            if (!string.IsNullOrEmpty(existingQuick) && !File.Exists(existingQuick))
                            {
                                lock (_idxQuick) _idxQuick.Remove(qkey);
                                existingQuick = null;
                                Log($"[IDX.PRUNE] Stale quick-entry: {qkey}");
                            }

                            // NEW: protect against image↔video collisions and bad quick-hit videos
                            if (!string.IsNullOrEmpty(existingQuick) && File.Exists(existingQuick) &&
                                !string.Equals(existingQuick, finalPath, StringComparison.OrdinalIgnoreCase))
                            {
                                var oldExt = (Path.GetExtension(existingQuick) ?? string.Empty).ToLowerInvariant();
                                var newExt = (Path.GetExtension(finalPath) ?? string.Empty).ToLowerInvariant();

                                bool oldIsVid = oldExt == ".mp4" || oldExt == ".m4v" || oldExt == ".mov"
                                             || oldExt == ".avi" || oldExt == ".mkv" || oldExt == ".webm";
                                bool newIsVid = newExt == ".mp4" || newExt == ".m4v" || newExt == ".mov"
                                             || newExt == ".avi" || newExt == ".mkv" || newExt == ".webm";

                                // 1) Cross-type quick-entry at same len+64k → treat as stale and drop it
                                if (oldIsVid != newIsVid)
                                {
                                    lock (_idxQuick) _idxQuick.Remove(qkey);
                                    existingQuick = null;
                                    Log($"[IDX.PRUNE] Cross-type quick-entry: {qkey}");
                                }

                                // 2) Video→video: kill tiny / non-playable ghosts instead of reusing them
                                else if (oldIsVid && newIsVid)
                                {
                                    try
                                    {
                                        var fi = new FileInfo(existingQuick);
                                        long qLen = fi.Length;

                                        bool looksTiny = qLen < MIN_VIDEO_BYTES; // e.g. < 3 MiB
                                        bool hasMoov = HasMoovOrMoofHeadTail(existingQuick); // structure scan
                                        bool playable = HasPlayableTrackQuick(existingQuick); // quick track scan

                                        if (looksTiny || !hasMoov || !playable)
                                        {
                                            // log + nuke this ghost and its quick entry
                                            try
                                            {
                                                Log($"[DEL.BAD] QUICK_VID_BAD file={Path.GetFileName(existingQuick)} len={qLen:N0}");
                                            }
                                            catch { }

                                            try { IndexRemoveQuick(qLen, h64k); } catch { }

                                            try
                                            {
                                                if (System.IO.File.Exists(existingQuick))
                                                    System.IO.File.Delete(existingQuick);
                                            }
                                            catch { }

                                            existingQuick = null; // so the quick-match branch below won’t fire
                                        }
                                    }
                                    catch
                                    {
                                        // any weirdness → treat as no quick hit and fall back to full flow
                                        existingQuick = null;
                                    }
                                }
                            }


                            if (!string.IsNullOrEmpty(existingQuick) && File.Exists(existingQuick) &&
                                !string.Equals(existingQuick, finalPath, StringComparison.OrdinalIgnoreCase))
                            {
                                try { File.Delete(finalPath); } catch { }
                                // No thumbnail deletion needed.
                                TryDeleteIfEmpty(targetDir); // same as your existing prune spot
                                _sumDedupLinks++;
                                canonical = existingQuick!;
                                Log($"[DEDUP] Quick-match (len+64k) — skipping new file; already have {Path.GetFileName(existingQuick)}");
                            }

                            else
                            {
                                // Fall back to strong hash
                                string full = await ComputeFileSha256Async(finalPath, ct).ConfigureAwait(false);

                                if (IndexTryGetByFull(full, out var existing) && File.Exists(existing) &&
                                    !string.Equals(existing, finalPath, StringComparison.OrdinalIgnoreCase))
                                {
                                    try { File.Delete(finalPath); } catch { }
                                    // No thumbnail deletion needed.
                                    TryDeleteIfEmpty(targetDir);
                                    _sumDedupLinks++;
                                    canonical = existing;
                                    Log($"[DEDUP] Duplicate detected — skipping new file; already have {Path.GetFileName(existing)}");
                                }


                                // Upsert FULL only if changed; quick add handled once post-save
                                bool __idxChanged = false;
                                try
                                {
                                    lock (_idxFull)
                                    {
                                        if (!_idxFull.TryGetValue(full, out var __oldF) ||
                                            !string.Equals(__oldF, canonical, StringComparison.OrdinalIgnoreCase))
                                        {
                                            __idxChanged = true;
                                        }
                                    }

                                    if (__idxChanged)
                                    {
                                        IndexUpsert(len, h64k, full, canonical); // full-only upsert
                                        IndexMarkDirty();
                                        if (_optSaveIndexPerFile)
                                            await SaveMediaIndexAsync().ConfigureAwait(false);
                                    }

                                    // QUICK add (single source of truth) — only when probe len matches real save len
                                    // NOTE: for IMG, defer quick-add until after THUMB.PRUNE to avoid stale entries
                                    if (!string.Equals(assetKind, "IMG", StringComparison.OrdinalIgnoreCase) &&
                                        File.Exists(finalPath))
                                    {
                                        long __realLen = 0;
                                        try { __realLen = new FileInfo(finalPath).Length; } catch { }

                                        if (__realLen > 0 &&
                                            _qLen > 0 &&
                                            _qLen == __realLen &&
                                            !string.IsNullOrWhiteSpace(_qHash64k))
                                        {
                                            IndexAddQuick(__realLen, _qHash64k!, finalPath);
                                        }
                                    }


                                }
                                catch { /* ignore index errors */ }





                                // clear in-flight key now that this item is finished
                                if (_qRegistered && _qKey != null) _inflightQuick.TryRemove(_qKey, out _);
                                _qRegistered = false; _qKey = null; _qLen = 0; _qHash64k = null;

                                return true;

                            }

                            // quick-match is a no-op for index (canonical already known); avoid dirty churn
                            // (we only write on strong-hash or final accept paths)
                            { /* no-op */ }

                        }
                        catch { /* ignore index errors */ }

                        _hadDownloads = true; _jitterScore = Math.Max(0, _jitterScore - 2);
                        AdjustHealthOnSuccess();
                        EndCurrentFileProgress();
                        // PATCH 2 — POST-SAVE inflight cleanup (quick add already done above)
                        try { /* no-op */ }
                        finally
                        {
                            if (_qRegistered && _qKey != null) _inflightQuick.TryRemove(_qKey, out _);
                            _qRegistered = false; _qKey = null; _qLen = 0; _qHash64k = null;
                            // clear global-queue inflight guard for this item
                            try
                            {
                                if (_globalQueueMode)
                                {
                                    var __core = matchKey
                                ?? (assetKind == "VID" ? VideoKeyFromUrl(remoteUrl)
                                                       : (ImageKey(remoteUrl.ToString()) ?? remoteUrl.ToString()));

                                    var __qk = (assetKind == "VID" ? "V:" : "I:") + __core;
                                    _inflightQ.TryRemove(__qk, out _);
                                }
                            }
                            catch { }

                        }

                        // If both "<name>.jpg" and "<name> (1).jpg" exist, keep the larger and delete the smaller.
                        if (string.Equals(assetKind, "IMG", StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                var tpDir = Path.GetDirectoryName(finalPath) ?? "";
                                var tpStem = Path.GetFileNameWithoutExtension(finalPath);
                                var tpExt = Path.GetExtension(finalPath); // renamed (no shadow)

                                // Normalize base name by stripping a trailing " (1)"
                                var tpRoot = tpStem.EndsWith(" (1)", StringComparison.Ordinal) ? tpStem[..^4] : tpStem;
                                var fileA = Path.Combine(tpDir, tpRoot + tpExt); // e.g., "01 - name.jpg"
                                var fileB = Path.Combine(tpDir, tpRoot + " (1)" + tpExt); // e.g., "01 - name (1).jpg"

                                if (File.Exists(fileA) && File.Exists(fileB))
                                {
                                    long lenA = 0, lenB = 0;
                                    try { lenA = new FileInfo(fileA).Length; } catch { }
                                    try { lenB = new FileInfo(fileB).Length; } catch { }

                                    // Delete the smaller; prefer the larger resolution
                                    if (lenA >= lenB)
                                    {
                                        if (!string.Equals(finalPath, fileB, StringComparison.OrdinalIgnoreCase))
                                            try { File.Delete(fileB); } catch { }
                                    }
                                    else
                                    {
                                        if (!string.Equals(finalPath, fileA, StringComparison.OrdinalIgnoreCase))
                                            try { File.Delete(fileA); } catch { }
                                    }
                                }
                            }
                            catch { /* best-effort */ }
                        }
                        // quick-add IMG only after prune picks the keeper
                        if (string.Equals(assetKind, "IMG", StringComparison.OrdinalIgnoreCase) &&
                            File.Exists(finalPath))
                        {
                            try
                            {
                                long __lenImg = new FileInfo(finalPath).Length;
                                if (__lenImg > 0)
                                {
                                    string __h64Img = await ComputeFirst64kSha256FromFileAsync(finalPath, ct).ConfigureAwait(false);
                                    if (!string.IsNullOrWhiteSpace(__h64Img))
                                        IndexAddQuick(__lenImg, __h64Img, finalPath);
                                }
                            }
                            catch { /* best-effort */ }
                        }

                        // On successful single-stream save, fully unban this host
                        if (!string.IsNullOrEmpty(remoteUrl?.Host))
                        {
                            lock (_noRangeHosts)
                            {
                                var h = remoteUrl.Host;
                                bool removed = _noRangeHosts.Remove(h) | (_range200?.Remove(h) ?? false); // no short-circuit
                                if (removed) { try { Log($"[RANGE] unban \u2190 {h} (single-stream success)"); } catch { } }
                            }
                        }
                        // B4B — clear TTL ban on SS success (exact paste line)
                        try { if (remoteUrl?.Host is string __h && __h.Length > 0) _rangeBanUntil.Remove(__h); } catch { }

                        // (keep whatever logging/counters you already have)
                        try { Log("[SS.DONE] saved OK"); } catch { }
                        try { if (!string.IsNullOrEmpty(_qKey)) _inflightQ.TryRemove(_qKey, out _); } catch { }

                        try { var h = remoteUrl?.Host; if (!string.IsNullOrEmpty(h)) lock (_noRangeHosts) _noRangeHosts.Remove(h); } catch { }
                        return true;

                    }
                    catch (Exception ex)
                    {
                        if (ct.IsCancellationRequested || ex is OperationCanceledException || ex is TaskCanceledException)
                            // CANCEL: end progress; if SS <50% written, scrap the .part so it redownloads next run
                            if (ct.IsCancellationRequested || ex is OperationCanceledException || ex is TaskCanceledException)
                            {
                                try
                                {
                                    if (assetKind == "VID" && !string.IsNullOrEmpty(tempPath))
                                    {
                                        long wrote = 0;
                                        try { var fi = new FileInfo(tempPath); if (fi.Exists) wrote = fi.Length; } catch { }

                                        long expect = Math.Max(_qLen, 0); // 0 = unknown → don’t delete
                                        if (expect > 0 && wrote > 0 && (wrote * 2) < expect)
                                        {
                                            try { Log($"[STOP] Discarding partial single-stream (<50%) {Path.GetFileName(finalPath)} ({wrote / (1024.0 * 1024):0.0} MB of {expect / (1024.0 * 1024):0.0} MB)"); } catch { }
                                            try { File.Delete(tempPath); } catch { /* best-effort */ }
                                        }
                                    }
                                }
                                catch { /* ignore cleanup errors */ }

                                EndCurrentFileProgress();
                                Log("[CANCEL] Download canceled");
                                return false;
                            }
                        try { EndCurrentFileProgress(); } catch { /* best-effort */ }

                        // On failure of single-stream || segmented path: //

                        if (!(assetKind == "VID")) { try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { } }
                        if (was5xxThisAttempt) server5xxCount++;
                        try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }

                        int? sc = TryStatusCodeFromException(ex);
                        var isData = remoteUrl.AbsolutePath.Contains("/data/", StringComparison.OrdinalIgnoreCase);
                        bool earlyRotateEligible = sc == 404 || sc == 410;

                        bool shouldTryRefresh = (!refreshedOnce) && ((server5xxCount >= 2) || (earlyRotateEligible && isData));
                        if (!NATURAL_URL_ONLY && shouldTryRefresh && matchKey != null && (assetKind == "IMG" || assetKind == "VID"))
                        {
                            var newUrl = await RefreshAssetUrlAsync(assetKind, referer, matchKey, ct).ConfigureAwait(false);
                            if (newUrl != null && !newUrl.Equals(remoteUrl))
                            {
                                Log($"[REFRESH] {assetKind} URL rotated → retrying with new URL");
                                remoteUrl = newUrl; refreshedOnce = true;
                            }
                        }
                        // Early bail policy: if consistently 404/410, allow only 2 attempts total and skip watchdog.
                        if (sc == 404 || sc == 410)
                        {
                            notFoundCount++;
                            if (attempt >= 1)
                            {
                                Log($"[GONE] {assetKind} HTTP {sc} after {attempt + 1} attempts → {Path.GetFileName(finalPath)} (early bail; skipping watchdog)");
                                bailNotFound = true;

                                // NEW: remember within this run so we don't re-queue this asset again
                                if (!string.IsNullOrWhiteSpace(finalPath))
                                    _knownGone.Add(finalPath);

                                return false;
                            }
                            // Skip edge health penalty but still do retry delay/log //
                            goto NoHealthPenalty;
                        }


                        // Start cooldown for network-class failures //
                        if (sc == 429 || sc == 420 || (sc >= 500 && sc <= 599) // rate-limit/5xx
                            || (ex is HttpRequestException) // conn/TLS errors
                            || (ex is TaskCanceledException) // hard timeout
                            || ex.Message.IndexOf("timeout", StringComparison.OrdinalIgnoreCase) >= 0) // timeouts
                        {
                            if (!string.IsNullOrEmpty(_lastEdgeHost))
                                _edgeCooldown[_lastEdgeHost] = DateTime.UtcNow.AddSeconds(120);
                        }

                        AdjustHealthOnFailure(sc, ex);
                    NoHealthPenalty:;

                        // If this is an early-bail not-found path, don’t spam a generic [RETRY] line || wait.
                        if (!bailNotFound)
                        {
                            // micro-jitter for video idle timeouts (avoid hammering same hot edge)
                            if (string.Equals(assetKind, "VID", StringComparison.Ordinal) &&
                                ex is IOException ioex &&
                                ioex.Message.IndexOf("read idle timeout", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                await Task.Delay(_rnd.Next(50, 151), ct); // 50–150 ms //
                            }

                            var delayMs = Math.Min(3200, 400 * (int)Math.Pow(2, attempt));
                            var jitterMul = 0.85 + _rnd.NextDouble() * 0.40;
                            delayMs = (int)(delayMs * jitterMul);

                            // IF2 — integrity failure → hop to a different edge for the next attempt (independent of IMG log suppression)
                            if (string.Equals(assetKind, "VID", StringComparison.Ordinal)
                                && (ex?.ToString()?.IndexOf("integrity verify failed", StringComparison.OrdinalIgnoreCase) >= 0)
                                && !NATURAL_URL_ONLY
                                && _edge is { } edgeHopIF2b)

                            {
                                var oldHostIF2b = remoteUrl?.Host;

                                // rotate until we get a different host (guard a few spins)
                                var guardIF2b = 0;
                                string nextHostIF2b = null;
                                do
                                {
                                    edgeHopIF2b.HopNext();
                                    nextHostIF2b = edgeHopIF2b.ResolveHostForNewDownload();
                                }
                                while (!string.IsNullOrEmpty(nextHostIF2b)
                                       && string.Equals(nextHostIF2b, oldHostIF2b, StringComparison.OrdinalIgnoreCase)
                                       && ++guardIF2b < 4);

                                if (!string.IsNullOrEmpty(nextHostIF2b)
                                    && !string.Equals(nextHostIF2b, oldHostIF2b, StringComparison.OrdinalIgnoreCase))
                                {
                                    remoteUrl = edgeHopIF2b.RewriteUriHost(remoteUrl, nextHostIF2b);
                                    try { Log($"[INTEGRITY] hop for next attempt: {oldHostIF2b} → {remoteUrl.Host}"); } catch { }
                                }
                            }
                            // small videos (≤96 MiB) get at most 2 attempts
                            long sizeBytes = (_qLen > 0) ? _qLen : -1; // existing field
                            int attemptCap = MaxAttempts; // read current budget; DO NOT assign back

                            if (string.Equals(assetKind, "VID", StringComparison.Ordinal) &&
                                sizeBytes > 0 && sizeBytes <= 96L * 1024 * 1024)
                            {
                                attemptCap = Math.Min(attemptCap, 2);
                            }

                            // Use `attemptCap` in your retry loop (replace the old bound):
                            // for (int attempt = 1; attempt <= attemptCap; attempt++) { ... }




                            // Keep the original IMG attempt-0 suppression ONLY around the retry log
                            if (!(string.Equals(assetKind, "IMG", StringComparison.Ordinal) && attempt == 0))
                                Log($"[RETRY] {assetKind} attempt {attempt + 1}/{MaxAttempts} failed: {ex.Message} (wait {delayMs}ms)");
                            try { StartCooldown(_lastEdgeHost, COOLDOWN_SEC); } catch { }




                            // release quick in-flight lock before we back off, so next attempt can re-register
                            try
                            {
                                if (_qRegistered && _qKey != null)
                                {
                                    _inflightQuick.TryRemove(_qKey, out _);
                                    _qRegistered = false; // ensure the next attempt re-adds via TryAdd
                                }
                            }
                            catch { /* best effort */ }

                            _jitterScore = Math.Min(6, _jitterScore + 1);
                            await Task.Delay(delayMs, ct);

                        }


                    }
                }

                Log($"[FAIL] {assetKind} after {MaxAttempts} attempts → {finalPath}");
                // ensure quick in-flight key is cleared after a final failure
                try
                {
                    if (_qRegistered && _qKey != null)
                    {
                        _inflightQuick.TryRemove(_qKey, out _);
                    }
                }
                catch { /* best-effort */ }
                finally
                {
                    _qRegistered = false;
                    _qKey = null;
                    _qLen = 0;
                    _qHash64k = null;
                }

                if (assetKind == "VID")
                {
                    _sumVidsFailed++;
                    try { _failedVidNames.Add(Path.GetFileName(finalPath)); } catch { }
                }
                // remember hard failure under matchKey (or finalPath)
                try
                {
                    string key = !string.IsNullOrWhiteSpace(matchKey)
                        ? matchKey!
                        : (!string.IsNullOrWhiteSpace(finalPath) ? finalPath : null);

                    if (!string.IsNullOrWhiteSpace(key))
                    {
                        lock (_failIndex)
                        {
                            if (!_failIndex.TryGetValue(key, out var meta) || meta == null)
                            {
                                meta = new FailMeta();
                                _failIndex[key] = meta;
                            }

                            meta.AttemptsTotal += MaxAttempts;
                            meta.LastAttemptUtc = DateTime.UtcNow;
                        }

                        // piggy-back on existing index flush timer
                        _idxDirty = 1;
                    }
                }
                catch { /* best-effort */ }

                // block watchdog during graceful/immediate drain
                bool _skipWd =
                    bailNotFound // 404/410 early-bail → never queue
                    || _stopImmediate // hard stop → don't seed WD
                    || (_stopRequested && _stopMode == StopMode.Graceful) // graceful drain → finish inflight only
                    || s_Draining; // global drain flag (planner snapped to SS)

                if (!_skipWd)
                {
                    if (!_stopImmediate && !(_stopRequested && _stopMode == StopMode.Graceful) && !s_Draining)
                    {
                        EnqueueForWatchdog(remoteUrl, naming, assetIndex, assetKind, referer, matchKey, "final failure");
                    }

                }
                else
                {
                    try
                    {
                        var why =
                            bailNotFound ? "404/410" :
                            _stopImmediate ? "immediate stop" :
                            (_stopRequested && _stopMode == StopMode.Graceful) ? "graceful" :
                            "drain";
                        Log($"[WD.SKIP] {why} → not re-queued");
                    }
                    catch { /* noop */ }
                }

                EndCurrentFileProgress();
                return false;



            }
            finally { _inProgress.TryRemove(finalPath, out _); }

        }
        private int _nextWorkerId = 0;
        private int _coomerLoginInFlight = 0;

        private int SweepOrphanOk(string root)
        {
            int n = 0;
            try
            {
                if (!Directory.Exists(root)) return 0;
                foreach (var ok in Directory.EnumerateFiles(root, "*.ok", SearchOption.AllDirectories))
                {
                    var media = ok.Substring(0, ok.Length - 3);
                    // delete marker if no media, || if the media is an image type (we don’t use .ok for images)
                    if (!File.Exists(media)
                        || media.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase)
                        || media.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase)
                        || media.EndsWith(".png", StringComparison.OrdinalIgnoreCase)
                        || media.EndsWith(".webp", StringComparison.OrdinalIgnoreCase)
                        || media.EndsWith(".gif", StringComparison.OrdinalIgnoreCase))
                    {
                        try { File.Delete(ok); n++; Log($"[SWEEP] deleted stray .ok → {ok}"); } catch { }
                    }
                }
            }
            catch { }
            return n;
        }
        // accept/quarantine counters
        private int _accVid = 0, _accImg = 0;
        private readonly Dictionary<string, int> _quarByReason = new(StringComparer.OrdinalIgnoreCase);

        private int _sumRejects = 0;
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _segHostLast = new(StringComparer.OrdinalIgnoreCase);
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> _pathsCreatedThisRun =
        new(StringComparer.OrdinalIgnoreCase);

        private long _segPlanTotal, _segPlanSupp, _segPlanInteresting;
        // per-post byte totals (for per-post summary)
        private readonly Dictionary<string, (long imgBytes, long vidBytes)> _postAssetBytes = new();

        // last post we were working on (so we can emit summary on next [NAV])
        private string? _lastNavPostUrl = null;


        private Dictionary<string, DateTime>? _segZeroTs;
        // soft per-host backoff instead of sticky ban
        private readonly Dictionary<string, DateTime> _rangeBanUntil = new(StringComparer.OrdinalIgnoreCase);
        // 20s is enough to drain current SS work without pinning us forever
        private const int RANGE_BAN_TTL_SECONDS = 20;
        private volatile bool _pwFullyReady = false;

        private int __autoFullStreak = 0, __autoFreeStreak = 0;
        private bool __autoForceSS = false;


        private volatile bool _segAutoPoolFull = false;
        private int _segAutoConsecFull = 0;
        private int _segAutoConsecFree = 0;
        private long _segAutoLastLogKey = -1;

        private long _writerGuardTotal;
        private long _writerGuardBurst;
        private string? _writerGuardSample;
        private long _probeHeadTotal, _probeHeadSupp, _probeHeadInteresting;
        private long _probeR00Total, _probeR00Supp, _probeR00Interesting;
        private long _fsWriteTotal, _fsWriteSupp, _fsWriteInteresting;
        private long _nameIdxTotal, _nameIdxSupp, _nameIdxInteresting;



        // graceful stop flags
        private enum StopMode { Immediate, Graceful }
        private volatile bool _stopRequested;
        private StopMode _stopMode;
        private volatile bool _stopImmediate = false;

        private int _sumDedupCopies; // count copy fallbacks (not links)
                                     // last activity baseline for the download watchdog
        private DateTime _lastProgressUtc = DateTime.UtcNow;
        // ---- Segmented video helpers ---- //
        private int ChooseSegmentCountTuned(long totalBytes)
        {
            if (totalBytes <= 24L * 1024 * 1024) return 1; // force SS for ≤24 MiB

            if (s_NoRangeThisRun && _lastSegZeroUtc.AddSeconds(20) > DateTime.UtcNow) return 1;
            s_NoRangeThisRun = false; // cap expired → let planner proceed

            // Delegate to dynamic planner based on size, pool, and current active videos //
            return SuggestSegments(totalBytes, RANGE_POOL_MAX, _activeSegVideos);
        }
        // Re-probe remote length a few times to let CDN/origin "settle" the true size
        private async Task<long> WaitForSettledLengthAsync(string url, CancellationToken ct)
        {
            // ~60s total: 0.5s + 1s + 2s + 4s + 8s + 16s + 28.5s
            int[] delaysMs = { 500, 1000, 2000, 4000, 8000, 16000, 28500 };

            long lastLen = 0;
            for (int i = 0; i < delaysMs.Length; i++)
            {
                ct.ThrowIfCancellationRequested();

                long probe = 0;
                try { probe = await GetRemoteLengthAsync(url, ct).ConfigureAwait(false); }
                catch { /* ignore transient */ }

                if (probe > 0)
                {
                    if (lastLen > 0 && probe == lastLen)
                        return probe; // stable two times in a row
                    lastLen = probe;
                }

                try { await Task.Delay(delaysMs[i], ct).ConfigureAwait(false); }
                catch (TaskCanceledException) { throw; }
            }

            return lastLen; // may be 0 if never learned; caller handles fallback
        }


        private async Task<(bool supportsRange, long totalSize)> ProbeRangeSupportAsync(
        Uri url, string? referer, CancellationToken ct)
        {
            try
            {
                // Some servers misreport on HEAD. We collect what we can from HEAD,
                // then ALWAYS validate with a tiny Range GET (0-0).
                long headLength = -1;
                bool headSaysBytes = false;
                if (_qLen > 0 && _qLen <= 24L * 1024 * 1024) { headLength = _qLen; headSaysBytes = false; goto AFTER_HEAD_PROBE; }

                // 1) HEAD probe: look for Content-Length + Accept-Ranges: bytes
                using (var head = new HttpRequestMessage(HttpMethod.Head, url))
                {
                    if (Uri.TryCreate(referer, UriKind.Absolute, out var ref1))
                        head.Headers.Referrer = ref1;

                    // Avoid gzip/etc. confusing length accounting
                    head.Headers.AcceptEncoding.Clear();

                    using var res = await _http.SendAsync(
                        head, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

                    if ((int)res.StatusCode >= 200 && (int)res.StatusCode < 400)
                    {
                        headLength = res.Content.Headers.ContentLength ?? -1;
                        headSaysBytes = res.Headers.AcceptRanges?.Any(v => v.Equals("bytes", StringComparison.OrdinalIgnoreCase)) == true;
                        // HEAD hints slicing → prefer segmented on next planner decision
                        try
                        {
                            bool __cdnSlices =
                                (res.Headers.TryGetValues("x-cache-range", out var __xcr) &&
                                 __xcr.Any(v => v?.IndexOf("bytes", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                v?.IndexOf("slice", StringComparison.OrdinalIgnoreCase) >= 0))
                                || (res.Headers.TryGetValues("x-akamai-transformed", out var __aka) && __aka.Any())
                                || (res.Headers.TryGetValues("server", out var __srv) &&
                                    __srv.Any(v => v?.IndexOf("cloudfront", StringComparison.OrdinalIgnoreCase) >= 0));

                            if (__cdnSlices)
                            {
                                System.Threading.Volatile.Write(ref __preferSegmentedNextTry, true);

                                // DIAG ONLY
                                // Log("[HEAD] CDN range slicing hinted — prefer segmented on next planner decision");
                            }

                        }
                        catch { /* best-effort */ }

                    }
                }
            AFTER_HEAD_PROBE:;
                // Coomer edge slow-sync guard: stabilize size via HEAD + Range 0–0

                {
                    // Hold-first-then-match gate (clean)
                    long __N0 = headLength; // from first credible probe
                    var __u0 = (url is System.Uri uu) ? uu : new System.Uri(url.ToString());
                    string __edge0 = __u0.Host;
                    // per-VID: don’t seed with any prior quick length; this lock is URL-local
                    int __sameCount = 0;
                    bool __matched = false;
                    bool __rotated = false;


                    // Require credible N0: large enough and range honored
                    if (__N0 >= MIN_LARGE_BYTES && (headSaysBytes == true))
                    {

                        // Legit-small fast path: ≤2 MiB → do not stall
                        if (__N0 > 0 && __N0 <= TINY_BYTES)
                        {
                            // DIAG ONLY
                            // Log($"[MATCH] N={__N0} reason=tiny-fastpath");

                            __matched = true;
                        }

                        else
                        {
                            // DIAG ONLY
                            // Log($"[LOCK] N0={__N0} edge={__edge0}");


                            for (int __pass = 0; __pass < 2 && !__matched; __pass++)
                            {
                                var __delays = SIZE_BACKOFFS;
                                for (int k = 0; k < __delays.Length && !__matched; k++)
                                {
                                    await Task.Delay(__delays[k], ct).ConfigureAwait(false);

                                    // HEAD probe
                                    using (var __h = new HttpRequestMessage(HttpMethod.Head, url))
                                    {
                                        try { __h.Headers.AcceptEncoding.Clear(); } catch { }
                                        using var __r = await _http.SendAsync(__h, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                                        long __cl = __r.Content.Headers.ContentLength ?? -1;
                                        string __etag = __r.Headers.ETag?.Tag ?? string.Empty;
                                        string __edge = __h.RequestUri?.Host ?? __edge0;
                                        string __cr = __r.Content.Headers.ContentRange?.ToString() ?? string.Empty;

                                        // DIAG ONLY
                                        // Log($"[PROBE] head={__cl} cr={__cr} etag={__etag} edge={__edge}");

                                        if (__cl == __N0)
                                        {
                                            if (__edge == __edge0) __sameCount++;
                                            if (__edge != __edge0 || __sameCount >= 2)
                                            {
                                                __matched = true;
                                                // DIAG ONLY
                                                // Log($"[MATCH] N={__cl} reason={(__edge == __edge0 ? "same-edge" : "cross-edge")}");
                                                break;
                                            }
                                        }
                                    }


                                    // Suffix probe (Range: bytes=-1)
                                    if (!__matched)
                                    {
                                        using var __sreq = new HttpRequestMessage(HttpMethod.Get, url);
                                        __sreq.Headers.Range = new RangeHeaderValue(null, -1);
                                        try { __sreq.Headers.AcceptEncoding.Clear(); } catch { }
                                        using var __sres = await _http.SendAsync(__sreq, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                                        var __scr = __sres.Content.Headers.ContentRange?.ToString() ?? string.Empty;

                                        if (__scr.EndsWith("/" + __N0) || __scr.Contains("/" + __N0))
                                        {
                                            __matched = true;

                                            // DIAG ONLY
                                            // Log($"[MATCH] N={__N0} reason=suffix");

                                            break;
                                        }
                                    }

                                }

                                if (!__matched && !__rotated)
                                {
                                    try { Log("[TIMEOUT] no match — rotate"); } catch { }
                                    __rotated = true; // actual edge flip handled by planner elsewhere
                                }
                            }

                            if (!__matched)
                            {
                                try { Log("[TIMEOUT] no match — DEFER warming"); } catch { }
                                await Task.Delay(90_000, ct).ConfigureAwait(false); // non-blocking requeue can replace this later
                            }
                        }
                    }
                }



                // One-shot Range sanity check (cached per host)
                {
                    var host = url.Host;
                    if (!_noRangeHosts.Contains(host))

                    {
                        try
                        {
                            using var rangeProbe = new HttpRequestMessage(HttpMethod.Get, url);
                            rangeProbe.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 0);
                            rangeProbe.Headers.ConnectionClose = true;
                            rangeProbe.Version = System.Net.HttpVersion.Version11;

                            using var resProbe = await _http.SendAsync(
                                rangeProbe, HttpCompletionOption.ResponseHeadersRead, ct
                            ).ConfigureAwait(false);
                            using var resProbe2 = await _http.SendAsync(
                            rangeProbe, HttpCompletionOption.ResponseHeadersRead, ct
                            ).ConfigureAwait(false);

                            // — bail if MIME is obviously wrong for the URL kind
                            var mime = resProbe2.Content.Headers.ContentType?.MediaType?.ToLowerInvariant() ?? "";
                            string u = rangeProbe.RequestUri?.AbsoluteUri ?? ""; // use rangeProbe instead of remoteUrl

                            bool looksVid = u.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase)
                                         || u.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase)
                                         || u.EndsWith(".mov", StringComparison.OrdinalIgnoreCase)
                                         || u.EndsWith(".webm", StringComparison.OrdinalIgnoreCase)
                                         || u.EndsWith(".mkv", StringComparison.OrdinalIgnoreCase);

                            bool looksImg = u.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase)
                                         || u.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase)
                                         || u.EndsWith(".png", StringComparison.OrdinalIgnoreCase)
                                         || u.EndsWith(".gif", StringComparison.OrdinalIgnoreCase)
                                         || u.EndsWith(".webp", StringComparison.OrdinalIgnoreCase);

                            bool mimeNonVideo = mime.StartsWith("image/") || mime.StartsWith("text/") || mime == "application/json" || mime == "application/xml";

                            if (looksVid && mimeNonVideo)
                            {
                                try { Log("[CT.GUARD] URL looks video but Content-Type is non-video; skipping quick fp"); } catch { }
                                return (false, 0L); // return a harmless default instead of null
                            }

                            if (looksImg && (mime.StartsWith("text/") || mime == "application/json"))
                            {
                                try { Log("[CT.GUARD] URL looks image but Content-Type is text/json; skipping quick fp"); } catch { }
                                return (false, 0L);
                            }

                            if (resProbe.StatusCode == System.Net.HttpStatusCode.PartialContent)
                            {
                                var h = url.Host;
                                bool __removed;
                                lock (_noRangeHosts) __removed = _noRangeHosts.Remove(h);
                                if (__removed && (s_ShouldLogOnce?.Invoke($"range.recover:{h}", 60) == true))
                                    try { Log($"[RANGE.RECOVER] {h} 206 probe OK — re-enabling segmentation"); } catch { }
                                try { s_NoRangeThisRun = false; lock (_noRangeHosts) { _noRangeHosts.Remove(h); _noRangeHosts.Remove("*.coomer.st"); } } catch { }



                                // score/cooldown touch for a good probe
                                try { BumpHostScore(h, +2); _hostCooldown.Remove(h); } catch { }

                                // probe OK log (throttled)
                                // ProbeLogThrottled(h, true, $"[RANGE.PROBE] {h} → OK (Range honored)");


                                // optional pin on first success (keep if you still want this behavior)
                                /* rangeSafe retired */
                                /* range200 retired */
                                if (!NATURAL_URL_ONLY && string.IsNullOrEmpty(_pinnedRangeHost) && !_noRangeHosts.Contains(h))
                                {
                                    _pinnedRangeHost = h;
                                    try { if (s_ShouldLogOnce?.Invoke("edge.pin", 60) == true) Log($"[EDGE.PIN] pin → {_pinnedRangeHost} (0–0 probe)"); } catch { }
                                }

                                // ...rest of your existing 206-handling code...
                            }



                            else if (resProbe.StatusCode == HttpStatusCode.OK)
                            {
                                // DIAG ONLY
                                // ProbeLogThrottled(host, false, $"[RANGE.PROBE] {host} → NO (server ignored Range)");
                            }

                        }
                        catch (Exception ex)
                        {
                            if (_rpFailSeen.Add(host)) // log once per host per run
                                try { Log($"[RANGE.PROBE] {host} → FAIL ({ex.GetType().Name})"); } catch { }
                        }



                    }
                }

                // 2) Validation probe: tiny ranged GET (0-0) to force Content-Range
                using var probe = new HttpRequestMessage(HttpMethod.Get, url);
                if (Uri.TryCreate(referer, UriKind.Absolute, out var ref2))
                    probe.Headers.Referrer = ref2;

                probe.Headers.Range = new RangeHeaderValue(0, 0);
                probe.Headers.AcceptEncoding.Clear();

                using var res2 = await _http.SendAsync(
                    probe, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

                if (res2.StatusCode == HttpStatusCode.PartialContent)
                {
                    var cr = res2.Content?.Headers?.ContentRange;
                    if (cr != null &&
                        string.Equals(cr.Unit, "bytes", StringComparison.OrdinalIgnoreCase) &&
                        cr.HasLength && cr.Length is long L && L > 0)
                    {
                        // Strong confirmation: server honors ranges and told us the full length.
                        return (true, L);
                    }
                }

                // 3) If validation didn’t produce 206, fall back to a *strong* HEAD result
                if (headSaysBytes && headLength > 0)
                    return (true, headLength);
            }
            catch
            {
                // Swallow probe errors; we'll treat as "no range support".
            }

            return (false, -1);
        }

        // Choose how many segments per video (adaptive; floor = VID) //
        private int ChooseSegmentCount(long totalBytes)
        {
            // size-based auto baseline (2..16) //
            int AutoSeg(long bytes)
            {
                double mb = bytes / (1024.0 * 1024.0);
                if (mb >= 1000) return 16;
                if (mb >= 500) return 8;
                if (mb >= 200) return 6;
                if (mb >= 100) return 4;
                return 2;
            }
            int userMin = Math.Max(2, _maxVID);
            int segmentsAvailable = Math.Max(1,
                (int)Math.Ceiling(totalBytes / (double)SEGMENT_BYTES));
            int w = Math.Clamp(
                Math.Max(AutoSeg(totalBytes), userMin),
                2, Math.Min(16, segmentsAvailable));
            return w;
        }
        // Ask server for 1 byte and read total length from Content-Range: bytes 0-0/TOTAL
        private async Task<long> TryGetTotalLengthViaRangeAsync(string url, CancellationToken ct)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                req.Version = System.Net.HttpVersion.Version11;
                req.VersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionOrLower;
                // identity + close keeps intermediaries simple
                try { req.Headers.AcceptEncoding.Clear(); req.Headers.AcceptEncoding.ParseAdd("identity"); } catch { }
                req.Headers.ConnectionClose = true;
                req.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 0); // bytes=0-0

                using var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                // early abort for non-video responses (scope-safe)
                {
                    var __u = req.RequestUri;
                    var __ct = res.Content.Headers.ContentType?.MediaType?.ToLowerInvariant() ?? "";

                    // Heuristic: URL or Content-Disposition looks like video, but CT is obviously non-video
                    bool __urlLooksVideo =
                        __u != null && (
                            __u.AbsolutePath.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".mov", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".webm", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".mkv", StringComparison.OrdinalIgnoreCase)
                        );

                    var __cd = res.Content.Headers.ContentDisposition;
                    var __cdName = __cd?.FileNameStar ?? __cd?.FileName ?? "";
                    bool __cdLooksVideo =
                        !string.IsNullOrEmpty(__cdName) && (
                            __cdName.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".mov", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".webm", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".mkv", StringComparison.OrdinalIgnoreCase)
                        );

                    bool __isObviouslyNonVideo =
                        __ct.StartsWith("image/") || __ct.StartsWith("text/") ||
                        __ct == "application/json" || __ct == "application/xml";

                    if ((__urlLooksVideo || __cdLooksVideo) && __isObviouslyNonVideo)
                    {
                        res.Dispose();
                        try { Log("[CT→RETRY] SS non-video — nudging segmented on next attempt"); } catch { }
                        System.Threading.Volatile.Write(ref __preferSegmentedNextTry, true);
                        // If the segmented retry label is in scope here, use it and delete the throw:
                        // goto __SEG_RETRY_ONCE;
                        throw new IOException("Non-video content-type on SS; retry segmented");

                    }
                }

                // early non-video abort (scope-safe: no assetKind/remoteUrl)
                {
                    var __u = req.RequestUri;
                    var __mt = res.Content.Headers.ContentType?.MediaType?.ToLowerInvariant() ?? "";

                    // Heuristics: only fire if the request/filename clearly looks like a video,
                    // but the server is returning an obviously non-video type.
                    bool __urlLooksVideo =
                        __u != null && (
                            __u.AbsolutePath.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".mov", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".webm", StringComparison.OrdinalIgnoreCase) ||
                            __u.AbsolutePath.EndsWith(".mkv", StringComparison.OrdinalIgnoreCase)
                        );

                    var __cd = res.Content.Headers.ContentDisposition;
                    var __cdName = __cd?.FileNameStar ?? __cd?.FileName ?? "";
                    bool __cdLooksVideo =
                        !string.IsNullOrEmpty(__cdName) && (
                            __cdName.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".m4v", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".mov", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".webm", StringComparison.OrdinalIgnoreCase) ||
                            __cdName.EndsWith(".mkv", StringComparison.OrdinalIgnoreCase)
                        );

                    bool __isObviouslyNonVideo =
                        __mt.StartsWith("image/") || __mt.StartsWith("text/") ||
                        __mt == "application/json" || __mt == "application/xml";

                    if ((__urlLooksVideo || __cdLooksVideo) && __isObviouslyNonVideo)
                    {
                        res.Dispose();
                        try { Log("[CT→RETRY] SS non-video — nudging segmented on next attempt"); } catch { }
                        System.Threading.Volatile.Write(ref __preferSegmentedNextTry, true);
                        // If the segmented retry label is in scope here, use it and delete the throw:
                        // goto __SEG_RETRY_ONCE;
                        throw new IOException("Non-video content-type on SS; retry segmented");

                    }
                }

                if ((int)res.StatusCode == 206) // Partial Content
                {
                    var cr = res.Content.Headers.ContentRange;
                    if (cr != null && cr.HasLength && cr.Length.HasValue && cr.Length.Value > 0)
                        return cr.Length.Value;
                }
            }
            catch { /* best effort */ }
            return -1;
        }

        private async Task<bool> DownloadVideoSegmentedAsync(Uri url, string tempPath, string finalPath, long totalSize, string? referer, CancellationToken ct, int bufferSize, bool forceSSPlan = false)
        {
            if (_stopImmediate || ct.IsCancellationRequested) { try { Log("[STOP] immediate — abort segmented worker"); } catch { } return false; }

            var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            // REPLACE with:
            if (_stopRequested && _stopMode == StopMode.Graceful)
            {
                Log("[STOP] Graceful: allow segmented start/rotation for in-flight; not blocking.");
                // Do NOT dispose cts || return here — keep current file’s segmented path alive.
            }

            int __act = System.Threading.Volatile.Read(ref _activeSegVideos);
            // cap-hit gate — short-circuit small jobs, else size-aware wait then re-check
            if (__act >= Math.Max(1, _maxVID))
            {
                // If the planned file is below the segmentation threshold, don't waste time waiting.
                double __mbHint = 0d;
                try
                {
                    // Prefer your quick-length hint if present.
                    if (_qLen > 0) __mbHint = _qLen / (1024d * 1024d);
                }
                catch { /* leave __mbHint = 0 */ }

                // If we know it's below MIN_SEGMENT_BYTES, skip gate and single-stream right away.
                if (__mbHint > 0 && __mbHint < (MIN_SEGMENT_BYTES / (1024d * 1024d)))
                {
                    try { Log($"[SEG] Size below threshold ({__mbHint:0.0} MB < {MIN_SEGMENT_BYTES / (1024d * 1024d):0} MB) — single-stream (skip gate)."); } catch { }
                    cts.Dispose();
                    return false; // go single-stream without waiting for a segmented slot
                }

                if (_lastSegGateLogUtc.AddSeconds(5) <= DateTime.UtcNow)
                {
                    _lastSegGateLogUtc = DateTime.UtcNow;

                    // DIAG ONLY
                    // if (s_ShouldLogOnce?.Invoke("seg.gate.hit", 2) == true)
                    //     if (s_ShouldLogOnce?.Invoke("seg.cap", 15) == true)
                    //         Log($"[SEG.GATE] Active segmented videos cap hit ({__act}/{_maxVID}); waiting briefly…");
                }

                int __holdMs = 800;
                try { if (__mbHint >= 240.0) __holdMs = 1800; } catch { }
                try { await Task.Delay(__holdMs, ct).ConfigureAwait(false); } catch { /* canceled → fall through */ }

                __act = Math.Max(0, System.Threading.Volatile.Read(ref _activeSegVideos));
                if (__act >= Math.Max(1, _maxVID))
                {
                    Log("[SEG] cap-hit → single-stream (no ban)");
                    cts.Dispose();
                    return false; // fall back to single-stream
                }
                // else: a slot freed; continue segmented
            }




            var parts = ChooseSegmentCountTuned(totalSize); // tuned lanes for fairness //
            parts = Math.Min(parts, 3); // hard ceiling per file; keeps pool fair & responsive
            System.Threading.Interlocked.Increment(ref _activeSegVideos);
            SemaphoreSlim? lockSlim = null; string? segTempPath = null;
            // path for one segment file (lives next to final; safe to resume) //
            string MakeSegPath(int segIndex) =>
                finalPath + $".seg.{segIndex}.{_runId}"; // unique per run

            List<Task>? workers = null;
            try
            {
                EnsureIndexFlushTimer();
                _pinnedRangeHost = null;
                try { _range200?.Clear(); } catch { } // clear per-run 200-on-Range memory (once logs)


                int W = parts;
                int _pool = RANGE_POOL_MAX; // must match MaxConnectionsPerServer/RANGE_POOL_MAX // must match MaxConnectionsPerServer //
                int _active = System.Threading.Volatile.Read(ref _activeSegVideos); if (_active <= 0) _active = 1;
                int _fair = Math.Max(2, _pool / _active); // fair share per active video (min 2) //
                int _allowedByPool = Math.Min(W, _fair); // clamp by pool //
                bool _poolLimited = _allowedByPool < W; // was the request above fair-share? //

                int _myInUse = 0; // dynamic per-file in-flight segments //
                const int _perFileCap = 4;

                // Final allowed parts after both pool and per-file caps
                int _finalAllowed = Math.Min(_allowedByPool, _perFileCap);

                // Accurate hinting
                if (_poolLimited)
                    Log($"[HINT] Segments limited by pool: requested {W}, fair-share {_fair} → using {_finalAllowed} (active videos={_active}, pool={_pool}).");
                else if (_finalAllowed < W)
                    Log($"[HINT] Segments limited by per-file cap ({_perFileCap}): requested {W} → using {_finalAllowed}.");

                // Commit final cap for this file
                int _myCap = _finalAllowed;


                // one writer per finalPath in-process
                lockSlim = PathLocks.GetOrAdd(finalPath, _ => new SemaphoreSlim(1, 1));

                await lockSlim.WaitAsync(cts.Token).ConfigureAwait(false);
                // unique seg temp so AV/indexer/collisions can't fight us
                segTempPath = tempPath + ".seg." + ShortHash(url);
                EnsureParent(segTempPath);
                // expected spans for each segment (inclusive end) //
                var spans = new (int idx, long start, long end, string path)[parts];
                long segSize = Math.Max(1, totalSize / parts);
                for (int i = 0; i < parts; i++)
                {
                    long s = i * segSize;
                    long e = (i == parts - 1) ? (totalSize - 1) : Math.Min(totalSize - 1, (s + segSize - 1));
                    var p = MakeSegPath(i);
                    spans[i] = (i, s, e, p);
                }

                // mark already-complete segments (resume) //
                for (int i = 0; i < spans.Length; i++)
                {
                    var (idx, s, e, p) = spans[i];
                    try
                    {
                        if (File.Exists(p))
                        {
                            long have = new FileInfo(p).Length;
                            long need = (e - s + 1);
                            if (have == need) continue; // segment done
                        }
                    }
                    catch { /* ignore */ }

                    // segment missing || incomplete → ensure parent before we write
                    EnsureParent(p);
                }




                // Pre-create the temp file at the final size so RandomAccess writes are valid //
                FileStream __pre = null!;
                try
                {
                    TraceAnyWrite(segTempPath, totalSize, "SEG.PRECREATE");
                    __pre = new FileStream(
                        segTempPath,
                        FileMode.Create,
                        FileAccess.ReadWrite,
                        FileShare.ReadWrite | FileShare.Delete,
                        bufferSize,
                        useAsync: true);
                }
                catch (IOException)
                {
                    await Task.Delay(350, ct).ConfigureAwait(false);
                    TraceAnyWrite(segTempPath, totalSize, "SEG.PRECREATE.RETRY");
                    __pre = new FileStream(
                        segTempPath,
                        FileMode.Create,
                        FileAccess.ReadWrite,
                        FileShare.ReadWrite | FileShare.Delete,
                        bufferSize,
                        useAsync: true);
                }
                using (__pre) { __pre.SetLength(totalSize); }




                using var handle = File.OpenHandle(
                    segTempPath,
                    FileMode.Open,
                    FileAccess.ReadWrite,
                    FileShare.ReadWrite | FileShare.Delete,
                    FileOptions.Asynchronous);


                // Warm-up the first chunk to align with CDN behavior (first ~4 MiB) //
                long firstEnd = Math.Min(totalSize, FIRST_CHUNK_BYTES) - 1;
                long progressed = 0;

                for (int _w = 0; ; _w++)
                {
                    try
                    {
                        await DownloadRangeToFileAsync(
                            url, 0, firstEnd, handle, referer, cts.Token, bufferSize,
                            n => { Interlocked.Add(ref progressed, n); UpdateCurrentFileProgress(progressed, totalSize); UpdateSpeedLabel(n); }
                        ).ConfigureAwait(false);
                        break;
                    }
                    catch (HttpRequestException) when (_w < 2) // retry warm-up on transient 5xx //
                    {
                        await Task.Delay(150 * (_w + 1), cts.Token).ConfigureAwait(false); // 150ms, 300ms //
                        continue;
                    }
                }
                // local resume offset for planner (aligned to 4 MiB)
                long resumeOffset = 0;
                // expected size for single-stream; used if we cancel mid-download
                long __ssExpected = Math.Max(_qLen, 0);

                try { if (File.Exists(tempPath)) resumeOffset = new FileInfo(tempPath).Length; } catch { }
                if (resumeOffset > 0) resumeOffset = (resumeOffset / (4L * 1024 * 1024)) * (4L * 1024 * 1024);

                // Build remaining 4 MiB ranges //
                var ranges = new List<(long s, long e)>(256);
                const long WINDOW = 4L * 1024 * 1024;
                // warmup if the temp file hasn't reached the first MiB
                if (resumeOffset < FIRST_CHUNK_BYTES)
                    ranges.Add((0, FIRST_CHUNK_BYTES - 1));

                // start aligned to the 4 MiB window that contains resumeOffset //
                long startAligned = (resumeOffset / WINDOW) * WINDOW;
                for (long s = startAligned; s < totalSize; s += WINDOW)
                {
                    long e = Math.Min(totalSize - 1, s + WINDOW - 1);
                    ranges.Add((s, e));
                }




                // subtract completed ranges from .partmap (if any)
                try
                {
                    var __done = PartMapLoad(finalPath);
                    if (__done != null && __done.Count > 0)
                    {
                        var __rem = SubtractRanges(ranges, __done);
                        if (__rem != null && __rem.Count > 0) ranges = __rem;
                        else ranges.Clear();
                        try { Log($"[PMAP] resume: {__done.Count} done range(s), {ranges.Count} remaining"); } catch { }
                    }
                }
                catch { /* best-effort */ }

                // contiguous sliding-window workers (W lanes), pull next segment in order //
                int next = 0;
                // coomer edge prefers fewer concurrent range streams
                try
                {
                    var h = _pinnedRangeHost; // field is in scope here
                    if (!string.IsNullOrEmpty(h) &&
                        h.IndexOf("coomer", StringComparison.OrdinalIgnoreCase) >= 0)
                        W = Math.Min(W, 2);
                }
                catch { /* best-effort */ }



                workers = new List<Task>(W);
                for (int wi = 0; wi < W; wi++)
                {
                    workers.Add(Task.Run(async () =>
                    {
                        while (true)
                        {
                            int i = Interlocked.Increment(ref next) - 1;
                            if (i >= ranges.Count) break;

                            await _rangeSlots.WaitAsync(cts.Token).ConfigureAwait(false);
                            var _slotHeld = true;
                            if ((System.Threading.Interlocked.Increment(ref _slotDiagTicker) & 0xF) == 1) // ~1/16 attempts //
                                Log($"[DBG] slots: global {RANGE_POOL_MAX - _rangeSlots.CurrentCount}/{RANGE_POOL_MAX}, " +
                                    $"mine {_myInUse}/{Math.Max(2, _pool / System.Threading.Volatile.Read(ref _activeSegVideos))}");

                            var (s, e) = ranges[i];
                            long s0 = s, e0 = e;

                            int tries = 0;
                            bool _laneHeld = false; // track if we acquired the per-file lane

                            try // ensure we always release both slot and lane //
                            { // acquire per-file lane ONCE per segment, with size-aware floor
                                int activeNow = Math.Max(1, System.Threading.Volatile.Read(ref _activeSegVideos));
                                int floor = (totalSize >= (200L << 20)) ? 4 : (totalSize >= (50L << 20)) ? 3 : 2;
                                int _dynCap = Math.Max(floor, _pool / activeNow);
                                int headroom = (activeNow <= 1) ? (int)Math.Ceiling(RANGE_POOL_MAX * 0.75) : (RANGE_POOL_MAX / 2);
                                _dynCap = Math.Min(_dynCap, headroom);

                                while (true)
                                {
                                    if (System.Threading.Volatile.Read(ref _myInUse) < _dynCap)
                                    {
                                        if (System.Threading.Interlocked.Increment(ref _myInUse) <= _dynCap)
                                        { _laneHeld = true; break; }
                                        System.Threading.Interlocked.Decrement(ref _myInUse);
                                    }
                                    await Task.Delay(10, cts.Token).ConfigureAwait(false);
                                }

                                for (; ; ) // attempt loop //
                                {
                                    long segLocal = 0; // bytes counted for THIS attempt only //
                                    try // single attempt //
                                    {
                                        await DownloadRangeToFileAsync(
                                            url, s, e, handle, referer, cts.Token, bufferSize,
                                            n =>
                                            {
                                                Interlocked.Add(ref progressed, n);
                                                Interlocked.Add(ref segLocal, n);
                                                UpdateCurrentFileProgress(System.Threading.Volatile.Read(ref progressed), totalSize);
                                                UpdateSpeedLabel(n);
                                            }
                                        ).ConfigureAwait(false);
                                        PartMapMarkCompleted(finalPath, s0, e0);
                                        break;
                                    }
                                    catch (HttpRequestException) when (++tries < 3)
                                    { // rollback + resume within this range
                                        System.Threading.Interlocked.Add(ref progressed, -segLocal);
                                        s = Math.Min(e + 1, s + segLocal);
                                        segLocal = 0;
                                        if (s > e) break;
                                        await Task.Delay(100 * tries, cts.Token).ConfigureAwait(false);
                                    }
                                    catch (IOException) when (++tries < 3)
                                    { // same rollback/resume for IO stalls
                                        System.Threading.Interlocked.Add(ref progressed, -segLocal);
                                        s = Math.Min(e + 1, s + segLocal);
                                        segLocal = 0;
                                        if (s > e) break;
                                        await Task.Delay(120 * tries, cts.Token).ConfigureAwait(false);
                                    }
                                    catch (OperationCanceledException) when (cts.IsCancellationRequested)
                                    { // keep totals truthful on cancel
                                        System.Threading.Interlocked.Add(ref progressed, -segLocal);
                                        return;
                                    }
                                }
                            }
                            finally // always release the global range slot and lane //
                            {
                                if (_slotHeld) { _rangeSlots.Release(); _slotHeld = false; }
                                if (_laneHeld) System.Threading.Interlocked.Decrement(ref _myInUse);
                            }
                        }
                    }, cts.Token));
                }

                await Task.WhenAll(workers).ConfigureAwait(false);

                try { PartMapClear(finalPath); } catch { }
                // Atomic move into place //
                await MoveWithSmallRetriesAsync(segTempPath!, finalPath, 3, ct).ConfigureAwait(false);

                // Verify/fix the tail of the final file before releasing the lock
                await RepairTailIfNeededAsync(finalPath, url.AbsoluteUri, ct).ConfigureAwait(false);

                // Release and bookkeeping
                lockSlim.Release();
                PathLocks.TryRemove(finalPath, out _);
                System.Threading.Interlocked.Decrement(ref _activeSegVideos);
                return true;
            }

            // NEW: SS/seg transport flake — prefer segmented on retry
            catch (Exception ex) when (
                (ex.Message?.IndexOf("idle timeout", StringComparison.OrdinalIgnoreCase) ?? -1) >= 0 ||
                (ex.Message?.IndexOf("unexpected EOF", StringComparison.OrdinalIgnoreCase) ?? -1) >= 0 ||
                ex is IOException)
            {
                try { Log("[SS.FAIL] transport error — will retry and prefer segmented"); } catch { }
                try { StartCooldown(_lastEdgeHost, COOLDOWN_SEC); } catch { }
                System.Threading.Volatile.Write(ref __preferSegmentedNextTry, true); // nudge via field (planner snapshots & clears)
                throw; // let the retry loop handle it
            }




            catch (Exception ex)
            {
                // cancellation/stop looks like a write failure — treat as cancel, not host fault
                if (ct.IsCancellationRequested || (_stopRequested && _stopMode == StopMode.Immediate))
                {
                    try { Log("[SEG] canceled during stop — ignoring segment error"); } catch { }
                    throw new OperationCanceledException(ct);
                }


                var wasUserCanceled = _cancelSignaled || ct.IsCancellationRequested;
                cts.Cancel(); // stop other range workers //
                try { if (workers != null) await Task.WhenAll(workers).ConfigureAwait(false); } catch { /* ignore */ }

                // ⬇️ DETAIL TRACER (add this)
                try { Log($"[SEG.FAIL] ex={ex.GetType().Name} inner={(ex.InnerException?.GetType().Name ?? "-")} msg={ex.Message}"); } catch { }

                Log((wasUserCanceled || (_stopRequested && _stopMode == StopMode.Graceful))
                    ? "[STOP] Segmented download abandoned during stop."
                    : $"[SEG] segmented write failed: {ex.GetType().Name} {ex.Message}");

                // count transport flakes
                try
                {
                    var _msg = ex?.ToString() ?? string.Empty;
                    if (_msg.IndexOf("ResponseEnded", System.StringComparison.OrdinalIgnoreCase) >= 0
                     || _msg.IndexOf("unexpected EOF", System.StringComparison.OrdinalIgnoreCase) >= 0
                     || _msg.IndexOf("0 bytes from the transport", System.StringComparison.OrdinalIgnoreCase) >= 0)
                        NoteTransportFlake();
                }
                catch { }


                // immediate demotion (first read == 0 bytes)
                if (ex.Message?.IndexOf("[SEG.ZERO]", System.StringComparison.Ordinal) >= 0)
                {


                    try { if (segTempPath != null && File.Exists(segTempPath)) File.Delete(segTempPath); } catch { }
                    try { if (File.Exists(finalPath)) File.Delete(finalPath); } catch { }
                    try { System.Threading.Interlocked.Decrement(ref _activeSegVideos); } catch { }
                    try
                    {
                        var h = url.Host;
                        if (!string.IsNullOrEmpty(h))
                        {
                            // no per-run ban; avoid sticky "range disabled for host"
                            // optional: cool the edge briefly if you already have a cooldown mechanism
                            // EdgeCooldown(h, TimeSpan.FromMinutes(5));
                            if (string.Equals(_pinnedRangeHost, h, StringComparison.OrdinalIgnoreCase)) _pinnedRangeHost = null;
                        }
                    }
                    catch { }

                    // Probe the edge before demotion so we know its behavior (Range/CE/protocol/TTFB)
                    try
                    {
                        if (!s_NoRangeThisRun)
                        {
                            var __h = url.Host;
                            if (!_noRangeHosts.Contains(__h))
                                await ProbeEdgeAsync(url, ct);
                        }
                    }
                    catch { }

                    Log("[SEG.ZERO] first-read 0 bytes — demote to single-stream now");

                    _lastSegZeroUtc = DateTime.UtcNow;
                    try { Log("[SEG.zero.mark] +20s SS cap=64MB"); } catch { }

                    // Kill any seg autoscale state so we don't reopen overflow later in this file/run
                    _segOverflowOpen = false;
                    _segGateBurst = 0;
                    _segGateBurstT0Ms = 0;

                    // Bias the rest of this run to single-stream; planner will compute __allowSeg=false later
                    s_NoRangeThisRun = true;
                    // rotate off current edge so SS fallback hits a different host
                    try
                    {
                        if (_edge is { } edgeHop)
                        {
                            var oldHost = url.Host;
                            try { EdgeCooldown(oldHost, TimeSpan.FromSeconds(COOLDOWN_SEC)); } catch { }
                            if (string.Equals(_pinnedRangeHost, oldHost, StringComparison.OrdinalIgnoreCase)) _pinnedRangeHost = null;

                            edgeHop.HopNext();
                            var next = edgeHop.ResolveHostForNewDownload();
                            if (!string.IsNullOrEmpty(next) && !string.Equals(next, oldHost, StringComparison.OrdinalIgnoreCase))
                            {
                                try
                                {
                                    url = edgeHop.RewriteUriHost(url, next);
                                    Log($"[SEG.ZERO.HOP] pre-SS rotate {oldHost} → {next}");
                                }
                                catch { /* best-effort */ }
                            }
                        }
                    }
                    catch { /* non-fatal */ }

                    return false; // caller proceeds with SS

                }

                // — rotate away from a host that flipped 206→200 so fallback hits a different edge
                if (_edge is { } e)
                {
                    var oldHost = url.Host;
                    try { EdgeCooldown(oldHost, TimeSpan.FromSeconds(COOLDOWN_SEC)); } catch { }
                    try { _range200?.Add(oldHost); } catch { /* best-effort */ }
                    if (string.Equals(_pinnedRangeHost, oldHost, StringComparison.OrdinalIgnoreCase))
                        _pinnedRangeHost = null;

                    // Range ignored → nudge host toward ss-only
                    try { if (!string.IsNullOrEmpty(oldHost)) HostRangeScore_Add(oldHost, -1); } catch { }

                    e.HopNext();
                    var next = e.ResolveHostForNewDownload();
                    if (!string.IsNullOrEmpty(next) && !string.Equals(next, oldHost, StringComparison.OrdinalIgnoreCase))
                    {
                        try { Log($"[RANGE] 200 on Range — rotating away from {oldHost} → {next} for fallback"); } catch { }
                        try { url = e.RewriteUriHost(url, next); } catch { /* best-effort */ }
                    }
                }


                // If the edge flipped 206→200 mid-segment, rotate away so fallback hits a different host
                if (!wasUserCanceled
                    && ex is HttpRequestException
                    && ex.Message.IndexOf("Expected 206", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    try
                    {
                        var oldHost = url.Host;
                        try { EdgeCooldown(oldHost, TimeSpan.FromSeconds(COOLDOWN_SEC)); } catch { }
                        try { _range200?.Add(oldHost); } catch { /* best-effort */ }
                        if (string.Equals(_pinnedRangeHost, oldHost, StringComparison.OrdinalIgnoreCase)) _pinnedRangeHost = null;

                        _edge?.HopNext(); // choose a different edge for the very next request
                        var next = _edge?.ResolveHostForNewDownload();
                        if (!string.IsNullOrEmpty(next) && !string.Equals(next, oldHost, StringComparison.OrdinalIgnoreCase))
                            try { Log($"[SEG] 206→200 on {oldHost}; rotating to {next} for fallback"); } catch { }
                    }
                    catch { /* ignore rotate errors; continue to cleanup */ }
                }

                try { if (segTempPath != null && File.Exists(segTempPath)) File.Delete(segTempPath); } catch { }
                // purge any partial artifacts from the segmented attempt
                try { if (File.Exists(finalPath)) File.Delete(finalPath); } catch { }
                try { var part = finalPath + ".part"; if (File.Exists(part)) File.Delete(part); } catch { }
                // if stop was requested, exit before host penalties / fallback churn
                if (ct.IsCancellationRequested || (_stopRequested && _stopMode == StopMode.Immediate))
                {
                    try { Log("[SEG] cleanup under stop — skipping host penalties/fallback"); } catch { }
                    throw new OperationCanceledException(ct);
                }

                try
                {
                    var dir = Path.GetDirectoryName(finalPath);
                    var name = Path.GetFileName(finalPath);
                    if (dir != null)
                    {
                        foreach (var f in Directory.GetFiles(dir, name + ".seg.*"))
                        {
                            try { File.Delete(f); } catch { }
                        }
                    }
                }
                catch { }

                try { if (lockSlim != null) { lockSlim.Release(); PathLocks.TryRemove(finalPath, out _); } } catch { }
                try { System.Threading.Interlocked.Decrement(ref _activeSegVideos); } catch { }
                Log("[SEG] write failed — disabling segmented for host; switching to single-stream.");
                try { var h = url.Host; if (!string.IsNullOrEmpty(h)) lock (_noRangeHosts) { _noRangeHosts.Add(h); } } catch { }
                return false;
            }

        }



        private static async Task MoveWithSmallRetriesAsync(string src, string dst, int attempts, CancellationToken ct)
        {
            if (string.Equals(src, dst, StringComparison.OrdinalIgnoreCase))
            {
                // nothing to do; already committed
                return;
            }
            for (int i = 0; i < attempts; i++)
            {
                try
                {
                    if (File.Exists(dst)) File.Delete(dst);
                    File.Move(src, dst);
                    return;
                }
                catch (IOException) when (i < attempts - 1)
                {
                    await Task.Delay(200 * (i + 1), ct).ConfigureAwait(false);
                }
            }
            // last attempt without catching to surface the error //
            if (File.Exists(dst)) File.Delete(dst);
            File.Move(src, dst);
        }

        private static async Task CopySegmentBodyGuardedAsync(HttpResponseMessage res, Stream dest, CancellationToken ct)
        {
            using var s = await res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);

            byte[] buf = new byte[1 << 16];
            int n = await s.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
            if (n == 0)
            {
                try { await Task.Delay(150, ct).ConfigureAwait(false); } catch (OperationCanceledException) { throw; }
                n = await s.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
                if (n == 0) throw new IOException("[SEG.ZERO]");
            }

            await dest.WriteAsync(buf, 0, n, ct).ConfigureAwait(false);
            await s.CopyToAsync(dest, 1 << 16, ct).ConfigureAwait(false);
        }


        private static string ShortHash(Uri u)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(u.ToString()));
            return Convert.ToHexString(bytes, 0, 4).ToLowerInvariant(); // 8 hex chars
        }
        private static string TK(string kind, string raw) =>
    string.Concat(
        string.Equals(kind, "VID", StringComparison.OrdinalIgnoreCase) ? "VID:"
      : string.Equals(kind, "IMG", StringComparison.OrdinalIgnoreCase) ? "IMG:"
      : string.Equals(kind, "ZIP", StringComparison.OrdinalIgnoreCase) ? "ZIP:"
      : "GEN:",
      raw ?? string.Empty);

        private void IndexRemoveTyped(string kind, string? key)
        {
            if (string.IsNullOrEmpty(key)) return;
            try { IndexRemove(TK(kind, key)); } catch { }
        }
        private static string _TryPostIdFromUrl(string? url)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(url)) return "";
                // expected: .../post/1957836855
                int i = url.LastIndexOf("/post/", StringComparison.OrdinalIgnoreCase);
                if (i >= 0)
                {
                    string tail = url.Substring(i + 6);
                    // strip query/fragment if any
                    int q = tail.IndexOfAny(new[] { '?', '#', '/' });
                    if (q >= 0) tail = tail.Substring(0, q);
                    return tail.Trim();
                }
            }
            catch { }
            return "";
        }

        private void TrackAssetBytesForPost(string? referer, string assetKind, string finalPath)
        {
            try
            {
                var postId = _TryPostIdFromUrl(referer);
                if (string.IsNullOrEmpty(postId)) return;

                long len = 0;
                try { len = new FileInfo(finalPath).Length; } catch { /* best-effort */ }

                lock (_postAssetBytes)
                {
                    _postAssetBytes.TryGetValue(postId, out var b);
                    if (assetKind == "IMG") b.imgBytes += len;
                    else if (assetKind == "VID") b.vidBytes += len;
                    _postAssetBytes[postId] = b;
                }
            }
            catch { }
        }

        private static string _HumanMB(long bytes)
        {
            try
            {
                if (bytes <= 0) return "0 MB";
                double mb = bytes / (1024.0 * 1024.0);
                if (mb >= 1024.0) return $"{mb / 1024.0:0.0} GB";
                return $"{mb:0.0} MB";
            }
            catch { return "0 MB"; }
        }

        private void TryLogPerPostSummary(string? postUrlJustFinished)
        {
            try
            {
                var postId = _TryPostIdFromUrl(postUrlJustFinished);
                if (string.IsNullOrEmpty(postId)) return;

                int img = 0, vid = 0;
                if (_postAssetCounts.TryGetValue(postId, out var stats))
                {
                    img = stats.Item1;
                    vid = stats.Item2;
                }

                long imgB = 0, vidB = 0;
                lock (_postAssetBytes)
                {
                    if (_postAssetBytes.TryGetValue(postId, out var b))
                    {
                        imgB = b.imgBytes;
                        vidB = b.vidBytes;
                    }
                }

                if (img > 0)
                    Log($"[OK] IMG post saved {img} files (total {_HumanMB(imgB)})");

                if (vid > 0)
                    Log($"[OK] VID post saved {vid} files (total {_HumanMB(vidB)})");

                // optional: clear to keep dict small during huge runs
                try { _postAssetCounts.TryRemove(postId, out _); } catch { }
                lock (_postAssetBytes) { _postAssetBytes.Remove(postId); }

            }
            catch { }
        }

        private void SegPlanLogOncePerHost(string host, string msg)
        {
            try
            {
                System.Threading.Interlocked.Increment(ref _segPlanTotal);
                host ??= "?";

                if (_segHostLast.TryGetValue(host, out var last) && string.Equals(last, msg, StringComparison.Ordinal))
                {
                    System.Threading.Interlocked.Increment(ref _segPlanSupp);
                    return;
                }

                _segHostLast[host] = msg;
                System.Threading.Interlocked.Increment(ref _segPlanInteresting);
                Log(msg);
            }
            catch { }
        }




        // Canonical quarantine name: "<orig>__Q_<REASON>_<hash>.ext"
        // Hash = SHA-256 of first 64 KiB; if hashing fails → "nohash".
        private static string MakeQuarantinePath(string qDir, string finalPath, string reason)
        {
            Directory.CreateDirectory(qDir);
            string name = Path.GetFileNameWithoutExtension(finalPath);
            string ext = Path.GetExtension(finalPath);

            // Compute quick hash (first 64 KiB), best-effort
            string hash = "nohash";
            try
            {
                using var fs = new FileStream(finalPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var sha = System.Security.Cryptography.SHA256.Create();
                byte[] buf = new byte[8192];
                int remaining = 65536, n;
                while (remaining > 0 && (n = fs.Read(buf, 0, Math.Min(buf.Length, remaining))) > 0)
                {
                    sha.TransformBlock(buf, 0, n, null, 0);
                    remaining -= n;
                }
                sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                hash = Convert.ToHexString(sha.Hash!).ToLowerInvariant();
            }
            catch { /* best-effort */ }

            string stem = $"{name}__Q_{reason}_{hash}";
            string qPath = Path.Combine(qDir, stem + ext);

            // Collision guard
            for (int i = 1; File.Exists(qPath) && i <= 50; i++)
                qPath = Path.Combine(qDir, $"{stem}({i}){ext}");

            return qPath;
        }
        // Hash first 64 KiB of a file (hex, lowercase). Best-effort.
        private static string QuickHash64k(string path)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var sha = System.Security.Cryptography.SHA256.Create();
                byte[] buf = new byte[8192];
                int remaining = 65536, n;
                while (remaining > 0 && (n = fs.Read(buf, 0, Math.Min(buf.Length, remaining))) > 0)
                {
                    sha.TransformBlock(buf, 0, n, null, 0);
                    remaining -= n;
                }
                sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                return Convert.ToHexString(sha.Hash!).ToLowerInvariant();
            }
            catch { return "nohash"; }
        }
        // Extract the "<hash>" from a path built by MakeQuarantinePath(...)
        // i.e., "<name>__Q_<REASON>_<hash>.ext" → returns "<hash>" or null
        private static string? ExtractHashFromQPath(string qPath)
        {
            try
            {
                var fn = Path.GetFileNameWithoutExtension(qPath);
                if (string.IsNullOrEmpty(fn)) return null;

                // Find the last '_' which precedes the hash
                int us = fn.LastIndexOf('_');
                if (us < 0 || us == fn.Length - 1) return null;

                var hash = fn.Substring(us + 1);
                // basic sanity: 64 hex chars for SHA-256 (lowercase in your code)
                if (hash.Length == 64) return hash;
                return null;
            }
            catch { return null; }
        }

        // Cheaper dedupe: reuse an existing quarantine file whose NAME already contains this hash.
        // (No hashing of those files; we just look at filenames.)
        private static string? FindQuarantineByHashName(string qDir, string hash)
        {
            if (string.IsNullOrEmpty(hash) || hash.Equals("nohash", StringComparison.OrdinalIgnoreCase)) return null;
            try
            {
                foreach (var p in Directory.EnumerateFiles(qDir))
                {
                    var stem = Path.GetFileNameWithoutExtension(p);
                    if (stem?.EndsWith("_" + hash, StringComparison.OrdinalIgnoreCase) == true ||
                        stem?.IndexOf("_" + hash, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        return p;
                    }
                }
            }
            catch { }
            return null;
        }

        // Look for any existing quarantine file in qDir that already contains _<hash> in its name
        private static string? FindQuarantineByHash(string qDir, string hash)
        {
            try
            {
                if (string.IsNullOrEmpty(hash) || hash == "nohash") return null;
                foreach (var p in Directory.EnumerateFiles(qDir))
                {
                    var name = Path.GetFileNameWithoutExtension(p);
                    if (name?.IndexOf("_" + hash, StringComparison.OrdinalIgnoreCase) >= 0)
                        return p;
                }
            }
            catch { }
            return null;
        }


        private async Task DownloadRangeToFileAsync(Uri url, long start, long endInclusive, SafeFileHandle handle, string? referer, CancellationToken ct, int bufferSize, Action<int> onBytes)
        {
            // If we learned a ranged-friendly edge, stick to it
            var __pin = _pinnedRangeHost; if (__pin != null && _noRangeHosts.Contains(__pin)) __pin = null;

            if (!string.IsNullOrEmpty(__pin) && !string.Equals(url.Host, __pin, StringComparison.OrdinalIgnoreCase)) { try { url = RewriteHost(url, __pin); } catch { /* ignore */ } }


            using var req = new HttpRequestMessage(HttpMethod.Get, url);

            req.Version = HttpVersion.Version11;
            req.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;



            // PATCH 5: set a sane Referer for media requests
            var refUri = PickReferer(url, referer); // use your (Uri,string?) overload
            if (refUri != null) req.Headers.Referrer = refUri;

            // PATCH 4: only send Range if the host isn’t on the no-range list
            bool tryRange = (_noRangeHosts == null ? true : !_noRangeHosts.Contains(url.Host)) && !s_NoRangeThisRun;
            if (tryRange)
            {
                long __s = (start < 0 ? 0 : start);
                long __e = (endInclusive >= __s ? endInclusive : __s); // never inverted

                // concrete, inclusive range
                // align segmented range to a single 4 MiB slab (tail may be smaller)
                const long SLAB4 = 4L << 20;
                __s = (__s / SLAB4) * SLAB4; // snap start to k*4MiB
                long __slabEnd = __s + SLAB4 - 1; // one full slab (inclusive)
                if (__e > __slabEnd || __e < __s) __e = __slabEnd; // cap to slab; guard inverted/unspecified end

                req.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(__s, __e);

                NormalizeDownloadRequest(req);

                req.Version = System.Net.HttpVersion.Version20;
                req.VersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionOrHigher;
                req.Headers.ConnectionClose = false;



                // keep offsets byte-true for ranged reads
                try { req.Headers.AcceptEncoding.Clear(); req.Headers.AcceptEncoding.ParseAdd("identity"); } catch { }


            }

            // If-Range guard for ranged requests (ETag/Last-Modified consistency)
            // Only keep this if you actually HAVE the caches; otherwise remove this whole block.
#if HAS_ETAG_LASTMOD_CACHE
            if (tryRange && req.Headers.Range != null)
            {
                var key = url.AbsoluteUri;
                if (_etagByUrl != null && _etagByUrl.TryGetValue(key, out var et))
                    req.Headers.IfRange = new System.Net.Http.Headers.RangeConditionHeaderValue(et);
                else if (_lastModByUrl != null && _lastModByUrl.TryGetValue(key, out var lm))
                    req.Headers.IfRange = new System.Net.Http.Headers.RangeConditionHeaderValue(lm);
            }
#endif




            // local aliases for the requested range
            long s = start;
            long e = endInclusive;

            // align segmented request to a single 4 MiB slab
            const long __SLAB4 = 4L << 20;
            s = (s / __SLAB4) * __SLAB4; // snap start to k*4MiB
            long slabEnd = s + __SLAB4 - 1; // one full slab (inclusive)
            if (e < 0 || e > slabEnd) e = slabEnd; // cap end to this slab (tail may be smaller)


            // set the aligned Range now (overwrites any earlier set)
            req.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(s, e);
            NormalizeDownloadRequest(req);


            if (url.Host.IndexOf("coomer", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                req.Version = System.Net.HttpVersion.Version11;
                req.VersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionOrLower;
            }

            // (no 'using' so we can swap once; we’ll re-wrap below)
            // avoid bursty H2 opens on this edge (segmented only)
            var __h = url.Host;
            if (__h.IndexOf("coomer", StringComparison.OrdinalIgnoreCase) >= 0)
                try { await Task.Delay(100).ConfigureAwait(false); } catch { }

            // isolate request creation from shared cancels
            HttpResponseMessage res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, CancellationToken.None).ConfigureAwait(false);
            // expect 206 + satisfiable Content-Range for ranged segments

            if (req.Headers.Range != null)
            {
                // If not 206, mark host SS-only for this run, then throw as before
                if (res.StatusCode != System.Net.HttpStatusCode.PartialContent)
                {
                    try
                    {
                        var h = res.RequestMessage?.RequestUri?.Host ?? url.Host;
                        s_NoRangeThisRun = true;
                        Log($"[SEG.AUTO→SS] {h}: not206=true noCR=— — SS for rest of run");
                    }
                    catch { /* best-effort */ }

                    try { res.Dispose(); } catch { }
                    throw new HttpRequestException("Expected 206 for ranged segment");
                }

                var crSeg = res.Content.Headers.ContentRange; // renamed to avoid 'cr' shadowing

                // If 206 but no valid Content-Range, also demote host and throw
                if (crSeg == null || !crSeg.HasRange || !crSeg.HasLength)
                {
                    try
                    {
                        var h = res.RequestMessage?.RequestUri?.Host ?? url.Host;
                        s_NoRangeThisRun = true;
                        Log($"[SEG.AUTO→SS] {h}: not206=false noCR=true — SS for rest of run");
                    }
                    catch { /* best-effort */ }

                    try { res.Dispose(); } catch { }
                    throw new HttpRequestException("Missing/invalid Content-Range for ranged segment");
                }

                // log what we asked vs got (no LINQ)
                try
                {
                    long? wantFrom = null, wantTo = null;
                    foreach (var ri in req.Headers.Range.Ranges) { wantFrom = ri.From; wantTo = ri.To; break; }
                    Log($"[SEG.GET] want={wantFrom}-{wantTo} got={crSeg?.From}-{crSeg?.To}/{crSeg?.Length} v={(res.Version?.ToString() ?? "1.1")}");
                }
                catch { }
            }


            // guard: server rejected our Range (usually stale resume)
            if (tryRange && res.StatusCode == System.Net.HttpStatusCode.RequestedRangeNotSatisfiable)
                throw new HttpRequestException("416 Requested Range Not Satisfiable – stale resume; restart without Range");

            // one-shot edge swap when Range is ignored (200 OK)
            if (!NATURAL_URL_ONLY && tryRange && res.StatusCode == System.Net.HttpStatusCode.OK)
            {
                var host = url.Host;
                string? altHost = NextEdgeHost(host); // use RR cursor instead of hardcoded ring

                // skip rewrite for signed/fragile URLs; only hop for obvious media
                bool __signed =
                    ((url.Query?.IndexOf("sig=", StringComparison.OrdinalIgnoreCase) ?? -1) >= 0) ||
                    ((url.Query?.IndexOf("token=", StringComparison.OrdinalIgnoreCase) ?? -1) >= 0) ||
                    ((url.Query?.IndexOf("x-amz-signature", StringComparison.OrdinalIgnoreCase) ?? -1) >= 0) ||
                    ((url.Query?.IndexOf("x-amz-credential", StringComparison.OrdinalIgnoreCase) ?? -1) >= 0) ||
                    ((url.Query?.IndexOf("policy=", StringComparison.OrdinalIgnoreCase) ?? -1) >= 0) ||
                    ((url.Query?.IndexOf("expires=", StringComparison.OrdinalIgnoreCase) ?? -1) >= 0);

                bool __isMedia =
                    url.AbsolutePath.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase) ||
                    url.AbsolutePath.EndsWith(".mov", StringComparison.OrdinalIgnoreCase) ||
                    url.AbsolutePath.EndsWith(".mkv", StringComparison.OrdinalIgnoreCase) ||
                    url.AbsolutePath.EndsWith(".webm", StringComparison.OrdinalIgnoreCase) ||
                    url.AbsolutePath.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) ||
                    url.AbsolutePath.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase) ||
                    url.AbsolutePath.EndsWith(".png", StringComparison.OrdinalIgnoreCase) ||
                    url.AbsolutePath.EndsWith(".gif", StringComparison.OrdinalIgnoreCase) ||
                    url.AbsolutePath.EndsWith(".webp", StringComparison.OrdinalIgnoreCase) ||
                    url.AbsolutePath.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ||
                    url.AbsolutePath.EndsWith(".7z", StringComparison.OrdinalIgnoreCase) ||
                    url.AbsolutePath.EndsWith(".rar", StringComparison.OrdinalIgnoreCase);

                bool __canRewrite = __isMedia && !__signed;

                if (!string.IsNullOrEmpty(altHost)
                    && !string.Equals(altHost, host, StringComparison.OrdinalIgnoreCase)
                    && __canRewrite)
                {
                    if (string.Equals(_pinnedRangeHost, host, StringComparison.OrdinalIgnoreCase)) _pinnedRangeHost = null;

                    var altUrl = new UriBuilder(url) { Host = altHost }.Uri;
                    var ref2 = PickReferer(altUrl, referer);

                    using var reqAlt = new HttpRequestMessage(HttpMethod.Get, altUrl);
                    if (ref2 != null) reqAlt.Headers.Referrer = ref2;
                    reqAlt.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(s, e);
                    reqAlt.Headers.AcceptEncoding.Clear();
                    reqAlt.Headers.AcceptEncoding.Add(new System.Net.Http.Headers.StringWithQualityHeaderValue("identity"));
                    reqAlt.Version = System.Net.HttpVersion.Version11;
                    reqAlt.VersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionOrLower;
                    // Force H/1.1 for ranged GET on alt edge as well
                    reqAlt.Version = System.Net.HttpVersion.Version11;
                    reqAlt.VersionPolicy = System.Net.Http.HttpVersionPolicy.RequestVersionOrLower;


                    var resAlt = await _http.SendAsync(reqAlt, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                    if (resAlt.StatusCode == System.Net.HttpStatusCode.PartialContent)
                    {
                        // success: pin this ranged-friendly edge and continue on it
                        _pinnedRangeHost = altHost;
                        Log($"[EDGE.PIN] {altHost} honored Range; pinning for this run.");

                        res.Dispose();
                        res = resAlt; // downstream will read from this
                        url = altUrl; // validators will key off actual URL
                    }
                    else
                    {
                        // alt also ignored/failed; proceed and let 206-check trigger fallback
                        if (string.Equals(_pinnedRangeHost, altHost, StringComparison.OrdinalIgnoreCase)) _pinnedRangeHost = null;

                        resAlt.Dispose();

                        var hosts = GetMediaHostsSafe();
                        if (_noRangeHosts.Count >= hosts.Length && !s_NoRangeThisRun)
                        {
                            s_NoRangeThisRun = true; // force single-stream for remainder
                            Log("[RANGE] All edges ignored Range; remainder will be single-stream.");
                        }
                    }
                }
                else
                {
                    try
                    {
                        if (!__canRewrite)
                            Log("[EDGE] rewrite skipped (signed || non-media URL)");
                    }
                    catch { }
                    // fall through to existing downstream logic on the natural URL
                }
            }

            // pooled buffer for segmented range read/write (Stage 5 — SS parity)
            {
                await using var segSrc = await res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);

                byte[] segBuf = System.Buffers.ArrayPool<byte>.Shared.Rent(bufferSize);
                long segPos = s;
                bool __firstRead = true;

                try
                {
                    while (segPos <= e)
                    {
                        int want = (int)Math.Min(bufferSize, (e - segPos + 1));
                        int n = await segSrc.ReadAsync(segBuf.AsMemory(0, want), ct).ConfigureAwait(false);
                        if (n == 0 && __firstRead)
                        {
                            __firstRead = false;
                            try { await Task.Delay(150, ct).ConfigureAwait(false); } catch (OperationCanceledException) { throw; }
                            n = await segSrc.ReadAsync(segBuf.AsMemory(0, want), ct).ConfigureAwait(false);
                            if (n == 0) throw new IOException("[SEG.ZERO]");
                        }
                        else
                        {
                            __firstRead = false;
                            if (n == 0) break;
                        }

                        await System.IO.RandomAccess.WriteAsync(handle, segBuf.AsMemory(0, n), segPos, ct).ConfigureAwait(false);
                        segPos += n;
                        onBytes?.Invoke(n);
                    }

                    if (segPos != e + 1)
                        throw new IOException($"Short write: wrote {segPos - s} of {(e - s + 1)} bytes for {url}");
                }
                finally
                {
                    try { System.Buffers.ArrayPool<byte>.Shared.Return(segBuf); } catch { /* best-effort */ }
                }
            }



            // Re-wrap the (possibly swapped) response so disposal matches prior pattern
            using var __res = res;

            // Require 206 + correct Content-Range for ranged requests
            if (tryRange)
            {
                if (__res.StatusCode != System.Net.HttpStatusCode.PartialContent)
                    throw new HttpRequestException($"Expected 206 for Range bytes={start}-{endInclusive}, got {(int)__res.StatusCode}");

                var contentRangeLR = __res.Content?.Headers?.ContentRange; // unique name to avoid shadowing
                if (contentRangeLR == null || contentRangeLR.From != start || contentRangeLR.To != endInclusive)
                    throw new HttpRequestException($"Bad Content-Range: got {contentRangeLR?.From}-{contentRangeLR?.To}, want {start}-{endInclusive}");

                // learn validators for future If-Range
                var keyLR = url.AbsoluteUri; // keep key format consistent with request-side lookup
                var etLR = __res.Headers.ETag;
                if (etLR != null) _etagByUrl[keyLR] = etLR;

                var lmLR = __res.Content?.Headers?.LastModified; // on Content headers, not Response headers
                if (lmLR.HasValue) _lastModByUrl[keyLR] = lmLR.Value;

                // sanity: Content-Length must match requested span
                var spanLen = endInclusive - start + 1;
                var cl = __res.Content?.Headers?.ContentLength;
                if (cl.HasValue && cl.Value != spanLen)
                    throw new HttpRequestException($"Bad Content-Length for range: got {cl.Value}, want {spanLen}");
            }


            // re-wrap for disposal after potential swap
            using var __res1155 = res;

            // Require 206 + correct Content-Range for ranged requests
            if (tryRange)
            {
                if (__res1155.StatusCode != System.Net.HttpStatusCode.PartialContent)
                    throw new HttpRequestException($"Expected 206 for Range bytes={start}-{endInclusive}, got {(int)__res1155.StatusCode}");

                var contentRangeLR = __res1155.Content?.Headers?.ContentRange;
                if (contentRangeLR == null || contentRangeLR.From != start || contentRangeLR.To != endInclusive)
                    throw new HttpRequestException($"Bad Content-Range: got {contentRangeLR?.From}-{contentRangeLR?.To}, want {start}-{endInclusive}");

                // learn validators for future If-Range
                var keyLR = url.AbsoluteUri;
                var etLR = __res1155.Headers.ETag; if (etLR != null) _etagByUrl[keyLR] = etLR;
                var lmLR = __res1155.Content?.Headers?.LastModified; if (lmLR.HasValue) _lastModByUrl[keyLR] = lmLR.Value;

                // sanity: Content-Length must match requested span
                var spanLen = endInclusive - start + 1;
                var cl = __res1155.Content?.Headers?.ContentLength;
                if (cl.HasValue && cl.Value != spanLen)
                    throw new HttpRequestException($"Bad Content-Length for range: got {cl.Value}, want {spanLen}");
            }





            // Require a correct partial response for the requested bytes s-e
            if (res.StatusCode != System.Net.HttpStatusCode.PartialContent)
                throw new HttpRequestException($"Expected 206 for Range bytes={s}-{e}, got {(int)res.StatusCode}");

            var cr = res.Content?.Headers?.ContentRange;
            if (cr == null || cr.From != s || cr.To != e)
                throw new HttpRequestException($"Bad Content-Range: got from={cr?.From} to={cr?.To}, want {s}-{e}");
            // Sanity-check Content-Length against requested span
            var expectedLen = (e - s + 1);
            var gotLen = res.Content.Headers.ContentLength;
            if (gotLen.HasValue && gotLen.Value != expectedLen)
                throw new HttpRequestException($"[LEN] expected {expectedLen} for {s}-{e}, got {gotLen.Value}");




            // If we asked for Range but got 200 OK, host ignored Range — remember that
            bool ignoredRange = tryRange && res.StatusCode == HttpStatusCode.OK;
            if (ignoredRange) // host returned 200 OK to a ranged request
            {
                _noRangeHosts.Add(url.Host);
                if (string.Equals(_pinnedRangeHost, url.Host, StringComparison.OrdinalIgnoreCase)) _pinnedRangeHost = null;

                Log($"[RANGE] host ignored Range → {_noRangeHosts.Count} host(s) flagged; latest={url.Host}");
            }



            if (res.StatusCode != HttpStatusCode.PartialContent && res.StatusCode != HttpStatusCode.OK)
                throw new HttpRequestException($"Segment HTTP {(int)res.StatusCode}");
            // cache validators for future requests
            var ukey = url.ToString();
            var etag = res.Headers.ETag;
            if (etag != null) _etagByUrl[ukey] = etag;

            var lastMod = res.Content?.Headers?.LastModified;
            if (lastMod.HasValue) _lastModByUrl[ukey] = lastMod.Value;

            // (REMOVE the duplicated [1156]/[1157] that follows in your file)

            await using var src = await res.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);

            // If server ignored Range (200 OK) but we need [start..end], skip 'start' bytes first
            if (ignoredRange && start > 0)
            {
                long toSkip = start;
                var skipBuf = new byte[Math.Min(bufferSize, 8192)];
                while (toSkip > 0)
                {
                    int n = await src.ReadAsync(skipBuf.AsMemory(0, (int)Math.Min(skipBuf.Length, toSkip)), ct).ConfigureAwait(false);
                    if (n <= 0) throw new IOException("server ignored Range; unexpected EOF while skipping");
                    toSkip -= n;
                }
            }

            var buf = System.Buffers.ArrayPool<byte>.Shared.Rent(bufferSize);
            long pos = start;
            int idleMs = 60000; // // 60s idle watchdog
            var tpSw = System.Diagnostics.Stopwatch.StartNew();
            long tpBytes = 0;
            const int TP_FLOOR = 32 * 1024; // // 32 KB/s floor
            const int TP_WINDOW_MS = 45000; // // 45s window


            while (pos <= endInclusive)
            {
                int want = (int)Math.Min(buf.Length, (endInclusive - pos + 1));
                var readTask = src.ReadAsync(buf.AsMemory(0, want), ct).AsTask();
                var read = await readTask.ConfigureAwait(false);
                if (pos == start && read == 0) throw new IOException("[SEG.ZERO]");

                var done = await Task.WhenAny(readTask, Task.Delay(idleMs, ct));
                if (done != readTask) throw new IOException("segment idle timeout");
                int n = readTask.Result;
                if (n <= 0) break;

                await RandomAccess.WriteAsync(handle, new ReadOnlyMemory<byte>(buf, 0, n), pos, ct).ConfigureAwait(false);
                pos += n;
                onBytes(n);
                UpdateSpeedLabel(n); // mirror bytes to WebUiStatus

                tpBytes += n;
                if (tpSw.ElapsedMilliseconds >= TP_WINDOW_MS)
                {
                    var secs = Math.Max(1.0, tpSw.ElapsedMilliseconds / 1000.0);
                    var rate = tpBytes / secs;

                    // Segmented path: fail fast on slow windows (no grace)
                    if (rate < TP_FLOOR)
                    {
                        // optional one-line tracer (keeps behavior identical):
                        try { Log($"[SEG.WATCHDOG] rate={rate:F1}B/s floor={TP_FLOOR}"); } catch { }
                        throw new IOException("segment throughput watchdog");
                    }

                    tpBytes = 0;
                    tpSw.Restart();
                }

            }
            // verify we wrote the full requested range
            if (pos != endInclusive + 1)
                throw new IOException($"Short write: wrote {pos - start} of {(endInclusive - start + 1)} bytes for {url}");
            try { System.Buffers.ArrayPool<byte>.Shared.Return(buf); } catch { }
        }


        // ===== Speed UI ===== //
        private void UpdateSpeedLabel(long deltaBytes)
        {
            try
            {
                Interlocked.Add(ref _sessionBytes, deltaBytes);
                Status.AddBytesFetched(deltaBytes);
                if (deltaBytes > 0) { try { CMDownloaderUI.WebUiStatus.AddBytes(deltaBytes); } catch { } }
                Status.SetSpeeds(
                    (deltaBytes > 0 ? (deltaBytes * 8.0) / (1024 * 1024) : 0.0),
                    (deltaBytes > 0 ? (deltaBytes * 8.0) / (1024 * 1024) : 0.0)
                );


                if (lblSpeed == null || lblSpeed.IsDisposed) return;
                if (_speedUiSw.ElapsedMilliseconds < 300 && deltaBytes > 0) return; // heartbeat-only
                double seconds = Math.Max(0.25, _sessionSw.Elapsed.TotalSeconds);
                double mb = _sessionBytes / (1024.0 * 1024.0);
                double mbps = mb / seconds;
                string text = $"SPEED: {mbps:0.0} MB/s ({mb:0.0} MB)";
                if (lblSpeed.InvokeRequired) { lblSpeed.BeginInvoke(new Action(() => lblSpeed.Text = text)); } else { lblSpeed.Text = text; }
                // mirror speeds to the web dashboard from the label text
                try
                {
                    // We try to parse from the label string. Supports:
                    // - "... 12.3 MB/s (avg 10.1)" -> MB/s (megabytes/sec), we convert to Mb/s
                    // - "... 98.6 Mbps (avg 75.4)" -> already Mb/s
                    string t = text ?? string.Empty;

                    double rollingMbps = 0, avgMbps = 0;

                    // rolling = first number with unit (MB/s or Mbps)
                    var mRollMB = System.Text.RegularExpressions.Regex.Match(t, @"([0-9]+(?:\.[0-9]+)?)\s*MB/s", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    var mRollMb = System.Text.RegularExpressions.Regex.Match(t, @"([0-9]+(?:\.[0-9]+)?)\s*Mb?p?s?", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

                    if (mRollMB.Success)
                        rollingMbps = double.Parse(mRollMB.Groups[1].Value) * 8.0; // MB/s -> Mb/s
                    else if (mRollMb.Success)
                        rollingMbps = double.Parse(mRollMb.Groups[1].Value);

                    // avg = number after 'avg'
                    var mAvgMB = System.Text.RegularExpressions.Regex.Match(t, @"avg\s*([0-9]+(?:\.[0-9]+)?)\s*MB/s", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    var mAvgMb = System.Text.RegularExpressions.Regex.Match(t, @"avg\s*([0-9]+(?:\.[0-9]+)?)\s*Mb?p?s?", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

                    if (mAvgMB.Success)
                        avgMbps = double.Parse(mAvgMB.Groups[1].Value) * 8.0;
                    else if (mAvgMb.Success)
                        avgMbps = double.Parse(mAvgMb.Groups[1].Value);

                    CMDownloaderUI.Status.SetSpeeds(avgMbps, rollingMbps);
                }
                catch { /* keep UI resilient */ }

                /* heartbeat-only: no activity blink */
            }
            catch { }
        }

        private void SweepQuarantineMeta()
        {
            try
            {
                var roots = new[] { ImagesRoot, VideoRoot }; // <-- your actual roots
                foreach (var root in roots)
                {
                    if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root)) continue;

                    // Remove stale qmeta + delete empty _quarantine dirs
                    foreach (var qmeta in Directory.EnumerateFiles(root, "*.qmeta.json", SearchOption.AllDirectories))
                    {
                        try
                        {
                            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(qmeta));
                            DateTime whenUtc = DateTime.MinValue;
                            if (doc.RootElement.TryGetProperty("whenUtc", out var p) && p.ValueKind == System.Text.Json.JsonValueKind.String)
                                whenUtc = p.GetDateTime();

                            // If the quarantine has been sitting for 7+ days, nuke the folder; otherwise just keep the qmeta
                            if ((DateTime.UtcNow - (whenUtc == DateTime.MinValue ? DateTime.UtcNow : whenUtc)).TotalDays >= 7)
                            {
                                var badDir = Path.GetDirectoryName(qmeta);
                                if (!string.IsNullOrEmpty(badDir) &&
                                    badDir.EndsWith("_quarantine", StringComparison.OrdinalIgnoreCase))
                                {
                                    try { Directory.Delete(badDir, true); } catch { }
                                    continue;
                                }
                            }
                        }
                        catch { /* ignore bad JSON/locked file */ }
                    }

                    // Best-effort: remove any leftover empty _quarantine directories
                    foreach (var qdir in Directory.GetDirectories(root, "_quarantine", SearchOption.AllDirectories))
                    {
                        try { if (!Directory.EnumerateFileSystemEntries(qdir).Any()) Directory.Delete(qdir, false); } catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                try { Log($"[QSWEEP.ERROR] {ex.Message}"); } catch { }
            }
        }


        private void LedKick()
        {
            // heartbeat-only: suppress activity-driven LED
            if (IsDisposed || _netLed == null) return;
            if (InvokeRequired) { BeginInvoke(new Action(LedKick)); return; }
            _lastLedKickMs = Environment.TickCount64; // keep timestamp for other logic
                                                      // no _netLed.On changes; no idle timer; no Refresh here
        }

        private long _rpLastMs = 0;
        private string? _rpKey = null;
        private const int _rpMinMs = 5000; // minimum 5s between identical probe logs
        private long _rangeProbeTotal, _rangeProbeOkSupp, _rangeProbeInteresting;

        private void ProbeLogThrottled(string host, bool ok, string msg)
        {
            // count everything
            System.Threading.Interlocked.Increment(ref _rangeProbeTotal);

            // OK probes are spammy: count + suppress
            if (ok)
            {
                System.Threading.Interlocked.Increment(ref _rangeProbeOkSupp);
                return;
            }

            // Non-OK: keep your existing throttle behavior
            System.Threading.Interlocked.Increment(ref _rangeProbeInteresting);

            var key = host + "|" + (ok ? "1" : "0");
            long now = Environment.TickCount64;
            if (_rpKey == key && (now - _rpLastMs) < _rpMinMs) return; // suppress duplicates
            _rpKey = key; _rpLastMs = now;

            try { Log(msg); } catch { }
        }




        private void SweepEmptySetFolders()
        {
            foreach (var root in new[] { ImagesRoot, VideoRoot })
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root)) continue;
                    foreach (var d in Directory.GetDirectories(root))
                        TryDeleteIfEmpty(d);
                }
                catch { /* ignore */ }
            }
        }

        // ---------------------------------------------
        // Single-item set folder flattener
        // ---------------------------------------------

        private static readonly string[] IMG_EXTS = { ".jpg", ".jpeg", ".png", ".webp", ".gif" };
        private static readonly string[] VID_EXTS = { ".mp4", ".webm", ".mov", ".m4v", ".mkv" };
        // quick banlist of placeholder images (len + SHA256(first 64KB))
        static readonly HashSet<string> _trashQuick = new(StringComparer.Ordinal);
        static bool IsTrashQuick(long len, string h) => _trashQuick.Contains(len + ":" + h);
        static void AddTrashQuick(long len, string h) { _trashQuick.Add(len + ":" + h); }

        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> _inflightQ
            = new System.Collections.Concurrent.ConcurrentDictionary<string, byte>(StringComparer.Ordinal);


        private void FlattenSingletonSetFolders()
        {
            try
            {
                FlattenUnder(Path.Combine(_userRootFolder, "Images"), IMG_EXTS, addTokenToName: true);
                FlattenUnder(Path.Combine(_userRootFolder, "VideoAudio"), VID_EXTS, addTokenToName: false);
            }
            catch { }
        }

        private void FlattenUnder(string root, string[] exts, bool addTokenToName)
        {
            if (!Directory.Exists(root)) return;

            foreach (var dir in Directory.GetDirectories(root))
            {
                // If you have any special subfolders to skip, do it here.
                // Example: if (Path.GetFileName(dir).Equals("DM", StringComparison.OrdinalIgnoreCase)) continue;

                var assetFiles = Directory.EnumerateFiles(dir)
                    .Where(f => exts.Contains(Path.GetExtension(f).ToLowerInvariant()))
                    .ToList();

                if (assetFiles.Count == 1)
                {
                    var src = assetFiles[0];
                    var token = Path.GetFileName(dir); // e.g. "354496-19"
                    var destName = Path.GetFileName(src);

                    if (addTokenToName)
                    {
                        var stem = Path.GetFileNameWithoutExtension(destName);
                        var ext = Path.GetExtension(destName);
                        // Append token so different posts don’t collide at root
                        if (!stem.Contains(token, StringComparison.OrdinalIgnoreCase))
                            destName = $"{stem}_{token}{ext}";
                    }

                    var dest = Path.Combine(root, destName);
                    dest = AvoidNameCollision(dest);

                    try
                    {
                        File.Move(src, dest);
                        Log($"[FLAT] Moved {Path.GetFileName(src)} → {destName}");
                    }
                    catch (IOException)
                    {
                        // If same file already exists, allow folder cleanup to proceed
                        try
                        {
                            if (File.Exists(dest))
                            {
                                var fiSrc = new FileInfo(src);
                                var fiDest = new FileInfo(dest);
                            }
                        }
                        catch { }
                    }

                    TryDeleteIfEmpty(dir); // remove now-empty set folder
                }
                // else: 0 || >1 assets => keep folder; empty folders are handled elsewhere
            }
        }
        private void FlushQueuesOnStop()
        {
            int v = 0, i = 0;
            try
            {
                if (_vidQ != null)
                {
                    while (_vidQ.TryTake(out _)) v++;
                }
            }
            catch { /* best-effort */ }

            try
            {
                if (_imgQ != null)
                {
                    while (_imgQ.TryTake(out _)) i++;
                }
            }
            catch { /* best-effort */ }

            try { Log($"[STOP] cleared queued items: vids={v} imgs={i}"); } catch { }
            // (No UI listview references here to avoid missing-symbol errors)
            // DASHBOARD
            try { Status.SetRunState("Idle"); Status.SetStartedAt(null); } catch { }

        }


        private string AvoidNameCollision(string path)
        {
            var dir = Path.GetDirectoryName(path)!;
            var name = Path.GetFileNameWithoutExtension(path);
            var ext = Path.GetExtension(path);
            var n = 1;
            var candidate = path;
            while (File.Exists(candidate))
                candidate = Path.Combine(dir, $"{name} ({n++}){ext}");
            return candidate;
        }



        private static string MakeUniquePath(string desired)
        {
            if (!File.Exists(desired)) return desired;
            var dir = Path.GetDirectoryName(desired)!;
            var baseName = Path.GetFileNameWithoutExtension(desired);
            var ext = Path.GetExtension(desired);
            int i = 1;
            string candidate;
            do { candidate = Path.Combine(dir, $"{baseName} ({i++}){ext}"); }
            while (File.Exists(candidate));
            return candidate;
        }

        // ===== Progress helpers ===== //
        // REPLACE [1212] (entire method)
        private void SetOverallProgress(int current, int total)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action<int, int>(SetOverallProgress), current, total);
                return;
            }

            pbOverall.Invalidate();
            pbOverall.Maximum = Math.Max(1, total);
            pbOverall.Value = Math.Min(Math.Max(0, current), pbOverall.Maximum);
            lblOverall.Text = $"OVERALL {current}/{Math.Max(1, total)}";
            pbOverall.Invalidate();

            _netLed.On = true;
            _ledIdleTimer.Stop();
            _ledIdleTimer.Start();

            // --- WEBUI MIRROR: posts overall (used for Posts x / y in web HUD) --- //
            try { CMDownloaderUI.WebUiStatus.SetOverall(current, total); } catch { }
        }





        // REPLACE [1213] (entire method)
        private void BeginCurrentFileProgress(long totalBytes, string name)
        {
            if (InvokeRequired) { BeginInvoke(new Action<long, string>(BeginCurrentFileProgress), totalBytes, name); return; }

            if (lblCurrent == null) lblCurrent = this.Controls.Find("lblCurrent", true).FirstOrDefault() as Label;
            if (lblCurrent != null) lblCurrent.Text = $"Current: {name}";

            pbCurrent.Minimum = 0;
            if (totalBytes > 0)
            {
                pbCurrent.Maximum = 1000; // percentage ×10
                pbCurrent.Value = 0;
            }
            else
            {
                pbCurrent.Maximum = 100; // indeterminate fallback
                pbCurrent.Value = 50; // mid-fill
            }
            pbCurrent.Invalidate();
        }


        // REPLACE [1214] (entire method)
        // DROP-IN
        // DROP-IN — throttle only off-UI thread; always update on start/finish
        private void UpdateCurrentFileProgress(long downloaded, long total)
        {
            // If we're not on the UI thread, throttle calls before marshaling
            if (InvokeRequired)
            {
                // Always allow first and final updates through
                bool isEdgeUpdate = (downloaded == 0) || (total > 0 && downloaded >= total);

                long now = Environment.TickCount64;
                long prev = System.Threading.Interlocked.Read(ref _lastUiUpdateTick);
                if (!isEdgeUpdate && (now - prev) < 100) return; // 100 ms gate off-UI thread
                System.Threading.Interlocked.Exchange(ref _lastUiUpdateTick, now);

                BeginInvoke(new Action<long, long>(UpdateCurrentFileProgress), downloaded, total);
                return;
            }

            if (pbCurrent == null || pbCurrent.IsDisposed) return;

            const int MAX = 1000;
            pbCurrent.Minimum = 0;
            pbCurrent.Maximum = MAX;

            int val = (int)Math.Min(MAX, (downloaded * (long)MAX) / Math.Max(1L, total));
            if (val != pbCurrent.Value)
            {
                pbCurrent.Value = val; // avoid redundant repaints

                // live progress
                try
                {
                    var __id = _qKey ?? ""; // finalPath isn't in scope here; _qKey is stable
                    int __pct = 0;
                    if (pbCurrent.Maximum > 0)
                        __pct = (int)Math.Clamp((pbCurrent.Value * 100.0) / pbCurrent.Maximum, 0, 100);

                    CMDownloaderUI.QueueTap.UpdateWorking(__id, __pct, 0);
                }
                catch { }
                // reflect progress (pct/done/size/host) to WebUI
                try
                {
                    // recompute percent locally (avoid relying on outer scope)
                    int __pct2 = (int)Math.Clamp(
                        (pbCurrent.Value * 100.0) / Math.Max(1, pbCurrent.Maximum), 0, 100);

                    string? __eta = null; // no ETA here
                    string? __host = _lastEdgeHost; // remoteUrl not in scope
                    CMDownloaderUI.WebUiStatus.SetCurrentProgress(__pct2, downloaded, total, __eta, __host);
                    CMDownloaderUI.WebUiHost.SetCurrentProgress(downloaded, total);

                }
                catch { }


            }
            pbCurrent.Invalidate();

        }






        // REPLACE [1215] (entire method)
        private void EndCurrentFileProgress()
        {
            if (InvokeRequired) { BeginInvoke(new Action(EndCurrentFileProgress)); return; }

            // null-safe label update
            if (lblCurrent == null) lblCurrent = this.Controls.Find("lblCurrent", true).FirstOrDefault() as Label;
            if (lblCurrent != null) lblCurrent.Text = "Current:";

            // Material bar reset
            pbCurrent.Minimum = 0;
            pbCurrent.Maximum = 1000;
            pbCurrent.Value = 0;
            // reset progress
            try
            {
                var __id = _qKey ?? "";
                CMDownloaderUI.QueueTap.UpdateWorking(__id, 0, 0);
            }
            catch { }

            pbCurrent.Invalidate();
        }

        // ========================== Logging & Utils ============================= //
        // UI marshaller: run any control updates on the UI thread
        private void Ui(Action a)
        {
            if (IsDisposed || !IsHandleCreated) return;
            if (InvokeRequired) { try { BeginInvoke(a); } catch { } }
            else a();
        }

        private void EdgeLogIfMeaningful(string? next)
        {
            next ??= string.Empty;
            if (!string.Equals(_lastEdgeHost, next, StringComparison.OrdinalIgnoreCase))
            {
                if (!string.IsNullOrWhiteSpace(next)) Log($"[EDGE] host → {next}");
                _lastEdgeHost = next;
            }
        }



        private void Log(string message)
        {
            // If the UI textbox isn't ready, still broadcast to SSE, then bail
            if (txtLog == null || txtLog.IsDisposed)
            {
                try { CMDownloaderUI.LogTap.Append(message); } catch { }
                System.Diagnostics.Debug.WriteLine(message);
                return;
            }

            // Marshal to UI thread if needed
            if (txtLog.InvokeRequired)
            {
                txtLog.BeginInvoke(new Action<string>(Log), message);
                return;
            }

            // suppress exact duplicate messages within 800ms
            try
            {
                long now = DateTime.UtcNow.Ticks; // 1s = 10,000,000 ticks
                if (string.Equals(message, _lastLogMsg, StringComparison.Ordinal) &&
                    (now - _lastLogTicksUtc) < 8_000_000) // 800 ms window
                    return;

                _lastLogMsg = message;
                _lastLogTicksUtc = now;
            }
            catch { /* never let logging fail */ }

            // Broadcast to web stream after dedupe passes (so SSE matches your UI log)
            try { CMDownloaderUI.LogTap.Append(message); } catch { }

            var line = $"[{DateTime.Now:HH:mm:ss}] {message}";
            txtLog.AppendText(line + Environment.NewLine);

            // Throttle UI flush (~30 FPS)
            if (!_logUiSw.IsRunning || _logUiSw.ElapsedMilliseconds >= 33)
            {
                try
                {
                    txtLog.SelectionStart = txtLog.TextLength;
                    txtLog.ScrollToCaret();
                    txtLog.Refresh(); // safe, non-reentrant
                    System.Diagnostics.Trace.Flush();
                }
                catch { /* best effort */ }

                _logUiSw.Restart();
            }
        }





        private static string? ExtractUserFromUrl(string url) { try { var u = new Uri(url); var parts = u.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries); int idx = Array.FindIndex(parts, p => p.Equals("user", StringComparison.OrdinalIgnoreCase)); if (idx >= 0 && idx + 1 < parts.Length) return parts[idx + 1]; } catch { } return null; }
        private static async Task<string> FirstNonEmptyAsync(IPage page, string[] jsExprs) { foreach (var js in jsExprs) { var t = await page.EvaluateAsync<string>(js); if (!string.IsNullOrWhiteSpace(t)) return t.Trim(); } return "untitled"; }

        // Regex helpers (NOVASTRIKE) //

        private static string SanitizeForPath(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return "untitled";
            var invalid = Path.GetInvalidFileNameChars();
            var s = new string(input.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray());
            s = RX_MULTI_WS.Replace(s, " ").Trim();
            return s.Length == 0 ? "untitled" : s;
        }


        // ===== Sanitize & Title helpers ===== //
        internal sealed class Naming { public required string CleanTitle { get; init; } public required bool UseSetFolder { get; init; } public required string? SetFolderName { get; init; } public required string CategoryFolder { get; init; } }
        private Naming BuildNaming(string rawPostTitle, string categoryFolder, int assetCount, string? usernameHint)
        {
            var clean = CleanPostTitle(rawPostTitle, usernameHint); var safe = SanitizeForPath(clean); bool useSet = assetCount > 1;
            return new Naming { CleanTitle = safe, UseSetFolder = useSet, SetFolderName = useSet ? SanitizeForPath(safe + "_set") : null, CategoryFolder = categoryFolder };
        }

        private static string CleanPostTitle(string raw, string? usernameHint = null)
        {
            if (string.IsNullOrWhiteSpace(raw)) return "untitled";
            var s = RX_POST_PREFIX.Replace(raw, string.Empty);
            s = Regex.Replace(RX_OF_SUFFIX.Replace(s, string.Empty), @"\s*(?:\(|-|–|—|\|)?\s*OnlyFans\)?\s*$", "", RegexOptions.IgnoreCase);
            // Also strip "(Fansly)" tokens at start || end (mirror OnlyFans handling) // [1058.1] //
            s = Regex.Replace(s, @"^\s*(\(|\[)?\s*Fansly\s*(\]|\))?\s*([:\-\|–—_])?\s*", "", RegexOptions.IgnoreCase); // //
            s = Regex.Replace(s, @"\s*(\(|\[)?\s*Fansly\s*(\]|\))?\s*$", "", RegexOptions.IgnoreCase); // //
            if (!string.IsNullOrWhiteSpace(usernameHint))
            {
                s = Regex.Replace(s, @"\b" + Regex.Escape(usernameHint) + @"\b", "", RegexOptions.IgnoreCase);
                s = s.Replace("_" + usernameHint + "_", "", StringComparison.OrdinalIgnoreCase);
            }
            s = RemoveEmojiAndNoise(s);
            s = RX_MULTI_WS.Replace(s, " ").Trim(' ', '-', '_', '.', '"', '\'');
            if (string.IsNullOrEmpty(s)) s = "untitled";
            return s;
        }

        private static string RemoveEmojiAndNoise(string input)
        {
            var tasks = new List<Task>();
            var sb = new StringBuilder(input.Length);
            foreach (var ch in input.Normalize(NormalizationForm.FormKC))
            {
                var cat = CharUnicodeInfo.GetUnicodeCategory(ch);
                switch (cat)
                {
                    case UnicodeCategory.OtherSymbol:
                    case UnicodeCategory.Surrogate:
                    case UnicodeCategory.PrivateUse:
                    case UnicodeCategory.ModifierSymbol:
                    case UnicodeCategory.NonSpacingMark:
                    case UnicodeCategory.Format:
                        break;
                    default: sb.Append(ch); break;
                }
            }
            return sb.ToString();
        }


        // //
        private static string TruncateFolder(string name, int max = 48)
        { // //
            if (string.IsNullOrWhiteSpace(name)) return name; // //
            return name.Length <= max ? name : name[..max].TrimEnd(' ', '.', '-'); // //
        } // //
        private static string TruncateFile(string name, int max = 96)
        {
            if (string.IsNullOrWhiteSpace(name)) return "untitled";
            return (name.Length <= max ? name : name[..max]).TrimEnd(' ', '.', '-');
        }
        // Logs the "no Range support" message only once per run
        private bool _loggedNoRangeOnce;
        // Edge log de-dup state
        private string? _lastEdgeHostLogged = null; // last host we logged

        private string? _lastSsSig;
        private long _ssSendTotal;
        private long _ssSendSuppressed;

        // ========================== Adblock helpers ============================= //
        private void LoadAdblockRulesFromDisk() { try { if (File.Exists(_easyListPath)) { var text = File.ReadAllText(_easyListPath); _adblockRules = ParseEasyList(text); lblAdblockUpdate.Text = "Updated"; Log($"[Adblock] Loaded rules: {_adblockRules.Count} from {_easyListPath}"); } } catch (Exception ex) { lblAdblockUpdate.Text = "Load failed"; Log($"[Adblock] Load failed: {ex.Message}"); } }
        private async Task UpdateFiltersAsync()
        {
            try
            {
                string url = "https://easylist-downloads.adblockplus.org/easylist.txt";
                using var hc = new HttpClient();
                var text = await hc.GetStringAsync(url);
                if (!string.IsNullOrWhiteSpace(text))
                {
                    File.WriteAllText(_easyListPath, text);
                    _adblockRules = ParseEasyList(text);
                    lblAdblockUpdate.Text = "Updated";
                    Log($"[Adblock] Rules updated: {_adblockRules.Count}");
                }
                else
                {
                    lblAdblockUpdate.Text = "No Update Needed";
                }
            }
            catch (Exception ex)
            {
                lblAdblockUpdate.Text = "Update failed";
                Log($"[Adblock] Update failed: {ex.Message}");
            }
        }
        private static HashSet<string> ParseEasyList(string text) { var rules = new HashSet<string>(StringComparer.OrdinalIgnoreCase); using var sr = new StringReader(text); string? line; while ((line = sr.ReadLine()) != null) { var t = line.Trim(); if (t.Length == 0 || t.StartsWith("!")) continue; if (t.Contains("##") || t.Contains("#@#")) continue; if (t.StartsWith("||")) { var dom = t.Trim('|', '^'); int cut = dom.IndexOfAny(new[] { '^', '/', '*' }); if (cut > 0) dom = dom[..cut]; if (!string.IsNullOrWhiteSpace(dom)) rules.Add(dom.ToLowerInvariant()); } else if (t.StartsWith("|http", StringComparison.OrdinalIgnoreCase)) { var pref = t.Trim('|'); int cut = pref.IndexOf('^'); if (cut > 0) pref = pref[..cut]; rules.Add(pref.ToLowerInvariant()); } } return rules; }
        private bool IsBlockedByAdblock(string lowerUrl) { foreach (var r in _adblockRules) { if (r.StartsWith("http")) { if (lowerUrl.StartsWith(r)) return true; } else { if (lowerUrl.Contains(r)) return true; } } return false; }


        private bool ShouldFallbackToSSWhenPoolFull(int activeSegVideos, int poolCap)
        {
            // 3-strike hysteresis: require 3 consecutive "full" checks before SS fallback.
            bool full = activeSegVideos >= poolCap;
            if (full)
            {
                _segAutoConsecFree = 0;
                if (++_segAutoConsecFull < 3) return false; // not yet
            }
            else
            {
                _segAutoConsecFull = 0;
                _segAutoConsecFree++;
            }
            _segAutoPoolFull = full;
            return full; // true only after 3 consecutive full ticks
        }

        private void LogAutoscaleIfChanged(int activeSegVideos, int poolCap, bool forcingSS)
        {
            long key = ((long)(_segAutoPoolFull ? 1 : 0) << 32)
                     | ((long)activeSegVideos << 16)
                     | (long)poolCap
                     | (forcingSS ? 1L : 0L);
            if (key == _segAutoLastLogKey) return;
            _segAutoLastLogKey = key;

            // DIAG ONLY
            // try { Log($"[SEG.AUTOSCALE] poolFull={_segAutoPoolFull} active={activeSegVideos}/{poolCap} forceSS={forcingSS}"); } catch { }
        }

        // ========================== Jitter + Cooldown =========================== //
        private async Task JitterAsync(string kind, CancellationToken ct) { try { int min = 100, max = 250; switch (kind) { case "IMG": min = 150; max = 500; break; case "VID": min = 400; max = 1200; break; case "ZIP": min = 600; max = 1500; break; case "POST": min = 800; max = 2000; break; } double factor = 1.0 + Math.Min(0.5, 0.1 * _jitterScore); int delay = (int)Math.Round(_rnd.Next(min, max + 1) * factor); var now = DateTime.UtcNow; if (_cooldownUntilUtc > now) { int extra = (int)Math.Max(0, (_cooldownUntilUtc - now).TotalMilliseconds); delay += extra; } await Task.Delay(delay, ct); } catch { } }
        private async Task CooldownIfNeededAsync(CancellationToken ct)
        {
            DecayRl();
            var now = DateTime.UtcNow;
            if (_cooldownUntilUtc > now)
            {
                int ms = (int)Math.Max(0, (_cooldownUntilUtc - now).TotalMilliseconds);
                Log($"[HEALTH] Cooldown active {ms}ms");
                await Task.Delay(ms, ct);
            }
        }

        private void ResetHealth() { _rlScore = 0; _cooldownUntilUtc = DateTime.MinValue; _healthState = "OK"; UpdateHealthLabel(); }
        private void AdjustHealthOnSuccess() { _rlScore = Math.Max(0, _rlScore - 3); if (_rlScore == 0) { _healthState = "OK"; } UpdateHealthLabel(); }
        private void ResetCurrentProgressUI()
        {
            if (InvokeRequired) { BeginInvoke(new Action(ResetCurrentProgressUI)); return; }
            try { pbCurrent.Value = 0; pbCurrent.Invalidate(); } catch { /* best-effort */ }
            // reset progress
            try
            {
                var __id = _qKey ?? "";
                CMDownloaderUI.QueueTap.UpdateWorking(__id, 0, 0);
            }
            catch { }

        }
        // enable double-buffering when the HWND is created (prevents restore flash)
        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            try
            {
                this.SetStyle(ControlStyles.OptimizedDoubleBuffer |
                              ControlStyles.AllPaintingInWmPaint |
                              ControlStyles.UserPaint, true);
                this.UpdateStyles();
            }
            catch { /* best-effort */ }
        }
        // skip background clear to avoid brief dark flash on restore
        protected override void OnPaintBackground(PaintEventArgs e)
        {
            // Intentionally no base.OnPaintBackground(); full-frame paint covers background.
        }


        private void AdjustHealthOnFailure(int? statusCode, Exception ex)
        {
            bool isTimeout = ex is TaskCanceledException;
            bool isPressure = false;
            if (statusCode.HasValue)
            {
                int sc = statusCode.Value;
                if (sc == 403 || sc == 429 || sc == 503) isPressure = true;
                else if (sc >= 500 && sc <= 599) isPressure = true;
            }
            if (isTimeout || isPressure) _rlScore += isPressure ? 2 : 1;
            _rlScore = Math.Min(_rlScore, 12);
            if (_rlScore >= 6) { int secs = 40 + _rnd.Next(0, 21); _cooldownUntilUtc = DateTime.UtcNow.AddSeconds(secs); _healthState = "COOLDOWN"; UpdateHealthLabel(); Log($"[HEALTH] Heavy cooldown {secs}s (score={_rlScore})"); }
            else if (_rlScore >= 3) { int secs = 10 + _rnd.Next(0, 11); var till = DateTime.UtcNow.AddSeconds(secs); if (till > _cooldownUntilUtc) _cooldownUntilUtc = till; _healthState = "WARN"; UpdateHealthLabel(); Log($"[HEALTH] Light cooldown {secs}s (score={_rlScore})"); }
            else UpdateHealthLabel();
        }

        private void UpdateHealthLabel()
        {
            if (lblHealth == null || lblHealth.IsDisposed) return;
            if (lblHealth.InvokeRequired) { lblHealth.BeginInvoke(new Action(UpdateHealthLabel)); return; }

            DecayRl();
            string state = "OK";
            if (_cooldownUntilUtc > DateTime.UtcNow) state = "COOLDOWN";
            else if (_rlScore >= 3) state = "WARN";
            _healthState = state;

            Color c = state switch { "COOLDOWN" => Color.Goldenrod, "WARN" => Color.Orange, _ => Color.ForestGreen };
            var limits = CurrentLimits();

            // Prefix stays white; color only the state label
            lblHealth.ForeColor = Color.White;
            lblHealth.Text = "HEALTH:";
            lblHealthState.ForeColor = c;
            lblHealthState.Text = state; // heartbeat will append ▮


            // Create-or-get the trailing info label once, place it right after lblHealth
            var parent = lblHealth.Parent;
            if (parent != null)
            {
                var iq = _imgQ?.Count ?? 0;
                var vq = _vidQ?.Count ?? 0;
                var iAct = System.Threading.Volatile.Read(ref _inflightNV);
                var vAct = System.Threading.Volatile.Read(ref _inflightVID);

                string tail = $"NV {limits.nv}  V {limits.vid}";
                if (_stopRequested && _stopMode == StopMode.Graceful)
                    tail += $"  Queued:{iq + vq}  Drain I{iAct}/V{vAct}";


                var extra = parent.Controls["lblHealthInfo"] as Label;
                if (extra == null)
                {
                    extra = new Label { Name = "lblHealthInfo", AutoSize = true, Margin = new Padding(6, 1, 0, 0) }; // nudge down 1px
                    parent.Controls.Add(extra);
                    parent.Controls.SetChildIndex(extra, parent.Controls.GetChildIndex(lblSpeed)); // sit just before SPEED
                    extra.Margin = new Padding(6, lblSpeed.Margin.Top + -1, 0, 0); // slight drop to align with SPEED
                    extra.ForeColor = Color.White;


                }
                extra.ForeColor = Color.White; // force white on dark theme
                extra.Text = tail;
            }
        }


        private void DecayRl()
        {
            var now = DateTime.UtcNow;
            var dt = now - _rlLastDecayUtc;
            if (dt.TotalSeconds >= 30 && _rlScore > 0)
            {
                int steps = (int)(dt.TotalSeconds / 30.0);
                _rlScore = Math.Max(0, _rlScore - steps);
                _rlLastDecayUtc = now;
            }
        }


        private static string RetryKey(string kind, Uri url, string titleKey, string? matchKey) => $"{kind}|{url}|{titleKey}|{matchKey}";

        private void EnqueueForWatchdog(Uri url, Naming naming, int idx, string kind, string? referer, string? matchKey, string reason)
        {
            // — never enqueue while stopping/draining
            if (_stopImmediate || (_stopRequested && _stopMode == StopMode.Graceful) || s_Draining)
            {
                try { Log($"[WD.SKIP] {(_stopImmediate ? "immediate" : "graceful/drain")} → not re-queued :: {kind} #{idx} :: {reason}"); } catch { }
                return;
            }

            if (url == null || naming == null) return;
            if (string.IsNullOrWhiteSpace(kind)) kind = "UNK";
            if (idx <= 0) idx = 1;

            var key = RetryKey(kind, url, naming.CleanTitle, matchKey);

            bool added;
            // HashSet<T> isn't thread-safe; guard the Add() + enqueue.
            lock (_retrySeen)
                added = _retrySeen.Add(key);

            if (added)
            {
                _retryQ.Enqueue((url, naming, idx, kind, referer, matchKey)); _wdEnqueued++;
                try { Log($"[WATCHDOG] queued {kind} #{idx} :: {reason}"); } catch { }

                // reflect watchdog backlog in WebUI queue count
                try
                {
                    WebUiStatus.SetQueue((_imgQ?.Count ?? 0) + (_vidQ?.Count ?? 0) + _retryQ.Count);
                }
                catch { }
            }

        }


        // ========================== URL Refresh helper ========================= //
        private async Task<Uri?> RefreshAssetUrlAsync(string kind, string postUrl, string matchKey, CancellationToken ct)
        {
            try
            {
                // Ensure we have a live Playwright page
                var page = _page;
                if (page == null || page.IsClosed)
                {
                    if (_browser == null || _context == null)
                        await SetupPlaywrightAsync().ConfigureAwait(false); // || EnsurePlaywrightAsync()

                    if (_context == null) throw new InvalidOperationException("Playwright context not ready.");
                    page = _page = await _context.NewPageAsync().ConfigureAwait(false);
                }

                await _page!.GotoAsync(postUrl, new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded, Timeout = 30000 });
                // ensure post content is present before scraping
                await _page!.WaitForSelectorAsync("div[class*=post__files], div[class*=post__body], video, img, footer", new() { Timeout = 15000 }).ConfigureAwait(false);

                try { await _page.WaitForSelectorAsync("article, .post, .post__files, a[href*='/data/'], img", new PageWaitForSelectorOptions { Timeout = 6000 }); } catch { }
                // ensure all real media URLs have hydrated before selecting best
                try
                {
                    // Wait for attachment links + hydrated image/video sources to stabilize
                    for (int i = 0; i < 5; i++)
                    {
                        await _page.WaitForTimeoutAsync(120);

                        var att = await _page.QuerySelectorAllAsync(".post__files a[href*='/data/']");
                        var imgs = await _page.QuerySelectorAllAsync(".post__files img[src*='/thumbnail/']");
                        var vids = await _page.QuerySelectorAllAsync("video source[src]");

                        // Break early when attachments, images, and video sources stop changing
                        if (att.Count >= 1 && vids.Count >= 1) break;
                    }
                }
                catch { }

                if (kind == "IMG")
                {
                    // IMAGE EXTENSIONS (strict)
                    var imgExts = new[] { ".jpg", ".jpeg", ".png", ".gif", ".webp" };

                    // PRIMARY: images from the official Coomer image block
                    var imgs = await CollectByExtensionsFromSelectorAsync(
                        _page,
                        "div.post__files a.fileThumb.image-link[href]",
                        imgExts);

                    // FALLBACK (image-only): if no images found from post__files
                    if (imgs.Count == 0)
                    {
                        var fb = await CollectByExtensionsFromSelectorAsync(
                            _page,
                            "a[href], img[src], img[data-src]",
                            imgExts);

                        imgs = fb.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    }

                    // Deduplicate & pick best
                    var best = await SelectBestImagesAsync(imgs, ct);
                    foreach (var u in best)
                        if (string.Equals(ImageKey(u.ToString()), matchKey, StringComparison.OrdinalIgnoreCase))
                            return u;
                }

                else if (kind == "VID")
                {
                    var exts = new[] { ".mp4", ".m4v", ".mkv", ".webm" }; // keep it local/minimal

                    // PRIMARY: Direct MP4 download links (correct source for all Coomer videos)
                    var vidAnchors = await CollectByExtensionsFromSelectorAsync(
                        _page,
                        "ul.post__attachments a.post__attachment-link[href]",
                        exts);

                    // FALLBACK: Embedded <video><source src="...mp4"> only if downloads list is empty
                    List<string> vids;
                    if (vidAnchors.Count == 0)
                    {
                        var vidSrcs = await CollectVideoSourcesFromSelectorAsync(
                            _page,
                            ".post__body",
                            exts);

                        vids = vidSrcs.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    }
                    else
                    {
                        vids = vidAnchors.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    }

                    // treat whatever we found here as direct-legit for matchKey re-find
                    var directVidSetLocal = new HashSet<string>(vids, StringComparer.OrdinalIgnoreCase);

                    var bestVids = await SelectBestVideosAsync(vids, ct, directVidSetLocal);
                    foreach (var v in bestVids)
                        if (string.Equals(VideoKeyFromUrl(v), matchKey, StringComparison.OrdinalIgnoreCase))
                            return v;

                }


            }
            catch { }
            return null;
        }

        private async Task RunWatchdogPassesAsync(CancellationToken ct)
        {
            for (int pass = 1; pass <= WD_MAX_PASSES && !ct.IsCancellationRequested; pass++)
            {
                int count = _retryQ.Count; if (count == 0) break;
                Log($"[WATCHDOG] pass {pass}/{WD_MAX_PASSES} — {count} item(s)");

                var batch = new List<(Uri url, Naming naming, int idx, string kind, string? referer, string? matchKey)>();
                while (_retryQ.TryDequeue(out var it)) batch.Add(it);

                // NEW: include in-flight retry batch so WebUI queue doesn't drop to 0 mid-pass
                try
                {
                    WebUiStatus.SetQueue((_imgQ?.Count ?? 0) + (_vidQ?.Count ?? 0) + _retryQ.Count + batch.Count);
                }
                catch { }

                int ok = 0;
                foreach (var it in batch)
                {
                    if (ct.IsCancellationRequested) break;
                    bool success = false;

                    for (int a = 0; a < WD_PER_ITEM_ATTEMPTS && !success; a++)
                    {
                        // Active-host counter wrap for this attempt
                        string __edgeHost = null; try { __edgeHost = it.url?.Host; } catch { }
                        if (!string.IsNullOrEmpty(__edgeHost))
                            _activeByHost.AddOrUpdate(__edgeHost, 1, static (_, v) => v + 1);
                        try
                        {
                            success = await DownloadWithNamingAsync(it.url, it.naming, it.idx, it.kind, it.referer, ct, it.matchKey);
                        }
                        finally
                        {
                            if (!string.IsNullOrEmpty(__edgeHost))
                                _activeByHost.AddOrUpdate(__edgeHost, 0, static (_, v) => (v > 1 ? v - 1 : 0));
                        }

                        if (!success) { try { await Task.Delay(150, ct); } catch { } }
                    }

                    if (success) { ok++; _wdSucceeded++; }
                }

                Log($"[WATCHDOG] pass {pass} done — success={ok}, remaining={_retryQ.Count}");
                { var remaining = _retryQ.Count; var fail = Math.Max(0, _wdEnqueued - _wdSucceeded - remaining); Log($"[WATCHDOG] totals: enqueued={_wdEnqueued} ok={_wdSucceeded} fail={fail} remaining={remaining}"); }

                // NEW: refresh queue after the pass (batch finished)
                try
                {
                    WebUiStatus.SetQueue((_imgQ?.Count ?? 0) + (_vidQ?.Count ?? 0) + _retryQ.Count);
                }
                catch { }

                if (pass < WD_MAX_PASSES) { try { await Task.Delay(TimeSpan.FromSeconds(8 * pass), ct); } catch { } }
            }

            // After all watchdog passes, reflect final backlog (usually 0) in the WebUI queue
            try
            {
                WebUiStatus.SetQueue((_imgQ?.Count ?? 0) + (_vidQ?.Count ?? 0) + _retryQ.Count);
            }
            catch { }
        }



        // ========================== UI Prefs =================================== //
        // REPLACE [1418]..[1435] (entire method)
        private void LoadUIPrefs()
        {
            try
            {
                _loadingPrefs = true;
                if (!File.Exists(_uiPrefsPath)) return;
                bool lockSize = false;
                foreach (var line in File.ReadAllLines(_uiPrefsPath))
                {
                    var t = line.Trim(); if (t.Length == 0 || t.StartsWith("#")) continue;
                    var parts = t.Split('='); if (parts.Length != 2) continue;
                    var k = parts[0].Trim().ToLowerInvariant(); var v = parts[1].Trim();
                    if (k == "parallel") _parallelOn = v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase);
                    else if (k == "nv") _maxNV = Math.Max(1, Math.Min(12, int.Parse(v)));
                    else if (k == "vid") _maxVID = Math.Max(1, Math.Min(4, int.Parse(v)));
                    else if (k == "locksize") lockSize = (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase));
                    else if (k == "adblock_last_update_utc")

                    {
                        if (DateTime.TryParse(v, CultureInfo.InvariantCulture,
                            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
                            _adblockLastUpdateUtc = dt;
                    }
                    else if (k == "wrap_log")
                    { _prefWrapLog = (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase)); }
                    else if (k == "media_mode")
                    {
                        var vv = v.ToLowerInvariant();
                        if (vv == "1" || vv.StartsWith("img")) _mediaMode = MediaMode.Images;
                        else if (vv == "2" || vv.StartsWith("vid") || vv.StartsWith("video") || vv.StartsWith("aud"))
                            _mediaMode = MediaMode.VideoAudio;
                        else _mediaMode = MediaMode.All;
                    }
                    else if (k == "open_on_done")
                    {
                        var ob = this.Controls.Find("chkOpenOnDone", true).OfType<CheckBox>().FirstOrDefault();
                        if (ob != null) ob.Checked = (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase));
                    }
                    else if (k == "adblock_on")
                    {
                        bool on = (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase));
                        var ab = this.Controls.Find("chkAdblockOn", true).OfType<CheckBox>().FirstOrDefault();
                        if (ab != null) ab.Checked = on;
                        _adblockOn = on; // keep internal flag in sync for ApplyAdblockUpdateVisibility()
                    }
                    else if (k == "tiny_off")
                    {
                        _tinyOff = (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase));
                    }

                    else if (k == "coomer_remember")
                    {
                        _coomerRemember = (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase));
                    }
                    else if (k == "coomer_user")
                    {
                        _coomerRememberUser = v ?? "";
                    }
                    else if (k == "coomer_pass_dpapi")
                    {
                        // decrypted only on demand
                        _coomerRememberPass = UnprotectFromB64(v ?? "");
                    }

                    else if (k == "nv_all") { if (int.TryParse(v, out var nAll)) _nvAll = Math.Min(MAX_IMG_CONC, Math.Max(0, nAll)); }
                    else if (k == "vid_all") { if (int.TryParse(v, out var vAll)) _vidAll = Math.Min(MAX_VID_CONC, Math.Max(0, vAll)); }
                    else if (k == "nv_img") { if (int.TryParse(v, out var nImg)) _nvImg = Math.Min(MAX_IMG_CONC, Math.Max(0, nImg)); }
                    else if (k == "vid_img") { if (int.TryParse(v, out var vImg)) _vidImg = Math.Min(MAX_VID_CONC, Math.Max(0, vImg)); }
                    else if (k == "nv_vid") { if (int.TryParse(v, out var nVid)) _nvVid = Math.Min(MAX_IMG_CONC, Math.Max(0, nVid)); }
                    else if (k == "vid_vid") { if (int.TryParse(v, out var vVid)) _vidVid = Math.Min(MAX_VID_CONC, Math.Max(0, vVid)); }





                }
                _maxNV = Math.Max(1, Math.Min(_maxNV, MAX_IMG_CONC));
                _maxVID = Math.Max(1, Math.Min(_maxVID, MAX_VID_CONC));
                chkParallel.Checked = _parallelOn;
                nudNV.Value = _maxNV; nudVID.Value = _maxVID;

                var lockBox = this.Controls.Find("chkLockSize", true).OfType<CheckBox>().FirstOrDefault();
                if (lockBox != null) lockBox.Checked = lockSize;
                if (lockSize) LockFormToCurrentSize(); else UnlockFormSize();
                // Reflect media mode into UI and lanes //
                var cmb = this.Controls.Find("cmbMode", true).OfType<ComboBox>().FirstOrDefault();
                if (cmb != null)
                {
                    cmb.SelectedIndex = _mediaMode switch
                    {
                        MediaMode.Images => 1,
                        MediaMode.VideoAudio => 2,
                        _ => 0
                    };
                }
                ApplyMediaModeLanes();

            }
            catch { }
            finally { _loadingPrefs = false; }
        }


        private void EdgeLogIfMeaningful(string prevHost, string nextHost)
        {
            if (string.IsNullOrEmpty(prevHost) || string.IsNullOrEmpty(nextHost)) return;

            bool changed = !string.Equals(prevHost, nextHost, StringComparison.OrdinalIgnoreCase);
            if (!changed) return;

            var now = DateTime.UtcNow;
            if (!string.Equals(_lastEdgeHostLogged, nextHost, StringComparison.OrdinalIgnoreCase) ||
                (now - _lastEdgeLogAt).TotalSeconds >= 3)
            {
                Log($"[EDGE] using {nextHost} (was {prevHost})");
                _lastEdgeHostLogged = nextHost;
                _lastEdgeLogAt = now;
            }
        }


        // [COOMER.REMEMBER] DPAPI helpers (CurrentUser)
        static string ProtectToB64(string plain)
        {
            if (string.IsNullOrEmpty(plain)) return "";
            try
            {
                var bytes = Encoding.UTF8.GetBytes(plain);
                var prot = System.Security.Cryptography.ProtectedData.Protect(
                    bytes, optionalEntropy: null,
                    System.Security.Cryptography.DataProtectionScope.CurrentUser);
                return Convert.ToBase64String(prot);
            }
            catch { return ""; }
        }

        static string UnprotectFromB64(string b64)
        {
            if (string.IsNullOrWhiteSpace(b64)) return "";
            try
            {
                var prot = Convert.FromBase64String(b64);
                var bytes = System.Security.Cryptography.ProtectedData.Unprotect(
                    prot, optionalEntropy: null,
                    System.Security.Cryptography.DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(bytes);
            }
            catch { return ""; }
        }

        private void SaveUIPrefs()
        {
            try
            {
                if (_loadingPrefs) return;

                var sb = new StringBuilder();
                sb.AppendLine("# CMDownloaderUI ui.ini");
                sb.AppendLine("parallel=" + (_parallelOn ? "1" : "0"));
                var lockBox = this.Controls.Find("chkLockSize", true).OfType<CheckBox>().FirstOrDefault();
                sb.AppendLine("locksize=" + ((lockBox?.Checked ?? false) ? "1" : "0"));
                var openBox = this.Controls.Find("chkOpenOnDone", true).OfType<CheckBox>().FirstOrDefault();
                var adbBox = this.Controls.Find("chkAdblockOn", true).OfType<CheckBox>().FirstOrDefault();
                sb.AppendLine("open_on_done=" + ((openBox?.Checked ?? false) ? "1" : "0"));
                sb.AppendLine("adblock_on=" + ((adbBox?.Checked ?? false) ? "1" : "0"));

                if (_adblockLastUpdateUtc.HasValue)
                    sb.AppendLine("adblock_last_update_utc=" + _adblockLastUpdateUtc.Value.ToString("o", CultureInfo.InvariantCulture));
                sb.AppendLine("wrap_log=" + (_prefWrapLog ? "1" : "0"));
                // Always start in All mode next launch; don't persist last used mode
                sb.AppendLine("media_mode=0");

                sb.AppendLine("tiny_off=" + (_tinyOff ? "1" : "0"));
                //sb.AppendLine("coomer_remember=" + (_coomerRemember ? "1" : "0"));
                //sb.AppendLine("coomer_user=" + (_coomerRememberUser ?? ""));
                //sb.AppendLine("coomer_pass_dpapi=" + (_coomerRemember ? ProtectToB64(_coomerRememberPass ?? "") : ""));


                sb.AppendLine("nv_all=" + _nvAll); sb.AppendLine("vid_all=" + _vidAll);
                sb.AppendLine("nv_img=" + _nvImg); sb.AppendLine("vid_img=" + _vidImg);
                sb.AppendLine("nv_vid=" + _nvVid); sb.AppendLine("vid_vid=" + _vidVid);
                // [COOMER.REMEMBER] persisted login preference
                // [COOMER.REMEMBER] preserve saved DPAPI blob if remember is on but pass isn't loaded in memory yet
                string existingDpapi = "";
                try
                {
                    if (File.Exists(_uiPrefsPath))
                    {
                        foreach (var line in File.ReadLines(_uiPrefsPath))
                        {
                            if (line.StartsWith("coomer_pass_dpapi=", StringComparison.OrdinalIgnoreCase))
                            {
                                var val = line.Split('=', 2).ElementAtOrDefault(1)?.Trim() ?? "";
                                if (!string.IsNullOrWhiteSpace(val))
                                    existingDpapi = val; // keep last non-empty
                                                         // no break
                            }
                        }
                    }


                }
                catch { }

                var dpapiOut =
                    !_coomerRemember ? "" :
                    (!string.IsNullOrWhiteSpace(_coomerRememberPass) ? ProtectToB64(_coomerRememberPass) : existingDpapi);

                sb.AppendLine("coomer_remember=" + (_coomerRemember ? "1" : "0"));
                sb.AppendLine("coomer_user=" + (_coomerRememberUser ?? ""));
                sb.AppendLine("coomer_pass_dpapi=" + (dpapiOut ?? ""));

                try
                {
                    var caller = new System.Diagnostics.StackTrace().GetFrame(1)?.GetMethod()?.Name ?? "?";
                    CMDownloaderUI.LogTap.Append($"[UIINI.SAVE] caller={caller} path={_uiPrefsPath}");
                }
                catch { }

                File.WriteAllText(_uiPrefsPath, sb.ToString());
            }
            catch { }
        }
        private void ApplyAdblockUpdateVisibility()
        {
            try
            {
                bool due = !_adblockLastUpdateUtc.HasValue ||
                           (DateTime.UtcNow - _adblockLastUpdateUtc.Value).TotalDays >= ADBLOCK_UPDATE_DAYS;
                if (btnAdblockUpdate != null) btnAdblockUpdate.Visible = due;
                // Do not touch any parent/row/host. LED remains independent. //
            }
            catch { }
        }


        // non-client paint hook
        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m);
            if (m.Msg == WM_NCPAINT || m.Msg == WM_NCACTIVATE)
                DrawCaptionBanner();
        }

        private void DrawCaptionBanner()
        {
            if (_captionBanner == null || !this.IsHandleCreated || this.IsDisposed) return;

            var hdc = GetWindowDC(this.Handle);
            if (hdc == IntPtr.Zero) return;

            try
            {
                using (var g = Graphics.FromHdc(hdc))
                {
                    int cx = GetSystemMetrics(SM_CXFRAME);
                    int cy = GetSystemMetrics(SM_CYFRAME);
                    int pad = GetSystemMetrics(SM_CXPADDEDBORDER);
                    int cap = GetSystemMetrics(SM_CYCAPTION);

                    int left = cx + pad; // inside left frame
                    int top = cy; // top of caption band
                    int rightButtonsReserve = 160; // space for min/max/close
                    int width = Math.Max(0, this.Width - left - rightButtonsReserve);
                    int height = Math.Max(20, cap + pad); // caption height

                    if (width > 0 && height > 0)
                    {
                        g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                        g.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.HighQuality;
                        if (_captionBanner != null)
                        {
                            var dst = new Rectangle(left, top, width, height);
                            g.SetClip(dst);
                            double s = width / (double)_captionBanner.Width; // fit by WIDTH
                            int w = width;
                            int h = Math.Max(1, (int)Math.Round(_captionBanner.Height * s));
                            int x = left;
                            int y = top + (height - h) / 2; // center vertically
                            g.DrawImage(_captionBanner, new Rectangle(x, y, w, h));
                            g.ResetClip();
                        }


                    }
                }
            }
            finally
            {
                ReleaseDC(this.Handle, hdc);
            }
        }

        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _quickAddedThisRun = new(StringComparer.OrdinalIgnoreCase);
        private long _staleQuickThisRun;

        // per-host score: +1 on 206 success, −1 on "Range ignored/failed".
        // Host is "range-safe" if score ≥ +1; "ss-only" if score ≤ −1.
        private readonly Dictionary<string, int> _hostRangeScore = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _hostRangeScoreLock = new();
        private const int RANGE_SAFE_MIN = +1;
        private const int RANGE_BAD_MAX = -1;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void HostRangeScore_Add(string? host, int delta)
        {
            if (string.IsNullOrEmpty(host)) return;
            lock (_hostRangeScoreLock)
            {
                _hostRangeScore.TryGetValue(host!, out var s);
                s += delta;
                if (s > 2) s = 2; // clamp
                else if (s < -2) s = -2;
                _hostRangeScore[host!] = s;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private int HostRangeScore_Get(string? host)
        {
            if (string.IsNullOrEmpty(host)) return 0;
            lock (_hostRangeScoreLock) return _hostRangeScore.TryGetValue(host!, out var s) ? s : 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private bool HostIsRangeSafe(string? host) => HostRangeScore_Get(host) >= RANGE_SAFE_MIN;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private bool HostIsSsOnly(string? host) => HostRangeScore_Get(host) <= RANGE_BAD_MAX;


        private readonly HashSet<string> _rpFailSeen = new(StringComparer.OrdinalIgnoreCase);
        // coalesce frequent active-count changes
        private static readonly TimeSpan __UiActiveMinGap = TimeSpan.FromMilliseconds(250);
        private DateTime __uiLastActivePush = DateTime.MinValue;
        private int __uiActivePushPending = 0;

        // bypass throttle so UI always updates
        private void WebUiPublishActiveThrottled()
        {
            try { WebUiPublishCooldowns(); } catch { }
        }



        private readonly HashSet<string> _rpSeen = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _qfFailSeen = new(StringComparer.OrdinalIgnoreCase);

        private void ProbeLogOnce(string host, string msg)
        {
            if (!_rpSeen.Add(host)) return; // already logged this host
            try { Log(msg); } catch { }
        }

        // compact ToolStrip renderer (takes accent from caller)
        public sealed class ThemedRenderer : ToolStripProfessionalRenderer
        {
            private readonly Color _accent;
            private static readonly Color _bg = Color.FromArgb(36, 36, 36);
            private static readonly Color _border = Color.FromArgb(64, 64, 64);

            public ThemedRenderer(Color accent) : base(new ProfessionalColorTable()) { _accent = accent; }

            protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
            {
                using var p = new Pen(_border);
                e.Graphics.DrawRectangle(p, 0, 0, e.ToolStrip.Width - 1, e.ToolStrip.Height - 1);
            }

            protected override void OnRenderImageMargin(ToolStripRenderEventArgs e)
            {
                using var b = new SolidBrush(_bg);
                e.Graphics.FillRectangle(b, e.AffectedBounds);
            }
            // inside ThemedRenderer
            protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e)
            {
                using var b = new SolidBrush(_bg);
                e.Graphics.FillRectangle(b, e.AffectedBounds);
            }


            protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
            {
                var r = e.Item.ContentRectangle;
                int y = r.Top + r.Height / 2;
                using var p = new Pen(_border);
                e.Graphics.DrawLine(p, r.Left, y, r.Right, y);
            }

            protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
            {
                var r = new Rectangle(Point.Empty, e.Item.Bounds.Size);
                var fill = e.Item.Selected ? _accent
                           : (e.ToolStrip is ToolStripDropDown ? _bg : Color.Transparent);
                using var b = new SolidBrush(fill);
                e.Graphics.FillRectangle(b, r);
            }

            protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
            {
                e.TextColor = e.Item.Enabled ? Color.White : Color.FromArgb(160, 160, 160);
                base.OnRenderItemText(e);
            }

            protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e)
            {
                e.ArrowColor = Color.White;
                base.OnRenderArrow(e);
            }

            protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e)
            {
                var r = e.ImageRectangle;
                using var bg = new SolidBrush(_accent);
                e.Graphics.FillRectangle(bg, r);

                var old = e.Graphics.SmoothingMode;
                e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                using var p = new Pen(Color.White, 2f);
                int x = r.Left + 3, y = r.Top + 4;
                e.Graphics.DrawLines(p, new[] {
            new Point(x, y+3),
            new Point(x+3, y+6),
            new Point(x+8, y)
        });
                e.Graphics.SmoothingMode = old;
            }
        }
        // end


        // === helpers: humanizers & log sanitizers (drop‑in) ===
        private static string HumanBytes(long bytes)
        {
            const long KB = 1024;
            const long MB = KB * 1024;
            const long GB = MB * 1024;
            if (bytes >= GB) return (bytes / (double)GB).ToString("0.00") + " GB";
            if (bytes >= MB) return (bytes / (double)MB).ToString("0.00") + " MB";
            if (bytes >= KB) return (bytes / (double)KB).ToString("0.00") + " KB";
            return bytes + " B";
        }

        private static string HumanRate(double bytesPerSecond)
        {
            if (double.IsNaN(bytesPerSecond) || double.IsInfinity(bytesPerSecond) || bytesPerSecond < 0) return "0 B/s";
            // round to nearest integer of bytes before formatting
            long bps = (long)Math.Round(bytesPerSecond);
            return HumanBytes(bps) + "/s";
        }
        // === [INDEX.HELPERS] quick-key parsing & index cleaning ===
        private static bool TryParseQuickKey(string key, out char kind, out long len, out string hash)
        {
            kind = '\0';
            len = 0;
            hash = string.Empty;

            if (string.IsNullOrWhiteSpace(key)) return false;

            // expected form: "I:1234567:abcdef..." or "V:9876543:abcdef..."
            var parts = key.Split(':');
            if (parts.Length != 3) return false;

            if (parts[0].Length != 1) return false;
            char k = parts[0][0];
            if (k != 'I' && k != 'V' && k != 'Z') return false;

            if (!long.TryParse(parts[1], out long length) || length <= 0) return false;

            string h = parts[2];
            // broken entries often have empty hash ⇒ "I:1234567:"
            if (string.IsNullOrWhiteSpace(h) || h.Length < 8) return false;

            kind = k;
            len = length;
            hash = h;
            return true;
        }

        private static Dictionary<string, string> CleanMediaIndex(Dictionary<string, string>? raw, Action<string>? log = null)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (raw == null || raw.Count == 0) return result;

            foreach (var kv in raw)
            {
                var key = kv.Key;
                var path = kv.Value;

                if (!TryParseQuickKey(key, out var kind, out var len, out var hash))
                {
                    try { log?.Invoke($"[INDEX.CLEAN] drop key='{key}' → malformed quick-key"); } catch { }
                    continue;
                }

                if (string.IsNullOrWhiteSpace(path))
                {
                    try { log?.Invoke($"[INDEX.CLEAN] drop key='{key}' → empty path"); } catch { }
                    continue;
                }

                try
                {
                    if (!File.Exists(path))
                    {
                        try { log?.Invoke($"[INDEX.CLEAN] drop key='{key}' → missing file: {Path.GetFileName(path)}"); } catch { }
                        continue;
                    }
                }
                catch
                {
                    // if path is weird enough to throw, just drop it
                    try { log?.Invoke($"[INDEX.CLEAN] drop key='{key}' → invalid path"); } catch { }
                    continue;
                }

                // if duplicate key maps to a different path, keep the first and log it
                if (result.TryGetValue(key, out var existing))
                {
                    if (!string.Equals(existing, path, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            log?.Invoke($"[INDEX.CLEAN] key='{key}' already mapped to {Path.GetFileName(existing)}, ignoring alt {Path.GetFileName(path)}");
                        }
                        catch { }
                    }
                    continue;
                }

                result[key] = path;
            }

            return result;
        }
        // === [INDEX.HELPERS] end ===

        private static string SanitizeLogName(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return string.Empty;
            // collapse whitespace and strip newlines/tabs for log safety
            s = Regex.Replace(s, @"\s+", " ").Trim();
            // avoid extremely long names in logs
            if (s.Length > 140) s = s.Substring(0, 140) + "…";
            return s;
        }
        // === end helpers ===


        // Create the selector and subscribe to UI updates
        private async void MainForm_Shown(object? sender, EventArgs e)
        {
            if (NATURAL_URL_ONLY) { try { _edge?.Dispose(); } catch { } _edge = null; return; }

            try
            {
                if (_edge == null)
                {
                    _edge = new EdgeSelector(
                        new EdgeSelectorOptions
                        {
                            // use runtime-safe discovery for n1..n4
                            CandidateHosts = GetMediaHostsSafe(),
                            BaseUriTemplate = new Uri("https://coomer.st/"),
                            HealthPath = "/robots.txt",
                            RangeSamplePath = "/robots.txt",
                            ProbeInterval = TimeSpan.FromMinutes(6),
                            MaxProbeConcurrency = 2,
                            SwitchMargin = 0.20,
                            ConfirmCount = 2,
                            CooldownAfterSwitch = TimeSpan.FromMinutes(5),
                        },
                        http: _http,
                        logger: Log,
                        decorateRequest: async req =>
                        {
                            foreach (var h in _http.DefaultRequestHeaders)
                                req.Headers.TryAddWithoutValidation(h.Key, h.Value);
                            await Task.CompletedTask;
                        });

                    _edge.ActiveHostChanged += (host, stats) =>
                    {
                        var ttfb = double.IsNaN(stats.EmaTtfbMs) ? 0 : stats.EmaTtfbMs;
                        var spd = double.IsNaN(stats.EmaMbps) ? 0 : stats.EmaMbps;
                        var chip = $"Edge: {host} ({ttfb:0} ms / {spd:0.0} MiB/s)";
                        if (lblSpeed != null)
                        {
                            if (InvokeRequired)
                                BeginInvoke(new Action(() => lblSpeed.Text = $"{lblSpeed.Text}  •  {chip}"));
                            else
                                lblSpeed.Text = $"{lblSpeed.Text}  •  {chip}";
                        }
                        LedKick();
                        _edgeCooldown.Remove(host);
                        _edgeStickUntil = DateTime.UtcNow.AddSeconds(60);
                        _lastEdgeHost = host;

                    };

                }

                await _edge.InitializeAsync(CancellationToken.None);
                // publish initial host list (n1..n4) to WebUI
                // try { _edge?.PublishHostsToWebUi(); } catch { /* best-effort */ }
                // seed stars/health in the dashboard immediately
                try { await _edge.UiProbeOnceAsync(CancellationToken.None); } catch { }

            }
            catch (Exception ex)
            {
                Log("[EDGE] init failed: " + ex.Message);
            }
        }
        private bool GetCoomerRememberFlag() => _coomerRemember;

        internal async void TryAutoLoginFromWebUi()
        {
            // one-shot per app run
            if (System.Threading.Interlocked.Exchange(ref _autoLoginAttempted, 1) != 0)
                return;
            // If PW is installing / not ready, defer (don’t burn the one-shot)
            if (_pwInstalling || !_pwFullyReady)
            {
                Interlocked.Exchange(ref _autoLoginDeferred, 1);
                Interlocked.Exchange(ref _autoLoginAttempted, 0); // allow retry after PW ready
                try { Log("[AUTOLOGIN] waiting for Playwright…"); } catch { }
                return;
            }

            // try { Log("[AUTOLOGIN] MainForm.TryAutoLoginFromWebUi entered"); } catch { }

            try
            {
                // already logged in?
                bool has = false;
                try { has = CoomerHasSession(); } catch { }
                if (has)
                {
                    try { Log("[AUTOLOGIN] already has session → skip"); } catch { }
                    return;
                }

                // remember enabled?
                if (!_coomerRemember)
                {
                    try { Log("[AUTOLOGIN] Save is OFF → skip"); } catch { }
                    return;
                }

                // user
                var user = _coomerRememberUser ?? "";
                if (string.IsNullOrWhiteSpace(user))
                {
                    try { Log("[AUTOLOGIN] remember user is empty → skip"); } catch { }
                    return;
                }

                // pass (may not be loaded even though ui.ini has dpapi blob)
                string pass = "";
                try
                {
                    pass = UnprotectFromB64(_coomerRememberPass ?? "");
                }
                catch { pass = ""; }

                if (string.IsNullOrWhiteSpace(pass))
                {
                    try { Log("[AUTOLOGIN] in-memory pass empty → try ui.ini dpapi"); } catch { }

                    // read dpapi blob from ui.ini directly (best-effort)
                    try
                    {

                        var iniPath = System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        "CMDownloaderUI",
                        "ui.ini"
);

                        if (!string.IsNullOrWhiteSpace(iniPath) && System.IO.File.Exists(iniPath))
                        {
                            string? dp = null;
                            foreach (var line in System.IO.File.ReadAllLines(iniPath))
                            {
                                if (line.StartsWith("coomer_pass_dpapi=", StringComparison.OrdinalIgnoreCase))
                                {
                                    dp = line.Substring("coomer_pass_dpapi=".Length).Trim();
                                    break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(dp))
                            {
                                try
                                {
                                    pass = UnprotectFromB64(dp);
                                    // keep it in memory for later
                                    _coomerRememberPass = dp;
                                    try { Log("[AUTOLOGIN] ui.ini dpapi decrypt OK"); } catch { }
                                }
                                catch
                                {
                                    try { Log("[AUTOLOGIN] ui.ini dpapi decrypt FAILED"); } catch { }
                                    pass = "";
                                }
                            }
                            else
                            {
                                try { Log("[AUTOLOGIN] ui.ini has no coomer_pass_dpapi"); } catch { }
                            }
                        }
                        else
                        {
                            try { Log("[AUTOLOGIN] ui.ini missing at '" + (iniPath ?? "") + "'"); } catch { }
                        }
                    }
                    catch (Exception exIni)
                    {
                        try { Log("[AUTOLOGIN] ui.ini read failed: " + exIni.Message); } catch { }
                    }
                }

                if (string.IsNullOrWhiteSpace(pass))
                {
                    try { Log("[AUTOLOGIN] pass still empty → skip"); } catch { }
                    return;
                }

                try { Log("[AUTOLOGIN] attempting login as '" + user + "'"); } catch { }

                bool ok = false;
                try
                {
                    var r = await CoomerLoginAsync(user, pass);
                    ok = r.ok;
                    try { Log("[AUTOLOGIN] " + (r.ok ? "login OK" : "login FAILED") + " :: " + (r.message ?? "")); } catch { }

                }
                catch (Exception exLogin)
                {
                    try { Log("[AUTOLOGIN] CoomerLoginAsync threw: " + exLogin.Message); } catch { }
                    ok = false;
                }

                try { Log(ok ? "[AUTOLOGIN] login OK" : "[AUTOLOGIN] login FAILED"); } catch { }
            }
            catch (Exception ex)
            {
                try { Log("[AUTOLOGIN] unexpected: " + ex.GetType().Name + " :: " + ex.Message); } catch { }
            }
        }


        // Respect saved UI pref on first show //
        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);

            if (_didShownOnce) return;
            _didShownOnce = true;
            



            try { MainForm_Shown(this, EventArgs.Empty); } catch { }


            // Default: locked ON unless a control/menu says otherwise
            bool wantLock = true;

            // Prefer the menu toggle if it exists
            if (_miLock != null)
                wantLock = _miLock.Checked;
            else
            {
                // Fallback to checkbox if it's still on the form somewhere
                var lockBox = this.Controls.Find("chkLockSize", true)
                                           .OfType<CheckBox>()
                                           .FirstOrDefault();
                if (lockBox != null) wantLock = lockBox.Checked;
            }

            if (wantLock) LockFormToCurrentSize();
            else UnlockFormSize();

            // Start local dashboard once, after the window is shown
            if (!_webUiStarted)
            {
                _webUiStarted = true;
                try { _ = CMDownloaderUI.WebUiHost.StartAsync(5088, "127.0.0.1"); } catch { }
                // [PW.STARTUP] init Playwright after WebUI is up so pwReady can become true
                try
                {
                    _ = System.Threading.Tasks.Task.Run(async () =>
                    {
                        await System.Threading.Tasks.Task.Delay(250).ConfigureAwait(false);
                        try { await SetupPlaywrightAsync(_edgeCts?.Token ?? CancellationToken.None).ConfigureAwait(false); }
                        catch (Exception ex) { try { Log("[PW] Setup failed (startup): " + ex.Message); } catch { } }
                    });
                }
                catch { }


                // let WebUI request a clean close of the app
                CMDownloaderUI.WebUiHost.OnExitRequested = () =>
                {
                    try
                    {
                        if (this.IsHandleCreated)
                            this.BeginInvoke(new System.Action(() => { try { this.Close(); } catch { } }));
                        else
                            this.Close();
                    }
                    catch { }
                };

                // open browser ONLY on normal launch (not after update)
                var args = Environment.GetCommandLineArgs();
                bool launchedFromUpdate = args.Any(a => string.Equals(a, "--updated", StringComparison.OrdinalIgnoreCase));

                var updatedFlag = Path.Combine(AppContext.BaseDirectory, "_updated.flag");
                if (!launchedFromUpdate && !File.Exists(updatedFlag))
                {
                    try
                    {
                        _ = Task.Run(async () =>
                        {
                            await Task.Delay(800);
                            try
                            {
                                Process.Start(new ProcessStartInfo
                                {
                                    FileName = "http://127.0.0.1:5088",
                                    UseShellExecute = true
                                });
                            }
                            catch { }
                        });
                    }
                    catch { }
                }
                else
                {
                    // consume flag so future launches behave normally
                    try { if (File.Exists(updatedFlag)) File.Delete(updatedFlag); } catch { }
                }




                try { _edge?.PublishHostsToWebUi(); } catch { }
                Log("[UPDATE] Update complete.");


            }
        }



        private void UnlockFormSize()
        {
            // replace the old minimum
            this.MinimumSize = new Size(780, 560);

            // optional: also start at that size
            this.Size = this.MinimumSize; // || new Size(782, 559)
            this.MaximumSize = Size.Empty; // removes the cap
            this.FormBorderStyle = FormBorderStyle.Sizable;
            this.MaximizeBox = true;
        }



        // Ensure EdgeSelector cleans up on form close
        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            try { _edge?.Stop(); } catch { }
            try { _edgeCts?.Cancel(); } catch { }
            try { _edgeCts?.Dispose(); } catch { }
            _edgeCts = null;

            try { _imgQ?.CompleteAdding(); _vidQ?.CompleteAdding(); } catch { }
            s_Draining = false;
            s_StopRequested = true;
            try { _cts?.Cancel(); } catch { }
            try { CleanStrayPartArtifacts(VideoRoot); } catch { }

            // make sure tray icon disappears on exit
            try
            {
                if (_trayIcon != null)
                {
                    _trayIcon.Visible = false;
                    _trayIcon.Dispose();
                    _trayIcon = null;
                }
            }
            catch { }

            base.OnFormClosing(e);
        }





        // Only rewrite to a known candidate host, and only when enqueueing
        private Uri MaybeRewriteMediaHost(Uri uri)
        {
            if (_edge == null) return uri;

            // Only rewrite when incoming host is one of our media hosts
            if (!MEDIA_HOST_CANDIDATES.Contains(uri.Host, StringComparer.OrdinalIgnoreCase))
                return uri;

            // Honor cooldown + stickiness before asking selector //
            if (!string.IsNullOrEmpty(_lastEdgeHost)
                && _edgeCooldown.TryGetValue(_lastEdgeHost, out var until)
                && until > DateTime.UtcNow)
            {
                return _edge.RewriteUriHost(uri, _lastEdgeHost); // stay on last good host
            }

            if (DateTime.UtcNow < _edgeStickUntil && !string.IsNullOrEmpty(_lastEdgeHost))
            {
                return _edge.RewriteUriHost(uri, _lastEdgeHost); // stick for 60s
            }

            var h = _edge.ResolveHostForNewDownload();
            EdgeLogIfMeaningful(h);
            return _edge.RewriteUriHost(uri, h);
        }

        // Draw banner across MaterialForm header band (uses transparent top in image)
        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            try
            {
                // Height of the Material header band that becomes the client top padding
                int headerH = this.Padding.Top;
                if (headerH <= 0) return;

                // Left/right margins inside client area
                int left = 12;
                int right = this.ClientSize.Width - 12;

                // If a MenuStrip sits inside the header band, stop the banner before it
                var ms = this.Controls.OfType<MenuStrip>().FirstOrDefault();
                if (ms != null)
                {
                    var p = this.PointToClient(ms.PointToScreen(Point.Empty));
                    if (p.Y < headerH)
                        right = Math.Max(left + 10, p.X - 12);
                }

                // keep banner clear of brand wordmark
                var brand = this.Controls["pnlBrand"] as Control;
                if (brand != null)
                {
                    var b = brand.Bounds; // already in Form client coords
                    if (b.Top < headerH && b.Bottom > 0) left = Math.Min(right - 10, Math.Max(left, b.Right + 8));
                }

                var dest = new Rectangle(left, 0, Math.Max(0, right - left), headerH);
                if (dest.Width <= 0) return;

                var g = e.Graphics;
                g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                g.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.HighQuality;




            }
            catch { /* never fail paint */ }
        }

        // Collect only links within a specific container and filter by extensions.
        private async Task<List<string>> CollectByExtensionsFromSelectorAsync(IPage page, string selector, IEnumerable<string> exts)
        {
            var extArr = exts?.ToArray() ?? Array.Empty<string>();

            // Collect href OR src for whatever selector you pass
            var urls = await page
                .Locator(selector)
                .EvaluateAllAsync<string[]>(
                    @"els => els
                .map(e => (e.href || e.getAttribute('href') || e.src || e.getAttribute('src') || ''))
                .filter(Boolean)"
                );

            return urls
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Where(u => HasAnySmartExtension(u, extArr))
                .Distinct()
                .ToList();
        }
        // === [IMG.HARVEST] container-time image candidate harvesting (raster only; no SVG) ===
        private static async Task<List<string>> HarvestBestImagesFromContainerAsync(IPage page, string containerSelector)
        {
            var best = await page.Locator(containerSelector).EvaluateAsync<string[]>(@"
(container) => {
  const abs = (u) => { try { return new URL(u, document.baseURI).toString(); } catch { return null; } };

 // Accept only raster images; allow coomer '/data/' originals even if query hides extension.
  const isRaster = (u) => /\.(?:jpe?g|png|webp|gif|avif)(?:[?#].*)?$/i.test(u) || (u && u.includes('/data/'));

 // normalize a url into a grouping key that ignores size tokens like 1080w/2048w
  const baseKey = (u) => {
    if (!u) return '';
    try {
      const url = new URL(u, document.baseURI);
      const p = url.pathname || '';
      const key = p
        .replace(/([_-])\d{3,5}x\d{3,5}(?=\.|$)/gi, '$1')
        .replace(/([_.-])\d{3,5}w(?=\.|$)/gi, '$1')
        .replace(/([?&])(width|w|h|height|quality|q)=\d+/gi, '$1')
        .replace(/(\?|&)$/,'');
      return key.toLowerCase();
    } catch { return u.toLowerCase(); }
  };

  const scoreOf = (u, hintedW) => {
    if (hintedW && +hintedW > 0) return +hintedW;
    const m = String(u).match(/(?:[=_-])(\d{3,5})w(?:[._-]|$)/i) || String(u).match(/(\d{3,5})x(\d{3,5})/);
    if (m) return m[2] ? Math.Max(+m[1], +m[2]) : +m[1];
    return 0;
  };

  const push = (map, url, hintedW) => {
    const a = abs(url);
    if (!a || !isRaster(a)) return; // <- drop non-raster (SVG, etc.)
    const k = baseKey(a);
    const s = scoreOf(a, hintedW);
    const prev = map.get(k);
    if (!prev || s > prev.score) map.set(k, { url: a, score: s });
  };

  const pickSrcset = (map, el) => {
    const ss = el.getAttribute('srcset') || '';
    ss.split(',').forEach(part => {
      const t = part.trim();
      if (!t) return;
      const m = t.match(/^(\S+)\s+(\d+)w$/i) || t.match(/^(\S+)\s+(\d+)x$/i);
      if (m) { if (isRaster(m[1])) push(map, m[1], +m[2]); }
      else {
        const maybeUrl = t.split(/\s+/)[0];
        if (isRaster(maybeUrl)) push(map, maybeUrl, 0);
      }
    });
  };

  const out = new Map();
  if (!container) return Array.from(out.values()).map(v => v.url);

 // <img>
  container.querySelectorAll('img').forEach(img => {
    if (img.src && isRaster(img.src)) push(out, img.src, 0);
    const ds = img.getAttribute('data-src'); if (ds && isRaster(ds)) push(out, ds, 0);
    if (img.hasAttribute('srcset')) pickSrcset(out, img);
  });

 // <picture><source> — skip SVG sources explicitly
  container.querySelectorAll('picture source[srcset]').forEach(src => {
    const t = (src.getAttribute('type') || '').toLowerCase();
    if (t.includes('svg')) return; // <- avoid image/svg+xml
    pickSrcset(out, src);
  });

 // <a href=...> direct images || coomer originals
  container.querySelectorAll('a[href]').forEach(a => {
    const href = a.getAttribute('href') || '';
    if (isRaster(href)) push(out, href, 0);
  });

  return Array.from(out.values()).sort((a,b) => b.score - a.score).map(v => v.url);
}
");

            // Final sanity filter on the C# side as well (defense in depth)
            var allow = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".jpg", ".jpeg", ".png", ".webp", ".gif", ".avif" };
            var list = new List<string>();
            foreach (var u in best ?? Array.Empty<string>())
            {
                try
                {
                    var path = new Uri(u).AbsolutePath;
                    var ext = System.IO.Path.GetExtension(path);
                    if (allow.Contains(ext) || u.IndexOf("/data/", StringComparison.OrdinalIgnoreCase) >= 0)
                        list.Add(u);
                }
                catch { /* ignore bad urls */ }
            }
            return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }


        private static bool HasAnySmartExtension(string url, string[] exts)
        {
            if (string.IsNullOrWhiteSpace(url) || exts.Length == 0) return false;

            // Drop fragment
            var hash = url.IndexOf('#');
            if (hash >= 0) url = url.Substring(0, hash);

            // Check path
            var q = url.IndexOf('?');
            var path = q >= 0 ? url.Substring(0, q) : url;
            if (exts.Any(e => path.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                return true;

            // Check common filename query params (?f=..., ?filename=..., ?name=...)
            if (q >= 0)
            {
                var query = url.Substring(q + 1);
                foreach (var kv in query.Split('&'))
                {
                    var parts = kv.Split('=', 2);
                    if (parts.Length != 2) continue;

                    var key = parts[0];
                    if (!key.Equals("f", StringComparison.OrdinalIgnoreCase) &&
                        !key.Equals("filename", StringComparison.OrdinalIgnoreCase) &&
                        !key.Equals("name", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var val = Uri.UnescapeDataString(parts[1]);
                    if (exts.Any(e => val.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                        return true;
                }
            }
            return false;
        }

        // Collect <video>/<source> srcs inside a container and filter by extensions.
        private async Task<List<string>> CollectVideoSourcesFromSelectorAsync(IPage page, string containerSelector, string[] exts)
        {
            var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string[] srcs;
            try
            {
                srcs = await page
                    .Locator($"{containerSelector} video, {containerSelector} source")
                    .EvaluateAllAsync<string[]>(
                        "els => els.map(e => e.currentSrc || e.src || e.getAttribute('src') || '').filter(Boolean)"
                    );
            }
            catch { srcs = Array.Empty<string>(); }

            foreach (var s in srcs)
            {
                // Fast media check without allocating lowercase strings
                bool mediaLike = exts.Any(e =>
                    s.EndsWith(e, StringComparison.OrdinalIgnoreCase) ||
                    s.Contains(e, StringComparison.OrdinalIgnoreCase));

                // Only do adblock work when it's actually on
                if (_adblockOn && _adblockRules.Count > 0)
                {
                    // Cheap path first (no allocations)
                    if (s.Contains("/ads/", StringComparison.OrdinalIgnoreCase) ||
                        s.Contains("/promo/", StringComparison.OrdinalIgnoreCase))
                        continue;

                    // Case-insensitive rule check WITHOUT lowercasing the URL
                    if (IsBlockedByAdblock(s)) // make IsBlockedByAdblock use OrdinalIgnoreCase internally
                        continue;
                }


                if (mediaLike)
                    urls.Add(s);
            }
            return urls.ToList();

        }



        // ===== Helpers injected by patch =====

        // helpers
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        private void NoteTransportFlake()
        {
            var now = DateTime.UtcNow;
            _simpleModeFlakes++;
            if (_simpleModeFlakes >= 6)
            {
                _simpleMode = true;
                _simpleModeUntil = now.AddMinutes(15);
                _simpleModeFlakes = 0;
                try { Log("[SIMPLE] on (15m) — too many transport flakes"); } catch { }
            }
        }

        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        private bool InSimpleMode()
        {
            if (!_simpleMode) return false;
            if (DateTime.UtcNow <= _simpleModeUntil) return true;
            _simpleMode = false;
            try { Log("[SIMPLE] off"); } catch { }
            return false;
        }

        private bool _didShownOnce = false;

        // helpers
        private void EdgeCooldown(string host, TimeSpan span)
        {
            if (string.IsNullOrEmpty(host)) return;
            _edgeCooldownUntil[host] = DateTime.UtcNow.Add(span);
        }

        private bool IsEdgeCooled(string host)
        {
            return !string.IsNullOrEmpty(host)
                && _edgeCooldownUntil.TryGetValue(host, out var until)
                && until > DateTime.UtcNow;
        }

        // ===== end helpers =====

        // === Edge score helpers ===
        private int GetHostScore(string host)
        {
            if (string.IsNullOrEmpty(host)) return 0;
            if (!_hostScore.TryGetValue(host, out var s)) s = 0;
            if (!_hostScoreAt.TryGetValue(host, out var t)) { _hostScoreAt[host] = System.DateTime.UtcNow; return s; }

            var elapsed = (int)(System.DateTime.UtcNow - t).TotalSeconds;
            if (elapsed >= SCORE_DECAY_SEC && s != 0)
            {
                var steps = System.Math.Max(1, elapsed / SCORE_DECAY_SEC);
                s = s > 0 ? System.Math.Max(0, s - steps) : System.Math.Min(0, s + steps);
                _hostScore[host] = s;
                _hostScoreAt[host] = System.DateTime.UtcNow;
            }
            return s;
        }

        private int BumpHostScore(string host, int delta)
        {
            if (string.IsNullOrEmpty(host)) return 0;
            var s = GetHostScore(host);
            s = System.Math.Max(SCORE_MIN, System.Math.Min(SCORE_MAX, s + delta));
            _hostScore[host] = s;
            _hostScoreAt[host] = System.DateTime.UtcNow;
            return s;
        }

        // check if a host is still cooling down; allow probe after ~60% elapsed
        private bool HostInCooldown(string host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            if (!_hostCooldown.TryGetValue(host, out var until)) return false;

            var now = System.DateTime.UtcNow;
            if (until <= now) return false;

            // allow probe when ≥60% of cooldown has elapsed
            var total = (until - now).TotalSeconds;
            var elapsed = COOLDOWN_SEC - total;
            if (elapsed >= COOLDOWN_SEC * 0.60) return false;

            return true; // still in cooldown
        }

        private void WebUiPublishCooldowns()
        {
            try
            {
                var activeHost = _edge?.ActiveHost;

                var hosts = GetMediaHostsSafe()
                    .Where(h => !string.IsNullOrWhiteSpace(h))
                    .Select(h => h.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Select(h =>
                    {
                        bool cooling = HostInCooldown(h);
                        return new CMDownloaderUI.HostHealth
                        {
                            name = h,
                            state = cooling ? "temp_banned" : "healthy",
                            stars = 3, // neutral; ES can overwrite
                            pinned = !cooling && !string.IsNullOrEmpty(activeHost) &&
                                       string.Equals(h, activeHost, StringComparison.OrdinalIgnoreCase),
                            cooldown = cooling,

                            // critical for the bar
                            active = CountActiveForHost(h),
                            limit = GetHostLimit(h),
                        };
                    })
                    .ToList();

                CMDownloaderUI.WebUiStatus.SetHosts(hosts);
                try
                {
                    _ = System.Threading.Tasks.Task.Run(async () =>
                    {
                        try
                        {
                            var e = _edge;
                            if (e != null)
                                await e.UiProbeOnceAsync(System.Threading.CancellationToken.None).ConfigureAwait(false);
                        }
                        catch { }
                    });
                }
                catch { }


            }
            catch { /* best-effort */ }
        }



        private void StartCooldown(string host, int seconds = COOLDOWN_SEC)
        {
            if (string.IsNullOrEmpty(host)) return;

            // If the cooling host is currently pinned, unpin immediately
            if (!string.IsNullOrEmpty(_pinnedRangeHost) &&
                string.Equals(_pinnedRangeHost, host, StringComparison.OrdinalIgnoreCase))
                _pinnedRangeHost = null;

            _hostCooldown[host] = System.DateTime.UtcNow.AddSeconds(seconds);

            // reflect per-host cooldowns in WebUI
            try { WebUiPublishCooldowns(); } catch { }
        }

        // === PartMap helpers (Stage 4) ===
        private static string PartMapPath(string finalPath) => finalPath + ".partmap";

        private static System.Collections.Generic.List<(long s, long e)> MergeRanges(System.Collections.Generic.IEnumerable<(long s, long e)> ranges)
        {
            var list = new System.Collections.Generic.List<(long s, long e)>(ranges);
            if (list.Count <= 1) return list;
            list.Sort((a, b) => a.s.CompareTo(b.s));
            var merged = new System.Collections.Generic.List<(long s, long e)>();
            long curS = list[0].s, curE = list[0].e;
            for (int i = 1; i < list.Count; i++)
            {
                var (s, e) = list[i];
                if (s <= curE + 1) { if (e > curE) curE = e; }
                else { merged.Add((curS, curE)); curS = s; curE = e; }
            }
            merged.Add((curS, curE));
            return merged;
        }

        private static System.Collections.Generic.List<(long s, long e)> SubtractRanges(
            System.Collections.Generic.IReadOnlyList<(long s, long e)> from,
            System.Collections.Generic.IReadOnlyList<(long s, long e)> subtract)
        {
            var result = new System.Collections.Generic.List<(long s, long e)>();
            int j = 0;
            var subs = MergeRanges(subtract);
            foreach (var (fs, fe) in from)
            {
                long s = fs, e = fe;
                while (j < subs.Count && subs[j].e < s) j++;
                long cur = s;
                int k = j;
                bool any = false;
                while (k < subs.Count && subs[k].s <= e)
                {
                    var cs = subs[k].s;
                    var ce = subs[k].e;
                    if (cs > cur) { result.Add((cur, System.Math.Min(e, cs - 1))); any = true; }
                    if (ce + 1 > cur) cur = ce + 1;
                    if (cur > e) break;
                    k++;
                }
                if (cur <= e) { result.Add((cur, e)); any = true; }
                if (!any) { /* fully covered by subtract; nothing to add */ }
            }
            return result;
        }

        private System.Collections.Generic.List<(long s, long e)> PartMapLoad(string finalPath)
        {
            var list = new System.Collections.Generic.List<(long s, long e)>();
            try
            {
                var fp = PartMapPath(finalPath);
                if (!System.IO.File.Exists(fp)) return list;
                foreach (var line in System.IO.File.ReadAllLines(fp))
                {
                    var t = line?.Trim();
                    if (string.IsNullOrEmpty(t)) continue;
                    var parts = t.Split('-', 2);
                    if (parts.Length != 2) continue;
                    if (long.TryParse(parts[0], out var s) && long.TryParse(parts[1], out var e) && s >= 0 && e >= s)
                        list.Add((s, e));
                }
            }
            catch { }
            return MergeRanges(list);
        }

        private void PartMapMarkCompleted(string finalPath, long s, long e)
        {
            if (s < 0 || e < s) return;
            var fp = PartMapPath(finalPath);
            var key = fp.ToLowerInvariant();
            object lockObj = _pmapLock.GetOrAdd(key, _ => new object());
            try
            {
                lock (lockObj)
                {
                    System.IO.File.AppendAllText(fp, $"{s}-{e}\n");
                }
            }
            catch { }
        }

        private void PartMapClear(string finalPath)
        {
            try
            {
                var fp = PartMapPath(finalPath);
                if (System.IO.File.Exists(fp)) System.IO.File.Delete(fp);
                var key = fp.ToLowerInvariant();
                _pmapLock.TryRemove(key, out _);
            }
            catch { }
        }







        // ======== MISSING HELPERS (auto-inserted) ========

        private static void EnsureIdentityIfRanged(System.Net.Http.HttpRequestMessage req)
        {
            try
            {
                if (req?.Headers?.Range != null)
                {
                    // Always avoid compression when doing Range reads
                    try { req.Headers.AcceptEncoding.Clear(); req.Headers.AcceptEncoding.ParseAdd("identity"); } catch { }

                    // Pin to HTTP/1.1 on older frameworks (use System.Version, not HttpVersion/VersionPolicy)
                    try { req.Version = new System.Version(1, 1); } catch { }
                }
            }
            catch { /* best-effort */ }
        }

        private static void PostAcceptCleanup(string finalPath)
        {
            try { var p = finalPath + ".part"; if (File.Exists(p)) File.Delete(p); } catch { }
            try { var m = finalPath + ".qmeta"; if (File.Exists(m)) File.Delete(m); } catch { }
        }



        private static void EnsureIdentity(System.Net.Http.HttpRequestMessage req)
        {
            try
            {
                if (req != null && req.Headers != null)
                {
                    req.Headers.AcceptEncoding.Clear();
                    req.Headers.AcceptEncoding.ParseAdd("identity");
                }
            }
            catch { }
        }

        private static System.Uri? SwapCoomerEdgeOnce(System.Uri u)
        {
            try
            {
                if (u == null || string.IsNullOrEmpty(u.Host)) return null;
                var host = u.Host;
                var parts = host.Split('.');
                if (parts.Length >= 3 && parts[0].Length >= 2 && parts[0][0] == 'n' && char.IsDigit(parts[0][1]) &&
                    parts[1].Equals("coomer", System.StringComparison.OrdinalIgnoreCase) &&
                    parts[2].Equals("st", System.StringComparison.OrdinalIgnoreCase))
                {
                    if (int.TryParse(parts[0].Substring(1), out int num))
                    {
                        int next = (num % 6) + 1;
                        var newHost = $"n{next}.coomer.st";
                        if (!newHost.Equals(host, System.StringComparison.OrdinalIgnoreCase))
                        {
                            var b = new System.UriBuilder(u) { Host = newHost };
                            return b.Uri;
                        }
                    }
                }
                return null;
            }
            catch { return null; }
        }

        private static async System.Threading.Tasks.Task<string> ComputeFileSha256Async(string path, System.Threading.CancellationToken ct)
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            await using var fs = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read,
                                                          bufferSize: 1 << 20, options: System.IO.FileOptions.SequentialScan);
            var buffer = new byte[1 << 20];
            int n;
            while ((n = await fs.ReadAsync(buffer.AsMemory(0, buffer.Length), ct)) > 0)
                sha.TransformBlock(buffer, 0, n, null, 0);
            sha.TransformFinalBlock(System.Array.Empty<byte>(), 0, 0);
            return System.Convert.ToHexString(sha.Hash!).ToLowerInvariant();
        }

        private static System.Uri? PickReferer(System.Uri target, string? explicitReferrer)
        {
            if (!string.IsNullOrWhiteSpace(explicitReferrer) &&
                System.Uri.TryCreate(explicitReferrer, System.UriKind.Absolute, out var r1))
                return r1;
            return PickReferer(target);
        }

        // ================== .OK FINALIZATION SYSTEM ==================
        private void FinalizeOkWrite(string finalPath)
        {
            try
            {
                long len = new FileInfo(finalPath).Length;
                long expected = (_qLen > 0 ? _qLen : -1);
                string h64 = _qHash64k ?? string.Empty;

                var okPath = finalPath + ".ok";
                TraceAnyWrite(okPath, -1, "SIDE.OK.FINAL.Helper");

                File.WriteAllText(okPath,
                    $"len={len};expected={expected};h64={h64};ts={DateTime.UtcNow:O}",
                    Encoding.UTF8);

            }
            catch { }
        }


        private bool ValidateOkMarker(string finalPath)
        {
            bool ok = false;
            try
            {
                string okp = finalPath + ".ok";
                if (File.Exists(okp))
                {
                    string s = File.ReadAllText(okp, Encoding.UTF8);
                    long len = -1, exp = -1;
                    foreach (var kv in s.Split(';'))
                    {
                        var p = kv.Split('=', 2);
                        if (p.Length != 2) continue;
                        if (p[0].Equals("len", StringComparison.OrdinalIgnoreCase)) long.TryParse(p[1], out len);
                        else if (p[0].Equals("expected", StringComparison.OrdinalIgnoreCase)) long.TryParse(p[1], out exp);
                    }
                    long actual = new FileInfo(finalPath).Length;
                    if (len == actual)
                    {
                        if (exp > 0)
                        {
                            long floor = Math.Max((long)(exp * 0.99), exp - 64 * 1024);
                            ok = (actual >= floor);
                        }
                        else ok = true;
                    }
                }
            }
            catch { ok = false; }
            return ok;
        }

        private void DeleteOkMarker(string finalPath)
        {
            try { File.Delete(finalPath + ".ok"); } catch { }
        }

        private int SweepMissingOk(string root)
        {
            int n = 0;
            try
            {
                if (!Directory.Exists(root)) return 0;
                foreach (var f in Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories))
                {
                    if (string.Equals(Path.GetExtension(f), ".ok", StringComparison.OrdinalIgnoreCase)) continue;
                    if (!File.Exists(f + ".ok"))
                    {
                        try { Log($"[SWEEP] missing .ok → {f}"); } catch { }
                        n++;
                    }
                }
            }
            catch { }
            return n;
        }

        // automatically run sweep at the end of cleanup
        private void RunEndCleanup()
        {
            try
            {
                SweepEmptySetFolders();
                SweepQuarantineMeta();

                try { SweepMissingOk(VideoRoot); } catch { }
                try { SweepMissingOk(ImagesRoot); } catch { }
                try { SweepOrphanOk(VideoRoot); } catch { } // ← add
                try { SweepOrphanOk(ImagesRoot); } catch { } // ← add
            }
            catch { }
        }


    }

    // ======== /MISSING HELPERS =============================================
} // closes class MainForm

