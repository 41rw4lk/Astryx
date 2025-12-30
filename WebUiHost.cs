// Astryx DL — WebUiHost
// Minimal Kestrel host + SSE logs + debounced Recent for the Astryx Web UI.
// Public-clean version: patch tags removed for sharing.

// (c) Astryx project. See repository LICENSE for terms.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Channels;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace CMDownloaderUI;

public static class WebUiHost
{
    // track live UI clients (SSE) and stop when zero for a bit
    static int _uiClients = 0;
    static int _logClearOnce = 0;
    // last worker tuners pushed from WebUI (used to reflect live values back to /api/status)
    static int _nvLastFromWebUi = 0;
    static int _vidLastFromWebUi = 0;
    static int _updBusy = 0;
    static volatile string _updMsg = "";
    static volatile int _updPct = 0;

    static CancellationTokenSource? _uiZeroCts;
    const int UI_ZERO_GRACE_MS = 3_000;
    // last WebUI ping (UTC)
    static System.DateTime _lastPingUtc = System.DateTime.MinValue;
    public static System.DateTime LastPingUtc => _lastPingUtc;

    static void MaybeScheduleUiZeroBackstop(int port = 5088)
    {
        // schedule only if currently zero
        if (System.Threading.Interlocked.CompareExchange(ref _uiClients, 0, 0) != 0) return;

        try { _uiZeroCts?.Cancel(); } catch { }
        var cts = _uiZeroCts = new System.Threading.CancellationTokenSource();

        _ = System.Threading.Tasks.Task.Run(async () =>
        {
            try
            {
                // wait a bit to distinguish refresh (reconnect) from real close
                await System.Threading.Tasks.Task.Delay(UI_ZERO_GRACE_MS, cts.Token);

                // if still zero UI clients after the grace period, kill the app
                if (System.Threading.Interlocked.CompareExchange(ref _uiClients, 0, 0) == 0)
                {
                    try { OnExitRequested?.Invoke(); } catch { }
                }
            }
            catch (System.OperationCanceledException)
            {
                // canceled because a new UI client connected; ignore
            }
            catch
            {
                // ignore any other backstop errors
            }
        }, cts.Token);
    }


    // callback assigned by MainForm so the WebUI can close the app
    public static System.Action? OnExitRequested;

    private static WebApplication? _app;
    // soft pause state driven by WebUI
    static volatile bool _pausedUi = false;

    // ======================
    // RECENT (single source)
    // ======================
    // debounced, verified list (name+path)
    static readonly object _recentLock = new();
    static readonly List<(string name, string path)> _recent = new(16);
    // current item byte progress
    static readonly object _tpLock = new();
    static long _tpBytes = 0, _tpTotal = 0;
    public static void SetCurrentProgress(long bytes, long total)
    {
        lock (_tpLock) { _tpBytes = bytes; _tpTotal = total; }
    }


    // wait a bit, then only add real, non-quarantine files
    public static void PushRecent(string path, int delayMs = 1200)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        _ = System.Threading.Tasks.Task.Run(async () =>
        {
            try
            {
                await System.Threading.Tasks.Task.Delay(Math.Max(0, delayMs));
                if (!System.IO.File.Exists(path)) return;

                var fi = new System.IO.FileInfo(path);
                if (fi.Length <= 16384) return; // skip tiny/truncated
                if (path.IndexOf("_quarantine", StringComparison.OrdinalIgnoreCase) >= 0) return;

                var name = System.IO.Path.GetFileName(path);

                lock (_recentLock)
                {
                    // de-dup by path, newest wins
                    for (int i = _recent.Count - 1; i >= 0; i--)
                        if (string.Equals(_recent[i].path, path, StringComparison.OrdinalIgnoreCase))
                            _recent.RemoveAt(i);

                    _recent.Insert(0, (name, path));
                    if (_recent.Count > 12) _recent.RemoveAt(_recent.Count - 1);
                }
            }
            catch { }
        });
    }

    // ---- compatibility shims for legacy callers (no __recent* anywhere) ----
    public static string[] GetRecent(int n = 12)
    {
        lock (_recentLock)
            return _recent.Take(Math.Clamp(n, 1, 100))
                          .Select(r => r.path)
                          .ToArray();
    }
    public static void AddRecent(string path) => PushRecent(path, 1200);

    public static async Task StartAsync(int port, string host)
    {
        if (_app != null)
        {
            try { CMDownloaderUI.LogTap.Append("[WEB] already running"); } catch { }
            return;
        }

        var builder = WebApplication.CreateBuilder();

        // bind explicitly; ignores launch profiles/env
        builder.WebHost.ConfigureKestrel(o =>
        {
            o.ListenLocalhost(port); // 127.0.0.1:<port>
                                     // If you also want IPv6 loopback: o.Listen(System.Net.IPAddress.IPv6Loopback, port);
        });

        var app = builder.Build();
        _app = app;
        app.Lifetime.ApplicationStarted.Register(() =>
        {
            try { CMDownloaderUI.LogTap.Append($"[WEB] listening 127.0.0.1:{port}"); } catch { }
        });

        // quick ping
        app.MapGet("/api/ping", () => Results.Text("pong"));

        // /api/update/check?cur=v0.1.1
        app.MapGet("/api/update/check", async (HttpRequest req) =>
        {
            string cur = (req.Query["cur"].ToString() ?? "").Trim();

            try
            {
                using var hc = new System.Net.Http.HttpClient();
                hc.DefaultRequestHeaders.UserAgent.ParseAdd("Astryx-Updater");

                // GitHub API: latest release
                var json = await hc.GetStringAsync("https://api.github.com/repos/41rw4lk/Astryx/releases/latest").ConfigureAwait(false);

                using var doc = System.Text.Json.JsonDocument.Parse(json);
                var root = doc.RootElement;

                var tag = root.TryGetProperty("tag_name", out var t) ? (t.GetString() ?? "") : "";
                string assetUrl = "";

                if (root.TryGetProperty("assets", out var assets) && assets.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    foreach (var a in assets.EnumerateArray())
                    {
                        var name = a.TryGetProperty("name", out var n) ? (n.GetString() ?? "") : "";
                        if (!name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) continue;

                        assetUrl = a.TryGetProperty("browser_download_url", out var u) ? (u.GetString() ?? "") : "";
                        break;
                    }
                }

                bool has = !string.IsNullOrWhiteSpace(tag) && !string.Equals(tag, cur, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(assetUrl);

                return Results.Json(new { ok = true, current = cur, latest = tag, hasUpdate = has, assetUrl });
            }
            catch (Exception ex)
            {
                return Results.Json(new { ok = false, message = ex.Message, hasUpdate = false }, statusCode: 500);
            }
        });

        app.MapGet("/api/update/status", () =>
        {
            return Results.Json(new { ok = true, busy = (_updBusy != 0), pct = _updPct, message = _updMsg });
        });

        // POST { assetUrl: "..." }
        app.MapPost("/api/update/apply", async (HttpRequest req) =>
        {
            if (System.Threading.Interlocked.Exchange(ref _updBusy, 1) != 0)
                return Results.Json(new { ok = false, message = "busy" }, statusCode: 409);

            _updMsg = "Starting…";
            _updPct = 0;
            CMDownloaderUI.LogTap.Append("[UPDATE] Updating application…");



            try
            {
                using var sr = new System.IO.StreamReader(req.Body);
                var body = await sr.ReadToEndAsync().ConfigureAwait(false);

                string assetUrl = "";
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(body);
                    assetUrl = doc.RootElement.TryGetProperty("assetUrl", out var u) ? (u.GetString() ?? "") : "";
                }
                catch { }

                if (string.IsNullOrWhiteSpace(assetUrl))
                    return Results.Json(new { ok = false, message = "missing assetUrl" }, statusCode: 400);

                var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? "";
                var appDirRaw = System.AppContext.BaseDirectory;
                var appDir = Path.TrimEndingDirectorySeparator(appDirRaw);


                var tmpDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "AstryxUpdate_" + Guid.NewGuid().ToString("N"));
                System.IO.Directory.CreateDirectory(tmpDir);

                var zipPath = System.IO.Path.Combine(tmpDir, "update.zip");
                var extractDir = System.IO.Path.Combine(tmpDir, "unz");

                _updMsg = "Downloading…";
                _updPct = 5;

                using (var hc = new System.Net.Http.HttpClient())
                {
                    hc.DefaultRequestHeaders.UserAgent.ParseAdd("Astryx-Updater");
                    var bytes = await hc.GetByteArrayAsync(assetUrl).ConfigureAwait(false);
                    await System.IO.File.WriteAllBytesAsync(zipPath, bytes).ConfigureAwait(false);
                }

                _updMsg = "Extracting…";
                _updPct = 25;

                System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, extractDir, overwriteFiles: true);

                _updMsg = "Staging…";
                _updPct = 45;

                // Spawn dedicated updater exe so we can overwrite Astryx.exe safely
                int parentPid = System.Diagnostics.Process.GetCurrentProcess().Id;

                string updaterPath = System.IO.Path.Combine(appDir, "Astryx.Updater.exe");

                try
                {
                    System.IO.File.WriteAllText(
                        System.IO.Path.Combine(appDir, "_wuh_update_spawn.txt"),
                        DateTime.Now.ToString("s") + "\r\n" +
                        updaterPath + "\r\n" +
                        extractDir + "\r\n" +
                        appDir + "\r\n" +
                        "Astryx.exe" + "\r\n" +
                        parentPid + "\r\n"
                    );
                }
                catch { }

                try
                {
                    // ArgumentList avoids all quoting/trailing-slash issues (no args string)
                    var psi2 = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = updaterPath,
                        WorkingDirectory = appDir,
                        UseShellExecute = true
                    };
                    psi2.ArgumentList.Add(extractDir);
                    psi2.ArgumentList.Add(appDir);
                    psi2.ArgumentList.Add("Astryx.exe");
                    psi2.ArgumentList.Add(parentPid.ToString());

                    System.Diagnostics.Process.Start(psi2);
                }
                catch (Exception ex)
                {
                    _updMsg = "Failed: " + ex.Message;
                    _updPct = 0;
                    return Results.Json(new { ok = false, message = _updMsg }, statusCode: 500);
                }


                _updMsg = "Restarting…";
                _updPct = 90;
                CMDownloaderUI.LogTap.Append("[UPDATE] Restarting…");
                CMDownloaderUI.LogTap.Append("[WEBUI] UPDATE_RESTART");


                File.WriteAllText(Path.Combine(Path.GetDirectoryName(exePath) ?? appDir, "_updated.flag"), "1");

                // exit on a tiny delay so HTTP response can return
                _ = System.Threading.Tasks.Task.Run(async () =>
                {
                    try { await System.Threading.Tasks.Task.Delay(350).ConfigureAwait(false); } catch { }
                    try { System.Environment.Exit(0); } catch { }
                });




                return Results.Json(new { ok = true });
            }
            catch (Exception ex)
            {
                _updMsg = "Failed: " + ex.Message;
                _updPct = 0;
                return Results.Json(new { ok = false, message = ex.Message }, statusCode: 500);
            }
            finally
            {
                System.Threading.Interlocked.Exchange(ref _updBusy, 0);
            }
        });

        // serve favicon.png from wwwroot if present
        app.MapGet("/favicon.ico", (Microsoft.AspNetCore.Hosting.IWebHostEnvironment env) =>
        {
            try
            {
                var webroot = env.WebRootPath ?? AppContext.BaseDirectory;
                var path = System.IO.Path.Combine(webroot, "favicon.png");
                if (System.IO.File.Exists(path)) return Results.File(path, "image/png");
            }
            catch { }
            return Results.StatusCode(204);
        });

        // Optional API key (for secured control endpoints)
        var controlKey = Environment.GetEnvironmentVariable("ASTROFETCH_API_KEY");
        static bool CheckKey(HttpRequest req, string? expected)
        {
            if (string.IsNullOrEmpty(expected)) return true; // no auth required
            if (req.Headers.TryGetValue("X-Api-Key", out var got) && got == expected) return true;
            return req.Cookies.TryGetValue("AFK", out var ck) && ck == expected; // cookie auth
        }

        // Set AFK cookie for convenience
        app.Use(async (ctx, next) =>
        {
            if (!string.IsNullOrEmpty(controlKey) && !ctx.Request.Cookies.ContainsKey("AFK"))
                ctx.Response.Cookies.Append("AFK", controlKey, new CookieOptions
                {
                    HttpOnly = true,
                    SameSite = SameSiteMode.Strict,
                    Secure = false,
                    IsEssential = true
                });
            await next();
        });

        // ---- Static files (wwwroot with index.html) ----
        var root = Path.Combine(AppContext.BaseDirectory, "wwwroot");
        if (!Directory.Exists(root)) Directory.CreateDirectory(root);

        var fp = new PhysicalFileProvider(root);

        app.UseDefaultFiles(new DefaultFilesOptions
        {
            DefaultFileNames = new List<string> { "index.html" },
            FileProvider = fp
        });

        app.UseStaticFiles(new StaticFileOptions
        {
            FileProvider = fp,
            ServeUnknownFileTypes = true,
            OnPrepareResponse = ctx =>
            {
                ctx.Context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
                ctx.Context.Response.Headers["Pragma"] = "no-cache";
                ctx.Context.Response.Headers["Expires"] = "0";
            }
        });


        // ---- SSE ping probe ----
        app.MapGet("/api/log/stream/ping", async (HttpContext ctx) =>
        {
            ctx.Response.Headers["Cache-Control"] = "no-cache";
            ctx.Response.Headers["X-Accel-Buffering"] = "no";
            ctx.Response.Headers["Connection"] = "keep-alive";
            ctx.Response.ContentType = "text/event-stream";
            await ctx.Response.WriteAsync("data: hello\n\n", ctx.RequestAborted);
            await ctx.Response.WriteAsync("data: world\n\n", ctx.RequestAborted);
            await ctx.Response.Body.FlushAsync(ctx.RequestAborted);
            try { await Task.Delay(1500, ctx.RequestAborted); } catch { }
        });

        // ---- SSE LOG STREAM (single mapping) ----
        app.MapGet("/api/log/stream", async (HttpContext ctx) =>
        {
            // a UI client connected
            var nowClients = System.Threading.Interlocked.Increment(ref _uiClients);
            var isFirst = (nowClients == 1);

            try { _uiZeroCts?.Cancel(); } catch { } // cancel any scheduled backstop

            // fire autologin exactly once when the first UI connects
            if (isFirst)
            {
                try { CMDownloaderUI.LogTap.Append("[AUTOLOGIN] SSE connect (first client)"); } catch { }

                try
                {
                    var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                    if (f == null)
                    {
                        try { CMDownloaderUI.LogTap.Append("[AUTOLOGIN] MainFormInstance is null"); } catch { }
                    }
                    else
                    {
                        try { _ = f.Handle; } catch { } // ensure handle exists
                        f.BeginInvoke(new Action(() =>
                        {
                            try { CMDownloaderUI.LogTap.Append("[AUTOLOGIN] invoking TryAutoLoginFromWebUi()"); } catch { }
                            try { f.TryAutoLoginFromWebUi(); }
                            catch (Exception ex)
                            {
                                try { CMDownloaderUI.LogTap.Append("[AUTOLOGIN] TryAutoLoginFromWebUi threw: " + ex.Message); } catch { }
                            }
                        }));
                    }
                }
                catch (Exception ex)
                {
                    try { CMDownloaderUI.LogTap.Append("[AUTOLOGIN] bridge failed: " + ex.Message); } catch { }
                }
            }

            ctx.Response.Headers["Cache-Control"] = "no-cache";
            ctx.Response.Headers["X-Accel-Buffering"] = "no";
            ctx.Response.Headers["Connection"] = "keep-alive";
            ctx.Response.ContentType = "text/event-stream";

            // fire disconnect hook (decrement + maybe schedule backstop)
            ctx.Response.OnCompleted(() =>
            {
                System.Threading.Interlocked.Decrement(ref _uiClients);
                MaybeScheduleUiZeroBackstop(port: port);
                return System.Threading.Tasks.Task.CompletedTask;
            });

            await ctx.Response.Body.FlushAsync(ctx.RequestAborted);

            static async System.Threading.Tasks.Task Write(HttpResponse resp, string? msg, System.Threading.CancellationToken ct)
            {
                await resp.WriteAsync("data: " + (msg ?? string.Empty) + "\n\n", ct);
                await resp.Body.FlushAsync(ct);
            }

            // Live stream
            ChannelReader<string> reader = CMDownloaderUI.LogTap.Subscribe(out var chan);
            try
            {
                await foreach (var line in reader.ReadAllAsync(ctx.RequestAborted))
                    await Write(ctx.Response, line, ctx.RequestAborted);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                try { await Write(ctx.Response, "[SSE.ERROR] " + ex.Message, System.Threading.CancellationToken.None); } catch { }
                try { CMDownloaderUI.LogTap.Append("[SSE.ERROR] " + ex); } catch { }
            }
            finally
            {
                try { CMDownloaderUI.LogTap.Unsubscribe(chan); } catch { }
                // NOTE: no decrement here; OnCompleted handles it reliably.
            }
        });


        // /api/log/tail — initial fill for the log box
        app.MapGet("/api/log/tail", (int? limit) =>
        {
            // If a UI asked to clear logs, the very next tail call returns empty once.
            if (System.Threading.Interlocked.Exchange(ref _logClearOnce, 0) == 1)
            {
                var empty = Array.Empty<string>();
                return Results.Json(new { lines = empty, items = empty });
            }

            var n = Math.Clamp(limit ?? 200, 1, 1000);
            var lines = CMDownloaderUI.LogTap.Tail(n) ?? Array.Empty<string>();
            return Results.Json(new { lines, items = lines });
        });

        // /api/log/clear — clear initial log fill for next UI reload
        app.MapPost("/api/log/clear", () =>
        {
            System.Threading.Interlocked.Exchange(ref _logClearOnce, 1);
            return Results.Ok(new { ok = true });
        });


        app.MapGet("/api/hosts", () =>
        {
            var s = CMDownloaderUI.WebUiStatus.Snapshot();
            return Results.Json(s.hosts ?? new List<CMDownloaderUI.HostHealth>());
        });

        // hardened payload (no early return) + curBytes/curTotal included
        app.MapGet("/api/status", () =>
        {
            try
            {
                var s = CMDownloaderUI.WebUiStatus.Snapshot(); // StatusDto

                // ---- HOSTS (flattened for UI) ----
                var __hostsUi = (s.hosts ?? new List<CMDownloaderUI.HostHealth>())
                    .Select(h => new
                    {
                        name = h.name,
                        stars = Math.Clamp(h.stars, 0, 5),
                        status = h.state,
                        pinned = (s.running && h.pinned),
                        cooldown = h.cooldown,
                        p50_ms = h.p50_ms,
                        p95_ms = h.p95_ms,
                        active = h.active,
                        limit = h.limit
                    })
                    .ToArray();

                // ---- DISK % (safe default = app drive) ----
                string rootPath = Path.GetPathRoot(AppContext.BaseDirectory) ?? AppContext.BaseDirectory;
                int diskPct = 0;
                try
                {
                    var di = new DriveInfo(rootPath);
                    if (di.TotalSize > 0)
                        diskPct = (int)Math.Round(100.0 * (di.TotalSize - di.AvailableFreeSpace) / di.TotalSize);
                }
                catch { }

                // ---- RUNTIME / THREADS / ERRORS (resilient) ----
                string runtime = "00:00:00";
                try
                {
                    var pr = s.GetType().GetProperty("runtime");
                    if (pr != null) runtime = (string?)pr.GetValue(s) ?? "00:00:00";
                }
                catch { }

                int threads = 0;
                try { threads = System.Diagnostics.Process.GetCurrentProcess().Threads.Count; } catch { }

                int errors = 0;
                try
                {
                    var pe = s.GetType().GetProperty("errors");
                    if (pe != null) errors = Convert.ToInt32(pe.GetValue(s) ?? 0);
                }
                catch { }

                // ---- Throughput bytes (used by the bar fallback) ----
                long tpB = 0, tpT = 0;
                lock (_tpLock) { tpB = _tpBytes; tpT = _tpTotal; }

                // ---- CURRENT SNAPSHOT ----
                var cur = CMDownloaderUI.WebUiStatus.GetCurrentSnapshot(); // { name, pct, done, size, eta, host }

                // ---- Worker limits (NV / VID) ----
                int nvWorkers = 0, vidWorkers = 0;

                // 1) Try to read from StatusDto (if it exposes limits)
                try
                {
                    var pNv = s.GetType().GetProperty("nvWorkers")
                          ?? s.GetType().GetProperty("nv_workers")
                          ?? s.GetType().GetProperty("nvLimit");
                    if (pNv != null) nvWorkers = Convert.ToInt32(pNv.GetValue(s) ?? 0);
                }
                catch { }

                try
                {
                    var pV = s.GetType().GetProperty("vidWorkers")
                         ?? s.GetType().GetProperty("vid_workers")
                         ?? s.GetType().GetProperty("vidLimit");
                    if (pV != null) vidWorkers = Convert.ToInt32(pV.GetValue(s) ?? 0);
                }
                catch { }

                // 2) Fallback to MainForm (matches /api/config behavior)
                if (nvWorkers <= 0 || vidWorkers <= 0)
                {
                    try
                    {
                        var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                        if (f != null)
                        {
                            if (nvWorkers <= 0)
                            {
                                var miNv = f.GetType().GetMethod(
                                    "GetNonVideoWorkerLimit",
                                    System.Reflection.BindingFlags.Instance |
                                    System.Reflection.BindingFlags.Public |
                                    System.Reflection.BindingFlags.NonPublic);

                                if (miNv != null)
                                    nvWorkers = Convert.ToInt32(miNv.Invoke(f, null) ?? 0);
                            }

                            if (vidWorkers <= 0)
                            {
                                var miVid = f.GetType().GetMethod(
                                    "GetVideoWorkerLimit",
                                    System.Reflection.BindingFlags.Instance |
                                    System.Reflection.BindingFlags.Public |
                                    System.Reflection.BindingFlags.NonPublic);

                                if (miVid != null)
                                    vidWorkers = Convert.ToInt32(miVid.Invoke(f, null) ?? 0);
                            }
                        }
                    }
                    catch { }
                }
                // 3) If WebUI has explicitly set tuners, prefer those over stale presets
                if (_nvLastFromWebUi > 0) nvWorkers = _nvLastFromWebUi;
                if (_vidLastFromWebUi > 0) vidWorkers = _vidLastFromWebUi;

                // derive runState from StatusDto, fallback to idle when unknown
                var runState = "Idle";

                try
                {
                    var ps = s.GetType().GetProperty("runState")
                          ?? s.GetType().GetProperty("run_state")
                          ?? s.GetType().GetProperty("state");
                    if (ps != null)
                    {
                        var val = ps.GetValue(s) as string;
                        if (!string.IsNullOrWhiteSpace(val))
                            runState = val;
                    }
                }
                catch { }

                // ---- LOGIN STATE (blink gear when not logged in) ----
                bool needLogin = true;
                bool coomerRemember = false;
                bool pwInstalling = false;
                bool pwReady = false;


                try
                {
                    var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                    if (f != null)
                    {
                        // needLogin
                        var mi = f.GetType().GetMethod("CoomerHasSession",
                            System.Reflection.BindingFlags.Instance |
                            System.Reflection.BindingFlags.Public |
                            System.Reflection.BindingFlags.NonPublic);

                        if (mi != null)
                        {
                            var has = mi.Invoke(f, null);
                            if (has is bool b) needLogin = !b;
                        }

                        // coomerRemember
                        var miR = f.GetType().GetMethod("GetCoomerRememberFlag",
                            System.Reflection.BindingFlags.Instance |
                            System.Reflection.BindingFlags.Public |
                            System.Reflection.BindingFlags.NonPublic);


                        if (miR != null)
                        {
                            var r = miR.Invoke(f, null);
                            if (r is bool rb) coomerRemember = rb;
                            else coomerRemember = Convert.ToBoolean(r ?? false);
                        }

                        // pwInstalling (Playwright first-run install in progress)
                        try
                        {
                            var fi = f.GetType().GetField("_pwInstalling",
                                System.Reflection.BindingFlags.Instance |
                                System.Reflection.BindingFlags.NonPublic);
                            if (fi != null)
                            {
                                var v = fi.GetValue(f);
                                if (v is bool bb) pwInstalling = bb;
                            }
                        }
                        catch { }

                        // pwReady (Playwright fully initialized: browser+context+page ready)
                        try
                        {
                            var fiR = f.GetType().GetField("_pwFullyReady",
                                System.Reflection.BindingFlags.Instance |
                                System.Reflection.BindingFlags.NonPublic);
                            if (fiR != null)
                            {
                                var v = fiR.GetValue(f);
                                if (v is bool bb) pwReady = bb;
                            }
                        }
                        catch { }

                    }
                }
                catch { needLogin = true; coomerRemember = false; pwInstalling = false; }

                // ---- ACTIVE (inflight) + RETRIES (retry backlog) ----
                int nvActive = 0, vidActive = 0, retries = 0;
                try
                {
                    var f2 = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                    if (f2 != null)
                    {
                        var bf = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;

                        // inflight actives
                        var fiNv = f2.GetType().GetField("_inflightNV", bf);
                        if (fiNv != null) nvActive = Convert.ToInt32(fiNv.GetValue(f2) ?? 0);

                        var fiVid = f2.GetType().GetField("_inflightVID", bf);
                        if (fiVid != null) vidActive = Convert.ToInt32(fiVid.GetValue(f2) ?? 0);

                        // retry backlog queue count
                        var fiRq = f2.GetType().GetField("_retryQ", bf) ?? f2.GetType().GetField("_retryQueue", bf);
                        var rq = fiRq?.GetValue(f2);
                        if (rq != null)
                        {
                            var pCount = rq.GetType().GetProperty("Count");
                            if (pCount != null) retries = Convert.ToInt32(pCount.GetValue(rq) ?? 0);
                        }
                    }
                }
                catch { }

                var payload = new
                {
                    state = _pausedUi ? "Paused" : runState,
                    paused = _pausedUi,
                    needLogin = needLogin,
                    coomerRemember = coomerRemember,
                    pwInstalling = pwInstalling,
                    pwReady = pwReady,
                    version = s.version ?? "dev",

                    // Speeds:
                    // - speedBps / speedRolling → "Now" (short-window bps → Mbps)
                    // - speedAvg → "Avg" (session-wide Mbps from StatusDto)
                    speedBps = (long)Math.Max(0, s.speed_bps),
                    speedAvg = Math.Round(s.speed_avg_mbps, 2),
                    speedRolling = Math.Round((s.speed_bps * 8.0) / 1_000_000.0, 2),


                    diskPct = diskPct,

                    // Status-row counters
                    runtime = runtime,
                    threads = threads,
                    errors = errors,
                    nvWorkers = nvWorkers,
                    vidWorkers = vidWorkers,
                    nvActive = nvActive,
                    vidActive = vidActive,


                    // Totals
                    imagesOk = 0,
                    videosOk = 0,
                    bytesFetched = s.bytes_downloaded,
                    bytesSaved = 0L,

                    // Overall
                    queue = s.queue,
                    completed = s.completed,
                    total = s.total,
                    overallPct = s.overallPct,

                    // NEW: expose raw current progress for the UI’s bar fallback
                    curBytes = tpB,
                    curTotal = tpT,

                    // Current item (nullable)
                    current = string.IsNullOrWhiteSpace(cur.name) ? null : new
                    {
                        name = cur.name,
                        pct = Math.Clamp((int)Math.Round(cur.pct), 0, 100),
                        done = cur.done, // bytes
                        size = cur.size, // bytes
                        eta = cur.eta,
                        host = cur.host
                    },

                    // Lists
                    recent = Array.Empty<string>(),
                    hosts = __hostsUi,

                    pinnedHost = s.running ? (__hostsUi.FirstOrDefault(h => h.pinned)?.name ?? "") : "",
                    retries = retries

                };

                return Results.Json(payload, new System.Text.Json.JsonSerializerOptions
                {
                    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
                    PropertyNamingPolicy = null
                });
            }
            catch (Exception ex)
            {
                try { CMDownloaderUI.LogTap.Append("[API.STATUS] FALLBACK: " + ex.GetType().Name + " :: " + ex.Message); } catch { }

                // Minimal, safe fallback — never 500
                return Results.Json(new
                {
                    state = "Idle",
                    version = "dev",
                    speedBps = 0L,
                    speedAvg = 0.0,
                    speedRolling = 0.0,
                    diskPct = 0,
                    runtime = "00:00:00",
                    threads = 0,
                    errors = 0,
                    nvWorkers = 0,
                    vidWorkers = 0,
                    nvActive = 0,
                    vidActive = 0,
                    retries = 0,
                    imagesOk = 0,
                    videosOk = 0,
                    bytesFetched = 0L,
                    bytesSaved = 0L,
                    queue = 0,
                    completed = 0,
                    total = 0,
                    overallPct = 0,
                    current = (object?)null,
                    recent = Array.Empty<object>(),
                    hosts = Array.Empty<object>(),
                    pinnedHost = "",
                    curBytes = 0L,
                    curTotal = 0L,
                    needLogin = true

                });
            }
        });

        // /api/coomer/login — WebUI gear login (generic user/pass)
        // NOTE: WebUI will not blink-stop until MainForm actually stores a session/cookies.
        app.MapPost("/api/coomer/login", async (HttpRequest req) =>
        {
            if (!CheckKey(req, controlKey)) return Results.Unauthorized();

            try
            {
                var root = await req.ReadFromJsonAsync<System.Text.Json.JsonElement>();

                string user = "";
                string pass = "";
                bool remember = false;

                try { if (root.ValueKind == System.Text.Json.JsonValueKind.Object && root.TryGetProperty("user", out var u)) user = (u.GetString() ?? ""); } catch { }
                try { if (root.ValueKind == System.Text.Json.JsonValueKind.Object && root.TryGetProperty("pass", out var p)) pass = (p.GetString() ?? ""); } catch { }

                // allow either boolean true/false OR string "1"/"true"
                try
                {
                    if (root.ValueKind == System.Text.Json.JsonValueKind.Object && root.TryGetProperty("remember", out var r))
                    {
                        if (r.ValueKind == System.Text.Json.JsonValueKind.True) remember = true;
                        else if (r.ValueKind == System.Text.Json.JsonValueKind.False) remember = false;
                        else if (r.ValueKind == System.Text.Json.JsonValueKind.String)
                        {
                            var s = (r.GetString() ?? "");
                            remember = (s == "1") || s.Equals("true", StringComparison.OrdinalIgnoreCase) || s.Equals("yes", StringComparison.OrdinalIgnoreCase);
                        }
                        else if (r.ValueKind == System.Text.Json.JsonValueKind.Number)
                        {
                            try { remember = r.GetInt32() != 0; } catch { }
                        }
                    }
                }
                catch { }


                if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(pass))
                    return Results.Json(new { ok = false, message = "Missing user/pass" }, statusCode: 400);

                var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                if (f == null)
                    return Results.Json(new { ok = false, message = "MainForm not available" }, statusCode: 409);
                // [COOMER.REMEMBER] tell MainForm whether to persist creds (DPAPI → ui.ini)
                try
                {
                    var miRemember = f.GetType().GetMethod("SetCoomerRememberFromWebUi",
                        System.Reflection.BindingFlags.Instance |
                        System.Reflection.BindingFlags.Public |
                        System.Reflection.BindingFlags.NonPublic);

                    miRemember?.Invoke(f, new object[] { user, pass, remember });
                }
                catch { }

                var mi = f.GetType().GetMethod("CoomerLoginAsync",
                    System.Reflection.BindingFlags.Instance |
                    System.Reflection.BindingFlags.Public |
                    System.Reflection.BindingFlags.NonPublic);

                if (mi == null)
                    return Results.Json(new { ok = false, message = "CoomerLoginAsync missing in MainForm" }, statusCode: 500);

                var obj = mi.Invoke(f, new object[] { user, pass });
                if (obj == null) return Results.Json(new { ok = false, message = "Login returned null" }, statusCode: 500);

                try
                {
                    // Preferred: Task<(bool ok, string message)>
                    if (obj is System.Threading.Tasks.Task<(bool ok, string message)> t2)
                    {
                        var res = await t2.ConfigureAwait(false);
                        return Results.Json(new { ok = res.ok, message = res.message });
                    }


                    // Back-compat: Task<bool>
                    if (obj is System.Threading.Tasks.Task<bool> t1)
                    {
                        var ok = await t1.ConfigureAwait(false);
                        return Results.Json(new { ok = ok, message = ok ? "ok" : "Login failed" });
                    }

                    return Results.Json(new { ok = false, message = "Unexpected return type from CoomerLoginAsync" }, statusCode: 500);
                }
                catch (Exception ex)
                {
                    return Results.Json(new { ok = false, message = ex.Message }, statusCode: 500);
                }

            }
            catch (Exception ex)
            {
                return Results.Json(new { ok = false, message = ex.Message }, statusCode: 500);
            }
        });

        // /api/coomer/retry — rerun auto-login (saved creds) once from WebUI
        app.MapPost("/api/coomer/retry", (HttpRequest req) =>
        {
            if (!CheckKey(req, controlKey)) return Results.Unauthorized();

            try
            {
                var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                if (f == null)
                    return Results.Json(new { ok = false, message = "MainForm not available" }, statusCode: 409);

                try { _ = f.Handle; } catch { } // ensure handle exists

                f.BeginInvoke(new Action(() =>
                {
                    try { CMDownloaderUI.LogTap.Append("[AUTOLOGIN] retry requested (webui)"); } catch { }
                    try { f.TryAutoLoginFromWebUi(); }
                    catch (Exception ex)
                    {
                        try { CMDownloaderUI.LogTap.Append("[AUTOLOGIN] retry threw: " + ex.Message); } catch { }
                    }
                }));

                return Results.Json(new { ok = true, message = "retry started" });
            }
            catch (Exception ex)
            {
                return Results.Json(new { ok = false, message = ex.Message }, statusCode: 500);
            }
        });


        // /api/coomer/remember — toggle/clear saved login without attempting login
        app.MapPost("/api/coomer/remember", async (HttpRequest req) =>
        {
            if (!CheckKey(req, controlKey)) return Results.Unauthorized();

            try
            {
                var root = await req.ReadFromJsonAsync<System.Text.Json.JsonElement>();
                bool remember = false;

                try
                {
                    if (root.ValueKind == System.Text.Json.JsonValueKind.Object &&
                        root.TryGetProperty("remember", out var r))
                    {
                        if (r.ValueKind == System.Text.Json.JsonValueKind.True) remember = true;
                        else if (r.ValueKind == System.Text.Json.JsonValueKind.False) remember = false;
                        else if (r.ValueKind == System.Text.Json.JsonValueKind.String)
                        {
                            var s = (r.GetString() ?? "");
                            remember = (s == "1") || s.Equals("true", StringComparison.OrdinalIgnoreCase);
                        }
                    }
                }
                catch { }

                var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                if (f != null)
                {
                    var mi = f.GetType().GetMethod("SetCoomerRememberFromWebUi",
                        System.Reflection.BindingFlags.Instance |
                        System.Reflection.BindingFlags.Public |
                        System.Reflection.BindingFlags.NonPublic);

                    if (mi != null && !remember)
                    {
                        mi.Invoke(f, new object?[] { "", "", false });
                        try { CMDownloaderUI.LogTap.Append("[AUTOLOGIN] remember=0 (webui)"); } catch { }
                    }
                }

                return Results.Ok(new { ok = true });
            }
            catch
            {
                return Results.Ok(new { ok = false });
            }
        });

        // /api/pick-folder — open WinForms FolderBrowserDialog via existing Browse button
        app.MapPost("/api/pick-folder", (HttpRequest req) =>
        {
            if (!CheckKey(req, controlKey)) return Results.Unauthorized();

            try
            {
                var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                if (f == null)
                    return Results.Json(new { ok = false, message = "MainForm not available" }, statusCode: 409);

                var mi = f.GetType().GetMethod("PickFolderFromWebUi",
                    System.Reflection.BindingFlags.Instance |
                    System.Reflection.BindingFlags.Public |
                    System.Reflection.BindingFlags.NonPublic);

                mi?.Invoke(f, null);
                return Results.Json(new { ok = true });
            }
            catch (Exception ex)
            {
                return Results.Json(new { ok = false, message = ex.Message }, statusCode: 500);
            }
        });

        // heartbeat from WebUI tab(s)
        app.MapPost("/api/ping", () =>
        {
            _lastPingUtc = System.DateTime.UtcNow;
            return Results.Json(new { ok = true });
        });


        // get/set tuners + mode (reflection; no Program.MainForm, no DTO types)
        app.MapGet("/api/config", () =>
        {
            try
            {
                var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                if (f == null) return Results.Json(new { nvWorkers = 0, vidWorkers = 0, mode = "all" });

                int nv = 0, vid = 0; string mode = "all";

                try
                {
                    var miNv = f.GetType().GetMethod("GetNonVideoWorkerLimit",
                        System.Reflection.BindingFlags.Instance |
                        System.Reflection.BindingFlags.Public |
                        System.Reflection.BindingFlags.NonPublic);
                    if (miNv != null) nv = Convert.ToInt32(miNv.Invoke(f, null) ?? 0);
                }
                catch { }

                try
                {
                    var miVid = f.GetType().GetMethod("GetVideoWorkerLimit",
                        System.Reflection.BindingFlags.Instance |
                        System.Reflection.BindingFlags.Public |
                        System.Reflection.BindingFlags.NonPublic);
                    if (miVid != null) vid = Convert.ToInt32(miVid.Invoke(f, null) ?? 0);
                }
                catch { }

                try
                {
                    var miMode = f.GetType().GetMethod("GetModeFromWebUi",
                        System.Reflection.BindingFlags.Instance |
                        System.Reflection.BindingFlags.Public |
                        System.Reflection.BindingFlags.NonPublic);
                    if (miMode != null) mode = (string?)(miMode.Invoke(f, null)) ?? "all";
                }
                catch { }

                return Results.Json(new { nvWorkers = nv, vidWorkers = vid, mode });
            }
            catch
            {
                return Results.Json(new { nvWorkers = 0, vidWorkers = 0, mode = "all" });
            }
        });

        app.MapPost("/api/config", async (HttpRequest req) =>
        {
            try
            {
                using var doc = await System.Text.Json.JsonDocument.ParseAsync(req.Body);
                var root = doc.RootElement;

                int nv = 0, vid = 0; string mode = "all";

                if (root.TryGetProperty("nvWorkers", out var nvEl) && nvEl.ValueKind == System.Text.Json.JsonValueKind.Number)
                    nv = nvEl.GetInt32();
                if (root.TryGetProperty("vidWorkers", out var vidEl) && vidEl.ValueKind == System.Text.Json.JsonValueKind.Number)
                    vid = vidEl.GetInt32();
                if (root.TryGetProperty("mode", out var mEl) && mEl.ValueKind == System.Text.Json.JsonValueKind.String)
                    mode = mEl.GetString() ?? "all";

                var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                if (f != null)
                {
                    try
                    {
                        var miNvSet = f.GetType().GetMethod("SetNonVideoWorkerLimit",
                            System.Reflection.BindingFlags.Instance |
                            System.Reflection.BindingFlags.Public |
                            System.Reflection.BindingFlags.NonPublic);
                        miNvSet?.Invoke(f, new object[] { nv });
                    }
                    catch { }

                    try
                    {
                        var miVidSet = f.GetType().GetMethod("SetVideoWorkerLimit",
                            System.Reflection.BindingFlags.Instance |
                            System.Reflection.BindingFlags.Public |
                            System.Reflection.BindingFlags.NonPublic);
                        miVidSet?.Invoke(f, new object[] { vid });
                    }
                    catch { }

                    try
                    {
                        var miModeSet = f.GetType().GetMethod("SetModeFromWebUi",
                            System.Reflection.BindingFlags.Instance |
                            System.Reflection.BindingFlags.Public |
                            System.Reflection.BindingFlags.NonPublic);
                        miModeSet?.Invoke(f, new object[] { mode });
                    }
                    catch { }
                }
                // NEW: echo latest tuners back through /api/status
                if (nv > 0) _nvLastFromWebUi = nv;
                if (vid > 0) _vidLastFromWebUi = vid;
                return Results.Ok();
            }
            catch
            {
                return Results.BadRequest();
            }
        });


        // inspect flattened hosts
        app.MapGet("/api/hosts/debug", () =>
        {
            var hs = CMDownloaderUI.WebUiStatus.Snapshot().hosts ?? new List<CMDownloaderUI.HostHealth>();
            var flat = hs.Select(h => new { h.name, h.stars, h.state }).ToArray();
            return Results.Json(flat);
        });

        // tolerant path resolver (handles decode/quote/slash variants)
        app.MapGet("/api/preview-by-path", (HttpRequest req) =>
        {
            // accept ?path=, ?p=, or ?name= (basename fallback)
            var rawPath = req.Query["path"].ToString();
            if (string.IsNullOrWhiteSpace(rawPath)) rawPath = req.Query["p"].ToString();

            // optional basename fallback, used if path fails
            var qName = req.Query["name"].ToString();

            static string Mime(string p)
            {
                var e = System.IO.Path.GetExtension(p).ToLowerInvariant();
                return e switch
                {
                    ".mp4" or ".m4v" or ".mov" or ".webm" => "video/mp4",
                    ".png" => "image/png",
                    ".jpg" or ".jpeg" => "image/jpeg",
                    ".gif" => "image/gif",
                    ".webp" => "image/webp",
                    _ => "application/octet-stream"
                };
            }

            // Try a few normalizations of the incoming path
            IEnumerable<string> Candidates(string s)
            {
                var list = new List<string>();
                if (!string.IsNullOrWhiteSpace(s)) list.Add(s);

                string? dec1 = null, dec2 = null, t = null, tDec1 = null, tDec2 = null;

                try { dec1 = System.Net.WebUtility.UrlDecode(s); } catch { }
                try { dec2 = Uri.UnescapeDataString(s); } catch { }

                // trim quotes and normalize slashes
                t = (s ?? string.Empty).Trim().Trim('"', '\'').Replace('/', '\\');

                try { tDec1 = System.Net.WebUtility.UrlDecode(t); } catch { }
                try { tDec2 = Uri.UnescapeDataString(t); } catch { }

                void add(string? v) { if (!string.IsNullOrWhiteSpace(v)) list.Add(v!); }

                add(dec1);
                add(dec2);
                add(t);
                add(tDec1);
                add(tDec2);

                // Distinct + case-insensitive
                return list.Distinct(StringComparer.OrdinalIgnoreCase);
            }


            // 1) Try every candidate form of the provided path
            foreach (var cand in Candidates(rawPath).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    if (!string.IsNullOrWhiteSpace(cand) && System.IO.File.Exists(cand))
                        return Results.File(cand, Mime(cand), enableRangeProcessing: true);
                }
                catch { /* skip */ }
            }

            // 2) As a fallback, try resolve by basename from the in-memory recent ring
            if (!string.IsNullOrWhiteSpace(qName))
            {
                var stem = System.IO.Path.GetFileName(qName);
                (string name, string path)[] snap;
                lock (_recentLock) snap = _recent.ToArray();

                var hit = snap.FirstOrDefault(r => string.Equals(r.name, stem, StringComparison.OrdinalIgnoreCase));
                if (!string.IsNullOrWhiteSpace(hit.path) && System.IO.File.Exists(hit.path))
                    return Results.File(hit.path, Mime(hit.path), enableRangeProcessing: true);
            }

            // 3) Not found
            return Results.NotFound();
        });


        // newest first, max 'limit'
        app.MapGet("/api/recent", (int? limit) =>
        {
            (string name, string path)[] snap;
            lock (_recentLock) snap = _recent.ToArray();
            var take = Math.Max(1, Math.Min(limit ?? 12, 12));
            var items = snap.Take(take).Select(it => new { name = it.name, path = it.path }).ToArray();
            return Results.Json(items);
        });

        app.MapPost("/api/recent/clear", () => { lock (_recentLock) _recent.Clear(); return Results.Ok(new { ok = true }); });

        // resolve by name against our recent ring, then stream
        app.MapGet("/api/preview", (string name) =>
        {
            if (string.IsNullOrWhiteSpace(name)) return Results.NotFound();

            (string name, string path)? hit = null;
            lock (_recentLock)
                hit = _recent.FirstOrDefault(r => string.Equals(r.name, name, StringComparison.OrdinalIgnoreCase));

            if (hit == null || !System.IO.File.Exists(hit.Value.path)) return Results.NotFound();

            static string Ct(string p)
            {
                var e = System.IO.Path.GetExtension(p).ToLowerInvariant();
                return e switch
                {
                    ".mp4" or ".m4v" or ".mov" or ".webm" => "video/mp4",
                    ".png" => "image/png",
                    ".jpg" or ".jpeg" => "image/jpeg",
                    ".gif" => "image/gif",
                    ".webp" => "image/webp",
                    _ => "application/octet-stream"
                };
            }

            return Results.File(hit.Value.path, Ct(hit.Value.path), enableRangeProcessing: true);
        });

        // /api/health — quick alive/ping (supports GET and HEAD)
        app.MapMethods("/api/health", new[] { "GET", "HEAD" }, () =>
        {
            return Results.Json(new { ok = true, utc = DateTimeOffset.UtcNow });
        });

        // /api/start — tolerate missing "Add" (enqueue then start)
        app.MapPost("/api/start", async (HttpRequest req) =>
        {
            if (!CheckKey(req, controlKey)) return Results.Unauthorized();

            try
            {
                string? url = null;
                try
                {
                    var json = await req.ReadFromJsonAsync<Dictionary<string, string>>();
                    if (json != null && json.TryGetValue("url", out var u)) url = u;
                }
                catch { }

                if (url is null && req.HasFormContentType)
                {
                    var form = await req.ReadFormAsync();
                    url = form["url"].FirstOrDefault();
                }

                if (string.IsNullOrWhiteSpace(url))
                    return Results.Json(new { ok = false, message = "Paste a URL before starting." }); // soft fail

                var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                if (f == null)
                    return Results.Problem(title: "UI not ready", detail: "MainForm not available.", statusCode: 409);

                try { f.EnqueueUrlFromWeb(url); } catch { /* ignore if already queued */ }

                f.StartFromWebUi();
                return Results.Json(new { ok = true });
            }
            catch (Exception ex)
            {
                return Results.Problem(title: "Start failed", detail: ex.Message, statusCode: 500);
            }
        });

        app.MapPost("/api/stop", (HttpRequest req) =>
        {
            if (!CheckKey(req, controlKey)) return Results.Unauthorized();
            try
            {
                var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                if (f == null)
                    return Results.Problem(title: "UI not ready", detail: "MainForm not available.", statusCode: 409);

                f.StopFromWebUi();
                return Results.Json(new { ok = true });
            }
            catch (Exception ex)
            {
                return Results.Problem(title: "Stop failed", detail: ex.Message, statusCode: 500);
            }
        });
        // hard-stop (second press)
        app.MapPost("/api/stop-hard", (HttpRequest req) =>
        {
            if (!CheckKey(req, controlKey)) return Results.Unauthorized();

            try
            {
                var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                if (f != null)
                {
                    try { f.HardStopFromWebUi(); } catch { f.StopFromWebUi(); }
                }
            }
            catch { }

            return Results.Json(new { ok = true, hard = true });
        });

        // /api/pause — soft pause (UI + best-effort backend)
        app.MapPost("/api/pause", (HttpRequest req) =>
        {
            if (!CheckKey(req, controlKey)) return Results.Unauthorized();
            try
            {
                _pausedUi = true;

                // best-effort: call PauseFromWebUi() if MainForm has it (reflection avoids compile dependency)
                try
                {
                    var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                    var mi = f?.GetType().GetMethod("PauseFromWebUi",
                        System.Reflection.BindingFlags.Instance |
                        System.Reflection.BindingFlags.Public |
                        System.Reflection.BindingFlags.NonPublic);
                    mi?.Invoke(f, null);
                }
                catch { }

                try { CMDownloaderUI.LogTap.Append("[WEB] pause"); } catch { }
                return Results.Json(new { ok = true });
            }
            catch (Exception ex)
            {
                return Results.Problem(title: "Pause failed", detail: ex.Message, statusCode: 500);
            }
        });

        // /api/resume — clear pause
        app.MapPost("/api/resume", (HttpRequest req) =>
        {
            if (!CheckKey(req, controlKey)) return Results.Unauthorized();
            try
            {
                _pausedUi = false;

                // best-effort: call ResumeFromWebUi() if present
                try
                {
                    var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                    var mi = f?.GetType().GetMethod("ResumeFromWebUi",
                        System.Reflection.BindingFlags.Instance |
                        System.Reflection.BindingFlags.Public |
                        System.Reflection.BindingFlags.NonPublic);
                    mi?.Invoke(f, null);
                }
                catch { }

                try { CMDownloaderUI.LogTap.Append("[WEB] resume"); } catch { }
                return Results.Json(new { ok = true });
            }
            catch (Exception ex)
            {
                return Results.Problem(title: "Resume failed", detail: ex.Message, statusCode: 500);
            }
        });

        // ---- EXIT APP (stop then close) ----
        app.MapPost("/api/exit", (HttpRequest req) =>
        {
            if (!CheckKey(req, controlKey)) return Results.Unauthorized();
            try
            {
                var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                if (f == null)
                    return Results.Problem(title: "UI not ready", detail: "MainForm not available.", statusCode: 409);

                // Stop the run (sync) — same as /api/stop
                try { f.StopFromWebUi(); } catch { }

                // Ask the desktop app to close
                try { OnExitRequested?.Invoke(); } catch { }

                // Fallback: if no handler wired, hard-exit
                try { System.Environment.Exit(0); } catch { }

                return Results.Json(new { ok = true });
            }
            catch (Exception ex)
            {
                return Results.Problem(title: "Exit failed", detail: ex.Message, statusCode: 500);
            }
        });

        // /api/enqueue-url — add a URL to the queue
        app.MapPost("/api/enqueue-url", async (HttpRequest req) =>
        {
            if (!CheckKey(req, controlKey)) return Results.Unauthorized();

            var payload = await req.ReadFromJsonAsync<UrlPayload>();
            if (payload is null || string.IsNullOrWhiteSpace(payload.url))
                return Results.BadRequest("Missing 'url'");

            var f = CMDownloaderUI.MainFormAccessor.Instance;
            if (f == null) return Results.Problem(title: "UI not ready", statusCode: 409);

            f.EnqueueUrlFromWeb(payload.url!);
            return Results.Json(new { ok = true });
        });

        // /api/open-folder — open current save folder
        app.MapPost("/api/open-folder", (HttpRequest req) =>
        {
            try
            {
                var f = CMDownloaderUI.MainFormAccessor.MainFormInstance;
                if (f != null)
                {
                    f.BeginInvoke(new Action(() =>
                    {
                        try
                        {
                            var path = f.CurrentFolderPath();
                            if (!string.IsNullOrWhiteSpace(path) && System.IO.Directory.Exists(path))
                                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                                {
                                    FileName = path,
                                    UseShellExecute = true
                                });
                        }
                        catch { }
                    }));
                }
                return Results.Json(new { ok = true });
            }
            catch (Exception ex)
            {
                return Results.Problem(title: "Open folder failed", detail: ex.Message, statusCode: 500);
            }
        });

        // /api/set-folder — set the save location
        app.MapPost("/api/set-folder", async (HttpRequest req) =>
        {
            if (!CheckKey(req, controlKey)) return Results.Unauthorized();

            var payload = await req.ReadFromJsonAsync<FolderPayload>();
            if (payload is null || string.IsNullOrWhiteSpace(payload.folder))
                return Results.BadRequest("Missing 'folder'");

            var f = CMDownloaderUI.MainFormAccessor.Instance;
            if (f == null) return Results.Problem(title: "UI not ready", statusCode: 409);

            f.SetFolderFromWeb(payload.folder!);
            return Results.Json(new { ok = true });
        });

        // make CSP final (runs after handlers)
        app.Use(async (ctx, next) =>
        {
            await next(); // let everything run first
            try
            {
                ctx.Response.Headers.Remove("Content-Security-Policy");

                var csp =
                    "default-src 'self'; " +
                    $"connect-src 'self' http://{host}:{port}; " + // reflect actual host/port
                    "img-src 'self' data: blob:; " +
                    "style-src 'self' 'unsafe-inline'; " +
                    "script-src 'self' 'unsafe-inline'; " +
                    "font-src 'self' data:; " +
                    "base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

                ctx.Response.Headers.Append("Content-Security-Policy", csp);
            }
            catch { }
        });

        await app.StartAsync();
        try { CMDownloaderUI.LogTap.Append($"[WEB] UI started http:// {host}:{port} root={root}"); } catch { }
    }

    public static async Task StopAsync()
    {
        var app = _app;
        _app = null;
        if (app == null) return;
        try { await app.StopAsync(TimeSpan.FromSeconds(2)); } catch { }
        try { await app.DisposeAsync(); } catch { }
        try { CMDownloaderUI.LogTap.Append("[WEB] UI stopped"); } catch { }
    }

    internal class UrlPayload { public string? url { get; set; } }
    internal class FolderPayload { public string? folder { get; set; } }
}
