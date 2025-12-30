using System;
using System.Collections.Generic;
using System.Linq;

namespace CMDownloaderUI
{
    internal sealed class HostHealth
    {
        public string name { get; init; } = "";
        public string state { get; init; } = "healthy"; // healthy|slow|flaky|temp_banned|offline
        public int stars { get; init; } = 3;            // 0..5
        public int? ttl_s { get; init; }                // for temp_banned
        public double? error_rate { get; init; }        // 0..1
        public int? p50_ms { get; init; }
        public int? p95_ms { get; init; }
        public bool pinned { get; init; } = false;     // active/pinned edge
        public bool cooldown { get; init; } = false;   // e.g., temp-banned / cooling

        public string stars_text => new string('★', Math.Clamp(stars, 0, 5)) + new string('☆', 5 - Math.Clamp(stars, 0, 5));
        public int active { get; set; }   // current active connections on this host
        public int limit { get; set; }   // soft cap used for the UI bar

    }

    internal sealed class StatusDto
    {
        public bool running { get; init; }
        public int queue { get; init; }
        public string? current { get; init; }
        public List<string> recent { get; init; } = new();
        public double speed_avg_mbps { get; init; }
        public int errors { get; init; }        // error counter (0 if unknown)

        public int completed { get; init; }
        public int total { get; init; }
        public int overallPct { get; init; }

        public long bytes_downloaded { get; init; }
        public List<HostHealth> hosts { get; init; } = new();
        public string? version { get; init; }
        public long speed_bps { get; set; }
        // --- top-row stats for UI ---
        public string? runtime { get; init; }   // "HH:mm:ss"
        public int threads { get; init; }       // process thread count

    }

    internal static class WebUiStatus
    {
        static readonly object _lock = new();
        static bool _running;
        static DateTimeOffset? _startedUtc;
        static long _bytes;
        static int _queue;
        static int _completed;      // legacy (files completed; still used for recent list)
        static int _postsDone;      // posts completed (mirrors OVERALL)
        static int _postsTotal;     // posts total    (mirrors OVERALL)


        static DateTimeOffset? _lastSnapUtc;
        static long _lastSnapBytes;

        static string? _current;
        static double _curPct;
        static long? _curDone, _curSize;
        static string? _curEta, _curHost;

        static readonly LinkedList<string> _recent = new();
        static List<HostHealth> _hosts = new();
        static string? _version;

        public static void SetVersion(string v) { lock (_lock) _version = v; }
        public static void StartRun()
        {
            lock (_lock)
            {
                _running = true;
                if (!_startedUtc.HasValue) _startedUtc = DateTimeOffset.UtcNow;
                _bytes = 0;
                _completed = 0;
                _recent.Clear();

                // B) reset post-level overall mirror
                _postsDone = 0;
                _postsTotal = 1;
            }
        }

        public static void StopRun() { lock (_lock) { _running = false; _current = null; } }
        public static void AddBytes(long n) { if (n <= 0) return; lock (_lock) _bytes += n; }
        public static void SetQueue(int n) { lock (_lock) _queue = Math.Max(0, n); }
        public static void SetCurrent(string? name) { lock (_lock) _current = string.IsNullOrWhiteSpace(name) ? null : name; }
        public static void SetOverall(int done, int total)
        {
            lock (_lock)
            {
                if (total < 1) total = 1;
                if (done < 0) done = 0;
                if (done > total) done = total;

                _postsDone = done;
                _postsTotal = total;
            }
        }


        public static void PushRecent(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return;
            try
            {
                var st = new System.Diagnostics.StackTrace(1, false);
                var m = st.GetFrame(0)?.GetMethod();
                var who = (m?.DeclaringType?.Name ?? "?") + "." + (m?.Name ?? "?");
                var p = System.IO.Path.Combine(AppContext.BaseDirectory, "recent.log");
                System.IO.File.AppendAllText(p, $"[RECENT] via {who} → {name}{Environment.NewLine}");
            }
            catch { }



            string disp = name;
            try
            {
                // If caller passed a "… => E:\...\file.ext", keep the right side
                int idx = name.LastIndexOf("=>", StringComparison.Ordinal);
                if (idx >= 0 && idx + 2 < name.Length)
                    disp = name.Substring(idx + 2).Trim();

                // URL → last path segment
                if (disp.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                {
                    try { disp = System.IO.Path.GetFileName(new Uri(disp).AbsolutePath); } catch { }
                }

                // Any path → filename only
                if (disp.IndexOfAny(new[] { '/', '\\' }) >= 0)
                    disp = System.IO.Path.GetFileName(disp);

                disp = disp.Trim().Trim('"');
            }
            catch { disp = name; }

            lock (_lock)
            {
                // Drop consecutive duplicates (compare by filename, case-insensitive)
                string prev = (_recent.Count > 0) ? _recent.First.Value : null;
                if (!string.IsNullOrEmpty(prev))
                {
                    string prevFile = prev;
                    try { if (prevFile.IndexOfAny(new[] { '/', '\\' }) >= 0) prevFile = System.IO.Path.GetFileName(prevFile); } catch { }
                    string currFile = disp;
                    try { if (currFile.IndexOfAny(new[] { '/', '\\' }) >= 0) currFile = System.IO.Path.GetFileName(currFile); } catch { }

                    if (string.Equals(prevFile, currFile, StringComparison.OrdinalIgnoreCase))
                        return;
                }

                _recent.AddFirst(disp);
                _completed++;
                while (_recent.Count > 5) _recent.RemoveLast();
            }
        }

        public static void SetCompleted(int n)
        {
            lock (_lock)
            {
                _completed = Math.Max(0, n);
            }
        }


        public static void SetCurrentProgress(double pct, long? done, long? size, string? eta, string? host)
        {
            lock (_lock)
            {
                _curPct = pct;
                _curDone = done;
                _curSize = size;
                _curHost = host;

                // derive ETA if missing
                if (string.IsNullOrWhiteSpace(eta) && done.HasValue && size.HasValue && size.Value > 0 && pct > 0)
                {
                    var remain = Math.Max(0, size.Value - done.Value);
                    var bps = Math.Max(1L, _bytes / Math.Max(1.0, (DateTimeOffset.UtcNow - (_startedUtc ?? DateTimeOffset.UtcNow)).TotalSeconds));
                    var sec = (int)Math.Round(remain / Math.Max(1.0, bps));
                    _curEta = $"{sec / 60:00}:{sec % 60:00}";
                }
                else _curEta = eta;
            }
        }


        public static (string? name, double pct, long? done, long? size, string? eta, string? host) GetCurrentSnapshot()
        { lock (_lock) return (_current, _curPct, _curDone, _curSize, _curEta, _curHost); }

        public static void ClearCurrent()
        { lock (_lock) { _current = null; _curPct = 0; _curDone = _curSize = null; _curEta = _curHost = null; } }

        // Merge incoming host health with existing cache
        public static void SetHosts(IEnumerable<HostHealth> hosts)
        {
            lock (_lock)
            {
                var incoming = (hosts?.ToList() ?? new List<HostHealth>());
                if (_hosts.Count == 0) { _hosts = incoming; return; }

                // merge by name (case-insensitive)
                var byName = _hosts.ToDictionary(h => h.name, StringComparer.OrdinalIgnoreCase);
                var merged = new List<HostHealth>(incoming.Count);

                foreach (var h in incoming)
                {
                    if (byName.TryGetValue(h.name, out var old))
                    {
                        merged.Add(new HostHealth
                        {
                            name = h.name,
                            state = h.state,
                            stars = (h.stars > 0 ? h.stars : (old.stars > 0 ? old.stars : 3)),
                            ttl_s = h.ttl_s ?? old.ttl_s,
                            error_rate = h.error_rate ?? old.error_rate,
                            p50_ms = h.p50_ms ?? old.p50_ms,   // keep RTT if not provided
                            p95_ms = h.p95_ms ?? old.p95_ms,   // keep RTT if not provided
                            pinned = h.pinned,
                            cooldown = h.cooldown,
                            active = h.active,
                            limit = h.limit
                        });
                    }
                    else merged.Add(h);
                }
                _hosts = merged;
            }
        }



        public static StatusDto Snapshot()
        {
            lock (_lock)
            {
                // Throughput + runtime
                double bpsAvg = 0.0;
                double bpsRolling = 0.0;

                var now = DateTimeOffset.UtcNow;
                var started = _startedUtc; // capture once

                if (_running && started.HasValue)
                {
                    var secsD = Math.Max(1.0, (now - started.Value).TotalSeconds);
                    bpsAvg = _bytes / secsD; // avg bytes/sec since start
                }

                // short-window "now" speed based on delta between snapshots
                if (_running && _lastSnapUtc.HasValue)
                {
                    var dt = Math.Max(0.25, (now - _lastSnapUtc.Value).TotalSeconds);
                    var db = Math.Max(0L, _bytes - _lastSnapBytes);
                    bpsRolling = (db > 0 && dt > 0) ? db / dt : 0.0;
                }

                // fallback: if no rolling sample yet, use avg
                if (bpsRolling <= 0.0) bpsRolling = bpsAvg;

                // update markers for next snapshot
                _lastSnapUtc = now;
                _lastSnapBytes = _bytes;

                // Keep legacy avg for UI labels (MiB/s ≈ Mbps/8*1.048)
                double mbpsAvg = (bpsAvg * 8.0) / 1_000_000.0; // SI Mbps from avg bps

                // runtime string (HH:mm:ss)
                string runtime = "00:00:00";
                if (started.HasValue)
                {
                    var secs = Math.Max(0, (int)(now - started.Value).TotalSeconds);
                    int hh = secs / 3600, mm = (secs % 3600) / 60, ss = secs % 60;
                    runtime = $"{hh:00}:{mm:00}:{ss:00}";
                }



                // threads (cheap, safe)
                int threads = 0;
                try { threads = System.Diagnostics.Process.GetCurrentProcess().Threads.Count; } catch { }

                // errors (replace with real counter if you have one)
                int errors = 0;
                // Mask impossible combo: temp_banned must never be pinned
                var hostsSafe = _hosts.Select(h =>
                    (h.state == "temp_banned" && h.pinned)
                        ? new HostHealth
                        {
                            name = h.name,
                            state = h.state,
                            stars = h.stars,
                            ttl_s = h.ttl_s,
                            error_rate = h.error_rate,
                            p50_ms = h.p50_ms,
                            p95_ms = h.p95_ms,
                            pinned = false,
                            cooldown = h.cooldown
                        }
                        : h
                ).ToList();


                return new StatusDto
                {
                    running = _running,
                    queue = (_queue < 0 ? 0 : _queue),

                    current = _current,

                    // Overall post progress (mirrors WinForms OVERALL)
                    completed = _postsDone,
                    total = Math.Max(1, _postsTotal),
                    overallPct = (int)Math.Clamp(
                    Math.Round(
                        100.0 * (_postsTotal > 0 ? (double)_postsDone / _postsTotal : 0.0)
                    ),
                    0, 100),


                    recent = _recent.ToList(),
                    speed_avg_mbps = Math.Round(mbpsAvg, 2),
                    speed_bps = (long)Math.Max(0, bpsRolling),


                    // NEW: top-row stats
                    runtime = runtime,
                    threads = threads,
                    errors = errors,

                    bytes_downloaded = _bytes,
                    hosts = hostsSafe,
                    version = _version
                };



            }
        }


    }
}
