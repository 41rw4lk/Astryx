using System;

namespace CMDownloaderUI
{
    // Thread-safe shared status for /api/status
    internal static class Status
    {
        private static readonly object _lock = new();

        // Backing fields (fill these from your app)
        private static string _runState = "Idle";
        private static double _speedAvgMbps, _speedRollingMbps;
        private static long _imgsOk, _vidsOk, _bytesFetched, _bytesSaved;
        private static DateTime? _startedAtUtc;

        // ---- Setters (call these from your existing code) ----
        public static void SetRunState(string state)
        { lock (_lock) _runState = state; }

        public static void SetStartedAt(DateTime? utc)
        { lock (_lock) _startedAtUtc = utc; }

        public static void SetSpeeds(double avgMbps, double rollingMbps)
        { lock (_lock) { _speedAvgMbps = avgMbps; _speedRollingMbps = rollingMbps; } }

        public static void SetTotals(long imgsOk, long vidsOk, long bytesFetched, long bytesSaved)
        { lock (_lock) { _imgsOk = imgsOk; _vidsOk = vidsOk; _bytesFetched = bytesFetched; _bytesSaved = bytesSaved; } }

        // Optional helpers
        public static void IncImgsOk(long n = 1) { lock (_lock) _imgsOk += n; }
        public static void IncVidsOk(long n = 1) { lock (_lock) _vidsOk += n; }
        public static void AddBytesFetched(long n) { lock (_lock) _bytesFetched += n; }
        public static void AddBytesSaved(long n) { lock (_lock) _bytesSaved += n; }

        // ---- Snapshot used by /api/status ----
        public static object Snapshot()
        {
            lock (_lock)
            {
                var flat = new
                {
                    runState = _runState,
                    version = "1.0.0",
                    started = _startedAtUtc?.ToString("o"),
                    speedAvgMbps = _speedAvgMbps,
                    speedRollingMbps = _speedRollingMbps,
                    imagesOk = _imgsOk,
                    videosOk = _vidsOk,
                    bytesFetched = _bytesFetched,
                    bytesSaved = _bytesSaved
                };

                // Back-compat for older dashboard script
                var compat = new
                {
                    speeds = new { avg = _speedAvgMbps, rolling = _speedRollingMbps },
                    totals = new { imgsOk = _imgsOk, vidsOk = _vidsOk, bytesFetched = _bytesFetched, bytesSaved = _bytesSaved }
                };

                return new
                {
                    flat.runState,
                    flat.version,
                    flat.started,
                    flat.speedAvgMbps,
                    flat.speedRollingMbps,
                    flat.imagesOk,
                    flat.videosOk,
                    flat.bytesFetched,
                    flat.bytesSaved,
                    compat.speeds,
                    compat.totals
                };
            }
        }


    }
}
