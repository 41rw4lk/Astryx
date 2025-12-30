using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq; // keep
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace CMDownloaderUI.Net
{
    public sealed class EdgeSelectorOptions
    {
        public IReadOnlyList<string> CandidateHosts { get; init; } = new[] { "localhost" };

        // optional knobs you already had
        public Uri BaseUriTemplate { get; init; } = new Uri("https://example.com/");
        public string HealthPath { get; init; } = "/robots.txt";
        public string RangeSamplePath { get; init; } = "/robots.txt";
        public TimeSpan ProbeInterval { get; init; } = TimeSpan.FromMinutes(6);
        public int MaxProbeConcurrency { get; init; } = 2;
        public double SwitchMargin { get; init; } = 0.20;
        public int ConfirmCount { get; init; } = 2;
        public TimeSpan CooldownAfterSwitch { get; init; } = TimeSpan.FromMinutes(5);
        public bool PinHost { get; set; } = false;
        public string? PinnedHost { get; set; }

        // required by ES implementation here
        public bool EnforceSameApex { get; init; } = true;
        public int SamplesPerHost { get; init; } = 3;
        public int TimeoutMs { get; init; } = 900; // ms for probe timeouts
        public bool FallbackGetRangeOnHeadFailure { get; init; } = true;
    }

    public sealed class HostStats
    {
        public required string Host { get; init; }
        public double EmaTtfbMs { get; set; }
        public double EmaMbps { get; set; }
    }

    public sealed class EdgeSelector : IDisposable
    {
        private readonly EdgeSelectorOptions _opt;
        private readonly HttpClient _http;
        private readonly Action<string>? _log;
        private readonly Func<HttpRequestMessage, Task>? _decorate;

        private CancellationTokenSource? _loopCts;
        private Task? _loopTask;
        private string? _activeHost;
        private DateTime _stickUntilUtc; // do not switch before this time
                                         // [ES.UIPUSH.TIMER] last time we pushed WebUI hosts
        private DateTime _lastUiPush = DateTime.MinValue;

        public event Action<string, HostStats>? ActiveHostChanged;

        // ---- validation / selection state ----
        private readonly HashSet<string> _validHosts = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, double> _avgRttMs = new(StringComparer.OrdinalIgnoreCase);
        // [ES.RTT.P95] store 95th-percentile RTT per host
        private readonly Dictionary<string, double> _p95RttMs = new(StringComparer.OrdinalIgnoreCase);

        private volatile string? _bestHost;
        private volatile bool _ready;
        // [EDGE.PROBE.TIMER]
        private System.Threading.Timer? _probeTimer;

        public string ActiveHost => _activeHost ?? _opt.PinnedHost ?? _opt.CandidateHosts[0];
        public string? SelectedHost => _bestHost;
        public IReadOnlyCollection<string> ValidHosts => _validHosts;
        // Return a candidate from the opposite host family (n1/n3 ↔ n2/n4)
        public string? ResolveOppositeFamilyHost(string? current)
        {
            if (string.IsNullOrWhiteSpace(current)) return null;
            var host = current!.Trim();

            // Families: A = n1/n3, B = n2/n4
            static bool IsFamA(string h) => h.Contains("n1.", StringComparison.OrdinalIgnoreCase) || h.Contains("n3.", StringComparison.OrdinalIgnoreCase);
            static bool IsFamB(string h) => h.Contains("n2.", StringComparison.OrdinalIgnoreCase) || h.Contains("n4.", StringComparison.OrdinalIgnoreCase);

            bool curIsA = IsFamA(host);
            bool curIsB = IsFamB(host);

            // prefer valid, otherwise fall back to any configured candidate in the opposite family
            IEnumerable<string> opp =
                _opt.CandidateHosts.Where(h => curIsA ? IsFamB(h) : IsFamA(h));

            foreach (var h in opp)
            {
                if (string.Equals(h, host, StringComparison.OrdinalIgnoreCase)) continue;
                if (_validHosts.Count == 0 || _validHosts.Contains(h)) return h;
            }
            return opp.FirstOrDefault(h => !string.Equals(h, host, StringComparison.OrdinalIgnoreCase));
        }

        public EdgeSelector(EdgeSelectorOptions opt, HttpClient http,
                            Action<string>? logger = null,
                            Func<HttpRequestMessage, Task>? decorateRequest = null)
        {
            _opt = opt;
            _http = http;
            _log = logger;
            _decorate = decorateRequest;
        }

        public async Task InitializeAsync(CancellationToken ct)
        {
            _activeHost = _opt.PinHost && !string.IsNullOrEmpty(_opt.PinnedHost)
                ? _opt.PinnedHost
                : _opt.CandidateHosts[0];

            ActiveHostChanged?.Invoke(ActiveHost, new HostStats { Host = ActiveHost, EmaMbps = 0, EmaTtfbMs = 0 });
            PushWebUiHosts(); // <— #1: initial announce
            try { await UiProbeOnceAsync(ct).ConfigureAwait(false); } catch { }

            await Task.CompletedTask;
        }
        // [ES.UIPROBE] single quick HEAD probe to seed _avgRttMs and push to WebUI
        public async Task UiProbeOnceAsync(CancellationToken ct)
        {
            try
            {
                var hosts = _opt.CandidateHosts ?? Array.Empty<string>();
                foreach (var h in hosts)
                {
                    var baseUri = new Uri($"https://{h}");
                    var url = new Uri(baseUri, "/robots.txt");

                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    try
                    {
                        using var req = new HttpRequestMessage(HttpMethod.Head, url);
                        using var res = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                        sw.Stop();

                        // accept anything non-catastrophic; we just want TTFB-ish RTT
                        if ((int)res.StatusCode < 500)
                            _avgRttMs[h] = Math.Max(1.0, sw.Elapsed.TotalMilliseconds);
                    }
                    catch { sw.Stop(); }
                }

                try { PushWebUiHosts(); } catch { }
            }
            catch { }
        }

        public void Start(CancellationToken outer)
        {
            Stop(); // ensure clean state
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(outer);

            // seed RTT once on start
            _loopTask = Task.Run(async () =>
            {
                try { await UiProbeOnceAsync(_loopCts.Token).ConfigureAwait(false); } catch { }
            }, _loopCts.Token);

            // [EDGE.PROBE.TIMER.START] periodic RTT refresh for WebUI p50/p95
            try
            {
                _probeTimer?.Dispose();
                _probeTimer = new System.Threading.Timer(async _ =>
                {
                    try { await UiProbeOnceAsync(_loopCts?.Token ?? System.Threading.CancellationToken.None).ConfigureAwait(false); } catch { }
                }, null, TimeSpan.FromSeconds(12), TimeSpan.FromSeconds(12));
            }
            catch { }
        }


        public void Stop()
        {
            // stop periodic RTT timer
            try { _probeTimer?.Dispose(); } catch { }
            _probeTimer = null;

            // stop the probe task/cts
            try { _loopCts?.Cancel(); } catch { }
            try { _loopTask?.Wait(250); } catch { }
            _loopCts?.Dispose();
            _loopCts = null;
            _loopTask = null;
        }


        // [EDGE.API] manual hop + stickiness control
        public void HopNext()
        {
            var hosts = (_opt.CandidateHosts ?? Array.Empty<string>())
                .Where(h => !string.IsNullOrWhiteSpace(h))
                .Select(h => h.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (hosts.Length == 0) return;

            var current = ActiveHost;
            int curIdx = Array.FindIndex(hosts, h => string.Equals(h, current, StringComparison.OrdinalIgnoreCase));
            int nextIdx = curIdx < 0 ? 0 : (curIdx + 1) % hosts.Length;

            var next = hosts[nextIdx];
            if (string.Equals(next, current, StringComparison.OrdinalIgnoreCase)) return;

            try { _log?.Invoke($"[EDGE] hop {current} → {next}"); } catch { }
            _activeHost = next;
            _stickUntilUtc = DateTime.UtcNow + _opt.CooldownAfterSwitch; // brief stick
            ActiveHostChanged?.Invoke(_activeHost, new HostStats { Host = _activeHost, EmaMbps = 0, EmaTtfbMs = 0 });
            PushWebUiHosts(); // <— #2: manual hop announce
        }
        public void PublishHostsToWebUi() => PushWebUiHosts();  // calls the private helper you already have

        public void ClearStickiness() => _stickUntilUtc = DateTime.MinValue;

        public void Dispose() => Stop();



        // ---- selection entry point used by downloader when it needs a host ----
        public string ResolveHostForNewDownload()
        {
            // If we’re not ready or don’t have a candidate, use current/pinned
            if (!_ready || _validHosts.Count == 0)
                return ActiveHost;

            // stickiness window: avoid flapping
            if (DateTime.UtcNow < _stickUntilUtc)
                return ActiveHost;

            // If measured “best” is different, switch
            if (!string.Equals(_activeHost, _bestHost, StringComparison.OrdinalIgnoreCase) && _bestHost is string best)
            {
                var prev = _activeHost ?? "(none)";
                _activeHost = best;
                _stickUntilUtc = DateTime.UtcNow + _opt.CooldownAfterSwitch;
                try { _log?.Invoke($"[EDGE] {prev} → {_activeHost} (auto)"); } catch { }
                ActiveHostChanged?.Invoke(_activeHost, new HostStats { Host = _activeHost, EmaMbps = 0, EmaTtfbMs = 0 });
                PushWebUiHosts(); // <— #3: auto switch announce
            }

            return ActiveHost;
        }

        // ---- validation / discovery ----
        public async Task DiscoverAsync(Uri[] samples, CancellationToken ct)
        {
            _validHosts.Clear();
            _avgRttMs.Clear();
            _bestHost = null;
            _ready = false;

            foreach (var host in _opt.CandidateHosts ?? Array.Empty<string>())
            {
                if (string.IsNullOrWhiteSpace(host)) continue;

                // (optional) enforce apex matching with sample base
                if (_opt.EnforceSameApex && samples.Length > 0)
                {
                    var sampleHost = samples[0].Host;
                    if (!SameApex(sampleHost, host))
                    {
                        try { _log?.Invoke($"[EDGE] skip {host}: apex mismatch vs {sampleHost}"); } catch { }
                        continue;
                    }
                }

                var rtts = new List<double>(_opt.SamplesPerHost);
                try
                {
                    int okCount = 0;
                    foreach (var s in samples)
                    {
                        var u = SwapHost(s, host);
                        var (ok, ms, code, why) = await ProbeAsync(u, ct).ConfigureAwait(false);
                        if (ok) { okCount++; rtts.Add(ms); }
                        else try { _log?.Invoke($"[EDGE] {host} failed probe {u.PathAndQuery} ({why})"); } catch { }
                    }

                    if (okCount == 0)
                    {
                        try { _log?.Invoke($"[EDGE] reject {host}: all probes failed"); } catch { }
                        continue;
                    }

                    var avg = rtts.Average();
                    // [ES.RTT.P95] compute 95th percentile from collected RTTs
                    rtts.Sort();
                    int idx95 = Math.Max(0, (int)Math.Ceiling(0.95 * rtts.Count) - 1);
                    double p95 = rtts[idx95];

                    _validHosts.Add(host);
                    _avgRttMs[host] = avg;
                    _p95RttMs[host] = p95;            // <-- store p95
                    try { _log?.Invoke($"[EDGE] {host} OK avg={avg:0} ms p95={p95:0} (n={okCount}/{samples.Length})"); } catch { }

                    _validHosts.Add(host);
                    _avgRttMs[host] = avg;
                    try { _log?.Invoke($"[ES.PROBE.RTT] {host} avg={avg:0.0}"); } catch { }

                    try { PushWebUiHosts(); } catch { }

                    try { _log?.Invoke($"[EDGE] {host} OK avg={avg:0} ms (n={okCount}/{samples.Length})"); } catch { }
                }
                catch (Exception ex)
                {
                    try { _log?.Invoke($"[EDGE] {host} probe error: {ex.GetType().Name} {ex.Message}"); } catch { }
                }
            }

            if (_validHosts.Count == 0)
            {
                try { _log?.Invoke("[EDGE] no valid hosts; pass-through"); } catch { }
                return;
            }

            _bestHost = _avgRttMs.OrderBy(kv => kv.Value).First().Key;
            _ready = true;
            // [ES.UIPUSH.SEED] push even if active host didn’t change
            try { PushWebUiHosts(); } catch { }

            try { _log?.Invoke($"[EDGE] discovery: valid=[{string.Join(", ", _validHosts)}] → best={_bestHost}"); } catch { }

            if (!string.Equals(_activeHost, _bestHost, StringComparison.OrdinalIgnoreCase))
            {
                var prev = _activeHost ?? "(none)";
                _activeHost = _bestHost;
                _stickUntilUtc = DateTime.UtcNow + _opt.CooldownAfterSwitch;
                try { _log?.Invoke($"[EDGE] {prev} → {_activeHost} (init)"); } catch { }
                ActiveHostChanged?.Invoke(_activeHost, new HostStats { Host = _activeHost, EmaMbps = 0, EmaTtfbMs = 0 });
                PushWebUiHosts(); // also push here so the UI sees the initial set
            }
        }

        // ---- helpers ----
        private static bool IsPublicIp(IPAddress ip)
        {
            if (IPAddress.IsLoopback(ip)) return false;

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var b = ip.GetAddressBytes();
                if (b[0] == 10) return false;                                 // 10.0.0.0/8
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;    // 172.16.0.0/12
                if (b[0] == 192 && b[1] == 168) return false;                 // 192.168.0.0/16
                if (b[0] == 169 && b[1] == 254) return false;                 // 169.254.0.0/16
                return true;
            }

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                return !(ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal);

            return true;
        }

        // Keep old call sites working: instance helper to rewrite only the host.
        public Uri RewriteUriHost(Uri original, string newHost)
        {
            var ub = new UriBuilder(original) { Host = newHost };
            return ub.Uri;
        }

        // Optional convenience overload if any call sites pass strings:
        public Uri RewriteUriHost(string original, string newHost)
        {
            return RewriteUriHost(new Uri(original, UriKind.Absolute), newHost);
        }

        private static bool SameApex(string a, string b)
        {
            static string Apex(string h)
            {
                var parts = h.Split('.');
                return parts.Length >= 2 ? parts[^2] + "." + parts[^1] : h;
            }
            return string.Equals(Apex(a), Apex(b), StringComparison.OrdinalIgnoreCase);
        }

        private static Uri SwapHost(Uri u, string host)
        {
            var ub = new UriBuilder(u) { Host = host };
            return ub.Uri;
        }

        private async Task<(bool ok, double ms, HttpStatusCode code, string why)> ProbeAsync(Uri url, CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                // HEAD first
                using var head = new HttpRequestMessage(HttpMethod.Head, url);
                if (_decorate != null) await _decorate(head).ConfigureAwait(false);

                using var headCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                headCts.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(200, _opt.TimeoutMs)));
                using var headResp = await _http.SendAsync(head, HttpCompletionOption.ResponseHeadersRead, headCts.Token).ConfigureAwait(false);

                sw.Stop();

                if (headResp.StatusCode == HttpStatusCode.OK || headResp.StatusCode == HttpStatusCode.PartialContent)
                    return (true, sw.Elapsed.TotalMilliseconds, headResp.StatusCode, "HEAD 2xx");

                // Fallback: GET Range: bytes=0-0
                if (_opt.FallbackGetRangeOnHeadFailure)
                {
                    sw.Restart();
                    using var get = new HttpRequestMessage(HttpMethod.Get, url);
                    get.Headers.Range = new RangeHeaderValue(0, 0);
                    if (_decorate != null) await _decorate(get).ConfigureAwait(false);

                    using var getCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    getCts.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(200, _opt.TimeoutMs)));
                    using var getResp = await _http.SendAsync(get, HttpCompletionOption.ResponseHeadersRead, getCts.Token).ConfigureAwait(false);
                    sw.Stop();

                    if (getResp.StatusCode == HttpStatusCode.OK || getResp.StatusCode == HttpStatusCode.PartialContent)
                        return (true, sw.Elapsed.TotalMilliseconds, getResp.StatusCode, "GET 2xx");

                    return (false, sw.Elapsed.TotalMilliseconds, getResp.StatusCode, $"GET {((int)getResp.StatusCode)}");
                }

                return (false, sw.Elapsed.TotalMilliseconds, headResp.StatusCode, $"HEAD {((int)headResp.StatusCode)}");
            }
            catch (TaskCanceledException)
            {
                sw.Stop();
                return (false, sw.Elapsed.TotalMilliseconds, 0, "timeout");
            }
            catch (Exception ex)
            {
                sw.Stop();
                return (false, sw.Elapsed.TotalMilliseconds, 0, ex.GetType().Name);
            }
        }

        // Build and publish the host list for the WebUI
        private void PushWebUiHosts()
        {
            try
            {
                // Candidates (dedupbed); fallback to n1..n4 if none provided
                var cand = (_opt.CandidateHosts ?? Array.Empty<string>())
                    .Where(h => !string.IsNullOrWhiteSpace(h))
                    .Select(h => h.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                if (cand.Length == 0)
                    cand = new[] { "n1.coomer.st", "n2.coomer.st", "n3.coomer.st", "n4.coomer.st" };

                // preserve per-host load (active/limit) from last WebUI snapshot so ES doesn't wipe it
                var __prevLoad = new Dictionary<string, (int active, int limit)>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    var __prev = CMDownloaderUI.WebUiStatus.Snapshot()?.hosts;
                    if (__prev != null)
                    {
                        foreach (var ph in __prev)
                        {
                            if (ph == null) continue;
                            var n = ph.name;
                            if (string.IsNullOrWhiteSpace(n)) continue;
                            __prevLoad[n.Trim()] = (ph.active, ph.limit);
                        }
                    }
                }
                catch { }


                // Measured first (fastest RTT → slowest), then unmeasured
                var measured = _avgRttMs.OrderBy(kv => kv.Value).Select(kv => kv.Key);
                var order = measured.Concat(cand.Except(measured, StringComparer.OrdinalIgnoreCase));

                var hosts = new List<CMDownloaderUI.HostHealth>(cand.Length);
                foreach (var h in order)
                {
                    // p50 from _avgRttMs; optional p95 from _p95RttMs (null-safe)
                    double p50 = _avgRttMs.TryGetValue(h, out var ms50) ? ms50 : 0;
                    double p95 = (_p95RttMs != null && _p95RttMs.TryGetValue(h, out var ms95)) ? ms95 : 0;

                    // Fallback: no cooldown wiring in EdgeSelector (avoid missing _hostCooldown)
                    bool onCooldown = false;

                    // Stars from p50; unknown ⇒ neutral 3
                    int stars =
                        (p50 <= 0) ? 3 :
                        (p50 <= 180) ? 5 :
                        (p50 <= 300) ? 4 :
                        (p50 <= 600) ? 3 : 2;

                    // Status label from p50 (no cooldown state here)
                    string status =
                        (p50 <= 0) ? "unknown" :
                        (p50 <= 300) ? "healthy" :
                        (p50 <= 600) ? "slow" : "flaky";

                    // Fallback pinned: only compare to _activeHost (avoid missing _pinnedRangeHost)
                    bool pinned =
                        !string.IsNullOrEmpty(_activeHost) &&
                        string.Equals(h, _activeHost, StringComparison.OrdinalIgnoreCase);

                    var __load = __prevLoad.TryGetValue(h, out var __al) ? __al : (0, 0);

                    hosts.Add(new CMDownloaderUI.HostHealth
                    {
                        name = h,
                        state = status,
                        stars = stars,
                        p50_ms = (p50 > 0) ? (int?)Math.Round(p50) : null,
                        p95_ms = (p95 > 0) ? (int?)Math.Round(p95) : null,
                        pinned = pinned,
                        cooldown = onCooldown,
                        active = __load.Item1,
                        limit = __load.Item2,
                    });


                }


                // If nothing measured yet, at least surface the active host
                if (hosts.Count == 0 && _activeHost is string a)
                {
                    hosts.Add(new CMDownloaderUI.HostHealth
                    {
                        name = a,
                        state = "unknown",
                        stars = 3,
                        p50_ms = 0,
                        pinned = true,
                        cooldown = false
                    });
                }

                CMDownloaderUI.WebUiStatus.SetHosts(hosts);
            }
            catch { /* best-effort */ }
        }


    }
}
