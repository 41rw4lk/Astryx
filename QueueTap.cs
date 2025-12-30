using System;
using System.Collections.Generic;

namespace CMDownloaderUI
{
    // Minimal queue mirror for the web UI (thread-safe)
    internal static class QueueTap
    {
        private static readonly object _lock = new();

        // Very small data model for the UI
        public sealed class QItem
        {
            public string id { get; init; } = Guid.NewGuid().ToString("n"); // keep init-only
            public string kind { get; set; } = "";   // was init; → now set;
            public string name { get; set; } = "";   // was init; → now set;
            public string host { get; set; } = "";   // was init; → now set;
            public string state { get; set; } = "Queued";
            public int pct { get; set; }             // 0..100
            public double bps { get; set; }          // bytes/sec
            public bool ok { get; set; }
        }
        public static class QueueTapBridge
        {
            /// <summary>
            /// Mirror per-file progress to the web queue. 
            /// Call from your existing per-file progress UI update.
            /// </summary>
            public static void MirrorProgress(string idOrPath, int value, int max, double bytesPerSecond = 0)
            {
                try
                {
                    if (max <= 0) return;
                    var pct = (int)Math.Clamp((value * 100.0) / max, 0, 100);
                    var id = idOrPath;
                    if (string.IsNullOrEmpty(id)) id = Guid.NewGuid().ToString("n");
                    CMDownloaderUI.QueueTap.UpdateWorking(id, pct, bytesPerSecond);
                }
                catch { /* never break worker */ }
            }
        }


        // Internal storage
        private static readonly Dictionary<string, QItem> _items = new();   // by id
        private static readonly LinkedList<string> _qQueued = new();
        private static readonly LinkedList<string> _qWorking = new();
        private static readonly LinkedList<string> _qDone = new();

        // ----- Public helpers you can call from your code (optional, add gradually) -----

        // Add or update a queued item
        public static void UpsertQueued(string id, string kind, string name, string host)
        {
            lock (_lock)
            {
                if (!_items.TryGetValue(id, out var it))
                {
                    it = new QItem { id = id, kind = kind, name = name, host = host, state = "Queued" };
                    _items[id] = it;
                    _qQueued.AddLast(id);
                }
                else
                {
                    it.kind = kind; it.name = name; it.host = host; it.state = "Queued"; it.pct = 0; it.bps = 0;
                    MoveRef(id, _qWorking, _qQueued); // ensure in correct list
                    MoveRef(id, _qDone, _qQueued);
                }
            }
        }

        // Mark as working (pct/bps optional)
        public static void MoveToWorking(string id, int pct = 0, double bps = 0)
        {
            lock (_lock)
            {
                if (_items.TryGetValue(id, out var it))
                {
                    it.state = "Working"; it.pct = pct; it.bps = bps;
                    MoveRef(id, _qQueued, _qWorking);
                    MoveRef(id, _qDone, _qWorking);
                }
            }
        }

        // Update progress
        public static void UpdateWorking(string id, int pct, double bps)
        {
            lock (_lock)
            {
                if (_items.TryGetValue(id, out var it))
                {
                    it.pct = Math.Clamp(pct, 0, 100);
                    it.bps = bps;
                }
            }
        }

        // Mark as done
        public static void MoveToDone(string id, bool ok = true)
        {
            lock (_lock)
            {
                if (_items.TryGetValue(id, out var it))
                {
                    it.state = "Done"; it.ok = ok; it.pct = 100; it.bps = 0;
                    MoveRef(id, _qQueued, _qDone);
                    MoveRef(id, _qWorking, _qDone);
                }
            }
        }

        // Clear everything (optional)
        public static void Reset()
        {
            lock (_lock) { _items.Clear(); _qQueued.Clear(); _qWorking.Clear(); _qDone.Clear(); }
        }

        // Snapshot for /api/queue
        public static object Snapshot()
        {
            lock (_lock)
            {
                QItem[] Map(LinkedList<string> ll)
                {
                    var list = new List<QItem>(ll.Count);
                    foreach (var id in ll)
                        if (_items.TryGetValue(id, out var it)) list.Add(it);
                    return list.ToArray();
                }
                return new
                {
                    queued = Map(_qQueued),
                    working = Map(_qWorking),
                    done = Map(_qDone)
                };
            }
        }

        // helper: move id between lists
        private static void MoveRef(string id, LinkedList<string> from, LinkedList<string> to)
        {
            for (var n = from.First; n != null; n = n.Next)
            {
                if (n.Value == id) { from.Remove(n); break; }
            }
            // ensure not already in 'to'
            for (var n = to.First; n != null; n = n.Next)
                if (n.Value == id) return;
            to.AddLast(id);
        }
    }
}
