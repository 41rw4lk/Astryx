using System;
using System.Collections.Generic;
using System.Threading.Channels;


namespace CMDownloaderUI
{
    internal static class LogTap
    {
        private static readonly object _lock = new();
        private static readonly Queue<string> _q = new(capacity: 2048);

        private const int MaxLines = 2048;

        // 👇 NEW: a list of live listeners for SSE
        private static readonly List<Channel<string>> _listeners = new();

        public static void Append(string line)
        {
            if (line == null) return;
            var msg = $"{DateTime.Now:HH:mm:ss} {line}";

            lock (_lock)
            {
                if (_q.Count >= MaxLines) _q.Dequeue();
                _q.Enqueue(msg);

                // broadcast to live listeners (best effort, non-blocking)
                foreach (var ch in _listeners.ToArray())
                {
                    try { ch.Writer.TryWrite(msg); } catch { }
                }
            }
        }

        public static string[] Tail(int lines = 500)
        {
            if (lines < 1) lines = 1;
            if (lines > MaxLines) lines = MaxLines;
            lock (_lock)
            {
                var arr = _q.ToArray();
                if (arr.Length <= lines) return arr;
                var start = arr.Length - lines;
                var result = new string[lines];
                Array.Copy(arr, start, result, 0, lines);
                return result;
            }
        }

        // 👇 NEW: subscribe/unsubscribe for SSE
        public static ChannelReader<string> Subscribe(out Channel<string> channel)
        {
            channel = Channel.CreateUnbounded<string>(new UnboundedChannelOptions
            {
                SingleReader = false,
                SingleWriter = false
            });
            lock (_lock) { _listeners.Add(channel); }
            return channel.Reader;
        }

        public static void Unsubscribe(Channel<string> channel)
        {
            lock (_lock) { _listeners.Remove(channel); }
            try { channel.Writer.TryComplete(); } catch { }
        }
    }

}
