using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Channels;

public sealed class LogBus
{
    private readonly Channel<string> _ch = Channel.CreateUnbounded<string>();
    private readonly LinkedList<string> _ring = new();
    private const int MAX = 200;

    public void Publish(string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return;
        lock (_ring) { _ring.AddLast(line); while (_ring.Count > MAX) _ring.RemoveFirst(); }
        _ch.Writer.TryWrite(line);
    }

    public string[] Tail() { lock (_ring) return _ring.ToArray(); }

    public async IAsyncEnumerable<string> Stream([EnumeratorCancellation] CancellationToken ct)
    {
        while (await _ch.Reader.WaitToReadAsync(ct))
            while (_ch.Reader.TryRead(out var l)) yield return l;
    }
}
