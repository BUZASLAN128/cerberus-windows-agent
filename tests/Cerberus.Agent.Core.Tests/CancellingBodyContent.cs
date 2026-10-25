using System.Net;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Response body whose read cancels the source and then observes the cancellation.</summary>
internal sealed class CancellingBodyContent(CancellationTokenSource cts) : HttpContent
{
    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => Task.CompletedTask;
    protected override bool TryComputeLength(out long length) { length = -1; return false; }
    protected override Stream CreateContentReadStream(CancellationToken cancellationToken) => new CancellingStream(cts);
    protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(new CancellingStream(cts));
}

internal sealed class CancellingStream(CancellationTokenSource cts) : Stream
{
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cts.Cancel();
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(0);
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
