using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateTransferTests
{
    [Fact]
    public void SignedLengthHasNoIndependentArtifactCap()
    {
        var manifest = Manifest(201L * 1024 * 1024);
        Assert.Equal(manifest.ArtifactLength, AgentUpdateArtifactTransfer.ExpectedLength(manifest));
        AgentUpdateArtifactTransfer.ValidateFileLength(manifest, manifest.ArtifactLength!.Value);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0L)]
    [InlineData(-1L)]
    public void MissingOrNonpositiveSignedLengthFailsClosed(long? length)
        => Assert.Throws<InvalidOperationException>(() => AgentUpdateArtifactTransfer.ExpectedLength(Manifest(length)));

    [Theory]
    [InlineData(0L)]
    [InlineData(2L)]
    [InlineData(4L)]
    public void FinalFileGateRequiresExactSignedLength(long length)
        => Assert.Throws<InvalidOperationException>(() => AgentUpdateArtifactTransfer.ValidateFileLength(Manifest(3), length));

    [Theory]
    [InlineData(2UL, 0UL, false)]
    [InlineData(4UL, 0UL, false)]
    [InlineData(3UL, 4UL, false)]
    [InlineData(3UL, 2UL, true)]
    [InlineData(ulong.MaxValue, 3UL, true)]
    public void BitsRejectsMismatchingCountersAtFirstObservation(ulong total, ulong transferred, bool complete)
        => Assert.Throws<InvalidOperationException>(() => AgentUpdateArtifactTransfer.ValidateBitsProgress(3, total, transferred, complete));

    [Fact]
    public void BitsAllowsUnknownTotalOnlyDuringTransferAndRequiresExactCompletion()
    {
        AgentUpdateArtifactTransfer.ValidateBitsProgress(3, ulong.MaxValue, 2, false);
        AgentUpdateArtifactTransfer.ValidateBitsProgress(3, 3, 3, true);
    }

    [Fact]
    public void DiskThresholdUsesDestinationVolumeAndLengthPlusHeadroom()
    {
        const long length = 2_000_000_000;
        Assert.Equal(2_100_000_000, AgentUpdateArtifactTransfer.RequiredFreeSpace(length));
        var destination = Path.Combine(Path.GetTempPath(), "agent.part");
        var required = AgentUpdateArtifactTransfer.RequiredFreeSpace(length);
        AgentUpdateArtifactTransfer.EnsureDiskSpace(destination, length, volume =>
        {
            Assert.Equal(Path.GetPathRoot(Path.GetFullPath(destination)), volume);
            return required;
        });
        Assert.Throws<InvalidOperationException>(() =>
            AgentUpdateArtifactTransfer.EnsureDiskSpace(destination, length, _ => required - 1));
        Assert.Throws<InvalidOperationException>(() =>
            AgentUpdateArtifactTransfer.EnsureDiskSpace(destination, length, _ => throw new IOException("probe failed")));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateArtifactTransfer.RequiredFreeSpace(long.MaxValue));
    }

    [Fact]
    public async Task ChunkedExactLengthStagesAndReusesWithoutAnotherDiskReservation()
    {
        using var fixture = new TransferFixture([1, 2, 3]);
        var plan = await fixture.Stage();
        Assert.NotNull(plan);
        Assert.Equal(new byte[] { 1, 2, 3 }, await File.ReadAllBytesAsync(plan.ArtifactPath));
        fixture.AvailableBytes = 0;
        Assert.Equal(plan.AttemptId, (await fixture.Stage())!.AttemptId);
        Assert.Equal(1, fixture.ArtifactRequests);
    }

    [Fact]
    public async Task HeaderMismatchIsRejectedBeforeReadingOrCreatingArtifact()
    {
        using var fixture = new TransferFixture([1, 2, 3], declaredLength: 4);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(fixture.Stage);
        Assert.Contains("Content-Length", error.Message);
        Assert.Equal(0, fixture.Body.BytesRead);
        Assert.Empty(Directory.GetFiles(fixture.Root, "*.part", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task ChunkedOverflowStopsAfterFirstExtraByteAndRemovesPartial()
    {
        using var fixture = new TransferFixture(new byte[1000]);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(fixture.Stage);
        Assert.Contains("length exceeds", error.Message);
        Assert.Equal(4, fixture.Body.BytesRead);
        Assert.Empty(Directory.GetFiles(fixture.Root, "*.part", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task ShortEofIsRejectedAndPartialIsRemoved()
    {
        using var fixture = new TransferFixture([1, 2]);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(fixture.Stage);
        Assert.Contains("length", error.Message);
        Assert.Empty(Directory.GetFiles(fixture.Root, "*.part", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task EqualLengthStillRequiresSignedChecksum()
    {
        using var fixture = new TransferFixture([3, 2, 1]);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(fixture.Stage);
        Assert.Contains("checksum", error.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DiskFailurePreventsArtifactRequest(bool probeFailure)
    {
        using var fixture = new TransferFixture([1, 2, 3]);
        fixture.AvailableBytes = 0;
        fixture.DiskProbeFailure = probeFailure;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(fixture.Stage);
        Assert.Contains("disk space", error.Message);
        Assert.Equal(0, fixture.ArtifactRequests);
        Assert.Empty(Directory.GetFiles(fixture.Root, "*.part", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task ReusedArtifactMustStillMatchSignedLengthAndHash()
    {
        using var fixture = new TransferFixture([1, 2, 3]);
        var plan = (await fixture.Stage())!;
        await File.WriteAllBytesAsync(plan.ArtifactPath, new byte[] { 3, 2, 1 });
        var error = await Assert.ThrowsAsync<InvalidOperationException>(fixture.Stage);
        Assert.Contains("checksum", error.Message);
        Assert.Equal(1, fixture.ArtifactRequests);
    }

    [Fact]
    public async Task LegacyManifestCanBeCheckedButCannotStartAnUnboundedDownload()
    {
        using var fixture = new TransferFixture([1, 2, 3], legacy: true);
        Assert.True((await fixture.Stager.CheckAsync(TransferFixture.Signal, CancellationToken.None)).Available);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(fixture.Stage);
        Assert.Contains("positive signed artifact length", error.Message);
        Assert.Equal(0, fixture.ArtifactRequests);
    }

    private static AgentUpdateManifest Manifest(long? length) => new(
        "msi", "2.0.0", "dev", "https://releases.cerberus.local/agent.msi", new string('a', 64), "test",
        DateTimeOffset.UtcNow.AddMinutes(-1).ToString("O"), "agent.heartbeat.v1", false, "",
        SchemaVersion: AgentUpdateManifest.V2SchemaVersion, Sequence: 1,
        ExpiresAtUtc: DateTimeOffset.UtcNow.AddDays(1).ToString("O"), ArtifactLength: length,
        SignerKeyIdentity: "test-signer");

    private sealed class TransferFixture : IDisposable
    {
        public static readonly AgentUpdateSignal Signal = new(true, false,
            "https://releases.cerberus.local/manifest.json", "test", "dev");
        private readonly RSA _rsa = RSA.Create(2048);
        private readonly HttpClient _http;
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "cerberus-update-test-" + Guid.NewGuid().ToString("N"));
        public AgentUpdateStager Stager { get; }
        public TrackingStream Body { get; }
        public long AvailableBytes { get; set; } = long.MaxValue;
        public bool DiskProbeFailure { get; set; }
        public int ArtifactRequests { get; private set; }

        public TransferFixture(byte[] actual, long? declaredLength = null, bool legacy = false)
        {
            Body = new TrackingStream(actual);
            var unsigned = Manifest(3) with { Sha256 = Convert.ToHexString(SHA256.HashData(new byte[] { 1, 2, 3 })).ToLowerInvariant() };
            if (legacy) unsigned = unsigned with
            {
                SchemaVersion = AgentUpdateManifest.V1SchemaVersion, Sequence = 0,
                ArtifactLength = null, SignerKeyIdentity = null, ExpiresAtUtc = null,
            };
            var signature = _rsa.SignData(Encoding.UTF8.GetBytes(AgentUpdateManifestValidator.CanonicalPayload(unsigned)),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var json = JsonSerializer.Serialize(unsigned with { Signature = Convert.ToBase64String(signature) });
            _http = new HttpClient(new Handler(request =>
            {
                if (request.RequestUri!.AbsolutePath.EndsWith("manifest.json", StringComparison.Ordinal))
                    return new StringContent(json, Encoding.UTF8, "application/json");
                ArtifactRequests++;
                var content = new StreamContent(Body);
                if (declaredLength is not null) content.Headers.ContentLength = declaredLength;
                return content;
            }));
            Stager = new AgentUpdateStager(_http,
                new AgentUpdateTrust([_rsa.ExportSubjectPublicKeyInfoPem()], "dev", ["https://releases.cerberus.local/"], "1.0.0",
                    AllowedSignerKeyIdentity: legacy ? null : "test-signer", RequireManifestV2: !legacy),
                Root, null, _ => DiskProbeFailure ? throw new IOException("probe failed") : AvailableBytes);
        }

        public Task<AgentUpdatePlan?> Stage() => Stager.StageAsync(Signal, CancellationToken.None);
        public void Dispose()
        {
            _http.Dispose();
            Body.Dispose();
            _rsa.Dispose();
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
    }

    private sealed class Handler(Func<HttpRequestMessage, HttpContent> content) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content(request), RequestMessage = request });
    }

    private sealed class TrackingStream(byte[] data) : Stream
    {
        public int BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => BytesRead; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            var size = Math.Min(count, data.Length - BytesRead);
            data.AsSpan(BytesRead, size).CopyTo(buffer.AsSpan(offset, size));
            BytesRead += size;
            return size;
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            var size = Math.Min(buffer.Length, data.Length - BytesRead);
            data.AsMemory(BytesRead, size).CopyTo(buffer);
            BytesRead += size;
            return ValueTask.FromResult(size);
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
