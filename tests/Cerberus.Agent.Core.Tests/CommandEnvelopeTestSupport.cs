using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Hand-written clock: only <see cref="Advance"/> moves it and fires due timers.</summary>
internal sealed class FakeTime : TimeProvider
{
    private readonly object _gate = new();
    private readonly List<FakeTimer> _timers = new();
    private DateTimeOffset _now;

    public FakeTime(long unixSeconds) => _now = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override DateTimeOffset GetUtcNow()
    {
        lock (_gate)
            return _now;
    }

    public override long GetTimestamp()
    {
        lock (_gate)
            return _now.Ticks;
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new FakeTimer(this, callback, state);
        timer.Change(dueTime, period);
        lock (_gate)
            _timers.Add(timer);
        return timer;
    }

    public void Advance(TimeSpan by)
    {
        List<FakeTimer> due;
        lock (_gate)
        {
            _now += by;
            due = _timers.Where(t => t.IsDue(_now)).ToList();
        }

        foreach (var timer in due)
            timer.Fire(this);
    }

    internal DateTimeOffset Now => GetUtcNow();

    private sealed class FakeTimer : ITimer
    {
        private readonly FakeTime _owner;
        private readonly TimerCallback _callback;
        private readonly object? _state;
        private DateTimeOffset? _due;
        private TimeSpan _period = Timeout.InfiniteTimeSpan;
        private bool _disposed;

        public FakeTimer(FakeTime owner, TimerCallback callback, object? state)
            => (_owner, _callback, _state) = (owner, callback, state);

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            _due = dueTime == Timeout.InfiniteTimeSpan ? null : _owner.Now + dueTime;
            _period = period;
            return true;
        }

        public bool IsDue(DateTimeOffset now) => !_disposed && _due is { } due && now >= due;

        public void Fire(FakeTime owner)
        {
            _due = _period == Timeout.InfiniteTimeSpan || _period == TimeSpan.Zero ? null : owner.Now + _period;
            _callback(_state);
        }

        public void Dispose() => _disposed = true;

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

internal sealed record BackendRequest(string Path, byte[] Body)
{
    public string Leaf => Path[(Path.LastIndexOf('/') + 1)..];

    public string CommandId => Path.Split('/')[^2];

    public JsonElement Json => JsonDocument.Parse(Body).RootElement.Clone();
}

/// <summary>Records every request body byte-for-byte and answers with a scripted status.</summary>
internal sealed class FakeBackend : HttpMessageHandler
{
    private readonly object _gate = new();
    private readonly List<BackendRequest> _requests = new();

    public Func<BackendRequest, CancellationToken, Task<HttpStatusCode>> Respond { get; set; }
        = (_, _) => Task.FromResult(HttpStatusCode.OK);

    public IReadOnlyList<BackendRequest> Requests
    {
        get
        {
            lock (_gate)
                return _requests.ToArray();
        }
    }

    public IReadOnlyList<BackendRequest> Acks => Requests.Where(r => r.Leaf == "ack").ToArray();

    public IReadOnlyList<BackendRequest> Results => Requests.Where(r => r.Leaf == "result").ToArray();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? Array.Empty<byte>() : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        var recorded = new BackendRequest(request.RequestUri!.AbsolutePath, body);
        lock (_gate)
            _requests.Add(recorded);
        var status = await Respond(recorded, cancellationToken);
        return new HttpResponseMessage(status) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
    }
}

internal sealed class FakeCommandHandler : ICommandHandler
{
    private int _calls;

    public FakeCommandHandler(string type) => Type = type;

    public string Type { get; }

    public int Calls => Volatile.Read(ref _calls);

    public Func<AgentCommand, CancellationToken, Task<CommandResult>>? Body { get; set; }

    public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public TaskCompletionSource Gate { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Makes every call wait on <see cref="Gate"/> (120 s safety bound, cancellable).</summary>
    public FakeCommandHandler Block()
    {
        Body = async (_, ct) =>
        {
            Started.TrySetResult();
            await Gate.Task.WaitAsync(TimeSpan.FromSeconds(120), ct);
            return Done();
        };
        return this;
    }

    public async Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
    {
        Interlocked.Increment(ref _calls);
        return Body is null ? Done() : await Body(command, ct);
    }

    internal static CommandResult Done() => new("DONE", 0, null, null, new { schema = "test.v1" });
}

/// <summary>Ephemeral signing key held in memory only.</summary>
internal sealed class TestSigner
{
    private static readonly Lazy<TestSigner> Shared = new(() => new TestSigner(2048));

    private readonly RSA _rsa;

    public TestSigner(int bits)
    {
        _rsa = RSA.Create(bits);
        var spki = _rsa.ExportSubjectPublicKeyInfo();
        KeyId = AgentProfileMetadata.ComputeKeyId(spki);
        Anchor = new CommandTrustAnchor(KeyId, spki);
    }

    public static TestSigner Default => Shared.Value;

    public string KeyId { get; }

    public CommandTrustAnchor Anchor { get; }

    public byte[] Sign(byte[] data) => _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
}

/// <summary>Everything a test may change in a signed command before it is serialized.</summary>
internal sealed class EnvelopeParts
{
    public string Id { get; set; } = "";
    public string AgentId { get; set; } = "";
    public string Type { get; set; } = "ping";
    public long Issued { get; set; }
    public long Expires { get; set; }
    public string Nonce { get; set; } = "";
    public string? SignedKeyId { get; set; }
    public string Delegation { get; set; } = "";
    public string PayloadJson { get; set; } = "{}";
    public TestSigner? SignWith { get; set; }
    public string? OuterType { get; set; }
    public string? WireKeyId { get; set; }
    public int WireVersion { get; set; } = 1;
    public string? WireDelegation { get; set; }
    public string? WireSignedBytesB64 { get; set; }
}

internal static class StoreFileWriter
{
    public static CommandReplayRecord Record(
        string agentId,
        string id,
        string nonce,
        string state = EnvelopeRecordStates.Done,
        long issuedAt = 1790000000,
        long expiresAt = 1790000120,
        string? resultB64 = null,
        bool submitted = true)
        => new(agentId, id, new string('a', 64), nonce, "ping", issuedAt, expiresAt, state, resultB64,
            resultB64 is null ? null : new string('b', 64), submitted);

    public static void Write(string path, long resetAt, IEnumerable<CommandReplayRecord> records)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["schema"] = "cerberus.command-envelopes.v1",
            ["reset_at"] = resetAt,
            ["records"] = records.ToList(),
        }));
    }
}

internal static class Wait
{
    /// <summary>Polls for a condition produced by the background queue; the deadline is a safety bound only.</summary>
    public static async Task UntilAsync(Func<bool> condition, string what)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
                throw new Xunit.Sdk.XunitException($"Timed out waiting for: {what}");
            await Task.Delay(5);
        }
    }
}

internal sealed class EnvelopeHarnessOptions
{
    public string AgentId { get; set; } = EnvelopeHarness.DefaultAgent;
    public long NowUnix { get; set; } = EnvelopeHarness.T0;
    public IReadOnlyList<CommandTrustAnchor>? Anchors { get; set; }
    public bool StartQueue { get; set; } = true;
    public string? StorePath { get; set; }
    public string? CorruptStoreContent { get; set; }
    public IHeartbeatCommandProcessor? Legacy { get; set; }
    public Func<AgentApiClient, IHeartbeatCommandProcessor>? LegacyFactory { get; set; }
}

internal sealed class EnvelopeHarness : IAsyncDisposable
{
    public const string DefaultAgent = "agent-0001";
    public const long T0 = 1790000000;
    private static readonly IReadOnlySet<string> Allowed =
        new HashSet<string>(StringComparer.Ordinal) { "ping", "collect_facts", "agent_state" };

    private readonly HttpClient _http;
    private readonly EnvelopeHarnessOptions _options;
    private readonly string _dir;
    private int _counter;

    private EnvelopeHarness(EnvelopeHarnessOptions options)
    {
        _options = options;
        AgentId = options.AgentId;
        Time = new FakeTime(options.NowUnix);
        _dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        StorePath = options.StorePath ?? Path.Combine(_dir, CommandReplayStore.FileName);
        if (options.CorruptStoreContent is { } corrupt)
        {
            Directory.CreateDirectory(_dir);
            File.WriteAllText(StorePath, corrupt);
        }

        _http = new HttpClient(Backend) { BaseAddress = new Uri("http://backend.test") };
        Api = new AgentApiClient(_http, new EnvSecretStore(() => AgentId), new EnvTokenManager(), new EnvRequestSigner());
        Ping = new FakeCommandHandler("ping");
        Facts = new FakeCommandHandler("collect_facts");
        State = new FakeCommandHandler("agent_state");
        Build();
    }

    public AgentApiClient Api { get; }
    public FakeBackend Backend { get; } = new();
    public FakeTime Time { get; }
    public string AgentId { get; set; }
    public bool Quarantined { get; set; }
    public string StorePath { get; }
    public FakeCommandHandler Ping { get; }
    public FakeCommandHandler Facts { get; }
    public FakeCommandHandler State { get; }
    public CommandReplayStore Store { get; private set; } = null!;
    public EnvelopeExecutionQueue Queue { get; private set; } = null!;
    public EnvelopeCommandProcessor Processor { get; private set; } = null!;
    public TestSigner Signer { get; set; } = TestSigner.Default;

    public static EnvelopeHarness Create(Action<EnvelopeHarnessOptions>? configure = null)
    {
        var options = new EnvelopeHarnessOptions();
        configure?.Invoke(options);
        return new EnvelopeHarness(options);
    }

    /// <summary>Simulates a process restart: queue stopped, store and processor rebuilt from disk.</summary>
    public async Task RestartAsync()
    {
        await Queue.StopAsync();
        Build();
    }

    private void Build()
    {
        Store = new CommandReplayStore(StorePath, Time);
        Queue = new EnvelopeExecutionQueue(
            Api, Store, new ICommandHandler[] { Ping, Facts, State }, _ => Task.FromResult(AgentId), () => Quarantined, Time);
        var anchors = _options.Anchors ?? new[] { TestSigner.Default.Anchor };
        Processor = new EnvelopeCommandProcessor(Api, anchors, Queue, Allowed, legacy: _options.Legacy ?? _options.LegacyFactory?.Invoke(Api));
        if (_options.StartQueue)
            Queue.Start();
    }

    public AgentCommand Cmd(Action<EnvelopeParts>? edit = null)
    {
        var n = Interlocked.Increment(ref _counter);
        var p = new EnvelopeParts
        {
            Id = $"00000000-0000-4000-8000-{n:D12}",
            AgentId = AgentId,
            Issued = Time.GetUtcNow().ToUnixTimeSeconds(),
            Nonce = $"nonce-{n}",
        };
        p.Expires = p.Issued + 120;
        edit?.Invoke(p);

        var keyId = p.SignedKeyId ?? Signer.KeyId;
        var text = string.Join("\n",
            "cerberus-agent-envelope.v1", $"id={p.Id}", $"agent_id={p.AgentId}", $"type={p.Type}",
            $"issued_at={p.Issued}", $"expires_at={p.Expires}", $"nonce={p.Nonce}", $"key_id={keyId}",
            "alg=rsa-pkcs1v15-sha256", $"delegation={p.Delegation}",
            $"payload={Convert.ToBase64String(Encoding.UTF8.GetBytes(p.PayloadJson))}");
        var signedBytes = Encoding.ASCII.GetBytes(text);
        var signature = (p.SignWith ?? Signer).Sign(signedBytes);
        var envelope = new JsonObject
        {
            ["v"] = p.WireVersion,
            ["alg"] = "rsa-pkcs1v15-sha256",
            ["key_id"] = p.WireKeyId ?? Signer.KeyId,
            ["delegation"] = p.WireDelegation,
            ["signed_bytes"] = p.WireSignedBytesB64 ?? Convert.ToBase64String(signedBytes),
            ["signature"] = Convert.ToBase64String(signature),
        };
        var entry = new JsonObject
        {
            ["id"] = p.Id,
            ["type"] = p.OuterType ?? p.Type,
            ["idempotency_key"] = p.Id,
            ["payload"] = new JsonObject(),
            ["envelope"] = envelope,
        };
        return JsonSerializer.Deserialize<AgentCommand>(entry.ToJsonString())!;
    }

    public static string ShaOf(AgentCommand command)
        => CommandEnvelope.Sha256Hex(Convert.FromBase64String(command.Envelope!.Value.GetProperty("signed_bytes").GetString()!));

    public Task Process(params AgentCommand[] commands)
        => Processor.ProcessAsync(commands, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(60));

    public CommandReplayRecord? Record(AgentCommand command) => Store.Find(AgentId, command.Id);

    public long Rejections(string code)
        => Processor.RejectionCounts.TryGetValue(code, out var count) ? count : 0;

    public async ValueTask DisposeAsync()
    {
        await Queue.StopAsync();
        _http.Dispose();
        try
        {
            if (Directory.Exists(_dir))
                Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup of the per-test temp directory.
        }
    }

    private sealed class EnvSecretStore(Func<string> agentId) : ISecretStore
    {
        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl,
            string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct) => Task.CompletedTask;

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => Task.FromResult((new AgentIdentity(agentId(), "t1"), "refresh", "private", "http://backend.test",
                (string?)null, (string?)null));

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class EnvTokenManager : ITokenManager
    {
        public Task<string> GetAccessTokenAsync(CancellationToken ct) => Task.FromResult("token");

        public Task RefreshAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class EnvRequestSigner : IRequestSigner
    {
        public string ComputeBodyHash(byte[] bodyBytes) => Convert.ToHexString(SHA256.HashData(bodyBytes)).ToLowerInvariant();

        public string CanonicalString(string method, string path, string nonce, long timestamp, string bodyHash)
            => $"{method}:{path}:{nonce}:{timestamp}:{bodyHash}";

        public string Sign(string canonical) => "signature";
    }
}
