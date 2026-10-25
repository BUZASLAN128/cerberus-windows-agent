using System.Net;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentApiClientTelemetryTests
{
    private static AgentBuildMetadata Metadata() => new(
        AgentVersion: "1.2.3",
        BuildId: "build-1",
        BuildChannel: "dev",
        BootId: "boot-1",
        SupportedSchemaVersions: AgentSchemaVersions.All);

    private static string HeartbeatResponseJson() =>
        """
        {
          "pending_commands": [],
          "next_poll_seconds": 60,
          "server_time": 0,
          "server_time_utc": "2026-06-01T00:00:00Z",
          "command_batch_size": 0,
          "next_snapshot_seconds": 300,
          "config_version": "agent-config.v1",
          "lifecycle_state": "connected",
          "registration_state": "claimed",
          "claim_required": false,
          "manifest_version": null,
          "managed_account_manifest_hash": null,
          "manifest_fresh_until": null,
          "require_manifest_before_unlock": true,
          "agent_status": "connected",
          "version_policy": null,
          "update": null,
          "revoke": null,
          "quarantine": null
        }
        """;

    private static string PadToLength(string value, int length)
    {
        var current = Encoding.UTF8.GetByteCount(value);
        Assert.True(current <= length);
        return value + new string(' ', length - current);
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        private readonly string _responseBody;

        public CaptureHandler(string? responseBody = null)
        {
            _responseBody = responseBody
                ?? """{"status":"accepted","accepted":1,"ignored":0,"reason":null,"changed_sections":["identity"]}""";
        }

        public HttpRequestMessage? CapturedRequest { get; private set; }
        public string? CapturedBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CapturedRequest = request;
            CapturedBody = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    _responseBody,
                    Encoding.UTF8,
                    "application/json"),
            };
        }
    }

    private sealed class RequestSequenceHandler : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];
        public List<string> Bodies { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);
            Bodies.Add(request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken));
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json"),
            };
        }
    }

    // Far above any scheduling delay; only reached if the client stops honoring its deadline.
    private static readonly TimeSpan HangGuard = TimeSpan.FromSeconds(30);

    private sealed class FailureHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly HttpContent _content;

        public FailureHandler(HttpStatusCode statusCode, HttpContent content, bool headersArriveAfterDeadline = false)
        {
            _statusCode = statusCode;
            _content = content;
            _headersArriveAfterDeadline = headersArriveAfterDeadline;
        }

        private readonly bool _headersArriveAfterDeadline;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_headersArriveAfterDeadline)
            {
                // A transport that ignores cancellation: the headers come back only once the deadline has fired.
                try
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                }

                // HttpClient's timeout and the caller's deadline are separate timers with no guaranteed order;
                // wait out any skew so the deadline has fired before the headers are returned.
                await Task.Delay(TimeSpan.FromMilliseconds(500), CancellationToken.None);
            }

            return new HttpResponseMessage(_statusCode) { Content = _content };
        }
    }

    private sealed class StallingContent : HttpContent
    {
        private readonly byte[] _prefix;

        public StallingContent(string? prefix = null) => _prefix = Encoding.UTF8.GetBytes(prefix ?? string.Empty);

        /// <summary>A body read began with a token that was not yet cancelled.</summary>
        public bool ReadStartedWithLiveToken { get; private set; }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new NotSupportedException();
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(new StallingStream(this, _prefix));
        protected override bool TryComputeLength(out long length) { length = 0; return false; }

        private sealed class StallingStream : Stream
        {
            private readonly StallingContent _owner;
            private readonly byte[] _prefix;
            private int _offset;

            public StallingStream(StallingContent owner, byte[] prefix)
            {
                _owner = owner;
                _prefix = prefix;
            }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => 0;
            public override long Position { get => 0; set => throw new NotSupportedException(); }
            public override void Flush() => throw new NotSupportedException();
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (_offset < _prefix.Length)
                {
                    var count = Math.Min(buffer.Length, _prefix.Length - _offset);
                    _prefix.AsSpan(_offset, count).CopyTo(buffer.Span);
                    _offset += count;
                    return count;
                }

                _owner.ReadStartedWithLiveToken |= !cancellationToken.IsCancellationRequested;
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return 0;
            }
        }
    }

    private sealed class TransientThenOkHandler : HttpMessageHandler
    {
        private readonly Queue<string> _expectedPaths;
        private readonly Queue<string> _okBodies;

        public Dictionary<string, int> AttemptsByPath { get; } = new(StringComparer.Ordinal);

        public TransientThenOkHandler(IEnumerable<string> expectedPaths, IEnumerable<string> okBodies)
        {
            _expectedPaths = new Queue<string>(expectedPaths);
            _okBodies = new Queue<string>(okBodies);
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            AttemptsByPath.TryGetValue(path, out var attempts);
            AttemptsByPath[path] = attempts + 1;

            if (attempts == 0)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
                {
                    Content = new StringContent("""{"detail":"unavailable"}""", Encoding.UTF8, "application/json"),
                });
            }

            Assert.Equal(_expectedPaths.Dequeue(), path);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_okBodies.Dequeue(), Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed class AlwaysUnavailableHandler : HttpMessageHandler
    {
        public Dictionary<string, int> AttemptsByPath { get; } = new(StringComparer.Ordinal);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            AttemptsByPath.TryGetValue(path, out var attempts);
            AttemptsByPath[path] = attempts + 1;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                Content = new StringContent("""{"detail":"unavailable"}""", Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed class UnauthorizedThenOkHandler : HttpMessageHandler
    {
        private readonly string _okResponseBody;

        public List<string?> CapturedAuthorizations { get; } = [];
        public List<string> CapturedNonces { get; } = [];
        public List<string?> CapturedBodies { get; } = [];

        public UnauthorizedThenOkHandler(string okResponseBody)
        {
            _okResponseBody = okResponseBody;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CapturedAuthorizations.Add(request.Headers.Authorization?.ToString());
            CapturedNonces.Add(request.Headers.GetValues("X-Nonce").Single());
            CapturedBodies.Add(request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken));
            if (CapturedAuthorizations.Count == 1)
            {
                return new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("""{"detail":"expired"}""", Encoding.UTF8, "application/json"),
                };
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_okResponseBody, Encoding.UTF8, "application/json"),
            };
        }
    }

    private sealed class UnauthorizedPreauthThenOkHandler : HttpMessageHandler
    {
        private readonly DisposableContent _firstContent;
        public int Attempts { get; private set; }

        public UnauthorizedPreauthThenOkHandler(DisposableContent firstContent) => _firstContent = firstContent;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Attempts++;
            return Task.FromResult(Attempts == 1
                ? new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = _firstContent }
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"tailscale_login_server\":\"https://login.test\",\"tailscale_authkey\":\"tskey-test\"}", Encoding.UTF8, "application/json"),
                });
        }
    }

    private sealed class DisposableContent : StringContent
    {
        public bool Disposed { get; private set; }
        public DisposableContent(string content) : base(content, Encoding.UTF8, "application/json") { }
        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    private sealed class StaticSecretStore : ISecretStore
    {
        public Task SaveAsync(
            AgentIdentity identity,
            string refreshToken,
            string privateKeyPem,
            string backendUrl,
            string? tailscaleLoginServer,
            string? tailscaleAuthkey,
            CancellationToken ct) => Task.CompletedTask;

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
        {
            return Task.FromResult((
                new AgentIdentity("a1", "t1"),
                "refresh",
                "private",
                "http://backend.test",
                (string?)null,
                (string?)null));
        }

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class StaticTokenManager : ITokenManager
    {
        public Task<string> GetAccessTokenAsync(CancellationToken ct) => Task.FromResult("token");
        public Task RefreshAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class RefreshAwareTokenManager : ITokenManager
    {
        public int RefreshCount { get; private set; }

        public Task<string> GetAccessTokenAsync(CancellationToken ct) =>
            Task.FromResult(RefreshCount == 0 ? "stale-token" : "fresh-token");

        public Task RefreshAsync(CancellationToken ct)
        {
            RefreshCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class StaticSigner : IRequestSigner
    {
        public string ComputeBodyHash(byte[] bodyBytes) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bodyBytes)).ToLowerInvariant();
        public string CanonicalString(string method, string path, string nonce, long timestamp, string bodyHash) => $"{method}:{path}:{nonce}:{timestamp}:{bodyHash}";
        public string Sign(string canonical) => "signature";
    }
}
