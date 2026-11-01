using System.Net;
using System.Security.Cryptography;
using System.Text;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

internal static class IdentityTestKey
{
    public static readonly string PrivateKeyPem = Generate();
    private static string Generate()
    {
        using var key = RSA.Create(2048);
        return key.ExportPkcs8PrivateKeyPem();
    }
}

public sealed class AgentIdentitySigningTests
{
    [Theory]
    [InlineData("https://PRIMARY.example:443", "primary.example", AgentProducts.Cerberus)]
    [InlineData("https://SECONDARY.example:8443", "secondary.example:8443", AgentProducts.Secondary)]
    [InlineData("http://localhost:80", "localhost", AgentProducts.Cerberus)]
    public async Task RefreshSignsExactBodyWithBothSignaturesAndNoBearer(string url, string authority, string product)
    {
        var store = new SigningStore(url, product);
        var handler = new VerifyHandler(authority);
        using var http = new HttpClient(handler) { BaseAddress = new Uri(url) };
        http.DefaultRequestHeaders.Authorization = new("Bearer", "must-not-be-sent");
        var manager = new AgentTokenManager(http, store);
        Assert.Equal("test-access", await manager.GetAccessTokenAsync(default));
        Assert.Equal(1, handler.Calls);
    }

    [Theory]
    [InlineData("https://PRIMARY.example:443", "primary.example")]
    [InlineData("https://SECONDARY.example:9443", "secondary.example:9443")]
    public void SharedSigningHeadersBindGetEmptyBodyToActualTarget(string url, string authority)
    {
        using var signer = new RequestSigner(IdentityTestKey.PrivateKeyPem);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/agents/identity/wakeup");
        AgentRequestSigning.AddHeaders(request, [], "identity", new Uri(url), signer);
        Verify(request, [], authority);
    }

    internal static void Verify(HttpRequestMessage request, byte[] body, string authority)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(IdentityTestKey.PrivateKeyPem);
        var hash = Convert.ToBase64String(SHA256.HashData(body));
        Assert.Equal(hash, request.Headers.GetValues("X-Body-Hash").Single());
        var canonical = $"v1:{request.Method.Method}:{(request.RequestUri!.IsAbsoluteUri ? request.RequestUri.AbsolutePath : request.RequestUri.OriginalString)}:" +
            $"{request.Headers.GetValues("X-Nonce").Single()}:{request.Headers.GetValues("X-Timestamp").Single()}:{hash}";
        Assert.True(rsa.VerifyData(Encoding.UTF8.GetBytes(canonical), Convert.FromBase64String(request.Headers.GetValues("X-Signature").Single()),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.True(rsa.VerifyData(Encoding.UTF8.GetBytes($"cerberus-agent-sig-v2\n{canonical}\n{authority}"),
            Convert.FromBase64String(request.Headers.GetValues("X-Signature-V2").Single()), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    private sealed class SigningStore(string url, string product) : ISecretStore
    {
        public Task<(AgentIdentity, string, string, string, string?, string?)> LoadAsync(CancellationToken ct)
            => Task.FromResult<(AgentIdentity, string, string, string, string?, string?)>((new("identity", "tenant", product),
                "test-refresh", IdentityTestKey.PrivateKeyPem, url, null, null));
        public Task SaveAsync(AgentIdentity id, string refresh, string key, string backend, string? login, string? auth, CancellationToken ct)
            => Task.CompletedTask;
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class VerifyHandler(string authority) : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            Assert.Null(request.Headers.Authorization);
            Assert.Equal("/api/v1/agents/token", request.RequestUri!.AbsolutePath);
            Verify(request, await request.Content!.ReadAsByteArrayAsync(ct), authority);
            return new(HttpStatusCode.OK) { Content = new StringContent("""{"access_token":"test-access","expires_in":900}""") };
        }
    }
}
