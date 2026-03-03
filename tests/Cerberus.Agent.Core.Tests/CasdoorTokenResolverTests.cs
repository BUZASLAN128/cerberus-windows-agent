using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class CasdoorTokenResolverTests
{
    [Fact]
    public async Task ResolveAsync_PrefersFile_WhenProvided()
    {
        var tmp = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tmp, "  Bearer file-token  ");

            var token = await CasdoorTokenResolver.ResolveAsync(
                envToken: "Bearer env-token",
                tokenFilePath: tmp,
                ct: CancellationToken.None);

            Assert.Equal("Bearer file-token", token);
        }
        finally
        {
            try { File.Delete(tmp); } catch { }
        }
    }

    [Fact]
    public async Task ResolveAsync_UsesEnv_WhenFileNotProvided()
    {
        var token = await CasdoorTokenResolver.ResolveAsync(
            envToken: "  Bearer env-token  ",
            tokenFilePath: null,
            ct: CancellationToken.None);

        Assert.Equal("Bearer env-token", token);
    }
}

