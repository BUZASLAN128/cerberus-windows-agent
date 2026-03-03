namespace Cerberus.Agent.Core;

public static class CasdoorTokenResolver
{
    public static async Task<string> ResolveAsync(string? envToken, string? tokenFilePath, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(tokenFilePath))
        {
            if (!File.Exists(tokenFilePath))
                throw new FileNotFoundException("Casdoor token file not found.", tokenFilePath);

            var token = (await File.ReadAllTextAsync(tokenFilePath, ct)).Trim();
            if (token.Length == 0)
                throw new InvalidOperationException("Casdoor token file was empty.");
            return token;
        }

        if (!string.IsNullOrWhiteSpace(envToken))
            return envToken.Trim();

        throw new InvalidOperationException(
            "Casdoor token missing. Provide env var CERBERUS_CASDOOR_TOKEN or a token file.");
    }
}

