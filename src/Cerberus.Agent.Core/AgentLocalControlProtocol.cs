using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

public sealed record AgentLocalControlRequest(string Operation, string? AttemptId = null)
{
    public string SchemaVersion { get; init; } = AgentLocalControlProtocol.SchemaVersion;
}

public sealed record AgentLocalControlResponse(
    bool Success,
    string Code,
    string? LifecycleState = null,
    string? UpdateState = null,
    string? AttemptId = null,
    string? CurrentVersion = null,
    string? TargetVersion = null,
    long? LifecycleGeneration = null);

/// <summary>One bounded request and response per local connection; no file, URL, executable or credential inputs.</summary>
public static class AgentLocalControlProtocol
{
    public const string SchemaVersion = "agent.local-control.v1";
    public const string PipeName = "CerberusAgent.Control.v1";
    public const int MaxFrameBytes = 16 * 1024;
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 4,
    };

    public static bool IsAllowed(AgentLocalControlRequest request, bool privileged)
    {
        if (request.SchemaVersion != SchemaVersion || string.IsNullOrEmpty(request.Operation))
            return false;
        if (request.Operation == "apply" && request.AttemptId is null)
            return false;
        if (request.AttemptId is not null &&
            (request.Operation != "apply" || !Guid.TryParseExact(request.AttemptId, "N", out _)))
            return false;
        return request.Operation is "status" or "check" or "apply" ||
            (privileged && request.Operation is "retry" or "enrollment-adopt" or "unregister");
    }

    public static async Task<T> ReadAsync<T>(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, ct).ConfigureAwait(false);
        var count = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (count is <= 0 or > MaxFrameBytes)
            throw new InvalidDataException("Invalid local control frame.");
        var bytes = new byte[count];
        await stream.ReadExactlyAsync(bytes, ct).ConfigureAwait(false);
        using (var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 }))
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("Invalid local control request.");
            var keys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in document.RootElement.EnumerateObject())
                if (!keys.Add(item.Name))
                    throw new InvalidDataException("Duplicate local control field.");
        }
        return JsonSerializer.Deserialize<T>(bytes, Options)
            ?? throw new InvalidDataException("Missing local control frame.");
    }

    public static async Task WriteAsync<T>(Stream stream, T value, CancellationToken ct)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, Options);
        if (bytes.Length > MaxFrameBytes)
            throw new InvalidDataException("Local control frame is too large.");
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, bytes.Length);
        await stream.WriteAsync(header, ct).ConfigureAwait(false);
        await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }
}
