using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Diagnostics;

internal sealed class DiagnosticBundleCollectCommandHandler : ICommandHandler
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);
    private readonly AgentDiagnosticBundleUploader _uploader;

    public DiagnosticBundleCollectCommandHandler(AgentDiagnosticBundleUploader uploader)
    {
        _uploader = uploader;
    }

    public string Type => AgentDiagnosticBundleUploader.CommandType;

    public async Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
    {
        var payload = ParsePayload(command.Payload);
        var source = ReadString(payload, "source") == "scheduled" ? "scheduled" : "manual";
        var context = new AgentDiagnosticRequestContext(
            Source: source,
            RequestedBy: ReadString(payload, "requested_by"),
            RequestCommandId: command.Id,
            Reason: ReadString(payload, "reason"));
        var ack = await _uploader.UploadAsync(context, ct).ConfigureAwait(false);
        return new CommandResult(
            Status: "DONE",
            ExitCode: 0,
            Stdout: null,
            Stderr: null,
            PostVerify: new
            {
                code = "diagnostic_bundle_uploaded",
                bundle_id = ack.BundleId,
                upload_status = ack.Status,
                source,
            });
    }

    private static Dictionary<string, JsonElement> ParsePayload(object payload)
    {
        var json = JsonSerializer.Serialize(payload, JsonOpts);
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
            return new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        return doc.RootElement
            .EnumerateObject()
            .ToDictionary(p => p.Name, p => p.Value.Clone(), StringComparer.Ordinal);
    }

    private static string? ReadString(IReadOnlyDictionary<string, JsonElement> payload, string key)
    {
        if (!payload.TryGetValue(key, out var value))
            return null;
        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
    }
}
