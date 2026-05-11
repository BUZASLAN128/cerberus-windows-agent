using System.Text.Json;

namespace Cerberus.Agent.Core;

public static class GovernedWindowsMutationGuard
{
    private static readonly HashSet<string> AllowedTypes = new(StringComparer.Ordinal)
    {
        "windows.user.create",
        "windows.user.update",
        "windows.user.disable",
        "windows.group.update",
        "windows.service.configure",
        "windows.firewall.configure",
    };

    public static CommandResult ValidateOrDeny(AgentCommand command, bool enabled)
    {
        if (!AllowedTypes.Contains(command.Type))
            return Deny("unsupported_windows_mutation", $"Unsupported Windows mutation type: {command.Type}");
        if (!enabled)
            return Deny("windows_mutation_disabled", "Windows mutation commands are disabled by local agent policy.");
        if (!PayloadHasString(command.Payload, "approval_id"))
            return Deny("missing_approval_id", "Windows mutation command requires approval_id.");
        if (!PayloadHasString(command.Payload, "audit_correlation_id"))
            return Deny("missing_audit_correlation_id", "Windows mutation command requires audit_correlation_id.");
        return new CommandResult("ACCEPTED", 0, null, null, new { code = "validated" });
    }

    private static CommandResult Deny(string code, string message)
        => new(
            Status: "DENIED",
            ExitCode: null,
            Stdout: null,
            Stderr: message,
            PostVerify: new { code });

    private static bool PayloadHasString(object payload, string key)
    {
        if (payload is JsonElement element)
        {
            return element.ValueKind == JsonValueKind.Object &&
                   element.TryGetProperty(key, out var value) &&
                   value.ValueKind == JsonValueKind.String &&
                   !string.IsNullOrWhiteSpace(value.GetString());
        }

        var json = JsonSerializer.SerializeToElement(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        return json.ValueKind == JsonValueKind.Object &&
               json.TryGetProperty(key, out var property) &&
               property.ValueKind == JsonValueKind.String &&
               !string.IsNullOrWhiteSpace(property.GetString());
    }
}

public sealed class GovernedWindowsMutationHandler : ICommandHandler
{
    private readonly string _type;
    private readonly bool _enabled;

    public GovernedWindowsMutationHandler(string type, bool enabled)
    {
        _type = string.IsNullOrWhiteSpace(type) ? throw new ArgumentException("Command type is required.", nameof(type)) : type;
        _enabled = enabled;
    }

    public string Type => _type;

    public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
    {
        var guard = GovernedWindowsMutationGuard.ValidateOrDeny(command, _enabled);
        if (guard.Status != "ACCEPTED")
            return Task.FromResult(guard);

        return Task.FromResult(new CommandResult(
            Status: "FAILED",
            ExitCode: 1,
            Stdout: null,
            Stderr: "Windows mutation executor is not implemented in this build.",
            PostVerify: new { code = "executor_not_implemented" }));
    }
}
