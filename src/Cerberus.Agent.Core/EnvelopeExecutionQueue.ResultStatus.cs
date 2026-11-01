namespace Cerberus.Agent.Core;

public sealed partial class EnvelopeExecutionQueue
{
    private static string ResultStatus(CommandReplayRecord record)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(Convert.FromBase64String(record.ResultB64!));
            return doc.RootElement.GetProperty("status").GetString() ?? "UNKNOWN";
        }
        catch (Exception ex) when (ex is FormatException or System.Text.Json.JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return "UNKNOWN";
        }
    }

    private async Task<CommandResult> InvokeBoundedAsync(ICommandHandler handler, AgentCommand command, CancellationToken ct)
    {
        var gate = command.Type == EnvelopeTypes.AgentState ? StateHandlerGate : HandlerGate;
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ct.ThrowIfCancellationRequested();
            if ((command.Type != EnvelopeTypes.AgentState && RequiresStateRecovery) ||
                (IsQuarantined() && command.Type is not (EnvelopeTypes.Ping or EnvelopeTypes.AgentState)))
                return new CommandResult("FAILED", null, null, EnvelopeCodes.Quarantined, null);
            return await InvokeAsync(handler, command, ct).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

}
