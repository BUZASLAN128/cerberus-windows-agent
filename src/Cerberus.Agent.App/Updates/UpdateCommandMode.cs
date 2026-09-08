using System.Text.Json;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

internal static class UpdateCommandMode
{
    public static async Task<int> RunAsync(bool apply, CancellationToken ct)
    {
        try
        {
            AgentLocalControlResponse response;
            if (apply)
            {
                var status = await AgentLocalControlClient.SendAsync(new AgentLocalControlRequest("status"), ct).ConfigureAwait(false);
                if (!status.Success || status.AttemptId is null || !AgentUpdateStates.CanApply(status.UpdateState))
                {
                    Console.WriteLine(JsonSerializer.Serialize(new { success = false, code = "attempt_required", state = status.UpdateState }));
                    return 2;
                }
                response = await AgentLocalControlClient.SendAsync(new AgentLocalControlRequest("apply", status.AttemptId), ct).ConfigureAwait(false);
            }
            else
                response = await AgentLocalControlClient.SendAsync(new AgentLocalControlRequest("check"), ct).ConfigureAwait(false);
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                success = response.Success, code = response.Code, state = response.UpdateState,
                attempt_id = response.AttemptId, current_version = response.CurrentVersion, target_version = response.TargetVersion,
            }));
            return response.Success ? 0 : 2;
        }
        catch (Exception)
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new { success = false, code = "service_unavailable" }));
            return 2;
        }
    }
}
