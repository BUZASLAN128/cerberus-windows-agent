namespace Cerberus.Agent.Core;

/// <summary>The actual MSI helper argv contract; parsing performs no privileged operation.</summary>
public sealed record AgentInstallerInvocation(string Operation, Guid ProductCode, string Version,
    string? LabTransaction, bool RequireBackendContact)
{
    public static bool TryParse(string[] args, out AgentInstallerInvocation? invocation)
    {
        invocation = null;
        if (args.Length < 6 || !Guid.TryParse(args[1], out var product)) return false;
        var operation = args[0];
        var validCount = operation switch
        {
            "bootstrap" or "validate-runtime" or "lab-commit" or "lab-rollback" => args.Length is 6 or 7,
            "health" => args.Length is 6 or 7 or 8,
            "capture" or "configure" or "stop" or "restore" or "commit" or "ensure-running" or "validate-proxy" => args.Length == 6,
            _ => false,
        };
        if (!validCount) return false;
        var transactionIndex = operation == "health" ? 7 : 6;
        invocation = new(operation, product, args[3], args.Length > transactionIndex ? args[transactionIndex] : null,
            operation == "health" && args.Length >= 7 && args[6] == "1");
        return true;
    }
}
