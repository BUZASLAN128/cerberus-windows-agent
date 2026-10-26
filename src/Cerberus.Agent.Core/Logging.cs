namespace Cerberus.Agent.Core;

public interface IAgentLogger
{
    void Info(string message);
    void Warn(string message);
    void Error(string message, Exception? ex = null);
}

public static class ExceptionSite
{
    /// <summary>Throw frame as <c>Type.Method</c>, plus <c>via</c> the first Cerberus.* frame when it differs; no paths or arguments. "unknown" when absent.</summary>
    public static string FirstFrame(Exception ex)
    {
        try
        {
            var trace = new System.Diagnostics.StackTrace(ex, fNeedFileInfo: false);
            var first = trace.GetFrame(0)?.GetMethod();
            if (first is null)
                return "unknown";

            var thrown = Format(first);
            for (var i = 0; i < trace.FrameCount; i++)
            {
                var m = trace.GetFrame(i)?.GetMethod();
                if (m?.DeclaringType?.FullName?.StartsWith("Cerberus.", StringComparison.Ordinal) != true)
                    continue;
                var ours = Format(m);
                return ours == thrown ? thrown : $"{thrown} via {ours}";
            }

            return thrown;
        }
        catch (Exception)
        {
            return "unknown";
        }
    }

    private static string Format(System.Reflection.MethodBase method)
    {
        var type = method.DeclaringType;
        var name = method.Name;
        // Async state machine <X>d__N.MoveNext -> Outer.X
        if (type is { DeclaringType: { } outer } && type.Name.Length > 2 && type.Name[0] == '<' && type.Name.IndexOf('>') is var end and > 1)
            return $"{outer.Name}.{type.Name[1..end]}";
        return $"{type?.Name ?? "?"}.{name}";
    }
}

public sealed class NullAgentLogger : IAgentLogger
{
    public static readonly NullAgentLogger Instance = new();

    private NullAgentLogger() { }

    public void Info(string message) { }
    public void Warn(string message) { }
    public void Error(string message, Exception? ex = null) { }
}

