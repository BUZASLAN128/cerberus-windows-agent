namespace Cerberus.Agent.Core;

public interface IAgentLogger
{
    void Info(string message);
    void Warn(string message);
    void Error(string message, Exception? ex = null);
}

public sealed class NullAgentLogger : IAgentLogger
{
    public static readonly NullAgentLogger Instance = new();

    private NullAgentLogger() { }

    public void Info(string message) { }
    public void Warn(string message) { }
    public void Error(string message, Exception? ex = null) { }
}

