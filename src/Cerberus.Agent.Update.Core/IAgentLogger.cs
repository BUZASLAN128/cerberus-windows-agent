namespace Cerberus.Agent.Core;

public interface IAgentLogger
{
    void Info(string message);
    void Warn(string message);
    void Error(string message, Exception? ex = null);
}
