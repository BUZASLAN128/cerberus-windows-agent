using System.Text.Json;

namespace Cerberus.Agent.Core;

public sealed class AgentUpdateJsonExtra : Dictionary<string, JsonElement>
{
    public override bool Equals(object? obj)
        => obj is AgentUpdateJsonExtra other && Count == other.Count &&
           this.All(entry => other.TryGetValue(entry.Key, out var value) && JsonElement.DeepEquals(entry.Value, value));

    public override int GetHashCode() => Count;
}
