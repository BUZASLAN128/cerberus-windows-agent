using System.Text.Json;
using System.Text.Json.Nodes;

namespace Cerberus.Agent.Core;

/// <summary>Current-consent redaction for all signed JSON bodies, including durable replay.</summary>
public sealed class AgentOutboundPrivacyPolicy(Func<bool>? hasCurrentMachineConsent = null)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly HashSet<string> DetailFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "failedlogons", "successfullogons", "localadmins", "logcleared",
        "addedby", "addedatutc", "additionsource",
    };

    public string Prepare(string json)
    {
        if (string.IsNullOrWhiteSpace(json) || AgentBuildProfile.IsServer || hasCurrentMachineConsent?.Invoke() == true)
            return json;
        var body = JsonNode.Parse(json);
        return Redact(body) ? body!.ToJsonString(JsonOptions) : json;
    }

    private static bool Redact(JsonNode? node)
    {
        var changed = false;
        if (node is JsonArray items)
        {
            foreach (var item in items) changed |= Redact(item);
        }
        else if (node is JsonObject obj)
        {
            if (obj["sections"] is JsonObject classified && classified["security"] is { } security && security is not JsonObject)
                throw new InvalidOperationException("Security section is not an object; privacy filtering refused.");
            foreach (var (name, value) in obj.ToArray())
            {
                if (DetailFields.Contains(name.Replace("_", "").Replace("-", "")))
                {
                    obj.Remove(name);
                    changed = true;
                }
                else changed |= Redact(value);
            }
            // Fact results and snapshots use this same section/hash contract at any nesting level.
            if (changed && obj["sections"] is JsonObject sections && obj["section_hashes"] is JsonObject hashes)
                foreach (var (section, value) in sections)
                    if (hashes.ContainsKey(section)) hashes[section] = AgentSnapshotFactory.HashSection(value);
        }
        return changed;
    }
}
