using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Legal;

internal static class SecurityTelemetryConsent
{
    public static bool IsAllowed() => IsAllowed(AgentBuildProfile.IsServer,
        scope => scope == LegalConsentScope.Machine && AgentLegalConsent.HasCurrentMachinePrivacyConsent());

    internal static bool IsAllowed(bool isServer, Func<LegalConsentScope, bool> hasCurrentConsent)
        // Server's existing headless/security behavior is unchanged. Desktop collects for the machine, not the tray user.
        => isServer || hasCurrentConsent(LegalConsentScope.Machine);
}
