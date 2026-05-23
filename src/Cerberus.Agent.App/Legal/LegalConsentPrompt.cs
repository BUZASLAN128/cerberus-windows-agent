using System.Windows;

namespace Cerberus.Agent.App.Legal;

internal static class LegalConsentPrompt
{
    public static bool EnsureUserConsent(Window? owner, string actionName)
    {
        if (AgentLegalConsent.HasCurrentConsent(LegalConsentScope.User))
            return true;

        var message =
            $"Before {actionName}, you must accept the current Cerberus Windows Agent legal package.\n\n"
            + $"{AgentLegalConsent.CurrentConsentSummary}\n\n"
            + "The agent may register this device, run as a Windows service, send operational health telemetry, "
            + "receive authorized control-plane commands, and manage Cerberus-owned local Windows accounts when your organization enables those features.\n\n"
            + "Select OK only if you accept these terms.";

        var result = owner is null
            ? System.Windows.MessageBox.Show(message, "Cerberus Legal Terms", MessageBoxButton.OKCancel, MessageBoxImage.Information)
            : System.Windows.MessageBox.Show(owner, message, "Cerberus Legal Terms", MessageBoxButton.OKCancel, MessageBoxImage.Information);

        if (result != MessageBoxResult.OK)
            return false;

        AgentLegalConsent.Accept(LegalConsentScope.User, "tray_control_center");
        return true;
    }
}
