namespace Cerberus.Agent.Core;

/// <summary>
/// Install-time identity of the agent on this machine: service, data directory,
/// HKLM keys and local IPC names. Selected at compile time by the build profile so
/// the desktop and server agents can be installed side by side. Desktop values are
/// the historical literals and must not change.
/// </summary>
public static class AgentInstallIdentity
{
#if CERBERUS_SERVER_PROFILE
    public const string ServiceName = "CerberusServerAgent";
    public const string ServiceDisplayName = "Cerberus Server Agent";
    public const string DataDirName = "CerberusServerAgent";
    public const string RegistryPath = @"Software\Cerberus\ServerAgent";
    public const string LegalConsentRegistryPath = @"Software\Cerberus\ServerAgent\LegalConsent";
    public const string ControlPipeName = "CerberusServerAgent.Control.v1";
    public const string UiMutexName = "Global\\CerberusServerAgent.Ui.SingleInstance";
    public const string UiPipeName = "CerberusServerAgent.Ui.SingleInstancePipe";
    public const string TrayMutexName = "Global\\CerberusServerAgent.Tray.SingleInstance";
    public const string TrayPipeName = "CerberusServerAgent.Tray.SingleInstancePipe";
#else
    public const string ServiceName = "CerberusAgent";
    public const string ServiceDisplayName = "CERBERUS Windows Agent";
    public const string DataDirName = "CerberusAgent";
    public const string RegistryPath = @"Software\Cerberus\WindowsAgent";
    public const string LegalConsentRegistryPath = @"Software\Cerberus\WindowsAgent\LegalConsent";
    public const string ControlPipeName = "CerberusAgent.Control.v1";
    public const string UiMutexName = "Global\\CerberusAgent.Ui.SingleInstance";
    public const string UiPipeName = "CerberusAgent.Ui.SingleInstancePipe";
    public const string TrayMutexName = "Global\\CerberusAgent.Tray.SingleInstance";
    public const string TrayPipeName = "CerberusAgent.Tray.SingleInstancePipe";
#endif
}
