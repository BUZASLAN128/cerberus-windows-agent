using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Xml;
using System.Xml.Linq;

namespace Cerberus.Agent.Core;

[SupportedOSPlatform("windows")]
public static class AgentUpdateWatchTask
{
    public const string TaskName = "CerberusServerAgentLkgWatch";
    internal const string TaskSddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
    internal const int Create = 2;
    internal const int CreateOrUpdate = 6;
    internal const int ServiceAccountLogon = 5;
    internal const int TaskNotFound = unchecked((int)0x80070002);
    internal const int TaskAlreadyExists = unchecked((int)0x800700B7);
    private const string SystemSid = "S-1-5-18";
    private const string StartBoundary = "2026-01-01T00:00:00";
    private static readonly XNamespace TaskNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    public static void CreateIfAbsent()
    {
        RequireSystemServer();
        var hostPath = ValidateHostPath();
        using var scheduler = new TaskSchedulerConnection();
        RegisterWhenNeeded(scheduler, hostPath, allowRepair: false);
    }

    public static void Delete()
    {
        RequireSystemServer();
        using var scheduler = new TaskSchedulerConnection();
        scheduler.Delete();
    }

    public static bool TryRun()
    {
        if (!AgentBuildProfile.IsServer || !AgentUpdateSecurity.IsLocalSystem())
            return false;

        try
        {
            var hostPath = ValidateHostPath();
            using var scheduler = new TaskSchedulerConnection();
            return scheduler.RunIfValid(hostPath);
        }
        catch (Exception ex) when (ex is COMException or IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    internal static void VerifyAndRepair()
    {
        RequireSystemServer();
        var hostPath = ValidateHostPath();
        using var scheduler = new TaskSchedulerConnection();
        RegisterWhenNeeded(scheduler, hostPath, allowRepair: true);
    }

    internal static void RegisterWhenNeeded(ITaskRegistration scheduler, string hostPath, bool allowRepair)
    {
        var existing = scheduler.Read();
        if (existing is not null && (!allowRepair || Matches(existing, hostPath)))
            return;

        var xml = BuildXml(hostPath);
        if (allowRepair)
        {
            scheduler.Register(xml, CreateOrUpdate, TaskSddl);
            if (scheduler.Read() is not { } registered || !Matches(registered, hostPath))
                throw new InvalidOperationException("The protected update task did not match its registered definition.");
        }
        else
        {
            try { scheduler.Register(xml, Create, TaskSddl); }
            catch (Exception ex) when (IsSchedulerError(ex, TaskAlreadyExists) && scheduler.Read() is not null)
            {
                // Another installer registered the task after the absence check.
            }
        }
    }

    // Late-bound COM calls surface a failing HRESULT as its mapped .NET exception (0x80070002 arrives as
    // FileNotFoundException), so scheduler outcomes are matched by HRESULT, not by exception type.
    internal static bool IsSchedulerError(Exception ex, int hresult)
        => ex is COMException or IOException && ex.HResult == hresult;

    internal static string BuildXml(string hostPath) => $$"""
        <Task version="1.3" xmlns="{{TaskNamespace}}">
          <Triggers>
            <BootTrigger>
              <Enabled>true</Enabled>
              <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
              <Delay>PT2M</Delay>
            </BootTrigger>
            <TimeTrigger>
              <Enabled>true</Enabled>
              <StartBoundary>{{StartBoundary}}</StartBoundary>
              <Repetition><Interval>PT10M</Interval></Repetition>
              <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
            </TimeTrigger>
          </Triggers>
          <Principals>
            <Principal id="System">
              <UserId>{{SystemSid}}</UserId>
              <RunLevel>HighestAvailable</RunLevel>
            </Principal>
          </Principals>
          <Settings>
            <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
            <StartWhenAvailable>true</StartWhenAvailable>
            <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
            <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
            <Hidden>true</Hidden>
            <AllowStartOnDemand>true</AllowStartOnDemand>
            <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
          </Settings>
          <Actions Context="System">
            <Exec>
              <Command>{{SecurityElement.Escape(hostPath)}}</Command>
              <Arguments>{{AgentUpdateWatchHostArgs.WatchArgument}}</Arguments>
            </Exec>
          </Actions>
        </Task>
        """;

    internal static bool Matches(TaskDefinition definition, string hostPath)
    {
        if (definition.LogonType != ServiceAccountLogon || !HasExpectedDacl(definition.Sddl))
            return false;
        try
        {
            using var xml = XmlReader.Create(new StringReader(definition.Xml), new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 64 * 1024,
            });
            var root = XDocument.Load(xml).Root;
            if (root?.Name != TaskNamespace + "Task")
                return false;

            var actions = root.Element(TaskNamespace + "Actions");
            var principals = root.Element(TaskNamespace + "Principals");
            if (actions?.Elements().ToArray() is not [var action] || action.Name != TaskNamespace + "Exec" ||
                !string.Equals(Value(action, "Command"), hostPath, StringComparison.OrdinalIgnoreCase) ||
                Value(action, "Arguments") != AgentUpdateWatchHostArgs.WatchArgument || !string.IsNullOrEmpty(Value(action, "WorkingDirectory")) ||
                principals?.Elements().ToArray() is not [var principal] || principal.Name != TaskNamespace + "Principal" ||
                Value(principal, "UserId") != SystemSid || Value(principal, "GroupId") is not null ||
                Value(principal, "RunLevel") != "HighestAvailable" ||
                (string?)actions.Attribute("Context") != (string?)principal.Attribute("id"))
                return false;

            return MatchesSchedule(root.Element(TaskNamespace + "Triggers"), root.Element(TaskNamespace + "Settings"));
        }
        catch (Exception ex) when (ex is XmlException or FormatException or OverflowException) { return false; }
    }

    private static bool MatchesSchedule(XElement? triggers, XElement? settings)
    {
        if (triggers?.Elements().Count() != 2 || triggers.Element(TaskNamespace + "BootTrigger") is not { } boot ||
            triggers.Element(TaskNamespace + "TimeTrigger") is not { } time || Value(boot, "StartBoundary") is not null ||
            Value(boot, "EndBoundary") is not null || boot.Element(TaskNamespace + "Repetition") is not null ||
            !DurationIs(boot, "Delay", TimeSpan.FromMinutes(2)) || !BooleanIs(boot, "Enabled", true, defaultValue: true) ||
            !DurationIs(boot, "ExecutionTimeLimit", TimeSpan.Zero) || !DurationIs(time, "ExecutionTimeLimit", TimeSpan.Zero) ||
            Value(time, "StartBoundary") != StartBoundary || Value(time, "EndBoundary") is not null ||
            !BooleanIs(time, "Enabled", true, defaultValue: true) || !DurationIs(time, "RandomDelay", TimeSpan.Zero, missingIsZero: true) ||
            time.Element(TaskNamespace + "Repetition") is not { } repetition ||
            !DurationIs(repetition, "Interval", TimeSpan.FromMinutes(10)) || Value(repetition, "Duration") is not null ||
            BooleanIs(repetition, "StopAtDurationEnd", true))
            return false;

        return settings is not null && (Value(settings, "MultipleInstancesPolicy") ?? "IgnoreNew") == "IgnoreNew" &&
            BooleanIs(settings, "Enabled", true, defaultValue: true) && BooleanIs(settings, "StartWhenAvailable", true) &&
            BooleanIs(settings, "DisallowStartIfOnBatteries", false, defaultValue: true) &&
            BooleanIs(settings, "StopIfGoingOnBatteries", false, defaultValue: true) && BooleanIs(settings, "Hidden", true) &&
            BooleanIs(settings, "AllowStartOnDemand", true, defaultValue: true) && !BooleanIs(settings, "RunOnlyIfIdle", true) &&
            !BooleanIs(settings, "RunOnlyIfNetworkAvailable", true) && DurationIs(settings, "ExecutionTimeLimit", TimeSpan.Zero);
    }

    private static bool HasExpectedDacl(string sddl)
    {
        const int fullAccess = 0x1F01FF;
        try
        {
            // Task Scheduler reports a registered "D:P(...)" DACL without the protected flag and adds a SYSTEM read
            // entry, so the check rests on the entries: explicit allow entries for SYSTEM and Administrators only.
            var sd = new RawSecurityDescriptor(sddl);
            if (sd.DiscretionaryAcl is not { } acl)
                return false;
            var system = 0;
            var admins = 0;
            foreach (var entry in acl)
            {
                if (entry is not CommonAce { AceQualifier: AceQualifier.AccessAllowed, AceFlags: AceFlags.None, IsCallback: false } ace)
                    return false;
                if (ace.SecurityIdentifier.IsWellKnown(WellKnownSidType.LocalSystemSid)) system |= ace.AccessMask;
                else if (ace.SecurityIdentifier.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)) admins |= ace.AccessMask;
                else return false;
            }

            return system == fullAccess && admins == fullAccess;
        }
        catch (ArgumentException) { return false; }
    }

    private static string? Value(XElement parent, string name) => (string?)parent.Element(TaskNamespace + name);

    private static bool DurationIs(XElement parent, string name, TimeSpan expected, bool missingIsZero = false)
        => Value(parent, name) is { } value ? XmlConvert.ToTimeSpan(value) == expected : missingIsZero && expected == TimeSpan.Zero;

    private static bool BooleanIs(XElement parent, string name, bool expected, bool defaultValue = false)
        => (Value(parent, name) is { } value ? XmlConvert.ToBoolean(value) : defaultValue) == expected;

    private static void RequireSystemServer()
    {
        if (!AgentBuildProfile.IsServer || !AgentUpdateSecurity.IsLocalSystem())
            throw new UnauthorizedAccessException("The server update task requires LocalSystem.");
    }

    private static string ValidateHostPath()
    {
        var lkg = new AgentUpdateLkgStore(AgentUpdateSecurity.DefaultPrivilegedRoot);
        AgentUpdateSecurity.ValidateProtectedPath(lkg.HostPath, lkg.UpdatesRoot, allowMissing: false);
        return lkg.HostPath;
    }

    internal sealed record TaskDefinition(string Xml, string Sddl, int LogonType);

    internal interface ITaskRegistration
    {
        TaskDefinition? Read();
        void Register(string xml, int flags, string sddl);
    }

    private sealed class TaskSchedulerConnection : ITaskRegistration, IDisposable
    {
        private readonly dynamic _folder;
        private readonly dynamic _service;

        public TaskSchedulerConnection()
        {
            var type = Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!;
            _service = Activator.CreateInstance(type)!;
            try
            {
                _service.Connect();
                _folder = _service.GetFolder("\\");
            }
            catch
            {
                Release(_service);
                throw;
            }
        }

        public TaskDefinition? Read() => WithTask<TaskDefinition?>(ReadDefinition, null);

        public void Register(string xml, int flags, string sddl)
            => Release(_folder.RegisterTask("\\" + TaskName, xml, flags, SystemSid, null, ServiceAccountLogon, sddl));

        public void Delete()
        {
            try { _folder.DeleteTask(TaskName, 0); }
            catch (Exception ex) when (IsSchedulerError(ex, TaskNotFound)) { }
        }

        public bool RunIfValid(string hostPath) => WithTask(task =>
        {
            if (!Matches(ReadDefinition(task), hostPath)) return false;
            Release(task.Run(null));
            return true;
        }, false);

        private T WithTask<T>(Func<dynamic, T> action, T absent)
        {
            dynamic task;
            try { task = _folder.GetTask(TaskName); }
            catch (Exception ex) when (IsSchedulerError(ex, TaskNotFound)) { return absent; }
            try { return action(task); }
            finally { Release(task); }
        }

        private static TaskDefinition ReadDefinition(dynamic task)
        {
            dynamic definition = task.Definition;
            try
            {
                dynamic principal = definition.Principal;
                try { return new((string)task.Xml, (string)task.GetSecurityDescriptor(4), (int)principal.LogonType); }
                finally { Release(principal); }
            }
            finally { Release(definition); }
        }

        private static void Release(object? value)
        {
            if (value is not null && Marshal.IsComObject(value))
                Marshal.ReleaseComObject(value);
        }

        public void Dispose()
        {
            Release(_folder);
            Release(_service);
        }
    }
}
