using System.Xml.Linq;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateWatchTaskTests
{
    private const string HostPath = @"C:\ProgramData\CerberusServerAgent\Privileged\Updates\lkg\Cerberus.Agent.Updater.exe";

    [Fact]
    public void DefinitionUsesCanonicalHostAndIndefiniteSystemSchedule()
    {
        var root = XElement.Parse(AgentUpdateWatchTask.BuildXml(HostPath));
        var ns = root.Name.Namespace;
        var boot = Assert.Single(root.Descendants(ns + "BootTrigger"));
        var time = Assert.Single(root.Descendants(ns + "TimeTrigger"));
        var settings = Assert.Single(root.Elements(ns + "Settings"));

        Assert.Equal("PT2M", (string?)boot.Element(ns + "Delay"));
        Assert.Equal("PT0S", (string?)boot.Element(ns + "ExecutionTimeLimit"));
        Assert.Equal("2026-01-01T00:00:00", (string?)time.Element(ns + "StartBoundary"));
        Assert.Equal("PT10M", (string?)time.Element(ns + "Repetition")?.Element(ns + "Interval"));
        Assert.Equal("PT0S", (string?)time.Element(ns + "ExecutionTimeLimit"));
        Assert.Null(time.Element(ns + "Repetition")?.Element(ns + "Duration"));
        Assert.Equal("PT0S", (string?)settings.Element(ns + "ExecutionTimeLimit"));
        Assert.Equal("IgnoreNew", (string?)settings.Element(ns + "MultipleInstancesPolicy"));
        Assert.Equal("S-1-5-18", Assert.Single(root.Descendants(ns + "UserId")).Value);
        Assert.Equal("HighestAvailable", Assert.Single(root.Descendants(ns + "RunLevel")).Value);
        Assert.Equal("--watch", Assert.Single(root.Descendants(ns + "Arguments")).Value);
        Assert.Equal(HostPath, Assert.Single(root.Descendants(ns + "Command")).Value);
        Assert.Equal("D:P(A;;FA;;;SY)(A;;FA;;;BA)", AgentUpdateWatchTask.TaskSddl);
        Assert.Equal(5, AgentUpdateWatchTask.ServiceAccountLogon);
    }

    [Fact]
    public void BootstrapCreatesOnceAndVerifiedHostRepairsChangedTask()
    {
        var scheduler = new SchedulerFixture();
        AgentUpdateWatchTask.RegisterWhenNeeded(scheduler, HostPath, allowRepair: false);
        Assert.Equal([2], scheduler.Writes);

        scheduler.Definition = scheduler.Definition! with { Sddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)" };
        AgentUpdateWatchTask.RegisterWhenNeeded(scheduler, HostPath, allowRepair: false);
        Assert.Equal([2], scheduler.Writes);
        Assert.False(AgentUpdateWatchTask.Matches(scheduler.Definition, HostPath));

        AgentUpdateWatchTask.RegisterWhenNeeded(scheduler, HostPath, allowRepair: true);
        AgentUpdateWatchTask.RegisterWhenNeeded(scheduler, HostPath, allowRepair: true);
        Assert.Equal([2, 6], scheduler.Writes);
        Assert.True(AgentUpdateWatchTask.Matches(scheduler.Definition!, HostPath));
    }

    [Theory]
    [InlineData("--watch", "--probe bad")]
    [InlineData("PT10M", "PT1M")]
    [InlineData("PT0S", "PT1M")]
    [InlineData("HighestAvailable", "LeastPrivilege")]
    [InlineData("Cerberus.Agent.Updater.exe", "retired-updater.exe")]
    public void DriftInExecutionIdentityOrScheduleIsRejected(string original, string altered)
    {
        var xml = AgentUpdateWatchTask.BuildXml(HostPath).Replace(original, altered, StringComparison.Ordinal);
        Assert.False(AgentUpdateWatchTask.Matches(new(xml, AgentUpdateWatchTask.TaskSddl, 5), HostPath));
    }

    [Fact]
    public void VerifyAndRepairFailsWhenSchedulerDoesNotApplySecurityDescriptor()
    {
        var scheduler = new SchedulerFixture { IgnoreSddl = true };
        Assert.Throws<InvalidOperationException>(() => AgentUpdateWatchTask.RegisterWhenNeeded(scheduler, HostPath, allowRepair: true));
        Assert.Equal([6], scheduler.Writes);
    }

    [Fact]
    public void TimeTriggerMayNotReintroduceAnExecutionDeadline()
    {
        var root = XElement.Parse(AgentUpdateWatchTask.BuildXml(HostPath));
        var ns = root.Name.Namespace;
        Assert.Single(root.Descendants(ns + "TimeTrigger")).SetElementValue(ns + "ExecutionTimeLimit", "PT1M");
        Assert.False(AgentUpdateWatchTask.Matches(new(root.ToString(), AgentUpdateWatchTask.TaskSddl, 5), HostPath));
    }

    private sealed class SchedulerFixture : AgentUpdateWatchTask.ITaskRegistration
    {
        public AgentUpdateWatchTask.TaskDefinition? Definition { get; set; }
        public bool IgnoreSddl { get; init; }
        public List<int> Writes { get; } = [];

        public AgentUpdateWatchTask.TaskDefinition? Read() => Definition;

        public void Register(string xml, int flags, string sddl)
        {
            Writes.Add(flags);
            Definition = new(xml, IgnoreSddl ? "D:(A;;FA;;;SY)" : sddl, AgentUpdateWatchTask.ServiceAccountLogon);
        }
    }
}
