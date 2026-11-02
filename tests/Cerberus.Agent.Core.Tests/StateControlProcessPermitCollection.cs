namespace Cerberus.Agent.Core.Tests;

// The production state-handler permit is static; other test classes must not own it during crash checkpoints.
[CollectionDefinition("StateControlProcessPermit", DisableParallelization = true)]
public sealed class StateControlProcessPermitCollection
{
}
