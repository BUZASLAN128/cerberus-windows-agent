using System.Reflection;
using System.Runtime.CompilerServices;
using Cerberus.Agent.Core;

[assembly: InternalsVisibleTo("Cerberus.Agent.Core.Tests")]
[assembly: InternalsVisibleTo("Cerberus.Agent")]
[assembly: InternalsVisibleTo("Cerberus.Agent.Runtime")]
[assembly: InternalsVisibleTo("Cerberus.Agent.Updater")]
[assembly: AssemblyMetadata("AgentUpdaterContractVersion", AgentUpdaterContract.Version)]
