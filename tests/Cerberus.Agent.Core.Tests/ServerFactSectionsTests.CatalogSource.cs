#if CERBERUS_SERVER_PROFILE
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class ServerFactSectionsTests
{
    [Fact]
    public void Catalog_ServerProfileSectionsEqualTheEnvelopeSectionSet()
    {
        var names = WindowsTelemetrySectionCatalog.CreateDefault((string?)null).Select(s => s.SectionName).ToArray();

        Assert.Equal(EnvelopeTypes.ServerFactSections.Count, names.Length);
        Assert.True(EnvelopeTypes.ServerFactSections.SetEquals(names));
    }
}
#endif
