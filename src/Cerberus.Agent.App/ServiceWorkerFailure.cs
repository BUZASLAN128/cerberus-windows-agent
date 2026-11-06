using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Cerberus.Agent.App;

/// <summary>Bounded worker-failure location without exception messages, data or file paths.</summary>
internal static class ServiceWorkerFailure
{
    internal static string Describe(Exception? failure)
    {
        var summary = $"Cerberus agent worker failed ({failure?.GetType().Name ?? "unknown"}).";
        if (failure is null) return summary;
        try
        {
            var trace = new StackTrace(failure, fNeedFileInfo: false);
            var locations = new List<string>();
            for (var index = 0; index < trace.FrameCount && locations.Count < 8; index++)
            {
                var method = trace.GetFrame(index)?.GetMethod();
                var type = method?.DeclaringType?.FullName;
                if (type is null || (!type.StartsWith("Cerberus.", StringComparison.Ordinal) &&
                    !type.StartsWith("System.", StringComparison.Ordinal))) continue;
                var location = type + "." + method!.Name;
                locations.Add(location.Length <= 200 ? location : location[..200]);
            }
            return $"{summary} HResult=0x{failure.HResult:X8}; origin={string.Join(" <- ", locations)}";
        }
        catch
        {
            // A diagnostic failure must never prevent the existing fail-fast path.
            return summary;
        }
    }
}
