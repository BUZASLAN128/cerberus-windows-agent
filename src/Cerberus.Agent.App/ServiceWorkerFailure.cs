using System;

namespace Cerberus.Agent.App;

/// <summary>Bounded worker-failure location without exception messages, data or file paths.</summary>
internal static class ServiceWorkerFailure
{
    internal static string Describe(Exception? failure)
    {
        var summary = $"Cerberus agent worker failed ({failure?.GetType().Name ?? "unknown"}).";
        if (failure is null) return summary;
        var details = $"{summary} HResult=0x{failure.HResult:X8}";
        try
        {
            var method = failure.TargetSite;
            var type = method?.DeclaringType?.FullName;
            if (type is null || (!type.StartsWith("Cerberus.", StringComparison.Ordinal) &&
                !type.StartsWith("System.", StringComparison.Ordinal))) return details;

            var name = method!.Name;
            if (type.Length + 1 + name.Length > 200)
            {
                // Keep the method visible even when its declaring type is long.
                name = name[..Math.Min(name.Length, 100)];
                type = type[..Math.Min(type.Length, 199 - name.Length)];
            }
            return $"{details}; origin={type}.{name}";
        }
        catch
        {
            // A diagnostic failure must never prevent the existing fail-fast path.
            return details;
        }
    }
}
