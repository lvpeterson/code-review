public static class AuditEndpoints
{
    public static IEndpointConventionBuilder MapAuditEndpoints(this IEndpointRouteBuilder e)
    {
        var a = e.MapGet("/audit/a", () => 1);
        var b = e.MapGet("/audit/b", () => 2);
        return new CompositeConventionBuilder(a, b);
    }
}

public class CompositeConventionBuilder : IEndpointConventionBuilder
{
    private readonly IEndpointConventionBuilder[] _parts;

    public CompositeConventionBuilder(params IEndpointConventionBuilder[] parts)
    {
        _parts = parts;
    }

    public void Add(Action<EndpointBuilder> convention)
    {
        foreach (var p in _parts) p.Add(convention);
    }

    public void Finally(Action<EndpointBuilder> finallyConvention)
    {
        foreach (var p in _parts) p.Finally(finallyConvention);
    }
}
