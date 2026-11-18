public static class OrphanEndpoints
{
    public static void MapOrphans(this IEndpointRouteBuilder e)
    {
        e.MapPost("/orphan", () => 1);
    }
}
