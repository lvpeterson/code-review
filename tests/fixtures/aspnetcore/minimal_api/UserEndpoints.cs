public static class UserEndpoints
{
    public static RouteGroupBuilder MapUserEndpoints(this RouteGroupBuilder g)
    {
        g.MapGet("/users", () => "list");
        return g;
    }
}
