var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddAuthentication().AddJwtBearer();
builder.Services.AddAuthorization();
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Middleware branches (not endpoint routed).
app.Map("/internal", branch => { branch.Run(async ctx => await ctx.Response.WriteAsync("x")); });
app.MapWhen(c => c.Request.Path.StartsWithSegments("/debug"), b => b.Run(async c => await c.Response.WriteAsync("d")));

// Groups through calls from a package that is not in the solution.
app.MapGroup("/api/orders").HasVersionInfo(1.0).MapGet("/", () => "list");
var catalog = app.NewVersionedApi("Catalog").MapGroup("api/catalog");
catalog.MapGet("/items", () => "items");
var billing = app.MapGroup("/api/billing").HasVersionInfo(2.0);
billing.MapBillingRoutes().RequireAuthorization();

// MapMethods with HttpMethods members.
app.MapMethods("/probe", [HttpMethods.Options], () => "o");
app.MapMethods("/probe2", new[] { HttpMethods.Post, HttpMethods.Put }, () => "p");
app.Run();

public static class BillingRoutes
{
    public static RouteGroupBuilder MapBillingRoutes(this RouteGroupBuilder g)
    {
        g.MapGet("/invoices", () => "i");
        return g;
    }
}
