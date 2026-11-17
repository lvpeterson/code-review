using System.Diagnostics;
using TaintApp.Models;
using TaintApp.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddRazorPages();
builder.Services.AddDbContext<AppDb>();
builder.Services.AddScoped<IReport, Report>();
builder.Services.AddScoped<Auditor>();

var app = builder.Build();

app.MapControllers();
app.MapRazorPages();
app.MapGet("/m/cmd", (string q) => Process.Start("tool", q));
app.MapGet("/m/args", ([AsParameters] SearchArgs a) => Process.Start("tool", a.Sql));
app.MapGet("/m/helper", (HttpContext ctx) => Helpers.Run(ctx));
app.Run();

static class Helpers
{
    public static IResult Run(HttpContext c)
    {
        var x = c.Request.Query["x"].ToString();
        Process.Start("tool", x);
        return Results.Ok();
    }
}
