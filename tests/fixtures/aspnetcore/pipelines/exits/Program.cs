var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.AddDevOnly();
app.AddNotProd();
app.AddOrThrow();
app.AddLoop();

if (IsDev())
{
    app.UseStaticFiles();
}

if (IsQa())
{
    app.UseRateLimiter();
}

var flag = false;
if (app.Environment.IsDevelopment())
{
    flag = true;
}
if (flag)
{
    app.UseCors();
}

var dev2 = app.Environment.IsDevelopment();
if (dev2)
{
    app.UseAntiforgery();
}

app.UseRouting();
app.Run();

bool IsDev() => app.Environment.IsDevelopment();

bool IsQa()
{
    var n = app.Environment.EnvironmentName;
    return n == "QA";
}
