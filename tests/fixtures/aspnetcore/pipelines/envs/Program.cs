var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
var dev = app.Environment.IsDevelopment();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else if (app.Environment.IsStaging())
{
    app.UseHsts();
}
else if (app.Environment.IsEnvironment(Environments.Production))
{
    app.UseHttpsRedirection();
}
else
{
    app.UseCors();
}

if (!app.Environment.IsDevelopment())
{
    if (app.Environment.IsEnvironment("staging"))
    {
        app.UseSession();
    }
    else
    {
        app.UseStaticFiles();
    }
}

if (app.Environment.IsDevelopment() || app.Environment.IsStaging())
{
    app.UseRateLimiter();
}

if (app.Environment.IsProduction() && app.Configuration["X"] == "1")
{
    app.UseAntiforgery();
}

if (dev)
{
    app.UseExceptionHandler("/dev-error");
}

if (app.Environment.EnvironmentName == Environments.Staging)
{
    app.UseAuthentication();
}

if (SomeCheck(app.Environment))
{
    app.UseAuthorization();
}

app.MapGroup("/a").RequireAuthorization().MapGet("/b", () => "b").AllowAnonymous();
app.Run();

static bool SomeCheck(IWebHostEnvironment env)
{
    var name = env.EnvironmentName;
    return name.Length > 3;
}
