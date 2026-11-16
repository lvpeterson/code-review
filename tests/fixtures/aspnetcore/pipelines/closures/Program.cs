var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// A local function closes over the caller's locals.
var dev = app.Environment.IsDevelopment();
bool IsX() => dev;
if (IsX())
{
    app.UseStaticFiles();
}

var flag = false;
if (app.Environment.IsStaging())
{
    flag = true;
}
bool IsFlag() => flag;
if (IsFlag())
{
    app.UseCors();
}

// A solution method sees only its parameters.
if (Env.IsDevEnv(app.Environment))
{
    app.UseSession();
}

Env.Gate(app);
app.UseRouting();
app.Run();

public static class Env
{
    public static bool IsDevEnv(IWebHostEnvironment e) => e.IsDevelopment();

    public static void Gate(WebApplication app)
    {
        foreach (var i in new[] { 1, 2 })
        {
            if (app.Environment.IsDevelopment()) break;
            app.UseHsts();
        }
    }
}
