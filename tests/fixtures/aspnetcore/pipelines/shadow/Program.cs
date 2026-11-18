var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var dev = app.Environment.IsDevelopment();
bool Chk(bool dev) => !dev;
bool Chk2(bool dev) => dev;
bool Chk3()
{
    var dev = true;
    return dev;
}

// The parameter hides the captured `dev`.
if (Chk(true))
{
    app.UseCors();
}

if (Chk2(builder.Configuration.GetValue<bool>("X")))
{
    app.UseSession();
}

if (Chk3())
{
    app.UseHsts();
}

app.UseRouting();
app.Run();
