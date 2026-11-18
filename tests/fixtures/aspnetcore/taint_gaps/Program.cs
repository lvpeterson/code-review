var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddRazorPages();
builder.Services.AddHttpClient();
var app = builder.Build();
app.MapControllers();
app.MapRazorPages();
app.Run();
