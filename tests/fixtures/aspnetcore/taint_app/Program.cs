var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddDbContext<AppDb>();

var app = builder.Build();

app.MapControllers();
app.Run();
