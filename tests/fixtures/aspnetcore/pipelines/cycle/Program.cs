var builder = WebApplication.CreateBuilder(args);
builder.Services.AddFirst();
var app = builder.Build();
app.Run();
