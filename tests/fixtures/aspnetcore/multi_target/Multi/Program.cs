var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.MapPost("/items/{id}", (int id) => Results.Ok(id));
app.Run();
