var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
#if NET8_0_OR_GREATER
app.MapPost("/gated/{id}", (int id) => Results.Ok(id));
#endif
app.Run();
