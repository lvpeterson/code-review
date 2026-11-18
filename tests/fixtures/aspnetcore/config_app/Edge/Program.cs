// Second web project of the fixture: a minimal pipeline with no exception handler at all
// (DNL-CFG-009). The first project keeps an (information-leaking) handler for DNL-ERR-002, so the
// two rules need separate pipelines.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/ping", () => "pong");
app.Run();
