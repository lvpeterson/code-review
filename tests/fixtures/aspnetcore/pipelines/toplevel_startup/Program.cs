var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors();

Host.CreateDefaultBuilder(args)
    .ConfigureWebHostDefaults(w => w.UseStartup<AppStartup>())
    .Build()
    .Run();
