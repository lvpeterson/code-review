var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages();
builder.Services.AddScoped<ICartService, CartService>();
var app = builder.Build();
app.MapRazorPages();
app.Run();
