var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews();
builder.Services.AddSession();
var app = builder.Build();
// Swagger UI only in development: not reachable in production.
if (app.Environment.IsDevelopment())
{
    app.UseSwaggerUI();
}
// Swagger document published in every environment.
app.UseSwagger();
app.UseStaticFiles();
app.UseRouting();
app.UseSession();
app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");
app.Run();
