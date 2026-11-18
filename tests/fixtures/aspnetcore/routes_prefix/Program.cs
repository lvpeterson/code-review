var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers(o => { o.Conventions.Add(new ApiPrefixConvention("v9")); });
builder.Services.AddAuthentication().AddJwtBearer();
builder.Services.AddAuthorization();
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
