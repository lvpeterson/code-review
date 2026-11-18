using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Text;

// Synthetic fixture: every setting below is deliberately weak so each configuration rule has
// something to report. The Development-only block at the end must stay silent.
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

// CFG-007: wildcard origin. CFG-015 is raised by [EnableCors("Tight")] on the reset action.
builder.Services.AddCors(o =>
{
    o.AddPolicy("Open", p => p.AllowAnyOrigin().AllowAnyHeader());
    o.AddPolicy("Tight", p => p.WithOrigins("https://app.example.test"));
});

// Cookies: SESS-001 (not Secure), SESS-002 (HttpOnly off), SESS-003 (long expiry), SESS-009 (SameSite None).
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.Cookie.SecurePolicy = CookieSecurePolicy.None;
        o.Cookie.HttpOnly = false;
        o.Cookie.SameSite = SameSiteMode.None;
        o.ExpireTimeSpan = TimeSpan.FromDays(90);
    })
    // JWT: CFG-012 (metadata over HTTP), SESS-010 (validation off), SESS-011 (clock skew),
    // SEC-004 (literal signing key).
    .AddJwtBearer(o =>
    {
        o.RequireHttpsMetadata = false;
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = false,
            ClockSkew = TimeSpan.FromMinutes(45),
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("fixture-signing-key-not-a-real-secret-0001")),
        };
    });

// Identity: SEC-005 (weak password rules), SEC-006 (lockout off), SEC-007 (confirmation off).
builder.Services.AddIdentity<IdentityUser, IdentityRole>(o =>
{
    o.Password.RequiredLength = 4;
    o.Password.RequireDigit = false;
    o.Lockout.AllowedForNewUsers = false;
    o.SignIn.RequireConfirmedAccount = false;
});

// CRY-009: key ring on disk with no ProtectKeysWith*.
builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo("/var/keys"));

// CFG-013: HTTP-only listener.
builder.WebHost.ConfigureKestrel(o =>
{
    o.ListenAnyIP(8080);
    // RES-001: unlimited request bodies.
    o.Limits.MaxRequestBodySize = null;
});

var app = builder.Build();

// CFG-008 (developer page in every environment) and ERR-002 (handler writes the exception text).
app.UseDeveloperExceptionPage();
app.UseExceptionHandler(a => a.Run(async c =>
{
    var f = c.Features.Get<IExceptionHandlerFeature>();
    await c.Response.WriteAsync(f!.Error.Message);
}));

// INV-003: API documentation served in Production. No UseHsts / UseHttpsRedirection (CFG-010, CFG-011),
// no UseRateLimiter (RES-004).
app.UseSwagger();
app.UseSwaggerUI();

app.UseRouting();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapDefaultControllerRoute();

// Weak settings that only run in Development: none of these may be reported.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseCors(p => p.AllowAnyOrigin());
    app.MapOpenApi();
}

app.Run();
