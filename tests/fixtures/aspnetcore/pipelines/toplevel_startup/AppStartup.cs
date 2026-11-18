using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

public class AppStartup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddRazorPages();
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseRouting();
    }
}

// Shaped like a startup class but not the one UseStartup names.
public class LegacyStartup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddSession();
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseStaticFiles();
    }
}
