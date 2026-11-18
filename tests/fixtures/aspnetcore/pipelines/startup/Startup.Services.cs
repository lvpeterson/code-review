using Microsoft.Extensions.DependencyInjection;

public partial class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllers();
        services.AddCompanyAuth();
    }
}
