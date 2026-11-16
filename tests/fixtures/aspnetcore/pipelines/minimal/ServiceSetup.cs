using Microsoft.Extensions.DependencyInjection;

public static class ServiceSetup
{
    public static void AddAppServices(this IServiceCollection s)
    {
        s.AddCors();
    }
}
