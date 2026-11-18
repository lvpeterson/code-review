using Microsoft.Extensions.DependencyInjection;

public static class Chain
{
    public static void AddFirst(this IServiceCollection s)
    {
        s.AddCors();
        s.AddSecond();
    }

    public static void AddSecond(this IServiceCollection s)
    {
        s.AddSession();
        s.AddFirst();
    }
}
