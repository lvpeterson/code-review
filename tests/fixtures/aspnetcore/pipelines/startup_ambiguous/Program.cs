public class Program
{
    public static void Main(string[] args)
    {
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(w => w.UseStartup(typeof(AppStartup)))
            .Build()
            .Run();
    }
}
