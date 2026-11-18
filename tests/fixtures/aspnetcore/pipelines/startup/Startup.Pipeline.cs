using Microsoft.AspNetCore.Builder;

public partial class Startup
{
    public void Configure(IApplicationBuilder app)
    {
        app.UseAuthorization();
        app.UseRouting();
        app.UseEndpoints(e => e.MapControllers());
    }
}
