public static class Setup
{
    public static void AddDevOnly(this WebApplication app)
    {
        if (!app.Environment.IsDevelopment()) return;
        app.UseDeveloperExceptionPage();
    }

    public static void AddNotProd(this WebApplication app)
    {
        if (app.Environment.IsProduction()) return;
        app.UseHsts();
    }

    public static void AddOrThrow(this WebApplication app)
    {
        if (app.Environment.IsDevelopment()) throw new System.Exception("no");
        app.UseHttpsRedirection();
    }

    public static void AddLoop(this WebApplication app)
    {
        foreach (var x in new[] { 1 })
        {
            if (!app.Environment.IsStaging()) continue;
            app.UseSession();
        }
    }
}
