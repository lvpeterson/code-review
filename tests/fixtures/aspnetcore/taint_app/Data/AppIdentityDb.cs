using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

public class AppIdentityDb : IdentityDbContext<ApplicationUser>
{
    public AppIdentityDb(DbContextOptions<AppIdentityDb> options) : base(options) { }
}
