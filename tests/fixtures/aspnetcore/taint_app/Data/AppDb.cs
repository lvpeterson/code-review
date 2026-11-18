using Microsoft.EntityFrameworkCore;

public class AppDb : DbContext
{
    public DbSet<Order> Orders { get; set; } = null!;
    public DbSet<User> Users { get; set; } = null!;
}
