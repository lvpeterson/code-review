using Microsoft.EntityFrameworkCore;

namespace CarriedApp.Data;

public class Order
{
    public int Id { get; set; }
    public string Item { get; set; } = "";
}

public class AppDb : DbContext
{
    public DbSet<Order> Orders { get; set; } = null!;
}
