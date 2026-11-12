using System.Data.Entity;

namespace Cs.Objects
{
    // EF context and entities for the object-level authz rules. EF types are not referenced by
    // the project, so the rules match these by the names written in source.
    public class ShopContext : DbContext
    {
        public DbSet<Order> Orders { get; set; }
    }

    public class Order
    {
        [System.ComponentModel.DataAnnotations.Key]
        public int Id { get; set; }
        public string OwnerId { get; set; }
        public string Name { get; set; }
        public decimal Total { get; set; }
    }

    // Plain transfer object: not an entity type.
    public class OrderDto
    {
        public string Name { get; set; }
    }

    // Entity guarded at class level against over-posting.
    [System.Web.Mvc.Bind(Include = "Title")]
    public class Note
    {
        [System.ComponentModel.DataAnnotations.Key]
        public int Id { get; set; }
        public string Title { get; set; }
    }
}
