public class Order
{
    public int Id { get; set; }
}

public class OrderStore
{
    public Order? Find(int id) => new Order { Id = id };
}
