namespace Misc3d.Services;

public class EmptyCartException : Exception { }

public interface ICartService
{
    Task Update(int id);
    Task PlaceOrder(int id);
}

public class CartService : ICartService
{
    public Task Update(int id) => Task.CompletedTask;
    public Task PlaceOrder(int id) => Task.CompletedTask;
}
