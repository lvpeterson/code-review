namespace Cs.Layered
{
    public class OrderService : IOrderService
    {
        private readonly OrderRepository _repo = new OrderRepository();

        public string Find(string term)
        {
            return _repo.FindByTerm(term);
        }
    }
}
