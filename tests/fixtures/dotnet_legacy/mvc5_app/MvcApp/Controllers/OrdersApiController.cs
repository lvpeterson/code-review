using System.Web.Http;
using MvcApp.Filters;

namespace MvcApp.Controllers
{
    public class Order
    {
        public int Id { get; set; }
    }

    [RealAuth]
    public class OrdersApiController : ApiController
    {
        public Order GetOrder(int id) { return new Order { Id = id }; }

        public void PostOrder(Order o) { }

        [HttpDelete]
        public void Remove(int id) { }
    }
}
