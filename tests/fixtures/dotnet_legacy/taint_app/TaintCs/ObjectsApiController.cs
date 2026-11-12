using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web.Mvc;
using System.Web.Http;

namespace Cs.Objects
{
    public class ObjectsApiController : ApiController
    {
        private readonly ShopContext db = new ShopContext();

        // Over-exposure: the entity goes out as is (also an IDOR candidate).
        public Order GetRaw(int id)
        {
            return db.Orders.Find(id);
        }

        public OrderDto GetDto(string name)
        {
            return new OrderDto { Name = name };
        }

        public IEnumerable<Order> GetAll()
        {
            return db.Orders.ToList();
        }

        public IHttpActionResult GetWrapped(string name)
        {
            Order o = db.Orders.FirstOrDefault(x => x.Name == name);
            return Ok(o);
        }

        public IHttpActionResult GetWrappedDto(string name)
        {
            return Ok(new OrderDto { Name = name });
        }

        // Projection to a DTO: not an entity result.
        public IHttpActionResult GetProjected()
        {
            return Ok(db.Orders.Select(o => new OrderDto { Name = o.Name }).ToList());
        }

        public async Task<IHttpActionResult> GetAsync(string name)
        {
            return Ok(await db.Orders.FirstOrDefaultAsync(x => x.Name == name));
        }

        // Web API model binding ignores [Bind].
        public IHttpActionResult PostBound([Bind(Include = "Name")] Order order)
        {
            return Ok();
        }

        public IHttpActionResult GetGrouped()
        {
            return Ok(db.Orders.GroupBy(o => o.OwnerId).ToList());
        }

        public IHttpActionResult GetOfType()
        {
            return Ok(db.Orders.OfType<Order>().ToList());
        }

        public IHttpActionResult GetAnon()
        {
            return Ok(db.Orders.Select(o => new { o.Id }).ToList());
        }

        private OrderDto NewThing(Order o)
        {
            return new OrderDto { Name = o.Name };
        }

        // A call is not known to build a DTO.
        public IHttpActionResult GetViaCall()
        {
            return Ok(db.Orders.Select(o => NewThing(o)).ToList());
        }

        // A collection of entities is still entities.
        public IHttpActionResult GetListNew()
        {
            return Ok(db.Orders.Select(o => new List<Order> { o }).ToList());
        }
    }
}
