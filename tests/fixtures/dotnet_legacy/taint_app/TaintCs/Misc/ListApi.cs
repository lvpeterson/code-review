using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;
using System.Web.Mvc;
using Cs.Objects;

namespace TaintCs.Misc
{
    // Every action projects into OrderDto, so the entity-exposure and IDOR rules stay quiet here.
    public class OrderStore
    {
        private readonly ShopContext db = new ShopContext();

        public List<OrderDto> All()
        {
            return db.Orders.Select(o => new OrderDto { Name = o.Name }).ToList();
        }

        public List<OrderDto> Page(int page, int size)
        {
            return db.Orders.OrderBy(o => o.Id).Skip(page * size).Take(Math.Min(size, 100)).Select(o => new OrderDto { Name = o.Name }).ToList();
        }
    }

    // RES-002: list endpoints with and without paging.
    public class OrdersListController : ApiController
    {
        private readonly ShopContext db = new ShopContext();
        private readonly OrderStore _repo = new OrderStore();

        public IHttpActionResult GetAll()
        {
            return Ok(db.Orders.Select(o => new OrderDto { Name = o.Name }).ToList());
        }

        public IQueryable<OrderDto> GetRaw()
        {
            return db.Orders.Select(o => new OrderDto { Name = o.Name });
        }

        public IHttpActionResult GetPaged(int page, int pageSize)
        {
            return Ok(db.Orders.OrderBy(o => o.Id).Skip(page * pageSize).Take(Math.Min(pageSize, 100)).Select(o => new OrderDto { Name = o.Name }).ToList());
        }

        // The page parameters are accepted and never applied.
        public IHttpActionResult GetPageIgnored(int page, int pageSize)
        {
            return Ok(db.Orders.Select(o => new OrderDto { Name = o.Name }).ToList());
        }

        // The Take is on a different query than the one returned.
        public IHttpActionResult GetOtherQueryPaged()
        {
            var small = db.Orders.Take(5).Select(o => new OrderDto { Name = o.Name }).ToList();
            var all = db.Orders.Select(o => new OrderDto { Name = o.Name }).ToList();
            return Ok(all);
        }

        public IHttpActionResult GetViaLocal(int n)
        {
            var q = db.Orders.Where(o => o.Total > 0);
            q = q.Take(Math.Min(n, 50));
            return Ok(q.Select(o => new OrderDto { Name = o.Name }).ToList());
        }

        public IHttpActionResult GetViaLocalUnpaged()
        {
            var q = db.Orders.Where(o => o.Total > 0);
            return Ok(q.Select(o => new OrderDto { Name = o.Name }).ToList());
        }

        // The caller chooses the page size: an unclamped parameter is not a bound.
        public IHttpActionResult GetPagedUnclamped(int pageSize)
        {
            return Ok(db.Orders.Take(pageSize).Select(o => new OrderDto { Name = o.Name }).ToList());
        }

        public IHttpActionResult GetTakeMax()
        {
            return Ok(db.Orders.Take(int.MaxValue).Select(o => new OrderDto { Name = o.Name }).ToList());
        }

        public IHttpActionResult GetTakeAfterList()
        {
            return Ok(db.Orders.Select(o => new OrderDto { Name = o.Name }).ToList().Take(10));
        }

        public IHttpActionResult GetCount()
        {
            return Ok(db.Orders.Count());
        }

        public IHttpActionResult GetFirst()
        {
            return Ok(db.Orders.Select(o => new OrderDto { Name = o.Name }).FirstOrDefault());
        }

        [EnableQuery(PageSize = 50)]
        public IQueryable<OrderDto> GetOData()
        {
            return db.Orders.Select(o => new OrderDto { Name = o.Name });
        }

        [EnableQuery]
        public IQueryable<OrderDto> GetODataNoSize()
        {
            return db.Orders.Select(o => new OrderDto { Name = o.Name });
        }

        public IHttpActionResult GetViaRepo()
        {
            return Ok(_repo.All());
        }

        public IHttpActionResult GetViaRepoPaged()
        {
            return Ok(_repo.Page(1, 10));
        }
    }

    public class MvcListController : Controller
    {
        private readonly ShopContext db = new ShopContext();

        public ActionResult Index()
        {
            return View(db.Orders.Select(o => new OrderDto { Name = o.Name }).ToList());
        }
    }
}
