using System.Data.SqlClient;
using System.Web.Mvc;

namespace Cs.Objects
{
    public class ObjectsController : Controller
    {
        private readonly ShopContext db = new ShopContext();
        private readonly OrderLookup _lookup = new OrderLookup();

        // IDOR: the id reaches Find and nothing checks who is asking.
        public ActionResult Get(int id)
        {
            Order order = db.Orders.Find(id);
            return View(order);
        }

        // Ownership is compared to the signed-in user.
        public ActionResult Mine(int id)
        {
            Order order = db.Orders.Find(id);
            if (order.OwnerId != User.Identity.GetUserId())
            {
                return HttpNotFound();
            }
            return View(order);
        }

        // IDOR through a project method.
        public ActionResult Via(int id)
        {
            return View(_lookup.Load(id));
        }

        // IDOR through a project method that builds SQL.
        public ActionResult Raw(int id)
        {
            return Content(_lookup.LoadRaw(id));
        }

        // The id never reaches a data access.
        public ActionResult Label(int id)
        {
            return Content(_lookup.Label(id));
        }

        // Over-posting: the whole entity is bound.
        [HttpPost]
        public ActionResult Update(Order order)
        {
            db.SaveChanges();
            return null;
        }

        [HttpPost]
        public ActionResult UpdateBound([Bind(Include = "Name")] Order order)
        {
            db.SaveChanges();
            return null;
        }

        // Entity class carries [Bind].
        [HttpPost]
        public ActionResult UpdateNote(Note note)
        {
            return null;
        }

        // GET with an entity parameter is not a write.
        public ActionResult Show(Order order)
        {
            return null;
        }

        // IDOR: SQL built from the id inside the action.
        public ActionResult RawInline(int id)
        {
            var cmd = new SqlCommand("select * from orders where id = " + id, new SqlConnection());
            return null;
        }

        // IDOR: raw EF query built from the id.
        public ActionResult EfRaw(int id)
        {
            var rows = db.Database.SqlQuery<Order>("select * from orders where id = " + id);
            return View(rows);
        }

        // A log line is not an ownership check.
        public ActionResult Logged(int id)
        {
            Order order = db.Orders.Find(id);
            System.Diagnostics.Debug.WriteLine(User.Identity.Name);
            return View(order);
        }

        // The helper reading the user is not on the path to the data access.
        public ActionResult Audited(int id)
        {
            var who = _lookup.AuditUser(id);
            Order order = db.Orders.Find(id);
            return View(order);
        }

        // A session key that is not an identity.
        public ActionResult Themed(int id)
        {
            var theme = Session["UserTheme"];
            Order order = db.Orders.Find(id);
            return View(order);
        }

        // Session user id compared to the owner.
        public ActionResult SessionOwner(int id)
        {
            Order order = db.Orders.Find(id);
            if (order.OwnerId != (string)Session["UserId"])
            {
                return HttpNotFound();
            }
            return View(order);
        }

        // The user is part of the query itself.
        public ActionResult Scoped(int id)
        {
            var order = db.Orders.Where(o => o.OwnerId == User.Identity.GetUserId() && o.Id == id).FirstOrDefault();
            return View(order);
        }

        // IsAuthenticated alone is not an ownership check.
        public ActionResult AuthOnly(int id)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return HttpNotFound();
            }
            return View(db.Orders.Find(id));
        }

        [HttpPost]
        public ActionResult UpdateMany(System.Collections.Generic.List<Order> orders)
        {
            return null;
        }

        [HttpPost]
        public ActionResult UpdatePrefix([Bind(Prefix = "o")] Order order)
        {
            return null;
        }

        // A comparison that is only stored does not gate the lookup.
        public ActionResult ViewBagOwner(int id)
        {
            Order order = db.Orders.Find(id);
            ViewBag.IsOwner = order.OwnerId == User.Identity.GetUserId();
            return View(db.Orders.Find(id));
        }

        // A null check around a log line gates nothing.
        public ActionResult NullCheckLog(int id)
        {
            if (User.Identity.Name != null)
            {
                System.Diagnostics.Debug.WriteLine("seen");
            }
            return View(db.Orders.Find(id));
        }

        // The fetched entity is compared to the user and the request is rejected.
        public ActionResult FetchedOwner(int id)
        {
            var o = db.Orders.Find(id);
            var uid = User.Identity.GetUserId();
            if (o.OwnerId != uid)
            {
                return HttpNotFound();
            }
            return View(o);
        }

        // ADO.NET: the id is a command parameter.
        public ActionResult AdoParam(int id)
        {
            var cmd = new SqlCommand("select * from orders where id = @id", new SqlConnection());
            cmd.Parameters.AddWithValue("@id", id);
            cmd.ExecuteReader();
            return null;
        }

        // Membership.GetUserNameByEmail is not the signed-in user.
        public ActionResult MemberLookup(int id)
        {
            if (Membership.GetUserNameByEmail("a@b.c") == null)
            {
                return HttpNotFound();
            }
            return View(db.Orders.Find(id));
        }

        // A cache entry named like a session key is not the session.
        public ActionResult CacheKey(int id)
        {
            if (HttpContext.Cache["UserId"] == null)
            {
                return HttpNotFound();
            }
            return View(db.Orders.Find(id));
        }

        // Exclude-only [Bind] leaves every other field bindable.
        [HttpPost]
        public ActionResult UpdateExcl([Bind(Exclude = "Id")] Order order)
        {
            return null;
        }

        // The gate compares the user to an unrelated record, not the one being fetched.
        public ActionResult CartGate(int id)
        {
            var cart = new Order();
            if (cart.OwnerId != User.Identity.GetUserId())
            {
                return HttpNotFound();
            }
            return View(db.Orders.Find(id));
        }

        // Sign-in only: says nothing about who owns the record.
        public ActionResult SignedInOnly(int id)
        {
            if (User.Identity.Name == null)
            {
                return HttpNotFound();
            }
            return View(db.Orders.Find(id));
        }

        // A ternary gate on the fetched record.
        public ActionResult TernaryOwner(int id)
        {
            var o = db.Orders.Find(id);
            var uid = User.Identity.GetUserId();
            return o.OwnerId == uid ? View(o) : (ActionResult)HttpNotFound();
        }

        // Async variant of the user marker.
        public ActionResult AsyncOwner(int id)
        {
            var o = db.Orders.Find(id);
            if (o.OwnerId != User.Identity.GetUserIdAsync().Result)
            {
                return HttpNotFound();
            }
            return View(o);
        }

        // Session reached through this.
        public ActionResult SessionThis(int id)
        {
            var o = db.Orders.Find(id);
            if (o.OwnerId != (string)this.Session["UserId"])
            {
                return HttpNotFound();
            }
            return View(o);
        }

        // ADO.NET: the id is assigned to a parameter Value.
        public ActionResult AdoValue(int id)
        {
            var cmd = new SqlCommand("select * from orders where id = @id", new SqlConnection());
            cmd.Parameters.Add("@id", System.Data.SqlDbType.Int).Value = id;
            cmd.ExecuteReader();
            return null;
        }
    }
}
