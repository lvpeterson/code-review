using System.Web.Mvc;

namespace Cs.Layered
{
    // Controller action -> service via interface -> repository that builds SQL.
    public class OrdersController : Controller
    {
        private readonly IOrderService _svc;

        public ActionResult Search(string term)
        {
            var rows = _svc.Find(term);
            return null;
        }

        // Numeric parameters cannot carry a payload.
        public ActionResult ById(int id)
        {
            var rows = _svc.Find("x" + id);
            return null;
        }
    }
}
