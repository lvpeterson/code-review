using System.Web.Mvc;

namespace Single48.Controllers
{
    public class OrdersController : Controller
    {
        [HttpPost]
        public ActionResult Cancel(int id)
        {
            return RedirectToAction("Index");
        }
    }
}
