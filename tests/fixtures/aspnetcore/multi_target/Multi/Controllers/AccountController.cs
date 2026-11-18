using System.Web.Mvc;

namespace Multi.Controllers
{
    public class AccountController : Controller
    {
        [HttpPost]
        public ActionResult Remove(int id)
        {
            return RedirectToAction("Index");
        }
    }
}
