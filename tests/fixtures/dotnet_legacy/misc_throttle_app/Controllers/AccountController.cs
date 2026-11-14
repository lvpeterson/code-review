using System.Web.Mvc;

namespace Throttled
{
    public class AccountController : Controller
    {
        [HttpPost]
        public ActionResult Login(string user, string password) { return View(); }

        [HttpPost]
        public ActionResult Register(string user) { return View(); }

        [HttpPost]
        public ActionResult Checkout(string cart) { return View(); }
    }
}
