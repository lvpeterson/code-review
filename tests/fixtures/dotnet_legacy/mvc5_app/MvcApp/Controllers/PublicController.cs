using System.Web.Mvc;

namespace MvcApp.Controllers
{
    public class PublicController : Controller
    {
        public ActionResult Index() { return View(); }

        [HttpPost]
        [AllowAnonymous]
        public ActionResult Register(string email, string password) { return View(); }
    }
}
