using System.Web.Mvc;

namespace MvcApp.Controllers
{
    [Authorize]
    public class AdminController : Controller
    {
        public ActionResult DeleteUser(int id) { return View(); }
    }
}
