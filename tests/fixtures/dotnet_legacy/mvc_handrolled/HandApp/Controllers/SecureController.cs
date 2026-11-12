using System.Web.Mvc;

namespace HandApp.Controllers
{
    // No attribute: covered only by the web.config <location path="secure"> deny rule.
    public class SecureController : Controller
    {
        public ActionResult Index() { return View(); }
    }
}
