using System.Web.Mvc;
using MvcApp.Filters;

namespace MvcApp.Controllers
{
    [AlwaysAllow]
    public class LooseController : Controller
    {
        public ActionResult Index() { return View(); }
    }
}
