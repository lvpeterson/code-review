using System.Web.Mvc;

namespace Tiny
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return Content("hello");
        }
    }
}
