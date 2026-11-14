using System.Web.Mvc;

namespace TaintCs.Areas.HelpPage.Controllers
{
    public class HelpController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Api(string apiId)
        {
            return View();
        }
    }
}
