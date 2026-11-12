using System.Web.Mvc;

namespace MvcApp.Controllers
{
    [RoutePrefix("reports")]
    public class ReportsController : Controller
    {
        [Route("{year:int}")]
        public ActionResult Year(int year) { return View(); }

        [AcceptVerbs(HttpVerbs.Get | HttpVerbs.Post)]
        [Route("multi/{id=5}")]
        [Route("multi2")]
        public ActionResult Multi(int id) { return View(); }

        [Route("~/r/latest")]
        public ActionResult Latest() { return View(); }
    }
}
