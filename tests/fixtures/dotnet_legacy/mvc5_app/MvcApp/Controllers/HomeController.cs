using System.Web.Mvc;

namespace MvcApp.Controllers
{
    public class HomeController : BaseController
    {
        public ActionResult Index() { return View(); }

        [NonAction]
        public string Helper() { return "x"; }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Save(string name) { return RedirectToAction("Index"); }

        protected override void Dispose(bool disposing) { base.Dispose(disposing); }
    }
}
