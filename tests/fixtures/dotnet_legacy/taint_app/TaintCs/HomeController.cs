using System.Web.Mvc;

namespace Cs.Home
{
    public class Profile
    {
        public string Name { get; set; }

        [AllowHtml]
        public string Bio { get; set; }
    }

    // Show feeds ViewBag and the view model from the request; the matching view is Views/Home/Show.cshtml.
    public class HomeController : Controller
    {
        public ActionResult Show(string msg)
        {
            ViewBag.Msg = msg;
            return View(new Profile { Bio = msg });
        }

        public ActionResult Save(Profile p)
        {
            return Content("saved");
        }

        [ValidateInput(false)]
        public ActionResult Raw(string body)
        {
            return Content("ok");
        }

        public ActionResult Fetch()
        {
            var s = Request.Unvalidated.QueryString["x"];
            return Content("ok");
        }
    }
}
