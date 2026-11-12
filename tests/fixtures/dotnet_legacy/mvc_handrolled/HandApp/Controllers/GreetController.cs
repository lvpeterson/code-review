using System.Web.Mvc;

namespace HandApp.Controllers
{
    // Reads IsAuthenticated only to personalise the page -- not an auth check.
    public abstract class GreetingBase : Controller
    {
        protected override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (User.Identity.IsAuthenticated)
            {
                ViewBag.Name = User.Identity.Name;
            }
            base.OnActionExecuting(filterContext);
        }
    }

    public class GreetController : GreetingBase
    {
        public ActionResult Index() { return View(); }
    }
}
