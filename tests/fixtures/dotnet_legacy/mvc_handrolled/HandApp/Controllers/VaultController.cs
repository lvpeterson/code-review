using System.Web.Mvc;

namespace HandApp.Controllers
{
    public abstract class GuardedBase : Controller
    {
        protected override void OnAuthorization(AuthorizationContext filterContext)
        {
            if (!filterContext.HttpContext.User.Identity.IsAuthenticated)
            {
                filterContext.Result = new HttpUnauthorizedResult();
            }
        }
    }

    public class VaultController : GuardedBase
    {
        public ActionResult Index() { return View(); }
    }
}
