using System.Web.Mvc;

namespace MvcApp.Controllers
{
    [Authorize]
    public abstract class BaseController : Controller
    {
    }
}
