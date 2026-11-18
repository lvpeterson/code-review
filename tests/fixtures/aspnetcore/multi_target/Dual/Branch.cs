#if NETFRAMEWORK
using System.Web.Mvc;

namespace Dual
{
    public class FrameworkBranchController : Controller
    {
        [HttpPost]
        public ActionResult Purge(int id)
        {
            return RedirectToAction("Index");
        }
    }
}
#else
namespace Dual
{
    public static class CoreBranch
    {
        public static void Map(WebApplication app)
        {
            app.MapPost("/purge/{id}", (int id) => Results.Ok(id));
        }
    }
}
#endif
