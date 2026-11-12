using System.Web.Mvc;

namespace Cs.Layered
{
    // Two actions reaching one sink.
    public class TwoRoutesController : Controller
    {
        public ActionResult Left(string t)
        {
            Shared.Run(t);
            return null;
        }

        public ActionResult Right(string t)
        {
            Shared.Run(t);
            return null;
        }
    }
}
