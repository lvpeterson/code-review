using System.Web.Mvc;

namespace Cs.Layered
{
    public class WriteController : Controller
    {
        private IWriter _w;

        public ActionResult Post(string v)
        {
            _w.Save(v, null);
            return null;
        }
    }
}
