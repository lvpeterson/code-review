using System.Diagnostics;
using System.Web.Mvc;
using log4net;

namespace TaintCs.Misc
{
    // LOG-003: request keys, pw / passwd segments, and the Windows event log as a sink.
    public class LogLeakExtraController : Controller
    {
        private static readonly ILog Log = LogManager.GetLogger(typeof(LogLeakExtraController));

        public ActionResult FormKey()
        {
            var v = Request.Form["Password"];
            Log.Info("got " + v);
            return Content("ok");
        }

        public ActionResult IndexerKey()
        {
            Log.Info(Request["Password"]);
            return Content("ok");
        }

        public ActionResult ParamsKey()
        {
            var v = Request.Params["pwd"];
            Log.Debug(v);
            return Content("ok");
        }

        public ActionResult PwSegment(string userPw)
        {
            Log.Info("pw " + userPw);
            return Content("ok");
        }

        public ActionResult PasswdName(string passwd)
        {
            Log.Info(passwd);
            return Content("ok");
        }

        public ActionResult EventLogSink(string password)
        {
            EventLog.WriteEntry("app", "login " + password);
            return Content("ok");
        }

        // Not secrets.
        public ActionResult PwrSupply(string pwrSupply)
        {
            Log.Info(pwrSupply);
            return Content("ok");
        }

        public ActionResult FormUser()
        {
            Log.Info(Request.Form["UserName"]);
            return Content("ok");
        }
    }
}
