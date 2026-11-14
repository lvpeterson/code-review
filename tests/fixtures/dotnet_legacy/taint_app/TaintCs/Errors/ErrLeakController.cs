using System;
using System.Web.Mvc;

namespace TaintCs.Errors
{
    public class ErrModel
    {
        public string Detail { get; set; }
    }

    // ERR-002: exception detail returned to the client.
    public class ErrLeakController : Controller
    {
        public ActionResult Direct()
        {
            try { Work(); }
            catch (Exception ex)
            {
                return Content(ex.Message);
            }
            return Content("ok");
        }

        public ActionResult ViaLocal()
        {
            try { Work(); }
            catch (Exception ex)
            {
                var msg = ex.Message;
                return Content(msg);
            }
            return Content("ok");
        }

        public ActionResult ViaJson()
        {
            try { Work(); }
            catch (Exception ex)
            {
                return Json(new { error = ex.ToString() });
            }
            return Content("ok");
        }

        public ActionResult ViaViewBag()
        {
            try { Work(); }
            catch (Exception ex)
            {
                ViewBag.Error = ex.Message;
            }
            return View();
        }

        public ActionResult ViaInnerAndConcat()
        {
            try { Work(); }
            catch (Exception ex)
            {
                string detail = "Failed: " + ex.InnerException.Message;
                string wrapped = String.Format("<{0}>", detail);
                return Content(wrapped);
            }
            return Content("ok");
        }

        public ActionResult ViaInterpolation()
        {
            try { Work(); }
            catch (Exception ex)
            {
                return Content($"error: {ex.StackTrace}");
            }
            return Content("ok");
        }

        public ActionResult ViaModel()
        {
            try { Work(); }
            catch (Exception ex)
            {
                var model = new ErrModel { Detail = ex.Message };
                return View("Failure", model);
            }
            return Content("ok");
        }

        public ActionResult ViaWholeException()
        {
            try { Work(); }
            catch (Exception ex)
            {
                var text = ex.ToString();
                Response.Write(text);
                return null;
            }
            return Content("ok");
        }

        // Safe: generic message; the exception goes to a log only.
        public ActionResult GenericMessage()
        {
            try { Work(); }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceError(ex.ToString());
                return Content("Something went wrong");
            }
            return Content("ok");
        }

        // Safe: exception type name only.
        public ActionResult TypeNameOnly()
        {
            try { Work(); }
            catch (Exception ex)
            {
                var kind = ex.GetType().Name;
                return Content("failure");
            }
            return Content("ok");
        }

        // ERR-003: swallowed.
        public ActionResult Swallowed()
        {
            try { Work(); }
            catch (Exception) { }
            return Content("ok");
        }

        public ActionResult SwallowedBare()
        {
            try { Work(); }
            catch { }
            return Content("ok");
        }

        // Not ERR-003: a narrow type with an empty body is a deliberate parse fallback.
        public ActionResult NarrowEmpty(string s)
        {
            int n = 0;
            try { n = int.Parse(s); }
            catch (FormatException) { }
            return Content(n.ToString());
        }

        private void Work() { }
    }
}
