using System;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;

namespace TaintCs.Errors
{
    public class RfLog { public void Error(Exception e) { } }

    // What really ends the request after a catch around an auth decision, and what does not.
    public class RfController : Controller
    {
        private RfLog _log = new RfLog();
        private void Work() { }

        // -- fail-open: nothing here stops execution ----------------------------------------
        public ActionResult N1() { try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); } catch (Exception ex) { HttpContext.GetOwinContext().Authentication.Challenge(); } return View(); }

        public ActionResult N2() { try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); } catch (Exception ex) { _log.Error(ex); } HttpContext.GetOwinContext().Authentication.Challenge(); return View(); }

        public ActionResult N3()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { Response.Redirect("/login", false); }
            Work();
            return View();
        }

        public ActionResult N4()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { RedirectToAction("Login"); }
            return View();
        }

        public ActionResult N5()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { HttpContext.GetOwinContext().Authentication.SignOut(); }
            return View();
        }

        public ActionResult N6()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { Response.StatusCode = 401; }
            Work();
            return View();
        }

        public ActionResult N7()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { _log.Error(ex); }
            Response.StatusCode = 401;
            Work();
            return View();
        }

        public ActionResult N8()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { _log.Error(ex); }
            HttpContext.ApplicationInstance.CompleteRequest();
            return View();
        }

        public ActionResult N9()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { _log.Error(ex); }
            Response.Redirect("/home", false);
            Work();
            return View();
        }

        // The decision try shares its line with the code that follows it.
        public ActionResult OneAct() { try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); } catch (Exception ex) { _log.Error(ex); } return View(); }

        // A lambda's return is not the method's success return.
        public ActionResult LambdaOnly()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { _log.Error(ex); }
            Func<RfController, bool> f = x => { return true; };
            throw new HttpException(403, "no");
        }

        // -- safe: the request really ends ---------------------------------------------------
        public ActionResult S1() { try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); } catch (Exception ex) { return new HttpUnauthorizedResult(); } return View(); }

        public ActionResult S2()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { Response.StatusCode = 401; return new EmptyResult(); }
            return View();
        }

        public ActionResult S3()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { Response.Redirect("/login"); }
            return View();
        }

        public ActionResult S4()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { Response.Redirect("/login", true); }
            return View();
        }

        public ActionResult S5()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { return RedirectToAction("Login"); }
            return View();
        }

        public ActionResult S6()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { Response.End(); }
            return View();
        }

        public ActionResult S7()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { _log.Error(ex); }
            Server.Transfer("/denied");
            return View();
        }

        public ActionResult S8()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { _log.Error(ex); }
            Response.End();
            return View();
        }

        public ActionResult S9()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { return Challenge(); }
            return View();
        }
    }

    public class RfBool
    {
        public bool OneLine(IPrincipal u) { try { if (!u.IsInRole("a")) throw new InvalidOperationException(); } catch { } return true; }

        public bool OneLineSafe(IPrincipal u) { try { if (!u.IsInRole("a")) throw new InvalidOperationException(); } catch (Exception ex) { return false; } return false; }

        // The lambda's `return true` is not the method's result.
        public bool LambdaTail(IPrincipal u)
        {
            try { if (!u.IsInRole("a")) throw new InvalidOperationException(); }
            catch (Exception ex) { }
            Func<int, bool> f = x => { return true; };
            return false;
        }
    }
}
